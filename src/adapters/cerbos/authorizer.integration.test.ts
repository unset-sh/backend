// The Cerbos adapter against a real PDP: the binary of the exact `cerbos` dev dependency, serving this repository's
// policies/ on Unix sockets in a fresh folder, with telemetry off. Covers what the spike measured (agent-kit
// notes/cerbos-authorization/spike.md): decisions over gRPC on a socket, and that a stopped or hung PDP is
// `unavailable`, never an allow.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ownProfile, principalOf } from "../../domains/access/index.ts";
import { type Did, parseDid } from "../../domains/identity/index.ts";
import { createLogger } from "../../shared/log/index.ts";
import { createCerbosAuthorizer } from "./authorizer.ts";

const ROOT = join(import.meta.dirname, "../../..");
/** The binary the `cerbos` package installs for this machine (its optional dependency per platform). */
const BINARY = join(
  ROOT,
  "node_modules/@cerbos",
  `cerbos-${process.platform}-${process.arch}`,
  `cerbos-${process.platform}-${process.arch}`,
);

const OWNER = parseDid("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa") as Did;
const OTHER = parseDid("did:plc:bbbbbbbbbbbbbbbbbbbbbbbb") as Did;
const TIMEOUT_MS = 200;

const lines: string[] = [];
const log = createLogger({
  service: "backend",
  commit: "a".repeat(40),
  env: "test",
  write: (line) => lines.push(line),
});

let folder: string;
let pdp: ReturnType<typeof Bun.spawn>;

const start = () =>
  Bun.spawn(
    [
      BINARY,
      "server",
      `--set=server.httpListenAddr=unix:${join(folder, "http.sock")}`,
      `--set=server.grpcListenAddr=unix:${join(folder, "grpc.sock")}`,
      "--set=storage.driver=disk",
      `--set=storage.disk.directory=${join(ROOT, "policies")}`,
      "--set=telemetry.disabled=true",
    ],
    { env: { CERBOS_NO_TELEMETRY: "1", PATH: process.env.PATH ?? "" }, stdout: "ignore", stderr: "ignore" },
  );

const untilReady = async (authorizer: ReturnType<typeof createCerbosAuthorizer>) => {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (existsSync(join(folder, "grpc.sock")) && (await authorizer.ready())) return;
    await Bun.sleep(50);
  }
  throw new Error("the PDP did not become ready");
};

describe("the Cerbos authorizer", () => {
  let authorizer: ReturnType<typeof createCerbosAuthorizer>;

  beforeAll(async () => {
    folder = mkdtempSync(join(tmpdir(), "cerbos-"));
    pdp = start();
    authorizer = createCerbosAuthorizer({ socketPath: join(folder, "grpc.sock"), timeoutMs: TIMEOUT_MS, log });
    await untilReady(authorizer);
  });

  afterAll(() => {
    authorizer.close();
    pdp.kill("SIGKILL");
    rmSync(folder, { recursive: true, force: true });
  });

  test("a member reads and updates their own profile", async () => {
    const me = principalOf({ did: OWNER });
    expect(await authorizer.may(me, "read", ownProfile(OWNER))).toBe("allow");
    expect(await authorizer.may(me, "update", ownProfile(OWNER))).toBe("allow");
  });

  test("another member and a caller with no session are denied", async () => {
    for (const principal of [principalOf({ did: OTHER }), principalOf(null)]) {
      expect(await authorizer.may(principal, "read", ownProfile(OWNER))).toBe("deny");
      expect(await authorizer.may(principal, "update", ownProfile(OWNER))).toBe("deny");
    }
  });

  test("a hung PDP is unavailable within the timeout, and not ready", async () => {
    pdp.kill("SIGSTOP");
    try {
      const begun = performance.now();
      expect(await authorizer.may(principalOf({ did: OWNER }), "read", ownProfile(OWNER))).toBe("unavailable");
      expect(performance.now() - begun).toBeLessThan(TIMEOUT_MS * 5);
      expect(await authorizer.ready()).toBe(false);
    } finally {
      pdp.kill("SIGCONT");
    }
  });

  test("a stopped PDP is unavailable, and not ready", async () => {
    pdp.kill("SIGKILL");
    await pdp.exited;
    expect(await authorizer.may(principalOf({ did: OWNER }), "update", ownProfile(OWNER))).toBe("unavailable");
    expect(await authorizer.ready()).toBe(false);
  });

  test("its log lines carry no DID", () => {
    expect(lines.join("\n")).not.toContain("did:plc:");
  });
});
