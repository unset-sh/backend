// serve.ts `serverTls`: over the internal API's mutual TLS, only a client with a certificate from the client CA gets an
// answer; no certificate, another CA's, or plain HTTP is refused at the handshake. The certificates are throwaway ones
// made here with OpenSSL in a temp folder and deleted after; real ones come from unset-sh/deployment's
// scripts/internal-tls.sh, run by Alex.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createLogger } from "../shared/log/index.ts";
import { createServer, serveProbe, serverTls } from "./serve.ts";
import { testDeps } from "./test-deps.ts";

const dir = mkdtempSync(join(tmpdir(), "backend-tls-"));
const pem = (name: string) => readFileSync(join(dir, name), "utf8");

function openssl(...args: string[]) {
  const run = Bun.spawnSync(["openssl", ...args], { cwd: dir, stderr: "pipe" });
  if (run.exitCode !== 0) throw new Error(`openssl ${args[0]}: ${run.stderr.toString()}`);
}

function ca(name: string) {
  openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", `${name}.key`);
  openssl(
    "req",
    "-x509",
    "-new",
    "-key",
    `${name}.key`,
    "-out",
    `${name}.crt`,
    "-days",
    "1",
    "-subj",
    `/CN=${name}`,
    "-addext",
    "basicConstraints=critical,CA:TRUE",
    "-addext",
    "keyUsage=critical,keyCertSign",
  );
}

function leaf(name: string, signer: string, extensions: string) {
  openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", `${name}.key`);
  openssl("req", "-new", "-key", `${name}.key`, "-subj", `/CN=${name}`, "-out", `${name}.csr`);
  writeFileSync(join(dir, `${name}.ext`), extensions);
  openssl(
    "x509",
    "-req",
    "-in",
    `${name}.csr`,
    "-CA",
    `${signer}.crt`,
    "-CAkey",
    `${signer}.key`,
    "-CAcreateserial",
    "-days",
    "1",
    "-extfile",
    `${name}.ext`,
    "-out",
    `${name}.crt`,
  );
}

let server: ReturnType<typeof createServer>;
let port = 0;

beforeAll(() => {
  ca("server-ca");
  ca("client-ca");
  ca("other-ca");
  leaf("backend", "server-ca", "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n");
  leaf("web", "client-ca", "extendedKeyUsage=clientAuth\n");
  leaf("stranger", "other-ca", "extendedKeyUsage=clientAuth\n");
  const log = createLogger({ service: "backend", commit: "a".repeat(40), env: "test", write: () => undefined });
  server = createServer(testDeps({ ready: async () => true }), log).listen({
    port: 0,
    hostname: "127.0.0.1",
    tls: serverTls({ cert: pem("backend.crt"), key: pem("backend.key"), clientCa: pem("client-ca.crt") }),
  });
  port = server.server?.port ?? 0;
});

afterAll(async () => {
  await server.stop(true);
  rmSync(dir, { recursive: true, force: true });
});

/** GET /health as a client holding `client`'s certificate, or none, trusting only backend's CA. */
const health = (client?: string) =>
  fetch(`https://localhost:${port}/health`, {
    tls: {
      ca: pem("server-ca.crt"),
      ...(client === undefined ? {} : { cert: pem(`${client}.crt`), key: pem(`${client}.key`) }),
    },
  });

describe("internal API over mutual TLS", () => {
  test("web's_certificate_is_answered", async () => {
    const response = await health("web");
    expect(response.status).toBe(200);
  });

  test("no_certificate_or_another_ca's_is_refused_at_the_handshake", async () => {
    await expect(health()).rejects.toThrow();
    await expect(health("stranger")).rejects.toThrow();
  });

  test("plain_http_gets_no_answer", async () => {
    await expect(fetch(`http://localhost:${port}/health`)).rejects.toThrow();
  });
});

describe("the image's health probe", () => {
  test("answers_health_on_loopback_in_plain_http_and_nothing_else", async () => {
    let ready = true;
    const probe = serveProbe(async () => ready, 0);
    try {
      const at = `http://127.0.0.1:${probe.port}`;
      expect((await fetch(`${at}/health`)).status).toBe(200);
      ready = false;
      expect(await (await fetch(`${at}/health`)).json()).toEqual({ status: "unavailable" });
      expect((await fetch(`${at}/me/session`)).status).toBe(404);
      expect(probe.hostname).toBe("127.0.0.1");
    } finally {
      await probe.stop(true);
    }
  });
});
