// The Bun dial (org-0015): the guard connects to the vetted address itself and keeps the name for Host, SNI and the
// certificate check (Bun 1.4.4 docs/runtime/networking/fetch.mdx, "Connecting to a specific address"). These pin the
// parts the old app's undici tests could not see: the name, not the dialled IP, is what the certificate must cover;
// every vetted address is tried in order; the environment's proxy is never used.

import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { createServer } from "node:net";
import type { TLSSocket } from "node:tls";
import { atproto, plc } from "./policies.ts";
import {
  type FakeServer,
  fakeResolver,
  httpServer,
  httpsServer,
  loopbackDial,
  testCertificate,
} from "./remote.fake.ts";
import { createNetGuardWith, type NetGuardHooks } from "./request.ts";
import { NetGuardError } from "./resolve.ts";

const tls = testCertificate();
const COMMIT = "c".repeat(40);
const PUBLIC = "93.184.215.14";
const PUBLIC_2 = "93.184.215.15";

const sni: (string | false | null)[] = [];
let server: FakeServer;
let proxy: FakeServer;
beforeAll(async () => {
  server = await httpsServer(tls, (req, res) => {
    sni.push((req.socket as TLSSocket).servername);
    res.end("ok");
  });
  proxy = await httpServer((_req, res) => res.end("proxied"));
});
afterAll(async () => {
  await server.close();
  await proxy.close();
});

const guardWith = (hooks: NetGuardHooks) =>
  createNetGuardWith({ internalHosts: [], allowLoopback: false, commit: COMMIT, ca: tls.cert }, hooks);

async function codeOf(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof NetGuardError) return error.code;
    throw error;
  }
  return "resolved";
}

describe("dial", () => {
  test("certificate_checked_against_the_name_not_the_address", async () => {
    // The certificate names plc.directory, never 127.0.0.1 or the vetted address: success means the name was checked.
    const ok = guardWith({
      lookup: fakeResolver({ "plc.directory": [PUBLIC] }).lookup,
      ...loopbackDial(server.port).hooks,
    });
    expect((await ok.request(plc, { url: "https://plc.directory/" })).status).toBe(200);
    expect(sni.at(-1)).toBe("plc.directory");
    // A trusted CA, the same server, a name the certificate does not cover: refused.
    const other = guardWith({
      lookup: fakeResolver({ "other.example": [PUBLIC] }).lookup,
      ...loopbackDial(server.port).hooks,
    });
    expect(await codeOf(other.request(atproto, { url: "https://other.example/" }))).toBe("egress.tls");
  });

  test("each_vetted_address_tried_in_order", async () => {
    const dialled: string[] = [];
    // The first address lands on a loopback address nothing listens on, so it cannot connect.
    const hooks: NetGuardHooks = {
      lookup: fakeResolver({ "plc.directory": [PUBLIC, PUBLIC_2] }).lookup,
      port: server.port,
      dial: (address) => {
        dialled.push(address);
        return address === PUBLIC ? "127.0.0.3" : "127.0.0.1";
      },
    };
    expect((await guardWith(hooks).request(plc, { url: "https://plc.directory/" })).status).toBe(200);
    expect(dialled).toEqual([PUBLIC, PUBLIC_2]);
  });

  test("silent_address_gives_way_to_the_next", async () => {
    // A listener that accepts and never answers: without a per-address limit the deadline would end the request.
    const silent = createServer(() => undefined);
    await new Promise<void>((resolve) => silent.listen(server.port, "127.0.0.4", resolve));
    try {
      const dialled: string[] = [];
      const hooks: NetGuardHooks = {
        lookup: fakeResolver({ "plc.directory": [PUBLIC, PUBLIC_2] }).lookup,
        port: server.port,
        dial: (address) => {
          dialled.push(address);
          return address === PUBLIC ? "127.0.0.4" : "127.0.0.1";
        },
      };
      const response = await guardWith(hooks).request(plc, { url: "https://plc.directory/", timeoutMs: 15_000 });
      expect(response.status).toBe(200);
      expect(dialled).toEqual([PUBLIC, PUBLIC_2]);
    } finally {
      silent.close();
    }
  }, 12_000);

  test("tls_failure_does_not_try_the_next_address", async () => {
    const dialled: string[] = [];
    const hooks: NetGuardHooks = {
      lookup: fakeResolver({ "other.example": [PUBLIC, PUBLIC_2] }).lookup,
      port: server.port,
      dial: (address) => {
        dialled.push(address);
        return "127.0.0.1";
      },
    };
    expect(await codeOf(guardWith(hooks).request(atproto, { url: "https://other.example/" }))).toBe("egress.tls");
    expect(dialled).toEqual([PUBLIC]);
  });

  describe("environment proxy", () => {
    const KEYS = ["HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"] as const;
    const saved = Object.fromEntries(KEYS.map((key) => [key, process.env[key]]));
    afterEach(() => {
      for (const [key, value] of Object.entries(saved)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    });

    test("proxy_variables_ignored", async () => {
      process.env.HTTPS_PROXY = `http://127.0.0.1:${proxy.port}`;
      process.env.https_proxy = `http://127.0.0.1:${proxy.port}`;
      // A NO_PROXY that names loopback (as on a developer machine behind a proxy) would hide the proxy from Bun.
      process.env.NO_PROXY = "";
      process.env.no_proxy = "";
      const guard = guardWith({
        lookup: fakeResolver({ "plc.directory": [PUBLIC] }).lookup,
        ...loopbackDial(server.port).hooks,
      });
      const response = await guard.request(plc, { url: "https://plc.directory/" });
      expect(new TextDecoder().decode(response.body)).toBe("ok");
      expect(proxy.requests).toHaveLength(0);
    });
  });
});
