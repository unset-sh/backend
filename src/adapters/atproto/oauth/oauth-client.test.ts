// P2.04 (oauth-client.ts): the loopback client's metadata, and construction of the library client over our stores,
// lock, fetch and identity resolvers.
import { describe, expect, test } from "bun:test";
import { JoseKey } from "@atproto/jwk-jose";
import { createDidResolver, type IdentityNetwork } from "../../../domains/identity/index.ts";
import type { LogEvent, LogFields, Logger } from "../../../shared/log/index.ts";
import {
  clientMetadata,
  createOAuthClient,
  runtimeImplementation,
  type SavedSession,
  type SavedState,
} from "./oauth-client.ts";
import { SCOPE } from "./scopes.ts";

const REDIRECT = "http://127.0.0.1:8080/auth/callback";

const memory = <V>() => {
  const map = new Map<string, V>();
  return {
    map,
    get: async (key: string) => map.get(key),
    set: async (key: string, value: V) => void map.set(key, value),
    del: async (key: string) => void map.delete(key),
  };
};

const silentLog: Logger = {
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
  logError: () => undefined,
};

const bytes = (body: unknown) => new TextEncoder().encode(JSON.stringify(body));

/** Client options with no network: every fetch answers 503 and no handle resolves. */
function baseOptions() {
  const network: IdentityNetwork = {
    txt: async () => ({ kind: "no_record" }),
    get: async () => ({ kind: "unavailable" }),
  };
  return {
    redirectUri: REDIRECT,
    stateStore: memory<SavedState>(),
    sessionStore: memory<SavedSession>(),
    requestLock: async <T>(_name: string, fn: () => T | PromiseLike<T>) => fn(),
    fetch: async () => new Response(null, { status: 503 }),
    network,
    resolveDid: createDidResolver({ network, plcUrl: new URL("https://plc.directory"), cacheTtlS: 60, cacheMax: 10 }),
    log: silentLog,
  };
}

describe("client", () => {
  test("metadata_is_the_loopback_client", () => {
    const metadata = clientMetadata(REDIRECT);
    const clientId = new URL(metadata.client_id);
    expect(clientId.origin).toBe("http://localhost");
    expect(clientId.searchParams.get("scope")).toBe(SCOPE);
    expect(clientId.searchParams.getAll("redirect_uri")).toEqual([REDIRECT]);
    expect(metadata).toMatchObject({ scope: SCOPE, redirect_uris: [REDIRECT], token_endpoint_auth_method: "none" });
  });

  test("runtime_digests_and_keys", async () => {
    const runtime = runtimeImplementation(async (_name, fn) => fn());
    const digest = await runtime.digest(new TextEncoder().encode("abc"), { name: "sha256" });
    expect(Buffer.from(digest).toString("hex")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    expect((await runtime.getRandomValues(32)).length).toBe(32);
    const key = await runtime.createKey(["ES256"]);
    expect(key.algorithms).toContain("ES256");
    // A DPoP key survives the store's JWK round trip.
    const back = await JoseKey.fromJWK(JSON.parse(JSON.stringify(key.privateJwk)));
    expect(back.publicJwk).toEqual(key.publicJwk);
  });

  test("library_identity_cache_bypassed", async () => {
    // atproto.com/specs/oauth: identity data used for auth is cached under 10 minutes. The library would put a 1-hour
    // DID cache in front of ours (@atproto-labs/did-resolver did-cache-memory.js), so each lookup must reach our
    // resolver, which decides its own freshness.
    const did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    const document = {
      id: did,
      service: [{ id: "#atproto_pds", type: "AtprotoPersonalDataServer", serviceEndpoint: "https://pds.example" }],
    };
    const options = baseOptions();
    const real = createDidResolver({
      network: { ...options.network, get: async () => ({ kind: "response", status: 200, body: bytes(document) }) },
      plcUrl: new URL("https://plc.directory"),
      cacheTtlS: 60,
      cacheMax: 10,
    });
    let calls = 0;
    const resolveDid: typeof real = (...args) => {
      calls += 1;
      return real(...args);
    };
    const { client } = createOAuthClient({ ...options, resolveDid });
    await client.identityResolver.resolve(did).catch(() => undefined);
    await client.identityResolver.resolve(did).catch(() => undefined);
    expect(calls).toBe(2);
  });

  test("library_handle_cache_bypassed", async () => {
    // The library's handle cache (@atproto-labs/handle-resolver cached-handle-resolver.js) keeps a handle ten minutes;
    // each lookup must reach our resolver too.
    const options = baseOptions();
    let lookups = 0;
    const network: IdentityNetwork = {
      ...options.network,
      txt: async () => {
        lookups += 1;
        return { kind: "records", records: ["did=did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"] };
      },
    };
    const { client } = createOAuthClient({ ...options, network });
    await client.identityResolver.resolve("alice.example.com").catch(() => undefined);
    await client.identityResolver.resolve("alice.example.com").catch(() => undefined);
    expect(lookups).toBe(2);
  });

  test("client_logs_deleted_sessions_by_reason_only", () => {
    const logged: { event: LogEvent; fields: LogFields }[] = [];
    const record = (event: LogEvent, fields: LogFields = {}) => {
      logged.push({ event, fields });
    };
    const log: Logger = { info: record, warn: record, error: record, logError: () => undefined };
    const { client, onSessionDeleted } = createOAuthClient({ ...baseOptions(), log });
    expect(client.clientMetadata.client_id).toBe(clientMetadata(REDIRECT).client_id);
    onSessionDeleted("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", new Error("whatever"));
    expect(logged).toEqual([{ event: "oauth.session_deleted", fields: { reason: "other" } }]);
  });
});
