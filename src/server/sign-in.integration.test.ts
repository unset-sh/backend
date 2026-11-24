// The first slice's step 7 (sign-in and session) end to end through the internal API, against real Postgres: Better
// Auth on its pg pool as `backend_auth`, the sealed OAuth stores as `backend`, migration 0007's links between them.
// Only the authorization server is a stand-in: `grant` plays the OAuth client's part, replacing the token set in the
// real sealed store as the library does once it has checked the server's answer (sign-in.test.ts covers that part),
// through the real sign-in lock on the real advisory lock.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createGrant, type FinishResult, type Grant } from "../adapters/atproto/oauth/grant.ts";
import { createSignInLock } from "../adapters/atproto/oauth/sign-in-lock.ts";
import { createAuth, createAuthDatabase, createSessions, placeholderEmail } from "../adapters/auth/index.ts";
import { createRequestLock } from "../adapters/postgres/lock.ts";
import { createOAuthSessionStore, oauthSessionExists } from "../adapters/postgres/oauthStores.ts";
import type { Pool } from "../adapters/postgres/pool.ts";
import { startTestPostgres, type TestPostgres } from "../adapters/postgres/test-database.ts";
import { createSealer, parseKeyring } from "../adapters/seal/index.ts";
import { type Did, parseDid } from "../domains/identity/index.ts";
import { Secret } from "../shared/config/index.ts";
import { createLogger } from "../shared/log/index.ts";
import { createServer } from "./serve.ts";
import { testDeps, WEB_ORIGIN } from "./test-deps.ts";

const DID_A = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa" as Did;
const DID_B = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb" as Did;
const HANDLE_A = "alice.example.com";
const keyring = parseKeyring(JSON.stringify({ active: "k1", keys: { k1: Buffer.alloc(32, 7).toString("base64") } }));
if (keyring === undefined) throw new Error("test keyring did not parse");

let postgres: TestPostgres;
let database: string;
let backend: Pool;
const lines: string[] = [];
const log = createLogger({
  service: "backend",
  commit: "0".repeat(40),
  env: "test",
  write: (line) => lines.push(line),
});
let app: ReturnType<typeof createServer>;
let closeAuth: () => Promise<void>;
/** The nonce the signing-in browser holds, and another browser's. */
const NONCE = `${"A".repeat(42)}Q`;
const OTHER_NONCE = `${"B".repeat(42)}Q`;
/** Every token a test was handed, for the log check. */
const tokens: string[] = [];
const ended: Did[] = [];

/**
 * The authorization server's part. `finish` reads the DID from the query (`sub=`), as if the server had vouched for
 * it, then does what @atproto/oauth-client 0.9.3 `callback` does with the store: deletes the account's old token set,
 * then stores the new one. Everything else is the real grant; its revoke deletes the set, as the library's does.
 */
function standInGrant(store: ReturnType<typeof createOAuthSessionStore>, lockPool: Pool): Grant {
  const lock = createSignInLock({ store, lock: createRequestLock({ pool: lockPool, log }) });
  const client = {
    revoke: async (did: string) => {
      ended.push(did as Did);
      await lock.tokenSets.del(did);
    },
  };
  const real = createGrant({ client: client as never, dropTokenSet: (did) => store.del(did), scopes: lock, log });
  return {
    ...real,
    start: async (handle, nonce) =>
      handle === HANDLE_A && nonce === NONCE
        ? { ok: true, url: "https://pds.example/oauth/authorize?request_uri=x" }
        : { ok: false, reason: "handle_unverified" },
    async finish(query, nonce): Promise<FinishResult> {
      // The real grant compares the nonce with the one the sign-in started with (grant.test.ts).
      if (nonce !== NONCE) return { ok: false, reason: "state_mismatch" };
      const did = parseDid(query.get("sub") ?? "");
      if (did === null) return { ok: false, reason: "expired" };
      await lock.tokenSets.del(did);
      await lock.tokenSets.set(did, { authMethod: { method: "none" }, tokenSet: { sub: did } } as never);
      return { ok: true, did };
    },
  };
}

beforeAll(async () => {
  postgres = await startTestPostgres();
  database = await postgres.migratedDatabase();
  backend = await postgres.connectAs(database, "backend");
  const authDatabase = createAuthDatabase({
    connection: await postgres.connectionAs(database, "backend_auth"),
    max: 2,
    connectTimeoutS: 5,
    log,
  });
  closeAuth = authDatabase.close;
  const store = createOAuthSessionStore({ pool: backend, sealer: createSealer(keyring), log });
  const auth = createAuth({
    database: authDatabase,
    secret: new Secret("s".repeat(48)),
    webOrigin: WEB_ORIGIN,
    grant: standInGrant(store, await postgres.connectAs(database, "backend")),
    log,
  });
  app = createServer({ ...testDeps(), sessions: createSessions(auth) }, log);
});
afterAll(async () => {
  await closeAuth();
  await postgres.stop();
});

const call = (method: string, path: string, options: { body?: unknown; headers?: Record<string, string> } = {}) =>
  app.handle(
    new Request(`http://backend${path}`, {
      method,
      headers: { ...(options.body === undefined ? {} : { "content-type": "application/json" }), ...options.headers },
      ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
    }),
  );
const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

/** A complete sign-in for `did`: the session token web would keep. */
async function signIn(did: Did): Promise<string> {
  const response = await call("POST", "/auth/sign-in/atproto/callback", {
    body: { query: `code=c&state=s&sub=${did}`, nonce: NONCE },
  });
  expect(response.status).toBe(200);
  const { sessionToken } = (await response.json()) as { sessionToken: string };
  tokens.push(sessionToken);
  return sessionToken;
}

const whoami = async (token: string) => {
  const response = await call("GET", "/me/session", { headers: bearer(token) });
  return response.status === 200 ? ((await response.json()) as { did: string }).did : response.status;
};
const admin = (sql: string) => postgres.sql(database, sql);

describe("sign-in and session", () => {
  test("without a session, every session operation is refused", async () => {
    expect((await call("GET", "/me/session")).status).toBe(401);
    expect((await call("POST", "/auth/sign-out")).status).toBe(401);
    expect(await whoami("not-a-token")).toBe(401);
    expect(await whoami("forged.c2lnbmF0dXJl")).toBe(401);
  });

  test("start answers the authorization server's URL; an unverified handle is refused", async () => {
    const ok = await call("POST", "/auth/sign-in/atproto", { body: { handle: HANDLE_A, nonce: NONCE } });
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({ url: "https://pds.example/oauth/authorize?request_uri=x" });
    const refused = await call("POST", "/auth/sign-in/atproto", {
      body: { handle: "mallory.example.com", nonce: NONCE },
    });
    expect(refused.status).toBe(400);
    expect(refused.headers.get("content-type")).toBe("application/problem+json");
    expect(await refused.json()).toEqual({
      type: "about:blank",
      title: "Bad Request",
      status: 400,
      code: "handle_unverified",
    });
    // A body that breaks the schema is a problem too, and does not echo the input.
    const invalid = await call("POST", "/auth/sign-in/atproto", { body: { handle: "", nonce: NONCE } });
    expect(invalid.status).toBe(422);
    expect(invalid.headers.get("content-type")).toBe("application/problem+json");
    expect(await invalid.json()).toEqual({
      type: "about:blank",
      title: "Unprocessable Content",
      status: 422,
      code: "invalid_request",
    });
    // A field the contract does not name is dropped before the handler runs (Elysia 1.4.32 normalises bodies).
    const extra = await call("POST", "/auth/sign-in/atproto", {
      body: { handle: "mallory.example.com", nonce: NONCE, did: DID_B },
    });
    expect(((await extra.json()) as { code: string }).code).toBe("handle_unverified");
  });

  test("a failed callback makes no session", async () => {
    const response = await call("POST", "/auth/sign-in/atproto/callback", {
      body: { query: "code=c&state=unknown", nonce: NONCE },
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ type: "about:blank", title: "Bad Request", status: 400, code: "expired" });
    expect(await admin("SELECT count(*) FROM auth.session")).toBe("0");
  });

  test("a callback with another browser's nonce makes no session", async () => {
    const response = await call("POST", "/auth/sign-in/atproto/callback", {
      body: { query: `code=c&state=s&sub=${DID_A}`, nonce: OTHER_NONCE },
    });
    expect(response.status).toBe(400);
    expect(((await response.json()) as { code: string }).code).toBe("state_mismatch");
    expect(await admin("SELECT count(*) FROM auth.session")).toBe("0");
  });

  test("a token for one DID never reads another DID's session", async () => {
    const a = await signIn(DID_A);
    const b = await signIn(DID_B);
    expect(await whoami(a)).toBe(DID_A);
    expect(await whoami(b)).toBe(DID_B);
    // The operations take no DID from the caller: a body or query naming another DID changes nothing.
    const response = await call("GET", `/me/session?did=${DID_B}`, { headers: bearer(a) });
    expect(await response.json()).toEqual({ did: DID_A });
  });

  test("a bearer call needs no Origin; a cookie needs web's", async () => {
    const token = await signIn(DID_A);
    expect(await whoami(token)).toBe(DID_A);
    const withCookie = (origin?: string) =>
      call("GET", "/me/session", {
        headers: { ...bearer(token), cookie: "x=1", ...(origin === undefined ? {} : { origin }) },
      });
    expect((await withCookie()).status).toBe(403);
    expect((await withCookie("https://evil.example")).status).toBe(403);
    expect((await withCookie(WEB_ORIGIN)).status).toBe(200);
  });

  test("the account is matched on the DID alone, with a placeholder email and no handle", async () => {
    await signIn(DID_A);
    await signIn(DID_A);
    expect(await admin(`SELECT count(*) FROM auth.account WHERE "accountId" = '${DID_A}'`)).toBe("1");
    const [email, name] = (
      await admin(
        `SELECT u.email, u.name FROM auth."user" u JOIN auth.account a ON a."userId" = u.id WHERE a."accountId" = '${DID_A}'`,
      )
    ).split("|");
    expect(email).toBe(placeholderEmail(DID_A));
    expect(email).not.toContain("aaaa");
    expect(name).toBe("");
    expect(await admin(`SELECT count(*) FROM auth.session WHERE "ipAddress" <> ''`)).toBe("0");
  });

  test("the member is a UUID inside backend, and no answer carries it", async () => {
    const token = await signIn(DID_A);
    const id = await admin(
      `SELECT u.id FROM auth."user" u JOIN auth.account a ON a."userId" = u.id WHERE a."accountId" = '${DID_A}'`,
    );
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    const response = await call("GET", "/me/session", { headers: bearer(token) });
    expect(await response.text()).not.toContain(id);
  });

  test("a session ends with its token set", async () => {
    const token = await signIn(DID_B);
    expect(await whoami(token)).toBe(DID_B);
    // A failed refresh or a revoke elsewhere deletes the token set; every session on it goes with it.
    await admin(`DELETE FROM app.oauth_session WHERE did = '${DID_B}'`);
    expect(await whoami(token)).toBe(401);
    expect(await admin(`SELECT count(*) FROM auth.session WHERE did = '${DID_B}'`)).toBe("0");
  });

  test("a sign-in on another browser leaves the account's other sessions", async () => {
    const first = await signIn(DID_A);
    const second = await signIn(DID_A);
    expect(await whoami(first)).toBe(DID_A);
    expect(await whoami(second)).toBe(DID_A);
  });

  test("two sign-ins at once both keep their sessions", async () => {
    const [x, y] = await Promise.all([signIn(DID_B), signIn(DID_B)]);
    expect(await whoami(x)).toBe(DID_B);
    expect(await whoami(y)).toBe(DID_B);
  });

  test("sign-out ends that browser's session only; the last one ends the grant", async () => {
    const token = await signIn(DID_A);
    const other = await signIn(DID_A);
    const live = await admin(`SELECT count(*) FROM auth.session WHERE did = '${DID_A}'`);
    ended.length = 0;
    const response = await call("POST", "/auth/sign-out", { headers: bearer(token) });
    expect(response.status).toBe(204);
    expect(await whoami(token)).toBe(401);
    expect((await call("POST", "/auth/sign-out", { headers: bearer(token) })).status).toBe(401);
    // The account's other browsers keep their sessions and the grant they ride on.
    expect(await whoami(other)).toBe(DID_A);
    expect(ended).toEqual([]);
    expect(await oauthSessionExists(backend, DID_A)).toBe(true);
    expect(await admin(`SELECT count(*) FROM auth.session WHERE did = '${DID_A}'`)).toBe(String(Number(live) - 1));
    // Signing out every remaining session: the last one ends the grant.
    const tokensLeft = (await admin(`SELECT token FROM auth.session WHERE did = '${DID_A}'`)).split("\n");
    for (const left of tokensLeft) {
      expect((await call("POST", "/auth/sign-out", { headers: bearer(left) })).status).toBe(204);
    }
    expect(ended).toEqual([DID_A]);
    expect(await oauthSessionExists(backend, DID_A)).toBe(false);
  });

  test("logs hold no DID, handle, email or token", () => {
    const text = lines.join("\n");
    expect(lines.length).toBeGreaterThan(0);
    for (const secret of [DID_A, DID_B, "aaaaaaaaaaaaaaaaaaaaaaaa", HANDLE_A, "mallory", "@did.invalid", ...tokens]) {
      expect(text).not.toContain(secret);
    }
  });
});
