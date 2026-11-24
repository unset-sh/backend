// P2.04 (oauthStores.ts, migration 0006): the OAuth client's state and session stores against real Postgres, connected
// as `backend`. What they store is sealed, bound to its row, and read back only before it expires; a row that does not
// open is deleted and reads as missing. Adapted from Undefined6799/unset@60228f5
// infrastructure/postgres/oauth-stores.integration.test.ts (role `web` there).
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import type { LogEvent, LogFields, Logger } from "../../shared/log/index.ts";
import { createSealer, parseKeyring } from "../seal/index.ts";
import { createOAuthSessionStore, createOAuthStateStore, oauthSessionExists } from "./oauthStores.ts";
import type { Pool } from "./pool.ts";
import { startTestPostgres, type TestPostgres } from "./test-database.ts";

let postgres: TestPostgres;
let database: string;
let backend: Pool;

beforeAll(async () => {
  postgres = await startTestPostgres();
  database = await postgres.migratedDatabase();
  backend = await postgres.connectAs(database, "backend");
});
afterAll(() => postgres.stop());

const keyring = parseKeyring(JSON.stringify({ active: "k1", keys: { k1: Buffer.alloc(32, 7).toString("base64") } }));
if (keyring === undefined) throw new Error("test keyring did not parse");
const sealer = createSealer(keyring);

const DID_A = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
const DID_B = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";
type Saved = { authMethod: { method: "private_key_jwt"; kid: string } | { method: "none" }; tokenSet: { a: string } };

function setup(pool: Pool = backend) {
  const logged: { event: LogEvent; fields: LogFields }[] = [];
  const record = (event: LogEvent, fields: LogFields = {}) => {
    logged.push({ event, fields });
  };
  const log: Logger = { info: record, warn: record, error: record, logError: () => undefined };
  return {
    state: createOAuthStateStore<{ verifier: string }>({ pool, sealer, log }),
    session: createOAuthSessionStore<Saved>({ pool, sealer, log }),
    logged,
  };
}

/** Runs `text` as the superuser, as an operator or an attacker with a dump would; rows as `a|b` lines. */
const admin = (text: string) => postgres.sql(database, text);

describe("oauth stores", () => {
  test("stores_sealed_at_rest", async () => {
    const { state, session } = setup();
    const verifier = "pkce-verifier-that-must-never-be-stored-in-clear";
    await state.set("state-1", { verifier });
    await session.set(DID_A, { authMethod: { method: "private_key_jwt", kid: "A" }, tokenSet: { a: verifier } });
    const stateRow = await admin("SELECT sealed FROM app.oauth_state WHERE key = 'state-1'");
    const sessionRow = await admin(`SELECT sealed FROM app.oauth_session WHERE did = '${DID_A}'`);
    expect(stateRow).toStartWith("s1.k1.");
    expect(sessionRow).toStartWith("s1.k1.");
    expect(stateRow).not.toContain(verifier);
    expect(sessionRow).not.toContain(verifier);
    expect(await state.get("state-1")).toEqual({ verifier });
    expect((await session.get(DID_A))?.tokenSet).toEqual({ a: verifier });
  });

  test("stores_aad_binding", async () => {
    const { session, logged } = setup();
    await session.set(DID_A, { authMethod: { method: "private_key_jwt", kid: "A" }, tokenSet: { a: "a" } });
    await session.set(DID_B, { authMethod: { method: "private_key_jwt", kid: "A" }, tokenSet: { a: "b" } });
    // A dump edited to give B's token set to A, and A's to B: each value is bound to its own DID, so neither opens.
    await admin(
      "UPDATE app.oauth_session s SET sealed = o.sealed FROM app.oauth_session o " +
        `WHERE (s.did = '${DID_A}' AND o.did = '${DID_B}') OR (s.did = '${DID_B}' AND o.did = '${DID_A}')`,
    );
    expect(await session.get(DID_A)).toBeUndefined();
    expect(await session.get(DID_B)).toBeUndefined();
    expect(await admin(`SELECT did FROM app.oauth_session WHERE did IN ('${DID_A}', '${DID_B}')`)).toBe("");
    expect(logged.filter((line) => line.event === "oauth.unseal_failed")).toEqual([
      { event: "oauth.unseal_failed", fields: { kind: "session" } },
      { event: "oauth.unseal_failed", fields: { kind: "session" } },
    ]);
  });

  test("stores_expiry", async () => {
    const { state } = setup();
    await state.set("state-old", { verifier: "v" });
    await admin("UPDATE app.oauth_state SET expires_at = now() - interval '1 second' WHERE key = 'state-old'");
    expect(await state.get("state-old")).toBeUndefined();
    await state.set("state-new", { verifier: "v" });
    const left = Number(
      await admin("SELECT extract(epoch FROM expires_at - now())::int FROM app.oauth_state WHERE key = 'state-new'"),
    );
    expect(left).toBeGreaterThan(590);
    expect(left).toBeLessThanOrEqual(600);
    // An abandoned login never reaches del; the hourly sweep removes it and keeps the live one.
    expect(await state.sweep()).toBe(1);
    expect(await admin("SELECT key FROM app.oauth_state WHERE key IN ('state-old', 'state-new')")).toBe("state-new");
  });

  test("stores_unseal_cleanup_spares_a_newer_value", async () => {
    // Between this replica's read of a value that does not open and its cleanup, another replica
    // stores a fresh token set for the same DID. The cleanup deletes only the ciphertext it read.
    const { session } = setup();
    await session.set(DID_B, { authMethod: { method: "private_key_jwt", kid: "A" }, tokenSet: { a: "b" } });
    await session.set(DID_A, { authMethod: { method: "private_key_jwt", kid: "A" }, tokenSet: { a: "a" } });
    await admin(
      `UPDATE app.oauth_session SET sealed = (SELECT sealed FROM app.oauth_session WHERE did = '${DID_B}') ` +
        `WHERE did = '${DID_A}'`,
    );
    const fresh: Saved = { authMethod: { method: "private_key_jwt", kid: "B" }, tokenSet: { a: "fresh" } };
    // The same pool, except that just before its first DELETE runs, another replica stores a fresh token set.
    let raced = false;
    const racing = ((strings: TemplateStringsArray, ...values: unknown[]) => {
      if (raced || !strings[0]?.trimStart().startsWith("DELETE")) return backend(strings, ...values);
      raced = true;
      return session.set(DID_A, fresh).then(() => backend(strings, ...values));
    }) as unknown as Pool;
    const slow = setup(racing).session;
    expect(await slow.get(DID_A)).toBeUndefined();
    expect(raced).toBe(true);
    expect((await session.get(DID_A))?.tokenSet).toEqual({ a: "fresh" });
  });

  test("stores_client_kid_recorded", async () => {
    const { session } = setup();
    await session.set(DID_A, { authMethod: { method: "private_key_jwt", kid: "A" }, tokenSet: { a: "1" } });
    await session.set(DID_A, { authMethod: { method: "private_key_jwt", kid: "B" }, tokenSet: { a: "2" } });
    expect(await admin(`SELECT client_kid FROM app.oauth_session WHERE did = '${DID_A}'`)).toBe("B");
    expect((await session.get(DID_A))?.tokenSet).toEqual({ a: "2" });
  });

  test("stores_del", async () => {
    const { state, session } = setup();
    await state.set("state-del", { verifier: "v" });
    await session.set(DID_B, { authMethod: { method: "private_key_jwt", kid: "A" }, tokenSet: { a: "x" } });
    await state.del("state-del");
    await session.del(DID_B);
    expect(await state.get("state-del")).toBeUndefined();
    expect(await session.get(DID_B)).toBeUndefined();
  });

  test("session_exists_follows_the_row", async () => {
    const { session } = setup();
    const did = "did:plc:cccccccccccccccccccccccc";
    expect(await oauthSessionExists(backend, did)).toBe(false);
    await session.set(did, { authMethod: { method: "private_key_jwt", kid: "A" }, tokenSet: { a: "x" } });
    expect(await oauthSessionExists(backend, did)).toBe(true);
    expect(await oauthSessionExists(backend, DID_A.replace(/a$/, "z"))).toBe(false);
    await session.del(did);
    expect(await oauthSessionExists(backend, did)).toBe(false);
  });
});
