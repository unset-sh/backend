// The OAuth client's state and session stores (P2.04; plan section 5.3 "OAuth client"), in the get/set/del shape
// @atproto/oauth-client 0.9.3 takes (`SimpleStore`, @atproto-labs/simple-store). Each value is sealed with the
// context of its own row (sealed-columns.json), so a dump yields nothing usable and a value moved to another row does
// not open. A row that does not open is deleted and reads as missing: an expired login for state, a new sign-in for a
// token set. Database errors are thrown; the library surfaces them as a failed sign-in.
import { AppError } from "../../shared/errors/index.ts";
import type { Logger } from "../../shared/log/index.ts";
import { SealError, type Sealer } from "../seal/index.ts";
import type { Pool } from "./pool.ts";
import { sealedContext } from "./sealedColumns.ts";

/**
 * `get`'s second argument is `GetOptions` from @atproto-labs/simple-store 0.5.1 (`dist/simple-store.d.ts`):
 * `{ signal?: AbortSignal }`. The library passes `set` and `del` no options; `del`'s optional signal is ours, for a
 * caller outside the library with a deadline (sign-out's fallback delete, P2.08). The signal is the caller's deadline.
 */
export type SealedStore<V> = {
  get(key: string, options?: { readonly signal?: AbortSignal }): Promise<V | undefined>;
  set(key: string, value: V): Promise<void>;
  del(key: string, options?: { readonly signal?: AbortSignal }): Promise<void>;
};
type Options = { readonly pool: Pool; readonly sealer: Sealer; readonly log: Logger };

/**
 * The query's result, run only while `signal` (the caller's deadline) has not fired. A query is lazy until awaited
 * (Bun 1.4.4 docs/runtime/sql.mdx, "Execute and Cancelling Queries"), so one past its deadline never takes a
 * connection; one that is running when it fires is cancelled on the server. Either way the caller gets http.deadline.
 */
async function untilAbort<T>(query: PromiseLike<T> & { cancel(): unknown }, signal?: AbortSignal): Promise<T> {
  if (signal === undefined) return await query;
  if (signal.aborted) {
    query.cancel();
    throw new AppError("http.deadline");
  }
  const onAbort = () => query.cancel();
  signal.addEventListener("abort", onAbort, { once: true });
  try {
    return await query;
  } catch (error) {
    throw signal.aborted ? new AppError("http.deadline", { cause: error }) : error;
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}

/** How long an authorization may take, from the redirect to the callback. */
const STATE_TTL_S = 600;

/** The value, or undefined when its seal does not open (a wrong row, an unknown key id); any other error is thrown. */
function opened<V>(log: Logger, kind: "state" | "session", open: () => unknown): V | undefined {
  try {
    return open() as V;
  } catch (error) {
    if (!(error instanceof SealError)) throw error;
    log.warn("oauth.unseal_failed", { kind });
    return undefined;
  }
}

/** The state store, plus the sweep the hourly job runs: an abandoned login never reaches `del`. */
export type OAuthStateStore<V> = SealedStore<V> & { sweep(): Promise<number> };

export function createOAuthStateStore<V>(options: Options): OAuthStateStore<V> {
  const { pool } = options;
  const context = (key: string) => sealedContext("app.oauth_state.sealed", key);
  const del = async (key: string, read?: { readonly signal?: AbortSignal }) => {
    await untilAbort(pool`DELETE FROM app.oauth_state WHERE key = ${key}`, read?.signal);
  };
  return {
    async get(key, read) {
      const rows: { sealed: string }[] = await untilAbort(
        pool`SELECT sealed FROM app.oauth_state WHERE key = ${key} AND expires_at > now()`,
        read?.signal,
      );
      const sealed = rows[0]?.sealed;
      if (sealed === undefined) return undefined;
      const value = opened<V>(options.log, "state", () => options.sealer.unsealJson(sealed, context(key)));
      // Only the value that did not open: a newer one written meanwhile stays.
      if (value === undefined) await pool`DELETE FROM app.oauth_state WHERE key = ${key} AND sealed = ${sealed}`;
      return value;
    },
    async set(key, value) {
      const sealed = options.sealer.sealJson(value, context(key));
      await pool`
        INSERT INTO app.oauth_state (key, sealed, expires_at)
        VALUES (${key}, ${sealed}, now() + make_interval(secs => ${STATE_TTL_S}::int))
        ON CONFLICT (key) DO UPDATE SET sealed = EXCLUDED.sealed, expires_at = EXCLUDED.expires_at`;
    },
    del,
    /**
     * Deletes every expired state and returns the count. It scans the table (no expiry index, P2.03i ruling): the
     * table holds at most an hour of abandoned logins, and no login write pays for the scan.
     */
    async sweep() {
      const deleted = await pool`DELETE FROM app.oauth_state WHERE expires_at <= now()`;
      return deleted.count;
    },
  };
}

/** What the session store reads of a token set: the client key id the library bound it to (`authMethod.kid`). */
type BoundToKey = { readonly authMethod: { readonly method: string; readonly kid?: string } };

export function createOAuthSessionStore<V extends BoundToKey>(options: Options): SealedStore<V> {
  const { pool } = options;
  const context = (did: string) => sealedContext("app.oauth_session.sealed", did);
  const del = async (did: string, read?: { readonly signal?: AbortSignal }) => {
    await untilAbort(pool`DELETE FROM app.oauth_session WHERE did = ${did}`, read?.signal);
  };
  return {
    async get(did, read) {
      const rows: { sealed: string }[] = await untilAbort(
        pool`SELECT sealed FROM app.oauth_session WHERE did = ${did}`,
        read?.signal,
      );
      const sealed = rows[0]?.sealed;
      if (sealed === undefined) return undefined;
      const value = opened<V>(options.log, "session", () => options.sealer.unsealJson(sealed, context(did)));
      // Only the value that did not open: a fresh token set another replica stored meanwhile stays.
      if (value === undefined) await pool`DELETE FROM app.oauth_session WHERE did = ${did} AND sealed = ${sealed}`;
      return value;
    },
    async set(did, value) {
      const sealed = options.sealer.sealJson(value, context(did));
      await pool`
        INSERT INTO app.oauth_session (did, sealed, client_kid, updated_at)
        VALUES (${did}, ${sealed}, ${value.authMethod.kid ?? ""}, now())
        ON CONFLICT (did) DO UPDATE SET sealed = EXCLUDED.sealed, client_kid = EXCLUDED.client_kid,
          updated_at = EXCLUDED.updated_at`;
    },
    del,
  };
}

/** Whether a token set is stored for `did`. It reads no sealed value, so it takes no sealer. */
export async function oauthSessionExists(pool: Pool, did: string): Promise<boolean> {
  const rows = await pool`SELECT 1 FROM app.oauth_session WHERE did = ${did}`;
  return rows.length === 1;
}
