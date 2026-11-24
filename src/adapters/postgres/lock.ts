// The per-key advisory lock (P1.17; plan §5.2; review 02 SERIOUS-5): work keyed on one DID, above all an OAuth token
// refresh, runs in at most one place at a time across every backend replica, so two replicas never spend the same
// refresh token. A transaction-level lock in the two-int4 key space (namespace, hashtext(key)), which never overlaps
// the migration runner's bigint lock, and which Postgres releases when the transaction ends, however it ends
// (https://www.postgresql.org/docs/18/functions-admin.html#FUNCTIONS-ADVISORY-LOCKS). On Bun.sql each lock is one
// `sql.begin` transaction on its own pool, so waiting on a lock never takes a connection from normal queries.
import type { Logger } from "../../shared/log/index.ts";
import { type Pool, sqlstateOf } from "./pool.ts";

/** What each lock serialises: the first int4 of the lock key. Closed; a new use adds a line, never reuses a number. */
export const LockNamespace = {
  oauth: 1,
} as const;
export type LockNamespace = (typeof LockNamespace)[keyof typeof LockNamespace];

export type LockErrorCode = "lock.timeout";

export class LockError extends Error {
  readonly code: LockErrorCode;

  constructor(code: LockErrorCode, options: { cause?: unknown } = {}) {
    super(code, options);
    this.name = "LockError";
    this.code = code;
  }
}

/** The lock holders' own pool (LOCK_POOL_MAX connections, counted beside PG_POOL_MAX), and where lock lines go. */
export type LockPool = { readonly pool: Pool; readonly log: Logger };

const LOCK_NOT_AVAILABLE = "55P03";
const QUERY_CANCELED = "57014";

type Outcome<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: unknown };

/**
 * Runs `fn` while holding the lock on (`namespace`, `key`) in every replica. Waits at most `waitMs` for the lock
 * (`lock.timeout`). `fn` past `holdMs` is logged, not aborted; the transaction's idle timeout (`holdMs` + 5 s) ends
 * it, which releases the lock. When the connection or the commit fails once `fn` has started, `fn`'s outcome still
 * stands and `lock.lost` is logged: the lock was released with the transaction either way.
 */
export async function withAdvisoryLock<T>(
  lock: LockPool,
  namespace: LockNamespace,
  key: string,
  fn: () => Promise<T>,
  options: { waitMs?: number; holdMs?: number } = {},
): Promise<T> {
  const waitMs = milliseconds(options.waitMs ?? 10_000);
  const holdMs = milliseconds(options.holdMs ?? 30_000);
  let running: Promise<Outcome<T>> | undefined;
  try {
    await lock.pool.begin(async (tx) => {
      // The role's own statement_timeout (2 s on `backend`) would cancel a longer wait first with 57014, so the wait
      // gets `waitMs` + 1 s, and the role's value comes back once the lock is held. set_config takes bound values.
      await tx`SELECT set_config('lock_timeout', ${`${waitMs}ms`}, true),
                      set_config('idle_in_transaction_session_timeout', ${`${holdMs + 5000}ms`}, true)`;
      const roleTimeout = await tx`SELECT current_setting('statement_timeout') AS value`;
      await tx`SELECT set_config('statement_timeout', ${`${waitMs + 1000}ms`}, true)`;
      try {
        await tx`SELECT pg_advisory_xact_lock(${namespace}::int4, hashtext(${key}))`;
      } catch (error) {
        const code = sqlstateOf(error);
        throw code === LOCK_NOT_AVAILABLE || code === QUERY_CANCELED
          ? new LockError("lock.timeout", { cause: error })
          : error;
      }
      await tx`SELECT set_config('statement_timeout', ${String(roleTimeout[0]?.value ?? "0")}, true)`;
      running = runWatched(lock.log, namespace, fn, holdMs);
      await running;
    });
  } catch (error) {
    // Before `fn` started, nothing ran: the caller gets the failure. After, Bun.sql rejects `begin` as soon as the
    // connection drops, even while `fn` still runs, so `fn` is waited for and its outcome stands. The lock went with
    // the connection, so the line says the lock was lost (never the key, usually a DID).
    if (running === undefined) throw error;
    lock.log.warn("lock.lost", { kind: namespaceName(namespace) });
  }
  return settle(await (running as Promise<Outcome<T>>));
}

/** The OAuth client's `requestLock` (@atproto/oauth-client 0.9.3 `RuntimeLock`, dist/runtime-implementation.d.ts). */
export function createRequestLock(lock: LockPool) {
  return <T>(name: string, fn: () => T | PromiseLike<T>): Promise<T> =>
    withAdvisoryLock(lock, LockNamespace.oauth, name, async () => fn());
}

/** Runs `fn` to its outcome, logging `lock.hold_exceeded` once if it is still running at `holdMs`. */
async function runWatched<T>(log: Logger, namespace: LockNamespace, fn: () => Promise<T>, holdMs: number) {
  const watchdog = setTimeout(
    () => log.warn("lock.hold_exceeded", { kind: namespaceName(namespace), ms: holdMs }),
    holdMs,
  );
  try {
    return { ok: true, value: await fn() } as const;
  } catch (error) {
    return { ok: false, error } as const;
  } finally {
    clearTimeout(watchdog);
  }
}

function settle<T>(outcome: Outcome<T>): T {
  if (outcome.ok) return outcome.value;
  throw outcome.error;
}

/** The namespace's name for a log line; the key is never logged, since it is usually a DID (SE-7). */
function namespaceName(namespace: LockNamespace): string {
  return Object.entries(LockNamespace).find(([, value]) => value === namespace)?.[0] ?? "unknown";
}

function milliseconds(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > 600_000) throw new RangeError("lock: ms out of range");
  return value;
}
