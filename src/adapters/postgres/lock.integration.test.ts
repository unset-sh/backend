// P1.17 (lock.ts): the advisory lock against real Postgres, connected as `backend`, the role that refreshes OAuth
// tokens, so its sessions run with that role's timeouts (migration 0003: statement_timeout 2 s,
// idle_in_transaction_session_timeout 10 s). Two pools stand in for two backend replicas. Adapted from
// Undefined6799/unset@60228f5 infrastructure/postgres/lock.integration.test.ts; the old pool_exhausted
// case is gone with node-postgres (Bun.sql has no acquire timeout).
import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import type { LogEvent, LogFields, Logger } from "../../shared/log/index.ts";
import { createRequestLock, LockError, LockNamespace, type LockPool, withAdvisoryLock } from "./lock.ts";
import { MIGRATE_LOCK_ID } from "./migrate.ts";
import type { Pool } from "./pool.ts";
import { startTestPostgres, type TestPostgres } from "./test-database.ts";

let postgres: TestPostgres;
let database: string;
let side: Pool;

beforeAll(async () => {
  postgres = await startTestPostgres();
  database = await postgres.migratedDatabase();
  side = await postgres.connectAs(database, "backend", 2);
});
afterAll(() => postgres.stop());
// Each test's replicas close with it: `backend` may hold only 40 connections at once.
const open: Pool[] = [];
afterEach(async () => {
  for (const pool of open.splice(0)) await pool.close();
});

/** One replica's lock pool, whose log lines land in `logged`. */
async function replica(max = 4) {
  const logged: { event: LogEvent; fields: LogFields }[] = [];
  const record = (event: LogEvent, fields: LogFields = {}) => {
    logged.push({ event, fields });
  };
  const log: Logger = { info: record, warn: record, error: record, logError: () => undefined };
  const pool = await postgres.connectAs(database, "backend", max);
  open.push(pool);
  const lock: LockPool = { pool, log };
  return { lock, logged };
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const DID = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
const codeOf = (promise: Promise<unknown>) =>
  promise.then(
    () => "resolved",
    (error: unknown) => (error instanceof LockError ? error.code : String(error)),
  );

/**
 * Holds `key` on `lock` for `ms`, recording when `fn` started and ended. `started` resolves once `fn` holds the lock,
 * so a test waits for that rather than for a fixed delay. A `gate` keeps `fn` from starting its `ms` until it opens.
 */
function hold(lock: LockPool, key: string, ms: number, options: { waitMs?: number; gate?: Promise<void> } = {}) {
  const { gate, ...lockOptions } = options;
  const times = { start: 0, end: 0 };
  let markStarted = (): void => undefined;
  const started = new Promise<void>((resolve) => {
    markStarted = resolve;
  });
  const done = withAdvisoryLock(
    lock,
    LockNamespace.oauth,
    key,
    async () => {
      times.start = Date.now();
      markStarted();
      await gate;
      await sleep(ms);
      times.end = Date.now();
      return "held";
    },
    lockOptions,
  );
  return { times, started, done };
}

describe("advisory lock", () => {
  test("serialises_same_key", async () => {
    const a = await replica();
    const b = await replica();
    const first = hold(a.lock, DID, 300);
    await first.started;
    const second = hold(b.lock, DID, 10);
    expect(await Promise.all([first.done, second.done])).toEqual(["held", "held"]);
    expect(second.times.start).toBeGreaterThanOrEqual(first.times.end);
  });

  test("parallel_different_keys", async () => {
    const a = await replica();
    const b = await replica();
    let open = (): void => undefined;
    const gate = new Promise<void>((resolve) => {
      open = resolve;
    });
    const x = hold(a.lock, "did:plc:xxxxxxxxxxxxxxxxxxxxxxxx", 300, { gate });
    const y = hold(b.lock, "did:plc:yyyyyyyyyyyyyyyyyyyyyyyy", 300, { gate });
    await Promise.all([x.started, y.started]);
    open();
    await Promise.all([x.done, y.done]);
    expect(y.times.start).toBeLessThan(x.times.end);
    expect(x.times.start).toBeLessThan(y.times.end);
  });

  test("wait_timeout", async () => {
    const a = await replica();
    const b = await replica();
    const first = hold(a.lock, DID, 2000);
    await first.started;
    const started = Date.now();
    expect(await codeOf(hold(b.lock, DID, 10, { waitMs: 200 }).done)).toBe("lock.timeout");
    const waited = Date.now() - started;
    expect(waited).toBeGreaterThanOrEqual(150);
    expect(waited).toBeLessThan(1000);
    expect(await first.done).toBe("held");
    // The timed-out transaction rolled back cleanly: the same pool takes the lock at once.
    expect(await hold(b.lock, DID, 10, { waitMs: 200 }).done).toBe("held");
  });

  test("wait_longer_than_role_timeout", async () => {
    const a = await replica();
    const b = await replica();
    const first = hold(a.lock, DID, 6000);
    await first.started;
    const started = Date.now();
    expect(await codeOf(hold(b.lock, DID, 10, { waitMs: 5000 }).done)).toBe("lock.timeout");
    const waited = Date.now() - started;
    expect(waited).toBeGreaterThanOrEqual(4500);
    expect(waited).toBeLessThan(5900);
    expect(await first.done).toBe("held");
  }, 20_000);

  test("role_timeout_restored_while_held", async () => {
    const { lock } = await replica();
    const inside = await withAdvisoryLock(lock, LockNamespace.oauth, DID, async () => "ok");
    expect(inside).toBe("ok");
    // A long query inside the lock still meets the role's 2 s statement_timeout, not the longer wait's.
    const slow = withAdvisoryLock(lock, LockNamespace.oauth, DID, () => lock.pool`SELECT pg_sleep(3)`.then(() => 1));
    expect(await codeOf(slow)).toContain("statement timeout");
  });

  test("releases_on_throw", async () => {
    const a = await replica();
    const b = await replica();
    const failing = withAdvisoryLock(a.lock, LockNamespace.oauth, DID, async () => {
      throw new Error("refresh failed");
    });
    await expect(failing).rejects.toThrow("refresh failed");
    const started = Date.now();
    expect(await hold(b.lock, DID, 10, { waitMs: 200 }).done).toBe("held");
    expect(Date.now() - started).toBeLessThan(200);
  });

  test("releases_on_success", async () => {
    const { lock } = await replica();
    expect(await withAdvisoryLock(lock, LockNamespace.oauth, "a lock name", async () => 7)).toBe(7);
    const rows = await side`
      SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND classid = ${LockNamespace.oauth} AND objsubid = 2`;
    expect(rows.length).toBe(0);
  });

  test("namespace_isolated", async () => {
    const { lock } = await replica();
    const holder = await postgres.connectAs(database, "backend", 1);
    open.push(holder);
    await holder.begin(async (tx) => {
      // The migration runner's bigint lock, and the bigint whose halves equal (oauth, hashtext(key)).
      await tx`SELECT pg_advisory_xact_lock(${MIGRATE_LOCK_ID}::bigint),
                      pg_advisory_xact_lock((${LockNamespace.oauth}::bigint << 32) | (hashtext(${DID})::bigint & 4294967295))`;
      expect(await withAdvisoryLock(lock, LockNamespace.oauth, DID, async () => "free", { waitMs: 500 })).toBe("free");
    });
  });

  test("lock_lost_keeps_the_outcome", async () => {
    const { lock, logged } = await replica();
    const result = await withAdvisoryLock(lock, LockNamespace.oauth, DID, async () => {
      // Postgres ends the transaction's connection under it; the lock goes with it.
      await side`SELECT pg_terminate_backend(pid) FROM pg_locks
                  WHERE locktype = 'advisory' AND classid = ${LockNamespace.oauth} AND objsubid = 2
                    AND pid <> pg_backend_pid()`;
      await sleep(200);
      return 42;
    });
    expect(result).toBe(42);
    expect(logged).toEqual([{ event: "lock.lost", fields: { kind: "oauth" } }]);
  });

  test("hold_exceeded_logged", async () => {
    const { lock, logged } = await replica();
    expect(await hold(lock, DID, 300, {}).done).toBe("held");
    expect(logged).toEqual([]);
    const late = await withAdvisoryLock(lock, LockNamespace.oauth, DID, () => sleep(300).then(() => "late"), {
      holdMs: 100,
    });
    expect(late).toBe("late");
    expect(logged).toEqual([{ event: "lock.hold_exceeded", fields: { kind: "oauth", ms: 100 } }]);
  });

  test("adapter_shape", async () => {
    const { lock } = await replica();
    const requestLock = createRequestLock(lock);
    expect(await requestLock("k", () => 42)).toBe(42);
    expect(await requestLock(DID, async () => "async")).toBe("async");
  });

  test("bad_wait_refused", async () => {
    const { lock } = await replica();
    await expect(withAdvisoryLock(lock, LockNamespace.oauth, DID, async () => 1, { waitMs: 0 })).rejects.toThrow(
      RangeError,
    );
  });
});
