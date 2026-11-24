// P2.08h: the sealed stores honour GetOptions.signal (@atproto-labs/simple-store 0.5.1 dist/simple-store.d.ts): a read
// or delete past the caller's deadline is refused before its query runs, so it takes no connection.
import { describe, expect, test } from "bun:test";
import type { Logger } from "../../shared/log/index.ts";
import { createSealer, parseKeyring } from "../seal/index.ts";
import { createOAuthSessionStore, createOAuthStateStore } from "./oauthStores.ts";
import type { Pool } from "./pool.ts";

const keyring = parseKeyring(JSON.stringify({ active: "k1", keys: { k1: Buffer.alloc(32, 7).toString("base64") } }));
if (keyring === undefined) throw new Error("test keyring did not parse");
const sealer = createSealer(keyring);
const log: Logger = { info: () => undefined, warn: () => undefined, error: () => undefined, logError: () => undefined };
const DID = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";

/** A stand-in for Bun.sql's tagged function: each query is lazy, and running one is counted. */
function countingPool() {
  const counts = { ran: 0, cancelled: 0 };
  const pool = (() => ({
    // biome-ignore lint/suspicious/noThenProperty: a stand-in for Bun's lazy, thenable query object.
    then: (resolve: (rows: unknown[]) => void) => {
      counts.ran += 1;
      resolve([]);
    },
    cancel: () => {
      counts.cancelled += 1;
    },
  })) as unknown as Pool;
  return { pool, counts };
}

describe("oauth stores", () => {
  test("get_and_del_past_the_deadline_run_no_query", async () => {
    const { pool, counts } = countingPool();
    const signal = AbortSignal.abort();
    const session = createOAuthSessionStore({ pool, sealer, log });
    const state = createOAuthStateStore({ pool, sealer, log });
    await expect(session.get(DID, { signal })).rejects.toMatchObject({ code: "http.deadline" });
    await expect(state.get("state-1", { signal })).rejects.toMatchObject({ code: "http.deadline" });
    await expect(session.del(DID, { signal })).rejects.toMatchObject({ code: "http.deadline" });
    await expect(state.del("state-1", { signal })).rejects.toMatchObject({ code: "http.deadline" });
    expect(counts).toEqual({ ran: 0, cancelled: 4 });
  });

  test("without_a_signal_the_query_runs", async () => {
    const { pool, counts } = countingPool();
    expect(await createOAuthSessionStore({ pool, sealer, log }).get(DID)).toBeUndefined();
    expect(counts.ran).toBe(1);
  });
});
