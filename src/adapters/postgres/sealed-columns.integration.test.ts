// P1.14d (migration 0005, sealed-columns.json, sealedColumns.ts): every `types.sealed` column has a registry row, and
// every row with a `form` names a real non-sealed text or bytea column. The catalog is the list. Adapted from
// Undefined6799/unset@60228f5 infrastructure/postgres/sealed-columns.integration.test.ts; its rewrap_all_counts case
// comes with the key-rotation runbook, which this slice does not carry.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createSealer, type Keyring, parseKeyring, sealContext } from "../seal/index.ts";
import type { Pool } from "./pool.ts";
import { sqlstateOf } from "./pool.ts";
import { SEALED_COLUMNS, type SealedRegistry, sealedColumns } from "./sealedColumns.ts";
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

/** A database migrated from scratch, then `sql` run in it: the "temporary migration" of each case. */
async function migratedWith(sql: string): Promise<string> {
  const name = await postgres.migratedDatabase();
  await postgres.sql(name, sql);
  return name;
}

/** Each problem between the catalog and `registry`, one readable line each. */
async function registryProblems(pool: Pool, registry: SealedRegistry = SEALED_COLUMNS): Promise<string[]> {
  const catalog = await sealedColumns(pool);
  const sealed = catalog.filter((c) => c.type === "sealed").map((c) => c.key);
  const plain = new Set(catalog.filter((c) => c.type === "text" || c.type === "bytea").map((c) => c.key));
  const entries = Object.entries(registry);
  // A value is opened and rewritten by its row key, so the row key must be unique on its own (primary key or unique).
  const uniqueRows: { key: string }[] = await pool`
    SELECT n.nspname || '.' || c.relname || '.' || a.attname AS key
      FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid = i.indrelid
           JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
           JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum = i.indkey[0]
     WHERE i.indisunique AND i.indnkeyatts = 1 AND i.indpred IS NULL`;
  const unique = new Set(uniqueRows.map((r) => r.key));
  const tableOf = (key: string) => key.split(".").slice(0, 2).join(".");
  return [
    ...sealed.filter((key) => !(key in registry)).map((key) => `add a sealed-columns row for ${key}`),
    ...entries
      .filter(([key, row]) => row.form === undefined && !sealed.includes(key))
      .map(([key]) => `${key} is registered but is not a types.sealed column`),
    ...entries
      .filter(([key, row]) => row.form !== undefined && !plain.has(key))
      .map(([key, row]) => `${key} (${row.form}) is not a text or bytea column`),
    ...entries
      .filter(([key, row]) => (sealed.includes(key) || plain.has(key)) && !unique.has(`${tableOf(key)}.${row.rowKey}`))
      .map(([key, row]) => `${key}: row key ${row.rowKey} is not unique on its own`),
  ];
}

const keyring = parseKeyring(
  JSON.stringify({ active: "k1", keys: { k1: Buffer.alloc(32, 1).toString("base64") } }),
) as Keyring;

/** The SQLSTATE casting `value` to types.sealed fails with as `backend`, or "ok". */
async function asBackend(value: string): Promise<string> {
  try {
    await backend`SELECT ${value}::types.sealed`;
    return "ok";
  } catch (error) {
    return sqlstateOf(error) ?? String(error);
  }
}

describe("sealed columns", () => {
  test("registry_complete", async () => {
    expect(await registryProblems(backend)).toEqual([]);
  });

  test("sealed_columns_registry", async () => {
    const database = await migratedWith(
      "CREATE TABLE app.t (id text PRIMARY KEY, secret types.sealed, media_key text, blob bytea, n int, owner text)",
    );
    const pool = await postgres.connectAs(database, "backend");
    // The real registry's rows ride along in each one given here, so only app.t's problems show.
    expect(await registryProblems(pool)).toEqual(["add a sealed-columns row for app.t.secret"]);
    expect(await registryProblems(pool, { ...SEALED_COLUMNS, "app.t.secret": { rowKey: "id" } })).toEqual([]);
    expect(
      await registryProblems(pool, {
        ...SEALED_COLUMNS,
        "app.t.secret": { rowKey: "id" },
        "app.t.gone": { rowKey: "id", form: "sealToStream" },
        "app.t.n": { rowKey: "id", form: "sealTo" },
        "app.t.media_key": { rowKey: "id", form: "sealStream" },
        "app.t.blob": { rowKey: "id", form: "sealTo" },
        "app.t.id": { rowKey: "id" },
      }),
    ).toEqual([
      "app.t.id is registered but is not a types.sealed column",
      "app.t.gone (sealToStream) is not a text or bytea column",
      "app.t.n (sealTo) is not a text or bytea column",
    ]);
    expect(await registryProblems(pool, { ...SEALED_COLUMNS, "app.t.secret": { rowKey: "owner" } })).toEqual([
      "app.t.secret: row key owner is not unique on its own",
    ]);
    // A types.sealed column registered with a form is refused: a form row names a text or bytea column only.
    expect(
      await registryProblems(pool, { ...SEALED_COLUMNS, "app.t.secret": { rowKey: "id", form: "sealTo" } }),
    ).toEqual(["app.t.secret (sealTo) is not a text or bytea column"]);
  });

  test("sealed_domain_check", async () => {
    const value = createSealer(keyring).seal(Buffer.from("x"), sealContext("app.t.c", "1"));
    expect(await asBackend(value)).toBe("ok");
    for (const bad of ["plain", "s1..x", "s1.K1.x", "s1.abcdefghijklmnopq.x", "a1.k1.x", "s1c.k1.x"]) {
      expect(await asBackend(bad), bad).toBe("23514");
    }
  });
});
