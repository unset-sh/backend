// The repository's migrations against a real Postgres: who may use which schema, and that Bun.sql passes a uuid
// parameter through an explicit cast (org-0015: Bun.sql sends parameters as text, so backend's own queries cast).
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { SQL } from "bun";
import { createLogger } from "../../shared/log/index.ts";
import { migrate } from "./migrate.ts";
import { MIGRATIONS } from "./migrate-cli.ts";
import { startTestPostgres, type TestPostgres } from "./test-database.ts";

let postgres: TestPostgres;
let database: string;

beforeAll(async () => {
  postgres = await startTestPostgres();
  database = await postgres.createDatabase();
  const log = createLogger({ service: "migrate", commit: "0".repeat(40), env: "test", write: () => undefined });
  const connection = {
    hostname: postgres.host,
    port: postgres.port,
    database,
    username: "migrator",
    password: postgres.migratorPassword,
    tls: false as const,
  };
  const result = await migrate({ connection, ...MIGRATIONS, log, retryDelaysMs: [] });
  if (!result.ok) throw new Error(`migrations failed: ${result.reason}`);
});
afterAll(() => postgres.stop());

const can = (role: string, schema: string) =>
  postgres.sql(database, `SELECT has_schema_privilege('${role}', '${schema}', 'USAGE')`);

describe("schemas and roles", () => {
  test("each runtime role reaches only its own schema", async () => {
    expect(await can("backend", "app")).toBe("t");
    expect(await can("backend", "auth")).toBe("f");
    expect(await can("backend_auth", "auth")).toBe("t");
    expect(await can("backend_auth", "app")).toBe("f");
  });

  test("no runtime role may create in a schema or use public", async () => {
    for (const role of ["backend", "backend_auth"]) {
      for (const schema of ["app", "auth"]) {
        expect(await postgres.sql(database, `SELECT has_schema_privilege('${role}', '${schema}', 'CREATE')`)).toBe("f");
      }
      expect(await postgres.sql(database, `SELECT has_schema_privilege('${role}', 'public', 'CREATE')`)).toBe("f");
    }
  });

  test("runtime roles are not privileged and have an empty search_path", async () => {
    const rows = await postgres.sql(
      database,
      `SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, 'search_path=""' = ANY (rolconfig)
         FROM pg_roles WHERE rolname IN ('backend', 'backend_auth') ORDER BY rolname`,
    );
    expect(rows).toBe("backend|f|f|f|f|t\nbackend_auth|f|f|f|f|t");
  });

  test("PUBLIC may not connect", async () => {
    expect(await postgres.sql(database, `SELECT has_database_privilege('public', current_database(), 'CONNECT')`)).toBe(
      "f",
    );
  });
});

describe("Bun.sql parameters", () => {
  test("a uuid parameter round-trips through an explicit cast", async () => {
    const sql = new SQL({
      adapter: "postgres",
      hostname: postgres.host,
      port: postgres.port,
      database,
      username: "migrator",
      password: postgres.migratorPassword,
      tls: false,
      max: 1,
    });
    try {
      const id = crypto.randomUUID();
      await sql`CREATE TABLE app.uuid_probe (id uuid PRIMARY KEY)`;
      await sql`INSERT INTO app.uuid_probe (id) VALUES (${id}::uuid)`;
      const [row] = await sql<{ id: string }[]>`SELECT id FROM app.uuid_probe WHERE id = ${id}::uuid`;
      expect(row?.id).toBe(id);
    } finally {
      await sql.close();
    }
  });
});
