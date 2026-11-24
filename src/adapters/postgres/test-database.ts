// Test support for the Postgres adapter: real databases on the Postgres the environment names, never a mock
// (first slice step 5). CI gets one from tooling's check (`postgres-image`, PGHOST/PGPORT/PGUSER/PGDATABASE);
// locally, point the same variables at a disposable server you run. No variable set fails the tests instead of
// skipping them, so a missing database can never pass for a green run.
//
// Each test file makes its own databases, owned by `migrator`, and drops them at the end. `migrator` is created as the
// old app's bootstrap made it (Undefined6799/unset@60228f5 deployment/postgres/init/00-bootstrap.sh): CREATEROLE and
// nothing else, with a password only this run knows.
import { randomBytes } from "node:crypto";
import { SQL } from "bun";
import { createLogger } from "../../shared/log/index.ts";
import { migrate } from "./migrate.ts";
import { MIGRATIONS } from "./migrate-cli.ts";
import { createPool, type Pool } from "./pool.ts";

const env = process.env;

function adminConnection(database: string): SQL {
  if (!env.PGHOST || !env.PGUSER) {
    throw new Error("Postgres tests need PGHOST and PGUSER (and PGPORT, PGPASSWORD if not default) for a superuser.");
  }
  return new SQL({
    adapter: "postgres",
    hostname: env.PGHOST,
    port: Number(env.PGPORT ?? 5432),
    username: env.PGUSER,
    password: env.PGPASSWORD ?? "",
    database,
    max: 1,
    tls: false,
  });
}

/** 24 random bytes as hex: long enough for any password rule, and safe inside a SQL literal. */
export const randomPassword = (): string => randomBytes(24).toString("hex");

export type TestPostgres = {
  readonly host: string;
  readonly port: number;
  readonly migratorPassword: string;
  /** A new database owned by migrator. */
  readonly createDatabase: () => Promise<string>;
  /** Runs `text` as the superuser in `database`; rows as `a|b` lines joined by newlines, like `psql -At`. */
  readonly sql: (database: string, text: string) => Promise<string>;
  /** A new database with the repository's migrations applied, as the migrate image applies them. */
  readonly migratedDatabase: () => Promise<string>;
  /**
   * A pool on `database` as a runtime role, as its process connects. The role gets a password only this run knows;
   * roles are cluster-global, so it is set once per run and every pool of the run shares it.
   */
  readonly connectAs: (database: string, role: RuntimeRole, max?: number) => Promise<Pool>;
  readonly stop: () => Promise<void>;
};

export type RuntimeRole = "backend" | "backend_auth";

/** Connects as the superuser, (re)creates `migrator` with a fresh password, and tracks the databases it makes. */
export async function startTestPostgres(): Promise<TestPostgres> {
  const admin = adminConnection(env.PGDATABASE ?? "postgres");
  const migratorPassword = randomPassword();
  await admin.unsafe(`SET password_encryption = 'scram-sha-256'`);
  await admin.unsafe(`DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'migrator') THEN
      CREATE ROLE migrator LOGIN NOSUPERUSER NOCREATEDB CREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
  END $$`);
  await admin.unsafe(`ALTER ROLE migrator PASSWORD '${migratorPassword}'`);
  const databases: string[] = [];
  const sql = async (database: string, text: string): Promise<string> => {
    const client = adminConnection(database);
    try {
      const rows = (await client.unsafe(text).values()) as unknown[][];
      return rows
        .map((row) => row.map((value) => (value === true ? "t" : value === false ? "f" : String(value))).join("|"))
        .join("\n");
    } finally {
      await client.close();
    }
  };
  const host = env.PGHOST ?? "";
  const port = Number(env.PGPORT ?? 5432);
  const createDatabase = async () => {
    const name = `t_${randomBytes(8).toString("hex")}`;
    await admin.unsafe(`CREATE DATABASE ${name} OWNER migrator`);
    databases.push(name);
    return name;
  };
  const passwords = new Map<RuntimeRole, string>();
  const pools: Pool[] = [];
  const silent = createLogger({ service: "migrate", commit: "0".repeat(40), env: "test", write: () => undefined });
  return {
    host,
    port,
    migratorPassword,
    createDatabase,
    sql,
    migratedDatabase: async () => {
      const database = await createDatabase();
      const connection = {
        hostname: host,
        port,
        database,
        username: "migrator",
        password: migratorPassword,
        tls: false as const,
      };
      const result = await migrate({ connection, ...MIGRATIONS, log: silent, retryDelaysMs: [] });
      if (!result.ok) throw new Error(`test migrations failed: ${result.reason}`);
      return database;
    },
    connectAs: async (database, role, max = 4) => {
      let password = passwords.get(role);
      if (password === undefined) {
        password = randomPassword();
        await admin.unsafe(`ALTER ROLE ${role} PASSWORD '${password}'`);
        passwords.set(role, password);
      }
      const connection = { hostname: host, port, database, username: role, password, tls: false as const };
      const pool = createPool({ connection, service: "test", max, connectTimeoutS: 5 });
      pools.push(pool);
      return pool;
    },
    stop: async () => {
      for (const pool of pools) await pool.close();
      for (const name of databases) await admin.unsafe(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
      await admin.close();
    },
  };
}
