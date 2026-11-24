// Better Auth's connection to Postgres (org-0015): a `pg` 8.23.1 pool under Kysely 0.29.9's PostgresDialect, for
// Better Auth's own tables only. Better Auth detects Postgres only through a `pg` pool, and its adapter suites passed on
// pg (468/468) but not on a Bun.sql dialect (agent-kit notes/first-e2e-slice/spike.md (f)); backend's own tables stay
// on Bun.sql. The pool logs in as `backend_auth`, whose search_path is empty (migration 0003), so it sets `auth` for
// its own sessions: Better Auth writes unqualified table names.
import { PostgresDialect } from "kysely";
import pg from "pg";
import type { Logger } from "../../shared/log/index.ts";
import type { Connection } from "../postgres/config.ts";

export type AuthDatabase = {
  readonly dialect: PostgresDialect;
  /** Whether a connection can be had and answers now; never throws. */
  readonly ready: () => Promise<boolean>;
  readonly close: () => Promise<void>;
};

export type AuthDatabaseOptions = {
  readonly connection: Connection;
  readonly max: number;
  readonly connectTimeoutS: number;
  readonly log: Logger;
};

export function createAuthDatabase(options: AuthDatabaseOptions): AuthDatabase {
  const { connection } = options;
  const pool = new pg.Pool({
    host: connection.hostname,
    port: connection.port,
    database: connection.database,
    user: connection.username,
    password: connection.password,
    // verify-full or nothing, as for Bun.sql (config.ts connectionOf): node:tls checks the chain and the host name.
    ssl: connection.tls === false ? false : { ...connection.tls },
    max: options.max,
    connectionTimeoutMillis: options.connectTimeoutS * 1000,
    idleTimeoutMillis: 30_000,
    application_name: "backend-auth",
    options: "-c search_path=auth",
  });
  // An idle client's connection error is emitted on the pool; unheard, it would end the process (pg-pool 3, README
  // "error"). The pool drops that client and the next query takes a new one. The class name only, never the message.
  pool.on("error", (error) => options.log.warn("auth.database_error", { kind: error.name || "Error" }));
  return {
    dialect: new PostgresDialect({ pool }),
    ready: async () => {
      try {
        await pool.query("SELECT 1");
        return true;
      } catch {
        return false;
      }
    },
    close: () => pool.end(),
  };
}
