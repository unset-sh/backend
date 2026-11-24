// The pool a process runs backend's own queries on: Bun.sql (org-0015), every option set, so Bun never falls back to a
// PG* environment variable (Bun 1.4.4 docs/runtime/sql.mdx, "PostgreSQL Options"). Queries are tagged templates, which
// bind each value as a parameter; Bun sends parameters as text, so a query casts where the column needs a type.
import { SQL } from "bun";
import type { Connection } from "./config.ts";

export type Pool = SQL;

export type PoolOptions = {
  readonly connection: Connection;
  /** Who is connecting, for `pg_stat_activity`; never a person or a secret. */
  readonly service: string;
  readonly max: number;
  /** Seconds; Bun.sql reads 0 as "wait forever", so the config refuses it. */
  readonly connectTimeoutS: number;
};

export function createPool(options: PoolOptions): Pool {
  return new SQL({
    adapter: "postgres",
    ...options.connection,
    max: options.max,
    connectionTimeout: options.connectTimeoutS,
    idleTimeout: 30,
    maxLifetime: 0,
    connection: { application_name: options.service },
  });
}

/**
 * The Postgres SQLSTATE of a driver error, never its message (which can quote row values). Bun.sql puts the server's
 * code in `errno` and its own `ERR_POSTGRES_*` name in `code` (docs/runtime/sql.mdx, "Error Handling").
 */
export function sqlstateOf(error: unknown): string | undefined {
  const errno = error instanceof SQL.PostgresError ? (error as { errno?: unknown }).errno : undefined;
  return typeof errno === "string" && /^[0-9A-Z]{5}$/.test(errno) ? errno : undefined;
}
