// The Postgres connection settings every process that connects merges into its schema (P1.11; moved here in P1.11p so
// the migrate CLI and each pool read the same fields). Each field carries its cross-field rule.
import { readFileSync } from "node:fs";
import { BlockList, isIP } from "node:net";
import { type Config, int, oneOf, secretFile, str, withRule } from "../../shared/config/index.ts";

/** A lowercase hostname or a Compose service name; no scheme, port or trailing dot. */
const HOSTNAME = /[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*/;
/** A Compose service name: one label, no dot, colon or bracket (architecture ruling 2026-10-06, P1.11p). */
const SERVICE_NAME = /^[a-z][a-z0-9-]{0,62}$/;
/** An unquoted Postgres identifier. */
const IDENTIFIER = /[a-z_][a-z0-9_]{0,62}/;

/** Loopback literals: 127.0.0.0/8 and ::1 (RFC 1122 3.2.1.3, RFC 4291 2.5.3). */
const LOOPBACK = new BlockList();
LOOPBACK.addSubnet("127.0.0.0", 8, "ipv4");
LOOPBACK.addAddress("::1", "ipv6");

/**
 * Whether `disable` may reach this host: a Compose service name, or a loopback address literal. Not a name such as
 * `localhost` or `.internal`, which can resolve outside the host. The egress guard's address classifier replaces
 * this table when it arrives (first slice step 6), so there is one IP class table.
 */
function plainTcpAllowed(host: string): boolean {
  const family = isIP(host);
  return SERVICE_NAME.test(host) || (family !== 0 && LOOPBACK.check(host, family === 4 ? "ipv4" : "ipv6"));
}

export const postgresFields = {
  PG_HOST: str({ pattern: HOSTNAME }),
  PG_PORT: int({ min: 1, max: 65535, default: 5432 }),
  PG_DATABASE: str({ pattern: IDENTIFIER }),
  PG_USER: str({ pattern: IDENTIFIER }),
  PG_PASSWORD: secretFile({ minBytes: 16 }),
  // Plain TCP only to a Compose service name or loopback; anything else is TLS with the server's certificate and name
  // checked. libpq's `require` (encrypt, check nothing) is left out: it stops no impostor.
  PG_SSLMODE: withRule(
    oneOf(["disable", "verify-full"]),
    (config) => config.PG_SSLMODE !== "disable" || plainTcpAllowed(String(config.PG_HOST)),
  ),
  /** A private CA's certificate file for verify-full (a managed Postgres); empty means the system CAs. */
  PG_SSLROOTCERT: withRule(
    str({ pattern: /\/[A-Za-z0-9._/-]+/, default: "" }),
    (config) => config.PG_SSLROOTCERT === "" || config.PG_SSLMODE === "verify-full",
  ),
};

/** Pool sizing (P1.11p), for processes that hold a pool; the migrate CLI has none. */
export const poolFields = {
  PG_POOL_MAX: int({ min: 1, max: 50 }),
  /** The longest wait for a new connection, in seconds. Bun.sql reads 0 as "wait forever", so it is outside the range. */
  PG_CONNECT_TIMEOUT_S: int({ min: 1, max: 30, default: 5 }),
};

/**
 * What a client or pool needs to reach Postgres, in Bun.sql's option names (Bun 1.4.4 docs/runtime/sql.mdx,
 * "PostgreSQL Options"). Every field is set, so Bun never falls back to a PG* environment variable.
 */
export type Connection = {
  readonly hostname: string;
  readonly port: number;
  readonly database: string;
  readonly username: string;
  readonly password: string;
  readonly tls: false | { readonly rejectUnauthorized: true; readonly ca?: string };
};

export type PostgresConfig = Config<typeof postgresFields>;

/**
 * libpq's sslmode in Bun.sql terms. A `tls` object with `rejectUnauthorized: true` (and `ca` for a private CA) is
 * verify-full: chain and host name checked (Bun 1.4.4 docs/runtime/sql.mdx, "SSL Modes"), and it keeps checking even
 * when NODE_TLS_REJECT_UNAUTHORIZED=0 is set. A missing CA file throws here, at boot.
 */
export function connectionOf(cfg: PostgresConfig): Connection {
  const tls =
    cfg.PG_SSLMODE === "disable"
      ? false
      : cfg.PG_SSLROOTCERT === ""
        ? ({ rejectUnauthorized: true } as const)
        : ({ rejectUnauthorized: true, ca: readFileSync(cfg.PG_SSLROOTCERT, "utf8") } as const);
  return {
    hostname: cfg.PG_HOST,
    port: cfg.PG_PORT,
    database: cfg.PG_DATABASE,
    username: cfg.PG_USER,
    password: cfg.PG_PASSWORD.reveal(),
    tls,
  };
}
