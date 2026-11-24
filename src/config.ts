// The backend process's configuration: the keys every entrypoint has (UNSET_ENV, UNSET_SERVICE, UNSET_COMMIT,
// LISTEN_PORT) and those of each dependency it builds. A missing or invalid key refuses boot (exit 78). Secrets come
// only from `<KEY>_FILE` files, which Alex places (agent-kit rules/org.md "Keys, tokens and secrets").
import { poolFields, postgresFields } from "./adapters/postgres/config.ts";
import { sealFields } from "./adapters/seal/index.ts";
import {
  type Config,
  defineEntrypointConfig,
  int,
  origin,
  secretFile,
  str,
  url,
  withRule,
} from "./shared/config/index.ts";

/**
 * This slice signs in with the atproto loopback client, whose redirect must be on 127.0.0.1
 * (https://atproto.com/specs/oauth, "Localhost Client Development"), so web's origin is exactly that. The confidential
 * client a public origin needs comes with its own key, which only Alex places.
 */
const LOOPBACK_ORIGIN = /^http:\/\/127\.0\.0\.1:[0-9]{1,5}$/;

export const backendConfig = defineEntrypointConfig({
  ...postgresFields,
  ...poolFields,
  // Better Auth's own pool, as `backend_auth` (migration 0003), on the same server and database.
  PG_AUTH_USER: str({ pattern: /[a-z_][a-z0-9_]{0,62}/, default: "backend_auth" }),
  PG_AUTH_PASSWORD: secretFile({ minBytes: 16 }),
  PG_AUTH_POOL_MAX: int({ min: 1, max: 20, default: 5 }),
  /** The advisory lock's own pool (lock.ts), so waiting on a lock never takes a connection from queries. */
  LOCK_POOL_MAX: int({ min: 1, max: 20, default: 4 }),
  ...sealFields,
  /** Signs the session token the bearer plugin accepts (Better Auth `secret`). */
  BETTER_AUTH_SECRET: secretFile({ minBytes: 32 }),
  WEB_ORIGIN: withRule(origin({ protocols: ["http:"] }), (config) => LOOPBACK_ORIGIN.test(String(config.WEB_ORIGIN))),
  PLC_URL: url({ protocols: ["https:"], default: "https://plc.directory/" }),
  IDENTITY_HTTP_TIMEOUT_MS: int({ min: 100, max: 30_000, default: 5_000 }),
  IDENTITY_DNS_TIMEOUT_MS: int({ min: 100, max: 30_000, default: 3_000 }),
  DID_DOC_CACHE_TTL_S: int({ min: 1, max: 3_600, default: 300 }),
  DID_DOC_CACHE_MAX: int({ min: 1, max: 100_000, default: 10_000 }),
  // The handle shown with a profile is cached once checked both ways (domains/identity/verify-handle.ts); the
  // defaults are the old app's (Undefined6799/unset@60228f5 interfaces/web/src/lib/server/config.ts).
  HANDLE_VERIFY_TTL_S: int({ min: 1, max: 3_600, default: 600 }),
  HANDLE_INVALID_TTL_S: int({ min: 1, max: 3_600, default: 60 }),
  HANDLE_CACHE_MAX: int({ min: 1, max: 100_000, default: 10_000 }),
});

export type BackendConfig = Config<typeof backendConfig.fields>;
