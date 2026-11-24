// The backend process's composition root: load the configuration (refusing to start on a missing or invalid key),
// build each dependency once, and hand them to the server. Nothing else constructs a dependency.
import { createIdentityNetwork } from "./adapters/atproto/identity-network.ts";
import { createGrant } from "./adapters/atproto/oauth/grant.ts";
import type { SavedSession, SavedState } from "./adapters/atproto/oauth/oauth-client.ts";
import { createOAuthClient } from "./adapters/atproto/oauth/oauth-client.ts";
import { createSignInLock } from "./adapters/atproto/oauth/sign-in-lock.ts";
import { createPdsCall } from "./adapters/atproto/pds/pds-call.ts";
import { createProfileStore } from "./adapters/atproto/pds/profile-store.ts";
import { createAuth, createAuthDatabase, createSessions, telemetryVariablesSet } from "./adapters/auth/index.ts";
import { createNetGuard, libraryFetch } from "./adapters/egress/index.ts";
import { connectionOf } from "./adapters/postgres/config.ts";
import { createRequestLock } from "./adapters/postgres/lock.ts";
import { createOAuthSessionStore, createOAuthStateStore, oauthSessionExists } from "./adapters/postgres/oauthStores.ts";
import { createPool } from "./adapters/postgres/pool.ts";
import { createSealer } from "./adapters/seal/index.ts";
import { backendConfig } from "./config.ts";
import { createDidResolver, createHandleVerifier, parseHandle, resolveHandle } from "./domains/identity/index.ts";
import { createProfiles } from "./domains/profile/operations.ts";
import { serve } from "./server/serve.ts";
import { bootOrExit, ConfigError, exitOnConfigError } from "./shared/config/index.ts";
import { createLogger } from "./shared/log/index.ts";

// Better Auth sends telemetry once both of these are set, whatever its config says (better-auth.ts). Checked first, so
// no other key can hide it.
const telemetry = telemetryVariablesSet(process.env);
if (telemetry.length > 0) exitOnConfigError(new ConfigError(telemetry.map((key) => ({ key, reason: "invalid" }))));

const config = bootOrExit(backendConfig);
const log = createLogger({ service: config.UNSET_SERVICE, commit: config.UNSET_COMMIT, env: config.UNSET_ENV });

const connection = connectionOf(config);
const pool = createPool({
  connection,
  service: "backend",
  max: config.PG_POOL_MAX,
  connectTimeoutS: config.PG_CONNECT_TIMEOUT_S,
});
const lockPool = createPool({
  connection,
  service: "backend-lock",
  max: config.LOCK_POOL_MAX,
  connectTimeoutS: config.PG_CONNECT_TIMEOUT_S,
});
const authDatabase = createAuthDatabase({
  connection: { ...connection, username: config.PG_AUTH_USER, password: config.PG_AUTH_PASSWORD.reveal() },
  max: config.PG_AUTH_POOL_MAX,
  connectTimeoutS: config.PG_CONNECT_TIMEOUT_S,
  log,
});

const sealer = createSealer(config.SEAL_KEYRING);
const guard = createNetGuard({ internalHosts: [], allowLoopback: false, commit: config.UNSET_COMMIT });
const plcUrl = new URL(config.PLC_URL);
const network = createIdentityNetwork({
  guard,
  plcUrl,
  httpTimeoutMs: config.IDENTITY_HTTP_TIMEOUT_MS,
  dnsTimeoutMs: config.IDENTITY_DNS_TIMEOUT_MS,
});
const resolveDid = createDidResolver({
  network,
  plcUrl,
  cacheTtlS: config.DID_DOC_CACHE_TTL_S,
  cacheMax: config.DID_DOC_CACHE_MAX,
});
const sessionStore = createOAuthSessionStore<SavedSession>({ pool, sealer, log });
// The library reaches the token sets and its lock through the sign-in lock, so a sign-in replaces an account's token
// set in place and a last sign-out cannot race it (sign-in-lock.ts).
const signInLock = createSignInLock({ store: sessionStore, lock: createRequestLock({ pool: lockPool, log }) });
const { client } = createOAuthClient({
  redirectUri: `${config.WEB_ORIGIN}/auth/callback`,
  stateStore: createOAuthStateStore<SavedState>({ pool, sealer, log }),
  sessionStore: signInLock.tokenSets,
  requestLock: signInLock.requestLock,
  fetch: libraryFetch(guard),
  network,
  resolveDid,
  log,
});
const grant = createGrant({
  client,
  dropTokenSet: (did) => sessionStore.del(did),
  scopes: signInLock,
  resolveHandle: async (handle) => {
    const parsed = parseHandle(handle);
    return parsed === null ? { status: "not_found" } : resolveHandle(network, parsed);
  },
  log,
});
const auth = createAuth({
  database: authDatabase,
  secret: config.BETTER_AUTH_SECRET,
  webOrigin: config.WEB_ORIGIN,
  grant,
  log,
});

// Every call to a member's PDS restores their OAuth session here (pds-call.ts). A grant found dead is deleted, and
// the sessions on it with it (migration 0007).
const { pdsCall } = createPdsCall({
  client,
  endSessions: (did) => sessionStore.del(did),
  tokenSetRemains: (did) => oauthSessionExists(pool, did),
  log,
});
const handles = createHandleVerifier({
  network,
  resolveDid,
  verifyTtlS: config.HANDLE_VERIFY_TTL_S,
  invalidTtlS: config.HANDLE_INVALID_TTL_S,
  cacheMax: config.HANDLE_CACHE_MAX,
  onUnexpected: (error) => log.logError(error),
});
const profiles = createProfiles({
  store: createProfileStore(pdsCall),
  handleOf: async (did) => {
    const verdict = await handles.verifyHandle(did);
    return verdict.status === "verified" ? verdict.handle : undefined;
  },
  now: () => new Date().toISOString(),
});

/** Ready when both pools answer; a database that is down makes /health 503, never an exception. */
const ready = async (): Promise<boolean> => {
  const backendUp = pool`SELECT 1`.then(
    () => true,
    () => false,
  );
  const [own, auth_] = await Promise.all([backendUp, authDatabase.ready()]);
  return own && auth_;
};

serve({ ready, sessions: createSessions(auth), profiles, webOrigin: config.WEB_ORIGIN }, log, config.LISTEN_PORT);
