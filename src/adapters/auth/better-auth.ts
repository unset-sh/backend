// Better Auth in backend (org-0015; first slice §3): the Unset session, on Better Auth 1.7.25 with the bearer plugin and
// the `atproto` plugin. Its HTTP handler is not mounted: the internal API calls `auth.api.*` from its own routes, which
// carry the contract (api/internal/openapi.yaml), so no Better Auth route is reachable in this slice. Web keeps the
// session token in its own cookie and sends it as `Authorization: Bearer`; Better Auth's cookies never leave backend.
// Every option below that has a default is set anyway, so an upgrade or an environment variable cannot change it
// (better-auth 1.7.25 dist/context/create-context.mjs; @better-auth/core dist/types/init-options.d.mts).
import { betterAuth } from "better-auth";
import { bearer } from "better-auth/plugins/bearer";
import type { Secret } from "../../shared/config/index.ts";
import type { Logger } from "../../shared/log/index.ts";
import type { Grant } from "../atproto/oauth/grant.ts";
import { atproto } from "./atproto-plugin.ts";
import type { AuthDatabase } from "./database.ts";

/**
 * Better Auth reads these at start, and `telemetry.enabled: false` does not hold once both are set
 * (@better-auth/telemetry 1.7.25 dist/index.mjs `createTelemetry`; spike (i)). Backend refuses to start with either.
 */
export const TELEMETRY_VARIABLES = ["BETTER_AUTH_TELEMETRY", "BETTER_AUTH_TELEMETRY_ENDPOINT"] as const;

/** The telemetry variables set in `env`; boot refuses a non-empty list. */
export const telemetryVariablesSet = (env: Record<string, string | undefined>): string[] =>
  TELEMETRY_VARIABLES.filter((name) => env[name] !== undefined);

export type AuthOptions = {
  readonly database: AuthDatabase;
  /** Signs the session token the bearer plugin accepts; Alex places it (BETTER_AUTH_SECRET_FILE). */
  readonly secret: Secret;
  /** Web's origin, the one trusted origin: a request that carries a cookie must come from it. */
  readonly webOrigin: string;
  readonly grant: Grant;
  readonly log: Logger;
};

export function createAuth(options: AuthOptions) {
  const { log } = options;
  return betterAuth({
    appName: "Unset",
    baseURL: options.webOrigin,
    secret: options.secret.reveal(),
    database: { dialect: options.database.dialect, type: "postgres" },
    trustedOrigins: [options.webOrigin],
    emailAndPassword: { enabled: false },
    account: { accountLinking: { enabled: false, disableImplicitLinking: true } },
    // The DID whose token set the session rides on; migration 0007 deletes the session with that token set.
    session: { additionalFields: { did: { type: "string", required: true, input: false } } },
    telemetry: { enabled: false },
    // Web is the only caller, so every request has web's address: a limit keyed on it would throttle every member
    // together, and Better Auth would store it on each session. Web's own request gate limits members.
    rateLimit: { enabled: false },
    advanced: {
      // Explicit, so NODE_ENV=test or TEST cannot turn the origin check off (create-context.mjs `skipOriginCheck`).
      disableOriginCheck: false,
      disableCSRFCheck: false,
      ipAddress: { disableIpTracking: true },
      // Members are keyed by a UUID that Postgres makes (migration 0008; docs/api-conventions.md "Identifiers").
      database: { generateId: "uuid" },
    },
    // Better Auth's messages can carry request data, so only their level is logged.
    logger: { level: "warn", log: (level) => log.warn("auth.library", { kind: level }) },
    plugins: [bearer(), atproto(options.grant)],
  });
}

export type Auth = ReturnType<typeof createAuth>;
