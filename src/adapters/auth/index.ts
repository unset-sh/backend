// The Unset session as the internal API uses it: four calls over Better Auth (better-auth.ts) and its `atproto` plugin.
// No Better Auth type leaves this folder.
import { APIError } from "better-auth/api";
import { type Did, parseDid } from "../../domains/identity/index.ts";
import type { StartResult } from "../atproto/oauth/grant.ts";
import type { CompleteResult } from "./atproto-plugin.ts";
import type { Auth } from "./better-auth.ts";

export { placeholderEmail } from "./atproto-plugin.ts";
export { createAuth, TELEMETRY_VARIABLES, telemetryVariablesSet } from "./better-auth.ts";
export { createAuthDatabase } from "./database.ts";

export type SignOutOutcome = "ok" | "no_session" | "failed";

export type Sessions = {
  start(handle: string): Promise<StartResult>;
  complete(query: string): Promise<CompleteResult>;
  /** The caller's session, from its `Authorization: Bearer` token; null when there is none or it ended. */
  current(headers: Headers): Promise<{ readonly did: Did } | null>;
  signOut(headers: Headers): Promise<SignOutOutcome>;
};

const unauthorized = (error: unknown): boolean => error instanceof APIError && error.status === "UNAUTHORIZED";

export function createSessions(auth: Auth): Sessions {
  return {
    start: (handle) => auth.api.atprotoSignIn({ body: { handle } }),
    complete: (query) => auth.api.atprotoCallback({ body: { query } }),
    async current(headers) {
      const found = await auth.api.getSession({ headers, query: { disableCookieCache: true } });
      const did = found === null ? null : parseDid(found.session.did);
      return did === null ? null : { did };
    },
    async signOut(headers) {
      try {
        const result = await auth.api.atprotoSignOut({ headers });
        return result.ok ? "ok" : "failed";
      } catch (error) {
        if (unauthorized(error)) return "no_session";
        throw error;
      }
    },
  };
}
