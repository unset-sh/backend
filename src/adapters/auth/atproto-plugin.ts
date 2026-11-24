// The Unset-owned Better Auth plugin `atproto` (org-0015; first slice §3 "Sign-in flow"). Better Auth owns the Unset
// session; AT Protocol OAuth stays in the OAuth client (src/adapters/atproto/oauth/), which this plugin reaches only
// through the `Grant` port. Every endpoint is server-only (better-auth 1.7.25 `createAuthEndpoint.serverOnly`,
// @better-auth/core dist/api/index.mjs): it is called through `auth.api.*` by the internal API and has no URL.
//
// Two-factor authentication is not on in this slice. When it is, this plugin must start Better Auth's pending
// second-factor step itself, because the two-factor plugin gates only the email, username and phone-number sign-in
// paths (better-auth 1.7.27 `plugins/two-factor`), not a session created here.
import { createHash } from "node:crypto";
import type { BetterAuthPlugin, StandardSchemaV1 } from "better-auth";
import { createAuthEndpoint, sessionMiddleware } from "better-auth/api";
import { type Did, parseDid } from "../../domains/identity/index.ts";
import type { FinishFailure, Grant, StartResult } from "../atproto/oauth/grant.ts";

export const PROVIDER_ID = "atproto";
/** The longest handle (https://atproto.com/specs/handle) and the longest callback query web relays. */
const HANDLE_MAX = 253;
const QUERY_MAX = 4096;

/**
 * Better Auth's `user.email` is required and unique, so it holds a fixed address derived from the DID under the
 * reserved `.invalid` domain (RFC 2606): it never receives mail and is never used to match or contact anyone. A hash,
 * so the value is not the DID in disguise (Alex, 2026-11-23). Migration 0007 refuses any other shape.
 */
export const placeholderEmail = (did: Did): string => `${createHash("sha256").update(did).digest("hex")}@did.invalid`;

export type CompleteResult =
  | { readonly ok: true; readonly sessionToken: string }
  | { readonly ok: false; readonly reason: FinishFailure };
export type SignOutResult = { readonly ok: true } | { readonly ok: false; readonly reason: "failed" };

/**
 * A body of one non-empty string field of at most `max` characters, as a Standard Schema (better-call 1.4.5
 * dist/validator.mjs runs `body["~standard"].validate`), so the plugin needs no schema library. The internal API's
 * TypeBox schemas check the same bounds first; this is the plugin's own check.
 */
function oneString<K extends string>(key: K, max: number): StandardSchemaV1<Record<K, string>> {
  return {
    "~standard": {
      version: 1,
      vendor: "unset",
      validate(value) {
        const field = typeof value === "object" && value !== null ? (value as Record<string, unknown>)[key] : undefined;
        return typeof field === "string" && field.length > 0 && field.length <= max
          ? { value: { [key]: field } as Record<K, string> }
          : { issues: [{ message: `${key}: a string of 1 to ${max} characters` }] };
      },
    },
  };
}

export function atproto(grant: Grant) {
  return {
    id: "atproto",
    endpoints: {
      /** Starts a sign-in for a handle and answers the authorization server's URL. */
      atprotoSignIn: createAuthEndpoint.serverOnly(
        { method: "POST", body: oneString("handle", HANDLE_MAX) },
        async (ctx): Promise<StartResult> =>
          grant.start(ctx.body.handle, ctx.request?.signal ?? AbortSignal.timeout(15_000)),
      ),
      /**
       * Completes a sign-in from the callback's query: the account found by its DID, or a new user and account, then a
       * session on that DID's token set. Matching is on the DID alone (`providerId` atproto, `accountId` the DID).
       */
      atprotoCallback: createAuthEndpoint.serverOnly(
        { method: "POST", body: oneString("query", QUERY_MAX) },
        async (ctx): Promise<CompleteResult> => {
          const finished = await grant.finish(new URLSearchParams(ctx.body.query));
          if (!finished.ok) return finished;
          const { did } = finished;
          const adapter = ctx.context.internalAdapter;
          const key = { providerId: PROVIDER_ID, accountId: did };
          let userId = (await adapter.findAccountByKey(key))?.userId;
          if (userId === undefined) {
            try {
              const created = await adapter.createOAuthUser(
                { name: "", email: placeholderEmail(did), emailVerified: false },
                { providerId: PROVIDER_ID, accountId: did },
              );
              userId = created.user.id;
            } catch (cause) {
              // A second callback for the same new DID created it first; the unique key (migration 0007) refused ours.
              userId = (await adapter.findAccountByKey(key))?.userId;
              if (userId === undefined) throw cause;
            }
          }
          const session = await adapter.createSession(userId, false, { did });
          return { ok: true, sessionToken: session.token };
        },
      ),

      /**
       * Ends the caller's session, then the grant it rides on: deleting the token set ends every other session of the
       * same account too (migration 0007), so no session outlives the grant.
       */
      atprotoSignOut: createAuthEndpoint.serverOnly(
        { method: "POST", use: [sessionMiddleware] },
        async (ctx): Promise<SignOutResult> => {
          const { session } = ctx.context.session;
          const did = parseDid(String((session as { did?: unknown }).did ?? ""));
          await ctx.context.internalAdapter.deleteSession(session.token);
          if (did === null) return { ok: true };
          try {
            await grant.end(did, ctx.request?.signal ?? AbortSignal.timeout(15_000));
            return { ok: true };
          } catch {
            return { ok: false, reason: "failed" };
          }
        },
      ),
    },
  } satisfies BetterAuthPlugin;
}
