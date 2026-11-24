// The member's atproto grant, as sign-in and sign-out use it: start an authorization, complete it, and end it. It is the
// one thing the Better Auth `atproto` plugin (src/adapters/auth/) knows of the OAuth client, so the plugin holds no
// @atproto type and this file holds no Better Auth one.
import { timingSafeEqual } from "node:crypto";
import type { Did } from "../../../domains/identity/index.ts";
import type { Logger } from "../../../shared/log/index.ts";
import type { createOAuthClient } from "./oauth-client.ts";
import { withRevokeTimeout } from "./revoke-timeout.ts";
import { grantCovers } from "./scopes.ts";
import { type AuthorizeFailure, authorize, type CallbackFailure, completeAuthorization } from "./sign-in.ts";

type Client = ReturnType<typeof createOAuthClient>["client"];

/**
 * What binds a sign-in to the browser that started it: a nonce web makes, keeps in that browser's cookie and sends
 * with both the start and the callback (32 random bytes, base64url). It travels as the library's appState, which the
 * library keeps sealed in its state store and never sends to the authorization server, as the old app's nonce did
 * (Undefined6799/unset interfaces/web/src/lib/server/sign-in-state.ts at 60228f5).
 */
export const BROWSER_NONCE = /^[A-Za-z0-9_-]{43}$/;

/** Equal nonces, compared in constant time. */
function sameNonce(a: string, b: string): boolean {
  const [x, y] = [Buffer.from(a), Buffer.from(b)];
  return x.length === y.length && timingSafeEqual(x, y);
}

export type StartResult =
  | { readonly ok: true; readonly url: string }
  | { readonly ok: false; readonly reason: AuthorizeFailure };
export type FinishFailure = CallbackFailure | "scope_missing" | "state_mismatch";
export type FinishResult =
  | { readonly ok: true; readonly did: Did }
  | { readonly ok: false; readonly reason: FinishFailure };

export type Grant = {
  /** The authorization server's URL for `handle`, where web sends the browser, bound to `nonce` (BROWSER_NONCE). */
  start(handle: string, nonce: string, deadline: AbortSignal): Promise<StartResult>;
  /**
   * The DID the server vouched for, with its token set stored, only when `nonce` is the one the sign-in started with;
   * every refusal leaves no grant behind.
   */
  finish(query: URLSearchParams, nonce: string): Promise<FinishResult>;
  /**
   * Revokes the grant and deletes its token set, which ends every session on it (migration 0007). When the revoke
   * fails or runs out of time, the token set is deleted here; only when that also fails does this throw.
   */
  end(did: Did, deadline: AbortSignal): Promise<void>;
};

export type GrantOptions = {
  readonly client: Pick<Client, "authorize" | "callback" | "revoke">;
  /** Deletes the stored token set for a DID (the sealed session store's `del`). */
  readonly dropTokenSet: (did: Did) => Promise<void>;
  readonly log: Logger;
};

const className = (cause: unknown): string => (cause instanceof Error && cause.name !== "" ? cause.name : "Error");

export function createGrant(options: GrantOptions): Grant {
  const { client, log } = options;
  return {
    async start(handle, nonce, deadline) {
      if (!BROWSER_NONCE.test(nonce)) throw new RangeError("grant.start: the nonce is not 32 bytes of base64url");
      const result = await authorize(client, handle, { appState: nonce, deadline, log });
      return result.ok ? { ok: true, url: result.url.href } : result;
    },
    async finish(query, nonce) {
      const result = await completeAuthorization(client, query, log);
      if (!result.ok) {
        // A refusal the server explains (consent denied, a page needed) is a failed sign-in here: no retry path yet.
        return result.reason === "interaction_required"
          ? { ok: false, reason: "failed" }
          : { ok: false, reason: result.reason };
      }
      // Another browser's callback (a sign-in CSRF), or one this code did not start: the grant is not kept.
      if (typeof result.appState !== "string" || !BROWSER_NONCE.test(nonce) || !sameNonce(result.appState, nonce)) {
        log.warn("oauth.callback_failed", { kind: "app_state" });
        await result.revoke();
        return { ok: false, reason: "state_mismatch" };
      }
      if (!grantCovers(result.scope).ok) {
        log.warn("pds.scope_missing");
        await result.revoke();
        return { ok: false, reason: "scope_missing" };
      }
      return { ok: true, did: result.did };
    },
    async end(did, deadline) {
      try {
        // oauth-client 0.9.3 `revoke` (dist/oauth-client.js): calls the revocation endpoint, then deletes the set.
        await withRevokeTimeout(client.revoke(did), deadline);
      } catch (cause) {
        log.warn("oauth.revoke_failed", { kind: className(cause) });
        await options.dropTokenSet(did);
      }
    },
  };
}
