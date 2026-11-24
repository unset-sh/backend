// The member's atproto grant, as sign-in and sign-out use it: start an authorization, complete it, and end it. It is the
// one thing the Better Auth `atproto` plugin (src/adapters/auth/) knows of the OAuth client, so the plugin holds no
// @atproto type and this file holds no Better Auth one.
import { timingSafeEqual } from "node:crypto";
import { type Did, type HandleResolution, parseDid, parseHandle } from "../../../domains/identity/index.ts";
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

/**
 * What a sign-in seals in the library's appState: the browser's nonce and the DID the typed handle named, so the
 * callback accepts only that browser and only that account (the old app's appState, sign-in-state.ts `appStateOf`).
 */
type SignInState = { readonly nonce: string; readonly did: Did };

const sealState = (state: SignInState): string => JSON.stringify({ v: 1, nonce: state.nonce, did: state.did });

/** The state `sealState` wrote, or null for anything else (an older sign-in's fixed value included). */
function openState(text: string | null): SignInState | null {
  let value: unknown;
  try {
    value = JSON.parse(text ?? "");
  } catch {
    return null;
  }
  if (typeof value !== "object" || value === null) return null;
  const { v, nonce, did } = value as Record<string, unknown>;
  if (v !== 1 || typeof nonce !== "string" || !BROWSER_NONCE.test(nonce) || typeof did !== "string") return null;
  const parsed = parseDid(did);
  return parsed === null ? null : { nonce, did: parsed };
}

/** Equal nonces, compared in constant time. */
function sameNonce(a: string, b: string): boolean {
  const [x, y] = [Buffer.from(a), Buffer.from(b)];
  return x.length === y.length && timingSafeEqual(x, y);
}

export type StartResult =
  | { readonly ok: true; readonly url: string }
  | { readonly ok: false; readonly reason: AuthorizeFailure };
export type FinishFailure = CallbackFailure | "scope_missing" | "state_mismatch" | "account_mismatch";
export type FinishResult =
  | { readonly ok: true; readonly did: Did }
  /**
   * A callback that is not this browser's, or not for the account it typed. The server's grant for `stray` is kept,
   * since the library put it in place of that account's token set, which its other sessions ride on; the caller
   * ends it with `endIfLast` once the sign-in's scope is over.
   */
  | { readonly ok: false; readonly reason: "state_mismatch" | "account_mismatch"; readonly stray: Did }
  | { readonly ok: false; readonly reason: Exclude<FinishFailure, "state_mismatch" | "account_mismatch"> };

export type Grant = {
  /** The authorization server's URL for `handle`, where web sends the browser, bound to `nonce` (BROWSER_NONCE). */
  start(handle: string, nonce: string, deadline: AbortSignal): Promise<StartResult>;
  /**
   * The DID the server vouched for, with its token set stored, only when `nonce` is the one the sign-in started with
   * and the DID is the one its handle named. A wrong scope is revoked; a mismatch names its stray grant.
   */
  finish(query: URLSearchParams, nonce: string): Promise<FinishResult>;
  /**
   * Runs a whole sign-in, from `finish` to its session row, holding the account's lock (sign-in-lock.ts `during`):
   * the library's delete of the old token set waits for the new one and is dropped, so the account's other sessions
   * stay, and a last browser's sign-out cannot revoke the new set before its session exists.
   */
  signingIn<T>(fn: () => Promise<T>): Promise<T>;
  /**
   * After one browser's session ended: under the account's lock, ends the grant only when `remaining` counts no live
   * session of `did`. If the lock or the count fails, the grant is ended anyway, so none outlives its last session.
   */
  endIfLast(did: Did, remaining: () => Promise<number>, deadline: AbortSignal): Promise<void>;
  /**
   * Revokes the grant and deletes its token set, which ends every session on it (migration 0007). When the revoke
   * fails or runs out of time, the token set is deleted here; only when that also fails does this throw.
   */
  end(did: Did, deadline: AbortSignal): Promise<void>;
};

/** The sign-in lock's scopes (sign-in-lock.ts), whose `tokenSets` and `requestLock` the client was built with. */
export type SignInScopes = {
  readonly during: <T>(fn: () => Promise<T>) => Promise<T>;
  readonly exclusive: <T>(did: string, fn: () => Promise<T>) => Promise<T>;
};

export type GrantOptions = {
  readonly client: Pick<Client, "authorize" | "callback" | "revoke">;
  /** Deletes the stored token set for a DID (the sealed session store's `del`). */
  readonly dropTokenSet: (did: Did) => Promise<void>;
  readonly scopes: SignInScopes;
  /** The identity domain's `resolveHandle`, so the callback knows which account the typed handle named. */
  readonly resolveHandle: (handle: string) => Promise<HandleResolution>;
  readonly log: Logger;
};

const className = (cause: unknown): string => (cause instanceof Error && cause.name !== "" ? cause.name : "Error");

export function createGrant(options: GrantOptions): Grant {
  const { client, log } = options;
  async function end(did: Did, deadline: AbortSignal): Promise<void> {
    try {
      // oauth-client 0.9.3 `revoke` (dist/oauth-client.js): calls the revocation endpoint, then deletes the set.
      await withRevokeTimeout(client.revoke(did), deadline);
    } catch (cause) {
      log.warn("oauth.revoke_failed", { kind: className(cause) });
      await options.dropTokenSet(did);
    }
  }
  return {
    async start(handle, nonce, deadline) {
      if (!BROWSER_NONCE.test(nonce)) throw new RangeError("grant.start: the nonce is not 32 bytes of base64url");
      // Resolved here as well as in the library, as the old app did (sign-in.ts `chooseAccount`): the library checks
      // that the DID document claims the handle, and the callback refuses any other account the server sends back.
      if (parseHandle(handle) === null) return { ok: false, reason: "handle_not_found" };
      const found = await options.resolveHandle(handle);
      if (found.status === "not_found") return { ok: false, reason: "handle_not_found" };
      if (found.status === "unavailable") return { ok: false, reason: "identity_unavailable" };
      const appState = sealState({ nonce, did: found.did });
      const result = await authorize(client, handle, { appState, deadline, log });
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
      // Another browser's callback (a sign-in CSRF), or one this code did not start: no session. The grant stays for
      // now, as in the old app (oauth-callback.ts): it replaced that account's token set, which other sessions use.
      const state = openState(result.appState);
      if (state === null || !BROWSER_NONCE.test(nonce) || !sameNonce(state.nonce, nonce)) {
        log.warn("oauth.callback_failed", { kind: "app_state" });
        return { ok: false, reason: "state_mismatch", stray: result.did };
      }
      // The server signed in another account than the handle named (its chooser let the member switch).
      if (result.did !== state.did) {
        log.warn("oauth.callback_failed", { kind: "account_mismatch" });
        return { ok: false, reason: "account_mismatch", stray: result.did };
      }
      if (!grantCovers(result.scope).ok) {
        log.warn("pds.scope_missing");
        await result.revoke();
        return { ok: false, reason: "scope_missing" };
      }
      return { ok: true, did: result.did };
    },
    signingIn: (fn) => options.scopes.during(fn),
    async endIfLast(did, remaining, deadline) {
      try {
        await options.scopes.exclusive(did, async () => {
          if ((await remaining()) === 0) await end(did, deadline);
        });
      } catch (cause) {
        // The old app's review F13: a failed lock or count must not leave a grant with no session.
        log.warn("oauth.revoke_failed", { kind: className(cause) });
        await end(did, deadline);
      }
    },
    end,
  };
}
