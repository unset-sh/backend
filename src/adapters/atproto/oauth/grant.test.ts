// grant.ts: what sign-in and sign-out see of the OAuth client. A callback is accepted only for the browser and the
// account that started it; a wrong scope is revoked, a mismatch names its grant for the caller to end once it is
// the last; ending a grant leaves no token set even when the revocation fails.
import { describe, expect, test } from "bun:test";
import type { Did } from "../../../domains/identity/index.ts";
import type { Logger } from "../../../shared/log/index.ts";
import { createGrant, type GrantOptions, type SignInScopes } from "./grant.ts";

const DID = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa" as Did;
const OTHER_DID = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb" as Did;
/** The nonce the browser that started the sign-in holds, and another browser's. */
const NONCE = `${"A".repeat(42)}Q`;
const OTHER_NONCE = `${"B".repeat(42)}Q`;
const log: Logger = { info: () => undefined, warn: () => undefined, error: () => undefined, logError: () => undefined };
/** Scopes that run their work at once (sign-in-lock.test.ts covers the real ones), recording which ran. */
const held: string[] = [];
const scopes: SignInScopes = {
  during: (fn) => fn(),
  exclusive: (did, fn) => {
    held.push(did);
    return fn();
  },
};

/** The appState a sign-in for `did` from the browser holding `nonce` seals (grant.ts `sealState`). */
const sealed = (nonce: string, did: Did = DID) => JSON.stringify({ v: 1, nonce, did });
/** The handle resolves to DID. */
const resolveHandle: GrantOptions["resolveHandle"] = async () => ({ status: "found", did: DID, via: "dns" });
const deps = { dropTokenSet: async () => undefined, scopes, resolveHandle, log };

/** A library client whose callback answers `state` and `scope`, recording revocations. */
function client(state: string | null, scope: string) {
  const revoked: string[] = [];
  const session = {
    did: DID,
    serverMetadata: { issuer: "https://pds.example" },
    getTokenInfo: async () => ({ scope }),
    signOut: async () => {
      revoked.push("callback");
    },
  };
  const fake = {
    authorize: async () => new URL("https://pds.example/authorize"),
    callback: async () => ({ session, state }),
    revoke: async () => {
      revoked.push("revoke");
    },
  } as unknown as GrantOptions["client"];
  return { fake, revoked };
}

describe("grant", () => {
  test("finish_returns_the_did_for_the_full_scope", async () => {
    const { fake, revoked } = client(sealed(NONCE), "atproto repo:sh.unset.profile");
    const grant = createGrant({ client: fake, ...deps });
    expect(await grant.finish(new URLSearchParams("code=c"), NONCE)).toEqual({ ok: true, did: DID });
    expect(revoked).toEqual([]);
  });

  test("finish_revokes_a_grant_missing_the_profile_scope", async () => {
    const { fake, revoked } = client(sealed(NONCE), "atproto");
    const grant = createGrant({ client: fake, ...deps });
    expect(await grant.finish(new URLSearchParams("code=c"), NONCE)).toEqual({ ok: false, reason: "scope_missing" });
    expect(revoked).toEqual(["callback"]);
  });

  test("finish_refuses_a_sign_in_another_browser_started_without_revoking", async () => {
    // Sign-in CSRF: the callback is real, but its nonce is not the one this browser holds. No session, and the grant
    // stays: the library put it in place of that account's token set, which its other sessions ride on.
    for (const [stored, nonce] of [
      [sealed(OTHER_NONCE), NONCE],
      [sealed(NONCE), OTHER_NONCE],
      ["web", NONCE],
      [NONCE, NONCE],
      [JSON.stringify({ v: 2, nonce: NONCE, did: DID }), NONCE],
      [JSON.stringify({ v: 1, nonce: NONCE, did: "alice" }), NONCE],
      [sealed(NONCE), "short"],
      [sealed(NONCE), `${NONCE}A`],
    ] as const) {
      const { fake, revoked } = client(stored, "atproto repo:sh.unset.profile");
      const grant = createGrant({ client: fake, ...deps });
      expect(await grant.finish(new URLSearchParams("code=c"), nonce)).toEqual({
        ok: false,
        reason: "state_mismatch",
        stray: DID,
      });
      expect(revoked).toEqual([]);
    }
  });

  test("finish_refuses_another_account_than_the_handle_named", async () => {
    // The member typed a handle for OTHER_DID, then picked DID at the server's chooser.
    const { fake, revoked } = client(sealed(NONCE, OTHER_DID), "atproto repo:sh.unset.profile");
    const grant = createGrant({ client: fake, ...deps });
    expect(await grant.finish(new URLSearchParams("code=c"), NONCE)).toEqual({
      ok: false,
      reason: "account_mismatch",
      stray: DID,
    });
    expect(revoked).toEqual([]);
  });

  test("start_seals_the_nonce_and_the_handle's_did_and_refuses_a_malformed_nonce", async () => {
    let seen: unknown;
    const fake = {
      authorize: async (_handle: string, options: { state?: string }) => {
        seen = options.state;
        return new URL("https://pds.example/authorize?request_uri=urn%3Aexample");
      },
    } as unknown as GrantOptions["client"];
    const grant = createGrant({ client: fake, ...deps });
    expect((await grant.start("alice.example.com", NONCE, AbortSignal.timeout(1000))).ok).toBe(true);
    expect(seen).toBe(sealed(NONCE));
    expect(grant.start("alice.example.com", "web", AbortSignal.timeout(1000))).rejects.toThrow(RangeError);
  });

  test("start_refuses_a_handle_that_names_no_account_before_asking_a_server", async () => {
    let asked = 0;
    const fake = {
      authorize: async () => {
        asked += 1;
        return new URL("https://pds.example/authorize?request_uri=urn%3Aexample");
      },
    } as unknown as GrantOptions["client"];
    const answers: Record<string, Awaited<ReturnType<GrantOptions["resolveHandle"]>>> = {
      "gone.example.com": { status: "not_found" },
      "slow.example.com": { status: "unavailable" },
    };
    const grant = createGrant({
      client: fake,
      ...deps,
      resolveHandle: async (handle) => answers[handle] ?? { status: "not_found" },
    });
    const start = (handle: string) => grant.start(handle, NONCE, AbortSignal.timeout(1000));
    expect(await start("gone.example.com")).toEqual({ ok: false, reason: "handle_not_found" });
    expect(await start("slow.example.com")).toEqual({ ok: false, reason: "identity_unavailable" });
    expect(await start("not a handle")).toEqual({ ok: false, reason: "handle_not_found" });
    expect(asked).toBe(0);
  });

  test("end_if_last_revokes_only_when_no_session_remains", async () => {
    const revoked: string[] = [];
    const fake = { revoke: async (did: string) => void revoked.push(did) } as unknown as GrantOptions["client"];
    const grant = createGrant({ client: fake, ...deps });
    held.length = 0;
    await grant.endIfLast(DID, async () => 1, AbortSignal.timeout(1000));
    expect(revoked).toEqual([]);
    await grant.endIfLast(DID, async () => 0, AbortSignal.timeout(1000));
    expect(revoked).toEqual([DID]);
    // Both counts ran under the account's own lock.
    expect(held).toEqual([DID, DID]);
  });

  test("end_if_last_ends_the_grant_when_the_lock_or_count_fails", async () => {
    const revoked: string[] = [];
    const fake = { revoke: async (did: string) => void revoked.push(did) } as unknown as GrantOptions["client"];
    const broken: SignInScopes = { during: (fn) => fn(), exclusive: async () => Promise.reject(new Error("timeout")) };
    const lockless = createGrant({ client: fake, ...deps, scopes: broken });
    await lockless.endIfLast(DID, async () => 1, AbortSignal.timeout(1000));
    const countless = createGrant({ client: fake, ...deps });
    await countless.endIfLast(DID, async () => Promise.reject(new Error("db down")), AbortSignal.timeout(1000));
    expect(revoked).toEqual([DID, DID]);
  });

  test("end_drops_the_token_set_when_the_revoke_fails", async () => {
    const dropped: Did[] = [];
    const failing = {
      revoke: async () => Promise.reject(new Error("unreachable")),
    } as unknown as GrantOptions["client"];
    const grant = createGrant({ client: failing, ...deps, dropTokenSet: async (did) => void dropped.push(did) });
    await grant.end(DID, AbortSignal.timeout(1000));
    expect(dropped).toEqual([DID]);
  });

  test("end_throws_when_the_token_set_may_remain", async () => {
    const failing = {
      revoke: async () => Promise.reject(new Error("unreachable")),
    } as unknown as GrantOptions["client"];
    const grant = createGrant({
      client: failing,
      dropTokenSet: async () => Promise.reject(new Error("db down")),
      scopes,
      resolveHandle,
      log,
    });
    await expect(grant.end(DID, AbortSignal.timeout(1000))).rejects.toThrow("db down");
  });
});
