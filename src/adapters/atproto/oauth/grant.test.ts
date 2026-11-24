// grant.ts: what sign-in and sign-out see of the OAuth client. Every refusal after the library stored a token set
// revokes it, and ending a grant leaves no token set even when the revocation fails.
import { describe, expect, test } from "bun:test";
import type { Did } from "../../../domains/identity/index.ts";
import type { Logger } from "../../../shared/log/index.ts";
import { createGrant, type GrantOptions } from "./grant.ts";

const DID = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa" as Did;
const log: Logger = { info: () => undefined, warn: () => undefined, error: () => undefined, logError: () => undefined };

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
    const { fake, revoked } = client("web", "atproto repo:sh.unset.profile");
    const grant = createGrant({ client: fake, dropTokenSet: async () => undefined, log });
    expect(await grant.finish(new URLSearchParams("code=c"))).toEqual({ ok: true, did: DID });
    expect(revoked).toEqual([]);
  });

  test("finish_revokes_a_grant_missing_the_profile_scope", async () => {
    const { fake, revoked } = client("web", "atproto");
    const grant = createGrant({ client: fake, dropTokenSet: async () => undefined, log });
    expect(await grant.finish(new URLSearchParams("code=c"))).toEqual({ ok: false, reason: "scope_missing" });
    expect(revoked).toEqual(["callback"]);
  });

  test("finish_revokes_a_sign_in_this_code_did_not_start", async () => {
    const { fake, revoked } = client("other", "atproto repo:sh.unset.profile");
    const grant = createGrant({ client: fake, dropTokenSet: async () => undefined, log });
    expect(await grant.finish(new URLSearchParams("code=c"))).toEqual({ ok: false, reason: "failed" });
    expect(revoked).toEqual(["callback"]);
  });

  test("end_drops_the_token_set_when_the_revoke_fails", async () => {
    const dropped: Did[] = [];
    const failing = {
      revoke: async () => Promise.reject(new Error("unreachable")),
    } as unknown as GrantOptions["client"];
    const grant = createGrant({ client: failing, dropTokenSet: async (did) => void dropped.push(did), log });
    await grant.end(DID, AbortSignal.timeout(1000));
    expect(dropped).toEqual([DID]);
  });

  test("end_throws_when_the_token_set_may_remain", async () => {
    const failing = {
      revoke: async () => Promise.reject(new Error("unreachable")),
    } as unknown as GrantOptions["client"];
    const grant = createGrant({ client: failing, dropTokenSet: async () => Promise.reject(new Error("db down")), log });
    await expect(grant.end(DID, AbortSignal.timeout(1000))).rejects.toThrow("db down");
  });
});
