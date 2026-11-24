// P2.04 (scopes.ts): what the client asks for and what a sign-in must have been granted.
import { describe, expect, test } from "bun:test";
import { isAtprotoOauthScope } from "@atproto/oauth-scopes";
import { grantCovers, SCOPE } from "./scopes.ts";

describe("scopes", () => {
  test("scopes_parse_all", () => {
    // An authorization server drops a token it cannot parse without an error (@atproto/oauth-provider
    // request-manager.ts), so a token the pinned parser refuses would silently never be granted.
    expect(SCOPE.split(" ").filter((token) => !isAtprotoOauthScope(token))).toEqual([]);
    expect(SCOPE).not.toMatch(/transition:|include:|account:email/);
  });

  test("grantCovers_what_we_ask_for", () => {
    expect(grantCovers(SCOPE)).toEqual({ ok: true });
  });

  test("grantCovers_missing_atproto_and_writes", () => {
    expect(grantCovers("repo:sh.unset.profile?action=create")).toEqual({
      ok: false,
      missing: ["atproto", "repo:sh.unset.profile?action=update", "repo:sh.unset.profile?action=delete"],
    });
  });

  test("grantCovers_another_collection_grants_nothing", () => {
    expect(grantCovers("atproto repo:sh.unset.card")).toMatchObject({ ok: false });
    expect(grantCovers("")).toMatchObject({ ok: false });
  });
});
