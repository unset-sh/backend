// The scope the OAuth client asks for and the grant a sign-in needs (P2.04; plan §3). This slice asks for `atproto`
// and write access to our profile record, written out (`repo:sh.unset.profile`): a permission set (`include:`) must
// resolve on the network, and our lexicons are not published yet. Coverage is decided by the pinned
// @atproto/oauth-scopes 0.5.14 matcher (`ScopePermissions`), never by comparing strings.
import { ScopePermissions } from "@atproto/oauth-scopes";

/** Our profile record's collection. */
export const PROFILE_NSID = "sh.unset.profile";

/** What the client requests and declares in its metadata. */
export const SCOPE = `atproto repo:${PROFILE_NSID}`;

type Requirement = { readonly scope: string; readonly granted: (permissions: ScopePermissions) => boolean };
const repoWrite = (collection: string): Requirement[] =>
  (["create", "update", "delete"] as const).map((action) => ({
    scope: `repo:${collection}?action=${action}`,
    granted: (permissions) => permissions.allowsRepo({ collection, action }),
  }));

/** The least a grant must hold to start a session: atproto, and writing our own profile record. */
const REQUIRED_GRANT: readonly Requirement[] = [
  { scope: "atproto", granted: (permissions) => permissions.scopes.has("atproto") },
  ...repoWrite(PROFILE_NSID),
];

/** Whether `granted` (the token response's scope) holds REQUIRED_GRANT. */
export function grantCovers(granted: string): { ok: true } | { ok: false; missing: string[] } {
  const permissions = new ScopePermissions(granted.split(" ").filter((token) => token !== ""));
  const missing = REQUIRED_GRANT.filter((requirement) => !requirement.granted(permissions)).map((r) => r.scope);
  return missing.length === 0 ? { ok: true } : { ok: false, missing };
}
