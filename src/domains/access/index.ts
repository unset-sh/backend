// Who may do what (agent-kit org-0018): the port every operation asks before it acts. The application names the
// principal, the action and the resource with the facts backend read itself; the decision is made outside this
// process by the policies in policies/. Nothing here knows which engine decides.
import type { Did } from "../identity/index.ts";

/** Who is asking: a signed-in member by DID, or a caller with no session. Never a claim taken from the request. */
export type Principal = { readonly kind: "member"; readonly did: Did } | { readonly kind: "anonymous" };

/**
 * Each kind of resource, the actions it has, and the facts a policy may read. `ownerDid` is read from backend's own
 * data, never from the request. A new kind or attribute comes with the policy and tests that use it.
 */
export type Resources = {
  readonly profile: {
    readonly actions: "read" | "update";
    readonly attributes: { readonly ownerDid: Did };
  };
};
export type ResourceKind = keyof Resources;
export type Resource<K extends ResourceKind = ResourceKind> = {
  readonly kind: K;
  /** The resource's own id; for a profile, its owner's DID. */
  readonly id: string;
  readonly attributes: Resources[K]["attributes"];
};

/** `unavailable`: no decision could be had in time. It is never an allow; the caller refuses with 503. */
export type Decision = "allow" | "deny" | "unavailable";

export type Authorizer = {
  may<K extends ResourceKind>(
    principal: Principal,
    action: Resources[K]["actions"],
    resource: Resource<K>,
  ): Promise<Decision>;
  /** True when a decision can be had now. Never throws. */
  ready(): Promise<boolean>;
};

/** The principal for a session, or the anonymous one without. */
export const principalOf = (session: { readonly did: Did } | null): Principal =>
  session === null ? { kind: "anonymous" } : { kind: "member", did: session.did };

/** A member's own profile, the one resource the `/me/profile` routes act on. */
export const ownProfile = (did: Did): Resource<"profile"> => ({
  kind: "profile",
  id: did,
  attributes: { ownerDid: did },
});
