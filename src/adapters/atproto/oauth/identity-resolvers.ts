// The OAuth library's identity resolvers over the identity domain (P2.04; P2.01 step C), so a login resolves handles and
// DIDs exactly as the rest of the app does: the domain's checks, its cache, its fail-closed outcomes and the egress
// guard under it. @atproto/oauth-client 0.9.3 takes a `handleResolver` (`resolve(handle) -> did | null`) and a
// `didResolver` (`resolve(did) -> DID document`) through CreateIdentityResolverOptions
// (@atproto-labs/identity-resolver dist/create-identity-resolver.d.ts). "Could not tell" throws, so an outage never
// reads as "no such handle". Accounts on any PDS sign in (Alex, 2026-11-23: "any pds is fine").
import {
  type AtprotoDid,
  type AtprotoIdentityDidMethods,
  type DidResolver,
  isAtprotoDid,
  type Did as LibraryDid,
  type ResolveDidOptions,
  type ResolvedDocument,
} from "@atproto/oauth-client";
import {
  type Consistency,
  type Did,
  IdentityError,
  type IdentityNetwork,
  parseDid,
  parseHandle,
  type ResolvedDid,
  resolveHandle,
} from "../../../domains/identity/index.ts";

type ResolveDid = (did: Did, consistency: Consistency) => Promise<ResolvedDid>;

/** A DID the library accepts (did:plc or did:web, its blessed methods); the domain allows no other, so this never throws today. */
function atprotoDid(did: Did): AtprotoDid {
  if (!isAtprotoDid(did)) throw new IdentityError("invalid_doc");
  return did;
}

export function handleResolverForOAuth(network: IdentityNetwork) {
  return {
    async resolve(input: string): Promise<AtprotoDid | null> {
      const handle = parseHandle(input);
      if (handle === null) return null;
      const found = await resolveHandle(network, handle);
      if (found.status === "found") return atprotoDid(found.did);
      if (found.status === "not_found") return null;
      throw new IdentityError("unavailable");
    },
  };
}

/**
 * The document the library reads, rebuilt from what the domain checked: the id, the PDS service and `alsoKnownAs`,
 * which the library compares with the handle it was given (the one accepted exception to "only verifyHandle reads
 * alsoKnownAs"). An unusable PDS endpoint means no service, so the login fails. The library checks the token's `sub`
 * against this document's PDS and that PDS's authorization server (oauth-client 0.9.3 dist/oauth-server-agent.js).
 */
export function didResolverForOAuth(resolveDid: ResolveDid): DidResolver<AtprotoIdentityDidMethods> {
  return {
    async resolve<D extends LibraryDid>(input: D, options?: ResolveDidOptions) {
      const did = parseDid(input);
      if (did === null) throw new IdentityError("invalid_doc");
      const resolved = await resolveDid(did, {
        consistency: "fresh",
        ...(options?.signal ? { signal: options.signal } : {}),
      });
      const service =
        resolved.pds === null
          ? []
          : [{ id: "#atproto_pds", type: "AtprotoPersonalDataServer", serviceEndpoint: resolved.pds.origin }];
      const document = { id: atprotoDid(resolved.did), alsoKnownAs: [...resolved.rawAlsoKnownAs], service };
      // The library types the result by the DID asked for; the document's id is that DID, checked by the domain.
      return document as ResolvedDocument<D, AtprotoIdentityDidMethods>;
    },
  };
}
