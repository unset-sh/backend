// The one atproto OAuth client (P2.04; plan §2 rules 3, 6, §3, §5.3 "OAuth client"), on the runtime-neutral
// @atproto/oauth-client 0.9.3 (org-0015: not NodeOAuthClient). DPoP-bound tokens; state and token sets live in the
// sealed Postgres stores (src/adapters/postgres/oauthStores.ts); a refresh is serialised across replicas by the
// advisory lock; every request goes through the egress guard; identities resolve through the identity domain
// (identity-resolvers.ts). Constructor options: dist/oauth-client.d.ts `OAuthClientOptions` at 0.9.3.
//
// This slice is the atproto loopback client (https://atproto.com/specs/oauth, "Localhost Client Development"): a
// public client with no key, for a stack on 127.0.0.1. The confidential `private_key_jwt` client production needs is
// out of scope: it needs a key only Alex places.
import { JoseKey } from "@atproto/jwk-jose";
import {
  type InternalStateData,
  type Key,
  OAuthClient,
  type RuntimeImplementation,
  type RuntimeLock,
  type Session,
  TokenInvalidError,
  TokenRefreshError,
  TokenRevokedError,
} from "@atproto/oauth-client";
import { buildAtprotoLoopbackClientMetadata } from "@atproto/oauth-types";
import type { Consistency, Did, IdentityNetwork, ResolvedDid } from "../../../domains/identity/index.ts";
import type { Logger } from "../../../shared/log/index.ts";
import type { Fetch } from "../../egress/index.ts";
import { didResolverForOAuth, handleResolverForOAuth } from "./identity-resolvers.ts";
import { SCOPE } from "./scopes.ts";

/** A private JWK as the library writes one (`Key.privateJwk`); read back with JoseKey.fromJWK. */
type PrivateJwk = Readonly<Record<string, unknown>>;
/** What the state store keeps: the library's state with its DPoP key as a private JWK, so it can be sealed as JSON. */
export type SavedState = Omit<InternalStateData, "dpopKey"> & { readonly dpopJwk: PrivateJwk };
/** What the session store keeps: the token set and auth method, the DPoP key as a private JWK. */
export type SavedSession = Omit<Session, "dpopKey"> & { readonly dpopJwk: PrivateJwk };

/** A get/set/del store, as the sealed stores implement it. */
export type SavedStore<V> = {
  get(key: string, options?: { readonly signal?: AbortSignal }): Promise<V | undefined>;
  set(key: string, value: V): Promise<void>;
  del(key: string): Promise<void>;
};

/** The key's private JWK; a key without one (never the library's DPoP key) is a programming error. */
function privateJwkOf(key: Key): PrivateJwk {
  const jwk = key.privateJwk;
  if (jwk === undefined) throw new TypeError("DPoP key has no private part");
  return jwk;
}

/** A store of library values over a store of JSON-safe ones: the DPoP key crosses as a JWK. */
function withJwk<V extends { dpopKey: Key }, S extends { dpopJwk: PrivateJwk }>(
  store: SavedStore<S>,
): {
  get(key: string, options?: { signal?: AbortSignal }): Promise<V | undefined>;
  set(key: string, value: V): Promise<void>;
  del(key: string): Promise<void>;
} {
  return {
    async get(key, options) {
      const saved = await store.get(key, options);
      if (saved === undefined) return undefined;
      const { dpopJwk, ...rest } = saved;
      return { ...rest, dpopKey: await JoseKey.fromJWK(dpopJwk as Record<string, unknown>) } as unknown as V;
    },
    async set(key, value) {
      const { dpopKey, ...rest } = value;
      await store.set(key, { ...rest, dpopJwk: privateJwkOf(dpopKey) } as unknown as S);
    },
    del: (key) => store.del(key),
  };
}

/** WebCrypto's name for each digest the library asks for (dist/runtime-implementation.d.ts `DigestAlgorithm`). */
const DIGEST = { sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" } as const;

/** Keys from @atproto/jwk-jose, randomness and digests from WebCrypto, and the cross-replica lock. */
export function runtimeImplementation(requestLock: RuntimeLock): RuntimeImplementation {
  return {
    createKey: (algs) => JoseKey.generate(algs),
    getRandomValues: (length) => crypto.getRandomValues(new Uint8Array(length)),
    digest: async (data, alg) => new Uint8Array(await crypto.subtle.digest(DIGEST[alg.name], data)),
    requestLock,
  };
}

/** The loopback client's metadata: our scope, and web's callback as the one redirect. */
export function clientMetadata(redirectUri: string) {
  return buildAtprotoLoopbackClientMetadata({ scope: SCOPE, redirect_uris: [redirectUri] });
}

/** Why the library dropped a token set, as one fixed word for the log line. */
function deletedBecause(cause: unknown): "revoked" | "refresh_failed" | "invalid" | "other" {
  if (cause instanceof TokenRevokedError) return "revoked";
  if (cause instanceof TokenRefreshError) return "refresh_failed";
  if (cause instanceof TokenInvalidError) return "invalid";
  return "other";
}

export type OAuthClientOptions = {
  /** Web's public callback, `http://127.0.0.1:<port>/auth/callback` for the loopback client. */
  readonly redirectUri: string;
  readonly stateStore: SavedStore<SavedState>;
  readonly sessionStore: SavedStore<SavedSession>;
  /** The advisory lock (src/adapters/postgres/lock.ts createRequestLock), so two replicas never spend one refresh. */
  readonly requestLock: RuntimeLock;
  /** The egress guard's libraryFetch: the `atproto` policy. */
  readonly fetch: Fetch;
  readonly network: IdentityNetwork;
  readonly resolveDid: (did: Did, consistency: Consistency) => Promise<ResolvedDid>;
  readonly log: Logger;
};

/** A cache that never holds anything, so every identity lookup reaches the domain's resolvers. */
const NO_CACHE = {
  get: async () => undefined,
  set: async () => undefined,
  del: async () => undefined,
};

/**
 * Builds the client. The library fires `onSessionDeleted` on every callback (it revokes the previous set first, even
 * when there was none) and on sign-out, so the hook writes nothing and ends no app session: that would sign a member
 * out of every other browser at each login (P2.04 step 7). It logs the reason word only.
 */
export function createOAuthClient(options: OAuthClientOptions) {
  const onSessionDeleted = (_sub: string, cause: unknown): void => {
    options.log.info("oauth.session_deleted", { reason: deletedBecause(cause) });
  };
  const client = new OAuthClient({
    responseMode: "query",
    clientMetadata: clientMetadata(options.redirectUri),
    stateStore: withJwk<InternalStateData, SavedState>(options.stateStore),
    sessionStore: withJwk<Session, SavedSession>(options.sessionStore),
    runtimeImplementation: runtimeImplementation(options.requestLock),
    // The library's Fetch type is Bun's `typeof fetch`, which adds `preconnect`; no @atproto package calls it, and a
    // preconnect would open a socket outside the guard, so it does nothing here.
    fetch: Object.assign((input: string | URL | Request, init?: RequestInit) => options.fetch(input, init), {
      preconnect: () => undefined,
    }),
    handleResolver: handleResolverForOAuth(options.network),
    didResolver: didResolverForOAuth(options.resolveDid),
    // No library cache in front of ours: by default it keeps DID documents an hour and handles ten minutes, longer
    // than atproto.com/specs/oauth allows for auth and past our own "fresh" lookup (ADR 0021 §3).
    didCache: NO_CACHE,
    handleCache: NO_CACHE,
    allowHttp: false,
    onSessionDeleted,
  });
  return { client, onSessionDeleted };
}
