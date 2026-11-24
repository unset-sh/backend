// The profile operations the internal API offers the signed-in member: read their profile, and set their display
// name. The record lives in the member's own repo, reached through the ProfileStore port (src/adapters/atproto/pds
// implements it over their OAuth session); the handle is the one identity verified both ways, or none.
import type { Did } from "../identity/index.ts";
import {
  type ProfileError,
  type ProfileRecord,
  parseDisplayName,
  readDisplayName,
  withDisplayName,
} from "./profile.ts";

/** Why the member's repo could not be read or written. */
export type StoreFailure =
  /** The PDS could not be reached in time, or answered a server error. */
  | "pds_unreachable"
  /** The member's grant is gone (revoked or refresh failed), and with it every session on it. */
  | "session_ended"
  /** The grant does not cover the profile collection. */
  | "scope_missing"
  /** The PDS refused the call for another reason. */
  | "failed";

export type Built =
  | { readonly ok: true; readonly record: ProfileRecord }
  | { readonly ok: false; readonly code: ProfileError };

export type ProfileStore = {
  /** The stored record's value, or null when the member has none. */
  load(
    did: Did,
  ): Promise<{ readonly ok: true; readonly value: unknown } | { readonly ok: false; readonly failure: StoreFailure }>;
  /**
   * Reads the record, builds the new one from it and writes it back only if it has not changed since the read
   * (compare-and-swap at the PDS).
   */
  save(
    did: Did,
    build: (existing: unknown) => Built,
  ): Promise<
    | { readonly ok: true }
    | { readonly ok: false; readonly failure: StoreFailure | "conflict" }
    | { readonly ok: false; readonly code: ProfileError }
  >;
};

export type Profile = { readonly did: Did; readonly handle?: string; readonly displayName?: string };

export type ReadFailure = StoreFailure;
export type WriteFailure = StoreFailure | ProfileError | "conflict";

export type ProfilesOptions = {
  readonly store: ProfileStore;
  /** The member's handle when it verifies against their DID document, else undefined. Never throws. */
  readonly handleOf: (did: Did) => Promise<string | undefined>;
  /** An ISO 8601 time, for a first profile's createdAt. */
  readonly now: () => string;
};

export function createProfiles(options: ProfilesOptions) {
  const { store } = options;
  const profileOf = async (did: Did, value: unknown): Promise<Profile> => {
    const [handle, displayName] = [await options.handleOf(did), readDisplayName(value)];
    return {
      did,
      ...(handle === undefined ? {} : { handle }),
      ...(displayName === undefined ? {} : { displayName }),
    };
  };

  return {
    async get(did: Did): Promise<{ ok: true; profile: Profile } | { ok: false; reason: ReadFailure }> {
      const loaded = await store.load(did);
      if (!loaded.ok) return { ok: false, reason: loaded.failure };
      return { ok: true, profile: await profileOf(did, loaded.value) };
    },

    /** Sets the display name, or removes it when `raw` is empty after trimming. Every other field is kept. */
    async setDisplayName(
      did: Did,
      raw: unknown,
    ): Promise<{ ok: true; profile: Profile } | { ok: false; reason: WriteFailure }> {
      const parsed = parseDisplayName(raw);
      if (!parsed.ok) return { ok: false, reason: parsed.code };
      let written: unknown = null;
      const saved = await store.save(did, (existing) => {
        const built = withDisplayName(parsed.value, existing, options.now());
        if (built.ok) written = built.record;
        return built;
      });
      if (!saved.ok) return { ok: false, reason: "code" in saved ? saved.code : saved.failure };
      return { ok: true, profile: await profileOf(did, written) };
    },
  };
}

export type Profiles = ReturnType<typeof createProfiles>;
