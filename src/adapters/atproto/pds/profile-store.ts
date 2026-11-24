// The profile domain's ProfileStore over the member's own repo: the PDS call (pds-call.ts) for the transport, the
// profile record helpers for the read and the compare-and-swap write. Each operation gets its own deadline, so a slow
// PDS answers `pds_unreachable` instead of holding the request; the session restored for it is reused for the write.
import type { Did } from "../../../domains/identity/index.ts";
import type { ProfileStore, StoreFailure } from "../../../domains/profile/operations.ts";
import type { PdsContext, PdsResult } from "./pds-call.ts";
import { loadProfileRecord, saveProfileRecord } from "./profile-record.ts";
import type { PdsCall } from "./repo-record.ts";

/** How long one profile operation may take, read and write together. */
export const PROFILE_OPERATION_MS = 15_000;

function context(ms: number): PdsContext {
  return { memo: new Map(), deadline: AbortSignal.timeout(ms), deadlineAt: performance.now() + ms };
}

function failureOf(result: Exclude<PdsResult<unknown>, { kind: "ok" }>): StoreFailure {
  switch (result.kind) {
    case "transient":
      return "pds_unreachable";
    case "auth_dead":
      return "session_ended";
    case "scope_missing":
      return "scope_missing";
    case "rejected":
      return "failed";
  }
}

export function createProfileStore(pdsCall: PdsCall, operationMs = PROFILE_OPERATION_MS): ProfileStore {
  return {
    async load(did: Did) {
      const result = await loadProfileRecord(pdsCall, context(operationMs), did);
      if (result.kind !== "ok") return { ok: false, failure: failureOf(result) };
      return { ok: true, value: result.value === null ? null : result.value.value };
    },
    async save(did, build) {
      const result = await saveProfileRecord(pdsCall, context(operationMs), did, build);
      if (result.kind !== "ok") return { ok: false, failure: failureOf(result) };
      const outcome = result.value;
      if (outcome.kind === "conflict") return { ok: false, failure: "conflict" };
      if (outcome.kind === "refused") return { ok: false, code: outcome.code };
      return { ok: true };
    },
  };
}
