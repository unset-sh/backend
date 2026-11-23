// net-guard (plan §2 rule 13): the single egress classifier. Every caller-influenced outbound connection resolves and
// vets its host here and connects only to the pinned addresses (a CI guard sends all such traffic through this folder).
export { type Classification, classifyAddress, isInternalName } from "./classify.ts";
export { resolveTxt, type TxtOptions, type TxtResolver } from "./dns.ts";
export { type FetchDefaults, guardedFetch, libraryFetch, objectStoreFetch } from "./libraryFetch.ts";
export {
  atproto,
  atprotoBlobUpload,
  DEFAULT_REQUEST_BYTES,
  internalPolicy,
  OBJECT_STORE_BYTES,
  objectStore,
  type Policy,
  pdsAdmin,
  plc,
  REQUEST_BODY_CEILING,
  review,
} from "./policies.ts";
export type { AddressClass, Range } from "./ranges.ts";
export {
  createNetGuard,
  type EgressEvent,
  type GuardedRequest,
  type GuardedResponse,
  type NetGuard,
  type NetGuardSettings,
} from "./request.ts";
export {
  type LookupAnswer,
  type NetGuardCode,
  NetGuardError,
  pinnedLookup,
  type ResolveOptions,
  resolveVetted,
} from "./resolve.ts";
