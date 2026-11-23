// The egress guard (plan §2 rule 13): the single egress classifier. Every caller-influenced outbound connection
// resolves and vets its host here and connects only to a vetted address (dependency-cruiser keeps raw network access
// inside this folder).
export { type Classification, classifyAddress, isInternalName } from "./classify.ts";
export { resolveTxt, type TxtOptions, type TxtResolver } from "./dns.ts";
export { type Fetch, type FetchDefaults, guardedFetch, libraryFetch } from "./libraryFetch.ts";
export {
  atproto,
  atprotoBlobUpload,
  DEFAULT_REQUEST_BYTES,
  internalPolicy,
  type Policy,
  plc,
  REQUEST_BODY_CEILING,
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
  type ResolveOptions,
  resolveVetted,
} from "./resolve.ts";
