// The internal API: the operations only web's server calls, over the private network (agent-kit org-0015, proposed).
// Its route schemas are the contract; scripts/openapi.ts writes them to api/internal/openapi.yaml. A public API, when
// there is one, is a separate group with its own contract, never added here.
import { Elysia, t } from "elysia";

/** A DID as the identity domain accepts it (src/domains/identity/syntax.ts), as the routes see one. */
type Did = string & { readonly __brand: "Did" };

/** What the sign-in operations need: the Unset session over Better Auth (src/adapters/auth/index.ts `Sessions`). */
export type SessionsPort = {
  start(handle: string): Promise<{ ok: true; url: string } | { ok: false; reason: StartFailure }>;
  complete(query: string): Promise<{ ok: true; sessionToken: string } | { ok: false; reason: CompleteFailure }>;
  current(headers: Headers): Promise<{ readonly did: Did | string } | null>;
  signOut(headers: Headers): Promise<"ok" | "no_session" | "failed">;
};

/** What the internal API needs from the rest of the process. Each operation adds the port it uses. */
export type InternalApiDeps = {
  /** True when every dependency a request needs can be reached now. Never throws. */
  readonly ready: () => Promise<boolean>;
  readonly sessions: SessionsPort;
  /** Web's origin: a request that carries a cookie must come from it (org-0015). */
  readonly webOrigin: string;
};

const START_FAILURES = [
  "handle_unverified",
  "handle_not_found",
  "identity_unavailable",
  "pds_unreachable",
  "failed",
] as const;
const COMPLETE_FAILURES = ["consent_denied", "expired", "pds_unreachable", "failed", "scope_missing"] as const;
type StartFailure = (typeof START_FAILURES)[number];
type CompleteFailure = (typeof COMPLETE_FAILURES)[number];

const closed = <P extends Parameters<typeof t.Object>[0]>(properties: P) =>
  t.Object(properties, { additionalProperties: false });
const oneOf = <const W extends readonly [string, ...string[]]>(words: W) => t.UnionEnum(words);

const Health = closed({ status: oneOf(["ok", "unavailable"]) });
const Problem = <const W extends readonly [string, ...string[]]>(words: W) => closed({ reason: oneOf(words) });
/** The longest handle (https://atproto.com/specs/handle). */
const SignInBody = closed({ handle: t.String({ minLength: 1, maxLength: 253 }) });
/** The callback URL's query exactly as the authorization server sent it, without the `?`. */
const CallbackBody = closed({ query: t.String({ minLength: 1, maxLength: 4096 }) });
const SessionToken = closed({ sessionToken: t.String({ minLength: 1 }) });
const SessionInfo = closed({ did: t.String({ minLength: 1 }) });

/** Status for each refusal: the member's input (400), or a server that could not be reached (503). */
const START_STATUS: Record<StartFailure, 400 | 502 | 503> = {
  handle_unverified: 400,
  handle_not_found: 400,
  identity_unavailable: 503,
  pds_unreachable: 503,
  failed: 502,
};
const COMPLETE_STATUS: Record<CompleteFailure, 400 | 502 | 503> = {
  consent_denied: 400,
  expired: 400,
  scope_missing: 400,
  pds_unreachable: 503,
  failed: 502,
};

export function internalApi(deps: InternalApiDeps) {
  const { sessions } = deps;
  return (
    new Elysia({ name: "internal-api" })
      // A cookie is a credential a browser attaches by itself, so a request carrying one must come from web's origin;
      // a bearer token is not, and web's server sends it with no Origin (org-0015; spike (c)). Better Auth makes the
      // same check on its own routes; this one covers every route here.
      .onBeforeHandle(({ request, status }) => {
        if (request.headers.has("cookie") && request.headers.get("origin") !== deps.webOrigin) {
          return status(403, { reason: "untrusted_origin" as const });
        }
      })
      .get(
        "/health",
        async ({ status }) =>
          (await deps.ready()) ? { status: "ok" as const } : status(503, { status: "unavailable" as const }),
        {
          response: { 200: Health, 503: Health },
          detail: { summary: "Readiness: whether backend can serve requests now", tags: ["operations"] },
        },
      )
      .post(
        "/auth/sign-in/atproto",
        async ({ body, status }) => {
          const result = await sessions.start(body.handle);
          return result.ok ? { url: result.url } : status(START_STATUS[result.reason], { reason: result.reason });
        },
        {
          parse: "json",
          body: SignInBody,
          response: {
            200: closed({ url: t.String({ format: "uri" }) }),
            400: Problem(START_FAILURES),
            403: Problem(["untrusted_origin"]),
            502: Problem(START_FAILURES),
            503: Problem(START_FAILURES),
          },
          detail: { summary: "Start a sign-in: the authorization server's URL for a handle", tags: ["auth"] },
        },
      )
      .post(
        "/auth/atproto/callback",
        async ({ body, status }) => {
          const result = await sessions.complete(body.query);
          return result.ok
            ? { sessionToken: result.sessionToken }
            : status(COMPLETE_STATUS[result.reason], { reason: result.reason });
        },
        {
          parse: "json",
          body: CallbackBody,
          response: {
            200: SessionToken,
            400: Problem(COMPLETE_FAILURES),
            403: Problem(["untrusted_origin"]),
            502: Problem(COMPLETE_FAILURES),
            503: Problem(COMPLETE_FAILURES),
          },
          detail: { summary: "Complete a sign-in from the callback query: a session token", tags: ["auth"] },
        },
      )
      .get(
        "/me/session",
        async ({ request, status }) => {
          const session = await sessions.current(request.headers);
          return session === null ? status(401, { reason: "no_session" as const }) : { did: session.did };
        },
        {
          response: { 200: SessionInfo, 401: Problem(["no_session"]), 403: Problem(["untrusted_origin"]) },
          detail: { summary: "The caller's session: whose it is", tags: ["auth"] },
        },
      )
      .post(
        "/auth/sign-out",
        async ({ request, status }) => {
          const outcome = await sessions.signOut(request.headers);
          if (outcome === "no_session") return status(401, { reason: "no_session" as const });
          if (outcome === "failed") return status(503, { reason: "failed" as const });
          return status(204, undefined);
        },
        {
          response: {
            204: t.Undefined(),
            401: Problem(["no_session"]),
            403: Problem(["untrusted_origin"]),
            503: Problem(["failed"]),
          },
          detail: {
            summary: "End the caller's session and revoke the grant it rides on, which ends its other sessions too",
            tags: ["auth"],
          },
        },
      )
  );
}
