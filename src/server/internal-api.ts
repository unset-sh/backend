// The internal API: the operations only web's server calls, over the private network (agent-kit org-0015, proposed).
// Its route schemas are the contract; scripts/openapi.ts writes them to api/internal/openapi.yaml. A public API, when
// there is one, is a separate group with its own contract, never added here.
import { Elysia, ElysiaCustomStatusResponse, t } from "elysia";
import { type Authorizer, ownProfile, principalOf } from "../domains/access/index.ts";
import type { Did } from "../domains/identity/index.ts";
import { PROBLEM_CONTENT_TYPE, Problem, problem } from "./problem.ts";

/** What the sign-in operations need: the Unset session over Better Auth (src/adapters/auth/index.ts `Sessions`). */
export type SessionsPort = {
  start(handle: string, nonce: string): Promise<{ ok: true; url: string } | { ok: false; reason: StartFailure }>;
  complete(
    query: string,
    nonce: string,
  ): Promise<{ ok: true; sessionToken: string } | { ok: false; reason: CompleteFailure }>;
  current(headers: Headers): Promise<{ readonly did: Did } | null>;
  signOut(headers: Headers): Promise<"ok" | "no_session" | "failed">;
};

type ProfileView = { readonly did: string; readonly handle?: string; readonly displayName?: string };
const PROFILE_READ_FAILURES = ["session_ended", "scope_missing", "pds_unreachable", "failed"] as const;
const PROFILE_WRITE_FAILURES = [
  ...PROFILE_READ_FAILURES,
  "name_invalid",
  "name_too_long",
  "conflict",
  "record_invalid",
] as const;
type ProfileReadFailure = (typeof PROFILE_READ_FAILURES)[number];
type ProfileWriteFailure = (typeof PROFILE_WRITE_FAILURES)[number];

/** The profile operations (src/domains/profile/operations.ts `Profiles`), for the caller's own DID only. */
export type ProfilesPort = {
  get(did: Did): Promise<{ ok: true; profile: ProfileView } | { ok: false; reason: ProfileReadFailure }>;
  setDisplayName(
    did: Did,
    displayName: string,
  ): Promise<{ ok: true; profile: ProfileView } | { ok: false; reason: ProfileWriteFailure }>;
};

/** What the internal API needs from the rest of the process. Each operation adds the port it uses. */
export type InternalApiDeps = {
  /** True when every dependency a request needs can be reached now. Never throws. */
  readonly ready: () => Promise<boolean>;
  readonly sessions: SessionsPort;
  readonly profiles: ProfilesPort;
  /** Who may do what (agent-kit org-0018): every route that acts on a resource asks it first. */
  readonly authorizer: Authorizer;
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
const COMPLETE_FAILURES = [
  "consent_denied",
  "expired",
  "state_mismatch",
  "account_mismatch",
  "pds_unreachable",
  "failed",
  "scope_missing",
] as const;
type StartFailure = (typeof START_FAILURES)[number];
type CompleteFailure = (typeof COMPLETE_FAILURES)[number];

const closed = <P extends Parameters<typeof t.Object>[0]>(properties: P) =>
  t.Object(properties, { additionalProperties: false });
const oneOf = <const W extends readonly [string, ...string[]]>(words: W) => t.UnionEnum(words);

const Health = closed({ status: oneOf(["ok", "unavailable"]) });
/**
 * What binds a sign-in to the browser that started it: 32 random bytes, base64url, that web keeps in that browser's
 * cookie and sends with the start and again with the callback. A callback with another nonce is refused.
 */
const Nonce = t.String({ pattern: "^[A-Za-z0-9_-]{43}$" });
/** The longest handle (https://atproto.com/specs/handle). */
const SignInBody = closed({ handle: t.String({ minLength: 1, maxLength: 253 }), nonce: Nonce });
/** The callback URL's query exactly as the authorization server sent it, without the `?`. */
const CallbackBody = closed({ query: t.String({ minLength: 1, maxLength: 4096 }), nonce: Nonce });
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
  state_mismatch: 400,
  account_mismatch: 400,
  scope_missing: 400,
  pds_unreachable: 503,
  failed: 502,
};

/** Every route can answer these: Elysia's own refusals and an error no handler caught (onError below). */
const ALWAYS = { 500: Problem(500, ["failed"]) } as const;
/** And every route with a body these. */
const WITH_BODY = {
  ...ALWAYS,
  422: Problem(422, ["invalid_request"]),
} as const;
const UNTRUSTED_ORIGIN = Problem(403, ["untrusted_origin"]);
/** A profile as web sees it: the DID, the handle only when it verifies both ways, the display name when set. */
const ProfileBody = closed({
  did: t.String({ minLength: 1 }),
  handle: t.Optional(t.String({ minLength: 1 })),
  displayName: t.Optional(t.String({ minLength: 1 })),
});
/** The lexicon's byte limit bounds the code units too; the grapheme and byte limits are the domain's to check. */
const DisplayNameBody = closed({ displayName: t.String({ maxLength: 640 }) });
const START_CODES = [...START_FAILURES, "invalid_request"] as const;
const COMPLETE_CODES = [...COMPLETE_FAILURES, "invalid_request"] as const;

/**
 * What each route needs before it runs (agent-kit org-0018): `public`, no session; `caller`, a session and nothing
 * more, for a route that only says who the caller is; or the resource and action the authorizer is asked about.
 * internal-api.test.ts fails a route missing here, so no route can skip the question.
 */
export const ROUTE_ACCESS = {
  "GET /health": "public",
  "POST /auth/sign-in/atproto": "public",
  "POST /auth/sign-in/atproto/callback": "public",
  "POST /auth/sign-out": "caller",
  "GET /me/session": "caller",
  "GET /me/profile": { resource: "profile", action: "read" },
  "PATCH /me/profile": { resource: "profile", action: "update" },
} as const;

export function internalApi(deps: InternalApiDeps) {
  const { sessions, profiles, authorizer } = deps;
  return (
    new Elysia({ name: "internal-api" })
      // Every refusal is a problem document (./problem.ts), including the ones Elysia makes: a body that does not
      // parse or match its schema, a path with no route, and an error no handler caught. Elysia's own answers carry
      // the input and the error's message (elysia 1.4.32 src/error.ts `ValidationError`), so none of that is passed
      // on. Global, so a path no route matches answers the same way from the server around this group.
      .onError({ as: "global" }, ({ code, set }) => {
        set.headers["content-type"] = PROBLEM_CONTENT_TYPE;
        if (code === "VALIDATION") {
          set.status = 422;
          return problem(422, "invalid_request");
        }
        if (code === "PARSE") {
          set.status = 400;
          return problem(400, "invalid_request");
        }
        if (code === "NOT_FOUND") {
          set.status = 404;
          return problem(404, "not_found");
        }
        set.status = 500;
        return problem(500, "failed");
      })
      // A refusal a route returns is labelled as a problem document too. In onAfterHandle, not mapResponse: a
      // mapResponse hook empties the body onError returns (seen on elysia 1.4.32; internal-api.test.ts
      // "a path with no route" fails if it comes back).
      // `status()` hands back an ElysiaCustomStatusResponse, whose `code` is the status.
      .onAfterHandle({ as: "global" }, ({ set, responseValue }) => {
        const answered = responseValue instanceof ElysiaCustomStatusResponse ? responseValue.code : set.status;
        if (typeof answered === "number" && answered >= 400) set.headers["content-type"] = PROBLEM_CONTENT_TYPE;
      })
      // A cookie is a credential a browser attaches by itself, so a request carrying one must come from web's origin;
      // a bearer token is not, and web's server sends it with no Origin (org-0015; spike (c)). Better Auth makes the
      // same check on its own routes; this one covers every route here.
      .onBeforeHandle(({ request, status }) => {
        if (request.headers.has("cookie") && request.headers.get("origin") !== deps.webOrigin) {
          return status(403, problem(403, "untrusted_origin"));
        }
      })
      .get(
        "/health",
        async ({ status }) =>
          (await deps.ready()) ? { status: "ok" as const } : status(503, { status: "unavailable" as const }),
        {
          response: { 200: Health, 503: Health },
          detail: {
            summary: "Readiness: whether backend can serve requests now",
            description: "A probe, not a refusal: it answers its status document in both cases.",
            tags: ["operations"],
          },
        },
      )
      .post(
        "/auth/sign-in/atproto",
        async ({ body, status }) => {
          const result = await sessions.start(body.handle, body.nonce);
          if (result.ok) return { url: result.url };
          // One branch per status, so each answer is checked against that status's schema.
          switch (START_STATUS[result.reason]) {
            case 400:
              return status(400, problem(400, result.reason));
            case 502:
              return status(502, problem(502, result.reason));
            case 503:
              return status(503, problem(503, result.reason));
          }
        },
        {
          parse: "json",
          body: SignInBody,
          response: {
            200: closed({ url: t.String({ format: "uri" }) }),
            400: Problem(400, START_CODES),
            403: UNTRUSTED_ORIGIN,
            502: Problem(502, START_FAILURES),
            503: Problem(503, START_FAILURES),
            ...WITH_BODY,
          },
          detail: {
            summary: "Start a sign-in: the authorization server's URL for a handle",
            description:
              "Wraps Better Auth's `auth.api.atprotoSignIn` (backend's server-only atproto plugin), so web codes " +
              "against this contract and this error shape, not Better Auth's routes, which are not mounted.",
            tags: ["auth"],
          },
        },
      )
      .post(
        "/auth/sign-in/atproto/callback",
        async ({ body, status }) => {
          const result = await sessions.complete(body.query, body.nonce);
          if (result.ok) return { sessionToken: result.sessionToken };
          // One branch per status, so each answer is checked against that status's schema.
          switch (COMPLETE_STATUS[result.reason]) {
            case 400:
              return status(400, problem(400, result.reason));
            case 502:
              return status(502, problem(502, result.reason));
            case 503:
              return status(503, problem(503, result.reason));
          }
        },
        {
          parse: "json",
          body: CallbackBody,
          response: {
            200: SessionToken,
            400: Problem(400, COMPLETE_CODES),
            403: UNTRUSTED_ORIGIN,
            502: Problem(502, COMPLETE_FAILURES),
            503: Problem(503, COMPLETE_FAILURES),
            ...WITH_BODY,
          },
          detail: {
            summary: "Complete a sign-in from the callback query: a session token",
            description:
              "Wraps Better Auth's `auth.api.atprotoCallback`: it finds or creates the member for the DID the " +
              "authorization server vouched for and starts a Better Auth session tied to that DID's token set.",
            tags: ["auth"],
          },
        },
      )
      .post(
        "/auth/sign-out",
        async ({ request, status }) => {
          const outcome = await sessions.signOut(request.headers);
          if (outcome === "no_session") return status(401, problem(401, "no_session"));
          if (outcome === "failed") return status(503, problem(503, "failed"));
          return status(204, undefined);
        },
        {
          response: {
            204: t.Undefined(),
            401: Problem(401, ["no_session"]),
            403: UNTRUSTED_ORIGIN,
            503: Problem(503, ["failed"]),
            ...ALWAYS,
          },
          detail: {
            summary: "End the caller's session: this browser only",
            description:
              "Wraps Better Auth's `auth.api.atprotoSignOut`, which deletes this session only; the member's other " +
              "browsers stay signed in. When it was the account's last session, the AT Protocol grant is revoked too, " +
              "so no grant outlives its sessions.",
            tags: ["auth"],
          },
        },
      )
      .get(
        "/me/session",
        async ({ request, status }) => {
          const session = await sessions.current(request.headers);
          return session === null ? status(401, problem(401, "no_session")) : { did: session.did };
        },
        {
          response: { 200: SessionInfo, 401: Problem(401, ["no_session"]), 403: UNTRUSTED_ORIGIN, ...ALWAYS },
          detail: {
            summary: "The caller's session: whose it is",
            description:
              "Wraps Better Auth's `auth.api.getSession` (no cookie cache) as a cheap signed-in check that answers " +
              "the DID alone, so web never sees Better Auth's session or user objects.",
            tags: ["auth"],
          },
        },
      )
      .get(
        "/me/profile",
        async ({ request, status }) => {
          const session = await sessions.current(request.headers);
          if (session === null) return status(401, problem(401, "no_session"));
          const decision = await authorizer.may(principalOf(session), "read", ownProfile(session.did));
          if (decision === "unavailable") return status(503, problem(503, "authorization_unavailable"));
          if (decision === "deny") return status(403, problem(403, "forbidden"));
          const result = await profiles.get(session.did);
          if (result.ok) return result.profile;
          switch (result.reason) {
            case "session_ended":
              return status(401, problem(401, result.reason));
            case "scope_missing":
              return status(403, problem(403, result.reason));
            case "failed":
              return status(502, problem(502, result.reason));
            case "pds_unreachable":
              return status(503, problem(503, result.reason));
          }
        },
        {
          response: {
            200: ProfileBody,
            401: Problem(401, ["no_session", "session_ended"]),
            403: Problem(403, ["untrusted_origin", "forbidden", "scope_missing"]),
            502: Problem(502, ["failed"]),
            503: Problem(503, ["authorization_unavailable", "pds_unreachable"]),
            ...ALWAYS,
          },
          detail: {
            summary: "The caller's profile: DID, verified handle and display name",
            description:
              "The session comes from Better Auth's `auth.api.getSession`; the profile is the caller's own " +
              "`sh.unset.profile/self` record, read from their PDS over their OAuth session. The handle is present " +
              "only when it resolves back to the DID. `session_ended`: the AT Protocol grant is gone, and every " +
              "session on it with it.",
            tags: ["profile"],
          },
        },
      )
      .patch(
        "/me/profile",
        async ({ request, body, status }) => {
          const session = await sessions.current(request.headers);
          if (session === null) return status(401, problem(401, "no_session"));
          const decision = await authorizer.may(principalOf(session), "update", ownProfile(session.did));
          if (decision === "unavailable") return status(503, problem(503, "authorization_unavailable"));
          if (decision === "deny") return status(403, problem(403, "forbidden"));
          const result = await profiles.setDisplayName(session.did, body.displayName);
          if (result.ok) return result.profile;
          const { reason } = result;
          switch (reason) {
            case "name_invalid":
            case "name_too_long":
              return status(400, problem(400, reason));
            case "session_ended":
              return status(401, problem(401, reason));
            case "scope_missing":
              return status(403, problem(403, reason));
            case "conflict":
              return status(409, problem(409, reason));
            case "record_invalid":
            case "failed":
              return status(502, problem(502, reason));
            case "pds_unreachable":
              return status(503, problem(503, reason));
          }
        },
        {
          parse: "json",
          body: DisplayNameBody,
          response: {
            200: ProfileBody,
            400: Problem(400, ["name_invalid", "name_too_long", "invalid_request"]),
            401: Problem(401, ["no_session", "session_ended"]),
            403: Problem(403, ["untrusted_origin", "forbidden", "scope_missing"]),
            409: Problem(409, ["conflict"]),
            502: Problem(502, ["record_invalid", "failed"]),
            503: Problem(503, ["authorization_unavailable", "pds_unreachable"]),
            ...WITH_BODY,
          },
          detail: {
            summary: "Set the caller's display name; an empty one removes it",
            description:
              "Reads the caller's `sh.unset.profile/self`, changes only `displayName` and writes it back with a " +
              "compare-and-swap on the CID it read: a change made in between answers `conflict` and writes nothing. " +
              "Every other field is kept. `record_invalid`: the stored record breaks the lexicon, so it is not " +
              "written back under the caller's name.",
            tags: ["profile"],
          },
        },
      )
  );
}
