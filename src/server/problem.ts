// The one error shape every route answers (docs/api-conventions.md "Errors"): an RFC 9457 problem document,
// `application/problem+json` (https://www.rfc-editor.org/rfc/rfc9457, read 2026-11-24). `type` is `about:blank`, so
// `title` is the status's standard phrase (§4.2.1); `code` is the extension member web branches on (§3.2). There is
// no `detail`: a problem never carries message text, input, an identifier or anything from inside backend.
import { t } from "elysia";

export const PROBLEM_CONTENT_TYPE = "application/problem+json";

/** The statuses backend refuses with, and their phrases (RFC 9110 §15). */
const TITLES = {
  400: "Bad Request",
  401: "Unauthorized",
  403: "Forbidden",
  404: "Not Found",
  409: "Conflict",
  422: "Unprocessable Content",
  500: "Internal Server Error",
  502: "Bad Gateway",
  503: "Service Unavailable",
} as const;

export type ProblemStatus = keyof typeof TITLES;
type Title<S extends ProblemStatus> = (typeof TITLES)[S];

/** Distributes over a union of statuses, so each status keeps its own title. */
export type ProblemBody<S extends ProblemStatus, C extends string> = S extends ProblemStatus
  ? { readonly type: "about:blank"; readonly title: Title<S>; readonly status: S; readonly code: C }
  : never;

/** The problem document for `status` and `code`. */
export const problem = <const S extends ProblemStatus, const C extends string>(status: S, code: C): ProblemBody<S, C> =>
  ({ type: "about:blank", title: TITLES[status], status, code }) as ProblemBody<S, C>;

/** The schema of the problem a route answers with `status`, naming every `code` it can carry. */
export const Problem = <const S extends ProblemStatus, const C extends readonly [string, ...string[]]>(
  status: S,
  codes: C,
) =>
  t.Object(
    {
      type: t.Literal("about:blank"),
      title: t.Literal(TITLES[status]),
      status: t.Literal(status),
      code: t.UnionEnum(codes),
    },
    { additionalProperties: false },
  );
