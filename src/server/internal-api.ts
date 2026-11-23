// The internal API: the operations only web's server calls, over the private network (agent-kit org-0015, proposed).
// Its route schemas are the contract; scripts/openapi.ts writes them to api/internal/openapi.yaml. A public API, when
// there is one, is a separate group with its own contract, never added here.
import { Elysia, t } from "elysia";

/** What the internal API needs from the rest of the process. Each operation adds the port it uses. */
export type InternalApiDeps = {
  /** True when every dependency a request needs can be reached now. Never throws. */
  readonly ready: () => Promise<boolean>;
};

const Health = t.Object(
  { status: t.Union([t.Literal("ok"), t.Literal("unavailable")]) },
  { additionalProperties: false },
);

export function internalApi(deps: InternalApiDeps) {
  return new Elysia({ name: "internal-api" }).get(
    "/health",
    async ({ status }) =>
      (await deps.ready()) ? { status: "ok" as const } : status(503, { status: "unavailable" as const }),
    {
      response: { 200: Health, 503: Health },
      detail: { summary: "Readiness: whether backend can serve requests now", tags: ["operations"] },
    },
  );
}
