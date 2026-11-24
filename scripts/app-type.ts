// The declaration `bun scripts/app-types.ts` emits: the internal API's type, for Eden Treaty in web (org-0017). The
// function is never called; it gives tsc a return type to write out in full, so the emitted file names no backend
// module and imports only `elysia`.
import { internalApi } from "../src/server/internal-api.ts";

function routes() {
  return internalApi(undefined as never);
}

/** The internal API: its routes, their request schemas and every response by status. */
export type App = ReturnType<typeof routes>;
