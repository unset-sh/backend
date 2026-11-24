// Writes the internal API's contract, api/internal/openapi.yaml, from its Elysia route schemas, or with --check
// fails when the committed file differs, so a route change without its contract cannot pass `bun run check`.
// Keys are sorted before writing, so the bytes depend on the schemas alone and not on registration order
// and repeated schemas are written out, not aliased (yaml 2.9.1 `sortMapEntries`, `aliasDuplicateObjects`).
// Bun 1.4.4 docs/runtime/yaml.mdx documents only `Bun.YAML.parse`, so Bun is not used to write it (org-0015).
import { toOpenAPISchema } from "@elysia/openapi";
import { stringify } from "yaml";
import { internalApi } from "../src/server/internal-api.ts";
import { PROBLEM_CONTENT_TYPE } from "../src/server/problem.ts";

export const SPEC_PATH = new URL("../api/internal/openapi.yaml", import.meta.url);

const OPENAPI_VERSION = "3.1.2";

/** The internal API's OpenAPI document as YAML text. Builds the routes only; nothing listens and no port is read. */
export function internalSpec(): string {
  const unserved = () => {
    throw new Error("the contract is built from the route schemas; no request is served");
  };
  const app = internalApi({
    ready: async () => true,
    webOrigin: "http://127.0.0.1:8080",
    sessions: { start: unserved, complete: unserved, current: unserved, signOut: unserved },
  });
  const { paths, components } = toOpenAPISchema(app, undefined, undefined, undefined, OPENAPI_VERSION);
  labelProblems(paths);
  const document = {
    openapi: OPENAPI_VERSION,
    info: {
      title: "Unset backend internal API",
      version: "0.0.0",
      description: "Called only by web's server over the private network. Not a public API.",
    },
    paths,
    components,
  };
  return stringify(document, { sortMapEntries: true, lineWidth: 0, aliasDuplicateObjects: false });
}

type Content = Record<string, { schema?: { properties?: Record<string, unknown> } }>;
type Operations = Record<string, Record<string, { responses?: Record<string, { content?: Content }> }>>;

/**
 * @elysia/openapi 1.4.17 lists every response as `application/json`; a refusal is sent as
 * `application/problem+json` (src/server/problem.ts), so the contract says that for every problem schema.
 */
function labelProblems(paths: unknown) {
  for (const operations of Object.values((paths ?? {}) as Record<string, Operations[string]>)) {
    for (const operation of Object.values(operations)) {
      for (const response of Object.values(operation.responses ?? {})) {
        const json = response.content?.["application/json"];
        const properties = json?.schema?.properties;
        if (response.content && json && properties && "type" in properties && "code" in properties) {
          response.content = { [PROBLEM_CONTENT_TYPE]: json };
        }
      }
    }
  }
}

if (import.meta.main) {
  const spec = internalSpec();
  if (process.argv.includes("--check")) {
    const file = Bun.file(SPEC_PATH);
    const committed = (await file.exists()) ? await file.text() : "";
    if (committed !== spec) {
      process.stderr.write("api/internal/openapi.yaml is out of date: run `bun run openapi` and commit the result.\n");
      process.exit(1);
    }
  } else {
    await Bun.write(SPEC_PATH, spec);
  }
}
