// Writes the internal API's contract, api/internal/openapi.yaml, from its Elysia route schemas, or with --check
// fails when the committed file differs, so a route change without its contract cannot pass `bun run check`.
// Keys are sorted before writing, so the bytes depend on the schemas alone and not on registration order
// and repeated schemas are written out, not aliased (yaml 2.9.1 `sortMapEntries`, `aliasDuplicateObjects`).
// Bun 1.4.4 docs/runtime/yaml.mdx documents only `Bun.YAML.parse`, so Bun is not used to write it (org-0015).
import { toOpenAPISchema } from "@elysia/openapi";
import { stringify } from "yaml";
import { internalApi } from "../src/server/internal-api.ts";

export const SPEC_PATH = new URL("../api/internal/openapi.yaml", import.meta.url);

const OPENAPI_VERSION = "3.1.2";

/** The internal API's OpenAPI document as YAML text. Builds the routes only; nothing listens and no port is read. */
export function internalSpec(): string {
  const app = internalApi({ ready: async () => true });
  const { paths, components } = toOpenAPISchema(app, undefined, undefined, undefined, OPENAPI_VERSION);
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
