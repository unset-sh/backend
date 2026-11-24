// `sql.unsafe` sends text as written, with no parameter binding (Bun 1.4.4 docs/runtime/sql.mdx, "Unsafe Queries"), so
// only the migration runner, which runs reviewed migration files, the role password sync and the tests' own database
// setup may call it.
// Every other query is a tagged template, which binds each value as a parameter.
import { describe, expect, test } from "bun:test";
import { Glob } from "bun";

// roles.ts: ALTER ROLE takes no bound parameter; its one statement is built from a checked name and SCRAM verifier.
const ALLOWED = new Set([
  "src/adapters/postgres/migrate.ts",
  "src/adapters/postgres/roles.ts",
  "src/adapters/postgres/test-database.ts",
]);

describe("sql.unsafe", () => {
  test("appears only in the migration runner, the role password sync and the test database setup", async () => {
    const offenders: string[] = [];
    for await (const path of new Glob("{src,scripts}/**/*.ts").scan(".")) {
      if (path.endsWith(".test.ts") || ALLOWED.has(path)) continue;
      if (/\.unsafe\s*\(/.test(await Bun.file(path).text())) offenders.push(path);
    }
    expect(offenders).toEqual([]);
  });
});
