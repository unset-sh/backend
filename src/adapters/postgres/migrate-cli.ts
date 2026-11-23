// `bun src/adapters/postgres/migrate-cli.ts` (P1.11): the one-shot `migrate` run, holding only the `migrator`
// credentials. Exit 0 ok, 1 error, 2 an applied migration was edited, 3 a gap in the versions; a configuration problem
// exits 78 (bootOrExit). Setting the runtime roles' passwords from secret files (the old app's P1.12p) comes with the
// first environment that needs them.
import { join } from "node:path";
import { bootOrExit, defineConfig, oneOf, str } from "../../shared/config/index.ts";
import { createLogger } from "../../shared/log/index.ts";
import { connectionOf, postgresFields } from "./config.ts";
import { type MigrateFailure, migrate } from "./migrate.ts";

export const migrateConfig = defineConfig({
  UNSET_ENV: oneOf(["dev", "test", "prod"]),
  UNSET_COMMIT: str({ pattern: /[0-9a-f]{40}/ }),
  ...postgresFields,
});

/** The migrations, and the repository root an index's `-- query:` file is looked up in (P1.36h). */
export const MIGRATIONS = {
  dir: join(import.meta.dirname, "migrations"),
  root: join(import.meta.dirname, "..", "..", ".."),
  checkQueryFiles: true,
} as const;

/** One line naming the fixed reason and the migration file and line; never a secret or a driver message. */
function describe(failure: MigrateFailure): string {
  const { reason, file, line } = failure;
  return `unset-migrate: ${reason}${file ? ` in ${file}` : ""}${line ? ` line ${line}` : ""}\n`;
}

if (import.meta.main) {
  const cfg = bootOrExit(migrateConfig);
  const log = createLogger({ service: "migrate", commit: cfg.UNSET_COMMIT, env: cfg.UNSET_ENV });
  const result = await migrate({ connection: connectionOf(cfg), ...MIGRATIONS, log });
  if (!result.ok) process.stderr.write(describe(result));
  process.exitCode = result.ok ? 0 : result.exit;
}
