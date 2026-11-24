// `bun src/adapters/postgres/migrate-cli.ts` (P1.11): the one-shot `migrate` run, holding only the `migrator`
// credentials. Exit 0 ok, 1 error, 2 an applied migration was edited, 3 a gap in the versions; a configuration problem
// exits 78 (bootOrExit). After the migrations, and never when they fail, it sets the runtime roles' passwords from their
// secret files in /run/secrets (roles.ts; the old app's `migrateThenSyncPasswords`, Undefined6799/unset@60228f5
// infrastructure/postgres/migrate-cli.ts); a password failure exits 1.
import { join } from "node:path";
import { bootOrExit, defineConfig, oneOf, str } from "../../shared/config/index.ts";
import { createLogger } from "../../shared/log/index.ts";
import { connectionOf, postgresFields } from "./config.ts";
import { type MigrateFailure, migrate } from "./migrate.ts";
import { type PasswordSyncResult, syncRolePasswords } from "./roles.ts";

/**
 * Where Compose mounts secrets. A constant, not configuration: an environment change must not point the password reader
 * at another folder.
 */
export const ROLE_PASSWORDS_DIR = "/run/secrets";

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

/** One line naming the fixed reason and the roster role; never a password or a driver message. */
function describePasswords(result: Exclude<PasswordSyncResult, { ok: true }>): string {
  const { reason, role, sqlstate } = result;
  return `unset-migrate: password sync ${reason}${role ? ` for ${role}` : ""}${sqlstate ? ` (${sqlstate})` : ""}\n`;
}

if (import.meta.main) {
  const cfg = bootOrExit(migrateConfig);
  const log = createLogger({ service: "migrate", commit: cfg.UNSET_COMMIT, env: cfg.UNSET_ENV });
  const connection = connectionOf(cfg);
  const result = await migrate({ connection, ...MIGRATIONS, log });
  if (!result.ok) {
    process.stderr.write(describe(result));
    process.exitCode = result.exit;
  } else {
    const passwords = await syncRolePasswords({ connection, secretsDir: ROLE_PASSWORDS_DIR });
    if (!passwords.ok) process.stderr.write(describePasswords(passwords));
    else log.info("migrate.passwords_set", { count: passwords.roles.length });
    process.exitCode = passwords.ok ? 0 : 1;
  }
}
