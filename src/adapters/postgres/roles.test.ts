// roles.ts, adapted from the old app's tests (Undefined6799/unset@60228f5, infrastructure/postgres/roles.test.ts and
// tests/integration/postgres/role-passwords.test.ts): the SCRAM verifier, the one statement sent, the checks that refuse
// before any connection, and the sync against real Postgres, checked against the verifier each role then holds. Every password is made at run
// time, so no credential-shaped literal sits in the repository.
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { alterRolePasswordSql, ROSTER, scramVerifier, syncRolePasswords } from "./roles.ts";
import { randomPassword, startTestPostgres, type TestPostgres } from "./test-database.ts";

const PASSWORD = randomBytes(24).toString("base64url");
const dir = mkdtempSync(join(tmpdir(), "backend-roles-"));
/** Nothing listens on port 1: a sync that got as far as connecting would report `database`. */
const NOWHERE = {
  hostname: "127.0.0.1",
  port: 1,
  database: "unset",
  username: "migrator",
  password: "x",
  tls: false as const,
};

/** Writes a fresh password file for each roster role and returns them by role. */
function newPasswords(folder: string): Record<string, string> {
  const passwords: Record<string, string> = {};
  for (const role of ROSTER) {
    passwords[role.name] = randomPassword();
    writeFileSync(join(folder, role.passwordFrom), `${passwords[role.name]}\n`);
  }
  return passwords;
}

describe("role passwords", () => {
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  test("scram_verifier_matches_the_rfc_vector", () => {
    // RFC 7677 section 3: user "user", password "pencil". The proof and signature the RFC lists follow from the
    // verifier's StoredKey and ServerKey, so a verifier that matches them is the one PostgreSQL derives at login.
    const salt = "W22ZaJ0SNY7soEsUEjb6gQ==";
    const verifier = scramVerifier("pencil", Buffer.from(salt, "base64"), 4096);
    const match = /^SCRAM-SHA-256\$4096:([^$]+)\$([^:]+):(.+)$/.exec(verifier);
    expect(match?.[1]).toBe(salt);
    const storedKey = Buffer.from(match?.[2] ?? "", "base64");
    const serverKey = Buffer.from(match?.[3] ?? "", "base64");
    const nonce = "rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
    const auth = `n=user,r=rOprNGfwEbeRWgbNEkqO,r=${nonce},s=${salt},i=4096,c=biws,r=${nonce}`;
    const hmac = (key: Buffer) => createHmac("sha256", key).update(auth).digest();
    const proof = Buffer.from("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=", "base64");
    const clientKey = Buffer.from(hmac(storedKey).map((byte, i) => byte ^ (proof[i] ?? 0)));
    expect(createHash("sha256").update(clientKey).digest()).toEqual(storedKey);
    expect(hmac(serverKey).toString("base64")).toBe("6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");
  });

  test("the_salt_is_random", () => {
    expect(scramVerifier(PASSWORD)).not.toBe(scramVerifier(PASSWORD));
  });

  test("the_password_is_never_sent_in_clear", () => {
    const verifier = scramVerifier(PASSWORD);
    const sql = alterRolePasswordSql("backend", verifier);
    expect(sql).toBe(`ALTER ROLE "backend" PASSWORD '${verifier}'`);
    expect(sql).not.toContain(PASSWORD);
    expect(() => alterRolePasswordSql("backend", PASSWORD)).toThrow("refused");
    expect(() => alterRolePasswordSql("backend", `${verifier}'; DROP ROLE backend; --`)).toThrow("refused");
    expect(() => alterRolePasswordSql('backend" SUPERUSER --', verifier)).toThrow("refused");
  });

  test("a_bad_roster_is_refused_before_connecting", async () => {
    for (const roster of [
      [{ name: 'backend" SUPERUSER --', passwordFrom: "pg_backend_password" }],
      [{ name: "Backend", passwordFrom: "pg_backend_password" }],
      [{ name: "backend", passwordFrom: "../../etc/passwd" }],
    ]) {
      expect(await syncRolePasswords({ connection: NOWHERE, secretsDir: dir, roster })).toEqual({
        ok: false,
        reason: "roster_invalid",
        role: roster[0]?.name as string,
      });
    }
  });

  test("a_missing_short_or_non_ascii_file_is_refused_before_connecting", async () => {
    const roster = [{ name: "backend", passwordFrom: "pg_backend_password" }];
    const sync = () => syncRolePasswords({ connection: NOWHERE, secretsDir: dir, roster });
    expect(await sync()).toEqual({ ok: false, reason: "secret_unreadable", role: "backend" });
    writeFileSync(join(dir, "pg_backend_password"), "short\n");
    expect(await sync()).toEqual({ ok: false, reason: "secret_unreadable", role: "backend" });
    writeFileSync(join(dir, "pg_backend_password"), `${"é".repeat(20)}\n`);
    expect(await sync()).toEqual({ ok: false, reason: "secret_not_ascii", role: "backend" });
    writeFileSync(join(dir, "pg_backend_password"), `${PASSWORD}\n`);
    expect(await sync()).toEqual({ ok: false, reason: "database" });
  });
});

describe("role passwords against Postgres", () => {
  let pg: TestPostgres;
  let database: string;
  const secrets = mkdtempSync(join(tmpdir(), "backend-role-passwords-"));
  beforeAll(async () => {
    pg = await startTestPostgres();
    database = await pg.migratedDatabase();
  });
  afterAll(async () => {
    await pg.stop();
    rmSync(secrets, { recursive: true, force: true });
  });
  const asMigrator = () => ({
    hostname: pg.host,
    port: pg.port,
    database,
    username: "migrator",
    password: pg.migratorPassword,
    tls: false as const,
  });
  /**
   * Whether the server holds `password` for `role`: the stored verifier recomputed from it with the stored salt and
   * iterations. It does not depend on pg_hba, which a disposable test cluster may set to trust.
   */
  async function holds(role: string, password: string): Promise<boolean> {
    const stored = await pg.sql("postgres", `SELECT rolpassword FROM pg_authid WHERE rolname = '${role}'`);
    const match = /^SCRAM-SHA-256\$(\d+):([^$]+)\$/.exec(stored);
    if (match === null) return false;
    return scramVerifier(password, Buffer.from(match[2] as string, "base64"), Number(match[1])) === stored;
  }

  test("each_role_holds_its_file's_password_and_a_rotation_replaces_it", async () => {
    const first = newPasswords(secrets);
    expect(await syncRolePasswords({ connection: asMigrator(), secretsDir: secrets })).toEqual({
      ok: true,
      roles: ["backend", "backend_auth"],
    });
    for (const role of ROSTER) expect(await holds(role.name, first[role.name] as string)).toBe(true);
    const second = newPasswords(secrets);
    expect((await syncRolePasswords({ connection: asMigrator(), secretsDir: secrets })).ok).toBe(true);
    for (const role of ROSTER) {
      expect(await holds(role.name, second[role.name] as string)).toBe(true);
      expect(await holds(role.name, first[role.name] as string)).toBe(false);
    }
  });

  test("the_server_stores_a_scram_verifier_never_the_password", async () => {
    const passwords = newPasswords(secrets);
    expect((await syncRolePasswords({ connection: asMigrator(), secretsDir: secrets })).ok).toBe(true);
    const stored = await pg.sql("postgres", "SELECT rolpassword FROM pg_authid WHERE rolname = 'backend'");
    expect(stored).toMatch(/^SCRAM-SHA-256\$4096:/);
    expect(stored).not.toContain(passwords.backend as string);
  });

  test("a_missing_role_sets_no_password_at_all", async () => {
    const passwords = newPasswords(secrets);
    writeFileSync(join(secrets, "pg_nobody_here_password"), `${randomPassword()}\n`);
    const roster = [...ROSTER, { name: "nobody_here", passwordFrom: "pg_nobody_here_password" }];
    expect(await syncRolePasswords({ connection: asMigrator(), secretsDir: secrets, roster })).toEqual({
      ok: false,
      reason: "role_absent",
      role: "nobody_here",
    });
    expect(await holds("backend", passwords.backend as string)).toBe(false);
  });
});
