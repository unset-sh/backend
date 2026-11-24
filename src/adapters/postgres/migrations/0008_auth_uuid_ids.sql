-- phase: contract
-- Members are keyed by a UUID inside backend (Alex, 2026-11-23; docs/api-conventions.md "Identifiers"), with the DID
-- in auth.account's unique ("providerId", "accountId"). Better Auth 1.7.25 with `advanced.database.generateId:
-- "uuid"` leaves the id to Postgres (@better-auth/kysely-adapter `supportsUUIDs` for postgres), so each table's id
-- now has the default its schema generator would write (better-auth/dist/db/get-migration.mjs: `uuid`,
-- `pg_catalog.gen_random_uuid()`). The UUID never leaves backend: no route takes or answers it.
--
-- Contract, because it changes types: release N-1 wrote non-UUID text ids. No environment has run 0007 yet (nothing
-- is deployed), so there is nothing to convert; the casts refuse any id that is not a UUID rather than invent one.
ALTER TABLE auth."session" DROP CONSTRAINT "session_userId_fkey";
ALTER TABLE auth."account" DROP CONSTRAINT "account_userId_fkey";

ALTER TABLE auth."user" ALTER COLUMN "id" TYPE uuid USING "id"::uuid,
  ALTER COLUMN "id" SET DEFAULT pg_catalog.gen_random_uuid();
ALTER TABLE auth."session" ALTER COLUMN "id" TYPE uuid USING "id"::uuid,
  ALTER COLUMN "id" SET DEFAULT pg_catalog.gen_random_uuid(),
  ALTER COLUMN "userId" TYPE uuid USING "userId"::uuid;
ALTER TABLE auth."account" ALTER COLUMN "id" TYPE uuid USING "id"::uuid,
  ALTER COLUMN "id" SET DEFAULT pg_catalog.gen_random_uuid(),
  ALTER COLUMN "userId" TYPE uuid USING "userId"::uuid;
ALTER TABLE auth."verification" ALTER COLUMN "id" TYPE uuid USING "id"::uuid,
  ALTER COLUMN "id" SET DEFAULT pg_catalog.gen_random_uuid();

ALTER TABLE auth."session" ADD CONSTRAINT "session_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES auth."user" ("id") ON DELETE CASCADE;
ALTER TABLE auth."account" ADD CONSTRAINT "account_userId_fkey"
  FOREIGN KEY ("userId") REFERENCES auth."user" ("id") ON DELETE CASCADE;
