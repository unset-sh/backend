-- phase: expand
-- The role roster and baseline grants (P1.12; plan section 5.2, roles map to processes; section 6.1, CIS Postgres).
-- Every runtime role is created here with no table privilege; each table's creating migration grants what its roles
-- need, by column list on a personal-data table. `backend` is the backend process's own pool (schema `app`);
-- `backend_auth` is Better Auth's pool in the same process (schema `auth`), so neither can read the other's tables.
--
-- Roles are cluster-global while every database runs this file (each test file clones its own), so it is idempotent:
-- a role is created only when missing, then brought to the roster's state. A CREATEROLE role may change LOGIN and
-- CONNECTION LIMIT on a role it created, but only a superuser may change SUPERUSER, REPLICATION or BYPASSRLS, and
-- only a CREATEDB role CREATEDB (PostgreSQL 18 ALTER ROLE, checked on postgres:18.6), so those are fixed at creation.
-- No role gets a password here: the environment that runs backend sets one, as migrator, so a role that has none
-- cannot log in.

-- The roster: name, login, connection limit (-1 for a group or owner), statement_timeout (null: none set).
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN SELECT * FROM (VALUES
    ('backend', true, 40, '2s'),
    ('backend_auth', true, 20, '2s')
  ) AS roster (name, login, connection_limit, statement_timeout)
  LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = r.name) THEN
      EXECUTE format('CREATE ROLE %I NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', r.name);
    END IF;
    EXECUTE format('ALTER ROLE %I %s CONNECTION LIMIT %s', r.name,
      CASE WHEN r.login THEN 'LOGIN' ELSE 'NOLOGIN' END, r.connection_limit);
    -- Every role: no stale setting, no session left idle in a transaction, no long lock wait, and an empty
    -- search_path, so code always schema-qualifies and an unqualified name can never be hijacked.
    EXECUTE format('ALTER ROLE %I RESET ALL', r.name);
    EXECUTE format('ALTER ROLE %I SET idle_in_transaction_session_timeout = %L', r.name, '10s');
    EXECUTE format('ALTER ROLE %I SET lock_timeout = %L', r.name, '3s');
    EXECUTE format('ALTER ROLE %I SET search_path = %L', r.name, '');
    IF r.statement_timeout IS NOT NULL THEN
      EXECUTE format('ALTER ROLE %I SET statement_timeout = %L', r.name, r.statement_timeout);
    END IF;
  END LOOP;
END
$$;

-- This database: CONNECT for every login role and nothing for PUBLIC. A database cloned from a template starts with
-- the default ACL, which lets PUBLIC connect, so the revoke runs in every database, named by current_database().
DO $$
BEGIN
  EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO backend, backend_auth', current_database());
END
$$;

-- Schema use. USAGE alone grants nothing inside a schema; table, sequence and function grants come with each object.
GRANT USAGE ON SCHEMA app TO backend;
GRANT USAGE ON SCHEMA auth TO backend_auth;

-- Default privileges, narrowed (plan section 5.2 at 9c54e52): no ON TABLES default for any role in any schema,
-- because a default cannot tell a personal-data table from another. Routines are never executable by PUBLIC: the
-- revoke is global, since a per-schema default privilege can only add to the global ones (PostgreSQL 18 ALTER
-- DEFAULT PRIVILEGES).
ALTER DEFAULT PRIVILEGES FOR ROLE migrator REVOKE EXECUTE ON ROUTINES FROM PUBLIC;
