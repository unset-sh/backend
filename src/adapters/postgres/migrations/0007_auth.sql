-- phase: expand
-- Better Auth's tables (org-0015), in schema `auth`, reached only by `backend_auth` through Better Auth's Kysely
-- adapter (src/adapters/auth/). The columns are what Better Auth 1.7.25 generates for Postgres with the bearer plugin
-- and the session's `did` field (better-auth/db/migration `getMigrations`, compiled against Postgres 18), plus the
-- constraints below, which Better Auth does not add.
CREATE TABLE auth."user" (
  "id" text NOT NULL PRIMARY KEY,
  "name" text NOT NULL,
  -- A fixed `.invalid` address derived from a hash of the DID (Alex, 2026-11-23); never mail, never matched on.
  "email" text NOT NULL UNIQUE CHECK ("email" ~ '^[0-9a-f]{64}@did\.invalid$'),
  "emailVerified" boolean NOT NULL,
  "image" text,
  "createdAt" timestamptz DEFAULT CURRENT_TIMESTAMP NOT NULL,
  "updatedAt" timestamptz DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- A session is valid only while the member's OAuth token set exists (old app ADR 0049): it names the DID whose token
-- set it rides on, and deleting that token set (sign-out, a revoked or failed refresh, a new sign-in that replaces it)
-- deletes the session with it. The cascade runs as the tables' owner, so backend_auth needs nothing in `app`.
-- No address is kept: IP tracking is off in Better Auth's config, and the check refuses one if that ever changes.
CREATE TABLE auth."session" (
  "id" text NOT NULL PRIMARY KEY,
  "expiresAt" timestamptz NOT NULL,
  "token" text NOT NULL UNIQUE,
  "createdAt" timestamptz DEFAULT CURRENT_TIMESTAMP NOT NULL,
  "updatedAt" timestamptz NOT NULL,
  "ipAddress" text CHECK ("ipAddress" IS NULL OR "ipAddress" = ''),
  "userAgent" text,
  "userId" text NOT NULL REFERENCES auth."user" ("id") ON DELETE CASCADE,
  "did" text NOT NULL REFERENCES app.oauth_session (did) ON DELETE CASCADE
);

-- One account per (provider, account id): a DID belongs to exactly one user. The OAuth tokens live sealed in
-- app.oauth_session, so Better Auth's token and password columns stay empty.
CREATE TABLE auth."account" (
  "id" text NOT NULL PRIMARY KEY,
  "accountId" text NOT NULL,
  "providerId" text NOT NULL CHECK ("providerId" = 'atproto'),
  "userId" text NOT NULL REFERENCES auth."user" ("id") ON DELETE CASCADE,
  "accessToken" text CHECK ("accessToken" IS NULL),
  "refreshToken" text CHECK ("refreshToken" IS NULL),
  "idToken" text CHECK ("idToken" IS NULL),
  "accessTokenExpiresAt" timestamptz,
  "refreshTokenExpiresAt" timestamptz,
  "scope" text,
  "password" text CHECK ("password" IS NULL),
  "createdAt" timestamptz DEFAULT CURRENT_TIMESTAMP NOT NULL,
  "updatedAt" timestamptz NOT NULL,
  UNIQUE ("providerId", "accountId")
);

CREATE TABLE auth."verification" (
  "id" text NOT NULL PRIMARY KEY,
  "identifier" text NOT NULL,
  "value" text NOT NULL,
  "expiresAt" timestamptz NOT NULL,
  "createdAt" timestamptz DEFAULT CURRENT_TIMESTAMP NOT NULL,
  "updatedAt" timestamptz DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- query: src/adapters/auth/better-auth.ts
-- why: foreign-key
CREATE INDEX session_user_id_idx ON auth."session" ("userId");
-- query: src/adapters/auth/better-auth.ts
-- why: foreign-key
CREATE INDEX session_did_idx ON auth."session" ("did");
-- query: src/adapters/auth/better-auth.ts
-- why: foreign-key
CREATE INDEX account_user_id_idx ON auth."account" ("userId");
-- query: src/adapters/auth/better-auth.ts
-- why: speed
CREATE INDEX verification_identifier_idx ON auth."verification" ("identifier");

-- backend_auth is Better Auth's pool and nothing else; it reads and writes these four tables and no other.
GRANT SELECT, INSERT, UPDATE, DELETE ON auth."user", auth."session", auth."account", auth."verification"
  TO backend_auth;
