-- phase: expand
-- The DID domain (P1.13; plan section 2 rule 11). Every column that holds a DID is declared with it, so a later
-- erasure step can find DID columns by type in pg_catalog rather than by name.
--
-- A domain's USAGE comes from PostgreSQL's default type privilege (PUBLIC; docs 18 ddl-priv, Table 5.2), so any role
-- that can reach the types schema may declare or cast to one. A domain holds no data; the schema USAGE granted here is
-- the gate.
CREATE SCHEMA types;
GRANT USAGE ON SCHEMA types TO backend;

-- did:plc is 24 base32 characters; did:web is a lowercase host name only, with no port or path, as atproto uses it
-- (https://atproto.com/specs/did).
CREATE DOMAIN types.did AS text
  CHECK (VALUE ~ '^did:(plc:[a-z2-7]{24}|web:[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+)$');
