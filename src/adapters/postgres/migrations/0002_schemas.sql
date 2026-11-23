-- phase: expand
-- The application schemas (P1.12; plan section 5.2), owned by migrator, the role every migration runs as. Nobody
-- else may use them until migration 0003 adds the roles and grants. `app` holds backend's own tables; `auth` holds
-- Better Auth's tables, which only Better Auth's own connection reaches (org-0015, proposed).
CREATE SCHEMA app;
CREATE SCHEMA auth;
