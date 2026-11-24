-- phase: expand
-- The sealed-value domain (P1.14d; plan section 5.3). A column that stores a seal envelope (`s1.<kid>.<rest>`, from
-- src/adapters/seal) is declared with it, so sealed-columns.integration.test.ts finds it by type in pg_catalog and
-- fails while it has no row in src/adapters/postgres/sealed-columns.json, which names the row key its seal context
-- binds. The check holds the format and key id only; opening a value is seal's job, never the database's.
CREATE DOMAIN types.sealed AS text
  CHECK (VALUE ~ '^s1\.[a-z0-9]{1,16}\.');
