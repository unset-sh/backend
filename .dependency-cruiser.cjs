// Module boundaries for backend (CLAUDE.md "Rules"; agent-kit rules/principles.md "Design").
// Domains model product capabilities and import no framework, vendor SDK or I/O built-in: I/O reaches them as a
// port another layer implements. Each vendor SDK is imported in exactly one place, so swapping it stays local.

/** Each vendor SDK and the one folder (or file) allowed to import it. A new SDK is a new row, in the same PR. */
const SDK_HOMES = [
  // The HTTP framework: the server composition, the script that writes the contract from it, and the published type
  // with the test that calls it through Eden (org-0017).
  { sdk: "elysia", home: "^(src/server/|scripts/openapi\\.ts$|api/internal/app\\.d\\.ts$)" },
  { sdk: "@elysia/[^/]+", home: "^(src/server/|scripts/openapi\\.ts$|scripts/app-types\\.test\\.ts$)" },
  { sdk: "yaml", home: "^scripts/openapi(\\.test)?\\.ts$" },
  // The atproto OAuth client and its key, scope and metadata packages: the atproto adapter.
  { sdk: "@atproto(-labs)?/[^/]+", home: "^src/adapters/atproto/" },
  // Better Auth: the auth adapter. Its database driver and query builder: the file that opens its pool.
  { sdk: "better-auth", home: "^src/adapters/auth/" },
  { sdk: "kysely", home: "^src/adapters/auth/database\\.ts$" },
  { sdk: "pg", home: "^src/adapters/auth/database\\.ts$" },
];

/** Built-ins a domain may not import: I/O arrives as a passed-in dependency. */
const IO_BUILTINS = "fs|net|http|https|http2|dgram|dns|tls|child_process|worker_threads";

module.exports = {
  forbidden: [
    {
      name: "no-circular",
      severity: "error",
      comment: "A cycle means two modules share one responsibility; split it out instead.",
      from: {},
      to: { circular: true },
    },
    ...SDK_HOMES.map(({ sdk, home }) => ({
      name: `sdk-home:${sdk}`,
      severity: "error",
      comment: `${sdk} is imported only from ${home}.`,
      from: { pathNot: home },
      to: { dependencyTypes: ["npm", "npm-dev"], path: `^node_modules/${sdk}/` },
    })),
    {
      name: "sql-home",
      severity: "error",
      comment: "Bun.sql (the `bun` module) is reached only through the Postgres adapter.",
      from: { pathNot: "^src/adapters/postgres/" },
      // dependency-cruiser resolves `bun` to its type package, @types/bun.
      to: { path: "^node_modules/@types/bun/" },
    },
    {
      name: "egress-home",
      severity: "error",
      comment:
        "Outbound network built-ins live in the egress guard, so every caller-influenced request is vetted (plan §2 rule 13).",
      from: { pathNot: "^src/adapters/egress/" },
      to: { dependencyTypes: ["core"], path: "^(node:)?(dns|dns/promises|http|https|http2|tls|dgram)$" },
    },
    {
      name: "domain-no-io",
      severity: "error",
      comment: "A domain gets I/O through a port, never from a built-in.",
      from: { path: "^src/domains/" },
      to: { dependencyTypes: ["core"], path: `^(node:)?(${IO_BUILTINS})(/|$)` },
    },
    {
      name: "domain-no-vendor",
      severity: "error",
      comment: "A domain imports no package; vendor types stay inside their adapter.",
      from: { path: "^src/domains/", pathNot: "\\.test\\.ts$" },
      to: { dependencyTypes: ["npm", "npm-dev", "npm-peer", "npm-optional"] },
    },
    {
      name: "domain-test-dev-only",
      severity: "error",
      comment: "A domain's tests may use test tools (dev dependencies, such as fast-check), never a runtime package.",
      from: { path: "^src/domains/.*\\.test\\.ts$" },
      to: { dependencyTypes: ["npm", "npm-peer", "npm-optional"] },
    },
    {
      name: "domain-inward-only",
      severity: "error",
      comment: "A domain never reaches an adapter, the server or the composition root; they depend on it.",
      from: { path: "^src/domains/" },
      to: { path: "^src/(adapters|server)/|^src/main\\.ts$" },
    },
    {
      name: "not-to-unresolvable",
      severity: "error",
      comment: "An import that resolves to nothing is a typo or a missing dependency.",
      from: {},
      to: { couldNotResolve: true },
    },
  ],
  options: {
    // dependency-cruiser 18.7.2 reads TypeScript only through typescript <7, so it parses with swc instead
    // (the old app did the same: Undefined6799/unset@60228f5 scripts/lint/.dependency-cruiser.cjs).
    parser: "swc",
    doNotFollow: { path: "node_modules" },
    // dependency-cruiser sets exportsFields to [] by default, so a package that publishes only an `exports` map
    // would never resolve and would escape every path rule (same source, P1.31d).
    enhancedResolveOptions: { exportsFields: ["exports"], conditionNames: ["import", "bun", "default"] },
  },
};
