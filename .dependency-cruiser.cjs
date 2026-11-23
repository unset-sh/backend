// Module boundaries for backend (CLAUDE.md "Rules"; agent-kit rules/principles.md "Design").
// Domains model product capabilities and import no framework, vendor SDK or I/O built-in: I/O reaches them as a
// port another layer implements. Each vendor SDK is imported in exactly one place, so swapping it stays local.

/** Each vendor SDK and the one folder (or file) allowed to import it. A new SDK is a new row, in the same PR. */
const SDK_HOMES = [
  // The HTTP framework: the server composition and the script that writes the contract from it.
  { sdk: "elysia", home: "^(src/server/|scripts/openapi\\.ts$)" },
  { sdk: "@elysia/[^/]+", home: "^(src/server/|scripts/openapi\\.ts$)" },
  { sdk: "yaml", home: "^scripts/openapi(\\.test)?\\.ts$" },
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
      from: { path: "^src/domains/" },
      to: { dependencyTypes: ["npm", "npm-dev", "npm-peer", "npm-optional"] },
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
