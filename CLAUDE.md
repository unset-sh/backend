# CLAUDE.md: unset-sh/backend

## Where this repository fits

This is `unset-sh/backend`: Unset's product operations, service contracts and server implementation.

- **Belongs here:** domains, published service contracts, AppView APIs and indexing, private server adapters,
  migrations, process composition and producer image builds. Messaging is a capability, not a separate repository.
- **Does not belong here:** screens and browser/device integrations (`unset-sh/web`); environment topology and
  rollout orchestration (`unset-sh/deployment`); PDS image customization (`unset-sh/pds`); canonical protocol
  definitions (`unset-sh/lexicons`); reusable automation (`unset-sh/tooling`).
- **Uses:** planned pinned lexicon and rendering artifacts, shared tooling and agent-kit. No dependencies are
  installed yet. **Used by:** planned web/mobile API consumers and deployment's artifact selection.
- **Licence:** AGPL-3.0-only first-party work; no outside code contributions for now. Third-party licences remain.

Read the [organisation map](https://github.com/unset-sh/.github/blob/main/MAP.md) before moving responsibility.
When responsibility, dependencies or outputs change, update `unset-sh/.github`'s `repos.json`, regenerate its
map with `npm run map`, and update this section in the same piece of work.

## Rules

- The original `Undefined6799/unset` stays read-only. Alex, 2026-11-23: reuse its code wherever it fits rather
  than reinvent it ("the idea is to reuse as much code as possible while doing that migration"). Copy the
  files and tests a change needs, change only what the move requires in a separate commit, cite the source
  path and commit, and note weak spots in agent-kit. Never copy a security weakness or retire a security control.
- Model product capabilities first. Keep provider types and errors inside adapters; domain imports must not
  depend on server frameworks or infrastructure. Wire known dependencies explicitly in each process.
- Write each Elysia route group as one plain `new Elysia({ name })` chain, not built by a generic factory or
  plugin function: web's Eden client reads `api/internal/app.d.ts`, and a factory's generics can widen it to `any`.
- Keep public API contracts, private domain ports and client UI interfaces distinct. Choose the public schema
  format with the first reviewed operation; this foundation does not select one.
- Preserve separate privileged processes, least-privilege database roles and device key custody. A repository
  boundary is not a security boundary. AppView projections must not become the only copy of authoritative state.
- Backend owns migration definitions and image builds; deployment owns environment wiring and execution order.
- Maintain human documentation under `docs/` when it has an audience. Keep AI working notes and review artifacts
  in agent-kit, following organisation rules. Install its approved kit before claiming local rule-copy checks.

## Commands

```sh
bun install --frozen-lockfile --ignore-scripts
bun run check     # type check, Biome, dependency-cruiser boundaries, bun test, contract drift
bun run openapi   # rewrite api/internal/openapi.yaml after changing a route's schema
bun run app-types # rewrite api/internal/app.d.ts, web's Eden type (org-0017), after the same change
bun run migrate   # apply the migrations as `migrator` (PG_* settings, PG_PASSWORD_FILE)
docker build .    # the image: server by default, `src/adapters/postgres/migrate-cli.ts` for migrations
```

The Postgres tests run against a real server and fail, never skip, without one: set `PGHOST`, `PGUSER` (a
superuser) and, if needed, `PGPORT` and `PGPASSWORD` for a disposable Postgres. CI gets one from tooling's check.

Bun is the runtime (`.bun-version`, `bunfig.toml`, `bun.lock`; 7-day release age, no lifecycle scripts). The
internal API's route schemas are its contract; commit the regenerated `api/internal/openapi.yaml` and
`api/internal/app.d.ts` with the route. CI runs tooling's Bun check and `pr-policy`; the agent-kit copy is not
installed yet.
