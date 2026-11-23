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
- Keep public API contracts, private domain ports and client UI interfaces distinct. Choose the public schema
  format with the first reviewed operation; this foundation does not select one.
- Preserve separate privileged processes, least-privilege database roles and device key custody. A repository
  boundary is not a security boundary. AppView projections must not become the only copy of authoritative state.
- Backend owns migration definitions and image builds; deployment owns environment wiring and execution order.
- Maintain human documentation under `docs/` when it has an audience. Keep AI working notes and review artifacts
  in agent-kit, following organisation rules. Install its approved kit before claiming local rule-copy checks.

## Commands

There are no application or check commands yet, and no CI or agent-kit copy is installed. Add real commands
and meaningful checks with implementation; do not claim that documentation establishes enforcement.
