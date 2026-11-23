# backend

Unset's backend: product operations, domain rules, published service contracts and server integrations.

**Status: repository foundation only.** This repository contains ownership and contribution instructions,
not a running backend. Application code, migrations, packages, images, checks and deployment automation have
not been added. The application move from [Undefined6799/unset](https://github.com/Undefined6799/unset) is
pending; that repository remains read-only during this foundation work.

## Responsibility

Backend is the product's server implementation, shared by web and future mobile clients. It is not a generic
utility kit. Keep cohesive capabilities together, with private implementations behind intentional interfaces.

| Belongs here | Boundary |
| --- | --- |
| Product domains and operations, including identity, profiles and messaging server behavior | Product concepts, authorization and observable results |
| Published service contracts and their compatibility checks | Operations clients can call; no server implementation imports |
| AppView APIs, indexing rules, feature projections and query/visibility rules | Read models served through supported APIs |
| AT Protocol, database, storage and other server adapters | Technology details behind domain-owned ports |
| API, indexer, worker and privileged administration process entry points | Explicit composition, separate roles and credentials where needed |
| Database migrations and producer image builds | Released artifacts with documented configuration and migration contracts |

An S3 adapter belongs behind a storage capability port here; SDK calls and provider details stay in that
adapter. A shared storage capability can own `domains/assets/contract.ts`; profile operations use its
public interface through explicit composition, without importing the S3 adapter. Bucket provisioning, IAM
policies, lifecycle settings and environment wiring belong in deployment.

AppView is a backend responsibility spanning query APIs and indexing, not a separate database by definition.
Keep rebuildable projections separate from authoritative decisions such as moderation and account state.
Preserve privileged process isolation when code moves; sharing a repository does not combine credentials.

Messaging server integrations belong here. Messaging screens and device-side encryption integrations belong
in clients. A Matrix integration may have both server and device responsibilities; a common capability
interface does not make different protocols interchangeable or move device keys onto the server.

## Contracts and consumers

[Web](https://github.com/unset-sh/web) and future mobile clients call supported backend operations. They do
not import Postgres drivers, storage administration or private backend modules. Keep UI capability
interfaces, published network APIs and private domain ports distinct.

Define each public operation from a real use case: inputs, results, authorization, errors, compatibility and
retry/concurrency behavior. The API schema format and client-generation mechanism are not selected by this
bootstrap. Shared types alone do not prove wire compatibility or safe deployment.

The [lexicons repository](https://github.com/unset-sh/lexicons) is the intended authority for `sh.unset.*`
protocol definitions. Consume its published artifacts at reviewed immutable versions when available; do
not maintain another schema source here. Keep internal ports private rather than publishing every function
as a permanent protocol.

## Related repositories

- [web](https://github.com/unset-sh/web) owns SvelteKit routes, SSR, screens and client adapters.
- [deployment](https://github.com/unset-sh/deployment) selects released images and orchestrates environments;
  backend defines its migrations and builds its own images.
- [pds](https://github.com/unset-sh/pds) owns maintained PDS packaging and customization; backend owns its
  integration and privileged administrative process, not a copy of upstream PDS source.
- [rendering](https://github.com/unset-sh/rendering) renders supplied data; backend retains decisions
  about visibility, data selection and removal. [brand](https://github.com/unset-sh/brand) owns brand assets.
- [tooling](https://github.com/unset-sh/tooling) owns reusable CI mechanisms, while backend owns meaningful
  product checks. [agent-kit](https://github.com/unset-sh/agent-kit) owns shared agent instructions.
- [docs](https://github.com/unset-sh/docs) publishes maintained documentation authored by its source owner.

## Working here

Read [CLAUDE.md](CLAUDE.md), [AGENTS.md](AGENTS.md) and the
[organisation map](https://github.com/unset-sh/.github/blob/main/MAP.md) before changing ownership.
The commands are in [CLAUDE.md](CLAUDE.md#commands): `bun run check` runs the type check, lint, module
boundaries, tests and the internal API contract's drift check.
Maintained guides belong under `docs/` when needed. AI task notes and review artifacts belong in agent-kit.
CI runs tooling's Bun check. Agent-kit installation, images, releases and automatic consumer adoption remain
pending.

## Licence

Copyright (c) 2026 Alex (Undefined6799). First-party work is [AGPL-3.0-only](LICENSE).
No outside code has been added, and outside code contributions are not accepted for now.
Third-party work, if introduced under an approved dependency decision, retains its own licence.
