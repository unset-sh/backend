---
title: "Backend"
description: "The unset.sh backend: product operations, domain rules, published service contracts and server integrations."
type: docs
cascade:
  type: docs
menus:
  main:
    weight: 110
params:
  doc_kind: overview
---

`unset-sh/backend` is the product's server implementation, shared by the web app and future mobile clients. It holds
product domains and operations, published service contracts, AppView query and indexing rules, AT Protocol,
database and storage adapters, process entry points, database migrations and the backend image build.

**Status: early.** The repository has a type-checked Bun project with module boundaries, tests against a real
Postgres and an internal API contract with a drift check. Most application code still moves in from
[Undefined6799/unset](https://github.com/Undefined6799/unset).

## How it is shaped

- Product rules live in domains and depend only on ports they define. Technology details, such as an S3 or
  Postgres adapter, stay behind those ports and are wired explicitly.
- Rebuildable projections stay separate from authoritative decisions such as moderation and account state.
- Privileged processes keep their own roles and credentials, even when they share the repository.
- Messaging server integrations live here; messaging screens and device-side encryption live in the clients.

## Contracts and consumers

The [web app](https://github.com/unset-sh/web) and future mobile clients call supported backend operations and
never import backend internals. Each public operation is defined from a real use case: inputs, results,
authorisation, errors, compatibility and retry behaviour. The [lexicons](https://github.com/unset-sh/lexicons)
repository is the authority for `sh.unset.*` protocol definitions.

[Deployment](https://github.com/unset-sh/deployment) runs the released images; backend defines its own migrations
and builds its own image. [PDS](https://github.com/unset-sh/pds) owns the PDS packaging; backend owns the
integration with it.

The [repository README](https://github.com/unset-sh/backend#readme) has the full notes and the commands. This
section is exported from `docs/site/` in `unset-sh/backend`; edit it there.
