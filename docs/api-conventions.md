---
title: "How backend's routes are named and answer"
description: "The conventions every backend route follows: paths, methods, bodies, errors, status codes and versioning."
weight: 20
params:
  doc_kind: reference
draft: true
---

Every route backend serves follows these conventions. A route that breaks one says why in its pull request. The
contract itself is the route schemas in `src/server/`, and `api/internal/openapi.yaml` is generated from them
(`bun run openapi`). This page covers what the schemas cannot show: how a route gets its name and its answers.

Status: proposed for Alex's review (2026-11-23). Nothing here is checked automatically yet.

## Two groups, two contracts

| Group | Caller | Where | Contract |
| --- | --- | --- | --- |
| Internal | Unset's web server only, over the private network | no public address | `api/internal/openapi.yaml`, unversioned |
| Public (later) | other clients, with scoped tokens | `api.unset.sh`, routed at the edge to its own route group | its own contract and decision record, not written yet |

The browser never calls backend. A route never moves from internal to public by being exposed. A public route is
a separate route with its own contract, even when it calls the same operation.

Anything that is AT Protocol data, such as records and the operations other AT Protocol services call, uses
Lexicon and XRPC (`/xrpc/<nsid>`) rather than these REST conventions.

## Paths

- **Lower case and kebab-case**, nouns for resources: `/me/profile`, not `/getProfile` or `/me/Profile`.
- **`/me` is the caller.** Everything under `/me` acts on the member the session belongs to. Backend takes the
  DID from the session, never from the path, query or body, so no `/me` route can reach another member's data.
- **A collection is plural, and one item is named by its id:** `/users/:did`, `/users/:did/profile`. A member is
  named by their DID, never by their handle, because a handle can change hands. A DID in a path is
  percent-encoded.
- **A singleton is singular:** `/me/profile`, `/health`.
- **An action that is not reading or writing a resource** is a verb under its area: `/auth/sign-in/atproto`,
  `/auth/sign-out`. Keep these few; most things are resources.
- No trailing slash, no file extensions except a rendered file (`/profiles/:did/preview.png`), and no version in
  internal paths.

## Methods

| Method | Use | Body | Repeating it |
| --- | --- | --- | --- |
| `GET` | read; never changes anything | none | safe |
| `PUT` | replace the whole resource with the body | the full resource | same result |
| `PATCH` | change only the fields the body names | those fields | same result |
| `POST` | create an item in a collection, or perform an action | the action's input | may differ |
| `DELETE` | remove the resource | none | same result |

## Bodies

- JSON only (`content-type: application/json`). Field names are camelCase, matching the lexicons (`displayName`).
- Every field has a limit in its schema: a length for strings and a count for arrays. Where a lexicon defines the
  field, its limits apply (graphemes and bytes).
- A field the schema does not name is dropped before the handler runs, not refused (Elysia 1.4.32 normalises
  bodies). A handler never reads anything the schema does not declare.
- A success answers the resource itself, with no envelope (`{"did": ..., "handle": ...}`). An answer with
  nothing to say is `204` with no body.

## Errors

A refusal answers `{"reason": "<snake_case_word>"}` and nothing else. Each route's schema lists the exact words
it can answer for each status, so web can handle every case and an unknown word is a contract break. A reason
names what happened from the caller's side (`handle_unverified`, `no_session`), never internal detail: no
message text, stack, SQL state, upstream answer or identifier.

| Status | Meaning here | Example reasons |
| --- | --- | --- |
| `400` | the input was well formed but refused | `handle_unverified`, `consent_denied`, `expired` |
| `401` | no valid session | `no_session` |
| `403` | the request may not do this | `untrusted_origin` (a cookie without web's Origin) |
| `404` | no such resource | `not_found` |
| `409` | the resource changed since it was read | `conflict` |
| `422` | the body or query does not match the schema | Elysia's validation answer |
| `502` | an upstream service answered, but wrongly | `failed` |
| `503` | a dependency could not be reached in time, or backend is not ready | `pds_unreachable`, `identity_unavailable` |

## Authentication

- Web sends the member's session token as `Authorization: Bearer <token>`. Routes that need a session say so in
  their schema and answer `401 no_session` without one.
- A request that carries a cookie must come from web's origin, or it is refused with `403 untrusted_origin`,
  before any route runs.
- Better Auth's own routes are not mounted. Backend's routes call Better Auth from inside.

## Changing a route

The internal contract has one caller, so it is not versioned. Change it in an order that keeps the running pair
working: add the new field or route in backend, move web to it, then remove the old one in a later release
(expand, then contract). Commit the regenerated `api/internal/openapi.yaml` in the same pull request as the
route. CI fails when they differ.

Logs never carry a DID, handle, email, address or token, so a route's log line names its outcome only.
