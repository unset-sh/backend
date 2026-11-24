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

Status: agreed with Alex on 2026-11-23 (problem+json errors, `/me`, `/users/:did`, the member id and the Better
Auth wrappers below). Nothing here is checked automatically yet. The step 7 routes still answer `{reason}`, and
the callback still sits at `/auth/atproto/callback`, until the next change moves them.

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

- **Plural, kebab-case nouns**, lower case: `/users`, `/me/profile`. The verb is the HTTP method, never in the
  path: `PATCH /me/profile`, not `/me/update-profile`.
- **`/me` is the caller.** Everything under `/me` acts on the member the session belongs to. Backend takes the
  DID from the session, never from the path, query or body, so no `/me` route can reach another member's data.
- **Other members are under `/users/:did`**, named by their full DID, colons included
  (`/users/did:plc:abc123/profile`). A colon is allowed in a path segment (RFC 3986 §3.3, `pchar`), so it needs
  no encoding. A handle is never an id, because it can change hands; a route that accepts one resolves it to the
  DID first.
- **One item of a collection is named by its id** (`/users/:did`). A singleton is singular (`/me/profile`,
  `/health`).
- **Nest at most one level** below an item: `/users/:did/profile` is fine. Anything deeper gets its own
  top-level collection, with a query to filter it (`/posts?author=:did`, not `/users/:did/posts/:id/likes`).
- **An action that is not reading or writing a resource** is a verb sub-path under its area, sent with `POST`:
  `/auth/sign-in/atproto`, `/auth/sign-in/atproto/callback`, `/auth/sign-out`. Keep these few.
- **Versions:** internal paths have none. The public API puts its version first (`api.unset.sh/v1/...`).
  AT Protocol operations stay under `/xrpc/<nsid>` and follow AT Protocol's rules, not these.
- No trailing slash, and no file extension except on a rendered file (`/profiles/:did/preview.png`).

## Identifiers

- **Outside backend, a member is their DID.** Every path, body and answer names a member by DID.
- **Inside backend, a member is a UUID**, Better Auth's user id (`generateId: "uuid"`), with the DID in a unique
  column beside it. Tables key on the UUID, so a member's rows stay theirs if the DID ever has to be remapped.
  The UUID never leaves backend: no route takes or answers it.

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
- A list answers `{"data": [...], "cursor": "..."}`, with `cursor` present only when there is a next page, and
  takes `?limit=` and `?cursor=` (the same shape as XRPC lists).

## Errors

A refusal answers an RFC 9457 problem document (`content-type: application/problem+json`,
<https://www.rfc-editor.org/rfc/rfc9457>), the same shape on every route, from one shared schema and one error
mapper in `src/server/`:

```json
{ "type": "about:blank", "title": "Unauthorized", "status": 401, "code": "no_session" }
```

- `type` is `about:blank` and `title` is the status's standard phrase (RFC 9457 §4.2.1), so neither says
  anything `code` and `status` do not.
- `code` is the extension member web branches on: one snake_case word. Each route's schema lists the exact
  codes it can answer for each status, so web can handle every case, and an unknown code is a contract break.
- A code names what happened from the caller's side (`handle_unverified`, `no_session`). There is no `detail`
  and no internal information: no message text, stack, SQL state, upstream answer, identifier or echoed input.
- Schema failures (`422`) and unexpected errors (`500`) go through the same mapper, as `invalid_request` and
  `failed`.

| Status | Meaning here | Example codes |
| --- | --- | --- |
| `400` | the input was well formed but refused | `handle_unverified`, `consent_denied`, `expired` |
| `401` | no valid session | `no_session` |
| `403` | the request may not do this | `untrusted_origin` (a cookie without web's Origin) |
| `404` | no such resource | `not_found` |
| `409` | the resource changed since it was read | `conflict` |
| `422` | the body or query does not match the schema | `invalid_request` |
| `500` | backend failed | `failed` |
| `502` | an upstream service answered, but wrongly | `failed` |
| `503` | a dependency could not be reached in time, or backend is not ready | `pds_unreachable`, `identity_unavailable` |

## Authentication

- Web sends the member's session token as `Authorization: Bearer <token>`. Routes that need a session say so in
  their schema and answer `401` with code `no_session` without one.
- A request that carries a cookie must come from web's origin, or it is refused with `403` and code `untrusted_origin`,
  before any route runs.
- Better Auth's own routes are not mounted. Backend's routes call Better Auth from inside (see below).

## Routes that wrap Better Auth

Better Auth's own HTTP routes are not mounted, so web cannot reach them. Every route web calls is backend's own,
with a contract in `api/internal/openapi.yaml`, and calls Better Auth inside through `auth.api.*`. The wrapper
exists so that:

- the contract web codes against is ours, and does not change when Better Auth's routes do;
- errors come back in this page's problem shape, with no Better Auth message text;
- a session is valid only while the member's AT Protocol token set is, which Better Auth alone does not know.

Each wrapping route's OpenAPI description names the Better Auth call it makes and why it wraps it. They are:

| Route | Better Auth call | What the wrapper adds |
| --- | --- | --- |
| `POST /auth/sign-in/atproto` | `auth.api.atprotoSignIn` (our server-only plugin endpoint) | handle checks, the PDS authorization URL |
| `POST /auth/sign-in/atproto/callback` | `auth.api.atprotoCallback` | the OAuth callback; finds or creates the member, starts the session |
| `POST /auth/sign-out` | `auth.api.atprotoSignOut` | ends the session and revokes the PDS grant |
| `GET /me/session` | `auth.api.getSession` | a cheap signed-in check that answers the DID only |

## The internal routes

| Method and path | Session | Answers |
| --- | --- | --- |
| `GET /health` | no | `{status}`; 503 when not ready |
| `POST /auth/sign-in/atproto` | no | `{url}` for `{handle}` |
| `POST /auth/sign-in/atproto/callback` | no | `{sessionToken}` for `{query}` |
| `POST /auth/sign-out` | yes | 204 |
| `GET /me/session` | yes | `{did}` |
| `GET /me/profile` | yes | `{did, handle, displayName?}` |
| `PATCH /me/profile` | yes | the updated profile, for `{displayName}`; 409 when the record changed meanwhile |

## Changing a route

The internal contract has one caller, so it is not versioned. Change it in an order that keeps the running pair
working: add the new field or route in backend, move web to it, then remove the old one in a later release
(expand, then contract). Commit the regenerated `api/internal/openapi.yaml` in the same pull request as the
route. CI fails when they differ.

Logs never carry a DID, handle, email, address or token, so a route's log line names its outcome only.
