// The internal API's published type (api/internal/app.d.ts, org-0017), used the way web will use it: Eden Treaty over
// the committed declaration, never the source. The calls run against the real routes with test ports, so a type that
// stopped matching what the routes answer fails here, in types (`bun run typecheck`) or in values (`bun test`).
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { treaty } from "@elysia/eden";
import type { App } from "../api/internal/app.d.ts";
import { type Did, parseDid } from "../src/domains/identity/index.ts";
import { internalApi } from "../src/server/internal-api.ts";
import { testDeps } from "../src/server/test-deps.ts";
import { elysiaVersion, TYPES_PATH } from "./app-types.ts";

const DID = parseDid("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa") as Did;
const TOKEN = "session-token";

/** A fetch that the routes answer in-process. */
const inProcess = (app: { handle: (request: Request) => Promise<Response> }) =>
  ((input: string | URL | Request, init?: RequestInit) =>
    app.handle(input instanceof Request ? input : new Request(String(input), init ?? {}))) as typeof fetch;

/** Eden over the declared type, answered in-process by the routes. */
function client() {
  const app = internalApi(
    testDeps({
      sessions: {
        current: async (headers) => (headers.get("authorization") === `Bearer ${TOKEN}` ? { did: DID } : null),
      },
      profiles: {
        get: async (did) => ({ ok: true, profile: { did, handle: "alice.example.com" } }),
        setDisplayName: async (did, displayName) =>
          displayName === "taken" ? { ok: false, reason: "conflict" } : { ok: true, profile: { did, displayName } },
      },
    }),
  );
  return treaty<App>("http://backend", { fetcher: inProcess(app), headers: { authorization: `Bearer ${TOKEN}` } });
}

type IsAny<T> = 0 extends 1 & T ? true : false;

describe("the declaration", () => {
  const text = readFileSync(TYPES_PATH, "utf8");

  test("imports elysia and nothing else, so it names no backend module", () => {
    expect([...text.matchAll(/import\("([^"]+)"\)|from\s+"([^"]+)"/g)].map((m) => m[1] ?? m[2])).toEqual(
      Array(text.match(/import\("elysia"\)/g)?.length ?? 0).fill("elysia"),
    );
  });

  test("names the exact elysia version it holds for", () => {
    expect(text).toContain(`It holds for elysia ${elysiaVersion()} exactly.`);
  });

  test("carries no Better Auth type", () => {
    expect(text.toLowerCase()).not.toContain("better");
  });
});

describe("Eden over the declaration", () => {
  test("GET /me/profile is typed, with no any", async () => {
    const result = await client().me.profile.get();
    const notAny: IsAny<typeof result.data> = false;
    expect(notAny).toBe(false);
    if (result.error) throw new Error(`unexpected ${result.error.status}`);
    const profile: { did: string; handle?: string; displayName?: string } = result.data;
    expect(profile).toEqual({ did: DID, handle: "alice.example.com" });
  });

  test("a refusal comes back as its status and problem code", async () => {
    const result = await client().me.profile.patch({ displayName: "taken" });
    expect(result.data).toBeNull();
    if (result.error?.status !== 409) throw new Error("expected 409");
    const code: "conflict" = result.error.value.code;
    expect(code).toBe("conflict");
  });

  test("no session is 401 no_session", async () => {
    const app = treaty<App>("http://backend", {
      fetcher: inProcess(internalApi(testDeps({ sessions: { current: async () => null } }))),
    });
    const result = await app.me.profile.get();
    if (result.error?.status !== 401) throw new Error("expected 401");
    expect(result.error.value.code).toBe("no_session");
  });

  test("a request body the route does not take is a type error", async () => {
    // @ts-expect-error displayTitle is not a field of PATCH /me/profile
    const call = () => client().me.profile.patch({ displayTitle: "x" });
    expect(typeof call).toBe("function");
  });
});
