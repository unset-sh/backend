import { describe, expect, test } from "bun:test";
import { createLogger } from "../shared/log/index.ts";
import { internalApi } from "./internal-api.ts";
import { createServer } from "./serve.ts";
import { testDeps, WEB_ORIGIN } from "./test-deps.ts";

const get = (app: ReturnType<typeof internalApi>, path: string) => app.handle(new Request(`http://backend${path}`));

describe("GET /health", () => {
  test("answers 200 ok when ready", async () => {
    const response = await get(internalApi(testDeps({ ready: async () => true })), "/health");
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: "ok" });
  });

  test("answers 503 unavailable when not ready", async () => {
    const response = await get(internalApi(testDeps({ ready: async () => false })), "/health");
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ status: "unavailable" });
  });
});

const problemOf = async (response: Response) => {
  expect(response.headers.get("content-type")).toBe("application/problem+json");
  return response.json();
};
const post = (app: { handle: (r: Request) => Promise<Response> }, path: string, body: string, headers = {}) =>
  app.handle(
    new Request(`http://backend${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body,
    }),
  );

describe("every refusal is an RFC 9457 problem document", () => {
  test("a path with no route, through the whole server", async () => {
    const lines: string[] = [];
    const log = createLogger({ service: "backend", commit: "0".repeat(40), env: "test", write: (l) => lines.push(l) });
    const response = await createServer(testDeps(), log).handle(new Request("http://backend/did:plc:abc"));
    expect(response.status).toBe(404);
    expect(await problemOf(response)).toEqual({
      type: "about:blank",
      title: "Not Found",
      status: 404,
      code: "not_found",
    });
  });

  test("a body that is not JSON is 400 invalid_request", async () => {
    const response = await post(internalApi(testDeps()), "/auth/sign-in/atproto", "{not json");
    expect(response.status).toBe(400);
    expect(await problemOf(response)).toEqual({
      type: "about:blank",
      title: "Bad Request",
      status: 400,
      code: "invalid_request",
    });
  });

  test("a body that breaks the schema is 422 and does not echo the input", async () => {
    const response = await post(internalApi(testDeps()), "/auth/sign-in/atproto", JSON.stringify({ handle: 7 }));
    expect(response.status).toBe(422);
    const text = JSON.stringify(await problemOf(response));
    expect(text).toBe(
      JSON.stringify({ type: "about:blank", title: "Unprocessable Content", status: 422, code: "invalid_request" }),
    );
  });

  test("an error no handler caught is 500 failed, without its message", async () => {
    const app = internalApi(
      testDeps({
        sessions: {
          start: async () => {
            throw new Error("secret detail did:plc:abc");
          },
        },
      }),
    );
    const response = await post(app, "/auth/sign-in/atproto", JSON.stringify({ handle: "alice.example.com" }));
    expect(response.status).toBe(500);
    expect(await problemOf(response)).toEqual({
      type: "about:blank",
      title: "Internal Server Error",
      status: 500,
      code: "failed",
    });
  });

  test("a route's own refusal, and the origin gate's", async () => {
    const app = internalApi(testDeps({ sessions: { current: async () => null } }));
    const none = await app.handle(new Request("http://backend/me/session"));
    expect(none.status).toBe(401);
    expect(await problemOf(none)).toEqual({
      type: "about:blank",
      title: "Unauthorized",
      status: 401,
      code: "no_session",
    });
    const foreign = await app.handle(
      new Request("http://backend/me/session", { headers: { cookie: "x=1", origin: "https://evil.example" } }),
    );
    expect(foreign.status).toBe(403);
    expect(((await problemOf(foreign)) as { code: string }).code).toBe("untrusted_origin");
    const ok = await app.handle(
      new Request("http://backend/me/session", { headers: { cookie: "x=1", origin: WEB_ORIGIN } }),
    );
    expect(ok.status).toBe(401);
  });

  test("a success is plain JSON", async () => {
    const app = internalApi(testDeps({ sessions: { current: async () => ({ did: "did:plc:abc" }) } }));
    const response = await app.handle(new Request("http://backend/me/session"));
    expect(response.headers.get("content-type")).toStartWith("application/json");
  });
});
