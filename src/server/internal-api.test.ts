import { describe, expect, test } from "bun:test";
import { internalApi } from "./internal-api.ts";
import { testDeps } from "./test-deps.ts";

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

  test("an unknown path is 404", async () => {
    const response = await get(internalApi(testDeps({ ready: async () => true })), "/nope");
    expect(response.status).toBe(404);
  });
});
