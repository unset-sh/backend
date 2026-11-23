import { describe, expect, test } from "bun:test";
import { createLogger } from "../shared/log/index.ts";
import { createServer } from "./serve.ts";

function capture() {
  const lines: string[] = [];
  const log = createLogger({ service: "backend", commit: "a".repeat(40), env: "test", write: (l) => lines.push(l) });
  const records = () => lines.map((l) => JSON.parse(l) as Record<string, unknown>);
  return { log, records };
}

/** onAfterResponse runs after the response is handed back, so wait a turn for its line. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 10));

describe("request log", () => {
  test("one line per response, with the route template", async () => {
    const { log, records } = capture();
    const app = createServer({ ready: async () => false }, log);
    const response = await app.handle(new Request("http://backend/health"));
    await settle();
    expect(response.status).toBe(503);
    expect(records()).toEqual([
      expect.objectContaining({ event: "http.request", route: "/health", method: "GET", status: 503 }),
    ]);
  });

  test("an unmatched path is logged without the path", async () => {
    const { log, records } = capture();
    const app = createServer({ ready: async () => true }, log);
    await app.handle(new Request("http://backend/did:plc:abcdefghijklmnopqrstuvwx/alice.example.com"));
    await settle();
    const text = JSON.stringify(records());
    expect(text).not.toContain("did:plc");
    expect(text).not.toContain("alice.example.com");
    expect(records()[0]).toMatchObject({ event: "http.request", route: "/*", status: 404 });
  });
});
