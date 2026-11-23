import { describe, expect, test } from "bun:test";
import { parse } from "yaml";
import { internalSpec } from "./openapi.ts";

describe("internal API contract", () => {
  test("two generations are byte-identical", () => {
    expect(internalSpec()).toBe(internalSpec());
  });

  test("every route declares its responses", () => {
    const document = parse(internalSpec()) as { paths: Record<string, Record<string, { responses?: object }>> };
    const operations = Object.values(document.paths).flatMap((methods) => Object.values(methods));
    expect(operations.length).toBeGreaterThan(0);
    for (const operation of operations) expect(Object.keys(operation.responses ?? {})).not.toHaveLength(0);
  });
});
