// Secret never prints its value (P1.02).

import { describe, expect, test } from "bun:test";
import { inspect } from "node:util";
import { defineConfig, loadConfig, Secret, secret } from "./index.ts";

const quiet = { onUnknownKeys: () => undefined };

describe("Secret", () => {
  test("secret_never_printed", () => {
    const s = new Secret("hunter2-hunter2");
    for (const shown of [String(s), `${s}`, JSON.stringify({ s }), inspect(s), inspect({ s })]) {
      expect(shown).not.toContain("hunter2");
      expect(shown).toContain("[secret]");
    }
    const config = loadConfig(defineConfig({ S: secret({ minBytes: 1 }) }), { UNSET_ENV: "test", S: "hunter2" }, quiet);
    expect(JSON.stringify(config)).toBe('{"S":"[secret]"}');
  });

  test("secret_equals", () => {
    expect(new Secret("abc").equals(new Secret("abc"))).toBe(true);
    expect(new Secret("abc").equals(new Secret("abd"))).toBe(false);
    expect(new Secret("abc").equals(new Secret("abcd"))).toBe(false);
  });
});
