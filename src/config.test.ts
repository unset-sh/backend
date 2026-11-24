// config.ts: the internal API's TLS is all three files or none, and none only in dev and test (Alex, 2026-11-24:
// mutual TLS between web and backend, staging included; staging runs as prod).
import { describe, expect, test } from "bun:test";
import { backendConfig } from "./config.ts";

const TLS = ["INTERNAL_TLS_CERT", "INTERNAL_TLS_KEY", "INTERNAL_TLS_CLIENT_CA"] as const;

/** The keys the TLS rules report invalid for `config`. */
const refused = (config: Record<string, unknown>) =>
  backendConfig.rules
    .filter((rule) => (TLS as readonly string[]).includes(rule.key))
    .filter((rule) => !rule.holds(config as never))
    .map((rule) => rule.key);

const all = Object.fromEntries(TLS.map((key) => [key, { reveal: () => "pem" }]));

describe("internal TLS settings", () => {
  test("prod_refuses_to_start_without_tls", () => {
    expect(refused({ UNSET_ENV: "prod" })).toEqual([...TLS]);
    expect(refused({ UNSET_ENV: "prod", ...all })).toEqual([]);
  });

  test("dev_and_test_may_serve_plain_http_or_tls", () => {
    for (const env of ["dev", "test"]) {
      expect(refused({ UNSET_ENV: env })).toEqual([]);
      expect(refused({ UNSET_ENV: env, ...all })).toEqual([]);
    }
  });

  test("a_partial_set_is_refused_everywhere", () => {
    for (const env of ["dev", "test", "prod"]) {
      expect(refused({ UNSET_ENV: env, INTERNAL_TLS_CERT: all.INTERNAL_TLS_CERT })).toEqual([...TLS]);
    }
  });
});
