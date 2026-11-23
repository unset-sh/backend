import { describe, expect, test } from "bun:test";
import { AppError, ERROR_CODES, isErrorCode } from "./index.ts";

const STATUSES = new Set([400, 401, 403, 404, 405, 409, 413, 415, 421, 429, 500, 503]);

describe("error catalog", () => {
  test("catalog_codes_well_formed", () => {
    for (const [code, entry] of Object.entries(ERROR_CODES)) {
      expect(code).toMatch(/^[a-z]+(\.[a-z_]+)+$/);
      expect(STATUSES.has(entry.status), code).toBe(true);
    }
  });

  test("only_own_keys_are_codes", () => {
    expect(isErrorCode("internal.error")).toBe(true);
    expect(isErrorCode("__proto__")).toBe(false);
    expect(isErrorCode("toString")).toBe(false);
  });

  test("app_error_message_is_code", () => {
    const cause = new Error("upstream said something with user input");
    const error = new AppError("http.payload_too_large", { cause });
    expect(error.message).toBe("http.payload_too_large");
    expect(error.code).toBe("http.payload_too_large");
    expect(error.status).toBe(413);
    expect(error.cause).toBe(cause);
  });
});
