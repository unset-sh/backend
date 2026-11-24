// The profile's display name and the record it is written to. Adapted from Undefined6799/unset@60228f5
// domains/profile/profile.test.ts to the one field this slice edits, against the pinned lexicon copy.
import { describe, expect, test } from "bun:test";
import { DISPLAY_NAME_LIMITS, parseDisplayName, readDisplayName, withDisplayName } from "./profile.ts";

const NOW = "2026-11-24T02:00:00.000Z";

test("the display name limits are the lexicon's", () => {
  expect(DISPLAY_NAME_LIMITS).toEqual({ graphemes: 64, bytes: 640 });
});

describe("parseDisplayName", () => {
  test("trims, and an empty name means remove it", () => {
    expect(parseDisplayName("  Alice Moreau ")).toEqual({ ok: true, value: "Alice Moreau" });
    expect(parseDisplayName("   ")).toEqual({ ok: true, value: "" });
  });

  test("a non-string is refused", () => {
    for (const raw of [7, null, undefined, ["a"], { a: 1 }]) {
      expect(parseDisplayName(raw)).toEqual({ ok: false, code: "name_invalid" });
    }
  });

  test("one line only, and no bidirectional control or invisible character", () => {
    for (const raw of ["a\nb", "a\u0000b", "Ali‮ce", "Ali⁧ce", "a​b", "a﻿b", "\ud800"]) {
      expect(parseDisplayName(raw)).toEqual({ ok: false, code: "name_invalid" });
    }
    expect(parseDisplayName("👩‍💻 Ada")).toEqual({ ok: true, value: "👩‍💻 Ada" });
  });

  test("graphemes and bytes are both limited, as the lexicon counts them", () => {
    expect(parseDisplayName("a".repeat(64))).toMatchObject({ ok: true });
    expect(parseDisplayName("a".repeat(65))).toEqual({ ok: false, code: "name_too_long" });
    // A family emoji is one grapheme of 18 bytes: 40 of them fit the grapheme limit but not the byte limit.
    expect(parseDisplayName("👨‍👩‍👧".repeat(40))).toEqual({ ok: false, code: "name_too_long" });
    expect(parseDisplayName("👨‍👩‍👧".repeat(3))).toMatchObject({ ok: true });
  });
});

describe("readDisplayName", () => {
  test("reads a stored name; a missing, bad or oversized one reads as unset", () => {
    expect(readDisplayName({ displayName: "Alice" })).toBe("Alice");
    for (const stored of [null, "x", [], {}, { displayName: 7 }, { displayName: "" }, { displayName: "‮ecilA" }]) {
      expect(readDisplayName(stored)).toBeUndefined();
    }
    expect(readDisplayName({ displayName: "a".repeat(65) })).toBeUndefined();
  });
});

describe("withDisplayName", () => {
  test("a first profile is the name and createdAt", () => {
    expect(withDisplayName("Alice", null, NOW)).toEqual({
      ok: true,
      record: { $type: "sh.unset.profile", displayName: "Alice", createdAt: NOW },
    });
  });

  test("an update keeps createdAt and every other field, including ones this version does not know", () => {
    const existing = {
      $type: "sh.unset.profile" as const,
      displayName: "Old",
      headline: "Designer",
      listed: true,
      avatar: { $type: "blob", ref: { $link: "bafy" }, mimeType: "image/png", size: 10 },
      pronouns: "they/them",
      createdAt: "2026-10-01T00:00:00.000Z",
    };
    expect(withDisplayName("New", existing, NOW)).toEqual({ ok: true, record: { ...existing, displayName: "New" } });
  });

  test("an empty name removes the field", () => {
    const existing = { $type: "sh.unset.profile", displayName: "Old", createdAt: "2026-10-01T00:00:00.000Z" };
    expect(withDisplayName("", existing, NOW)).toEqual({
      ok: true,
      record: { $type: "sh.unset.profile", createdAt: "2026-10-01T00:00:00.000Z" },
    });
  });

  test("a stored record another client broke is refused, never written back", () => {
    for (const broken of [{ listed: "yes" }, { headline: 7 }, { location: "x".repeat(101) }, { avatar: "x" }]) {
      expect(withDisplayName("Alice", broken, NOW)).toEqual({ ok: false, code: "record_invalid" });
    }
  });
});
