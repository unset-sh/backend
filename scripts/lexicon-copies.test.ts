// Every lexicon copied into backend still matches what its source.json records (org rule: a copy of another
// repository's files needs a pin and a check that it still matches). Today: sh.unset.profile, read by
// src/domains/profile/. A copy is refreshed by copying the file at a new lexicons commit and updating source.json.
import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const COPIES = [join(import.meta.dirname, "..", "src", "domains", "profile", "lexicon")];

describe.each(COPIES)("the lexicon copy in %s", (dir) => {
  const source = JSON.parse(readFileSync(join(dir, "source.json"), "utf8")) as {
    repository: string;
    commit: string;
    files: Record<string, { sourcePath: string; sha256: string }>;
  };

  test("names the lexicons repository at a full commit", () => {
    expect(source.repository).toBe("https://github.com/unset-sh/lexicons");
    expect(source.commit).toMatch(/^[0-9a-f]{40}$/);
  });

  test("every file matches its recorded hash, and every file is recorded", () => {
    const files = readdirSync(dir).filter((name) => name !== "source.json");
    expect(files.sort()).toEqual(Object.keys(source.files).sort());
    for (const [file, entry] of Object.entries(source.files)) {
      expect(
        createHash("sha256")
          .update(readFileSync(join(dir, file)))
          .digest("hex"),
      ).toBe(entry.sha256);
    }
  });
});
