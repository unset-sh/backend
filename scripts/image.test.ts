// The image's Dockerfile and build context, checked without building: every base is pinned by digest at the Bun
// version backend runs on, the runtime runs as a non-root user and carries no secret, and the build context holds only
// what the Dockerfile copies, so no production source imports a file .dockerignore leaves out.
import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";

const ROOT = join(import.meta.dirname, "..");
const dockerfile = readFileSync(join(ROOT, "Dockerfile"), "utf8");
const instructions = dockerfile
  .replace(/\\\n/g, " ")
  .split("\n")
  .map((line) => line.trim())
  .filter((line) => line !== "" && !line.startsWith("#"));
const bunVersion = readFileSync(join(ROOT, ".bun-version"), "utf8").trim();

describe("the Dockerfile", () => {
  const froms = instructions.filter((line) => /^FROM\s/i.test(line));

  test("pins every base to the official Bun image of .bun-version, by digest", () => {
    expect(froms.length).toBeGreaterThan(0);
    for (const from of froms) {
      expect(from).toMatch(
        new RegExp(`^FROM oven/bun:${bunVersion.replaceAll(".", "\\.")}-[a-z]+@sha256:[0-9a-f]{64} AS [a-z]+$`),
      );
    }
  });

  test("runs the last stage as a numeric non-root user", () => {
    const lastStage = instructions.slice(instructions.lastIndexOf(froms.at(-1) as string));
    const users = lastStage.filter((line) => /^USER\s/i.test(line));
    expect(users).toHaveLength(1);
    const [uid, gid] = (users[0] as string).replace(/^USER\s+/i, "").split(":");
    expect(Number(uid)).toBeGreaterThan(0);
    expect(Number(gid)).toBeGreaterThan(0);
  });

  test("takes no build argument and sets no secret", () => {
    expect(instructions.filter((line) => /^ARG\s/i.test(line))).toEqual([]);
    for (const line of instructions.filter((l) => /^ENV\s/i.test(l))) {
      expect(line).not.toMatch(/SECRET|PASSWORD|TOKEN|KEY/i);
    }
  });
});

describe("the build context", () => {
  const ignore = readFileSync(join(ROOT, ".dockerignore"), "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#"));
  const excluded = ignore.filter((line) => !line.startsWith("!") && line !== "*").map((line) => new Bun.Glob(line));
  const included = (path: string) => !excluded.some((glob) => glob.match(path));

  test("starts from nothing, so a secret or local file never reaches it", () => {
    expect(ignore[0]).toBe("*");
    expect(ignore.filter((line) => line.startsWith("!"))).toEqual([
      "!package.json",
      "!bun.lock",
      "!bunfig.toml",
      "!tsconfig.json",
      "!src/",
    ]);
  });

  const sources = (readdirSync(join(ROOT, "src"), { recursive: true }) as string[])
    .map((file) => `src/${file}`)
    .filter((file) => file.endsWith(".ts"));

  test("leaves out the tests and their helpers", () => {
    for (const file of ["src/main.test.ts", "src/server/test-deps.ts", "src/adapters/egress/remote.fake.ts"]) {
      expect(sources).toContain(file);
      expect(included(file)).toBe(false);
    }
  });

  test("holds every file a source in the image imports", () => {
    const missing: string[] = [];
    for (const file of sources.filter(included)) {
      const text = readFileSync(join(ROOT, file), "utf8");
      for (const match of text.matchAll(/(?:from|import)\s*\(?\s*["'](\.{1,2}\/[^"']+)["']/g)) {
        const target = relative(ROOT, join(ROOT, dirname(file), String(match[1])));
        if (!included(target)) missing.push(`${file} -> ${target}`);
      }
    }
    expect(missing).toEqual([]);
  });
});
