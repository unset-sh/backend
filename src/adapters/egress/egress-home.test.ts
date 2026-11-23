// The global `fetch` reaches any address, so only the egress guard calls it (plan §2 rule 13); everything else is
// handed the guard's fetch (libraryFetch, guardedFetch). dependency-cruiser keeps the network built-ins here too.
import { describe, expect, test } from "bun:test";

describe("global fetch", () => {
  test("is called only inside the egress guard", async () => {
    const offenders: string[] = [];
    for await (const path of new Bun.Glob("{src,scripts}/**/*.ts").scan(".")) {
      if (path.startsWith("src/adapters/egress/") || path.endsWith(".test.ts")) continue;
      if (/(^|[^.\w])fetch\s*\(|globalThis\.fetch|Bun\.fetch/.test(await Bun.file(path).text())) offenders.push(path);
    }
    expect(offenders).toEqual([]);
  });
});
