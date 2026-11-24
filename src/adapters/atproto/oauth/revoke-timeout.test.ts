// withRevokeTimeout (revoke-timeout.ts): a revoke that is already running when the deadline has passed is still observed,
// because an unhandled rejection would end the process.
import { describe, expect, test } from "bun:test";
import { withRevokeTimeout } from "./revoke-timeout.ts";

describe("withRevokeTimeout", () => {
  test("revoke.spent_deadline_observes_work", async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => unhandled.push(reason);
    process.on("unhandledRejection", onUnhandled);
    try {
      const work = new Promise<void>((_, reject) => setTimeout(() => reject(new Error("revoke failed")), 5));
      await expect(withRevokeTimeout(work, AbortSignal.abort())).rejects.toThrow("revoke timed out");
      await new Promise((done) => setTimeout(done, 30));
      expect(unhandled).toEqual([]);
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }
  });
});
