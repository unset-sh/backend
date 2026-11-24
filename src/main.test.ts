// The composition root refuses to start while Better Auth's telemetry variables are set, whatever else is configured
// (better-auth.ts TELEMETRY_VARIABLES), with the configuration exit code and the variable's name only.
import { describe, expect, test } from "bun:test";
import { TELEMETRY_VARIABLES } from "./adapters/auth/index.ts";

describe("boot", () => {
  test.each(TELEMETRY_VARIABLES)("refuses_to_start_with_%s_set", async (name) => {
    const child = Bun.spawn(["bun", "src/main.ts"], {
      cwd: `${import.meta.dir}/..`,
      env: { PATH: process.env.PATH ?? "", [name]: "1" },
      stdout: "pipe",
      stderr: "pipe",
    });
    const [code, stderr] = await Promise.all([child.exited, new Response(child.stderr).text()]);
    expect(code).toBe(78);
    expect(stderr).toContain(`"key":"${name}"`);
  });
});
