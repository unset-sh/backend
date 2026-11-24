// Test support: internal API dependencies whose every operation fails the test if called, so a test names only what
// it uses.
import type { InternalApiDeps, SessionsPort } from "./internal-api.ts";

const unused = (name: string) => () => {
  throw new Error(`test called sessions.${name}, which it did not provide`);
};

export const WEB_ORIGIN = "http://127.0.0.1:8080";

export function testDeps(
  overrides: Partial<Omit<InternalApiDeps, "sessions">> & { sessions?: Partial<SessionsPort> } = {},
) {
  const sessions: SessionsPort = {
    start: unused("start"),
    complete: unused("complete"),
    current: unused("current"),
    signOut: unused("signOut"),
    ...overrides.sessions,
  };
  return { ready: async () => true, webOrigin: WEB_ORIGIN, ...overrides, sessions } satisfies InternalApiDeps;
}
