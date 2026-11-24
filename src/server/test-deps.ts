// Test support: internal API dependencies whose every operation fails the test if called, so a test names only what
// it uses.
import type { InternalApiDeps, ProfilesPort, SessionsPort } from "./internal-api.ts";

const unused = (name: string) => () => {
  throw new Error(`test called ${name}, which it did not provide`);
};

export const WEB_ORIGIN = "http://127.0.0.1:8080";

export function testDeps(
  overrides: Partial<Omit<InternalApiDeps, "sessions" | "profiles">> & {
    sessions?: Partial<SessionsPort>;
    profiles?: Partial<ProfilesPort>;
  } = {},
) {
  const sessions: SessionsPort = {
    start: unused("sessions.start"),
    complete: unused("sessions.complete"),
    current: unused("sessions.current"),
    signOut: unused("sessions.signOut"),
    ...overrides.sessions,
  };
  const profiles: ProfilesPort = {
    get: unused("profiles.get"),
    setDisplayName: unused("profiles.setDisplayName"),
    ...overrides.profiles,
  };
  return { ready: async () => true, webOrigin: WEB_ORIGIN, ...overrides, sessions, profiles } satisfies InternalApiDeps;
}
