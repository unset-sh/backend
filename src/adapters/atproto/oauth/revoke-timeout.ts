// The time limit on revoking an OAuth grant at sign-out (src/adapters/auth/). Its own file so it can be tested alone.
// Copied from Undefined6799/unset@60228f5 interfaces/web/src/lib/server/revoke-timeout.ts.

/** Book P2.08: the revocation call gets 10 seconds. */
const REVOKE_MS = 10_000;

/**
 * `work`, or a rejection after 10 seconds or when `deadline` aborts, whichever comes first. `work` is already running,
 * so it is always observed: a late rejection must not be an unhandled one.
 */
export function withRevokeTimeout(work: Promise<void>, deadline: AbortSignal): Promise<void> {
  const limit = AbortSignal.any([deadline, AbortSignal.timeout(REVOKE_MS)]);
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(new Error("revoke timed out"));
    work.then(resolve, reject).finally(() => limit.removeEventListener("abort", onAbort));
    if (limit.aborted) onAbort();
    else limit.addEventListener("abort", onAbort, { once: true });
  });
}
