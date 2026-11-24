// Where the Cerbos PDP listens and how long a decision may take (agent-kit org-0018).
import { int, str } from "../../shared/config/index.ts";

export const cerbosFields = {
  /** The PDP's gRPC Unix socket: an absolute path on a volume only backend and the PDP mount. */
  CERBOS_SOCKET: str({ pattern: /(?:\/[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}){1,8}/ }),
  /** A decision that takes longer is `unavailable`, answered as 503. The spike's warm p99 was about 1 ms. */
  CERBOS_TIMEOUT_MS: int({ min: 10, max: 5_000, default: 200 }),
};
