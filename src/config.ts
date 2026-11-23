// The backend process's configuration: the keys every entrypoint has (UNSET_ENV, UNSET_SERVICE, UNSET_COMMIT,
// LISTEN_PORT). Each later step adds the keys it reads, here, so boot refuses a missing one.
import { defineEntrypointConfig } from "./shared/config/index.ts";

export const backendConfig = defineEntrypointConfig({});
