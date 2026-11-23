// The backend process's composition root: load the configuration (refusing to start on a missing or invalid key),
// build each dependency once, and hand them to the server. Nothing else constructs a dependency.
import { backendConfig } from "./config.ts";
import { serve } from "./server/serve.ts";
import { bootOrExit } from "./shared/config/index.ts";
import { createLogger } from "./shared/log/index.ts";

const config = bootOrExit(backendConfig);
const log = createLogger({ service: config.UNSET_SERVICE, commit: config.UNSET_COMMIT, env: config.UNSET_ENV });

serve({ ready: async () => true }, log, config.LISTEN_PORT);
