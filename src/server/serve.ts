// Starts the HTTP server for the internal API and writes one log line per response. The line holds the route
// template, never the raw path, so a handle or DID in a URL never reaches the log (shared/log, rule SE-7).
import { Elysia } from "elysia";
import type { Logger } from "../shared/log/index.ts";
import { type InternalApiDeps, internalApi } from "./internal-api.ts";

const METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] as const);
type Method = typeof METHODS extends Set<infer M> ? M : never;
const isMethod = (value: string): value is Method => (METHODS as Set<string>).has(value);

/** The internal API with its request log, not yet listening. */
export function createServer(deps: InternalApiDeps, log: Logger) {
  const started = new WeakMap<Request, number>();
  const api = internalApi(deps);
  // Elysia 1.4.32 sets `Context.route` to the raw path when no route matched, so only a registered template is logged.
  const templates = new Set(api.routes.map((r) => r.path));
  return new Elysia()
    .onRequest(({ request }) => {
      started.set(request, performance.now());
    })
    .onAfterResponse(({ request, route, set }) => {
      const begun = started.get(request);
      log.info("http.request", {
        route: templates.has(route) ? route : "/*",
        ...(isMethod(request.method) ? { method: request.method } : {}),
        status: typeof set.status === "number" ? set.status : 200,
        ...(begun === undefined ? {} : { ms: Math.round(performance.now() - begun) }),
      });
    })
    .use(api);
}

/** Listens on `port`, and stops taking requests on SIGTERM or SIGINT, letting those in flight finish. */
export function serve(deps: InternalApiDeps, log: Logger, port: number) {
  const app = createServer(deps, log);
  try {
    app.listen(port);
  } catch (error) {
    log.error("http.listen_failed", { kind: error instanceof Error ? error.name : typeof error });
    process.exit(1);
  }
  const stop = () => {
    log.info("http.drain");
    void app.stop();
  };
  process.once("SIGTERM", stop);
  process.once("SIGINT", stop);
  return app;
}
