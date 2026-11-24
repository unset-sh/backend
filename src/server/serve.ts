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

/**
 * GET /health in plain HTTP on 127.0.0.1 only, for the image's HEALTHCHECK: under mutual TLS a probe inside the
 * container has no client certificate, and must not be given web's. It answers nothing else, and nothing outside the
 * container reaches loopback.
 */
export function serveProbe(ready: InternalApiDeps["ready"], port: number) {
  return Bun.serve({
    hostname: "127.0.0.1",
    port,
    fetch: async (request) => {
      if (new URL(request.url).pathname !== "/health" || request.method !== "GET")
        return new Response(null, { status: 404 });
      const ok = await ready().catch(() => false);
      return Response.json({ status: ok ? "ok" : "unavailable" }, { status: ok ? 200 : 503 });
    },
  });
}

/** PEM text for the internal API's mutual TLS: backend's certificate and key, and the CA web's certificate is from. */
export type InternalTls = { readonly cert: string; readonly key: string; readonly clientCa: string };

/**
 * Bun.serve's TLS for `tls`: a client must show a certificate from `clientCa`, or the handshake fails before any
 * request reaches a route. Bun 1.4.4 bun-types `TLSOptions`: `requestCert` asks for the certificate, and a server's
 * `rejectUnauthorized` (true by default) refuses one that does not verify against `ca`, which replaces the public CAs.
 */
export const serverTls = (tls: InternalTls) =>
  ({ cert: tls.cert, key: tls.key, ca: tls.clientCa, requestCert: true, rejectUnauthorized: true }) as const;

/**
 * Listens on `port`, over mutual TLS when `tls` is given (plain HTTP only in dev and test, config.ts), and stops
 * taking requests on SIGTERM or SIGINT, letting those in flight finish.
 */
export function serve(
  deps: InternalApiDeps,
  log: Logger,
  ports: { readonly api: number; readonly probe: number },
  tls?: InternalTls,
) {
  const app = createServer(deps, log);
  let probe: ReturnType<typeof serveProbe> | undefined;
  try {
    app.listen(tls === undefined ? ports.api : { port: ports.api, tls: serverTls(tls) });
    probe = serveProbe(deps.ready, ports.probe);
  } catch (error) {
    log.error("http.listen_failed", { kind: error instanceof Error ? error.name : typeof error });
    process.exit(1);
  }
  const stop = () => {
    log.info("http.drain");
    void app.stop();
    void probe?.stop();
  };
  process.once("SIGTERM", stop);
  process.once("SIGINT", stop);
  return app;
}
