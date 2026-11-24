# The backend image: one image for both processes, the server (the default command, `bun src/main.ts`) and the
# one-shot migration (`bun src/adapters/postgres/migrate-cli.ts`, which deployment runs as its own service with the
# migrator's credentials only). Bun runs the TypeScript sources directly, so there is no build step.
#
# Both stages use the official Bun 1.4.4 images (.bun-version), pinned by their multi-arch index digests
# (https://hub.docker.com/r/oven/bun, tags 1.4.4-slim and 1.4.4-distroless, published 2026-10-22). The install stage
# needs a shell; the runtime stage is distroless (no shell, no package manager). scripts/image.test.ts holds every
# FROM to a digest. The image carries no secret: deployment supplies each <KEY>_FILE at run time.

FROM oven/bun:1.4.4-slim@sha256:1846adf22496bd711036aae8be147e57bdebbaea2e5264e3e0b5af1db187d9a4 AS deps
WORKDIR /app
COPY package.json bun.lock bunfig.toml ./
# Production dependencies only, exactly as locked, with no lifecycle scripts (bunfig.toml).
RUN bun install --frozen-lockfile --ignore-scripts --production

FROM oven/bun:1.4.4-distroless@sha256:153a951ae40106e125898103e6e990ee0f38e6aee7f561029e26cf9fbed23470 AS runtime
LABEL org.opencontainers.image.source="https://github.com/unset-sh/backend"
LABEL org.opencontainers.image.licenses="AGPL-3.0-only"
ENV NODE_ENV=production
WORKDIR /app
COPY --from=deps /app/node_modules /app/node_modules
COPY package.json bunfig.toml tsconfig.json ./
# The sources, migrations and lexicon copy; .dockerignore keeps the tests and fakes out.
COPY src /app/src
# The base runs as root; neither process needs it.
USER 65532:65532
EXPOSE 8080
# GET /health on the loopback probe (src/server/serve.ts `serveProbe`, PROBE_PORT, default 8081), which answers in
# plain HTTP while the API itself needs web's client certificate. Exec form, as there is no shell.
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=3 \
  CMD ["bun", "-e", "fetch(`http://127.0.0.1:${process.env.PROBE_PORT ?? 8081}/health`).then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
ENTRYPOINT ["bun"]
CMD ["src/main.ts"]
