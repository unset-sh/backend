// The Authorizer port (domains/access) on a Cerbos PDP running beside backend (agent-kit org-0018), reached over gRPC
// on a Unix socket that only backend and the PDP share. The only file that imports a Cerbos package.
//
// @cerbos/grpc 0.29.4 takes `unix:<path>` as its target with `tls: false` (packages/grpc/src/client.ts at
// cerbos/cerbos-sdk-javascript cf8dfd3), and every call takes `RequestOptions.signal` (@cerbos/core 0.33.3
// lib/client.d.ts). The spike (agent-kit notes/cerbos-authorization/spike.md) found that a stopped, paused or garbled
// PDP makes the call throw, never answer, so every throw and every timeout is `unavailable` here.
import { GRPC } from "@cerbos/grpc";
import type { Authorizer, Decision, Principal, Resource, ResourceKind, Resources } from "../../domains/access/index.ts";
import type { Logger } from "../../shared/log/index.ts";

export type CerbosOptions = {
  /** The PDP's gRPC socket, an absolute path. */
  readonly socketPath: string;
  /** The longest a decision may take before it is `unavailable`. */
  readonly timeoutMs: number;
  readonly log: Logger;
};

/** The roles the policies name: `member` with a session, `anonymous` without. The id is the DID, or a fixed word. */
const principalOf = (principal: Principal) =>
  principal.kind === "member" ? { id: principal.did, roles: ["member"] } : { id: "anonymous", roles: ["anonymous"] };

export function createCerbosAuthorizer(options: CerbosOptions): Authorizer & { close(): void } {
  const cerbos = new GRPC(`unix:${options.socketPath}`, { tls: false });
  const signal = () => AbortSignal.timeout(options.timeoutMs);
  return {
    async may<K extends ResourceKind>(
      principal: Principal,
      action: Resources[K]["actions"],
      resource: Resource<K>,
    ): Promise<Decision> {
      try {
        const allowed = await cerbos.isAllowed(
          {
            principal: principalOf(principal),
            resource: { kind: resource.kind, id: resource.id, attr: { ...resource.attributes } },
            action,
          },
          { signal: signal() },
        );
        return allowed === true ? "allow" : "deny";
      } catch (error) {
        options.log.logError(error);
        return "unavailable";
      }
    },
    async ready() {
      try {
        const { status } = await cerbos.checkHealth(undefined, { signal: signal() });
        return status === "SERVING";
      } catch {
        return false;
      }
    },
    close: () => cerbos.close(),
  };
}
