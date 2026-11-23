// Guarded outbound requests (P1.18a). Every caller-influenced HTTP request names a policy, connects only to
// addresses vetted by resolveVetted, never follows a redirect, and is capped in time, bytes and decompressed bytes.
// On Bun the connection is Bun's fetch to the vetted address itself, with the name kept for Host, SNI and the
// certificate check (Bun 1.4.4 docs/runtime/networking/fetch.mdx, "Connecting to a specific address"). The old app's
// undici Agent and pinned lookup are not used: Bun replaces undici with a shim whose connect hooks did nothing before
// oven-sh/bun PR 38855, so a guard built on them would silently stop guarding (org-0015).
import { isIP } from "node:net";
import { pipeline, Readable, Transform } from "node:stream";
import type { ReadableStream as NodeReadableStream } from "node:stream/web";
import { createBrotliDecompress, createGunzip, createInflate } from "node:zlib";
import { classifyAddress, isInternalName, normaliseHost } from "./classify.ts";
import { type Policy, requestCap } from "./policies.ts";
import { type LookupAnswer, type NetGuardCode, NetGuardError, resolveVettedWith } from "./resolve.ts";

/** What the composition root passes in (parsed by shared/config netGuardFields, plus wiring). */
export type NetGuardSettings = {
  readonly internalHosts: readonly string[];
  readonly allowLoopback: boolean;
  /** Build commit, sent as `user-agent: unset.sh/<commit>`. */
  readonly commit: string;
  /** Trusted CA certificates (PEM). When set they replace the default trust store; when absent it is used. */
  readonly ca?: string | readonly string[];
  /** Called once per request. It never receives the host, URL or address, so none can reach a log. */
  readonly onRequest?: (event: EgressEvent) => void;
};

/** The one log line per request (SE-7 allowlist: event, dep, status, ms, counts, code). */
export type EgressEvent = {
  readonly event: "egress.request";
  /** The policy's name ("plc", "atproto"): which dependency was called, never which host. */
  readonly dep: string;
  readonly status: number | null;
  readonly ms: number;
  readonly counts: { readonly bytes: number };
  /** Why it failed; `egress.invalid` is a malformed request, thrown as a TypeError or RangeError. */
  readonly code?: NetGuardCode | "egress.invalid";
};

export type GuardedRequest = {
  url: string;
  /** PUT only on an `internal` policy (the object store's objects and tags, P2.18k); GET and POST on any. */
  method?: "GET" | "POST" | "PUT";
  /** Sent with keys lowercased. A `host` header is refused; `user-agent` and `accept-encoding` are always ours. */
  headers?: Record<string, string>;
  /** At most the policy's `requestBytes` (1 MiB unless it names more); a stream is read into memory first. */
  body?: Uint8Array | AsyncIterable<Uint8Array>;
  timeoutMs?: number;
  maxBytes?: number;
  accept?: readonly string[];
  signal?: AbortSignal;
};

export type GuardedResponse = { status: number; headers: Record<string, string | string[]>; body: Uint8Array };

/** Test seams, not exported from the package: the resolver stub and where sockets land. Vetting still runs. */
export type NetGuardHooks = {
  lookup?: (host: string) => Promise<LookupAnswer>;
  /** Given each vetted address the guard is about to dial, the address to dial instead (a fake server on loopback). */
  dial?: (address: string) => string;
  port?: number;
};

const MAX_TIMEOUT_MS = 30_000;
const MAX_BYTES = 64 * 1024 * 1024;
const DNS_TIMEOUT_MS = 3_000;
const CONNECT_TIMEOUT_MS = 5_000;
const ACCEPT_ENCODING = "gzip, br, identity";
const REDIRECTS = new Set([301, 302, 303, 307, 308]);
/** Statuses that never carry a body (WHATWG Fetch "null body status"). */
export const NULL_BODY_STATUSES: ReadonlySet<number> = new Set([101, 204, 205, 304]);

type Limits = { timeoutMs: number; maxBytes: number; requestBytes: number };
type Seen = { status: number | null; bytes: number };
type Target = { host: string; allow: "public" | "private"; loopbackOnly: boolean };

/** Method and limits: a bad value is the caller's programming error, not an egress failure. */
function checkRequest(policy: Policy, req: GuardedRequest): Limits {
  const method: string = req.method ?? "GET";
  const allowed = policy.kind === "internal" ? ["GET", "POST", "PUT"] : ["GET", "POST"];
  if (!allowed.includes(method)) throw new TypeError(`net-guard does not send ${method} on ${policy.kind} policies`);
  const timeoutMs = req.timeoutMs ?? 10_000;
  const maxBytes = req.maxBytes ?? 1024 * 1024;
  if (!(Number.isInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= MAX_TIMEOUT_MS)) {
    throw new RangeError("timeoutMs must be an integer in (0, 30000]");
  }
  if (!(Number.isInteger(maxBytes) && maxBytes > 0 && maxBytes <= MAX_BYTES)) {
    throw new RangeError("maxBytes must be an integer in (0, 64 MiB]");
  }
  return { timeoutMs, maxBytes, requestBytes: requestCap(policy) };
}

/**
 * The caller's headers with keys lowercased, then ours, which win: the user agent names us, and we decode only what
 * we advertise. A caller `host` header is refused, in any case: the guard sets Host itself to the name it vetted, and
 * a caller's would name another origin than the one the certificate is checked for.
 */
function requestHeaders(headers: Record<string, string> = {}, commit: string): Record<string, string> {
  const lowered = Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value] as const);
  if (lowered.some(([name]) => name === "host")) throw new TypeError("net-guard does not take a host header");
  return { ...Object.fromEntries(lowered), "accept-encoding": ACCEPT_ENCODING, "user-agent": `unset.sh/${commit}` };
}

const isLoopbackTarget = (host: string): boolean => host === "localhost" || classifyAddress(host) === "loopback";

/** Step 1: an absolute http(s) URL without credentials. */
function parseTarget(raw: string): URL {
  if (!URL.canParse(raw)) throw new NetGuardError("egress.scheme");
  const url = new URL(raw);
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new NetGuardError("egress.scheme");
  if (url.username !== "" || url.password !== "") throw new NetGuardError("egress.scheme");
  return url;
}

/** Steps 1 to 3: scheme, port and policy, before any DNS. The dev loopback flag never widens a fixed policy. */
function checkTarget(policy: Policy, raw: string, settings: NetGuardSettings): Target {
  const url = parseTarget(raw);
  const host = normaliseHost(url.hostname);
  if (policy.kind === "internal") {
    if (!policy.origins.includes(url.origin)) throw new NetGuardError("egress.host_not_allowed");
    return { host, allow: "private", loopbackOnly: false };
  }
  const devLoopback = settings.allowLoopback && isLoopbackTarget(host);
  if (url.protocol !== "https:" && !devLoopback) throw new NetGuardError("egress.scheme");
  if (url.port !== "" && url.port !== "443" && !devLoopback) throw new NetGuardError("egress.port");
  if (policy.kind === "fixed" && !policy.hosts.includes(host)) throw new NetGuardError("egress.host_not_allowed");
  if (devLoopback) return { host, allow: "private", loopbackOnly: true };
  if (policy.kind === "fixed") return { host, allow: "public", loopbackOnly: false };
  if (settings.internalHosts.includes(host)) return { host, allow: "private", loopbackOnly: false };
  if (isInternalName(host)) throw new NetGuardError("egress.internal_name");
  return { host, allow: "public", loopbackOnly: false };
}

/** The request body in memory, refused past `cap`; a stream stops being read once the deadline passes. */
async function bufferBody(body: GuardedRequest["body"], cap: number, signal: AbortSignal) {
  if (body === undefined || body instanceof Uint8Array) {
    if ((body?.length ?? 0) > cap) throw new NetGuardError("egress.too_large");
    return body;
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  for await (const chunk of body) {
    if (signal.aborted) throw new NetGuardError("egress.timeout");
    total += chunk.length;
    if (total > cap) throw new NetGuardError("egress.too_large");
    chunks.push(chunk);
  }
  return new Uint8Array(Buffer.concat(chunks));
}

/** The media type of a content-type header, lowercase, without parameters. */
const mediaType = (value: string | string[] | undefined): string =>
  String(Array.isArray(value) ? value[0] : (value ?? ""))
    .split(";")[0]
    ?.trim()
    .toLowerCase() ?? "";

function decoderFor(encoding: string): Transform | null {
  if (encoding === "" || encoding === "identity") return null;
  if (encoding === "gzip" || encoding === "x-gzip") return createGunzip();
  if (encoding === "deflate") return createInflate();
  if (encoding === "br") return createBrotliDecompress();
  throw new NetGuardError("egress.encoding");
}

/** zlib (`Z_DATA_ERROR`, `Z_BUF_ERROR`) and brotli (`ERR__ERROR_FORMAT_…`) decode failures. */
const isDecodeError = (error: unknown): boolean =>
  /^(Z_|ERR__ERROR_)/.test(String((error as { code?: unknown } | null)?.code ?? ""));

/** Drops a body we will not read; the abort it causes is expected, not an unhandled error. */
function discard(body: Readable): void {
  body.on("error", () => undefined);
  body.destroy();
}

function refuse(body: Readable, code: NetGuardCode): never {
  discard(body);
  throw new NetGuardError(code);
}

/** Passes bytes through, failing with `egress.too_large` once more than `maxBytes` raw (encoded) bytes arrive. */
function rawCap(maxBytes: number): Transform {
  let total = 0;
  return new Transform({
    transform(chunk: Buffer, _encoding, done) {
      total += chunk.length;
      done(total > maxBytes ? new NetGuardError("egress.too_large") : null, chunk);
    },
  });
}

async function collect(source: AsyncIterable<Buffer>, maxBytes: number, stop: () => void): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of source) {
    total += chunk.length;
    if (total > maxBytes) {
      stop();
      throw new NetGuardError("egress.too_large");
    }
    chunks.push(chunk);
  }
  return new Uint8Array(Buffer.concat(chunks));
}

/**
 * Steps 9 and 10: the body under the cap, counted both as it arrives and as it decodes, so neither a bomb nor an
 * endless run of empty compressed members gets past it. A corrupt encoding is `egress.encoding`.
 */
async function readCapped(body: Readable, encoding: string, maxBytes: number): Promise<Uint8Array> {
  const decoder = decoderFor(encoding);
  if (decoder === null) return collect(body, maxBytes, () => discard(body));
  const decoded = pipeline(body, rawCap(maxBytes), decoder, () => undefined); // errors reach the iterator
  try {
    return await collect(decoded, maxBytes, () => decoded.destroy());
  } catch (error) {
    throw isDecodeError(error) ? new NetGuardError("egress.encoding") : error;
  }
}

/** Response headers as a record with lowercase names; `set-cookie` keeps each value (WHATWG Headers getSetCookie). */
function headersOf(response: Response): GuardedResponse["headers"] {
  const headers: GuardedResponse["headers"] = {};
  for (const [name, value] of response.headers) if (name !== "set-cookie") headers[name] = value;
  const cookies = response.headers.getSetCookie();
  if (cookies.length > 0) headers["set-cookie"] = cookies;
  return headers;
}

/** The response checks, in order, then the body. A status outside 200 to 599 is not a final HTTP response. */
async function readBody(response: Response, req: GuardedRequest, maxBytes: number) {
  const { status } = response;
  const headers = headersOf(response);
  const body = response.body
    ? Readable.fromWeb(response.body as unknown as NodeReadableStream<Uint8Array>)
    : Readable.from([]);
  if (status < 200 || status > 599) refuse(body, "egress.connect");
  if (REDIRECTS.has(status)) refuse(body, "egress.redirect"); // never followed: the caller decides
  if (NULL_BODY_STATUSES.has(status) || headers["content-length"] === "0") {
    discard(body); // nothing to type-check or decode, whatever content-encoding claims
    return { status, headers, body: new Uint8Array() };
  }
  if (req.accept && !req.accept.includes(mediaType(headers["content-type"]))) refuse(body, "egress.content_type");
  if (Number(headers["content-length"] ?? 0) > maxBytes) refuse(body, "egress.too_large");
  const encoding = String(headers["content-encoding"] ?? "")
    .trim()
    .toLowerCase();
  return { status, headers, body: await readCapped(body, encoding, maxBytes) };
}

/** A socket or TLS failure as a NetGuardError; an abort (deadline or caller) is `egress.timeout`, during DNS too. */
function egressError(error: unknown, signal: AbortSignal): NetGuardError {
  const isGuardError = error instanceof NetGuardError;
  if (signal.aborted && (!isGuardError || error.code === "egress.dns_timeout")) {
    return new NetGuardError("egress.timeout");
  }
  if (isGuardError) return error;
  const code = String((error as { code?: unknown; cause?: { code?: unknown } })?.code ?? "");
  const cause = String((error as { cause?: { code?: unknown } })?.cause?.code ?? "");
  return /CERT|SSL|TLS|SIGNATURE|DEPTH_ZERO|ISSUER/.test(`${code} ${cause}`)
    ? new NetGuardError("egress.tls")
    : new NetGuardError("egress.connect");
}

/** An address in a URL's host: IPv6 in brackets (RFC 3986 3.2.2). */
const urlHost = (address: string): string => (isIP(address) === 6 ? `[${address}]` : address);

/**
 * One request to one vetted address: the URL names the address, so Bun dials it and resolves nothing; `Host` and
 * `tls.serverName` name the host, so SNI and the certificate check use the name. An IP literal gets no server name
 * (RFC 6066 3 forbids one), so its certificate must name the address. `proxy: false`, or Bun would judge the
 * environment's proxy against the address. `decompress: false`, so readCapped counts and decodes the bytes itself.
 * `keepalive: false`: no connection outlives the request it was vetted for.
 */
function dialOnce(
  address: string,
  url: URL,
  host: string,
  req: GuardedRequest,
  prepared: Prepared,
  signal: AbortSignal,
  settings: NetGuardSettings,
  hooks: NetGuardHooks,
): Promise<Response> {
  const target = new URL(url);
  target.hostname = urlHost(hooks.dial ? hooks.dial(address) : address);
  if (hooks.port !== undefined) target.port = String(hooks.port);
  const hostHeader = url.port === "" ? urlHost(host) : `${urlHost(host)}:${url.port}`;
  const ca = settings.ca === undefined ? {} : { ca: settings.ca as string | string[] };
  const tls =
    url.protocol === "https:"
      ? { tls: { rejectUnauthorized: true, ...(isIP(host) === 0 ? { serverName: host } : {}), ...ca } }
      : {};
  return fetch(target, {
    method: req.method ?? "GET",
    headers: { ...prepared.headers, host: hostHeader },
    ...(prepared.body ? { body: prepared.body } : {}),
    signal,
    redirect: "manual",
    proxy: false,
    decompress: false,
    keepalive: false,
    ...tls,
  } as BunFetchRequestInit);
}

type Prepared = { limits: Limits; headers: Record<string, string>; body: Uint8Array | undefined };

/** Steps 4 to 10 for one vetted target. */
async function exchange(
  target: Target,
  req: GuardedRequest,
  prepared: Prepared,
  signal: AbortSignal,
  settings: NetGuardSettings,
  hooks: NetGuardHooks,
  seen: Seen,
): Promise<GuardedResponse> {
  const { limits } = prepared;
  const addresses = await resolveVettedWith(
    target.host,
    { allow: target.allow },
    {
      timeoutMs: Math.min(DNS_TIMEOUT_MS, limits.timeoutMs),
      signal,
      ...(hooks.lookup ? { lookup: hooks.lookup } : {}),
    },
  );
  if (target.loopbackOnly && !addresses.every((a) => classifyAddress(a) === "loopback")) {
    throw new NetGuardError("egress.private_address");
  }
  const url = new URL(req.url);
  // Every vetted address in resolver order until one connects (Bun's fetch has no fallback for a dialled address,
  // docs/runtime/networking/fetch.mdx); a TLS failure or an abort ends the attempt, since another address of the
  // same name would present the same certificate.
  let response: Response | undefined;
  let lastError: unknown;
  for (const [index, address] of addresses.entries()) {
    // Bun's fetch has no connect timeout of its own, so while another address is left an address gets
    // CONNECT_TIMEOUT_MS to answer with headers before the next is tried; the last one has the whole deadline.
    const attempt = new AbortController();
    const timer = index < addresses.length - 1 ? setTimeout(() => attempt.abort(), CONNECT_TIMEOUT_MS) : undefined;
    try {
      const both = AbortSignal.any([signal, attempt.signal]);
      response = await dialOnce(address, url, target.host, req, prepared, both, settings, hooks);
      break;
    } catch (error) {
      lastError = error;
      const slow = attempt.signal.aborted && !signal.aborted;
      if (!slow && (signal.aborted || egressError(error, signal).code !== "egress.connect")) throw error;
      if (slow) lastError = new NetGuardError("egress.connect");
    } finally {
      clearTimeout(timer);
    }
  }
  if (response === undefined) throw lastError;
  seen.status = response.status;
  const read = await readBody(response, req, limits.maxBytes);
  seen.bytes = read.body.length;
  return read;
}

/** Every step in order: the request's own checks, then target, body and exchange under one deadline. */
async function guarded(
  policy: Policy,
  req: GuardedRequest,
  settings: NetGuardSettings,
  hooks: NetGuardHooks,
  seen: Seen,
): Promise<GuardedResponse> {
  const limits = checkRequest(policy, req);
  const headers = requestHeaders(req.headers, settings.commit);
  const deadline = AbortSignal.timeout(limits.timeoutMs);
  const signal = req.signal ? AbortSignal.any([deadline, req.signal]) : deadline;
  try {
    if (signal.aborted) throw new NetGuardError("egress.timeout"); // before any DNS lookup
    const target = checkTarget(policy, req.url, settings);
    const body = await bufferBody(req.body, limits.requestBytes, signal);
    return await exchange(target, req, { limits, headers, body }, signal, settings, hooks, seen);
  } catch (error) {
    throw egressError(error, signal);
  }
}

function report(settings: NetGuardSettings, event: EgressEvent): void {
  try {
    settings.onRequest?.(event);
  } catch {
    // DC-4 exception: a failing log callback must not change the egress outcome, and there is nowhere left to
    // report it from here without risking the target reaching a log.
  }
}

/** The guard with test seams; production code uses `createNetGuard`. */
export function createNetGuardWith(settings: NetGuardSettings, hooks: NetGuardHooks) {
  const request = async (policy: Policy, req: GuardedRequest): Promise<GuardedResponse> => {
    const started = performance.now();
    const seen: Seen = { status: null, bytes: 0 };
    let code: EgressEvent["code"];
    try {
      return await guarded(policy, req, settings, hooks, seen);
    } catch (error) {
      code = error instanceof NetGuardError ? error.code : "egress.invalid";
      throw error;
    } finally {
      const ms = Math.round(performance.now() - started);
      const event = {
        event: "egress.request",
        dep: policy.name,
        status: seen.status,
        ms,
        counts: { bytes: seen.bytes },
      } as const;
      report(settings, code === undefined ? event : { ...event, code });
    }
  };
  return { request };
}

export type NetGuard = ReturnType<typeof createNetGuardWith>;

export const createNetGuard = (settings: NetGuardSettings): NetGuard => createNetGuardWith(settings, {});
