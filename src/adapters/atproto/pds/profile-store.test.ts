// The profile operations over the PDS adapter, end to end below the HTTP layer: the domain's createProfiles over
// createProfileStore over the real pdsCall and @atproto/api Agent, against an in-memory repo that keeps one record
// and enforces swapRecord the way a PDS does (com.atproto.repo.putRecord; InvalidSwap when the CID moved).
import { describe, expect, test } from "bun:test";
import { TokenRefreshError } from "@atproto/oauth-client";
import type { Did } from "../../../domains/identity/index.ts";
import { createProfiles } from "../../../domains/profile/operations.ts";
import type { Logger } from "../../../shared/log/index.ts";
import { createPdsCall } from "./pds-call.ts";
import { createProfileStore } from "./profile-store.ts";

const DID = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa" as Did;
const NOW = "2026-11-24T02:00:00.000Z";
const log: Logger = { info: () => undefined, warn: () => undefined, error: () => undefined, logError: () => undefined };

/** Valid dag-cbor CIDs (sha256 of "r0".."r3"), one per revision of the record. */
const CIDS = [
  "bafyreig5deljnyk6f3rjgqinajcuyx4umgrcjhponvl4oxzgj2xlqorxqi",
  "bafyreiec6pu4nfo4nogrwembrvlqdem6fbw6rvd7pq7lgeamjbpxtzlyfa",
  "bafyreig3o76qdl4voiq2jge3mszxocudupcwa2calopq5fai72xfp7ix4q",
  "bafyreihetvr3fkfhr4cixl6ewrmqaklahjneczporp4yv4k5mlzezwbupe",
];

type Repo = { value: Record<string, unknown> | null; cid: number };

function world(options: { restore?: () => never; answer?: (path: string) => Response | null; handle?: string } = {}) {
  const repo: Repo = { value: null, cid: 0 };
  const puts: Record<string, unknown>[] = [];
  const ended: Did[] = [];
  const cidOf = (n: number) => CIDS[n % CIDS.length] as string;
  const { pdsCall } = createPdsCall({
    client: {
      restore: async () => {
        if (options.restore !== undefined) options.restore();
        return {
          async fetchHandler(url: string, init: RequestInit) {
            const parsed = new URL(url, "https://pds.example");
            const forced = options.answer?.(parsed.pathname);
            if (forced) return forced;
            if (parsed.pathname === "/xrpc/com.atproto.repo.getRecord") {
              return repo.value === null
                ? Response.json({ error: "RecordNotFound", message: "Could not locate record" }, { status: 400 })
                : Response.json({ uri: `at://${DID}/sh.unset.profile/self`, cid: cidOf(repo.cid), value: repo.value });
            }
            const body = JSON.parse(await new Response(init.body).text()) as Record<string, unknown>;
            puts.push(body);
            const current = repo.value === null ? null : cidOf(repo.cid);
            if (body.swapRecord !== current) {
              return Response.json({ error: "InvalidSwap", message: "Record was at another CID" }, { status: 400 });
            }
            repo.value = body.record as Record<string, unknown>;
            repo.cid += 1;
            return Response.json({ uri: `at://${DID}/sh.unset.profile/self`, cid: cidOf(repo.cid) });
          },
        };
      },
    },
    endSessions: async (did) => {
      ended.push(did);
    },
    tokenSetRemains: async () => true,
    log,
  });
  const profiles = createProfiles({
    store: createProfileStore(pdsCall),
    handleOf: async () => options.handle,
    now: () => NOW,
  });
  return { repo, puts, ended, profiles };
}

describe("reading the profile", () => {
  test("a member with no record yet has a profile with no name", async () => {
    const { profiles } = world({ handle: "alice.example.com" });
    expect(await profiles.get(DID)).toEqual({ ok: true, profile: { did: DID, handle: "alice.example.com" } });
  });

  test("the stored name shows; an unverified handle is left out", async () => {
    const w = world();
    w.repo.value = { $type: "sh.unset.profile", displayName: "Alice", createdAt: NOW };
    expect(await w.profiles.get(DID)).toEqual({ ok: true, profile: { did: DID, displayName: "Alice" } });
  });

  test("a dead grant ends the sessions and answers session_ended", async () => {
    const w = world({
      restore: () => {
        throw new TokenRefreshError(DID, "The session was deleted");
      },
    });
    expect(await w.profiles.get(DID)).toEqual({ ok: false, reason: "session_ended" });
    expect(w.ended).toEqual([DID]);
  });

  test("a grant without the profile scope answers scope_missing, and ends nothing", async () => {
    const w = world({
      answer: () =>
        Response.json(
          { error: "ScopeMissingError", message: 'Missing required scope "repo:sh.unset.profile"' },
          {
            status: 403,
          },
        ),
    });
    expect(await w.profiles.get(DID)).toEqual({ ok: false, reason: "scope_missing" });
    expect(w.ended).toEqual([]);
  });

  test("a PDS that keeps failing answers pds_unreachable", async () => {
    const w = world({ answer: () => new Response("down", { status: 502 }) });
    expect(await w.profiles.get(DID)).toEqual({ ok: false, reason: "pds_unreachable" });
  });
});

describe("setting the display name", () => {
  test("a first profile is created with the name and createdAt, swapping on no record", async () => {
    const w = world();
    expect(await w.profiles.setDisplayName(DID, " Alice ")).toEqual({
      ok: true,
      profile: { did: DID, displayName: "Alice" },
    });
    expect(w.puts).toHaveLength(1);
    expect(w.puts[0]).toMatchObject({ repo: DID, collection: "sh.unset.profile", rkey: "self", swapRecord: null });
    expect(w.repo.value).toEqual({ $type: "sh.unset.profile", displayName: "Alice", createdAt: NOW });
  });

  test("an update keeps every other field, and an empty name removes it", async () => {
    const w = world();
    w.repo.value = {
      $type: "sh.unset.profile",
      displayName: "Old",
      headline: "Designer",
      pronouns: "they/them",
      createdAt: "2026-10-01T00:00:00.000Z",
    };
    await w.profiles.setDisplayName(DID, "New");
    expect(w.repo.value).toEqual({
      $type: "sh.unset.profile",
      displayName: "New",
      headline: "Designer",
      pronouns: "they/them",
      createdAt: "2026-10-01T00:00:00.000Z",
    });
    expect(await w.profiles.setDisplayName(DID, "")).toEqual({ ok: true, profile: { did: DID } });
    expect(w.repo.value).not.toHaveProperty("displayName");
  });

  test("a record changed between the read and the write is a conflict, and nothing is overwritten", async () => {
    // Another client writes after our read: the PDS refuses our swap.
    const w = world({
      answer: (path) =>
        path === "/xrpc/com.atproto.repo.putRecord"
          ? Response.json({ error: "InvalidSwap", message: "Record was at another CID" }, { status: 400 })
          : null,
    });
    const original = { $type: "sh.unset.profile", displayName: "Old", createdAt: NOW };
    w.repo.value = original;
    expect(await w.profiles.setDisplayName(DID, "New")).toEqual({ ok: false, reason: "conflict" });
    expect(w.repo.value).toEqual(original);
  });

  test("our write swaps on the CID it read", async () => {
    const w = world();
    w.repo.value = { $type: "sh.unset.profile", displayName: "Old", createdAt: NOW };
    w.repo.cid = 3;
    await w.profiles.setDisplayName(DID, "New");
    expect(w.puts[0]?.swapRecord).toBe(CIDS[3]);
  });

  test("a bad name never reaches the PDS", async () => {
    const w = world();
    expect(await w.profiles.setDisplayName(DID, "a‮b")).toEqual({ ok: false, reason: "name_invalid" });
    expect(await w.profiles.setDisplayName(DID, "a".repeat(65))).toEqual({ ok: false, reason: "name_too_long" });
    expect(w.puts).toEqual([]);
  });

  test("a stored record another client broke is not written back", async () => {
    const w = world();
    w.repo.value = { $type: "sh.unset.profile", listed: "yes", createdAt: NOW };
    expect(await w.profiles.setDisplayName(DID, "Alice")).toEqual({ ok: false, reason: "record_invalid" });
    expect(w.puts).toEqual([]);
  });
});
