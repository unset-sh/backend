// The profile: what a member writes about themselves on their page, kept as their own sh.unset.profile record. This
// slice edits the display name only. Adapted from Undefined6799/unset@60228f5 domains/profile/profile.ts: limits come
// from the pinned lexicon copy (./lexicon, checked by profile.test.ts against source.json), graphemes are counted the
// way the lexicon counts them (Intl.Segmenter; https://atproto.com/specs/lexicon "string" maxGraphemes, maxLength in
// UTF-8 bytes). The lexicon at 964b523 makes the display name optional ("Absent means readers show the handle"), so
// unlike the old app an emptied name removes the field rather than being refused.
import lexicon from "./lexicon/sh.unset.profile.json" with { type: "json" };
import { isPlainName, isPlainText } from "./member-text.ts";

export const PROFILE_COLLECTION = "sh.unset.profile";

const properties = lexicon.defs.main.record.properties;

/** The display name's limits, from the lexicon. */
export const DISPLAY_NAME_LIMITS = {
  graphemes: properties.displayName.maxGraphemes,
  bytes: properties.displayName.maxLength,
} as const;

export type ProfileError = "name_invalid" | "name_too_long" | "record_invalid";

const segmenter = new Intl.Segmenter("en", { granularity: "grapheme" });
function graphemes(text: string, stopAfter: number): number {
  let count = 0;
  for (const _ of segmenter.segment(text)) if (++count > stopAfter) break;
  return count;
}
const bytes = (text: string) => new TextEncoder().encode(text).length;

const fits = (text: string, limits: { readonly graphemes?: number | undefined; readonly bytes?: number | undefined }) =>
  (limits.bytes === undefined || bytes(text) <= limits.bytes) &&
  (limits.graphemes === undefined || graphemes(text, limits.graphemes) <= limits.graphemes);

/**
 * A display name from untrusted input: one line of printable text with no bidirectional control or invisible
 * character (member-text.ts), trimmed, within the lexicon's limits. An empty name means "remove it".
 */
export function parseDisplayName(raw: unknown): { ok: true; value: string } | { ok: false; code: ProfileError } {
  if (typeof raw !== "string") return { ok: false, code: "name_invalid" };
  const value = raw.trim();
  if (!isPlainName(value)) return { ok: false, code: "name_invalid" };
  if (!fits(value, DISPLAY_NAME_LIMITS)) return { ok: false, code: "name_too_long" };
  return { ok: true, value };
}

/** The display name a stored record holds, or undefined. Another client may have written it, so a bad one is unset. */
export function readDisplayName(stored: unknown): string | undefined {
  const value = storedObject(stored).displayName;
  if (typeof value !== "string" || value === "") return undefined;
  return isPlainName(value) && fits(value, DISPLAY_NAME_LIMITS) ? value : undefined;
}

function storedObject(existing: unknown): Readonly<Record<string, unknown>> {
  return typeof existing === "object" && existing !== null && !Array.isArray(existing)
    ? (existing as Readonly<Record<string, unknown>>)
    : {};
}

type StringDef = { readonly maxLength?: number; readonly maxGraphemes?: number };
const STRING_FIELDS: Readonly<Record<string, StringDef>> = {
  displayName: properties.displayName,
  headline: properties.headline,
  avatarShape: properties.avatarShape,
  location: properties.location,
  website: properties.website,
  createdAt: {},
};

/**
 * Whether every field the lexicon defines holds a value of its type within its limits, so a record another client
 * broke is never written back under the member's name. A field the lexicon does not define is kept and not judged
 * (atproto.com/specs/lexicon, "Authority and Control"). The website's URI and createdAt's datetime formats are not
 * checked here: this slice never writes them, only carries them over.
 */
function definedFieldsValid(record: Readonly<Record<string, unknown>>): boolean {
  for (const [field, def] of Object.entries(STRING_FIELDS)) {
    const value = record[field];
    if (value === undefined) continue;
    if (typeof value !== "string" || !isPlainText(value, false)) return false;
    if (!fits(value, { bytes: def.maxLength, graphemes: def.maxGraphemes })) return false;
  }
  if (record.listed !== undefined && typeof record.listed !== "boolean") return false;
  const avatar = record.avatar;
  if (avatar !== undefined && (typeof avatar !== "object" || avatar === null || Array.isArray(avatar))) return false;
  return true;
}

export type ProfileRecord = { readonly $type: "sh.unset.profile"; readonly createdAt: string } & Readonly<
  Record<string, unknown>
>;

/**
 * The record to write over `existing` (the stored value, or null for a first profile) with `displayName` set, or
 * removed when empty. Every other field is kept as it was, createdAt too; a first profile gets `now`.
 */
export function withDisplayName(
  displayName: string,
  existing: unknown,
  now: string,
): { readonly ok: true; readonly record: ProfileRecord } | { readonly ok: false; readonly code: ProfileError } {
  const stored = storedObject(existing);
  if (!definedFieldsValid(stored)) return { ok: false, code: "record_invalid" };
  const { $type: _type, displayName: _old, ...kept } = stored;
  const createdAt = typeof stored.createdAt === "string" ? stored.createdAt : now;
  const record: ProfileRecord = {
    ...kept,
    $type: PROFILE_COLLECTION,
    ...(displayName === "" ? {} : { displayName }),
    createdAt,
  };
  return { ok: true, record };
}
