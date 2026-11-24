// Key rotation without downtime (P1.14): a value or a stream header sealed under an old KEK gets its DEK re-wrapped by
// the active one. The data part is untouched, so no plaintext is ever produced and the value stays bound to its context.
import { SealError } from "./error.ts";
import { type Keys, unwrapDek, wrapDek } from "./seal.ts";

/**
 * `sealed` (an `s1` value) with its DEK wrapped by the active key.
 * A value already under the active key comes back unchanged.
 */
export function rewrap(keys: Keys, sealed: string): string {
  const parts = sealed.split(".");
  if (parts[0] !== "s1" || parts.length !== 6) throw new SealError("seal.format");
  const [form, kid, wrapIv, wrapped, ...data] = parts as [string, string, string, string, ...string[]];
  const dek = unwrapDek(keys, kid, wrapIv, wrapped);
  if (kid === keys.keyring.active) return sealed;
  return [form, wrapDek(keys, dek), ...data].join(".");
}
