// ── canonical-json — the one canonicalisation rule, per design §C.4 ──────────
//
// 1. Object keys sorted ascending by Unicode code point, after NFC of the key.
// 2. All strings NFC-normalized (keys and values) before serialization.
// 3. UTF-8. No \uXXXX escaping except where JSON requires it.
// 4. undefined and absent are the same thing and are omitted. null is KEPT.
// 5. No whitespace anywhere.
// 6. Numbers here are whatever JSON.stringify would emit for a JS number;
//    the design's "integers only in hashed bodies" is a caller discipline
//    for request/event bodies, not something this function enforces — this
//    function is the shared primitive both the declaration hash and the
//    request/event hashes are built on.
// 7. Arrays keep their order.
// 8. sha256(canonical) is written as lowercase hex, no "sha256:" prefix.

import { createHash } from "crypto";

function nfc(s: string): string {
  return s.normalize("NFC");
}

function canonicalizeValue(value: unknown): unknown {
  if (value === undefined) return undefined;
  if (value === null) return null;
  if (typeof value === "string") return nfc(value);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) {
    return value.map((v) => canonicalizeValue(v));
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj)
      .filter((k) => obj[k] !== undefined)
      .map((k) => nfc(k))
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const out: Record<string, unknown> = {};
    for (const k of keys) {
      // re-fetch by original key if NFC changed it; declarations here are ASCII so this is a no-op guard
      const original = Object.keys(obj).find((ok) => nfc(ok) === k) as string;
      out[k] = canonicalizeValue(obj[original]);
    }
    return out;
  }
  throw new Error(`canonical-json: unsupported value type ${typeof value}`);
}

/** Recursively-sorted-key, NFC, no-whitespace JSON text of `value`. */
export function canonicalStringify(value: unknown): string {
  const c = canonicalizeValue(value);
  return serialize(c);
}

function serialize(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("canonical-json: non-finite number");
    return String(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map((v) => serialize(v)).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const parts = Object.keys(obj).map((k) => JSON.stringify(k) + ":" + serialize(obj[k]));
    return "{" + parts.join(",") + "}";
  }
  throw new Error(`canonical-json: unsupported value type ${typeof value}`);
}

/** sha256 hex digest over the canonical form of `value`. */
export function canonicalHash(value: unknown): string {
  const text = canonicalStringify(value);
  return createHash("sha256").update(text, "utf8").digest("hex");
}
