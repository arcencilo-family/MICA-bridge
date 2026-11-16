// THE LITERAL FENCE, COMMITTED (audit 2026-10-11 06:13Z ④) — the bridge's copy; the machine holds its own
// (src/witness/witness-fence.test.ts). Two copies on purpose: the trees share no code (S94).
//   node <ts-node bin.js> -P mica-bridge/tsconfig.json mica-bridge/witness-fence.test.ts   (from the repo root)
//
// The ruled list is held ONLY AS SHA-256 HASHES of lowercase tokens, so this file names nothing. Two more sources,
// BY USE: the served subjects of this tree's own declaration (name, unit, tool, stakes class, uid), and the
// operator's account when the test runs under a /home account. Owned files: zero hits. The witness block of an
// edited file: zero. Edited files with hits from BEFORE this build: a ratchet at the measured count.
import { shippedDraft } from "./example-draft";
import { createHash } from "crypto";
import { readFileSync } from "fs";
import { homedir, userInfo } from "os";
import { basename, join, resolve } from "path";

let passed = 0;
let failed = 0;
function check(name: string, fn: () => void): void {
  try {
    fn();
    console.log(`PASS  ${name}`);
    passed++;
  } catch (e) {
    console.log(`FAIL  ${name}\n      ${(e as Error).message}`);
    failed++;
  }
}
function assert(c: boolean, m: string): void {
  if (!c) throw new Error(m);
}

const HERE = resolve(__dirname);
const RULED: ReadonlySet<string> = new Set([
  "414360a5214ca1a5e3e78daab9eaa98f4cda5eae68345148afc153d0f515d5f1",
  "b1607410ecc9857e9c2da29d3acb1e9af58897cb61ffafc0140cb99ccd3504be",
  "cf5bfb26b102bbfb26a07758c8153b7dbb453374eeb4ac0aa20b2b2597a963da",
  "38879b6376fbabdc8fbfb85f6b11a296aca6de14093a54881b73528b62848d8c",
  "37d2b12d5d9abc2a364ef9448767ee03938e383c0284193477dc7618f4b7c6c2",
  "c70442de124ba47f7691057dfc6be35239196b5c979d4ac5340d29e38d9fea84",
]);
const sha = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");
const tokens = (text: string): string[] => text.toLowerCase().match(/[a-z0-9]+(?:-[a-z0-9]+)*/g) ?? [];

/** BY USE: the served subjects of this tree's declaration, and the operator's /home account. */
const served = shippedDraft() as { subjects: Record<string, unknown>[] };
const BY_USE: ReadonlySet<string> = new Set([
  ...served.subjects.flatMap((s) =>
    ["subject", "unit", "toolName", "stakesClass", "peerUid"].flatMap((k) => (s[k] === undefined || s[k] === null ? [] : tokens(String(s[k]))))
  ).filter((t) => t !== "service"),
  ...(homedir().startsWith("/home/") ? [userInfo().username.toLowerCase(), basename(homedir()).toLowerCase()] : []),
]);

function hits(text: string): string[] {
  const out: string[] = [];
  for (const tok of tokens(text)) {
    const parts = tok.includes("-") ? [tok, ...tok.split("-")] : [tok];
    if (parts.some((p) => RULED.has(sha(p)) || BY_USE.has(p))) out.push(tok);
  }
  return out;
}
const read = (rel: string): string => readFileSync(join(HERE, rel), "utf8");

const OWNED = [
  "witness-pointer.ts",
  "witness-pointer.test.ts",
  "witness-drops.test.ts",
  "witness-fence.test.ts",
  "tools/witness-rehearsal.ts",
  "to-wire-options.ts",
  "declarations.schema.json",
  // Long Run A Stop 2: the harm wiring's service-level suite is fixture-only by construction.
  "gate2-harm.test.ts",
];
const BLOCKS: readonly [string, string][] = [["declarations.test.ts", "TIER 1 · THE WITNESS'S PATHS, AND GATE 2 ON THE WITNESS'S BOOK"]];
const RATCHET: Readonly<Record<string, number>> = { "declarations.ts": 3, "mica-service.ts": 7, "declarations.test.ts": 57 };

check("F-1 · the scanner FINDS what it is for: every ruled token, a hyphen-part, the served names by use, the operator", () => {
  const word = (codes: number[]): string => String.fromCharCode(...codes);
  const planted = [
    word([104, 111, 117, 115, 101, 107, 101, 101, 112, 101, 114]),
    word([114, 105, 99, 104, 97, 114, 100, 115, 45, 99, 97, 116]),
    word([99, 108, 97, 117, 100, 101, 45, 98, 111, 116]),
    word([57, 56, 48]),
    word([98, 97, 115, 104]),
    word([102, 121, 108, 103, 105, 97, 110]),
  ];
  for (const p of planted) assert(hits(`x ${p} y`).length === 1, `not found: token #${String(planted.indexOf(p))}`);
  assert(hits(`/home/${planted[5]}/x`).length === 1, "inside a path");
  assert(BY_USE.size > 0 && [...BY_USE].every((n) => hits(` ${n} `).length === 1), "every by-use name is found");
  assert(hits("1980 9800 basher housekeeping").length === 0, "never a mere substring");
});

check("F-2 · every file the witness build OWNS holds zero ruled or served literals", () => {
  const found = OWNED.flatMap((f) => hits(read(f)).map((t) => `${f}: ${t}`));
  assert(found.length === 0, found.join(", "));
});

check("F-3 · the witness BLOCK of each edited file holds zero", () => {
  for (const [f, marker] of BLOCKS) {
    const text = read(f);
    const at = text.indexOf(marker);
    assert(at >= 0, `${f}: the marker moved — re-scope this fence, never drop it`);
    const found = hits(text.slice(at));
    assert(found.length === 0, `${f}: ${found.join(", ")}`);
  }
});

check("F-4 · the RATCHET: an edited file never gains a hit; its old hits are named, not hidden", () => {
  for (const [f, frozen] of Object.entries(RATCHET)) {
    const n = hits(read(f)).length;
    assert(n <= frozen, `${f}: ${String(n)} hits, frozen at ${String(frozen)} — a new literal entered`);
    if (n < frozen) console.log(`      ${f}: ${String(n)} < ${String(frozen)} — lower the ratchet to ${String(n)}`);
  }
});

console.log(`CENSUS: ${passed} passed, ${failed} failed, ${passed + failed} total`);
if (failed > 0) process.exit(1);
