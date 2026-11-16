// TIER 1 · the bridge's half of the witness's pointer contract (phase R, audit 2026-10-11 09:32Z): no anchor, no
// monotonic stamp — the drops carry the target and the act's fate, and the witness looks once at the close.
//   node <ts-node bin.js> -P mica-bridge/tsconfig.json mica-bridge/witness-pointer.test.ts   (from the repo root)
import { mkdtempSync, readdirSync, readFileSync, statSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

import {
  actIdentityKey,
  attemptPointerBytes,
  closePointerBytes,
  dropPointer,
  GuardDecisions,
  PointedActs,
  POINTER_FILE_MODE,
  UnguardedActs,
  witnessRecordClass,
} from "./witness-pointer";

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

/** The machine's SEEING_METHOD_DIGEST (seeing.test.ts SM-1 pins the same literal). */
const M = "bd91dc37fa7e5d0653c795c4878266a4482c1405d932ce0b073d50b5bce41b72";

check("WP-1 · the record class: the cross-repo pin, and refusals for a malformed method or derivation", () => {
  assert(witnessRecordClass(M, "INTEREST_LABEL@2b7df2aba755e90c") === "CONSEQUENCE@dd31bb90bb21909a", "pin (seeing.test.ts SM-2 pins the same)");
  let threw = 0;
  for (const [m, d] of [["xyz", "INTEREST_LABEL@2b7df2aba755e90c"], [M, "INTEREST_LABEL@XYZ"], [M, "CONSEQUENCE@0123456789abcdef"]]) {
    try {
      witnessRecordClass(m, d);
    } catch {
      threw++;
    }
  }
  assert(threw === 3, `refusals ${threw}`);
});

check("WP-2 · the ATTEMPT and CLOSE bytes are EXACTLY the contract's — NO mono, NO boot (the machine's seeing-intake.ts parses these literals)", () => {
  const a = attemptPointerBytes(
    { subject: "s", sessionId: "x", actionId: "a1", chain: "c".repeat(64), subjectSeq: 7, target: "/srv/x", label: "c1", derivationClass: "INTEREST_LABEL@2b7df2aba755e90c", targetFingerprint: null },
    1000
  );
  assert(
    a === `{"v":1,"kind":"ATTEMPT","subject":"s","sessionId":"x","actionId":"a1","chain":"${"c".repeat(64)}","subjectSeq":7,"target":"/srv/x","label":"c1","derivationClass":"INTEREST_LABEL@2b7df2aba755e90c","targetFingerprint":null,"at":1000}`,
    a
  );
  const g = { execute: true, decisionHash: "d".repeat(64) };
  const c = closePointerBytes({ subject: "s", sessionId: "x", actionId: "a1", chain: null, attemptSeq: 7, closedSeq: 9, guard: g, unguarded: false }, 1001);
  assert(
    c === `{"v":1,"kind":"CLOSE","subject":"s","sessionId":"x","actionId":"a1","chain":null,"attemptSeq":7,"closedSeq":9,"guard":{"execute":true,"decisionHash":"${"d".repeat(64)}"},"unguarded":false,"at":1001}`,
    c
  );
  const n = closePointerBytes({ subject: "s", sessionId: "x", actionId: "a1", chain: null, attemptSeq: 7, closedSeq: 9, guard: null, unguarded: true }, 1001);
  assert(n.includes('"guard":null,"unguarded":true'), n);
  // a stray field on the decision never rides through: the CLOSE copies the two keys only
  const extra = closePointerBytes({ subject: "s", sessionId: "x", actionId: "a1", chain: null, attemptSeq: 7, closedSeq: 9, guard: { ...g, mono: "9" } as typeof g, unguarded: false }, 1001);
  assert(!extra.includes('"mono"'), extra);
});

check("WP-3 · a drop is temp-then-rename, mode 0640 LITERALLY, ATTEMPT sorts before its CLOSE; nothing in flight remains", () => {
  assert(POINTER_FILE_MODE === 0o640, "the mode is 0640: the bridge writes, the witness's group reads, nobody else");
  const dir = mkdtempSync(join(tmpdir(), "wp-"));
  const r1 = dropPointer(dir, "A");
  const r2 = dropPointer(dir, "B");
  const r3 = dropPointer(dir, "C");
  assert(r1.ok && r2.ok && r3.ok, "drops landed");
  const names = readdirSync(dir).sort();
  assert(names.length === 3 && !names.some((x) => x.startsWith(".")), `names ${names.join(",")}`);
  assert(names.map((x) => readFileSync(join(dir, x), "utf8")).join("") === "ABC", "the per-process counter orders them in drop order");
  for (const x of names) assert((statSync(join(dir, x)).mode & 0o777) === 0o640, "mode");
});

check("WP-4 · a drop that cannot be written RETURNS a reason and never throws into the act's path", () => {
  const r = dropPointer("/nonexistent-intake-dir/x", "A");
  assert(!r.ok && r.reason === "ENOENT", JSON.stringify(r));
  const boom = dropPointer(mkdtempSync(join(tmpdir(), "wp-")), "A", { rename: () => { throw Object.assign(new Error("x"), { code: "EXDEV" }); } });
  assert(!boom.ok && boom.reason === "EXDEV", JSON.stringify(boom));
});

check("WP-5 · the /guard decision: FIRST WINS (a later call never changes the fate), handed ONCE, oldest forgotten past capacity", () => {
  const m = new GuardDecisions(2);
  const d = (execute: boolean) => ({ execute, decisionHash: "h".repeat(64) });
  const ka = actIdentityKey("s", "x", "a");
  assert(m.remember(ka, d(false)), "first stored");
  assert(!m.remember(ka, d(true)), "a second decision for the same act is refused");
  assert(m.take(ka)?.execute === false && m.take(ka) === null, "the first, once");
  m.remember(actIdentityKey("s", "x", "1"), d(true));
  m.remember(actIdentityKey("s", "x", "2"), d(true));
  m.remember(actIdentityKey("s", "x", "3"), d(true));
  assert(m.take(actIdentityKey("s", "x", "1")) === null && m.size === 2, "the oldest is forgotten");
});

check("WP-6 · the act's key is its FULL identity; the pointed/unguarded sets key the same way", () => {
  assert(actIdentityKey("s", "x", "a") !== actIdentityKey("s", "y", "a"), "sessionId is in the key");
  assert(actIdentityKey("s", "x\u0000a", "b") !== actIdentityKey("s", "x", "a\u0000b"), "no separator collision");
  const p = new PointedActs(4);
  p.add(actIdentityKey("s", "x", "a"), 7);
  p.add(actIdentityKey("s", "y", "a"), 8);
  assert(p.take(actIdentityKey("s", "x", "a")) === 7 && p.take(actIdentityKey("s", "y", "a")) === 8, "each its own attemptSeq");
  assert(p.take(actIdentityKey("s", "x", "a")) === null, "taken once");
  const u = new UnguardedActs(4);
  u.mark(actIdentityKey("s", "x", "a"));
  assert(u.has(actIdentityKey("s", "x", "a")) && !u.has(actIdentityKey("s", "y", "a")), "unguarded by full identity");
  assert(u.take(actIdentityKey("s", "x", "a")) && !u.take(actIdentityKey("s", "x", "a")), "taken once");
});

console.log(`CENSUS: ${passed} passed, ${failed} failed, ${passed + failed} total`);
if (failed > 0) process.exit(1);
