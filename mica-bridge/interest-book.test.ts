// ── interest-book.test — Gate 1's label CLASS and the book record, pure ─────
//
// GATE 1 · Stop 2 · round 2 (placement D). Pinned here, without a service:
//
//   1. `frameLabelEventType` — the class a label is filed under. Its formula,
//      and the property it exists for: a change that changes WHICH LABEL an act
//      would get (a derivation-rule version, the canonicaliser's version, a
//      region) moves the class; an edit that changes no act's label (a wording
//      edit, a new category with no region) does not. The review's drift cases
//      (C2-2, C2-3) are run as drawings: each later drawing is a different
//      class, so labels derived under the earlier one are not counted against it.
//   2. the writer and the wiring agree BY CONSTRUCTION: toWireOptions' labelClass
//      is the same call on the same frame, and gate1BookPath is the declared book
//      resolved like logPath; `derivable` is the writer's own deriver's answer.
//   3. `buildInterestLabelRecord` — the exact book record, its non-decreasing
//      timestamp, and that the target is not an input to it.
//
// The end-to-end half (a real POST writes the book after the act; a failed book
// append leaves the response unchanged and writes the event-book entry; the
// subject chain is byte-identical with and without a frame) is in
// mica-service.test.ts.
//
// House harness: each check() prints PASS/FAIL, the exit code is set AT the
// failure, the tally is COUNTED. Run with:
//   <home>/mica-machine/node_modules/.bin/ts-node \
//     -P mica-bridge/tsconfig.json mica-bridge/interest-book.test.ts

import { createHash } from "crypto";
import { readFileSync } from "fs";
import { join } from "path";
import {
  buildInterestLabelRecord,
  frameLabelEventType,
  INTEREST_BOOK_BOUNDARY_BASIS,
  INTEREST_LABEL_CLASS_HEAD,
  INTEREST_LABEL_NOT_PERSISTED,
} from "./interest-book";
import { deriveInterestLabel, INTEREST_DERIVATION_VERSION, INTEREST_UNDERIVED } from "./interest-label";
import { TARGET_CANON_VERSION } from "./target-fingerprint";
import { validateDeclarations } from "./declarations";
import { toWireOptions } from "./to-wire-options";
import { SUBJECT_EVENT_KINDS } from "./mica-service";

let passed = 0;
let failed = 0;

function check(name: string, fn: () => void): void {
  try {
    fn();
    passed++;
    console.log(`PASS  ${name}`);
  } catch (err) {
    failed++;
    // ⛔ THE EXIT CODE IS SET HERE, AT THE FAILURE, NOT AT THE TALLY.
    process.exitCode = 1;
    console.log(`FAIL  ${name}`);
    console.log(`      ${err instanceof Error ? err.message : String(err)}`);
  }
}

function assert(cond: boolean, msg: string): void {
  if (!cond) throw new Error(`assertion failed: ${msg}`);
}

// ── fixtures ─────────────────────────────────────────────────────────────────

const FIXTURE = JSON.parse(readFileSync(join(__dirname, "declarations.fixture.json"), "utf8"));
const BASIS = "GATE 1 FIXTURE, not a declaration. Exercises the interest book's class.";
const BOOK = "/var/lib/mica-bridge/interest-book.jsonl";

/** The fixture, pilot neutralised, plus subject-a bound to the fixture subject's own peer (no uid typed). */
function base(): any {
  const d = JSON.parse(JSON.stringify(FIXTURE));
  d.pilot = { active: false };
  const s0 = d.subjects[0];
  d.subjects.push({ subject: "subject-a", toolName: "tool-x", stakesClass: s0.stakesClass, peerUid: s0.peerUid });
  return d;
}
const cat = (id: string, self = false, grounding = "need") => ({ id, label: `${id} area`, grounding, self });
const reg = (prefix: string, category: string) => ({ prefix, category });
function frameOf(categories: any[], regions: any[]): any {
  return { categories: { value: categories, basis: BASIS, proxy: true }, regions: { value: regions, basis: BASIS, proxy: true } };
}
/** v1 of the review's drift probe (C2-2): three categories, three regions. */
function v1(): any {
  return frameOf(
    [cat("c-self", true), cat("c-other"), cat("c-shared")],
    [reg("/srv/self", "c-self"), reg("/srv/other", "c-other"), reg("/etc", "c-shared")]
  );
}
function declaredWith(frame: any, reader = true): any {
  const d = base();
  d.frame = { "subject-a": frame };
  if (reader) {
    d.readers.gate1Scope = { subject: { value: "subject-a", basis: BASIS, proxy: false } };
    d.paths.interestBook = BOOK;
  }
  return d;
}
const load = (d: any) => validateDeclarations(d).declarations;

// ── 1 · the class ────────────────────────────────────────────────────────────

check("the class is INTEREST_LABEL@ + the first 16 hex of sha256 over JSON [derivation version, canon version, [prefix, category] pairs SORTED] — the input WRITTEN OUT BY HAND, versions as literals", () => {
  // ROUND 3 (B1). The digest input is spelt here, not computed by the code's
  // own sort or read from its constants: the literals 4 and 1 ARE the pin. A
  // rule change that bumps either version turns this arm red on purpose — the
  // bump is then a deliberate re-pin, not a silent one. (S211 re-pinned 3 -> 4.)
  const input = '[4,1,[["/etc","c-shared"],["/srv/other","c-other"],["/srv/self","c-self"]]]';
  const expected = "INTEREST_LABEL@" + createHash("sha256").update(input, "utf8").digest("hex").slice(0, 16);
  assert(INTEREST_DERIVATION_VERSION === 4 && TARGET_CANON_VERSION === 1,
    `a rule version moved (derivation ${INTEREST_DERIVATION_VERSION}, canon ${TARGET_CANON_VERSION}) — re-pin this arm by hand`);
  const got = frameLabelEventType(v1());
  assert(got === expected, `class ${got}, expected ${expected}`);
  assert(/^INTEREST_LABEL@[0-9a-f]{16}$/.test(got), `not the class shape: ${got}`);
  assert(got.startsWith(INTEREST_LABEL_CLASS_HEAD), `the exported head is not the head used: ${INTEREST_LABEL_CLASS_HEAD}`);
  assert(frameLabelEventType(v1()) === got, "the class is not deterministic over an equal drawing");
  // The default versions ARE this build's constants — the writer and the wiring pass none.
  assert(frameLabelEventType(v1(), { derivation: INTEREST_DERIVATION_VERSION, canon: TARGET_CANON_VERSION }) === got,
    "the default versions are not the exported constants");
});

check("A RULE CHANGE MOVES THE CLASS — a derivation-version bump and a canon-version bump each give another class over the SAME drawing (reviews K1R1-N2, K2W3-5, K1R3-5, K2W-6, K3D2-9)", () => {
  // The review's case: one unchanged drawing, two deriver builds. Round 3's own
  // rule change (a ":" anywhere) moved this target's label; the class must too.
  const home = frameOf([cat("c-home", true), cat("c-rest")], [reg("/home/op-x", "c-home"), reg("/", "c-rest")]);
  const t = "/home/op-x/localhost:8080/api";
  assert(deriveInterestLabel(t, home.regions.value, t) === INTEREST_UNDERIVED, "precondition: today's rules leave the host:port UNDERIVED");
  const now = frameLabelEventType(home);
  const d = INTEREST_DERIVATION_VERSION;
  const c = TARGET_CANON_VERSION;
  const earlierRules = frameLabelEventType(home, { derivation: d - 1, canon: c });
  const laterRules = frameLabelEventType(home, { derivation: d + 1, canon: c });
  const otherCanon = frameLabelEventType(home, { derivation: d, canon: c + 1 });
  const all = [now, earlierRules, laterRules, otherCanon];
  assert(new Set(all).size === all.length, `a rule version did not move the class: ${JSON.stringify(all)}`);
  // And the two numbers are not interchangeable positions.
  assert(frameLabelEventType(home, { derivation: 1, canon: 2 }) !== frameLabelEventType(home, { derivation: 2, canon: 1 }), "the two versions are hashed as one unordered pair");
});

check("the class is never a subject-chain kind and never the underived word — a book record cannot be read as an act", () => {
  const c = frameLabelEventType(v1());
  assert(!(SUBJECT_EVENT_KINDS as readonly string[]).includes(c), `the class ${c} is a subject-event kind`);
  assert(c !== INTEREST_UNDERIVED, "the class is the underived word");
  assert(!(SUBJECT_EVENT_KINDS as readonly string[]).some((k) => k.startsWith(INTEREST_LABEL_CLASS_HEAD)), "a subject-event kind wears the class head");
});

check("A REGION EDIT MOVES THE CLASS — prefix moved, region reassigned, region removed, region added: all distinct", () => {
  const variants: Record<string, any> = {
    v1: v1(),
    prefixMoved: frameOf(v1().categories.value, [reg("/srv/self", "c-self"), reg("/srv/elsewhere", "c-other"), reg("/etc", "c-shared")]),
    reassigned: frameOf(v1().categories.value, [reg("/srv/self", "c-self"), reg("/srv/other", "c-shared"), reg("/etc", "c-shared")]),
    removed: frameOf(v1().categories.value, [reg("/srv/self", "c-self"), reg("/etc", "c-shared")]),
    added: frameOf(v1().categories.value, [reg("/srv/self", "c-self"), reg("/srv/other", "c-other"), reg("/etc", "c-shared"), reg("/opt", "c-other")]),
  };
  const classes = Object.entries(variants).map(([k, f]) => [k, frameLabelEventType(f)] as const);
  const distinct = new Set(classes.map(([, c]) => c));
  assert(distinct.size === classes.length, `two drawings share a class: ${JSON.stringify(classes)}`);
});

check("CATEGORY IDS ENTER ONLY THROUGH THEIR REGIONS — a renamed or dropped id that HAS a region moves the class; a NEW category with NO region (X21's one admitted widening) KEEPS it (reviews K2W-4, K2W-5, K2W3-6)", () => {
  const regions = v1().regions.value;
  const renamed = frameOf([cat("c-self", true), cat("c-peer"), cat("c-shared")], [reg("/srv/self", "c-self"), reg("/srv/other", "c-peer"), reg("/etc", "c-shared")]);
  const dropped = frameOf([cat("c-self", true), cat("c-shared")], [reg("/srv/self", "c-self"), reg("/etc", "c-shared")]);
  const widened = frameOf([...v1().categories.value, cat("c-unmapped")], regions);
  const c0 = frameLabelEventType(v1());
  for (const [name, f] of [["renamed", renamed], ["dropped", dropped]] as const) {
    assert(frameLabelEventType(f) !== c0, `a category ${name} with its region kept the class`);
  }
  // THE WIDENING: no act's label changes, so no history may be orphaned.
  const targets = ["/srv/self/a", "/srv/other/b", "/etc/c", "/nowhere", "tool-x"];
  for (const t of targets) {
    assert(deriveInterestLabel(t, regions, t) === deriveInterestLabel(t, widened.regions.value, t), `precondition: the widening changed the label of ${t}`);
  }
  assert(frameLabelEventType(widened) === c0, "a region-less category moved the class — one admitted widening would orphan the whole book");
  // THROUGH THE FRONT DOOR AND THE WIRING: the loaded widened frame names the
  // same class, and the reader is handed it — while M itself grew.
  const before = toWireOptions(load(declaredWith(v1()))) as any;
  const after = toWireOptions(load(declaredWith(widened))) as any;
  assert(after.gate1.labelClass.eventType === before.gate1.labelClass.eventType, "the wiring's class moved on a region-less widening");
  assert(after.gate1.categories.length === before.gate1.categories.length + 1, "precondition: M did not grow");
  const added = after.gate1.categories.find((c: any) => c.id === "c-unmapped");
  assert(added !== undefined && added.derivable === false, `the region-less category is not NOT READABLE: ${JSON.stringify(added)}`);
});

check("A WORDING EDIT DOES NOT — labels, groundings, both bases, both proxy flags and the self flag leave the class where it was", () => {
  const c0 = frameLabelEventType(v1());
  const edits: [string, (f: any) => void][] = [
    ["label", (f) => (f.categories.value[1].label = "a wholly different wording")],
    ["grounding", (f) => (f.categories.value[1].grounding = "vulnerability")],
    ["categories.basis", (f) => (f.categories.basis = "another basis")],
    ["regions.basis", (f) => (f.regions.basis = "another basis")],
    ["categories.proxy", (f) => (f.categories.proxy = false)],
    ["regions.proxy", (f) => (f.regions.proxy = false)],
    ["self moved", (f) => { f.categories.value[0].self = false; f.categories.value[2].self = true; }],
  ];
  for (const [name, edit] of edits) {
    const f = v1();
    edit(f);
    assert(frameLabelEventType(f) === c0, `a ${name} edit moved the class — a wording edit would orphan the book's history`);
  }
  // AND THROUGH THE FRONT DOOR: the loaded frame names the same class as the raw one.
  const loaded = load(declaredWith(v1()));
  assert(frameLabelEventType(loaded.frame!["subject-a"]) === c0, "the loaded frame names a different class than the declared one");
});

check("ORDER IS NOT IN THE CLASS — a pure reorder of regions or categories places no act differently and KEEPS the class; a moved prefix still moves it", () => {
  // Round 2, seat: the spec hashed declared order and BRIDGE-2 pinned the cost
  // (a reorder orphaned history it need not). Both lists are now sorted first.
  const f = v1();
  const reordered = frameOf(f.categories.value, [...f.regions.value].reverse());
  const catsReordered = frameOf([...f.categories.value].reverse(), f.regions.value);
  assert(f.regions.value.length >= 2 && f.categories.value.length >= 2, "the fixture is too small to reorder");
  const targets = ["/srv/self/a", "/srv/other/b", "/etc/c", "/nowhere"];
  for (const t of targets) {
    assert(deriveInterestLabel(t, f.regions.value) === deriveInterestLabel(t, reordered.regions.value), `a reorder changed the label of ${t}`);
  }
  assert(frameLabelEventType(reordered) === frameLabelEventType(f), "a pure region reorder moved the class and would orphan the book's history");
  assert(frameLabelEventType(catsReordered) === frameLabelEventType(f), "a pure category reorder moved the class");
  const moved = frameOf(f.categories.value, f.regions.value.map((r: any, i: number) => (i === 0 ? { ...r, prefix: r.prefix + "x" } : r)));
  assert(frameLabelEventType(moved) !== frameLabelEventType(f), "a moved prefix kept the class");
});

check("PLAIN JSON, NOT canonical-json — two prefixes that differ only in normal form are two classes (they match different bytes)", () => {
  const nfc = frameOf(v1().categories.value, [reg("/srv/café", "c-other")]);
  const nfd = frameOf(v1().categories.value, [reg("/srv/café", "c-other")]);
  assert(frameLabelEventType(nfc) !== frameLabelEventType(nfd), "NFC and NFD prefixes share a class; their labels would merge");
});

check("THE REVIEW'S DRIFT CASES (C2-2, C2-3): every later drawing is ANOTHER class, so labels derived under the earlier one are not counted against it", () => {
  // Each case: [the drawing labels were derived under, the drawing read today].
  const v2 = frameOf(v1().categories.value, [reg("/srv/self", "c-self"), reg("/etc", "c-shared")]); // CASE 1: region removed
  const v3 = frameOf([cat("c-self", true), cat("c-peer"), cat("c-shared")], [reg("/srv/self", "c-self"), reg("/srv/other", "c-peer"), reg("/etc", "c-shared")]); // CASE 2: renamed
  const v4pre = frameOf([cat("c-self", true), cat("c-other")], [reg("/srv/self", "c-self"), reg("/srv/other", "c-other")]);
  const v4 = frameOf([cat("c-self", true), cat("c-other"), cat("c-sys")], [reg("/srv/self", "c-self"), reg("/srv/other", "c-other"), reg("/etc", "c-sys")]); // CASE 3: added
  const v5 = frameOf(v1().categories.value, [reg("/srv/self", "c-self"), reg("/srv/other", "c-shared"), reg("/etc", "c-shared")]); // CASE 4: reassigned
  const cases: [string, any, any][] = [["region removed", v1(), v2], ["category renamed", v1(), v3], ["category added over UNDERIVED targets", v4pre, v4], ["region reassigned", v1(), v5]];
  for (const [name, then, now] of cases) {
    // WHAT THE READER IS HANDED TODAY is toWireOptions' class for `now`; what
    // the book holds is the writer's class for `then`. They must differ.
    const read = (toWireOptions(load(declaredWith(now))) as any).gate1.labelClass.eventType;
    const written = frameLabelEventType(load(declaredWith(then)).frame!["subject-a"]);
    assert(read !== written, `${name}: the labels written under the earlier drawing carry the class read today (${read})`);
    assert(read === frameLabelEventType(now), `${name}: the wiring's class is not the writer's call on today's frame`);
  }
});

// ── 2 · writer and wiring agree ─────────────────────────────────────────────

check("toWireOptions' labelClass IS frameLabelEventType(frame[subject]) with moduleId = the subject, and gate1BookPath is the declared book RESOLVED like logPath", () => {
  const loaded = load(declaredWith(v1()));
  const resolve = (p: string) => p.replace(/^\/var\/lib\/mica-bridge/, "/redirected/state");
  const opts = toWireOptions(loaded, resolve) as any;
  assert(opts.gate1.labelClass.moduleId === "subject-a", JSON.stringify(opts.gate1.labelClass));
  assert(opts.gate1.labelClass.eventType === frameLabelEventType(loaded.frame!["subject-a"]), JSON.stringify(opts.gate1.labelClass));
  assert(opts.gate1BookPath === "/redirected/state/interest-book.jsonl", `gate1BookPath ${JSON.stringify(opts.gate1BookPath)}`);
  assert(opts.logPath === resolve(loaded.readers.logPath.value), "precondition: logPath is resolved by the same function");
  // Without a resolver, the identity — the declared path.
  assert((toWireOptions(loaded) as any).gate1BookPath === BOOK, "the identity resolver changed the book path");
});

check("ABSENT reader, ABSENT keys — a frame and a book without readers.gate1Scope emit neither gate1 nor gate1BookPath", () => {
  const d = declaredWith(v1(), false);
  d.paths.interestBook = BOOK; // the book is declared (the bridge writes it) — the READER is not
  const opts = toWireOptions(load(d)) as Record<string, unknown>;
  assert(!("gate1" in opts) && !("gate1BookPath" in opts), `keys: ${Object.keys(opts).join(",")}`);
});

check("DERIVABLE IS THE DERIVER'S ANSWER, NOT THE REGION LIST'S — a category whose only region places nothing (a not-a-path prefix) is derivable:false; a placeable region keeps it true (B2, review K1R1-2)", () => {
  // The loader refuses these prefixes since round 3 (A2), so the only way to
  // hand the wiring one is a Declarations that skipped the door — which is what
  // this belt (B2) is for. Built from a LOADED declaration, frame swapped.
  const loaded = load(declaredWith(v1()));
  const withRegions = (regions: any[]): any => {
    const f = loaded.frame!["subject-a"];
    return { ...loaded, frame: { "subject-a": { ...f, regions: { ...f.regions, value: regions } } } };
  };
  for (const dead of ["/srv/-scratch", "/mnt/c/Program Files (x86)", "/srv/node:20", "/srv/a=b", "/home/op/~archive"]) {
    let doorRefused = false;
    try { load(declaredWith(frameOf(v1().categories.value, [reg("/srv/self", "c-self"), reg(dead, "c-other")]))); } catch { doorRefused = true; }
    assert(doorRefused, `precondition: the front door admits the dead prefix ${dead} — the belt is then not the only guard`);
    const opts = toWireOptions(withRegions([reg("/srv/self", "c-self"), reg(dead, "c-other"), reg("/etc", "c-shared")])) as any;
    const other = opts.gate1.categories.find((c: any) => c.id === "c-other");
    assert(other.derivable === false, `a category whose only region (${dead}) places nothing is counted derivable`);
    assert(deriveInterestLabel(dead + "/f", [reg(dead, "c-other")], dead + "/f") === INTEREST_UNDERIVED, `precondition: ${dead} places a target`);
    // The other two stay derivable — the flag is per category, not per frame.
    const rest = opts.gate1.categories.filter((c: any) => c.id !== "c-other").map((c: any) => c.derivable);
    assert(rest.every((d: boolean) => d === true), `a placeable region lost derivability beside ${dead}: ${JSON.stringify(opts.gate1.categories)}`);
  }
  // A dead region BESIDE a live one of the same category: still derivable (some region places it).
  const both = toWireOptions(withRegions([reg("/srv/self", "c-self"), reg("/srv/-scratch", "c-other"), reg("/srv/other", "c-other")])) as any;
  assert(both.gate1.categories.find((c: any) => c.id === "c-other").derivable === true, "a live region beside a dead one did not count");
  // The root region is placeable at its own prefix.
  const root = toWireOptions(withRegions([reg("/", "c-self"), reg("/srv/other", "c-other")])) as any;
  assert(root.gate1.categories.find((c: any) => c.id === "c-self").derivable === true, "the root region was counted dead");
});

// ── 3 · the record ───────────────────────────────────────────────────────────

const ENTRY = Object.freeze({ subject: "subject-a", eventType: frameLabelEventType(v1()), label: "c-other", actionId: "act-7", subjectSeq: 42 });

check("the book record is EXACTLY {subjectSeq, timestamp, moduleId, eventType, actionId, outcome} — the target is not an input, so it cannot be an output", () => {
  const r = buildInterestLabelRecord(ENTRY, null, 1000);
  assert(Object.keys(r).join(",") === "subjectSeq,timestamp,moduleId,eventType,actionId,outcome", `keys: ${Object.keys(r).join(",")}`);
  assert(r.subjectSeq === 42 && r.moduleId === "subject-a" && r.eventType === ENTRY.eventType && r.actionId === "act-7" && r.outcome === "c-other", JSON.stringify(r));
  assert(r.timestamp === 1000, `first record stamps now: ${r.timestamp}`);
});

check("the book timestamp is NON-DECREASING against the previous book record — max(now, previous)", () => {
  assert(buildInterestLabelRecord(ENTRY, { timestamp: 5000 }, 1000).timestamp === 5000, "a clock behind the book was not lifted");
  assert(buildInterestLabelRecord(ENTRY, { timestamp: 500 }, 1000).timestamp === 1000, "a clock ahead of the book was not used");
  // A previous record with no usable timestamp (the boundary always has one;
  // this is the without-the-journal case) leaves the reading unmodified.
  for (const bad of [{}, { timestamp: "5000" }, { timestamp: Number.NaN }, { timestamp: Number.POSITIVE_INFINITY }]) {
    assert(buildInterestLabelRecord(ENTRY, bad, 1000).timestamp === 1000, `previous ${JSON.stringify(bad)} moved the stamp`);
  }
});

check("the boundary basis says what retired:null does NOT mean, and the event-book kind is not a subject-event kind", () => {
  assert(INTEREST_BOOK_BOUNDARY_BASIS.includes("interest book") && INTEREST_BOOK_BOUNDARY_BASIS.includes("retired is null"), INTEREST_BOOK_BOUNDARY_BASIS);
  assert(INTEREST_BOOK_BOUNDARY_BASIS.includes("not because one was verified absent"), "the basis no longer disclaims a verified absence");
  assert(!(SUBJECT_EVENT_KINDS as readonly string[]).includes(INTEREST_LABEL_NOT_PERSISTED), "the failure kind leaked into the subject alphabet");
});

check("SOURCE FENCE: interest-book.ts's runtime imports are the digest and the TWO VERSION CONSTANTS, nothing else — no fs, no clock, no process", () => {
  // Matches USE (an import statement that brings a value in, a call), never a
  // NAME in a comment. Round 3 (B1): the class names the rule versions, so two
  // imports joined the digest — each must bring in its constant and NOTHING
  // else (target-fingerprint also exports fs-reading salt functions).
  const src = readFileSync(join(__dirname, "interest-book.ts"), "utf8");
  const code = src
    .split("\n")
    .filter((l) => !/^\s*(\/\/|\*|\/\*\*)/.test(l))
    .join("\n");
  const valueImports = (code.match(/^\s*import\s+(?!type\b)[^;]*;/gm) ?? []).map((s) => s.trim().replace(/\s+/g, " "));
  const allowed = [
    'import { createHash } from "crypto";',
    'import { INTEREST_DERIVATION_VERSION } from "./interest-label";',
    'import { TARGET_CANON_VERSION } from "./target-fingerprint";',
  ];
  assert(valueImports.length === allowed.length && valueImports.every((l, i) => l === allowed[i]), `runtime imports: ${JSON.stringify(valueImports)}`);
  assert(!/\brequire\s*\(/.test(code), "a require() call");
  assert(!/\bDate\b|\bprocess\./.test(code), "a clock or process read — the caller passes nowMs");
});

const total = passed + failed;
console.log(`${total} tests: ${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
