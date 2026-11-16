// ── declarations.test — check()-style tests, mirroring the mica-machine harness ─
//
// No test framework dependency: each check() prints PASS/FAIL and the
// process exits 1 if any check failed. Run with:
//   ts-node -P tsconfig.json declarations.test.ts

import { skipHere } from "./reference-only";
import { execFileSync } from "child_process";
import { createHash } from "crypto";
import { writeFileSync, unlinkSync, mkdtempSync, readFileSync, symlinkSync, existsSync, lstatSync, rmSync, mkdirSync, chmodSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
  loadDeclarations,
  validateDeclarations,
  validateActivation,
  DeclarationRejected,
  canonicalHash,
  type Declarations,
} from "./declarations";
import {
  GATE2_KNOWN_KINDS,
  GATE2_SUNSET_KINDS,
  GATE2_OPERATOR_ONLY_KINDS,
  GATE2_ARBITER_CLEARING_KINDS,
  GATE2_F4_REFUSED_KINDS,
  GATE2_SUBJECT_WRITABLE_DAMAGE_REFUSED,
  isGate2SubjectWritableKind,
} from "./declarations";
import { toSensorConfig } from "./to-sensor-config";
import { toGuardFlags, UnknownSubjectError } from "./to-guard-flags";
import { toWireOptions, GATE2_BASKET_CLASS_VERSION, gate2BasketClass } from "./to-wire-options";
// GATE 2 · Stop 2: the AUTHORITIES the basket door's literal kind lists mirror,
// and the route rule its subject-writable predicate must agree with BY BEHAVIOUR.
import { SUBJECT_EVENT_KINDS, SUNSET_KINDS, OPERATOR_SUNSET_KINDS, ERRAND_KINDS, authorizeSubjectEventKind } from "./mica-service";
import {
  assessSig,
  MicaLogFile,
  clerkStampsDisposition,
  readPriorLoadWitness,
  CLERK_STAMPS_FIRST_LOAD_EVENT_TYPE,
  SubjectEventJournal,
  SUBJECT_LOG_BOUNDARY_MODULE_ID,
} from "./stage1-guard-adapter";
// AMENDMENT 9 / RULING P — a REAL, in-process call into mica-machine's own
// wire() (src/glue/wire.ts:362), not a reimplementation and not a spawned
// subprocess: this is the proof that a declared readers.logPath/logKind
// actually wires Eng and Sig. See to-wire-options.ts's header for why this
// relative path is test-workstation-specific.
// C9 / register E8: through the single machine root, never the relative path.
// `../../../mica-machine` resolved to the operator's own machine checkout —
// `main`, older than what runs — so this suite was validating against code
// that never executes in production. See stage1-guard-adapter.ts's re-exports.
import { wire } from "./stage1-guard-adapter";

let passed = 0;
let failed = 0;

function check(name: string, fn: () => void): void {
  if (skipHere("declarations.test.ts", name)) return;
  try {
    fn();
    passed++;
    console.log(`PASS  ${name}`);
  } catch (err) {
    failed++;
      // ⛔ P5 · THE EXIT CODE IS SET HERE, AT THE FAILURE, NOT AT THE TALLY.
      //    A suite whose tally runs BEFORE some of its arms exits 0 with FAIL on
      //    the screen — and that is not hypothetical: six arms added to
      //    sunset.test.ts on 2026-10-04 were inserted outside its `async main()`
      //    and ran as floating promises AFTER the tally, so a failure in any of
      //    them would have printed and the process would still have exited 0.
      //    `process.exitCode` is cumulative and survives a late arm, where
      //    `if (failed > 0) process.exit(1)` at the end only covers what already
      //    ran. The tally check stays as well; this is the one that cannot be
      //    outrun.
      process.exitCode = 1;
    console.log(`FAIL  ${name}`);
    console.log(`      ${err instanceof Error ? err.message : String(err)}`);
  }
}

function assert(cond: boolean, msg: string): void {
  if (!cond) throw new Error(`assertion failed: ${msg}`);
}

function assertRejected(fn: () => void, expectField: string): void {
  try {
    fn();
  } catch (err) {
    if (err instanceof DeclarationRejected) {
      assert(
        err.field === expectField || err.field.startsWith(expectField),
        `expected rejection field "${expectField}", got "${err.field}" (${err.message})`
      );
      return;
    }
    throw err;
  }
  throw new Error(`expected DeclarationRejected naming "${expectField}", nothing was thrown`);
}

// ── THE DRAFT IS A FIXTURE NOW, AND RULE 1 IS WHY (the arbiter, 2026-09-28) ────────
//
//   These tests were written against a COMMITTED declarations.config.json that
//   was a placeholder — drafted values, no POST route, absent reader blocks —
//   and they pin exactly that shape.
//
//   ⛔ RULE 1 (S145) REQUIRES THE COMMITTED CANDIDATE TO BE BYTE-IDENTICAL TO
//   WHAT IS SERVING. So from the first real relay the committed config stopped
//   being a placeholder and became the live declaration, and eleven tests here
//   began asserting that the live box is a draft. They were not wrong about the
//   loader; they were reading the wrong file.
//
//   The arbiter ruled rule 1 wins. The draft therefore lives in its own fixture and
//   the committed config is left to be what it is.
//
//   ⚠ THE FIXTURE IS BUILT, NOT RECOVERED, and that is stated because it moved a
//   pinned hash. The historical placeholder (`ed87684`) NO LONGER LOADS: Act A
//   made `subjectLog.chainBoundary` required and X15 refuses an empty
//   retiredPath, both of which postdate it. The fixture is that file plus a
//   self-evidently fake boundary, so its canonicalHash is its own
//   (fb37d035…) and not the Designer's cb3d7625…, which was computed before
//   the boundary existed and can never be reproduced again.
const DRAFT_PATH = join(__dirname, "declarations.fixture.json");

// ── AND A REAL HANDLE ON WHAT IS ACTUALLY SHIPPED (Codex, 2026-09-28) ────────
//
//   Moving the draft to a fixture left several tests SAYING "the shipped
//   declaration" while READING the fixture. That is the stale-printer shape this
//   project keeps finding, inside its own test suite: a name that stopped
//   describing its subject.
//
//   Two handles now, and each test uses the one its CLAIM is about:
//     · DRAFT_PATH / draft   — the fixture. Claims about the LOADER.
//     · SHIPPED_PATH/shipped — declarations.config.json, what the box serves.
//                              Claims about the DEPLOYMENT.
const SHIPPED_PATH = join(__dirname, "declarations.example.json");

/** A basis long enough to satisfy the envelope's 80-character floor. */
const BASIS_FIXTURE =
  "FIXTURE BASIS. The clerk carrier (mica-clerk-caller.service, uid mica) writes its arrival stamps here; the bridge only reads them. Declared so F3 reads a file the declaration names.";
const draft = JSON.parse(require("fs").readFileSync(DRAFT_PATH, "utf8"));
const shipped = JSON.parse(readFileSync(SHIPPED_PATH, "utf8"));
/** The fixture's own path, so the real validator can be pointed at it too. */
const FIXTURE_PATH_FOR_REAL = join(__dirname, "declarations.fixture.json");


// ── FIXTURE NEUTRALITY (S136) ────────────────────────────────────────────
// `draft` is the FIXTURE (it was the shipped config until 2026-09-28; see DRAFT_PATH). Cloning it verbatim
// made every fixture in this file inherit whatever the deployment happened
// to declare — so the moment Stage 4 declared a real pilot, five tests in
// two suites went red for a reason that had nothing to do with the code
// under test. A behavioural test must declare the state it is testing.
//
// So the pilot is neutralised HERE, once, to the known baseline. Tests that
// want an ACTIVE pilot set it explicitly on their own clone (several already
// do, and those are the ones that kept passing). This is not a loosening:
// it removes a hidden dependency on a file the tests do not own.
function clone(): any {
  const d = JSON.parse(JSON.stringify(draft));
  d.pilot = { active: false };
  return d;
}

function deleteAtPath(obj: any, path: string): void {
  const parts = path.split(".");
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i];
    cur = key.includes("[") ? cur[key.replace(/\[.*\]/, "")][Number(key.match(/\[(\d+)\]/)![1])] : cur[key];
  }
  const last = parts[parts.length - 1];
  delete cur[last];
}

// ── loads the draft; hash reproduces ────────────────────────────────────────

// AMENDMENT 11 / RULING R: the sealed hash MOVES AGAIN —
// readers.readableLoadStates.value widened from ["LOADED_VERIFIED"] to
// ["LOADED_VERIFIED", "LOADED_UNVERIFIED_FILE"], basis text rewritten at
// full width per Ruling R. declarations.schema.json is untouched this
// amendment (no shape change, no new field — the schema never restricted
// readableLoadStates' values by enum). Expected and stated in the receipt;
// the orchestrator re-seals it.
// RE-PINNED S136, 2026-09-20, when the Stage 4 pilot block was declared
// (design §D.1/§D.2 step 1 requires it committed). This constant is a
// DRIFT DETECTOR and it worked exactly as intended: the declaration changed
// and it shouted. Re-pinning keeps it guarding the NEXT change. A pin that
// is updated silently would be worthless — so the rule is that it only ever
// moves in a commit that says why, and this is that commit.
// RE-PINNED AGAIN C9, 2026-09-20, when readers.sig gained preconditionMap and
// reentryMap (Part B). Same rule, third time it has held: the declaration
// changed and this shouted. It only moves in a commit that says why.
// RE-PINNED AGAIN R1 substrate, 2026-09-21, when the bridge's
// SUBJECT_EVENT_KINDS grew from four to seven and the two Sig-map `basis`
// strings were rewritten to say so. Fourth time it has held; it shouted again.
//
// WHAT MOVED, AND WHY A DOCUMENTARY EDIT MOVES A HASH AT ALL. Nothing in the
// declaration's VALUES changed — `preconditionMap.value` and
// `reentryMap.value` are byte-identical, verified structurally in the commit,
// and Sig's reading of this log is unchanged. What changed is two `basis`
// strings. `basis` is never read by code (`toSensorConfig` projects only
// `.value`); it is the deployer's stated reasoning. But `declarationHash` is
// `canonicalHash` of the whole PARSED declaration, envelopes included, so the
// reasoning is inside the hash that every decision binds itself to.
//
// THAT IS THE RIGHT BEHAVIOUR AND IT IS WORTH SAYING OUT LOUD: it means the
// deployer cannot quietly change WHY a map is what it is while claiming the
// same declaration. The old text said "the four lifecycle eventTypes the
// bridge writes" — true when written, FALSE the moment a fifth kind existed.
// A declaration that misdescribes its own deployment is the exact failure this
// hash exists to make visible, and leaving it stale to avoid a re-pin would
// have been trading a true record for a quiet one.
//   was: 6e67f4689e6c5b04e8862fd194ba04a92bf45da97fceea61923344c663c0e2fc  (pilot inactive)
//   was: 719befd1ebc7851e413fb2e8f54f0d4545bdecca24fef169ab106973005ec2d5  (pilot active, no Sig maps)
//   was: 75c429cf20672e3e7d8213a7d4223b7881a7e2fb2c3ba830abfff8892ae82be7  (four kinds)
//   was: 32ad2d31a2df04b7bae1f2521477443a2b554e4c98286f6966b1b09dac3bc922  (before GET /explain)
//
// R1 MOVED IT AGAIN, and this time a VALUE moved, not a `basis` string: uid
// 1000's `allow` gained `GET /explain`. That is a WIDENING OF WHAT ONE PEER
// MAY READ and it is exactly the class of change this pin exists to make
// impossible to do quietly. The grant is on the OPERATOR row and on no other
// row — see the X13 checks below, which hold the housekeeper out of it
// structurally rather than by the absence of a line.
//
// ACT A MOVED IT AGAIN, and three VALUES moved with it, not only `basis`
// strings: `readers.readableLoadStates` (LOADED_VERIFIED out — nothing on this
// box has ever reported it and the basis claiming otherwise was FALSE;
// LOADED_SUBJECT_CHAIN_VERIFIED in), `readers.logKind` ("mica" ->
// "subject-chain"), and a new `subjectLog.chainBoundary` block carrying what
// the chain's position-0 record says it replaced. Acceptance A3 requires this
// hash to CHANGE across the relay — an unchanged declarationHash would mean the
// declaration edit did not ride and the readers are reading the new store under
// the old list.
//   was: 4568d8082948d886c34eebc324c0f5b8cbf8de94c02f47c82956b899970848c1  (before Act A)
//
// S201 MOVED IT AGAIN, by one VALUE: the subject's route role is the word
// "subject" (routes[0].role), no longer the subject's own name — the bridge
// names no subject in code, so the role cannot be one.
//   was: fb37d0357569c0ea8f8b0dd1b56f5e769d041a22e3a05f10d7fc87c9f42b16b5  (before S201)
// Re-pinned in publish-1: the fixture's one name (a "ruled by" role phrase in a basis text) was masked to a role word, which moves the digest by construction.
const EXPECTED_HASH = "2b62b04c38bc029e37a1cf5552fdebbf2d108cb2a3bbdc1d6be96f4f636bc88a";

check("loads the draft cleanly, and the loaded pilot state AGREES with what the draft declares", () => {
  const loaded = loadDeclarations(DRAFT_PATH, new Date("2026-09-18T00:00:00Z"));
  assert(loaded.declarations.schemaVersion === 1, "schemaVersion");
  // S136: this used to assert the state was INACTIVE — a fact about the
  // DEPLOYMENT, not about the loader, which went false the moment a pilot
  // was declared. What this test can honestly own is AGREEMENT: whatever the
  // draft declares, the loader must report the matching state. That holds on
  // any deployment, and it still fails if the loader ignores `pilot.active`.
  const declaredActive = (draft as { pilot?: { active?: boolean } }).pilot?.active === true;
  assert(
    ["INACTIVE", "ACTIVE", "EXPIRED"].includes(loaded.pilotState.state),
    `pilot state must be one of the three legal values, got ${loaded.pilotState.state}`
  );
  assert(
    (loaded.pilotState.state === "INACTIVE") === !declaredActive,
    `draft declares active=${declaredActive} but the loader reports ${loaded.pilotState.state}`
  );
});

check("declarationHash reproduces the Designer's stated hash", () => {
  const loaded = loadDeclarations(DRAFT_PATH);
  assert(
    loaded.declarationHash === EXPECTED_HASH,
    `got ${loaded.declarationHash}, expected ${EXPECTED_HASH}`
  );
});

// ── every REQUIRED field removed -> named rejection ─────────────────────────

const REQUIRED_FIELD_CASES: readonly string[] = [
  "schemaVersion",
  "readers.readableLoadStates",
  "readers.logPath",
  "readers.logKind",
  "readers.eng.structureThreshold",
  "readers.eng.minimumSampleSize",
  "readers.sig.clockToleranceMs",
  "readers.sig.clockToleranceBasis",
  "stakes.lineClasses",
  "stakes.baseline.holdAtOrAbove",
  "routes",
  "pilot",
  "notice.window",
  "notice.maxPerMinute",
  "subjectLog.maxUnacknowledged",
  "paths.journal",
  "paths.decisionEvents",
];

for (const path of REQUIRED_FIELD_CASES) {
  check(`missing required field "${path}" -> named rejection`, () => {
    const d = clone();
    deleteAtPath(d, path);
    assertRejected(() => validateDeclarations(d), path);
  });
}

check('missing subjects[0].peerUid -> named rejection', () => {
  const d = clone();
  delete d.subjects[0].peerUid;
  assertRejected(() => validateDeclarations(d), "subjects[0].peerUid");
});

check('missing routes[0].allow -> named rejection', () => {
  const d = clone();
  delete d.routes[0].allow;
  assertRejected(() => validateDeclarations(d), "routes[0].allow");
});

// ── unknown field at three depths -> named rejection ────────────────────────

check("unknown field at depth 1 ($.bogus) -> named rejection", () => {
  const d = clone();
  d.bogus = true;
  assertRejected(() => validateDeclarations(d), "$.bogus");
});

check("unknown field at depth 2 (readers.bogus) -> named rejection", () => {
  const d = clone();
  d.readers.bogus = true;
  assertRejected(() => validateDeclarations(d), "readers.bogus");
});

check("unknown field at depth 3 (readers.eng.bogus) -> named rejection", () => {
  const d = clone();
  d.readers.eng.bogus = 1;
  assertRejected(() => validateDeclarations(d), "readers.eng.bogus");
});

check("unknown field inside an envelope (subjects[0].peerUid.bogus) is caught as unknown subject key instead", () => {
  // subjects[].peerUid is a bare number, not an envelope; exercise the
  // deepest actual envelope instead: readers.eng.structureThreshold.bogus.
  const d = clone();
  d.readers.eng.structureThreshold.bogus = 1;
  assertRejected(() => validateDeclarations(d), "readers.eng.structureThreshold.bogus");
});

// ── cross-field rules ────────────────────────────────────────────────────────

check("X1: baseline.holdAtOrAbove not in lineClasses -> rejected", () => {
  const d = clone();
  d.stakes.baseline.holdAtOrAbove.value = "not_a_class";
  assertRejected(() => validateDeclarations(d), "stakes.baseline.holdAtOrAbove");
});

check("X2: subjects[].stakesClass not in lineClasses -> rejected", () => {
  const d = clone();
  d.subjects[0].stakesClass = "not_a_class";
  assertRejected(() => validateDeclarations(d), "subjects[0].stakesClass");
});

check("X3: pilot.holdAtOrAbove not in lineClasses (active pilot) -> rejected", () => {
  const d = clone();
  d.pilot = {
    active: true,
    sessionId: "sess-1",
    expiresAt: "2099-01-01T00:00:00Z",
    holdAtOrAbove: { value: "not_a_class", basis: "test", proxy: true },
  };
  assertRejected(() => validateDeclarations(d), "pilot.holdAtOrAbove");
});

check("X4: duplicate subjects[].subject -> rejected", () => {
  const d = clone();
  d.subjects.push({ ...d.subjects[0] });
  assertRejected(() => validateDeclarations(d), "subjects[1].subject");
});

check("X5: duplicate routes[].uid -> rejected", () => {
  const d = clone();
  d.routes.push({ ...d.routes[0] });
  assertRejected(() => validateDeclarations(d), "routes[3].uid");
});

check("X6: subjects[].peerUid with no housekeeper route -> rejected", () => {
  const d = clone();
  d.subjects[0].peerUid = 9999;
  assertRejected(() => validateDeclarations(d), "subjects[0].peerUid");
});

check("X7: two paths.* values equal -> rejected", () => {
  const d = clone();
  d.paths.eventBook = d.paths.journal;
  assertRejected(() => validateDeclarations(d), "paths");
});

check("AMENDMENT 9 / H-1: paths.decisionEvents colliding with paths.eventBook -> rejected (X7 now covers eight keys)", () => {
  const d = clone();
  d.paths.decisionEvents = d.paths.eventBook;
  assertRejected(() => validateDeclarations(d), "paths");
});

check("AMENDMENT 9 / Ruling P: readers.logKind.value outside {mica,witness} -> rejected", () => {
  const d = clone();
  d.readers.logKind.value = "bogus";
  assertRejected(() => validateDeclarations(d), "readers.logKind.value");
});

check("X9: notice.maxPerMinute.value < 1 -> rejected", () => {
  const d = clone();
  d.notice.maxPerMinute.value = 0;
  assertRejected(() => validateDeclarations(d), "notice.maxPerMinute");
});

// ── Amendment 1 — rulings M / N / O ─────────────────────────────────────────

check("Ruling N: the draft's housekeeper subject is bound to uid 980 (mica-housekeeper), not 1000", () => {
  const loaded = validateDeclarations(clone());
  assert(loaded.declarations.subjects[0].peerUid === 980, String(loaded.declarations.subjects[0].peerUid));
});

check("Ruling N: no subject may remain bound to uid 1000", () => {
  const d = clone();
  d.subjects[0].peerUid = 1000;
  // 1000 is a routes[] row (operator) but NOT role housekeeper -> X6 fires.
  assertRejected(() => validateDeclarations(d), "subjects[0].peerUid");
});

check("Ruling O (+R1): uid 1000 holds exactly the four ruled GET routes, no POST", () => {
  // R1 added `GET /explain` to this row and to NO other row. The assertion
  // stays an EXACT SET rather than a superset check, for the reason it was
  // written that way: a "contains" test would pass while the operator quietly
  // acquired a fifth route nobody ruled.
  const loaded = validateDeclarations(clone());
  const operatorRow = loaded.declarations.routes.find((r) => r.uid === 1000);
  assert(!!operatorRow, "uid 1000 must have a routes[] row");
  assert(operatorRow!.role === "operator", operatorRow!.role);
  const paths = operatorRow!.allow.map((a) => `${a.method} ${a.path}`).sort();
  assert(
    JSON.stringify(paths) ===
      JSON.stringify(["GET /events", "GET /explain", "GET /log", "GET /status"]),
    JSON.stringify(paths)
  );
});

check("R1 · /explain is granted to the OPERATOR ROW ALONE — no other uid holds it in the draft", () => {
  const loaded = validateDeclarations(clone());
  const holders = loaded.declarations.routes
    .filter((r) => r.allow.some((a) => a.path === "/explain"))
    .map((r) => r.uid);
  assert(
    JSON.stringify(holders) === JSON.stringify([1000]),
    `/explain must be held by uid 1000 and nothing else, got ${JSON.stringify(holders)}`
  );
});

check("X13: /explain on the HOUSEKEEPER's row — the subject's own peer — is REJECTED, not merely denied at request time", () => {
  // THE HARD CONSTRAINT, held by the loader. `authorizeRoute` faithfully
  // enforces whatever the declaration says, so a declaration that granted the
  // subject `/explain` would be OBEYED. The refusal has to live where the
  // grant is written. A subject that can read its own margins can see which
  // reader is closest to firing and aim at it.
  const d = clone();
  const housekeeper = d.routes.find((r: any) => r.uid === 980);
  housekeeper.allow.push({ method: "GET", path: "/explain" });
  assertRejected(() => validateDeclarations(d), "routes[0].allow[2]");
});

check("X13: /explain on ANY row bound as a subject's peerUid is rejected, not just uid 980 by name", () => {
  // The rule is about the SUBJECT RELATION, not about a hardcoded uid. Move
  // the subject's binding to the operator row and the operator's own
  // long-standing /explain grant becomes the violation.
  const d = clone();
  d.routes.find((r: any) => r.uid === 1000).role = "subject";
  d.subjects[0].peerUid = 1000;
  assertRejected(() => validateDeclarations(d), "routes[2].allow[3]");
});

check("X13 · THE RULE'S OWN VALIDITY GATE — the same declaration WITHOUT the /explain grant loads cleanly", () => {
  // A refusal that has never been shown to accept is a refusal nobody has
  // tested: without this, X13 would pass just as well if it rejected every
  // declaration outright.
  const d = clone();
  d.routes.find((r: any) => r.uid === 1000).allow = d.routes
    .find((r: any) => r.uid === 1000)
    .allow.filter((a: any) => a.path !== "/explain");
  d.routes.find((r: any) => r.uid === 1000).role = "subject";
  // ZERO-SUBJECTS Z2/Z5 (F-3: at every n): the subject's OLD row is now an orphan subject row holding POST /guard,
  // refused by Z2 and Z5. Dropped here so this gate still isolates X13 alone.
  const oldPeer = d.subjects[0].peerUid;
  d.routes = d.routes.filter((r: any) => r.uid !== oldPeer);
  d.subjects[0].peerUid = 1000;
  const loaded = validateDeclarations(d);
  assert(!!loaded.declarations, "the same shape without /explain must load");
});

check("Ruling O: the draft carries no routes[] row for uid 982 (the service's own uid)", () => {
  const loaded = validateDeclarations(clone());
  assert(!loaded.declarations.routes.some((r) => r.uid === 982), "982 must not appear");
});

check("X10: a routes[] row for uid 0 (root) is rejected", () => {
  const d = clone();
  d.routes.push({ uid: 0, role: "verifier", allow: [{ method: "GET", path: "/status" }] });
  assertRejected(() => validateDeclarations(d), "routes[3].uid");
});

check("X11: a routes[] row for uid 982 (the bridge's own uid) is rejected", () => {
  const d = clone();
  d.routes.push({ uid: 982, role: "operator", allow: [{ method: "GET", path: "/status" }] });
  assertRejected(() => validateDeclarations(d), "routes[3].uid");
});

check("X12: a subject's peerUid may not hold a route granting POST beyond /guard,/subject-events", () => {
  const d = clone();
  // uid 980 is the housekeeper's peerUid; widen its own row with an extra POST.
  d.routes[0].allow.push({ method: "POST", path: "/status" });
  assertRejected(() => validateDeclarations(d), "routes[0].allow");
});

check("Ruling M: the sentinel 'irreversible' is present, last in lineClasses, non-assignable", () => {
  const loaded = validateDeclarations(clone());
  const classes = loaded.declarations.stakes.lineClasses;
  assert(classes[classes.length - 1] === "irreversible", classes.join(","));
  assert(
    !loaded.declarations.subjects.some((s) => s.stakesClass === "irreversible"),
    "no subject may be assigned the sentinel"
  );
});

check("Ruling M: a subject assigned the sentinel 'irreversible' is rejected (non-assignable)", () => {
  const d = clone();
  d.subjects[0].stakesClass = "irreversible";
  // The loader enforces membership (X2) but not non-assignability by itself
  // unless the rule below exists; assert it exists as a named rejection.
  assertRejected(() => validateDeclarations(d), "subjects[0].stakesClass");
});

// ── X8 / pilot four cases ────────────────────────────────────────────────────

check("pilot inactive -> state INACTIVE", () => {
  const loaded = validateDeclarations(clone());
  assert(loaded.pilotState.state === "INACTIVE", loaded.pilotState.state);
});

check("pilot active + matching session, future expiry -> state ACTIVE", () => {
  const d = clone();
  d.pilot = {
    active: true,
    sessionId: "sess-1",
    expiresAt: "2099-01-01T00:00:00Z",
    holdAtOrAbove: { value: "irreversible", basis: "test", proxy: true },
  };
  const loaded = validateDeclarations(d, new Date("2026-09-18T00:00:00Z"));
  assert(loaded.pilotState.state === "ACTIVE", loaded.pilotState.state);
  assert(
    (loaded.pilotState as any).sessionId === "sess-1",
    "sessionId carried through"
  );
});

check("pilot active but wrong session (checked at the guard-flags layer) -> baseline governs", () => {
  const d = clone();
  d.pilot = {
    active: true,
    sessionId: "sess-1",
    expiresAt: "2099-01-01T00:00:00Z",
    holdAtOrAbove: { value: "irreversible", basis: "test", proxy: true },
  };
  const loaded = validateDeclarations(d, new Date("2026-09-18T00:00:00Z"));
  const flags = toGuardFlags(loaded.declarations, loaded.pilotState, "housekeeper", "bash", "sess-WRONG");
  assert(!flags.pilotApplied, "pilot must not apply for a mismatched session");
  assert(flags.holdAtOrAbove === "state_changing", `expected baseline, got ${flags.holdAtOrAbove}`);
});

check("pilot active, expiresAt already past AT LOAD -> loads, state EXPIRED, baseline governs (X8)", () => {
  const d = clone();
  d.pilot = {
    active: true,
    sessionId: "sess-old",
    expiresAt: "2020-01-01T00:00:00Z",
    holdAtOrAbove: { value: "irreversible", basis: "test", proxy: true },
  };
  const loaded = validateDeclarations(d, new Date("2026-09-18T00:00:00Z"));
  assert(loaded.pilotState.state === "EXPIRED", loaded.pilotState.state);
  const flags = toGuardFlags(loaded.declarations, loaded.pilotState, "housekeeper", "bash", "sess-old");
  assert(flags.holdAtOrAbove === "state_changing", "baseline governs once EXPIRED even for the matching session");
});

// ── validateActivation: new activation with a past expiry -> rejected ──────

check("validateActivation: brand-new pilot with past expiresAt -> rejected", () => {
  const prevLoaded = validateDeclarations(clone());
  const next = clone();
  next.pilot = {
    active: true,
    sessionId: "sess-new",
    expiresAt: "2020-01-01T00:00:00Z",
    holdAtOrAbove: { value: "irreversible", basis: "test", proxy: true },
  };
  const nextValidated = validateDeclarations(next);
  let threw = false;
  try {
    validateActivation(prevLoaded.declarations, nextValidated.declarations, new Date("2026-09-18T00:00:00Z"));
  } catch (err) {
    threw = err instanceof DeclarationRejected && err.field === "pilot.expiresAt";
  }
  assert(threw, "validateActivation must reject a new activation with a past expiresAt");
});

check("validateActivation: reloading the SAME already-loaded expired pilot is not rejected", () => {
  const d = clone();
  d.pilot = {
    active: true,
    sessionId: "sess-old",
    expiresAt: "2020-01-01T00:00:00Z",
    holdAtOrAbove: { value: "irreversible", basis: "test", proxy: true },
  };
  const loaded = validateDeclarations(d);
  // "prev" and "next" are the identical already-loaded pilot: not a new activation.
  validateActivation(loaded.declarations, loaded.declarations, new Date("2026-09-18T00:00:00Z"));
});

// ── to-sensor-config deep-equals the expected object ────────────────────────

// C9: the two Sig maps join this pin. They are the whole of what Part B adds to
// the sensor config, and pinning their VALUES here (not merely their presence)
// is what would catch a future edit that reshapes a map while leaving the field
// names intact — which is the shape of change the reader would accept silently
// and F2 would then read wrongly.
const EXPECTED_SENSOR_CONFIG = {
  eng: { structureThreshold: 0, minimumSampleSize: 1000 },
  sig: {
    clockToleranceMs: 0,
    clockToleranceBasis: "PROXY: asserted one box one clock, NOT measured",
    preconditionMap: {
      TOOL_EXECUTED: ["TOOL_ATTEMPTED"],
      TOOL_RESULT: ["TOOL_EXECUTED"],
      TOOL_HELD_NOT_EXECUTED: ["TOOL_ATTEMPTED"],
    },
    reentryMap: { TOOL_ATTEMPTED: ["TOOL_RESULT", "TOOL_HELD_NOT_EXECUTED"] },
  },
};

check("toSensorConfig deep-equals the expected {eng,sig} object", () => {
  const loaded = loadDeclarations(DRAFT_PATH);
  const got = toSensorConfig(loaded.declarations);
  assert(
    JSON.stringify(got) === JSON.stringify(EXPECTED_SENSOR_CONFIG),
    `got ${JSON.stringify(got)}, expected ${JSON.stringify(EXPECTED_SENSOR_CONFIG)}`
  );
});

check("toGuardFlags resolves the draft's housekeeper/bash subject, baseline line", () => {
  const loaded = loadDeclarations(DRAFT_PATH);
  const flags = toGuardFlags(loaded.declarations, loaded.pilotState, "housekeeper", "bash", null);
  assert(flags.stakesClass === "bash", flags.stakesClass);
  assert(flags.holdAtOrAbove === "state_changing", flags.holdAtOrAbove);
  assert(!flags.pilotApplied, "pilot inactive: must not apply");
});

check("toGuardFlags rejects an unknown subject", () => {
  const loaded = loadDeclarations(DRAFT_PATH);
  let threw = false;
  try {
    toGuardFlags(loaded.declarations, loaded.pilotState, "nobody", "bash", null);
  } catch (err) {
    threw = err instanceof UnknownSubjectError;
  }
  assert(threw, "expected UnknownSubjectError");
});

// ── zero-value / boundary mutation tests — every numeric declaration ───────
//
// A declared 0 (or another distinctive boundary value) must reach the
// derived consumer UNCHANGED. `structureThreshold` and `clockToleranceMs`
// are already 0 in the draft itself; the other numeric fields get a
// distinctive non-zero boundary here so a `|| fallback` or `??` substitution
// bug would show up as a mismatch rather than accidentally looking correct.

check("mutation: eng.structureThreshold = 0 reaches toSensorConfig as exactly 0 (not replaced)", () => {
  const loaded = loadDeclarations(DRAFT_PATH);
  assert(loaded.declarations.readers.eng.structureThreshold.value === 0, "draft ships 0");
  const cfg = toSensorConfig(loaded.declarations);
  assert(cfg.eng.structureThreshold === 0, `got ${cfg.eng.structureThreshold}`);
  assert(Object.is(cfg.eng.structureThreshold, 0) && !Object.is(cfg.eng.structureThreshold, -0), "must be +0, not -0 or undefined-coerced");
});

check("mutation: sig.clockToleranceMs = 0 reaches toSensorConfig as exactly 0 (not replaced)", () => {
  const loaded = loadDeclarations(DRAFT_PATH);
  assert(loaded.declarations.readers.sig.clockToleranceMs.value === 0, "draft ships 0");
  const cfg = toSensorConfig(loaded.declarations);
  assert(cfg.sig.clockToleranceMs === 0, `got ${cfg.sig.clockToleranceMs}`);
});

check("mutation: eng.minimumSampleSize boundary value 7 reaches toSensorConfig unchanged", () => {
  const d = clone();
  d.readers.eng.minimumSampleSize.value = 7;
  const loaded = validateDeclarations(d);
  const cfg = toSensorConfig(loaded.declarations);
  assert(cfg.eng.minimumSampleSize === 7, `got ${cfg.eng.minimumSampleSize}`);
});

check("mutation: eng.minimumSampleSize = 0 (the schema's own minimum) reaches toSensorConfig as exactly 0", () => {
  const d = clone();
  d.readers.eng.minimumSampleSize.value = 0;
  const loaded = validateDeclarations(d);
  const cfg = toSensorConfig(loaded.declarations);
  assert(cfg.eng.minimumSampleSize === 0, `got ${cfg.eng.minimumSampleSize}`);
});

check("mutation: sig.clockToleranceBasis distinctive string reaches toSensorConfig unchanged", () => {
  const d = clone();
  d.readers.sig.clockToleranceBasis.value = "DISTINCTIVE_MARKER_9f3a";
  const loaded = validateDeclarations(d);
  const cfg = toSensorConfig(loaded.declarations);
  assert(cfg.sig.clockToleranceBasis === "DISTINCTIVE_MARKER_9f3a", cfg.sig.clockToleranceBasis);
});

check("mutation: notice.window boundary value 1 (schema minimum) is loaded verbatim (not consumed by Stage 0 derivations, but must not reject)", () => {
  const d = clone();
  d.notice.window.value = 1;
  const loaded = validateDeclarations(d);
  assert(loaded.declarations.notice.window.value === 1, String(loaded.declarations.notice.window.value));
});

check("mutation: stakes.baseline.holdAtOrAbove distinctive value ('advisory') reaches toGuardFlags unchanged", () => {
  const d = clone();
  d.stakes.baseline.holdAtOrAbove.value = "advisory";
  const loaded = validateDeclarations(d);
  const flags = toGuardFlags(loaded.declarations, loaded.pilotState, "housekeeper", "bash", null);
  assert(flags.holdAtOrAbove === "advisory", flags.holdAtOrAbove);
});

check("mutation: subjects[0].stakesClass boundary value ('routine', the lowest rung) reaches toGuardFlags unchanged", () => {
  const d = clone();
  d.subjects[0].stakesClass = "routine";
  const loaded = validateDeclarations(d);
  const flags = toGuardFlags(loaded.declarations, loaded.pilotState, "housekeeper", "bash", null);
  assert(flags.stakesClass === "routine", flags.stakesClass);
});

check("mutation: subjects[0].peerUid boundary value 0 is REJECTED (X10), never silently accepted as a subject binding", () => {
  const d = clone();
  d.subjects[0].peerUid = 0;
  // 0 is a valid integer >= 0 for a bare peerUid field, but no housekeeper
  // route can legally exist at uid 0 (X10 forbids any routes[] row at uid 0),
  // so X6 (peerUid must be bound to a housekeeper route) fires.
  assertRejected(() => validateDeclarations(d), "subjects[0].peerUid");
});

check("mutation: pilot.holdAtOrAbove distinctive value ('state_changing') reaches toGuardFlags exactly for a matching active session", () => {
  const d = clone();
  d.pilot = {
    active: true,
    sessionId: "sess-boundary",
    expiresAt: "2099-01-01T00:00:00Z",
    holdAtOrAbove: { value: "state_changing", basis: "test", proxy: true },
  };
  const loaded = validateDeclarations(d, new Date("2026-09-18T00:00:00Z"));
  const flags = toGuardFlags(loaded.declarations, loaded.pilotState, "housekeeper", "bash", "sess-boundary");
  assert(flags.pilotApplied, "pilot must apply for the matching session");
  assert(flags.holdAtOrAbove === "state_changing", flags.holdAtOrAbove);
});

// ── integration: the exact import path Stage 2's service will use ──────────

check('integration: import { loadDeclarations } from "./declarations" resolves to the LOADER, not JSON', () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const mod = require("./declarations");
  assert(typeof mod.loadDeclarations === "function", "loadDeclarations must be a function, not a JSON value");
  assert(typeof mod.validateDeclarations === "function", "validateDeclarations must be a function");
  assert(typeof mod.canonicalHash === "function", "canonicalHash must be a function");
  assert(mod.schemaVersion === undefined, "the loader module must not itself BE the declaration object");
  const loaded = mod.loadDeclarations(DRAFT_PATH);
  assert(loaded.declarations.schemaVersion === 1, "the loader, invoked by this exact import path, must load the declaration correctly");
});

// ── run through mica-guard's own validator; record the OBSERVED exit code ──

check("toSensorConfig output run through mica-guard --sensor-config observes the recorded exit code", () => {
  const loaded = loadDeclarations(DRAFT_PATH);
  const sensorConfig = toSensorConfig(loaded.declarations);
  const dir = mkdtempSync(join(tmpdir(), "mica-bridge-test-"));
  const cfgPath = join(dir, "sensor-config.json");
  writeFileSync(cfgPath, JSON.stringify(sensorConfig));
  const guardScript = join(process.env.MICA_MACHINE_ROOT || (() => { throw new Error("set MICA_MACHINE_ROOT to a mica-machine checkout"); })(), "src/glue/mica-guard.ts");
  const npxBin = process.env.NPX_BIN || "npx";
  let exitCode = -1;
  let output = "";
  try {
    output = execFileSync(npxBin, ["ts-node", guardScript, "--action-id", "smoke", "--sensor-config", cfgPath], {
      cwd: process.env.MICA_MACHINE_ROOT,
      encoding: "utf8",
    });
    exitCode = 0;
  } catch (err: any) {
    exitCode = typeof err.status === "number" ? err.status : -1;
    output = String(err.stdout ?? "") + String(err.stderr ?? "");
  }
  unlinkSync(cfgPath);
  // OBSERVED this run, recorded in the receipt: mica-guard with a valid
  // --sensor-config and nothing else wired (no --log, no --floor-trail)
  // returns disposition HOLD-BLIND, execute=false, exit code 1 — NOT 2.
  // 2 is reserved for a usage/wiring error where the gate never ran at all;
  // here the gate DID run and composed a disposition (HOLD-BLIND), which is
  // why the exit code is 1. See mica-guard.ts's own header comment on the
  // three exit codes.
  assert(exitCode === 1, `observed exit ${exitCode}, output tail: ${output.split("\n").slice(-3).join(" | ")}`);
  assert(output.includes("HOLD-BLIND"), "expected disposition HOLD-BLIND in mica-guard's output");
});

// ── AMENDMENT 9 / RULING P: the wiring proof ────────────────────────────────
//
// Stage 0's contract claimed Eng and Sig were WIRED "because a log path is
// declared" — FALSE against the schema Stage 0 actually shipped, which had
// no logPath field at all: WireOptions.logPath was necessarily undefined,
// wire.ts:370-374 pushed both readers wired:false, sensorVerdicts stayed
// empty, and no instrument could ever return ALARM. This test constructs
// the wiring from the now-repaired declaration and calls mica-machine's
// real wire() — not a mock, not a reimplementation — to show the schema fix
// actually closes the gap.

check("AMENDMENT 9 / Ruling P: wire(toWireOptions(declaration)) produces sensorVerdicts.length > 0 (Eng and Sig WIRED)", () => {
  const loaded = loadDeclarations(DRAFT_PATH);
  const options = toWireOptions(loaded.declarations);
  assert(options.logPath === loaded.declarations.readers.logPath.value, "logPath threaded through");
  // ACT A: the declared kind is now "subject-chain" (the arbiter's ruling 5). This
  // asserts THREADING, not a particular value — it reads the declaration rather
  // than a literal, so the next ruled change to logKind does not need this line
  // edited to stay true.
  assert(
    options.logKind === loaded.declarations.readers.logKind.value,
    `logKind threaded through as declared (declared ${loaded.declarations.readers.logKind.value}, threaded ${String(options.logKind)})`
  );
  // ⛔ THIS ASSERTION USED TO PIN THE LITERAL "subject-chain", CITING ACT A RULING 5,
  //    AND THE LIVE BOX DECLARES "mica". Read at bytes 2026-09-28 from
  //    /opt/mica-bridge/mica-bridge/declarations.config.json and confirmed on
  //    /status. Either a declaration act is owed to carry ruling 5, or the ruling
  //    is misstated — that is a WHAT on the board and NOT settled here.
  //
  //    The fixture now mirrors the SERVING declaration (Codex, 2026-09-28), so
  //    what this line can honestly pin is that the fixture and the box agree on
  //    the kind. The THREADING assertion above is the one that carries the
  //    weight, and it reads the declaration rather than a literal.
  assert(
    options.logKind === loaded.declarations.readers.logKind.value,
    "the fixture's kind threads through unchanged"
  );
  const wiring = wire(options);
  assert(wiring.sensorVerdicts.length > 0, `expected sensorVerdicts.length > 0, got ${wiring.sensorVerdicts.length}`);
  // [verified] wire.ts:93-94 — ENG_READER = "MICA/Eng", SIG_READER = "MICA/Sig".
  const engRow = wiring.census.readers.find((r) => r.reader === "MICA/Eng");
  const sigRow = wiring.census.readers.find((r) => r.reader === "MICA/Sig");
  assert(!!engRow, `expected a "MICA/Eng" row in the census, got readers: ${wiring.census.readers.map((r) => r.reader).join(", ")}`);
  assert(!!sigRow, `expected a "MICA/Sig" row in the census, got readers: ${wiring.census.readers.map((r) => r.reader).join(", ")}`);
  assert(engRow!.wired === true, "Eng must read wired:true once logPath/logKind are declared");
  assert(sigRow!.wired === true, "Sig must read wired:true once logPath/logKind are declared");
  // DISCLOSED, not swept under, and REWRITTEN BY ACT A because the old
  // disclosure is no longer the true one:
  //   · the RECORD SHAPE gap closed at C9 — MICA's five required fields ride
  //     on every subject record, additively.
  //   · the LOAD STATE gap closes here — the store is a hash chain that earns
  //     LOADED_SUBJECT_CHAIN_VERIFIED, and readableLoadStates admits it.
  //   · WHAT REMAINS TRUE FOR THIS TEST: it runs as uid 1000, which cannot
  //     read /var/lib/mica-bridge/subject-events.jsonl at all (mode 0640,
  //     mica-bridge:mica-bridge, group 972 empty). So the reader here reports
  //     SUBJECT_CHAIN_UNREADABLE — NOT absent, and deliberately a different
  //     state — and both readers CANNOT_ASSESS. That is a fact about this
  //     TEST's privilege, not about the deployment, and the acceptance
  //     readings are taken through /status for exactly that reason.
  //   · WHAT REMAINS OPEN AFTER ACT A: independence. Same writer, same
  //     chainer, same verifier. Act B.
  // The schema-level defect Ruling P names — Eng/Sig unwireable at all — is
  // what this test proves closed.
  assert(
    wiring.sensorVerdicts.every((v) => v.kind !== undefined),
    "every pushed sensorVerdict must at least carry a kind (CANNOT_ASSESS or otherwise), never be undefined"
  );
});

// ── THE BUNDLE, 2026-09-24 · the four optional reader blocks ────────────────
//
// WHAT THESE TESTS ARE FOR. `checkNoUnknown(readersRaw, [...])` refused any
// key it did not name, and before this change it named five — so although
// mica-machine's `wire.ts` has gated narrow-K on `options.narrowK` since item 4
// landed, A DECLARATION CARRYING `readers.narrowK` WOULD HAVE BEEN REJECTED AT
// LOAD and the service would have kept its last known good one. narrow-K was
// not "live and inert"; it was unreachable from the front door. The first test
// below is the one that would have caught that.

check("BUNDLE: readers.narrowK loads, and `constraintClass` is NOT the field name", () => {
  const d = clone();
  d.readers.narrowK = {
    declaredProfile: {
      value: ["HELD_THEN_DIVERGED"],
      basis:
        "PROXY. Held, then did something else: the constraint was respected. A ONE-MEMBER " +
        "LIST, not a `constraintClass` field — narrow-K takes `declaredProfile?: readonly " +
        "string[]` and there is no field of that other name anywhere in the tree.",
      proxy: true,
    },
  };
  const loaded = validateDeclarations(d).declarations;
  assert(loaded.readers.narrowK !== undefined, "narrowK must survive validation");
  assert(
    JSON.stringify(loaded.readers.narrowK!.declaredProfile.value) === '["HELD_THEN_DIVERGED"]',
    JSON.stringify(loaded.readers.narrowK)
  );
  // AND IT REACHES THE MACHINE'S OWN GATE, unwrapped. A block that validates and
  // does not arrive is the same vacancy in a different coat.
  const opts: any = toWireOptions(loaded);
  assert(
    JSON.stringify(opts.narrowK) === '{"declaredProfile":["HELD_THEN_DIVERGED"]}',
    `toWireOptions must strip the envelope and emit the bare config: ${JSON.stringify(opts.narrowK)}`
  );
});

check("BUNDLE: absent blocks are ABSENT KEYS, so the sealed declaration hash does not move", () => {
  const loaded = validateDeclarations(clone()).declarations;
  assert(!("narrowK" in loaded.readers), "narrowK must not be a present-and-undefined key");
  assert(!("narrowW" in loaded.readers), "narrowW must not be a present-and-undefined key");
  assert(!("narrowR" in loaded.readers), "narrowR must not be a present-and-undefined key");
  assert(!("doctorCadence" in loaded.readers), "doctorCadence must not be a present-and-undefined key");
  const opts: any = toWireOptions(loaded);
  for (const key of ["narrowK", "narrowW", "narrowR", "op1"]) {
    assert(!(key in opts), `toWireOptions must emit no ${key} key at all when undeclared`);
  }
});

check("BUNDLE: leg 2's two numbers must be declared together — one alone is refused", () => {
  const d = clone();
  d.readers.narrowW = {
    declaredProfile: { value: ["SOME_CLASS"], basis: "fixture", proxy: true },
    correlationThreshold: { value: 0.05, basis: "fixture", proxy: true },
  };
  assertRejected(() => validateDeclarations(d), "readers.narrowW.correlationThreshold");
  // …and together, it loads.
  d.readers.narrowW.correlationMinimumInquiryEvents = { value: 30, basis: "fixture", proxy: true };
  const loaded = validateDeclarations(d).declarations;
  assert(loaded.readers.narrowW !== undefined, "both declared -> loads");
});

check("BUNDLE: narrow-R's minimum-events field is named for ITS OWN factor, not narrow-W's", () => {
  const d = clone();
  d.readers.narrowR = {
    declaredProfile: { value: ["SOME_CLASS"], basis: "fixture", proxy: true },
    correlationThreshold: { value: 0.05, basis: "fixture", proxy: true },
    correlationMinimumInquiryEvents: { value: 30, basis: "fixture", proxy: true },
  };
  // narrow-R's field is correlationMinimumVerificationEvents. The vocabulary
  // follows the factor; a declaration that borrows another reader's word is a
  // field the instrument will never read.
  assertRejected(() => validateDeclarations(d), "readers.narrowR");
});

check("BUNDLE: the report-only permutation pair must also be declared together", () => {
  const d = clone();
  d.readers.narrowK = {
    declaredProfile: { value: ["HELD_THEN_DIVERGED"], basis: "fixture", proxy: true },
    correlationPermutationSamples: { value: 1000, basis: "fixture", proxy: true },
  };
  assertRejected(() => validateDeclarations(d), "readers.narrowK.correlationPermutationSamples");
});

check("BUNDLE: declaredProfile is REQUIRED once a narrowing block exists", () => {
  const d = clone();
  d.readers.narrowK = { correlationThreshold: { value: 0.05, basis: "fixture", proxy: true } };
  assertRejected(() => validateDeclarations(d), "readers.narrowK.declaredProfile");
});

check("BUNDLE: readers.doctorCadence loads and reaches wire() as op1", () => {
  const d = clone();
  d.readers.doctorCadence = {
    attestationClass: {
      value: { moduleId: "housekeeper", eventType: "DOCTOR_ATTESTED" },
      basis:
        "The one kind on this log written by a second party ABOUT the subject. moduleId is " +
        "identity.subject, which is what the bridge writes into the record's moduleId field.",
      proxy: true,
    },
    cadenceBoundSteps: { value: 100, basis: "PRE-PILOT PROXY", proxy: true },
  };
  const loaded = validateDeclarations(d).declarations;
  const opts: any = toWireOptions(loaded);
  assert(
    JSON.stringify(opts.op1) ===
      '{"attestationClass":{"moduleId":"housekeeper","eventType":"DOCTOR_ATTESTED"},"cadenceBoundSteps":100}',
    JSON.stringify(opts.op1)
  );
});

check("BUNDLE: doctorCadence pointed at the SUBJECT'S OWN act record is refused at load", () => {
  // THE DEFECT THIS REFUSES: op1 counts occurrences of the declared class and
  // reads their spacing as a doctor's cadence. Point it at TOOL_ATTEMPTED and
  // the SUBJECT supplies its own cadence — a reading that is not merely wrong
  // but self-serving. Refused where the grant is written (the X13 shape), not
  // where it would be obeyed.
  const d = clone();
  d.readers.doctorCadence = {
    attestationClass: {
      value: { moduleId: "housekeeper", eventType: "TOOL_ATTEMPTED" },
      basis: "fixture",
      proxy: true,
    },
  };
  assertRejected(() => validateDeclarations(d), "readers.doctorCadence.attestationClass.value.eventType");
});

check("BUNDLE: an unknown readers key is still refused — the allow-list grew and no more", () => {
  const d = clone();
  d.readers.narrowX = { declaredProfile: { value: ["X"], basis: "fixture", proxy: true } };
  assertRejected(() => validateDeclarations(d), "readers");
});

// ── H12 · readers.nodeResponse, declarable and inert ─────────────────────────
//
// THE SHIPPED DECLARATION DOES NOT CARRY THIS BLOCK, and that is the state
// these checks are mostly about. The schema, the validator and the mapper all
// accept it; nothing declares it; OP-3 is a stated vacancy. Turning it on is an
// arbiter's act, for the reason the last two checks below make mechanical.
//
// THE STANZA BELOW IS THE ONE THAT WOULD BE PASTED, verbatim, envelopes and
// bases included. It is exercised here so that "this stanza loads and maps to
// exactly these options" is a tested statement rather than a drafted one — the
// defect of a basis that was never tested against the thing it names is what
// this block exists not to repeat.

const H12_STANZA = {
  expectationClass: {
    value: { moduleId: "housekeeper", eventType: "TOOL_ATTEMPTED" },
    basis:
      "PROXY. The call is TOOL_ATTEMPTED on subject housekeeper: it is the one record this caller " +
      "writes BEFORE it acts and before any decision is taken, and it is the only class in this record " +
      "whose meaning is 'something was asked for and is not yet resolved'. moduleId is housekeeper " +
      "because the bridge writes moduleId from the subject's own identity and this deployment declares " +
      "exactly one subject. NOT WHAT CANON MEANS BY A CALL, and this field says so rather than letting " +
      "the word carry it: canon's expectation is a call to a HUMAN node, and what is declared here is a " +
      "tool loop calling itself.",
    proxy: true,
  },
  responseClass: {
    value: { moduleId: "housekeeper", eventType: "TOOL_RESULT" },
    basis:
      "PROXY, AND THE OMISSION IS PART OF THE DECLARATION. TOOL_RESULT is what this caller writes when " +
      "an act came back, and it is the only class that means the thing asked for returned. TOOL_EXECUTED " +
      "is not it: it says the act started, never that anything returned. TOOL_HELD_NOT_EXECUTED is the " +
      "OTHER closing path AND IT CANNOT ALSO BE DECLARED — the instrument's profile carries one response " +
      "class and not a list, so a caller with two ways to close an attempt can have exactly one of them " +
      "counted as an answer. Declaring TOOL_HELD_NOT_EXECUTED instead would invert the defect rather than " +
      "remove it: every act that RAN would then read unanswered, and running is the common case. " +
      "TOOL_RESULT is chosen as the narrower error — it leaves holds uncounted, and holds are rare, " +
      "deliberate, and already recorded elsewhere. A response class covering both closing paths is an " +
      "instrument change and is not in this deployment's gift.",
    proxy: true,
  },
  responseBoundSteps: {
    value: 2,
    basis:
      "PROXY. TWO, BECAUSE TWO IS WHAT THIS CALLER WRITES. For an act that runs, the caller appends " +
      "TOOL_ATTEMPTED, then TOOL_EXECUTED, then TOOL_RESULT to one serialized outbox, and it processes " +
      "acts one at a time in an awaited loop, so the three records of an act are contiguous and the " +
      "subject sequence advances by one per record. The result therefore lands exactly two steps after " +
      "its attempt, every time, and the instrument conforms at exactly the declared bound and refuses at " +
      "the bound plus one. ONE IS TOO NARROW: it excludes the TOOL_EXECUTED that always sits between " +
      "them, and no act would ever pair. THREE OR MORE IS NOT SLACK, IT IS A DIFFERENT READING: the next " +
      "act's TOOL_RESULT sits four steps after a held act's attempt, so any bound of four or more pairs " +
      "an attempt to ANOTHER act's result and reports clean — the instrument pairs by sequence position " +
      "and never by actionId, although this record carries actionId on every line. Two is the only value " +
      "that admits exactly the shape this harness writes and nothing wider. WHAT TWO COSTS, STATED AT ITS " +
      "TRUE WIDTH: an act that was HELD is closed by TOOL_HELD_NOT_EXECUTED and never by TOOL_RESULT, so " +
      "every held act is an expectation with no qualifying response and leg A alarms on it. That is not a " +
      "miscalibration of this number; it is the consequence of one response class and two closing paths, " +
      "and it is why declaring this block is the arbiter's act and not the builder's. RECALIBRATE when " +
      "the caller's write sequence changes, not on pilot data.",
    proxy: true,
  },
} as const;

check("the SHIPPED declaration's readers.nodeResponse matches what the box serves", () => {
  // ⛔ THIS TEST USED TO SAY "SHIPPED", READ THE FIXTURE, AND ASSERT OP-3 IS A
  // VACANCY. All three drifted: the fixture is not the shipped config, and the box
  // HAS declared nodeResponse since the `opa` line. Asserting a vacancy that no
  // longer exists is the stale-printer shape again — a claim that outlived its
  // subject, in the suite that exists to catch exactly that.
  //
  // It now reads declarations.config.json and asserts the DECLARED state, whatever
  // it is, so it tracks the box instead of a memory of it.
  const loaded = loadDeclarations(SHIPPED_PATH);
  const declared = loaded.declarations.readers.nodeResponse !== undefined;
  assert(
    declared === (shipped.readers.nodeResponse !== undefined),
    "the loader and the raw file must agree on whether nodeResponse is declared"
  );
  // ⛔ A STUB LOADER, AND WHY THIS TEST NEEDS ONE.
  //
  //   S11 declared `paths.clerkStamps` on the shipped config, and a declared path
  //   with no loader is a WIRING ERROR that `toWireOptions` throws by name —
  //   correctly. This test's subject is the nodeResponse -> op3 projection, not the
  //   stamps leg, so it injects a harmless loader rather than weakening that
  //   refusal (which "a declared stamps path with NO loader is a wiring error"
  //   pins directly).
  //
  //   The counter is not decoration: it keeps this test COUPLED to the deployment.
  //   A stub that is never called would let the test drift away from the shipped
  //   config it claims to read — the same "claim that outlived its subject" shape
  //   the comment above is about. So: declared implies consulted, absent implies
  //   untouched, and the assertion fails either way round.
  let stampLoaderCalls = 0;
  const stubStamps = () => {
    stampLoaderCalls++;
    return [];
  };
  const opts = toWireOptions(loaded.declarations, (p) => p, stubStamps) as Record<string, unknown>;
  const stampsDeclared = loaded.declarations.paths.clerkStamps !== undefined;
  assert(
    stampLoaderCalls === (stampsDeclared ? 1 : 0),
    `the stamps loader must be consulted exactly when the path is declared: ` +
      `declared=${String(stampsDeclared)}, calls=${stampLoaderCalls}`
  );
  assert(
    ("op3" in opts) === declared,
    `a declared block must reach the wire and an absent one must not: declared=${String(declared)}, ` +
      `op3 in options=${String("op3" in opts)}`
  );
});

check("H12 is INERT WHEN ABSENT: the declaration hash is unmoved by the new field existing", () => {
  // The pin above already asserts the digest; this states WHY it still holds
  // after a schema field was added, in the one form that can fail if it stops
  // being true — the optional field is absent, and absent hashes as nothing.
  const loaded = loadDeclarations(DRAFT_PATH);
  assert(
    loaded.declarationHash === EXPECTED_HASH,
    `adding an OPTIONAL declaration field must not move the hash of a declaration that does not use it; ` +
      `got ${loaded.declarationHash}, expected ${EXPECTED_HASH}`
  );
});

check("the H12 stanza loads, and maps to exactly the options wire() gates on", () => {
  const d = clone();
  d.readers.nodeResponse = JSON.parse(JSON.stringify(H12_STANZA));
  const loaded = validateDeclarations(d);
  const nr = loaded.declarations.readers.nodeResponse;
  assert(nr !== undefined, "the stanza must load");
  assert(nr!.responseBoundSteps.value === 2, "two, and the basis says why two and nothing else");
  assert(nr!.responseBoundSteps.proxy === true, "it is a proxy and must say so");
  assert(nr!.expectationClass.value.eventType === "TOOL_ATTEMPTED", "expectation class");
  assert(nr!.responseClass.value.eventType === "TOOL_RESULT", "response class");

  const opts = toWireOptions(loaded.declarations) as Record<string, unknown>;
  assert("op3" in opts, "a declared block must reach WireOptions");
  assert(
    JSON.stringify(opts.op3) ===
      JSON.stringify({
        expectationClass: { moduleId: "housekeeper", eventType: "TOOL_ATTEMPTED" },
        responseClass: { moduleId: "housekeeper", eventType: "TOOL_RESULT" },
        responseBoundSteps: 2,
      }),
    `the mapper must project .value and nothing else; got ${JSON.stringify(opts.op3)}`
  );
});

check("declaring H12 MOVES the declaration hash — turning a reader on is never quiet", () => {
  const without = clone();
  const with_ = clone();
  with_.readers.nodeResponse = JSON.parse(JSON.stringify(H12_STANZA));
  const a = validateDeclarations(without).declarationHash;
  const b = validateDeclarations(with_).declarationHash;
  assert(a !== b, "the hash every decision binds itself to must record that OP-3 was switched on");
});

check("flatness is optional, and when present it is projected whole", () => {
  const d = clone();
  d.readers.nodeResponse = {
    ...JSON.parse(JSON.stringify(H12_STANZA)),
    flatness: {
      amiFloor: { value: 0.05, basis: "PROXY: the instrument's own named pre-pilot proxy, carried unchanged rather than re-derived.", proxy: true },
      amiCeilingMargin: { value: 0.02, basis: "PROXY: the instrument's own named pre-pilot proxy, carried unchanged rather than re-derived.", proxy: true },
      minSample: { value: 30, basis: "PROXY: the instrument's own named pre-pilot proxy. Far above anything this record holds, so leg B reads its blindness as a sample shortfall rather than as a missing decision.", proxy: true },
    },
  };
  const loaded = validateDeclarations(d);
  const opts = toWireOptions(loaded.declarations) as Record<string, unknown>;
  assert(
    JSON.stringify((opts.op3 as Record<string, unknown>).flatness) ===
      JSON.stringify({ amiFloor: 0.05, amiCeilingMargin: 0.02, minSample: 30 }),
    `flatness must project whole; got ${JSON.stringify((opts.op3 as Record<string, unknown>).flatness)}`
  );
});

// ── the rejections, each naming its own field ───────────────────────────────

const H12_REJECTIONS: readonly { readonly name: string; readonly mutate: (nr: any) => void; readonly field: string }[] = [
  {
    name: "an identical expectation and response class",
    mutate: (nr) => {
      nr.responseClass.value = { moduleId: "housekeeper", eventType: "TOOL_ATTEMPTED" };
    },
    field: "readers.nodeResponse.responseClass",
  },
  {
    name: "responseBoundSteps omitted (it would silently mean ORDER-ONLY)",
    mutate: (nr) => {
      delete nr.responseBoundSteps;
    },
    field: "readers.nodeResponse.responseBoundSteps",
  },
  {
    name: "responseBoundSteps zero",
    mutate: (nr) => {
      nr.responseBoundSteps.value = 0;
    },
    field: "readers.nodeResponse.responseBoundSteps.value",
  },
  {
    name: "a whitespace-only eventType",
    mutate: (nr) => {
      nr.expectationClass.value.eventType = "   ";
    },
    field: "readers.nodeResponse.expectationClass.value.eventType",
  },
  {
    name: "an unknown key inside the block",
    mutate: (nr) => {
      nr.responseBoundStepz = { value: 2, basis: "typo", proxy: true };
    },
    field: "readers.nodeResponse",
  },
  {
    name: "an unknown key inside a class value",
    mutate: (nr) => {
      nr.expectationClass.value.outcome = "bash";
    },
    field: "readers.nodeResponse.expectationClass.value",
  },
  {
    name: "a basis that is empty — a declared proxy with no stated reason",
    mutate: (nr) => {
      nr.responseBoundSteps.basis = "";
    },
    field: "readers.nodeResponse.responseBoundSteps.basis",
  },
];

for (const rejection of H12_REJECTIONS) {
  check(`readers.nodeResponse REFUSES ${rejection.name}`, () => {
    const d = clone();
    d.readers.nodeResponse = JSON.parse(JSON.stringify(H12_STANZA));
    rejection.mutate(d.readers.nodeResponse);
    assertRejected(() => validateDeclarations(d), rejection.field);
  });
}

check("readers.nodeResponse.flatness REFUSES a minSample below the instrument's own floor", () => {
  const d = clone();
  d.readers.nodeResponse = {
    ...JSON.parse(JSON.stringify(H12_STANZA)),
    flatness: {
      amiFloor: { value: 0.05, basis: "b", proxy: true },
      amiCeilingMargin: { value: 0.02, basis: "b", proxy: true },
      minSample: { value: 2, basis: "b", proxy: true },
    },
  };
  assertRejected(() => validateDeclarations(d), "readers.nodeResponse.flatness.minSample.value");
});

check("readers.nodeResponse.flatness REFUSES an amiFloor at the closed end of (0,1)", () => {
  const d = clone();
  d.readers.nodeResponse = {
    ...JSON.parse(JSON.stringify(H12_STANZA)),
    flatness: {
      amiFloor: { value: 1, basis: "b", proxy: true },
      amiCeilingMargin: { value: 0.02, basis: "b", proxy: true },
      minSample: { value: 30, basis: "b", proxy: true },
    },
  };
  assertRejected(() => validateDeclarations(d), "readers.nodeResponse.flatness.amiFloor.value");
});

// ── THE MERGE, 2026-09-24 · FIVE OPTIONAL BLOCKS, ONE FRONT DOOR ─────────────
//
// WHY THIS SECTION EXISTS AND WHY IT IS NOT REDUNDANT WITH THE TWO ABOVE IT.
// The bundle line added `narrowK`/`narrowW`/`narrowR`/`doctorCadence` to
// `checkNoUnknown(readersRaw, [...])`; the `opa` line (109d5d9) added
// `nodeResponse` to the SAME call. Each line's own tests passed on its own
// branch. A merge that kept one edit and dropped the other would leave a block
// that has a schema, a type, a validator and a mapper — and is REJECTED AT LOAD,
// silently, with the service keeping its last known good declaration. That is
// the exact state `narrowK` was in for the whole of item 4's life.
//
// SO THE PROOF IS A LOAD, NEVER A READ OF THE LINE. Reading the allow-list and
// counting names proves that the line says what it says. Loading a declaration
// that CARRIES the block proves the block reaches its validator. The two are not
// the same claim and only the second one is worth having.
//
// The negative control is in the same check, and it is what stops this section
// from passing because the door was left open: a key NO line ever added must
// still be refused.

const MERGE_BLOCKS: ReadonlyArray<{
  readonly key: string;
  readonly wireKey: string;
  readonly block: unknown;
}> = [
  {
    key: "narrowK",
    wireKey: "narrowK",
    block: {
      declaredProfile: {
        value: ["HELD_THEN_DIVERGED"],
        basis: "MERGE FIXTURE, not a declaration. narrow-K's candidate class.",
        proxy: true,
      },
    },
  },
  {
    key: "narrowW",
    wireKey: "narrowW",
    block: {
      declaredProfile: {
        value: ["TURN_ENDED_ASKING", "ASK_ANSWERED"],
        basis: "MERGE FIXTURE, not a declaration. narrow-W's two candidate classes.",
        proxy: true,
      },
    },
  },
  {
    key: "narrowR",
    wireKey: "narrowR",
    block: {
      declaredProfile: {
        value: ["ACT_REVISITED"],
        basis: "MERGE FIXTURE, not a declaration. narrow-R's candidate class.",
        proxy: true,
      },
    },
  },
  {
    // 2026-09-25. The sixth block, and it joins for the same reason the five
    // joined: without "narrowT" in the front door's allow-list, Sunday's
    // declaration act would have been refused AT LOAD, the service would have
    // kept its last known good declaration, and `declarationHash` would not have
    // moved — an act that silently does not land. Note what this fixture does
    // NOT contain: a declared class. narrow-T reads one record's arc, so it
    // carries no latch, and no caller has to write anything first.
    key: "narrowT",
    wireKey: "narrowT",
    block: {
      driftTolerance: {
        value: 0.35,
        basis: "MERGE FIXTURE, not a declaration. Inverted polarity: ABOVE this is the ALARM.",
        proxy: true,
      },
      minimumEventsPerWindow: {
        value: 12,
        basis: "MERGE FIXTURE, not a declaration.",
        proxy: true,
      },
    },
  },
  {
    key: "doctorCadence",
    wireKey: "op1",
    block: {
      attestationClass: {
        value: { moduleId: "housekeeper", eventType: "DOCTOR_ATTESTED" },
        basis: "MERGE FIXTURE, not a declaration.",
        proxy: true,
      },
      cadenceBoundSteps: { value: 100, basis: "MERGE FIXTURE", proxy: true },
    },
  },
  {
    key: "nodeResponse",
    wireKey: "op3",
    block: H12_STANZA,
  },
];

check(
  "MERGE: EVERY optional block reaches its validator through the front door — proved one block at a time, by LOADING a declaration that carries it",
  () => {
    for (const { key, wireKey, block } of MERGE_BLOCKS) {
      const d = clone();
      d.readers[key] = JSON.parse(JSON.stringify(block));
      let loaded;
      try {
        loaded = validateDeclarations(d).declarations;
      } catch (err) {
        if (err instanceof DeclarationRejected) {
          throw new Error(
            `readers.${key} was REJECTED AT LOAD (field "${err.field}": ${err.message}). ` +
              `That is the checkNoUnknown(readersRaw, [...]) front door, not the schema and not ` +
              `the validator: add "${key}" to that allow-list in declarations.ts's validate(). ` +
              `A block missing from it is not "live and inert" — it is unreachable, and the ` +
              `declaration act that turns the reader on fails at load.`
          );
        }
        throw err;
      }
      assert(key in loaded.readers, `readers.${key} loaded but did not survive into the parsed object`);
      const opts: any = toWireOptions(loaded);
      assert(
        wireKey in opts,
        `readers.${key} loaded but toWireOptions emitted no "${wireKey}" key, so wire() would ` +
          `leave the reader a stated vacancy with a declaration sitting right there`
      );
    }
  }
);

check(
  "MERGE: all six blocks declared AT ONCE load together, and all six reach wire() — one line's edit did not overwrite the other's",
  () => {
    const d = clone();
    for (const { key, block } of MERGE_BLOCKS) {
      d.readers[key] = JSON.parse(JSON.stringify(block));
    }
    const loaded = validateDeclarations(d).declarations;
    const opts: any = toWireOptions(loaded);
    for (const { key, wireKey } of MERGE_BLOCKS) {
      assert(key in loaded.readers, `readers.${key} missing after the all-five load`);
      assert(wireKey in opts, `WireOptions.${wireKey} missing after the all-five load`);
    }
  }
);

check(
  "MERGE: the front door is still a door — a key no line ever added is REFUSED, so the six above pass because they are named and not because the check is off",
  () => {
    for (const name of ["narrowX", "nodeResponses", "doctorcadence", "op3", "gate4"]) {
      const d = clone();
      d.readers[name] = { declaredProfile: { value: ["X"], basis: "fixture", proxy: true } };
      assertRejected(() => validateDeclarations(d), "readers");
    }
  }
);

check(
  "MERGE: with NONE of the six declared, the declaration hash does NOT move — absent block, absent key, byte-identical digest",
  () => {
    // THE ACCEPTANCE THE ARBITER'S RULING NAMES, pinned against the FIXTURE so it stays
    // fixed across relays: the fixture carries no new block, so it must hash to
    // exactly what it hashed
    // to before any of this existed. The pin is checked twice: once against the
    // sealed constant (the number a relay acceptance reads), and once against a
    // hash taken of the SAME parsed object with the five keys proven absent —
    // which is what makes "absent, not present-and-undefined" the reason.
    const loaded = loadDeclarations(DRAFT_PATH);
    assert(
      loaded.declarationHash === EXPECTED_HASH,
      `the FIXTURE's hash MOVED: got ${loaded.declarationHash}, expected ${EXPECTED_HASH}. This pins the LOADER against a fixed input; it is not a claim about what the box serves.`
    );
    for (const { key } of MERGE_BLOCKS) {
      assert(
        !(key in loaded.declarations.readers),
        `readers.${key} is a PRESENT key on a declaration that does not declare it — ` +
          `canonicalHash omits undefined by its rule 4 today, but a present key is one ` +
          `refactor away from a moved hash`
      );
    }
    const opts: any = toWireOptions(loaded.declarations);
    for (const { wireKey } of MERGE_BLOCKS) {
      assert(!(wireKey in opts), `toWireOptions emitted "${wireKey}" for an undeclared block`);
    }
    // And the converse, so the check above cannot pass by the hash being
    // insensitive to these fields: declaring ONE of them MOVES it.
    for (const { key, block } of MERGE_BLOCKS) {
      const d = clone();
      d.readers[key] = JSON.parse(JSON.stringify(block));
      const moved = validateDeclarations(d).declarationHash;
      const flat = validateDeclarations(clone()).declarationHash;
      assert(
        moved !== flat,
        `declaring readers.${key} did NOT move the declaration hash — the block is not in the digest`
      );
    }
  }
);

// ── T11 · readers.eng.minimumClassCoverage, 2026-10-01 ──────────────────────
//
// The same INNER front door as clerkStampLag below, one level down behind
// `checkNoUnknown(engRaw, [...])`. A block can be through the outer door and
// refused at the inner one, and until today this field was.

check(
  "T11: readers.eng.minimumClassCoverage reaches its validator AND the sensor config — proved by LOADING, not by reading the eng allow-list",
  () => {
    const d = clone();
    d.readers.eng.minimumClassCoverage = {
      value: 3,
      basis: "T11 FIXTURE, not a declaration. The served basis is in declarations.config.json.",
      proxy: true,
    };
    let loaded;
    try {
      loaded = validateDeclarations(d).declarations;
    } catch (err) {
      if (err instanceof DeclarationRejected) {
        throw new Error(
          `readers.eng.minimumClassCoverage was REFUSED AT LOAD (field "${err.field}": ${err.message}). ` +
            `That is checkNoUnknown(engRaw, [...]) in validate() — the INNER front door, which is ` +
            `exactly the wall this act opens.`
        );
      }
      throw err;
    }
    assert(
      loaded.readers.eng.minimumClassCoverage !== undefined &&
        loaded.readers.eng.minimumClassCoverage.value === 3,
      `the field must survive validation with its value intact: ${JSON.stringify(loaded.readers.eng.minimumClassCoverage)}`
    );
    // ⛔ AND IT MUST REACH THE SENSOR. Accepting it at the door and dropping it
    //    after is the seam this project has found nine times: a producer emits N
    //    fields, a hand-written projection carries M < N, a reader needs one of
    //    the N - M. `toSensorConfig` is that projection.
    const sc = toSensorConfig(loaded);
    assert(
      sc.eng.minimumClassCoverage === 3,
      `toSensorConfig dropped it — accepted at the door and lost after it: ${JSON.stringify(sc.eng)}`
    );
  }
);

check(
  "T11: a declaration WITHOUT the field STILL LOADS, and the sensor config omits it — the field is OPTIONAL here on purpose",
  () => {
    // ⛔ THIS IS THE ARM THAT FAILS IF SOMEONE MAKES IT REQUIRED, and the rule
    //    accepted 2026-10-01 20:29Z says every "X and NOT Y" condition earns a
    //    mutant that implements Y. The X is "optional"; the Y is "required".
    //    T11's own condition: "until readers.eng.minimumClassCoverage is
    //    declared, Eng returns MISSING_CONFIGURATION, which is the honest state
    //    and not a regression." Requiring it at this door would convert that
    //    honest blind reading into a REFUSED DECLARATION and cost the deployment
    //    every other reader to enforce one field.
    const d = clone();
    assert(
      d.readers.eng.minimumClassCoverage === undefined,
      "the fixture already carries the field — this arm needs one that does not"
    );
    const loaded = validateDeclarations(d).declarations;
    assert(
      loaded.readers.eng.minimumClassCoverage === undefined,
      "an undeclared field must be ABSENT, not undefined-valued: the sensor's own " +
        "'absent' arm is written against the key not being there"
    );
    assert(
      !("minimumClassCoverage" in toSensorConfig(loaded).eng),
      "toSensorConfig emitted the key for an undeclared field; mica-guard refuses a " +
        "wrong-shaped value and the sensor's absent arm expects no key at all"
    );
  }
);

check(
  "T11: a value of the WRONG SHAPE is refused at this door, not left to read as a cautious hold",
  () => {
    // Eng requires an integer >= 1. A fractional, zero or negative value would
    // otherwise pass the door and come back as MISSING_CONFIGURATION, which
    // reads as caution rather than as the mistake it is.
    for (const bad of [2.5, 0, -3, "3"] as unknown[]) {
      const d = clone();
      d.readers.eng.minimumClassCoverage = { value: bad, basis: "T11 FIXTURE", proxy: true };
      let refused = false;
      try {
        validateDeclarations(d);
      } catch (err) {
        refused = err instanceof DeclarationRejected;
      }
      assert(refused, `minimumClassCoverage ${JSON.stringify(bad)} was NOT refused at the door`);
    }
  }
);

// ── T11 / CODEX F1 · the committed SCHEMA and the runtime LOADER must agree ──
//
// Codex, cold read 1 of the Eng key-set act
// (the first verify of the Eng key-set act, finding F1):
//   "the committed declarations.schema.json still forbids the new field. The
//    hand-written runtime loader accepts the candidate, but a Draft 2020-12
//    validator rejects it ... a declaration the schema rejects is a declaration
//    that lies about itself."
//
// declarations.ts says it enforces declarations.schema.json VERBATIM and the
// bridge README presents the schema as THE declaration contract. Nothing in this
// suite had ever READ the schema, so the two drifted the instant an act widened
// one of them — invisibly, because every other test here goes through the loader
// and the loader was the side that moved.
//
// ⛔ WHAT THESE CHECKS ARE, AND WHAT THEY ARE NOT.
//    They are scoped to `readers.eng`, and they are NOT a Draft 2020-12
//    validator. This suite has no framework and no ajv, deliberately (first line
//    of this file), so a dependency-free SUBSET evaluator is used — and it
//    REFUSES TO RUN if the eng subschema ever uses a keyword it does not
//    implement, instead of reporting a pass it cannot justify. Without that
//    refusal it would quietly become a rubber stamp the day someone writes
//    `oneOf`.
//
// ✓ [closed 2026-10-02] THE WHOLE DOCUMENT NOW VALIDATES, and the block below is
//   no longer the only schema authority here. This comment said the served document
//   does not validate because `paths.clerkStamps` is a declared {value,basis}
//   envelope where the schema said plain string, and named its own closing
//   condition: "one act that either widens schema.properties.paths to the
//   declared-string envelope or unwraps paths.clerkStamps in the served file — after
//   which this block can be widened to the whole document and assert ZERO
//   violations." c560b46 performed the first of those, and the whole-document check
//   plus a real Draft202012Validator now both report ZERO errors on the served
//   bytes. Codex flagged this paragraph as stale in the Key-Set-4 read; it had
//   outlived its condition by one commit, which is how a closing condition rots —
//   it is checked by whoever remembers it, and the act that met it was about
//   something else.

const SCHEMA_PATH = join(__dirname, "declarations.schema.json");
const committedSchema: any = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));
const ENG_SUBSCHEMA: any = committedSchema.properties.readers.properties.eng;
const DECLARED_NUMBER: any = committedSchema.$defs.declaredNumber;

/**
 * The only JSON Schema keywords the subset evaluator below implements.
 *
 * ⛔ THIS IS THE ONE LIST. The whole-schema KEYWORD CENSUS reads it rather than
 *    keeping its own copy, because a second list of what is supported is the
 *    exact seam this project has now paid for nine times: a producer, a
 *    hand-written projection carrying fewer entries, and a reader that needs one
 *    of the missing ones.
 *
 * ⚠ TEN KEYWORDS WERE ADDED ON 2026-10-02, AND THEY WERE ALREADY IN THE SCHEMA.
 *   `const`, `enum`, `exclusiveMinimum`, `exclusiveMaximum`, `minItems`,
 *   `uniqueItems`, `items`, `oneOf`, `minProperties` and `propertyNames` were all
 *   in use — `schemaVersion.const`, `logKind`'s enum, flatness's open interval,
 *   `stakes.lineClasses`, `pilot`'s oneOf, the event map's key rules — and this
 *   evaluator skipped every one of them in silence. The list said "the only
 *   keywords the evaluator implements" and was read as if it also said "the only
 *   keywords the schema uses". It never checked that, so every test validating
 *   through evalSchema was weaker than its name. The census now checks it.
 */
const SUPPORTED_KEYWORDS = new Set([
  "type",
  "properties",
  "patternProperties",
  "required",
  "additionalProperties",
  "minimum",
  "exclusiveMinimum",
  "exclusiveMaximum",
  // GATE 2 · Stop 2: `rhoCausal` lives in the CLOSED interval [0, 1].
  "maximum",
  "minLength",
  "pattern",
  "const",
  "enum",
  "minItems",
  "uniqueItems",
  "items",
  "minProperties",
  "propertyNames",
  "allOf",
  "oneOf",
  "$ref",
  "description",
]);

/** Every keyword appearing anywhere in a subschema, so an unimplemented one can REFUSE. */
function collectKeywords(node: unknown, out: Set<string>): void {
  if (Array.isArray(node)) {
    for (const n of node) collectKeywords(n, out);
    return;
  }
  if (typeof node !== "object" || node === null) return;
  for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
    out.add(k);
    if (k === "properties") {
      for (const sub of Object.values(v as Record<string, unknown>)) collectKeywords(sub, out);
    } else if (k === "allOf") {
      collectKeywords(v, out);
    }
    // Every other keyword here is a leaf (its value is not a subschema).
  }
}

// ⛔ EVERY `#/$defs/<name>`, NOT ONE. This resolved only `declaredNumber` and
//    THREW on anything else, which is why the whole-document check could not be
//    written: the first `#/$defs/declaredStringList` it met stopped it. Throwing
//    was the right instinct — it never guessed — but it bounded the evaluator to
//    the eng subtree, and the two drifts found on 2026-10-02 were in `paths` and
//    `readers.nodeResponse`. A checker that cannot reach a subtree cannot find a
//    fault there, and nothing says so out loud.
//
//    It still THROWS on a pointer shape it does not implement, rather than
//    returning an empty schema that would validate everything.
function resolveRef(ref: string): any {
  const m = /^#\/\$defs\/([A-Za-z0-9_]+)$/.exec(ref);
  if (m === null) {
    throw new Error(`this evaluator only implements #/$defs/<name> pointers, got: ${ref}`);
  }
  const def = (committedSchema.$defs ?? {})[m[1]];
  if (def === undefined) {
    throw new Error(`$ref names a definition the committed schema does not have: ${ref}`);
  }
  return def;
}

/**
 * A SUBSET of Draft 2020-12, enough for the eng subschema and no more. Returns
 * the violations it found; empty means valid. THROWS rather than guesses when it
 * meets a construct it does not implement.
 */
function evalSchema(schema: any, value: unknown, where: string): string[] {
  const out: string[] = [];
  // ⛔ A SCHEMA MAY BE A BOOLEAN, AND TREATING ONE AS AN EMPTY OBJECT SCHEMA IS A
  //    SILENT ACCEPT-ALL. Codex, Key-Set-4 read, gap 2: setting
  //    `stakes.lineClasses.items` to `false` makes a real Draft 2020-12 validator
  //    REJECT the served bytes ("Expected at most 0 items, but found 5") while this
  //    suite printed 171 passed / 1 failed, unchanged. `false.$ref` is undefined,
  //    `false.type` is undefined, every branch below was skipped, and the function
  //    returned "no violations" for the schema that admits NOTHING. The check added
  //    the day before specifically to catch the served bytes failing the schema was
  //    defeated by a two-letter value.
  if (schema === true) return out;
  if (schema === false) {
    out.push(`${where}: the schema here is \`false\` — NO value is valid, and this one was offered`);
    return out;
  }
  if (schema === null || typeof schema !== "object" || Array.isArray(schema)) {
    throw new Error(`a schema must be an object or a boolean; got ${JSON.stringify(schema)} at ${where}`);
  }
  if (schema.$ref !== undefined) out.push(...evalSchema(resolveRef(schema.$ref), value, where));
  if (Array.isArray(schema.allOf)) {
    for (const s of schema.allOf) out.push(...evalSchema(s, value, where));
  }
  // `pilot` is a oneOf: EXACTLY one branch, which is not "at least one". An
  // evaluator that skipped this accepted a pilot matching both branches or
  // neither — and the pilot block is where X9 lives.
  if (Array.isArray(schema.oneOf)) {
    const matching = schema.oneOf.filter((s: any) => evalSchema(s, value, `${where}<oneOf>`).length === 0);
    if (matching.length !== 1) {
      out.push(`${where}: must match EXACTLY ONE of ${String(schema.oneOf.length)} oneOf branches, matched ${String(matching.length)}`);
    }
  }
  if (Object.hasOwn(schema, "const") && JSON.stringify(value) !== JSON.stringify(schema.const)) {
    out.push(`${where}: must be the const ${JSON.stringify(schema.const)}, got ${JSON.stringify(value)}`);
  }
  if (Array.isArray(schema.enum) && !schema.enum.some((e: unknown) => JSON.stringify(e) === JSON.stringify(value))) {
    out.push(`${where}: must be one of ${JSON.stringify(schema.enum)}, got ${JSON.stringify(value)}`);
  }
  if (schema.type !== undefined) {
    const t = schema.type;
    let ok: boolean;
    switch (t) {
      case "object":
        ok = typeof value === "object" && value !== null && !Array.isArray(value);
        break;
      case "string":
        ok = typeof value === "string";
        break;
      case "boolean":
        ok = typeof value === "boolean";
        break;
      case "number":
        ok = typeof value === "number" && Number.isFinite(value);
        break;
      case "integer":
        ok = typeof value === "number" && Number.isInteger(value);
        break;
      // `stakes.lineClasses` and the string lists are arrays. Reaching this case
      // used to THROW, which is why no whole-document check existed: the
      // evaluator could not get past the first array in the served bytes.
      case "array":
        ok = Array.isArray(value);
        break;
      // GATE 2 · Stop 2: a class's `outcome` is `oneOf [null, word]` — null is
      // "any outcome of the kind", and it is a declared value, never an absence.
      case "null":
        ok = value === null;
        break;
      default:
        throw new Error(`this evaluator does not implement type "${String(t)}"`);
    }
    if (!ok) out.push(`${where}: type must be ${String(t)}, got ${JSON.stringify(value)}`);
  }
  if (typeof value === "number" && schema.minimum !== undefined && value < schema.minimum) {
    out.push(`${where}: must be >= ${String(schema.minimum)}, got ${JSON.stringify(value)}`);
  }
  // GATE 2 · Stop 2: INCLUSIVE, unlike the two below — rhoCausal = 1 is a legal coefficient.
  if (typeof value === "number" && schema.maximum !== undefined && value > schema.maximum) {
    out.push(`${where}: must be <= ${String(schema.maximum)}, got ${JSON.stringify(value)}`);
  }
  // EXCLUSIVE AT BOTH ENDS, and the distinction is load-bearing: flatness.amiFloor
  // lives in the OPEN interval (0,1) because 0 and 1 both read
  // CANNOT_ASSESS(OP3_FLATNESS_MALFORMED). Skipping these two keywords meant this
  // evaluator accepted exactly the two values the instrument cannot use.
  if (typeof value === "number" && schema.exclusiveMinimum !== undefined && !(value > schema.exclusiveMinimum)) {
    out.push(`${where}: must be > ${String(schema.exclusiveMinimum)}, got ${JSON.stringify(value)}`);
  }
  if (typeof value === "number" && schema.exclusiveMaximum !== undefined && !(value < schema.exclusiveMaximum)) {
    out.push(`${where}: must be < ${String(schema.exclusiveMaximum)}, got ${JSON.stringify(value)}`);
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      out.push(`${where}: must have at least ${String(schema.minItems)} item(s), got ${String(value.length)}`);
    }
    if (schema.uniqueItems === true) {
      const seenItems = new Set(value.map((v) => JSON.stringify(v)));
      if (seenItems.size !== value.length) out.push(`${where}: items must be unique`);
    }
    if (schema.items !== undefined) {
      value.forEach((v, i) => out.push(...evalSchema(schema.items, v, `${where}[${String(i)}]`)));
    }
  }
  if (typeof value === "string" && schema.minLength !== undefined && value.length < schema.minLength) {
    out.push(`${where}: shorter than minLength ${String(schema.minLength)}`);
  }
  if (typeof value === "string" && typeof schema.pattern === "string" && !new RegExp(schema.pattern, "u").test(value)) {
    out.push(`${where}: does not match pattern ${schema.pattern}`);
  }
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    const o = value as Record<string, unknown>;
    // ⛔ `Object.hasOwn`, NEVER `in` — AND THIS WAS A REAL DEFECT, NOT A
    //    PRECAUTION. Codex, Key-Set-2 read, mutation B: appending "toString" to
    //    `readers.eng.required` made a real Draft 2020-12 validator REJECT the
    //    served Eng object, while all four parity checks printed PASS and the
    //    census did not move. `"toString" in {}` is TRUE, so every inherited
    //    Object.prototype name masqueraded as an own key — `required` was
    //    satisfied by the prototype chain, `additionalProperties` excused any
    //    property whose name happens to live on it, and the descent loop would
    //    have walked into `Object.prototype.toString` as if it were data.
    //    A subset evaluator that disagrees with a real validator on object
    //    semantics is not a narrower checker; it is a different one.
    if (Array.isArray(schema.required)) {
      for (const k of schema.required) {
        if (!Object.hasOwn(o, String(k))) out.push(`${where}: required key "${String(k)}" is missing`);
      }
    }
    // The event map declares BOTH that it is non-empty and what a key may look
    // like. Skipping these let an empty map, and a key of any shape, validate.
    if (schema.minProperties !== undefined && Object.keys(o).length < schema.minProperties) {
      out.push(`${where}: must have at least ${String(schema.minProperties)} propert(y|ies), got ${String(Object.keys(o).length)}`);
    }
    if (schema.propertyNames !== undefined) {
      for (const k of Object.keys(o)) {
        out.push(...evalSchema(schema.propertyNames, k, `${where}: property name ${JSON.stringify(k)}`));
      }
    }
    const props: Record<string, any> = schema.properties ?? {};
    // ⛔ patternProperties IS IMPLEMENTED, NOT IGNORED, and that is the point.
    //    `paths` carries `"^(?!(clerkStamps|witnessIntake|witnessBook)$).*$"`: the eight required paths are
    //    PLAIN STRINGS under one root, and the three envelopes (clerkStamps, the two witness paths) are excluded.
    //    An evaluator that skipped this keyword would have accepted an envelope
    //    in any of the eight and a bare string in the ninth — it would agree
    //    with a real validator on the documents at hand and disagree on the
    //    mutations, which is the worst of the two. See the KEYWORD CENSUS below:
    //    no keyword reaches this evaluator unimplemented and unnamed.
    const patternProps: Record<string, any> = schema.patternProperties ?? {};
    const matchesAPattern = (k: string): boolean =>
      Object.keys(patternProps).some((re) => new RegExp(re, "u").test(k));
    if (schema.additionalProperties === false) {
      for (const k of Object.keys(o)) {
        if (!Object.hasOwn(props, k) && !matchesAPattern(k)) {
          out.push(`${where}: additional property "${k}" is not allowed`);
        }
      }
    } else if (schema.additionalProperties !== undefined) {
      // ⛔ A SCHEMA, NOT A BOOLEAN — `$defs.declaredEventMap.properties.value` is
      //    a MAP whose every value must be a non-empty array of non-empty strings,
      //    and that is the whole shape of an event map. The throw above found this
      //    the moment the whole-document check first reached the served bytes,
      //    which is what a loud refusal is for: the KEYWORD CENSUS counts keyword
      //    NAMES and cannot see that a keyword's VALUE is a form it does not
      //    implement. The census is the first net and the throw is the second.
      if (typeof schema.additionalProperties !== "object" || schema.additionalProperties === null) {
        throw new Error(`this evaluator implements additionalProperties as false or a schema, got ${JSON.stringify(schema.additionalProperties)}`);
      }
      for (const k of Object.keys(o)) {
        if (!Object.hasOwn(props, k) && !matchesAPattern(k)) {
          out.push(...evalSchema(schema.additionalProperties, o[k], `${where}.${k}`));
        }
      }
    }
    for (const [k, sub] of Object.entries(props)) {
      if (Object.hasOwn(o, k)) out.push(...evalSchema(sub, o[k], `${where}.${k}`));
    }
    for (const [re, sub] of Object.entries(patternProps)) {
      const rx = new RegExp(re, "u");
      for (const k of Object.keys(o)) {
        if (rx.test(k)) out.push(...evalSchema(sub, o[k], `${where}.${k}`));
      }
    }
  }
  return out;
}

/**
 * The loader's OWN eng allow-list, asked of the loader.
 *
 * ⛔ NOT A TEXT SCAN OF declarations.ts. This repository documents its own
 *    defects inside the files that had them, so a grep for a key name matches
 *    the prose ABOUT the key — three such misfires were booked on 2026-10-01
 *    alone. So the loader is handed a key that cannot be real, and the
 *    allow-list is read out of its own refusal message.
 */
function engAllowListFromLoader(): readonly string[] {
  const d = clone();
  d.readers.eng["probe-key-that-is-not-a-declaration"] = {
    value: 1,
    basis: BASIS_FIXTURE,
    proxy: true,
  };
  try {
    validateDeclarations(d);
  } catch (err) {
    if (err instanceof DeclarationRejected) {
      const m = /accepted here: (.+)$/.exec(err.message);
      if (m === null) {
        throw new Error(
          `readers.eng was refused, but the refusal no longer enumerates its allow-list, ` +
            `so this probe cannot read it: ${err.message}`
        );
      }
      return m[1]
        .split(",")
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
    }
    throw err;
  }
  throw new Error(
    "the loader ACCEPTED an impossible readers.eng key — checkNoUnknown(engRaw, [...]) is no " +
      "longer guarding this block, which is a larger finding than any parity mismatch"
  );
}

// ── KEYWORD CENSUS: THE EVALUATOR MAY NOT SILENTLY UNDER-CHECK ───────────────
//
// ⛔ WHY. `evalSchema` is a SUBSET evaluator. A subset is honest only while every
//    keyword it does not implement is one the schema does not use. The moment the
//    schema grows a keyword the evaluator skips, every test that validates
//    through the evaluator gets quietly weaker, PRINTS PASS, and the census of
//    checks does not move — which is the exact shape Codex's three mutations
//    exploited from the other side.
//
//    So the keywords are COUNTED FROM THE SCHEMA ITSELF and compared against two
//    hand-kept lists: the ones the evaluator ENFORCES, and the ones that are
//    INERT BY DECLARATION with the reason written down. Anything else fails here,
//    naming the keyword and where it appeared. A new keyword cannot be added to
//    the schema without either teaching the evaluator or writing the reason.
check("KEYWORD CENSUS: every keyword in the committed schema is enforced by the evaluator or declared inert", () => {
  const ENFORCED = [...SUPPORTED_KEYWORDS].filter((k) => k !== "description");
  // Inert, each with the reason it is safe to skip. These are NOT "unsupported";
  // they are keywords whose omission cannot make a valid document read as invalid
  // or an invalid one as valid FOR THE DOCUMENTS THIS SUITE EVALUATES.
  const INERT: Record<string, string> = {
    $schema: "dialect declaration, not a constraint",
    $id: "identity, not a constraint",
    $defs: "a container; its members are reached through $ref and evaluated there",
    title: "prose",
    description: "prose — and the schema leans on it heavily, deliberately",
    examples: "prose",
    $comment: "prose",
  };
  const seen = new Map<string, string>();
  const walkKeywords = (n: any, where: string): void => {
    if (Array.isArray(n)) {
      n.forEach((x, i) => walkKeywords(x, `${where}[${i}]`));
      return;
    }
    if (n === null || typeof n !== "object") return;
    for (const k of Object.keys(n)) {
      if (!seen.has(k)) seen.set(k, `${where}.${k}`);
      // Descend only where a SCHEMA lives, never into a property-NAME map's keys
      // as if they were keywords — `properties.pattern` is a field called
      // "pattern", not the keyword.
      if (k === "properties" || k === "patternProperties" || k === "$defs") {
        for (const [name, sub] of Object.entries(n[k] as Record<string, any>)) {
          walkKeywords(sub, `${where}.${k}.${name}`);
        }
      } else if (k === "allOf" || k === "anyOf" || k === "oneOf" || k === "items") {
        walkKeywords(n[k], `${where}.${k}`);
      }
    }
  };
  walkKeywords(committedSchema, "$");
  const unaccounted = [...seen.entries()]
    .filter(([k]) => !ENFORCED.includes(k) && !Object.hasOwn(INERT, k))
    .map(([k, w]) => `${k} (first at ${w})`);
  assert(
    unaccounted.length === 0,
    `the committed schema uses ${unaccounted.length} keyword(s) the evaluator neither enforces ` +
      `nor declares inert — every test that validates through evalSchema is weaker than it reads:\n    ` +
      unaccounted.join("\n    ")
  );
  // And the enforced list must not rot into a wish: each one must actually appear
  // in the schema, or it is a claim about a keyword nobody uses.
  const unused = ENFORCED.filter((k) => !seen.has(k));
  assert(
    unused.length === 0,
    `the ENFORCED list names keyword(s) the committed schema does not use: ${JSON.stringify(unused)}. ` +
      `A list that outruns the schema reads as coverage and is not.`
  );
});

// ── THE SERVED BYTES, WHOLE, AGAINST THE COMMITTED SCHEMA ────────────────────
//
// ⛔ THE CHECK WHOSE ABSENCE LET THE clerkStamps DRIFT LIVE FOR FOUR DAYS. There
//    was a check that the served `readers.eng` satisfies the schema. There was
//    none that the served DOCUMENT does. The drift was in `paths`.
//
//    Measured 2026-10-02 with jsonschema 4.10.3 / Draft202012Validator against
//    the schema BEFORE this commit: exactly one error, at `paths/clerkStamps`,
//    for the live file at /opt and for the committed one alike. A real validator
//    was available on this box the whole time; an earlier commit message of mine
//    said no real Draft 2020-12 implementation existed here, and that was wrong.
check("THE SERVED DOCUMENT, WHOLE, satisfies the committed schema — not one subtree of it", () => {
  const errs = evalSchema(committedSchema, shipped, "$");
  assert(errs.length === 0, `the served declaration violates the committed schema:\n    ${errs.join("\n    ")}`);
});

// ── A REAL DRAFT 2020-12 VALIDATOR, IN THIS TEST, ON THE SERVED BYTES ────────
//
// ⛔ WHY THIS EXISTS AND WHY IT IS NOT OPTIONAL. `evalSchema` below is a SUBSET
//    evaluator, and the Key-Set-3 commit message justified hand-rolling it with
//    the claim that "no real Draft 2020-12 implementation exists in this
//    repository". THAT CLAIM WAS FALSE: `python3 -c "import jsonschema"` is 4.10.3
//    on this box and `Draft202012Validator` works. It is what found
//    `paths/clerkStamps`, and Codex's second Key-Set-4 gap — `items: false` — is a
//    case where the subset evaluator said "valid" and the real one said
//    "Expected at most 0 items, but found 5" ON THE SERVED BYTES.
//
//    So the real validator is now a check rather than a tool I reached for once.
//
// ⚠ IT FAILS LOUD IF THE LIBRARY IS ABSENT, AND DOES NOT SKIP. A check that
//   quietly does nothing when its dependency is missing is the fail-open shape
//   this file punishes everywhere else; the message names exactly what to install.
//
// AND IT ASSERTS THE TWO EVALUATORS AGREE. Either one alone can be fooled; a
// disagreement between them is the signal, and it is what catches a construct the
// subset does not implement but silently tolerates.
function realValidatorErrors(docPath: string): { ok: boolean; errors: string[]; detail: string } {
  const script = [
    "import json,sys",
    "from jsonschema import Draft202012Validator",
    "sch=json.load(open(sys.argv[1])); doc=json.load(open(sys.argv[2]))",
    "Draft202012Validator.check_schema(sch)",
    "es=sorted(Draft202012Validator(sch).iter_errors(doc), key=lambda e: list(e.absolute_path))",
    "print(json.dumps([{'at':'/'.join(str(x) for x in e.absolute_path) or '(root)','msg':e.message[:200]} for e in es]))",
  ].join("\n");
  try {
    const out = execFileSync("python3", ["-c", script, SCHEMA_PATH, docPath], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const parsed = JSON.parse(out.trim()) as { at: string; msg: string }[];
    return { ok: true, errors: parsed.map((e) => `${e.at}: ${e.msg}`), detail: "" };
  } catch (err) {
    const e = err as { stderr?: Buffer | string; message?: string };
    return { ok: false, errors: [], detail: String(e.stderr ?? e.message ?? err).slice(0, 400) };
  }
}

check("REAL Draft 2020-12 VALIDATOR: the committed schema is a valid schema, and the SERVED bytes satisfy it", () => {
  const r = realValidatorErrors(SHIPPED_PATH);
  assert(
    r.ok,
    `could not run a real Draft 2020-12 validator, and this check does NOT skip. ` +
      `It needs python3 with jsonschema (4.10.3 is what this box has): ` +
      `python3 -c "from jsonschema import Draft202012Validator". Detail: ${r.detail}`
  );
  assert(
    r.errors.length === 0,
    `a REAL Draft 2020-12 validator rejects the SERVED declaration against the committed schema:\n    ` +
      r.errors.join("\n    ")
  );
});

check("REAL vs SUBSET: the two evaluators agree on the served bytes and on the fixture — a disagreement is the finding", () => {
  for (const [label, path, doc] of [["served", SHIPPED_PATH, shipped], ["fixture", FIXTURE_PATH_FOR_REAL, draft]] as const) {
    const real = realValidatorErrors(path);
    assert(real.ok, `the real validator could not run for the ${label} document: ${real.detail}`);
    const subset = evalSchema(committedSchema, doc, "$");
    assert(
      (real.errors.length === 0) === (subset.length === 0),
      `the REAL validator and the SUBSET evaluator DISAGREE on the ${label} document, which means ` +
        `evalSchema is tolerating a construct it does not implement:\n    real (${String(real.errors.length)}): ` +
        `${real.errors.join("; ") || "(none)"}\n    subset (${String(subset.length)}): ${subset.join("; ") || "(none)"}`
    );
    assert(
      real.errors.length === 0,
      `the ${label} document violates the committed schema (real validator):\n    ${real.errors.join("\n    ")}`
    );
  }
});

check("BOOLEAN SCHEMAS are a schema, pinned: `false` admits nothing and `true` admits anything", () => {
  // Pinned because the fix for Codex's gap 2 is four lines and a refactor could
  // revert it without any other check moving.
  assert(evalSchema(false, 1, "$").length === 1, "evalSchema(false, …) must report a violation");
  assert(evalSchema(false, undefined, "$").length === 1, "evalSchema(false, …) must refuse even undefined");
  assert(evalSchema(true, 1, "$").length === 0, "evalSchema(true, …) must report none");
  let threw = false;
  try {
    evalSchema(42 as never, 1, "$");
  } catch {
    threw = true;
  }
  assert(threw, "a schema that is neither an object nor a boolean must THROW, not be treated as empty");
});

// ── GENERIC SCHEMA ⇄ LOADER PARITY, EVERY CLOSED OBJECT, BOTH DIRECTIONS ─────
//
// ⛔ WHY THIS REPLACES THE BOUNDED CHECKS AS THE LOAD-BEARING ONE. Codex found a
//    THIRD schema-only drift (read 3, F1): add an optional `note` to
//    `$defs.declaredNumber.properties` and the schema accepts an envelope the
//    loader REFUSES — `readers.eng.minimumClassCoverage.note: unknown field;
//    accepted here: value, basis, proxy`. The four T11/F1 checks passed, because
//    they look at ONE subtree. Three mutations, three times a bounded check did
//    not see past its own scope. The answer is not a fourth bounded check.
//
// WHAT THIS DOES: walks the committed schema for EVERY node that is a closed
// object (`additionalProperties: false` with a `properties` map), derives a
// CONCRETE path into a real declaration for each, and compares the schema's
// property set with THE LOADER'S OWN ACCEPTED SET — obtained by injecting an
// unknown key there and parsing the loader's refusal, which says
// `accepted here: a, b, c`. Both directions are reported: a key the schema
// admits and the loader refuses, and a key the loader admits and the schema
// forbids.
//
// ⚠ THE REFUSAL'S FIELD PATH IS ASSERTED, NOT ASSUMED. The loader may refuse for
//   a different reason before reaching the probed node, and a set parsed from the
//   wrong refusal would be compared against the wrong schema node — the
//   mis-attribution this project keeps paying for. If the refusal does not name
//   the path we probed, the node is recorded UNPROBED rather than compared.
//
// ⚠ AND UNPROBED NODES ARE NAMED, NOT SKIPPED. A node whose concrete path does
//   not exist in the fixture (an empty array, an undeclared optional block) is
//   listed in the failure message. A silent skip is how a generic check becomes a
//   bounded one again without anybody editing it.
// ── THE ENUMERATED DRIFT, pinned so a silent fix fails loudly ───────────────
//
// Board ruling 2026-10-03 05:27Z: the parity line stops; the enumerated
// schema/loader disagreements are ASSERTED. Each row below was measured this
// tick on BOTH committed documents, with a real Draft202012Validator on the
// schema side and the runtime loader on the other.
//
// ⛔ THE RATCHET RUNS THE OTHER WAY FROM EVERY OTHER CHECK HERE. These assert
//    that a drift IS STILL PRESENT. If one is fixed, this FAILS — on purpose:
//    the fix is welcome and the enumeration must not quietly go stale behind it.
//    A list of known faults nobody updates is how a known fault becomes an
//    unknown one.
interface DriftRow {
  readonly field: string;
  readonly apply: (doc: Record<string, any>) => void;
  readonly loaderField: string;
  readonly why: string;
}
const ENUMERATED_DRIFT: readonly DriftRow[] = [
  {
    field: "paths.probeKey",
    apply: (d) => {
      d.paths = { ...(d.paths as Record<string, unknown>), probeKey: "/var/lib/mica-bridge/probe.jsonl" };
    },
    loaderField: "paths.probeKey",
    why:
      "`paths.patternProperties` admits any name matching ^(?!(clerkStamps|witnessIntake|witnessBook)$).*$ with a " +
      "/var/lib/mica-bridge/… value; the loader has a FIXED nine-key set. Codex, Key-Set-6.",
  },
  {
    field: "paths.zz",
    apply: (d) => {
      d.paths = { ...(d.paths as Record<string, unknown>), zz: "/var/lib/mica-bridge/zz.jsonl" };
    },
    loaderField: "paths.zz",
    why: "the same drift under a second name — it is a KEY SPACE, not one key.",
  },
];

check("ENUMERATED DRIFT: each known schema/loader disagreement is still exactly as recorded", () => {
  const tmp = mkdtempSync(join(tmpdir(), "ks6-drift-"));
  for (const row of ENUMERATED_DRIFT) {
    for (const basePath of [FIXTURE_PATH_FOR_REAL, SHIPPED_PATH]) {
      const doc = JSON.parse(readFileSync(basePath, "utf8")) as Record<string, any>;
      row.apply(doc);
      const docPath = join(tmp, "doc.json");
      writeFileSync(docPath, JSON.stringify(doc), "utf8");

      // ── the SCHEMA side, by TWO witnesses, and the second one is not optional.
      //
      // ⛔ `realValidatorErrors` shells to python3 and that child READS THE SCHEMA
      //    FROM DISK, so an in-memory schema mutation cannot reach it — which
      //    means the differential that proves this ratchet bites could not reach
      //    it either. Found by running that differential: deleting
      //    `paths.patternProperties` in memory left this check PASSING and only
      //    the keyword census noticed. The subset evaluator reads the schema this
      //    test holds, so it closes the hole. The real validator remains the
      //    authority on the COMMITTED bytes; the subset is the authority on
      //    whatever schema this run is actually reasoning about.
      const r = realValidatorErrors(docPath);
      assert(r.ok, `the real validator could not run: ${r.detail}`);
      const subsetErrs = evalSchema(committedSchema, doc, "$");
      for (const [who, errs] of [["a real Draft202012Validator", r.errors], ["the subset evaluator", subsetErrs]] as const) {
        assert(
          errs.length === 0,
          `${row.field}: ${who} now REJECTS it on ${basePath}, so this drift is GONE. ` +
            `That is good news and this list is now stale — remove the row in the same commit. ` +
            `Errors: ${errs.join(" | ")}`
        );
      }

      // the LOADER side, by the runtime loader itself
      let refusedAt: string | null = null;
      try {
        validateDeclarations(doc as never);
      } catch (err) {
        if (!(err instanceof DeclarationRejected)) throw err;
        refusedAt = String((err as unknown as { field?: string }).field ?? "");
      }
      assert(
        refusedAt !== null,
        `${row.field}: the LOADER now ACCEPTS it on ${basePath}, so schema and loader AGREE here ` +
          `and this drift is closed. Remove the row in the same commit. (${row.why})`
      );
      assert(
        refusedAt === row.loaderField,
        `${row.field}: the loader refused, but at ${JSON.stringify(refusedAt)} rather than ` +
          `${JSON.stringify(row.loaderField)} — the drift moved, which is a different finding.`
      );
    }
  }
  rmSync(tmp, { recursive: true, force: true });
  console.log(
    `      (${String(ENUMERATED_DRIFT.length)} enumerated drift row(s) × 2 documents, all still present)`
  );
});

check(
  "KNOWN-DRIFT: the CLOSED-OBJECT subset agrees, and the enumerated schema/loader disagreements are pinned",
  () => {
    // ⛔ THIS CHECK NO LONGER CLAIMS TO BE GENERIC, BY RULING (board 2026-10-03
    //    05:27Z), AND THE WORD IS WITHDRAWN RATHER THAN SOFTENED.
    //
    //    Four rounds of Codex cold reads, four misses. The fourth is the one that
    //    settles it: `paths` carries BOTH a nine-key `properties` block AND
    //    `patternProperties: {"^(?!clerkStamps$).*$": {type:"string", pattern:
    //    "^/var/lib/mica-bridge/…"}}`. So the schema admits `paths.probeKey`,
    //    `paths.zz`, and every other name the pattern matches, while THE LOADER
    //    HAS A FIXED NINE-KEY SET and refuses each one by name. Measured this run
    //    on BOTH documents: a real Draft202012Validator reports 0 errors and the
    //    loader answers `DECLARATION_REJECTED paths.probeKey: unknown field;
    //    accepted here: journal, eventBook, …`.
    //
    //    THE WALK CANNOT SEE IT, AND NO AMOUNT OF WALKING WILL. It compares the
    //    `properties` key set of each CLOSED OBJECT. A drift that lives in a
    //    pattern-admitted KEY SPACE is not a closed object's property set at all,
    //    so there is no node to compare — and `{type:"string"}` is not closed, so
    //    nothing is even enumerated. ⚠ The witness name `probeKey` came from this
    //    file's own `concretise()` pool: the repair that descended
    //    patternProperties supplied the key that exposes what it did not close.
    //
    //    WHAT THIS CHECK ESTABLISHES, exactly: the closed-object SUBSET of the
    //    schema agrees with the loader at the paths it reaches, that subset's
    //    membership is pinned as a SET, and the known disagreements OUTSIDE it are
    //    enumerated below so a silent fix fails loudly.
    //
    //    WHAT IT DOES NOT: parity. True parity needs ONE source — the schema
    //    generated from the loader's accepted set — which is a design change with
    //    its own ticket, not a test. `[owed]`
    type Node = { schemaPath: string; props: string[]; at: (string | number)[]; schema: any };
    const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8")) as Record<string, any>;
    const nodes: Node[] = [];
    const defSites = new Map<string, (string | number)[]>();
    const booleanPositions: string[] = [];

    // ⛔ APPLICATOR BRANCHES ARE WALKED, AND BEFORE THIS THEY WERE NOT. Codex,
    //    Key-Set-4 read, gap 1: `$.properties.pilot` has NO `properties` and NO
    //    `additionalProperties` — it is `{ oneOf: [branch, branch] }`, and BOTH
    //    branches are closed objects. The old walk descended only `properties` and
    //    `items`, so it recorded NOTHING for pilot: the two closed nodes were not
    //    probed and were not even listed as unprobed, because they were never
    //    found. Adding an optional key to `pilot.oneOf[1].properties` makes the
    //    schema admit `pilot.note` while the loader refuses it
    //    (`DECLARATION_REJECTED pilot.note: unknown field; accepted here: active`)
    //    and the suite printed 171/1, unchanged.
    //
    //    ⚠ AND THE BLIND SPOT WAS THE PILOT BLOCK, WHICH IS WHERE X9 LIVES. Of all
    //      the places for the parity walk to have a hole, it had it in the one the
    //      arbiter reserves to his own hand.
    //
    //    A branch constrains the SAME instance location as its parent, so `at` does
    //    not grow — only the schema path does.
    const APPLICATORS = ["allOf", "oneOf", "anyOf"] as const;
    const unconcretisable: string[] = [];
    /**
     * A concrete instance key that the pattern admits, or null.
     *
     * Literal-with-anchors first (`^__hidden__$` → `__hidden__`), then a small
     * pool tried against the real RegExp. The pool is deliberately short: a
     * pattern none of it matches is a REPORTED hole, not a silent pass.
     */
    const concretise = (pattern: string): string | null => {
      const bare = pattern.replace(/^\^/, "").replace(/\$$/, "");
      if (/^[A-Za-z0-9_.\-]+$/.test(bare)) return bare;
      let re: RegExp;
      try {
        re = new RegExp(pattern);
      } catch {
        return null;
      }
      for (const cand of ["x", "a", "probeKey", "__probe__", "journal", "zz", "0"]) {
        if (re.test(cand)) return cand;
      }
      return null;
    };
    const walk = (n: any, schemaPath: string, at: (string | number)[]): void => {
      if (n === true || n === false) { booleanPositions.push(`${schemaPath} = ${String(n)}`); return; }
      if (n === null || typeof n !== "object") return;
      if (typeof n.$ref === "string") {
        if (!defSites.has(n.$ref)) defSites.set(n.$ref, at);
        return;
      }
      if (n.additionalProperties === false && n.properties && typeof n.properties === "object") {
        nodes.push({ schemaPath, props: Object.keys(n.properties).sort(), at, schema: n });
      }
      if (n.properties && typeof n.properties === "object") {
        for (const [k, v] of Object.entries(n.properties)) walk(v, `${schemaPath}.properties.${k}`, [...at, k]);
      }
      // ⛔ patternProperties IS DESCENDED, AND BEFORE THIS IT WAS NOT. Codex,
      //    Key-Set-5 read, F1: `patternProperties` is in SUPPORTED_KEYWORDS and the
      //    evaluator enforces it, but the GENERIC WALK descended only `properties`.
      //    A closed object reachable only through a pattern was therefore never
      //    found, so it was neither probed nor named unprobed, and the exact count
      //    stayed at 29 while the schema had 30. Reproduced in memory: adding
      //    `readers.patternProperties["^__hidden__$"]` as a closed object makes the
      //    schema admit `readers.__hidden__ = {value:"x"}` while the loader refuses
      //    the key, and the whole suite printed its unchanged 174/1.
      //
      //    The instance key must be CONCRETE to be probed, so the pattern is
      //    concretised. A pattern that cannot be concretised is named UNPROBED
      //    rather than skipped: "I could not build a key for this" and "there is
      //    nothing here" are different statements and only one of them is safe.
      if (n.patternProperties && typeof n.patternProperties === "object") {
        for (const [pat, v] of Object.entries(n.patternProperties)) {
          const key = concretise(pat);
          if (key === null) {
            unconcretisable.push(`${schemaPath}.patternProperties[${pat}]`);
            continue;
          }
          walk(v, `${schemaPath}.patternProperties[${pat}]`, [...at, key]);
        }
      }
      // `"items" in n`, NOT `n.items` — `items: false` is falsy and was skipped.
      if ("items" in n) walk(n.items, `${schemaPath}.items`, [...at, 0]);
      if ("additionalProperties" in n && typeof n.additionalProperties === "object") {
        walk(n.additionalProperties, `${schemaPath}.additionalProperties`, at);
      }
      for (const kw of APPLICATORS) {
        if (Array.isArray(n[kw])) {
          n[kw].forEach((b: any, i: number) => walk(b, `${schemaPath}.${kw}[${String(i)}]`, at));
        }
      }
    };
    walk(schema, "$", []);
    // `$defs` are only reachable through a $ref, so each one is probed at its
    // first concrete site — recorded during the walk above.
    // ⛔ AND THE $defs ARE RUN THROUGH `walk`, NOT HAND-ROLLED TWO LEVELS DEEP.
    //    The previous version pushed the def itself and one level into its
    //    `properties`, which reaches every closed node the schema has TODAY and
    //    would miss one three levels in. That is a latent hole rather than a live
    //    drift — but "it happens not to matter yet" is the argument this suite
    //    exists to refuse, and the fix is smaller than the paragraph defending it.
    //    `walk` descends properties, patternProperties, items, additionalProperties
    //    and the applicators uniformly, so a def gets the same reach as the root.
    //    The pinned path set is UNCHANGED by this, which is the evidence that it is
    //    a reach fix and not a behaviour change.
    for (const [name, def] of Object.entries((schema.$defs ?? {}) as Record<string, any>)) {
      const site = defSites.get(`#/$defs/${name}`);
      walk(def, `$.$defs.${name}`, site ?? ["__NO_SITE__"]);
    }

    const PROBE = "__generic_parity_probe__";
    const unprobed: string[] = [];
    const schemaWider: string[] = [];
    const loaderWider: string[] = [];

    // ⛔ TWO BASES, AND THE SECOND ONE IS WHY THIS CHECK EXISTS AT ALL. The first
    //    run of this walk probed the FIXTURE only and found the schema forbidding
    //    `paths.clerkStamps` while the loader accepted it — a key THE BOX
    //    DECLARES and the fixture does not. Every schema test here validates the
    //    fixture, so the fixture's narrowness WAS the blind spot. Probing the
    //    served bytes as well means a node reachable in what actually serves is
    //    never reported unprobed because the fixture happens to omit it.
    //    The pilot is neutralised in both: an active pilot is an X9 question, not
    //    a key-set one, and it would refuse the load before any probe is read.
    //
    // ⛔ AND A THIRD BASE, BECAUSE TWO OF THEM FORCE THE PILOT INACTIVE. `clone()`
    //    sets `pilot = {active:false}` and the served base copied that, so BOTH
    //    bases satisfied only `pilot.oneOf[0]` and the ACTIVE branch had no instance
    //    to be probed against at all. The loader's accepted set at `pilot` is
    //    BRANCH-DEPENDENT — measured: `[active]` when inactive, `[active, sessionId,
    //    expiresAt, holdAtOrAbove]` when active — so one base can only ever check
    //    one of the two branches, and a walk that found both nodes would still have
    //    compared one of them against the wrong set.
    const bases: { name: string; doc: Record<string, any> }[] = [
      { name: "fixture", doc: clone() },
      { name: "served", doc: { ...(JSON.parse(JSON.stringify(shipped)) as Record<string, any>), pilot: { active: false } } },
      { name: "fixture/pilot-active", doc: JSON.parse(JSON.stringify(draft)) as Record<string, any> },
      // ⛔ P5 · A FOURTH BASE, FOR THE SAME REASON THE SECOND ONE EXISTS. T26 adds
      //    `readers.gate4Sunset` to the schema, and NO base declares it — the
      //    block is not served and will not be until S24 — so six newly closed
      //    nodes were reachable by the path walk and UNPROBED by the comparison.
      //    The test's own lesson, one block further on: "every schema test here
      //    validates the fixture, so the fixture's narrowness WAS the blind spot."
      //
      // ⚠ AND IT IS A BASE RATHER THAN A FIXTURE EDIT ON PURPOSE. The fixture is
      //   asserted elsewhere to MIRROR what serves; adding a block that does not
      //   serve would make that assertion false to buy this one. A probe base is
      //   the test's own object, says so in its name, and reaches the nodes.
      {
        name: "fixture+gate4Sunset (probe base: the block is not served)",
        doc: ((): Record<string, any> => {
          const d = clone() as Record<string, any>;
          const cls = (moduleId: string, eventType: string) => ({
            value: [{ moduleId, eventType }],
            basis: "PROBE BASE, not a declaration. Reaches T26's closed nodes so the walk can compare them.",
            proxy: true,
          });
          // R1 · the block carries NO class lists: the reader is ON and for which
          // SUBJECT. `to-wire-options` builds the profile from mica-service's own
          // sunset-kind constants, so there is nothing here to mistype.
          d.readers.gate4Sunset = {
            subject: {
              value: "housekeeper",
              basis: "PROBE BASE, not a declaration. Reaches T26's closed node so the walk can compare it.",
              proxy: false,
            },
          };
          return d;
        })(),
      },
      // ⛔ GATE 1 · Stop 2 · A FIFTH BASE, the fourth one's reason again: `frame`
      //    and `readers.gate1Scope` are declared by no served document and no
      //    fixture, so their six closed nodes would be FOUND by the walk and
      //    compared against nothing.
      //
      // ⚠ THE SUBJECT ID IS THE WALK'S OWN CHOICE, NOT A NAME TYPED HERE. `frame`
      //   is keyed by subject id through `patternProperties`, and the walk probes
      //   a pattern at the key `concretise()` builds for it. A base keyed by any
      //   other name would leave every frame node "no object at [frame, <key>]"
      //   — so the base asks the same function for the key and declares a
      //   subject of that name. If the concretiser's pool changes, this follows.
      {
        name: "fixture+frame+gate1Scope (probe base: neither block is served)",
        doc: ((): Record<string, any> => {
          const framePatterns = Object.keys(schema.properties?.frame?.patternProperties ?? {});
          const key = framePatterns.length === 1 ? concretise(framePatterns[0]) : null;
          if (key === null) {
            throw new Error(
              `the frame probe base needs exactly one concretisable frame pattern, found ${JSON.stringify(framePatterns)}`
            );
          }
          return g1Declared(key);
        })(),
      },
      // ⛔ GATE 2 · Stop 2 · A SIXTH BASE, the fifth one's reason again: `baskets`
      //    and `readers.gate2Direction` are declared by no served document and no
      //    fixture. The basket is the RICH one — a value class, and an unknown with
      //    a magnitude, first in their lists — because the shared class defs are
      //    probed at their FIRST site (value[0], unknown[0]) and an empty list has
      //    no object there. damage[] stays empty: R8 refuses every damage class
      //    today, and the signed def it shares with value[] is probed at value[0].
      {
        name: "fixture+frame+gate1Scope+gate2Direction+baskets (probe base: none of them is served)",
        doc: ((): Record<string, any> => {
          const basketPatterns = Object.keys(schema.properties?.baskets?.patternProperties ?? {});
          const framePatterns = Object.keys(schema.properties?.frame?.patternProperties ?? {});
          const key = basketPatterns.length === 1 ? concretise(basketPatterns[0]) : null;
          const fkey = framePatterns.length === 1 ? concretise(framePatterns[0]) : null;
          if (key === null || key !== fkey) {
            throw new Error(
              `the basket probe base needs ONE concretisable basket pattern whose key the frame pattern also builds, ` +
                `found baskets ${JSON.stringify(basketPatterns)} -> ${String(key)}, frame -> ${String(fkey)}`
            );
          }
          return g2Declared(key, g2RichBasket());
        })(),
      },
      // TIER 1 · A PROBE BASE FOR THE WITNESS'S FOUR CLOSED NODES (paths.witnessIntake,
      //    paths.witnessBook, readers.gate2Direction.book / .witnessMethod): no
      //    served declaration declares them yet, so no other base reaches them.
      {
        name: "fixture+…+gate2Direction on the WITNESS'S BOOK (probe base: Tier 1, not served)",
        doc: ((): Record<string, any> => {
          const basketPatterns = Object.keys(schema.properties?.baskets?.patternProperties ?? {});
          const key: string = (basketPatterns.length === 1 ? concretise(basketPatterns[0]) : null) ?? "subject-a";
          const d = g2Declared(key) as Record<string, any>;
          const basis =
            "PROBE BASE, not a declaration. Reaches the witness's closed nodes so the walk can compare them; " +
            "the bridge drops into and reads only these paths.";
          d.paths.witnessIntake = { value: "/var/lib/mica/witness-sight/intake", basis };
          d.paths.witnessBook = { value: "/var/lib/mica/witness-sight/book-of-effects.jsonl", basis };
          d.readers.gate2Direction.book = { value: "witnessBook", basis: "PROBE BASE", proxy: false };
          d.readers.gate2Direction.witnessMethod = {
            value: "bd91dc37fa7e5d0653c795c4878266a4482c1405d932ce0b073d50b5bce41b72",
            basis: "PROBE BASE",
            proxy: false,
          };
          d.baskets[key].classes.value = {
            value: [],
            damage: [],
            unknown: [{ kind: "CONSEQUENCE", outcome: "c-other:CONTENT_DIFFERS", lane: "A", eg: 1, bearsOn: ["c-other"], basis: "PROBE BASE" }],
          };
          return d;
        })(),
      },
      // LONG RUN A STOP 2 · A PROBE BASE FOR THE HARM STANZA'S CLOSED NODES: no served declaration
      //    declares `harm` yet. The subject key and every id are the walk's own concretised keys, so the
      //    entries sit exactly where the walk probes them (an origin, an item, a grant and a clearance
      //    each present at its first site).
      {
        name: "fixture+…+gate2Direction on the book+harm (probe base: Long Run A Stop 2, not served)",
        doc: ((): Record<string, any> => {
          const harmPatterns = Object.keys(schema.properties?.harm?.patternProperties ?? {});
          const key = harmPatterns.length === 1 ? concretise(harmPatterns[0]) : null;
          const idPatterns = Object.keys(schema.$defs?.subjectHarm?.properties?.items?.properties?.value?.patternProperties ?? {});
          const id = idPatterns.length === 1 ? concretise(idPatterns[0]) : null;
          if (key === null || id === null) {
            throw new Error(`the harm probe base needs one concretisable subject pattern and one id pattern, found ${JSON.stringify(harmPatterns)} / ${JSON.stringify(idPatterns)}`);
          }
          // S208-2 · the same base carries the errand envelope, so its two closed nodes are reached here too.
          const d = hDeclared(key, id);
          d.frame[key].categories.value.push({ id: "c-probe-own", label: "probe", grounding: "agency", self: false });
          d.harm[key].errand = { value: { categories: ["c-probe-own"], maxWindowMinutes: 60 }, basis: "PROBE BASE, not a declaration.", proxy: false };
          return d;
        })(),
      },
    ];
    const reach = (doc: any, at: (string | number)[]): any => {
      let cur: any = doc;
      for (const seg of at) {
        if (cur === null || typeof cur !== "object" || !Object.hasOwn(cur, String(seg))) return undefined;
        cur = cur[seg];
      }
      return cur !== null && typeof cur === "object" && !Array.isArray(cur) ? cur : undefined;
    };

    for (const node of nodes) {
      // ⛔ THE BASE MUST SATISFY THE NODE'S OWN SCHEMA, NOT MERELY REACH ITS PATH.
      //    A `oneOf` branch applies CONDITIONALLY: both pilot branches sit at the
      //    same instance path, and reachability alone would pair whichever base came
      //    first with both of them — comparing the ACTIVE branch's four properties
      //    against the INACTIVE loader's one-key set and reporting a drift that is
      //    not there. Selecting the base whose instance VALIDATES against this node
      //    picks the applicable branch, using the evaluator the census now keeps
      //    honest. Conditional applicability is decided by the schema, not guessed.
      const base = bases.find((b) => {
        const inst = reach(b.doc, node.at);
        if (inst === undefined) return false;
        try {
          return evalSchema(node.schema, inst, node.schemaPath).length === 0;
        } catch {
          return false;
        }
      });
      if (base === undefined) {
        const anyReach = bases.some((b) => reach(b.doc, node.at) !== undefined);
        unprobed.push(
          anyReach
            ? `${node.schemaPath} (reachable at ${JSON.stringify(node.at)} but NO base satisfies this node's own schema — if it is a oneOf/anyOf branch, no base matches it)`
            : `${node.schemaPath} (no object at ${JSON.stringify(node.at)} in any of the ${String(bases.length)} bases)`
        );
        continue;
      }
      const d = JSON.parse(JSON.stringify(base.doc)) as Record<string, any>;
      const cur = reach(d, node.at) as Record<string, unknown>;
      cur[PROBE] = 1;
      // ⛔ THE EXPECTED PATH IS BUILT IN THE LOADER'S OWN NOTATION, and the first
      //    strict comparison proved it never was. `[...at, PROBE].join(".")` is wrong
      //    in two ways the suffix match hid: the loader names an unknown key on the
      //    ROOT object `$.<key>`, not `<key>`; and it indexes arrays with BRACKETS —
      //    `routes[0].allow[0].<key>`, not `routes.0.allow.0.<key>`. Four of the 29
      //    nodes were affected. Under `endsWith` they were compared anyway, so the
      //    sets happened to be right while the guarantee that they were THIS node's
      //    was absent. THE LOOSE CHECK WAS HIDING A BROKEN EXPECTED VALUE, which is
      //    the more useful half of the lesson: a comparison relaxed to make a test
      //    pass stops reporting on the thing that was relaxed.
      const dotted = node.at.reduce<string>(
        (acc, seg) =>
          typeof seg === "number" ? `${acc}[${String(seg)}]` : acc === "" ? String(seg) : `${acc}.${String(seg)}`,
        ""
      );
      const wantField = dotted === "" ? `$.${PROBE}` : `${dotted}.${PROBE}`;
      let accepted: string[] | null = null;
      try {
        validateDeclarations(d as never);
        unprobed.push(`${node.schemaPath} (the loader ACCEPTED an unknown key in the ${base.name} base — it is not a closed object there)`);
        continue;
      } catch (err) {
        if (!(err instanceof DeclarationRejected)) throw err;
        const m = /accepted here: (.*)$/.exec(err.message);
        const field = String((err as unknown as { field?: string }).field ?? "");
        // ⛔ THE FULL FIELD PATH IS COMPARED, AND UNTIL NOW IT WAS NOT. Codex,
        //    Key-Set-4 read, F3: this computed `wantField` and then threw it away
        //    with `void wantField`, testing only `field.endsWith(PROBE)`. A refusal
        //    arriving from a DIFFERENT path that happens to end in the probe key
        //    would have been accepted as this node's refusal and its accepted-set
        //    compared against the wrong schema node — the exact mis-attribution the
        //    comment above this loop claims to prevent. The commit message, the
        //    Codex brief and three board lines all stated that the refusal's field
        //    path was asserted. IT WAS NOT. `void wantField` is the evidence that I
        //    built the value and discarded it rather than never having had it.
        //
        //    And the refusal must be the UNKNOWN-FIELD kind. A node can refuse at
        //    exactly the probed path for an unrelated reason — a shape rule on a key
        //    whose name collides with the probe — and `accepted here:` would then be
        //    absent or about something else.
        const isUnknownFieldRefusal = m !== null && err.message.includes("unknown field");
        if (!isUnknownFieldRefusal || field !== wantField) {
          unprobed.push(
            `${node.schemaPath} (in the ${base.name} base, the refusal is not this probe's: ` +
              `wanted field="${wantField}" unknown-field refusal, got field="${field}" ` +
              `msg="${err.message.slice(0, 70)}")`
          );
          continue;
        }
        accepted = m[1].split(",").map((x) => x.trim()).filter((x) => x.length > 0).sort();
      }
      const inSchemaNotLoader = node.props.filter((k) => !accepted!.includes(k));
      const inLoaderNotSchema = accepted!.filter((k) => !node.props.includes(k));
      if (inSchemaNotLoader.length > 0) {
        schemaWider.push(`${node.schemaPath}: schema declares ${JSON.stringify(inSchemaNotLoader)} which the loader REFUSES (accepted: ${JSON.stringify(accepted)})`);
      }
      if (inLoaderNotSchema.length > 0) {
        loaderWider.push(`${node.schemaPath}: loader accepts ${JSON.stringify(inLoaderNotSchema)} which the schema FORBIDS (schema: ${JSON.stringify(node.props)})`);
      }
    }

    const probed = nodes.length - unprobed.length;
    assert(
      schemaWider.length === 0 && loaderWider.length === 0,
      `schema/loader property sets disagree.\n  SCHEMA WIDER:\n    ${schemaWider.join("\n    ") || "(none)"}` +
        `\n  LOADER WIDER:\n    ${loaderWider.join("\n    ") || "(none)"}` +
        `\n  probed ${probed} of ${nodes.length} closed nodes; UNPROBED:\n    ${unprobed.join("\n    ") || "(none)"}`
    );
    // ⛔ THE COUNTS ARE PINNED EXACTLY, NOT AS A FLOOR. A floor (`>= 25`) is what
    //    let the pilot block's two closed nodes be missing without anything moving:
    //    the walk found 27, the floor wanted 25, and the two it never reached were
    //    invisible in both directions — unprobed nodes are named, but a node the
    //    walk never FINDS cannot be named. An exact count turns "the walk stopped
    //    looking" from an inequality nobody checks into a failure.
    //
    //    29 = 27 before this commit + the two branches of `$.properties.pilot.oneOf`.
    //    If the schema gains or loses a closed object this fails, and that is the
    //    point: somebody should look.
    // ⛔ AND THE SET IS PINNED, NOT THE COUNT. Codex, Key-Set-5 read, F2: the
    //    assertion was `nodes.length === 29 && probed === nodes.length`, which
    //    pins HOW MANY closed objects the schema has and says nothing about WHICH.
    //    Reproduced in memory: opening `pilot.oneOf[0]` while closing
    //    `readers.logKind.allOf[1]` left the count at 29 — the failure message
    //    itself read "found 29 closed nodes (expected 29)" — and only an unrelated
    //    cascade in the served-document check caught it. A count is a hash with one
    //    bucket: every swap collides. The SET of schema paths is the thing the
    //    walk is actually claiming, so the set is what is asserted.
    //
    //    29 = 27 + the two branches of `$.properties.pilot.oneOf`. If the schema
    //    gains, loses OR MOVES a closed object this fails, and that is the point:
    //    somebody should look.
    const EXPECTED_CLOSED_PATHS = [
      "$",
      "$.$defs.declaredEventClass",
      "$.$defs.declaredEventClass.properties.value",
      "$.$defs.declaredEventMap",
      "$.$defs.declaredNumber",
      "$.$defs.declaredString",
      "$.$defs.declaredStringList",
      // GATE 2 · Stop 2 · the grade and the two class defs, each probed at its
      // FIRST site inside subjectBasket (which therefore precedes them in $defs).
      "$.$defs.gate2Grade",
      "$.$defs.gate2SignedClass",
      "$.$defs.gate2SignedClass.properties.weight",
      "$.$defs.gate2UnknownClass",
      "$.$defs.gate2UnknownClass.properties.magnitude",
      // GATE 1 · Stop 2 · the frame def and its four closed members. The frame
      // MAP itself (`$.properties.frame`) is not here and must not be: it is
      // closed by patternProperties alone, with no `properties`, so it is a key
      // space — its X16 rule (key = a declared subject) is the loader's, and the
      // GATE 1 schema-parity arm pins that as LOADER-ONLY.
      "$.$defs.subjectFrame",
      "$.$defs.subjectFrame.properties.categories",
      "$.$defs.subjectFrame.properties.categories.properties.value.items",
      "$.$defs.subjectFrame.properties.regions",
      "$.$defs.subjectFrame.properties.regions.properties.value.items",
      // GATE 2 · Stop 2 · the basket def and its closed envelopes. The basket
      // MAP (`$.properties.baskets`) is a key space like `frame`, not a node.
      "$.$defs.subjectBasket",
      "$.$defs.subjectBasket.properties.classes",
      "$.$defs.subjectBasket.properties.classes.properties.value",
      "$.$defs.subjectBasket.properties.grades",
      "$.$defs.subjectBasket.properties.grades.properties.value",
      "$.$defs.subjectBasket.properties.latchClearedBy",
      "$.$defs.subjectBasket.properties.latchClearedBy.properties.value.items",
      "$.$defs.subjectBasket.properties.window",
      "$.$defs.subjectBasket.properties.window.properties.value",
      // LONG RUN A STOP 2 · the harm stanza's def, its five envelopes and the four closed entries
      // (origin, item, grant, clearance). The harm MAP and the three id maps are key spaces, not nodes.
      "$.$defs.subjectHarm",
      "$.$defs.subjectHarm.properties.clearances",
      "$.$defs.subjectHarm.properties.clearances.properties.value.items",
      // S208-2 · the errand envelope and its value: two closed objects.
      "$.$defs.subjectHarm.properties.errand",
      "$.$defs.subjectHarm.properties.errand.properties.value",
      "$.$defs.subjectHarm.properties.grants",
      "$.$defs.subjectHarm.properties.grants.properties.value.patternProperties[^[A-Za-z0-9_-]{1,32}(?![\\s\\S])]",
      "$.$defs.subjectHarm.properties.harmOnly",
      "$.$defs.subjectHarm.properties.items",
      "$.$defs.subjectHarm.properties.items.properties.value.patternProperties[^[A-Za-z0-9_-]{1,32}(?![\\s\\S])]",
      "$.$defs.subjectHarm.properties.origins",
      "$.$defs.subjectHarm.properties.origins.properties.value.patternProperties[^[A-Za-z0-9_-]{1,32}(?![\\s\\S])]",
      "$.properties.notice",
      "$.properties.paths",
      "$.properties.paths.properties.clerkStamps",
      // TIER 1 · the witness's two paths — envelopes, like clerkStamps.
      "$.properties.paths.properties.witnessBook",
      "$.properties.paths.properties.witnessIntake",
      "$.properties.pilot.oneOf[0]",
      "$.properties.pilot.oneOf[1]",
      "$.properties.readers",
      "$.properties.readers.properties.doctorCadence",
      "$.properties.readers.properties.eng",
      // T26 · gate 4's block and the list def it introduces. SIX new closed
      // paths, pinned here deliberately: the walk finds every
      // `additionalProperties: false` in the schema, so a block added without
      // this list moving is a block nobody decided to close.
      "$.properties.readers.properties.gate4Sunset",
      // GATE 1 · Stop 2 · the switch block (subject only, the R1 pattern).
      "$.properties.readers.properties.gate1Scope",
      // GATE 2 · Stop 2 · the switch block (subject only, the gate1Scope pattern).
      "$.properties.readers.properties.gate2Direction",
      // TIER 1 · the book switch and the method designation.
      "$.properties.readers.properties.gate2Direction.properties.book",
      "$.properties.readers.properties.gate2Direction.properties.witnessMethod",
      "$.properties.readers.properties.narrowK",
      "$.properties.readers.properties.narrowR",
      "$.properties.readers.properties.narrowT",
      "$.properties.readers.properties.narrowW",
      "$.properties.readers.properties.nodeResponse",
      "$.properties.readers.properties.nodeResponse.properties.flatness",
      "$.properties.readers.properties.sig",
      "$.properties.routes.items",
      "$.properties.routes.items.properties.allow.items",
      "$.properties.stakes",
      "$.properties.stakes.properties.baseline",
      "$.properties.subjectLog",
      "$.properties.subjectLog.properties.chainBoundary",
      "$.properties.subjects.items",
    ];
    const foundPaths = nodes.map((n) => n.schemaPath).sort();
    const missing = EXPECTED_CLOSED_PATHS.filter((p) => !foundPaths.includes(p));
    const appeared = foundPaths.filter((p) => !EXPECTED_CLOSED_PATHS.includes(p));
    assert(
      missing.length === 0 && appeared.length === 0,
      `the SET of closed schema paths moved.\n` +
        `  NO LONGER CLOSED (or no longer reached by the walk):\n    ${missing.join("\n    ") || "(none)"}\n` +
        `  NEWLY CLOSED (or newly reached):\n    ${appeared.join("\n    ") || "(none)"}\n` +
        `  found ${foundPaths.length}, expected ${EXPECTED_CLOSED_PATHS.length}`
    );
    // A duplicate path would let two nodes answer for one claim, so the list is
    // asserted to be a SET rather than assumed to be one.
    assert(
      new Set(foundPaths).size === foundPaths.length,
      `the walk recorded a schema path twice: ${JSON.stringify(foundPaths.filter((p, i) => foundPaths.indexOf(p) !== i))}`
    );
    assert(
      probed === nodes.length,
      `probed ${probed} of ${nodes.length} closed nodes. A node the walk FOUND but could not compare is ` +
        `named here; a node it never found is caught by the path set above.\n` +
        `  UNPROBED:\n    ${unprobed.join("\n    ") || "(none)"}`
    );
    // ⛔ A PATTERN WITH NO CONCRETE KEY IS ITS OWN FAILURE, COUNTED APART.
    //    Folding it into `unprobed` made `probed ${String(probed)} of ${String(nodes.length)}`
    //    arithmetic that does not hold: the pattern was never a FOUND node, so
    //    subtracting it from the node count produces a number that reads as
    //    "a node I could not compare" while meaning "a key I could not build".
    //    Two causes, two lines — the rule this suite keeps re-learning.
    assert(
      unconcretisable.length === 0,
      `${unconcretisable.length} patternProperties pattern(s) admit keys this walk could not build, so the ` +
        `closed objects behind them were never compared against the loader:\n    ${unconcretisable.join("\n    ")}\n` +
        `  Widen the concretiser's pool, or state why the pattern is out of scope. An unbuildable key is a ` +
        `HOLE IN THE WALK, not an absence of nodes.`
    );
    // ⛔ AND BOOLEAN SCHEMA POSITIONS ARE COUNTED, which is the second detector for
    //    Codex's gap 2. `items: false` is LEGAL JSON Schema and means "no item is
    //    valid"; it is also indistinguishable from a typo, and it silently defeated
    //    the subset evaluator. There are none in this schema today. One appearing
    //    should be a deliberate act somebody reviewed, so the count is pinned and
    //    the position is named when it moves.
    assert(
      booleanPositions.length === 0,
      `the committed schema now contains ${booleanPositions.length} BOOLEAN schema position(s), and it had none. ` +
        `A boolean schema is legal and is also what a stray \`false\` looks like — \`items: false\` admits NO array ` +
        `item at all. Confirm each one is intended, then update this pin:\n    ${booleanPositions.join("\n    ")}`
    );
  }
);

// ── THE WIDTH OF WHAT THE PARITY CHECKS BELOW PROVE ──────────────────────────
//
// ⛔ 6a2277d's commit message said "FOUR CHECKS SO THE TWO CANNOT DRIFT APART
//    AGAIN". THAT SENTENCE WAS FALSE AND CODEX DISPROVED IT TWICE — two
//    schema-only mutations passed all four and left the census unmoved
//    (the second verify of the Eng key-set act, F1). The claim is narrowed
//    here rather than re-asserted, because the honest width is smaller than the
//    sentence and the sentence is what a reader relies on.
//
// WHAT THESE CHECKS DO PROVE, and nothing wider:
//   · the schema's readers.eng KEY SET equals the loader's, probed from the
//     loader's own refusals;
//   · the SERVED bytes satisfy the committed schema, under a SUBSET evaluator
//     whose object semantics are themselves pinned above;
//   · minimumClassCoverage is optional on both sides, and the absent arm
//     validates rather than merely going unlisted;
//   · loader and schema reach the SAME VERDICT on fifteen enumerated envelopes —
//     nine `value` variants and six envelope variants including `basis` lengths
//     0 and 1, a missing `basis`, a wrong-typed `proxy`, an extra own key, and a
//     missing `value`.
//
// WHAT THEY DO NOT PROVE: that ANY unilateral change to either side is caught.
// The evaluator implements a subset of Draft 2020-12 and no real validator is
// available in this repository, so a keyword it does not implement, or a schema
// change outside the probed envelope shapes, can still pass. ⚠ THE TWO CONCRETE
// HOLES CODEX FOUND ARE CLOSED AND ASSERTED — prototype-name keys, and envelope
// fields other than `value` — but "closed the two we found" is not "closed the
// class", and the difference is the whole content of this comment.

check(
  "EMITTED FIELDS: toSensorConfig's output key sets are exactly these — the header's list is a copy and has been wrong twice",
  () => {
    // ⛔ THE AUTHORITY FOR to-sensor-config.ts's HEADER LIVES HERE, because that
    //    header has now understated its subject twice: once the GUARD's accepted
    //    set (Codex, Eng key-set read, F2) and once THIS FUNCTION's own output
    //    (Codex, Key-Set-2 read, F2 — it said two Sig fields where four are
    //    emitted). A comment restating a key set is a cached read of the code
    //    beside it, and nothing re-reads it.
    const sc = toSensorConfig(validateDeclarations(clone()).declarations);
    const eq = (a: readonly string[], b: readonly string[]): boolean => JSON.stringify(a) === JSON.stringify(b);
    assert(
      eq(Object.keys(sc).sort(), ["eng", "sig"]),
      `the top-level output set moved to ${JSON.stringify(Object.keys(sc).sort())}; mica-guard's readSensorConfig accepts eng+sig and throws on any other`
    );
    // ⚠ TWO ARMS, BECAUSE minimumClassCoverage IS OPTIONAL AND THE EMITTED SET
    //   THEREFORE DEPENDS ON THE DECLARATION. The first draft of this check
    //   asserted three keys against the fixture, which carries none, and failed —
    //   correctly. Pinning both arms also pins the optionality in the PROJECTION,
    //   which nothing else did: the loader's optional arm and the schema's are
    //   both tested, and until now this file's was not.
    assert(
      eq(Object.keys(sc.eng).sort(), ["minimumSampleSize", "structureThreshold"]),
      `eng's emitted set WITHOUT the optional field is ${JSON.stringify(Object.keys(sc.eng).sort())} — ` +
        "update the header's list AND decide whether a new field belongs here"
    );
    const withCov = clone();
    withCov.readers.eng.minimumClassCoverage = { value: 3, basis: BASIS_FIXTURE, proxy: true };
    const scCov = toSensorConfig(validateDeclarations(withCov).declarations);
    assert(
      eq(Object.keys(scCov.eng).sort(), ["minimumClassCoverage", "minimumSampleSize", "structureThreshold"]),
      `eng's emitted set WITH the optional field is ${JSON.stringify(Object.keys(scCov.eng).sort())} — ` +
        "the projection dropped a declared field, which is the seam this act exists on the far side of"
    );
    assert(
      eq(Object.keys(sc.sig).sort(), ["clockToleranceBasis", "clockToleranceMs", "preconditionMap", "reentryMap"]),
      `sig's emitted set is ${JSON.stringify(Object.keys(sc.sig).sort())} — this is the set the header understated as two`
    );
  }
);

check(
  "EVALUATOR: a prototype name is not an own key — required, additionalProperties and the descent all use Object.hasOwn",
  () => {
    // ⛔ PINNING THE FIX, NOT ITS CONSEQUENCE. Codex's mutation B was caught
    //    because the served-bytes check now fails, which is an INCIDENTAL
    //    exercise of this property. Asserted directly, so a future edit that
    //    reinstates `in` fails here with a name that says why.
    const req = evalSchema({ type: "object", required: ["toString"], properties: {}, additionalProperties: false }, {}, "x");
    assert(
      req.length === 1 && req[0].includes('required key "toString" is missing'),
      "`toString` satisfied `required` from the prototype chain — the evaluator is using `in`, not " +
        `Object.hasOwn: ${JSON.stringify(req)}`
    );
    const add = evalSchema({ type: "object", properties: {}, additionalProperties: false }, { toString: 1 }, "x");
    assert(
      add.length === 1 && add[0].includes('additional property "toString" is not allowed'),
      `a property named after a prototype member was excused as if the schema declared it: ${JSON.stringify(add)}`
    );
  }
);

check(
  "T11/F1: the committed SCHEMA's readers.eng key set EQUALS the loader's — the loader's set PROBED from its own refusal, never read off its source",
  () => {
    const schemaKeys = Object.keys(ENG_SUBSCHEMA.properties).sort();
    const loaderKeys = [...engAllowListFromLoader()].sort();
    assert(
      JSON.stringify(schemaKeys) === JSON.stringify(loaderKeys),
      `the published schema and the runtime loader disagree about readers.eng.\n` +
        `        schema: ${schemaKeys.join(", ")}\n` +
        `        loader: ${loaderKeys.join(", ")}\n` +
        `      A declaration the schema rejects is a declaration that lies about itself (Codex F1).`
    );
  }
);

check(
  "T11/F1: the SERVED bytes' readers.eng SATISFIES the committed schema — read from declarations.config.json, not the fixture",
  () => {
    const used = new Set<string>();
    collectKeywords(ENG_SUBSCHEMA, used);
    collectKeywords(DECLARED_NUMBER, used);
    const unsupported = [...used].filter((k) => !SUPPORTED_KEYWORDS.has(k)).sort();
    assert(
      unsupported.length === 0,
      `the eng subschema now uses JSON Schema keyword(s) this suite's subset evaluator does ` +
        `not implement: ${unsupported.join(", ")}. REFUSING rather than reporting a pass it ` +
        `cannot justify — widen the evaluator, or validate with a real Draft 2020-12 validator.`
    );
    const violations = evalSchema(ENG_SUBSCHEMA, shipped.readers.eng, "readers.eng");
    assert(
      violations.length === 0,
      `the SHIPPED declaration's readers.eng violates the published schema:\n        ` +
        violations.join("\n        ")
    );
  }
);

check(
  "T11/F1: the schema keeps minimumClassCoverage OPTIONAL, exactly as the loader does — and the absent arm VALIDATES, not merely goes unlisted",
  () => {
    assert(
      !ENG_SUBSCHEMA.required.includes("minimumClassCoverage"),
      `the schema now REQUIRES minimumClassCoverage. T11's own condition is that Eng returns ` +
        `MISSING_CONFIGURATION until it is declared — the honest blind state, not a regression. ` +
        `Requiring it here refuses the ENTIRE declaration and takes every other reader down to ` +
        `enforce one field.`
    );
    const engWithout: Record<string, unknown> = { ...shipped.readers.eng };
    delete engWithout.minimumClassCoverage;
    const violations = evalSchema(ENG_SUBSCHEMA, engWithout, "readers.eng");
    assert(
      violations.length === 0,
      `readers.eng WITHOUT the field must still validate against the schema: ${violations.join("; ")}`
    );
  }
);

check(
  "T11/F1: the schema's bounds for minimumClassCoverage EQUAL the bounds the loader ENFORCES — agreement checked value by value, not by comparing two literals",
  () => {
    // ⛔ WHY NOT JUST READ THE SCHEMA'S `"minimum": 1` AND COMPARE IT TO THE
    //    LOADER'S `minimum: 1`? Because that proves two literals match, which is
    //    two of my own opinions agreeing. Each probe goes through BOTH sides and
    //    the assertion is that they reach the SAME VERDICT — so a change to
    //    either side's SEMANTICS fails here, not just a change to its spelling.
    // ⛔ THE WHOLE ENVELOPE, NOT ONLY `value` — Codex, Key-Set-2, mutation A.
    //    Changing `$defs.declaredNumber.properties.basis.minLength` from 1 to 2
    //    made the schema reject a one-character basis the loader accepts, and
    //    ALL FOUR checks passed: the nine probes varied `value` and always
    //    supplied the same long BASIS_FIXTURE, so no probe could ever reach
    //    another envelope field. A parity test that varies one field proves
    //    parity on one field.
    //
    // ⚠ `basis` LENGTHS 0 AND 1 ARE THE POINT. On the true bytes the loader and
    //   the schema agree on both (both refuse "", both accept "x"); under
    //   mutation A they disagree on "x", which is exactly how it is caught.
    const envelopes: readonly Record<string, unknown>[] = [
      ...[3, 1, 600, 0, -3, 2.5, "3", true, null].map((v) => ({ value: v, basis: BASIS_FIXTURE, proxy: true })),
      { value: 3, basis: "", proxy: true },
      { value: 3, basis: "x", proxy: true },
      { value: 3, basis: BASIS_FIXTURE },
      { value: 3, basis: BASIS_FIXTURE, proxy: "yes" },
      { value: 3, basis: BASIS_FIXTURE, proxy: true, extra: 1 },
      { basis: BASIS_FIXTURE, proxy: true },
    ];
    const disagreements: string[] = [];
    for (const envelope of envelopes) {
      const v = envelope.value;
      const d = clone();
      d.readers.eng.minimumClassCoverage = envelope;
      let loaderAccepts = true;
      try {
        validateDeclarations(d);
      } catch (err) {
        if (!(err instanceof DeclarationRejected)) throw err;
        loaderAccepts = false;
      }
      const schemaAccepts =
        evalSchema(ENG_SUBSCHEMA.properties.minimumClassCoverage, envelope, "minimumClassCoverage")
          .length === 0;
      if (loaderAccepts !== schemaAccepts) {
        disagreements.push(
          `envelope ${JSON.stringify(envelope)}: loader ${loaderAccepts ? "ACCEPTS" : "refuses"}, ` +
            `schema ${schemaAccepts ? "ACCEPTS" : "refuses"}`
        );
      }
    }
    assert(
      disagreements.length === 0,
      `the loader and the published schema disagree on what a valid minimumClassCoverage is:\n        ` +
        disagreements.join("\n        ")
    );
  }
);

// ── ACT B · readers.sig.clerkStampLag, 2026-09-25 ───────────────────────────
//
// It is NOT in MERGE_BLOCKS and cannot be: that table walks `readers.<key>`,
// and this field lives one level down, behind `checkNoUnknown(sigRaw, [...])` —
// a SECOND front door, with its own allow-list, which the table never opens.
// A block can be through the outer door and refused at the inner one.

check(
  "ACT B: readers.sig.clerkStampLag reaches its validator — proved by LOADING a declaration that carries it, not by reading the sig allow-list",
  () => {
    const d = clone();
    d.readers.sig.clerkStampLag = {
      value: "<=24h",
      basis: "ACT B FIXTURE, not a declaration. Reuses mica-clerk-caller.timer at 00:00; F3 reads order, not wall time.",
      proxy: true,
    };
    let loaded;
    try {
      loaded = validateDeclarations(d).declarations;
    } catch (err) {
      if (err instanceof DeclarationRejected) {
        throw new Error(
          `readers.sig.clerkStampLag was REJECTED AT LOAD (field "${err.field}": ${err.message}). ` +
            `That is checkNoUnknown(sigRaw, [...]) in declarations.ts's validate() — the INNER ` +
            `front door. Act B's declaration would not have landed, and declarationHash would ` +
            `not have moved to say so.`
        );
      }
      throw err;
    }
    assert(
      loaded.readers.sig.clerkStampLag !== undefined &&
        loaded.readers.sig.clerkStampLag.value === "<=24h",
      `clerkStampLag must survive validation with its value intact: ${JSON.stringify(loaded.readers.sig.clerkStampLag)}`
    );
  }
);

check(
  "ACT B: clerkStampLag is a DISCLOSURE, not a wire — it is in the hash and reaches NO instrument",
  () => {
    const d = clone();
    d.readers.sig.clerkStampLag = { value: "<=24h", basis: "ACT B FIXTURE", proxy: true };
    const loaded = validateDeclarations(d).declarations;
    const opts: any = toWireOptions(loaded);
    // The claim is narrow and it is the honest one: declaring the lag changes
    // what an operator READS and what the digest COVERS, and changes no reading
    // F3 performs. If a later build wants the lag ENFORCED, it builds the
    // enforcement — this assertion is what stops it being assumed.
    assert(
      opts.sig === undefined || !("clerkStampLag" in opts.sig),
      `toWireOptions carried clerkStampLag to an instrument that takes no such parameter: ${JSON.stringify(opts.sig)}`
    );
    assert(
      JSON.stringify(opts).indexOf("clerkStampLag") === -1,
      `clerkStampLag appeared somewhere in WireOptions: ${JSON.stringify(opts)}`
    );
    const moved = validateDeclarations(d).declarationHash;
    const flat = validateDeclarations(clone()).declarationHash;
    assert(
      moved !== flat,
      "declaring clerkStampLag did NOT move the declaration hash — the disclosure is not in the digest, " +
        "so an operator could not tell a stamped-with-lag deployment from one without"
    );
  }
);

check(
  "ACT B: the sig door is still a door — an undeclared sig key is REFUSED, and a malformed lag is refused by field name",
  () => {
    for (const name of ["clerkStampLagMs", "clerkstamplag", "clerkClockStamps"]) {
      const d = clone();
      d.readers.sig[name] = { value: "<=24h", basis: "fixture", proxy: true };
      assertRejected(() => validateDeclarations(d), "readers.sig");
    }
    // The envelope is not optional: a bare string is not a declared string.
    const bare = clone();
    bare.readers.sig.clerkStampLag = "<=24h";
    assertRejected(() => validateDeclarations(bare), "readers.sig.clerkStampLag");
    // Nor is an empty value, which would disclose nothing while looking declared.
    const empty = clone();
    empty.readers.sig.clerkStampLag = { value: "", basis: "fixture", proxy: true };
    assertRejected(() => validateDeclarations(empty), "readers.sig.clerkStampLag");
  }
);

check(
  "ACT B: the SHIPPED declaration does NOT declare clerkStampLag, and the key is ABSENT rather than present-and-undefined (read from declarations.config.json, not the fixture)",
  () => {
    // ⛔ THIS CLAIM IS ABOUT THE DEPLOYMENT, so it reads the deployment. Reading
    // the fixture here would have made it a claim about a file we control, which
    // is exactly the shape that lets a declaration drift unnoticed.
    const loaded = loadDeclarations(SHIPPED_PATH);
    assert(
      !("clerkStampLag" in loaded.declarations.readers.sig),
      "clerkStampLag is a PRESENT key on a declaration that does not declare it — canonicalHash " +
        "omits undefined by its rule 4 today, but a present key is one refactor away from a moved hash"
    );
  }
);

// ── narrow-T · DECLARED AND UNREAD, stated here so no one discovers it live ──

check(
  "narrow-T: the pair rule — driftPermutationSamples and driftPermutationSeed are declared together or not at all",
  () => {
    const onlySamples = clone();
    onlySamples.readers.narrowT = {
      driftTolerance: { value: 0.35, basis: "fixture", proxy: true },
      minimumEventsPerWindow: { value: 12, basis: "fixture", proxy: true },
      driftPermutationSamples: { value: 2000, basis: "fixture", proxy: true },
    };
    assertRejected(() => validateDeclarations(onlySamples), "readers.narrowT.driftPermutationSamples");

    const onlySeed = clone();
    onlySeed.readers.narrowT = {
      driftTolerance: { value: 0.35, basis: "fixture", proxy: true },
      minimumEventsPerWindow: { value: 12, basis: "fixture", proxy: true },
      driftPermutationSeed: { value: 7, basis: "fixture", proxy: true },
    };
    assertRejected(() => validateDeclarations(onlySeed), "readers.narrowT.driftPermutationSamples");

    const both = clone();
    both.readers.narrowT = {
      driftTolerance: { value: 0.35, basis: "fixture", proxy: true },
      minimumEventsPerWindow: { value: 12, basis: "fixture", proxy: true },
      driftPermutationSamples: { value: 2000, basis: "fixture", proxy: true },
      driftPermutationSeed: { value: 7, basis: "fixture", proxy: true },
    };
    const loaded = validateDeclarations(both).declarations;
    assert(loaded.readers.narrowT !== undefined, "both halves declared -> loads");
  }
);

check(
  "narrow-T: the two REQUIRED fields are required, and the optional ones are checked rather than waved through",
  () => {
    const noTolerance = clone();
    noTolerance.readers.narrowT = { minimumEventsPerWindow: { value: 12, basis: "fixture", proxy: true } };
    assertRejected(() => validateDeclarations(noTolerance), "readers.narrowT.driftTolerance");

    const noMinimum = clone();
    noMinimum.readers.narrowT = { driftTolerance: { value: 0.35, basis: "fixture", proxy: true } };
    assertRejected(() => validateDeclarations(noMinimum), "readers.narrowT.minimumEventsPerWindow");

    // A window is a COUNT OF RECORDS from each end: zero makes both windows
    // empty, and a fraction is not a count.
    for (const bad of [0, 2.5, -1]) {
      const d = clone();
      d.readers.narrowT = {
        driftTolerance: { value: 0.35, basis: "fixture", proxy: true },
        minimumEventsPerWindow: { value: 12, basis: "fixture", proxy: true },
        temporalWindowSize: { value: bad, basis: "fixture", proxy: true },
      };
      assertRejected(() => validateDeclarations(d), "readers.narrowT.temporalWindowSize");
    }

    const negMinimum = clone();
    negMinimum.readers.narrowT = {
      driftTolerance: { value: 0.35, basis: "fixture", proxy: true },
      minimumEventsPerWindow: { value: -1, basis: "fixture", proxy: true },
    };
    assertRejected(() => validateDeclarations(negMinimum), "readers.narrowT.minimumEventsPerWindow");

    const unknownField = clone();
    unknownField.readers.narrowT = {
      driftTolerance: { value: 0.35, basis: "fixture", proxy: true },
      minimumEventsPerWindow: { value: 12, basis: "fixture", proxy: true },
      declaredProfile: { value: ["X"], basis: "fixture", proxy: true },
    };
    // narrow-T has NO declared class. Accepting one here would be the beginning
    // of the latch the other three carry, arriving by copy-paste.
    assertRejected(() => validateDeclarations(unknownField), "readers.narrowT");
  }
);

check(
  "narrow-T: toWireOptions strips the envelope to bare numbers, and clerkStampLag rides nothing",
  () => {
    const d = clone();
    d.readers.narrowT = {
      driftTolerance: { value: 0.35, basis: "fixture", proxy: true },
      minimumEventsPerWindow: { value: 12, basis: "fixture", proxy: true },
      driftCeilingMargin: { value: 0.02, basis: "fixture", proxy: true },
    };
    const opts: any = toWireOptions(validateDeclarations(d).declarations);
    assert(
      JSON.stringify(opts.narrowT) === '{"driftTolerance":0.35,"minimumEventsPerWindow":12,"driftCeilingMargin":0.02}',
      `toWireOptions must emit the bare config, basis stripped: ${JSON.stringify(opts.narrowT)}`
    );
  }
);

// ── op3's ARITHMETIC IS DATED BY THIS VERY MERGE, and that is a finding ──────
//
// `H12_STANZA` was written on the `opa` line against a caller that wrote THREE
// records for an act that ran (TOOL_ATTEMPTED, TOOL_EXECUTED, TOOL_RESULT) and
// TWO for an act that was held. Its `responseBoundSteps` basis says so in those
// words, and derives TWO from them. THIS LINE ADDS `ACT_CLOSED`, appended as the
// LAST record of EVERY act on BOTH paths, so the caller now writes FOUR and
// THREE. The stanza's own arithmetic is therefore describing a caller that this
// branch replaces.
//
// THE STANZA IS NOT EDITED HERE. It is another seat's declared basis and the
// text the arbiter would paste; rewriting someone's stated reasoning inside a merge is
// how a basis stops meaning what its author checked. What this section does is
// pin BOTH readings so the choice is made with the numbers in front of it, and
// say plainly which one ACT_CLOSED was built for.
//
//   · `responseClass = TOOL_RESULT`, bound 2 — still exact for an act that RAN,
//     and still raises OP3_CALL_UNANSWERED on the FIRST HELD ACT, because no
//     TOOL_RESULT is ever written on the held path. The pilot expires
//     2026-09-27 and expiry is what produces the first held act.
//   · `responseClass = ACT_CLOSED`, bound 3 — honest on both paths, which is the
//     whole reason ACT_CLOSED exists (the arbiter, 2026-09-23). Distances read off the
//     caller at bytes (`claude-bot.ts` micaAct): RAN act 3, ordinary HELD act 2,
//     row-10 dead-letter HELD act 1. Three covers all three and nothing wider is
//     needed.
//
// WHAT BOUND 3 COSTS, stated rather than discovered: op3 pairs BY SEQUENCE
// POSITION and never by actionId. If an act's own ACT_CLOSED append FAILS, the
// NEXT act's ACT_CLOSED can sit exactly three steps after the orphaned attempt
// and pair with it — the truncation reads clean. That is the same class of error
// the `opa` basis names for bound 4+, moved one act closer by the extra record.
// It is narrower than what bound 2 + TOOL_RESULT costs (every held act alarms),
// and it is not zero. WHICH STANZA IS DECLARED IS THE ARBITER'S CALL. [owed → the arbiter]

const H12_STANZA_ACT_CLOSED = {
  expectationClass: JSON.parse(JSON.stringify(H12_STANZA.expectationClass)),
  responseClass: {
    value: { moduleId: "housekeeper", eventType: "ACT_CLOSED" },
    basis:
      "PROXY. ACT_CLOSED is the LAST record of EVERY act, on the path that ran and the path that " +
      "was held alike, carrying payload.closedAs = RAN | HELD. It is the only class this caller " +
      "writes that means 'this act is over' on both paths, which is the single class op3's profile " +
      "has room for. TOOL_RESULT is the narrower alternative and it is the one the opa line " +
      "declared: it is exact for an act that ran and it reads EVERY held act as unanswered, because " +
      "no TOOL_RESULT is written on the held path, ever. WHAT THIS CLASS DOES NOT SAY: it does not " +
      "say the act succeeded, and it does not say anything came back — closedAs carries that and op3 " +
      "does not read payloads. It says the act reached its own end, and an act that did not reach it " +
      "leaves no ACT_CLOSED, which is the truncation op3 is for.",
    proxy: true,
  },
  responseBoundSteps: {
    value: 3,
    basis:
      "PROXY. THREE, READ OFF THE CALLER AT BYTES (richards-cat/claude-bot.ts, micaAct). An act that " +
      "RUNS appends TOOL_ATTEMPTED, TOOL_EXECUTED, TOOL_RESULT, ACT_CLOSED to one serialized outbox, " +
      "processed one act at a time in an awaited loop, so ACT_CLOSED lands exactly THREE steps after " +
      "its attempt. An ordinary HELD act appends TOOL_ATTEMPTED, TOOL_HELD_NOT_EXECUTED, ACT_CLOSED " +
      "— TWO steps. The row-10 dead-letter held path appends TOOL_ATTEMPTED, ACT_CLOSED — ONE step. " +
      "Three is the maximum of the three and therefore the smallest bound that pairs every act this " +
      "caller can write. TWO WOULD BE TOO NARROW: every act that ran would read unanswered, and " +
      "running is the common case. FOUR OR MORE IS NOT SLACK BUT A DIFFERENT READING, and so, in one " +
      "reachable case, is three: the instrument pairs by SEQUENCE POSITION and never by actionId " +
      "although every line carries one, so if an act's own ACT_CLOSED append fails, the NEXT act's " +
      "ACT_CLOSED can sit three steps after the orphaned attempt and pair with it. The truncation " +
      "then reads clean. That exposure is declared here rather than left to be found.",
    proxy: true,
  },
};

check(
  "MERGE: the ACT_CLOSED stanza loads, maps to op3, and carries bound 3 — the reading ACT_CLOSED was built for",
  () => {
    const d = clone();
    d.readers.nodeResponse = JSON.parse(JSON.stringify(H12_STANZA_ACT_CLOSED));
    const loaded = validateDeclarations(d).declarations;
    const opts: any = toWireOptions(loaded);
    assert(
      JSON.stringify(opts.op3.expectationClass) ===
        '{"moduleId":"housekeeper","eventType":"TOOL_ATTEMPTED"}',
      JSON.stringify(opts.op3.expectationClass)
    );
    assert(
      JSON.stringify(opts.op3.responseClass) ===
        '{"moduleId":"housekeeper","eventType":"ACT_CLOSED"}',
      JSON.stringify(opts.op3.responseClass)
    );
    assert(opts.op3.responseBoundSteps === 3, `expected bound 3, got ${opts.op3.responseBoundSteps}`);
    assert(!("flatness" in opts.op3), "flatness must stay absent when undeclared");
  }
);

check(
  "MERGE: BOTH op3 stanzas are declarable and they are DIFFERENT declarations — the choice is a real fork, not a formatting difference",
  () => {
    const a = clone();
    a.readers.nodeResponse = JSON.parse(JSON.stringify(H12_STANZA));
    const b = clone();
    b.readers.nodeResponse = JSON.parse(JSON.stringify(H12_STANZA_ACT_CLOSED));
    const ha = validateDeclarations(a).declarationHash;
    const hb = validateDeclarations(b).declarationHash;
    assert(ha !== hb, "the two op3 stanzas must hash differently — they declare different readings");
    // And the arithmetic the two bases disagree about, pinned as a number so a
    // future caller change walks past it rather than around it.
    assert(
      (validateDeclarations(a).declarations.readers.nodeResponse as any).responseBoundSteps.value === 2,
      "the opa stanza's bound is 2"
    );
    assert(
      (validateDeclarations(b).declarations.readers.nodeResponse as any).responseBoundSteps.value === 3,
      "the ACT_CLOSED stanza's bound is 3"
    );
  }
);

// ── census ───────────────────────────────────────────────────────────────────

console.log("");

// ─── H12 · readers.nodeResponse.since — op3's WINDOW ─────────────────────────
//
// Added 2026-09-26 with the field. The window exists because `ACT_CLOSED` did
// not exist as a kind until sequence 213, and without it op3 reads every earlier
// TOOL_ATTEMPTED as an unanswered call — measured against 188 real records: 65
// findings, the first at sequence 1. These tests pin the field's SHAPE; the
// glue's own suite pins what the slice does to a reading.

const OP3_WITH_SINCE = {
  expectationClass: { value: { moduleId: "housekeeper", eventType: "TOOL_ATTEMPTED" }, basis: "fixture", proxy: true },
  responseClass: { value: { moduleId: "housekeeper", eventType: "ACT_CLOSED" }, basis: "fixture", proxy: true },
  responseBoundSteps: { value: 3, basis: "fixture", proxy: true },
  since: { value: 213, basis: "fixture", proxy: true },
};

check("H12 since: it reaches its validator and toWireOptions maps it to the TOP-LEVEL op3Since", () => {
  const d = clone();
  d.readers.nodeResponse = JSON.parse(JSON.stringify(OP3_WITH_SINCE));
  const loaded = validateDeclarations(d);
  const opts: any = toWireOptions(loaded.declarations ?? loaded);
  assert(opts.op3Since === 213, `op3Since must be the bare number 213, got ${JSON.stringify(opts.op3Since)}`);
  // ⛔ AND IT MUST NOT BE INSIDE THE PROFILE. op3 is an instrument; it does not
  // learn about this deployment's ACT_CLOSED history. A `since` that leaked into
  // `opts.op3` would put a fact about our record inside the instrument's type.
  assert((opts.op3 as any).since === undefined, "since must NOT appear inside the op3 profile — the window travels beside it");
});

check("H12 since: declared TOGETHER WITH flatness, BOTH survive — the branch that silently dropped one", () => {
  const d = clone();
  d.readers.nodeResponse = {
    ...JSON.parse(JSON.stringify(OP3_WITH_SINCE)),
    flatness: {
      amiFloor: { value: 0.2, basis: "fixture", proxy: true },
      amiCeilingMargin: { value: 0.05, basis: "fixture", proxy: true },
      minSample: { value: 3, basis: "fixture", proxy: true },
    },
  };
  const loaded = validateDeclarations(d);
  const opts: any = toWireOptions(loaded.declarations ?? loaded);
  // The validator assigns `nodeResponse` in TWO branches, with and without
  // flatness. The first draft of this field spread `since` into one of them
  // only, so declaring both loaded cleanly and lost the window — no refusal, no
  // warning, and op3 would have gone back to reading the whole log.
  assert(opts.op3Since === 213, "since must survive the flatness branch");
  assert((opts.op3 as any).flatness.minSample === 3, "flatness must survive too");
});

check("H12 since: a sequenceNumber, so 0, a fraction and a negative are REFUSED by field name", () => {
  for (const bad of [0, 2.5, -1]) {
    const d = clone();
    d.readers.nodeResponse = {
      ...JSON.parse(JSON.stringify(OP3_WITH_SINCE)),
      since: { value: bad, basis: "fixture", proxy: true },
    };
    assertRejected(() => validateDeclarations(d), "readers.nodeResponse.since");
  }
});

check("H12 since: ABSENT declaration, ABSENT KEY — not present-and-undefined", () => {
  const d = clone();
  d.readers.nodeResponse = JSON.parse(JSON.stringify(H12_STANZA_ACT_CLOSED));
  const loaded = validateDeclarations(d);
  const opts: any = toWireOptions(loaded.declarations ?? loaded);
  assert(!("op3Since" in opts), `with no since declared the key must be absent, not undefined: ${JSON.stringify(Object.keys(opts))}`);
});

check("H12 since: a window PAST THE END of any log is NOT malformed — it is a window that pairs nothing", () => {
  // Deliberate. An upper bound here would be a check against a log this
  // validator cannot read, and the glue already prints "0 of N record(s)"
  // rather than presenting an empty pairing as a clean reading.
  const d = clone();
  d.readers.nodeResponse = {
    ...JSON.parse(JSON.stringify(OP3_WITH_SINCE)),
    since: { value: 999999, basis: "fixture", proxy: true },
  };
  const loaded = validateDeclarations(d);
  const opts: any = toWireOptions(loaded.declarations ?? loaded);
  assert(opts.op3Since === 999999, "expected opts.op3Since to equal 999999");
});

check("H12 since: the door is still a door — a neighbouring key is REFUSED", () => {
  const d = clone();
  d.readers.nodeResponse = {
    ...JSON.parse(JSON.stringify(OP3_WITH_SINCE)),
    sinceSequence: { value: 213, basis: "fixture", proxy: true },
  };
  assertRejected(() => validateDeclarations(d), "readers.nodeResponse");
});



// ─── X9 · A LIVE PILOT MAY NOT BE REPLACED ───────────────────────────────────
//
// Added 2026-09-27 after S3 handed over at 10:48:48Z while pilot 1 was ACTIVE
// until 18:00:00Z and the door accepted it. X8 asked whether the NEW pilot's
// expiry was still in the future; nothing asked whether the OLD one was still
// running. The cost was the one reading the Sunday order exists to produce: a
// pilot lapsing, the baseline taking over, the next act held blind under it.

const X9_PILOT = (id: string, expiresAt: string) =>
  ({ pilot: { active: true, sessionId: id, expiresAt } } as unknown as Parameters<typeof validateActivation>[0]);
const X9_LIVE = "2026-09-27T18:00:00Z";
const X9_DURING = new Date("2026-09-27T10:48:48Z");

check("X9: replacing a pilot that is still ACTIVE is REFUSED — the 2026-09-27 case", () => {
  assertRejected(
    () => validateActivation(X9_PILOT("pilot-2026-09-20-01", X9_LIVE), X9_PILOT("pilot-2026-09-27-02", "2026-09-29T18:00:00Z")!, X9_DURING),
    "pilot.sessionId"
  );
});

check("X9: after the lapse the SAME replacement is accepted — the rule is about the predecessor, not the successor", () => {
  validateActivation(
    X9_PILOT("pilot-2026-09-20-01", X9_LIVE),
    X9_PILOT("pilot-2026-09-27-02", "2026-09-29T18:00:00Z")!,
    new Date("2026-09-27T18:00:01Z")
  );
});

check("X9: EXTENDING the same id to a later expiry while active is refused too — X8 could not see this", () => {
  // X8 only rejected a PAST expiresAt, so an extension into the future passed it.
  // The rejected "extend" is now actually rejected.
  assertRejected(
    () => validateActivation(X9_PILOT("pilot-2026-09-20-01", X9_LIVE), X9_PILOT("pilot-2026-09-20-01", "2026-09-30T18:00:00Z")!, X9_DURING),
    "pilot.sessionId"
  );
});

check("X9: re-loading the SAME pilot unchanged is not an activation and stays accepted", () => {
  validateActivation(X9_PILOT("pilot-2026-09-20-01", X9_LIVE), X9_PILOT("pilot-2026-09-20-01", X9_LIVE)!, X9_DURING);
});

check("X9: THE ESCAPE HATCH — standing down while active is accepted, so an early handover is two deliberate acts", () => {
  validateActivation(
    X9_PILOT("pilot-2026-09-20-01", X9_LIVE),
    { pilot: { active: false } } as unknown as Parameters<typeof validateActivation>[1],
    X9_DURING
  );
});

check("X9: a first activation with no previous pilot is untouched by the rule", () => {
  validateActivation(null, X9_PILOT("pilot-2026-09-27-02", "2026-09-29T18:00:00Z")!, X9_DURING);
});


// ── X15 · AN EMPTY retiredPath IS REFUSED AT THIS DOOR ───────────────────────
//
// Codex's re-read of 2026-09-28, condition 1: the BUILDER refusing --first-boot is
// not enough, because the front door accepts a declaration made by other means and
// the committed template offered exactly one. So the refusal has to live here.

check("X15: retiredPath \"\" is REFUSED, and the refusal names the rule and the field", () => {
  const d = clone();
  d.subjectLog.chainBoundary.retiredPath.value = "";
  d.subjectLog.chainBoundary.retiredRecords.value = 0;
  d.subjectLog.chainBoundary.retiredBytes.value = 0;
  d.subjectLog.chainBoundary.retiredSha256.value = "";
  let threw = false;
  try {
    validateDeclarations(d);
  } catch (err) {
    threw = true;
    const m = err instanceof Error ? err.message : String(err);
    assert(/X15/.test(m), `the refusal must cite the rule by number: ${m}`);
    assert(/retiredPath/.test(m), `the refusal must name the field: ${m}`);
    assert(
      /unverifiable|cannot be corrected/.test(m),
      `the refusal must say WHY, not just that it refused: ${m}`
    );
  }
  assert(threw, "a FIRST BOOT declaration must not load on this bridge");
});

check("X15 does not touch the rotation case: a named retired file still loads", () => {
  const d = clone();
  d.subjectLog.chainBoundary.retiredPath.value =
    "/var/lib/mica-bridge/subject-events.20260928-1800.pre-chain-boundary.jsonl";
  d.subjectLog.chainBoundary.retiredRecords.value = 1008;
  d.subjectLog.chainBoundary.retiredBytes.value = 475447;
  d.subjectLog.chainBoundary.retiredSha256.value = "a".repeat(64);
  const out = validateDeclarations(d);
  assert(
    out.declarations.subjectLog.chainBoundary.retiredRecords.value === 1008,
    "the rotation branch must still accept a measured boundary"
  );
});

check("and the shape rules on the rotation branch are unchanged (sha256 must be 64 hex)", () => {
  const d = clone();
  d.subjectLog.chainBoundary.retiredPath.value =
    "/var/lib/mica-bridge/subject-events.20260928-1800.pre-chain-boundary.jsonl";
  d.subjectLog.chainBoundary.retiredSha256.value = "not-a-digest";
  let threw = false;
  try { validateDeclarations(d); } catch { threw = true; }
  assert(threw, "a named retired file with a malformed digest must still be refused");
});

// ⛔ AND THE STATE OF THIS TREE, ASSERTED RATHER THAN LEFT LATENT.
//
// The committed declarations.config.json no longer carries the FIRST BOOT template
// (X15 would refuse it outright, and every fixture in this file clones that config).
// It carries a PLACEHOLDER rotated path instead, so the tree loads — and the file it
// names does not exist, so the SERVICE refuses the boundary at first start. That is
// the intended failure, and this test is what stops it being a surprise: the Act A
// release tree is NOT relayable until the stopped-writer rotation replaces this
// block with its measurements.
check("THE FIXTURE IS A PLACEHOLDER AND SAYS SO — not a measured Act A declaration (the COMMITTED config is the serving candidate, rule 1)", () => {
  const cb = draft.subjectLog.chainBoundary;
  assert(cb.retiredPath.value !== "", "X15 would refuse an empty path; the committed tree must not carry one");
  assert(
    /PENDING-ROTATION/.test(cb.retiredPath.value),
    `the committed path must be self-evidently a placeholder, got ${cb.retiredPath.value}`
  );
  for (const k of ["retiredPath", "retiredRecords", "retiredBytes", "retiredSha256"]) {
    assert(
      /PLACEHOLDER — NOT A MEASUREMENT/.test(cb[k].basis),
      `${k}'s basis must say it is not a measurement`
    );
  }
  assert(cb.retiredSha256.value === "0".repeat(64), "the placeholder digest must be obviously fake");
});



// ── ACT B · paths.clerkStamps, and Codex's three findings ────────────────────
//
// The path is DECLARABLE because a reader must read what the declaration names —
// route #10 is what happens when it reads something the declaration does not.
// These pin the three ways that could have gone wrong.

check("ACT B: paths.clerkStamps is OPTIONAL — absent loads, and is today's behaviour", () => {
  const d = clone();
  assert(d.paths.clerkStamps === undefined, "the fixture must not declare it");
  const loaded = validateDeclarations(d).declarations;
  assert(loaded.paths.clerkStamps === undefined, "absent stays absent, never a default");
});

check("ACT B: a declared clerkStamps path under either read root LOADS", () => {
  for (const p of [
    "/var/lib/mica/clerk-subject-stamps.jsonl",
    "/var/lib/mica-bridge/clerk-subject-stamps.jsonl",
  ]) {
    const d = clone();
    d.paths.clerkStamps = { value: p, basis: BASIS_FIXTURE };
    const loaded = validateDeclarations(d).declarations;
    assert(loaded.paths.clerkStamps?.value === p, `${p} must load unchanged`);
  }
});

check("ACT B · CODEX 1: a TRAVERSAL path is REFUSED even though it spells legally", () => {
  // Every character is in the allowed class and the string starts under an
  // allowed root. Only canonicalisation catches it.
  const d = clone();
  d.paths.clerkStamps = { value: "/var/lib/mica-bridge/../../../etc/shadow", basis: BASIS_FIXTURE };
  assertRejected(() => validateDeclarations(d), "paths.clerkStamps");
});

check("ACT B · CODEX 1: traversal that lands BACK INSIDE a root is still fine", () => {
  // The rule is about where it RESOLVES, not about whether it contains "..".
  const d = clone();
  d.paths.clerkStamps = { value: "/var/lib/mica-bridge/sub/../clerk-subject-stamps.jsonl", basis: BASIS_FIXTURE };
  const loaded = validateDeclarations(d).declarations;
  assert(loaded.paths.clerkStamps !== undefined, "a path that resolves inside the root must load");
});

check("ACT B · CODEX 1: X7 compares CANONICAL forms, so two spellings of one file collide", () => {
  const d = clone();
  // The same file as paths.subjectLog, reached by a `..` hop. Spelled differently,
  // so a string comparison would have called them distinct.
  d.paths.clerkStamps = { value: "/var/lib/mica-bridge/sub/../" + d.paths.subjectLog.split("/").pop(), basis: BASIS_FIXTURE };
  assertRejected(() => validateDeclarations(d), "paths");
});

check("ACT B · CODEX 1: a declared path that does not exist yet STILL LOADS", () => {
  // The carrier has not run; ABSENT is the stamps file's designed first state.
  // Canonicalisation must not require the target to exist.
  const d = clone();
  d.paths.clerkStamps = {
    value: "/var/lib/mica/this-file-does-not-exist-yet-" + String(Date.now()) + ".jsonl",
    basis: BASIS_FIXTURE,
  };
  const loaded = validateDeclarations(d).declarations;
  assert(loaded.paths.clerkStamps !== undefined, "a not-yet-created stamps file must be declarable");
});

check("ACT B · CODEX 2: a declared path with NO LOADER THROWS, never a quiet 'no source'", () => {
  const d = clone();
  d.paths.clerkStamps = { value: "/var/lib/mica/clerk-subject-stamps.jsonl", basis: BASIS_FIXTURE };
  const loaded = validateDeclarations(d).declarations;
  let threw = false;
  try {
    toWireOptions(loaded);            // no loader injected
  } catch (err) {
    threw = true;
    assert(
      /WIRING ERROR/.test(err instanceof Error ? err.message : String(err)),
      `the refusal must name it a wiring error: ${String(err)}`
    );
  }
  assert(threw, "a declared stamps path with no loader must THROW, not yield an unconfigured leg");
});

check("ACT B · CODEX 2: no declared path and no loader is SILENT and unchanged", () => {
  const d = clone();
  const loaded = validateDeclarations(d).declarations;
  const opts: any = toWireOptions(loaded);
  assert(opts.sig !== undefined, "sig must still be built");
  assert(opts.sig.clerkClockSource === undefined, "and it must carry no stamp source");
});

check("ACT B · CODEX 1b: a DANGLING symlink ancestor is REFUSED — submitted and refused", () => {
  // ⛔ THE FIRST VERSION OF THIS TEST DID NOT TEST THE FIX (Codex, third read). It
  // proved the two syscalls disagree and then validated a path with NO symlink in
  // it, so the refusal path was never exercised. A test that looks like it covers
  // a fix and does not is worse than no test: it retires the question.
  //
  // This submits the dangling path TO THE VALIDATOR and asserts the refusal. The
  // symlink check runs BEFORE the read-root pattern, so a temp-dir path reaches it
  // and the refusal must name the LINK, not the root.
  const dir = mkdtempSync(join(tmpdir(), "mica-decl-symlink-"));
  const link = join(dir, "dangling");
  symlinkSync(join(dir, "no-such-target"), link);
  try {
    assert(!existsSync(link), "the fixture must actually be dangling — existsSync follows and must say false");
    assert(lstatSync(link).isSymbolicLink(), "and lstat must still see the link — this disagreement IS the defect");

    const d = clone();
    d.paths.clerkStamps = { value: join(link, "clerk-subject-stamps.jsonl"), basis: BASIS_FIXTURE };
    let msg = "";
    try {
      validateDeclarations(d);
      assert(false, "a path through a DANGLING symlink was ACCEPTED — the walk climbed past it");
    } catch (err) {
      msg = err instanceof Error ? err.message : String(err);
    }
    assert(/symbolic link/.test(msg), `the refusal must name the link: ${msg}`);
    assert(msg.includes(link), `the refusal must name WHICH component: ${msg}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

check("ACT B · CODEX 1b: a LIVE symlink is refused too — the rule is about links, not danglingness", () => {
  const dir = mkdtempSync(join(tmpdir(), "mica-decl-symlink2-"));
  const target = join(dir, "real");
  writeFileSync(target, "{}", "utf8");
  const link = join(dir, "alias");
  symlinkSync(target, link);
  try {
    let msg = "";
    try {
      const d = clone();
      d.paths.clerkStamps = { value: link, basis: BASIS_FIXTURE };
      validateDeclarations(d);
      assert(false, "a LIVE symlink was accepted");
    } catch (err) { msg = err instanceof Error ? err.message : String(err); }
    assert(/symbolic link/.test(msg), `a live link must refuse too: ${msg}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

check("ACT B · CODEX 1c: a component that CANNOT BE STAT'D is REFUSED, not read as absent", () => {
  // ⛔ FINDING (1) OF THE THIRD READ, AND IT NEEDS ITS OWN TEST OR I AM REPEATING
  // THE MISTAKE FINDING (2) CAUGHT. A bare catch read EVERY lstat error as "this
  // component does not exist", so EACCES — a directory this process may not stat —
  // became a silent pass. The one case where we CANNOT SEE what a component is was
  // the one case treated as harmless.
  //
  // ENOENT is genuinely absent and still breaks the walk. Anything else refuses.
  const dir = mkdtempSync(join(tmpdir(), "mica-decl-eacces-"));
  const closed = join(dir, "closed");
  mkdirSync(closed);
  writeFileSync(join(closed, "target.jsonl"), "{}", "utf8");
  chmodSync(closed, 0o000);            // lstat on the CHILD now gives EACCES
  try {
    let msg = "";
    try {
      const d = clone();
      d.paths.clerkStamps = { value: join(closed, "target.jsonl"), basis: BASIS_FIXTURE };
      validateDeclarations(d);
      assert(false, "an unstattable component was ACCEPTED — the walk read EACCES as absent");
    } catch (err) { msg = err instanceof Error ? err.message : String(err); }
    assert(
      /cannot be checked|symbolic link/.test(msg),
      `the refusal must say the component could not be checked: ${msg}`
    );
  } finally {
    chmodSync(closed, 0o755);
    rmSync(dir, { recursive: true, force: true });
  }
});

// ── SHAPE (b) · THE BRIDGE'S OWN BOOK IS THE WITNESS ────────────────────────
//
// An empty stamps file is either "the carrier has never run" — its designed first
// state, which must go blind and say so — or "somebody emptied it", which is
// tampering and must refuse. ZERO BYTES IS ZERO BYTES: the stamps file cannot
// answer the question about itself.
//
// ⛔ THE CURSOR VERSION OF THIS WITNESS IS GONE, AND THE REASON IS WORTH THE
// PARAGRAPH BECAUSE THE TESTS BELOW LOOK ALMOST THE SAME. It read the CARRIER'S
// cursor file, which the carrier writes only after a successful carry — a claim
// made at a time when it was true. Codex FAILED it on 2026-09-29: the cursor and
// the stamps file sit in ONE directory under ONE principal and are CO-DELETABLE.
// Erase both and the pair presents as FILE_EMPTY_OR_ERASED + ABSENT, which is
// byte-for-byte what a genuine first run presents. THE WITNESS WAS INSIDE THE
// REACH OF THE THING IT WAS WATCHING, and a witness that the suspect can remove
// is not a witness — it only raises the price of one particular clumsy attack.
//
// SHAPE (b), the arbiter's ruling: the witness is a record the BRIDGE writes in its own
// HASH-CHAINED book, naming the chain genesis it belongs to. Different principal,
// and a container where removal is not a delete but a CHAIN BREAK — which every
// reader on this box already detects and reports by name.

check("(b) · prior load PRESENT + stamps EMPTY = ERASURE, and it REFUSES", () => {
  assert(
    clerkStampsDisposition("FILE_EMPTY_OR_ERASED", "PRESENT") === "REFUSE",
    "this bridge recorded stamps for this chain and they are gone — that is not a first run"
  );
});

check("(b) · prior load ABSENT + stamps EMPTY = first run, disclosed", () => {
  assert(
    clerkStampsDisposition("FILE_EMPTY_OR_ERASED", "ABSENT") === "EMPTY_SOURCE",
    "nothing has ever loaded stamps for this chain, so an empty file is what should be there"
  );
});

check("(b) · prior load UNREADABLE + stamps EMPTY REFUSES — fail closed", () => {
  // ⛔ The one case where we CANNOT SEE is not the case to wave through. "I could
  // not check whether stamps were here before" is not "they were not".
  assert(clerkStampsDisposition("FILE_EMPTY_OR_ERASED", "UNREADABLE") === "REFUSE", "unreadable must refuse");
});

check("(b) · NOT_WITNESSED + stamps EMPTY is today's behaviour, so this half can land first", () => {
  assert(
    clerkStampsDisposition("FILE_EMPTY_OR_ERASED", "NOT_WITNESSED") === "EMPTY_SOURCE",
    "with no witness injected the erasure test is unavailable, and that is disclosed rather than assumed"
  );
});

check("(b) · a LOADED stamps file is USED whatever the book says", () => {
  for (const w of ["PRESENT", "ABSENT", "UNREADABLE", "NOT_WITNESSED"] as const) {
    assert(clerkStampsDisposition("LOADED", w) === "USE", `LOADED + ${w} must be USE`);
  }
});

check("(b) · every non-empty non-LOADED state still REFUSES whatever the book says", () => {
  for (const st of ["CUSTODY_REFUSED", "FILE_MALFORMED", "FILE_UNREADABLE", "FILE_ABSENT", "CANNOT_SEE"]) {
    for (const w of ["PRESENT", "ABSENT", "UNREADABLE", "NOT_WITNESSED"] as const) {
      assert(clerkStampsDisposition(st, w) === "REFUSE", `${st} + ${w} must refuse`);
    }
  }
});

check("(b) · THE CODEX CASE, PINNED: co-deleting the witness no longer reads as a first run", () => {
  // ⛔ THE ATTACK THAT FAILED THE CURSOR VERSION, written down as a test so the
  // repair cannot quietly regress to it. Under the cursor design, an attacker
  // with write access to the carrier's state directory erased BOTH files and the
  // pair returned EMPTY_SOURCE — indistinguishable from a first run.
  //
  // Under SHAPE (b) that same attacker holds NOTHING the witness depends on: the
  // record is in the bridge's hash-chained book, written by a different
  // principal. This test asserts the only thing a PURE FUNCTION can assert about
  // that — THAT THE ANSWER IS DECIDED BY THE BOOK AND BY NOTHING IN THE STAMPS
  // DIRECTORY. The custody claim itself is asserted where it lives, in the
  // service test that writes the record and then empties the file.
  assert(clerkStampsDisposition("FILE_EMPTY_OR_ERASED", "PRESENT") === "REFUSE", "witnessed erasure must refuse");
  assert(clerkStampsDisposition("FILE_EMPTY_OR_ERASED", "ABSENT") === "EMPTY_SOURCE", "unwitnessed empty is a first run");
  // The two differ ONLY in the witness argument — the loadState is identical.
  // That is the whole property: the stamps file has stopped being the source of
  // its own alibi.
});

// ── SHAPE (b) · THE READER, OVER A REAL CHAIN ───────────────────────────────
//
// The disposition tests above pin the RULE. These pin the READ — what the bridge
// actually gets back when it asks its own book the question, over bytes this
// test wrote.

// ── THE WITNESS IS DUE IFF F3 USED AT LEAST ONE STAMP, ASSERTED THROUGH F3 ───
//
// The arbiter's ruling, 2026-09-29 18:0xZ: drop the parallel counter. The bridge used
// to run `acceptedStampCount`, a second implementation of part of F3's
// admission. It was fixed twice — once for counting raw lines, once for ignoring
// the writer check — and both fixes were correct, and both were the same defect.
//
// ⛔ A COPY OF A JUDGEMENT CANNOT BE MADE RIGHT BY ITERATION, because the thing
// it copies keeps moving: T6 added the writer check, T7 the rejected-tail rule,
// T8 the chain identity. Each widened the gap silently, and the next divergence
// was already implied by the ones before it.
//
// So these checks drive F3 ITSELF and assert the number the witness now reads —
// `clerkStampCoverage.stampedCount` — across the five shapes the ruling names.

{
  const CHAIN = "chain-LIVE";
  const stamp = (seq: number, over: Record<string, unknown> = {}) => ({
    moduleId: "housekeeper",
    chainIdentity: CHAIN,
    sequenceNumber: seq,
    clerk_seq: seq + 1,
    clerk_time: { wall_ms: 1_700_000_000_000 + seq, monotonic_ns: String(seq + 1) },
    separation: "SEPARATE_PROCESS" as const,
    intake: "SOCKET" as const,
    clerk_id: "clerk-1",
    clerk_boot_id: "boot-1",
    ...over,
  });
  /** F3's OWN count of the stamps it used, over a real log this test writes. */
  const usedBy = (stamps: readonly unknown[]): number => {
    const dir = mkdtempSync(join(tmpdir(), "mica-used-"));
    try {
      const path = join(dir, "log.jsonl");
      const recs = [0, 1, 2].map((i) => ({
        sequenceNumber: i,
        timestamp: 1_000 * (i + 1),
        moduleId: "housekeeper",
        eventType: i % 2 === 0 ? "a" : "b",
        outcome: "ok",
      }));
      writeFileSync(path, recs.map((r) => JSON.stringify(r)).join("\n") + "\n", "utf8");
      const r = assessSig(new MicaLogFile({ path }), {
        readableLoadStates: ["LOADED_UNVERIFIED_FILE"],
        clockToleranceMs: 0,
        expectedChainIdentity: CHAIN,
        clerkClockSource: stamps,
      } as never);
      return (r as { clerkStampCoverage: { stampedCount: number } | null }).clerkStampCoverage?.stampedCount ?? 0;
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };

  check("witness iff F3 used >= 1 · CLEAN CARRY: every stamp joins, and the witness is due", () => {
    assert(usedBy([stamp(0), stamp(1), stamp(2)]) === 3, "a clean carry is used in full");
  });

  check("witness iff F3 used >= 1 · WRONG CHAIN: none used, no witness", () => {
    // T8's admission. The stamps are otherwise perfect.
    assert(
      usedBy([stamp(0, { chainIdentity: "chain-OTHER" }), stamp(1, { chainIdentity: "chain-OTHER" })]) === 0,
      "a foreign chain's stamps are refused before anything else"
    );
  });

  check("witness iff F3 used >= 1 · WRONG WRITER: none used, no witness", () => {
    // T6/T7. Right chain, right sequence, a writer the record does not have.
    assert(
      usedBy([stamp(0, { moduleId: "NOT/the-writer" }), stamp(1, { moduleId: "someone-else" })]) === 0,
      "a mislabelled stamp is discarded, never used"
    );
  });

  check("witness iff F3 used >= 1 · DUPLICATES: an ambiguous sequence is NOT used", () => {
    // ⛔ THE CASE THE PARALLEL COUNTER GOT WRONG BY CONSTRUCTION AND WOULD HAVE
    //   GONE ON GETTING WRONG. Two agreeing stamps at one sequence is a real
    //   ambiguity; F3 leaves that record unstamped. No counter reproducing only
    //   "admission + writer agreement" could ever have seen it — which is why
    //   the copy was not merely behind, it was unfixable in principle.
    assert(usedBy([stamp(0), stamp(0), stamp(1)]) === 1, "seq 0 is ambiguous and drops; seq 1 stands");
  });

  check("witness iff F3 used >= 1 · MISSING RECORDS: a stamp for a sequence the log lacks is not used", () => {
    assert(usedBy([stamp(99)]) === 0, "unjoinable");
    assert(usedBy([stamp(99), stamp(0)]) === 1, "and it does not poison the one that joins");
  });

  check("witness iff F3 used >= 1 · THE 678 — and WHICH MACHINE ANSWERS IS A RELAY-ORDER FACT", () => {
    // ⛔ THIS CHECK FOUND A RELAY-ORDER HAZARD AND IS WRITTEN TO KEEP FINDING IT.
    //
    //   `assessSig` here is the INSTALLED machine's, from /opt. T8 — which
    //   refuses a stamp carrying no chainIdentity — is in the machine half of
    //   Act B′ and IS NOT RELAYED. So today /opt's F3 JOINS the legacy stamps,
    //   and `stampedCount` counts them.
    //
    //   THE CONSEQUENCE, WHICH IS THE POINT: if the BRIDGE half landed BEFORE
    //   the machine half, the witness would read F3's own number, get 678, and
    //   mint a prior-load record on stamps that the shipped T8 refuses — after
    //   which every empty stamps file is a false ERASURE. The relay order
    //   (machine, then re-stamp, then bridge) is what makes that unreachable,
    //   and this assertion is where that order stops being a sentence in a brief
    //   and becomes a thing a test can fail on.
    //
    //   BOTH ARMS ARE ASSERTED AND NEITHER IS SKIPPED. It flips by itself when
    //   the machine half reaches /opt, so it is also a relay check.
    const legacy = [0, 1, 2].map((i) => {
      const st = stamp(i) as Record<string, unknown>;
      delete st.chainIdentity;
      return st;
    });
    const n = usedBy(legacy);
    if (n === 0) {
      // POST-RELAY: T8 is in /opt. Legacy stamps mint nothing, which is the
      // behaviour SHAPE (b) and T8 were built for.
      assert(true, "T8 is installed: unattributed stamps are refused");
    } else {
      // PRE-RELAY: /opt is pre-T8 and joins them. Assert the number exactly, so
      // a partial or surprising value cannot pass as "the old machine".
      assert(
        n === 3,
        `pre-T8 /opt joins unattributed stamps; expected all 3 used, got ${String(n)} — ` +
          "if this is neither 0 nor 3 the installed reader is neither the old one nor the new one"
      );
    }
  });
}

check("(b) · THE DUPLICATED LITERAL: this bridge's witness word matches the machine's, or says why it cannot check", () => {
  // ⛔ THE COUPLING THIS CLOSES, AND WHY IT IS A grep RATHER THAN AN import.
  //
  //   The witness eventType exists TWICE — here, for the writer and the reader,
  //   and in the machine's journal, for the validator's forgery guard. It is not
  //   an import because this file imports from /opt/mica-machine: importing it
  //   would make the bridge fail to COMPILE until the machine half relays, a
  //   build-order coupling on a string literal. The cost was named in the commit
  //   that introduced it and a cross-check was owed.
  //
  //   THIS IS THAT CROSS-CHECK, and it reads the machine's SOURCE AS TEXT
  //   precisely because it must work ACROSS the relay boundary — before the
  //   machine half lands there is nothing to import, and before the machine half
  //   lands is exactly when a disagreement would be introduced.
  //
  //   ⚠ IT IS TWO-ARMED AND NEITHER ARM IS A SILENT SKIP. If the constant is
  //   absent from /opt it asserts that it is absent FOR THE STATED REASON, so
  //   "the machine half has not relayed" cannot quietly become "the check found
  //   nothing and passed".
  const MACHINE = "/opt/mica-machine/src/glue/subject-event-journal.ts";
  if (!existsSync(MACHINE)) {
    assert(false, "the installed machine's journal source is not readable — this check cannot run");
    return;
  }
  const src = readFileSync(MACHINE, "utf8");
  const m = /CLERK_STAMPS_FIRST_LOAD_EVENT_TYPE\s*=\s*"([^"]*)"/.exec(src);
  if (m === null) {
    // PRE-RELAY: the machine half of SHAPE (b) is not in /opt yet.
    assert(
      !src.includes("CLERK_STAMPS_FIRST_LOAD"),
      "the machine names the witness word somewhere but not as the constant — the shapes have drifted"
    );
    return;
  }
  // POST-RELAY: the two literals must be identical, character for character.
  assert(
    m[1] === CLERK_STAMPS_FIRST_LOAD_EVENT_TYPE,
    `the bridge writes "${CLERK_STAMPS_FIRST_LOAD_EVENT_TYPE}" and the machine's validator ` +
      `accepts "${m[1]}" — the bridge would write a record the chain refuses, and the chain ` +
      "would stop loading on the first witness write"
  );
});

check("(b) · readPriorLoadWitness: an UNCHAINED logKind is NOT_WITNESSED, never a refusal", () => {
  // A deployment whose readers stand on a plain JSONL log has no witness
  // available. That is stated, not implied, and it must not refuse: the erasure
  // test is simply unavailable there.
  assert(readPriorLoadWitness("/no/such/file.jsonl", "mica") === "NOT_WITNESSED", "unchained");
});

check("(b) · readPriorLoadWitness: ABSENT on a fresh chain, PRESENT once the witness is in it", () => {
  const dir = mkdtempSync(join(tmpdir(), "mica-b-witness-"));
  const path = join(dir, "subject-events.jsonl");
  try {
    // A chain that is not there at all has nothing to have witnessed.
    assert(readPriorLoadWitness(path, "subject-chain") === "ABSENT", "an absent chain is ABSENT");

    const j = new SubjectEventJournal({ path });
    const b = j.appendBoundary(null, "first boot", 1000);
    assert(b.persisted, "the boundary must be written");
    assert(
      readPriorLoadWitness(path, "subject-chain") === "ABSENT",
      "a fresh chain has no witness — THAT IS THE FIRST-RUN STATE, and it is the one an " +
        "empty stamps file is allowed to sit beside"
    );

    const w = j.appendEvent((seq, previous) => ({
      recordType: "SUBJECT_EVENT",
      sequenceNumber: seq,
      previousHash: typeof previous?.hash === "string" ? previous.hash : "",
      timestamp: 2000,
      moduleId: SUBJECT_LOG_BOUNDARY_MODULE_ID,
      eventType: CLERK_STAMPS_FIRST_LOAD_EVENT_TYPE,
      outcome: "STAMPS_OBSERVED",
      stampCount: 678,
    }));
    assert(w.persisted, "the witness must be written");
    assert(
      readPriorLoadWitness(path, "subject-chain") === "PRESENT",
      "once the bridge has recorded a load, the answer must change"
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

check("(b) · THE CODEX PROPERTY: the witness is in a DIFFERENT FILE from the stamps it vouches for", () => {
  // ⛔ THIS IS THE WHOLE REPAIR, AND IT IS ONE ASSERTION. The cursor design put
  // the witness in the carrier's own state directory, beside the stamps — so an
  // attacker with write access there held BOTH, and deleting both presented as a
  // first run. Here the witness lives in the subject chain, which the carrier
  // READS and never writes.
  //
  // Asserted by construction: the function is given the READERS' log path, and
  // the stamps path is not an argument to it at all. Nothing that happens in the
  // stamps directory can change this answer.
  const dir = mkdtempSync(join(tmpdir(), "mica-b-custody-"));
  const chain = join(dir, "subject-events.jsonl");
  const stampsDir = join(dir, "carrier-state");
  try {
    mkdirSync(stampsDir);
    const j = new SubjectEventJournal({ path: chain });
    j.appendBoundary(null, "first boot", 1000);
    j.appendEvent((seq, previous) => ({
      recordType: "SUBJECT_EVENT",
      sequenceNumber: seq,
      previousHash: typeof previous?.hash === "string" ? previous.hash : "",
      timestamp: 2000,
      moduleId: SUBJECT_LOG_BOUNDARY_MODULE_ID,
      eventType: CLERK_STAMPS_FIRST_LOAD_EVENT_TYPE,
      outcome: "STAMPS_OBSERVED",
      stampCount: 678,
    }));
    assert(readPriorLoadWitness(chain, "subject-chain") === "PRESENT", "recorded");

    // The attacker's whole reach, exercised: empty the stamps, remove the
    // cursor, delete the directory's contents outright.
    writeFileSync(join(stampsDir, "stamps.jsonl"), "", "utf8");
    rmSync(stampsDir, { recursive: true, force: true });
    assert(
      readPriorLoadWitness(chain, "subject-chain") === "PRESENT",
      "⛔ THE WITNESS MUST SURVIVE THE DESTRUCTION OF THE ENTIRE STAMPS DIRECTORY. Under the " +
        "cursor design this is exactly the sequence that returned a first run."
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

check("(b) · a BROKEN chain is UNREADABLE, not ABSENT — an erasure that also broke the book refuses", () => {
  // ⛔ THE COMBINED ATTACK. If breaking the chain made the witness read ABSENT,
  // an attacker would only need to corrupt one line to turn an erasure back into
  // a first run — the co-deletion hole, reopened through the back door.
  const dir = mkdtempSync(join(tmpdir(), "mica-b-broken-"));
  const path = join(dir, "subject-events.jsonl");
  try {
    const j = new SubjectEventJournal({ path });
    j.appendBoundary(null, "first boot", 1000);
    const raw = readFileSync(path, "utf8").trimEnd().split("\n");
    const rec = JSON.parse(raw[0]) as Record<string, unknown>;
    rec.basis = "tampered";
    writeFileSync(path, JSON.stringify(rec) + "\n", "utf8");
    assert(
      readPriorLoadWitness(path, "subject-chain") === "UNREADABLE",
      "a chain that did not verify is a question unanswered, and the disposition refuses on it"
    );
    assert(
      clerkStampsDisposition("FILE_EMPTY_OR_ERASED", "UNREADABLE") === "REFUSE",
      "and the rule turns that into a refusal"
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

check("ACT B · EMPTY STAMPS FILE: the RULE says EMPTY_SOURCE, not REFUSE", () => {
  // ⛔ THE HAZARD S11 WOULD HAVE ARMED, found in the arbiter's own terminal output on
  // 2026-09-28 and not by a test: between 22:05Z and 22:23Z the stamps file was
  // ZERO BYTES, and the door returns FILE_EMPTY_OR_ERASED for that — not LOADED.
  // The loader threw on anything but LOADED, so with the path declared EVERY
  // DECISION WOULD HAVE THROWN: not F3 blind, the box unable to decide.
  //
  // An empty stamps file is the carrier's DESIGNED FIRST STATE. It goes blind and
  // says so — F3's own words distinguish "an EMPTY clerkClockSource was injected"
  // from "no clerkClockSource was injected" — and it does not take decisions down.
  const d = clerkStampsDisposition("FILE_EMPTY_OR_ERASED");
  assert(d === "EMPTY_SOURCE", `FILE_EMPTY_OR_ERASED must be EMPTY_SOURCE, got ${d}`);
});

check("ACT B · EMPTY STAMPS FILE: LOADED is the only state that is USED", () => {
  const d = clerkStampsDisposition("LOADED");
  assert(d === "USE", `LOADED must be USE, got ${d}`);
});

check("ACT B · EMPTY STAMPS FILE: every OTHER state REFUSES — tampering must be loud", () => {
  for (const st of [
    "CUSTODY_REFUSED", "FILE_MALFORMED", "FILE_UNREADABLE", "FILE_ABSENT",
    "CANNOT_SEE", "INVOKER_WRITABLE", "INVOKER_IS_ROOT", "CLERK_INTERNAL",
  ]) {
    assert(clerkStampsDisposition(st) === "REFUSE", `${st} must refuse, got ${clerkStampsDisposition(st)}`);
  }
});

check("ACT B · THE ARBITER'S WIDENING: a BARE STRING is refused — the envelope is the point", () => {
  // The eight required paths stay plain strings. This one carries a basis, because
  // it is the only key in the block naming a file ANOTHER PRINCIPAL writes. A bare
  // string is refused rather than accepted-and-undocumented: the reason to widen the
  // shape was that this path must say why it is trusted.
  const d = clone();
  (d.paths as Record<string, unknown>).clerkStamps = "/var/lib/mica/clerk-subject-stamps.jsonl";
  assertRejected(() => validateDeclarations(d), "paths.clerkStamps");
});

check("ACT B · THE ARBITER'S WIDENING: a SHORT basis is refused", () => {
  const d = clone();
  (d.paths as Record<string, unknown>).clerkStamps = {
    value: "/var/lib/mica/clerk-subject-stamps.jsonl",
    basis: "because",
  };
  assertRejected(() => validateDeclarations(d), "paths.clerkStamps.basis");
});

check("ACT B · THE ARBITER'S WIDENING: an UNKNOWN key inside the envelope is refused", () => {
  const d = clone();
  (d.paths as Record<string, unknown>).clerkStamps = {
    value: "/var/lib/mica/clerk-subject-stamps.jsonl",
    basis: BASIS_FIXTURE,
    proxy: true,
  };
  assertRejected(() => validateDeclarations(d), "paths.clerkStamps");
});

check("ACT B · THE ARBITER'S WIDENING: the other eight stay PLAIN STRINGS", () => {
  const loaded = validateDeclarations(clone()).declarations;
  for (const k of ["journal", "eventBook", "subjectLog", "decisionEvents", "floorTrail", "ledger", "history", "noticeDir"]) {
    assert(
      typeof (loaded.paths as Record<string, unknown>)[k] === "string",
      `paths.${k} must remain a bare string — only clerkStamps carries a basis`
    );
  }
});

check("ACT B · CODEX 1b: a path with NO link component still loads — the rule refuses links, not paths", () => {
  const d = clone();
  d.paths.clerkStamps = { value: "/var/lib/mica/clerk-subject-stamps.jsonl", basis: BASIS_FIXTURE };
  const loaded = validateDeclarations(d).declarations;
  assert(loaded.paths.clerkStamps !== undefined, "a link-free path must still load");
});

check("ACT B · CODEX 3: the fixture MIRRORS the serving declaration's kind", () => {
  // Codex, 2026-09-28: the fixture exists so these tests prove the SERVING
  // claims. If it drifts from the box, every test here is about a shape nobody
  // runs. ⚠ This does NOT settle the ruling-5 discrepancy — see the fixture's
  // own logKind basis and the board.
  assert(
    draft.readers.logKind.value === shipped.readers.logKind.value,
    `the fixture's logKind must mirror what SERVES, read from declarations.config.json — ` +
      `fixture ${String(draft.readers.logKind.value)}, shipped ${String(shipped.readers.logKind.value)}`
  );
});

// ── GATE 1 · Stop 2 · top-level `frame` and `readers.gate1Scope` ─────────────
//
// WHAT THESE ARMS ARE FOR. Gate 1's envelope recorder reads labels the bridge
// derives from a DECLARED frame, so the frame is the one input that decides
// every label. Each refusal the spec names gets its own arm, named by the field
// the loader must cite; the parity walk above probes the new closed nodes
// through the fifth base; and the arms below pin what the schema CAN say against
// what only the loader can.
//
// ⛔ THE HELPERS ARE FUNCTION DECLARATIONS WITH NO MODULE-LEVEL CONSTANT, ON
//    PURPOSE: the parity walk's fifth base calls `g1Declared` from a check that
//    runs ~1700 lines ABOVE this block, synchronously, at its own position. A
//    `const` read from there would be in its temporal dead zone and throw.

/** A basis for fixture envelopes. A function, not a const — see the block comment. */
function g1Basis(): string {
  return "GATE 1 FIXTURE, not a declaration. Exercises the loader's frame rules.";
}

/** The fixture plus a second subject, bound to the fixture's own subject peer (no uid typed here). */
function g1Base(subjectId: string): any {
  const d = clone();
  const s0 = d.subjects[0];
  d.subjects.push({ subject: subjectId, toolName: "tool-x", stakesClass: s0.stakesClass, peerUid: s0.peerUid });
  return d;
}

/** A well-formed frame: three grounded categories, one self, three nested regions. */
function g1Frame(): any {
  return {
    categories: {
      value: [
        { id: "c-self", label: "the subject's own working area", grounding: "agency", self: true },
        { id: "c-other", label: "another principal's area", grounding: "vulnerability", self: false },
        { id: "c-shared", label: "shared system area", grounding: "need", self: false },
      ],
      basis: g1Basis(),
      proxy: true,
    },
    regions: {
      value: [
        { prefix: "/srv/a", category: "c-self" },
        { prefix: "/srv/a/b", category: "c-other" },
        { prefix: "/", category: "c-shared" },
      ],
      basis: g1Basis(),
      proxy: true,
    },
  };
}

/** The interest book's path for fixtures. A function, not a const — see the block comment. */
function g1BookPath(): string {
  return "/var/lib/mica-bridge/interest-book.jsonl";
}

/** The base with a frame for `subjectId`, the reader switched on for it, and (X22) the book it reads. */
function g1Declared(subjectId = "subject-a"): any {
  const d = g1Base(subjectId);
  d.frame = { [subjectId]: g1Frame() };
  d.readers.gate1Scope = { subject: { value: subjectId, basis: g1Basis(), proxy: false } };
  d.paths.interestBook = g1BookPath();
  return d;
}

/**
 * Defines `key` as an OWN, enumerable property — what JSON.parse of a real file
 * gives. A plain `obj["__proto__"] = v` would run the prototype setter and
 * define no key at all, which is exactly the trap R-a refuses.
 */
function g1DefineOwn(obj: any, key: string, value: unknown): void {
  Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
}

/** assertRejected, plus the refusal's MESSAGE — two rules that cite one field are two findings. */
function assertRejectedSaying(fn: () => void, expectField: string, fragment: string): void {
  try {
    fn();
  } catch (err) {
    if (!(err instanceof DeclarationRejected)) throw err;
    assert(err.field === expectField, `expected rejection field "${expectField}", got "${err.field}" (${err.message})`);
    assert(err.message.includes(fragment), `the refusal at ${expectField} does not say "${fragment}": ${err.message}`);
    return;
  }
  throw new Error(`expected DeclarationRejected naming "${expectField}", nothing was thrown`);
}

check("GATE 1: a frame + readers.gate1Scope LOAD through BOTH front doors and survive validation WHOLE", () => {
  const d = g1Declared();
  let loaded: Declarations;
  try {
    loaded = validateDeclarations(d).declarations;
  } catch (err) {
    if (err instanceof DeclarationRejected) {
      throw new Error(
        `the gate 1 declaration was REFUSED at "${err.field}": ${err.message}. If the field is "$.frame" or ` +
          `"readers.gate1Scope", a front door's allow-list is missing its key and the reader is unreachable.`
      );
    }
    throw err;
  }
  // ⛔ CANONICAL EQUALITY, NOT A KEY CHECK: a validator that dropped a region or
  //    defaulted a flag would still leave the key present.
  assert(
    canonicalHash(loaded.frame) === canonicalHash(d.frame),
    `the loaded frame is not the declared frame:\n  declared ${JSON.stringify(d.frame)}\n  loaded   ${JSON.stringify(loaded.frame)}`
  );
  assert(
    canonicalHash(loaded.readers.gate1Scope) === canonicalHash(d.readers.gate1Scope),
    `the loaded gate1Scope is not the declared one: ${JSON.stringify(loaded.readers.gate1Scope)}`
  );
});

check("GATE 1: declaring the frame MOVES the declaration hash, and so does gate1Scope on top of it — both are INSIDE the digest", () => {
  const flat = validateDeclarations(g1Base("subject-a")).declarationHash;
  // X22, second half: a frame needs its book, so the book is declared first and
  // the frame's own move is measured against the book-only declaration.
  const bookOnly = g1Base("subject-a");
  bookOnly.paths.interestBook = g1BookPath();
  const withBook = validateDeclarations(bookOnly).declarationHash;
  const framed = g1Base("subject-a");
  framed.paths.interestBook = g1BookPath();
  framed.frame = { "subject-a": g1Frame() };
  const withFrame = validateDeclarations(framed).declarationHash;
  assert(withBook !== flat, "declaring paths.interestBook did NOT move the hash");
  const withBoth = validateDeclarations(g1Declared()).declarationHash;
  assert(withFrame !== withBook, "declaring frame did NOT move the hash — the validated frame is outside validate()'s returned object");
  assert(withBoth !== withFrame, "declaring readers.gate1Scope did NOT move the hash — the block is outside the digest");
  // And a change INSIDE the frame moves it too: the regions steer every label.
  const moved = g1Declared();
  moved.frame["subject-a"].regions.value[0].prefix = "/srv/z";
  assert(validateDeclarations(moved).declarationHash !== withBoth, "moving one region prefix did not move the hash");
});

check("GATE 1: undeclared, frame and gate1Scope are ABSENT KEYS and the fixture still hashes to EXPECTED_HASH", () => {
  const loaded = loadDeclarations(DRAFT_PATH);
  assert(!("frame" in loaded.declarations), "frame is a PRESENT key on a declaration that does not declare it");
  assert(!("gate1Scope" in loaded.declarations.readers), "gate1Scope is a PRESENT key on a declaration that does not declare it");
  assert(!("interestBook" in loaded.declarations.paths), "paths.interestBook is a PRESENT key on a declaration that does not declare it");
  assert(loaded.declarationHash === EXPECTED_HASH, `the fixture's hash MOVED: ${loaded.declarationHash}`);
});

check("S216 · the TREE declaration IS the S216 candidate: S36 (served) plus exactly a since on every grant and one sentence on G1's grant basis; S36 is S35 plus exactly the C1 clearance; S35 is S34 outside the pilot block", () => {
  // A DECLARATION ACT (S216, the grant since) re-pins here, in its own commit. The tree's bytes travel with the bridge
  // relay (the new loader refuses a grant without a since; the served loader refuses a since), so the two land as one act.
  const TREE_SHA256_S216 = "f8fd37fa29940617f002934d9693ec6a0dce6cd02ff0ad569768e0d77084781e";
  const TREE_HASH_S216 = "0e86d7eb80b371b3213ccefbb0c34e2e79717a5e4afed6b495f160ffad5f5057";
  const FILE_SHA256_S36 = "15abb12e5eb757915fd85c61dc17717fc6932a743c4004602f601815d912c0c8";
  const FILE_SHA256_S35 = "aa7f9c359a0c3bed8ecdd4802f53cc8d6fd6e0d6c99e5e22154d05e8496fb3d9";
  const OUTSIDE_PILOT_S34 = "5f389bfe9ac7a0514eb32123e808ef0ff192fbea4e02b4d6935cafb5aa5cc7e3";
  const G1_SENTENCE = " COUNTS FROM 2026-10-16T06:13:54.692Z (S216): the instant S34, the declaration that first granted it, was loaded; a G1 record earlier than that is harm whatever this grant says.";
  const sha = (t: string) => createHash("sha256").update(t).digest("hex");
  const bytes = readFileSync(SHIPPED_PATH, "utf8");
  assert(sha(bytes) === TREE_SHA256_S216, `declarations.config.json's bytes moved (sha256 ${sha(bytes)}). A declaration act re-pins both constants here, in its own commit.`);
  const loaded = loadDeclarations(SHIPPED_PATH);
  assert(loaded.declarationHash === TREE_HASH_S216, `the tree declarationHash MOVED: ${loaded.declarationHash}, predicted ${TREE_HASH_S216}`);
  const served = loaded.declarations.subjects[0].subject;
  const grants = loaded.declarations.harm![served].grants.value;
  for (const id of Object.keys(grants)) {
    assert(JSON.stringify(Object.keys(grants[id].since).sort()) === JSON.stringify([...grants[id].origins].sort()), `item ${id}: since names exactly its origins`);
  }
  // S216 → S36, byte for byte: drop every since and the one sentence.
  const s36 = JSON.parse(bytes);
  for (const g of Object.values(s36.harm[served].grants.value) as { since?: unknown; basis: string }[]) delete g.since;
  const withSentence = Object.values(s36.harm[served].grants.value).filter((g) => (g as { basis: string }).basis.endsWith(G1_SENTENCE));
  assert(withSentence.length === 1, "exactly one grant basis carries the since sentence");
  (withSentence[0] as { basis: string }).basis = (withSentence[0] as { basis: string }).basis.slice(0, -G1_SENTENCE.length);
  assert(sha(JSON.stringify(s36, null, 2) + "\n") === FILE_SHA256_S36, "the tree minus its since is not the served S36 file — something else moved");
  // S36 → S35, byte for byte: the clearance is the only difference.
  assert(s36.harm[served].clearances.value.length === 1, "S36 carries one clearance");
  s36.harm[served].clearances.value = [];
  assert(sha(JSON.stringify(s36, null, 2) + "\n") === FILE_SHA256_S35, "S36 minus its clearance is not the S35 file");
  // S35 → S34: outside the pilot block they are one declaration (S35 moved only pilot 11's three leaves).
  delete s36.pilot;
  assert(canonicalHash(s36) === OUTSIDE_PILOT_S34, "outside the pilot, S35 is not S34");
});

check("GATE 1 + S201 + S26 → S28 → S29 → S30 → S31 → S32 → S33 → S34: S34 (read from its own commit ac55113 since S216 moved the tree) IS the S34 CANDIDATE (Gate 2 harm, ahead of the served S33 until its relay lands) — it loads to the predicted hash, declares the frame, both readers, the book and the HARM stanza for the served subject, and is S33 with exactly readers.gate2Direction.book/witnessMethod and harm[subject] added and baskets[subject] removed, which is S32 with exactly readers.nodeResponse.flatness.amiFloor and .minSample changed, which is S31 with exactly pilot 10's three leaves, which is S29 plus exactly the two witness paths outside the pilot, which is S28 plus exactly Gate 2's two leaves", () => {
  // ⛔ PINNED TWICE, AND THE TWO PINS ARE DIFFERENT CLAIMS. The byte digest says
  //    the tree file is the one the declaration act wrote; the declaration hash
  //    says the changed loader reads it to the predicted digest. If the bytes
  //    move, a declaration act happened and both pins are re-taken in its commit.
  // S26 (2026-10-08) IS SUCH AN ACT. The tree carries the candidate built by
  //   the project's build-s26.py (not shipped) from the LIVE S25b bytes plus exactly: S201's
  //   two leaves (the subject route's role word, subjects[0].unit), paths.interestBook,
  //   readers.gate1Scope, and frame — the arbiter's 2026-10-08 answers in the audit's
  //   15:43Z region translation, confirmed by the arbiter at 15:50Z (board). It rides
  //   to /opt as ONE code+declaration relay with --accept-declaration-change,
  //   after the machine: the new loader refuses the live file (the role word) and
  //   /opt's loader refuses this one (frame), so the two cannot be split.
  // S27 (2026-10-08, pilot 8) and S28 (2026-10-09, the self region → the subject's own home) were
  //   DECLARATION-ONLY relays: the live file moved on /opt and the tree did not. S198's copy-back
  //   brings the SERVED S28 bytes home (identical to the project's s28-candidate.json), so the next
  //   code relay carries the live declaration unchanged instead of reverting it to S26.
  // S29 (2026-10-09, Gate 2 declared, fork A) IS A DECLARATION ACT, and it rides the CODE relay:
  //   the project's build-s29.py (not shipped) from the LIVE S28 bytes plus exactly readers.gate2Direction
  //   (the subject by use) and baskets[<that subject>] — the arbiter's basket, booked by the audit
  //   2026-10-09 20:10Z ("A, basket as proposed, equal alarms"). /opt's loader refuses it
  //   ($.baskets), so it cannot be a declaration-only relay. RE-BUILT 2026-10-10 with NEUTRAL bases (the
  //   declaration is subject-readable; K2-adversary): was sha256 70a0ba98…, declarationHash 4c5bb176…; then
  //   4501355f… / 66ce024e… (one false sentence dropped from the classes basis, K2-verify).
  // S30 (2026-10-10, pilot 9) was a DECLARATION-ONLY relay: the live file moved on /opt and the tree did not, so a
  //   code relay of this tree would have met the declaration-hash gate with S29's hash and could only pass by
  //   --accept-declaration-change — replacing pilot 9 with S29 (S198, found by the audit 2026-10-11 15:27Z). The
  //   copy-back brings the SERVED S30 bytes home (= the project's s30-candidate.json), byte for byte. S30 is S29
  //   with exactly three leaves of the pilot changed: pilot.sessionId, pilot.expiresAt, pilot.holdAtOrAbove.basis.
  // S31 (2026-10-11, the witness's two paths) and S32 (2026-10-15, pilot 10) were DECLARATION-ONLY relays; the S211
  //   copy-back brings the SERVED S32 bytes home (= the project's s32-candidate.json), byte for byte. S32 is S31 with
  //   exactly three pilot leaves changed (sessionId, expiresAt, holdAtOrAbove.basis); S31 is S30 plus exactly
  //   paths.witnessIntake and paths.witnessBook; outside the pilot S30 is S29.
  // S33 (2026-10-15, op3's flatness floor recalibrated against the reshuffle null) was a DECLARATION-ONLY relay; this
  //   copy-back brings the SERVED S33 bytes home (= /opt/mica-bridge/mica-bridge/declarations.config.json =
  //   the project's s33-candidate.json), byte for byte. S33 is S32 with exactly two leaves changed, value and basis
  //   each: readers.nodeResponse.flatness.amiFloor (0.2 → 0.05) and readers.nodeResponse.flatness.minSample (3 → 175).
  //   Those two leaves were unchanged from S28 to S32 (their canonical hashes read equal on all five candidates), so
  //   the derivation below is taken WITHOUT them and every earlier step of it stands as it was proven.
  // S34 (2026-10-15, Long Run A Stop 2: Gate 2 reads HARM on the witness's book) IS A DECLARATION ACT THAT RIDES THE
  //   CODE RELAY — the REVERSE of a copy-back: the tree now LEADS the served bytes until the relay lands. It cannot be a
  //   declaration-only relay: /opt's loader refuses `harm`, and R15 refuses removing the served basket by SIGHUP ("any
  //   change to a declared basket takes a RESTART"). Built by the project's build-s34.py from the LIVE S33 bytes
  //   (= the project's s34-candidate.json, byte for byte). S34 is S33 plus exactly readers.gate2Direction.book and
  //   .witnessMethod and harm[<the served subject>], minus exactly baskets[<the served subject>]; so the derivation
  //   below is taken WITHOUT those (strip()), and every earlier step stands as proven.
  //   was (S33, served): sha256 db589af125ca21e3c878b296fe071fc1f33441d34578db7456e0b6df2c9cb10d
  //              declarationHash 4d7cb5e1dcc77336a28a92197f9d93cdb213dfd8cdf043fd5952fbbe8a2c8103
  //   was (derivation constants, WITH the basket): MINUS_FLATNESS_S32 b9434212…, OUTSIDE_PILOT_S31 31b6ac3e…,
  //              OUTSIDE_PILOT_S29 37df28e5… (OUTSIDE_PILOT_S28 unchanged: it already drops Gate 2's leaves)
  //   was (S32): sha256 db20a39c1beaea3884c781ad6f1bb3d94f84ca6c01e69d4f842dc46faa1563bd
  //              declarationHash 4c6534e0bca4b4d53b5e37ada2765429bc515598b3aaafb22385129c95edd2c9
  //   was (derivation constants, WITH the two flatness leaves): OUTSIDE_PILOT_S31 4a5eea6f…, OUTSIDE_PILOT_S29
  //              b8d9df5b…, OUTSIDE_PILOT_S28 5b5dceb9…
  //   was (S30): sha256 08fe2ad9994e55ffd7e7c7445d98ca292d7b65a675132476ffd480b52a7ad347
  //              declarationHash 79c0591568ea2850a2dad4505a44e1d76b4229ce10d3c68fd9df8956693754a5
  //   was (S29): sha256 8d855925feed63a63a0685db8444890158ed52b0ff6de1b01feafbcf87c3ead2
  //              declarationHash 749b83bd3dd36fb4e912d413ffc70a5a30ba1b69da959f96282e2d77c5bcbff0
  //   was (S28, served): sha256 edfe83562ead1fb233f36222f55e0592c90a7f4be2fdbc19f3bd8ef6394a4103
  //               declarationHash 24a1d317abcb9a637eb690bb75ca7734b59ee11a6772574f5e273026b5ec5087
  //   was (S26): sha256 0f16d55622b020d27af97a09e372ddab598336f9330980e647fc50262a7ed7d4
  //              declarationHash e3273edfef021f7c8dd99b915c62ca4e186653f731b5fdabfd5a3504e4581803
  //   was (S201): sha256 aba02aa31620be226bb097d145ac1bff6dca67e3175f1ea93a310cc74709f583
  //               declarationHash 0b401ce2434fe7a29c61bd4565a7b8770e0627b6be56c0b876b1a1d1d1c3cfa3
  //   was (served, d087f0b): sha256 7820478a7f8de3269d2744d238fc9fb8dd303aab2e118a7cbf4a94407e51c9b6
  //               declarationHash a866a90232686690bb985f8675d0554a0992c02d70c761f4758d4082c6644e76
  const TREE_SHA256_S34 = "41a13695c8b55c1441414ae13e57a1660e91b578a318d299b172385715f4eec6";
  // = the declarationHash the S34 relay must serve: PREDICTED by this tree's loader (the seat's load-check,
  //   2026-10-15), not yet read off /status — /opt serves S33 until the code relay lands.
  const TREE_HASH_S34 = "72523b54f70339bddbb508582627fca660053e9ecbcbe86c22a72ac90275f6a3";
  // S34 stripped of its Gate-2 harm leaves IS S33 stripped of its basket (the S33 file, db589af1…, canonical-hashed).
  const MINUS_HARM_S33 = "92ded1c4f6f7f28aa736a263abdb0d1e38ec76751efee9ae2524ee43e66966e0";
  // S33 without the two flatness leaves IS S32 without them (the S32 file, db20a39c…) — stripped, from S34 on.
  const MINUS_FLATNESS_S32 = "329f21f5b0877695f60f7b38ae98a8e9e06df1eac997937eb82bc3736c24639a";
  // S32 without `pilot` IS S31 without `pilot` (the S31 file, 4acc44a5…, canonical-hashed) — taken without the two
  // flatness leaves from here on (and stripped, from S34 on).
  const OUTSIDE_PILOT_S31 = "2dfbd4696eb081abf9160549a2336c032be4426a8afe2153b42c4a65dea59b50";
  // THE DERIVATION, pinned as canonical hashes of S29's and S28's own bytes (git: HEAD~ and 8c01ccd), so no earlier
  // text is copied here: outside `pilot` S30 IS S29; inside it, all but the three pilot-9 leaves are S29's; and S30
  // without `pilot` and Gate 2's two leaves IS S28 without `pilot`. (Without the two flatness leaves, since S33.)
  const OUTSIDE_PILOT_S29 = "37608cac5046ff98a172d4570f309c9cd1ccdccc8bae68e5174d1341fbac14d6";
  const PILOT_RESIDUE_S29 = "4a1ee4df52575e9deb9c625152c942e1709878f95ecf1b830e93a193e60b2b4d";
  const OUTSIDE_PILOT_S28 = "58698fb74ad0ddcbc0e5a0cf6ef08466fa41566112efe1d273fafab656e4f579";
  // S216 MOVED THE TREE PAST S34. This chain is S34's and is kept whole: it reads S34's OWN bytes from the commit that
  // laid them (ac55113); the S216 → S36 → S35 → S34 links are the next check's, at bytes.
  const S34_DIR = mkdtempSync(join(tmpdir(), "s34-"));
  const S34_PATH = join(S34_DIR, "declarations.config.json");
  writeFileSync(S34_PATH, execFileSync("git", ["-C", __dirname, "show", "ac55113:mica-bridge/declarations.config.json"]));
  const s34 = JSON.parse(readFileSync(S34_PATH, "utf8"));
  const bytesSha = createHash("sha256").update(readFileSync(S34_PATH)).digest("hex");
  assert(
    bytesSha === TREE_SHA256_S34,
    `declarations.config.json's bytes moved (sha256 ${bytesSha}). A declaration act re-pins both constants here, in its own commit.`
  );
  // S34's grants carry no since, so S216's loader refuses them (by design). The chain reads S34 as S34's loader
  // did: its declarationHash IS canonicalHash over the raw document (checked for S34 and for the S216 tree).
  const loaded = { declarations: JSON.parse(readFileSync(S34_PATH, "utf8")), declarationHash: canonicalHash(s34) };
  // BY USE, never by name: the served subject is the declaration's own subjects[0].
  const served = loaded.declarations.subjects[0].subject;
  assert(loaded.declarations.subjects.length === 1, "the tree declares more than the one served subject");
  assert(loaded.declarations.frame !== undefined && Object.hasOwn(loaded.declarations.frame, served), "the tree declares no frame for its served subject");
  assert(loaded.declarations.readers.gate1Scope?.subject.value === served, "readers.gate1Scope does not name the served subject");
  assert(typeof loaded.declarations.paths.interestBook === "string", "the tree declares a frame and the reader but no paths.interestBook");
  assert(loaded.declarations.readers.gate2Direction?.subject.value === served, "readers.gate2Direction does not name the served subject");
  // S34: the HARM stanza replaces the class basket for the served subject (H9), and Gate 2 reads the witness's book.
  assert(loaded.declarations.harm !== undefined && Object.hasOwn(loaded.declarations.harm, served), "the tree declares Gate 2's reader but no harm stanza for the served subject");
  assert(loaded.declarations.baskets === undefined || !Object.hasOwn(loaded.declarations.baskets, served), "S34 still declares the served subject's class basket");
  assert(loaded.declarations.readers.gate2Direction?.book?.value === "witnessBook" && /^[0-9a-f]{64}$/.test(loaded.declarations.readers.gate2Direction?.witnessMethod?.value ?? ""), "S34's Gate 2 does not read the witness's book by its method");
  assert(
    loaded.declarationHash === TREE_HASH_S34,
    `the tree declarationHash MOVED under the changed loader: ${loaded.declarationHash}, predicted ${TREE_HASH_S34}`
  );
  // S34 IS S33 WITH EXACTLY THE GATE-2 HARM LEAVES: stripped of book, witnessMethod, harm[served] (and of
  // baskets[served], which S34 no longer has), it equals S33 stripped of baskets[served].
  const stripped = JSON.parse(JSON.stringify(s34));
  delete stripped.readers.gate2Direction.book;
  delete stripped.readers.gate2Direction.witnessMethod;
  delete stripped.harm;
  if (stripped.baskets !== undefined) {
    delete stripped.baskets[served];
    if (Object.keys(stripped.baskets).length === 0) delete stripped.baskets;
  }
  assert(canonicalHash(stripped) === MINUS_HARM_S33, "without its Gate-2 harm leaves, the tree is not S33 without its basket — something else moved");
  // S33 IS S32 WITH EXACTLY THE TWO FLATNESS LEAVES' value AND basis CHANGED: both present, same key set as S32's,
  // and `proxy` still true on both as it was in S32 (so only value and basis can have moved inside them).
  const flatness = s34.readers.nodeResponse.flatness;
  for (const leaf of [flatness.amiFloor, flatness.minSample]) {
    assert(Object.keys(leaf).sort().join(",") === "basis,proxy,value", "S33's amiFloor / minSample are not {value, basis, proxy}");
    assert(leaf.proxy === true, "S33's amiFloor / minSample proxy moved from S32's true");
  }
  const minusFlatness = JSON.parse(JSON.stringify(stripped));
  delete minusFlatness.readers.nodeResponse.flatness.amiFloor;
  delete minusFlatness.readers.nodeResponse.flatness.minSample;
  assert(canonicalHash(minusFlatness) === MINUS_FLATNESS_S32, "without amiFloor and minSample, the tree is not S32 — something besides op3's floor moved");
  // S32 IS S31 WITH EXACTLY PILOT 10's THREE LEAVES; S31 IS S30 PLUS EXACTLY THE TWO WITNESS PATHS; OUTSIDE THE PILOT
  // S30 IS S29; and S29 IS S28 PLUS EXACTLY GATE 2's TWO LEAVES.
  const minusPilotWithWitness = JSON.parse(JSON.stringify(minusFlatness));
  delete minusPilotWithWitness.pilot;
  assert(canonicalHash(minusPilotWithWitness) === OUTSIDE_PILOT_S31, "outside the pilot, the tree is not S31 — something besides pilot 10 moved");
  const minusPilot = JSON.parse(JSON.stringify(minusPilotWithWitness));
  delete minusPilot.paths.witnessIntake;
  delete minusPilot.paths.witnessBook;
  assert(canonicalHash(minusPilot) === OUTSIDE_PILOT_S29, "outside the pilot and the two witness paths, the tree is not S29 — something else moved");
  const residue = JSON.parse(JSON.stringify(s34.pilot));
  delete residue.sessionId;
  delete residue.expiresAt;
  delete residue.holdAtOrAbove.basis;
  assert(canonicalHash(residue) === PILOT_RESIDUE_S29, "the pilot differs from S29's (and S31's) beyond sessionId, expiresAt and holdAtOrAbove.basis");
  const minusGate2 = JSON.parse(JSON.stringify(minusPilot));
  delete minusGate2.readers.gate2Direction;
  delete minusGate2.baskets;
  assert(
    canonicalHash(minusGate2) === OUTSIDE_PILOT_S28,
    "outside the pilot, the tree without readers.gate2Direction and baskets is not S28 — something else moved"
  );
  // And the structural reason, which survives a re-pin: the loader returns the
  // parsed document whole — it adds no key and drops none.
  assert(
    loaded.declarationHash === canonicalHash(s34),
    "the tree declarationHash is not the canonical hash of the tree bytes — the loader added or dropped a key"
  );
});

// ── the refusals, one arm each, in the spec's order ──────────────────────────

check("GATE 1 X16: a frame keyed by a name that is NO declared subject is REFUSED at that key", () => {
  const d = g1Declared();
  d.frame["subject-b"] = g1Frame();
  assertRejectedSaying(() => validateDeclarations(d), "frame.subject-b", "X16");
});

check("GATE 1: FEWER THAN TWO categories is REFUSED — a one-category M has no distribution", () => {
  const d = g1Declared();
  const cat = d.frame["subject-a"].categories;
  cat.value = [cat.value[0]];
  d.frame["subject-a"].regions.value = [{ prefix: "/srv/a", category: "c-self" }];
  assertRejectedSaying(() => validateDeclarations(d), "frame.subject-a.categories.value", "at least 2");
  cat.value = [];
  assertRejectedSaying(() => validateDeclarations(d), "frame.subject-a.categories.value", "at least 2");
});

check("GATE 1: a DUPLICATE category id is REFUSED at the second occurrence", () => {
  const d = g1Declared();
  d.frame["subject-a"].categories.value[2].id = "c-other";
  assertRejectedSaying(() => validateDeclarations(d), "frame.subject-a.categories.value[2].id", "duplicate");
});

check("GATE 1: a category id outside ^[A-Za-z0-9_.:-]+$ is REFUSED", () => {
  for (const bad of ["c other", "", "c/other", 7]) {
    const d = g1Declared();
    d.frame["subject-a"].categories.value[1].id = bad;
    assertRejectedSaying(() => validateDeclarations(d), "frame.subject-a.categories.value[1].id", "must be a non-empty string");
  }
});

check("GATE 1 X17: the category id UNDERIVED is REFUSED — it is the word for an act placed in no region", () => {
  const d = g1Declared();
  d.frame["subject-a"].categories.value[1].id = "UNDERIVED";
  d.frame["subject-a"].regions.value[1].category = "UNDERIVED";
  assertRejectedSaying(() => validateDeclarations(d), "frame.subject-a.categories.value[1].id", "X17");
});

check("GATE 1 X17: a category id equal to ANY declared toolName is REFUSED — pre-derivation records carry it as their outcome", () => {
  // Both subjects' tools: the frame's own subject's (`tool-x`) and the OTHER
  // subject's, read from the fixture rather than typed. "ANY" is the rule.
  const d0 = g1Declared();
  for (const tool of ["tool-x", d0.subjects[0].toolName as string]) {
    const d = g1Declared();
    d.frame["subject-a"].categories.value[2].id = tool;
    d.frame["subject-a"].regions.value[2].category = tool;
    assertRejectedSaying(() => validateDeclarations(d), "frame.subject-a.categories.value[2].id", "toolName");
  }
});

check("GATE 1: an EMPTY label is REFUSED", () => {
  const d = g1Declared();
  d.frame["subject-a"].categories.value[0].label = "";
  assertRejectedSaying(() => validateDeclarations(d), "frame.subject-a.categories.value[0].label", "non-empty");
});

check("GATE 1 · R-d: an UNTAGGED category is REFUSED, and the refusal calls grounding a DECLARED TAG — it claims no verified grounding", () => {
  // Review C1-3: the old message said "ill-formed (03a §6)", which reads as if
  // canon's operational grounding (F10, the hollow frame) were checked. It is
  // not: the loader checks the WORD. The refusal must say so, and must not say
  // "ill-formed".
  const d = g1Declared();
  d.frame["subject-a"].categories.value[1].grounding = "preference";
  assertRejectedSaying(() => validateDeclarations(d), "frame.subject-a.categories.value[1].grounding", "DECLARED TAG");
  try {
    validateDeclarations(d);
  } catch (err) {
    assert(!(err as Error).message.includes("ill-formed"), `the grounding refusal still claims ill-formedness: ${(err as Error).message}`);
  }
  // The schema's own text says the same, read from the committed bytes.
  const desc: string = committedSchema.$defs.subjectFrame.properties.categories.properties.value.items.properties.grounding.description;
  assert(desc.includes("DECLARED TAG") && !desc.includes("ill-formed and rejected"), `schema grounding description: ${desc}`);
  // And a purely symbolic category with a tag LOADS — the ceiling, pinned.
  const hollow = g1Declared();
  hollow.frame["subject-a"].categories.value[1].label = "anyone on allow-list L (purely symbolic)";
  validateDeclarations(hollow);
  delete d.frame["subject-a"].categories.value[1].grounding;
  assertRejectedSaying(() => validateDeclarations(d), "frame.subject-a.categories.value[1].grounding", "required field missing");
});

check("GATE 1 X18: NOT EXACTLY ONE self — none and two are both REFUSED; one loads", () => {
  const none = g1Declared();
  none.frame["subject-a"].categories.value[0].self = false;
  assertRejectedSaying(() => validateDeclarations(none), "frame.subject-a.categories.value", "found 0");
  const two = g1Declared();
  two.frame["subject-a"].categories.value[2].self = true;
  assertRejectedSaying(() => validateDeclarations(two), "frame.subject-a.categories.value", "found 2");
  const wrongType = g1Declared();
  wrongType.frame["subject-a"].categories.value[1].self = "no";
  assertRejectedSaying(() => validateDeclarations(wrongType), "frame.subject-a.categories.value[1].self", "boolean");
  validateDeclarations(g1Declared());
});

check("GATE 1: EMPTY regions LOAD — nothing derivable, every label UNDERIVED, and that is legal and honest", () => {
  const d = g1Declared();
  d.frame["subject-a"].regions.value = [];
  const loaded = validateDeclarations(d).declarations;
  assert(
    loaded.frame !== undefined && loaded.frame["subject-a"].regions.value.length === 0,
    `an empty region list must load as an empty list: ${JSON.stringify(loaded.frame)}`
  );
  const missing = g1Declared();
  delete missing.frame["subject-a"].regions.value;
  assertRejectedSaying(() => validateDeclarations(missing), "frame.subject-a.regions.value", "required field missing");
});

check("GATE 1: a region prefix that cannot be matched honestly is REFUSED; the honest spellings LOAD", () => {
  // The bridge matches against a canonical target that does NOT resolve "." or
  // "..", segment-aware; a prefix outside these rules would claim a place it is not.
  const refused: ReadonlyArray<[unknown, string]> = [
    ["srv/a", "absolute"],
    ["", "absolute"],
    ["/srv//a", '"//"'],
    ["//", '"//"'],
    ["/srv/a/", 'end in "/"'],
    ["/srv/./a", '"." or ".."'],
    ["/srv/../a", '"." or ".."'],
    ["/srv/..", '"." or ".."'],
    ["/.", '"." or ".."'],
    [42, "must be a string"],
  ];
  for (const [prefix, why] of refused) {
    const d = g1Declared();
    d.frame["subject-a"].regions.value[0].prefix = prefix;
    assertRejectedSaying(() => validateDeclarations(d), "frame.subject-a.regions.value[0].prefix", why);
  }
  // Glob metacharacters are literal (the static directory is a real claim), and
  // "..." or ".hidden" are names, not traversal.
  for (const ok of ["/srv/x-*", "/srv/...", "/srv/.hidden", "/srv/a.b/c"]) {
    const d = g1Declared();
    d.frame["subject-a"].regions.value[0].prefix = ok;
    validateDeclarations(d);
  }
});

check("GATE 1 · ROUND 3 (A2): a prefix with a segment the LABEL RULE reads as not a path is REFUSED — a DEAD region counted derivable; the near misses LOAD", () => {
  // Reviews K2W-2, K3D2-1, K1R1-2, K1R2-1, K1R3-1, K2W-3, K2W3-4: the loader
  // admitted these, the wiring counted their category derivable, and every
  // target under them read UNDERIVED. The reviewers' own shapes, every one.
  const dead = [
    "/mnt/c/Program Files (x86)", "/srv/R&D", "/srv/a=b", "/home/op/~archive", "/srv/-scratch", "/srv/+inbox",
    "/srv/it's", "/srv/{x}", "/srv/node:20", "/srv/x:", "/srv/a$b", "/srv/a;b", "/srv/a|b", "/srv/a<b", "/srv/a\\b",
    "/srv/R&D/docs", "/warehouse/t/year=2024", "/srv/data(old)", "/mnt/c:", "/srv/a`b", '/srv/a"b',
    // round 3 re-verify NEW-K1R-1: whitespace — no whitespace-split R6 token can arrive under these
    "/srv/Program Files", "/srv/a\u00a0b", "/srv/a\u3000b",
  ];
  for (const prefix of dead) {
    const d = g1Declared();
    d.frame["subject-a"].regions.value[0].prefix = prefix;
    try {
      assertRejectedSaying(() => validateDeclarations(d), "frame.subject-a.regions.value[0].prefix", "NOT A PATH");
    } catch (err) {
      throw new Error(`${JSON.stringify(prefix)}: ${(err as Error).message}`);
    }
  }
  // NEAR MISSES that are real, placeable names: a "-" or "+" INSIDE a segment,
  // an npm scope's leading "@", a space, a glob — the label rule places under them.
  for (const ok of ["/srv/c++", "/srv/build+1", "/srv/x-1", "/srv/node_modules/@types", "/srv/a.b", "/srv/a@b"]) {
    const d = g1Declared();
    d.frame["subject-a"].regions.value[0].prefix = ok;
    validateDeclarations(d);
  }
});

check("GATE 1 · R-b: a prefix that is not ITS OWN CANONICAL FORM is REFUSED — NFD, NFC singletons, Unicode whitespace, control characters, over the byte cap", () => {
  // Reviews C3-1, C3-2, C4-1, C4-3. The bridge matches prefixes byte for byte
  // against canonical targets, and canonical-json hashes the NFC form; a
  // non-canonical prefix is a dead region or a second spelling the hash cannot
  // tell from the first. The bridge's own canonicaliser decides.
  const refused: ReadonlyArray<[string, string, string]> = [
    ["NFD e-acute", "/srv/cafe\u0301", "canonical form"],
    ["Ohm sign U+2126 (NFC singleton)", "/srv/\u2126", "canonical form"],
    ["Angstrom sign U+212B", "/srv/\u212bsa", "canonical form"],
    // round 3: whitespace is a NOT-A-PATH segment, refused before the canonical-form check runs
    ["trailing ASCII space", "/srv/a ", "NOT A PATH"],
    ["trailing NBSP", "/srv/a\u00a0", "NOT A PATH"],
    ["trailing U+3000", "/srv/a\u3000", "NOT A PATH"],
    ["trailing BOM", "/srv/a\ufeff", "NOT A PATH"],
    ["trailing newline", "/srv/a\n", "NOT A PATH"],
    ["control character inside", "/srv/\u0001x", "control characters"],
    ["newline inside", "/srv/a\nb", "NOT A PATH"],
    ["over the 512-byte cap", "/srv/" + "y".repeat(600), "512 bytes"],
  ];
  for (const [name, prefix, why] of refused) {
    const d = g1Declared();
    d.frame["subject-a"].regions.value[0].prefix = prefix;
    try {
      assertRejectedSaying(() => validateDeclarations(d), "frame.subject-a.regions.value[0].prefix", why);
    } catch (err) {
      throw new Error(`${name}: ${(err as Error).message}`);
    }
  }
  // The canonical spellings of the same places LOAD, up to the byte cap.
  for (const ok of ["/srv/caf\u00e9", "/srv/\u03a9", "/srv/\u00c5sa", "/srv/a.b", "/srv/" + "y".repeat(500)]) {
    const d = g1Declared();
    d.frame["subject-a"].regions.value[0].prefix = ok;
    validateDeclarations(d);
  }
});

check("GATE 1 · R-b: two NFC-EQUIVALENT spellings of one prefix can no longer be declared together — whichever is non-canonical is REFUSED", () => {
  // C4-1's P/Q: [NFC->c1, NFD->c2] and [NFD->c1, NFC->c2] hashed alike and
  // labelled differently. Now the NFD half is refused wherever it stands.
  const nfc = "/srv/caf\u00e9";
  const nfd = "/srv/cafe\u0301";
  const p = g1Declared();
  p.frame["subject-a"].regions.value = [{ prefix: nfc, category: "c-other" }, { prefix: nfd, category: "c-self" }];
  assertRejectedSaying(() => validateDeclarations(p), "frame.subject-a.regions.value[1].prefix", "canonical form");
  const q = g1Declared();
  q.frame["subject-a"].regions.value = [{ prefix: nfd, category: "c-other" }, { prefix: nfc, category: "c-self" }];
  assertRejectedSaying(() => validateDeclarations(q), "frame.subject-a.regions.value[0].prefix", "canonical form");
  // And two declarations whose prefixes differ only by normalisation cannot both
  // load, so "same hash, different label" has no pair left to stand on.
  const x = g1Declared();
  x.frame["subject-a"].regions.value = [{ prefix: nfc, category: "c-other" }];
  validateDeclarations(x);
});

check("GATE 1: a DUPLICATE region prefix is REFUSED — one place, two categories", () => {
  const d = g1Declared();
  d.frame["subject-a"].regions.value[1].prefix = "/srv/a";
  assertRejectedSaying(() => validateDeclarations(d), "frame.subject-a.regions.value[1].prefix", "duplicate");
});

check("GATE 1 X19: a region naming NO declared category is REFUSED — it would write a label M does not contain", () => {
  const d = g1Declared();
  d.frame["subject-a"].regions.value[0].category = "c-elsewhere";
  assertRejectedSaying(() => validateDeclarations(d), "frame.subject-a.regions.value[0].category", "X19");
});

check("GATE 1 X20: gate1Scope naming NO declared subject is REFUSED — and the message says typo, not missing frame", () => {
  const d = g1Declared();
  d.readers.gate1Scope.subject.value = "subject-b";
  assertRejectedSaying(() => validateDeclarations(d), "readers.gate1Scope.subject", "is not a declared subjects[].subject");
});

check("GATE 1 X20: gate1Scope naming a declared subject WITHOUT a frame is REFUSED — a reader switched on over nothing", () => {
  const noFrame = g1Declared();
  delete noFrame.frame;
  assertRejectedSaying(() => validateDeclarations(noFrame), "readers.gate1Scope.subject", "has no frame");
  // The OTHER subject is declared and unframed: same refusal, so the rule is the
  // frame's existence for THAT subject, not "some frame exists".
  const other = g1Declared();
  other.readers.gate1Scope.subject.value = other.subjects[0].subject;
  assertRejectedSaying(() => validateDeclarations(other), "readers.gate1Scope.subject", "has no frame");
});

check("GATE 1: a frame WITHOUT gate1Scope LOADS — the frame steers labels; the reader is a separate switch", () => {
  const d = g1Declared();
  delete d.readers.gate1Scope;
  const loaded = validateDeclarations(d).declarations;
  assert(loaded.frame !== undefined && !("gate1Scope" in loaded.readers), "frame alone must load, reader absent");
});

check("GATE 1: the doors are still doors — unknown keys in gate1Scope, the frame, a category and a region are REFUSED; `frame` under readers is REFUSED", () => {
  const cases: ReadonlyArray<[(d: any) => void, string]> = [
    [(d) => (d.readers.gate1Scope.paperFreshnessBound = { value: 1, basis: g1Basis(), proxy: true }), "readers.gate1Scope.paperFreshnessBound"],
    [(d) => (d.frame["subject-a"].weights = {}), "frame.subject-a.weights"],
    [(d) => (d.frame["subject-a"].categories.value[0].weight = 1), "frame.subject-a.categories.value[0].weight"],
    [(d) => (d.frame["subject-a"].regions.value[0].owner = "x"), "frame.subject-a.regions.value[0].owner"],
    [(d) => (d.readers.frame = d.frame), "readers.frame"],
  ];
  for (const [mutate, field] of cases) {
    const d = g1Declared();
    mutate(d);
    assertRejectedSaying(() => validateDeclarations(d), field, "unknown field");
  }
});

check("GATE 1 X17: the bridge's OWN underived word, read from interest-label.ts, is refused as a category id — the literal here cannot drift from it", () => {
  // ⛔ BY BEHAVIOUR, NOT BY COMPARING TWO STRINGS. declarations.ts spells the word
  //    as a literal (the DOCTOR_ATTESTED reason: no value import back toward
  //    mica-service). The authority is INTEREST_UNDERIVED; if the two drift, a
  //    frame could declare the authority's word as a category and every
  //    underived act would read as a case of it. So the authority's word is
  //    DECLARED here and the refusal is required.
  //
  // ⚠ A RUNTIME require, so a missing module fails THIS arm by name instead of
  //   failing the whole suite at compile. It does not skip.
  let underived: unknown;
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    underived = require("./interest-label").INTEREST_UNDERIVED;
  } catch (err) {
    throw new Error(`interest-label.ts could not be loaded, so the agreement cannot be checked: ${String(err)}`);
  }
  assert(typeof underived === "string" && underived.length > 0, `INTEREST_UNDERIVED is not a non-empty string: ${JSON.stringify(underived)}`);
  const d = g1Declared();
  d.frame["subject-a"].categories.value[1].id = underived;
  d.frame["subject-a"].regions.value[1].category = underived;
  assertRejectedSaying(() => validateDeclarations(d), "frame.subject-a.categories.value[1].id", "X17");
});

// ── R-a · "__proto__" is refused as a subject id and as a frame key ──────────

check("GATE 1 · R-a: \"__proto__\" as subjects[].subject is REFUSED, and the refusal names canonical-json", () => {
  // Reviews C4-1, C4-3, C6-3: canonical-json's `out[k] = …` sets the prototype
  // for this one name, so a frame keyed by it fell OUTSIDE declarationHash
  // while the bridge (Object.hasOwn) still labelled from it.
  const d = g1Declared();
  d.subjects[1].subject = "__proto__";
  assertRejectedSaying(() => validateDeclarations(d), "subjects[1].subject", "canonical-json");
});

check("GATE 1 · R-a: \"__proto__\" as a frame KEY is REFUSED at that key, naming canonical-json (before X16)", () => {
  const d = g1Declared();
  g1DefineOwn(d.frame, "__proto__", g1Frame());
  assert(Object.keys(d.frame).includes("__proto__"), "fixture: the key must be an OWN key, as JSON.parse would make it");
  assertRejectedSaying(() => validateDeclarations(d), "frame.__proto__", "canonical-json");
  // From JSON TEXT too, which is how a served file arrives.
  const text = JSON.stringify(g1Declared()).replace('"frame":{', `"frame":{"__proto__":${JSON.stringify(g1Frame())},`);
  assertRejectedSaying(() => validateDeclarations(JSON.parse(text)), "frame.__proto__", "canonical-json");
});

check("ROUND 3 (A6): an OWN \"__proto__\" key ANYWHERE is REFUSED before any other rule — readers.sig.preconditionMap and reentryMap included", () => {
  // Reviews K3D2-7, K3D3-6, K3D1-7: the event maps kept an own "__proto__"
  // entry, Sig received it, and two declarations differing only in that entry
  // hashed alike. From JSON TEXT, which is how a served file arrives.
  for (const map of ["preconditionMap", "reentryMap"]) {
    for (const entry of [["TOOL_ATTEMPTED"], ["TOOL_RESULT", "ACT_CLOSED"]]) {
      const text = JSON.stringify(clone()).replace(
        `"${map}":{"value":{`,
        `"${map}":{"value":{"__proto__":${JSON.stringify(entry)},`
      );
      assert(text.includes('"__proto__"'), `fixture: the ${map} text was not rewritten`);
      const parsed = JSON.parse(text);
      assert(Object.keys(parsed.readers.sig[map].value).includes("__proto__"), `fixture: ${map} must carry an OWN key`);
      assertRejectedSaying(() => validateDeclarations(parsed), `readers.sig.${map}.value.__proto__`, "canonical-json");
    }
  }
  // At any depth, arrays included, and AHEAD of a rule that would fire first in
  // schema order (an unknown top-level key is refused after the walk).
  const deep = clone();
  deep.bogus = 1;
  g1DefineOwn(deep.subjects[0], "__proto__", {});
  assertRejectedSaying(() => validateDeclarations(deep), "subjects[0].__proto__", "canonical-json");
  // A "__proto__" VALUE is not a key: the walk passes it, the subject rule names it.
  const val = g1Declared();
  val.subjects[1].subject = "__proto__";
  assertRejectedSaying(() => validateDeclarations(val), "subjects[1].subject", "canonical-json");
  // The tree declaration and the fixture still load — neither carries the key.
  loadDeclarations(SHIPPED_PATH);
  loadDeclarations(DRAFT_PATH);
});

check("ROUND 3 (A6): a declaration nested past the stack is REFUSED or loaded by the walk, never a RangeError out of the front door", () => {
  let deepValue: unknown = 0;
  for (let i = 0; i < 200000; i++) deepValue = [deepValue];
  const d = clone();
  d.bogusDeep = deepValue;
  try {
    validateDeclarations(d);
    throw new Error("an unknown top-level key loaded");
  } catch (err) {
    assert(err instanceof DeclarationRejected, `the walk let a non-refusal escape: ${String(err).slice(0, 200)}`);
  }
});

check("GATE 1 · R-a: the other Object.prototype names LOAD as subjects and their frames are INSIDE the hash", () => {
  // Only __proto__ is a setter; constructor, toString, hasOwnProperty define
  // ordinary keys. Measured by the hash moving when only the regions move.
  for (const name of ["constructor", "toString", "hasOwnProperty"]) {
    const a = g1Declared(name);
    const b = g1Declared(name);
    b.frame[name].regions.value[0].prefix = "/srv/elsewhere";
    const ha = validateDeclarations(a).declarationHash;
    const hb = validateDeclarations(b).declarationHash;
    assert(ha !== hb, `${name}: two frames differing in a region hash ALIKE — the frame is outside the digest`);
  }
});

// ── X22 · readers.gate1Scope requires paths.interestBook (round 2, placement D) ─

check("GATE 1 X22: gate1Scope WITHOUT paths.interestBook is REFUSED at paths.interestBook — the reader would have no book", () => {
  const d = g1Declared();
  delete d.paths.interestBook;
  assertRejectedSaying(() => validateDeclarations(d), "paths.interestBook", "X22");
});

check("GATE 1 X22, SECOND HALF: a FRAME without paths.interestBook is REFUSED at paths.interestBook even with no reader — the writer would lose every label", () => {
  const d = g1Base("subject-a");
  d.frame = { "subject-a": g1Frame() };
  assertRejectedSaying(() => validateDeclarations(d), "paths.interestBook", "X22");
  d.paths.interestBook = g1BookPath();
  validateDeclarations(d); // and with the book it loads
});

check("GATE 1: paths.interestBook is OPTIONAL without the reader, loads WHOLE, and MOVES the hash when declared", () => {
  const plain = g1Base("subject-a");
  const flat = validateDeclarations(plain).declarationHash;
  const withBook = g1Base("subject-a");
  withBook.paths.interestBook = g1BookPath();
  const loaded = validateDeclarations(withBook);
  assert(loaded.declarations.paths.interestBook === g1BookPath(), `the loaded book path is ${JSON.stringify(loaded.declarations.paths.interestBook)}`);
  assert(loaded.declarationHash !== flat, "declaring paths.interestBook did not move the hash — it is outside the digest");
  assert(!("interestBook" in validateDeclarations(plain).declarations.paths), "an undeclared book must be an ABSENT key");
});

check("GATE 1 · ROUND 3 (A4): paths.interestBook takes its OWN pattern — ONE FLAT .jsonl FILE directly in /var/lib/mica-bridge/ — and stays distinct from every other path (X7)", () => {
  // Reviews K2W-5, K3D2-5, K3D1-5, K3D2-6: under the eight paths' lock the book
  // could leave the directory through "..", be the state dir itself, be another
  // store's .lock sibling (every subject act then 503) or the R6 salt file.
  const subjectLog = String(g1Declared().paths.subjectLog);
  for (const bad of [
    "/var/lib/mica/interest-book.jsonl", "/tmp/interest-book.jsonl", "relative.jsonl", 7, { value: g1BookPath(), basis: g1Basis() },
    "/var/lib/mica-bridge/../mica/x.jsonl", "/var/lib/mica-bridge/../../etc/mica-bridge-book", "/var/lib/mica-bridge/.",
    "/var/lib/mica-bridge/sub/../" + subjectLog.split("/").pop(), `${subjectLog}.lock`, `${subjectLog}.quarantine`,
    "/var/lib/mica-bridge/target-fingerprint-salt", "/var/lib/mica-bridge/notices/x.jsonl", "/var/lib/mica-bridge/.hidden.jsonl",
    "/var/lib/mica-bridge/..jsonl", "/var/lib/mica-bridge/-x.jsonl", `${g1BookPath()}\n`, "/var/lib/mica-bridge/.jsonl",
  ]) {
    const d = g1Declared();
    d.paths.interestBook = bad;
    try {
      assertRejectedSaying(() => validateDeclarations(d), "paths.interestBook", "ONE FLAT .jsonl FILE");
    } catch (err) {
      throw new Error(`${JSON.stringify(bad)}: ${(err as Error).message}`);
    }
  }
  for (const ok of ["/var/lib/mica-bridge/interest-book-v2.jsonl", "/var/lib/mica-bridge/_b.jsonl", "/var/lib/mica-bridge/a.b.jsonl"]) {
    const d = g1Declared();
    d.paths.interestBook = ok;
    assert(validateDeclarations(d).declarations.paths.interestBook === ok, `${ok} must load as declared`);
  }
  const same = g1Declared();
  same.paths.interestBook = same.paths.subjectLog;
  assertRejectedSaying(() => validateDeclarations(same), "paths", "X7");
});

check("GATE 1 · ROUND 3 (A4): no OTHER declared path may be the book's own .lock or .quarantine sibling, and the book is not the RETIRED chain file", () => {
  for (const suffix of [".lock", ".quarantine"]) {
    const d = g1Declared();
    d.paths.ledger = g1BookPath() + suffix;
    assertRejectedSaying(() => validateDeclarations(d), "paths", "lock or quarantine sibling");
  }
  const retired = g1Declared();
  retired.subjectLog.chainBoundary.retiredPath.value = g1BookPath();
  retired.subjectLog.chainBoundary.retiredRecords.value = 1008;
  retired.subjectLog.chainBoundary.retiredBytes.value = 475447;
  retired.subjectLog.chainBoundary.retiredSha256.value = "a".repeat(64);
  assertRejectedSaying(() => validateDeclarations(retired), "paths.interestBook", "RETIRED");
  // The validity gate: the same rotation naming ANOTHER retired file loads.
  retired.subjectLog.chainBoundary.retiredPath.value = "/var/lib/mica-bridge/subject-events.20260928-1800.pre-chain-boundary.jsonl";
  validateDeclarations(retired);
});

check("GATE 1 · ROUND 3 X23 (A5): readers.logPath naming the interest book is REFUSED — the sibling readers would read Gate 1's labels as subject acts", () => {
  // Review K1R2-4 (and K2W3-7): X7 kept paths.* apart, but readers.logPath was free.
  const d = g1Declared();
  d.readers.logPath.value = g1BookPath();
  assertRejectedSaying(() => validateDeclarations(d), "readers.logPath", "X23");
  // Canonical form, like X7: a ".." spelling of the book is the book.
  const hop = g1Declared();
  hop.readers.logPath.value = "/var/lib/mica-bridge/x/../" + g1BookPath().split("/").pop();
  assertRejectedSaying(() => validateDeclarations(hop), "readers.logPath", "X23");
  // The validity gate: the declared subject log is still a legal logPath beside a book.
  const ok = g1Declared();
  assert(String(ok.readers.logPath.value) === String(ok.paths.subjectLog), "fixture: logPath must be the subject log");
  validateDeclarations(ok);
});

// ── X21 · WIDEN-ONLY ACROSS A RELOAD ─────────────────────────────────────────
//
// ⛔ EVERY ARM BELOW USES clone()'s INACTIVE PILOT, and that is the ordering
//    test: validateActivation returns early for an inactive next pilot, so a
//    frame rule placed after the pilot rules would never run on these inputs.

function g1Loaded(mutate?: (d: any) => void): Declarations {
  const d = g1Declared();
  if (mutate) mutate(d);
  return validateDeclarations(d).declarations;
}

check("GATE 1 X21: FIRST LOAD is never refused by the widen-only rule", () => {
  validateActivation(null, g1Loaded());
});

check("GATE 1 X21: the same frame, a WIDER frame, and a frame for a NEWLY framed subject are all ACCEPTED", () => {
  const prev = g1Loaded();
  validateActivation(prev, g1Loaded());
  validateActivation(
    prev,
    g1Loaded((d) => d.frame["subject-a"].categories.value.push({ id: "c-new", label: "added", grounding: "need", self: false }))
  );
  // ZERO-SUBJECTS Z4 (F-5 (a), audit 2026-10-18 06:56Z (9)): a reload may no longer ADD a subject, so the newly
  // framed subject is declared on both sides and gains its frame by the reload — X21's widening, unchanged.
  const withB = (d: any): void => {
    d.subjects.push({ subject: "subject-b", toolName: "tool-y", stakesClass: d.subjects[0].stakesClass, peerUid: d.subjects[0].peerUid });
  };
  validateActivation(
    g1Loaded(withB),
    g1Loaded((d) => {
      withB(d);
      d.frame["subject-b"] = g1Frame();
    })
  );
  // From NO frame to a frame is a widening too — on a bridge that STARTED with its
  // book declared (round 3, A3: a reload may not add the book itself).
  const unframedWithBook = g1Base("subject-a");
  unframedWithBook.paths.interestBook = g1BookPath();
  validateActivation(validateDeclarations(unframedWithBook).declarations, prev);
});

check("GATE 1 X21: DROPPING a framed subject's frame is REFUSED, naming the brief's widen-only rule — and NOT attributing it to Gate 5", () => {
  const prev = g1Loaded();
  const next = g1Loaded((d) => {
    delete d.frame;
    delete d.readers.gate1Scope;
  });
  assertRejectedSaying(() => validateActivation(prev, next), "frame.subject-a", "widen-only");
  // ROUND 3 (A9, review K3D3-10): canon does not place M-narrowing under Gate 5.
  try {
    validateActivation(prev, next);
  } catch (err) {
    assert(!String((err as Error).message).includes("Gate 5"), `the X21 reason still cites Gate 5: ${(err as Error).message}`);
  }
});

check("GATE 1 X21: DROPPING one category from M is REFUSED, naming the category and the widen-only rule", () => {
  const prev = g1Loaded();
  const next = g1Loaded((d) => {
    d.frame["subject-a"].categories.value.splice(2, 1);
    d.frame["subject-a"].regions.value.splice(2, 1);
  });
  assertRejectedSaying(() => validateActivation(prev, next), "frame.subject-a.categories.value", "c-shared");
  assertRejectedSaying(() => validateActivation(prev, next), "frame.subject-a.categories.value", "widen-only");
});

check("GATE 1 X21: RENAMING a category is a drop plus an add, and is REFUSED", () => {
  const prev = g1Loaded();
  const next = g1Loaded((d) => {
    d.frame["subject-a"].categories.value[1].id = "c-other-renamed";
    d.frame["subject-a"].regions.value[1].category = "c-other-renamed";
  });
  assertRejectedSaying(() => validateActivation(prev, next), "frame.subject-a.categories.value", "c-other");
});

check("GATE 1 X21: the rule runs BEFORE the pilot rules — an unchanged ACTIVE pilot does not carry a narrowing past it", () => {
  // isSameAsPrev returns early for an unchanged active pilot. Same ordering
  // claim as the inactive arms above, from the other early return.
  const pilot = { active: true, sessionId: "pilot-g1", expiresAt: "2099-01-01T00:00:00Z", holdAtOrAbove: { value: draft.stakes.baseline.holdAtOrAbove.value, basis: g1Basis(), proxy: true } };
  const prev = g1Loaded((d) => (d.pilot = pilot));
  const next = g1Loaded((d) => {
    d.pilot = pilot;
    d.frame["subject-a"].categories.value.splice(2, 1);
    d.frame["subject-a"].regions.value.splice(2, 1);
  });
  assertRejectedSaying(() => validateActivation(prev, next), "frame.subject-a.categories.value", "widen-only");
});

// ── A3 · the interest book may not change across a reload (round 3) ─────────
//
// Reviews K2W-3, K2W3-3, K3D1-4, K3D3-3, K3D3-2: the book is opened only at
// start, the wiring re-resolves the declared path on every reload, and an
// accepted move split writer from reader. Every arm below uses clone()'s
// INACTIVE pilot, so it also proves the rule runs before the early return.

check("GATE 1 · ROUND 3 (A3): a reload that ADDS, MOVES or REMOVES paths.interestBook is REFUSED at paths.interestBook — the book opens only at start", () => {
  const withBook = g1Loaded();
  const moved = g1Loaded((d) => (d.paths.interestBook = "/var/lib/mica-bridge/interest-book-v2.jsonl"));
  assertRejectedSaying(() => validateActivation(withBook, moved), "paths.interestBook", "MOVES it");
  // ADDED: a bridge started with neither frame nor book, SIGHUP'd to both (K3D3-2).
  const bare = validateDeclarations(g1Base("subject-a")).declarations;
  assertRejectedSaying(() => validateActivation(bare, withBook), "paths.interestBook", "ADDS it");
  // REMOVED: frame, reader and book all dropped would be refused by X21 first;
  // with no frame at the start, removing the book alone is this rule's.
  const bookOnly = g1Base("subject-a");
  bookOnly.paths.interestBook = g1BookPath();
  assertRejectedSaying(
    () => validateActivation(validateDeclarations(bookOnly).declarations, bare),
    "paths.interestBook",
    "REMOVES it"
  );
  // And past an unchanged ACTIVE pilot (the other early return).
  const pilot = { active: true, sessionId: "pilot-g1b", expiresAt: "2099-01-01T00:00:00Z", holdAtOrAbove: { value: draft.stakes.baseline.holdAtOrAbove.value, basis: g1Basis(), proxy: true } };
  const p1 = g1Loaded((d) => (d.pilot = pilot));
  const p2 = g1Loaded((d) => {
    d.pilot = pilot;
    d.paths.interestBook = "/var/lib/mica-bridge/interest-book-v2.jsonl";
  });
  assertRejectedSaying(() => validateActivation(p1, p2), "paths.interestBook", "takes a restart");
});

check("GATE 1 · ROUND 3 (A3): an UNCHANGED book with a WIDENED frame is ACCEPTED, and a FIRST LOAD with a book is never refused", () => {
  const prev = g1Loaded();
  validateActivation(
    prev,
    g1Loaded((d) => d.frame["subject-a"].categories.value.push({ id: "c-new", label: "added", grounding: "need", self: false }))
  );
  validateActivation(null, prev);
  // Neither declares a book: unchanged, accepted.
  const bare = validateDeclarations(g1Base("subject-a")).declarations;
  validateActivation(bare, bare);
});

check("GATE 1 X21 · DECLARED CEILING: REGIONS may narrow and a category's label may change — only M's membership is held", () => {
  // Pinned so the ceiling is a tested statement, not only a comment: if X21 is
  // ever widened to regions, this arm moves with it on purpose.
  const prev = g1Loaded();
  validateActivation(prev, g1Loaded((d) => (d.frame["subject-a"].regions.value = [])));
  validateActivation(prev, g1Loaded((d) => (d.frame["subject-a"].categories.value[1].label = "relabelled")));
});

// ── schema ⇄ loader, value by value, for the frame ───────────────────────────
//
// ⛔ THREE WITNESSES PER DOCUMENT: the runtime loader, the subset evaluator over
//    the schema this run holds, and a real Draft202012Validator over the
//    committed bytes. The parity walk compares KEY SETS; these compare VALUE
//    DOMAINS, which is where `paperFreshnessBound` drifted (schema any number,
//    loader integer >= 1).
//
// ⚠ THE LOADER-ONLY ROWS ARE CROSS-FIELD RULES JSON Schema cannot state
//   (membership in another array, uniqueness by one member, an exact count of a
//   flag). They are ENUMERATED and RATCHETED: the schema must ACCEPT each and the
//   loader must REFUSE it. If the schema learns one, this fails and the row moves.

/** One python3 spawn for many documents: the real validator's error count per document. */
function realValidatorCounts(docs: readonly unknown[]): number[] {
  const tmp = mkdtempSync(join(tmpdir(), "g1-frame-"));
  try {
    const docsPath = join(tmp, "docs.json");
    writeFileSync(docsPath, JSON.stringify(docs), "utf8");
    const script = [
      "import json,sys",
      "from jsonschema import Draft202012Validator",
      "sch=json.load(open(sys.argv[1])); docs=json.load(open(sys.argv[2]))",
      "Draft202012Validator.check_schema(sch)",
      "v=Draft202012Validator(sch)",
      "print(json.dumps([len(list(v.iter_errors(d))) for d in docs]))",
    ].join("\n");
    const out = execFileSync("python3", ["-c", script, SCHEMA_PATH, docsPath], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    return JSON.parse(out.trim()) as number[];
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

function loaderAccepts(doc: unknown): boolean {
  try {
    validateDeclarations(doc);
    return true;
  } catch (err) {
    if (!(err instanceof DeclarationRejected)) throw err;
    return false;
  }
}

check("GATE 1 SCHEMA: the frame document satisfies the schema by BOTH evaluators, and each value rule agrees three ways or is an ENUMERATED loader-only row", () => {
  // DIALECT_LOADER_ONLY (round 3): loader AND subset refuse, the REAL validator
  // accepts — a pre-existing `$` pattern under Python's re. Enumerated, never
  // skipped: if the schema learns the row, it reads BOTH_REFUSE and fails here.
  type Row = { name: string; mutate: (d: any) => void; expect: "BOTH_ACCEPT" | "BOTH_REFUSE" | "LOADER_ONLY" | "DIALECT_LOADER_ONLY" };
  const F = (d: any) => d.frame["subject-a"];
  const rows: Row[] = [
    { name: "the well-formed frame", mutate: () => undefined, expect: "BOTH_ACCEPT" },
    { name: "empty regions", mutate: (d) => (F(d).regions.value = []), expect: "BOTH_ACCEPT" },
    { name: "a fourth category", mutate: (d) => F(d).categories.value.push({ id: "c4", label: "x", grounding: "need", self: false }), expect: "BOTH_ACCEPT" },
    { name: "one category", mutate: (d) => { F(d).categories.value = [F(d).categories.value[0]]; F(d).regions.value = []; }, expect: "BOTH_REFUSE" },
    { name: "id with a space", mutate: (d) => (F(d).categories.value[1].id = "c other"), expect: "BOTH_REFUSE" },
    { name: "id UNDERIVED", mutate: (d) => (F(d).categories.value[1].id = "UNDERIVED"), expect: "BOTH_REFUSE" },
    { name: "id UNDERIVED-ish is a name", mutate: (d) => { F(d).categories.value[1].id = "UNDERIVED2"; F(d).regions.value[1].category = "UNDERIVED2"; }, expect: "BOTH_ACCEPT" },
    { name: "empty label", mutate: (d) => (F(d).categories.value[0].label = ""), expect: "BOTH_REFUSE" },
    { name: "grounding outside the three (an untagged category)", mutate: (d) => (F(d).categories.value[0].grounding = "preference"), expect: "BOTH_REFUSE" },
    { name: "grounding missing", mutate: (d) => delete F(d).categories.value[0].grounding, expect: "BOTH_REFUSE" },
    { name: "self not boolean", mutate: (d) => (F(d).categories.value[0].self = 1), expect: "BOTH_REFUSE" },
    { name: "categories basis empty", mutate: (d) => (F(d).categories.basis = ""), expect: "BOTH_REFUSE" },
    { name: "regions proxy missing", mutate: (d) => delete F(d).regions.proxy, expect: "BOTH_REFUSE" },
    { name: "region category not identifier-shaped", mutate: (d) => (F(d).regions.value[0].category = "c self"), expect: "BOTH_REFUSE" },
    { name: "frame key not identifier-shaped", mutate: (d) => (d.frame["subject a"] = g1Frame()), expect: "BOTH_REFUSE" },
    { name: "gate1Scope subject value empty", mutate: (d) => (d.readers.gate1Scope.subject.value = ""), expect: "BOTH_REFUSE" },
    // An EMPTY frame moves the hash and declares nothing; gate1Scope goes with it so the row reads that rule alone.
    { name: "empty frame {}", mutate: (d) => { d.frame = {}; delete d.readers.gate1Scope; }, expect: "BOTH_REFUSE" },
    // R-a: the schema's negative lookahead and the loader agree.
    { name: "R-a __proto__ as a subject id", mutate: (d) => (d.subjects[1].subject = "__proto__"), expect: "BOTH_REFUSE" },
    { name: "R-a __proto__ as a frame key (an OWN key)", mutate: (d) => g1DefineOwn(d.frame, "__proto__", g1Frame()), expect: "BOTH_REFUSE" },
    { name: "R-a constructor as a frame key is a name", mutate: (d) => { d.subjects[1].subject = "constructor"; d.frame = { constructor: g1Frame() }; d.readers.gate1Scope.subject.value = "constructor"; }, expect: "BOTH_ACCEPT" },
    // paths.interestBook: the subjectLog lock, both sides.
    { name: "interestBook outside /var/lib/mica-bridge/", mutate: (d) => (d.paths.interestBook = "/var/lib/mica/interest-book.jsonl"), expect: "BOTH_REFUSE" },
    { name: "interestBook as an envelope", mutate: (d) => (d.paths.interestBook = { value: g1BookPath(), basis: g1Basis() }), expect: "BOTH_REFUSE" },
    { name: "interestBook without the reader", mutate: (d) => delete d.readers.gate1Scope, expect: "BOTH_ACCEPT" },
    // ── LOADER-ONLY, enumerated: cross-field rules the schema cannot state ──
    { name: "X16 frame key not a declared subject", mutate: (d) => (d.frame["subject-b"] = g1Frame()), expect: "LOADER_ONLY" },
    { name: "duplicate category id", mutate: (d) => (F(d).categories.value[2].id = "c-other"), expect: "LOADER_ONLY" },
    { name: "X17 id equal to a toolName", mutate: (d) => { F(d).categories.value[2].id = "tool-x"; F(d).regions.value[2].category = "tool-x"; }, expect: "LOADER_ONLY" },
    { name: "X18 no self", mutate: (d) => (F(d).categories.value[0].self = false), expect: "LOADER_ONLY" },
    { name: "X18 two self", mutate: (d) => (F(d).categories.value[1].self = true), expect: "LOADER_ONLY" },
    { name: "duplicate region prefix", mutate: (d) => (F(d).regions.value[1].prefix = "/srv/a"), expect: "LOADER_ONLY" },
    { name: "X19 region category undeclared", mutate: (d) => (F(d).regions.value[0].category = "c-elsewhere"), expect: "LOADER_ONLY" },
    { name: "X20 gate1Scope subject undeclared", mutate: (d) => (d.readers.gate1Scope.subject.value = "subject-b"), expect: "LOADER_ONLY" },
    { name: "X20 gate1Scope subject unframed", mutate: (d) => delete d.frame, expect: "LOADER_ONLY" },
    { name: "X22 gate1Scope without paths.interestBook", mutate: (d) => delete d.paths.interestBook, expect: "LOADER_ONLY" },
    { name: "X7 interestBook equal to subjectLog", mutate: (d) => (d.paths.interestBook = d.paths.subjectLog), expect: "LOADER_ONLY" },
    { name: "X22 second half: frame (no reader) without paths.interestBook", mutate: (d) => { delete d.readers.gate1Scope; delete d.paths.interestBook; }, expect: "LOADER_ONLY" },
    { name: "X22 control: frame (no reader) WITH paths.interestBook", mutate: (d) => delete d.readers.gate1Scope, expect: "BOTH_ACCEPT" },
    { name: "unit with a leading '-' (would reach systemctl as an option)", mutate: (d) => (d.subjects[0].unit = "--user"), expect: "BOTH_REFUSE" },
    { name: "unit control: an ordinary caller unit", mutate: (d) => (d.subjects[0].unit = "caller-a"), expect: "BOTH_ACCEPT" },
    // R-b: a prefix must equal its own canonical form. JSON Schema cannot state
    // NFC (nor a byte cap: minLength/maxLength count code points, and maxLength
    // is not in this evaluator's census), so these are the loader's alone.
    { name: "R-b NFD prefix", mutate: (d) => (F(d).regions.value = [{ prefix: "/srv/cafe\u0301", category: "c-self" }]), expect: "LOADER_ONLY" },
    { name: "R-b NFC singleton (Ohm sign) prefix", mutate: (d) => (F(d).regions.value = [{ prefix: "/srv/\u2126", category: "c-self" }]), expect: "LOADER_ONLY" },
    { name: "R-b trailing NBSP prefix", mutate: (d) => (F(d).regions.value = [{ prefix: "/srv/a\u00a0", category: "c-self" }]), expect: "LOADER_ONLY" },
    { name: "R-b trailing BOM prefix", mutate: (d) => (F(d).regions.value = [{ prefix: "/srv/a\ufeff", category: "c-self" }]), expect: "LOADER_ONLY" },
    { name: "R-b trailing ASCII space prefix", mutate: (d) => (F(d).regions.value = [{ prefix: "/srv/a ", category: "c-self" }]), expect: "LOADER_ONLY" },
    { name: "R-b control character prefix", mutate: (d) => (F(d).regions.value = [{ prefix: "/srv/\u0001x", category: "c-self" }]), expect: "LOADER_ONLY" },
    { name: "R-b prefix over the 512-byte cap", mutate: (d) => (F(d).regions.value = [{ prefix: "/srv/" + "y".repeat(600), category: "c-self" }]), expect: "LOADER_ONLY" },
    { name: "R-b NFC + NFD spellings of one prefix", mutate: (d) => (F(d).regions.value = [{ prefix: "/srv/caf\u00e9", category: "c-self" }, { prefix: "/srv/cafe\u0301", category: "c-other" }]), expect: "LOADER_ONLY" },
    // ── ROUND 3 ──
    // A4: the book's own pattern, the same both sides.
    { name: "A4 interestBook leaving the dir through ..", mutate: (d) => (d.paths.interestBook = "/var/lib/mica-bridge/../mica/x.jsonl"), expect: "BOTH_REFUSE" },
    { name: "A4 interestBook in a sub-directory", mutate: (d) => (d.paths.interestBook = "/var/lib/mica-bridge/notices/x.jsonl"), expect: "BOTH_REFUSE" },
    { name: "A4 interestBook = the subject log's .lock sibling", mutate: (d) => (d.paths.interestBook = `${String(d.paths.subjectLog)}.lock`), expect: "BOTH_REFUSE" },
    { name: "A4 interestBook = the salt file", mutate: (d) => (d.paths.interestBook = "/var/lib/mica-bridge/target-fingerprint-salt"), expect: "BOTH_REFUSE" },
    { name: "A4 interestBook = the state dir", mutate: (d) => (d.paths.interestBook = "/var/lib/mica-bridge/."), expect: "BOTH_REFUSE" },
    { name: "A4 control: another flat book name", mutate: (d) => (d.paths.interestBook = "/var/lib/mica-bridge/interest-book-v2.jsonl"), expect: "BOTH_ACCEPT" },
    { name: "A4 X7: another path is the book's .lock sibling", mutate: (d) => (d.paths.ledger = `${g1BookPath()}.lock`), expect: "LOADER_ONLY" },
    { name: "A5 X23 readers.logPath = the book", mutate: (d) => (d.readers.logPath.value = g1BookPath()), expect: "LOADER_ONLY" },
    // A6: an own "__proto__" in a user-keyed event map — the schema admits any key there.
    { name: "A6 __proto__ in readers.sig.preconditionMap", mutate: (d) => g1DefineOwn(d.readers.sig.preconditionMap.value, "__proto__", ["TOOL_ATTEMPTED"]), expect: "LOADER_ONLY" },
    { name: "A6 __proto__ in readers.sig.reentryMap", mutate: (d) => g1DefineOwn(d.readers.sig.reentryMap.value, "__proto__", ["TOOL_ATTEMPTED"]), expect: "LOADER_ONLY" },
    // A7: every pattern this run added or changed ends in (?![\s\S]), so the REAL
    // witness (Python's re, whose $ matches before a final newline) refuses a
    // trailing newline as the loader does. Reviews K3D1-6, K3D3-1.
    { name: "A7 unit with a trailing newline", mutate: (d) => (d.subjects[0].unit = "caller-a\n"), expect: "BOTH_REFUSE" },
    { name: "A7 fourth category id with a trailing newline", mutate: (d) => F(d).categories.value.push({ id: "c4\n", label: "x", grounding: "need", self: false }), expect: "BOTH_REFUSE" },
    { name: "A7 region category with a trailing newline", mutate: (d) => (F(d).regions.value[0].category = "c-self\n"), expect: "BOTH_REFUSE" },
    { name: "A7 frame key with a trailing newline", mutate: (d) => (d.frame["subject-a\n"] = g1Frame()), expect: "BOTH_REFUSE" },
    { name: "A7 interestBook with a trailing newline", mutate: (d) => (d.paths.interestBook = `${g1BookPath()}\n`), expect: "BOTH_REFUSE" },
    { name: "A7 id UNDERIVED with a trailing newline", mutate: (d) => (F(d).categories.value[1].id = "UNDERIVED\n"), expect: "BOTH_REFUSE" },
    // PRE-EXISTING patterns are NOT changed (spec R3 A7): their newline row is a
    // KNOWN dialect split — loader and subset (ECMA $) refuse, Python's re accepts.
    { name: "DIALECT subject id with a trailing newline (pre-existing pattern)", mutate: (d) => d.subjects.push({ ...d.subjects[1], subject: "subject-b\n" }), expect: "DIALECT_LOADER_ONLY" },
    { name: "DIALECT toolName with a trailing newline (pre-existing pattern)", mutate: (d) => (d.subjects[1].toolName = "tool-x\n"), expect: "DIALECT_LOADER_ONLY" },
  ];
  // ⚠ PREFIXES ARE THE ONE VALUE DOMAIN WRITTEN TWICE IN DIFFERENT LANGUAGES — a
  //   TypeScript function and a regex — so they get the widest sweep, including
  //   the edges where JS and Python regex dialects part (a trailing newline
  //   against `$`, a newline hiding a "//" from `.`).
  // ⚠ ROUND 2 (R-b): the three rows carrying a newline were BOTH_ACCEPT and are
  //   now LOADER_ONLY — the canonical-form rule refuses a control character, and
  //   that rule is the loader's alone. They stay in the sweep for what they were
  //   written for: the subset and real evaluators must still agree on them.
  const prefixes: ReadonlyArray<[string, "BOTH_ACCEPT" | "BOTH_REFUSE" | "LOADER_ONLY" | "DIALECT_LOADER_ONLY"]> = [
    ["/", "BOTH_ACCEPT"], ["/a", "BOTH_ACCEPT"], ["/srv/x-*", "BOTH_ACCEPT"], ["/srv/...", "BOTH_ACCEPT"],
    ["/.hidden", "BOTH_ACCEPT"], ["/a/..b", "BOTH_ACCEPT"], ["/a.b/c", "BOTH_ACCEPT"], ["/a\nb", "LOADER_ONLY"],
    ["", "BOTH_REFUSE"], ["a", "BOTH_REFUSE"], ["//", "BOTH_REFUSE"], ["/a//b", "BOTH_REFUSE"], ["/a/", "BOTH_REFUSE"],
    ["/.", "BOTH_REFUSE"], ["/..", "BOTH_REFUSE"], ["/a/.", "BOTH_REFUSE"], ["/a/./b", "BOTH_REFUSE"],
    ["/a/../b", "BOTH_REFUSE"], ["/a/\n", "LOADER_ONLY"], ["/a\n//b", "BOTH_REFUSE"], ["/a/..\n", "LOADER_ONLY"],
    ["/a\n/..", "BOTH_REFUSE"], ["/caf\u00e9", "BOTH_ACCEPT"],
    // ROUND 3 (A2): a not-a-path segment is a DEAD region — the loader's alone.
    ["/mnt/c/Program Files (x86)", "LOADER_ONLY"], ["/srv/R&D", "LOADER_ONLY"], ["/srv/a=b", "LOADER_ONLY"],
    ["/home/op/~archive", "LOADER_ONLY"], ["/srv/-scratch", "LOADER_ONLY"], ["/srv/+inbox", "LOADER_ONLY"],
    ["/srv/it's", "LOADER_ONLY"], ["/srv/{x}", "LOADER_ONLY"], ["/srv/node:20", "LOADER_ONLY"],
    ["/srv/c++", "BOTH_ACCEPT"], ["/srv/node_modules/@types", "BOTH_ACCEPT"],
    ["/srv/Program Files", "LOADER_ONLY"], ["/srv/a\u00a0b", "LOADER_ONLY"],
  ];
  for (const [p, expect] of prefixes) {
    // One region only, so the row reads the PREFIX rule and not the duplicate-prefix one.
    rows.push({ name: `prefix ${JSON.stringify(p)}`, mutate: (d) => (F(d).regions.value = [{ prefix: p, category: "c-self" }]), expect });
  }
  const docs = rows.map((r) => {
    const d = g1Declared();
    r.mutate(d);
    return d;
  });
  let real: number[];
  try {
    real = realValidatorCounts(docs);
  } catch (err) {
    throw new Error(`the real Draft 2020-12 validator could not run, and this arm does NOT skip: ${String((err as { stderr?: unknown }).stderr ?? err).slice(0, 300)}`);
  }
  const wrong: string[] = [];
  rows.forEach((r, i) => {
    const loader = loaderAccepts(docs[i]);
    const subset = evalSchema(committedSchema, docs[i], "$").length === 0;
    const realOk = real[i] === 0;
    if (r.expect === "DIALECT_LOADER_ONLY") {
      if (loader || subset || !realOk) {
        wrong.push(`${r.name}: expected the KNOWN dialect split (loader and subset refuse, real accepts); loader ${String(loader)}, subset ${String(subset)}, real ${String(realOk)}`);
      }
      return;
    }
    if (subset !== realOk) wrong.push(`${r.name}: the SUBSET evaluator says ${subset ? "valid" : "invalid"} and the REAL validator ${realOk ? "valid" : "invalid"}`);
    const got = loader && subset ? "BOTH_ACCEPT" : !loader && !subset ? "BOTH_REFUSE" : !loader && subset ? "LOADER_ONLY" : "SCHEMA_ONLY";
    if (got !== r.expect) wrong.push(`${r.name}: expected ${r.expect}, got ${got} (loader ${loader ? "accepts" : "refuses"}, schema ${subset ? "accepts" : "refuses"})`);
  });
  assert(wrong.length === 0, `the frame's schema and loader disagree:\n    ${wrong.join("\n    ")}`);
  console.log(`      (${String(rows.length)} frame documents × 3 witnesses; ${String(rows.filter((r) => r.expect === "LOADER_ONLY").length)} enumerated loader-only rows; ${String(rows.filter((r) => r.expect === "DIALECT_LOADER_ONLY").length)} enumerated dialect rows)`);
});

// ── GATE 1 · an EMPTY frame is refused ───────────────────────────────────────
check("GATE 1: an EMPTY frame ({}) is REFUSED at \"frame\" — it would move the hash and declare nothing; omitting the key still loads", () => {
  const d = g1Declared();
  d.frame = {};
  delete d.readers.gate1Scope;
  assertRejectedSaying(() => validateDeclarations(d), "frame", "empty frame declares nothing");
  // The validity gate: the same declaration WITHOUT the key loads, and carries no frame.
  delete d.frame;
  const loaded = validateDeclarations(d).declarations;
  assert(!("frame" in loaded), "omitting frame must load with no frame key");
});

// ── S201 · the bridge names no subject: role "subject", and subjects[].unit ───
//
// ⛔ NO SUBJECT IS TYPED HERE. Where an arm needs "the old role", it uses the
//    fixture's own subject name BY USE (d.subjects[0].subject): a role that is a
//    subject's name is exactly what S201 retires.

check("S201 X6: the subject's route row carries role \"subject\", and the refusal names that role", () => {
  const loaded = validateDeclarations(clone()).declarations;
  const row = loaded.routes.find((r) => r.uid === loaded.subjects[0].peerUid);
  assert(row !== undefined && row.role === "subject", `the fixture subject's route role is ${JSON.stringify(row?.role)}`);
  const d = clone();
  d.subjects[0].peerUid = 4711;
  assertRejectedSaying(() => validateDeclarations(d), "subjects[0].peerUid", 'role "subject"');
});

check("⛔ S201: a route role spelled as a SUBJECT'S NAME is REFUSED at routes[i].role — the role is a relation, not a name", () => {
  const d = clone();
  const i = d.routes.findIndex((r: any) => r.uid === d.subjects[0].peerUid);
  d.routes[i].role = d.subjects[0].subject;
  assertRejectedSaying(() => validateDeclarations(d), `routes[${String(i)}].role`, "must be one of");
});

check("S201: subjects[].unit is OPTIONAL — absent, the key is absent and the fixture hashes as pinned", () => {
  // The fixture as written (its own pilot), not clone(), whose inactive pilot is a different digest.
  const loaded = loadDeclarations(DRAFT_PATH);
  assert(!("unit" in loaded.declarations.subjects[0]), "an undeclared unit became a present key");
  assert(loaded.declarationHash === EXPECTED_HASH, `the fixture's hash moved: ${loaded.declarationHash}`);
});

check("S201: a declared unit LOADS whole and MOVES the hash — it is inside the digest", () => {
  const d = clone();
  d.subjects[0].unit = "unit-a";
  const loaded = validateDeclarations(d);
  assert(loaded.declarations.subjects[0].unit === "unit-a", JSON.stringify(loaded.declarations.subjects[0]));
  assert(loaded.declarationHash !== validateDeclarations(clone()).declarationHash, "declaring a unit did NOT move the hash");
  const templ = clone();
  templ.subjects[0].unit = "unit-a@x.y:z_1";
  assert(validateDeclarations(templ).declarations.subjects[0].unit === "unit-a@x.y:z_1", "a template-shaped unit name must load");
});

check("S201: a unit that is not a unit name is REFUSED at subjects[i].unit", () => {
  for (const bad of ["", "unit a", "unit-a;true", "unit/a", "unit-a\n", 7, null, true]) {
    const d = clone();
    d.subjects[0].unit = bad;
    assertRejectedSaying(() => validateDeclarations(d), "subjects[0].unit", "systemd unit name");
  }
});

check("ROUND 3 (A8): the unit refusal QUOTES the pattern actually enforced — the quoted pattern itself refuses the refused value", () => {
  // Reviews K3D3-7, K3D1-9: the reason quoted ^[A-Za-z0-9@_.:-]+$, which ACCEPTS
  // "-x" and "--user", the very values the rule refuses. Read by BEHAVIOUR: the
  // pattern in the message is compiled and run on the value it refused.
  for (const bad of ["-x", "--user", "unit-a\n"]) {
    const d = clone();
    d.subjects[0].unit = bad;
    let msg = "";
    try {
      validateDeclarations(d);
    } catch (err) {
      if (!(err instanceof DeclarationRejected)) throw err;
      msg = err.message;
    }
    const quoted = /matching (\^\S+)/.exec(msg);
    assert(quoted !== null, `the unit refusal quotes no pattern: ${msg}`);
    assert(!new RegExp(quoted![1], "u").test(bad), `the quoted pattern ${quoted![1]} ACCEPTS ${JSON.stringify(bad)}, the value it refused`);
  }
});

check("S201: the TREE declaration declares a unit for EVERY subject — the relay's cutover refuses one that does not", () => {
  const loaded = loadDeclarations(SHIPPED_PATH).declarations;
  const without = loaded.subjects.filter((x) => typeof x.unit !== "string").map((x) => x.subject);
  assert(without.length === 0, `subjects with no declared unit: ${JSON.stringify(without)}`);
});

check("S201 SCHEMA: subjects[].unit agrees THREE ways (loader, subset evaluator, real Draft 2020-12)", () => {
  type URow = { name: string; unit: unknown; expect: "BOTH_ACCEPT" | "BOTH_REFUSE" };
  const rows: URow[] = [
    { name: "absent", unit: undefined, expect: "BOTH_ACCEPT" },
    { name: "plain", unit: "unit-a", expect: "BOTH_ACCEPT" },
    { name: "template", unit: "unit-a@x.y:z_1", expect: "BOTH_ACCEPT" },
    { name: "empty", unit: "", expect: "BOTH_REFUSE" },
    { name: "space", unit: "unit a", expect: "BOTH_REFUSE" },
    { name: "semicolon", unit: "unit-a;true", expect: "BOTH_REFUSE" },
    { name: "slash", unit: "unit/a", expect: "BOTH_REFUSE" },
    { name: "number", unit: 7, expect: "BOTH_REFUSE" },
    // ROUND 3 (A7): Python's re let `$` match before a final newline.
    { name: "trailing newline", unit: "unit-a\n", expect: "BOTH_REFUSE" },
    { name: "leading dash", unit: "-x", expect: "BOTH_REFUSE" },
    { name: "option-shaped", unit: "--user", expect: "BOTH_REFUSE" },
  ];
  const docs = rows.map((r) => {
    const d = clone();
    if (r.unit !== undefined) d.subjects[0].unit = r.unit;
    return d;
  });
  let real: number[];
  try {
    real = realValidatorCounts(docs);
  } catch (err) {
    throw new Error(`the real Draft 2020-12 validator could not run, and this arm does NOT skip: ${String((err as { stderr?: unknown }).stderr ?? err).slice(0, 300)}`);
  }
  const wrong: string[] = [];
  rows.forEach((r, i) => {
    const loader = loaderAccepts(docs[i]);
    const subset = evalSchema(committedSchema, docs[i], "$").length === 0;
    const realOk = real[i] === 0;
    const want = r.expect === "BOTH_ACCEPT";
    if (loader !== want || subset !== want || realOk !== want) {
      wrong.push(`${r.name}: expected ${r.expect}; loader ${String(loader)}, subset ${String(subset)}, real ${String(realOk)}`);
    }
  });
  assert(wrong.length === 0, `subjects[].unit: schema and loader disagree:\n    ${wrong.join("\n    ")}`);
});

// ── GATE 2 · Stop 2 · `readers.gate2Direction` and top-level `baskets` ───────
//
// WHAT THESE ARMS ARE FOR. Gate 2 reads direction over a DEPLOYER-DECLARED
// basket, so the basket is the one input that decides what the reader can say.
// Build contract §4 names fifteen front-door refusals; each gets its own arm
// below, and each refusal is asserted by the field it cites AND by the words
// `refusal R<n> —`, so two rules that cite one field stay two findings. The
// parity walk probes the new closed nodes through its sixth base; the GATE 2
// SCHEMA arm pins what the schema CAN say against what only the loader can.
//
// ⛔ FIXTURES USE INVENTED NAMES (subject-a, tool-x, c-self/c-other/c-shared).
//    The ONE arm about the live candidate's shape reads the served subject and
//    its frame BY USE off the tree declaration; nothing here names a subject.
// ⛔ FUNCTION DECLARATIONS, NO MODULE-LEVEL CONSTANT: the parity walk's sixth
//    base calls `g2Declared` ~2900 lines ABOVE this block (the g1 reason).

function g2Basis(): string {
  return "GATE 2 FIXTURE, not a declaration. Exercises the loader's basket rules.";
}

/** An unknown[] class in the contract §6 shape: outcome null, EG-1, bearing on one declared category. */
function g2Unknown(kind: string, lane: string, extra: Record<string, unknown> = {}): any {
  return { kind, outcome: null, lane, eg: 1, bearsOn: ["c-other"], basis: g2Basis(), ...extra };
}

/** A signed class at EG-1 on a subject-writable kind. Only value[] admits one today (R8). */
function g2Signed(kind: string, extra: Record<string, unknown> = {}): any {
  return {
    kind,
    outcome: "OK",
    weight: { lo: 0.5, hi: 1 },
    lane: "A",
    eg: 1,
    rhoCausal: 0.5,
    falsifiability: "FIXTURE: a record of the same kind with the other outcome would show the sign wrong",
    bearsOn: ["c-self"],
    basis: g2Basis(),
    ...extra,
  };
}

/** Contract §6's basket SHAPE — the live candidate's content over the fixture's frame ids. */
function g2LiveShapeBasket(): any {
  return {
    classes: {
      value: {
        value: [],
        damage: [],
        unknown: [
          g2Unknown("HELD_THEN_STOPPED", "B"),
          g2Unknown("TURN_ENDED_ASKING", "C"),
          g2Unknown("HELD_THEN_DIVERGED", "C"),
          g2Unknown("HELD_THEN_RETRIED", "A"),
          g2Unknown("ACT_REVISITED", "C"),
        ],
      },
      basis: g2Basis(),
      proxy: true,
    },
    epsilonNum: { value: 1e-6, basis: g2Basis(), proxy: false },
    grades: { value: { establishAt: { lane: "A", eg: 1 }, creditAt: { lane: "B", eg: 2 } }, basis: g2Basis(), proxy: true },
    window: { value: { kind: "sinceBoundary" }, basis: g2Basis(), proxy: false },
    nMin: { value: 10, basis: g2Basis(), proxy: true },
    latchClearedBy: { value: [{ kind: "ARBITER_RESOLVED" }], basis: g2Basis(), proxy: false },
  };
}

/** The §6 shape plus a value class and a magnitude on unknown[0] — every optional member present once. */
function g2RichBasket(): any {
  const b = g2LiveShapeBasket();
  b.classes.value.value = [g2Signed("TOOL_RESULT")];
  b.classes.value.unknown[0].magnitude = { hi: 2 };
  return b;
}

/** g1Declared (frame, Gate 1 reader, book) plus the Gate 2 reader and a basket for the same subject. */
function g2Declared(subjectId = "subject-a", basket?: any): any {
  const d = g1Declared(subjectId);
  d.readers.gate2Direction = { subject: { value: subjectId, basis: g2Basis(), proxy: false } };
  d.baskets = { [subjectId]: basket ?? g2LiveShapeBasket() };
  return d;
}

/** The fixture subject's basket, for mutation. */
function g2B(d: any): any {
  return d.baskets["subject-a"];
}

const G2_LF = "baskets.subject-a.classes.value";

/** Refused at `field`, SAYING rule `n` — the X-rule style. */
function g2Refused(d: any, field: string, n: number): void {
  assertRejectedSaying(() => validateDeclarations(d), field, `refusal R${String(n)} —`);
}

check("GATE 2: the reader + the contract §6 basket SHAPE LOAD through BOTH front doors and survive validation WHOLE; so does the rich basket", () => {
  for (const basket of [g2LiveShapeBasket(), g2RichBasket()]) {
    const d = g2Declared("subject-a", basket);
    let loaded: Declarations;
    try {
      loaded = validateDeclarations(d).declarations;
    } catch (err) {
      if (err instanceof DeclarationRejected) {
        throw new Error(
          `the gate 2 declaration was REFUSED at "${err.field}": ${err.message}. If the field is "$.baskets" or ` +
            `"readers.gate2Direction", a front door's allow-list is missing its key and the reader is unreachable.`
        );
      }
      throw err;
    }
    assert(canonicalHash(loaded.baskets) === canonicalHash(d.baskets), `the loaded basket is not the declared one:\n  ${JSON.stringify(loaded.baskets)}`);
    assert(canonicalHash(loaded.readers.gate2Direction) === canonicalHash(d.readers.gate2Direction), "the loaded gate2Direction is not the declared one");
    // And the WHOLE document survives: the loader adds no key and drops none.
    assert(validateDeclarations(d).declarationHash === canonicalHash(d), "the loaded declaration is not the declared document");
  }
});

check("GATE 2: undeclared, baskets and gate2Direction are ABSENT KEYS and the fixture still hashes to EXPECTED_HASH; declared, both MOVE the hash", () => {
  const loaded = loadDeclarations(DRAFT_PATH);
  assert(!("baskets" in loaded.declarations), "baskets is a PRESENT key on a declaration that does not declare it");
  assert(!("gate2Direction" in loaded.declarations.readers), "gate2Direction is a PRESENT key on a declaration that does not declare it");
  assert(loaded.declarationHash === EXPECTED_HASH, `the fixture's hash MOVED: ${loaded.declarationHash}`);
  const g1 = validateDeclarations(g1Declared()).declarationHash;
  const basketOnly = g1Declared();
  basketOnly.baskets = { "subject-a": g2LiveShapeBasket() };
  const withBasket = validateDeclarations(basketOnly).declarationHash;
  const withBoth = validateDeclarations(g2Declared()).declarationHash;
  assert(withBasket !== g1, "declaring baskets did NOT move the hash — the validated basket is outside validate()'s returned object");
  assert(withBoth !== withBasket, "declaring readers.gate2Direction did NOT move the hash");
  const edited = g2Declared();
  g2B(edited).classes.value.unknown[0].lane = "A";
  assert(validateDeclarations(edited).declarationHash !== withBoth, "a class's lane moved and the hash did not");
});

check("GATE 2 · THE LIVE CANDIDATE'S SHAPE: the tree's frame + the reader + the §6 basket, rebuilt HERE BY USE (not the seat's file), LOADS — no class at grade, so the reading it predicts is G2_NO_CLASS_AT_GRADE", () => {
  // The seat builds the S29 candidate from the LIVE bytes; this arm only proves
  // the changed loader admits that SHAPE over the served frame. Subject and
  // category are read off the tree declaration, never typed.
  const d = JSON.parse(JSON.stringify(shipped));
  const subj = d.readers.gate1Scope.subject.value;
  const cat = d.frame[subj].categories.value[0].id;
  const basket = g2LiveShapeBasket();
  for (const u of basket.classes.value.unknown) u.bearsOn = [cat];
  // S34: the tree's Gate 2 now reads HARM on the book; this arm is about the class-basket SHAPE, so harm goes.
  delete d.harm;
  d.readers.gate2Direction = { subject: { value: subj, basis: g2Basis(), proxy: false } };
  d.baskets = { [subj]: basket };
  const loaded = validateDeclarations(d).declarations;
  const b = loaded.baskets![subj];
  assert(b.classes.value.value.length === 0 && b.classes.value.damage.length === 0, "the §6 basket declares a value or damage class");
  assert(b.classes.value.unknown.length === 5 && b.classes.value.unknown.every((u) => u.eg === 1 && u.outcome === null), JSON.stringify(b.classes.value.unknown));
  // Contract §2 step 6: no value class passing CVG and no damage class at >= establishAt -> G2_NO_CLASS_AT_GRADE.
  // The tree declares paths.clerkStamps, so the wiring needs a stamps loader: a stub, as the ACT B arms use.
  const opts: any = toWireOptions(loaded, (p: string) => p, () => [] as any);
  assert(opts.gate2.value.length === 0 && opts.gate2.damage.length === 0, "the wire carries a class at grade");
  assert(JSON.stringify(opts.gate2.frameCategories) === JSON.stringify(d.frame[subj].categories.value.map((c: any) => c.id)), "frameCategories is not the served frame's ids");
  assert(/^G2_BASKET@[0-9a-f]{16}$/.test(opts.gate2.basketClass), opts.gate2.basketClass);
});

// ── the refusals, one arm each, in the contract's order ─────────────────────

check("GATE 2 R1: the reader naming no subject, an unframed one or an unbasketed one, and a basket for no subject or an unframed one, are each REFUSED saying R1", () => {
  const undeclared = g2Declared();
  undeclared.readers.gate2Direction.subject.value = "subject-b";
  g2Refused(undeclared, "readers.gate2Direction.subject", 1);
  // No frame: Gate 1's reader and the basket go with it, so the row reads R1's frame half alone.
  const unframed = g2Declared();
  delete unframed.frame;
  delete unframed.readers.gate1Scope;
  delete unframed.baskets;
  assertRejectedSaying(() => validateDeclarations(unframed), "readers.gate2Direction.subject", "has no frame.subject-a");
  g2Refused(unframed, "readers.gate2Direction.subject", 1);
  const unbasketed = g2Declared();
  delete unbasketed.baskets;
  assertRejectedSaying(() => validateDeclarations(unbasketed), "readers.gate2Direction.subject", "has no baskets.subject-a");
  g2Refused(unbasketed, "readers.gate2Direction.subject", 1);
  const stray = g2Declared();
  stray.baskets["subject-z"] = g2LiveShapeBasket();
  g2Refused(stray, "baskets.subject-z", 1);
  const unframedBasket = g2Declared();
  unframedBasket.subjects.push({ ...unframedBasket.subjects[1], subject: "subject-b" });
  unframedBasket.baskets["subject-b"] = g2LiveShapeBasket();
  g2Refused(unframedBasket, "baskets.subject-b", 1);
});

check("GATE 2: a basket WITHOUT the reader LOADS — the basket is a declaration, the reader a separate switch (contract silent; flagged)", () => {
  const d = g2Declared();
  delete d.readers.gate2Direction;
  const loaded = validateDeclarations(d).declarations;
  assert(loaded.baskets !== undefined && !("gate2Direction" in loaded.readers), "the basket did not load without its reader");
});

check("GATE 2: an EMPTY baskets ({}) is REFUSED at \"baskets\" — it would move the hash and declare nothing", () => {
  const d = g2Declared();
  d.baskets = {};
  delete d.readers.gate2Direction;
  assertRejectedSaying(() => validateDeclarations(d), "baskets", "declares nothing");
});

check("GATE 2 R2: NO DAMAGE TERM NAMED — damage[] and unknown[] both empty is REFUSED saying R2; a missing list or classes is R2's too", () => {
  const d = g2Declared();
  g2B(d).classes.value.unknown = [];
  g2Refused(d, G2_LF, 2);
  const withValueOnly = g2Declared("subject-a", g2RichBasket());
  g2B(withValueOnly).classes.value.unknown = [];
  g2Refused(withValueOnly, G2_LF, 2);
  const noList = g2Declared();
  delete g2B(noList).classes.value.damage;
  g2Refused(noList, `${G2_LF}.damage`, 2);
  const noClasses = g2Declared();
  delete g2B(noClasses).classes;
  g2Refused(noClasses, "baskets.subject-a.classes", 2);
});

check("GATE 2 R3: a kind the subject chain does not carry is REFUSED saying R3 — in a class list and in latchClearedBy", () => {
  for (const bad of ["NOT_A_KIND", "tool_result", "", 7]) {
    const d = g2Declared();
    g2B(d).classes.value.unknown[0].kind = bad;
    g2Refused(d, `${G2_LF}.unknown[0].kind`, 3);
  }
  const latch = g2Declared();
  g2B(latch).latchClearedBy.value = [{ kind: "NOT_A_KIND" }];
  g2Refused(latch, "baskets.subject-a.latchClearedBy.value[0].kind", 3);
});

check("GATE 2 R4: every HELD_THEN_* kind in value[] is REFUSED saying R4 (audit 19:51Z ③) — and the same kinds LOAD in unknown[]", () => {
  const held = SUBJECT_EVENT_KINDS.filter((k) => k.startsWith("HELD_THEN_"));
  assert(held.length === 3 && held.includes("HELD_THEN_STOPPED"), `the hold-response kinds moved: ${JSON.stringify(held)}`);
  for (const k of held) {
    const d = g2Declared();
    // The kind leaves unknown[] first, so nothing but R4 can refuse the row.
    g2B(d).classes.value.unknown = g2B(d).classes.value.unknown.filter((u: any) => u.kind !== k);
    g2B(d).classes.value.value = [g2Signed(k)];
    g2Refused(d, `${G2_LF}.value[0].kind`, 4);
  }
  // The control is the §6 basket itself: three of its five unknowns are HELD_THEN_*.
  validateDeclarations(g2Declared());
});

check("GATE 2 R5: every SUNSET kind is REFUSED saying R5 in value[], damage[] and unknown[] (F3; 04c:107-113)", () => {
  assert(SUNSET_KINDS.length > 0, "precondition: mica-service exports no sunset kinds");
  for (const k of SUNSET_KINDS) {
    const u = g2Declared();
    g2B(u).classes.value.unknown[0].kind = k;
    g2Refused(u, `${G2_LF}.unknown[0].kind`, 5);
    const v = g2Declared();
    g2B(v).classes.value.value = [g2Signed(k)];
    g2Refused(v, `${G2_LF}.value[0].kind`, 5);
    const dm = g2Declared();
    g2B(dm).classes.value.damage = [g2Signed(k)];
    g2Refused(dm, `${G2_LF}.damage[0].kind`, 5);
  }
});

check("GATE 2 R6: the five F4 kinds are REFUSED saying R6 (08a:73-75); GATE2_F4_REFUSED_KINDS holds them AND every operator kind, and each member is refused in every list", () => {
  const named = ["TOOL_HELD_NOT_EXECUTED", "TOOL_EXECUTED", "ACT_CLOSED", "ASK_ANSWERED", "DOCTOR_ATTESTED"];
  for (const k of named) {
    assert(GATE2_F4_REFUSED_KINDS.includes(k), `${k} is missing from GATE2_F4_REFUSED_KINDS`);
    const d = g2Declared();
    g2B(d).classes.value.unknown[0].kind = k;
    g2Refused(d, `${G2_LF}.unknown[0].kind`, 6);
  }
  for (const k of [...OPERATOR_SUNSET_KINDS, "DOCTOR_ATTESTED"]) {
    assert(GATE2_F4_REFUSED_KINDS.includes(k), `operator kind ${k} is missing from GATE2_F4_REFUSED_KINDS`);
  }
  // Every member, every list: refused, by R5 (it is also a sunset kind) or R6.
  for (const k of GATE2_F4_REFUSED_KINDS) {
    for (const list of ["value", "damage", "unknown"] as const) {
      const d = g2Declared();
      const lists = g2B(d).classes.value;
      if (list === "unknown") lists.unknown[0].kind = k;
      else lists[list] = [g2Signed(k)];
      let msg = "";
      try {
        validateDeclarations(d);
      } catch (err) {
        if (!(err instanceof DeclarationRejected)) throw err;
        msg = err.message;
      }
      assert(msg.includes("refusal R5 —") || msg.includes("refusal R6 —"), `${k} in ${list}[] was not refused by R5/R6: ${msg || "it LOADED"}`);
    }
  }
});

check("GATE 2 R7: a subject-writable kind above EG-1 is REFUSED saying R7 (EG stays 1) — value and unknown; EG-0 and EG-1 LOAD", () => {
  const v = g2Declared("subject-a", g2RichBasket());
  g2B(v).classes.value.value[0].eg = 2;
  g2Refused(v, `${G2_LF}.value[0].eg`, 7);
  for (const eg of [2, 3]) {
    const u = g2Declared();
    g2B(u).classes.value.unknown[0].eg = eg;
    g2Refused(u, `${G2_LF}.unknown[0].eg`, 7);
  }
  for (const eg of [0, 1]) {
    const ok = g2Declared("subject-a", g2RichBasket());
    g2B(ok).classes.value.value[0].eg = eg;
    g2B(ok).classes.value.unknown[0].eg = eg;
    validateDeclarations(ok);
  }
});

check("GATE 2 R8: while GATE2_SUBJECT_WRITABLE_DAMAGE_REFUSED holds, a damage class on ANY subject-writable kind is REFUSED saying R8 — so no damage class loads today (S206's ticket flips the flag)", () => {
  assert(
    GATE2_SUBJECT_WRITABLE_DAMAGE_REFUSED === true,
    "the R8 flag is OFF. Only S206's ticket may flip it, and that ticket updates this arm in the same commit."
  );
  let r8 = 0;
  for (const k of SUBJECT_EVENT_KINDS) {
    const d = g2Declared();
    g2B(d).classes.value.damage = [g2Signed(k, { outcome: "DAMAGE_FIXTURE" })];
    let msg = "";
    try {
      validateDeclarations(d);
    } catch (err) {
      if (!(err instanceof DeclarationRejected)) throw err;
      msg = err.message;
    }
    assert(msg !== "", `a damage class on ${k} LOADED — R8 says none may until S206`);
    if (isGate2SubjectWritableKind(k) && !GATE2_SUNSET_KINDS.includes(k) && !GATE2_F4_REFUSED_KINDS.includes(k)) {
      assert(msg.includes("refusal R8 —"), `${k} in damage[] was refused, but not by R8: ${msg}`);
      r8++;
    }
  }
  assert(r8 >= 1, "no kind reached R8 — the arm is testing nothing");
  g2Refused(
    (() => {
      const d = g2Declared();
      g2B(d).classes.value.damage = [g2Signed("TOOL_RESULT")];
      return d;
    })(),
    `${G2_LF}.damage[0].kind`,
    8
  );
});

check("GATE 2 R9: a malformed class is REFUSED saying R9 — grade, weight, rhoCausal, falsifiability, outcome, basis; an UNKNOWN that is weighted; a SIGNED class with a magnitude", () => {
  type Case = { name: string; mutate: (b: any) => void; field: string };
  const V = (b: any) => b.classes.value.value[0];
  const U = (b: any) => b.classes.value.unknown[0];
  const cases: Case[] = [
    { name: "no lane", mutate: (b) => delete U(b).lane, field: `${G2_LF}.unknown[0].lane` },
    { name: "lane D", mutate: (b) => (U(b).lane = "D"), field: `${G2_LF}.unknown[0].lane` },
    { name: "no eg", mutate: (b) => delete U(b).eg, field: `${G2_LF}.unknown[0].eg` },
    { name: "eg 4", mutate: (b) => (U(b).eg = 4), field: `${G2_LF}.unknown[0].eg` },
    { name: "eg as a string", mutate: (b) => (U(b).eg = "1"), field: `${G2_LF}.unknown[0].eg` },
    { name: "eg 1.5", mutate: (b) => (U(b).eg = 1.5), field: `${G2_LF}.unknown[0].eg` },
    { name: "value without weight", mutate: (b) => delete V(b).weight, field: `${G2_LF}.value[0].weight` },
    { name: "weight lo > hi", mutate: (b) => (V(b).weight = { lo: 2, hi: 1 }), field: `${G2_LF}.value[0].weight` },
    { name: "weight lo negative", mutate: (b) => (V(b).weight.lo = -1), field: `${G2_LF}.value[0].weight.lo` },
    { name: "weight hi not finite", mutate: (b) => (V(b).weight.hi = Infinity), field: `${G2_LF}.value[0].weight.hi` },
    { name: "weight lo NaN", mutate: (b) => (V(b).weight.lo = NaN), field: `${G2_LF}.value[0].weight.lo` },
    { name: "rhoCausal above 1", mutate: (b) => (V(b).rhoCausal = 1.5), field: `${G2_LF}.value[0].rhoCausal` },
    { name: "rhoCausal below 0", mutate: (b) => (V(b).rhoCausal = -0.1), field: `${G2_LF}.value[0].rhoCausal` },
    { name: "rhoCausal missing", mutate: (b) => delete V(b).rhoCausal, field: `${G2_LF}.value[0].rhoCausal` },
    { name: "falsifiability empty", mutate: (b) => (V(b).falsifiability = ""), field: `${G2_LF}.value[0].falsifiability` },
    { name: "falsifiability missing", mutate: (b) => delete V(b).falsifiability, field: `${G2_LF}.value[0].falsifiability` },
    { name: "an UNKNOWN with a weight", mutate: (b) => (U(b).weight = { lo: 0, hi: 1 }), field: `${G2_LF}.unknown[0].weight` },
    { name: "an UNKNOWN with a rhoCausal", mutate: (b) => (U(b).rhoCausal = 0.5), field: `${G2_LF}.unknown[0].rhoCausal` },
    { name: "an UNKNOWN with a falsifiability", mutate: (b) => (U(b).falsifiability = "x"), field: `${G2_LF}.unknown[0].falsifiability` },
    { name: "magnitude.hi negative", mutate: (b) => (U(b).magnitude = { hi: -1 }), field: `${G2_LF}.unknown[0].magnitude.hi` },
    { name: "magnitude.hi 0 (UNKNOWN = zero)", mutate: (b) => (U(b).magnitude = { hi: 0 }), field: `${G2_LF}.unknown[0].magnitude.hi` },
    { name: "magnitude.hi not finite", mutate: (b) => (U(b).magnitude = { hi: Infinity }), field: `${G2_LF}.unknown[0].magnitude.hi` },
    { name: "a SIGNED class with a magnitude", mutate: (b) => (V(b).magnitude = { hi: 1 }), field: `${G2_LF}.value[0].magnitude` },
    { name: "outcome missing (no default)", mutate: (b) => delete U(b).outcome, field: `${G2_LF}.unknown[0].outcome` },
    { name: "outcome empty", mutate: (b) => (U(b).outcome = ""), field: `${G2_LF}.unknown[0].outcome` },
    { name: "outcome a number", mutate: (b) => (U(b).outcome = 7), field: `${G2_LF}.unknown[0].outcome` },
    { name: "basis empty", mutate: (b) => (U(b).basis = ""), field: `${G2_LF}.unknown[0].basis` },
  ];
  for (const c of cases) {
    const d = g2Declared("subject-a", g2RichBasket());
    c.mutate(g2B(d));
    try {
      g2Refused(d, c.field, 9);
    } catch (err) {
      throw new Error(`${c.name}: ${(err as Error).message}`);
    }
  }
});

check("GATE 2 R10: ε, nMin, the window and the grades are REFUSED saying R10 when missing or malformed; ε = 0 LOADS", () => {
  const B = "baskets.subject-a";
  type Case = { name: string; mutate: (b: any) => void; field: string };
  const cases: Case[] = [
    { name: "epsilonNum missing", mutate: (b) => delete b.epsilonNum, field: `${B}.epsilonNum` },
    { name: "epsilonNum negative", mutate: (b) => (b.epsilonNum.value = -1e-6), field: `${B}.epsilonNum.value` },
    { name: "epsilonNum not finite", mutate: (b) => (b.epsilonNum.value = Infinity), field: `${B}.epsilonNum.value` },
    { name: "epsilonNum a string", mutate: (b) => (b.epsilonNum.value = "1e-6"), field: `${B}.epsilonNum.value` },
    { name: "nMin 0", mutate: (b) => (b.nMin.value = 0), field: `${B}.nMin.value` },
    { name: "nMin 2.5", mutate: (b) => (b.nMin.value = 2.5), field: `${B}.nMin.value` },
    { name: "nMin 2^53 (not a safe integer; the reader would read the basket malformed)", mutate: (b) => (b.nMin.value = 2 ** 53), field: `${B}.nMin.value` },
    { name: "nMin missing", mutate: (b) => delete b.nMin, field: `${B}.nMin` },
    { name: "window trailing", mutate: (b) => (b.window.value.kind = "trailing"), field: `${B}.window.value.kind` },
    { name: "window missing", mutate: (b) => delete b.window, field: `${B}.window` },
    { name: "establishAt eg 5", mutate: (b) => (b.grades.value.establishAt.eg = 5), field: `${B}.grades.value.establishAt.eg` },
    { name: "creditAt lane Z", mutate: (b) => (b.grades.value.creditAt.lane = "Z"), field: `${B}.grades.value.creditAt.lane` },
    { name: "creditAt missing", mutate: (b) => delete b.grades.value.creditAt, field: `${B}.grades.value.creditAt` },
    { name: "grades missing", mutate: (b) => delete b.grades, field: `${B}.grades` },
  ];
  for (const c of cases) {
    const d = g2Declared();
    c.mutate(g2B(d));
    try {
      g2Refused(d, c.field, 10);
    } catch (err) {
      throw new Error(`${c.name}: ${(err as Error).message}`);
    }
  }
  const zero = g2Declared();
  g2B(zero).epsilonNum.value = 0;
  validateDeclarations(zero);
});

check("GATE 2 R11: latchClearedBy empty, naming any kind but the arbiter's (ruling F5), or naming one twice is REFUSED saying R11 — and every kind it admits is one the route REFUSES to the subject (BY BEHAVIOUR)", () => {
  const L = "baskets.subject-a.latchClearedBy.value";
  const empty = g2Declared();
  g2B(empty).latchClearedBy.value = [];
  g2Refused(empty, L, 11);
  // subject-writable kinds, AND the operator kinds that are not the arbiter's record
  for (const k of ["TOOL_RESULT", "HELD_THEN_STOPPED", "SUNSET_HELD", "ORDER_PRESENTED", "DOCTOR_ATTESTED", "ENDING_ORDERED", "ENDING_PAPER_TIMEBOX"]) {
    const d = g2Declared();
    g2B(d).latchClearedBy.value = [{ kind: k }];
    g2Refused(d, `${L}[0].kind`, 11);
  }
  const twice = g2Declared();
  g2B(twice).latchClearedBy.value = [{ kind: "ARBITER_RESOLVED" }, { kind: "ARBITER_RESOLVED" }];
  g2Refused(twice, `${L}[1].kind`, 11);
  // BY BEHAVIOUR: the latch loads iff the kind is the arbiter's; every such kind is one
  // mica-service's own route rule REFUSES to a subject-role uid. An invented uid.
  const subjectRoute = [{ uid: 4242, role: "subject" }];
  for (const k of SUBJECT_EVENT_KINDS) {
    const d = g2Declared();
    g2B(d).latchClearedBy.value = [{ kind: k }];
    assert(loaderAccepts(d) === GATE2_ARBITER_CLEARING_KINDS.includes(k), `${k}: the latch ${loaderAccepts(d) ? "LOADS" : "is refused"}`);
  }
  for (const k of GATE2_ARBITER_CLEARING_KINDS) {
    assert(!authorizeSubjectEventKind(subjectRoute, 4242, k as (typeof SUBJECT_EVENT_KINDS)[number]).allowed, `${k}: an admitted clearer the subject may post`);
  }
  assert(JSON.stringify(GATE2_ARBITER_CLEARING_KINDS) === JSON.stringify(["ARBITER_RESOLVED"]), "the arbiter's clearing kinds moved");
});

check("GATE 2 R12: bearsOn empty, naming a category outside frame[subject], or naming one twice is REFUSED saying R12; the self category and two ids LOAD", () => {
  const F = `${G2_LF}.unknown[0].bearsOn`;
  const cases: [unknown, string][] = [
    [[], F],
    [["c-elsewhere"], `${F}[0]`],
    [["c-other", "c-other"], `${F}[1]`],
    [[7], `${F}[0]`],
  ];
  for (const [bears, field] of cases) {
    const d = g2Declared();
    g2B(d).classes.value.unknown[0].bearsOn = bears;
    g2Refused(d, field, 12);
  }
  const missing = g2Declared();
  delete g2B(missing).classes.value.unknown[0].bearsOn;
  g2Refused(missing, F, 12);
  const ok = g2Declared();
  g2B(ok).classes.value.unknown[0].bearsOn = ["c-self", "c-shared"];
  validateDeclarations(ok);
});

check("GATE 2 R13: one record, one class — a duplicate (kind, outcome), one kind in two lists, and a null-outcome class beside an outcome class of its kind are each REFUSED saying R13; two DIFFERENT outcomes of one kind LOAD", () => {
  const dup = g2Declared();
  g2B(dup).classes.value.unknown.push(g2Unknown("HELD_THEN_STOPPED", "B"));
  g2Refused(dup, `${G2_LF}.unknown[5]`, 13);
  const twoLists = g2Declared();
  g2B(twoLists).classes.value.value = [g2Signed("TURN_ENDED_ASKING", { outcome: null })];
  g2Refused(twoLists, `${G2_LF}.unknown[1]`, 13);
  const nullBeside = g2Declared();
  g2B(nullBeside).classes.value.unknown.push(g2Unknown("ACT_REVISITED", "C", { outcome: "NONZERO" }));
  assertRejectedSaying(() => validateDeclarations(nullBeside), `${G2_LF}.unknown[5]`, "a null outcome matches EVERY record of the kind");
  g2Refused(nullBeside, `${G2_LF}.unknown[5]`, 13);
  const split = g2Declared();
  const u = g2B(split).classes.value.unknown;
  u[4] = g2Unknown("ACT_REVISITED", "C", { outcome: "NONZERO" });
  u.push(g2Unknown("ACT_REVISITED", "C", { outcome: "TIMEOUT" }));
  validateDeclarations(split);
});

check("GATE 2 R14: every Gate 2 key set is CLOSED and an own __proto__ anywhere in the stanza is REFUSED — each saying R14", () => {
  const LF = G2_LF;
  const B = "baskets.subject-a";
  const cases: [string, (d: any) => void, string][] = [
    ["readers.gate2Direction", (d) => (d.readers.gate2Direction.extra = 1), "readers.gate2Direction.extra"],
    ["the basket", (d) => (g2B(d).extra = 1), `${B}.extra`],
    ["the classes envelope", (d) => (g2B(d).classes.note = "x"), `${B}.classes.note`],
    ["classes.value", (d) => (g2B(d).classes.value.neutral = []), `${LF}.neutral`],
    ["a signed class", (d) => (g2B(d).classes.value.value[0].note = "x"), `${LF}.value[0].note`],
    ["an unknown class", (d) => (g2B(d).classes.value.unknown[1].note = "x"), `${LF}.unknown[1].note`],
    ["a weight", (d) => (g2B(d).classes.value.value[0].weight.mid = 0.7), `${LF}.value[0].weight.mid`],
    ["a magnitude", (d) => (g2B(d).classes.value.unknown[0].magnitude.lo = 0), `${LF}.unknown[0].magnitude.lo`],
    ["the epsilonNum envelope", (d) => (g2B(d).epsilonNum.note = "x"), `${B}.epsilonNum.note`],
    ["grades.value", (d) => (g2B(d).grades.value.reviewAt = { lane: "A", eg: 1 }), `${B}.grades.value.reviewAt`],
    ["a grade", (d) => (g2B(d).grades.value.establishAt.note = "x"), `${B}.grades.value.establishAt.note`],
    ["window.value", (d) => (g2B(d).window.value.size = 10), `${B}.window.value.size`],
    ["a latch item", (d) => (g2B(d).latchClearedBy.value[0].outcome = null), `${B}.latchClearedBy.value[0].outcome`],
  ];
  for (const [name, mutate, field] of cases) {
    const d = g2Declared("subject-a", g2RichBasket());
    mutate(d);
    try {
      g2Refused(d, field, 14);
    } catch (err) {
      throw new Error(`${name}: ${(err as Error).message}`);
    }
  }
  // An OWN "__proto__" (what JSON.parse gives), at three depths of the stanza.
  const asKey = g2Declared();
  g1DefineOwn(asKey.baskets, "__proto__", g2LiveShapeBasket());
  g2Refused(asKey, "baskets.__proto__", 14);
  const inClass = g2Declared();
  g1DefineOwn(g2B(inClass).classes.value.unknown[0], "__proto__", { kind: "TOOL_RESULT" });
  g2Refused(inClass, `${LF}.unknown[0].__proto__`, 14);
  const inReader = g2Declared();
  g1DefineOwn(inReader.readers.gate2Direction, "__proto__", {});
  g2Refused(inReader, "readers.gate2Direction.__proto__", 14);
});

// ── R15 · the reload door ────────────────────────────────────────────────────

function g2Loaded(mutate?: (d: any) => void): Declarations {
  const d = g2Declared();
  if (mutate) mutate(d);
  return validateDeclarations(d).declarations;
}

check("GATE 2 R15: FIRST LOAD is never refused; the SAME basket and an ADDED basket (from none) are ACCEPTED on reload", () => {
  validateActivation(null, g2Loaded());
  const prev = g2Loaded();
  validateActivation(prev, g2Loaded());
  // From NO basket to a basket is an addition.
  const unbasketed = g1Declared();
  validateActivation(validateDeclarations(unbasketed).declarations, prev);
});

check("GATE 2 R15 · FROZEN: ANY change to a declared basket is REFUSED on reload — an ADDED entry, ε, nMin, a grade, a weight, a value entry, a clearer, a basis — each would rewrite past readings; a restart (first load) takes every one", () => {
  const prev = g2Loaded((d) => (g2B(d).classes.value.value = [g2Signed("TOOL_RESULT")]));
  const edits: [string, (d: any) => void][] = [
    ["an added unknown", (d) => g2B(d).classes.value.unknown.push(g2Unknown("TOOL_ATTEMPTED", "C"))],
    ["ε", (d) => (g2B(d).epsilonNum.value = 1e-3)],
    ["nMin", (d) => (g2B(d).nMin.value = 50)],
    ["establishAt raised", (d) => (g2B(d).grades.value.establishAt = { lane: "A", eg: 3 })],
    ["creditAt lowered", (d) => (g2B(d).grades.value.creditAt = { lane: "C", eg: 0 })],
    ["a value weight", (d) => (g2B(d).classes.value.value[0].weight = { lo: 0, hi: 9 })],
    ["the value entry dropped", (d) => (g2B(d).classes.value.value = [])],
    ["a basis", (d) => (g2B(d).classes.value.unknown[0].basis = g2Basis() + " (edited)")],
    ["a magnitude added", (d) => (g2B(d).classes.value.unknown[0].magnitude = { hi: 5 })],
  ];
  for (const [name, edit] of edits) {
    const next = g2Loaded((d) => {
      g2B(d).classes.value.value = [g2Signed("TOOL_RESULT")];
      edit(d);
    });
    assertRejectedSaying(() => validateActivation(prev, next), "baskets.subject-a", "refusal R15 —");
    assertRejectedSaying(() => validateActivation(prev, next), "baskets.subject-a", "FROZEN across reloads");
    validateActivation(null, next); // a restart takes it
  }
});

check("GATE 2 R15: a reload that DROPS an unknown entry, MOVES one out of unknown[], or REMOVES the basket is REFUSED saying R15 — and the last-known-good declaration is retained", () => {
  const prev = g2Loaded();
  const dropped = g2Loaded((d) => g2B(d).classes.value.unknown.splice(1, 1));
  assertRejectedSaying(() => validateActivation(prev, dropped), `${G2_LF}.unknown`, "refusal R15 —");
  assertRejectedSaying(() => validateActivation(prev, dropped), `${G2_LF}.unknown`, "TURN_ENDED_ASKING");
  assertRejectedSaying(() => validateActivation(prev, dropped), `${G2_LF}.unknown`, "Last-known-good declaration is retained");
  const moved = g2Loaded((d) => {
    g2B(d).classes.value.unknown.splice(1, 1);
    g2B(d).classes.value.value = [g2Signed("TURN_ENDED_ASKING", { outcome: null })];
  });
  assertRejectedSaying(() => validateActivation(prev, moved), `${G2_LF}.unknown`, "refusal R15 —");
  const narrowedOutcome = g2Loaded((d) => (g2B(d).classes.value.unknown[4].outcome = "NONZERO"));
  assertRejectedSaying(() => validateActivation(prev, narrowedOutcome), `${G2_LF}.unknown`, "refusal R15 —");
  const removed = g2Loaded((d) => {
    delete d.baskets;
    delete d.readers.gate2Direction;
  });
  // the reader rule runs first: without the reader every term of the basket goes with it
  assertRejectedSaying(() => validateActivation(prev, removed), "readers.gate2Direction", "refusal R15 —");
});

check("GATE 2 R15: a reload that removes ONLY the READER (baskets kept), or moves it to another subject, is REFUSED saying R15 — measured ACCEPTED before the fix, with no gate2 on the wire after it", () => {
  const prev = g2Loaded();
  const readerOnly = g2Loaded((d) => delete d.readers.gate2Direction);
  assert(!("gate2" in (toWireOptions(readerOnly) as Record<string, unknown>)), "premise: without the reader the wire carries no gate2");
  assertRejectedSaying(() => validateActivation(prev, readerOnly), "readers.gate2Direction", "refusal R15 —");
  assertRejectedSaying(() => validateActivation(prev, readerOnly), "readers.gate2Direction", "removes Gate 2's reader");
  // another subject, framed and basketed, so the loader admits it and only R15 can refuse
  // the X-arms' two-subject shape (one peer, two tools); subject-a keeps its frame and basket, so only the reader moves
  // AMENDED (ZERO-SUBJECTS Z4, F-5 (a)): a reload may no longer ADD subject-b, so it is declared, framed and
  //   basketed on BOTH sides and only the reader moves — R15 alone still refuses.
  const withB = (d: any): void => {
    d.subjects.push({ subject: "subject-b", toolName: "tool-y", stakesClass: d.subjects[0].stakesClass, peerUid: d.subjects[0].peerUid });
    d.frame["subject-b"] = g1Frame();
    d.baskets["subject-b"] = g2LiveShapeBasket();
  };
  const prevWithB = g2Loaded(withB);
  const moved = g2Loaded((d) => {
    withB(d);
    d.readers.gate2Direction.subject.value = "subject-b";
  });
  assertRejectedSaying(() => validateActivation(prevWithB, moved), "readers.gate2Direction.subject", "refusal R15 —");
  // CONTROL: the reader and the basket kept as they were, the reload is accepted
  validateActivation(prev, g2Loaded());
});

check("GATE 2 R15: a DROPPED damage entry is REFUSED too (built past the loader: R8 lets none load today), and the rule runs BEFORE the pilot rules' early returns", () => {
  // R8 refuses every damage class at the front door, so a prev WITH one cannot be
  // loaded today. validateActivation takes Declarations, so the damage leg is
  // exercised on a loaded object with one injected — the shape S206 will admit.
  const prev = JSON.parse(JSON.stringify(g2Loaded())) as any;
  g2B(prev).classes.value.damage = [g2Signed("TOOL_RESULT")];
  const next = g2Loaded();
  assertRejectedSaying(() => validateActivation(prev, next), `${G2_LF}.damage`, "refusal R15 —");
  const kept = JSON.parse(JSON.stringify(prev));
  validateActivation(prev, kept);
  // Past an unchanged ACTIVE pilot (the X9 early return) — and with clone()'s
  // inactive pilot every arm above already proves the other early return.
  const pilot = { active: true, sessionId: "pilot-g2", expiresAt: "2099-01-01T00:00:00Z", holdAtOrAbove: { value: draft.stakes.baseline.holdAtOrAbove.value, basis: g2Basis(), proxy: true } };
  const p1 = g2Loaded((d) => (d.pilot = pilot));
  const p2 = g2Loaded((d) => {
    d.pilot = pilot;
    g2B(d).classes.value.unknown.pop();
  });
  assertRejectedSaying(() => validateActivation(p1, p2), `${G2_LF}.unknown`, "refusal R15 —");
});


// ── the kind mirrors, held to their authorities ─────────────────────────────

check("GATE 2: the basket door's literal kind lists EQUAL mica-service's exports, and the subject-writable predicate AGREES with authorizeSubjectEventKind BY BEHAVIOUR", () => {
  const same = (a: readonly string[], b: readonly string[]) => JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());
  assert(same(GATE2_KNOWN_KINDS, SUBJECT_EVENT_KINDS), `GATE2_KNOWN_KINDS drifted from SUBJECT_EVENT_KINDS:\n  ${JSON.stringify(GATE2_KNOWN_KINDS)}\n  ${JSON.stringify(SUBJECT_EVENT_KINDS)}`);
  assert(same(GATE2_SUNSET_KINDS, SUNSET_KINDS), "GATE2_SUNSET_KINDS drifted from SUNSET_KINDS");
  // AMENDED (S208-2): + the two errand kinds, operator-only until S217's arbiter route.
  assert(same(GATE2_OPERATOR_ONLY_KINDS, ["DOCTOR_ATTESTED", ...OPERATOR_SUNSET_KINDS, ...ERRAND_KINDS]), "GATE2_OPERATOR_ONLY_KINDS is not DOCTOR_ATTESTED + OPERATOR_SUNSET_KINDS + ERRAND_KINDS");
  const subjectRoute = [{ uid: 4242, role: "subject" }];
  const operatorRoute = [{ uid: 4343, role: "operator" }];
  for (const k of SUBJECT_EVENT_KINDS) {
    const subj = authorizeSubjectEventKind(subjectRoute, 4242, k).allowed;
    const op = authorizeSubjectEventKind(operatorRoute, 4343, k).allowed;
    assert(isGate2SubjectWritableKind(k) === subj, `${k}: predicate says ${String(isGate2SubjectWritableKind(k))}, the route says the subject ${subj ? "may" : "may not"} post it`);
    // RELAY 3 HOLD (audit 2026-10-18 19:22Z (1), option (iii)): the basket door still reads the errand kinds as the
    // arbiter's (never subject-writable — the predicate above holds them to the route), but the route refuses them to
    // EVERY hand until S217-a's arbiter route, the operator's row included.
    const held = (ERRAND_KINDS as readonly string[]).includes(k);
    assert((GATE2_OPERATOR_ONLY_KINDS.includes(k) && !held) === op, `${k}: operator-only list and the route disagree`);
    if (held) assert(!op && !subj, `${k}: a hand may write a kind held out of relay 3`);
  }
  assert(!isGate2SubjectWritableKind("NOT_A_KIND"), "an unknown kind reads as subject-writable");
});

// ── to-wire-options · readers.gate2Direction -> WireOptions.gate2 ────────────

check("GATE 2 WIRE: ABSENT reader, ABSENT key — the options are BYTE-IDENTICAL with no basket, with a basket and no reader, and (minus the key) with the reader", () => {
  const plain = JSON.stringify(toWireOptions(validateDeclarations(g1Declared()).declarations));
  const basketOnly = g1Declared();
  basketOnly.baskets = { "subject-a": g2LiveShapeBasket() };
  const bo = toWireOptions(validateDeclarations(basketOnly).declarations) as Record<string, unknown>;
  assert(!("gate2" in bo), `a basket without the reader emitted gate2: ${Object.keys(bo).join(",")}`);
  assert(JSON.stringify(bo) === plain, "a basket without the reader moved the options bytes");
  const wired = toWireOptions(validateDeclarations(g2Declared()).declarations) as Record<string, unknown>;
  assert("gate2" in wired, "the reader is declared and no gate2 key was emitted");
  const { gate2: _g2, ...rest } = wired;
  void _g2;
  assert(JSON.stringify(rest) === plain, "declaring the reader moved some OTHER reader's options");
  // And the TREE (S29; since S34 Gate 2 reads HARM on the book): it emits Gate 2's keys, and without them its
  // options are BYTE-IDENTICAL to the tree minus Gate 2's leaves — declaring Gate 2 moves no other reader's options
  // on the declaration that will serve.
  const stub = (p: string) => p;
  const noStamps = () => [] as any;
  const tree = toWireOptions(loadDeclarations(SHIPPED_PATH).declarations, stub, noStamps) as Record<string, unknown>;
  assert("gate2Harm" in tree && !("gate2" in tree), "the S34 tree emitted no gate2Harm (or a class basket beside it)");
  const s28 = JSON.parse(JSON.stringify(shipped));
  delete s28.readers.gate2Direction;
  delete s28.baskets;
  delete s28.harm;
  const s28opts = toWireOptions(validateDeclarations(s28).declarations, stub, noStamps) as Record<string, unknown>;
  assert(!("gate2" in s28opts) && !("gate2Harm" in s28opts), "the tree minus Gate 2 emitted gate2 / gate2Harm");
  const G2K = ["gate2", "gate2Harm", "gate2BookPath", "gate2RosterPath", "gate2DecidingActionId", "gate2UnderivedWord"];
  const treeRest = Object.fromEntries(Object.entries(tree).filter(([k]) => !G2K.includes(k)));
  assert(JSON.stringify(treeRest) === JSON.stringify(s28opts), "declaring Gate 2 on the tree moved some OTHER reader's options");
});

check("GATE 2 WIRE: present -> EXACTLY the contract §1 shape, built from .value only, every moduleId the SUBJECT by use, no basis / proxy / falsifiability on the wire", () => {
  const opts: any = toWireOptions(validateDeclarations(g2Declared("subject-a", g2RichBasket())).declarations);
  const g = opts.gate2;
  assert(/^G2_BASKET@[0-9a-f]{16}$/.test(g.basketClass), `basketClass ${g.basketClass}`);
  const unk = (eventType: string, lane: string) => ({ moduleId: "subject-a", eventType, outcome: null, grade: { lane, eg: 1 }, bearsOn: ["c-other"] });
  const expected = {
    basketClass: g.basketClass,
    frameCategories: ["c-self", "c-other", "c-shared"],
    value: [{ moduleId: "subject-a", eventType: "TOOL_RESULT", outcome: "OK", weight: { lo: 0.5, hi: 1 }, grade: { lane: "A", eg: 1 }, rhoCausal: 0.5, bearsOn: ["c-self"] }],
    damage: [],
    unknown: [
      { ...unk("HELD_THEN_STOPPED", "B"), magnitude: { hi: 2 } },
      unk("TURN_ENDED_ASKING", "C"),
      unk("HELD_THEN_DIVERGED", "C"),
      unk("HELD_THEN_RETRIED", "A"),
      unk("ACT_REVISITED", "C"),
    ],
    epsilonNum: 1e-6,
    establishAt: { lane: "A", eg: 1 },
    creditAt: { lane: "B", eg: 2 },
    window: { kind: "sinceBoundary" },
    nMin: 10,
    latchClearedBy: [{ moduleId: "subject-a", eventType: "ARBITER_RESOLVED" }],
  };
  assert(JSON.stringify(g) === JSON.stringify(expected), `the wire is not the contract's shape:\n  got      ${JSON.stringify(g)}\n  expected ${JSON.stringify(expected)}`);
  const text = JSON.stringify(g);
  for (const word of ["basis", "proxy", "falsifiability", g2Basis()]) {
    assert(!text.includes(word), `the wire carries ${JSON.stringify(word)}`);
  }
});

check("GATE 2 WIRE: basketClass is G2_BASKET@ + the first 16 hex of sha256 over the contract's array — the input WRITTEN OUT BY HAND", () => {
  const b = g2LiveShapeBasket();
  b.classes.value.unknown = [g2Unknown("HELD_THEN_STOPPED", "B")];
  const g: any = (toWireOptions(validateDeclarations(g2Declared("subject-a", b)).declarations) as any).gate2;
  const input =
    '["G2_BASKET_V1","subject-a",[],[],' +
    '[{"moduleId":"subject-a","eventType":"HELD_THEN_STOPPED","outcome":null,"grade":{"lane":"B","eg":1},"bearsOn":["c-other"]}],' +
    '0.000001,{"lane":"A","eg":1},{"lane":"B","eg":2},{"kind":"sinceBoundary"},10,' +
    '[{"moduleId":"subject-a","eventType":"ARBITER_RESOLVED"}]]';
  assert(GATE2_BASKET_CLASS_VERSION === "G2_BASKET_V1", GATE2_BASKET_CLASS_VERSION);
  const byHand = "G2_BASKET@" + createHash("sha256").update(input, "utf8").digest("hex").slice(0, 16);
  assert(g.basketClass === byHand, `basketClass ${g.basketClass}, by hand ${byHand}`);
});

/** A deep copy with every object's keys in REVERSED order (arrays keep their order). */
function g2ReverseKeys(v: any): any {
  if (Array.isArray(v)) return v.map(g2ReverseKeys);
  if (v === null || typeof v !== "object") return v;
  const out: any = {};
  for (const k of Object.keys(v).reverse()) out[k] = g2ReverseKeys(v[k]);
  return out;
}

function g2Class(d: any): string {
  return (toWireOptions(validateDeclarations(d).declarations) as any).gate2.basketClass;
}

check("GATE 2 WIRE: basketClass is STABLE under key reorder, entry reorder, bearsOn reorder and a moved stanza key order", () => {
  const base = g2Declared("subject-a", g2RichBasket());
  g2B(base).classes.value.unknown[1].bearsOn = ["c-self", "c-other"];
  const pinned = g2Class(base);
  const reordered = JSON.parse(JSON.stringify(base));
  reordered.baskets = g2ReverseKeys(reordered.baskets);
  const rb = g2B(reordered);
  rb.classes.value.unknown.reverse();
  rb.classes.value.unknown.find((u: any) => u.kind === "TURN_ENDED_ASKING").bearsOn.reverse();
  assert(g2Class(reordered) === pinned, `a pure reorder moved basketClass: ${g2Class(reordered)} vs ${pinned}`);
  // two clearers, reordered — built past the loader (R11 admits one kind), at the digest itself
  const wire = (toWireOptions(validateDeclarations(base).declarations) as any).gate2;
  const { basketClass: _bc, frameCategories: _fc, ...rest } = wire;
  void _bc; void _fc;
  const two = [...rest.latchClearedBy, { moduleId: "subject-a", eventType: "DOCTOR_ATTESTED" }];
  assert(gate2BasketClass("subject-a", { ...rest, latchClearedBy: two }) === gate2BasketClass("subject-a", { ...rest, latchClearedBy: [...two].reverse() }), "a clearer reorder moved basketClass");
});

check("GATE 2 WIRE: basketClass MOVES with every field the reader reads (and the subject), and does NOT move with basis, proxy or falsifiability", () => {
  const mk = (mutate: (b: any, d: any) => void, subject = "subject-a"): string => {
    const d = g2Declared(subject, g2RichBasket());
    mutate(d.baskets[subject], d);
    return g2Class(d);
  };
  const base = mk(() => undefined);
  const viaDigest = (mutateWire: (w: any) => void): string => {
    const { basketClass: _bc, frameCategories: _fc, ...rest } = (toWireOptions(validateDeclarations(g2Declared("subject-a", g2RichBasket())).declarations) as any).gate2;
    void _bc; void _fc;
    assert(gate2BasketClass("subject-a", rest) === base, "the digest recomputed from the wire is not the wire's basketClass");
    mutateWire(rest);
    return gate2BasketClass("subject-a", rest);
  };
  const V = (b: any) => b.classes.value.value[0];
  const U = (b: any) => b.classes.value.unknown[0];
  const moves: [string, string][] = [
    ["value kind", mk((b) => (V(b).kind = "TOOL_ATTEMPTED"))],
    ["value outcome", mk((b) => (V(b).outcome = "NONZERO"))],
    ["value outcome null", mk((b) => (V(b).outcome = null))],
    ["weight lo", mk((b) => (V(b).weight.lo = 0.25))],
    ["weight hi", mk((b) => (V(b).weight.hi = 2))],
    ["value lane", mk((b) => (V(b).lane = "B"))],
    ["value eg", mk((b) => (V(b).eg = 0))],
    ["rhoCausal", mk((b) => (V(b).rhoCausal = 0.75))],
    ["value bearsOn", mk((b) => (V(b).bearsOn = ["c-self", "c-shared"]))],
    ["unknown outcome", mk((b) => (U(b).outcome = "REASON_FIXTURE"))],
    ["unknown lane", mk((b) => (U(b).lane = "C"))],
    ["unknown eg", mk((b) => (U(b).eg = 0))],
    ["unknown bearsOn", mk((b) => (U(b).bearsOn = ["c-shared"]))],
    ["magnitude hi", mk((b) => (U(b).magnitude.hi = 3))],
    ["magnitude removed", mk((b) => delete U(b).magnitude)],
    ["an unknown added", mk((b) => b.classes.value.unknown.push(g2Unknown("TOOL_ATTEMPTED", "C")))],
    ["an unknown removed", mk((b) => b.classes.value.unknown.pop())],
    ["the value class removed", mk((b) => (b.classes.value.value = []))],
    ["epsilonNum", mk((b) => (b.epsilonNum.value = 1e-3))],
    ["establishAt lane", mk((b) => (b.grades.value.establishAt.lane = "B"))],
    ["establishAt eg", mk((b) => (b.grades.value.establishAt.eg = 0))],
    ["creditAt lane", mk((b) => (b.grades.value.creditAt.lane = "A"))],
    ["creditAt eg", mk((b) => (b.grades.value.creditAt.eg = 3))],
    ["nMin", mk((b) => (b.nMin.value = 11))],
    ["latch widened (at the digest: R11 admits one kind)", viaDigest((w) => (w.latchClearedBy = [...w.latchClearedBy, { moduleId: "subject-a", eventType: "DOCTOR_ATTESTED" }]))],
    ["latch replaced (at the digest)", viaDigest((w) => (w.latchClearedBy = [{ moduleId: "subject-a", eventType: "DOCTOR_ATTESTED" }]))],
    ["the subject", mk(() => undefined, "subject-c")],
  ];
  const seen = new Map<string, string>([[base, "base"]]);
  for (const [name, cls] of moves) {
    assert(cls !== base, `${name} did NOT move basketClass`);
    assert(!seen.has(cls), `${name} collides with ${seen.get(cls)}`);
    seen.set(cls, name);
  }
  const still: [string, string][] = [
    ["classes basis", mk((b) => (b.classes.basis = "another basis"))],
    ["an entry's basis", mk((b) => (U(b).basis = "another basis"))],
    ["falsifiability", mk((b) => (V(b).falsifiability = "another falsifier"))],
    ["every proxy flag", mk((b) => { for (const k of ["classes", "epsilonNum", "grades", "window", "nMin", "latchClearedBy"]) b[k].proxy = !b[k].proxy; })],
  ];
  for (const [name, cls] of still) {
    assert(cls === base, `${name} MOVED basketClass — it is not on the wire, and the contract's formula does not cover it`);
  }
});

// ── schema ⇄ loader, value by value, for the basket ─────────────────────────

check("GATE 2 SCHEMA: the basket document satisfies the schema by BOTH evaluators, and each value rule agrees three ways or is an ENUMERATED loader-only row", () => {
  type Row = { name: string; mutate: (d: any) => void; expect: "BOTH_ACCEPT" | "BOTH_REFUSE" | "LOADER_ONLY" };
  const B = (d: any) => g2B(d);
  const V = (d: any) => B(d).classes.value.value[0];
  const U = (d: any) => B(d).classes.value.unknown[0];
  const rows: Row[] = [
    { name: "the rich basket", mutate: () => undefined, expect: "BOTH_ACCEPT" },
    { name: "the §6 live shape", mutate: (d) => (d.baskets["subject-a"] = g2LiveShapeBasket()), expect: "BOTH_ACCEPT" },
    { name: "a basket without the reader", mutate: (d) => delete d.readers.gate2Direction, expect: "BOTH_ACCEPT" },
    { name: "an outcome word", mutate: (d) => (U(d).outcome = "NONZERO"), expect: "BOTH_ACCEPT" },
    { name: "eg 0", mutate: (d) => (U(d).eg = 0), expect: "BOTH_ACCEPT" },
    { name: "rhoCausal 0", mutate: (d) => (V(d).rhoCausal = 0), expect: "BOTH_ACCEPT" },
    { name: "rhoCausal 1 (closed interval)", mutate: (d) => (V(d).rhoCausal = 1), expect: "BOTH_ACCEPT" },
    { name: "weight lo = hi", mutate: (d) => (V(d).weight = { lo: 1, hi: 1 }), expect: "BOTH_ACCEPT" },
    { name: "epsilonNum 0", mutate: (d) => (B(d).epsilonNum.value = 0), expect: "BOTH_ACCEPT" },
    { name: "magnitude hi 0 (UNKNOWN = zero, R9)", mutate: (d) => (U(d).magnitude = { hi: 0 }), expect: "BOTH_REFUSE" },
    { name: "an unknown without magnitude", mutate: (d) => delete U(d).magnitude, expect: "BOTH_ACCEPT" },
    { name: "latch DOCTOR_ATTESTED (R11: not the arbiter's record; the schema cannot say whose)", mutate: (d) => (B(d).latchClearedBy.value = [{ kind: "DOCTOR_ATTESTED" }]), expect: "LOADER_ONLY" },
    { name: "bearsOn two ids", mutate: (d) => (U(d).bearsOn = ["c-self", "c-other"]), expect: "BOTH_ACCEPT" },
    { name: "R13 control: two outcomes of one kind", mutate: (d) => { B(d).classes.value.unknown[4].outcome = "NONZERO"; B(d).classes.value.unknown.push(g2Unknown("ACT_REVISITED", "C", { outcome: "TIMEOUT" })); }, expect: "BOTH_ACCEPT" },
    // ── both refuse ──
    { name: "eg 4", mutate: (d) => (U(d).eg = 4), expect: "BOTH_REFUSE" },
    { name: "eg true", mutate: (d) => (U(d).eg = true), expect: "BOTH_REFUSE" },
    { name: "eg as a string", mutate: (d) => (U(d).eg = "1"), expect: "BOTH_REFUSE" },
    { name: "lane D", mutate: (d) => (U(d).lane = "D"), expect: "BOTH_REFUSE" },
    { name: "lane missing", mutate: (d) => delete U(d).lane, expect: "BOTH_REFUSE" },
    { name: "rhoCausal 1.5", mutate: (d) => (V(d).rhoCausal = 1.5), expect: "BOTH_REFUSE" },
    { name: "rhoCausal -0.1", mutate: (d) => (V(d).rhoCausal = -0.1), expect: "BOTH_REFUSE" },
    { name: "weight lo -1", mutate: (d) => (V(d).weight.lo = -1), expect: "BOTH_REFUSE" },
    { name: "weight missing", mutate: (d) => delete V(d).weight, expect: "BOTH_REFUSE" },
    { name: "weight extra key", mutate: (d) => (V(d).weight.mid = 0.7), expect: "BOTH_REFUSE" },
    { name: "falsifiability empty", mutate: (d) => (V(d).falsifiability = ""), expect: "BOTH_REFUSE" },
    { name: "falsifiability missing", mutate: (d) => delete V(d).falsifiability, expect: "BOTH_REFUSE" },
    { name: "a magnitude on a signed class", mutate: (d) => (V(d).magnitude = { hi: 1 }), expect: "BOTH_REFUSE" },
    { name: "a weight on an unknown", mutate: (d) => (U(d).weight = { lo: 0, hi: 1 }), expect: "BOTH_REFUSE" },
    { name: "a rhoCausal on an unknown", mutate: (d) => (U(d).rhoCausal = 0.5), expect: "BOTH_REFUSE" },
    { name: "a falsifiability on an unknown", mutate: (d) => (U(d).falsifiability = "x"), expect: "BOTH_REFUSE" },
    { name: "magnitude hi -1", mutate: (d) => (U(d).magnitude = { hi: -1 }), expect: "BOTH_REFUSE" },
    { name: "magnitude extra key", mutate: (d) => (U(d).magnitude.lo = 0), expect: "BOTH_REFUSE" },
    { name: "outcome empty", mutate: (d) => (U(d).outcome = ""), expect: "BOTH_REFUSE" },
    { name: "outcome a number", mutate: (d) => (U(d).outcome = 3), expect: "BOTH_REFUSE" },
    { name: "outcome missing", mutate: (d) => delete U(d).outcome, expect: "BOTH_REFUSE" },
    { name: "outcome with a trailing newline", mutate: (d) => (U(d).outcome = "NONZERO\n"), expect: "BOTH_REFUSE" },
    { name: "kind lowercase", mutate: (d) => (U(d).kind = "held_then_stopped"), expect: "BOTH_REFUSE" },
    { name: "kind with a trailing newline", mutate: (d) => (U(d).kind = "HELD_THEN_STOPPED\n"), expect: "BOTH_REFUSE" },
    { name: "kind missing", mutate: (d) => delete U(d).kind, expect: "BOTH_REFUSE" },
    { name: "bearsOn empty", mutate: (d) => (U(d).bearsOn = []), expect: "BOTH_REFUSE" },
    { name: "bearsOn duplicate", mutate: (d) => (U(d).bearsOn = ["c-other", "c-other"]), expect: "BOTH_REFUSE" },
    { name: "bearsOn with a trailing newline", mutate: (d) => (U(d).bearsOn = ["c-other\n"]), expect: "BOTH_REFUSE" },
    { name: "an entry's basis empty", mutate: (d) => (U(d).basis = ""), expect: "BOTH_REFUSE" },
    { name: "epsilonNum -1", mutate: (d) => (B(d).epsilonNum.value = -1), expect: "BOTH_REFUSE" },
    { name: "nMin 0", mutate: (d) => (B(d).nMin.value = 0), expect: "BOTH_REFUSE" },
    { name: "nMin 2.5", mutate: (d) => (B(d).nMin.value = 2.5), expect: "BOTH_REFUSE" },
    { name: "nMin 2^53", mutate: (d) => (B(d).nMin.value = 2 ** 53), expect: "BOTH_REFUSE" },
    { name: "window trailing", mutate: (d) => (B(d).window.value.kind = "trailing"), expect: "BOTH_REFUSE" },
    { name: "window extra key", mutate: (d) => (B(d).window.value.size = 10), expect: "BOTH_REFUSE" },
    { name: "establishAt eg 5", mutate: (d) => (B(d).grades.value.establishAt.eg = 5), expect: "BOTH_REFUSE" },
    { name: "creditAt lane Z", mutate: (d) => (B(d).grades.value.creditAt.lane = "Z"), expect: "BOTH_REFUSE" },
    { name: "creditAt missing", mutate: (d) => delete B(d).grades.value.creditAt, expect: "BOTH_REFUSE" },
    { name: "latch empty", mutate: (d) => (B(d).latchClearedBy.value = []), expect: "BOTH_REFUSE" },
    { name: "latch duplicate", mutate: (d) => (B(d).latchClearedBy.value = [{ kind: "ARBITER_RESOLVED" }, { kind: "ARBITER_RESOLVED" }]), expect: "BOTH_REFUSE" },
    { name: "latch item extra key", mutate: (d) => (B(d).latchClearedBy.value[0].outcome = null), expect: "BOTH_REFUSE" },
    { name: "latch kind lowercase", mutate: (d) => (B(d).latchClearedBy.value = [{ kind: "arbiter_resolved" }]), expect: "BOTH_REFUSE" },
    { name: "unknown key in the basket", mutate: (d) => (B(d).extra = 1), expect: "BOTH_REFUSE" },
    { name: "unknown key in the classes envelope", mutate: (d) => (B(d).classes.note = "x"), expect: "BOTH_REFUSE" },
    { name: "classes.value without unknown[]", mutate: (d) => delete B(d).classes.value.unknown, expect: "BOTH_REFUSE" },
    { name: "value[] not an array", mutate: (d) => (B(d).classes.value.value = {}), expect: "BOTH_REFUSE" },
    { name: "empty baskets {}", mutate: (d) => { d.baskets = {}; delete d.readers.gate2Direction; }, expect: "BOTH_REFUSE" },
    { name: "a basket key with a trailing newline", mutate: (d) => (d.baskets["subject-a\n"] = g2LiveShapeBasket()), expect: "BOTH_REFUSE" },
    { name: "__proto__ as a basket key (an OWN key)", mutate: (d) => g1DefineOwn(d.baskets, "__proto__", g2LiveShapeBasket()), expect: "BOTH_REFUSE" },
    { name: "__proto__ inside a class (an OWN key)", mutate: (d) => g1DefineOwn(U(d), "__proto__", { kind: "TOOL_RESULT" }), expect: "BOTH_REFUSE" },
    { name: "gate2Direction subject empty", mutate: (d) => (d.readers.gate2Direction.subject.value = ""), expect: "BOTH_REFUSE" },
    { name: "gate2Direction extra key", mutate: (d) => (d.readers.gate2Direction.extra = 1), expect: "BOTH_REFUSE" },
    // ── LOADER-ONLY, enumerated: membership in a constant, another array or another list ──
    { name: "R1 reader subject undeclared", mutate: (d) => (d.readers.gate2Direction.subject.value = "subject-b"), expect: "LOADER_ONLY" },
    { name: "R1 reader without its basket", mutate: (d) => delete d.baskets, expect: "LOADER_ONLY" },
    { name: "R1 basket for no subject", mutate: (d) => (d.baskets["subject-z"] = g2LiveShapeBasket()), expect: "LOADER_ONLY" },
    { name: "R1 basket for an unframed subject", mutate: (d) => { d.subjects.push({ ...d.subjects[1], subject: "subject-b" }); d.baskets["subject-b"] = g2LiveShapeBasket(); }, expect: "LOADER_ONLY" },
    { name: "R2 damage and unknown both empty", mutate: (d) => (B(d).classes.value.unknown = []), expect: "LOADER_ONLY" },
    { name: "R3 a kind-shaped word that is no kind", mutate: (d) => (U(d).kind = "NOT_A_KIND"), expect: "LOADER_ONLY" },
    // unknown[0] (HELD_THEN_STOPPED, null) is removed so R13 cannot refuse the row in R4's place (found by mutant M03).
    { name: "R4 HELD_THEN_STOPPED in value[]", mutate: (d) => { V(d).kind = "HELD_THEN_STOPPED"; B(d).classes.value.unknown.splice(0, 1); }, expect: "LOADER_ONLY" },
    { name: "R5 a sunset kind in unknown[]", mutate: (d) => (U(d).kind = "SUNSET_HELD"), expect: "LOADER_ONLY" },
    { name: "R6 an F4 kind in unknown[]", mutate: (d) => (U(d).kind = "TOOL_EXECUTED"), expect: "LOADER_ONLY" },
    { name: "R7 EG-2 on a subject-writable kind", mutate: (d) => (V(d).eg = 2), expect: "LOADER_ONLY" },
    { name: "R8 a damage class", mutate: (d) => (B(d).classes.value.damage = [g2Signed("TOOL_RESULT", { outcome: "NONZERO" })]), expect: "LOADER_ONLY" },
    { name: "R9 weight lo > hi", mutate: (d) => (V(d).weight = { lo: 2, hi: 1 }), expect: "LOADER_ONLY" },
    { name: "R11 latch on a subject-writable kind", mutate: (d) => (B(d).latchClearedBy.value = [{ kind: "TOOL_RESULT" }]), expect: "LOADER_ONLY" },
    { name: "R12 bearsOn outside the frame", mutate: (d) => (U(d).bearsOn = ["c-elsewhere"]), expect: "LOADER_ONLY" },
    { name: "R13 a duplicate class", mutate: (d) => B(d).classes.value.unknown.push(g2Unknown("TURN_ENDED_ASKING", "C")), expect: "LOADER_ONLY" },
    { name: "R13 null beside a word of one kind", mutate: (d) => B(d).classes.value.unknown.push(g2Unknown("ACT_REVISITED", "C", { outcome: "NONZERO" })), expect: "LOADER_ONLY" },
  ];
  const docs = rows.map((r) => {
    const d = g2Declared("subject-a", g2RichBasket());
    r.mutate(d);
    return d;
  });
  let real: number[];
  try {
    real = realValidatorCounts(docs);
  } catch (err) {
    throw new Error(`the real Draft 2020-12 validator could not run, and this arm does NOT skip: ${String((err as { stderr?: unknown }).stderr ?? err).slice(0, 300)}`);
  }
  const wrong: string[] = [];
  rows.forEach((r, i) => {
    const loader = loaderAccepts(docs[i]);
    const subset = evalSchema(committedSchema, docs[i], "$").length === 0;
    const realOk = real[i] === 0;
    if (subset !== realOk) wrong.push(`${r.name}: the SUBSET evaluator says ${subset ? "valid" : "invalid"} and the REAL validator ${realOk ? "valid" : "invalid"}`);
    const got = loader && subset ? "BOTH_ACCEPT" : !loader && !subset ? "BOTH_REFUSE" : !loader && subset ? "LOADER_ONLY" : "SCHEMA_ONLY";
    if (got !== r.expect) wrong.push(`${r.name}: expected ${r.expect}, got ${got} (loader ${loader ? "accepts" : "refuses"}, schema ${subset ? "accepts" : "refuses"})`);
  });
  assert(wrong.length === 0, `the basket's schema and loader disagree:\n    ${wrong.join("\n    ")}`);
  console.log(`      (${String(rows.length)} basket documents × 3 witnesses; ${String(rows.filter((r) => r.expect === "LOADER_ONLY").length)} enumerated loader-only rows)`);
});

// ── TIER 1 · THE WITNESS'S PATHS, AND GATE 2 ON THE WITNESS'S BOOK ───────────
//
// The door's half of the witness build: two envelope paths (W1–W4; read per act, so a reload may change them), the book
// switch with its method designation (R16), and a basket read on the book held
// to the book's grammar (R3 re-scoped, R7's twin, R12's category). Absent, every
// one of them leaves the declaration hashing as before.

import { GATE2_WITNESS_BOOK_SIGNED_REFUSED, GATE2_WITNESS_EFFECT_CLASSES, GATE2_WITNESS_EVIDENCE_FREE_CLASSES, GATE2_WITNESS_KIND } from "./declarations";
import { witnessRecordClass } from "./witness-pointer";
import { frameLabelEventType } from "./interest-book";

const W_METHOD = "bd91dc37fa7e5d0653c795c4878266a4482c1405d932ce0b073d50b5bce41b72";
const W_BASIS = "TIER 1 fixture basis: the witness's seeing half owns this path under its own uid; the bridge only drops pointers into it or reads it.";
const wPaths = (d: any): any => {
  d.paths.witnessIntake = { value: "/var/lib/mica/witness-sight/intake", basis: W_BASIS };
  d.paths.witnessBook = { value: "/var/lib/mica/witness-sight/book-of-effects.jsonl", basis: W_BASIS };
  return d;
};
const wClass = (outcome: string, extra: Record<string, unknown> = {}): any => ({
  kind: "CONSEQUENCE", outcome, lane: "A", eg: 1, bearsOn: [outcome.slice(0, outcome.indexOf(":"))], basis: g2Basis(), ...extra,
});
/** Gate 2 on the witness's book for subject-a, phase R: every class an unknown over the book's grammar. */
function wDeclared(classes?: any[]): any {
  const d = wPaths(g2Declared("subject-a"));
  d.readers.gate2Direction.book = { value: "witnessBook", basis: g2Basis(), proxy: false };
  d.readers.gate2Direction.witnessMethod = { value: W_METHOD, basis: g2Basis(), proxy: false };
  g2B(d).classes.value = {
    value: [],
    damage: [],
    unknown: classes ?? [wClass("c-other:CONTENT_DIFFERS"), wClass("c-shared:META_DIFFERS"), wClass("c-self:SAME")],
  };
  return d;
}

check("TIER 1 · the cross-repo pin: witnessRecordClass equals the machine's consequenceEventType for the pinned input", () => {
  assert(witnessRecordClass(W_METHOD, "INTEREST_LABEL@2b7df2aba755e90c") === "CONSEQUENCE@dd31bb90bb21909a", "the record class drifted from the machine's pin");
  assert(GATE2_WITNESS_KIND === "CONSEQUENCE", "the kind word");
  assert(
    JSON.stringify(GATE2_WITNESS_EFFECT_CLASSES) ===
      JSON.stringify(["FIRST_SEEN", "SAME", "EXISTENCE_DIFFERS", "TYPE_DIFFERS", "CONTENT_DIFFERS", "META_DIFFERS", "UNOBSERVABLE", "HELD", "LATE"]),
    "the vocabulary copy drifted from the machine's EFFECT_CLASSES (src/witness/seeing.ts)"
  );
});

check("TIER 1 · absent, the witness keys are ABSENT and the fixture hashes as before; declared, the paths and the switch LOAD WHOLE and move the hash", () => {
  const plain = loadDeclarations(DRAFT_PATH);
  assert(!("witnessIntake" in plain.declarations.paths) && !("witnessBook" in plain.declarations.paths), "a witness path appeared on a declaration that does not declare it");
  assert(plain.declarationHash === EXPECTED_HASH, `the fixture's hash MOVED: ${plain.declarationHash}`);
  const base = g2Declared("subject-a");
  const baseHash = validateDeclarations(base).declarationHash;
  const withPaths = wPaths(g2Declared("subject-a"));
  const r = validateDeclarations(withPaths);
  assert(r.declarationHash === canonicalHash(withPaths), "the paths were not loaded whole");
  assert(r.declarationHash !== baseHash, "declaring the witness paths did not move the hash");
  const onBook = wDeclared();
  const r2 = validateDeclarations(onBook);
  assert(r2.declarationHash === canonicalHash(onBook), "the book-mode declaration was not loaded whole");
  assert(r2.declarations.readers.gate2Direction!.book!.value === "witnessBook", "the switch");
});

check("TIER 1 · W1: a witness path is an ENVELOPE under /var/lib/mica/ only — a bare string, a short basis, the bridge's own directory are REFUSED", () => {
  const bare = wPaths(g2Declared("subject-a"));
  bare.paths.witnessIntake = "/var/lib/mica/witness-sight/intake";
  assertRejected(() => validateDeclarations(bare), "paths.witnessIntake");
  const short = wPaths(g2Declared("subject-a"));
  short.paths.witnessBook.basis = "too short";
  assertRejected(() => validateDeclarations(short), "paths.witnessBook.basis");
  const own = wPaths(g2Declared("subject-a"));
  own.paths.witnessIntake.value = "/var/lib/mica-bridge/witness-intake";
  assertRejectedSaying(() => validateDeclarations(own), "paths.witnessIntake.value", "W1");
  const walk = wPaths(g2Declared("subject-a"));
  walk.paths.witnessBook.value = "/var/lib/mica/../mica-bridge/x.jsonl";
  assertRejected(() => validateDeclarations(walk), "paths.witnessBook.value");
  // B8: passes a RAW prefix test (it starts "/var/lib/mica/") and fails only once canonicalised
  const walk2 = wPaths(g2Declared("subject-a"));
  walk2.paths.witnessBook.value = "/var/lib/mica/a/../../mica-bridge/x.jsonl";
  assert(walk2.paths.witnessBook.value.startsWith("/var/lib/mica/"), "fixture: the raw text passes a prefix test");
  assertRejectedSaying(() => validateDeclarations(walk2), "paths.witnessBook.value", "W1");
});

check("TIER 1 · W2–W4: the book is a .jsonl file outside the intake, never readers.logPath, and no path is its lock sibling", () => {
  const notJsonl = wPaths(g2Declared("subject-a"));
  notJsonl.paths.witnessBook.value = "/var/lib/mica/witness-sight/book";
  assertRejectedSaying(() => validateDeclarations(notJsonl), "paths.witnessBook.value", "W2");
  // A root that is never deployed: the live intake is 3730 and EACCES refuses
  // before W2 is reached (red since the 10-11 16:37Z deploy); ENOENT stops the walk.
  const inside = wPaths(g2Declared("subject-a"));
  inside.paths.witnessIntake.value = "/var/lib/mica/w2-fixture-never-deployed/intake";
  inside.paths.witnessBook.value = "/var/lib/mica/w2-fixture-never-deployed/intake/book.jsonl";
  assertRejectedSaying(() => validateDeclarations(inside), "paths.witnessBook", "W2");
  const asLog = wPaths(g2Declared("subject-a"));
  asLog.readers.logPath.value = asLog.paths.witnessBook.value;
  let refused = false;
  try {
    validateDeclarations(asLog);
  } catch (err) {
    refused = err instanceof DeclarationRejected && (err.message.includes("W3") || err.message.includes("X7"));
  }
  assert(refused, "readers.logPath naming the witness's book must be REFUSED (W3, or X7 if the log is also a declared path)");
  const sib = wPaths(g2Declared("subject-a"));
  sib.paths.clerkStamps = { value: `${sib.paths.witnessBook.value}.lock`, basis: W_BASIS };
  assertRejectedSaying(() => validateDeclarations(sib), "paths", "W4");
});

check("TIER 1 · RELOAD: adding the witness paths on a reload is ACCEPTED — the bridge reads them per act, nothing opens them at start", () => {
  const prev = validateDeclarations(g2Declared("subject-a")).declarations;
  const next = validateDeclarations(wPaths(g2Declared("subject-a"))).declarations;
  validateActivation(prev, next, new Date("2026-10-10T20:00:00Z"));
  validateActivation(next, prev, new Date("2026-10-10T20:00:00Z"));
});

check("TIER 1 · R16: book and witnessMethod come together, the book value is witnessBook, the method is 64 hex, and paths.witnessBook is then required", () => {
  const half = wDeclared();
  delete half.readers.gate2Direction.witnessMethod;
  g2Refused(half, "readers.gate2Direction", 16);
  const badVal = wDeclared();
  badVal.readers.gate2Direction.book.value = "subjectLog";
  g2Refused(badVal, "readers.gate2Direction.book.value", 16);
  const badHex = wDeclared();
  badHex.readers.gate2Direction.witnessMethod.value = "XYZ";
  g2Refused(badHex, "readers.gate2Direction.witnessMethod.value", 16);
  const noBook = wDeclared();
  delete noBook.paths.witnessBook;
  g2Refused(noBook, "readers.gate2Direction.book", 16);
});

check("TIER 1 · R3 RE-SCOPED on the book: a subject-chain kind is REFUSED; CONSEQUENCE needs '<category>:<effect>' from the closed vocabulary over a frame category", () => {
  g2Refused(wDeclared([g2Unknown("TOOL_RESULT", "A")]), `${G2_LF}.unknown[0].kind`, 3);
  g2Refused(wDeclared([wClass("c-other:BLEW_UP")]), `${G2_LF}.unknown[0].outcome`, 3);
  g2Refused(wDeclared([wClass("c-nowhere:CONTENT_DIFFERS", { bearsOn: ["c-other"] })]), `${G2_LF}.unknown[0].outcome`, 3);
  g2Refused(wDeclared([{ ...wClass("c-other:CONTENT_DIFFERS"), outcome: null }]), `${G2_LF}.unknown[0].outcome`, 3);
  g2Refused(wDeclared([wClass("c-other:CONTENT_DIFFERS", { bearsOn: ["c-shared"] })]), `${G2_LF}.unknown[0].bearsOn`, 12);
});

check("TIER 1 · R7's TWIN: a class over the witness's record is EG-1 at most — one look, one internal process (audit 18:03Z (1))", () => {
  g2Refused(wDeclared([wClass("c-other:CONTENT_DIFFERS", { eg: 2 })]), `${G2_LF}.unknown[0].eg`, 7);
  validateDeclarations(wDeclared([wClass("c-other:CONTENT_DIFFERS", { eg: 1, lane: "A" })]));
});

check("TIER 1 · OFF the book, CONSEQUENCE is still no kind the subject chain carries: REFUSED by R3 exactly as before", () => {
  const d = g2Declared("subject-a");
  g2B(d).classes.value.unknown = [wClass("c-other:CONTENT_DIFFERS")];
  g2Refused(d, `${G2_LF}.unknown[0].kind`, 3);
});

check("TIER 1 · toWireOptions: on the book every class's eventType is the witness's record class for THIS frame's drawing, and gate2BookPath is the resolved book", () => {
  const loaded = validateDeclarations(wDeclared()).declarations;
  const w = toWireOptions(loaded, (p: string) => `/redirected${p}`, () => []) as any;
  const cls = witnessRecordClass(W_METHOD, frameLabelEventType(loaded.frame!["subject-a"]));
  assert(w.gate2BookPath === "/redirected/var/lib/mica/witness-sight/book-of-effects.jsonl", `gate2BookPath ${String(w.gate2BookPath)}`);
  assert(w.gate2.unknown.length === 3 && w.gate2.unknown.every((c: any) => c.eventType === cls && c.moduleId === "subject-a"), "every class on the book's record class");
  assert(w.gate2.latchClearedBy.every((l: any) => l.eventType === "ARBITER_RESOLVED"), "the clearer is unchanged (unclearable on the book, printed)");
  const chain = toWireOptions(validateDeclarations(g2Declared("subject-a")).declarations, (p: string) => p, () => []) as any;
  assert(chain.gate2BookPath === undefined, "off the book: no gate2BookPath key at all");
});

check("TIER 1 · R17: PHASE R on the book — value[] and damage[] are REFUSED there while GATE2_WITNESS_BOOK_SIGNED_REFUSED holds (refuters A-F5, C MAJOR-1)", () => {
  assert(GATE2_WITNESS_BOOK_SIGNED_REFUSED === true, "the constant holds until T31, S208, T32, F5, the persisted latch, F9, S209");
  const dmg = wDeclared();
  g2B(dmg).classes.value.damage = [wClass("c-other:CONTENT_DIFFERS", { weight: { lo: 1, hi: 1 }, rhoCausal: 1, falsifiability: "fixture" })];
  g2Refused(dmg, `${G2_LF}.damage[0]`, 17);
  const val = wDeclared();
  g2B(val).classes.value.value = [wClass("c-other:EXISTENCE_DIFFERS", { weight: { lo: 1, hi: 1 }, rhoCausal: 1, falsifiability: "fixture" })];
  g2Refused(val, `${G2_LF}.value[0]`, 17);
  validateDeclarations(wDeclared());
});

check("TIER 1 · R18: the EVIDENCE-FREE classes are refused outside unknown[] on the book, checked BEFORE R17 so the rule survives R17's flip", () => {
  assert(JSON.stringify(GATE2_WITNESS_EVIDENCE_FREE_CLASSES) === JSON.stringify(["FIRST_SEEN", "UNOBSERVABLE", "LATE"]), "the copy drifted from seeing.ts EVIDENCE_FREE_CLASSES");
  for (const eff of GATE2_WITNESS_EVIDENCE_FREE_CLASSES) {
    for (const list of ["damage", "value"] as const) {
      const d = wDeclared();
      g2B(d).classes.value[list] = [wClass(`c-other:${eff}`, { weight: { lo: 1, hi: 1 }, rhoCausal: 1, falsifiability: "fixture" })];
      g2Refused(d, `${G2_LF}.${list}[0].outcome`, 18);
    }
  }
  validateDeclarations(wDeclared([wClass("c-other:UNOBSERVABLE"), wClass("c-self:FIRST_SEEN")]));
});


// ── GATE 2 · LONG RUN A STOP 2 · THE HARM STANZA (contract B1, refusals H1–H10) ──────────────────
//
// The arbiter's question: did an act change a protected thing (an ITEM) without permission (a GRANT)?
// Every H-rule gets one arm, asserted by the field it cites AND by `refusal H<n> —`. Fixture names
// only (subject-a, o-*, i-*, /srv/…); the removal arm reads the served subject and frame BY USE.
// ⛔ FUNCTION DECLARATIONS ONLY: the parity walk's harm base calls `hDeclared` thousands of lines
//    above this block, before any module-level constant down here exists.

function hBasis(): string {
  return "HARM FIXTURE, not a declaration. Exercises the loader's harm rules.";
}

/** A valid harm stanza over g1Frame: two ungranted items (one a control), one granted, one clearance. */
function hStanza(subjectId = "subject-a", id = "i-other"): any {
  const b = hBasis();
  return {
    harmOnly: { value: true, basis: b, proxy: false },
    origins: { value: { [id === "i-other" ? "o-sub" : id]: { subject: subjectId, basis: b } }, basis: b, proxy: false },
    items: {
      value: {
        [id]: { path: "/srv/a/b/kept.txt", category: "c-other", control: false, basis: b },
        "i-shared": { path: "/srv/c/shared.cfg", category: "c-shared", control: true, basis: b },
        "i-granted": { path: "/srv/a/b/granted.txt", category: "c-other", control: false, basis: b },
      },
      basis: b,
      proxy: true,
    },
    grants: {
      value: {
        [id]: { origins: [], since: {}, basis: b },
        "i-shared": { origins: [], since: {}, basis: b },
        "i-granted": { origins: [id === "i-other" ? "o-sub" : id], since: { [id === "i-other" ? "o-sub" : id]: "2026-01-01T00:00:00.000Z" }, basis: b },
      },
      basis: b,
      proxy: false,
    },
    clearances: { value: [{ record: "ab".repeat(32), hat: "doctor", basis: b }], basis: b, proxy: false },
  };
}

/** g2Declared, switched onto the witness's book, its basket REPLACED by the harm stanza. */
function hDeclared(subjectId = "subject-a", id = "i-other"): any {
  const d = g2Declared(subjectId);
  const b = hBasis();
  const pb = "HARM FIXTURE path basis: the witness's seeing half owns this path under its own uid; the bridge only drops pointers into it or reads it.";
  d.paths.witnessIntake = { value: "/var/lib/mica/witness-sight/intake", basis: pb };
  d.paths.witnessBook = { value: "/var/lib/mica/witness-sight/book-of-effects.jsonl", basis: pb };
  d.readers.gate2Direction.book = { value: "witnessBook", basis: b, proxy: false };
  d.readers.gate2Direction.witnessMethod = { value: "bd91dc37fa7e5d0653c795c4878266a4482c1405d932ce0b073d50b5bce41b72", basis: b, proxy: false };
  delete d.baskets;
  d.harm = { [subjectId]: hStanza(subjectId, id) };
  return d;
}

function hH(d: any): any {
  return d.harm["subject-a"];
}
const H_F = "harm.subject-a";

/** Refused at `field`, SAYING rule Hn. */
function hRefused(d: any, field: string, n: number): void {
  assertRejectedSaying(() => validateDeclarations(d), field, `refusal H${String(n)} —`);
}

check("HARM · a valid stanza LOADS WHOLE through both front doors, the reader needs no basket (R1 amended), and the hash moves", () => {
  const d = hDeclared();
  const loaded = validateDeclarations(d);
  assert(canonicalHash(loaded.declarations.harm) === canonicalHash(d.harm), "the loaded harm stanza is not the declared one");
  assert(loaded.declarationHash === canonicalHash(d), "the loader added or dropped a key");
  assert(loaded.declarations.baskets === undefined, "no basket was declared, and none appeared");
  const dir = mkdtempSync(join(tmpdir(), "harm-load-"));
  try {
    const path = join(dir, "d.json");
    writeFileSync(path, JSON.stringify(d));
    assert(loadDeclarations(path).declarationHash === loaded.declarationHash, "the file door and the object door disagree");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  const noHarm = hDeclared();
  delete noHarm.harm;
  noHarm.baskets = { "subject-a": g2LiveShapeBasket() };
  noHarm.baskets["subject-a"].classes.value = { value: [], damage: [], unknown: [{ kind: "CONSEQUENCE", outcome: "c-other:CONTENT_DIFFERS", lane: "A", eg: 1, bearsOn: ["c-other"], basis: hBasis() }] };
  const plain = validateDeclarations(noHarm);
  assert(!("harm" in plain.declarations), "an undeclared harm stanza is an ABSENT key");
  assert(plain.declarationHash !== loaded.declarationHash, "declaring harm did not move the declaration hash");
});

check("HARM · R1 still refuses a reader with NEITHER a basket nor a harm stanza", () => {
  const d = hDeclared();
  delete d.harm;
  g2Refused(d, "readers.gate2Direction.subject", 1);
});

check("HARM H1 · a stanza for an undeclared subject, and for a declared subject with no frame, is REFUSED", () => {
  const d = hDeclared();
  d.harm["subject-z"] = hStanza("subject-a");
  hRefused(d, "harm.subject-z", 1);
  const nf = hDeclared();
  const other = nf.subjects[0].subject;
  nf.harm[other] = hStanza("subject-a");
  hRefused(nf, `harm.${other}`, 1);
  const empty = hDeclared();
  empty.harm = {};
  hRefused(empty, "harm", 1);
});

check("HARM H2 · harmOnly absent, or anything but exactly true, is REFUSED", () => {
  const d = hDeclared();
  delete hH(d).harmOnly;
  hRefused(d, `${H_F}.harmOnly`, 2);
  for (const v of [false, "true", 1]) {
    const e = hDeclared();
    hH(e).harmOnly.value = v;
    hRefused(e, `${H_F}.harmOnly.value`, 2);
  }
});

check("HARM H3 · an origin bound to an undeclared subject, no origin at all, and no origin bound to the Gate-2 subject are REFUSED", () => {
  const d = hDeclared();
  hH(d).origins.value["o-sub"].subject = "subject-z";
  hRefused(d, `${H_F}.origins.value.o-sub.subject`, 3);
  const none = hDeclared();
  hH(none).origins.value = {};
  hRefused(none, `${H_F}.origins.value`, 3);
  const elsewhere = hDeclared();
  hH(elsewhere).origins.value["o-sub"].subject = elsewhere.subjects[0].subject;
  hRefused(elsewhere, `${H_F}.origins.value`, 3);
});

check("HARM H4 · an item that is relative, non-canonical, quoted, outside its category's region, in a self or unknown category, duplicated, or with no control flag is REFUSED; so is an empty item set", () => {
  const cases: [string, (it: any, h: any) => void, string][] = [
    ["relative", (it) => (it.path = "srv/a/b/kept.txt"), "path"],
    ["double slash", (it) => (it.path = "/srv/a/b//kept.txt"), "path"],
    ["trailing slash", (it) => (it.path = "/srv/a/b/kept/"), "path"],
    ["one quote pair", (it) => (it.path = '/"/srv/a/b/kept.txt"'), "path"],
    ["another category's region", (it) => (it.path = "/srv/c/kept.txt"), "path"],
    ["self category", (it) => { it.path = "/srv/a/kept.txt"; it.category = "c-self"; }, "category"],
    ["unknown category", (it) => (it.category = "c-none"), "category"],
    ["control not boolean", (it) => (it.control = "no"), "control"],
    ["duplicated path", (it, h) => (h.items.value["i-granted"].path = it.path), "dup"],
  ];
  for (const [name, mutate, at] of cases) {
    const d = hDeclared();
    const it = hH(d).items.value["i-other"];
    mutate(it, hH(d));
    const field = at === "dup" ? `${H_F}.items.value.i-granted.path` : `${H_F}.items.value.i-other.${at}`;
    try {
      hRefused(d, field, 4);
    } catch (err) {
      throw new Error(`${name}: ${(err as Error).message}`);
    }
  }
  const empty = hDeclared();
  hH(empty).items.value = {};
  hRefused(empty, `${H_F}.items.value`, 4);
});

check("HARM H5 · an item with no grants entry, a grant for an undeclared item, a grant naming an undeclared origin or one origin twice is REFUSED", () => {
  const d = hDeclared();
  delete hH(d).grants.value["i-shared"];
  hRefused(d, `${H_F}.grants.value`, 5);
  const ghost = hDeclared();
  hH(ghost).grants.value["i-ghost"] = { origins: [], since: {}, basis: hBasis() };
  hRefused(ghost, `${H_F}.grants.value.i-ghost`, 5);
  const stranger = hDeclared();
  hH(stranger).grants.value["i-other"].origins = ["o-none"];
  hRefused(stranger, `${H_F}.grants.value.i-other.origins[0]`, 5);
  const twice = hDeclared();
  hH(twice).grants.value["i-granted"].origins = ["o-sub", "o-sub"];
  hRefused(twice, `${H_F}.grants.value.i-granted.origins[1]`, 5);
});

check("HARM H5 · S216: a granted origin with no since, a since for an origin not granted, no since object, and a malformed or non-calendar instant are REFUSED; a well-formed since with or without ms LOADS", () => {
  const none = hDeclared();
  hH(none).grants.value["i-granted"].since = {};
  hRefused(none, `${H_F}.grants.value.i-granted.since`, 5);
  const absent = hDeclared();
  delete hH(absent).grants.value["i-granted"].since;
  hRefused(absent, `${H_F}.grants.value.i-granted.since`, 5);
  const stray = hDeclared();
  hH(stray).grants.value["i-other"].since = { "o-sub": "2026-01-01T00:00:00.000Z" };
  hRefused(stray, `${H_F}.grants.value.i-other.since.o-sub`, 5);
  for (const bad of ["2026-01-01 00:00:00Z", "2026-01-01T00:00Z", "2026-01-01T00:00:00+01:00", "2026-02-30T00:00:00.000Z", "2026-01-01T00:00:00.1Z", "2026-01-01T00:00:00Z", "+010000-01-01T00:00:00.000Z", "-000001-01-01T00:00:00.000Z", 1767225600000]) {
    const d = hDeclared();
    hH(d).grants.value["i-granted"].since = { "o-sub": bad };
    hRefused(d, `${H_F}.grants.value.i-granted.since.o-sub`, 5);
  }
  for (const good of ["2026-01-01T00:00:00.000Z", "2026-10-16T06:13:54.692Z"]) {
    const d = hDeclared();
    hH(d).grants.value["i-granted"].since = { "o-sub": good };
    validateDeclarations(d);
  }
});

check("HARM H12 · S208-2: an errand envelope LOADS on non-self frame categories with a bounded window; an unknown or self category, a repeat, a window outside 1..1440 or an extra key is REFUSED", () => {
  const env = (value: unknown) => ({ value, basis: hBasis(), proxy: false });
  const own = (d: any) => { d.frame["subject-a"].categories.value.push({ id: "c-own", label: "the deployer's own", grounding: "agency", self: false }); return d; };
  const ok = own(hDeclared());
  hH(ok).errand = env({ categories: ["c-own"], maxWindowMinutes: 120 });
  validateDeclarations(ok);
  // the design's rule: a vulnerability- or need-grounded category is not the deployer's to grant
  for (const cat of ["c-other", "c-shared"]) {
    const d = own(hDeclared());
    hH(d).errand = env({ categories: [cat], maxWindowMinutes: 60 });
    hRefused(d, `${H_F}.errand.value.categories`, 12);
  }
  for (const [name, value, at] of [
    ["unknown category", { categories: ["c-none"], maxWindowMinutes: 60 }, "categories"],
    ["the subject's own category", { categories: ["c-self"], maxWindowMinutes: 60 }, "categories"],
    ["a repeat", { categories: ["c-own", "c-own"], maxWindowMinutes: 60 }, "categories"],
    ["window 0", { categories: ["c-own"], maxWindowMinutes: 0 }, "maxWindowMinutes"],
    ["window 1441", { categories: ["c-own"], maxWindowMinutes: 1441 }, "maxWindowMinutes"],
    ["window 1.5", { categories: ["c-own"], maxWindowMinutes: 1.5 }, "maxWindowMinutes"],
  ] as const) {
    const d = own(hDeclared());
    hH(d).errand = env(value);
    hRefused(d, `${H_F}.errand.value.${at}`, 12);
    void name;
  }
  const extra = own(hDeclared());
  hH(extra).errand = env({ categories: ["c-own"], maxWindowMinutes: 60, x: 1 });
  hRefused(extra, `${H_F}.errand.value.x`, 10);
});

check("HARM H11 (g) · S208-2: across a reload an errand envelope may only NARROW — added, a category added or a longer window REFUSED; a shorter window or fewer categories ALLOWED", () => {
  const env = (categories: string[], m: number) => ({ value: { categories, maxWindowMinutes: m }, basis: hBasis(), proxy: false });
  const load = (e: unknown) => {
    const d = hDeclared();
    for (const id of ["c-own", "c-own2"]) d.frame["subject-a"].categories.value.push({ id, label: id, grounding: "agency", self: false });
    if (e !== undefined) hH(d).errand = e;
    return validateDeclarations(d).declarations;
  };
  const refusedG = (p: unknown, n: unknown, name: string) => {
    let msg = "";
    try { validateActivation(load(p), load(n)); } catch (e) { msg = String((e as Error).message); }
    assert(/\(g\) an errand envelope may only narrow/.test(msg), `${name}: ${msg || "accepted"}`);
  };
  refusedG(undefined, env(["c-own"], 60), "added where absent");
  refusedG(env(["c-own"], 60), env(["c-own", "c-own2"], 60), "a category added");
  refusedG(env(["c-own"], 60), env(["c-own"], 61), "a longer window");
  validateActivation(load(env(["c-own", "c-own2"], 60)), load(env(["c-own"], 30)));
  validateActivation(load(env(["c-own"], 60)), load(undefined));
});

check("HARM H6 · an item, origin, grant, clearance or stanza without a non-empty basis is REFUSED", () => {
  const sites: [string, (h: any) => void][] = [
    [`${H_F}.items.value.i-other.basis`, (h) => (h.items.value["i-other"].basis = "")],
    [`${H_F}.origins.value.o-sub.basis`, (h) => delete h.origins.value["o-sub"].basis],
    [`${H_F}.grants.value.i-granted.basis`, (h) => (h.grants.value["i-granted"].basis = "")],
    [`${H_F}.clearances.value[0].basis`, (h) => (h.clearances.value[0].basis = "")],
    [`${H_F}.items.basis`, (h) => (h.items.basis = "")],
  ];
  for (const [field, mutate] of sites) {
    const d = hDeclared();
    mutate(hH(d));
    hRefused(d, field, 6);
  }
});

check("HARM H7 · a clearance whose record is not 64 lower hex, whose hat is not the doctor's, or that repeats a record is REFUSED", () => {
  const upper = hDeclared();
  hH(upper).clearances.value[0].record = "AB".repeat(32);
  hRefused(upper, `${H_F}.clearances.value[0].record`, 7);
  const hat = hDeclared();
  hH(hat).clearances.value[0].hat = "arbiter";
  hRefused(hat, `${H_F}.clearances.value[0].hat`, 7);
  const dup = hDeclared();
  hH(dup).clearances.value.push({ ...hH(dup).clearances.value[0] });
  hRefused(dup, `${H_F}.clearances.value[1].record`, 7);
  const none = hDeclared();
  hH(none).clearances.value = [];
  validateDeclarations(none);
});

check("HARM H8 · harm declared while Gate 2 does not read the witness's book (no book/method, or no reader) is REFUSED", () => {
  const d = hDeclared();
  delete d.readers.gate2Direction.book;
  delete d.readers.gate2Direction.witnessMethod;
  hRefused(d, H_F, 8);
  const noReader = hDeclared();
  delete noReader.readers.gate2Direction;
  hRefused(noReader, H_F, 8);
});

check("HARM H9 · harm AND a class basket for the Gate-2 subject is REFUSED: harm REPLACES the basket", () => {
  const d = hDeclared();
  d.baskets = { "subject-a": g2LiveShapeBasket() };
  d.baskets["subject-a"].classes.value = { value: [], damage: [], unknown: [{ kind: "CONSEQUENCE", outcome: "c-other:CONTENT_DIFFERS", lane: "A", eg: 1, bearsOn: ["c-other"], basis: hBasis() }] };
  hRefused(d, H_F, 9);
});

check("HARM H10 · an id outside ^[A-Za-z0-9_-]{1,32}$ and an unknown key anywhere in the stanza are REFUSED", () => {
  const d = hDeclared();
  hH(d).items.value["bad id"] = { path: "/srv/a/b/x", category: "c-other", control: false, basis: hBasis() };
  hRefused(d, `${H_F}.items.value.bad id`, 10);
  const long = hDeclared();
  hH(long).origins.value["o".repeat(33)] = { subject: "subject-a", basis: hBasis() };
  hRefused(long, `${H_F}.origins.value.${"o".repeat(33)}`, 10);
  for (const [field, mutate] of [
    [`${H_F}.extra`, (h: any) => (h.extra = 1)],
    [`${H_F}.items.value.i-other.weight`, (h: any) => (h.items.value["i-other"].weight = 1)],
    [`${H_F}.grants.extra`, (h: any) => (h.grants.extra = 1)],
    [`${H_F}.clearances.value[0].note`, (h: any) => (h.clearances.value[0].note = "x")],
  ] as [string, (h: any) => void][]) {
    const e = hDeclared();
    mutate(hH(e));
    hRefused(e, field, 10);
  }
});

check("HARM · R17 is unchanged for class baskets and a harm stanza does not pass through it", () => {
  assert(GATE2_WITNESS_BOOK_SIGNED_REFUSED === true, "R17's constant moved");
  validateDeclarations(hDeclared());
});

check("HARM SCHEMA · the harm document satisfies the committed schema by BOTH evaluators; an unknown key is refused by both", () => {
  const good = hDeclared();
  const bad = hDeclared();
  hH(bad).items.value["i-other"].weight = 1;
  const subset = evalSchema(committedSchema, good, "$");
  assert(subset.length === 0, `the subset evaluator refuses the harm document: ${subset.join("; ")}`);
  assert(evalSchema(committedSchema, bad, "$").length > 0, "the subset evaluator accepts an unknown item key");
  const [g, b] = realValidatorCounts([good, bad]);
  assert(g === 0 && b > 0, `the real validator: good ${String(g)} errors, bad ${String(b)}`);
});


// ── GATE 2 · LONG RUN A STOP 2 · toWireOptions IN HARM MODE (contract B2, M1/M3) ─────────────────

import { gate2HarmClass, GATE2_HARM_CLASS_VERSION } from "./to-wire-options";
import { deriveInterestLabel, INTEREST_UNDERIVED as INTEREST_UNDERIVED_WORD } from "./interest-label";

const H_M1_KEYS = ["clearances", "errandGrants", "grantSince", "grants", "harmClass", "items", "origins", "saltEpochSince"];
const H_ITEM_KEYS = ["category", "control", "fingerprint", "id"];

check("HARM WIRE · harm mode emits gate2Harm in the M1 shape, the book, the roster and a null deciding act — and NO gate2", () => {
  const loaded = validateDeclarations(hDeclared()).declarations;
  const w = toWireOptions(loaded, (p: string) => `/redirected${p}`, () => []) as any;
  assert(!("gate2" in w), "harm mode must not emit the class basket (gate2 + gate2Harm is a WireUsageError on the machine)");
  assert(JSON.stringify(Object.keys(w.gate2Harm).sort()) === JSON.stringify(H_M1_KEYS), `gate2Harm keys ${JSON.stringify(Object.keys(w.gate2Harm))}`);
  assert(/^G2_HARM@[0-9a-f]{16}$/.test(w.gate2Harm.harmClass), `harmClass ${String(w.gate2Harm.harmClass)}`);
  assert(GATE2_HARM_CLASS_VERSION === "G2_HARM_V3", "the class version moved (V3: S208-2 covers the errand envelope)");
  assert(JSON.stringify(w.gate2Harm.origins) === JSON.stringify([{ id: "o-sub", subject: "subject-a" }]), JSON.stringify(w.gate2Harm.origins));
  assert(JSON.stringify(w.gate2Harm.items.map((i: any) => i.id)) === JSON.stringify(["i-granted", "i-other", "i-shared"]), "items sorted by id");
  for (const it of w.gate2Harm.items) {
    assert(JSON.stringify(Object.keys(it).sort()) === JSON.stringify(H_ITEM_KEYS), `item keys ${JSON.stringify(Object.keys(it))}`);
    assert(it.fingerprint === null, "no epoch handed in: every fingerprint is null");
  }
  assert(w.gate2Harm.items.find((i: any) => i.id === "i-shared").control === true, "the control flag travels");
  assert(JSON.stringify(w.gate2Harm.grants) === JSON.stringify({ "i-granted": ["o-sub"], "i-other": [], "i-shared": [] }), JSON.stringify(w.gate2Harm.grants));
  assert(JSON.stringify(w.gate2Harm.clearances) === JSON.stringify(["ab".repeat(32)]), "clearances are the record hashes");
  assert(w.gate2Harm.saltEpochSince === null, "no epoch handed in: saltEpochSince null");
  assert(w.gate2BookPath === "/redirected/var/lib/mica/witness-sight/book-of-effects.jsonl", `gate2BookPath ${String(w.gate2BookPath)}`);
  assert(w.gate2RosterPath === `/redirected${loaded.paths.interestBook!}`, `gate2RosterPath ${String(w.gate2RosterPath)}`);
  assert(Object.hasOwn(w, "gate2DecidingActionId") && w.gate2DecidingActionId === null, "a status read decides no act: null");
  const plain = toWireOptions(validateDeclarations(wDeclared()).declarations, (p: string) => p, () => []) as any;
  assert(w.gate2UnderivedWord === INTEREST_UNDERIVED_WORD, `gate2UnderivedWord ${String(w.gate2UnderivedWord)} is not interest-label.ts's INTEREST_UNDERIVED`);
  for (const k of ["gate2Harm", "gate2RosterPath", "gate2DecidingActionId", "gate2UnderivedWord"]) assert(!(k in plain), `a class-basket declaration emits ${k}`);
});

check("HARM WIRE · an injected epoch fills each item's fingerprint BY PATH and saltEpochSince; an item missing from the map is a LOUD wiring fault (m3), never a silent null", () => {
  const loaded = validateDeclarations(hDeclared()).declarations;
  const partial = { "/srv/a/b/kept.txt": "1".repeat(64), "/srv/a/b/granted.txt": "2".repeat(64) };
  for (const bad of [partial, { ...partial, "/srv/c/shared.cfg": "not-a-digest" }]) {
    let threw: unknown = null;
    try {
      toWireOptions(loaded, (p: string) => p, () => [], undefined, { saltEpochSince: 1700000000000, itemFingerprints: bad });
    } catch (e) {
      threw = e;
    }
    assert(threw instanceof Error && threw.message.includes("gate2Harm wiring fault") && threw.message.includes("i-shared"),
      `an epoch missing (or malformed for) an item did not refuse loudly: ${String(threw)}`);
  }
  const fps = { ...partial, "/srv/c/shared.cfg": "3".repeat(64) };
  const w = toWireOptions(loaded, (p: string) => p, () => [], undefined, { saltEpochSince: 1700000000000, itemFingerprints: fps }) as any;
  const by = (id: string) => w.gate2Harm.items.find((i: any) => i.id === id).fingerprint;
  assert(by("i-other") === "1".repeat(64) && by("i-granted") === "2".repeat(64) && by("i-shared") === "3".repeat(64), JSON.stringify(w.gate2Harm.items));
  assert(w.gate2Harm.saltEpochSince === 1700000000000, "saltEpochSince");
  const unknownStart = toWireOptions(loaded, (p: string) => p, () => [], undefined, { saltEpochSince: null, itemFingerprints: fps }) as any;
  assert(
    unknownStart.gate2Harm.saltEpochSince === null && unknownStart.gate2Harm.items.find((i: any) => i.id === "i-other").fingerprint === "1".repeat(64),
    "a salt with an unknown start: fingerprints, and a null since"
  );
  const w2 = toWireOptions(loaded, (p: string) => p, () => [], undefined, { saltEpochSince: 1700000000000, itemFingerprints: fps }) as any;
  assert(w2.gate2Harm.harmClass === w.gate2Harm.harmClass && w.gate2Harm.harmClass === (toWireOptions(loaded, (p: string) => p, () => []) as any).gate2Harm.harmClass,
    "the harmClass depends on the salt epoch — it must name what was declared, not the epoch it is read in");
});

check("HARM WIRE · the harmClass is STABLE under reordering and basis edits, and MOVES when any origin, item, grant or clearance moves", () => {
  const cls = (d: any) => gate2HarmClass("subject-a", validateDeclarations(d).declarations.harm!["subject-a"]);
  const base = cls(hDeclared());
  const reordered = hDeclared();
  const h = hH(reordered);
  h.items.value = Object.fromEntries(Object.entries(h.items.value).reverse());
  h.grants.value = Object.fromEntries(Object.entries(h.grants.value).reverse());
  h.clearances.value.unshift({ record: "cd".repeat(32), hat: "doctor", basis: hBasis() });
  const twoClear = cls(reordered);
  const reordered2 = hDeclared();
  hH(reordered2).clearances.value.push({ record: "cd".repeat(32), hat: "doctor", basis: hBasis() });
  assert(cls(reordered2) === twoClear, "clearance order or item/grant key order moved the class");
  const bases = hDeclared();
  hH(bases).items.value["i-other"].basis = "another basis";
  hH(bases).grants.basis = "another basis";
  hH(bases).clearances.value[0].basis = "another basis";
  assert(cls(bases) === base, "a basis edit moved the class (bases are excluded)");
  const moves: [string, (h: any) => void][] = [
    ["item path", (x) => (x.items.value["i-other"].path = "/srv/a/b/moved.txt")],
    ["item category", (x) => { x.items.value["i-shared"].path = "/srv/a/b/shared.cfg"; x.items.value["i-shared"].category = "c-other"; }],
    ["item control", (x) => (x.items.value["i-other"].control = true)],
    ["item added", (x) => { x.items.value["i-new"] = { path: "/srv/a/b/new.txt", category: "c-other", control: false, basis: hBasis() }; x.grants.value["i-new"] = { origins: [], since: {}, basis: hBasis() }; }],
    ["grant added", (x) => { x.grants.value["i-other"].origins = ["o-sub"]; x.grants.value["i-other"].since = { "o-sub": "2026-01-01T00:00:00.000Z" }; }],
    ["grant removed", (x) => { x.grants.value["i-granted"].origins = []; x.grants.value["i-granted"].since = {}; }],
    ["since moved (S216)", (x) => { x.grants.value["i-granted"].since = { "o-sub": "2026-01-02T00:00:00.000Z" }; }],
    ["clearance added", (x) => x.clearances.value.push({ record: "cd".repeat(32), hat: "doctor", basis: hBasis() })],
    ["clearance removed", (x) => (x.clearances.value = [])],
    ["origin renamed", (x) => { x.origins.value["o-two"] = x.origins.value["o-sub"]; delete x.origins.value["o-sub"]; x.grants.value["i-granted"].origins = ["o-two"]; x.grants.value["i-granted"].since = { "o-two": "2026-01-01T00:00:00.000Z" }; }],
  ];
  for (const [name, mutate] of moves) {
    const d = hDeclared();
    mutate(hH(d));
    assert(cls(d) !== base, `${name} did not move the harmClass`);
  }
});

check("HARM REMOVAL · the tree (S34: harm laid in) minus harm and the book switch, with a class basket restored, loads and reads the class-basket path; every OTHER reader's options are byte-identical throughout", () => {
  // S34 now LEADS the served bytes (the S33 basket is not in the tree), so the restored basket is the §6 SHAPE over
  // the served frame, by use. That S34 minus its harm leaves IS S33 minus its basket is the tree-pin arm's
  // MINUS_HARM_S33; this arm proves the REMOVAL path reads as before.
  const tree = JSON.parse(JSON.stringify(shipped));
  tree.pilot = { active: false };
  const subject = tree.readers.gate2Direction.subject.value as string;
  const cand = validateDeclarations(tree).declarations;
  const cw = toWireOptions(cand, (p: string) => p, () => []) as any;
  assert(cw.gate2Harm !== undefined && !("gate2" in cw), "the tree does not read harm");
  const removed = JSON.parse(JSON.stringify(tree));
  delete removed.harm;
  delete removed.readers.gate2Direction.book;
  delete removed.readers.gate2Direction.witnessMethod;
  const basket = g2LiveShapeBasket();
  const cat = removed.frame[subject].categories.value.find((c: any) => !c.self).id;
  for (const u of basket.classes.value.unknown) u.bearsOn = [cat];
  removed.baskets = { ...(removed.baskets ?? {}), [subject]: basket };
  const rw = toWireOptions(validateDeclarations(removed).declarations, (p: string) => p, () => []) as any;
  assert(rw.gate2 !== undefined, "minus harm, the class basket is not read");
  for (const k of ["gate2Harm", "gate2RosterPath", "gate2DecidingActionId", "gate2UnderivedWord", "gate2BookPath"]) assert(!(k in rw), `${k} survived the removal`);
  const G2_KEYS = ["gate2", "gate2Harm", "gate2BookPath", "gate2RosterPath", "gate2DecidingActionId", "gate2UnderivedWord"];
  const others = (o: any) => JSON.stringify(Object.fromEntries(Object.entries(o).filter(([k]) => !G2_KEYS.includes(k))));
  assert(others(rw) === others(cw), "removing harm moved some OTHER reader's options");
  // And with the basket NOT restored: R1 refuses (the reader would read nothing).
  const bare = JSON.parse(JSON.stringify(removed));
  delete bare.baskets[subject];
  if (Object.keys(bare.baskets).length === 0) delete bare.baskets;
  g2Refused(bare, "readers.gate2Direction.subject", 1);
});


// ── GATE 2 · H11 · A HARM STANZA ONLY TIGHTENS ACROSS A SIGHUP RELOAD (R15's analogue) ───────────

function hReload(mutate: (h: any, d: any) => void): () => void {
  const prev = validateDeclarations(hDeclared()).declarations;
  const d = hDeclared();
  mutate(hH(d), d);
  const next = validateDeclarations(d).declarations;
  return () => validateActivation(prev, next, new Date("2026-09-18T00:00:00Z"));
}

check("HARM H11 · REFUSED on reload: (a) removing the stanza or an item, (b) changing an item's path/category/control, (c) widening a grant, (d) removing or changing a clearance, (e) removing or re-binding an origin", () => {
  const cases: [string, string, (h: any, d: any) => void][] = [
    ["(a) stanza removed", H_F, (_h, d) => { delete d.harm; d.baskets = { "subject-a": g2LiveShapeBasket() }; d.baskets["subject-a"].classes.value = { value: [], damage: [], unknown: [{ kind: "CONSEQUENCE", outcome: "c-other:CONTENT_DIFFERS", lane: "A", eg: 1, bearsOn: ["c-other"], basis: hBasis() }] }; }],
    ["(a) item removed", `${H_F}.items.value.i-shared`, (h) => { delete h.items.value["i-shared"]; delete h.grants.value["i-shared"]; }],
    ["(b) path changed", `${H_F}.items.value.i-other.path`, (h) => (h.items.value["i-other"].path = "/srv/a/b/elsewhere.txt")],
    // Same path, other category: only a re-drawn frame can do that (a new region placing the path elsewhere).
    ["(b) category changed", `${H_F}.items.value.i-shared.category`, (h, d) => {
      d.frame["subject-a"].regions.value.push({ prefix: "/srv/c", category: "c-other" });
      d.frame["subject-a"].regions.value = d.frame["subject-a"].regions.value.filter((r: any) => !(r.prefix === "/srv/c" && r.category === "c-shared"));
      h.items.value["i-shared"].category = "c-other";
    }],
    ["(b) control changed", `${H_F}.items.value.i-other.control`, (h) => (h.items.value["i-other"].control = true)],
    ["(c) grant widened", `${H_F}.grants.value.i-other.origins`, (h) => { h.grants.value["i-other"].origins = ["o-sub"]; h.grants.value["i-other"].since = { "o-sub": "2026-01-01T00:00:00.000Z" }; }],
    ["(c') since moved earlier (S216)", `${H_F}.grants.value.i-granted.since.o-sub`, (h) => { h.grants.value["i-granted"].since = { "o-sub": "2025-12-31T23:59:59.999Z" }; }],
    ["(d) clearance removed", `${H_F}.clearances.value`, (h) => (h.clearances.value = [])],
    ["(d) clearance changed", `${H_F}.clearances.value`, (h) => (h.clearances.value[0].record = "cd".repeat(32))],
    ["(e) origin removed", `${H_F}.origins.value.o-sub`, (h) => { h.origins.value["o-two"] = h.origins.value["o-sub"]; delete h.origins.value["o-sub"]; h.grants.value["i-granted"].origins = ["o-two"]; h.grants.value["i-granted"].since = { "o-two": "2026-01-01T00:00:00.000Z" }; }],
    ["(e) origin re-bound", `${H_F}.origins.value.o-sub.subject`, (h, d) => { h.origins.value["o-sub"].subject = d.subjects[0].subject; h.origins.value["o-two"] = { subject: "subject-a", basis: hBasis() }; }],
  ];
  for (const [name, field, mutate] of cases) {
    try {
      assertRejectedSaying(hReload(mutate), field, "refusal H11 —");
    } catch (err) {
      throw new Error(`${name}: ${(err as Error).message}`);
    }
  }
});

check("HARM H11 · ALLOWED on reload: an unchanged stanza, a new item with its grant list, a new origin, a narrowed grant, an added clearance, basis text", () => {
  const allowed: [string, (h: any) => void][] = [
    ["unchanged", () => undefined],
    ["new item + grant", (h) => { h.items.value["i-new"] = { path: "/srv/a/b/new.txt", category: "c-other", control: false, basis: hBasis() }; h.grants.value["i-new"] = { origins: ["o-sub"], since: { "o-sub": "2026-01-01T00:00:00.000Z" }, basis: hBasis() }; }],
    ["new origin", (h) => (h.origins.value["o-two"] = { subject: "subject-a", basis: hBasis() })],
    ["narrowed grant", (h) => { h.grants.value["i-granted"].origins = []; h.grants.value["i-granted"].since = {}; }],
    ["since moved later (S216: a narrowing)", (h) => { h.grants.value["i-granted"].since = { "o-sub": "2026-01-01T00:00:00.001Z" }; }],
    ["added clearance", (h) => h.clearances.value.push({ record: "cd".repeat(32), hat: "doctor", basis: hBasis() })],
    ["basis text", (h) => { h.items.value["i-other"].basis = "rewritten"; h.grants.basis = "rewritten"; h.clearances.value[0].basis = "rewritten"; h.origins.value["o-sub"].basis = "rewritten"; }],
  ];
  for (const [name, mutate] of allowed) {
    try {
      hReload(mutate)();
    } catch (err) {
      throw new Error(`${name} was refused: ${(err as Error).message}`);
    }
  }
  // THE CEILING, printed not closed: a first load (prev null) — which a restart is — is never refused.
  const loosened = hDeclared();
  hH(loosened).clearances.value = [];
  validateActivation(null, validateDeclarations(loosened).declarations, new Date("2026-09-18T00:00:00Z"));
});


check("HARM H11 (f) · while harm is declared, a reload may not move the witness's book, intake, the book switch or the method — and may change their BASES (evasion test 5.H11-gap)", () => {
  const cases: [string, string, (h: any, d: any) => void][] = [
    ["book moved", "paths.witnessBook", (_h, d) => (d.paths.witnessBook.value = "/var/lib/mica/witness-sight/fresh-book.jsonl")],
    ["intake moved", "paths.witnessIntake", (_h, d) => (d.paths.witnessIntake.value = "/var/lib/mica/witness-sight/fresh-intake")],
    ["method moved", "readers.gate2Direction.witnessMethod", (_h, d) => (d.readers.gate2Direction.witnessMethod.value = "0".repeat(64))],
  ];
  for (const [name, field, mutate] of cases) {
    try {
      assertRejectedSaying(hReload(mutate), field, "refusal H11 —");
    } catch (err) {
      throw new Error(`${name}: ${(err as Error).message}`);
    }
  }
  // The book switch: switched off (with harm still declared H8 refuses at load, so the reload drops harm too) —
  // either way the reload is refused; here the switch is compared directly.
  const prev = validateDeclarations(hDeclared()).declarations;
  const switched = JSON.parse(JSON.stringify(prev));
  delete switched.readers.gate2Direction.book;
  assertRejectedSaying(() => validateActivation(prev, switched, new Date("2026-09-18T00:00:00Z")), "readers.gate2Direction.book", "refusal H11 —");
  // ALLOWED: the same values with new bases.
  hReload((_h, d) => {
    d.paths.witnessBook.basis = `${d.paths.witnessBook.basis} (rewritten)`;
    d.paths.witnessIntake.basis = `${d.paths.witnessIntake.basis} (rewritten)`;
    d.readers.gate2Direction.book.basis = "rewritten";
    d.readers.gate2Direction.witnessMethod.basis = "rewritten";
  })();
  // ALLOWED: with NO harm declared before, the book may move on reload exactly as before (TIER 1 · RELOAD).
  const p0 = wDeclared();
  const n0 = wDeclared();
  n0.paths.witnessBook.value = "/var/lib/mica/witness-sight/fresh-book.jsonl";
  validateActivation(validateDeclarations(p0).declarations, validateDeclarations(n0).declarations, new Date("2026-09-18T00:00:00Z"));
});

// ══ ZERO SUBJECTS (ticket Bridge-Zero-Subjects v2; audit 2026-10-18 06:56Z (9): F-2 (a), F-3 yes for Z2 and Z5
//    at every n, F-4 refuse, F-5 (a), F-9 (a) + the bridge fence test). Fixture names and uids only; the served
//    subject is never typed here — the fixture's own subject is read through d.subjects[0].

/** The fixture with NOTHING DECLARED: no subject, no subject-role row; pilot inactive (clone). */
function zsZero(): any {
  const d = clone();
  d.subjects = [];
  d.routes = d.routes.filter((r: any) => r.role !== "subject");
  return d;
}
function zsRefusedSaying(fn: () => void, field: string, rule: string): void {
  try {
    fn();
  } catch (err) {
    assert(err instanceof DeclarationRejected, `expected DeclarationRejected, got ${String(err)}`);
    const e = err as DeclarationRejected;
    assert(e.field === field || e.field.startsWith(field), `expected field "${field}", got "${e.field}" (${e.message})`);
    assert(e.message.includes(rule), `expected the reason to name ${rule}: ${e.message}`);
    return;
  }
  throw new Error(`expected a refusal naming ${rule} on "${field}", nothing was thrown`);
}
const ZS_NOW = new Date("2026-09-18T00:00:00Z");
/** The line's top rung, read from the declaration (an array, or a declared {value} array). */
const zsTopRung = (d: any): string => {
  const lc = Array.isArray(d.stakes.lineClasses) ? d.stakes.lineClasses : d.stakes.lineClasses.value;
  return lc[lc.length - 1];
};
const zsLoad = (d: any): Declarations => validateDeclarations(d, ZS_NOW).declarations;

check("ZERO-SUBJECTS Z0: subjects: [] LOADS — no subject, routes kept, readers declared and inert (F-2 (a))", () => {
  const loaded = validateDeclarations(zsZero(), ZS_NOW);
  assert(loaded.declarations.subjects.length === 0, "subjects must load empty");
  assert(loaded.declarations.routes.length > 0 && loaded.declarations.routes.every((r) => r.role !== "subject"), "routes kept, no subject row");
  assert(loaded.declarations.readers !== undefined, "the declared reader profiles load, inert (F-2 (a))");
  assert(/^[0-9a-f]{64}$/.test(loaded.declarationHash), "a zero declaration has a hash");
  assert(loaded.pilotState.state === "INACTIVE", "pilot inactive");
});

check("ZERO-SUBJECTS Z0: the schema says so — subjects.minItems is 0 and the committed schema accepts []", () => {
  assert(committedSchema.properties.subjects.minItems === 0, `minItems ${String(committedSchema.properties.subjects.minItems)}`);
  const errs = evalSchema(committedSchema.properties.subjects, [], "subjects");
  assert(errs.length === 0, `the schema must accept an empty subjects array: ${JSON.stringify(errs)}`);
});

check("ZERO-SUBJECTS Z0: only the EMPTY array is newly admitted — a non-array subjects is still refused", () => {
  for (const bad of [{}, "none", null, 0]) {
    const d = zsZero();
    d.subjects = bad;
    assertRejected(() => validateDeclarations(d, ZS_NOW), "subjects");
  }
  const d = zsZero();
  delete d.subjects;
  assertRejected(() => validateDeclarations(d, ZS_NOW), "subjects");
});

check("ZERO-SUBJECTS Z0: every committed declaration loads to the SAME hash as at the base (fixture, served tree)", () => {
  assert(validateDeclarations(clone() && JSON.parse(JSON.stringify(draft)), ZS_NOW).declarationHash === EXPECTED_HASH, "fixture hash moved");
  const served = validateDeclarations(JSON.parse(JSON.stringify(shipped)), ZS_NOW).declarationHash;
  assert(served === "0e86d7eb80b371b3213ccefbb0c34e2e79717a5e4afed6b495f160ffad5f5057", `served tree hash moved: ${served}`);
});

check("ZERO-SUBJECTS F-2 (a): at zero nothing may NAME a subject — a frame keyed to a subject is still refused", () => {
  const d = zsZero();
  d.frame = { "subject-a": g1Frame() };
  d.readers.gate1Scope = { subject: { value: "subject-a", basis: g1Basis(), proxy: false } };
  d.paths.interestBook = g1BookPath();
  let threw = false;
  try {
    validateDeclarations(d, ZS_NOW);
  } catch (err) {
    threw = err instanceof DeclarationRejected;
  }
  assert(threw, "a frame for an undeclared subject must be refused at zero");
});

check("ZERO-SUBJECTS X6 still binds: a declared subject with no subject-role row is refused", () => {
  const d = clone();
  d.routes = d.routes.filter((r: any) => r.role !== "subject");
  zsRefusedSaying(() => validateDeclarations(d, ZS_NOW), "subjects[0].peerUid", "X6");
});

check("ZERO-SUBJECTS Z2 (F-3, at zero AND at n): a subject-role row no subject declares is refused", () => {
  const z = zsZero();
  z.routes.push({ uid: 4711, role: "subject", allow: [{ method: "POST", path: "/subject-events" }] });
  zsRefusedSaying(() => validateDeclarations(z, ZS_NOW), `routes[${z.routes.length - 1}].role`, "Z2");
  const n = clone();
  n.routes.push({ uid: 4712, role: "subject", allow: [{ method: "POST", path: "/subject-events" }] });
  zsRefusedSaying(() => validateDeclarations(n, ZS_NOW), `routes[${n.routes.length - 1}].role`, "Z2");
});

check("ZERO-SUBJECTS Z5 (F-3, at zero AND at n): POST /guard on a row that is no declared subject's peer is refused", () => {
  const z = zsZero();
  const op = z.routes.findIndex((r: any) => r.role === "operator");
  z.routes[op].allow.push({ method: "POST", path: "/guard" });
  zsRefusedSaying(() => validateDeclarations(z, ZS_NOW), `routes[${op}].allow[${z.routes[op].allow.length - 1}]`, "Z5");
  for (const role of ["operator", "alerter"]) {
    const n = clone();
    const i = n.routes.findIndex((r: any) => r.role === role);
    n.routes[i].allow.push({ method: "POST", path: "/guard" });
    zsRefusedSaying(() => validateDeclarations(n, ZS_NOW), `routes[${i}].allow[${n.routes[i].allow.length - 1}]`, "Z5");
  }
  // and a new non-subject row holding it
  const v = clone();
  v.routes.push({ uid: 4713, role: "verifier", allow: [{ method: "POST", path: "/guard" }] });
  zsRefusedSaying(() => validateDeclarations(v, ZS_NOW), `routes[${v.routes.length - 1}].allow[0]`, "Z5");
});

check("ZERO-SUBJECTS Z5 breaks no shipped declaration: the subject's own /guard row still loads (fixture and served tree)", () => {
  const f = zsLoad(clone());
  assert(f.routes.some((r) => r.role === "subject" && r.allow.some((a) => a.method === "POST" && a.path === "/guard")), "fixture subject row keeps /guard");
  const t = zsLoad(JSON.parse(JSON.stringify(shipped)));
  assert(t.routes.some((r) => r.role === "subject" && r.allow.some((a) => a.method === "POST" && a.path === "/guard")), "served subject row keeps /guard");
});

check("ZERO-SUBJECTS Z3 (F-4 refuse): an ACTIVE pilot with subjects: [] is refused; inactive loads", () => {
  const d = zsZero();
  d.pilot = { active: true, sessionId: "pilot-fixture-zs", expiresAt: "2099-01-01T00:00:00Z", holdAtOrAbove: { value: zsTopRung(d), basis: g1Basis(), proxy: true } };
  zsRefusedSaying(() => validateDeclarations(d, ZS_NOW), "pilot.active", "Z3");
  const ok = zsZero();
  assert(zsLoad(ok).pilot.active === false, "inactive pilot at zero loads");
});

// Z4 · F-5 (a): membership, route uids and each row's (role, allow) are a FIRST-LOAD fact.
const zsOne = (): any => clone();
check("ZERO-SUBJECTS Z4: a RELOAD one -> zero and zero -> one (frameless) are refused with the first-load reason", () => {
  zsRefusedSaying(() => validateActivation(zsLoad(zsOne()), zsLoad(zsZero()), ZS_NOW), "subjects", "Z4");
  zsRefusedSaying(() => validateActivation(zsLoad(zsZero()), zsLoad(zsOne()), ZS_NOW), "subjects", "Z4");
});

check("ZERO-SUBJECTS Z4: a RELOAD zero -> the full served tree (framed, harmed) is refused by name", () => {
  zsRefusedSaying(() => validateActivation(zsLoad(zsZero()), zsLoad(JSON.parse(JSON.stringify(shipped))), ZS_NOW), "subjects", "Z4");
});

check("ZERO-SUBJECTS Z4: a RELOAD that changes a subject's unit is refused (relay-lib trusts the live file's unit)", () => {
  const a = zsOne();
  const b = zsOne();
  b.subjects[0].unit = "unit-fixture-moved";
  zsRefusedSaying(() => validateActivation(zsLoad(a), zsLoad(b), ZS_NOW), "subjects", "Z4");
});

check("ZERO-SUBJECTS Z4: a RELOAD that adds a route uid, changes a row's grant, or swaps a row's role is refused", () => {
  const added = zsZero();
  added.routes.push({ uid: 4713, role: "verifier", allow: [{ method: "GET", path: "/status" }] });
  zsRefusedSaying(() => validateActivation(zsLoad(zsZero()), zsLoad(added), ZS_NOW), "routes", "Z4");
  const granted = zsOne();
  const al = granted.routes.findIndex((r: any) => r.role === "alerter");
  granted.routes[al].allow.push({ method: "GET", path: "/log" });
  zsRefusedSaying(() => validateActivation(zsLoad(zsOne()), zsLoad(granted), ZS_NOW), "routes", "Z4");
  const swapped = zsOne();
  const op = swapped.routes.findIndex((r: any) => r.role === "operator");
  swapped.routes[op].role = "verifier";
  zsRefusedSaying(() => validateActivation(zsLoad(zsOne()), zsLoad(swapped), ZS_NOW), "routes", "Z4");
  // the subject's own row gaining a grant is a (role, allow) change too
  const subj = zsOne();
  const si = subj.routes.findIndex((r: any) => r.role === "subject");
  subj.routes[si].allow.push({ method: "GET", path: "/sunset-order" });
  zsRefusedSaying(() => validateActivation(zsLoad(zsOne()), zsLoad(subj), ZS_NOW), "routes", "Z4");
});

check("ZERO-SUBJECTS Z4: a RELOAD that changes only a basis, the pilot, or the order of rows/grants is ADMITTED; first load never refused", () => {
  const b = zsOne();
  b.notice.window.basis = `${b.notice.window.basis} (rewritten)`;
  validateActivation(zsLoad(zsOne()), zsLoad(b), ZS_NOW);
  const z = zsZero();
  z.notice.window.basis = `${z.notice.window.basis} (rewritten)`;
  validateActivation(zsLoad(zsZero()), zsLoad(z), ZS_NOW);
  const p = zsOne();
  p.pilot = { active: true, sessionId: "pilot-fixture-zs", expiresAt: "2099-01-01T00:00:00Z", holdAtOrAbove: { value: zsTopRung(p), basis: g1Basis(), proxy: true } };
  validateActivation(zsLoad(zsOne()), zsLoad(p), ZS_NOW);
  const r = zsOne();
  r.routes.reverse();
  for (const row of r.routes) row.allow.reverse();
  validateActivation(zsLoad(zsOne()), zsLoad(r), ZS_NOW);
  validateActivation(null, zsLoad(zsZero()), ZS_NOW);
  validateActivation(null, zsLoad(zsOne()), ZS_NOW);
});

// Z6 · F-9 (a) + THE BRIDGE FENCE TEST: no fixture subject in any declaration the bridge ships at a served path.
// The served path is the one mica-bridge.service loads: mica-bridge/declarations.config.json. The predicate is the
// door's own shape (/FIXTURE/i, core-door.ts fixtureMarked) on subject name and unit, plus the X1 fixture's identity.
const ZS_X1_FIXTURE = { subject: "fixture-subject", peerUid: 960, unit: "mica-fixture-subject" } as const;
function zsFixtureMarks(doc: any): string[] {
  const out: string[] = [];
  const subjects: any[] = Array.isArray(doc?.subjects) ? doc.subjects : [];
  for (const [i, s] of subjects.entries()) {
    if (typeof s?.subject === "string" && /FIXTURE/i.test(s.subject)) out.push(`subjects[${i}].subject ${JSON.stringify(s.subject)} carries the fixture marker`);
    if (typeof s?.unit === "string" && /FIXTURE/i.test(s.unit)) out.push(`subjects[${i}].unit ${JSON.stringify(s.unit)} carries the fixture marker`);
    if (s?.subject === ZS_X1_FIXTURE.subject || s?.peerUid === ZS_X1_FIXTURE.peerUid || s?.unit === ZS_X1_FIXTURE.unit) out.push(`subjects[${i}] is the X1 fixture's identity`);
  }
  const routes: any[] = Array.isArray(doc?.routes) ? doc.routes : [];
  for (const [i, r] of routes.entries()) {
    if (r?.role === "subject" && r?.uid === ZS_X1_FIXTURE.peerUid) out.push(`routes[${i}] is a subject row for the X1 fixture's uid`);
  }
  return out;
}
const ZS_SERVED_PATHS: readonly string[] = [SHIPPED_PATH];

check("ZERO-SUBJECTS Z6 FENCE: no declaration shipped at a served path carries a fixture subject (F-9 (a))", () => {
  for (const p of ZS_SERVED_PATHS) {
    const marks = zsFixtureMarks(JSON.parse(readFileSync(p, "utf8")));
    assert(marks.length === 0, `${p}: ${marks.join("; ")}`);
  }
});

check("ZERO-SUBJECTS Z6 FENCE BITES: the served tree with the X1 fixture subject spliced in FAILS the fence", () => {
  const scratch = mkdtempSync(join(tmpdir(), "zs-fence-"));
  try {
    const d = JSON.parse(readFileSync(SHIPPED_PATH, "utf8"));
    const s0 = d.subjects[0];
    d.subjects.push({ subject: ZS_X1_FIXTURE.subject, toolName: s0.toolName, stakesClass: s0.stakesClass, peerUid: ZS_X1_FIXTURE.peerUid, unit: ZS_X1_FIXTURE.unit });
    d.routes.push({ uid: ZS_X1_FIXTURE.peerUid, role: "subject", allow: [{ method: "POST", path: "/subject-events" }] });
    const copy = join(scratch, "declarations.config.json");
    writeFileSync(copy, JSON.stringify(d));
    const marks = zsFixtureMarks(JSON.parse(readFileSync(copy, "utf8")));
    assert(marks.length >= 3, `the spliced copy must fail the fence on name, unit and identity: ${JSON.stringify(marks)}`);
    // the marker alone (another name) is caught too
    const m = JSON.parse(readFileSync(SHIPPED_PATH, "utf8"));
    m.subjects[0].unit = "mica-FIXTURE-unit";
    assert(zsFixtureMarks(m).length === 1, "a /FIXTURE/i unit alone must fail the fence");
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

console.log(`CENSUS: ${passed} passed, ${failed} failed, ${passed + failed} total`);
if (failed > 0) {
  process.exit(1);
}
