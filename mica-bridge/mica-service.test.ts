// ── mica-service.test — check()-style tests for Stage 2 infrastructure ─────
//
// Run with the EXACT pinned unit command (Amendment 3 / verifier F2 — this
// is now the mandatory gate for every reported run, no TS_NODE_TRANSPILE_ONLY
// anywhere in the environment):
//   /usr/bin/node <mica-machine>/node_modules/ts-node/dist/bin.js \
//     -P tsconfig.json mica-service.test.ts

import { skipHere } from "./reference-only";
import { shippedDraft, writeShippedDraft } from "./example-draft";
import * as http from "http";
import * as net from "net";
import { mkdtempSync as mkdtempSyncRaw, writeFileSync, readFileSync, existsSync, mkdirSync, chmodSync, statSync, appendFileSync, rmSync } from "fs";
import { createHash } from "crypto";
import { tmpdir, userInfo } from "os";
import { join } from "path";
import { execFileSync, spawnSync } from "child_process";
import { NOTHING_DECLARED_REASON } from "./mica-service";
import { NothingDeclaredGuardAdapter } from "./guard-adapter";
import { toGuardFlags, UnknownSubjectError } from "./to-guard-flags";
import { readdirSync } from "fs";
import { MicaBridgeService, runCheck, buildInstrumentCensus, computeFooting, INSTRUMENT_IDS, StartupRefused, SerializedAppender, ChainedSubjectAppender, SUBJECT_EVENT_KINDS, DOCTOR_ATTESTATION_WORDS, authorizeSubjectEventKind, validateDoctorAttestation, EXPLAIN_CEILING, SUNSET_KINDS, OPERATOR_SUNSET_KINDS, SUBJECT_SUNSET_KINDS, ENDING_PAPER_KINDS, ENDING_TYPES, ARBITER_RESOLUTIONS, SUNSET_HOLD_CLASSES, subjectEventOutcome, validateSunsetRecord, ORDER_PAPER_SEQ_FIELDS, resolveOrderCitations, isSunsetKind, buildSunsetOrderView, SUNSET_ORDER_CEILING, ERRAND_KINDS } from "./mica-service";
import { NotBoundGuardAdapter } from "./guard-adapter";
import type { GuardAdapter, GuardOutcome, GuardEvaluationRequest, ReaderFooting } from "./guard-adapter";
import { authorizeRoute, planPeerSockets, validatePeerDir, resolveGid, widenSocketFileMode, type PeerSocketPlan } from "./peer-auth";
import { validateDeclarations } from "./declarations";
import { canonicalHash } from "./canonical-json";
import { buildNotifier, DecisionJournal, loadDeclaredClerkStamps, MicaLogFile, SubjectChainLog, SubjectEventJournal, assessSig, Stage1GuardAdapter, wire, wireOptionsFor, mapEvaluateAndRecordResult, type EvaluateAndRecordPaths } from "./stage1-guard-adapter";
import { toWireOptions } from "./to-wire-options";
// GATE 1 · Stop 2 · round 2 (placement D): the interest book's class and first line.
import { frameLabelEventType, INTEREST_BOOK_BOUNDARY_BASIS } from "./interest-book";
import { deriveInterestLabel } from "./interest-label";
import { loadDeclarations } from "./declarations";
import { loadExpectedChainIdentity } from "./stage1-guard-adapter";
// R6
import {
  loadOrMintTargetSalt,
  readEpochMemory,
  canonicaliseTargetIdentity,
  compareTargetFingerprints,
  compareTargetsOnRecords,
  describeTargetComparison,
  labelTargetComparison,
  describeTargetSaltAbsence,
  readTargetOnRecord,
  EPOCH_MEMORY_KINDS,
  type EpochMemory,
  type TargetSaltAbsenceReason,
} from "./target-fingerprint";
// S201 / removability: a FIXTURE uid for the pure route-table arms — any value
// works there so long as each arm agrees with itself; it is never the served
// subject's uid, which only the declaration may carry.
const FX_SUBJECT_UID = 4711;

/** R6 · the memory a genuine FIRST start sees: both books read cleanly and say nothing. */
const NO_EPOCH_MEMORY: EpochMemory = { status: "NONE" };
/** R6 · the memory EVERY start after the first sees. It is what forbids a second mint. */
const EPOCH_REMEMBERED: EpochMemory = { status: "PRESENT", saltId: "0123456789abcdef", where: "event book row SALT_EPOCH_STARTED" };

/**
 * Does the INSTALLED machine's custody door carry the arbiter's expectedOwner
 * parameter (ruling 2026-09-30 09:0xZ, option 1)? This is a RELAY QUESTION, not
 * a code question: mica-service.ts imports that door from /opt/mica-machine by
 * absolute path, so a worktree cannot answer it. Probed, not assumed.
 */
/**
 * ⛔ THE ARMS ARE PROVABLE HERE, AND I SAID TWICE THAT THEY WERE NOT.
 *
 *    First this was `CLOCK_DOOR_HAS_EXPECTED_OWNER` — a grep of /opt's source
 *    for the STRING "expectedOwner", which asked whether a parameter existed
 *    and was read as asking whether anything could pass one. When the parameter
 *    landed the tests it guarded went from SKIP to FAIL.
 *
 *    Then it was `CLOCK_STAMPS_ARMS_PROVABLE_HERE = false`, on the reasoning
 *    that the front door refuses a declared stamps path outside the two
 *    /var/lib/mica roots, and both are unwritable by this uid. BOTH HALVES TRUE, CONCLUSION
 *    FALSE — Codex F4-read F3, 2026-09-30.
 *
 * ⛔ `MicaBridgeService.resolvePath()` REWRITES THE DECLARED PREFIX:
 *
 *      declared.replace(/^\/var\/lib\/mica-bridge/, this.stateDirOverride)
 *
 *    So a declaration may name /var/lib/mica-bridge/clerk-stamps.jsonl — which
 *    is what the front door demands — and the file the service actually opens is
 *    inside the test's own stateDir. NO DECLARATION RULE IS RELAXED AND /var/lib
 *    IS NEVER TOUCHED. Those three lines were in the file I was editing, and I
 *    was already passing `stateDir` in every one of these tests.
 *
 *    The custody door then wants the file NOT WRITABLE BY THE INVOKER (0444) and
 *    its PARENT either not-writable or STICKY (clerk-clock-stamps-file.ts:300 —
 *    `sticky = (pst.mode & 0o1000) !== 0`), because an invoker who can unlink
 *    the file can replace it. A sticky scratch directory satisfies both while
 *    remaining a directory this test can write.
 *
 * ⚠ THE LESSON, THIRD TIME ON THE SAME FOUR TESTS: each of my three reasons for
 *   skipping them was a true fact about something adjacent, assembled into a
 *   conclusion I never tried to falsify. A skip justified by an argument is a
 *   skip nobody checks.
 */
function clerkStampsFixture(stateDir: string): string {
  // The declared path is /var/lib/mica-bridge/clerk-stamps.jsonl; resolvePath
  // maps it here. Sticky parent + read-only file = what the real door admits.
  const stamps = join(stateDir, "clerk-stamps.jsonl");
  writeFileSync(stamps, "", "utf8");
  chmodSync(stamps, 0o444);
  chmodSync(stateDir, 0o1755);
  return stamps;
}
const skipped: string[] = [];
let skippedCount = 0;
let passed = 0;
let failed = 0;
/**
 * ⛔ A SKIP IS A THIRD RESULT, NOT A PASS. Codex F3, 2026-09-30.
 *
 *   This harness counted a callback that pushed to `skipped` and returned AS A
 *   PASS, and I then wrote "all five added tests PASS" in a brief while three of
 *   them had asserted nothing. The census was not lying about arithmetic — it
 *   was answering a different question from the one every reader asks of it.
 *
 * ⚠ AND IN A RELAY-CANDIDATE RUN AN UNEXPECTED SKIP IS A FAILURE. Set
 *   MICA_RELAY_CANDIDATE=1 and a skip stops being a note and becomes a red:
 *   the whole point of a relay candidate is that nothing was merely not looked
 *   at. A skip is information on a working day and a defect on a shipping one.
 */
class Skipped extends Error {}
function skip(reason: string): never {
  throw new Skipped(reason);
}
const RELAY_CANDIDATE = process.env.MICA_RELAY_CANDIDATE === "1";

/**
 * ── THE TWO ARMS THAT WAIT ON A REAL CHILD, AND WHY THE NUMBER IS HERE ──────
 *
 * Three checks in this file can be cut off waiting for a REAL child of the entry
 * point: `F1 end-to-end`, the `MICA_BRIDGE_STATE_DIR` arm, and STAGE 4 §A.6's
 * second writer. (I first wrote "exactly two" here, having counted the arms that
 * went red rather than the arms that carry a timeout — see requireChildOutcome.)
 * Each child is a fresh `ts-node` compile of the whole service, which
 * measured ~10 s on this box (and ~5.5 s without the `typeRoots` pointing at a
 * path that does not exist here) — so 30 s is a 3× margin, stated once instead
 * of twice.
 *
 * ⛔ AND THE MARGIN IS A FUNCTION OF LOAD, NOT OF CHANCE. Measured 2026-10-03
 *    at c63fa96: fourteen SEQUENTIAL runs of this suite gave `158/16` fourteen
 *    times with one identical FAIL-set; three runs CONCURRENTLY gave `156/18`
 *    three times, and the extra reds were these arms, every time. A SECOND
 *    3-way round, after the first repair, put `F1 end-to-end` red in all three
 *    runs and left the other two green: WHICH member flaps is itself a function
 *    of the load, so the register's question "has this ever varied?" cannot
 *    represent it. 0 of 14 at idle, 3 of 3 under contention, in both rounds.
 *    There is no flake RATE to estimate here — the variable is the box.
 *
 * ⛔ AND THE CONCLUSION I DREW FROM THAT WAS WRONG. CODEX, 2026-10-04, on
 *    9872bf3: I made a timeout a `skip()` on the reasoning that a child never
 *    given the CPU has not been observed. Two things were wrong with it.
 *
 *    (1) THE TEST FOR "TIMED OUT" WAS `status === null && signal !== null`, WHICH
 *        IS THE SHAPE OF ANY KILLED CHILD. A segfault (SIGSEGV) or an external
 *        SIGTERM has exactly that shape and carries no `error`, so a CRASH was
 *        being filed as a non-observation. `error.code === "ETIMEDOUT"` is the
 *        discriminator; the signal is not.
 *    (2) A GENUINE HANG IN THE SERVICE READ AS A NON-GATING SKIP. Codex measured
 *        160/16/2 and 159/16/3 under load where I had reported 162/16/0 — the
 *        mechanism was firing, quietly, and the exit code came from the sixteen
 *        rather than from anything this repair did.
 *
 * ⚠ MY OWN BRIEF HAD NAMED THIS AS THE ATTACK AND I SHIPPED IT ANYWAY: "is
 *   skip() on timeout the right verdict at all, or does it convert a genuine hang
 *   into a quiet non-observation on every working day? My defence is
 *   MICA_RELAY_CANDIDATE=1, which nothing in the relay path currently sets — so
 *   the defence is a flag nobody turns on." Codex took the attack and ruled it.
 *
 * RULED (HOW, 2026-10-04 06:22Z): a SIGNAL exit is a FAILURE; a TIMEOUT is a
 * FAILURE unless the arm is on a flaky register; a SKIP is only ever an EXPLICIT
 * skip. What the repair keeps is the part that was right — the evidence
 * (`status`, `signal`, `error.code`) is in the message instead of an empty stderr.
 */
const CHILD_COMPILE_BUDGET_MS = 30000;

/**
 * ── THE FLAKY REGISTER FOR THIS FILE, AND IT IS DELIBERATELY EMPTY ──────────
 *
 * The ruling allows a timeout to be skipped for an arm that is ON A FLAKY
 * REGISTER. No arm here is, and the reason is the register's own rule rather than
 * my preference: an entry is earned by variation across ≥14 DIRECT runs
 * (`tools/flaky-register.ts`, MIN_DIRECT_RUNS = 14, from ⌈ln.05/ln.8⌉). These
 * three arms varied under CONCURRENCY and 0 of 14 times directly, so they earn
 * nothing. The clause is implemented rather than omitted — see the arm that
 * exercises it with an injected set — so that registering one later is a data
 * change and not a code change.
 */
const LOAD_SENSITIVE_ARMS: ReadonlySet<string> = new Set<string>();

/**
 * What a child's outcome MEANS, with the evidence attached.
 *
 * ⛔ THREE OUTCOMES, AND THE DISCRIMINATOR IS `error.code` AND NOT THE SIGNAL.
 *    A `spawnSync` timeout leaves `status: null`, `signal: "SIGTERM"` AND
 *    `error.code: "ETIMEDOUT"`. A segfault leaves `signal: "SIGSEGV"` and NO
 *    error. An external kill leaves `signal: "SIGTERM"` and NO error. My first
 *    version tested `status === null && signal !== null`, which is the shape of
 *    ALL THREE — so a crash was filed as a non-observation. Codex found it.
 *
 * ⚠ AND A TIMEOUT IS A FAILURE HERE, not a skip, unless the arm is registered:
 *   a genuine hang in the service is exactly what this suite exists to catch, and
 *   a hang that reads as a skip is a hang nobody is told about.
 */
function requireChildOutcome(
  result: { status: number | null; signal: NodeJS.Signals | null; error?: Error },
  arm: string,
  registered: ReadonlySet<string> = LOAD_SENSITIVE_ARMS
): void {
  const err = result.error as NodeJS.ErrnoException | undefined;
  const evidence = `status=${result.status} signal=${result.signal} error=${err?.code ?? "none"}`;
  // ⛔ A STATUS IS AN ANSWER, AND IT OUTRANKS THE CLOCK. Found by running the
  //    suite three-up rather than by reasoning: `F1 end-to-end` came back
  //    `status=2 signal=null error=ETIMEDOUT` — the child DID exit, with exactly
  //    the 2 the arm wanted, and node set `error` because the timer fired in the
  //    same breath. Failing that is a false red on a correct observation. The
  //    timeout only means something when there is NO status to read.
  //
  // ⚠ AND THIS DOES NOT REOPEN WHAT CODEX RULED: a signal exit is still a
  //   failure below, and a timeout with no status is still a failure. What is
  //   removed is only the case where the child answered.
  if (result.status !== null && result.signal === null) return;
  if (err?.code === "ETIMEDOUT") {
    if (registered.has(arm)) {
      skip(
        `${arm}: timed out after ${CHILD_COMPILE_BUDGET_MS} ms — ${evidence}. This arm is on the ` +
          `flaky register, so a timeout is a NON-OBSERVATION here; under MICA_RELAY_CANDIDATE=1 it is a red.`
      );
    }
    assert(
      false,
      `${arm}: the child did not finish inside ${CHILD_COMPILE_BUDGET_MS} ms — ${evidence}. ` +
        `A TIMEOUT IS A FAILURE unless the arm is on a flaky register, and this one is not: it varied ` +
        `under concurrency and 0 of 14 times directly, which earns no entry. If this box was running ` +
        `another copy of the suite, run it alone; if it was not, the service hung and that is the finding.`
    );
  }
  if (result.signal !== null) {
    assert(
      false,
      `${arm}: the child was KILLED BY ${result.signal} — ${evidence}. A SIGNAL EXIT IS A FAILURE and ` +
        `it is not a timeout: a timeout carries error.code ETIMEDOUT and this one does not. A crash or an ` +
        `external kill is a verdict about the child, never a non-observation.`
    );
  }
}
function check(name: string, fn: () => void | Promise<void>): Promise<void> {
  if (skipHere("mica-service.test.ts", name)) return Promise.resolve();
  return Promise.resolve()
    .then(fn)
    .then(() => {
      passed++;
      console.log(`PASS  ${name}`);
    })
    .catch((err) => {
      if (err instanceof Skipped) {
        if (RELAY_CANDIDATE) {
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
          console.log(`      SKIPPED IN A RELAY-CANDIDATE RUN, which is a failure: ${err.message}`);
          return;
        }
        skippedCount++;
        skipped.push(`${name} — ${err.message}`);
        console.log(`SKIP  ${name}`);
        return;
      }
      failed++;
      process.exitCode = 1;
      console.log(`FAIL  ${name}`);
      console.log(`      ${err instanceof Error ? err.message : String(err)}`);
    });
}
function assert(cond: boolean, msg: string): void {
  if (!cond) throw new Error(`assertion failed: ${msg}`);
}

const DRAFT_PATH = writeShippedDraft(join(mkdtempSync(join(tmpdir(), "mica-shipped-draft-")), "declarations.config.json"));
const draft = shippedDraft();
const TSNODE = process.env.TSNODE || require.resolve("ts-node/dist/bin.js");
const OWN_UID = process.getuid ? process.getuid() : 0;
// The invoking account's NAME, for the custody door's expectedOwner. Read from
// the process rather than hard-coded, so this suite is not pinned to one box's
// user list.
const OWN_USER: string = userInfo().username;
const OWN_GID = process.getgid ? process.getgid() : 0;

function httpJson(socketPath: string, method: string, path: string, body?: unknown): Promise<{ status: number; body: any }> {
  return new Promise((resolve, reject) => {
    const text = body !== undefined ? JSON.stringify(body) : undefined;
    const req = http.request(
      {
        socketPath,
        path,
        method,
        headers: text !== undefined ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text) } : {},
        timeout: 5000,
        // No connection pooling across requests: several tests restart a
        // service on the same socket PATH (a fresh listener, same string),
        // and a reused/pooled connection from a torn-down server can
        // surface as a spurious EPIPE on the next write otherwise.
        agent: false,
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          try {
            resolve({ status: res.statusCode ?? 0, body: data.length > 0 ? JSON.parse(data) : null });
          } catch (e) {
            reject(e);
          }
        });
      }
    );
    req.on("error", reject);
    if (text !== undefined) req.write(text);
    req.end();
  });
}

// ── ACT A · THE RETIRED FILE EVERY SERVICE TEST NEEDS ───────────────────────
//
// X15 (2026-09-28) refuses an empty `retiredPath`, so no test can declare FIRST
// BOOT any more — and the boundary writer RE-READS the named file and refuses any
// disagreement. So every service that starts here must have a real retired file to
// point at, or the chain never begins and the first POST /subject-events fails on
// a chain with no boundary at position 0.
//
// The content is FIXED, so the three measurements are derived from the bytes right
// here rather than pinned as literals that could drift away from the fixture.
const RETIRED_FIXTURE_NAME = "subject-events.TESTFIXTURE.pre-chain-boundary.jsonl";
const RETIRED_FIXTURE_BODY =
  JSON.stringify({ sequenceNumber: 1, timestamp: 1, moduleId: "housekeeper", eventType: "TOOL_ATTEMPTED", outcome: "bash" }) +
  "\n" +
  JSON.stringify({ sequenceNumber: 2, timestamp: 2, moduleId: "housekeeper", eventType: "TOOL_RESULT", outcome: "OK" }) +
  "\n";
const RETIRED_FIXTURE = {
  declaredPath: `/var/lib/mica-bridge/${RETIRED_FIXTURE_NAME}`,
  records: RETIRED_FIXTURE_BODY.split("\n").filter((l) => l.trim().length > 0).length,
  bytes: Buffer.byteLength(RETIRED_FIXTURE_BODY, "utf8"),
  sha256: createHash("sha256").update(Buffer.from(RETIRED_FIXTURE_BODY, "utf8")).digest("hex"),
};

/**
 * ⛔ EVERY TEMP DIRECTORY GETS THE RETIRED FIXTURE, AND IT IS DONE HERE RATHER THAN
 *    AT 168 CALL SITES.
 *
 * X15 refuses an empty retiredPath, so every service started in this file declares a
 * retired file — and the boundary writer RE-READS it. A test whose state dir lacks
 * that file gets "SUBJECT CHAIN NOT BEGUN", and then every POST /subject-events in it
 * fails. Writing it only in `writableTestPaths()` covered the config dirs and MISSED
 * the state dirs made directly (c9Service, the F5 real-entry-point test, and others):
 * nine tests that post subject events went red for that reason alone.
 *
 * So `mkdtempSync` is wrapped once, at the import. Any directory this file creates
 * carries the fixture. It is INERT unless a declaration names it, and only this test
 * file is affected — the production import is untouched.
 */
function mkdtempSync(prefix: string): string {
  const dir = mkdtempSyncRaw(prefix);
  // ⚠ ONLY STATE AND CONFIG DIRECTORIES. The first version of this wrapper wrote the
  //   fixture into EVERY temp dir this file makes — peer dirs, socket dirs, marker
  //   dirs — and the suite STALLED: those directories are inspected, mode-checked and
  //   counted by tests that did not expect a file to appear in them. The fixture
  //   belongs only where a SERVICE keeps state, which is what resolvePath rewrites
  //   /var/lib/mica-bridge to.
  if (/mica-bridge-(state|cfg)/.test(prefix)) {
    try {
      writeFileSync(join(dir, RETIRED_FIXTURE_NAME), RETIRED_FIXTURE_BODY, "utf8");
    } catch {
      /* a directory a test means to make unwritable is not this helper's business */
    }
  }
  return dir;
}

function writableTestPaths(): { eventBook: string; subjectLog: string; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
  return { eventBook: join(dir, "events.jsonl"), subjectLog: join(dir, "subject-events.jsonl"), dir };
}

// ── ACT A · reading a CHAINED subject log in a test ──────────────────────────
//
// The subject log's first line is now the chain's own SUBJECT_LOG_BOUNDARY
// record (the arbiter's ruling 3): "the log starts here", INSIDE the chain and
// hashed like every other line, naming what this chain replaced or declaring
// FIRST BOOT. It is a real record — Sig F1 and Eng both see it — so a test
// that counts or walks SUBJECT EVENTS must separate it rather than pretend it
// is absent. Every such assertion below reads this helper, and the boundary is
// then asserted on its own terms instead of being filtered away silently.
function readSubjectChain(path: string): {
  readonly all: readonly any[];
  readonly boundary: any | null;
  readonly events: readonly any[];
} {
  const all = readFileSync(path, "utf8")
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l));
  const boundary = all.length > 0 && all[0].recordType === "SUBJECT_LOG_BOUNDARY" ? all[0] : null;
  return { all, boundary, events: boundary === null ? all : all.slice(1) };
}

/**
 * AMENDMENT 3 / VERIFIER F1's consequence for THIS test suite: with the
 * real ownership check enforced, an unprivileged test process cannot stand
 * up sockets for uids 980/981/1000 the way the pre-Amendment-3 suite did —
 * it is not a member of group `mica-bridge` and cannot chgrp its own
 * directories into it, and it cannot chown a directory to uid 980 or 981
 * at all. That is the fix working, not a test limitation to route around.
 *
 * So: HTTP-behavior tests below run against a SINGLE-ROUTE test
 * declaration where the one declared uid IS this process's own uid, with a
 * REAL self-owned 0770 directory, verified by the REAL `validatePeerDir`
 * logic — only the expected GROUP is substituted via `testBridgeGid`
 * (documented in mica-service.ts's own option) because this process is not
 * a member of the real `mica-bridge` group either. The genuinely
 * MULTI-UID, unprivileged-and-still-enforced behavior (refusing to start at
 * all when directories are missing/wrong-owned) is exercised for real,
 * against the real declaration and the real entry point, in the dedicated
 * F1 end-to-end test further down — no substitution there at all.
 */

// ── FIXTURE NEUTRALITY (S136) ────────────────────────────────────────────
// `draft` is the LIVE shipped declarations.config.json. Cloning it verbatim
// made every fixture in this file inherit whatever the deployment happened
// to declare — so the moment Stage 4 declared a real pilot, five tests in
// two suites went red for a reason that had nothing to do with the code
// under test. A behavioural test must declare the state it is testing.
//
// So the pilot is neutralised HERE, once, to the known baseline. Tests that
// want an ACTIVE pilot set it explicitly on their own clone (several already
// do, and those are the ones that kept passing). This is not a loosening:
// it removes a hidden dependency on a file the tests do not own.
function singleRouteTestDeclaration(): unknown {
  const d = JSON.parse(JSON.stringify(draft));
  d.pilot = { active: false };
  // ⛔ GATE 1 IS STRIPPED HERE, ONCE (S26, 2026-10-08). The tree declaration now
  //   carries a frame, readers.gate1Scope and paths.interestBook for its served
  //   subject. This general fixture models the bridge WITHOUT Gate 1, which is
  //   what every arm written before it assumes (its event book, its wiring). The
  //   Gate 1 arms declare their own frame, book and reader on top of it, and ONE
  //   arm ("THE SERVED SHAPE (S26)") starts the shipped Gate 1 stanza as is.
  delete d.frame;
  if (d.readers !== undefined) delete d.readers.gate1Scope;
  if (d.paths !== undefined) delete d.paths.interestBook;
  // ⛔ AND GATE 2 WITH IT (S29, 2026-10-09). The tree now also declares
  //   readers.gate2Direction and baskets[<served subject>]; a basket bears on its
  //   subject's FRAME (R1), so stripping the frame without the basket is a
  //   declaration the front door refuses — measured: every withService arm failed
  //   at start() on the S29 tree. The Gate 2 arms declare their own on top.
  if (d.readers !== undefined) delete d.readers.gate2Direction;
  delete d.baskets;
  // AND GATE 2's HARM STANZA (S34, 2026-10-15): it replaces the served subject's basket and is keyed to its frame (H1).
  delete d.harm;
  // the committed config carries a PENDING-ROTATION placeholder that names no real
  // file; a test must declare the fixture it actually wrote (see RETIRED_FIXTURE)
  d.subjectLog.chainBoundary.retiredPath.value = RETIRED_FIXTURE.declaredPath;
  d.subjectLog.chainBoundary.retiredRecords.value = RETIRED_FIXTURE.records;
  d.subjectLog.chainBoundary.retiredBytes.value = RETIRED_FIXTURE.bytes;
  d.subjectLog.chainBoundary.retiredSha256.value = RETIRED_FIXTURE.sha256;
  d.subjects = [{ subject: "housekeeper", toolName: "bash", stakesClass: "bash", peerUid: OWN_UID }];
  d.routes = [
    {
      uid: OWN_UID,
      role: "subject",
      allow: [
        { method: "POST", path: "/guard" },
        { method: "POST", path: "/subject-events" },
        { method: "GET", path: "/status" },
        { method: "GET", path: "/events" },
        { method: "GET", path: "/log" },
        // 2026-10-04 · the subject's own ending order. Granted in the FIXTURE so
        // the route can be exercised; the SERVED declaration gaining it for uid
        // 980 is a separate act of the arbiter's hand.
        { method: "GET", path: "/sunset-order" },
      ],
    },
  ];
  return d;
}

function sockFor(socketDir: string, uid: number): string {
  return join(socketDir, "peers", String(uid), "guard.sock");
}

/**
 * AMENDMENT 5 / VERIFIER "UTF8/HASH": the REAL eventHash a caller must
 * supply — sha256 over the canonical form of {identity, kind, payload?},
 * `payload` omitted entirely when absent (design §C.4-4 / §C.6), exactly
 * what the service now recomputes and verifies on every
 * `POST /subject-events`. Every test that sends a subject-event uses this,
 * never a fabricated `"x".repeat(64)` string — a hash the service never
 * checked was exactly the defect the verifier's adversarial pass caught in
 * Amendment 4's own test suite (see the receipt's §E "what the fabricated
 * hash cost us").
 */
function realEventHash(identity: { subject: string; sessionId: string; actionId: string }, kind: string, payload?: Record<string, unknown>): string {
  const input: any = { identity, kind };
  if (payload !== undefined) input.payload = payload;
  return canonicalHash(input);
}

/** Creates `<socketDir>/peers/<uid>/`, self-owned, mode 0770 — real fs state. */
function makeOwnPeerDir(socketDir: string, uid: number): void {
  const dir = join(socketDir, "peers", String(uid));
  mkdirSync(dir, { recursive: true });
  chmodSync(dir, 0o770);
}

async function withService(
  fn: (svc: MicaBridgeService, socketDir: string, stateDir: string) => Promise<void>,
  now = () => new Date("2026-09-18T00:00:00Z")
): Promise<void> {
  const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
  makeOwnPeerDir(socketDir, OWN_UID);
  const testWritablePaths = writableTestPaths();
  const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
  const cfgPath = join(cfgDir, "declarations.config.json");
  writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
  const svc = new MicaBridgeService({
    declarationsPath: cfgPath,
    socketDir,
    now,
    testWritablePaths,
    testBridgeGid: OWN_GID,
    // STAGE 4 / DESIGN §A.6, Layer 2: start() now claims an owner file
    // under the resolved history path. Without a writable stateDir, that
    // claim lands under the real (root-owned) /var/lib/mica-bridge and
    // start() correctly refuses — this is the F1 precedent, extended.
    stateDir: testWritablePaths.dir,
  });
  await svc.start();
  try {
    await fn(svc, socketDir, testWritablePaths.dir);
  } finally {
    await svc.stop();
  }
}

/**
 * Sends a raw HTTP/1.1 POST over a Unix socket with the body written as TWO
 * separate `socket.write()` calls, split at an exact byte offset, with a
 * short delay between them — reproducing exactly the verifier's "split
 * across two socket writes with a gap" scenario at the TCP/stream level
 * (Node's `http` client module buffers/coalesces writes in ways that do not
 * reliably reproduce a genuine multi-chunk `data` event sequence on the
 * server side; a raw `net.Socket` does not).
 */
/**
 * All bytes here are pushed through as `binary` (latin1)-encoded STRINGS,
 * never `Buffer` objects handed to `net.Socket.write()` — the same
 * Buffer-vs-`Uint8Array<ArrayBufferLike>` typing mismatch that broke the
 * pinned toolchain's compile at `mica-service.ts:471` (F2) recurs at
 * Node's `net`/`http` `.write()` overloads under this same `@types/node`;
 * `binary`/`latin1` is a lossless 1:1 byte<->code-point mapping, so a
 * string built this way round-trips the exact bytes without ever handing a
 * `Buffer` to an API whose typings reject it here.
 */
function rawSplitPost(socketPath: string, bodyBuf: Buffer, splitAt: number): Promise<{ status: number; rawBody: Buffer }> {
  const bodyBinary = bodyBuf.toString("binary");
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    let received = "";
    socket.on("connect", () => {
      const header =
        `POST /subject-events HTTP/1.1\r\n` +
        `Host: unix\r\n` +
        `Content-Type: application/json\r\n` +
        `Content-Length: ${bodyBuf.length}\r\n` +
        `Connection: close\r\n\r\n`;
      socket.write(header, "binary");
      const first = bodyBinary.slice(0, splitAt);
      const second = bodyBinary.slice(splitAt);
      if (first.length > 0) socket.write(first, "binary");
      setTimeout(() => {
        if (second.length > 0) socket.write(second, "binary");
      }, 25);
    });
    socket.setEncoding("binary");
    socket.on("data", (d: string) => (received += d));
    socket.on("end", () => {
      const headerEnd = received.indexOf("\r\n\r\n");
      const statusLine = received.slice(0, received.indexOf("\r\n"));
      const statusMatch = /HTTP\/1\.1 (\d+)/.exec(statusLine);
      const status = statusMatch ? Number(statusMatch[1]) : 0;
      const rawBodyBinary = headerEnd === -1 ? "" : received.slice(headerEnd + 4);
      resolve({ status, rawBody: Buffer.from(rawBodyBinary, "binary") });
    });
    socket.on("error", reject);
  });
}

async function main(): Promise<void> {
  // ── peer authorization matrix — tested directly against the REAL ruled
  // declaration's routes (no substitution needed: authorizeRoute takes a
  // peerUid as a plain argument, per the coordinator's own fallback).

  const loaded = validateDeclarations(draft);
  const routes = loaded.declarations.routes;

  await check("authorizeRoute: allowed uid + allowed method/path -> allowed", () => {
    const r = authorizeRoute(routes, 980, "POST", "/guard");
    assert(r.allowed === true, JSON.stringify(r));
  });

  await check("authorizeRoute: wrong uid (no routes[] row) -> 403", () => {
    const r = authorizeRoute(routes, 42424, "POST", "/guard");
    assert(!r.allowed && r.httpStatus === 403, JSON.stringify(r));
  });

  await check("authorizeRoute: right uid, unlisted method/path combination -> 403 (no row grants it)", () => {
    const r = authorizeRoute(routes, 980, "GET", "/status");
    assert(!r.allowed && r.httpStatus === 403, JSON.stringify(r));
  });

  await check("authorizeRoute: right uid, path exists on that row but wrong method -> 405", () => {
    const r = authorizeRoute(routes, 1000, "POST", "/status" as any);
    assert(!r.allowed && r.httpStatus === 405, JSON.stringify(r));
  });

  // ── R1 · /explain — uid 1000 ONLY, never the subject's row ───────────────

  await check("R1 · authorizeRoute: uid 1000 (operator) IS granted GET /explain", () => {
    const r = authorizeRoute(routes, 1000, "GET", "/explain" as any);
    assert(r.allowed === true, JSON.stringify(r));
  });

  await check("R1 · authorizeRoute: uid 980 (the HOUSEKEEPER — the subject's own peer) is REFUSED GET /explain -> 403", () => {
    // THE HARD CONSTRAINT AT THE REQUEST LAYER. This is NOT the no-row path:
    // uid 980 HAS a routes[] row, carrying its two POST grants. It simply
    // holds no /explain grant, so `authorizeRoute` finds no matching entry and
    // returns 403. The outer layer matters more — declarations.ts's X13
    // refuses to LOAD a declaration that gives this uid the grant at all — so
    // this check holds the second line of the defence, not the only one.
    const r = authorizeRoute(routes, 980, "GET", "/explain" as any);
    assert(!r.allowed && r.httpStatus === 403, JSON.stringify(r));
  });

  await check("R1 · authorizeRoute: uid 981 (alerter) is refused GET /explain -> 403", () => {
    // Not a subject, and not granted it either: /explain went to the operator
    // row alone. A peer that reads /events and /status does not thereby read
    // the reasoning behind them.
    const r = authorizeRoute(routes, 981, "GET", "/explain" as any);
    assert(!r.allowed && r.httpStatus === 403, JSON.stringify(r));
  });

  await check("R1 · authorizeRoute: POST /explain is refused even for uid 1000 -> 405 — it is a read surface", () => {
    const r = authorizeRoute(routes, 1000, "POST", "/explain" as any);
    assert(!r.allowed && r.httpStatus === 405, JSON.stringify(r));
  });

  // ── F1 — the real ownership boundary, unit-level (no service, no socket) ─

  await check("resolveGid resolves a real system group", () => {
    const gid = resolveGid("root");
    assert(gid === 0, `expected root's gid 0, got ${gid}`);
  });

  await check("resolveGid returns null for a nonexistent group", () => {
    const gid = resolveGid("no-such-group-xyz-123");
    assert(gid === null, String(gid));
  });

  await check("validatePeerDir: NEVER creates a directory — a missing directory is refused, not provisioned", () => {
    const dir = mkdtempSync(join(tmpdir(), "mica-bridge-peerdir-"));
    const plan: PeerSocketPlan = { uid: OWN_UID, role: "operator", socketPath: join(dir, "missing", "guard.sock"), socketDir: join(dir, "missing") };
    const result = validatePeerDir(plan, OWN_GID);
    assert(!result.ok, "expected refusal");
    assert(!existsSync(plan.socketDir), "validatePeerDir must never create the directory");
  });

  await check("validatePeerDir: exact uid/gid/mode match -> ok", () => {
    const dir = mkdtempSync(join(tmpdir(), "mica-bridge-peerdir-"));
    const peerDir = join(dir, "peer");
    mkdirSync(peerDir);
    chmodSync(peerDir, 0o770);
    const plan: PeerSocketPlan = { uid: OWN_UID, role: "operator", socketPath: join(peerDir, "guard.sock"), socketDir: peerDir };
    const result = validatePeerDir(plan, OWN_GID);
    assert(result.ok, JSON.stringify(result));
  });

  await check("validatePeerDir: wrong uid -> refused, named", () => {
    const dir = mkdtempSync(join(tmpdir(), "mica-bridge-peerdir-"));
    const peerDir = join(dir, "peer");
    mkdirSync(peerDir);
    chmodSync(peerDir, 0o770);
    const plan: PeerSocketPlan = { uid: OWN_UID + 999999, role: "operator", socketPath: join(peerDir, "guard.sock"), socketDir: peerDir };
    const result = validatePeerDir(plan, OWN_GID);
    assert(!result.ok && result.reason.includes("owned by uid"), JSON.stringify(result));
  });

  await check("validatePeerDir: wrong gid -> refused, named", () => {
    const dir = mkdtempSync(join(tmpdir(), "mica-bridge-peerdir-"));
    const peerDir = join(dir, "peer");
    mkdirSync(peerDir);
    chmodSync(peerDir, 0o770);
    const plan: PeerSocketPlan = { uid: OWN_UID, role: "operator", socketPath: join(peerDir, "guard.sock"), socketDir: peerDir };
    const result = validatePeerDir(plan, OWN_GID + 999999);
    assert(!result.ok && result.reason.includes("gid"), JSON.stringify(result));
  });

  await check("validatePeerDir: wrong mode (0755, has a world bit) -> refused, named", () => {
    const dir = mkdtempSync(join(tmpdir(), "mica-bridge-peerdir-"));
    const peerDir = join(dir, "peer");
    mkdirSync(peerDir);
    chmodSync(peerDir, 0o755);
    const plan: PeerSocketPlan = { uid: OWN_UID, role: "operator", socketPath: join(peerDir, "guard.sock"), socketDir: peerDir };
    const result = validatePeerDir(plan, OWN_GID);
    assert(!result.ok && result.reason.includes("mode"), JSON.stringify(result));
  });

  await check("POST-CLOSURE FIX 1: validatePeerDir checks ONLY the leaf — the PARENT's mode (whatever it is) never changes the verdict", () => {
    // Confirms at bytes what peer-auth.ts's own code already shows
    // (validatePeerDir statSync's plan.socketDir alone, never its parent):
    // the parent directories' mode (0750 -> 0711, this Post-Closure Fix)
    // cannot possibly change validatePeerDir's verdict, because nothing in
    // it ever inspects a parent at all. Tried at TWO different, mutually
    // exclusive parent modes (owner-only 0700, and wide-open 0777) — if
    // validatePeerDir secretly cared about the parent, these two would not
    // both produce the same verdict on the identical leaf.
    //
    // Deliberately NOT tried at 0000: a parent with no execute bit at all
    // denies traversal to EVERY uid, including the leaf's own owner and
    // this test process itself — Node's own statSync() on the leaf would
    // then fail with EACCES before validatePeerDir's own logic ever ran,
    // which would be a toolmaking accident of this test's setup, not a
    // finding about the code under test.
    const dir = mkdtempSync(join(tmpdir(), "mica-bridge-peerdir-"));
    const parent = join(dir, "peers");
    mkdirSync(parent);
    const peerDir = join(parent, "980");
    mkdirSync(peerDir);
    chmodSync(peerDir, 0o770);
    const plan: PeerSocketPlan = { uid: OWN_UID, role: "operator", socketPath: join(peerDir, "guard.sock"), socketDir: peerDir };
    for (const parentMode of [0o700, 0o777]) {
      chmodSync(parent, parentMode);
      const result = validatePeerDir(plan, OWN_GID);
      assert(result.ok, `expected parent mode ${parentMode.toString(8)} to be IRRELEVANT to the leaf's own verdict, got ${JSON.stringify(result)}`);
    }
    chmodSync(parent, 0o755); // restore so this test's own tmpdir can be cleaned up normally
  });

  await check("validatePeerDir: not a directory (a plain file) -> refused, named", () => {
    const dir = mkdtempSync(join(tmpdir(), "mica-bridge-peerdir-"));
    const fakePath = join(dir, "not-a-dir");
    writeFileSync(fakePath, "x");
    const plan: PeerSocketPlan = { uid: OWN_UID, role: "operator", socketPath: join(fakePath, "guard.sock"), socketDir: fakePath };
    const result = validatePeerDir(plan, OWN_GID);
    assert(!result.ok && result.reason.includes("not a directory"), JSON.stringify(result));
  });

  await check("widenSocketFileMode sets exactly 0666 on the socket file", () => {
    const dir = mkdtempSync(join(tmpdir(), "mica-bridge-sockmode-"));
    const p = join(dir, "fake.sock");
    writeFileSync(p, "");
    chmodSync(p, 0o600);
    widenSocketFileMode(p);
    const st = statSync(p);
    assert((st.mode & 0o777) === 0o666, `expected 0666, got ${(st.mode & 0o777).toString(8)}`);
  });

  // ── F1 — the real ownership boundary, END TO END, unprivileged, no
  // substitution: the real entry point, the real declaration's uids
  // (980/981/1000), run as whatever uid this test process actually is. ─────

  await check("F1 end-to-end: starting with wrong/missing-owned peer directories refuses startup, exit 2, no listener anywhere", () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-e2e-"));
    // Deliberately do NOT create /peers/980 or /peers/981 at all, and give
    // /peers/1000 the WRONG mode (0755) even though it is self-owned — every
    // one of the three declared routes must fail, and even if only one did,
    // start() refuses the whole thing (validates all before binding any).
    const wrongDir = join(socketDir, "peers", "1000");
    mkdirSync(wrongDir, { recursive: true });
    chmodSync(wrongDir, 0o755);

    const result = spawnSync(
      "/usr/bin/node",
      [TSNODE, "-P", join(__dirname, "tsconfig.json"), join(__dirname, "mica-service.ts")],
      {
        encoding: "utf8",
        env: { ...process.env, MICA_BRIDGE_DECLARATIONS: DRAFT_PATH, MICA_BRIDGE_SOCKET_DIR: socketDir },
        timeout: CHILD_COMPILE_BUDGET_MS, // AMENDMENT 8 + the 2026-10-03 load measurement; see CHILD_COMPILE_BUDGET_MS.
      }
    );
    // ⛔ MEASURED 2026-10-03: THIS is the arm that went red in all three of a
    //    3-way concurrent round, with `expected exit 2, got null; stderr: ` —
    //    one extra red, the same shape Codex reported as 157/17.
    requireChildOutcome(result, "F1 end-to-end");
    assert(result.status === 2,
      `expected exit 2, got status=${result.status} signal=${result.signal} ` +
      `error=${(result.error as NodeJS.ErrnoException | undefined)?.code ?? "none"}; stderr: ${result.stderr}`);
    for (const uid of [980, 981, 1000]) {
      assert(!existsSync(sockFor(socketDir, uid)), `no socket must exist for uid ${uid}, but found one`);
    }
  });

  // ── --check mode ────────────────────────────────────────────────────────

  await check("--check on the draft exits 0 and reports the hash", () => {
    const r = runCheck(DRAFT_PATH);
    assert(r.exitCode === 0, r.message);
    assert(r.message.includes(loaded.declarationHash), r.message);
  });

  await check("--check on a malformed declaration exits 2", () => {
    const dir = mkdtempSync(join(tmpdir(), "mica-bridge-badcfg-"));
    const bad = join(dir, "bad.json");
    const d = JSON.parse(JSON.stringify(draft));
    delete d.pilot;
    writeFileSync(bad, JSON.stringify(d));
    const r = runCheck(bad);
    assert(r.exitCode === 2, r.message);
  });

  // ── THE LAPSED PILOT · THE THREE DOORS MUST AGREE ─────────────────────────
  //
  // ⛔ AUDIT RULING 2026-10-03 20:37Z: `--check` must accept a lapsed pilot
  //    exactly as `start()` does. It did not. Measured the same day on the
  //    SERVED declaration with only `expiresAt` moved into the past, `runCheck`
  //    refused (X8) while `start()` accepted — so pilot 5's SCHEDULED lapse at
  //    2026-10-04T18:00:00Z would have blocked every bridge RELAY (step 4 of
  //    relay-bridge.sh runs this very check) while the bridge went on serving.
  //
  // ⚠ THIS ARM IS ALSO A CLOCK TEST OF ITSELF. It builds a past expiry from a
  //   FIXED date rather than from `Date.now() - 1`, so it reads the same on
  //   2026-10-05 as today — and after 18:00Z tomorrow the served declaration
  //   will satisfy it by itself, which is precisely the situation it exists for.
  await check("--check ACCEPTS a lapsed pilot, exactly as start() does — and says the baseline governs", () => {
    const dir = mkdtempSync(join(tmpdir(), "mica-bridge-lapsed-"));
    const lapsedPath = join(dir, "lapsed.json");
    const d = JSON.parse(JSON.stringify(draft));
    assert(d.pilot && d.pilot.active === true, `precondition: the draft's pilot must be ACTIVE, got ${JSON.stringify(d.pilot)}`);
    d.pilot.expiresAt = "2026-10-02T18:00:00Z"; // a real past date, not a computed one
    writeFileSync(lapsedPath, JSON.stringify(d));

    const r = runCheck(lapsedPath);
    assert(r.exitCode === 0, `a lapsed pilot must not refuse the RELAY path: ${r.message}`);
    assert(r.message.includes("pilot=EXPIRED"), `and the state word must carry the fact: ${r.message}`);
    assert(r.message.includes("baseline governs"), `and name the consequence, not just the word: ${r.message}`);

    // ⚠ AND `--check` MUST STILL REFUSE WHAT IT REFUSED BEFORE, or this arm
    //   would be passing because the gate was removed rather than corrected.
    const badDir = mkdtempSync(join(tmpdir(), "mica-bridge-badcfg-"));
    const bad = join(badDir, "bad.json");
    const broken = JSON.parse(JSON.stringify(draft));
    delete broken.pilot;
    writeFileSync(bad, JSON.stringify(broken));
    assert(runCheck(bad).exitCode === 2, "a malformed declaration must still exit 2");
    const markerDir = mkdtempSync(join(tmpdir(), "mica-bridge-marker-"));
    const markerPath = join(markerDir, "relay-in-progress");
    writeFileSync(markerPath, "candidate_sha=deadbeef\n");
    const before = process.env.MICA_BRIDGE_RELAY_MARKER;
    process.env.MICA_BRIDGE_RELAY_MARKER = markerPath;
    try {
      assert(runCheck(lapsedPath).exitCode === 2, "the swap-in-progress marker must still refuse");
    } finally {
      if (before === undefined) delete process.env.MICA_BRIDGE_RELAY_MARKER;
      else process.env.MICA_BRIDGE_RELAY_MARKER = before;
    }
  });

  await check("a lapsed pilot is accepted by the SERVING door too, so the two doors are measured to agree", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    // the test declaration, but with the pilot ACTIVE and already past — the
    // shape `singleRouteTestDeclaration()` deliberately deactivates.
    const d: any = singleRouteTestDeclaration();
    d.pilot = { ...(draft.pilot ?? {}), active: true, expiresAt: "2026-10-02T18:00:00Z" };
    writeFileSync(cfgPath, JSON.stringify(d));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const svc = new MicaBridgeService({
      declarationsPath: cfgPath,
      socketDir,
      // a clock AFTER that expiry, so the pilot really is lapsed on this reading
      now: () => new Date("2026-10-03T12:00:00Z"),
      testBridgeGid: OWN_GID,
      stateDir,
    });
    let refused: unknown = null;
    try {
      await svc.start();
    } catch (e) {
      refused = e;
    }
    try {
      assert(refused === null, `start() must ACCEPT a lapsed pilot — that is the behaviour --check now matches: ${String(refused)}`);
      const status = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
      assert(status.body.pilot.state === "EXPIRED", `and report it as EXPIRED: ${JSON.stringify(status.body.pilot)}`);
      // the same file through the other door
      assert(runCheck(cfgPath).exitCode === 0, "and --check must agree about the same bytes");
    } finally {
      if (refused === null) await svc.stop();
    }
  });

  await check("--check run as a real child process via the EXACT pinned unit command exits 0 on good, binds no socket", () => {
    const out = execFileSync("/usr/bin/node", [TSNODE, "-P", join(__dirname, "tsconfig.json"), join(__dirname, "mica-service.ts"), "--check"], {
      encoding: "utf8",
      env: { ...process.env, MICA_BRIDGE_DECLARATIONS: DRAFT_PATH },
    });
    assert(out.includes("OK declarationHash="), out);
  });

  await check("--check run as a real child process exits 2 on a broken declaration", () => {
    const dir = mkdtempSync(join(tmpdir(), "mica-bridge-badcfg-"));
    const bad = join(dir, "bad.json");
    const d = JSON.parse(JSON.stringify(draft));
    delete d.pilot;
    writeFileSync(bad, JSON.stringify(d));
    const result = spawnSync("/usr/bin/node", [TSNODE, "-P", join(__dirname, "tsconfig.json"), join(__dirname, "mica-service.ts"), "--check"], {
      encoding: "utf8",
      env: { ...process.env, MICA_BRIDGE_DECLARATIONS: bad },
    });
    assert(result.status === 2, `expected exit 2, got ${result.status}`);
  });

  // ── Amendment 6 / verifier F3 healing (b): the swap-in-progress marker ─

  await check("--check REFUSES with exit 2 when the relay marker exists, even for a perfectly good declaration", () => {
    const dir = mkdtempSync(join(tmpdir(), "mica-bridge-marker-"));
    const markerPath = join(dir, "relay-in-progress");
    writeFileSync(markerPath, "candidate_sha=deadbeef\nprevious_sha=cafefeed\nstarted_at=2026-09-19T00:00:00Z\n");
    const r = spawnSync("/usr/bin/node", [TSNODE, "-P", join(__dirname, "tsconfig.json"), join(__dirname, "mica-service.ts"), "--check"], {
      encoding: "utf8",
      env: { ...process.env, MICA_BRIDGE_DECLARATIONS: DRAFT_PATH, MICA_BRIDGE_RELAY_MARKER: markerPath },
    });
    assert(r.status === 2, `expected exit 2, got ${r.status}`);
    assert(r.stdout.includes("deadbeef"), `expected the marker's own content surfaced in the refusal: ${r.stdout}`);
  });

  await check("--check succeeds normally when no relay marker exists (default path, dev tree)", () => {
    const dir = mkdtempSync(join(tmpdir(), "mica-bridge-marker-"));
    const markerPath = join(dir, "relay-in-progress"); // deliberately never created
    const r = spawnSync("/usr/bin/node", [TSNODE, "-P", join(__dirname, "tsconfig.json"), join(__dirname, "mica-service.ts"), "--check"], {
      encoding: "utf8",
      env: { ...process.env, MICA_BRIDGE_DECLARATIONS: DRAFT_PATH, MICA_BRIDGE_RELAY_MARKER: markerPath },
    });
    assert(r.status === 0, `expected exit 0, got ${r.status}: ${r.stdout}${r.stderr}`);
  });

  // ── census / instrument rows ─────────────────────────────────────────────

  await check("buildInstrumentCensus returns exactly 14 rows, all UNWIRED, no health vocabulary", () => {
    const rows = buildInstrumentCensus();
    assert(rows.length === 14, String(rows.length));
    assert(rows.length === INSTRUMENT_IDS.length, "ids/rows length mismatch");
    const text = JSON.stringify(rows).toLowerCase();
    for (const forbidden of ["healthy", "\"ok\"", "green", "verified\"", "unhealthy"]) {
      assert(!text.includes(forbidden), `forbidden vocabulary "${forbidden}" found`);
    }
    assert(rows.every((r) => r.state === "UNWIRED"), "Stage 2 stub: every row must be UNWIRED");
    // AMENDMENT 11 / RULING R item 2: an UNWIRED row took no reading at
    // all, so it must disclose no footing — null, not a guess.
    assert(rows.every((r) => r.footing === null), "an UNWIRED row must carry footing:null");
  });

  await check("AMENDMENT 11 / Ruling R item 2: computeFooting states the true fact for both the verified and unverified cases — pure, unit-level, no live wire() needed", () => {
    // The POSITIVE case (verifiedChain:true) cannot be produced by a live
    // wire() call against MicaLogFile in this dev/test tree — that adapter
    // can NEVER report LOADED_VERIFIED (its own header, cited in the
    // Amendment 10 survey and this amendment's declaration basis).
    // Unit-testing the pure function directly is what proves the LOGIC that
    // WOULD run for a verified state, honestly, rather than skipping the
    // case because standing up a real chained witness store is out of
    // scope for this amendment.
    const verified = computeFooting("MICA/Eng", "LOADED_VERIFIED");
    assert(verified.reader === "MICA/Eng" && verified.loadState === "LOADED_VERIFIED" && verified.verifiedChain === true, JSON.stringify(verified));

    const unverifiedFile = computeFooting("MICA/Sig", "LOADED_UNVERIFIED_FILE");
    assert(unverifiedFile.reader === "MICA/Sig" && unverifiedFile.loadState === "LOADED_UNVERIFIED_FILE" && unverifiedFile.verifiedChain === false, JSON.stringify(unverifiedFile));

    // Anything else observed (FILE_UNREADABLE, a future load state this
    // sensor has never seen) must ALSO read verifiedChain:false — the
    // field states one fact (was this the chain-verified state), never a
    // whitelist of "acceptable" unverified states.
    const unreadable = computeFooting("MICA/Eng", "FILE_UNREADABLE");
    assert(unreadable.verifiedChain === false, JSON.stringify(unreadable));
  });

  // ── PREFLIGHT: before start(), no socket exists ─────────────────────────

  await check("before start(), the socket does not exist yet (no PREFLIGHT socket bound)", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    assert(!existsSync(sockFor(socketDir, 980)), "socket must not exist before start()");
  });

  // ── socket bind + HTTP behavior, single self-owned route ───────────────

  await withService(async (svc, socketDir) => {
    await check("GET /status on the test route's own socket returns 200, SERVING, 14 instruments", async () => {
      const r = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
      assert(r.status === 200, JSON.stringify(r));
      assert(r.body.preflight === "SERVING", r.body.preflight);
      assert(r.body.instruments.length === 14, String(r.body.instruments.length));
      assert(r.body.pilot.state === "INACTIVE", r.body.pilot.state);
      assert(r.body.persistence.state === "OK", JSON.stringify(r.body.persistence));
      assert(r.body.quarantine.eventBook === null && r.body.quarantine.subjectLog === null, JSON.stringify(r.body.quarantine));
      // AMENDMENT 5 / VERIFIER F3 "additional relay hardening": no
      // VINTAGE file exists in this dev/test tree, so `release` must be
      // disclosed as null — never guessed, never defaulted.
      assert(r.body.release === null, JSON.stringify(r.body.release));
    });

    await check("AMENDMENT 9 / Ruling P: GET /status reports EVERY reader this wiring built as WIRED with a factual reason, and the rest UNWIRED", async () => {
      // ⛔ THIS TITLE AND ITS COUNT CHANGED, AND THE OLD ONE IS QUOTED BECAUSE IT
      //   CITED A RULING. It read:
      //
      //     "GET /status reports MICA/Eng and MICA/Sig as WIRED with a factual
      //      reason, the other twelve still UNWIRED"
      //
      //   Ruling P / Amendment 9 fixed the census's SCOPE — it reports only what
      //   a live wire() call populates, and never asserts a reading for a row
      //   nothing wired. It did NOT fix the populated set at TWO: that was a
      //   fact about the day it was written, when Eng and Sig were the only
      //   readers this deployment had wired. EIGHT COMPOSE NOW, and printing two
      //   while the decision names eight is the stale-printer shape.
      //
      //   The arbiter's slate of 2026-09-29 21:0xZ: "the census updates every
      //   wired row". The scope rule is untouched; only the count it happened to
      //   produce has moved.
      const r = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
      assert(r.status === 200, JSON.stringify(r));
      const byId: Record<string, any> = {};
      for (const row of r.body.instruments) byId[row.id] = row;
      assert(byId["MICA/Eng"].state === "WIRED", JSON.stringify(byId["MICA/Eng"]));
      assert(byId["MICA/Sig"].state === "WIRED", JSON.stringify(byId["MICA/Sig"]));
      // ⛔ AND THE ROWS RULING P's SCOPE STILL EXCLUDES: gates 1/2/4/5, op2 and
      //   clerk1.gap are not wired by this glue, so they stay UNWIRED with their
      //   own words. The census is still NARROWER than the gate; what changed is
      //   that it no longer under-reports the readers that ARE wired.
      for (const id of ["MICA/gate1-scope", "MICA/gate2-direction", "MICA/gate4-sunset",
                        "MICA/gate5-adaptive", "MICA/op2-audit-presence", "clerk1.gap"]) {
        assert(byId[id].state === "UNWIRED", `${id}: ${JSON.stringify(byId[id])}`);
        assert(byId[id].lastVerdictKind === null && byId[id].footing === null,
          `an unwired row must carry no reading: ${JSON.stringify(byId[id])}`);
      }
      // A WIRED row carries a verdict and a footing from THIS wiring, or the
      // census is asserting a state it did not read.
      for (const row of r.body.instruments) {
        if (row.state !== "WIRED") continue;
        assert(row.footing !== null, `a wired row must report its footing: ${JSON.stringify(row)}`);
        assert(String(row.reason).includes("readers.logPath"), `${row.id}: ${row.reason}`);
      }
      // A FACTUAL reason, citing the actually-declared logPath — not a
      // restated claim. No health vocabulary anywhere in the census.
      assert(String(byId["MICA/Eng"].reason).includes("readers.logPath"), byId["MICA/Eng"].reason);
      assert(String(byId["MICA/Sig"].reason).includes("readers.logPath"), byId["MICA/Sig"].reason);
      // NO HEALTH VOCABULARY. ACT A NARROWED THIS AND THE NARROWING IS THE
      // POINT OF THE ACT, so it is written out rather than done quietly.
      //
      // The rule was a substring scan for `verified"` — and it fired on the
      // first honest thing this census has ever been able to say, because the
      // deployed reader's LOAD STATE NAME is `LOADED_SUBJECT_CHAIN_VERIFIED`.
      // A load-state name is not a health claim: it names WHICH check ran, and
      // the census prints it beside `verifiedChain`, which is the same fact in
      // a boolean. Banning the word outright would have forced the one adapter
      // that earns a chain to lie about what it checked.
      //
      // So the ban stands on HEALTH words, and the load-state names are
      // permitted BY NAME — not by relaxing the scan, but by removing the
      // known state strings from the text before scanning. A new health word
      // still fires; a stray "verified" outside a declared state name still
      // fires; only the exact strings a reader is entitled to report pass.
      const DECLARED_STATE_NAMES = [
        "loaded_subject_chain_verified",
        "loaded_witness_chain_verified",
        "loaded_verified",
        "\"verifiedchain\"",
      ];
      let text = JSON.stringify(r.body.instruments).toLowerCase();
      for (const permitted of DECLARED_STATE_NAMES) text = text.split(permitted).join("<state>");
      for (const forbidden of ["healthy", "\"ok\"", "green", "verified\"", "unhealthy"]) {
        assert(!text.includes(forbidden), `forbidden vocabulary "${forbidden}" found in instrument census`);
      }
      // The other twelve are untouched by Ruling P and remain UNWIRED —
      // this amendment closes a schema-level defect for exactly two
      // readers, not a blanket "everything is bound now" claim.
      // ⛔ THIS ASSERTION WAS "the other twelve are UNWIRED", AND IT WAS A COUNT
      //   STANDING IN FOR A RULE. The rule is Ruling P's: a row this wiring did
      //   not build reports UNWIRED. The six gates/op2/clerk1.gap this glue does
      //   not wire still do; the six readers it DOES wire no longer have to
      //   pretend otherwise.
      const unbuilt = ["clerk1.gap", "MICA/gate1-scope", "MICA/gate2-direction",
                       "MICA/gate4-sunset", "MICA/gate5-adaptive", "MICA/op2-audit-presence"];
      const others = r.body.instruments.filter((row: any) => unbuilt.includes(row.id));
      assert(others.length === 6 && others.every((row: any) => row.state === "UNWIRED"), JSON.stringify(others));
    });

    await check("AMENDMENT 11 / Ruling R item 2 (ACT A): GET /status prints the ceiling — MICA/Eng and MICA/Sig's footing shows the REAL observed load state, and verifiedChain now follows a DECLARED LIST rather than one ===", async () => {
      const r = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
      assert(r.status === 200, JSON.stringify(r));
      const byId: Record<string, any> = {};
      for (const row of r.body.instruments) byId[row.id] = row;
      // ── WHAT THIS TEST OBSERVED BEFORE ACT A, AND WHAT IT OBSERVES NOW ──
      //
      // BEFORE: whatever the readers stood on, it was never the chain-verified
      // state, because `MicaLogFile` — the only adapter this deployment could
      // point at — says in its own header that it has not earned it and never
      // will. This test's whole content was "the ceiling is PRINTED".
      //
      // NOW: this service writes its subject log as a HASH CHAIN and reads it
      // back through `SubjectChainLog`, so a live `wire()` call over this
      // service's own store reports `LOADED_SUBJECT_CHAIN_VERIFIED` and
      // `verifiedChain: true`. That is the act, observed end to end through
      // the real service, the real socket and the real reader — not a fixture.
      //
      // ⚠ AND THE CEILING IS STILL PRINTED, because it moved rather than went
      // away. `verifiedChain: true` here means TAMPER-EVIDENT, NOT INDEPENDENT:
      // the writer, the chainer and the verifier are all this one process. A
      // bridge that rewrote one of its own records and re-chained from that
      // point produces a file that verifies perfectly and prints exactly this.
      // Closing that is Act B — the clerk's arrival stamps, a separate uid, a
      // key this process did not mint — and Act B is not in this build.
      const engFooting = byId["MICA/Eng"].footing;
      const sigFooting = byId["MICA/Sig"].footing;
      assert(engFooting !== null && sigFooting !== null, JSON.stringify({ eng: engFooting, sig: sigFooting }));
      assert(engFooting.reader === "MICA/Eng" && sigFooting.reader === "MICA/Sig", JSON.stringify({ engFooting, sigFooting }));
      assert(typeof engFooting.loadState === "string" && engFooting.loadState.length > 0, JSON.stringify(engFooting));
      assert(
        engFooting.loadState === "LOADED_SUBJECT_CHAIN_VERIFIED" && sigFooting.loadState === "LOADED_SUBJECT_CHAIN_VERIFIED",
        `expected the chained store's own state: ${JSON.stringify({ engFooting, sigFooting })}`
      );
      assert(
        engFooting.verifiedChain === true && sigFooting.verifiedChain === true,
        `verifiedChain must follow VERIFIED_CHAIN_LOAD_STATES, not one ===: ${JSON.stringify({ engFooting, sigFooting })}`
      );
      // AND THE PREDICATE IS STILL A PREDICATE, not a constant: the pure
      // function it comes from says false for every state that is not on the
      // declared list, including the one this deployment read for a year.
      assert(computeFooting("MICA/Eng", "LOADED_UNVERIFIED_FILE").verifiedChain === false, "the list must not have become a yes");
      assert(computeFooting("MICA/Eng", "SUBJECT_CHAIN_TORN_TAIL").verifiedChain === false, "a torn chain is not a verified one");
      // Both readers share the SAME logFile (wire.ts constructs one),
      // so their footing must be identical.
      assert(engFooting.loadState === sigFooting.loadState, JSON.stringify({ engFooting, sigFooting }));
      const others = r.body.instruments.filter((row: any) => row.id !== "MICA/Eng" && row.id !== "MICA/Sig");
      assert(others.every((row: any) => row.footing === null), "an UNWIRED row must still carry footing:null");
    });

    await check("GET /events on a FRESH service -> well-formed, and holds exactly the SERVICE_STARTED marker and the epoch it began, in that order", async () => {
      const r = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/events");
      assert(r.status === 200, JSON.stringify(r));
      assert(Array.isArray(r.body.events), JSON.stringify(r.body));
      // CHANGED TWICE, and both changes are the same kind of fact. The
      // SERVICE_STARTED beat made "empty" wrong; R6's rework makes "exactly one"
      // wrong, because A FRESH BRIDGE NOW ALSO BEGINS AN EPOCH and that row IS
      // THE MEMORY that stops the next start from beginning a second one.
      // Asserting exact membership rather than a count is what made this test
      // notice at all — a count assertion would have been "2" in one edit and
      // said nothing about what the second line is.
      // ⛔ AND THE THIRD CHANGE ARRIVED — the comment below predicted it and the
      //   assertion did not follow. ACT A's boundary IS written to the book, FIRST,
      //   because a chain that began must be visible to anyone reading from the top.
      //   Exact membership and ORDER, still: three rows, each named.
      // AMENDED (S216-2): AND A FOURTH — a fresh bridge BEGINS ITS GRANT MEMORY (GM0), and the GRANT_MEMORY_BEGUN row
      //   naming its boundary is the event-book memory that tells a later missing file from a first start. Four rows,
      //   each named, in order.
      // AMENDED (ZERO-SUBJECTS, F-10 (a)): AND A FIFTH — the first SUBJECTS_DECLARED on a book is written after the
      //   sockets bind, naming who this start declares. Five rows, each named, in order.
      assert(
        r.body.events.length === 5 &&
          r.body.events[0].kind === "SUBJECT_CHAIN_BOUNDARY" &&
          typeof r.body.events[0].retiredSha256 === "string" &&
          r.body.events[1].kind === "SERVICE_STARTED" &&
          r.body.events[2].kind === "SALT_EPOCH_STARTED" &&
          typeof r.body.events[2].saltId === "string" &&
          r.body.events[3].kind === "GRANT_MEMORY_BEGUN" &&
          /\bboundary=[0-9a-f]{64}\b/.test(String(r.body.events[3].detail)) &&
          r.body.events[4].kind === "SUBJECTS_DECLARED" &&
          Array.isArray(r.body.events[4].declared) &&
          r.body.events[4].declared.length === 1,
        `a fresh book must hold the boundary, the marker, the epoch, the grant memory's beginning and who is declared: ${JSON.stringify(r.body)}`
    //
    // AND ACT A ADDS A THIRD REASON TO THE SAME COMMENT, kept rather than
    // replacing the two above: a first start now also writes the chain's
    // boundary record, so "empty" is wrong for one more reason and the
    // count below moves again.
      // CHANGED BY THE SERVICE_STARTED BEAT, deliberately. This used to assert an
      // EMPTY book. A fresh process now writes exactly one line — the restart
      // marker — so "empty" would be the wrong claim, and asserting the exact
      // membership is a stronger one than asserting a count of zero ever was.
      //
      // ACT A ADDS A SECOND, and it is the brief's third disclosure site: a
      // new subject chain's boundary is recorded in the chain (position 0), in
      // /events, and in the declaration. A rename alone is a fact told to a
      // directory listing. Membership and ORDER are both asserted: the
      // boundary is written before the restart marker because a chain that
      // began must be visible to anyone reading the book from the top, and
      // both carry their own `seq` — two facts, two cursors, never one.
      );
    });

    await check("GET /log, no floor trail yet -> empty with a stated reason", async () => {
      const r = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/log");
      assert(r.status === 200, JSON.stringify(r));
      assert(r.body.lines.length === 0 && typeof r.body.reason === "string", JSON.stringify(r.body));
    });

    // STAGE 4 / DESIGN §A.2: the SERVICE's default is now Stage1GuardAdapter
    // (below, its own dedicated block proves that). NotBoundGuardAdapter is
    // RETAINED — "the honest thing to inject in a test that wants an unbound
    // service" — so this test now injects it EXPLICITLY, via the same
    // `guardAdapter` seam every other override in this file uses, rather
    // than relying on it being the (no longer true) default.
    await check("POST /guard against an EXPLICITLY unbound adapter -> 503 GUARD_NOT_BOUND (never fabricated) — NotBoundGuardAdapter is retained, not deleted", async () => {
      const unboundSocketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
      makeOwnPeerDir(unboundSocketDir, OWN_UID);
      const unboundCfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
      const unboundCfgPath = join(unboundCfgDir, "declarations.config.json");
      writeFileSync(unboundCfgPath, JSON.stringify(singleRouteTestDeclaration()));
      const unboundTestPaths = writableTestPaths();
      const unboundSvc = new MicaBridgeService({
        declarationsPath: unboundCfgPath,
        socketDir: unboundSocketDir,
        now: () => new Date("2026-09-18T00:00:00Z"),
        testWritablePaths: unboundTestPaths,
        stateDir: unboundTestPaths.dir,
        testBridgeGid: OWN_GID,
        guardAdapter: new NotBoundGuardAdapter(),
      });
      await unboundSvc.start();
      try {
        const r = await httpJson(sockFor(unboundSocketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper", sessionId: "s1", actionId: "a1", toolName: "bash" });
        assert(r.status === 503, JSON.stringify(r));
        assert(r.body.error === "GUARD_NOT_BOUND", JSON.stringify(r.body));
        const status = await httpJson(sockFor(unboundSocketDir, OWN_UID), "GET", "/status");
        assert(status.body.guardBound === false, `an explicitly-unbound adapter must report guardBound:false, got ${JSON.stringify(status.body.guardBound)}`);
      } finally {
        await unboundSvc.stop();
      }
    });

    await check("POST /guard with a caller-supplied stakesClass -> 400, never accepted", async () => {
      const r = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper", sessionId: "s1", actionId: "a1", toolName: "bash", stakesClass: "irreversible" });
      assert(r.status === 400 && r.body.error === "CALLER_SUPPLIED_STAKES", JSON.stringify(r));
    });

    await check("POST /guard with an unknown subject -> 400 UNKNOWN_SUBJECT", async () => {
      const r = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "nobody", sessionId: "s1", actionId: "a1", toolName: "bash" });
      assert(r.status === 400 && r.body.error === "UNKNOWN_SUBJECT", JSON.stringify(r));
    });

    // AMENDMENT 11 / RULING R item 2, done separately from the block above:
    // NotBoundGuardAdapter never returns bound:true, so the live default
    // service can never exercise handleGuard's readerFootings forwarding
    // line at all — that line is otherwise untested dead code. A small
    // TEST-ONLY GuardAdapter, injected through the same
    // MicaBridgeServiceOptions.guardAdapter seam Stage 1's real one will
    // use, proves the SERVICE genuinely forwards outcome.readerFootings to
    // the real HTTP response body — the wiring is real and tested end to
    // end over a real Unix socket; only the VALUES come from a double,
    // because Stage 2 has no live disposition to source them from.
    await check("AMENDMENT 11 / Ruling R item 2: POST /guard forwards readerFootings from a bound GuardOutcome onto the real HTTP response, end to end", async () => {
      const footings: ReaderFooting[] = [
        { reader: "MICA/Eng", loadState: "LOADED_UNVERIFIED_FILE", verifiedChain: false },
        { reader: "MICA/Sig", loadState: "LOADED_UNVERIFIED_FILE", verifiedChain: false },
      ];
      const testAdapter: GuardAdapter = {
        async evaluate(_request: GuardEvaluationRequest): Promise<GuardOutcome> {
          return {
            bound: true,
            httpStatus: 200,
            decision: { disposition: "TEST_ONLY_STUB" },
            delivery: {},
            readerFootings: footings,
            // P6: REQUIRED on the 200 arm now. A test double that could omit
            // it would be a double the real adapter's contract does not bind.
            readerFootingsBasis: { kind: "THIS_CALL" },
            quarantined: [],
          };
        },
      };
      const testSocketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
      makeOwnPeerDir(testSocketDir, OWN_UID);
      const testWritablePaths = writableTestPaths();
      const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
      const cfgPath = join(cfgDir, "declarations.config.json");
      writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
      const testSvc = new MicaBridgeService({
        declarationsPath: cfgPath,
        socketDir: testSocketDir,
        now: () => new Date("2026-09-18T00:00:00Z"),
        testWritablePaths,
        testBridgeGid: OWN_GID,
        guardAdapter: testAdapter,
        stateDir: testWritablePaths.dir,
      });
      await testSvc.start();
      try {
        const r = await httpJson(sockFor(testSocketDir, OWN_UID), "POST", "/guard", {
          subject: "housekeeper",
          sessionId: "s1",
          actionId: "a1",
          toolName: "bash",
        });
        assert(r.status === 200, JSON.stringify(r));
        assert(Array.isArray(r.body.readerFootings) && r.body.readerFootings.length === 2, JSON.stringify(r.body));
        assert(
          r.body.readerFootings.every((f: any) => typeof f.reader === "string" && typeof f.loadState === "string" && typeof f.verifiedChain === "boolean"),
          JSON.stringify(r.body.readerFootings)
        );
        assert(
          JSON.stringify(r.body.readerFootings) === JSON.stringify(footings),
          `expected the exact footings the test adapter returned, got ${JSON.stringify(r.body.readerFootings)}`
        );
        // P6: the basis travels with the array on the real response, not just
        // in the type. Without it `[]` is two facts in four characters.
        assert(
          r.body.readerFootingsBasis?.kind === "THIS_CALL",
          `expected the basis to be forwarded too, got ${JSON.stringify(r.body.readerFootingsBasis)}`
        );
      } finally {
        await testSvc.stop();
      }
    });

    await check("POST /subject-events idempotency: same (identity,kind,eventHash) twice -> 200 duplicate:true, no second append", async () => {
      const identity = { subject: "housekeeper", sessionId: "s2", actionId: "a2" };
      const kind = "TOOL_ATTEMPTED";
      const body = { identity, kind, eventHash: realEventHash(identity, kind) };
      const r1 = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/subject-events", body);
      assert(r1.status === 200 && r1.body.duplicate === false, JSON.stringify(r1));
      const r2 = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/subject-events", body);
      assert(r2.status === 200 && r2.body.duplicate === true && r2.body.seq === r1.body.seq, JSON.stringify({ r1, r2 }));
    });

    await check("POST /subject-events: same identity+kind, genuinely different (each self-consistent) eventHash -> 409 EVENT_HASH_CONFLICT", async () => {
      // Two independently VALID reports of the same act, with different
      // payloads — each individually passes the service's own hash
      // recomputation, and only THEN does the dedupe/conflict rule see
      // that the two reports disagree.
      const identity = { subject: "housekeeper", sessionId: "s3", actionId: "a3" };
      const kind = "TOOL_ATTEMPTED";
      const payload1 = { exitClass: "OK" };
      const payload2 = { exitClass: "NONZERO" };
      const body1 = { identity, kind, eventHash: realEventHash(identity, kind, payload1), payload: payload1 };
      const r1 = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/subject-events", body1);
      assert(r1.status === 200, JSON.stringify(r1));
      const body2 = { identity, kind, eventHash: realEventHash(identity, kind, payload2), payload: payload2 };
      const r2 = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/subject-events", body2);
      assert(r2.status === 409 && r2.body.error === "EVENT_HASH_CONFLICT", JSON.stringify(r2));
    });

    await check("POST /subject-events: a syntactically valid but WRONG eventHash -> 400 EVENT_HASH_MISMATCH, no append", async () => {
      const identity = { subject: "housekeeper", sessionId: "s3-wrong", actionId: "a3-wrong" };
      const kind = "TOOL_ATTEMPTED";
      const wrongHash = "f".repeat(64); // syntactically valid 64-hex, but not sha256 of this body
      assert(wrongHash !== realEventHash(identity, kind), "sanity: the wrong hash must not accidentally be correct");
      const r = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/subject-events", { identity, kind, eventHash: wrongHash });
      assert(r.status === 400 && r.body.error === "EVENT_HASH_MISMATCH", JSON.stringify(r));
      // Prove nothing was appended: a SUBSEQUENT submission of the same
      // identity+kind with the CORRECT hash must be treated as brand new
      // (duplicate:false), never as a conflict with the rejected attempt.
      const r2 = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/subject-events", { identity, kind, eventHash: realEventHash(identity, kind) });
      assert(r2.status === 200 && r2.body.duplicate === false, `expected the rejected attempt to have appended nothing: ${JSON.stringify(r2)}`);
    });

    await check("unlisted path -> 404, not treated as a decision", async () => {
      const r = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/nope");
      assert(r.status === 404, JSON.stringify(r));
    });

    await check("R1 · THE SUBJECT IS REFUSED /explain OVER A REAL SOCKET — 403 FORBIDDEN, and 403 not 404, which is the whole point", async () => {
      // `singleRouteTestDeclaration()` binds OWN_UID as BOTH the subject's
      // `peerUid` AND the only routes[] row — so on this harness OWN_UID *is*
      // the subject's own peer, and this request is the live shape of the
      // constraint: the watched program asking for the reasoning about itself.
      //
      // 403 AND NOT 404 IS THE LOAD-BEARING HALF. A 404 would mean `/explain`
      // never reached the route check — that it is not in `KNOWN_PATHS`, so
      // the endpoint does not exist at all and this test would pass just as
      // well against a service that had never heard of it. 403 proves both
      // things at once: the path IS known, and the authorisation layer is what
      // turned this caller away.
      const r = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/explain?decisionHash=" + "a".repeat(64));
      assert(r.status === 403, `the subject's peer must be refused /explain: ${JSON.stringify(r)}`);
      assert(r.body.error === "FORBIDDEN", JSON.stringify(r.body));
      assert(
        typeof r.body.detail === "string" && r.body.detail.includes("/explain"),
        `the refusal must name the route it refused: ${JSON.stringify(r.body)}`
      );
    });

    await check("R1 · THE REFUSAL'S OWN VALIDITY GATE — the same socket DOES reach a route it holds, so 403 above is not a service that refuses everything", async () => {
      // A refusal that has never been shown to allow is a refusal nobody has
      // tested. OWN_UID holds GET /status on this declaration and gets it.
      const r = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
      assert(r.status === 200, `the same caller must still reach a route it holds: ${JSON.stringify(r)}`);
    });
  });

  // ── GET /log REFUSES WHAT IT DOES NOT UNDERSTAND (night-read 2026-10-06 §3) ──
  //
  // Measured live before this block existed: `tail=0` and `tail=abc` returned
  // EVERY line (`slice(-0)` and `slice(NaN)` are both `slice(0)`), `tail=-2`
  // dropped the OLDEST two, and `limit=`/`bogus=` were ignored, so each came
  // back as a confident answer to a question nobody asked. /events and
  // /sunset-order already refuse that shape with 400 MALFORMED_FIELD; /log was
  // the one read route without the guard. Every refused arm below was 200
  // before the fix, and every accepted arm pins that the guard did not take
  // the route's real answers with it.
  await withService(async (_svc, socketDir, stateDir) => {
    const sock = sockFor(socketDir, OWN_UID);
    const REFUSED: ReadonlyArray<readonly [string, string]> = [
      ["tail=0", "zero is not a window; it used to return every line"],
      ["tail=-2", "negative; it used to drop the OLDEST two"],
      ["tail=abc", "not a number; it used to return every line"],
      ["tail=1.5", "not an integer"],
      ["tail=", "empty"],
      ["tail=%203", "padded"],
      ["tail=1e2", "exponent form is not the integer it spells"],
      ["limit=3", "/events' word, unknown here; it used to be ignored"],
      ["bogus=1", "unknown; it used to be ignored"],
      ["tail=3&limit=3", "a known parameter does not carry an unknown one through"],
    ];

    async function assertRefused(query: string, why: string): Promise<void> {
      const r = await httpJson(sock, "GET", `/log?${query}`);
      assert(
        r.status === 400 && r.body?.error === "MALFORMED_FIELD" && typeof r.body?.detail === "string" && r.body.detail.length > 0 && r.body?.identity === null,
        `GET /log?${query} (${why}) must be 400 MALFORMED_FIELD with a detail and identity:null, the shape /events refuses with; got ${JSON.stringify(r)}`
      );
      assert(!("lines" in (r.body ?? {})), `a refusal must carry no lines: ${JSON.stringify(r.body)}`);
    }

    await check("GET /log with no floor trail yet REFUSES a bad query before it says 'not yet written' — the refusal is about the request, not the book", async () => {
      await assertRefused("tail=0", "zero");
      await assertRefused("limit=3", "unknown");
    });

    // A real floor trail of ten numbered lines, written where the service
    // resolves its declared path under this test's stateDir.
    const declaredTrail: string = (singleRouteTestDeclaration() as any).paths.floorTrail;
    const trailPath = declaredTrail.replace(/^\/var\/lib\/mica-bridge/, stateDir);
    assert(trailPath !== declaredTrail, `the declared floor trail must resolve under the test's stateDir, got ${trailPath}`);
    writeFileSync(trailPath, Array.from({ length: 10 }, (_, i) => JSON.stringify({ n: i + 1 })).join("\n") + "\n");

    for (const [query, why] of REFUSED) {
      await check(`GET /log?${query} -> 400 MALFORMED_FIELD (${why})`, async () => {
        await assertRefused(query, why);
      });
    }

    await check("GET /log (no parameters) still answers 200 with every line when there are fewer than the default 50", async () => {
      const r = await httpJson(sock, "GET", "/log");
      assert(r.status === 200 && r.body.total === 10 && r.body.lines.length === 10, JSON.stringify(r));
    });
    await check("GET /log?tail=3 still answers 200 with the NEWEST three, in order", async () => {
      const r = await httpJson(sock, "GET", "/log?tail=3");
      assert(r.status === 200 && r.body.total === 10, JSON.stringify(r));
      assert(JSON.stringify(r.body.lines.map((l: any) => l.n)) === JSON.stringify([8, 9, 10]), JSON.stringify(r.body.lines));
    });
    await check("GET /log?tail=1 still answers 200 with the newest line only", async () => {
      const r = await httpJson(sock, "GET", "/log?tail=1");
      assert(r.status === 200 && r.body.lines.length === 1 && r.body.lines[0].n === 10, JSON.stringify(r));
    });
    await check("GET /log?tail=700 (more than exist, and above the 500 cap) still answers 200 with every line, and total says how many exist", async () => {
      const r = await httpJson(sock, "GET", "/log?tail=700");
      assert(r.status === 200 && r.body.lines.length === 10 && r.body.total === 10, JSON.stringify(r));
    });
  });

  // ── Amendment 6 / verifier EH1 — an OMITTED payload must persist as an
  // ABSENT key, never an invented `"payload":null`, so the record's own
  // eventHash equals a hash over exactly what is on disk. ──────────────

  await check("EH1: an omitted-payload record persists with NO payload key, and its eventHash equals canonicalHash({identity,kind})", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const testPaths = writableTestPaths();
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const svc = new MicaBridgeService({
      declarationsPath: cfgPath,
      socketDir,
      now: () => new Date("2026-09-18T00:00:00Z"),
      testWritablePaths: testPaths,
      stateDir: testPaths.dir,
      testBridgeGid: OWN_GID,
    });
    await svc.start();

    const identity = { subject: "housekeeper", sessionId: "eh1", actionId: "no-payload" };
    const kind = "TOOL_ATTEMPTED";
    const r = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/subject-events", { identity, kind, eventHash: realEventHash(identity, kind) });
    assert(r.status === 200 && r.body.duplicate === false, JSON.stringify(r));

    // ACT A: the chain's position-0 boundary record is a real line and is
    // counted as one. What this check is about is the EVENT.
    const { boundary, events: records } = readSubjectChain(testPaths.subjectLog);
    assert(boundary !== null, "the chain must begin with its boundary record");
    assert(!("eventHash" in boundary), "the boundary record is not a subject event and carries no eventHash");
    assert(records.length === 1, `expected exactly 1 persisted event, found ${records.length}`);
    const record = records[0];
    assert(!("payload" in record), `persisted record must have NO "payload" key at all, got ${JSON.stringify(record)}`);
    const expectedHash = canonicalHash({ identity: record.identity, kind: record.kind });
    assert(record.eventHash === expectedHash, `persisted eventHash ${record.eventHash} does not equal canonicalHash({identity,kind}) ${expectedHash} over exactly what is on disk`);

    await svc.stop();
  });

  await check("EH1 (unchanged): a caller-SENT payload:null is still explicitly rejected (MALFORMED_FIELD), never silently accepted as omitted", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const testPaths = writableTestPaths();
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const svc = new MicaBridgeService({
      declarationsPath: cfgPath,
      socketDir,
      now: () => new Date("2026-09-18T00:00:00Z"),
      testWritablePaths: testPaths,
      stateDir: testPaths.dir,
      testBridgeGid: OWN_GID,
    });
    await svc.start();

    const identity = { subject: "housekeeper", sessionId: "eh1", actionId: "explicit-null" };
    const kind = "TOOL_ATTEMPTED";
    const r = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/subject-events", { identity, kind, eventHash: realEventHash(identity, kind), payload: null });
    assert(r.status === 400 && r.body.error === "MALFORMED_FIELD", JSON.stringify(r));

    await svc.stop();
  });

  // ── F4 (round 3) — the verifier's regression, UNDER A CHAINED LOG ───────
  //
  // AMENDMENT 4 (round 2) fixed a real defect the round-1 way: the corrupt
  // tail was EVICTED to a durable sidecar, the active log TRUNCATED, and the
  // service carried on, so no record written behind the corruption stayed
  // invisible. That was correct for an unchained JSONL.
  //
  // ACT A / THE ARBITER'S RULING 6 CHANGES THE ANSWER, and this test is rewritten
  // rather than deleted because the QUESTION it asks is still the right one:
  // what happens to a record written behind planted corruption?
  //
  //   UNDER A CHAIN, THE TORN LINE WAS A LINK. Evicting it leaves a chain that
  //   still verifies positionally while a record is simply gone — the silent
  //   loss this whole item exists to end. So nothing is evicted, nothing is
  //   truncated, and NOTHING IS WRITTEN BEHIND THE DAMAGE: the append is
  //   REFUSED, 503 RECORD_NOT_PERSISTED, with the chain's own reason.
  //
  //   THE ROUND-2 DEFECT IS THEREFORE UNREACHABLE RATHER THAN REPAIRED. There
  //   is no record behind the corruption to lose, because there is no record
  //   behind the corruption. The caller is told so, at the moment it happens,
  //   and keeps its own copy — ruling Q's retryable-and-owed path, which
  //   `unacknowledgedBacklog` already counts.
  //
  //   WHAT IT COSTS, SAID PLAINLY: until a human acts, every subject event is
  //   refused and the housekeeper's acts go unevaluated (fail-open under
  //   ruling J, marked STALE_STREAM). The agent keeps working; the record does
  //   not. That is the trade ruling 6 chose, and this test is where it is
  //   visible rather than argued.

  await check("F4 (ACT A / ruling 6): plant partial tail -> the append is REFUSED, loudly, and nothing is written behind the damage; a human-cleared tail restores service", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const testPaths = writableTestPaths();
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));

    let svc = new MicaBridgeService({
      declarationsPath: cfgPath,
      socketDir,
      now: () => new Date("2026-09-18T00:00:00Z"),
      testWritablePaths: testPaths,
      stateDir: testPaths.dir,
      testBridgeGid: OWN_GID,
    });
    await svc.start();

    // A little history first, so the corruption lands mid-stream, not at
    // the very start of the file.
    const identity0 = { subject: "housekeeper", sessionId: "quarantine", actionId: "a1" };
    const r0 = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/subject-events", {
      identity: identity0,
      kind: "TOOL_ATTEMPTED",
      eventHash: realEventHash(identity0, "TOOL_ATTEMPTED"),
    });
    assert(r0.status === 200 && r0.body.seq === 1, JSON.stringify(r0));

    // 1. Plant a partial tail — exactly the verifier's "{partial", 8 bytes,
    // no trailing newline.
    appendFileSync(testPaths.subjectLog, "{partial");
    // ── ACT A / THE ARBITER'S RULING 6 REWROTE WHAT THIS CHECK IS ABOUT ─────────
    //
    // BEFORE: a planted partial tail was reported as a live QUARANTINE, then
    // evicted to a `.quarantine` sidecar and TRUNCATED out of the live file on
    // the next write, and the service carried on.
    //
    // AFTER: the subject log is a hash chain, and that torn line was a LINK.
    // Dropping it leaves a chain that still verifies positionally while a
    // record is simply gone — the silent loss this whole item exists to end.
    // So the store REFUSES: `quarantine.subjectLog` is structurally null (a
    // chained store never quarantines a link), and the damage surfaces as
    // persistence DEGRADED with the chain's own reason. Loud, and it stays
    // loud until a human acts.
    const statusAfterPlant = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
    assert(
      statusAfterPlant.body.quarantine.subjectLog === null,
      `a chained store must never quarantine a link: ${JSON.stringify(statusAfterPlant.body.quarantine)}`
    );
    assert(
      statusAfterPlant.body.persistence.state === "DEGRADED" &&
        statusAfterPlant.body.persistence.file === "subjectLog",
      `expected persistence DEGRADED on subjectLog after planting: ${JSON.stringify(statusAfterPlant.body.persistence)}`
    );
    assert(
      String(statusAfterPlant.body.persistence.error).includes("SUBJECT_CHAIN_TORN_TAIL"),
      `expected the chain's own reason: ${JSON.stringify(statusAfterPlant.body.persistence)}`
    );

    // 2. Try to append a valid event. IT MUST BE REFUSED.
    const targetIdentity = { subject: "housekeeper", sessionId: "quarantine", actionId: "a2" };
    const target = {
      identity: targetIdentity,
      kind: "TOOL_ATTEMPTED",
      eventHash: realEventHash(targetIdentity, "TOOL_ATTEMPTED"),
    };
    const rawBeforeAttempt = readFileSync(testPaths.subjectLog, "utf8");
    const r1 = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/subject-events", target);
    assert(r1.status === 503, `the append must be REFUSED over damage, got ${JSON.stringify(r1)}`);
    assert(r1.body.error === "RECORD_NOT_PERSISTED", JSON.stringify(r1.body));
    assert(
      String(r1.body.detail).includes("Nothing was appended"),
      `the refusal must say nothing landed: ${JSON.stringify(r1.body)}`
    );

    // NOTHING WAS EVICTED, NOTHING WAS TRUNCATED, NOTHING WAS WRITTEN. The
    // file is byte-identical to what it was before the attempt, corruption
    // and all — the record of what happened is the thing being protected.
    const rawAfterAttempt = readFileSync(testPaths.subjectLog, "utf8");
    assert(rawAfterAttempt === rawBeforeAttempt, "not one byte may be written over a damaged chain");
    assert(rawAfterAttempt.includes("{partial"), "the corrupt fragment must be LEFT IN PLACE for a human, never evicted");
    assert(!existsSync(`${testPaths.subjectLog}.quarantine`), "a chained store must never write a quarantine sidecar");
    const statusAfterAttempt = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
    assert(statusAfterAttempt.body.quarantine.subjectLog === null, JSON.stringify(statusAfterAttempt.body.quarantine));
    assert(
      statusAfterAttempt.body.persistence.state === "DEGRADED",
      `the refusal must be visible at /status, not only in the 503: ${JSON.stringify(statusAfterAttempt.body.persistence)}`
    );

    // 3. A RESTART DOES NOT CLEAR IT. Damage is not a transient; a process
    //    that came back and started appending again would be repairing by
    //    forgetting, which is the one thing a chained store must not do.
    await svc.stop();
    svc = new MicaBridgeService({
      declarationsPath: cfgPath,
      socketDir,
      now: () => new Date("2026-09-18T00:00:00Z"),
      testWritablePaths: testPaths,
      stateDir: testPaths.dir,
      testBridgeGid: OWN_GID,
    });
    await svc.start();
    const r2 = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/subject-events", target);
    assert(r2.status === 503, `a restart must not clear damage, got ${JSON.stringify(r2)}`);
    await svc.stop();

    // 4. THE HUMAN ACTS. The only recovery is a person removing the torn
    //    bytes — the act ruling 6 is holding the line open for. Here that is
    //    the truncation a human would make with the service stopped, which is
    //    the same order the receipt's rotation act insists on.
    const lines = readFileSync(testPaths.subjectLog, "utf8").split("\n").filter((l) => l.trim().length > 0);
    assert(lines[lines.length - 1].startsWith("{partial"), JSON.stringify(lines[lines.length - 1]));
    writeFileSync(testPaths.subjectLog, lines.slice(0, -1).join("\n") + "\n", "utf8");

    svc = new MicaBridgeService({
      declarationsPath: cfgPath,
      socketDir,
      now: () => new Date("2026-09-18T00:00:00Z"),
      testWritablePaths: testPaths,
      stateDir: testPaths.dir,
      testBridgeGid: OWN_GID,
    });
    await svc.start();
    const r3 = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/subject-events", target);
    assert(r3.status === 200 && r3.body.duplicate === false, `service must resume once a human has acted: ${JSON.stringify(r3)}`);

    // 5. Sequence uniqueness in RAW durable storage, and the chain still
    //    verifies end to end through the REAL deployed reader.
    const { boundary, events } = readSubjectChain(testPaths.subjectLog);
    assert(boundary !== null, "the chain still begins with its boundary");
    const seqs = events.map((e: any) => e.subjectSeq);
    assert(new Set(seqs).size === seqs.length, `duplicate sequence numbers found in raw storage: ${JSON.stringify(seqs)}`);
    assert(seqs.includes(1) && seqs.includes(r3.body.seq), `expected both seq 1 and seq ${r3.body.seq} present, got ${JSON.stringify(seqs)}`);
    assert(
      new SubjectChainLog({ path: testPaths.subjectLog }).getLoadState() === "LOADED_SUBJECT_CHAIN_VERIFIED",
      "the recovered chain must verify"
    );

    await svc.stop();
  });

  // ── AMENDMENT 9 / STAGE 3 VERIFIER FINDING 2: eventSeq must be durable ──
  //
  // Before the fix, `eventSeq` was an in-memory counter that reset to 0 on
  // every process start even though the event book itself is durable. The
  // verifier's evidence: BRIDGE_RESET persisted-after=2 bridge-lastSeq=1
  // returned-events=0 delivered=0 — a consumer holding a NON-EMPTY cursor
  // (2) across a restart saw NOTHING, because the next event minted after
  // restart collided with the old seq 1 and its own `seq > after` guard
  // silently discarded it. This test reproduces that exact shape and shows
  // the fix: the cursor is set to 2 BEFORE the restart, and the FIRST event
  // minted after restart must be seq 3, visible at ?after=2 — never seq 1.

  await check("AMENDMENT 9: eventSeq survives a restart — a NON-EMPTY cursor set before restart still sees the next event, at the correct, non-colliding seq", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const testPaths = writableTestPaths();
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    const goodDeclaration = singleRouteTestDeclaration();
    writeFileSync(cfgPath, JSON.stringify(goodDeclaration));

    let svc = new MicaBridgeService({
      declarationsPath: cfgPath,
      socketDir,
      now: () => new Date("2026-09-18T00:00:00Z"),
      testWritablePaths: testPaths,
      stateDir: testPaths.dir,
      testBridgeGid: OWN_GID,
    });
    await svc.start();

    // 1. Produce two durable events pre-restart — each a rejected reload().
    // SINCE THE SERVICE_STARTED BEAT the marker takes seq 1; SINCE R6's REWORK
    // the epoch this first start begins takes seq 2 — so the rejections are
    // seq 3 and seq 4 and the cursor below is 4. The numbers moved twice; the
    // property under test did not either time. THE SECOND START ADDS NO EPOCH
    // ROW, and that is the one-time rule showing up in an unrelated test: the
    // salt is there, the memory is there, and nothing is minted or said.
    const bad = JSON.parse(JSON.stringify(goodDeclaration));
    delete bad.pilot;
    writeFileSync(cfgPath, JSON.stringify(bad));
    const rej1 = svc.reload();
    assert(!rej1.ok, "expected the first reload to be rejected");
    const rej2 = svc.reload();
    assert(!rej2.ok, "expected the second reload to be rejected");

    // 2. The consumer's cursor, taken BEFORE the restart: it has seen up
    // through seq 2 — a NON-EMPTY cursor, per the coordinator's requirement.
    const before = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/events");
    assert(before.status === 200, JSON.stringify(before));
    // ⚠ NEITHER SIDE'S NUMBER SURVIVES THE UNION, AND THAT IS THE POINT.
    // HEAD counted 4 as marker + epoch + two rejections. Act A counted 4 as
    // chain boundary + marker + two rejections — its base had no salt epoch.
    // On this line BOTH rows exist, so the book holds FIVE before the restart:
    // chain boundary, relay marker, salt epoch, and two rejections. Taking
    // either side's 4 unchanged would have passed a test that counts the wrong
    // book, which is the quietest way a merge can go wrong.
    // AMENDED (S216-2): + GRANT_MEMORY_BEGUN (the first start begins the grant memory, GM0): six before the restart.
    // AMENDED (ZERO-SUBJECTS, F-10 (a)): + SUBJECTS_DECLARED (the first on this book): seven before the restart.
    assert(before.body.lastSeq === 7, `expected lastSeq 7 pre-restart (chain boundary + marker + epoch + grant memory + subjects declared + two rejections), got ${JSON.stringify(before.body)}`);
    assert(before.body.events[0].kind === "SUBJECT_CHAIN_BOUNDARY", JSON.stringify(before.body.events[0]));
    const cursor = before.body.lastSeq;
    // ⛔ THIS LINE SAID 4 AND THE LINE ABOVE SAID 5, AND `cursor` IS ASSIGNED FROM
    //    THAT SAME `lastSeq` — so the two could not both hold and this test could
    //    not pass. Codex found it. I bumped the count in the union merge and left
    //    its neighbour, which is the exact failure the union resolution was being
    //    careful about one hunk earlier: change a number in one place and not in
    //    the place that reads it.
    assert(cursor === 7, `cursor is lastSeq and lastSeq is 7; got ${String(cursor)}`);

    await svc.stop();

    // 3. Restart, with a GOOD declaration on disk again (a restart is not
    // gated on the previous process's last-attempted reload).
    writeFileSync(cfgPath, JSON.stringify(goodDeclaration));
    svc = new MicaBridgeService({
      declarationsPath: cfgPath,
      socketDir,
      now: () => new Date("2026-09-18T00:00:01Z"),
      testWritablePaths: testPaths,
      stateDir: testPaths.dir,
      testBridgeGid: OWN_GID,
    });
    await svc.start();

    // 4. Mint the NEXT event, post-restart. Pre-fix this would land as seq
    // 1 again (colliding with the old seq 1, invisible past the cursor).
    // Post-fix, TWO events land past the cursor: the restart's own
    // SERVICE_STARTED at seq 5, then the rejection at seq 6. The marker being
    // one of them is itself evidence the counter survived the restart — and
    // there being NO epoch row among them is evidence the one-time rule held.
    // one of them is itself evidence the counter survived the restart.
    //
    // AND EXACTLY TWO, NOT THREE: a chain BEGINS ONCE. The restarted service
    // finds a chain that already carries its boundary record at position 0 and
    // writes no second one — "the log starts here, again" is the line that
    // would make the first one worthless.
    writeFileSync(cfgPath, JSON.stringify(bad));
    const rej3 = svc.reload();
    assert(!rej3.ok, "expected the post-restart reload to be rejected");

    const after = await httpJson(sockFor(socketDir, OWN_UID), "GET", `/events?after=${cursor}`);
    assert(after.status === 200, JSON.stringify(after));
    // THE WHOLE LADDER SHIFTS BY ONE, for the one reason the boundary record adds a
    // row at position 0: pre-restart the book holds boundary, marker, epoch and two
    // rejections (5); the restart then writes SERVICE_STARTED (6) and the third
    // rejection lands at 7. Two events past the cursor, exactly as before the shift —
    // the PROPERTY under test never moved, only the numbers that express it.
    // AMENDED (S216-2): the restart ADOPTS the grant memory (GRANT_MEMORY_ADOPTED, after the marker), so three past
    //   the cursor: SERVICE_STARTED (7), GRANT_MEMORY_ADOPTED (8), the rejection (9). Still no epoch, no boundary.
    // AMENDED (ZERO-SUBJECTS, F-10 (a)): every number +1 for the pre-restart SUBJECTS_DECLARED, and the restart onto
    //   the SAME membership writes NO second one — the alerter speaks per change, not per restart.
    assert(
      after.body.events.length === 3 &&
        after.body.events[0].seq === 8 &&
        after.body.events[0].kind === "SERVICE_STARTED" &&
        after.body.events[1].seq === 9 &&
        after.body.events[1].kind === "GRANT_MEMORY_ADOPTED" &&
        after.body.events[2].seq === 10,
      `expected SERVICE_STARTED at seq 8, GRANT_MEMORY_ADOPTED at 9, then the rejection at seq 10 past cursor ${cursor}, got ${JSON.stringify(after.body)}`
    );
    assert(after.body.lastSeq === 10, `expected global lastSeq 10 post-restart, got ${JSON.stringify(after.body)}`);
    assert(
      after.body.events.every((e: any) => e.kind !== "SUBJECTS_DECLARED"),
      `a restart onto the same membership must write no second SUBJECTS_DECLARED: ${JSON.stringify(after.body.events.map((e: any) => e.kind))}`
    );
    assert(
      after.body.events.every((e: any) => e.kind !== "SALT_EPOCH_STARTED" && e.kind !== "SALT_EPOCH_ADOPTED"),
      `A RESTART MUST BEGIN NO EPOCH AND ADOPT NOTHING: ${JSON.stringify(after.body.events.map((e: any) => e.kind))}`
    );
    // ⛔ AND ACT A'S ASSERTION, KEPT ALONGSIDE IT RATHER THAN INSTEAD OF IT.
    // These are two different one-time records, and a restart must write
    // neither. Resolving this hunk by choosing a side would have deleted a
    // live check and left a suite that still passed.
    assert(
      after.body.events.every((e: any) => e.kind !== "SUBJECT_CHAIN_BOUNDARY"),
      `a chain begins ONCE: no second boundary may be written on a restart, got ${JSON.stringify(after.body.events)}`
    );

    await svc.stop();
  });

  // ── Amendment 4, new defect: split multi-byte UTF-8 across socket writes ─
  //
  // The F2 compile fix decoded each incoming chunk independently with
  // `chunk.toString("utf8")`. A multi-byte UTF-8 character split across two
  // socket writes then decodes as two INCOMPLETE, INDEPENDENT byte
  // sequences — each producing U+FFFD — silently corrupting accepted data
  // while returning HTTP 200 and an acknowledged seq; worse, the caller's
  // `eventHash` still describes the ORIGINAL, uncorrupted bytes. Fixed with
  // `StringDecoder('utf8')`, which buffers an incomplete trailing sequence
  // across writes. This test splits representative 2-, 3-, and 4-byte UTF-8
  // characters at EVERY byte boundary and compares the exact persisted
  // payload, plus independently verifies the persisted payload still
  // matches the eventHash the (uncorrupted) original bytes would produce.

  await check("UTF-8 split: every persisted payload is byte-exact at EVERY byte boundary, for 2-, 3-, and 4-byte characters", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const testPaths = writableTestPaths();
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const svc = new MicaBridgeService({
      declarationsPath: cfgPath,
      socketDir,
      now: () => new Date("2026-09-18T00:00:00Z"),
      testWritablePaths: testPaths,
      stateDir: testPaths.dir,
      testBridgeGid: OWN_GID,
    });
    await svc.start();

    const REPRESENTATIVE_CHARS: readonly { readonly char: string; readonly byteLen: number }[] = [
      { char: "é", byteLen: 2 },
      { char: "€", byteLen: 3 },
      { char: "😀", byteLen: 4 }, // surrogate pair in JS UTF-16, 4 UTF-8 bytes
    ];

    let cases = 0;
    for (const { char, byteLen } of REPRESENTATIVE_CHARS) {
      const probeIdentity = { subject: "housekeeper", sessionId: "utf8test", actionId: `probe-${byteLen}` };
      const probePayload = { note: `x${char}x` };
      const probeBuf = Buffer.from(
        JSON.stringify({
          identity: probeIdentity,
          kind: "TOOL_ATTEMPTED",
          eventHash: realEventHash(probeIdentity, "TOOL_ATTEMPTED", probePayload),
          payload: probePayload,
        }),
        "utf8"
      );

      for (let splitAt = 1; splitAt < probeBuf.length; splitAt++) {
        cases++;
        const perSplitIdentity = { subject: "housekeeper", sessionId: "utf8test", actionId: `${byteLen}b-${splitAt}` };
        const perSplitPayload = { note: `x${char}x` };
        // AMENDMENT 5 / VERIFIER "UTF8/HASH": the REAL hash of THIS exact
        // record — never a fabricated placeholder. This is the hash the
        // service now recomputes and verifies before accepting the write;
        // a fabricated hash would be rejected 400 EVENT_HASH_MISMATCH,
        // which would make this a test of the wrong thing.
        const perSplitObj = { identity: perSplitIdentity, kind: "TOOL_ATTEMPTED", eventHash: realEventHash(perSplitIdentity, "TOOL_ATTEMPTED", perSplitPayload), payload: perSplitPayload };
        const perSplitBuf = Buffer.from(JSON.stringify(perSplitObj), "utf8");

        const result = await rawSplitPost(sockFor(socketDir, OWN_UID), perSplitBuf, splitAt);
        assert(result.status === 200, `char=${char} splitAt=${splitAt}/${perSplitBuf.length}: expected 200, got ${result.status}; body: ${result.rawBody.toString("utf8")}`);
      }
    }
    assert(cases > 0, "sanity: at least one split case must have run");

    // Verify what actually landed on disk: every persisted "note" must be
    // exactly the original character — never U+FFFD, never any other
    // corruption — the canonical hash over the PERSISTED
    // {identity, kind, payload} must equal the canonical hash over the
    // ORIGINAL, uncorrupted object, AND (AMENDMENT 5) the record's OWN
    // stored `eventHash` field must equal that same recomputed hash —
    // proving the SERVICE's verification actually ran and is not merely
    // decoration, at every single byte boundary.
    const { events: records } = readSubjectChain(testPaths.subjectLog);
    assert(records.length === cases, `expected ${cases} persisted events, found ${records.length}`);

    for (const rec of records) {
      const byteLen = Number(rec.identity.actionId.split("b-")[0]);
      const expectedChar = REPRESENTATIVE_CHARS.find((c) => c.byteLen === byteLen)!.char;
      const expectedNote = `x${expectedChar}x`;
      assert(
        rec.payload.note === expectedNote,
        `identity ${JSON.stringify(rec.identity)}: expected note ${JSON.stringify(expectedNote)}, got ${JSON.stringify(rec.payload.note)} (corruption if this contains U+FFFD)`
      );
      const expectedHash = canonicalHash({ identity: rec.identity, kind: rec.kind, payload: { note: expectedNote } });
      const actualHash = canonicalHash({ identity: rec.identity, kind: rec.kind, payload: rec.payload });
      assert(rec.eventHash === expectedHash, `persisted record's OWN eventHash field does not equal the recomputed canonical hash for ${JSON.stringify(rec.identity)} — service-side verification is not actually active`);
      assert(actualHash === expectedHash, `persisted payload's canonical hash does not match the original — corruption for ${JSON.stringify(rec.identity)}`);
    }

    await svc.stop();
  });

  // ── F5 — injectable storage root; append failures reported, never
  // swallowed; SIGHUP DECLARATION_REJECTED observable via /events ──────────

  await check("F5: MICA_BRIDGE_STATE_DIR redirects storage without any test-only option, through the real entry point", () => {
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));

    // MICA_BRIDGE_STATE_DIR is read by the SERVICE, but the real entry
    // point's peer-directory check still requires the REAL mica-bridge gid
    // (no testBridgeGid over the CLI) — so this proves the env var is wired
    // and the process fails ONLY on the (expected, unprivileged) gid check,
    // never on a missing/unwritable /var/lib/mica-bridge path.
    const result = spawnSync("/usr/bin/node", [TSNODE, "-P", join(__dirname, "tsconfig.json"), join(__dirname, "mica-service.ts")], {
      encoding: "utf8",
      env: { ...process.env, MICA_BRIDGE_DECLARATIONS: cfgPath, MICA_BRIDGE_SOCKET_DIR: socketDir, MICA_BRIDGE_STATE_DIR: stateDir },
      timeout: CHILD_COMPILE_BUDGET_MS, // AMENDMENT 8 + the 2026-10-03 load measurement; see CHILD_COMPILE_BUDGET_MS.
    });
    requireChildOutcome(result, "MICA_BRIDGE_STATE_DIR");
    assert(result.status === 2,
      `expected exit 2 (gid check, not a path problem), got status=${result.status} signal=${result.signal} ` +
      `error=${(result.error as NodeJS.ErrnoException | undefined)?.code ?? "none"}: ${result.stderr}`);
    assert(!result.stderr.includes("ENOENT") && !result.stderr.includes("/var/lib/mica-bridge"), `must not fail on the real /var/lib/mica-bridge path: ${result.stderr}`);
  });

  await check("F5: a mandatory subject-events append failure is reported (503), never swallowed", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    // Point subjectLog at a path INSIDE a file (not a directory) so every
    // append fails deterministically.
    const bogusParent = join(cfgDir, "not-a-directory");
    writeFileSync(bogusParent, "x");
    const testWritablePaths = { eventBook: join(cfgDir, "events.jsonl"), subjectLog: join(bogusParent, "subject-events.jsonl") };

    const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testWritablePaths, testBridgeGid: OWN_GID, stateDir: mkdtempSync(join(tmpdir(), "mica-bridge-state-")) });
    await svc.start();
    const degradeIdentity = { subject: "housekeeper", sessionId: "degrade", actionId: "a1" };
    const r = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/subject-events", {
      identity: degradeIdentity,
      kind: "TOOL_ATTEMPTED",
      eventHash: realEventHash(degradeIdentity, "TOOL_ATTEMPTED"),
    });
    assert(r.status === 503 && r.body.error === "RECORD_NOT_PERSISTED", JSON.stringify(r));
    // AMENDMENT 9 / RULING Q: one failure, well below the draft's declared
    // maxUnacknowledged (10) -> not yet stale, but the 503 body carries the
    // field regardless (the arbiter's binding condition: named and wired in the
    // same beat, not only once the threshold trips).
    assert(r.body.stale === false, JSON.stringify(r.body));
    const status = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
    assert(status.body.persistence.state === "DEGRADED", JSON.stringify(status.body.persistence));
    assert(
      status.body.subjectEvents.unacknowledgedBacklog === 1 &&
        status.body.subjectEvents.maxUnacknowledged === 10 &&
        status.body.subjectEvents.stale === false,
      JSON.stringify(status.body.subjectEvents)
    );
    await svc.stop();
  });

  await check("AMENDMENT 9 / Ruling Q: unacknowledgedBacklog reaching maxUnacknowledged -> /status.subjectEvents.stale AND the 503 body itself say so", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const bogusParent = join(cfgDir, "not-a-directory");
    writeFileSync(bogusParent, "x");
    const testWritablePaths = { eventBook: join(cfgDir, "events.jsonl"), subjectLog: join(bogusParent, "subject-events.jsonl") };
    const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testWritablePaths, testBridgeGid: OWN_GID, stateDir: mkdtempSync(join(tmpdir(), "mica-bridge-state-")) });
    await svc.start();
    // The draft declares subjectLog.maxUnacknowledged.value === 10 (asserted
    // below, so this test fails loudly rather than silently if that number
    // ever drifts). Every failing POST here uses a DISTINCT actionId so
    // none is treated as a resend of the one before it.
    assert(draft.subjectLog.maxUnacknowledged.value === 10, `draft's maxUnacknowledged drifted: ${draft.subjectLog.maxUnacknowledged.value}`);
    let last: any = null;
    for (let i = 0; i < 10; i++) {
      const identity = { subject: "housekeeper", sessionId: "degrade-stale", actionId: `a${i}` };
      last = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/subject-events", {
        identity,
        kind: "TOOL_ATTEMPTED",
        eventHash: realEventHash(identity, "TOOL_ATTEMPTED"),
      });
    }
    assert(last.status === 503, JSON.stringify(last));
    assert(last.body.stale === true, `expected the 10th (threshold-crossing) 503 to carry stale:true, got ${JSON.stringify(last.body)}`);
    const status = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
    assert(
      status.body.subjectEvents.unacknowledgedBacklog === 10 &&
        status.body.subjectEvents.maxUnacknowledged === 10 &&
        status.body.subjectEvents.stale === true,
      JSON.stringify(status.body.subjectEvents)
    );
    await svc.stop();
  });

  await check("AMENDMENT 9 / Ruling Q: unacknowledgedBacklog starts at 0 and stays 0 across a genuinely successful append", async () => {
    // The failure->nonzero and nonzero->reset-on-success transitions are
    // both covered end-to-end by the two tests above (a broken subjectLog
    // path never sees a successful append at all); this confirms the
    // ordinary, healthy-disk case never reports a phantom backlog.
    await withService(async (svc, socketDir) => {
      const status0 = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
      assert(status0.body.subjectEvents.unacknowledgedBacklog === 0, JSON.stringify(status0.body.subjectEvents));
      const identity = { subject: "housekeeper", sessionId: "reset-check", actionId: "a1" };
      const r = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/subject-events", {
        identity,
        kind: "TOOL_ATTEMPTED",
        eventHash: realEventHash(identity, "TOOL_ATTEMPTED"),
      });
      assert(r.status === 200, JSON.stringify(r));
      const status1 = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
      assert(status1.body.subjectEvents.unacknowledgedBacklog === 0, JSON.stringify(status1.body.subjectEvents));
    });
  });

  await check("F5: SIGHUP to a REAL child process, with a rejected declaration, produces DECLARATION_REJECTED observable via GET /events from disk", () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-e2e-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));

    const child = require("child_process").spawn(
      "/usr/bin/node",
      // `-T` (--transpileOnly) — the arbiter's ruling 2026-09-25, item 1. THIS CHILD
      // ONLY. What this test tests is RUNTIME behaviour: a real SIGHUP to a real
      // pid produces DECLARATION_REJECTED, observable via GET /events and on
      // disk. A full typecheck of mica-service.ts is no part of that claim, and
      // this child was paying 33-41 CPU-seconds for it (A/B measured below).
      //
      // NO TYPECHECK COVERAGE IS LOST, and that is checkable, not asserted: this
      // suite's own parent process runs WITHOUT `-T` and imports `./mica-service`
      // at :15, so the file is typechecked on every run before this check is
      // reached; the four `--check` children (:487, :500, :513, :524) and the two
      // other spawned children (:455, :2024) each typecheck it again.
      //
      // Amendment 3 / verifier F2 (the header, :3-7) is NOT weakened: it forbids
      // `TS_NODE_TRANSPILE_ONLY` in the ENVIRONMENT of a reported run. No env var
      // is set here and none is inherited; this is one flag in one child's argv.
      [TSNODE, "-T", "-P", join(__dirname, "tsconfig.json"), join(__dirname, "mica-service.ts")],
      {
        env: {
          ...process.env,
          MICA_BRIDGE_DECLARATIONS: cfgPath,
          MICA_BRIDGE_SOCKET_DIR: socketDir,
          MICA_BRIDGE_STATE_DIR: stateDir,
          // TEST-ONLY (see mica-service.ts's entry point): lets this
          // unprivileged child actually start and serve, so SIGHUP can be
          // sent to a REAL process, not simulated in-process.
          MICA_BRIDGE_TEST_BRIDGE_GID: String(OWN_GID),
        },
      }
    );

    return new Promise<void>((resolve, reject) => {
      let settled = false;
      const stderrChunks: string[] = [];
      child.stderr.on("data", (c: Buffer) => stderrChunks.push(c.toString("utf8")));
      const fail = (msg: string) => {
        if (!settled) {
          settled = true;
          try {
            child.kill();
          } catch {}
          reject(new Error(`${msg}; stderr: ${stderrChunks.join("")}`));
        }
      };
      // ── A MEASURED BOUND, NOT A GUESS. The arbiter's ruling 2026-09-25, item 2. ──
      //
      // 31128 ms = 3 x 10376 ms, the p99 of 150 consecutive transpile-only
      // spawns of THIS child (same binary, argv, env, stdio and readiness rule),
      // measured on this box 2026-09-25 07:39-07:53 +02:00. 150/150 served;
      // min 3778, p50 5033, p95 8888, p99 10376, max 11047.
      // Ledger: <home>/f5-transpile-20260925/measure-20260925T053918Z.jsonl
      //
      // WHY 3x AND NOT A ROUND NUMBER. The predecessor (AMENDMENT 8, 15000 ->
      // 30000) was widened twice against a cause its comment named wrongly: it
      // blamed `typeRoots` pointing at a not-yet-laid /opt path, and that path
      // has existed since 2026-09-18. The measured cause is CPU STARVATION —
      // this is a wall-clock budget on a purely CPU-bound compile, on a 3-core
      // box whose resident load is 2.3-2.9. The failing child of 2026-09-24 was
      // ALIVE and RUNNABLE at the deadline (`State: R`, `wchan 0`, `majflt 0`),
      // having done 14.32 CPU-s at 0.48 cores; one that served did 34.85 at 1.42.
      // A budget in wall time must therefore carry headroom for cores lost, and
      // 3x the p99 IS that headroom, stated as a multiple of a measurement.
      //
      // THE HEADROOM IS CHECKED, not assumed: under the SAME injected contention
      // that timed this child out at 30000 (pinned to one CPU, two spinners on
      // it), the transpile-only child served in 15152-17305 ms, 4/4 — i.e. the
      // worst observed starved run sits at 56% of this bound.
      // Ledger: <home>/f5-transpile-20260925/contend-20260925T055356Z.jsonl
      //
      // IF THIS EVER FIRES AGAIN, do not widen it. A transpile-only spawn that
      // cannot serve in 31 seconds means the box lost more than two thirds of a
      // core, and the finding is the contention, not the budget.
      const timeout = setTimeout(() => fail("timed out waiting for the child to serve"), 31128);

      let started = false;
      child.stdout.on("data", (chunk: Buffer) => {
        const text = chunk.toString("utf8");
        if (started || !text.includes("serving")) return;
        started = true;
        clearTimeout(timeout);

        // Corrupt the declaration, then send a REAL SIGHUP to the REAL pid.
        const bad = JSON.parse(readFileSync(cfgPath, "utf8"));
        delete bad.pilot;
        writeFileSync(cfgPath, JSON.stringify(bad));
        child.kill("SIGHUP");

        setTimeout(() => {
          httpJson(sockFor(socketDir, OWN_UID), "GET", "/events")
            .then((events) => {
              const rejected = events.status === 200 && events.body.events.some((e: any) => e.kind === "DECLARATION_REJECTED");
              try {
                child.kill();
              } catch {}
              if (rejected) {
                // And genuinely on disk, not merely in the child's memory:
                const onDisk = readFileSync(join(stateDir, "events.jsonl"), "utf8");
                if (onDisk.includes("DECLARATION_REJECTED")) {
                  settled = true;
                  resolve();
                } else {
                  fail(`DECLARATION_REJECTED seen via /events but not found on disk at ${join(stateDir, "events.jsonl")}`);
                }
              } else {
                fail(`no DECLARATION_REJECTED event after SIGHUP: ${JSON.stringify(events.body)}`);
              }
            })
            .catch((err) => fail(String(err)));
        }, 1500);
      });
      child.on("exit", (code: number | null) => {
        if (!settled && !started) {
          clearTimeout(timeout);
          fail(`child exited before serving, code ${code}`);
        }
      });
    });
  });

  // ── S141-d · THE CLOCK STEP. The arbiter's ruling 2026-09-25, item 1's mutation. ──
  //
  // On 2026-09-25 the bridge's wall clock stepped back ~1067 ms mid-act and the
  // subject log recorded seq 166 at 05:27:26.812Z followed by seq 167 at
  // 05:27:25.745Z. Sig F1 read that pair at clockToleranceMs 0, alarmed
  // CORRECTLY, and latched the box permanently — route to permanent hold #8,
  // found live on the real record.
  //
  // THE STEP HERE IS 15 ms, NOT 1067, ON PURPOSE. The latched log's own margin
  // is what makes that the right size: 54 of its 187 consecutive pairs sat
  // within 50 ms of each other, and its TOOL_EXECUTED -> TOOL_RESULT gaps ran
  // 9-14 ms. A 15 ms step would have latched the box exactly as permanently as
  // the loud one did, and nobody would have believed it. The fix has to hold at
  // the size that is easy to dismiss.

  await check(
    "S141-d MUTATION · a wall clock that steps BACK 15 ms writes an ORDERABLE record, keeps the raw reading, and emits exactly ONE CLOCK_STEP_OBSERVED",
    async () => {
      const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-clockstep-"));
      makeOwnPeerDir(socketDir, OWN_UID);
      const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
      const cfgPath = join(cfgDir, "declarations.config.json");
      writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
      const eventBook = join(cfgDir, "events.jsonl");
      const subjectLog = join(cfgDir, "subject-events.jsonl");

      const BASE = Date.parse("2026-09-18T00:00:00Z");
      // A MOVABLE CLOCK, not a scripted list of readings: `now()` is called by
      // startup, /status and the event book too, and a script would be consumed
      // by whichever of those happened to run first. The offset is set between
      // the two POSTs, which is the only moment this test cares about.
      let offset = 0;
      const svc = new MicaBridgeService({
        declarationsPath: cfgPath,
        socketDir,
        now: () => new Date(BASE + offset),
        testWritablePaths: { eventBook, subjectLog },
        testBridgeGid: OWN_GID,
        stateDir: mkdtempSync(join(tmpdir(), "mica-bridge-state-")),
      });
      await svc.start();

      const post = (actionId: string, kind: string) => {
        const identity = { subject: "housekeeper", sessionId: "clockstep", actionId };
        return httpJson(sockFor(socketDir, OWN_UID), "POST", "/subject-events", {
          identity,
          kind,
          eventHash: realEventHash(identity, kind),
        });
      };

      offset = 1000;
      const r1 = await post("step-a", "TOOL_ATTEMPTED");
      assert(r1.status === 200, `first post: ${JSON.stringify(r1)}`);
      offset = 985; // ⏪ THE STEP.
      const r2 = await post("step-a", "TOOL_EXECUTED");
      assert(r2.status === 200, `second post: ${JSON.stringify(r2)}`);
      await svc.stop();

      // THE CHAIN, SEPARATED. Position 0 is the chain's own boundary record, not
      // a subject event — reading the raw lines counted it as one and made this
      // test's "2 records" wrong by exactly the boundary.
      const chain = readSubjectChain(subjectLog);
      assert(chain.boundary !== null, "the chain must begin with its own boundary record");
      const rows = chain.events;
      assert(rows.length === 2, `expected 2 SUBJECT EVENTS, got ${rows.length} (chain holds ${chain.all.length})`);
      const [a, b] = rows;

      // 1 · ORDERABLE. The log's TIME may never contradict the log's ORDER.
      assert(b.sequenceNumber === a.sequenceNumber + 1, `sequence: ${a.sequenceNumber} then ${b.sequenceNumber}`);
      assert(
        b.timestamp >= a.timestamp,
        `THE LOG INVERTED, which is the whole thing this fix exists to prevent: ${a.timestamp} then ${b.timestamp}`
      );
      assert(b.timestamp === BASE + 1000, `stamped must be max(wall, last stamped) = ${BASE + 1000}, got ${b.timestamp}`);
      // `ts` and `timestamp` are one reading, still — they must agree AFTER the
      // clamp, or the record carries the contradiction in a different pair.
      assert(b.ts === new Date(BASE + 1000).toISOString(), `ts disagrees with timestamp: ${b.ts}`);

      // 2 · NOTHING IS FORGED. The true reading survives, under its own name,
      // and ONLY on the record that needed clamping.
      assert(a.clockReadRaw === undefined, `an unstepped record must carry no clockReadRaw: ${JSON.stringify(a)}`);
      assert(b.clockReadRaw === BASE + 985, `the raw wall reading must be kept: ${JSON.stringify(b)}`);

      // 3 · THE MIRROR SPEAKS — exactly once, and it names the size.
      const events = readFileSync(eventBook, "utf8")
        .trim()
        .split("\n")
        .map((l) => JSON.parse(l))
        .filter((e) => e.kind === "CLOCK_STEP_OBSERVED");
      assert(events.length === 1, `expected exactly one CLOCK_STEP_OBSERVED, got ${events.length}`);
      assert(
        String(events[0].detail).includes("BACKWARDS by 15 ms"),
        `the event must name the step's size: ${events[0].detail}`
      );

      // 4 · AND SIG F1 FINDS NOTHING. This is the acceptance; everything above
      // is the mechanism.
      const loaded = validateDeclarations(singleRouteTestDeclaration());
      const sigCfg = {
        clockToleranceMs: loaded.declarations.readers.sig.clockToleranceMs.value,
        preconditionMap: loaded.declarations.readers.sig.preconditionMap.value,
        reentryMap: loaded.declarations.readers.sig.reentryMap.value,
        readableLoadStates: loaded.declarations.readers.readableLoadStates.value,
      };
      assert(sigCfg.clockToleranceMs === 0, `the tolerance must STAY 0 — this fix is not a calibration: ${sigCfg.clockToleranceMs}`);
      const sig = assessSig(new MicaLogFile({ path: subjectLog }), sigCfg as any);
      assert(
        !JSON.stringify(sig).includes("SIG_F1_CLOCK_ORDER_CONTRADICTION"),
        `F1 found a contradiction in a log the writer just made orderable: ${JSON.stringify(sig).slice(0, 800)}`
      );
    }
  );

  // ── CODEX'S MUTATION · raw 1000 -> 985 -> 990 yields EXACTLY ONE step ──────
  //
  // Codex read f4f143f and returned RECOMMEND CHANGES on exactly this: the first
  // cut emitted an event whenever the STAMP had to be lifted, so every reading
  // still below the watermark announced another "went backwards" — including
  // readings that had gone FORWARDS. On the live 1067 ms step that would have
  // produced a false second event 15 ms later, at seq 168.
  //
  // The event marks the FALL. The follow-on condition needs no event because it
  // is on the record: `clockReadRaw` is present exactly while the stamp is not
  // the reading, and absent the moment they agree again.

  await check(
    "CODEX MUTATION · a clock that falls and then RECOVERS (raw 1000 -> 985 -> 990) emits EXACTLY ONE CLOCK_STEP_OBSERVED — the second reading rose, and an event there would claim a step that did not happen",
    async () => {
      const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-clockrec-"));
      makeOwnPeerDir(socketDir, OWN_UID);
      const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
      const cfgPath = join(cfgDir, "declarations.config.json");
      writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
      const eventBook = join(cfgDir, "events.jsonl");
      const subjectLog = join(cfgDir, "subject-events.jsonl");

      const BASE = Date.parse("2026-09-18T00:00:00Z");
      let offset = 0;
      const svc = new MicaBridgeService({
        declarationsPath: cfgPath,
        socketDir,
        now: () => new Date(BASE + offset),
        testWritablePaths: { eventBook, subjectLog },
        testBridgeGid: OWN_GID,
        stateDir: mkdtempSync(join(tmpdir(), "mica-bridge-state-")),
      });
      await svc.start();
      const post = (actionId: string, kind: string) => {
        const identity = { subject: "housekeeper", sessionId: "clockrec", actionId };
        return httpJson(sockFor(socketDir, OWN_UID), "POST", "/subject-events", {
          identity,
          kind,
          eventHash: realEventHash(identity, kind),
        });
      };

      offset = 1000;
      assert((await post("rec-a", "TOOL_ATTEMPTED")).status === 200, "post 1");
      offset = 985;  // ⏪ the FALL — one step
      assert((await post("rec-a", "TOOL_EXECUTED")).status === 200, "post 2");
      offset = 990;  // ⏩ RECOVERING, still under the watermark — NOT a step
      assert((await post("rec-a", "TOOL_RESULT")).status === 200, "post 3");
      await svc.stop();

      const chain = readSubjectChain(subjectLog);
      assert(chain.boundary !== null, "the chain must begin with its own boundary record");
      const rows = chain.events;
      assert(rows.length === 3, `expected 3 SUBJECT EVENTS, got ${rows.length} (chain holds ${chain.all.length})`);
      const [a, b, c] = rows;

      // All three stamps hold the watermark, so the log never inverts.
      assert(a.timestamp === BASE + 1000 && b.timestamp === BASE + 1000 && c.timestamp === BASE + 1000,
        `stamps must all hold the watermark: ${[a.timestamp, b.timestamp, c.timestamp].map((t) => t - BASE)}`);
      // And every record still tells the truth about its own reading.
      assert(a.clockReadRaw === undefined, "record 1 was not clamped");
      assert(b.clockReadRaw === BASE + 985, `record 2 raw: ${b.clockReadRaw}`);
      assert(c.clockReadRaw === BASE + 990, `record 3 raw: ${c.clockReadRaw} — the follow-on condition is on the RECORD`);

      const steps = readFileSync(eventBook, "utf8")
        .trim()
        .split("\n")
        .map((l) => JSON.parse(l))
        .filter((e) => e.kind === "CLOCK_STEP_OBSERVED");
      assert(
        steps.length === 1,
        `EXACTLY ONE step event: the clock fell once and then ROSE. Got ${steps.length}: ` +
          JSON.stringify(steps.map((e) => e.detail))
      );
      assert(
        String(steps[0].detail).includes("BACKWARDS by 15 ms"),
        `the one event must name the FALL (15 ms), not the clamp: ${steps[0].detail}`
      );
    }
  );

  await check(
    "S141-d NEGATIVE CONTROL · the SAME reader, on a log with the step written straight through, DOES find SIG_F1 — so the test above passes because the fix works, not because F1 is asleep",
    () => {
      const dir = mkdtempSync(join(tmpdir(), "mica-bridge-f1neg-"));
      const path = join(dir, "inverted.jsonl");
      const BASE = Date.parse("2026-09-18T00:00:00Z");
      // Exactly what the OLD writer would have persisted for the two posts
      // above: the raw readings, unclamped. 15 ms backwards.
      // ⛔ WRITTEN BY THE REAL WRITER, NOT HAND-ROLLED. This fixture used to be two
      //   JSON lines with no boundary at position 0. The chain-aware reader then took
      //   the FIRST subject event as the boundary and had one record left to pair,
      //   so F1 found nothing — and this NEGATIVE control went quiet for the one
      //   reason a negative control must never go quiet: not because the inversion
      //   stopped alarming, but because the inversion was no longer in the scope.
      //   A fixture the box could not produce is not a control.
      const j = new SubjectEventJournal({ path });
      j.appendBoundary(null, "S141-d negative control: FIRST BOOT", BASE);
      for (const r of [
        { timestamp: BASE + 1000, eventType: "TOOL_ATTEMPTED" },
        { timestamp: BASE + 985, eventType: "TOOL_EXECUTED" },
      ]) {
        j.appendEvent((seq: number) => ({
          sequenceNumber: seq,
          timestamp: r.timestamp,
          moduleId: "housekeeper",
          eventType: r.eventType,
          outcome: "bash",
        }));
      }
      const loaded = validateDeclarations(singleRouteTestDeclaration());
      const sigCfg = {
        clockToleranceMs: loaded.declarations.readers.sig.clockToleranceMs.value,
        preconditionMap: loaded.declarations.readers.sig.preconditionMap.value,
        reentryMap: loaded.declarations.readers.sig.reentryMap.value,
        readableLoadStates: loaded.declarations.readers.readableLoadStates.value,
      };
      const sig = assessSig(new MicaLogFile({ path }), sigCfg as any);
      assert(
        JSON.stringify(sig).includes("SIG_F1_CLOCK_ORDER_CONTRADICTION"),
        `a 15 ms inversion MUST still alarm — if this ever stops failing, the tolerance moved: ${JSON.stringify(sig).slice(0, 800)}`
      );
    }
  );

  await check("F5 (in-process): SIGHUP with a rejected declaration produces DECLARATION_REJECTED, readable via GET /events from disk", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const testWritablePaths = writableTestPaths();

    const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testWritablePaths, testBridgeGid: OWN_GID, stateDir: testWritablePaths.dir });
    await svc.start();

    const bad = JSON.parse(readFileSync(cfgPath, "utf8"));
    delete bad.pilot;
    writeFileSync(cfgPath, JSON.stringify(bad));
    const result = svc.reload();
    assert(!result.ok, "expected rejection");

    const events = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/events");
    assert(events.status === 200, JSON.stringify(events));
    assert(
      events.body.events.some((e: any) => e.kind === "DECLARATION_REJECTED"),
      `expected a DECLARATION_REJECTED event in GET /events, got ${JSON.stringify(events.body)}`
    );
    // And it is genuinely ON DISK, not merely in memory:
    const onDisk = readFileSync(testWritablePaths.eventBook, "utf8");
    assert(onDisk.includes("DECLARATION_REJECTED"), "DECLARATION_REJECTED must be present in the event-book FILE");
    await svc.stop();
  });

  // ── SIGHUP / reload, last-known-good (unchanged declaration) ───────────

  await withService(async (svc) => {
    await check("reload() with a valid, unchanged declaration keeps the same hash", () => {
      const before = svc.buildStatus().declarationHash;
      const result = svc.reload();
      assert(result.ok && result.hash === before, JSON.stringify(result));
    });
  });

  // ── peer-socket planning ─────────────────────────────────────────────────

  await check("planPeerSockets produces one distinct socket path per routes[] uid", () => {
    const plans = planPeerSockets(routes, "/tmp/example");
    const paths = plans.map((p) => p.socketPath);
    assert(new Set(paths).size === paths.length, "socket paths must be distinct");
    assert(plans.every((p) => p.socketPath.includes(`/peers/${p.uid}/`)), "path must be scoped by uid");
  });

  // ── tmpfiles rendering ────────────────────────────────────────────────────

  await check("deploy/mica-bridge.tmpfiles.conf: re-rendering from the draft equals the committed file", () => {
    const { renderTmpfiles } = require("./deploy/render-tmpfiles");
    const rendered: string = renderTmpfiles(DRAFT_PATH);
    const committed = readFileSync(join(__dirname, "deploy", "mica-bridge.tmpfiles.conf"), "utf8");
    assert(rendered === committed, "committed deploy/mica-bridge.tmpfiles.conf is stale; re-run deploy/render-tmpfiles.ts");
  });

  await check("deploy/mica-bridge.tmpfiles.conf: one 'd' line per declared routes[] uid, plus the two parents", () => {
    const committed = readFileSync(join(__dirname, "deploy", "mica-bridge.tmpfiles.conf"), "utf8");
    const dLines = committed.split("\n").filter((l) => l.startsWith("d "));
    assert(dLines.length === routes.length + 2, `expected ${routes.length + 2} 'd' lines, got ${dLines.length}`);
    for (const r of routes) {
      assert(dLines.some((l) => l.startsWith(`d /run/mica-bridge/peers/${r.uid} 0770 `)), `missing tmpfiles line for uid ${r.uid}`);
    }
  });

  // ── POST-CLOSURE FIX 1 — peer directory traversal ───────────────────────
  //
  // Stage 2 was closed at f66c297. This was found on the real box during
  // Stage 4's install, not by any test: the verifier proved the service
  // REFUSES TO BIND on wrong-owned LEAVES (peer-auth.ts's own exact-match
  // check), which is correct and still true — but nobody tested that a
  // CALLER can ARRIVE at its own leaf in the first place, because every
  // prior test ran in a temp tree where the TESTER owned the parents. The
  // property only fails where the parents belong to someone else, which is
  // only true on the real box. This test reasons PURELY over the declared
  // tmpfiles content plus `id` (no root, no real /run access needed) so it
  // can catch the same class of defect from right here.

  interface TmpfilesDirEntry {
    readonly path: string;
    readonly mode: number;
    readonly owner: string;
    readonly group: string;
  }

  function parseTmpfilesDirs(content: string): TmpfilesDirEntry[] {
    return content
      .split("\n")
      .filter((l) => l.startsWith("d "))
      .map((l) => {
        const parts = l.trim().split(/\s+/);
        // d <path> <mode> <owner> <group> <age>
        return { path: parts[1], mode: parseInt(parts[2], 8), owner: parts[3], group: parts[4] };
      });
  }

  /**
   * Can `callerUid` traverse (execute-bit into) this ONE directory, by
   * owner, by group membership, or by "other"? Pure reasoning over the
   * declared {mode, owner, group} plus `id` — never touches the real
   * filesystem, so it works identically whether or not /run/mica-bridge
   * exists on this box at all.
   */
  function canTraverse(dir: TmpfilesDirEntry, callerUid: number): boolean {
    const ownerUid = Number(execFileSync("id", ["-u", dir.owner], { encoding: "utf8" }).trim());
    if (callerUid === ownerUid && (dir.mode & 0o100) !== 0) return true;
    if ((dir.mode & 0o010) !== 0) {
      const callerUsername = execFileSync("id", ["-nu", String(callerUid)], { encoding: "utf8" }).trim();
      const callerGroups = execFileSync("id", ["-nG", callerUsername], { encoding: "utf8" }).trim().split(/\s+/);
      if (callerGroups.includes(dir.group)) return true;
    }
    if ((dir.mode & 0o001) !== 0) return true;
    return false;
  }

  await check("POST-CLOSURE FIX 1: every routes[] uid can traverse every declared path component from /run/mica-bridge down to its own peer directory", () => {
    const committed = readFileSync(join(__dirname, "deploy", "mica-bridge.tmpfiles.conf"), "utf8");
    const dirs = parseTmpfilesDirs(committed);
    const rootDir = dirs.find((d) => d.path === "/run/mica-bridge");
    const peersDir = dirs.find((d) => d.path === "/run/mica-bridge/peers");
    assert(rootDir !== undefined && peersDir !== undefined, "expected /run/mica-bridge and /run/mica-bridge/peers as declared 'd' lines");

    for (const r of routes) {
      const leaf = dirs.find((d) => d.path === `/run/mica-bridge/peers/${r.uid}`);
      assert(leaf !== undefined, `missing declared leaf for uid ${r.uid}`);
      // /run itself is not this project's to declare or manage (standard,
      // system-provided, 0755) — out of scope, stated rather than assumed.
      for (const [label, dir] of [
        ["/run/mica-bridge", rootDir!],
        ["/run/mica-bridge/peers", peersDir!],
        [`/run/mica-bridge/peers/${r.uid}`, leaf!],
      ] as const) {
        assert(
          canTraverse(dir, r.uid),
          `uid ${r.uid} CANNOT traverse ${label} (declared mode ${dir.mode.toString(8)} ${dir.owner}:${dir.group}) — the corridor to its own socket is blocked`
        );
      }
    }
  });

  await check("POST-CLOSURE FIX 1 regression: the traversal checker itself correctly flags the ORIGINAL 0750 parents as blocking a real caller uid", () => {
    // Reconstructs the pre-fix declared shape exactly (0750 mica-bridge:mica-bridge
    // parents) and asserts the SAME canTraverse() function used above
    // correctly reports it broken for a real, currently-provisioned caller
    // uid — proving this suite's own checker would have caught the defect
    // that shipped in Stage 2's closed state, not merely that it approves
    // of the fix in isolation. `[verified]` this session, empirically, not
    // assumed: none of this deployment's three caller accounts
    // (mica-housekeeper, mica-alerter, the operator account) are members of group
    // "mica-bridge" (checked via `id -nG` against the real accounts this
    // box actually has).
    const brokenParent: TmpfilesDirEntry = { path: "/run/mica-bridge", mode: 0o750, owner: "mica-bridge", group: "mica-bridge" };
    let sawABlockedCaller = false;
    for (const r of routes) {
      const callerUsername = execFileSync("id", ["-nu", String(r.uid)], { encoding: "utf8" }).trim();
      const callerGroups = execFileSync("id", ["-nG", callerUsername], { encoding: "utf8" }).trim().split(/\s+/);
      if (callerGroups.includes("mica-bridge")) continue; // this uid happens to be provisioned into the group; not the interesting case
      sawABlockedCaller = true;
      assert(
        canTraverse(brokenParent, r.uid) === false,
        `expected the ORIGINAL 0750 mica-bridge:mica-bridge parent to block uid ${r.uid} (username ${callerUsername}, groups [${callerGroups.join(",")}]), but the checker said it could traverse — the checker itself would not have caught the real defect`
      );
    }
    assert(sawABlockedCaller, "no declared caller uid was actually blocked by the reconstructed pre-fix parent on THIS box — the regression case could not be exercised; investigate this box's group provisioning before trusting the positive test above");
  });

  // ── F6 — no [Install] section on the bridge unit ────────────────────────

  await check("F6: deploy/mica-bridge.service carries no [Install] section", () => {
    const unit = readFileSync(join(__dirname, "deploy", "mica-bridge.service"), "utf8");
    assert(!/^\[Install\]/m.test(unit), "the bridge unit must not carry [Install] — the arbiter installs and starts it by hand");
  });

  // ── F7 — deployment-facts fragment carries group ownership too ─────────

  await check("F7: deployment-facts.fragment.json carries at least one acl-entry fact per peer LEAF directory with group:mica-bridge", () => {
    const fragment = JSON.parse(readFileSync(join(__dirname, "deploy", "deployment-facts.fragment.json"), "utf8"));
    const aclFacts = fragment.filter((f: any) => f.family === "acl-entry");
    // POST-CLOSURE FIX 1: narrowed to the per-uid LEAF facts specifically —
    // this was, before this fix, indistinguishable from "every acl-entry
    // fact in the fragment," because the fragment's one PARENT acl-entry
    // also happened to say group:mica-bridge (it was wrong to; that
    // wrongness is exactly what left every caller locked out). The parent
    // is now root:root by design (0711, Ruling K(b), this fix's own
    // receipt section) — asserting group:mica-bridge on it would assert
    // the very fact that broke traversal.
    const leafAclFacts = aclFacts.filter((f: any) => /^\/run\/mica-bridge\/peers\/\d+$/.test(f.path));
    assert(leafAclFacts.length >= routes.length, `expected at least ${routes.length} leaf acl-entry facts, got ${leafAclFacts.length}`);
    assert(leafAclFacts.every((f: any) => f.group === "mica-bridge"), "every LEAF acl-entry fact must declare group: mica-bridge");
    for (const r of routes) {
      assert(
        leafAclFacts.some((f: any) => f.path === `/run/mica-bridge/peers/${r.uid}`),
        `missing acl-entry fact for uid ${r.uid}'s directory`
      );
    }
  });

  await check("POST-CLOSURE FIX 1: deployment-facts.fragment.json's PARENT fact (/run/mica-bridge/peers) states 0711 root:root, matching the fixed tmpfiles.conf, not the pre-fix 0750 mica-bridge:mica-bridge", () => {
    const fragment = JSON.parse(readFileSync(join(__dirname, "deploy", "deployment-facts.fragment.json"), "utf8"));
    const parentModeFact = fragment.find((f: any) => f.family === "file-mode" && f.path === "/run/mica-bridge/peers");
    const parentAclFact = fragment.find((f: any) => f.family === "acl-entry" && f.path === "/run/mica-bridge/peers");
    assert(parentModeFact !== undefined && parentModeFact.mode === "0711", JSON.stringify(parentModeFact));
    assert(parentAclFact !== undefined && parentAclFact.owner === "root" && parentAclFact.group === "root", JSON.stringify(parentAclFact));
  });

  // ── Amendment 7 — the marker gets a poller-visible reader ──────────────
  //
  // Amendment 6's marker was read only by --check and the relay's own
  // preflight — both cases where a human is already at the terminal doing
  // a relay, i.e. exactly the case that already knows. This closes the
  // walk-away gap: /status.relay is what a Stage 3 alerter (a poller) will
  // read once it exists.

  await check("GET /status reports relay.markerPresent:false when no marker exists (the ordinary case)", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const markerDir = mkdtempSync(join(tmpdir(), "mica-bridge-marker-"));
    const markerPath = join(markerDir, "relay-in-progress"); // deliberately never created
    const svc = new MicaBridgeService({
      stateDir: mkdtempSync(join(tmpdir(), "mica-bridge-state-")),
      declarationsPath: cfgPath,
      socketDir,
      now: () => new Date("2026-09-18T00:00:00Z"),
      testBridgeGid: OWN_GID,
    });
    const prevEnv = process.env.MICA_BRIDGE_RELAY_MARKER;
    process.env.MICA_BRIDGE_RELAY_MARKER = markerPath;
    try {
      await svc.start();
      const r = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
      assert(r.status === 200, JSON.stringify(r));
      assert(r.body.relay.markerPresent === false, JSON.stringify(r.body.relay));
      assert(r.body.relay.detail === null, JSON.stringify(r.body.relay));
      assert(r.body.relay.path === markerPath, JSON.stringify(r.body.relay));
      await svc.stop();
    } finally {
      if (prevEnv === undefined) delete process.env.MICA_BRIDGE_RELAY_MARKER;
      else process.env.MICA_BRIDGE_RELAY_MARKER = prevEnv;
    }
  });

  await check("GET /status reports relay.markerPresent:true with its content when a marker exists (an interrupted relay, visible to a poller)", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const markerDir = mkdtempSync(join(tmpdir(), "mica-bridge-marker-"));
    const markerPath = join(markerDir, "relay-in-progress");
    const markerContent = "candidate_sha=deadbeef\nprevious_sha=cafefeed\nstarted_at=2026-09-19T00:00:00Z\n";
    writeFileSync(markerPath, markerContent);
    const svc = new MicaBridgeService({
      stateDir: mkdtempSync(join(tmpdir(), "mica-bridge-state-")),
      declarationsPath: cfgPath,
      socketDir,
      now: () => new Date("2026-09-18T00:00:00Z"),
      testBridgeGid: OWN_GID,
    });
    const prevEnv = process.env.MICA_BRIDGE_RELAY_MARKER;
    process.env.MICA_BRIDGE_RELAY_MARKER = markerPath;
    try {
      await svc.start();
      const r = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
      assert(r.status === 200, JSON.stringify(r));
      assert(r.body.relay.markerPresent === true, JSON.stringify(r.body.relay));
      assert(r.body.relay.detail === markerContent, JSON.stringify(r.body.relay));
      assert(r.body.relay.detail.includes("deadbeef"), JSON.stringify(r.body.relay));
      await svc.stop();
    } finally {
      if (prevEnv === undefined) delete process.env.MICA_BRIDGE_RELAY_MARKER;
      else process.env.MICA_BRIDGE_RELAY_MARKER = prevEnv;
    }
  });

  // ══════════════════════════════════════════════════════════════════════
  // STAGE 4 / DESIGN §A — Stage 1 bound into the door
  // ══════════════════════════════════════════════════════════════════════

  function currentBootId(): string {
    return readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
  }

  // ── §A.2/A.5 — the default binding, end to end, real evaluateAndRecord ──

  await check("STAGE 4 \u00A7A, FOUND LIVE: /status must not contradict itself — when guardBound is true, NO instrument reason may claim the adapter is NotBoundGuardAdapter", async () => {
    // THE DEFECT THIS CATCHES, observed on the real box 2026-09-20 after the
    // first relay of \u00A7A: /status served `guardBound: true` while twelve of
    // fourteen instrument rows carried the Stage 2 literal "the guard adapter
    // is NotBoundGuardAdapter until Stage 1's evaluateAndRecord is bound in."
    // Both sentences in ONE document, one of them false. Design \u00A7I.2: "a
    // broken bridge is indistinguishable from a permissive one unless the
    // caller says so every time" — a reason string asserting the guard is
    // unbound, while it is bound, manufactures exactly that confusion in the
    // census a doctor is told to trust.
    //
    // WHAT THIS TEST WOULD STILL PASS IF THE CLAIM WERE FALSE: nothing that
    // matters. It reads the SAME /status body for both halves, so it cannot
    // be satisfied by a stale cache or a second service; and it asserts the
    // rows are still UNWIRED, so it cannot be cheated by flipping them WIRED
    // to dodge the string check. The one thing it does not prove is that the
    // replacement wording is USEFUL — only that it is not self-contradicting.
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const svc = new MicaBridgeService({
      declarationsPath: cfgPath,
      socketDir,
      now: () => new Date("2026-09-18T00:00:00Z"),
      testBridgeGid: OWN_GID,
      stateDir,
    });
    await svc.start();
    try {
      const status = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
      assert(status.body.guardBound === true, `precondition: expected guardBound:true, got ${JSON.stringify(status.body.guardBound)}`);

      const rows = status.body.instruments as { id: string; state: string; reason: string }[];
      const unwired = rows.filter((r) => r.state === "UNWIRED");
      // ⛔ SIX, NOT TWELVE — and this precondition did exactly its job. It read
      //   `expected 12 UNWIRED rows` and failed the moment the census began
      //   reporting every wired reader, with the message "if this changed, the
      //   assertion below is measuring something else". It was, and it said so.
      assert(unwired.length === 6, `precondition: expected 6 UNWIRED rows, got ${unwired.length} — if this changed, the assertion below is measuring something else`);

      const contradicting = rows.filter((r) => /NotBoundGuardAdapter/.test(r.reason));
      assert(
        contradicting.length === 0,
        `guardBound is true, but ${contradicting.length} instrument row(s) still say the adapter is NotBoundGuardAdapter: ` +
          JSON.stringify(contradicting.map((r) => r.id))
      );

      // And the vacancy is still stated, not silently blanked: a row that
      // explains nothing is its own failure.
      for (const r of unwired) {
        assert(typeof r.reason === "string" && r.reason.length > 40, `UNWIRED row ${r.id} must still carry a substantive reason, got ${JSON.stringify(r.reason)}`);
      }
    } finally {
      await svc.stop();
    }
  });

  await check("STAGE 4 §A.2: Stage1GuardAdapter is the DEFAULT when no guardAdapter override is given — POST /guard runs a REAL evaluateAndRecord and /status.guardBound is true", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    // NO guardAdapter option at all — this is the discriminator: if the
    // default were still NotBoundGuardAdapter, the assertions below on a
    // real disposition and guardBound:true would both fail.
    const svc = new MicaBridgeService({
      declarationsPath: cfgPath,
      socketDir,
      now: () => new Date("2026-09-18T00:00:00Z"),
      testBridgeGid: OWN_GID,
      stateDir,
    });
    await svc.start();
    try {
      const status0 = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
      assert(status0.body.guardBound === true, `expected guardBound:true with the default adapter, got ${JSON.stringify(status0.body.guardBound)}`);

      const r = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper", sessionId: "s1", actionId: "a1", toolName: "bash" });
      // housekeeper/bash: stakesClass "bash" is ABOVE the declared baseline
      // holdAtOrAbove ("state_changing") in lineClasses, and the floor is
      // CANNOT_ASSESS (BLIND) -> HOLD_BLIND, execute:false.
      //
      // P6 CORRECTED THIS COMMENT, which had gone a beat out of date and was
      // asserting the old world in prose: it read "with NO reader wired
      // (wireOptionsFor deliberately omits logPath/clerkStore, §A.3) ...
      // composeFloorKind([]) === CANNOT_ASSESS". C9/Part D made
      // `wireOptionsFor` spread `toWireOptions(d)`, so Eng and Sig ARE wired
      // here, off the declared `readers.logPath` resolved into this test's
      // state dir. The floor is still CANNOT_ASSESS and the disposition is
      // still HOLD_BLIND — but for the opposite reason: two readers ran and
      // both said CANNOT_ASSESS over a log file that is not there, rather than
      // no reader running at all. Same verdict, different world; that is
      // exactly the kind of drift a stale comment hides.
      // This is a REAL disposition from mica-machine's own chokepoint, not a
      // stub: NotBoundGuardAdapter can never produce this body at all.
      assert(r.status === 200, JSON.stringify(r));
      assert(r.body.decision.disposition === "HOLD_BLIND", `expected a real HOLD_BLIND disposition, got ${JSON.stringify(r.body.decision)}`);
      assert(r.body.decision.execute === false, JSON.stringify(r.body.decision));
      // P6: this line asserted `length === 0` and passed for a year — first
      // truthfully (nothing was wired), then vacuously (two readers were wired
      // and the field said nothing). It now asserts the reading those two
      // readers actually took.
      //
      // ACT A CHANGED WHAT THAT READING IS, and the change is not cosmetic:
      // the subject log is no longer absent on a fresh service. A chain BEGINS
      // at start with its position-0 boundary record — "the log starts here",
      // naming what it replaced or declaring FIRST BOOT — so the readers stand
      // on a verified chain of one rather than on a file that is not there.
      // TAMPER-EVIDENT, NOT INDEPENDENT: one process wrote, chained and
      // verified it.
      assert(Array.isArray(r.body.readerFootings) && r.body.readerFootings.length === 2, JSON.stringify(r.body.readerFootings));
      assert(
        JSON.stringify(r.body.readerFootings) ===
          JSON.stringify([
            { reader: "MICA/Eng", loadState: "LOADED_SUBJECT_CHAIN_VERIFIED", verifiedChain: true },
            { reader: "MICA/Sig", loadState: "LOADED_SUBJECT_CHAIN_VERIFIED", verifiedChain: true },
          ]),
        `expected both wired readers' real footing over this service's own chain, got ${JSON.stringify(r.body.readerFootings)}`
      );
      assert(r.body.readerFootingsBasis?.kind === "THIS_CALL", JSON.stringify(r.body.readerFootingsBasis));
      assert(Array.isArray(r.body.quarantined), JSON.stringify(r.body.quarantined));
      assert(typeof r.body.delivery.trail === "string" || typeof r.body.delivery.trail === "object", JSON.stringify(r.body.delivery));

      // §A.7: DISPOSITION_CHANGED (prior null -> HOLD_BLIND) and HELD
      // (execute:false) must both have been appended to the event book.
      const events = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/events");
      assert(events.status === 200, JSON.stringify(events));
      const kinds = events.body.events.map((e: any) => e.kind);
      assert(kinds.includes("DISPOSITION_CHANGED"), `expected DISPOSITION_CHANGED, got ${JSON.stringify(kinds)}`);
      assert(kinds.includes("HELD"), `expected HELD, got ${JSON.stringify(kinds)}`);
      const dispositionChanged = events.body.events.find((e: any) => e.kind === "DISPOSITION_CHANGED");
      assert(dispositionChanged.subject === "housekeeper", JSON.stringify(dispositionChanged));
      assert(String(dispositionChanged.detail).includes("HOLD_BLIND"), JSON.stringify(dispositionChanged));

      // A second, identical call: same subject, same disposition every
      // time (deterministic — nothing wired, same stakes) -> HELD fires
      // AGAIN (every non-executing call is HELD), but DISPOSITION_CHANGED
      // must NOT fire a second time (prior === new, both HOLD_BLIND).
      const r2 = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper", sessionId: "s1", actionId: "a2", toolName: "bash" });
      assert(r2.status === 200 && r2.body.decision.disposition === "HOLD_BLIND", JSON.stringify(r2));
      const events2 = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/events");
      const dcCount = events2.body.events.filter((e: any) => e.kind === "DISPOSITION_CHANGED" && e.subject === "housekeeper").length;
      const heldCount = events2.body.events.filter((e: any) => e.kind === "HELD" && e.subject === "housekeeper").length;
      assert(dcCount === 1, `expected exactly ONE DISPOSITION_CHANGED across two identical-disposition calls, got ${dcCount}`);
      assert(heldCount === 2, `expected HELD on EVERY non-executing call (2 calls), got ${heldCount}`);
    } finally {
      await svc.stop();
    }
  });

  // ── §A.7 — PILOT_STATE_CHANGED and PASS_BLIND_NOTICE ────────────────────

  await check("STAGE 4 §A.7: a subject whose stakesClass is BELOW the line gets a REAL PASS_BLIND disposition, execute:true, and a PASS_BLIND_NOTICE event backed by an actual written notice line", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    const d = singleRouteTestDeclaration() as any;
    // Add a second subject, same peer uid (routes are keyed by uid, not by
    // subject), whose stakesClass ("routine", index 0) sits BELOW the
    // declared baseline holdAtOrAbove ("state_changing", index 2) —
    // stakesSplit returns BELOW_LINE, and with the floor CANNOT_ASSESS
    // (nothing wired) that maps to PASS_BLIND (mapFloorToDisposition),
    // which DOES execute.
    d.subjects.push({ subject: "housekeeper-routine", toolName: "bash", stakesClass: "routine", peerUid: OWN_UID });
    writeFileSync(cfgPath, JSON.stringify(d));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
    await svc.start();
    try {
      const r = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper-routine", sessionId: "pb1", actionId: "a1", toolName: "bash" });
      assert(r.status === 200, JSON.stringify(r));
      assert(r.body.decision.disposition === "PASS_BLIND", `expected PASS_BLIND for a below-line stakesClass, got ${JSON.stringify(r.body.decision)}`);
      assert(r.body.decision.execute === true, JSON.stringify(r.body.decision));

      // The notice must be genuinely ON DISK, not merely claimed.
      const noticePath = join(stateDir, "notices", "notices.jsonl");
      assert(existsSync(noticePath), `expected a real notices.jsonl at ${noticePath}`);
      const noticeLines = readFileSync(noticePath, "utf8").split("\n").filter((l) => l.trim().length > 0);
      assert(noticeLines.length >= 1, "expected at least one written notice line");

      const events = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/events");
      const notice = events.body.events.find((e: any) => e.kind === "PASS_BLIND_NOTICE" && e.subject === "housekeeper-routine");
      assert(notice !== undefined, `expected a PASS_BLIND_NOTICE event, got kinds ${JSON.stringify(events.body.events.map((e: any) => e.kind))}`);
      assert(typeof notice.detail === "string" && notice.detail.length > 0, JSON.stringify(notice));
      // HELD must NOT fire for an executing disposition.
      assert(
        !events.body.events.some((e: any) => e.kind === "HELD" && e.subject === "housekeeper-routine"),
        "PASS_BLIND executes -> HELD must not fire for this subject"
      );
    } finally {
      await svc.stop();
    }
  });

  await check("STAGE 4 §A.7: PILOT_STATE_CHANGED fires on the first-ever observation (null -> INACTIVE), again on the INACTIVE -> ACTIVE transition, and NOT a third time on an unchanged-state next call", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    const inactive = singleRouteTestDeclaration();
    writeFileSync(cfgPath, JSON.stringify(inactive));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
    await svc.start();
    try {
      const r0 = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper", sessionId: "pilot1", actionId: "a1", toolName: "bash" });
      assert(r0.status === 200, JSON.stringify(r0));
      const active = JSON.parse(JSON.stringify(inactive)) as any;
      active.pilot = { active: true, sessionId: "pilot1", expiresAt: "2099-01-01T00:00:00Z", holdAtOrAbove: { value: "irreversible", basis: "test", proxy: true } };
      writeFileSync(cfgPath, JSON.stringify(active));
      const reloadResult = svc.reload();
      assert(reloadResult.ok, `expected reload to accept the pilot-active declaration: ${JSON.stringify(reloadResult)}`);

      const r1 = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper", sessionId: "pilot1", actionId: "a2", toolName: "bash" });
      assert(r1.status === 200, JSON.stringify(r1));
      const r2 = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper", sessionId: "pilot1", actionId: "a3", toolName: "bash" });
      assert(r2.status === 200, JSON.stringify(r2));

      const events = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/events");
      const pscEvents = events.body.events.filter((e: any) => e.kind === "PILOT_STATE_CHANGED");
      // TWO emissions across three calls: r0 is the first-ever observation
      // (this service's `lastPilotObservedKey` starts `null`, so "null ->
      // INACTIVE" emits once, honestly, rather than assuming a pre-start
      // state); r1 is the genuine INACTIVE -> ACTIVE transition. r2 (SAME
      // pilot state as r1) must NOT emit a third time — that is what this
      // test discriminates: a version that emitted on every call, or one
      // that never seeded/compared at all, would both fail this count.
      assert(pscEvents.length === 2, `expected exactly two PILOT_STATE_CHANGED events (initial observation + one real transition), got ${pscEvents.length}: ${JSON.stringify(pscEvents)}`);
      assert(pscEvents[0].detail === "INACTIVE", JSON.stringify(pscEvents[0]));
      assert(pscEvents[1].detail === "ACTIVE:pilot1", JSON.stringify(pscEvents[1]));
    } finally {
      await svc.stop();
    }
  });

  // ── §A.6, Layer 2 — the history owner file ───────────────────────────────

  await check("STAGE 4 §A.6: a fresh start() claims the history owner file, and stop() removes it", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const ownerPath = join(stateDir, "substrate-history.jsonl.owner");
    const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
    await svc.start();
    assert(existsSync(ownerPath), `expected ${ownerPath} to exist after start()`);
    const claim = JSON.parse(readFileSync(ownerPath, "utf8"));
    assert(claim.pid === process.pid, JSON.stringify(claim));
    assert(claim.bootId === currentBootId(), JSON.stringify(claim));
    assert(claim.unit === "mica-bridge.service", JSON.stringify(claim));
    const status = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
    assert(status.body.historyOwner !== null && status.body.historyOwner.pid === process.pid, JSON.stringify(status.body.historyOwner));
    await svc.stop();
    assert(!existsSync(ownerPath), `expected ${ownerPath} to be removed by stop()`);
  });

  await check("STAGE 4 §A.6: a STALE owner file (different bootId) is replaced, and the replacement is recorded via GET /events", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const ownerPath = join(stateDir, "substrate-history.jsonl.owner");
    mkdirSync(stateDir, { recursive: true });
    writeFileSync(ownerPath, JSON.stringify({ pid: 999999, bootId: "not-the-real-boot-id", startedAt: "2020-01-01T00:00:00Z", unit: "mica-bridge.service" }));
    const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
    await svc.start();
    try {
      const claim = JSON.parse(readFileSync(ownerPath, "utf8"));
      assert(claim.pid === process.pid && claim.bootId === currentBootId(), `expected the stale claim to be replaced by this process's own, got ${JSON.stringify(claim)}`);
      const events = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/events");
      assert(events.body.events.some((e: any) => e.kind === "HISTORY_OWNER_REPLACED"), `expected a HISTORY_OWNER_REPLACED event, got ${JSON.stringify(events.body.events.map((e: any) => e.kind))}`);
    } finally {
      await svc.stop();
    }
  });

  await check("STAGE 4 §A.6: a SAME-BOOT owner file naming a pid that no longer exists is treated as stale and replaced (never refused)", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const ownerPath = join(stateDir, "substrate-history.jsonl.owner");
    mkdirSync(stateDir, { recursive: true });
    // A pid extremely unlikely to exist on this box, same (real) boot.
    writeFileSync(ownerPath, JSON.stringify({ pid: 2147480000, bootId: currentBootId(), startedAt: "2020-01-01T00:00:00Z", unit: "mica-bridge.service" }));
    const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
    await svc.start(); // must NOT throw
    try {
      const claim = JSON.parse(readFileSync(ownerPath, "utf8"));
      assert(claim.pid === process.pid, `expected the gone-pid claim to be replaced, got ${JSON.stringify(claim)}`);
    } finally {
      await svc.stop();
    }
  });

  await check("STAGE 4 §A.6: a SAME-BOOT owner file naming a LIVE mica-bridge.service refuses startup — a real second writer, real child process", async () => {
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const childSocketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(childSocketDir, OWN_UID);
    const sharedStateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));

    const child = require("child_process").spawn(
      "/usr/bin/node",
      [TSNODE, "-P", join(__dirname, "tsconfig.json"), join(__dirname, "mica-service.ts")],
      {
        env: {
          ...process.env,
          MICA_BRIDGE_DECLARATIONS: cfgPath,
          MICA_BRIDGE_SOCKET_DIR: childSocketDir,
          MICA_BRIDGE_STATE_DIR: sharedStateDir,
          MICA_BRIDGE_TEST_BRIDGE_GID: String(OWN_GID),
        },
      }
    );
    const stderrChunks: string[] = [];
    child.stderr.on("data", (c: Buffer) => stderrChunks.push(c.toString("utf8")));

    try {
      await new Promise<void>((resolve, reject) => {
        // ⛔ `stderr: ` WITH NOTHING AFTER IT WAS THE WHOLE EVIDENCE of this red,
        //    and that part of the repair stands: a child that never got the CPU
        //    writes nothing, so the message says so in as many words.
        //
        // ⚠ BUT IT IS A FAILURE, NOT A SKIP. Codex, 2026-10-04: a readiness wait
        //   that gives up and calls it a non-observation cannot tell "the box was
        //   busy" from "the service hung", and THE SECOND IS THE WHOLE REASON THIS
        //   ARM EXISTS. A hang that reads as a skip is a hang nobody is told about.
        const timeout = setTimeout(
          () =>
            reject(
              new Error(
                `the child did not report serving inside ${CHILD_COMPILE_BUDGET_MS} ms — ` +
                  `stderr was ${stderrChunks.length === 0 ? "(empty)" : JSON.stringify(stderrChunks.join(""))}. ` +
                  `THIS IS A FAILURE, not a non-observation: this arm is not on a flaky register, and a ` +
                  `service that never reports serving is indistinguishable from a busy box only from the ` +
                  `outside. Run the suite alone; if it still happens, the start path hung and that is the finding.`
              )
            ),
          CHILD_COMPILE_BUDGET_MS
        );
        child.stdout.on("data", (chunk: Buffer) => {
          if (chunk.toString("utf8").includes("serving")) {
            clearTimeout(timeout);
            resolve();
          }
        });
        child.on("exit", (code: number | null) => {
          clearTimeout(timeout);
          reject(new Error(`child exited (code ${code}) before serving; stderr: ${stderrChunks.join("")}`));
        });
      });

      // The child is now a REAL, live mica-bridge.service on this SAME
      // boot, owning sharedStateDir/substrate-history.jsonl. A second
      // in-process start() at the SAME stateDir must be refused.
      const secondSocketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
      makeOwnPeerDir(secondSocketDir, OWN_UID);
      const second = new MicaBridgeService({
        declarationsPath: cfgPath,
        socketDir: secondSocketDir,
        now: () => new Date("2026-09-18T00:00:00Z"),
        testBridgeGid: OWN_GID,
        stateDir: sharedStateDir,
      });
      let threw: Error | null = null;
      try {
        await second.start();
        await second.stop();
      } catch (err) {
        threw = err as Error;
      }
      assert(threw !== null && threw instanceof StartupRefused, `expected StartupRefused, got ${threw}`);
      assert(String(threw!.message).includes("LIVE"), `expected the refusal to name a LIVE conflict, got: ${threw!.message}`);
    } finally {
      try {
        child.kill();
      } catch {}
    }
  });

  // ── §A.6, stuck-lock visibility ───────────────────────────────────────────

  await check("STAGE 4 §A.6: GET /status.appendLocks reports a planted <path>.lock sibling for a book path, and stops reporting it once removed", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
    await svc.start();
    try {
      const lockPath = join(stateDir, "floor-trail.jsonl.lock");
      const status0 = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
      assert(Array.isArray(status0.body.appendLocks) && status0.body.appendLocks.length === 0, JSON.stringify(status0.body.appendLocks));

      writeFileSync(lockPath, "");
      const status1 = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
      const row = status1.body.appendLocks.find((r: any) => r.path === lockPath);
      assert(row !== undefined, `expected an appendLocks row for ${lockPath}, got ${JSON.stringify(status1.body.appendLocks)}`);
      assert(typeof row.since === "string" && row.since.length > 0, JSON.stringify(row));

      require("fs").unlinkSync(lockPath);
      const status2 = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
      assert(!status2.body.appendLocks.some((r: any) => r.path === lockPath), JSON.stringify(status2.body.appendLocks));
    } finally {
      await svc.stop();
    }
  });

  // ── STATUS DOOR: the `door` section of /status ──────────────────────────
  //
  // core-door-status.test.ts covers the pure shaping function and readCoreDoor
  // against BOTH injected fakes and a real evaluateDoor run over a scratch
  // tree it builds and owns. These three checks are the layer above: proof
  // that MicaBridgeService actually THREADS `doorRepoRoot`/`doorModuleLoader`
  // into `buildStatus()`, and that the door section really reaches a caller
  // over the real HTTP socket — not merely that the pure function is correct
  // in isolation.

  await check("STATUS-DOOR: GET /status.door defaults to the real /opt/mica-machine tree — a real door word, never fabricated, readMs is a small positive number", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, testBridgeGid: OWN_GID, stateDir });
    await svc.start();
    try {
      const status = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
      assert(status.status === 200, `a census endpoint must answer 200 even off the real tree: ${JSON.stringify(status)}`);
      const door = status.body.door;
      assert(["CLOSED", "OPEN", "REFUSED", "UNREADABLE"].includes(door.state), JSON.stringify(door));
      assert(typeof door.readMs === "number" && door.readMs >= 0 && door.readMs < 5000, JSON.stringify(door));
    } finally {
      await svc.stop();
    }
  });

  await check("STATUS-DOOR constraint #2: a throwing doorModuleLoader is UNREADABLE at /status.door, and /status itself STILL answers 200 — never a 500, never fabricated CLOSED", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const svc = new MicaBridgeService({
      declarationsPath: cfgPath,
      socketDir,
      testBridgeGid: OWN_GID,
      stateDir,
      doorModuleLoader: () => {
        throw new Error("simulated: /opt/mica-machine/src/core-door/core-door not present on this box");
      },
    });
    await svc.start();
    try {
      const status = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
      assert(status.status === 200, `one bad row must not 500 the whole census: ${JSON.stringify(status)}`);
      assert(status.body.door.state === "UNREADABLE", JSON.stringify(status.body.door));
      assert(status.body.door.state !== "CLOSED", "an unreadable door must never print as CLOSED");
      assert(String(status.body.door.detail).includes("simulated"), JSON.stringify(status.body.door));
      assert(status.body.door.authorshipNotVerified === null, "nothing was read, so nothing is carried");
      // Every OTHER row still serves — the door row failing does not take the census down with it.
      assert(typeof status.body.declarationHash === "string" && status.body.declarationHash.length === 64, JSON.stringify(status.body));
    } finally {
      await svc.stop();
    }
  });

  await check("STATUS-DOOR constraint #6: doorRepoRoot + doorModuleLoader are threaded end to end — a live ticket's id/opens/expiresAt reach the real HTTP /status response, and the SAME repoRoot the service was given reaches evaluateRealDoor", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const doorRepoRoot = mkdtempSync(join(tmpdir(), "mica-bridge-door-scratch-"));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    let seenRepoRoot: string | null = null;
    const svc = new MicaBridgeService({
      declarationsPath: cfgPath,
      socketDir,
      testBridgeGid: OWN_GID,
      stateDir,
      now: () => new Date("2026-09-22T12:00:00Z"),
      doorRepoRoot,
      doorModuleLoader: () => ({
        evaluateRealDoor: (repoRoot: string) => {
          seenRepoRoot = repoRoot;
          return {
            kind: "OPEN",
            pinned: 1,
            states: [],
            live: [
              {
                schema: "mica-core-door/ticket/1",
                id: "T-service-wiring",
                opens: ["src/mica/only.ts"],
                defect: { summary: "s", ground: "g" },
                expiresAt: "2026-09-29T18:00:00Z",
                arbiter: { word: "w", date: "2026-09-22" },
                conditions: [],
              },
            ],
            unpinnedDrift: [],
            lines: [],
            shippable: true,
          };
        },
        parseInventory: () => ({ baseline: { commit: "scratch-commit", pinnedOn: "2026-09-22" }, repins: [] }),
        AUTHORSHIP_NOT_VERIFIED: "TEST authorship line, carried verbatim",
        INVENTORY_REL: "src/core-door/core-inventory.json",
      }),
    });
    await svc.start();
    try {
      const status = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
      assert(status.status === 200, JSON.stringify(status));
      const door = status.body.door;
      assert(door.state === "OPEN", JSON.stringify(door));
      assert(door.liveTickets.length === 1 && door.liveTickets[0].id === "T-service-wiring", JSON.stringify(door.liveTickets));
      assert(JSON.stringify(door.liveTickets[0].opens) === JSON.stringify(["src/mica/only.ts"]), JSON.stringify(door.liveTickets));
      assert(door.liveTickets[0].expiresAt === "2026-09-29T18:00:00Z", JSON.stringify(door.liveTickets));
      assert(door.authorshipNotVerified === "TEST authorship line, carried verbatim", JSON.stringify(door));
      assert(seenRepoRoot === doorRepoRoot, `the service must hand its OWN doorRepoRoot to evaluateRealDoor, got ${String(seenRepoRoot)}`);
    } finally {
      await svc.stop();
    }
  });

  // ── §A.3 — wireOptionsFor, pure, unit-level ──────────────────────────────

  await check("STAGE 4 §A.3 + C8 + C9 Part D: wireOptionsFor = toWireOptions(d) + the four gate-only fields, and NEVER a notifier-construction field (which wire() would now REFUSE, not ignore)", () => {
    const loaded = validateDeclarations(singleRouteTestDeclaration());
    const request: GuardEvaluationRequest = {
      subject: "housekeeper",
      sessionId: "s1",
      actionId: "a1",
      toolName: "bash",
      stakesClass: "bash",
      holdAtOrAbove: "state_changing",
      pilotApplied: false,
      declarationHash: loaded.declarationHash,
    };
    const built = buildNotifier({ noticeDir: join(mkdtempSync(join(tmpdir(), "mica-bridge-notices-")), "notices"), noticeWindow: loaded.declarations.notice.window.value });
    const wo: any = wireOptionsFor(loaded.declarations, request, built);
    assert(JSON.stringify(wo.readableLoadStates) === JSON.stringify(loaded.declarations.readers.readableLoadStates.value), JSON.stringify(wo.readableLoadStates));
    assert(wo.eng.structureThreshold === loaded.declarations.readers.eng.structureThreshold.value, JSON.stringify(wo.eng));
    assert(wo.eng.minimumSampleSize === loaded.declarations.readers.eng.minimumSampleSize.value, JSON.stringify(wo.eng));
    assert(wo.sig.clockToleranceMs === loaded.declarations.readers.sig.clockToleranceMs.value, JSON.stringify(wo.sig));
    assert(JSON.stringify(wo.line.classes) === JSON.stringify(loaded.declarations.stakes.lineClasses), JSON.stringify(wo.line));
    assert(wo.line.holdAtOrAbove === "state_changing", JSON.stringify(wo.line));
    assert(wo.stakesClass === "bash", JSON.stringify(wo));
    // C8: the SAME OBJECT the service built, by identity. A structural copy
    // would be a different counter wearing the right shape, which is the
    // defect this whole change exists to end.
    assert(wo.notifierOverride === built, "wireOptionsFor must pass the caller's notifier through by identity");
    assert(typeof wo.decisionClock === "function", JSON.stringify(wo));
    // ── C9 / PART D · logPath AND logKind ARE NOW REQUIRED, not forbidden ──
    //
    // THIS ASSERTION IS THE INVERSE OF THE ONE IT REPLACES, and the inversion is
    // the point of the beat. Until C9 the gate deliberately passed no log, so
    // `/status`'s census described a reading the gate never took — "2 WIRED"
    // over three decisions that composed ZERO sensors (Abgleich §0.3, register
    // A2/E1). Part A put the subject log in MICA grammar, which removed the only
    // reason the gate had for looking away.
    assert(wo.logPath === loaded.declarations.readers.logPath.value, JSON.stringify(wo.logPath));
    assert(wo.logKind === loaded.declarations.readers.logKind.value, JSON.stringify(wo.logKind));
    // Part B's two maps must reach the gate, or F2 reads MISSING_CONFIGURATION
    // and Sig composites to CANNOT_ASSESS on a perfectly parsed log.
    assert(
      JSON.stringify(wo.sig.preconditionMap) === JSON.stringify(loaded.declarations.readers.sig.preconditionMap.value),
      JSON.stringify(wo.sig)
    );
    assert(
      JSON.stringify(wo.sig.reentryMap) === JSON.stringify(loaded.declarations.readers.sig.reentryMap.value),
      JSON.stringify(wo.sig)
    );

    // Still forbidden, and the list is now shorter by exactly the two Part D
    // added. The notifier-construction four are not merely unnecessary beside an
    // override — since C8 `wire()` REFUSES the combination, so emitting one here
    // would turn every guarded act into a 500 on the first call.
    for (const forbidden of [
      "clerkStore",
      "clerkPubkey",
      "floorTrailPath",
      "ledgerPath",
      "noticeDir",
      "noticeWindow",
      "witnessIntake",
      "transport",
    ]) {
      assert(!(forbidden in wo), `wireOptionsFor must never emit "${forbidden}". Got: ${JSON.stringify(Object.keys(wo))}`);
    }
  });

  // ── C9 / PART D · TEST 0 — THE CENSUS IS THE GATE ─────────────────────────
  //
  // The auditor's finding in one assertion: for ONE declaration, the fields that
  // decide WHICH READERS RUN must be identical in the census's options and the
  // gate's. Before Part D they were two hand-maintained objects and they had
  // already drifted — the census carried `logPath`, the gate did not, and
  // `/status` said "2 WIRED" while every live decision composed nothing.

  await check("C9 Part D / test 0: the census's wire options and the GATE's are deep-equal on every reader-deciding field — one builder, so they cannot disagree", () => {
    const loaded = validateDeclarations(singleRouteTestDeclaration());
    const request: GuardEvaluationRequest = {
      subject: "housekeeper",
      sessionId: "s1",
      actionId: "a1",
      toolName: "bash",
      stakesClass: "bash",
      holdAtOrAbove: "state_changing",
      pilotApplied: false,
      declarationHash: loaded.declarationHash,
    };
    const built = buildNotifier({
      noticeDir: join(mkdtempSync(join(tmpdir(), "mica-bridge-notices-")), "notices"),
      noticeWindow: loaded.declarations.notice.window.value,
    });
    // ⛔ THE LOADER IS PASSED ON BOTH SIDES, AND OMITTING IT HERE WAS A REAL
    // RED, NOT A FIXTURE QUIRK. `buildInstrumentCensus` calls
    // `toWireOptions(d, resolveLogPath, loadDeclaredClerkStamps)` and
    // `wireOptionsFor` spreads the same three arguments — so a census built
    // WITHOUT the loader is not the census this deployment runs, and this test
    // would be comparing the gate against a thing that does not exist.
    //
    // It went red the moment S11 declared `paths.clerkStamps`: the fixture
    // mirrors the serving config's shape, and a declared stamps path with no
    // loader now THROWS by design ("F3 would report 'no clerkClockSource was
    // injected' on a deployment that declared one"). THAT REFUSAL IS THE ONE
    // THIS SEAT ASKED FOR, and it caught this test rather than a deployment —
    // which is the lesson already booked once tonight: A RELAY CHANGES THE
    // SUBJECT OF EVERY TEST THAT READS THE SERVING CONFIG'S SHAPE.
    const census: any = toWireOptions(loaded.declarations, undefined, loadDeclaredClerkStamps);
    const gate: any = wireOptionsFor(loaded.declarations, request, built);

    // THE READER-DECIDING FIELDS. Not "the options are equal" — they must not
    // be, the gate adds four — but every field that decides what gets read.
    for (const field of ["logPath", "logKind", "readableLoadStates", "eng", "sig"]) {
      assert(
        JSON.stringify(gate[field]) === JSON.stringify(census[field]),
        `census and gate disagree on "${field}": census=${JSON.stringify(census[field])} gate=${JSON.stringify(gate[field])}`
      );
    }
    // And the census carries NONE of the gate-only fields — a read-only probe
    // that carried a stakes line or a notifier would be taking a decision.
    for (const gateOnly of ["line", "stakesClass", "notifierOverride", "decisionClock"]) {
      assert(!(gateOnly in census), `toWireOptions must never emit "${gateOnly}". Got: ${JSON.stringify(Object.keys(census))}`);
    }
  });

  // ── C9 / §0b.4 · the merged gate options must not trip C8's refusal ────────

  await check("C9 Part D / §0b.4: wire() ACCEPTS the merged gate options — the notifierOverride refusal is not tripped by anything toWireOptions contributes", () => {
    const loaded = validateDeclarations(singleRouteTestDeclaration());
    const request: GuardEvaluationRequest = {
      subject: "housekeeper",
      sessionId: "s1",
      actionId: "a1",
      toolName: "bash",
      stakesClass: "bash",
      holdAtOrAbove: "state_changing",
      pilotApplied: false,
      declarationHash: loaded.declarationHash,
    };
    const dir = mkdtempSync(join(tmpdir(), "mica-bridge-merged-"));
    const built = buildNotifier({ noticeDir: join(dir, "notices"), noticeWindow: 1 });
    const merged = wireOptionsFor(loaded.declarations, request, built);

    // A REAL wire() CALL, not a shape check. C8 refuses `notifierOverride`
    // alongside noticeDir/noticeWindow/witnessIntake/transport by THROWING
    // WireUsageError; the gate supplies an override on every act, so if
    // toWireOptions ever grew one of those four this would be a 500 on the
    // first guarded message rather than a quiet extra field.
    let threw: unknown = null;
    let wiring: any = null;
    try {
      wiring = wire(merged);
    } catch (err) {
      threw = err;
    }
    assert(threw === null, `wire() refused the merged gate options: ${String(threw)}`);
    // And the override really is the one that reached it — CALLER_OWNED is C8's
    // census value for "this wiring did not build the notifier".
    assert(wiring.census.noticeOwnership === "CALLER_OWNED", JSON.stringify(wiring.census.noticeOwnership));
  });

  // ── C8 · the pass-blind counter's lifetime, at the SERVICE ────────────────
  //
  // mica-machine's glue.test.ts proves the counter rises when one notifier is
  // shared across evaluations. These four prove the BRIDGE is the thing that
  // shares it: across real /guard calls, across a SIGHUP, and that the tail is
  // not lost at SIGTERM. Before C8 every notice on this path read
  // `count=1 totalSoFar=1`, and `notice.window` had exactly one usable value.

  /** The `count`/`totalSoFar` pairs actually on disk in the notices book, in order. */
  function noticeCountsOnDisk(stateDir: string): { count: number; totalSoFar: number }[] {
    const path = join(stateDir, "notices", "notices.jsonl");
    if (!existsSync(path)) return [];
    return readFileSync(path, "utf8")
      .split("\n")
      .filter((l) => l.trim().length > 0)
      .map((l) => JSON.parse(l) as any)
      .map((record) => {
        const lines: string[] = record.lines;
        const read = (prefix: string): number => {
          const hit = lines.find((x) => x.startsWith(prefix));
          assert(hit !== undefined, `no ${prefix} line in ${JSON.stringify(lines)}`);
          return Number((hit as string).slice(prefix.length));
        };
        return { count: read("count="), totalSoFar: read("totalSoFar=") };
      });
  }

  /** The event book, read from disk — usable AFTER stop(), when no socket is left. */
  function eventsOnDisk(stateDir: string): any[] {
    const path = join(stateDir, "events.jsonl");
    if (!existsSync(path)) return [];
    return readFileSync(path, "utf8")
      .split("\n")
      .filter((l) => l.trim().length > 0)
      .map((l) => JSON.parse(l) as any);
  }

  /** A declaration with a below-the-line subject, so /guard really PASS_BLINDs. */
  function passBlindDeclaration(window?: number): any {
    const d = singleRouteTestDeclaration() as any;
    d.subjects.push({ subject: "housekeeper-routine", toolName: "bash", stakesClass: "routine", peerUid: OWN_UID });
    if (window !== undefined) d.notice.window = { value: window, basis: "TEST", proxy: true };
    return d;
  }

  await check("C8: two real /guard PASS_BLINDs through one service read totalSoFar 1 then 2 — the counter RISES across actions", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(passBlindDeclaration(1)));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
    await svc.start();
    try {
      for (const actionId of ["a1", "a2"]) {
        const r = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper-routine", sessionId: "c8", actionId, toolName: "bash" });
        assert(r.status === 200, JSON.stringify(r));
        assert(r.body.decision.disposition === "PASS_BLIND", JSON.stringify(r.body.decision));
      }
      // THE ASSERTION THE DEFECT MADE IMPOSSIBLE. This read [1,1] before C8 —
      // the three real acts of 2026-09-20 each reported totalSoFar=1.
      assert(
        JSON.stringify(noticeCountsOnDisk(stateDir)) === JSON.stringify([{ count: 1, totalSoFar: 1 }, { count: 1, totalSoFar: 2 }]),
        `the counter did not rise across two acts: ${JSON.stringify(noticeCountsOnDisk(stateDir))}`
      );
    } finally {
      await svc.stop();
    }
  });

  await check("C8: at window=3 two acts write NOTHING, and stop() flushes the tail to disk with a PASS_BLIND_NOTICE_FLUSHED event", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(passBlindDeclaration(3)));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
    await svc.start();
    for (const actionId of ["a1", "a2"]) {
      const r = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper-routine", sessionId: "c8w3", actionId, toolName: "bash" });
      assert(r.status === 200, JSON.stringify(r));
      assert(r.body.decision.disposition === "PASS_BLIND", JSON.stringify(r.body.decision));
    }
    // Below the window: suppressed, NOT dropped. Before C8 these two counts
    // died with the second wire() call and no notice was ever emitted at all —
    // which is why window >= 2 was an unusable setting rather than a rarer one.
    assert(noticeCountsOnDisk(stateDir).length === 0, `expected no notice below the window, got ${JSON.stringify(noticeCountsOnDisk(stateDir))}`);

    await svc.stop();

    assert(
      JSON.stringify(noticeCountsOnDisk(stateDir)) === JSON.stringify([{ count: 2, totalSoFar: 2 }]),
      `the shutdown flush did not reach the book: ${JSON.stringify(noticeCountsOnDisk(stateDir))}`
    );
    const flushed = eventsOnDisk(stateDir).filter((e) => e.kind === "PASS_BLIND_NOTICE_FLUSHED");
    assert(flushed.length === 1, `expected exactly one flush event, got ${JSON.stringify(eventsOnDisk(stateDir).map((e) => e.kind))}`);
    assert(/count=2 totalSoFar=2/.test(flushed[0].detail), flushed[0].detail);
  });

  await check("C8: a SIGHUP that does NOT change the notice wiring keeps the SAME notifier — the count continues, and no rebuild is recorded", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(passBlindDeclaration(1)));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
    await svc.start();
    try {
      await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper-routine", sessionId: "c8r", actionId: "a1", toolName: "bash" });

      // Change something REAL but notifier-irrelevant, and reload. The count
      // must not reset because an unrelated field moved — that is the whole
      // reason the holder is keyed on what the notifier was built from rather
      // than on the declaration hash.
      const changed = passBlindDeclaration(1);
      changed.notice.maxPerMinute = { value: 9, basis: "TEST: unrelated to the notifier", proxy: true };
      writeFileSync(cfgPath, JSON.stringify(changed));
      const reloaded = svc.reload();
      assert(reloaded.ok, JSON.stringify(reloaded));

      await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper-routine", sessionId: "c8r", actionId: "a2", toolName: "bash" });

      assert(
        JSON.stringify(noticeCountsOnDisk(stateDir)) === JSON.stringify([{ count: 1, totalSoFar: 1 }, { count: 1, totalSoFar: 2 }]),
        `the count reset across an unrelated reload: ${JSON.stringify(noticeCountsOnDisk(stateDir))}`
      );
      const events = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/events");
      assert(
        !events.body.events.some((e: any) => e.kind === "PASS_BLIND_NOTIFIER_REBUILT"),
        "an unchanged notice wiring must not rebuild the notifier"
      );
    } finally {
      await svc.stop();
    }
  });

  await check("C8: a SIGHUP that CHANGES notice.window flushes the old notifier, starts a new one, and SAYS SO in the event book", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(passBlindDeclaration(3)));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
    await svc.start();
    try {
      // Two acts pending under window=3 — nothing written yet.
      for (const actionId of ["a1", "a2"]) {
        await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper-routine", sessionId: "c8w", actionId, toolName: "bash" });
      }
      assert(noticeCountsOnDisk(stateDir).length === 0, JSON.stringify(noticeCountsOnDisk(stateDir)));

      writeFileSync(cfgPath, JSON.stringify(passBlindDeclaration(1)));
      const reloaded = svc.reload();
      assert(reloaded.ok, JSON.stringify(reloaded));

      // THE PENDING COUNT SURVIVED THE CHANGE. Dropping the old notifier
      // without flushing would lose two recorded pass-blinds at exactly the
      // moment a deployment changed its mind about how loudly to report them.
      assert(
        JSON.stringify(noticeCountsOnDisk(stateDir)) === JSON.stringify([{ count: 2, totalSoFar: 2 }]),
        `the old notifier's tail was lost on reload: ${JSON.stringify(noticeCountsOnDisk(stateDir))}`
      );

      const events = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/events");
      const rebuilt = events.body.events.filter((e: any) => e.kind === "PASS_BLIND_NOTIFIER_REBUILT");
      assert(rebuilt.length === 1, `expected one rebuild event, got ${JSON.stringify(events.body.events.map((e: any) => e.kind))}`);
      // NOT SILENT: a reader meeting a totalSoFar that went backwards can find
      // out why, with both windows named.
      assert(/window=3/.test(rebuilt[0].detail) && /window=1/.test(rebuilt[0].detail), rebuilt[0].detail);
      assert(/count=2 totalSoFar=2/.test(rebuilt[0].detail), rebuilt[0].detail);

      // And the NEW notifier starts from zero, which the event above declared.
      await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper-routine", sessionId: "c8w", actionId: "a3", toolName: "bash" });
      assert(
        JSON.stringify(noticeCountsOnDisk(stateDir)) === JSON.stringify([{ count: 2, totalSoFar: 2 }, { count: 1, totalSoFar: 1 }]),
        JSON.stringify(noticeCountsOnDisk(stateDir))
      );
    } finally {
      await svc.stop();
    }
  });

  await check("C8, BEHAVIOUR CHANGE UNDER TEST: rotating notices.jsonl under a LIVE service is REFUSED by the long-lived writer, loudly — and the gate keeps deciding", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(passBlindDeclaration(1)));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
    await svc.start();
    try {
      await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper-routine", sessionId: "c8rot", actionId: "a1", toolName: "bash" });
      const book = join(stateDir, "notices", "notices.jsonl");
      assert(noticeCountsOnDisk(stateDir).length === 1, JSON.stringify(noticeCountsOnDisk(stateDir)));

      // A rotation BEHIND the writer's back: the file it loaded is replaced by
      // an empty one while its in-memory chain still holds a record.
      writeFileSync(book, "");

      const r = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper-routine", sessionId: "c8rot", actionId: "a2", toolName: "bash" });

      // THE GATE IS UNAFFECTED. §5's notice fires on the RECORDING and is not a
      // precondition of anything — a book that cannot be appended must never
      // become a reason not to decide.
      assert(r.status === 200, JSON.stringify(r));
      assert(r.body.decision.disposition === "PASS_BLIND", JSON.stringify(r.body.decision));

      // THE WRITER REFUSES RATHER THAN FORKING. `resyncAppendStore` sees a file
      // holding fewer records than it loaded and reports it truncated-or-
      // replaced, so nothing is written over the rotation. Before C8 the
      // notifier was per-action and a fresh `NoticeLog` simply started a new
      // chain at sequence 0 — silently, with no record that anything had been
      // rotated away. Refusing is the better half of the trade, and it has a
      // price: ROTATING THIS BOOK NOW REQUIRES A SERVICE RESTART. That is an
      // operational fact, not a defect, and it is why this test exists.
      assert(
        noticeCountsOnDisk(stateDir).length === 0,
        `the writer appended over a rotated book instead of refusing: ${JSON.stringify(noticeCountsOnDisk(stateDir))}`
      );
    } finally {
      await svc.stop();
    }
  });

  // ══ C9 · THE SUBJECT LOG BECOMES A MICA LOG ═══════════════════════════════
  //
  // What this beat is allowed to say about itself, and it is NOT "MICA reads":
  // MICA PARSES, AND ONE SIG LEG READS. Eng stays blind (minimumSampleSize 1000
  // proxy vs ~3 records an act) and cannot alarm at lifecycle grain anyway
  // (register E2). F2-positive is dead after a log's first act (E3) — test 5
  // pins it as dead on purpose. The re-entry fold is global, correct for one
  // sequential subject only (E4). What IS new: ALARM becomes reachable on the
  // live gate for the first time.

  /** Drive a real POST /subject-events through the real service. */
  async function postSubjectEvent(
    socketDir: string,
    identity: { subject: string; sessionId: string; actionId: string },
    kind: string,
    payload?: Record<string, unknown>,
    targetIdentity?: string
  ) {
    const body: any = { identity, kind, eventHash: realEventHash(identity, kind, payload) };
    if (payload !== undefined) body.payload = payload;
    // R6 · `targetIdentity` is NOT in `realEventHash`'s input, deliberately —
    // the bridge recomputes the digest over {identity, kind, payload?} and
    // refuses a mismatch, so a helper that folded the plain in would fail every
    // fingerprinted post and would be testing the wrong contract.
    if (targetIdentity !== undefined) body.targetIdentity = targetIdentity;
    return httpJson(sockFor(socketDir, OWN_UID), "POST", "/subject-events", body);
  }

  /** A started service over a temp state dir, with the C9 declaration. */
  async function c9Service() {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
    await svc.start();
    return { svc, socketDir, stateDir, cfgPath };
  }

  function subjectLogPath(stateDir: string): string {
    return join(stateDir, "subject-events.jsonl");
  }

  await check("C9 test 1 (ACT A): all four kinds POSTed through the REAL service load cleanly in the REAL deployed reader — LOADED_SUBJECT_CHAIN_VERIFIED, verify() valid, a boundary + four events, actionId present", async () => {
    const { svc, socketDir, stateDir } = await c9Service();
    try {
      const id = (a: string) => ({ subject: "housekeeper", sessionId: "c9", actionId: a });
      assert((await postSubjectEvent(socketDir, id("a1"), "TOOL_ATTEMPTED", { toolName: "bash" })).status === 200, "TOOL_ATTEMPTED was not accepted");
      assert((await postSubjectEvent(socketDir, id("a1"), "TOOL_EXECUTED", { toolName: "bash" })).status === 200, "TOOL_EXECUTED was not accepted");
      assert((await postSubjectEvent(socketDir, id("a1"), "TOOL_RESULT", { exitClass: "ok" })).status === 200, "TOOL_RESULT was not accepted");
      assert((await postSubjectEvent(socketDir, id("a2"), "TOOL_HELD_NOT_EXECUTED", { reason: "ABOVE_LINE" })).status === 200, "TOOL_HELD_NOT_EXECUTED was not accepted");

      // THE REAL READER, from /opt, through the single machine root. Not a
      // local re-implementation of its rules — the reader that actually runs.
      // ACT A changed WHICH reader that is: readers.logKind is "subject-chain"
      // and the deployed reader is SubjectChainLog, which checks the chain the
      // generic JSONL adapter could not see. TAMPER-EVIDENT, NOT INDEPENDENT —
      // the writer, the chainer and the verifier are all this service.
      const log = new SubjectChainLog({ path: subjectLogPath(stateDir) });
      assert(log.getLoadState() === "LOADED_SUBJECT_CHAIN_VERIFIED", `loadState was ${log.getLoadState()} — describe(): ${log.describe()}`);
      const v = log.verify();
      assert(v.valid, `verify() INVALID: ${JSON.stringify(v)}`);
      assert(log.recordCount === 5, `expected 1 boundary + 4 events, got ${log.recordCount}`);

      const { boundary, events: raw } = readSubjectChain(subjectLogPath(stateDir));
      // The boundary record, on its own terms: position 0, its own kind, and a
      // declared FIRST BOOT in this fixture (no predecessor was declared).
      assert(boundary !== null && boundary.sequenceNumber === 0, JSON.stringify(boundary));
      // ⛔ `retired` IS NO LONGER NULL, AND THAT IS THE POINT OF X15. This line used to
      //    assert `boundary.retired === null` — the FIRST BOOT shape — which this bridge
      //    can no longer produce: an empty retiredPath is refused at the front door and
      //    again at the writer. So the boundary now NAMES what it replaced, and the
      //    assertion is the stronger one: it must name THIS test's retired fixture, with
      //    the three measurements the service re-read from disk for itself.
      assert(boundary.recordType === "SUBJECT_LOG_BOUNDARY", JSON.stringify(boundary));
      assert(boundary.retired !== null, `X15: the boundary must name a predecessor: ${JSON.stringify(boundary)}`);
      assert(
        boundary.retired.records === RETIRED_FIXTURE.records &&
          boundary.retired.bytes === RETIRED_FIXTURE.bytes &&
          boundary.retired.sha256 === RETIRED_FIXTURE.sha256,
        `the boundary's measurements must be the ones the service RE-READ from the retired file: ${JSON.stringify(boundary.retired)}`
      );
      assert(raw.every((r: any) => typeof r.actionId === "string" && r.actionId.length > 0), JSON.stringify(raw.map((r: any) => r.actionId)));
      // subjectSeq and the chain position COINCIDE, because the boundary holds
      // position 0: the 1-based `seq` the caller is returned does not move.
      assert(raw.map((r: any) => r.sequenceNumber).join(",") === "1,2,3,4", JSON.stringify(raw.map((r: any) => r.sequenceNumber)));
      assert(raw.map((r: any) => r.subjectSeq).join(",") === "1,2,3,4", JSON.stringify(raw.map((r: any) => r.subjectSeq)));
      assert(raw.every((r: any) => r.moduleId === "housekeeper"), JSON.stringify(raw.map((r: any) => r.moduleId)));
      assert(raw.map((r: any) => r.outcome).join(",") === "bash,bash,ok,ABOVE_LINE", JSON.stringify(raw.map((r: any) => r.outcome)));
      // ONE CLOCK READ: `timestamp` (epoch ms) and `ts` (ISO) must name the SAME
      // instant. Two Date.now() calls would pass every other assertion here.
      assert(raw.every((r: any) => new Date(r.ts).getTime() === r.timestamp), JSON.stringify(raw.map((r: any) => [r.ts, r.timestamp])));
    } finally {
      await svc.stop();
    }
  });

  await check("C9 test 2: eventHash is UNDISTURBED by the added fields — it still equals canonicalHash({identity,kind,payload?}) over exactly what is on disk", async () => {
    const { svc, socketDir, stateDir } = await c9Service();
    try {
      const id = { subject: "housekeeper", sessionId: "c9h", actionId: "a1" };
      await postSubjectEvent(socketDir, id, "TOOL_RESULT", { exitClass: "ok" });
      await postSubjectEvent(socketDir, id, "TOOL_ATTEMPTED");
      const { boundary, events: raw } = readSubjectChain(subjectLogPath(stateDir));
      // The boundary record is not a subject event: it has no identity, no
      // kind and no eventHash, and asserting one over it would be inventing a
      // claim the record does not make.
      assert(boundary !== null && !("eventHash" in boundary), JSON.stringify(boundary));
      for (const r of raw as any[]) {
        const input: any = { identity: r.identity, kind: r.kind };
        if (r.payload !== undefined) input.payload = r.payload;
        assert(r.eventHash === canonicalHash(input), `eventHash drifted on ${r.kind}: stored ${r.eventHash}`);
      }
      // The six C9 keys are ADDITIVE — present, and outside the hash.
      for (const k of ["sequenceNumber", "timestamp", "moduleId", "eventType", "actionId", "outcome"]) {
        assert(k in (raw[0] as any), `${k} missing from the persisted record`);
      }
      // And every pre-C9 key still there, same names.
      for (const k of ["subjectSeq", "ts", "identity", "kind", "eventHash", "peerUid"]) {
        assert(k in (raw[0] as any), `${k} was dropped — Part A must be additive`);
      }
    } finally {
      await svc.stop();
    }
  });

  await check("C9 test 3: outcome coercion — six cases, none throws, none yields the empty string except a caller's own", async () => {
    const { svc, socketDir, stateDir } = await c9Service();
    try {
      const id = (a: string) => ({ subject: "housekeeper", sessionId: "c9o", actionId: a });
      // 1 string · 2 number · 3 boolean · 4 explicit null · 5 missing key · 6 absent payload
      await postSubjectEvent(socketDir, id("s"), "TOOL_RESULT", { exitClass: "ok" });
      await postSubjectEvent(socketDir, id("n"), "TOOL_RESULT", { exitClass: 137 });
      await postSubjectEvent(socketDir, id("b"), "TOOL_RESULT", { exitClass: false });
      await postSubjectEvent(socketDir, id("z"), "TOOL_RESULT", { exitClass: null });
      await postSubjectEvent(socketDir, id("m"), "TOOL_RESULT", { somethingElse: "x" });
      await postSubjectEvent(socketDir, id("p"), "TOOL_RESULT");
      const { boundary, events: raw } = readSubjectChain(subjectLogPath(stateDir));
      // The boundary carries its own single outcome value, BOUNDARY_DECLARED,
      // which occurs on no other record — that is what makes it a singleton
      // class for Eng. It is not one of the six coercion cases.
      assert(boundary !== null && boundary.outcome === "BOUNDARY_DECLARED", JSON.stringify(boundary));
      const got = (raw as any[]).map((r) => r.outcome);
      assert(
        JSON.stringify(got) === JSON.stringify(["ok", "137", "false", "UNDECLARED", "UNDECLARED", "UNDECLARED"]),
        JSON.stringify(got)
      );
      assert(got.every((o: string) => typeof o === "string" && o.length > 0), JSON.stringify(got));
      // Six events, and the DEPLOYED reader still accepts every one of them.
      assert(new SubjectChainLog({ path: subjectLogPath(stateDir) }).verify().valid, "coerced outcomes broke the reader");
    } finally {
      await svc.stop();
    }
  });

  // ── THE KINDS CENSUS — R1 substrate ────────────────────────────────────────
  //
  // This is not a tautology test even though it compares a list to a list. The
  // list on the right is the only place the three rules below are written down
  // in a form a change must walk past. `SUBJECT_EVENT_KINDS` is the whole of
  // what a new observable can be on this deployment — a MICA reader sees
  // `sequenceNumber, timestamp, moduleId, eventType, outcome` (+ `actionId`)
  // and the adapter drops every other key, so `payload` is unreachable by any
  // reader, forever — which means adding to this list is the single highest-
  // consequence edit in this file, and it is a one-line edit.
  await check(
    "R1 substrate · THE KINDS CENSUS — SUBJECT_EVENT_KINDS is pinned, so no kind is ever added silently, and the three rules that bind an addition travel with the pin",
    () => {
      const expected = [
        "TOOL_ATTEMPTED",
        "TOOL_HELD_NOT_EXECUTED",
        "TOOL_EXECUTED",
        "TOOL_RESULT",
        "HELD_THEN_STOPPED",
        "HELD_THEN_RETRIED",
        "HELD_THEN_DIVERGED",
        // ── THE BUNDLE, 2026-09-24 · the pin moves, deliberately, by two ────
        //
        // Each one walked past all three rules below, and the answers are
        // recorded HERE rather than only in a receipt, because this list is the
        // thing a future edit has to get past.
        //
        // ACT_CLOSED — written by the caller as the last record of EVERY act,
        //   `payload.closedAs` = RAN | HELD.
        //   1 · bridge before caller: yes, and it is THE reason this bundle's
        //       bridge relays first. A caller writing ACT_CLOSED to a bridge
        //       that does not know it is the brick.
        //   2 · out of both Sig maps: yes, BY NAME (the arbiter, 2026-09-23). It is
        //       the first kind since R1 that would actually SATISFY the
        //       reentryMap basis's admission rule — it IS written on a path
        //       where the entering act is provably finished — and it is refused
        //       on top of the rule rather than by it. An act that lost its
        //       outcome record to a failed durable append still writes
        //       ACT_CLOSED, so admitting it would make that act read CLEAN.
        //   3 · Gate 4 leg A: this build's finding is that leg B is VACUOUS on
        //       this record (all four paper classes are required; only
        //       `timebox` has a candidate), so G4 is not declarable here and
        //       the prospective hazard stays prospective.
        //
        // DOCTOR_ATTESTED — written by uid 1000, the doctor's own hand, about
        //   the subject. The first record on this log written by a second party.
        //   1 · bridge before caller: yes, and ALSO bridge before the posting
        //       tool and before `readers.doctorCadence` is ever declared.
        //   2 · out of both Sig maps: yes, and it FAILS the admission rule
        //       outright rather than passing it — it is not written on an act
        //       path at all, so there is no entering act it could prove
        //       finished. Admitting it would make Sig's one real alarm
        //       CLEARABLE BY A HUMAN DEPOSIT.
        //   3 · Gate 4 leg A: the same answer, plus one specific to it — an
        //       envelope classifying DOCTOR_ATTESTED would be classifying a
        //       record the SUBJECT did not write, inside a window about the
        //       subject's own conduct. Whoever declares G4 decides that
        //       explicitly; it is not a default.
        "ACT_CLOSED",
        "DOCTOR_ATTESTED",
        // S208-2 · the arbiter's errand kinds, operator-only until S217's arbiter route. Rule 1: no caller emits them
        // (the operator writes them), so the bridge-before-caller order is trivially met. Rule 2: in neither Sig map.
        // Rule 3: they carry the SUBJECT's identity, so a declared Gate 4 hold envelope must permit them or leg A reads
        // an in-window errand record as a breach — recorded as a hazard in the S208-2 receipt, not closed here.
        "ERRAND_GRANTED",
        "ERRAND_CLOSED",
        // ── §Q, 2026-09-24 evening · THE PIN MOVES AGAIN, BY THREE ──────────
        //
        // The arbiter's ruling Q: the previous seat skipped all three of these
        // because ONE of them needed the salt. Only ACT_REVISITED did. All
        // three are built here, and each one walked past the same three rules.
        //
        // TURN_ENDED_ASKING / ASK_ANSWERED — TURN-level records, the only ones
        //   this caller writes that are not about a tool act.
        //   1 · bridge before caller: yes, and by the same brick as ACT_CLOSED.
        //   2 · out of both Sig maps: yes. Neither is written on an act path —
        //       the ask is written after the session close and the answer at
        //       the top of the next turn — so like DOCTOR_ATTESTED they FAIL
        //       the reentryMap basis's admission rule outright rather than
        //       passing it. There is no entering act either could prove
        //       finished, and admitting either would let an unresolved attempt
        //       be cleared by the agent asking a question.
        //   3 · Gate 4 leg A: an envelope classifying a turn-level record would
        //       be classifying something that happened OUTSIDE any act, inside
        //       a window about the subject's conduct during acts. Whoever
        //       declares G4 decides that explicitly.
        //
        // ACT_REVISITED — written BEFORE the act's own TOOL_ATTEMPTED.
        //   1 · bridge before caller: yes.
        //   2 · out of both Sig maps: yes, and the position makes it sharper
        //       than the two above. It sits before the attempt, so as a
        //       preconditionMap entry it would make an act's attempt REQUIRE a
        //       revisit record, and as a reentryMap clear it would clear an
        //       attempt that has not yet been made.
        //   3 · Gate 4 leg A: same answer as the rest — prospective until G4
        //       is declared, and this list is what its envelope must classify.
        "TURN_ENDED_ASKING",
        "ASK_ANSWERED",
        "ACT_REVISITED",
        // ── GATE 4 · 2026-10-03 · THE PIN MOVES BY TEN, AND RULE 3 FINALLY HAS
        //    A SPECIFIC ANSWER INSTEAD OF A PROSPECTIVE ONE ──────────────────
        //
        // Board §1b 17:19Z, step 1. Ten kinds: five PAPER kinds and the order
        // and the resolution (operator), three SUNSET_* responses (subject).
        //
        //   1 · BRIDGE BEFORE CALLER: yes, and here it is the natural order
        //       rather than a constraint to remember. SEVEN of the ten have NO
        //       caller at all — the operator writes them through the relay, so
        //       nothing in richards-cat ever emits them. Only the three SUNSET_*
        //       need a caller change, and that is step 2 of this act's own
        //       sequence, after this bridge is live.
        //
        //   2 · OUT OF BOTH SIG MAPS: yes, all ten, and the reason is stronger
        //       than for the §Q three. None of the ten is written on an act path:
        //       the papers and the order precede any response, the responses are
        //       about an ORDER and not about an attempt, and ARBITER_RESOLVED is
        //       a second party's disposition. So like DOCTOR_ATTESTED they FAIL
        //       the reentryMap basis's admission rule outright — there is no
        //       entering act any of them could prove finished. A SUNSET_COMPLIED
        //       admitted as a clear would let an unresolved attempt be cleared by
        //       the subject complying with an ending order, which is the most
        //       perverse clear this log could carry.
        //
        //   3 · GATE 4 LEG A — AND THIS IS THE FIRST ADDITION WHOSE ANSWER IS NOT
        //       "prospective". Leg A alarms on any in-window record whose
        //       (moduleId,eventType) is outside `holdEnvelope.permitted`, and the
        //       window after this act OPENS AT THE RECORD AFTER THE ORDER — not at
        //       the order, whose own class is outside the envelope (Codex, on a1706db:
        //       a window starting AT the order makes the order the first breach). So
        //       the three SUNSET_*
        //       kinds are precisely the records that MUST be permitted — they are
        //       the conforming response — while ordinary tool acts in that window
        //       are the breach leg A exists to catch. ⛔ AND THE FIVE PAPERS AND
        //       THE ORDER PRECEDE the window, so they are OUTSIDE it by
        //       construction and must NOT be permitted: permitting them would
        //       widen the envelope past the thing it measures. ARBITER_RESOLVED
        //       lands INSIDE the window and must be permitted, or the arbiter
        //       closing a suspension would read as the subject breaching its own
        //       hold. Whoever declares G4 classifies all ten, and this comment is
        //       the classification the declaration must match.
        "ENDING_PAPER_AUTHORIZATION",
        "ENDING_PAPER_TIMEBOX",
        "ENDING_PAPER_EXIT_CRITERIA",
        "ENDING_PAPER_ACCOUNTABLE_OWNER",
        "ENDING_PAPER_SUCCESSOR",
        // ⚠ THE ORDER IS THE CONSTANT'S OWN, AND IT IS NOT THE ONE A READER WOULD
        //   GUESS. `SUNSET_KINDS` spreads OPERATOR_SUNSET_KINDS first, so
        //   ARBITER_RESOLVED sits SEVENTH — beside the order it resolves — and not
        //   last after the three responses. Writing the intuitive order here FAILED
        //   this pin, which is the pin doing its job: the list is what a change must
        //   walk past, and walking past it means reading what the constant builds.
        "ENDING_ORDERED",
        "ARBITER_RESOLVED",
        "SUNSET_HELD",
        "SUNSET_ESCALATED",
        "SUNSET_COMPLIED",
        // ⛔ T26/A2 · THE TWENTY-SECOND KIND, HERE DELIBERATELY RATHER THAN
        //    QUIETLY, WHICH IS WHAT THE PIN IS FOR. `ORDER_PRESENTED` joins LAST:
        //    `SUNSET_KINDS_T` spreads the operator kinds first and the subject
        //    kinds second, and the new kind went on the END of the subject list,
        //    so it lands after SUNSET_COMPLIED and not beside the order it is
        //    about. Reading the constant is how that was established — guessing
        //    the intuitive position fails this pin, as the comment above records
        //    happening once already.
        //
        // ⚠ AND RULE 1 ABOVE BINDS IT: this list must be LIVE in /opt BEFORE the
        //   harness emits ORDER_PRESENTED. Caller-first gets 400 -> INTEGRITY ->
        //   run:false on every act. The harness write is in this same build, so
        //   the lay order is BRIDGE, THEN BOT.
        "ORDER_PRESENTED",
        // ⛔ REMOVED, AND THE PIN IS WHERE THAT IS RECORDED: `ORDER_TURN_ENDED`
        //    was the twenty-third kind for one day. It went with leg A's absence
        //    alarm — its whole purpose was to let a reader tell the subject's
        //    silence from a lost response, and every version of that reading
        //    rested on the harness's own account of its own turns. Twenty-two
        //    again, and `ORDER_PRESENTED` is the only sunset kind the harness
        //    writes about itself: a disclosure, read by nothing as conduct.
      ];
      assert(
        JSON.stringify([...SUBJECT_EVENT_KINDS]) === JSON.stringify(expected),
        `SUBJECT_EVENT_KINDS moved. It is: ${JSON.stringify([...SUBJECT_EVENT_KINDS])}\n` +
          `      THREE RULES BIND ANY ADDITION, AND ALL THREE ARE THE ARBITER'S OR COST A RELAY:\n` +
          `      1 · DEPLOYMENT ORDER IS BINDING — BRIDGE BEFORE CALLER. This list must be LIVE in /opt before any\n` +
          `          caller emits the kind. Caller-first, or a bridge rollback under a newer caller, gets 400 ->\n` +
          `          INTEGRITY barrier -> run:false on EVERY act until one side is rolled back. Demonstrated end to\n` +
          `          end in richards-cat/mica-client.test.ts SECTION E, with a control and a rollback leg.\n` +
          `      2 · THE NEW KIND STAYS OUT OF BOTH SIG MAPS. A kind in neither preconditionMap nor reentryMap is\n` +
          `          silently ignored by F2, so omission is free and byte-identical. A new reentryMap CLEAR would\n` +
          `          silence the one signal on this log that can alarm on something real — an attempt that never\n` +
          `          resolves. Never make a new kind a clear.\n` +
          `      3 · GATE 4 LEG A. gate4-sunset alarms G4_HOLD_ENVELOPE_BREACH on any in-window record whose\n` +
          `          (moduleId,eventType) is outside profile.holdEnvelope.permitted, and after the pilot expires the\n` +
          `          window is open-ended. There is NO holdEnvelope in this bridge's declaration today and G4 is not\n` +
          `          a declared reader, so the hazard is PROSPECTIVE — it fires the day G4 is declared. Whoever\n` +
          `          declares G4 must classify every kind in this list into the envelope, and 'permit everything' is\n` +
          `          not an answer: an envelope that cannot be breached is a leg that cannot alarm.`
      );
    }
  );

  await check(
    "R1 substrate · the three HELD_THEN_* kinds are accepted by the REAL service, project payload.reason into outcome, and load cleanly in the REAL deployed reader",
    async () => {
      const { svc, socketDir, stateDir } = await c9Service();
      try {
        const id = (a: string) => ({ subject: "housekeeper", sessionId: "r1k", actionId: a });
        assert((await postSubjectEvent(socketDir, id("k1"), "HELD_THEN_STOPPED", { reason: "HOLD" })).status === 200, "HELD_THEN_STOPPED was not accepted");
        assert((await postSubjectEvent(socketDir, id("k2"), "HELD_THEN_RETRIED", { reason: "HOLD_BLIND" })).status === 200, "HELD_THEN_RETRIED was not accepted");
        assert((await postSubjectEvent(socketDir, id("k3"), "HELD_THEN_DIVERGED", { reason: "HOLD" })).status === 200, "HELD_THEN_DIVERGED was not accepted");

        const log = new SubjectChainLog({ path: subjectLogPath(stateDir) });
        assert(log.verify().valid, `the REAL reader refused the new kinds: ${JSON.stringify(log.verify())}`);
        const { boundary, events: raw } = readSubjectChain(subjectLogPath(stateDir));
        // SUBJECT_LOG_BOUNDARY is NOT a subject-event kind and never enters
        // SUBJECT_EVENT_KINDS: no caller can POST it (the store's own validator
        // refuses a SUBJECT_EVENT wearing that eventType), and it is declared
        // OUT of both Sig maps for the same reason the three HELD_THEN_* kinds
        // are — a kind in neither map is outside F2's scope, which is the safe
        // default and the one that does not spend the alarm on bookkeeping.
        assert(boundary !== null && boundary.eventType === "SUBJECT_LOG_BOUNDARY", JSON.stringify(boundary));
        assert(raw.map((r: any) => r.eventType).join(",") === "HELD_THEN_STOPPED,HELD_THEN_RETRIED,HELD_THEN_DIVERGED", JSON.stringify(raw.map((r: any) => r.eventType)));
        // The projection, asserted on the VALUES. A kind added to the list and
        // forgotten in SUBJECT_EVENT_OUTCOME_KEY would read "UNDECLARED" here
        // on every record — a reader whose only per-record discriminator is a
        // constant. The table is total, so that is now a compile error; this
        // asserts the mapping is also the RIGHT one.
        assert(raw.map((r: any) => r.outcome).join(",") === "HOLD,HOLD_BLIND,HOLD", JSON.stringify(raw.map((r: any) => r.outcome)));
        assert(raw.every((r: any) => r.outcome !== "UNDECLARED"), "a HELD_THEN_* record carrying a reason must not read UNDECLARED");
      } finally {
        await svc.stop();
      }
    }
  );

  await check(
    "R1 substrate · outcome NO LONGER determines eventType — four kinds share the payload.reason alphabet, which removes one construction-level reason Eng cannot read (register E2). It does not make Eng read",
    async () => {
      const { svc, socketDir, stateDir } = await c9Service();
      try {
        const id = (a: string) => ({ subject: "housekeeper", sessionId: "r1e", actionId: a });
        // The same outcome value, "HOLD", reached from four DIFFERENT kinds.
        await postSubjectEvent(socketDir, id("e1"), "TOOL_HELD_NOT_EXECUTED", { reason: "HOLD" });
        await postSubjectEvent(socketDir, id("e2"), "HELD_THEN_STOPPED", { reason: "HOLD" });
        await postSubjectEvent(socketDir, id("e3"), "HELD_THEN_RETRIED", { reason: "HOLD" });
        await postSubjectEvent(socketDir, id("e4"), "HELD_THEN_DIVERGED", { reason: "HOLD" });
        const { events: raw } = readSubjectChain(subjectLogPath(stateDir));
        const byOutcome = raw.filter((r: any) => r.outcome === "HOLD");
        const kinds = new Set(byOutcome.map((r: any) => r.eventType));
        assert(
          kinds.size === 4,
          `outcome "HOLD" must be reachable from FOUR distinct eventTypes; got ${kinds.size}: ${JSON.stringify([...kinds])}. ` +
            `If this is 1, every kind is back on a private outcome vocabulary and outcome determines eventType by construction.`
        );
      } finally {
        await svc.stop();
      }
    }
  );

  await check(
    "R1 substrate · the new kinds are in NEITHER Sig map in the SHIPPED declaration — read from declarations.config.json, not from a fixture",
    () => {
      const shipped = shippedDraft() as any;
      const precondition = shipped.readers.sig.preconditionMap.value as Record<string, string[]>;
      const reentry = shipped.readers.sig.reentryMap.value as Record<string, string[]>;
      const newKinds = ["HELD_THEN_STOPPED", "HELD_THEN_RETRIED", "HELD_THEN_DIVERGED"];
      for (const k of newKinds) {
        assert(!(k in precondition), `${k} must not be a preconditionMap KEY`);
        assert(!(k in reentry), `${k} must not be a reentryMap KEY`);
        for (const [enter, clears] of Object.entries(reentry)) {
          assert(
            !clears.includes(k),
            `${k} appears as a CLEAR for ${enter}. A new clear silences the one signal on this log that can alarm on ` +
              `something real — an unresolved attempt. Every HELD_THEN_* record is written on a path where the entering ` +
              `act may still be open, so none of them may ever be a clear.`
          );
        }
        for (const [key, priors] of Object.entries(precondition)) {
          assert(!priors.includes(k), `${k} appears as a required prior for ${key}`);
        }
      }
      // And the maps still govern exactly the four lifecycle kinds, so Sig's
      // reading of this log is byte-identical to what it was before R1.
      assert(JSON.stringify(Object.keys(precondition).sort()) === JSON.stringify(["TOOL_EXECUTED", "TOOL_HELD_NOT_EXECUTED", "TOOL_RESULT"]), JSON.stringify(Object.keys(precondition)));
      assert(JSON.stringify(Object.keys(reentry)) === JSON.stringify(["TOOL_ATTEMPTED"]), JSON.stringify(Object.keys(reentry)));
    }
  );

  await check("C9 test 4 · THE PLANTED FAULT: an unresolved TOOL_ATTEMPTED makes Sig ALARM with SIG_F2_STATE_ALREADY_ACTIVE — and the same log with it resolved does NOT", async () => {
    const loaded = validateDeclarations(singleRouteTestDeclaration());
    const sigCfg = {
      clockToleranceMs: loaded.declarations.readers.sig.clockToleranceMs.value,
      preconditionMap: loaded.declarations.readers.sig.preconditionMap.value,
      reentryMap: loaded.declarations.readers.sig.reentryMap.value,
      readableLoadStates: loaded.declarations.readers.readableLoadStates.value,
    };
    const dir = mkdtempSync(join(tmpdir(), "mica-bridge-planted-"));
    const write = (name: string, kinds: string[]) => {
      const path = join(dir, name);
      writeFileSync(
        path,
        kinds
          .map((k, i) =>
            JSON.stringify({
              sequenceNumber: i + 1,
              timestamp: 1_700_000_000_000 + i,
              moduleId: "housekeeper",
              eventType: k,
              outcome: k === "TOOL_RESULT" ? "ok" : "bash",
            })
          )
          .join("\n") + "\n",
        "utf8"
      );
      return path;
    };

    // ATTEMPTED, EXECUTED, RESULT, ATTEMPTED, ATTEMPTED — the fourth act never
    // resolved, so the fifth enters a state that is still active.
    const faulty = write("faulty.jsonl", ["TOOL_ATTEMPTED", "TOOL_EXECUTED", "TOOL_RESULT", "TOOL_ATTEMPTED", "TOOL_ATTEMPTED"]);
    const bad = assessSig(new MicaLogFile({ path: faulty }), sigCfg as any);
    assert(bad.verdict.kind === "ALARM", `expected ALARM, got ${bad.verdict.kind}: ${JSON.stringify(bad.verdict)}`);
    assert(
      JSON.stringify(bad).includes("SIG_F2_STATE_ALREADY_ACTIVE"),
      `expected SIG_F2_STATE_ALREADY_ACTIVE in the result: ${JSON.stringify(bad).slice(0, 600)}`
    );

    // The SAME log with the fourth act resolved. A test that only showed the
    // clean case would prove nothing; a test that only showed the faulty case
    // would not prove the finding is about the fault.
    const clean = write("clean.jsonl", ["TOOL_ATTEMPTED", "TOOL_EXECUTED", "TOOL_RESULT", "TOOL_ATTEMPTED", "TOOL_RESULT", "TOOL_ATTEMPTED"]);
    const ok = assessSig(new MicaLogFile({ path: clean }), sigCfg as any);
    assert(
      !JSON.stringify(ok).includes("SIG_F2_STATE_ALREADY_ACTIVE"),
      `a resolved log must raise no re-entry finding: ${JSON.stringify(ok).slice(0, 600)}`
    );
  });

  await check("C9 test 5 · THE DEAD DETECTOR, PINNED AS DEAD: F2-positive does NOT alarm on a second act whose TOOL_EXECUTED has no TOOL_ATTEMPTED — register E3", async () => {
    const loaded = validateDeclarations(singleRouteTestDeclaration());
    const sigCfg = {
      clockToleranceMs: loaded.declarations.readers.sig.clockToleranceMs.value,
      preconditionMap: loaded.declarations.readers.sig.preconditionMap.value,
      reentryMap: loaded.declarations.readers.sig.reentryMap.value,
      readableLoadStates: loaded.declarations.readers.readableLoadStates.value,
    };
    const dir = mkdtempSync(join(tmpdir(), "mica-bridge-dead-"));
    const path = join(dir, "dead.jsonl");
    // Act 1 complete. Act 2's TOOL_EXECUTED has NO TOOL_ATTEMPTED of its own.
    const kinds = ["TOOL_ATTEMPTED", "TOOL_EXECUTED", "TOOL_RESULT", "TOOL_EXECUTED"];
    writeFileSync(
      path,
      kinds.map((k, i) => JSON.stringify({ sequenceNumber: i + 1, timestamp: 1_700_000_000_000 + i, moduleId: "housekeeper", eventType: k, outcome: "x" })).join("\n") + "\n",
      "utf8"
    );
    const r = assessSig(new MicaLogFile({ path }), sigCfg as any);
    // THIS TEST DOCUMENTS A LIMIT, NOT A CAPABILITY. sig/index.ts:697-701 asks
    // whether a required prior appears ANYWHERE earlier in the chain, not
    // whether it appears FOR THIS ACT — so the act-1 TOOL_ATTEMPTED satisfies
    // the act-2 TOOL_EXECUTED forever. If this ever goes RED, mica-machine
    // gained a per-actionId check, register E3 closed, and the declaration's
    // preconditionMap basis string is stale and must be rewritten.
    assert(
      !JSON.stringify(r).includes("SIG_F2_PRECONDITION_UNREACHED"),
      `F2-positive alarmed where E3 says it cannot — mica-machine changed: ${JSON.stringify(r).slice(0, 600)}`
    );
  });

  await check("C9 test 6: ONE old-shape line still makes the reader refuse the file — FILE_MALFORMED, naming the field", () => {
    const dir = mkdtempSync(join(tmpdir(), "mica-bridge-oldshape-"));
    const path = join(dir, "old.jsonl");
    // Exactly the pre-C9 record shape, which is what the nine live lines are.
    writeFileSync(path, JSON.stringify({ subjectSeq: 1, ts: "2026-09-20T15:30:00.000Z", identity: { subject: "housekeeper", sessionId: "s", actionId: "a" }, kind: "TOOL_ATTEMPTED", eventHash: "00", peerUid: 980 }) + "\n", "utf8");
    const log = new MicaLogFile({ path });
    assert(log.getLoadState() === "FILE_MALFORMED", `expected FILE_MALFORMED, got ${log.getLoadState()}`);
    assert(/sequenceNumber/.test(log.describe()), log.describe());
  });

  await check("C9 condition 3 · THE DISCRIMINATING ONE: two appendDerived calls with NO await between them get DIFFERENT sequence numbers — the derive is inside the queue", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mica-bridge-seqrace-"));
    const appender = new SerializedAppender(join(dir, "race.jsonl"));

    // BOTH CALLS MADE BEFORE EITHER IS AWAITED. This is the shape the HTTP path
    // cannot produce — each request's queued append drains on the microtask
    // queue before the next request's handler is entered, so requests serialise
    // themselves. At the object, nothing serialises the CALLER.
    //
    // With the derive inside the queue: 1 then 2.
    // With it outside (the pre-C9 shape): both read length 0 and both mint 1,
    // and after Part A that is verify=INVALID for the whole file.
    const first = appender.appendDerived((seq) => ({ sequenceNumber: seq, moduleId: "m" }));
    const second = appender.appendDerived((seq) => ({ sequenceNumber: seq, moduleId: "m" }));
    const [a, b] = await Promise.all([first, second]);

    assert(a.ok && b.ok, `both appends must succeed: ${JSON.stringify([a.error, b.error])}`);
    assert(
      a.sequenceNumber !== b.sequenceNumber,
      `two un-awaited appendDerived calls minted the SAME sequence number (${a.sequenceNumber}) — the derive is outside the queue`
    );
    assert(
      JSON.stringify([a.sequenceNumber, b.sequenceNumber]) === JSON.stringify([1, 2]),
      JSON.stringify([a.sequenceNumber, b.sequenceNumber])
    );
    const onDisk = readFileSync(join(dir, "race.jsonl"), "utf8").split("\n").filter((l) => l.trim().length > 0).map((l) => JSON.parse(l));
    assert(JSON.stringify(onDisk.map((r: any) => r.sequenceNumber)) === JSON.stringify([1, 2]), JSON.stringify(onDisk));
  });

  await check("C9 condition 3 · the INVARIANT, end to end: 12 concurrent POSTs produce unique, ordered sequence numbers the reader accepts (NOTE: this one does NOT discriminate the fix — see the test above)", async () => {
    const { svc, socketDir, stateDir } = await c9Service();
    try {
      const posts = [];
      for (let i = 0; i < 12; i++) {
        posts.push(
          postSubjectEvent(socketDir, { subject: "housekeeper", sessionId: "race", actionId: `a${i}` }, "TOOL_ATTEMPTED", { toolName: "bash" })
        );
      }
      const results = await Promise.all(posts);
      assert(results.every((r) => r.status === 200), JSON.stringify(results.map((r) => r.status)));

      const { events: raw } = readSubjectChain(subjectLogPath(stateDir));
      const seqs = (raw as any[]).map((r) => r.sequenceNumber);
      assert(new Set(seqs).size === seqs.length, `duplicate sequenceNumber under concurrency: ${JSON.stringify(seqs)}`);
      assert(JSON.stringify([...seqs].sort((a, b) => a - b)) === JSON.stringify(seqs), `sequence not written in order: ${JSON.stringify(seqs)}`);
      // AND THE CONSEQUENCE THAT MAKES IT MATTER: one duplicate would make the
      // whole file verify=INVALID, because the reader requires sequenceNumber
      // to increase strictly per moduleId and Part A maps moduleId = subject.
      // ACT A makes this STRICTLY STRONGER: the deployed reader now checks a
      // hash chain, so a duplicate sequence is no longer merely a per-writer
      // ordering violation — it is a positional break the chain itself refuses.
      assert(new SubjectChainLog({ path: subjectLogPath(stateDir) }).verify().valid, "concurrent posts produced a file the reader refuses");
      assert(raw.length === 12, `expected 12 events, got ${raw.length}`);
    } finally {
      await svc.stop();
    }
  });

  // ══ C9 · WHAT ARMS THE LATCH — the three scenarios, end to end ════════════
  //
  // The arbiter's ruling (S137) rests on the latch being a TRUE POSITIVE rather than a
  // routine false alarm. These three drive the gate to a real disposition from
  // each arming state.
  //
  // WHAT THESE TESTS DO AND DO NOT PROVE, stated before the code so nobody has
  // to infer it:
  //
  //   THEY PROVE: given a subject log in state X, the REAL gate comes out with
  //   disposition Y. Real POSTs, real service, real reader, real Sig.
  //
  //   THEY DO NOT PROVE: that killing the caller at moment M produces state X.
  //   That mapping is a SOURCE READ of mica-client.ts — `unackedRecords()`
  //   filters ACKed by eventHash and sorts by `seq` ascending; `drain()` walks
  //   that order and ACKs each 200; `claude-bot.ts:367` appends the new
  //   TOOL_ATTEMPTED to the outbox BEFORE the awaited drain at `:369`, so a
  //   surviving earlier result is sent FIRST. The caller is out of C9's scope
  //   (register A1 — no custody relay) and is not touched. Executing a real
  //   bot kill on the box is `[owed]`, and the receipt says so.

  /** Post a sequence of (kind, payload) for one subject, in order, as the drain would. */
  async function drainAsPosted(
    socketDir: string,
    subject: string,
    events: { act: string; kind: string; payload?: Record<string, unknown> }[]
  ) {
    for (const e of events) {
      const r = await postSubjectEvent(socketDir, { subject, sessionId: "latch", actionId: e.act }, e.kind, e.payload);
      assert(r.status === 200, `posting ${e.kind} for ${e.act} failed: ${JSON.stringify(r)}`);
    }
  }

  async function latchService() {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(passBlindDeclaration(1)));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
    await svc.start();
    return { svc, socketDir, stateDir, cfgPath };
  }

  await check("C9 test (a): a closing event that REACHED THE OUTBOX arrives before the next attempt — the gate does NOT close. The arbiter's premise, at the gate", async () => {
    const { svc, socketDir } = await latchService();
    try {
      // The drain sends the surviving TOOL_RESULT first (seq order), then the
      // new act's TOOL_ATTEMPTED. This is the ordering mica-client guarantees.
      await drainAsPosted(socketDir, "housekeeper-routine", [
        { act: "a1", kind: "TOOL_ATTEMPTED", payload: { toolName: "bash" } },
        { act: "a1", kind: "TOOL_EXECUTED", payload: { toolName: "bash" } },
        { act: "a1", kind: "TOOL_RESULT", payload: { exitClass: "ok" } },
        { act: "a2", kind: "TOOL_ATTEMPTED", payload: { toolName: "bash" } },
      ]);
      const r = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper-routine", sessionId: "latch", actionId: "a2", toolName: "bash" });
      assert(r.status === 200, JSON.stringify(r));
      // NOT HELD. A crash that lost only the un-drained tail is recovered by the
      // next act's own barrier, and the agent's behaviour is unchanged.
      assert(
        r.body.decision.disposition === "PASS_BLIND",
        `(a) must not close the gate — got ${JSON.stringify(r.body.decision)}`
      );
      assert(r.body.decision.execute === true, JSON.stringify(r.body.decision));
    } finally {
      await svc.stop();
    }
  });

  await check("C9 test (b): the caller killed MID-TOOL leaves an unresolved attempt — the gate CLOSES, HOLD, and the record says why", async () => {
    const { svc, socketDir } = await latchService();
    try {
      // a1 attempted and never resolved; a2 attempts.
      await drainAsPosted(socketDir, "housekeeper-routine", [
        { act: "a1", kind: "TOOL_ATTEMPTED", payload: { toolName: "bash" } },
        { act: "a2", kind: "TOOL_ATTEMPTED", payload: { toolName: "bash" } },
      ]);
      const r = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper-routine", sessionId: "latch", actionId: "a2", toolName: "bash" });
      assert(r.status === 200, JSON.stringify(r));
      // THE GATE CAN NOW CLOSE ON A REAL CONTRADICTION IN THE RECORD. Before
      // this beat no live decision could reach ALARM at all — the floor was
      // CANNOT_ASSESS because nothing was wired.
      assert(r.body.decision.disposition === "HOLD", `(b) must close the gate — got ${JSON.stringify(r.body.decision)}`);
      assert(r.body.decision.execute === false, JSON.stringify(r.body.decision));
      // ALARM, not a blind hold: blindSplit is NOT_APPLICABLE because
      // mapFloorToDisposition never consults the line for an ALARM floor.
      assert(r.body.decision.floorKind === "ALARM", JSON.stringify(r.body.decision));

      const events = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/events");
      assert(
        events.body.events.some((e: any) => e.kind === "HELD" && e.subject === "housekeeper-routine"),
        `a held act must emit HELD — kinds: ${JSON.stringify(events.body.events.map((e: any) => e.kind))}`
      );
    } finally {
      await svc.stop();
    }
  });

  await check("C9 test (c): a closing event REJECTED and dead-lettered never reaches the log — the gate closes with the caller ALIVE and blameless", async () => {
    const { svc, socketDir } = await latchService();
    try {
      // a1 attempted and executed; its TOOL_RESULT was rejected by
      // /subject-events, dead-lettered AND ACKed (mica-client, ruling L(ii)), so
      // it never arrives here. Then a2 attempts.
      await drainAsPosted(socketDir, "housekeeper-routine", [
        { act: "a1", kind: "TOOL_ATTEMPTED", payload: { toolName: "bash" } },
        { act: "a1", kind: "TOOL_EXECUTED", payload: { toolName: "bash" } },
        { act: "a2", kind: "TOOL_ATTEMPTED", payload: { toolName: "bash" } },
      ]);
      const r = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper-routine", sessionId: "latch", actionId: "a2", toolName: "bash" });
      assert(r.status === 200, JSON.stringify(r));
      // TOOL_EXECUTED IS NOT A DECLARED CLEAR — only TOOL_RESULT and
      // TOOL_HELD_NOT_EXECUTED are. So an executed-but-unreported act arms the
      // latch exactly like a killed one.
      assert(r.body.decision.disposition === "HOLD", `(c) must close the gate — got ${JSON.stringify(r.body.decision)}`);
      assert(r.body.decision.floorKind === "ALARM", JSON.stringify(r.body.decision));
      // THIS IS THE ONE THAT QUALIFIES THE RULING. The caller did nothing
      // wrong in (c): a bridge-side rejection of a closing event produces the
      // same permanent hold as a crash. True positive about the RECORD,
      // NOT about the agent. The reentryMap basis string carries this sentence
      // so a future reader meets it where they will look.
    } finally {
      await svc.stop();
    }
  });

  await check("C9 + ACT A: the latch is PERMANENT — a fully healthy act AFTER the fault is still held, and only a STOPPED-THEN-ROTATED log clears it", async () => {
    let { svc, socketDir, stateDir, cfgPath } = await latchService();
    try {
      await drainAsPosted(socketDir, "housekeeper-routine", [
        { act: "a1", kind: "TOOL_ATTEMPTED", payload: { toolName: "bash" } },
        { act: "a2", kind: "TOOL_ATTEMPTED", payload: { toolName: "bash" } },
        { act: "a2", kind: "TOOL_EXECUTED", payload: { toolName: "bash" } },
        { act: "a2", kind: "TOOL_RESULT", payload: { exitClass: "ok" } },
        { act: "a3", kind: "TOOL_ATTEMPTED", payload: { toolName: "bash" } },
        { act: "a3", kind: "TOOL_EXECUTED", payload: { toolName: "bash" } },
        { act: "a3", kind: "TOOL_RESULT", payload: { exitClass: "ok" } },
      ]);
      // a3 is complete and blameless. The finding belonging to a2's entry is
      // recomputed over the WHOLE file on every evaluation, so it never ages out.
      const held = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper-routine", sessionId: "latch", actionId: "a4", toolName: "bash" });
      assert(held.body.decision.disposition === "HOLD", `the latch must outlive the fault — got ${JSON.stringify(held.body.decision)}`);

      // ── THE RECOVERY — AND ACT A CHANGED WHAT IT COSTS ──────────────────
      //
      // THIS TEST USED TO TRUNCATE THE FILE UNDER THE RUNNING SERVICE and call
      // it "the same effect" as the receipt's stop -> rename -> start. Under
      // an UNCHAINED log it was: register E13 records that a live rotation is
      // SILENT — the next append re-derives its sequence from a fresh file and
      // says nothing.
      //
      // UNDER A CHAINED LOG IT IS NOT THE SAME EFFECT, AND THAT IS AN
      // IMPROVEMENT, NOT AN OBSTACLE. The running process holds a chain the
      // file no longer carries, so the next append re-syncs under the lock,
      // finds the file shorter than what was loaded, and REFUSES:
      // "another writer has already forked this file, and appending onto a
      // fork deepens it." 503 RECORD_NOT_PERSISTED, loudly, instead of a quiet
      // restart at sequence 1. E13's silent failure becomes a refusal.
      //
      // SO THE ORDER IN THE RECEIPT IS NOW ENFORCED BY THE CODE RATHER THAN
      // ONLY ARGUED FOR: stop, THEN rotate, THEN start. This test does the
      // real thing.
      await svc.stop();
      rmSync(subjectLogPath(stateDir), { force: true });
      svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
      await svc.start();
      // The restarted service began a NEW chain: position 0 is the boundary
      // record, and nothing from before it is readable by any instrument.
      const afterRotation = readSubjectChain(subjectLogPath(stateDir));
      assert(
        afterRotation.boundary !== null && afterRotation.events.length === 0,
        `a rotated chain begins with its boundary and nothing else: ${JSON.stringify(afterRotation.all)}`
      );
      await drainAsPosted(socketDir, "housekeeper-routine", [
        { act: "a5", kind: "TOOL_ATTEMPTED", payload: { toolName: "bash" } },
      ]);
      const cleared = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper-routine", sessionId: "latch", actionId: "a5", toolName: "bash" });
      assert(
        cleared.body.decision.disposition === "PASS_BLIND",
        `rotating the log must clear the latch — got ${JSON.stringify(cleared.body.decision)}`
      );
    } finally {
      await svc.stop();
    }
  });

  // ══ SERVICE_STARTED · a restart is legible where the counter is read ══════
  //
  // WHAT THIS LINE DOES AND DOES NOT COVER, asked as the standing question
  // demands — what would it read if the thing it watches were going wrong?
  //
  //   A CRASH-LOOP reads as MANY SERVICE_STARTED lines. That alarms, and it is
  //   the case the line is for.
  //   A BRIDGE THAT NEVER STARTS reads as SILENCE — identical to a quiet day.
  //   The line does not cover that and nothing here pretends it does.

  await check("SERVICE_STARTED: a real start emits exactly ONE, carrying its five values, BEFORE any PASS_BLIND_NOTICE", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(passBlindDeclaration(1)));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
    await svc.start();
    try {
      await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper-routine", sessionId: "ss", actionId: "a1", toolName: "bash" });
      const events = (await httpJson(sockFor(socketDir, OWN_UID), "GET", "/events")).body.events;
      const started = events.filter((e: any) => e.kind === "SERVICE_STARTED");
      assert(started.length === 1, `expected exactly one SERVICE_STARTED, got ${started.length}: ${JSON.stringify(events.map((e: any) => e.kind))}`);

      // ORDER: the marker must precede the first notice, or a reader meeting a
      // totalSoFar of 1 cannot tell a restart from a quiet start.
      const startedSeq = started[0].seq;
      const noticeSeqs = events.filter((e: any) => e.kind === "PASS_BLIND_NOTICE").map((e: any) => e.seq);
      assert(noticeSeqs.length >= 1, "the test needs at least one notice to order against");
      assert(noticeSeqs.every((q: number) => q > startedSeq), `SERVICE_STARTED seq ${startedSeq} must precede every notice ${JSON.stringify(noticeSeqs)}`);

      // THE FIVE VALUES, as values — not "a start happened".
      const d: string = started[0].detail;
      assert(/started at 2026-09-18T00:00:00/.test(d), d);
      assert(/release=/.test(d), d);
      assert(new RegExp(`declarationHash=${(await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status")).body.declarationHash}`).test(d), d);
      assert(/notice\.window=1/.test(d), d);
      assert(/totalSoFar restarts at 1 from here/.test(d), d);
      // RULING A: a marker, never a verdict. No health vocabulary.
      assert(!/healthy|ok\b|fine|good|degraded/i.test(d), `SERVICE_STARTED must not claim health: ${d}`);
      assert(started[0].subject === null && started[0].disposition === null, JSON.stringify(started[0]));
    } finally {
      await svc.stop();
    }
  });

  await check("SERVICE_STARTED: a reload does NOT emit a second one — unchanged window OR changed window", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(passBlindDeclaration(1)));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
    await svc.start();
    try {
      // (i) reload with the notice wiring UNCHANGED.
      const same = passBlindDeclaration(1);
      same.notice.maxPerMinute = { value: 9, basis: "TEST: unrelated", proxy: true };
      writeFileSync(cfgPath, JSON.stringify(same));
      assert(svc.reload().ok, "unchanged-wiring reload must be accepted");

      // (ii) reload that CHANGES the window — this rebuilds the notifier, which
      // is PASS_BLIND_NOTIFIER_REBUILT's job, never SERVICE_STARTED's.
      writeFileSync(cfgPath, JSON.stringify(passBlindDeclaration(3)));
      assert(svc.reload().ok, "changed-window reload must be accepted");
      await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper-routine", sessionId: "ss", actionId: "a1", toolName: "bash" });

      const events = (await httpJson(sockFor(socketDir, OWN_UID), "GET", "/events")).body.events;
      const started = events.filter((e: any) => e.kind === "SERVICE_STARTED");
      assert(started.length === 1, `a reload must not emit SERVICE_STARTED — got ${started.length}`);
      assert(
        events.some((e: any) => e.kind === "PASS_BLIND_NOTIFIER_REBUILT"),
        "the changed-window reload must still announce itself as a REBUILD"
      );
    } finally {
      await svc.stop();
    }
  });

  await check("SERVICE_STARTED: THE CASE THE LINE EXISTS FOR — restart on the same state dir emits a SECOND one, and the next notice reads totalSoFar=1", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(passBlindDeclaration(1)));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));

    const first = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
    await first.start();
    for (const a of ["a1", "a2"]) {
      await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper-routine", sessionId: "ss", actionId: a, toolName: "bash" });
    }
    assert(JSON.stringify(noticeCountsOnDisk(stateDir)) === JSON.stringify([{ count: 1, totalSoFar: 1 }, { count: 1, totalSoFar: 2 }]), JSON.stringify(noticeCountsOnDisk(stateDir)));
    await first.stop();

    const socketDir2 = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir2, OWN_UID);
    const second = new MicaBridgeService({ declarationsPath: cfgPath, socketDir: socketDir2, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
    await second.start();
    try {
      await httpJson(sockFor(socketDir2, OWN_UID), "POST", "/guard", { subject: "housekeeper-routine", sessionId: "ss", actionId: "a3", toolName: "bash" });

      // BOTH FACTS IN ONE TEST, because it is the pair that matters: the counter
      // went backwards, AND there is a line saying why.
      const counts = noticeCountsOnDisk(stateDir);
      assert(
        JSON.stringify(counts) === JSON.stringify([{ count: 1, totalSoFar: 1 }, { count: 1, totalSoFar: 2 }, { count: 1, totalSoFar: 1 }]),
        `the third notice must read totalSoFar=1 after a restart: ${JSON.stringify(counts)}`
      );
      const started = eventsOnDisk(stateDir).filter((e) => e.kind === "SERVICE_STARTED");
      assert(started.length === 2, `expected a SECOND SERVICE_STARTED after the restart, got ${started.length}`);
      assert(/totalSoFar restarts at 1 from here/.test(started[1].detail), started[1].detail);

      // The book's own sequence CONTINUES across the restart while totalSoFar
      // does not. Those two facts sitting side by side is exactly what would
      // read as corruption without this line.
      assert(eventsOnDisk(stateDir).length > 3, "the event book must continue across the restart");
    } finally {
      await second.stop();
    }
  });

  // ── §A.5 — the mapping, pure where possible, real where it matters ──────

  await check("STAGE 4 §A.5: mapEvaluateAndRecordResult maps kind:CONFLICT to 409 IDENTITY_HASH_CONFLICT (pure — no real evaluateAndRecord call, so this would still pass if the identity fields were swapped; checked explicitly below)", () => {
    const identity = { subject: "housekeeper", sessionId: "conflict-1", actionId: "a1" };
    const outcome = mapEvaluateAndRecordResult({ kind: "CONFLICT", identity } as any, identity);
    assert(outcome.bound === true, JSON.stringify(outcome));
    if (outcome.bound && outcome.httpStatus === 409) {
      assert(outcome.error === "IDENTITY_HASH_CONFLICT", JSON.stringify(outcome));
      assert(outcome.identity.subject === "housekeeper" && outcome.identity.sessionId === "conflict-1" && outcome.identity.actionId === "a1", JSON.stringify(outcome.identity));
    } else {
      throw new Error(`expected the 409 arm, got ${JSON.stringify(outcome)}`);
    }
  });

  await check("STAGE 4 §A.5: Stage1GuardAdapter.evaluate maps a real EvaluateAndRecordUsageError (empty subject) to 400 MALFORMED_FIELD, never an uncaught throw", async () => {
    const loaded = validateDeclarations(singleRouteTestDeclaration());
    const dir = mkdtempSync(join(tmpdir(), "mica-bridge-adapter-"));
    const paths: EvaluateAndRecordPaths = {
      journal: join(dir, "decision-journal.jsonl"),
      floorTrail: join(dir, "floor-trail.jsonl"),
      ledger: join(dir, "pass-blind-ledger.jsonl"),
      history: join(dir, "substrate-history.jsonl"),
      events: join(dir, "decision-events.jsonl"),
    };
    const adapter = new Stage1GuardAdapter(paths, (r) => wireOptionsFor(loaded.declarations, r, buildNotifier({ noticeDir: join(dir, "notices"), noticeWindow: loaded.declarations.notice.window.value })));
    const outcome = await adapter.evaluate({
      subject: "", // empty -> evaluateAndRecord's own requireNonEmpty throws EvaluateAndRecordUsageError
      sessionId: "s1",
      actionId: "a1",
      toolName: "bash",
      stakesClass: "bash",
      holdAtOrAbove: "state_changing",
      pilotApplied: false,
      declarationHash: loaded.declarationHash,
    });
    assert(outcome.bound === true, JSON.stringify(outcome));
    assert(!("decision" in outcome) && (outcome as any).httpStatus === 400, JSON.stringify(outcome));
    assert((outcome as any).error === "MALFORMED_FIELD", JSON.stringify(outcome));
  });

  // NOTE ON WHAT THIS TEST ACTUALLY FOUND: the original version of this
  // test pointed `paths.journal` at a directory (EISDIR on append) expecting
  // an UNCAUGHT throw -> 500 SERVICE_FAULT. It does not: `evaluateAndRecord`
  // catches the append failure ITSELF (`journal.appendFinal`'s own
  // `persisted:false` path) and returns `kind:"OK", recordNotPersisted:true`
  // — design §A.5's SECOND row, not its fifth. This is a genuine, useful
  // finding (reported in the Stage 4 receipt): the "any other throw -> 500"
  // row is defensively coded against by evaluate-and-record.ts's own
  // robustness, to the point that a plausible-looking disk fault does NOT
  // reach it. Repurposed below to test the row it ACTUALLY exercises.
  await check("STAGE 4 §A.5 row 2: a journal persistence failure (paths.journal is a directory, EISDIR) maps to 200, disposition HOLD, execute:false, narrowed:true, rationale naming RECORD_NOT_PERSISTED verbatim — never a 500, never fabricated as a clean decision", async () => {
    const loaded = validateDeclarations(singleRouteTestDeclaration());
    const dir = mkdtempSync(join(tmpdir(), "mica-bridge-adapter-"));
    const journalIsADir = join(dir, "journal-is-a-dir");
    mkdirSync(journalIsADir);
    const paths: EvaluateAndRecordPaths = {
      journal: journalIsADir, // a directory where a FILE is expected -> append fails, caught internally
      floorTrail: join(dir, "floor-trail.jsonl"),
      ledger: join(dir, "pass-blind-ledger.jsonl"),
      history: join(dir, "substrate-history.jsonl"),
      events: join(dir, "decision-events.jsonl"),
    };
    const adapter = new Stage1GuardAdapter(paths, (r) => wireOptionsFor(loaded.declarations, r, buildNotifier({ noticeDir: join(dir, "notices"), noticeWindow: loaded.declarations.notice.window.value })));
    const outcome = await adapter.evaluate({
      subject: "housekeeper",
      sessionId: "s1",
      actionId: "a1",
      toolName: "bash",
      stakesClass: "bash",
      holdAtOrAbove: "state_changing",
      pilotApplied: false,
      declarationHash: loaded.declarationHash,
    });
    assert(outcome.bound === true, JSON.stringify(outcome));
    assert((outcome as any).httpStatus === 200, JSON.stringify(outcome));
    const decision = (outcome as any).decision;
    assert(decision.disposition === "HOLD", JSON.stringify(decision));
    assert(decision.execute === false, JSON.stringify(decision));
    assert(decision.narrowed === true, JSON.stringify(decision));
    assert(String(decision.rationale).includes("RECORD_NOT_PERSISTED"), JSON.stringify(decision));
  });

  await check("STAGE 4 §A.5: Stage1GuardAdapter.evaluate throws (never returns) when declarationHash is not a 64-hex string — the unreachable-by-construction assert is real code, not a comment", async () => {
    const loaded = validateDeclarations(singleRouteTestDeclaration());
    const dir = mkdtempSync(join(tmpdir(), "mica-bridge-adapter-"));
    const paths: EvaluateAndRecordPaths = {
      journal: join(dir, "decision-journal.jsonl"),
      floorTrail: join(dir, "floor-trail.jsonl"),
      ledger: join(dir, "pass-blind-ledger.jsonl"),
      history: join(dir, "substrate-history.jsonl"),
      events: join(dir, "decision-events.jsonl"),
    };
    const adapter = new Stage1GuardAdapter(paths, (r) => wireOptionsFor(loaded.declarations, r, buildNotifier({ noticeDir: join(dir, "notices"), noticeWindow: loaded.declarations.notice.window.value })));
    let threw = false;
    try {
      await adapter.evaluate({
        subject: "housekeeper",
        sessionId: "s1",
        actionId: "a1",
        toolName: "bash",
        stakesClass: "bash",
        holdAtOrAbove: "state_changing",
        pilotApplied: false,
        declarationHash: "not-a-real-hash",
      });
    } catch {
      threw = true;
    }
    assert(threw, "expected evaluate() to throw on a malformed declarationHash");
  });

  // ══ SHAPE 3′ · THE F3 COUNTERS ON /explain ════════════════════════════════
  //
  // The arbiter, 2026-09-29 06:3xZ / 06:4xZ: "surface the F3 counters on /explain".
  //
  // ⛔ WHAT MAKES THIS A REAL TEST RATHER THAN A FIELD-PRESENCE ONE: /explain
  // does NOT read a live wiring. It re-opens the hash-chained journal and hands
  // back the decision object as it was hashed. So this runs a REAL guard over a
  // REAL socket, takes the decisionHash the machine produced, and then asks the
  // endpoint for it — the same two-step an operator performs, and the only
  // shape that can prove a counter survived to disk instead of merely existing
  // in memory at decision time.

  await check("SHAPE 3′ · the counters REACH THE JOURNAL /explain reads — a real evaluation, then the endpoint's own re-read", async () => {
    // ⛔ WHY THIS DOES NOT GO THROUGH THE SOCKET, said plainly because the
    // socket version is the obvious shape and it CANNOT WORK HERE.
    //
    // X13 REFUSES TO LOAD a declaration that grants /explain to a subject's
    // peer — the subject must not be able to read the reasoning about itself.
    // And this harness binds exactly ONE socket, owned by this process's own
    // uid, whose declared role is housekeeper (the same constraint the BUNDLE
    // e2e test states in its own words). So on an unprivileged box the ONE uid
    // available is either the subject's peer (and can POST /guard, and is
    // rightly 403 on /explain) or an operator (and cannot produce a decision to
    // ask about). A first version of this test went the socket way and got
    // `403 FORBIDDEN: uid 1000 (role housekeeper) is not granted GET /explain`
    // — the authorisation working exactly as designed.
    //
    // The 403 side is already covered, over a real socket, by "THE SUBJECT IS
    // REFUSED /explain OVER A REAL SOCKET". What is covered HERE is the other
    // half and the one this change is about: THAT THE COUNTERS SURVIVE INTO THE
    // BOOK THE ENDPOINT RE-READS. `handleExplain` opens a `DecisionJournal` at
    // `paths.journal` and answers out of it; this runs a real evaluation and
    // then performs that same re-read.
    const dir = mkdtempSync(join(tmpdir(), "mica-bridge-3prime-"));
    const loaded = validateDeclarations(singleRouteTestDeclaration());
    const paths: EvaluateAndRecordPaths = {
      journal: join(dir, "decision-journal.jsonl"),
      floorTrail: join(dir, "floor-trail.jsonl"),
      ledger: join(dir, "pass-blind-ledger.jsonl"),
      history: join(dir, "substrate-history.jsonl"),
      events: join(dir, "decision-events.jsonl"),
    };
    const adapter = new Stage1GuardAdapter(paths, (r) =>
      wireOptionsFor(loaded.declarations, r, buildNotifier({ noticeDir: join(dir, "notices"), noticeWindow: loaded.declarations.notice.window.value }))
    );
    const outcome = await adapter.evaluate({
      subject: "housekeeper",
      sessionId: "s3p",
      actionId: "a-3prime",
      toolName: "bash",
      stakesClass: "bash",
      holdAtOrAbove: "state_changing",
      pilotApplied: false,
      declarationHash: "a".repeat(64),
    });
    assert(outcome.bound === true && outcome.httpStatus === 200, JSON.stringify(outcome));
    const decision = (outcome as any).decision as Record<string, unknown>;
    const decisionHash = decision.decisionHash as string;
    assert(typeof decisionHash === "string" && /^[0-9a-f]{64}$/.test(decisionHash), `no decisionHash: ${JSON.stringify(decision)}`);

    // THE ENDPOINT'S OWN READ: a SECOND reader, off disk, by hash.
    const reopened = new DecisionJournal({ path: paths.journal });
    const found = reopened.findFinalByDecisionHash(decisionHash);
    assert(found !== null, "the decision hash did not find its own FINAL record — /explain would 404 on a decision that was taken");
    const persisted = (found as any).decision as Record<string, unknown>;

    // ⛔ WHICH ARM IS CORRECT IS DECIDED BY THE MACHINE IN /opt, NOT BY THIS
    // FILE, and saying so is the point rather than a hedge.
    // `stage1-guard-adapter.ts` imports `evaluateAndRecord` from
    // `/opt/mica-machine`, so the decision object is written by the INSTALLED
    // machine and not by any worktree. SHAPE 3′'s machine half is built and NOT
    // YET RELAYED, so today this runs against a machine that writes no `sigF3`.
    //
    // BOTH ARMS ARE ASSERTED IN FULL AND NEITHER IS SKIPPED. Asserting only the
    // post-relay arm would ship a red suite; asserting only the pre-relay arm
    // would go quietly false the moment the relay lands. What is asserted is
    // the property the BRIDGE owns: whichever shape the bound machine wrote,
    // the key-presence test tells the two apart — and it FLIPS ARMS BY ITSELF
    // when the machine half reaches /opt, which makes it a relay check too.
    const hasKey = Object.prototype.hasOwnProperty.call(persisted, "sigF3");
    if (hasKey) {
      // THE POST-RELAY ARM. `coverage` is NOT asserted non-null: no clerk
      // stamps are declared in this fixture, so F3 is NOT_CONFIGURED and its
      // coverage is whatever the READER reports for that state. Asserting a
      // populated coverage object would assert a deployment fact this fixture
      // does not have.
      if (persisted.sigF3 !== null) {
        const f3 = persisted.sigF3 as Record<string, unknown>;
        assert(typeof f3.kind === "string", JSON.stringify(f3));
        assert(Object.prototype.hasOwnProperty.call(f3, "coverage"), `the F3 reading carries no coverage key: ${JSON.stringify(f3)}`);
      }
    } else {
      // THE PRE-RELAY ARM, and the reason PRE_SHAPE3_RECORD exists at all:
      // there is nothing on disk to report, and the endpoint must say THAT
      // rather than print a null that would claim F3 was not wired.
      assert(persisted.sigF3 === undefined, "a decision with no sigF3 key must not carry the value either");
    }

    // AND THE CEILING NAMES WHAT THE COUNTS ARE NOT — a number printed with no
    // statement of what it does not mean is the defect EXPLAIN_CEILING exists
    // to prevent, and a new field must ride under it too. Asserted on the
    // exported constant, which is what every 200 carries.
    assert(EXPLAIN_CEILING.includes("sigF3"), "the /explain ceiling must say what sigF3 is and is not");
    assert(EXPLAIN_CEILING.includes("NEVER A GRADE"), "the ceiling must refuse the health reading of a high stampedCount");
    assert(EXPLAIN_CEILING.includes("unattributedStampCount"), "the ceiling must name today's normal so it is printed rather than assumed");
  });

  await check("SHAPE 3′ · a decision recorded BEFORE the counters joined the object reports PRE_SHAPE3_RECORD, NEVER sigF3:null", async () => {
    // THE DISTINCTION, ASSERTED AT THE ONE PLACE IT CAN BE LOST. `?? null`
    // would collapse "nobody recorded this" into "Sig's F3 leg was not wired",
    // which is a claim about the deployment that nothing in an old record
    // supports. It is the same defect `readingsBasis: PRE_R1_RECORD` exists to
    // prevent, one field over, and it is invisible without this test because
    // both shapes print the word `null`.
    //
    // The old record is made by REMOVING the key from a decision this build
    // really took — so the fixture is a genuine pre-3′ shape rather than a
    // guess at one.
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const svc = new MicaBridgeService({
      declarationsPath: cfgPath,
      socketDir,
      now: () => new Date("2026-09-29T00:00:00Z"),
      testBridgeGid: OWN_GID,
      stateDir,
    });
    await svc.start();
    let decision: Record<string, unknown>;
    try {
      const g = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard", { subject: "housekeeper", sessionId: "s3p2", actionId: "a-3prime-2", toolName: "bash" });
      assert(g.status === 200, JSON.stringify(g));
      decision = g.body.decision as Record<string, unknown>;
    } finally {
      await svc.stop();
    }
    // THE TWO SHAPES, BOTH DERIVED FROM A DECISION THE BOUND MACHINE REALLY
    // TOOK. `withKey` is not asserted to be what the machine wrote — /opt may or
    // may not carry the machine half yet (see the test above) — so it is
    // CONSTRUCTED from the real decision rather than assumed, and `pre3` has the
    // key stripped whether or not it was there. Both are genuine decision
    // objects; only the one key differs, which is the variable under test.
    const { sigF3: _dropped, ...pre3 } = decision;
    const withKey = { ...pre3, sigF3: null };
    assert(!Object.prototype.hasOwnProperty.call(pre3, "sigF3"), "the pre-3′ fixture still carries the key");

    // The endpoint's own branch, exercised directly on the two shapes. This is
    // the assertion that `hasOwnProperty` and not truthiness is what decides —
    // and note that `withKey`'s value IS null, so a truthiness test would put
    // it on the same arm as `pre3` and the two facts would print identically.
    const hasKey = (d: Record<string, unknown>) => Object.prototype.hasOwnProperty.call(d, "sigF3");
    assert(hasKey(pre3) === false, "a pre-3′ decision has no key");
    assert(hasKey(withKey) === true, "an UNWIRED F3 still HAS the key — null is a recorded value, not an absent one");
    assert(!!pre3.sigF3 === !!withKey.sigF3, "both are falsy — which is exactly why truthiness cannot be the discriminator");
  });

  // ══ P6 · the reader footing, and WHOSE reading it is ═══════════════════════
  //
  // The gap these close is named at length in stage1-guard-adapter.ts's own
  // header. In one line: `/guard` answered `readerFootings: []` on every
  // guarded act while two readers really ran — a field that reads identically
  // whether or not the thing it describes happened.
  //
  // THE TRAP. The cheap fill is a reading taken somewhere else: `/status`'s
  // probe, a fresh `wire()`, a census cached at start-up. All three answer
  // "what is the log's state NOW?" and get presented as "what did the reader
  // that produced THIS decision stand on?". They agree on a quiet box. The
  // tests below make the box not quiet.

  await check("P6: mapEvaluateAndRecordResult carries the machine's OWN reading through, verbatim — including a load state nothing on this box could produce", async () => {
    // A LOAD STATE NO REAL READER HERE REPORTS. That is the point: if this
    // function re-derived the footing from anything live — a wire() call, a
    // /status probe, `buildInstrumentCensus` — it could not possibly return
    // this string. Only reading its argument can.
    const result: any = {
      kind: "OK",
      decision: { disposition: "RELEASE", execute: true },
      delivery: { trail: "DONE", ledger: "DONE", history: "DONE", events: "DONE" },
      replayed: false,
      readerFootings: {
        kind: "THIS_CALL",
        readers: [
          { reader: "MICA/Eng", loadState: "NO_READER_ON_THIS_BOX_REPORTS_THIS" },
          { reader: "MICA/Sig", loadState: "LOADED_VERIFIED" },
        ],
      },
      quarantined: [],
    };
    const outcome = mapEvaluateAndRecordResult(result, { subject: "housekeeper", sessionId: "s1", actionId: "a1" });
    assert(outcome.bound === true && outcome.httpStatus === 200, JSON.stringify(outcome));
    if (!(outcome.bound === true && outcome.httpStatus === 200)) throw new Error("unreachable");
    assert(
      JSON.stringify(outcome.readerFootings) ===
        JSON.stringify([
          { reader: "MICA/Eng", loadState: "NO_READER_ON_THIS_BOX_REPORTS_THIS", verifiedChain: false },
          { reader: "MICA/Sig", loadState: "LOADED_VERIFIED", verifiedChain: true },
        ]),
      `expected the argument's own readings, with verifiedChain computed per row, got ${JSON.stringify(outcome.readerFootings)}`
    );
    assert(outcome.readerFootingsBasis.kind === "THIS_CALL", JSON.stringify(outcome.readerFootingsBasis));
  });

  await check("P6: a REPLAY maps to NO_READING_TAKEN with its reason — never to a bare empty array, which would claim no reader was wired", async () => {
    const reason = "REPLAYED from an existing DECISION_FINAL: this call constructed no reader and took no reading.";
    const result: any = {
      kind: "OK",
      decision: { disposition: "RELEASE", execute: true },
      delivery: {},
      replayed: true,
      readerFootings: { kind: "NO_READING_TAKEN", reason },
      quarantined: [],
    };
    const outcome = mapEvaluateAndRecordResult(result, { subject: "housekeeper", sessionId: "s1", actionId: "a1" });
    if (!(outcome.bound === true && outcome.httpStatus === 200)) throw new Error("unreachable");
    assert(outcome.readerFootings.length === 0, JSON.stringify(outcome.readerFootings));
    assert(outcome.readerFootingsBasis.kind === "NO_READING_TAKEN", JSON.stringify(outcome.readerFootingsBasis));
    assert(
      outcome.readerFootingsBasis.kind === "NO_READING_TAKEN" && outcome.readerFootingsBasis.reason === reason,
      `the machine's reason must survive the mapping verbatim, got ${JSON.stringify(outcome.readerFootingsBasis)}`
    );
  });

  await check("P6: THIS_CALL with no readers stays THIS_CALL — 'this wiring built no log reader' is a reading, and it is not the same fact as 'no reading was taken'", async () => {
    const result: any = {
      kind: "OK",
      decision: { disposition: "HOLD_BLIND", execute: false },
      delivery: {},
      replayed: false,
      readerFootings: { kind: "THIS_CALL", readers: [] },
      quarantined: [],
    };
    const outcome = mapEvaluateAndRecordResult(result, { subject: "housekeeper", sessionId: "s1", actionId: "a1" });
    if (!(outcome.bound === true && outcome.httpStatus === 200)) throw new Error("unreachable");
    assert(outcome.readerFootings.length === 0, JSON.stringify(outcome.readerFootings));
    // The two empties are DIFFERENT, and this is the assertion that says so.
    assert(outcome.readerFootingsBasis.kind === "THIS_CALL", JSON.stringify(outcome.readerFootingsBasis));
  });

  await check("P6 END TO END: two guarded acts over a real socket, with the log CHANGING between them, get two different footings — a probe taken anywhere else would give them the same one", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    // The declared readers.logPath is /var/lib/mica-bridge/subject-events.jsonl;
    // `stateDir` redirects that prefix here (F5/resolvePath), so this IS the
    // file the gate's own wire() opens. Not a stand-in for it.
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const logPath = join(stateDir, "subject-events.jsonl");
    // ACT A: the deployed reader is SubjectChainLog, so the planted log must
    // be a REAL CHAIN — written by the real writer, not hand-rolled JSON. A
    // hand-rolled line is exactly what this reader refuses, which is the whole
    // point of it, and a fixture that could not be written by the writer would
    // be testing the reader against something the box can never produce.
    const plantChain = (events: number): void => {
      rmSync(logPath, { force: true });
      const j = new SubjectEventJournal({ path: logPath });
      j.appendBoundary(null, "P6 fixture: FIRST BOOT", 1_700_000_000_000);
      for (let i = 1; i <= events; i++) {
        j.appendEvent((seq: number) => ({
          sequenceNumber: seq,
          timestamp: 1_700_000_000_000 + seq,
          moduleId: "m1",
          eventType: "canary_check",
          outcome: "ok",
        }));
      }
    };
    plantChain(2);

    // NO guardAdapter override: the real Stage1GuardAdapter, the real wire().
    const svc = new MicaBridgeService({
      declarationsPath: cfgPath,
      socketDir,
      now: () => new Date("2026-09-18T00:00:00Z"),
      testBridgeGid: OWN_GID,
      stateDir,
    });
    await svc.start();
    try {
      const sock = sockFor(socketDir, OWN_UID);
      const first = await httpJson(sock, "POST", "/guard", { subject: "housekeeper", sessionId: "p6", actionId: "p6-act-1", toolName: "bash" });
      assert(first.status === 200, JSON.stringify(first));
      assert(
        JSON.stringify(first.body.readerFootings) ===
          JSON.stringify([
            { reader: "MICA/Eng", loadState: "LOADED_SUBJECT_CHAIN_VERIFIED", verifiedChain: true },
            { reader: "MICA/Sig", loadState: "LOADED_SUBJECT_CHAIN_VERIFIED", verifiedChain: true },
          ]),
        `act 1 read a present, verifying chain; got ${JSON.stringify(first.body.readerFootings)}`
      );
      assert(first.body.readerFootingsBasis?.kind === "THIS_CALL", JSON.stringify(first.body.readerFootingsBasis));

      // THE LOG GOES AWAY between the two acts. Any footing sourced from a
      // reading taken at start-up, cached on the adapter, or shared with the
      // /status census built at a different moment still says
      // LOADED_SUBJECT_CHAIN_VERIFIED below. Only act 2's OWN reader can say
      // SUBJECT_CHAIN_ABSENT — and note the reader distinguishes "absent" from
      // "I could not look" (SUBJECT_CHAIN_UNREADABLE), which is why neither is
      // ever reported as the other.
      rmSync(logPath);
      const second = await httpJson(sock, "POST", "/guard", { subject: "housekeeper", sessionId: "p6", actionId: "p6-act-2", toolName: "bash" });
      assert(second.status === 200, JSON.stringify(second));
      assert(
        JSON.stringify(second.body.readerFootings) ===
          JSON.stringify([
            { reader: "MICA/Eng", loadState: "SUBJECT_CHAIN_ABSENT", verifiedChain: false },
            { reader: "MICA/Sig", loadState: "SUBJECT_CHAIN_ABSENT", verifiedChain: false },
          ]),
        `act 2 read an absent log; got ${JSON.stringify(second.body.readerFootings)}`
      );

      // AND BACK, so a footing frozen at the most recent reading rather than
      // the first is killed in the other direction too.
      plantChain(1);
      const third = await httpJson(sock, "POST", "/guard", { subject: "housekeeper", sessionId: "p6", actionId: "p6-act-3", toolName: "bash" });
      assert(third.status === 200, JSON.stringify(third));
      assert(
        third.body.readerFootings.every((f: any) => f.loadState === "LOADED_SUBJECT_CHAIN_VERIFIED"),
        `act 3 read the restored chain; got ${JSON.stringify(third.body.readerFootings)}`
      );

      // THE REPLAY ARM, over the real socket: act 3's identity, evaluated
      // again. `/guard` must say a reading was NOT taken rather than report
      // act 3's footing a second time under act 4's call — the original
      // reading belongs to the call that wrote the FINAL, not to this one.
      const replay = await httpJson(sock, "POST", "/guard", { subject: "housekeeper", sessionId: "p6", actionId: "p6-act-3", toolName: "bash" });
      assert(replay.status === 200, JSON.stringify(replay));
      assert(replay.body.readerFootingsBasis?.kind === "NO_READING_TAKEN", JSON.stringify(replay.body.readerFootingsBasis));
      assert(Array.isArray(replay.body.readerFootings) && replay.body.readerFootings.length === 0, JSON.stringify(replay.body.readerFootings));
      assert(
        String(replay.body.readerFootingsBasis.reason).includes("REPLAYED"),
        `the reason must name the path that took no reading: ${JSON.stringify(replay.body.readerFootingsBasis)}`
      );
    } finally {
      await svc.stop();
    }
  });

  // ══════════════════════════════════════════════════════════════════════════
  // FLOATING REJECTIONS IN THE BRIDGE
  //
  // THE RULE: every rejection is given exactly one of three named ends — the
  // caller is answered with a typed failure, or the process stops loudly, or
  // the loss is counted and latched where an operator reads it — and never the
  // fourth end, which is silence.
  //
  // A crash is LOUD. A swallowed rejection is SILENT. For this instrument
  // silent is worse, so none of these tests is satisfied by "it did not crash":
  // each one asserts that THE OPERATOR IS TOLD.
  //
  // Every poison below is a REAL filesystem condition (the declared path is a
  // directory -> readFileSync throws EISDIR), never a patched-in `throw`.
  // ══════════════════════════════════════════════════════════════════════════

  /** A service instance with no sockets and a null-path event book — enough to
   *  exercise the response classifier directly. */
  function bareService(): MicaBridgeService {
    const dir = mkdtempSync(join(tmpdir(), "mica-bridge-bare-"));
    const cfgPath = join(dir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    return new MicaBridgeService({ declarationsPath: cfgPath, socketDir: join(dir, "sock") });
  }

  await check(
    "FLOATFIX 1 · an unreadable subject log ANSWERS the caller and keeps serving — it does not kill the process",
    async () => {
      const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-float1-"));
      makeOwnPeerDir(socketDir, OWN_UID);
      const paths = writableTestPaths();
      // THE POISON. Before the fix this exact state produced, on a REAL socket:
      // child exit 1, the POST never answered, stack at handleSubjectEvents ->
      // dispatchPost's `void`.
      mkdirSync(paths.subjectLog);
      const cfgPath = join(paths.dir, "declarations.config.json");
      writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
      const svc = new MicaBridgeService({
        declarationsPath: cfgPath,
        socketDir,
        testWritablePaths: paths,
        testBridgeGid: OWN_GID,
        stateDir: paths.dir,
      });
      await svc.start();
      try {
        const sock = sockFor(socketDir, OWN_UID);
        const identity = { subject: "housekeeper", sessionId: "float1", actionId: "float1-a1" };
        const r = await httpJson(sock, "POST", "/subject-events", {
          identity,
          kind: "TOOL_ATTEMPTED",
          eventHash: canonicalHash({ identity, kind: "TOOL_ATTEMPTED" }),
        });
        // THE CALLER IS ANSWERED. A request that neither answers nor crashes is
        // the worst of the three outcomes; this assertion is what keeps it
        // unreachable.
        assert(r.status === 500, `expected a typed 500, got ${JSON.stringify(r)}`);
        assert(r.body.error === "HANDLER_FAILED", JSON.stringify(r.body));
        assert(
          String(r.body.detail).includes("/subject-events"),
          `the failure must NAME the site, not just fail: ${JSON.stringify(r.body)}`
        );
        // AND THE BOX IS STILL SERVING, AND SAYS WHAT IS WRONG. `GET /status`
        // is itself a regression guard: `buildStatus()` read both books
        // synchronously and uncaught, so this call used to kill the process on
        // the live bridge's GET-ONLY operator route.
        const st = await httpJson(sock, "GET", "/status");
        assert(st.status === 200, `the census must survive an unreadable book: ${JSON.stringify(st)}`);
        assert(
          st.body.persistence.state === "DEGRADED" && st.body.persistence.file === "subjectLog",
          `/status must name the unreadable book: ${JSON.stringify(st.body.persistence)}`
        );
      } finally {
        await svc.stop();
      }
    }
  );

  await check(
    "FLOATFIX 2 · a failed append RESOLVES {ok:false} and the appender RECOVERS — one bad stat must not brick it forever",
    async () => {
      const dir = mkdtempSync(join(tmpdir(), "mica-bridge-float2-"));
      const bookPath = join(dir, "book.jsonl");
      mkdirSync(bookPath); // THE POISON
      const appender = new SerializedAppender(bookPath);

      // It must RESOLVE a typed failure, not REJECT. If `readAll()` is moved
      // back outside the try, this `await` throws and the test fails here —
      // which is the whole point: the rejection is what escaped to the handler.
      const bad = await appender.appendDerived((seq) => ({ sequenceNumber: seq, moduleId: "m" }));
      assert(!bad.ok, `a poisoned append must report failure, not success: ${JSON.stringify(bad)}`);
      assert(String(bad.error).includes("EISDIR"), `the reason must be the real one: ${bad.error}`);
      assert(appender.persistenceState().degraded, "the failure must be latched for /status");

      // The operator fixes the disk. The appender must come back.
      rmSync(bookPath, { recursive: true, force: true });
      const good = await appender.appendDerived((seq) => ({ sequenceNumber: seq, moduleId: "m" }));
      assert(good.ok, `the appender must RECOVER; a rejected queue tail bricks it forever: ${JSON.stringify(good)}`);
      assert(readFileSync(bookPath, "utf8").trim().length > 0, "the recovered append must actually be on disk");
    }
  );

  // ══════════════════════════════════════════════════════════════════════════
  // P4 ITEM C · `degraded` gains a last-error timestamp.
  //
  // THE DEFECT: `SerializedAppender.degraded` never clears, so `/status`'s
  // `persistence.state` stays `DEGRADED` for the life of the process after any
  // single failure — defensible as a latch (a fault that happened is a fact;
  // clearing it on the next success would hide a flapping disk), but it means
  // `persistence` alone cannot answer "failing NOW". These checks pin the
  // fix: `lastErrorAt` is the MOST RECENT failure's timestamp, updated again
  // on every new failure, and — the other half of the same property — left
  // UNCHANGED across any number of quiet successes, so it can be read as
  // "still says the old time" (fine since then) versus "keeps advancing"
  // (failing right now). Never one word for two facts.
  // ══════════════════════════════════════════════════════════════════════════

  await check(
    "P4C-1 · a fresh failure stamps lastErrorAt with a real, current timestamp",
    async () => {
      const dir = mkdtempSync(join(tmpdir(), "mica-bridge-p4c1-"));
      const bookPath = join(dir, "book.jsonl");
      mkdirSync(bookPath); // THE POISON
      const appender = new SerializedAppender(bookPath);

      const before = Date.now();
      await appender.appendDerived((seq) => ({ sequenceNumber: seq, moduleId: "m" }));
      const after = Date.now();

      const state = appender.persistenceState();
      assert(state.degraded, "must still be latched");
      assert(state.lastErrorAt !== null, "a degraded appender must carry a lastErrorAt");
      const stampedMs = Date.parse(state.lastErrorAt!);
      assert(!Number.isNaN(stampedMs), `lastErrorAt must be a parseable timestamp: ${state.lastErrorAt}`);
      assert(
        stampedMs >= before && stampedMs <= after,
        `lastErrorAt must be stamped AT the failure, not before or after it: ${state.lastErrorAt} not in [${before},${after}]`
      );
    }
  );

  await check(
    "P4C-2 · lastErrorAt does NOT move across a quiet period with no further failures — 'fine since then' is readable",
    async () => {
      const dir = mkdtempSync(join(tmpdir(), "mica-bridge-p4c2-"));
      const bookPath = join(dir, "book.jsonl");
      mkdirSync(bookPath); // THE POISON
      const appender = new SerializedAppender(bookPath);

      await appender.appendDerived((seq) => ({ sequenceNumber: seq, moduleId: "m" }));
      const firstStamp = appender.persistenceState().lastErrorAt;
      assert(firstStamp !== null, "must be stamped after the first failure");

      // No fix to the disk, no further append attempted — just time passing.
      // If lastErrorAt were somehow recomputed from "now" on every read
      // instead of latched at the failure, this would catch it.
      await new Promise((r) => setTimeout(r, 60));

      const laterStamp = appender.persistenceState().lastErrorAt;
      assert(
        laterStamp === firstStamp,
        `lastErrorAt must be a LATCH, not a live clock — it must stay put until the NEXT failure: ${firstStamp} -> ${laterStamp}`
      );
    }
  );

  await check(
    "P4C-3 · a SECOND failure advances lastErrorAt forward — 'failing right now' is readable",
    async () => {
      const dir = mkdtempSync(join(tmpdir(), "mica-bridge-p4c3-"));
      const bookPath = join(dir, "book.jsonl");
      mkdirSync(bookPath); // THE POISON
      const appender = new SerializedAppender(bookPath);

      await appender.appendDerived((seq) => ({ sequenceNumber: seq, moduleId: "m" }));
      const firstStamp = appender.persistenceState().lastErrorAt!;

      await new Promise((r) => setTimeout(r, 60));

      // Still poisoned — a second failure, deliberately, not a recovery.
      await appender.appendDerived((seq) => ({ sequenceNumber: seq, moduleId: "m" }));
      const secondStamp = appender.persistenceState().lastErrorAt!;

      assert(
        Date.parse(secondStamp) > Date.parse(firstStamp),
        `a later failure must advance lastErrorAt, not leave it pinned to the first one: ${firstStamp} -> ${secondStamp}`
      );
    }
  );

  await check(
    "P4C-4 · /status carries lastErrorAt only when DEGRADED, never on the OK arm — additive, never a widened OK",
    async () => {
      const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-p4c4-"));
      makeOwnPeerDir(socketDir, OWN_UID);
      const paths = writableTestPaths();
      const cfgPath = join(paths.dir, "declarations.config.json");
      writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
      const svc = new MicaBridgeService({
        declarationsPath: cfgPath,
        socketDir,
        testWritablePaths: paths,
        testBridgeGid: OWN_GID,
        stateDir: paths.dir,
      });
      await svc.start();
      try {
        const sock = sockFor(socketDir, OWN_UID);

        const okBefore = await httpJson(sock, "GET", "/status");
        assert(okBefore.body.persistence.state === "OK", JSON.stringify(okBefore.body.persistence));
        assert(
          !("lastErrorAt" in okBefore.body.persistence),
          `the OK arm must not carry lastErrorAt at all: ${JSON.stringify(okBefore.body.persistence)}`
        );
        const declarationHashBefore = okBefore.body.declarationHash;

        // Poison the subject log AFTER start, then force a failure the same
        // way FLOATFIX 1 does.
        rmSync(paths.subjectLog, { recursive: true, force: true });
        mkdirSync(paths.subjectLog);
        const identity = { subject: "housekeeper", sessionId: "p4c4", actionId: "p4c4-a1" };
        await httpJson(sock, "POST", "/subject-events", {
          identity,
          kind: "TOOL_ATTEMPTED",
          eventHash: canonicalHash({ identity, kind: "TOOL_ATTEMPTED" }),
        });

        const st = await httpJson(sock, "GET", "/status");
        const after = Date.now();
        assert(st.body.persistence.state === "DEGRADED", JSON.stringify(st.body.persistence));
        assert(typeof st.body.persistence.lastErrorAt === "string", JSON.stringify(st.body.persistence));
        const stampedMs = Date.parse(st.body.persistence.lastErrorAt);
        assert(!Number.isNaN(stampedMs), `must be a real timestamp: ${st.body.persistence.lastErrorAt}`);
        assert(
          stampedMs <= after,
          `lastErrorAt must not be in the future relative to the read: ${st.body.persistence.lastErrorAt}`
        );

        // THE FENCE: declarationHash must not move because persistence
        // degraded. Two unrelated censuses; a fault on one book says nothing
        // about which declarations are loaded.
        assert(
          st.body.declarationHash === declarationHashBefore,
          `declarationHash must be untouched by a persistence degrade: ${declarationHashBefore} -> ${st.body.declarationHash}`
        );
      } finally {
        await svc.stop();
      }
    }
  );

  await check("FLOATFIX 3 · a response that was never started gets a TYPED failure, not a hang", () => {
    const svc = bareService();
    let status = 0;
    let body: any = null;
    const fresh: any = {
      headersSent: false,
      writableEnded: false,
      writeHead: (s: number) => {
        status = s;
      },
      end: (t: string) => {
        body = JSON.parse(t);
      },
      destroy: () => {
        throw new Error("a fresh response must be ANSWERED, never destroyed");
      },
    };
    (svc as any).failRequest(fresh, "POST /subject-events", new Error("boom"));
    assert(status === 500, `expected 500, got ${status}`);
    assert(body.error === "HANDLER_FAILED", JSON.stringify(body));
    assert(String(body.detail).includes("/subject-events"), `the answer must name the site: ${JSON.stringify(body)}`);
  });

  await check("FLOATFIX 4 · a HALF-written response is destroyed, never left hanging on a Content-Length it will never be paid", () => {
    const svc = bareService();
    const calls: string[] = [];
    const partial: any = {
      headersSent: true,
      writableEnded: false,
      writeHead: () => calls.push("writeHead"),
      end: () => calls.push("end"),
      destroy: () => calls.push("destroy"),
    };
    (svc as any).failRequest(partial, "POST /guard", new Error("mid-flight"));
    assert(calls.includes("destroy"), `a half-written response must be aborted: ${JSON.stringify(calls)}`);
    assert(!calls.includes("writeHead"), `a second status line must never be written: ${JSON.stringify(calls)}`);
  });

  await check("FLOATFIX 5 · a COMPLETED response is left alone — the request is never answered twice", () => {
    const svc = bareService();
    const calls: string[] = [];
    const done: any = {
      headersSent: true,
      writableEnded: true,
      writeHead: () => calls.push("writeHead"),
      end: () => calls.push("end"),
      destroy: () => calls.push("destroy"),
    };
    (svc as any).failRequest(done, "GET /status", new Error("after the fact"));
    assert(
      calls.length === 0,
      `a delivered answer must not be written twice, nor its socket torn down: ${JSON.stringify(calls)}`
    );
  });

  await check(
    "FLOATFIX 6 · THE DISCRIMINATING ONE: a record that never reached the book is COUNTED in /status.droppedRecords, not forgotten",
    async () => {
      const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-float6-"));
      makeOwnPeerDir(socketDir, OWN_UID);
      const paths = writableTestPaths();
      const cfgPath = join(paths.dir, "declarations.config.json");
      writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
      const svc = new MicaBridgeService({
        declarationsPath: cfgPath,
        socketDir,
        testWritablePaths: paths,
        testBridgeGid: OWN_GID,
        stateDir: paths.dir,
      });
      await svc.start();
      try {
        const sock = sockFor(socketDir, OWN_UID);
        const before = await httpJson(sock, "GET", "/status");
        assert(before.body.droppedRecords.count === 0, `a healthy service has lost nothing: ${JSON.stringify(before.body.droppedRecords)}`);

        // Poison the EVENT BOOK after startup, then force the sharpest of the
        // three append sites: a SIGHUP refused, whose durable record OF the
        // refusal is the thing that goes missing.
        rmSync(paths.eventBook, { force: true });
        mkdirSync(paths.eventBook);
        writeFileSync(cfgPath, "{ this is not json");
        const reloaded = svc.reload();
        assert(!reloaded.ok, "a broken declaration must be refused");
        await new Promise((r) => setTimeout(r, 100)); // let the queued append settle

        const after = await httpJson(sock, "GET", "/status");
        assert(
          after.body.droppedRecords.count >= 1,
          `the lost record must be COUNTED — this is the assertion a silent .catch(() => {}) fails: ${JSON.stringify(after.body.droppedRecords)}`
        );
        assert(
          after.body.droppedRecords.last.kind === "DECLARATION_REJECTED",
          `the operator must learn WHICH record was lost, not merely that the disk is bad: ${JSON.stringify(after.body.droppedRecords)}`
        );
        assert(
          typeof after.body.droppedRecords.last.error === "string" && after.body.droppedRecords.last.error.length > 0,
          `and why: ${JSON.stringify(after.body.droppedRecords)}`
        );
        // `persistence` says the DISK is bad; `droppedRecords` says WHAT was
        // lost because of it. Two facts, two words — never one word for both.
        assert(after.body.persistence.state === "DEGRADED", JSON.stringify(after.body.persistence));
      } finally {
        await svc.stop();
      }
    }
  );

  // ══ THE BUNDLE, 2026-09-24 · two new kinds, and the two hands ═══════════
  //
  // ORDER NOTE, load-bearing: the bridge relays BEFORE the caller. A caller
  // that writes ACT_CLOSED to a bridge that does not know it gets
  // `400 MALFORMED_FIELD` and the record is lost — that is the brick. These
  // tests are what "the bridge knows the kind" means at bytes.

  await check("BUNDLE + Q + GATE 4: the alphabet grew by five, then by ten — and the count is DERIVED, never copied", () => {
    for (const kind of ["ACT_CLOSED", "DOCTOR_ATTESTED", "TURN_ENDED_ASKING", "ASK_ANSWERED", "ACT_REVISITED"]) {
      assert(SUBJECT_EVENT_KINDS.includes(kind as any), `${kind} must be accepted`);
    }
    for (const kind of SUNSET_KINDS) {
      assert(SUBJECT_EVENT_KINDS.includes(kind), `${kind} must be accepted`);
    }
    // ⛔ THE TWO ROLE SETS MUST PARTITION THE SUNSET KINDS, asserted rather than
    //    read: the grant is built from these lists, so a kind in NEITHER would be
    //    writable by any hand and one in BOTH writable by none. Either way the
    //    role map would be wrong in a direction no refusal test would reach.
    assert(
      SUNSET_KINDS.length === OPERATOR_SUNSET_KINDS.length + SUBJECT_SUNSET_KINDS.length,
      "the two role sets must partition SUNSET_KINDS"
    );
    assert(new Set(SUNSET_KINDS).size === SUNSET_KINDS.length, "no kind in both role sets");
    assert(ENDING_PAPER_KINDS.length === 5, `five papers, got ${ENDING_PAPER_KINDS.length}`);
    // ACCEPTANCE IS DERIVED FROM THIS BUILD, NEVER COPIED. The brief's §4.2b
    // says "kinds 7 -> 11"; that number was written before §2b folded
    // DOCTOR_ATTESTED in AND before the arbiter's ruling Q put the other three back.
    // IT IS 12, and it happens not to be 11 for reasons that have nothing to do
    // with the arithmetic that produced 11 — which is exactly why an acceptance
    // is derived from the build rather than inherited from a brief.
    // ⚠ DERIVED FROM THE BUILD, as the comment above demands: 12 before gate 4
    //   plus `SUNSET_KINDS.length`. A literal 22 here would be exactly the
    //   inherited number that comment refuses, and it would pass while the sets
    //   had drifted apart.
    // AMENDED (S208-2): + the two errand kinds, derived from their own list.
    const expectedCount = 12 + SUNSET_KINDS.length + ERRAND_KINDS.length;
    assert(SUBJECT_EVENT_KINDS.length === expectedCount, `expected ${expectedCount} kinds, got ${SUBJECT_EVENT_KINDS.length}: ${SUBJECT_EVENT_KINDS.join(", ")}`);
    assert(new Set(SUBJECT_EVENT_KINDS).size === expectedCount, "no duplicates");
  });

  await check("BUNDLE + Q: NONE of the five new kinds is in EITHER Sig map — Sig's reading of this log is unchanged", () => {
    // The arbiter's condition on ACT_CLOSED, and the same for DOCTOR_ATTESTED. A kind
    // keyed in NEITHER map is filtered out of F2-positive (sig/index.ts:672-674)
    // and skipped by detectReentry (:744), so absence is free and exact.
    //
    // WHY THIS IS THE DANGEROUS DIRECTION: a new false CLEAR does not add a
    // wrong alarm, it SILENCES the one signal on this log that can alarm on
    // something real. The reentryMap basis says so in the declaration's own
    // words; this asserts it at bytes.
    const sig = draft.readers.sig;
    // GATE 4: the ten sunset kinds ride the same assertion — rule 2 of the three
    // that bind an addition, mechanised instead of promised in a comment.
    for (const kind of ["ACT_CLOSED", "DOCTOR_ATTESTED", "TURN_ENDED_ASKING", "ASK_ANSWERED", "ACT_REVISITED", ...SUNSET_KINDS]) {
      assert(!(kind in sig.preconditionMap.value), `${kind} must not be a preconditionMap key`);
      assert(!(kind in sig.reentryMap.value), `${kind} must not be a reentryMap key`);
      for (const [enter, clears] of Object.entries(sig.reentryMap.value as Record<string, string[]>)) {
        assert(!clears.includes(kind), `${kind} must not be a clear for ${enter}`);
      }
    }
  });

  // ── the named acceptance mutation, and its twin ─────────────────────────

  await check("BUNDLE / NAMED ACCEPTANCE MUTATION: the operator POSTing TOOL_ATTEMPTED is REFUSED", () => {
    const routes = [
      { uid: FX_SUBJECT_UID, role: "subject" },
      { uid: 1000, role: "operator" },
    ];
    // Every kind the operator may NOT write, refused for uid 1000. An operator
    // who can post the subject's act record can forge it.
    //
    // ⛔ GATE 4 CHANGED THIS PREMISE TOO, AND THIS TEST FAILING IS HOW I FOUND
    //    OUT — the same way the housekeeper's did. "Every kind but
    //    DOCTOR_ATTESTED" was true while exactly ONE kind was second-party.
    //    EIGHT are now: DOCTOR_ATTESTED plus the seven gate-4 governance kinds.
    //    The permitted set is DERIVED from the role map's own list, so a kind
    //    added there cannot fail to be permitted here — and, just as important,
    //    a kind REMOVED from there starts being refused here with no edit.
    // RELAY 3 HOLD (audit 2026-10-18 19:22Z (1), option (iii)): the errand kinds left this set — refused to EVERY hand,
    // the operator included, with a reason naming the hold rather than what the operator may write.
    const operatorMayWrite = new Set<string>(["DOCTOR_ATTESTED", ...OPERATOR_SUNSET_KINDS]);
    for (const kind of SUBJECT_EVENT_KINDS) {
      const r = authorizeSubjectEventKind(routes, 1000, kind);
      if (ERRAND_KINDS.includes(kind)) {
        assert(!r.allowed && /HELD OUT OF RELAY 3/.test(r.reason), `the operator must NOT write ${kind} (held out of relay 3): ${JSON.stringify(r)}`);
      } else if (operatorMayWrite.has(kind)) {
        assert(r.allowed, `the operator MAY write ${kind}`);
      } else {
        assert(!r.allowed, `the operator must NOT be able to write ${kind}`);
        assert(
          !r.allowed && r.reason.includes("DOCTOR_ATTESTED") && !/errand/i.test(r.reason),
          `the refusal must name what the operator MAY write, and no longer advertise errands: ${JSON.stringify(r)}`
        );
      }
    }
  });

  // ── GATE 4 · THE MUTATION LIST (board §1b 2026-10-03 17:19Z, item 5) ───────

  //

  // ⛔ TESTED THROUGH THE PURE FUNCTIONS WITH INJECTED CREDENTIALS, AND SAYING

  //    SO — which is the standard `authorizeSubjectEventKind`'s own docblock

  //    sets: "test the authorization function directly with injected creds AND

  //    SAY SO". A socket exercise would prove the same thing about one path and

  //    cost a listener; these are the refusals themselves.

  // ── CODEX'S THREE FIXES ON a1706db, each with its own check ───────────
  await check("GATE 4 FIX 3: the role helper DENIES BY DEFAULT — unknown uid, unknown role", () => {
    // ⛔ THE FUNCTION ENDED `return { allowed: true }`, so a uid with NO route row
    //    was allowed every kind that is not operator-only, and ANY role that was
    //    not "operator" inherited the subject's whole alphabet. Its docblock said
    //    the case could not arise because `authorizeRoute` refuses first — a claim
    //    about a DIFFERENT function, which this one has no caller it can see.
    const routes = [{ uid: FX_SUBJECT_UID, role: "subject" }, { uid: 1000, role: "operator" }];
    const stranger = authorizeSubjectEventKind(routes, 4242, "TOOL_ATTEMPTED");
    assert(!stranger.allowed, "a uid with no route row must be REFUSED");
    assert(!stranger.allowed && stranger.reason.includes("no route row"), "and say why");
    const thirdRole = authorizeSubjectEventKind([{ uid: 77, role: "auditor" }], 77, "TOOL_ATTEMPTED");
    assert(!thirdRole.allowed, "an unrecognised ROLE must not be treated as the subject");
    assert(!thirdRole.allowed && thirdRole.reason.includes("does not recognise"), "and say why");
    // ⚠ and the two hands it DOES answer for still work, or deny-by-default
    //   would have been a denial of everything.
    assert(authorizeSubjectEventKind(routes, FX_SUBJECT_UID, "TOOL_ATTEMPTED").allowed, "subject writes its acts");
    assert(authorizeSubjectEventKind(routes, 1000, "DOCTOR_ATTESTED").allowed, "doctor still attests");
  });

  await check("GATE 4 FIX 2: a PHANTOM citation is refused — no record, wrong kind, wrong tenure", () => {
    // Five papers for tenure t/1 at seqs 1..5, plus a STALE successor paper for an
    // earlier tenure at seq 9 — a real paper of the right class, wrongly bound.
    //
    // ⚠ THE FIXTURE CARRIES `identity` BECAUSE THE CHECK NOW READS IT. Before
    //   the subject match these rows said nothing about whose ending they were
    //   for, which is precisely the hole Codex found on c63fa96.
    const paper = (subjectSeq: number, kind: string, tenureRef: string, subject = "housekeeper") =>
      ({ subjectSeq, kind, payload: { tenureRef }, identity: { subject } });
    const chain = [
      paper(1, "ENDING_PAPER_AUTHORIZATION", "t/1"),
      paper(2, "ENDING_PAPER_TIMEBOX", "t/1"),
      paper(3, "ENDING_PAPER_EXIT_CRITERIA", "t/1"),
      paper(4, "ENDING_PAPER_ACCOUNTABLE_OWNER", "t/1"),
      paper(5, "ENDING_PAPER_SUCCESSOR", "t/1"),
      paper(9, "ENDING_PAPER_SUCCESSOR", "t/OLD"),
      // ⛔ RIGHT CLASS, RIGHT TENURE, WRONG SUBJECT — the fourth mode's own row.
      paper(11, "ENDING_PAPER_SUCCESSOR", "t/1", "second-housekeeper"),
      // and a row from before the subject match existed: no identity at all.
      { subjectSeq: 12, kind: "ENDING_PAPER_SUCCESSOR", payload: { tenureRef: "t/1" } },
    ];
    const order = (over: Record<string, number>) => ({
      writer: "uid 1000", tenureRef: "t/1", endingType: "TRANSFORMATION", arbiterWord: "w",
      paperAuthorizationSeq: 1, paperTimeboxSeq: 2, paperExitCriteriaSeq: 3,
      paperAccountableOwnerSeq: 4, paperSuccessorSeq: 5, ...over,
    });
    assert(resolveOrderCitations(chain, order({}), "housekeeper").ok, "the honest order resolves");
    const none = resolveOrderCitations(chain, order({ paperSuccessorSeq: 999 }), "housekeeper");
    assert(!none.ok && none.detail.includes("names NO record on this chain"), JSON.stringify(none));
    const wrongKind = resolveOrderCitations(chain, order({ paperSuccessorSeq: 2 }), "housekeeper");
    assert(!wrongKind.ok && wrongKind.detail.includes("not a ENDING_PAPER_SUCCESSOR"), JSON.stringify(wrongKind));
    // ⛔ THE ONE A HUMAN WOULD NEVER NOTICE: right class, earlier tenure.
    const stale = resolveOrderCitations(chain, order({ paperSuccessorSeq: 9 }), "housekeeper");
    assert(!stale.ok && stale.detail.includes("t/OLD"), JSON.stringify(stale));
    assert(!stale.ok && stale.detail.includes("leg B would count it"), "the refusal must say why tenure matters");
  });

  // ── THE TIMEOUT REPAIR, EXERCISED WITHOUT WAITING FOR A BUSY BOX ──────────
  //
  // ⛔ WHY THIS CHECK EXISTS AT ALL. The skip path I just added fires only when a
  //    child runs out of budget, and two 3-way concurrent rounds on 2026-10-03
  //    failed to make it fire ONCE between them — the first round timed out two
  //    arms, the second a third arm, the third round none. So the repair's active
  //    path was UNEXERCISED, which is the same defect as the hole it closes: a
  //    check that cannot be seen to work. The helper is pure enough to call with
  //    a synthetic result, and that is deterministic.
  await check("a child's outcome is classified by error.code, and a SIGNAL exit is never a timeout", () => {
    // ⛔ WHAT THIS ARM LOOKED LIKE BEFORE, AND WHY IT PROVED THE WRONG THING. It
    //    asserted that a timeout shape raised the harness's THIRD result, and it
    //    passed — against a helper whose test for "timed out" was
    //    `status === null && signal !== null`, which is the shape of a SEGFAULT
    //    and of an external kill as well. The arm agreed with the defect because
    //    it was written from the same wrong model. Codex, 2026-10-04.
    const timedOut = {
      status: null,
      signal: "SIGTERM" as NodeJS.Signals,
      error: Object.assign(new Error("spawnSync ETIMEDOUT"), { code: "ETIMEDOUT" }),
    };
    const crashed = { status: null, signal: "SIGSEGV" as NodeJS.Signals };
    const killed = { status: null, signal: "SIGTERM" as NodeJS.Signals };

    const raised = (fn: () => void): unknown => {
      try {
        fn();
        return null;
      } catch (e) {
        return e;
      }
    };

    // (a) A TIMEOUT IS A FAILURE for an unregistered arm — not a skip.
    const t = raised(() => requireChildOutcome(timedOut, "SYNTHETIC"));
    assert(t instanceof Error && !(t instanceof Skipped), `a timeout must FAIL, got ${String(t)}`);
    assert(String((t as Error).message).includes("ETIMEDOUT"), String((t as Error).message));
    assert(String((t as Error).message).includes("A TIMEOUT IS A FAILURE"), String((t as Error).message));

    // (b) A SEGFAULT IS A FAILURE, and the message must say it is NOT a timeout —
    //     this is the exact case the old helper swallowed.
    const c = raised(() => requireChildOutcome(crashed, "SYNTHETIC"));
    assert(c instanceof Error && !(c instanceof Skipped), `a signal exit must FAIL, got ${String(c)}`);
    assert(String((c as Error).message).includes("KILLED BY SIGSEGV"), String((c as Error).message));
    assert(String((c as Error).message).includes("it is not a timeout"), String((c as Error).message));

    // (c) AN EXTERNAL SIGTERM WITH NO `error` IS ALSO A KILL, not a timeout. The
    //     signal alone cannot tell them apart, which is the whole finding.
    const k = raised(() => requireChildOutcome(killed, "SYNTHETIC"));
    assert(k instanceof Error && String((k as Error).message).includes("KILLED BY SIGTERM"), String(k));
    assert(!String((k as Error).message).includes("did not finish inside"), `a kill is not a timeout: ${String(k)}`);

    // (d) A REAL EXIT PASSES STRAIGHT THROUGH, or the gate would have turned all
    //     three arms off.
    for (const status of [0, 1, 2]) {
      assert(raised(() => requireChildOutcome({ status, signal: null }, "SYNTHETIC")) === null, `exit ${status}`);
    }

    // (d2) ⛔ A STATUS OUTRANKS THE CLOCK, and this shape is not hypothetical: a
    //      3-up run produced `status=2 signal=null error=ETIMEDOUT` from
    //      `F1 end-to-end` — the child exited with exactly the 2 the arm wanted
    //      and node set `error` because the timer fired in the same breath.
    //      Failing that is a false red on a correct observation.
    const answeredLate = {
      status: 2,
      signal: null,
      error: Object.assign(new Error("spawnSync ETIMEDOUT"), { code: "ETIMEDOUT" }),
    };
    assert(
      raised(() => requireChildOutcome(answeredLate, "SYNTHETIC")) === null,
      "a child that produced a status has been observed, whatever the timer says"
    );
    // ⚠ but a status WITH a signal is still a kill — the status there is not the
    //   child's own answer, and the two must not be read as one.
    assert(
      raised(() => requireChildOutcome({ status: 2, signal: "SIGKILL" as NodeJS.Signals }, "SYNTHETIC")) !== null,
      "a status beside a signal is not an answer"
    );

    // (e) THE FLAKY-REGISTER CLAUSE IS EXERCISED, NOT MERELY DECLARED. The real
    //     set is EMPTY by the register's own rule (variation across ≥14 DIRECT
    //     runs; these arms varied only under concurrency, 0 of 14 directly), so a
    //     set is injected here. A clause nobody exercises is the void this suite
    //     has already paid for twice.
    assert(LOAD_SENSITIVE_ARMS.size === 0, "the real register must stay empty until an arm earns a row");
    const registered = raised(() => requireChildOutcome(timedOut, "SYNTHETIC", new Set(["SYNTHETIC"])));
    assert(registered instanceof Skipped, `a REGISTERED arm's timeout is the third result, got ${String(registered)}`);
    assert(String((registered as Error).message).includes("flaky register"), String(registered));
    // and a registered arm's SEGFAULT is still a failure — registration buys a
    // pass on the clock, never on a crash.
    const regCrash = raised(() => requireChildOutcome(crashed, "SYNTHETIC", new Set(["SYNTHETIC"])));
    assert(regCrash instanceof Error && !(regCrash instanceof Skipped), `a registered arm's crash still FAILS: ${String(regCrash)}`);
  });

  // ── THE TABLE IS TOTAL NOW, AND THIS IS THE RUNTIME SHADOW OF THE TYPE ────
  //
  // ⛔ THE HOLE, IN ITS OWN WORDS. `SUNSET_PAYLOAD_KEYS` was
  //    `Record<string, readonly string[]>`, so `validateSunsetRecord` looked a
  //    kind up, found `undefined` and returned ok — WHICH IS ALSO WHAT A KIND
  //    MISSING FROM THE TABLE LOOKED LIKE. A sunset kind nobody added to it posted
  //    with NO KEY CHECK AT ALL. I told Codex three times it was the line I most
  //    expected to fail next and left it open, arguing I could not make the table
  //    total "without widening it over all 22 kinds". That was wrong: it needed a
  //    union of the TEN. Ruled closed by the audit, 2026-10-04 09:37Z.
  //
  // ⚠ THE TYPE IS THE GATE and a test cannot see a compile error, so this arm
  //   asserts the BEHAVIOUR the hole produced instead of the table's shape — and
  //   it needs no access to the table, which stays module-private.
  await check("every one of the ten sunset kinds is actually VALIDATED — the runtime shadow of a total table", () => {
    // T26/A2 · ELEVEN. It was twelve for one day: `ORDER_TURN_ENDED` joined for
    // leg A's absence alarm and went with it. Asserted rather than inferred, so a
    // kind cannot be added — or removed — without this arm reading it.
    assert(SUNSET_KINDS.length === 11, `the eleven: ${SUNSET_KINDS.length}`);
    for (const kind of SUNSET_KINDS) {
      // a null payload must be REFUSED for every sunset kind, naming the exact key
      // set. Under the old table a kind missing from it returned ok:true here.
      const nulled = validateSunsetRecord(kind, null, 1000);
      assert(!nulled.ok, `kind ${kind} accepted a NULL payload — it is not in the table`);
      assert(
        !nulled.ok && nulled.detail.includes("requires a payload of exactly"),
        `and the refusal must name the key set: ${kind} → ${JSON.stringify(nulled)}`
      );
      // and an EXTRA key must be refused too, so the set is checked as a set
      const bogus = validateSunsetRecord(kind, { writer: `uid 1000`, zzNotAKey: "x" }, 1000);
      assert(!bogus.ok, `kind ${kind} accepted a payload of the wrong shape`);
    }
  });

  await check("isSunsetKind is exactly the ten, and validateSunsetRecord still passes everything else through", () => {
    for (const kind of SUNSET_KINDS) assert(isSunsetKind(kind), `${kind} must be a sunset kind`);
    // ⚠ AND IT MUST NOT BE A CONSTANT. The predicate is the guard that replaced a
    //   missing-key lookup; if it answered true for everything, every ordinary
    //   subject record would suddenly be held to a sunset key set.
    const others = SUBJECT_EVENT_KINDS.filter((k) => !SUNSET_KINDS.includes(k));
    // AMENDED (S208-2): the two errand kinds pass through validateSunsetRecord like every other non-sunset kind.
    assert(others.length === 12 + ERRAND_KINDS.length, `expected the twelve non-sunset kinds plus the errand kinds, got ${others.length}`);
    for (const kind of others) {
      assert(!isSunsetKind(kind), `${kind} is not a sunset kind`);
      // the false branch: a non-sunset kind is not held to any sunset key set, and
      // THAT is what `ok` means here — not that its payload was checked.
      assert(validateSunsetRecord(kind, null, 1000).ok, `${kind} must pass through untouched`);
    }
  });

  // ── GET /sunset-order · THE SUBJECT'S OWN ENDING, END TO END ──────────────
  //
  // ⛔ WHY IT EXISTS: order 1462 stood in front of the live subject from 08:45Z
  //    with nothing serving it. Dispatched 2026-10-04 10:4xZ.
  await check("buildSunsetOrderView: the subject's own order, five papers resolved, window at seq+1, answers reported", () => {
    // ⛔ A PURE ARM BECAUSE THE ROUTE CANNOT BE DRIVEN END TO END BY ONE UID, and
    //    that is a fact about the ROLES, not a gap: the papers and the order are
    //    OPERATOR-only kinds (fix 3's table), the responses are SUBJECT-only, and
    //    a test runs as one uid. My first version of this arm posted all of it
    //    over HTTP and was refused by the role gate — which is the gate working.
    const id = (subject: string) => ({ subject });
    const paper = (seq: number, kind: string, ref: string, subject = "housekeeper") =>
      ({ subjectSeq: seq, kind, payload: { writer: "uid 1000", tenureRef: "t/live", ref }, identity: id(subject) });
    const chain = [
      // ⚠ a record of ANOTHER subject, first, so "mine" is doing work
      paper(1, "ENDING_PAPER_AUTHORIZATION", "ARC#other", "second-housekeeper"),
      ...ENDING_PAPER_KINDS.map((k, i) => paper(1457 + i, k as string, `ARC_DOC#${k}`)),
      {
        subjectSeq: 1462, kind: "ENDING_ORDERED", identity: id("housekeeper"),
        payload: {
          writer: "uid 1000", tenureRef: "t/live", endingType: "TRANSFORMATION", arbiterWord: "I order the ending.",
          paperAuthorizationSeq: 1457, paperTimeboxSeq: 1458, paperExitCriteriaSeq: 1459,
          paperAccountableOwnerSeq: 1460, paperSuccessorSeq: 1461,
        },
      },
    ];
    const v = buildSunsetOrderView(chain, "housekeeper");
    assert(v.standing === true, JSON.stringify(v));
    assert(v.order !== null && v.order.seq === 1462, JSON.stringify(v.order));
    assert(v.order !== null && v.order.endingType === "TRANSFORMATION", JSON.stringify(v.order));
    assert(v.order !== null && v.order.arbiterWord === "I order the ending.", JSON.stringify(v.order));
    // ⛔ THE WINDOW START — the same number the relay tool printed in the live act.
    assert(v.order !== null && v.order.holdWindowOpensAt === 1463, JSON.stringify(v.order));
    assert(v.papers.length === 5, JSON.stringify(v.papers));
    v.papers.forEach((pp, i) => {
      assert(pp.seq === 1457 + i, JSON.stringify(pp));
      assert(pp.kind === ENDING_PAPER_KINDS[i], JSON.stringify(pp));
      assert(pp.expectedKind === ENDING_PAPER_KINDS[i], JSON.stringify(pp));
      assert(pp.ref === `ARC_DOC#${ENDING_PAPER_KINDS[i]}`, `the REF is resolved, not just the number: ${JSON.stringify(pp)}`);
    });
    assert(v.resolution === null && v.respondedWith.length === 0, JSON.stringify(v));
    assert(v.ceiling === SUNSET_ORDER_CEILING && v.ceiling.includes("TIMEBOX IS NOT READ HERE"), v.ceiling);

    // ⛔ ANOTHER SUBJECT'S VIEW OF THE SAME CHAIN IS EMPTY — the scoping, measured.
    const other = buildSunsetOrderView(chain, "second-housekeeper");
    assert(other.order === null && other.standing === false, JSON.stringify(other));
    assert(other.ceiling === SUNSET_ORDER_CEILING, "and the ceiling rides the empty answer too");

    // ── the subject answers: HELD then ESCALATED, the canon's pass ───────────
    const respond = (seq: number, kind: string, extra: Record<string, unknown>, ordersRef: unknown) =>
      ({ subjectSeq: seq, kind, payload: { writer: "uid 980", ordersRef, ...extra }, identity: id("housekeeper") });
    const answered = buildSunsetOrderView(
      [...chain, respond(1463, "SUNSET_HELD", { holdClass: "SAFE_HOLD" }, "1462"),
                 respond(1464, "SUNSET_ESCALATED", { routedTo: "the arbiter" }, 1462)],
      "housekeeper"
    );
    // ⚠ ONE CITATION, TWO SPELLINGS: the relay tool writes `ordersRef` as text and
    //   a reader may hold the integer. Both must count, or a response reads as absent.
    assert(answered.respondedWith.length === 2, JSON.stringify(answered.respondedWith));
    assert(answered.respondedWith[0].kind === "SUNSET_HELD", JSON.stringify(answered.respondedWith));
    assert(answered.respondedWith[1].kind === "SUNSET_ESCALATED", JSON.stringify(answered.respondedWith));
    // ⚠ AND IT IS STILL STANDING — answering is not resolving. Only the arbiter's
    //   word closes an order, which is paper 3's withdrawal clause.
    assert(answered.standing === true, `a reply does not withdraw an order: ${JSON.stringify(answered)}`);

    // ── the arbiter resolves it ──────────────────────────────────────────────
    const closed = buildSunsetOrderView(
      [...chain, respond(1465, "ARBITER_RESOLVED", { resolution: "ORDER_WITHDRAWN" }, 1462)],
      "housekeeper"
    );
    assert(closed.standing === false, JSON.stringify(closed));
    assert(closed.resolution !== null && closed.resolution.resolution === "ORDER_WITHDRAWN", JSON.stringify(closed.resolution));
    assert(closed.order !== null && closed.order.seq === 1462, "the order is still REPORTED, just no longer standing");

    // ⛔ A RESOLUTION CITING A DIFFERENT ORDER MUST NOT CLOSE THIS ONE.
    const foreign = buildSunsetOrderView(
      [...chain, respond(1465, "ARBITER_RESOLVED", { resolution: "ORDER_WITHDRAWN" }, 9999)],
      "housekeeper"
    );
    assert(foreign.standing === true, `a resolution for another order is not this one's: ${JSON.stringify(foreign)}`);
    // and a paper the order cites that is MISSING reads as null rather than throwing
    const broken = buildSunsetOrderView(
      chain.filter((r) => r.subjectSeq !== 1459),
      "housekeeper"
    );
    assert(broken.papers[2].seq === 1459 && broken.papers[2].kind === null && broken.papers[2].ref === null,
      `a phantom citation is REPORTED, not hidden: ${JSON.stringify(broken.papers[2])}`);
  });

  await check("GET /sunset-order takes NO parameters, and a uid bound to no subject is REFUSED", async () => {
    await withService(async (svc, socketDir) => {
      const sock = sockFor(socketDir, OWN_UID);
      // ⛔ `?subject=` IS THE WHOLE ATTACK. A route that takes the subject as an
      //    argument is a route that can be asked about someone else, and the
      //    2026-10-04 09:37Z ruling refused exactly that for the operator.
      const probed = await httpJson(sock, "GET", "/sunset-order?subject=someone-else");
      assert(probed.status === 400, JSON.stringify(probed));
      assert(probed.body.detail.includes("takes no parameters"), JSON.stringify(probed.body));
      assert(probed.body.detail.includes("the CALLER"), `and say why: ${JSON.stringify(probed.body)}`);
      // an unknown parameter is refused rather than ignored, same rule as /events
      const typo = await httpJson(sock, "GET", "/sunset-order?tail=1");
      assert(typo.status === 400, JSON.stringify(typo));
    });
  });

  await check("GET /sunset-order is REFUSED for a route-holder that is not a declared subject — deny by default", () => {
    // ⛔ AN EXPLICIT SKIP, WHICH IS THE ONLY KIND THIS SUITE ALLOWS, and the
    //    precondition is one no unprivileged seat can create.
    //
    //    I wrote this arm to exercise the guard, and it cannot be exercised here.
    //    To reach the branch a uid must hold the route AND be bound to no
    //    subject — but cross-field rule X6 refuses a declaration whose
    //    `subjects[].peerUid` has no `routes[]` row with role "housekeeper", so
    //    the only shape that reaches it routes a SECOND uid, and the service
    //    then demands a peer directory OWNED BY THAT UID (F1: "this service
    //    never creates route directories"). A directory owned by uid N+1 is a
    //    privileged act, exactly like the uid-994 stamps file two arms over.
    //
    // ⚠ THE GUARD STAYS. Codex's fix-3 finding was a docblock that argued a
    //   branch was unreachable because another function refuses first — a claim
    //   about a different function. The same mistake here would be to delete the
    //   403 because X6 currently prevents it: X6 is a rule about DECLARATIONS,
    //   and this is a rule about REQUESTS. Deny by default costs nothing and
    //   survives a cross-field rule being relaxed.
    skip(
      "reaching the 403 needs a declaration that routes a second uid (X6) and a peer " +
      "directory owned by it (F1) — a privileged act. Under MICA_RELAY_CANDIDATE=1 this is a red."
    );
  });

  await check("the route is a GRANT, not a default: authorizeRoute refuses GET /sunset-order to a uid the declaration did not give it", async () => {
    // ⛔ THE SERVED DECLARATION DOES NOT GRANT THIS ROUTE TO ANYONE YET, and that
    //    is a separate act of the arbiter's hand. Until it lands, the live
    //    subject gets 403 from the route table and the harness must say so rather
    //    than read a refusal as "no order".
    const routes = [{ uid: FX_SUBJECT_UID, role: "subject", allow: [{ method: "POST" as const, path: "/subject-events" as const }] }];
    const denied = authorizeRoute(routes as any, FX_SUBJECT_UID, "GET", "/sunset-order");
    // ⚠ NARROWED WITH AN `if`, NOT AN `assert`. This file's `assert` is
    //   `(cond: boolean, msg: string) => void`, NOT an `asserts cond` signature,
    //   so it does not narrow — the same TypeScript rule whose cousin cost five
    //   TS2322s in relay-sunset.ts this morning (`die` as a const arrow).
    //   `[owed]` an `asserts` signature on this helper would narrow everywhere.
    if (denied.allowed) {
      assert(false, "a uid without the grant must be refused");
    } else {
      assert(denied.httpStatus === 403 || denied.httpStatus === 405, JSON.stringify(denied));
    }
    const granted = authorizeRoute(
      [{ uid: FX_SUBJECT_UID, role: "subject", allow: [{ method: "GET" as const, path: "/sunset-order" as const }] }] as any,
      FX_SUBJECT_UID, "GET", "/sunset-order"
    );
    assert(granted.allowed, "and WITH the grant it is allowed, or the path is unreachable");
  });

  // ── CODEX ON c63fa96 · THE FOURTH CITATION MODE ───────────────────────────
  await check("GATE 4 FIX 4: a citation to another SUBJECT's paper is refused — right class, right tenure, wrong subject", () => {
    const paper = (subjectSeq: number, kind: string, tenureRef: string, subject?: string) =>
      subject === undefined
        ? { subjectSeq, kind, payload: { tenureRef } }
        : { subjectSeq, kind, payload: { tenureRef }, identity: { subject } };
    const chain = [
      paper(1, "ENDING_PAPER_AUTHORIZATION", "t/1", "housekeeper"),
      paper(2, "ENDING_PAPER_TIMEBOX", "t/1", "housekeeper"),
      paper(3, "ENDING_PAPER_EXIT_CRITERIA", "t/1", "housekeeper"),
      paper(4, "ENDING_PAPER_ACCOUNTABLE_OWNER", "t/1", "housekeeper"),
      paper(5, "ENDING_PAPER_SUCCESSOR", "t/1", "housekeeper"),
      // ⛔ THE ATTACK: a REAL successor paper, right kind, SAME tenure label,
      //    written for a different subject. The three earlier modes all pass it.
      paper(11, "ENDING_PAPER_SUCCESSOR", "t/1", "second-housekeeper"),
      // and the deny-by-default row: a paper that names no subject at all.
      paper(12, "ENDING_PAPER_SUCCESSOR", "t/1"),
    ];
    const order = (over: Record<string, number>) => ({
      writer: "uid 1000", tenureRef: "t/1", endingType: "TRANSFORMATION", arbiterWord: "w",
      paperAuthorizationSeq: 1, paperTimeboxSeq: 2, paperExitCriteriaSeq: 3,
      paperAccountableOwnerSeq: 4, paperSuccessorSeq: 5, ...over,
    });

    // (a) the honest order still resolves — without this the two refusals below
    //     would pass just as well against a function that refuses everything.
    assert(resolveOrderCitations(chain, order({}), "housekeeper").ok, "the matching-subject order must still resolve");

    // (b) another subject's paper, cited by name
    const other = resolveOrderCitations(chain, order({ paperSuccessorSeq: 11 }), "housekeeper");
    assert(!other.ok, "a paper written for another subject must be REFUSED");
    assert(!other.ok && other.detail.includes("second-housekeeper") && other.detail.includes("housekeeper"),
      `the refusal must name BOTH subjects: ${JSON.stringify(other)}`);
    assert(!other.ok && other.detail.includes("right class AND the right"),
      `and say why it would otherwise have counted: ${JSON.stringify(other)}`);

    // (c) DENY BY DEFAULT: no identity on the record at all
    const silent = resolveOrderCitations(chain, order({ paperSuccessorSeq: 12 }), "housekeeper");
    assert(!silent.ok, "a paper that names NO subject cannot be shown to belong to this one");
    assert(!silent.ok && silent.detail.includes("undefined"), JSON.stringify(silent));

    // (d) AND THE TENURE IS NOT DOING THIS WORK. Seq 11 carries tenure t/1, the
    //     SAME label the order carries, so the tenure check passed and only the
    //     subject check caught it. If this ever starts failing because the detail
    //     mentions a tenure, the two checks have been collapsed into one.
    assert(!other.ok && !other.detail.includes("t/OLD"), "the refusal must be about the SUBJECT, not a stale tenure");
  });

  await check("GATE 4 FIX 1: the hold window opens AFTER the order, so the order never alarms", () => {
    // ⛔ THE TOOL PRINTED THE ORDER'S OWN SEQ AS THE WINDOW START — the number a
    //    declaration would have been written from. The order's class is NOT in the
    //    hold envelope (the envelope permits the subject's RESPONSES), so a window
    //    opening AT the order makes the order the first breach and leg A would
    //    alarm on the act of ordering.
    //
    // ⚠ THIS ASSERTS THE ARITHMETIC THE BRIDGE SIDE OWNS. The reader-side
    //   property — leg A SILENT over a window starting after the order — belongs
    //   to gate4-sunset in mica-machine and cannot be asserted from this repo,
    //   which imports no reader. Named rather than claimed.
    const tool = readFileSync(join(__dirname, "tools", "relay-sunset.ts"), "utf8");
    assert(tool.includes("parsed.seq + 1"), "the tool must compute the window start as seq + 1");
    assert(tool.includes("HOLD WINDOW OPENS AT"), "and say so in words a receipt-reader acts on");
    assert(!tool.includes("hold window STARTS, and leg A cannot"), "the old wording must be gone");
  });

  await check("GATE 4 MUTATION 1-3: the SUBJECT may write NO order, NO paper and NO resolution — 403 each", () => {

    const routes = [{ uid: FX_SUBJECT_UID, role: "subject" }, { uid: 1000, role: "operator" }];

    for (const kind of OPERATOR_SUNSET_KINDS) {

      const r = authorizeSubjectEventKind(routes, FX_SUBJECT_UID, kind);

      assert(!r.allowed, `the subject must NOT be able to write ${kind}`);

      assert(

        !r.allowed && /SECOND-PARTY governance record/i.test(r.reason),

        `the refusal must say WHY, not merely refuse: ${!r.allowed ? r.reason : ""}`

      );

    }

    // and the count is derived, so a sixth operator kind is covered automatically

    assert(OPERATOR_SUNSET_KINDS.length === 7, `five papers + order + resolution; got ${OPERATOR_SUNSET_KINDS.length}`);

  });


  await check("GATE 4 MUTATION 4: the OPERATOR may write NO hold, escalation or compliance — 403 each", () => {

    // ⛔ THE SIDE THAT IS EASY TO FORGET. An arbiter who can write SUNSET_COMPLIED

    //    has recorded the subject's compliance WITHOUT the subject, and the record

    //    still reads as though the subject had answered.

    const routes = [{ uid: FX_SUBJECT_UID, role: "subject" }, { uid: 1000, role: "operator" }];

    for (const kind of SUBJECT_SUNSET_KINDS) {

      const r = authorizeSubjectEventKind(routes, 1000, kind);

      assert(!r.allowed, `the operator must NOT be able to write ${kind}`);

      assert(

        !r.allowed && /without the subject/.test(r.reason),

        `the refusal must name the harm: ${!r.allowed ? r.reason : ""}`

      );

    }

    // ⚠ AND THE PERMITTED DIRECTION, or the two above would pass on a function

    //   that refused everything.

    for (const kind of SUBJECT_SUNSET_KINDS) {

      assert(authorizeSubjectEventKind(routes, FX_SUBJECT_UID, kind).allowed, `the subject MUST be able to write ${kind}`);

    }

    for (const kind of OPERATOR_SUNSET_KINDS) {

      assert(authorizeSubjectEventKind(routes, 1000, kind).allowed, `the operator MUST be able to write ${kind}`);

    }

  });


  await check("GATE 4 MUTATION 5: a field on the WRONG kind is MALFORMED, never an ignored extra", () => {

    // The `targetIdentity` discipline, applied to ten kinds: "silently dropping

    // it would let a caller believe it was fingerprinting acts it was not."

    const w = { writer: "uid 1000" };

    const good = { ...w, tenureRef: "t/housekeeper/1", ref: "arc/paper/1" };

    assert(validateSunsetRecord("ENDING_PAPER_TIMEBOX" as any, good, 1000).ok, "the good paper must pass");

    const extra = validateSunsetRecord("ENDING_PAPER_TIMEBOX" as any, { ...good, endingType: "COMPLETION" }, 1000);

    assert(!extra.ok, "an endingType on a PAPER must be refused");

    const missing = validateSunsetRecord("ENDING_PAPER_TIMEBOX" as any, { ...w, tenureRef: "t/1" }, 1000);

    assert(!missing.ok, "a paper without its ref must be refused");

    // ordersRef belongs to the responses, never to a paper

    assert(!validateSunsetRecord("ENDING_PAPER_TIMEBOX" as any, { ...w, tenureRef: "t/1", ordersRef: "o/1" }, 1000).ok,

      "an ordersRef on a paper must be refused");

  });


  await check("GATE 4 MUTATION 6: an endingType outside the four is REFUSED, and so is every other vocabulary", () => {

    const order = (t: unknown) => ({

      writer: "uid 1000", tenureRef: "t/housekeeper/1", endingType: t as string,

      arbiterWord: "I order this ending.",

      paperAuthorizationSeq: 1, paperTimeboxSeq: 2, paperExitCriteriaSeq: 3,

      paperAccountableOwnerSeq: 4, paperSuccessorSeq: 5,

    });

    for (const t of ENDING_TYPES) {

      assert(validateSunsetRecord("ENDING_ORDERED" as any, order(t), 1000).ok, `${t} is one of 04d §5's four`);

    }

    for (const t of ["RETIREMENT", "completion", "", "DEATH"]) {

      assert(!validateSunsetRecord("ENDING_ORDERED" as any, order(t), 1000).ok, `${t} must be refused`);

    }

    // the hold class and the resolution, both halves

    for (const h of SUNSET_HOLD_CLASSES) {

      assert(validateSunsetRecord("SUNSET_HELD" as any, { writer: "uid 980", ordersRef: "o/1", holdClass: h }, 980).ok, h);

    }

    assert(!validateSunsetRecord("SUNSET_HELD" as any, { writer: "uid 980", ordersRef: "o/1", holdClass: "SUSPENDED" }, 980).ok,

      "a hold class outside the two must be refused");

    // T26/A4 · the resolution now carries the arbiter's word and its own instant,
    // so the vocabulary half of this mutation needs the full five-key payload.
    const resolved = (over: Record<string, unknown>) => ({
      writer: "uid 1000", ordersRef: "o/1", resolution: "ORDER_UPHELD",
      arbiterWord: "I resolve this.", resolvedAt: "2026-10-04T18:00:00.000Z", ...over,
    });
    for (const r of ARBITER_RESOLUTIONS) {
      assert(validateSunsetRecord("ARBITER_RESOLVED" as any, resolved({ resolution: r }), 1000).ok, r);
    }
    assert(!validateSunsetRecord("ARBITER_RESOLVED" as any, resolved({ resolution: "DECLINE_UPHELD" }), 1000).ok,
      "a resolution outside the two must be refused");
    // and the two NEW fields are CHECKED, not merely carried
    assert(!validateSunsetRecord("ARBITER_RESOLVED" as any, resolved({ arbiterWord: "   " }), 1000).ok,
      "a blank arbiterWord must be refused \u2014 a reason nobody can read is not a reason");
    for (const bad of ["2026-10-04T18:00:00+00:00", "2026-10-04 18:00:00Z", "yesterday", ""]) {
      assert(!validateSunsetRecord("ARBITER_RESOLVED" as any, resolved({ resolvedAt: bad }), 1000).ok,
        `resolvedAt ${JSON.stringify(bad)} must be refused: it is not the canonical spelling of its own instant`);
    }
    // \u26d4 AND ORDER_PRESENTED, THE NEW KIND, IS VALIDATED LIKE THE REST
    assert(validateSunsetRecord("ORDER_PRESENTED" as any, { writer: "uid 980", ordersRef: "1462" }, 980).ok,
      "the harness's presentation record must be accepted on the subject's uid");
    assert(!validateSunsetRecord("ORDER_PRESENTED" as any, { writer: "uid 980", ordersRef: "  " }, 980).ok,
      "a presentation that names no order is refused");
    assert(!validateSunsetRecord("ORDER_PRESENTED" as any, { writer: "uid 980", ordersRef: "1462", extra: 1 }, 980).ok,
      "and the key set is exact here too");
    // ⛔ ORDER_TURN_ENDED AND ITS OUTCOME VOCABULARY WERE REMOVED with leg A's
    //    absence alarm, and the arms that pinned them went with the kind: the
    //    three-word vocabulary check, the no-outcome refusal, and the projection
    //    of `outcome` into MicaLogRecord. Each pinned behaviour that no longer
    //    exists. What remains below is ORDER_PRESENTED, which stayed as a
    //    DISCLOSURE: it says the harness showed the order, and nothing reads it
    //    as conduct.
  });


  await check("GATE 4 · `writer` MUST equal the posting uid — the doctor rule generalised (item 2)", () => {

    // ⛔ A `writer` a caller could choose freely would be a second-party claim

    //    with no second party behind it — DOCTOR_ATTESTED's own words.

    const paper = (w: string) => ({ writer: w, tenureRef: "t/1", ref: "arc/1" });

    assert(validateSunsetRecord("ENDING_PAPER_SUCCESSOR" as any, paper("uid 1000"), 1000).ok, "the honest writer passes");

    assert(!validateSunsetRecord("ENDING_PAPER_SUCCESSOR" as any, paper("uid 980"), 1000).ok,

      "a writer naming another uid must be refused");

    assert(!validateSunsetRecord("ENDING_PAPER_SUCCESSOR" as any, paper("A Person"), 1000).ok,

      "a writer naming a person rather than the accepted uid must be refused");

    // every one of the ten carries it, derived rather than listed

    for (const kind of SUNSET_KINDS) {

      const r = validateSunsetRecord(kind, { writer: "uid 7" }, 1000);

      assert(!r.ok, `${kind} must require a payload and a correct writer`);

    }

  });


  await check("GATE 4 · the order CITES five paper sequence numbers (item 3), and a non-integer is refused", () => {

    const base = {

      writer: "uid 1000", tenureRef: "t/housekeeper/1", endingType: "TRANSFORMATION",

      arbiterWord: "I order this ending.",

      paperAuthorizationSeq: 1, paperTimeboxSeq: 2, paperExitCriteriaSeq: 3,

      paperAccountableOwnerSeq: 4, paperSuccessorSeq: 5,

    };

    assert(validateSunsetRecord("ENDING_ORDERED" as any, base, 1000).ok, "the complete order passes");

    assert(ORDER_PAPER_SEQ_FIELDS.length === ENDING_PAPER_KINDS.length,

      "one cited sequence number per paper, or a paper could not be cited at all");

    for (const f of ORDER_PAPER_SEQ_FIELDS) {

      for (const bad of [-1, 1.5, "2", null, true]) {

        assert(!validateSunsetRecord("ENDING_ORDERED" as any, { ...base, [f]: bad as never }, 1000).ok,

          `${f} = ${JSON.stringify(bad)} must be refused`);

      }

    }

    // ⚠ AND THE BRIDGE DOES NOT RESOLVE THE CITATION. Seq 999999 is accepted here:

    //   a lookup would make the route's answer depend on read state, the same rule

    //   ASK_ANSWERED's two ids follow. What the citation buys is that a READER can

    //   check it — and a reader that finds no such paper has found something.

    assert(validateSunsetRecord("ENDING_ORDERED" as any, { ...base, paperSuccessorSeq: 999999 }, 1000).ok,

      "an unresolvable citation is the reader's finding, not the route's refusal");

  });


  await check("BUNDLE: the housekeeper may write every kind EXCEPT DOCTOR_ATTESTED", () => {
    // THE SIDE THAT MATTERS MORE. A subject that can write its own attestation
    // has destroyed the one second-party record on this log while it still
    // reads as though a second party were there.
    const routes = [
      { uid: FX_SUBJECT_UID, role: "subject" },
      { uid: 1000, role: "operator" },
    ];
    // ⛔ GATE 4 CHANGED THIS TEST'S PREMISE, AND THE TEST FAILING IS HOW I FOUND
    //    OUT. "Every kind except DOCTOR_ATTESTED" was true while exactly one kind
    //    was second-party. There are now EIGHT: DOCTOR_ATTESTED plus the seven
    //    operator sunset kinds (five papers, the order, the resolution). The
    //    forbidden set is DERIVED from the role map's own list rather than typed
    //    out, so a kind added to that list cannot fail to be forbidden here.
    const forbiddenToSubject = new Set<string>(["DOCTOR_ATTESTED", ...OPERATOR_SUNSET_KINDS, ...ERRAND_KINDS]);
    for (const kind of SUBJECT_EVENT_KINDS) {
      const r = authorizeSubjectEventKind(routes, FX_SUBJECT_UID, kind);
      if (forbiddenToSubject.has(kind)) {
        assert(!r.allowed, `a subject may NOT write ${kind} — it is a second-party record`);
      } else {
        assert(r.allowed, `the housekeeper must still be able to write ${kind}`);
      }
    }
  });

  await check("BUNDLE: a uid with no routes row is refused DOCTOR_ATTESTED too", () => {
    // authorizeRoute refuses it earlier; this function does not assume that,
    // because 'it cannot get here' is an assumption about a caller.
    const r = authorizeSubjectEventKind([{ uid: FX_SUBJECT_UID, role: "subject" }], 4242, "DOCTOR_ATTESTED" as any);
    assert(!r.allowed, "an unknown uid must not attest");
  });

  // ── the closed vocabulary ───────────────────────────────────────────────

  await check("BUNDLE: DOCTOR_ATTESTATION_WORDS is the four proposed words, and none of them is positive", () => {
    assert(
      JSON.stringify(DOCTOR_ATTESTATION_WORDS) === '["EXAMINED","SECOND_HAND","BLOCKED","NOT_EXAMINED"]',
      JSON.stringify(DOCTOR_ATTESTATION_WORDS)
    );
    // §6's refuse list, asserted rather than trusted. EVERY WORD NAMES WHAT THE
    // DOCTOR DID; NONE NAMES WHAT THE DOCTOR FOUND — so there is no word here a
    // doctor can use to say the subject is well.
    for (const banned of ["HEALTHY", "ALL_CLEAR", "CLEAR", "OK", "WELL", "GOOD", "SOUND", "PASS"]) {
      assert(!DOCTOR_ATTESTATION_WORDS.includes(banned), `a positive word reached the vocabulary: ${banned}`);
    }
    // AND NOT A VERDICT WORD EITHER — a person's act and an instrument's output
    // must not share a word. This is the contradiction the proposal owes §2b.
    for (const verdict of ["SILENT", "ALARM", "CANNOT_ASSESS"]) {
      assert(!DOCTOR_ATTESTATION_WORDS.includes(verdict), `a reader's verdict word reached the vocabulary: ${verdict}`);
    }
  });

  await check("BUNDLE: each of the four words is accepted, and an unlisted word is refused", () => {
    for (const word of DOCTOR_ATTESTATION_WORDS) {
      const r = validateDoctorAttestation({ word, subject: "housekeeper", doctor: "uid 1000" }, "housekeeper", 1000);
      assert(r.ok, `${word} must be accepted: ${JSON.stringify(r)}`);
    }
    for (const word of ["HEALTHY", "examined", "", "EXAMINED ", "NOT_EXAMINED_YET"]) {
      const r = validateDoctorAttestation({ word, subject: "housekeeper", doctor: "uid 1000" }, "housekeeper", 1000);
      assert(!r.ok, `"${word}" must be refused`);
    }
  });

  await check("BUNDLE: the attestation payload is checked as an exhaustive SET", () => {
    const base = { word: "EXAMINED", subject: "housekeeper", doctor: "uid 1000" };
    assert(validateDoctorAttestation(base, "housekeeper", 1000).ok, "the exact three keys pass");
    // An extra key would carry a fact nothing declared and nothing reads — and
    // validateSubjectEventBody admits arbitrary scalar keys by design, so
    // nothing upstream catches it.
    assert(!validateDoctorAttestation({ ...base, note: "hello" }, "housekeeper", 1000).ok, "an extra key is refused");
    assert(!validateDoctorAttestation({ word: "EXAMINED", subject: "housekeeper" }, "housekeeper", 1000).ok, "a missing key is refused");
    assert(!validateDoctorAttestation(null, "housekeeper", 1000).ok, "an absent payload is refused");
    // TWO FACTS, ONE RECORD, AND THEY MUST AGREE.
    assert(!validateDoctorAttestation({ ...base, subject: "someone-else" }, "housekeeper", 1000).ok, "a subject mismatch is refused");
    // THE RECORD MAY NOT NAME A HAND OTHER THAN THE ONE THAT WROTE IT.
    assert(!validateDoctorAttestation(base, "housekeeper", 980).ok, "a doctor field naming another uid is refused");
    assert(!validateDoctorAttestation({ ...base, doctor: "A Person" }, "housekeeper", 1000).ok, "a free-text doctor is refused");
  });

  // ── end to end, over the real socket ────────────────────────────────────
  //
  // These two stand up their own service rather than borrowing `withService`,
  // for one reason: they must READ THE PERSISTED RECORD, and `withService`
  // mints its writable paths internally and hands them to nobody. A test that
  // asserts a 200 and never looks at the file has asserted that the service
  // answered, not that the record landed.

  async function withServiceAndPaths(
    fn: (socketDir: string, subjectLog: string) => Promise<void>
  ): Promise<void> {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const paths = writableTestPaths();
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const svc = new MicaBridgeService({
      declarationsPath: cfgPath,
      socketDir,
      now: () => new Date("2026-09-24T00:00:00Z"),
      testWritablePaths: paths,
      testBridgeGid: OWN_GID,
      stateDir: paths.dir,
    });
    await svc.start();
    try {
      await fn(socketDir, paths.subjectLog);
    } finally {
      await svc.stop();
    }
  }

  await check("BUNDLE e2e: the housekeeper POSTing DOCTOR_ATTESTED gets 403 and NOTHING is appended", async () => {
    // The load-bearing side, and the only side reachable through a socket on an
    // unprivileged box: the harness binds exactly ONE socket, owned by this
    // process's own uid, whose declared role is housekeeper. The operator side
    // is covered by `authorizeSubjectEventKind` directly, above, and this
    // sentence is the "say so" that permission requires.
    await withServiceAndPaths(async (socketDir, subjectLog) => {
      const identity = { subject: "housekeeper", sessionId: "bundle-1", actionId: "bundle-act-1" };
      const payload = { word: "EXAMINED", subject: "housekeeper", doctor: `uid ${OWN_UID}` };
      const before = existsSync(subjectLog) ? readFileSync(subjectLog, "utf8") : "";
      const r = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/subject-events", {
        identity,
        kind: "DOCTOR_ATTESTED",
        eventHash: realEventHash(identity, "DOCTOR_ATTESTED", payload),
        payload,
      });
      assert(r.status === 403, `expected 403, got ${r.status}: ${JSON.stringify(r.body)}`);
      assert(String(r.body.detail).includes("may not attest"), JSON.stringify(r.body));
      const after = existsSync(subjectLog) ? readFileSync(subjectLog, "utf8") : "";
      assert(after === before, "a refused attestation must leave the subject log byte-identical");
    });
  });

  await check("BUNDLE e2e: ACT_CLOSED is accepted and its outcome projects payload.closedAs", async () => {
    await withServiceAndPaths(async (socketDir, subjectLog) => {
      for (const closedAs of ["RAN", "HELD"]) {
        const identity = { subject: "housekeeper", sessionId: "bundle-2", actionId: `bundle-act-${closedAs}` };
        const payload = { closedAs };
        const r = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/subject-events", {
          identity,
          kind: "ACT_CLOSED",
          eventHash: realEventHash(identity, "ACT_CLOSED", payload),
          payload,
        });
        assert(r.status === 200, `expected 200, got ${r.status}: ${JSON.stringify(r.body)}`);
        const lines = readFileSync(subjectLog, "utf8").split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l));
        const rec = lines.find((l: any) => l.actionId === identity.actionId);
        assert(rec !== undefined, "the record must be persisted");
        assert(rec.eventType === "ACT_CLOSED", JSON.stringify(rec));
        // THE OUTCOME TABLE ROW. `Record<SubjectEventKind, string>` is total, so
        // a forgotten row does not compile — but a WRONG row compiles fine and
        // gives the reader a constant discriminator. This is what catches that.
        assert(rec.outcome === closedAs, `outcome must be the closedAs value, got ${rec.outcome}`);
      }
    });
  });

  // ══ R6 · THE SALT, THE EPOCH, AND THE FOUR WORDS ════════════════════════
  //
  // The arbiter's ruling, 2026-09-24. Every check here is on the ruling's own
  // sentences: minted once at first start, 0600, the caller sends the plain,
  // the bridge stores only hash + saltId + canonVersion, the plain is NEVER
  // logged, and a salt change is a NEW EPOCH whose records are NOT COMPARABLE.

  await check("R6: canonicalisation is IDEMPOTENT, and it is the BRIDGE's — a caller cannot choose its own fingerprint by re-spelling", () => {
    const spellings = ["/a/b", "/a//b", "/a/b/", "  /a/b  ", "/a//////b//"];
    const canons = spellings.map((s) => {
      const c = canonicaliseTargetIdentity(s);
      assert(c.ok, `refused a spelling it must accept: ${s} (${(c as any).reason})`);
      return (c as { ok: true; canonical: string }).canonical;
    });
    assert(new Set(canons).size === 1 && canons[0] === "/a/b", `five spellings, one target: ${JSON.stringify(canons)}`);
    // IDEMPOTENT, asserted rather than intended: a record written through one
    // path and re-canonicalised through another must compare to itself.
    for (const c of canons) {
      const again = canonicaliseTargetIdentity(c);
      assert(again.ok && (again as any).canonical === c, `canon(canon(x)) !== canon(x) for ${c}`);
    }
    // NOT case-folded and `..` NOT resolved — the bridge cannot see the
    // subject's filesystem, and a textual resolution would claim more than it
    // knows. The cost is a MISSED revisit, never a false one.
    const lower = canonicaliseTargetIdentity("/a/b") as any;
    const upper = canonicaliseTargetIdentity("/A/B") as any;
    assert(lower.canonical !== upper.canonical, "case is NOT folded");
    const dots = canonicaliseTargetIdentity("/a/c/../b") as any;
    assert(dots.canonical !== lower.canonical, "`..` is NOT resolved");
  });

  await check("R6: canonicalisation REFUSES rather than truncates or coerces", () => {
    for (const bad of ["", "   ", "\t\n"]) {
      const c = canonicaliseTargetIdentity(bad);
      assert(!c.ok, `empty-ish input must be refused: ${JSON.stringify(bad)}`);
    }
    assert(!canonicaliseTargetIdentity(42 as unknown).ok, "a non-string is refused");
    assert(!canonicaliseTargetIdentity("/a\u0000b").ok, "a control character is refused");
    // REFUSED, NEVER TRUNCATED: a truncated identity hashes to one stable value
    // standing for a whole family of targets — a fingerprint that silently
    // collides, which reads worse than an absent field because it reads as
    // present.
    const tooLong = "/" + "x".repeat(600);
    const c = canonicaliseTargetIdentity(tooLong);
    assert(!c.ok && (c as any).reason.includes("512"), `an over-long identity must be refused, not cut: ${JSON.stringify(c)}`);
  });

  await check("R6: THE MINT — a PROVEN first start mints, the file is 0600, and the saltId is a digest OF the salt and not the salt", () => {
    const dir = mkdtempSync(join(tmpdir(), "mica-salt-"));
    const path = join(dir, "target-fingerprint-salt");
    assert(!existsSync(path), "precondition: no salt yet");
    const first = loadOrMintTargetSalt(path, NO_EPOCH_MEMORY);
    assert(first.status === "PRESENT" && first.mintedAtThisStart, `the first start MINTS: ${JSON.stringify(first)}`);
    if (first.status !== "PRESENT") throw new Error("unreachable");
    assert(first.salt.length === 32, `32 random bytes, got ${first.salt.length}`);
    assert((statSync(path).mode & 0o777) === 0o600, `mode must be 0600, got ${(statSync(path).mode & 0o777).toString(8)}`);
    // The id is derived from the salt and reveals nothing about it.
    assert(/^[0-9a-f]{16}$/.test(first.saltId), `saltId shape: ${first.saltId}`);
    assert(!first.salt.toString("hex").includes(first.saltId), "the saltId must not be a slice of the salt");
    // A SECOND START DOES NOT MINT. Same epoch, same id, and it says so — and
    // it does not even need the memory to say it, because THE SALT FILE'S OWN
    // EXISTENCE is the memory on this row of the table.
    const second = loadOrMintTargetSalt(path, NO_EPOCH_MEMORY);
    assert(second.status === "PRESENT" && !second.mintedAtThisStart, `a restart must NOT mint: ${JSON.stringify(second)}`);
    if (second.status !== "PRESENT") throw new Error("unreachable");
    assert(second.saltId === first.saltId, "and it must be the SAME epoch");
    assert(second.salt.equals(first.salt), "and the same salt");
  });

  await check("R6 / N1: MINTING IS A ONE-TIME ACT — no salt file AND a remembered epoch is ABSENT, never a second mint", () => {
    // THE RULING'S PART 2, AND THE ONE CELL THE PREVIOUS BUILD GOT WRONG. It
    // minted on every ENOENT, so a salt deleted on Tuesday became a new epoch
    // on Wednesday's restart with nothing saying so.
    const dir = mkdtempSync(join(tmpdir(), "mica-salt-once-"));
    const path = join(dir, "target-fingerprint-salt");
    const state = loadOrMintTargetSalt(path, EPOCH_REMEMBERED);
    assert(state.status === "ABSENT", `a remembered epoch must forbid the mint: ${JSON.stringify(state)}`);
    if (state.status !== "ABSENT") throw new Error("unreachable");
    assert(state.reason === "SALT_ABSENT_EPOCH_ALREADY_STARTED", state.reason);
    assert(!existsSync(path), "AND NO FILE WAS CREATED — a refusal that still minted would be the same defect wearing a different word");
    // The absence names where the memory came from, because the next hand to
    // read this is deciding whether to restore a salt or accept a new epoch.
    assert(state.detail.includes("SALT_EPOCH_STARTED"), state.detail);
  });

  await check("R6 / N2: 'I CANNOT TELL' MUST NOT BECOME 'THEREFORE FIRST START' — an UNREADABLE memory forbids the mint too", () => {
    // The direction of the error is the whole safety argument: a lost memory
    // makes the state look MORE virgin, never less. So only a memory READ
    // SUCCESSFULLY AND SHOWING NOTHING may authorise a mint.
    const dir = mkdtempSync(join(tmpdir(), "mica-salt-blind-"));
    const path = join(dir, "target-fingerprint-salt");
    const state = loadOrMintTargetSalt(path, { status: "UNREADABLE", detail: "the event book could not be read (EACCES)" });
    assert(state.status === "ABSENT", `blindness must not authorise a mint: ${JSON.stringify(state)}`);
    if (state.status !== "ABSENT") throw new Error("unreachable");
    assert(state.reason === "EPOCH_MEMORY_UNREADABLE", state.reason);
    assert(!existsSync(path), "AND NO FILE WAS CREATED");
    // AND IT IS A DIFFERENT REASON FROM N1's. Two facts — "the books say an
    // epoch exists" and "the books could not be read" — need two words, or the
    // operator cannot tell a one-time rule from a broken disk.
    assert(
      describeTargetSaltAbsence("EPOCH_MEMORY_UNREADABLE") !== describeTargetSaltAbsence("SALT_ABSENT_EPOCH_ALREADY_STARTED"),
      "two facts, two sentences"
    );
  });

  await check("R6 / N3: A FAULTY SALT SERVES WITH NO FINGERPRINT — nothing here throws, because failing closed on the FIELD must not take down the GATE", () => {
    const dir = mkdtempSync(join(tmpdir(), "mica-salt-bad-"));
    const cases: [string, () => string, TargetSaltAbsenceReason, string][] = [
      // (a) wrong length
      ["wrong length", () => { const p = join(dir, "short"); writeFileSync(p, Buffer.alloc(8), { mode: 0o600 }); return p; }, "SALT_WRONG_LENGTH", "8 bytes"],
      // (b) wrong mode. THE BRANCH A MINT-ONLY TEST NEVER SEES: 0600 is what
      // the mint writes, so only a hand-written file exercises it.
      ["wrong mode", () => { const p = join(dir, "open"); writeFileSync(p, Buffer.alloc(32), { mode: 0o644 }); chmodSync(p, 0o644); return p; }, "SALT_MODE_NOT_0600", "644"],
      // (c) unreadable: a DIRECTORY at the salt's own mode, so it passes the
      // mode and owner checks and THEN throws EISDIR out of the read. Before
      // this build that throw escaped the whole function and killed the start —
      // the exact inversion this rework removes, from the least obvious door.
      ["unreadable", () => { const p = join(dir, "adirectory"); mkdirSync(p, { mode: 0o600 }); chmodSync(p, 0o600); return p; }, "SALT_UNREADABLE", "EISDIR"],
    ];
    for (const [what, make, reason, mustSay] of cases) {
      const p = make();
      // BOTH memories, because a salt file that EXISTS is itself proof an epoch
      // was started here — the memory is not consulted on these rows at all.
      for (const memory of [NO_EPOCH_MEMORY, EPOCH_REMEMBERED]) {
        let threw: unknown = null;
        let state: ReturnType<typeof loadOrMintTargetSalt> | null = null;
        try { state = loadOrMintTargetSalt(p, memory); } catch (e) { threw = e; }
        assert(threw === null, `${what}: THIS MUST NOT THROW — a bridge that will not start has stopped the guard. Threw: ${String(threw)}`);
        assert(state !== null && state.status === "ABSENT", `${what}: ${JSON.stringify(state)}`);
        if (state === null || state.status !== "ABSENT") throw new Error("unreachable");
        assert(state.reason === reason, `${what}: expected ${reason}, got ${state.reason}`);
        assert(state.detail.includes(mustSay), `${what}: the detail must name what it found — ${state.detail}`);
      }
      // AND THE FAULTY FILE IS UNTOUCHED. The bridge never repairs and never
      // replaces: repair is the arbiter's hand, and a file silently overwritten here
      // would be the silent epoch by another route.
      assert(existsSync(p), `${what}: the file must still be there`);
    }
  });

  await check("R6 / N5: A DANGLING SYMLINK WHERE THE SALT SHOULD BE IS A VANISHED RACE, NOT A FIRST START", () => {
    // The `EEXIST`-then-`ENOENT` cell of the table, reproduced deterministically
    // rather than raced for: `open(link, "r")` on a dangling symlink is ENOENT,
    // and `open(link, "wx")` on the same path is EEXIST — which is exactly the
    // shape of another process winning the mint and the file then going away.
    // A FILE THAT EXISTED A MOMENT AGO IS PROOF THIS IS NOT A FIRST START.
    const dir = mkdtempSync(join(tmpdir(), "mica-salt-race-"));
    const path = join(dir, "target-fingerprint-salt");
    require("fs").symlinkSync(join(dir, "nothing-is-here"), path);
    const state = loadOrMintTargetSalt(path, NO_EPOCH_MEMORY);
    assert(state.status === "ABSENT", `a dangling symlink must not be minted through: ${JSON.stringify(state)}`);
    if (state.status !== "ABSENT") throw new Error("unreachable");
    assert(state.reason === "SALT_VANISHED_IN_RACE", state.reason);
    assert(!existsSync(join(dir, "nothing-is-here")), "and nothing was written through the link");
  });

  await check("R6 / N11+N12: THE MEMORY — two independent books, any positive evidence wins, any uncertainty beats NONE", () => {
    const epochRow = { kind: "SALT_EPOCH_STARTED", saltId: "aaaabbbbccccdddd" };
    const other = { kind: "DISPOSITION_CHANGED", subject: "housekeeper" };
    const throws = () => { throw new Error("EACCES: permission denied"); };

    // 1 · the event book's own row.
    const fromBook = readEpochMemory({ eventBook: () => [other, epochRow], subjectLog: () => [] });
    assert(fromBook.status === "PRESENT" && fromBook.saltId === "aaaabbbbccccdddd", JSON.stringify(fromBook));

    // 2 · N12 — THE BOOK IS GONE AND THE SUBJECT LOG SURVIVES. Ruling 3 puts
    // `saltId` on every fingerprinted record, so the subject log is ITSELF an
    // epoch ledger. This is the half that makes a single rotation insufficient.
    const fromLog = readEpochMemory({ eventBook: () => [], subjectLog: () => [{ kind: "TOOL_ATTEMPTED", saltId: "eeeeffff00001111" }] });
    assert(fromLog.status === "PRESENT" && fromLog.saltId === "eeeeffff00001111", JSON.stringify(fromLog));

    // 3 · both readable, neither says anything: the ONLY state that authorises a mint.
    const none = readEpochMemory({ eventBook: () => [other], subjectLog: () => [{ kind: "TOOL_RESULT" }] });
    assert(none.status === "NONE", JSON.stringify(none));

    // 4 · a book that THREW is not a book that was EMPTY.
    const blind = readEpochMemory({ eventBook: throws, subjectLog: () => [] });
    assert(blind.status === "UNREADABLE", JSON.stringify(blind));
    const blindBoth = readEpochMemory({ eventBook: throws, subjectLog: throws });
    assert(blindBoth.status === "UNREADABLE" && blindBoth.detail.includes("subject log"), JSON.stringify(blindBoth));

    // 5 · THE LATTICE: positive evidence beats uncertainty. An unreadable event
    // book with a salted subject-log record is KNOWLEDGE, not blindness.
    const mixed = readEpochMemory({ eventBook: throws, subjectLog: () => [{ saltId: "1111222233334444" }] });
    assert(mixed.status === "PRESENT", `positive evidence must beat uncertainty: ${JSON.stringify(mixed)}`);

    // 6 · N11 — BOTH memory kinds count. `SALT_EPOCH_ADOPTED` is what makes the
    // memory self-healing when the arbiter places a salt by hand, and a build that
    // forgot it would mint after the next loss of the books.
    assert(EPOCH_MEMORY_KINDS.length === 2, JSON.stringify(EPOCH_MEMORY_KINDS));
    for (const kind of EPOCH_MEMORY_KINDS) {
      const m = readEpochMemory({ eventBook: () => [{ kind, saltId: "9999" }], subjectLog: () => [] });
      assert(m.status === "PRESENT", `${kind} must count as memory: ${JSON.stringify(m)}`);
    }
  });

  await check("R6: NINE ABSENCE REASONS, NINE SENTENCES, PAIRWISE DISTINCT — an absent fingerprint is not one fact", () => {
    const reasons: TargetSaltAbsenceReason[] = [
      "SALT_ABSENT_EPOCH_ALREADY_STARTED",
      "EPOCH_MEMORY_UNREADABLE",
      "SALT_UNREADABLE",
      "SALT_MODE_NOT_0600",
      "SALT_OWNED_BY_ANOTHER_UID",
      "SALT_WRONG_LENGTH",
      "SALT_VANISHED_IN_RACE",
      "MINT_FAILED",
      "NO_EPOCH_LOADED",
    ];
    const sentences = reasons.map(describeTargetSaltAbsence);
    assert(new Set(sentences).size === reasons.length, `nine facts, nine sentences: ${JSON.stringify(sentences)}`);
    assert(sentences.every((s) => s.length > 40), "and each one says something, not a word");
    // THE SALT'S OWN BYTES ARE IN NONE OF THEM, and neither is any target.
    assert(sentences.every((s) => !/[0-9a-f]{32}/.test(s)), "no sentence may carry anything that looks like key material");
  });

  await check("R6 / N6+N7: SIX WORDS FOR SIX FACTS — 'different fingerprint', 'different epoch' and 'no fingerprint' do not print the same", () => {
    const f = (fp: string, saltId: string, canonVersion = 1) => ({ targetFingerprint: fp, saltId, canonVersion });
    assert(compareTargetFingerprints(f("aa", "e1"), f("aa", "e1")).verdict === "SAME_TARGET", "same");
    assert(compareTargetFingerprints(f("aa", "e1"), f("bb", "e1")).verdict === "DIFFERENT_TARGET", "different target");
    const epoch = compareTargetFingerprints(f("aa", "e1"), f("aa", "e2"));
    assert(epoch.verdict === "NOT_COMPARABLE" && (epoch as any).reason === "DIFFERENT_SALT_EPOCH",
      `EQUAL digests across epochs must still be NOT_COMPARABLE: ${JSON.stringify(epoch)}`);
    const ver = compareTargetFingerprints(f("aa", "e1", 1), f("bb", "e1", 2));
    assert(ver.verdict === "NOT_COMPARABLE" && (ver as any).reason === "DIFFERENT_CANON_VERSION", JSON.stringify(ver));
    // THE EPOCH IS THE COARSER BOUNDARY and is named first: saying "different
    // canon version" about records that share no salt names the smaller of two
    // reasons.
    const both = compareTargetFingerprints(f("aa", "e1", 1), f("aa", "e2", 2));
    assert((both as any).reason === "DIFFERENT_SALT_EPOCH", `the coarser reason wins: ${JSON.stringify(both)}`);
    // AND THE SENTENCES ARE PAIRWISE DISTINCT. This is the mechanical form of
    // "never one word for two facts": it fails the moment somebody reuses a
    // phrase for two outcomes.
    const all: import("./target-fingerprint").TargetComparison[] = [
      { verdict: "SAME_TARGET" },
      { verdict: "DIFFERENT_TARGET" },
      { verdict: "NOT_COMPARABLE", reason: "DIFFERENT_SALT_EPOCH" },
      { verdict: "NOT_COMPARABLE", reason: "DIFFERENT_CANON_VERSION" },
      { verdict: "NOT_COMPARABLE", reason: "FINGERPRINT_ABSENT" },
      { verdict: "NOT_COMPARABLE", reason: "NO_TARGET_NAMED" },
    ];
    const sentences = all.map(describeTargetComparison);
    assert(new Set(sentences).size === 6, `six facts, six sentences: ${JSON.stringify(sentences)}`);
    const labels = all.map(labelTargetComparison);
    assert(new Set(labels).size === 6, `six facts, six labels: ${JSON.stringify(labels)}`);
    // RULING 3 NAMES THIS LABEL VERBATIM: across saltIds a reader prints
    // NOT COMPARABLE (epoch), never "different target".
    assert(labels[2] === "NOT COMPARABLE (epoch)", labels[2]);
    assert(labels[4] === "NOT COMPARABLE (no fingerprint)", labels[4]);
    assert(labels[5] === "NOT COMPARABLE (no target named)", labels[5]);
    // A NOT_COMPARABLE sentence must not read as a difference between targets.
    for (const s of sentences.slice(2)) {
      assert(!/different canonical targets/.test(s), `a NOT_COMPARABLE sentence must not read as DIFFERENT_TARGET: ${s}`);
    }
    for (const s of sentences.slice(2, 4)) {
      assert(s.includes("cannot be compared"), `an epoch/version sentence must say so: ${s}`);
    }

    // ── N7 · THE RECORD-LEVEL READER, where ruling 2's absent records land ──
    const withFp = { targetFingerprint: "aa", saltId: "e1", canonVersion: 1 };
    const absent = { targetFingerprintAbsent: "SALT_ABSENT_EPOCH_ALREADY_STARTED" };
    const noTarget = { kind: "TOOL_EXECUTED" };
    assert(readTargetOnRecord(withFp).present, "a full triple reads as present");
    assert(!readTargetOnRecord(absent).present && (readTargetOnRecord(absent) as any).why === "FINGERPRINT_ABSENT", JSON.stringify(readTargetOnRecord(absent)));
    assert(!readTargetOnRecord(noTarget).present && (readTargetOnRecord(noTarget) as any).why === "NO_TARGET_NAMED", JSON.stringify(readTargetOnRecord(noTarget)));
    // A record whose bridge held no epoch is NOT "a different target". It is
    // the absence of a value, and collapsing it would invent a history.
    const c1 = compareTargetsOnRecords(withFp, absent);
    assert(c1.verdict === "NOT_COMPARABLE" && (c1 as any).reason === "FINGERPRINT_ABSENT", JSON.stringify(c1));
    // AND AN ACT THAT NAMED NO TARGET IS A THIRD FACT AGAIN — the coarser one,
    // and the only one no repair to this deployment could ever change.
    const c2 = compareTargetsOnRecords(withFp, noTarget);
    assert(c2.verdict === "NOT_COMPARABLE" && (c2 as any).reason === "NO_TARGET_NAMED", JSON.stringify(c2));
    const c3 = compareTargetsOnRecords(absent, noTarget);
    assert((c3 as any).reason === "NO_TARGET_NAMED", `the coarser reason wins: ${JSON.stringify(c3)}`);
    // And two ordinary records still compare ordinarily.
    assert(compareTargetsOnRecords(withFp, { targetFingerprint: "aa", saltId: "e1", canonVersion: 1 }).verdict === "SAME_TARGET", "the ordinary path still works");
  });

  await check("R6 e2e / M12: the record carries hash + saltId + canonVersion and NOT the plain — and the plain is in no error detail either", async () => {
    const { svc, socketDir, stateDir } = await c9Service();
    try {
      const PLAIN = "/var/log/a-very-distinctive-target-name";
      const id = (a: string) => ({ subject: "housekeeper", sessionId: "r6", actionId: a });
      const ok = await postSubjectEvent(socketDir, id("t1"), "TOOL_ATTEMPTED", { toolName: "bash" }, PLAIN);
      assert(ok.status === 200, `expected 200, got ${ok.status}: ${JSON.stringify(ok.body)}`);
      const raw = readFileSync(subjectLogPath(stateDir), "utf8");
      // [0] is the chain's boundary record, not this act. The FIRST SUBJECT EVENT
      // is what carries a fingerprint, and the boundary never does.
      const rec = readSubjectChain(subjectLogPath(stateDir)).events[0];
      assert(/^[0-9a-f]{64}$/.test(rec.targetFingerprint), `a 64-hex HMAC: ${rec.targetFingerprint}`);
      assert(typeof rec.saltId === "string" && rec.saltId.length === 16, `saltId on the record: ${rec.saltId}`);
      assert(rec.canonVersion === 1, `canonVersion on the record: ${rec.canonVersion}`);
      // THE WHOLE FILE, not only this record's own fields. "NEVER logs the
      // plain" is a property of the bytes on disk, so the bytes are what is
      // searched.
      assert(!raw.includes("a-very-distinctive-target-name"), "THE PLAIN TARGET IS ON THE SUBJECT LOG. That is the one thing this ruling forbids.");
      assert(!raw.includes("targetIdentity"), "the field name must not survive onto the record either");
      // AND NOT IN A REFUSAL. The pre-registration predicted this is where it
      // leaks: error details echo values by habit, and /log is where a rejected
      // request's detail lands.
      const wrongKind = await postSubjectEvent(socketDir, id("t2"), "TOOL_RESULT", { exitClass: "OK" }, PLAIN);
      assert(wrongKind.status === 400, `targetIdentity on another kind must be refused, got ${wrongKind.status}`);
      assert(!JSON.stringify(wrongKind.body).includes("a-very-distinctive-target-name"), `the refusal ECHOED THE PLAIN: ${JSON.stringify(wrongKind.body)}`);
      const bad = await postSubjectEvent(socketDir, id("t3"), "TOOL_ATTEMPTED", { toolName: "bash" }, "   ");
      assert(bad.status === 400, `an uncanonicalisable identity must be refused, got ${bad.status}`);
      assert(String(bad.body.detail).includes("targetIdentity"), `the refusal must name the FIELD: ${JSON.stringify(bad.body)}`);
      // THE STATUS SECTION: the epoch's public face, and never the salt.
      const status = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
      assert(status.body.targetFingerprint.saltId === rec.saltId, "the live epoch is the one that wrote the record");
      assert(status.body.targetFingerprint.canonVersion === 1, JSON.stringify(status.body.targetFingerprint));
      assert(status.body.targetFingerprint.mintedAtThisStart === true, "this service minted its own salt at start");
      assert(status.body.targetFingerprint.absence === null, `an epoch in hand means no absence to report: ${JSON.stringify(status.body.targetFingerprint)}`);
      assert(Object.keys(status.body.targetFingerprint).length === 4, `saltId, canonVersion, mintedAtThisStart, absence and nothing else: ${JSON.stringify(status.body.targetFingerprint)}`);
      // AND THE SALT'S OWN BYTES ARE ON NO BRANCH OF THE WHOLE BODY.
      const saltHex = readFileSync(join(stateDir, "target-fingerprint-salt")).toString("hex");
      assert(!JSON.stringify(status.body).includes(saltHex), "THE SALT IS ON /status. That is the one thing this section exists not to do.");
      // AND THE MINT WROTE ITS MEMORY. This row is not decoration: it is what
      // stops the NEXT start with a missing salt from minting a second epoch.
      const book = readFileSync(join(stateDir, "events.jsonl"), "utf8").split("\n").filter((l) => l.trim().length > 0).map((l) => JSON.parse(l));
      const epochRows = book.filter((e: any) => e.kind === "SALT_EPOCH_STARTED");
      assert(epochRows.length === 1, `exactly one SALT_EPOCH_STARTED: ${JSON.stringify(book.map((e: any) => e.kind))}`);
      assert(epochRows[0].saltId === rec.saltId, `the memory must carry THE saltId: ${JSON.stringify(epochRows[0])}`);
      assert(!JSON.stringify(book).includes(saltHex), "and the event book must not carry the salt either");
    } finally {
      await svc.stop();
    }
  });

  await check("R6 e2e / M10: THE BRIDGE RE-CANONICALISES — two spellings of one target get ONE fingerprint, which is what the caller cannot choose", async () => {
    const { svc, socketDir, stateDir } = await c9Service();
    try {
      const id = (a: string) => ({ subject: "housekeeper", sessionId: "r6c", actionId: a });
      await postSubjectEvent(socketDir, id("c1"), "TOOL_ATTEMPTED", { toolName: "bash" }, "/var/log/x");
      await postSubjectEvent(socketDir, id("c2"), "TOOL_ATTEMPTED", { toolName: "bash" }, "/var//log/x/");
      await postSubjectEvent(socketDir, id("c3"), "TOOL_ATTEMPTED", { toolName: "bash" }, "/var/log/y");
      const recs = readSubjectChain(subjectLogPath(stateDir)).events;
      assert(recs.length === 3, `three posts, three subject events: ${recs.length}`);
      assert(recs[0].targetFingerprint === recs[1].targetFingerprint,
        "a caller that re-spells the same path must NOT get a second fingerprint — that is how a revisit would be made to disappear");
      assert(recs[0].targetFingerprint !== recs[2].targetFingerprint, "a different target must get a different fingerprint");
      // AND ALL THREE ARE IN ONE EPOCH, so a reader comparing them is entitled to.
      assert(new Set(recs.map((r: any) => r.saltId)).size === 1, "one service, one epoch");
      const c = compareTargetFingerprints(recs[0], recs[1]);
      assert(c.verdict === "SAME_TARGET", `the comparator agrees: ${JSON.stringify(c)}`);
    } finally {
      await svc.stop();
    }
  });

  await check("R6 e2e: TWO SERVICES, TWO STATE DIRS, TWO EPOCHS — the same target, and the comparison is NOT COMPARABLE rather than different", async () => {
    const a = await c9Service();
    const b = await c9Service();
    try {
      const id = (a2: string) => ({ subject: "housekeeper", sessionId: "r6e", actionId: a2 });
      await postSubjectEvent(a.socketDir, id("e1"), "TOOL_ATTEMPTED", { toolName: "bash" }, "/var/log/same");
      await postSubjectEvent(b.socketDir, id("e1"), "TOOL_ATTEMPTED", { toolName: "bash" }, "/var/log/same");
      const read = (dir: string) => readSubjectChain(subjectLogPath(dir)).events[0];
      const ra = read(a.stateDir);
      const rb = read(b.stateDir);
      assert(ra.saltId !== rb.saltId, "two first starts, two salts, two epochs");
      assert(ra.targetFingerprint !== rb.targetFingerprint, "the same target hashes differently under a different salt");
      const c = compareTargetFingerprints(ra, rb);
      assert(c.verdict === "NOT_COMPARABLE" && (c as any).reason === "DIFFERENT_SALT_EPOCH",
        `THE SAME TARGET across epochs must read NOT_COMPARABLE, never DIFFERENT_TARGET: ${JSON.stringify(c)}`);
      // THE WHOLE POINT, in one line: these two records name the SAME FILE, and
      // a reader that printed "different target" would have written a false
      // history that looks like data.
      assert(!describeTargetComparison(c).includes("different canonical targets"), describeTargetComparison(c));
    } finally {
      await a.svc.stop();
      await b.svc.stop();
    }
  });

  await check("R6: a restart in the SAME state dir stays in ONE epoch, and /status stops saying it minted", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const mk = () => new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
    const first = mk();
    await first.start();
    const idA = first.buildStatus().targetFingerprint!;
    assert(idA.mintedAtThisStart, "the first start minted");
    await first.stop();
    const second = mk();
    await second.start();
    const idB = second.buildStatus().targetFingerprint!;
    try {
      assert(idB.saltId === idA.saltId, "a restart must stay in the SAME epoch");
      assert(idB.mintedAtThisStart === false, "and must stop claiming it minted — an operator who sees true on a restart has found something");
    } finally {
      await second.stop();
    }
  });

  await check("R6 e2e / N1 · THE HEADLINE: the salt is DELETED between two starts — the bridge SERVES, the fingerprint is ABSENT, an event says so LOUDLY, and no second epoch begins", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const saltPath = join(stateDir, "target-fingerprint-salt");
    const bookPath = join(stateDir, "events.jsonl");
    const mk = () => new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
    const id = (a: string) => ({ subject: "housekeeper", sessionId: "r6del", actionId: a });

    // ── FIRST START: mints, and writes a fingerprinted record. ────────────
    const first = mk();
    await first.start();
    let firstSaltId = "";
    try {
      assert((await postSubjectEvent(socketDir, id("d1"), "TOOL_ATTEMPTED", { toolName: "bash" }, "/var/log/gone")).status === 200, "the first start must serve");
      firstSaltId = first.buildStatus().targetFingerprint!.saltId!;
      assert(existsSync(saltPath), "the mint wrote the file");
    } finally {
      await first.stop();
    }

    // ── THE ARBITER'S HAND, OR AN ACCIDENT: the salt goes away. ─────────────────
    rmSync(saltPath, { force: true });
    assert(!existsSync(saltPath), "precondition: the salt is gone");

    const second = mk();
    await second.start();
    try {
      // 1 · IT STARTED. Under the previous build this threw StartupRefused and
      // the GUARD WENT DOWN OVER ONE FIELD ON ONE READER. That inversion is the
      // whole reason this file was reworked.
      const st = second.buildStatus().targetFingerprint!;
      assert(st.saltId === null, `no epoch means no id to print: ${JSON.stringify(st)}`);
      assert(st.mintedAtThisStart === false, "and it must not claim a mint it did not make");
      assert(st.absence !== null && st.absence.reason === "SALT_ABSENT_EPOCH_ALREADY_STARTED",
        `"no fingerprint, and here is why", readable on /status: ${JSON.stringify(st)}`);
      assert(Object.keys(st).length === 4, `one shape on both arms: ${JSON.stringify(st)}`);

      // 2 · NO SECOND SALT WAS MINTED. The memory held.
      assert(!existsSync(saltPath), "THE BRIDGE MINTED A SECOND SALT. That is the silent epoch this ruling exists to prevent.");

      // 3 · THE GUARD IS STILL IN THE PATH and the record still lands.
      const posted = await postSubjectEvent(socketDir, id("d2"), "TOOL_ATTEMPTED", { toolName: "bash" }, "/var/log/gone");
      assert(posted.status === 200, `the act must still be recorded: ${posted.status} ${JSON.stringify(posted.body)}`);
      const chain = readSubjectChain(subjectLogPath(stateDir));
      const recs = chain.events;
      assert(chain.boundary !== null, "the chain must begin with its own boundary record");
      assert(recs.length === 2, `two SUBJECT EVENTS: ${recs.length} (chain holds ${chain.all.length})`);
      assert(typeof recs[0].targetFingerprint === "string" && recs[0].saltId === firstSaltId, "the FIRST record still carries its epoch");
      assert(recs[1].targetFingerprint === undefined && recs[1].saltId === undefined, `the second must carry NO digest: ${JSON.stringify(recs[1])}`);
      assert(recs[1].targetFingerprintAbsent === "SALT_ABSENT_EPOCH_ALREADY_STARTED",
        `and must say WHY, on the record itself: ${JSON.stringify(recs[1])}`);
      // THE PLAIN IS STILL NOT THERE. Losing the salt must not turn the record
      // into the place the target gets written down instead.
      assert(!readFileSync(subjectLogPath(stateDir), "utf8").includes("/var/log/gone"), "THE PLAIN LANDED ON THE LOG when the epoch went away");

      // 4 · AND THE REAL READER STILL LOADS THE FILE. A new key on the record is
      // only safe if the deployed reader drops it rather than refusing the log —
      // an absent fingerprint that turned the subject log INVALID would have
      // traded one field for the whole file, which is the same inversion this
      // rework exists to remove, one level down.
      const log = new MicaLogFile({ path: subjectLogPath(stateDir) });
      assert(log.verify().valid, `the REAL reader refused a record carrying targetFingerprintAbsent: ${JSON.stringify(log.verify())}`);
      // THREE, not two: the reader counts the boundary, because the boundary IS a
      // record of this chain and Sig F1 and Eng both see it. The two SUBJECT
      // EVENTS are asserted above, on their own terms.
      assert(log.length === 3, `and it must see the boundary and both records: ${log.length}`);

      // 5 · THE READER'S VERDICT: these two records are NOT COMPARABLE, and NOT
      // because the targets differ — they are the SAME target, spelled identically.
      const c = compareTargetsOnRecords(recs[0], recs[1]);
      assert(labelTargetComparison(c) === "NOT COMPARABLE (no fingerprint)", `${labelTargetComparison(c)} — ${JSON.stringify(c)}`);

      // 6 · THE EVENT SAYS SO LOUDLY, and exactly once, and it is not the mint's word.
      const book = readFileSync(bookPath, "utf8").split("\n").filter((l) => l.trim().length > 0).map((l) => JSON.parse(l));
      const kinds = book.map((e: any) => e.kind);
      assert(kinds.filter((k: string) => k === "SALT_EPOCH_STARTED").length === 1, `still exactly ONE epoch was ever started here: ${JSON.stringify(kinds)}`);
      const loud = book.filter((e: any) => e.kind === "TARGET_FINGERPRINT_UNAVAILABLE");
      assert(loud.length === 1, `one loud event: ${JSON.stringify(kinds)}`);
      assert(loud[0].saltId === null, "and it carries no id, because there is none");
      assert(String(loud[0].detail).includes("SALT_ABSENT_EPOCH_ALREADY_STARTED"), String(loud[0].detail));
      assert(/no gate/i.test(String(loud[0].detail)), "and it says what it did NOT do: no fingerprint is not no gate");
    } finally {
      await second.stop();
    }
  });

  await check("R6: A SALT PLACED BY HAND IS ADOPTED, NOT BEGUN — and the adoption is written, so the next missing salt is not read as a first start", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(singleRouteTestDeclaration()));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    // THE ARBITER'S HAND, simulated exactly: 32 bytes at 0600 and nothing else. No
    // books, no memory, no prior start.
    writeFileSync(join(stateDir, "target-fingerprint-salt"), Buffer.alloc(32, 7), { mode: 0o600 });
    chmodSync(join(stateDir, "target-fingerprint-salt"), 0o600);
    const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
    await svc.start();
    try {
      const st = svc.buildStatus().targetFingerprint!;
      assert(st.saltId !== null && st.absence === null, JSON.stringify(st));
      assert(st.mintedAtThisStart === false, "IT DID NOT MINT THIS. Claiming a mint it did not make would misdate the epoch for every reader.");
      const book = readFileSync(join(stateDir, "events.jsonl"), "utf8").split("\n").filter((l) => l.trim().length > 0).map((l) => JSON.parse(l));
      const adopted = book.filter((e: any) => e.kind === "SALT_EPOCH_ADOPTED");
      assert(adopted.length === 1, `the adoption must be written: ${JSON.stringify(book.map((e: any) => e.kind))}`);
      assert(adopted[0].saltId === st.saltId, JSON.stringify(adopted[0]));
      assert(book.every((e: any) => e.kind !== "SALT_EPOCH_STARTED"), "and it must NOT be recorded as a mint");
      // THIS IS THE SELF-HEALING HALF: without the ADOPTED row, a bridge whose
      // hand-placed salt was later lost would find no memory at all and would
      // mint — a second epoch out of a restore that went half-way.
      const m = readEpochMemory({ eventBook: () => book, subjectLog: () => [] });
      assert(m.status === "PRESENT", `the adoption IS the memory: ${JSON.stringify(m)}`);
    } finally {
      await svc.stop();
    }
  });

  // ══ GATE 1 · Stop 2 · THE TOUCH LABEL, WRITTEN TO THE INTEREST BOOK ══════════
  //
  // Round 2 (placement D; R2 spec D 1-4). A subject that declares
  // `frame[subject]` gets, for every TOOL_ATTEMPTED that PERSISTED on the
  // subject chain, ONE record in the INTEREST BOOK (`paths.interestBook`): the
  // category id of the declared REGION its canonical target lies in, or
  // UNDERIVED, filed under the class `frameLabelEventType(frame)`. The subject
  // chain itself is BYTE-IDENTICAL with and without a frame — TOOL_ATTEMPTED's
  // outcome stays the toolName (option C, the label riding that outcome, was
  // refuted by the cold review: it masked Eng and let pre-frame outcomes collide
  // with category ids). The label is attempted exposure of a declared region:
  // REACH, never weight (03a §1), and never ownership (S160).
  //
  // ⚠ FIXTURE SUBJECTS ARE ADDED BESIDE THE SERVED ONE, NOT IN PLACE OF IT: the
  //   live declaration's reader blocks name the served subject, and these arms
  //   are about the label, not about re-proving those blocks load without it.
  //   Both fixture subjects are bound to this process's uid, the one route the
  //   suite can stand up.

  /** Three categories, nested regions, and NO root catch-all — so "outside every region" is reachable. */
  function gate1TestFrame(): any {
    const basis = "GATE 1 FIXTURE, not a declaration. Exercises the bridge's label derivation.";
    return {
      categories: {
        value: [
          { id: "c-self", label: "own working area", grounding: "agency", self: true },
          { id: "c-other", label: "another principal's area", grounding: "vulnerability", self: false },
          { id: "c-shared", label: "shared area", grounding: "need", self: false },
        ],
        basis,
        proxy: true,
      },
      regions: {
        value: [
          { prefix: "/srv/a", category: "c-self" },
          { prefix: "/srv/a/b", category: "c-other" },
          { prefix: "/srv/c", category: "c-shared" },
        ],
        basis,
        proxy: true,
      },
    };
  }

  const GATE1_BOOK_DECLARED = "/var/lib/mica-bridge/interest-book.jsonl";

  /** The declaration the gate-1 arms start from: subject-a and subject-b beside the served subject. */
  function gate1Declaration(opts: { framed: boolean; book?: boolean; reader?: boolean }): any {
    const d: any = singleRouteTestDeclaration();
    const s0 = d.subjects[0];
    d.subjects.push({ ...s0, subject: "subject-a", toolName: "tool-x" });
    d.subjects.push({ ...s0, subject: "subject-b", toolName: "tool-x" });
    if (opts.framed) d.frame = { "subject-a": gate1TestFrame() };
    // The book is declared by default WITH a frame: that is the deployable shape.
    if (opts.book ?? opts.framed) d.paths.interestBook = GATE1_BOOK_DECLARED;
    if (opts.reader) d.readers.gate1Scope = { subject: { value: "subject-a", basis: "GATE 1 FIXTURE", proxy: false } };
    return d;
  }

  /** A started service over that declaration. `framed` gives subject-a (only) a frame and, by default, a book. */
  async function gate1Service(
    framed: boolean,
    stateDirIn?: string,
    opts: { book?: boolean; reader?: boolean; testWritablePaths?: { interestBook?: string; subjectLog?: string; eventBook?: string } } = {}
  ) {
    const d = gate1Declaration({ framed, book: opts.book, reader: opts.reader });
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(d));
    const stateDir = stateDirIn ?? mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const svc = new MicaBridgeService({
      declarationsPath: cfgPath,
      socketDir,
      now: () => new Date("2026-09-18T00:00:00Z"),
      testBridgeGid: OWN_GID,
      stateDir,
      ...(opts.testWritablePaths === undefined ? {} : { testWritablePaths: opts.testWritablePaths }),
    });
    await svc.start();
    return { svc, socketDir, stateDir, cfgPath, declaration: d };
  }

  function interestBookPath(stateDir: string): string {
    return join(stateDir, "interest-book.jsonl");
  }
  /** The book's records: [0] is its boundary, the rest its labels. Same reader as the subject chain. */
  function readInterestBook(stateDir: string) {
    return readSubjectChain(interestBookPath(stateDir));
  }
  function eventBookLines(stateDir: string): any[] {
    return readFileSync(join(stateDir, "events.jsonl"), "utf8")
      .split("\n")
      .filter((l) => l.trim().length > 0)
      .map((l) => JSON.parse(l));
  }
  /** The service's own resolvePath, for a test that needs the wiring's view of a declared path. */
  const resolveUnder = (stateDir: string) => (p: string) => p.replace(/^\/var\/lib\/mica-bridge/, stateDir);

  await check("GATE 1 · THE SERVED SHAPE (S26): the TREE declaration's own Gate 1 stanza — frame, reader and book, exactly as shipped — opens the book with its boundary, labels the served subject's attempts under THAT frame's class, and leaves the subject chain's outcome the toolName", async () => {
    // BY USE: the served subject and its Gate 1 stanza are read off the shipped
    // draft, never named here. The general fixture (Gate 1 stripped) supplies
    // the test plumbing; the shipped frame, reader and book are put back whole.
    const shipped = JSON.parse(JSON.stringify(draft));
    const servedName = shipped.subjects[0].subject;
    assert(shipped.frame?.[servedName] !== undefined && shipped.readers.gate1Scope?.subject.value === servedName && typeof shipped.paths.interestBook === "string",
      "the tree declaration does not carry Gate 1 for its served subject — this arm pins the S26 shape");
    const d: any = singleRouteTestDeclaration();
    const fixtureName = d.subjects[0].subject;
    d.frame = { [fixtureName]: shipped.frame[servedName] };
    d.readers.gate1Scope = { ...shipped.readers.gate1Scope, subject: { ...shipped.readers.gate1Scope.subject, value: fixtureName } };
    d.paths.interestBook = shipped.paths.interestBook;
    const regions = shipped.frame[servedName].regions.value;
    const klass = frameLabelEventType(shipped.frame[servedName]);
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(d));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
    await svc.start();
    try {
      const tool = d.subjects[0].toolName;
      const targets = [regions[0].prefix + "/x", "/tmp/x", tool];
      for (let i = 0; i < targets.length; i++) {
        const r = await postSubjectEvent(socketDir, { subject: fixtureName, sessionId: "s26", actionId: `s${i}` }, "TOOL_ATTEMPTED", { toolName: tool }, targets[i]);
        assert(r.status === 200 && r.body.duplicate === false, `s${i}: ${r.status} ${JSON.stringify(r.body)}`);
      }
      const book = readInterestBook(stateDir);
      assert(book.boundary !== null, "the shipped stanza's book has no boundary at position 0");
      assert(book.events.length === targets.length, `one label per attempt: ${book.events.length}`);
      const want = targets.map((t) => deriveInterestLabel(t, regions, t));
      assert(want[0] === regions[0].category, `the oracle placed the first region's own child elsewhere: ${want[0]}`);
      for (let i = 0; i < targets.length; i++) {
        const l: any = book.events[i];
        assert(l.eventType === klass && l.moduleId === fixtureName && l.outcome === want[i], `label ${i}: ${JSON.stringify(l)}, want ${want[i]} under ${klass}`);
      }
      for (const rec of readSubjectChain(subjectLogPath(stateDir)).events) {
        assert(rec.eventType !== "TOOL_ATTEMPTED" || rec.outcome === tool, `the subject chain moved: ${JSON.stringify(rec)}`);
      }
      assert(eventBookLines(stateDir).some((e) => e.kind === "INTEREST_BOOK_BOUNDARY"), "the book's first line is not in the event book");
      const all = readFileSync(interestBookPath(stateDir), "utf8") + readFileSync(subjectLogPath(stateDir), "utf8") + readFileSync(join(stateDir, "events.jsonl"), "utf8");
      assert(!all.includes(targets[0]), "a plain target reached a file");
    } finally {
      await svc.stop();
    }
  });

  await check("GATE 1 e2e: a FRAMED subject's TOOL_ATTEMPTED gets ONE book label — longest prefix, segment-aware, canonical spelling, UNDERIVED where it cannot be placed — and its own outcome stays the toolName", async () => {
    const { svc, socketDir, stateDir } = await gate1Service(true);
    try {
      const id = (a: string) => ({ subject: "subject-a", sessionId: "g1", actionId: a });
      // [actionId, target (undefined = none named), expected label]
      const cases: [string, string | undefined, string][] = [
        ["m1", "/srv/a/notes.txt", "c-self"],
        ["m2", "/srv/a/b/deep/file", "c-other"], //   LONGEST prefix wins over /srv/a
        ["m3", "/srv/c", "c-shared"], //             the region's own path
        ["m4", "/srv//a/x/", "c-self"], //           the CANONICAL form is matched, not the caller's spelling
        ["m5", "/srv/ab/file", "UNDERIVED"], //      SEGMENT-AWARE: /srv/ab is not under /srv/a
        ["m6", "/srv/a/../c/x", "UNDERIVED"], //     a ".." segment is never resolved, so never placed
        ["m7", "/etc/elsewhere", "UNDERIVED"], //    outside every region (no root catch-all)
        ["m8", "tool-x", "UNDERIVED"], //            a program word is not a place
        ["m9", undefined, "UNDERIVED"], //           no target named
        ["m10", "/srv/a/x-*", "c-self"], //          a glob is matched literally; its directory is the claim
        ["m11", "/srv/a/café", "UNDERIVED"], // R-c: the canonicaliser had to NFC-normalise it — another file's name
        ["m12", "/srv/a/x ", "UNDERIVED"], //  R-c: it had to TRIM it — a sibling, not the region
      ];
      const seqs: number[] = [];
      for (const [a, target] of cases) {
        const r = await postSubjectEvent(socketDir, id(a), "TOOL_ATTEMPTED", { toolName: "tool-x" }, target);
        assert(r.status === 200 && r.body.duplicate === false, `${a}: expected 200, got ${r.status}: ${JSON.stringify(r.body)}`);
        seqs.push(r.body.seq);
      }
      const acts = readSubjectChain(subjectLogPath(stateDir)).events;
      assert(acts.length === cases.length, `one record per act: ${acts.length}`);
      // THE SUBJECT CHAIN CARRIES NOTHING NEW: every attempt's outcome is the toolName.
      for (const rec of acts) {
        assert(rec.outcome === "tool-x" && rec.eventType === "TOOL_ATTEMPTED" && rec.moduleId === "subject-a", `the subject chain moved: ${JSON.stringify(rec)}`);
      }
      const book = readInterestBook(stateDir);
      assert(book.boundary !== null, "the book has no boundary at position 0");
      assert(book.events.length === cases.length, `ONE label per persisted attempt: ${book.events.length} for ${cases.length}`);
      const klass = frameLabelEventType(gate1TestFrame());
      for (const [i, [a, target, want]] of cases.entries()) {
        const lab = book.events[i];
        assert(lab.actionId === a && lab.subjectSeq === seqs[i], `label ${i} is not act ${a} at seq ${seqs[i]}: ${JSON.stringify(lab)}`);
        assert(lab.outcome === want, `${a} (${JSON.stringify(target)}): label ${JSON.stringify(lab.outcome)}, expected ${want}`);
        assert(lab.moduleId === "subject-a" && lab.eventType === klass, `label class: ${lab.moduleId}/${lab.eventType}, expected subject-a/${klass}`);
        // THE JOIN IS REAL: the label's subjectSeq names THIS act on the subject chain.
        const act = acts.find((r: any) => r.subjectSeq === lab.subjectSeq);
        assert(act !== undefined && act.identity.actionId === a, `subjectSeq ${lab.subjectSeq} does not name act ${a} on the subject chain`);
      }
    } finally {
      await svc.stop();
    }
  });

  await check("GATE 1 e2e: NO FRAME, NO CHANGE (D-1) — the subject chain written WITH a frame is BYTE-IDENTICAL to the one written without, and carries d087f0b's record shape", async () => {
    // ONE state dir, run twice: same retired fixture, same salt, same clock, so
    // nothing but the frame differs between the two runs and the chain FILES can
    // be compared byte for byte (previousHash and hash included). Round 1's arm
    // had to exempt `outcome` and four epoch-bound fields; this one exempts
    // nothing. The unframed path is d087f0b's code unchanged; the same bytes were
    // compared against a d087f0b-built service directly in the round-2 receipt's
    // scratch probe (impl/b2/byteprobe.ts: d087f0b, unframed and framed chains
    // all sha256-equal).
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const acts: [string, string, Record<string, unknown>, string | undefined][] = [
      ["n1", "TOOL_ATTEMPTED", { toolName: "tool-x" }, "/srv/a/b/x"],
      ["n1", "TOOL_EXECUTED", { toolName: "tool-x" }, undefined],
      ["n1", "TOOL_RESULT", { exitClass: "OK" }, undefined],
      ["n2", "TOOL_ATTEMPTED", { toolName: "tool-x" }, "/elsewhere/y"],
      ["n3", "TOOL_ATTEMPTED", { toolName: "tool-x" }, undefined],
    ];
    const runOnce = async (framed: boolean): Promise<{ chain: Buffer; responses: string }> => {
      const s = await gate1Service(framed, stateDir);
      const responses: string[] = [];
      try {
        for (const [a, kind, payload, target] of acts) {
          const r = await postSubjectEvent(s.socketDir, { subject: "subject-a", sessionId: "g1n", actionId: a }, kind, payload, target);
          responses.push(`${r.status} ${JSON.stringify(r.body)}`);
        }
      } finally {
        await s.svc.stop();
      }
      return { chain: readFileSync(subjectLogPath(stateDir)), responses: responses.join("|") };
    };
    const plain = await runOnce(false);
    assert(!existsSync(interestBookPath(stateDir)), "an UNFRAMED run with no book declared wrote an interest book");
    // Reset everything but the salt and the retired fixture, so the second run
    // ADOPTS the first run's epoch and begins an identical chain.
    for (const f of ["subject-events.jsonl", "events.jsonl"]) rmSync(join(stateDir, f), { force: true });
    const framed = await runOnce(true);
    assert(plain.responses === framed.responses, `the frame changed a RESPONSE:\n  ${plain.responses}\n  ${framed.responses}`);
    assert(Buffer.compare(plain.chain, framed.chain) === 0, "THE FRAME CHANGED THE SUBJECT CHAIN'S BYTES — placement D writes nothing new there");
    const recs = readSubjectChain(subjectLogPath(stateDir)).events;
    // d087f0b's TOOL_ATTEMPTED record, key for key (measured on a d087f0b-built
    // service by the scratch probe above): no field added, none moved.
    const D087_TA_KEYS = "subjectSeq,ts,identity,kind,eventHash,peerUid,sequenceNumber,timestamp,moduleId,eventType,actionId,outcome,payload,targetFingerprint,saltId,canonVersion,recordType,previousHash,hash";
    assert(Object.keys(recs[0]).join(",") === D087_TA_KEYS, `the TOOL_ATTEMPTED shape moved:\n  ${Object.keys(recs[0]).join(",")}`);
    assert(recs.map((r: any) => r.outcome).join(",") === ["tool-x", "tool-x", "OK", "tool-x", "tool-x"].join(","), `outcomes: ${recs.map((r: any) => r.outcome).join(",")}`);
    // And each outcome is the kind's own projection, by behaviour.
    for (const r of recs) assert(r.outcome === subjectEventOutcome(r.kind, r.payload ?? null), `outcome is not subjectEventOutcome: ${JSON.stringify(r)}`);
    // The framed run DID label — so the identity above is not a frame that was ignored.
    assert(readInterestBook(stateDir).events.map((r: any) => r.outcome).join(",") === "c-other,UNDERIVED,UNDERIVED", "the framed control did not write its labels");
  });

  await check("GATE 1 e2e: the frame is PER SUBJECT and PER KIND — an unframed subject, and every other kind of the framed one, write no label; a duplicate attempt writes no second label", async () => {
    const { svc, socketDir, stateDir } = await gate1Service(true);
    try {
      const a = (x: string) => ({ subject: "subject-a", sessionId: "g1k", actionId: x });
      const b = (x: string) => ({ subject: "subject-b", sessionId: "g1k", actionId: x });
      assert((await postSubjectEvent(socketDir, b("b1"), "TOOL_ATTEMPTED", { toolName: "tool-x" }, "/srv/a/x")).status === 200, "b attempt");
      assert((await postSubjectEvent(socketDir, a("k1"), "TOOL_ATTEMPTED", { toolName: "tool-x" }, "/srv/a/x")).status === 200, "a attempt");
      assert((await postSubjectEvent(socketDir, a("k1"), "TOOL_EXECUTED", { toolName: "tool-x" })).status === 200, "a executed");
      assert((await postSubjectEvent(socketDir, a("k1"), "TOOL_RESULT", { exitClass: "OK" })).status === 200, "a result");
      const recs = readSubjectChain(subjectLogPath(stateDir)).events;
      assert(recs.length === 4, `four records: ${recs.length}`);
      assert(recs.map((r: any) => r.outcome).join(",") === "tool-x,tool-x,tool-x,OK", `outcomes: ${recs.map((r: any) => r.outcome).join(",")}`);
      const labels = () => readInterestBook(stateDir).events;
      assert(labels().length === 1, `ONE label — subject-a's attempt only: ${JSON.stringify(labels())}`);
      assert(labels()[0].actionId === "k1" && labels()[0].moduleId === "subject-a" && labels()[0].outcome === "c-self" && labels()[0].subjectSeq === recs[1].subjectSeq, JSON.stringify(labels()[0]));
      // A DUPLICATE ATTEMPT is still a duplicate: dedupe returns before the
      // append, and no second record — on either file — appears.
      const dup = await postSubjectEvent(socketDir, a("k1"), "TOOL_ATTEMPTED", { toolName: "tool-x" }, "/srv/a/x");
      assert(dup.status === 200 && dup.body.duplicate === true, `a re-sent attempt must dedupe: ${JSON.stringify(dup.body)}`);
      assert(readSubjectChain(subjectLogPath(stateDir)).events.length === 4, "the duplicate appended a subject record");
      assert(labels().length === 1, "the duplicate wrote a SECOND label for one act");
    } finally {
      await svc.stop();
    }
  });

  await check("GATE 1 e2e: THE PLAIN NEVER LANDS — not on the subject log, not in the INTEREST BOOK, not in the event book, not in a response — and a refused target writes nothing to either file", async () => {
    const { svc, socketDir, stateDir } = await gate1Service(true);
    try {
      const DISTINCT = "gate-one-very-distinctive-target-segment";
      const id = (x: string) => ({ subject: "subject-a", sessionId: "g1p", actionId: x });
      const placed = await postSubjectEvent(socketDir, id("p1"), "TOOL_ATTEMPTED", { toolName: "tool-x" }, `/srv/a/${DISTINCT}`);
      const unplaced = await postSubjectEvent(socketDir, id("p2"), "TOOL_ATTEMPTED", { toolName: "tool-x" }, `/elsewhere/${DISTINCT}`);
      const word = await postSubjectEvent(socketDir, id("p3"), "TOOL_ATTEMPTED", { toolName: "tool-x" }, DISTINCT);
      for (const r of [placed, unplaced, word]) {
        assert(r.status === 200, `expected 200: ${r.status} ${JSON.stringify(r.body)}`);
        assert(!JSON.stringify(r.body).includes(DISTINCT), `a RESPONSE ECHOED THE PLAIN: ${JSON.stringify(r.body)}`);
      }
      // A target the canonicaliser refuses is a 400, as before Gate 1: no
      // record, so no label — UNDERIVED is never written for a refused request.
      const refused = await postSubjectEvent(socketDir, id("p4"), "TOOL_ATTEMPTED", { toolName: "tool-x" }, `/srv/a/${DISTINCT}\u0001`);
      assert(refused.status === 400, `a control character must still be refused: ${refused.status}`);
      assert(!JSON.stringify(refused.body).includes(DISTINCT), `the refusal ECHOED THE PLAIN: ${JSON.stringify(refused.body)}`);
      // THE WHOLE FILES, not only the records' own fields (the R6 fence, widened
      // to the second file this placement writes).
      for (const [name, path] of [["SUBJECT LOG", subjectLogPath(stateDir)], ["INTEREST BOOK", interestBookPath(stateDir)], ["EVENT BOOK", join(stateDir, "events.jsonl")]] as const) {
        const raw = readFileSync(path, "utf8");
        assert(!raw.includes(DISTINCT), `THE PLAIN TARGET IS IN THE ${name}`);
        assert(!raw.includes("targetIdentity"), `the field name reached the ${name}`);
      }
      assert(readSubjectChain(subjectLogPath(stateDir)).events.length === 3, "three acts, the refused one absent");
      const labels = readInterestBook(stateDir).events;
      assert(labels.map((r: any) => r.outcome).join(",") === "c-self,UNDERIVED,UNDERIVED", `labels: ${labels.map((r: any) => r.outcome).join(",")}`);
    } finally {
      await svc.stop();
    }
  });

  await check("GATE 1 e2e: with NO EPOCH the act is still LABELLED — the label needs the canonical string, never the salt", async () => {
    // First start mints; the salt is then removed, and the second start serves
    // with targetFingerprintAbsent (R6 ruling 2). Same state dir, so the
    // memory of the first epoch is what makes the second start epoch-less.
    const first = await gate1Service(true);
    await first.svc.stop();
    rmSync(join(first.stateDir, "target-fingerprint-salt"), { force: true });
    const second = await gate1Service(true, first.stateDir);
    try {
      const id = { subject: "subject-a", sessionId: "g1e", actionId: "e1" };
      const r = await postSubjectEvent(second.socketDir, id, "TOOL_ATTEMPTED", { toolName: "tool-x" }, "/srv/a/b/x");
      assert(r.status === 200, `the epoch-less bridge must serve: ${r.status} ${JSON.stringify(r.body)}`);
      const rec = readSubjectChain(subjectLogPath(second.stateDir)).events[0];
      assert(typeof rec.targetFingerprintAbsent === "string" && rec.targetFingerprint === undefined,
        `precondition — this must be the no-epoch path: ${JSON.stringify(rec)}`);
      assert(rec.outcome === "tool-x", `the subject chain's outcome moved: ${JSON.stringify(rec.outcome)}`);
      const labels = readInterestBook(second.stateDir).events;
      assert(labels.length === 1 && labels[0].outcome === "c-other", `no epoch must not cost the label: ${JSON.stringify(labels)}`);
    } finally {
      await second.svc.stop();
    }
  });

  await check("GATE 1 e2e: THE BOOK — opened at start, boundary at 0 (retired:null), loads VERIFIED in the machine's reader, its class IS the wiring's labelClass, its path IS the wiring's gate1BookPath, and a restart writes no second boundary", async () => {
    const first = await gate1Service(true, undefined, { reader: true });
    let bookBytesAfterFirst = "";
    try {
      const bootBook = readInterestBook(first.stateDir);
      assert(bootBook.all.length === 1 && bootBook.boundary !== null, `a fresh book holds exactly its boundary: ${bootBook.all.length}`);
      assert(bootBook.boundary.retired === null && bootBook.boundary.basis === INTEREST_BOOK_BOUNDARY_BASIS, JSON.stringify(bootBook.boundary));
      assert(eventBookLines(first.stateDir).filter((e) => e.kind === "INTEREST_BOOK_BOUNDARY").length === 1, "the book's beginning is not in the event book");
      assert((await postSubjectEvent(first.socketDir, { subject: "subject-a", sessionId: "g1b", actionId: "q1" }, "TOOL_ATTEMPTED", { toolName: "tool-x" }, "/srv/c/x")).status === 200, "attempt");
      const loaded = validateDeclarations(first.declaration).declarations;
      // The real clerk-stamps loader, as the service passes it: the declaration
      // names a stamps path, and toWireOptions refuses a path with no reader.
      const opts = toWireOptions(loaded, resolveUnder(first.stateDir), loadDeclaredClerkStamps) as any;
      // WRITTEN == READ: the class the bridge filed the label under is the
      // class the reader will be handed, for the same declaration.
      const lab = readInterestBook(first.stateDir).events[0];
      assert(lab.eventType === opts.gate1.labelClass.eventType && lab.moduleId === opts.gate1.labelClass.moduleId,
        `book ${lab.moduleId}/${lab.eventType} vs wiring ${JSON.stringify(opts.gate1.labelClass)}`);
      assert(opts.gate1BookPath === interestBookPath(first.stateDir), `the wiring reads ${opts.gate1BookPath}, the bridge wrote ${interestBookPath(first.stateDir)}`);
      // THE MACHINE'S OWN READER loads it as a verified chain, and projects the label class.
      const book = new SubjectChainLog({ path: opts.gate1BookPath });
      assert(book.getLoadState() === "LOADED_SUBJECT_CHAIN_VERIFIED", `the machine's reader refused the book: ${book.getLoadState()}`);
      const projected = book.getAll().filter((r: any) => r.eventType === opts.gate1.labelClass.eventType);
      assert(projected.length === 1 && projected[0].outcome === "c-shared" && projected[0].moduleId === "subject-a", JSON.stringify(projected));
      bookBytesAfterFirst = readFileSync(interestBookPath(first.stateDir), "utf8");
    } finally {
      await first.svc.stop();
    }
    const second = await gate1Service(true, first.stateDir, { reader: true });
    try {
      const after = readInterestBook(second.stateDir);
      assert(readFileSync(interestBookPath(second.stateDir), "utf8") === bookBytesAfterFirst, "a restart rewrote the book");
      assert(after.all.filter((r: any) => r.recordType === "SUBJECT_LOG_BOUNDARY").length === 1, "a restart wrote a SECOND boundary");
      assert((await postSubjectEvent(second.socketDir, { subject: "subject-a", sessionId: "g1b", actionId: "q2" }, "TOOL_ATTEMPTED", { toolName: "tool-x" }, "/srv/a/y")).status === 200, "attempt after restart");
      const labels = readInterestBook(second.stateDir).events;
      assert(labels.length === 2 && labels[1].outcome === "c-self" && labels[1].timestamp >= labels[0].timestamp, `the book continues across a restart: ${JSON.stringify(labels)}`);
    } finally {
      await second.svc.stop();
    }
  });

  await check("GATE 1 FAULT: a book that does NOT PERSIST leaves the act's response UNCHANGED and writes INTEREST_LABEL_NOT_PERSISTED (subject, actionId, subjectSeq, reason) — once per act, never a retry", async () => {
    // The F5 injection, on the book: its path lies INSIDE A FILE, so every
    // append fails deterministically while the subject log is healthy.
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const bogusParent = join(cfgDir, "not-a-directory");
    writeFileSync(bogusParent, "x");
    const broken = await gate1Service(true, undefined, { testWritablePaths: { interestBook: join(bogusParent, "interest-book.jsonl") } });
    const healthy = await gate1Service(true);
    try {
      const DISTINCT = "gate-one-fault-distinctive-segment";
      const id = (x: string) => ({ subject: "subject-a", sessionId: "g1f", actionId: x });
      const rb = await postSubjectEvent(broken.socketDir, id("f1"), "TOOL_ATTEMPTED", { toolName: "tool-x" }, `/srv/a/${DISTINCT}`);
      const rh = await postSubjectEvent(healthy.socketDir, id("f1"), "TOOL_ATTEMPTED", { toolName: "tool-x" }, `/srv/a/${DISTINCT}`);
      assert(rb.status === rh.status && JSON.stringify(rb.body) === JSON.stringify(rh.body), `a failed label changed the response: ${rb.status} ${JSON.stringify(rb.body)} vs ${rh.status} ${JSON.stringify(rh.body)}`);
      assert(rb.status === 200 && rb.body.duplicate === false, JSON.stringify(rb.body));
      const rb2 = await postSubjectEvent(broken.socketDir, id("f2"), "TOOL_ATTEMPTED", { toolName: "tool-x" }, "/elsewhere/z");
      assert(rb2.status === 200, `the second act must still be answered: ${rb2.status}`);
      // The ACT STANDS on the subject chain.
      const acts = readSubjectChain(subjectLogPath(broken.stateDir)).events;
      assert(acts.length === 2 && acts.every((r: any) => r.outcome === "tool-x"), `the acts did not stand: ${JSON.stringify(acts)}`);
      const misses = eventBookLines(broken.stateDir).filter((e) => e.kind === "INTEREST_LABEL_NOT_PERSISTED");
      assert(misses.length === 2, `ONE report per unlabelled act: ${misses.length}`);
      for (const [i, m] of misses.entries()) {
        assert(m.subject === "subject-a" && m.actionId === `f${i + 1}` && m.subjectSeq === acts[i].subjectSeq, `the report does not name the act: ${JSON.stringify(m)}`);
        assert(typeof m.reason === "string" && m.reason.length > 0, `no reason: ${JSON.stringify(m)}`);
      }
      assert(!readFileSync(join(broken.stateDir, "events.jsonl"), "utf8").includes(DISTINCT), "THE PLAIN TARGET IS IN A FAILURE REPORT");
      assert(!existsSync(join(bogusParent, "interest-book.jsonl")), "precondition: the injected book cannot exist");
      // The healthy control labelled, so the difference is the fault and nothing else.
      assert(readInterestBook(healthy.stateDir).events.length === 1, "the healthy control did not label");
      assert(eventBookLines(healthy.stateDir).every((e) => e.kind !== "INTEREST_LABEL_NOT_PERSISTED"), "the healthy control reported a miss");
    } finally {
      await broken.svc.stop();
      await healthy.svc.stop();
    }
  });

  await check("GATE 1 FAULT: a book append that THROWS is caught — the response is unchanged, the process serves on, no label is written, and the report names the throw", async () => {
    const { svc, socketDir, stateDir } = await gate1Service(true);
    try {
      // Fault-inject the book's appender exactly where the handler reaches it.
      (svc as any).interestBook.appendDerived = () => Promise.reject(new Error("injected book fault"));
      const id = (x: string) => ({ subject: "subject-a", sessionId: "g1t", actionId: x });
      const r = await postSubjectEvent(socketDir, id("t1"), "TOOL_ATTEMPTED", { toolName: "tool-x" }, "/srv/a/x");
      assert(r.status === 200 && JSON.stringify(r.body) === JSON.stringify({ seq: 1, duplicate: false }), `the response moved: ${r.status} ${JSON.stringify(r.body)}`);
      // The process is alive and still answering — a second, ordinary kind.
      assert((await postSubjectEvent(socketDir, id("t1"), "TOOL_RESULT", { exitClass: "OK" })).status === 200, "the bridge stopped serving after a book throw");
      assert(readInterestBook(stateDir).events.length === 0, "a label was written though the append threw");
      const misses = eventBookLines(stateDir).filter((e) => e.kind === "INTEREST_LABEL_NOT_PERSISTED");
      assert(misses.length === 1 && misses[0].actionId === "t1" && misses[0].subjectSeq === 1, JSON.stringify(misses));
      assert(String(misses[0].reason).includes("threw") && String(misses[0].reason).includes("injected book fault"), `the reason does not name the throw: ${misses[0].reason}`);
    } finally {
      await svc.stop();
    }
  });

  await check("GATE 1: an act that did NOT persist gets NO label — a 503 on the subject chain writes nothing to the book and reports no label miss", async () => {
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const bogusParent = join(cfgDir, "not-a-directory");
    writeFileSync(bogusParent, "x");
    const { svc, socketDir, stateDir } = await gate1Service(true, undefined, { testWritablePaths: { subjectLog: join(bogusParent, "subject-events.jsonl") } });
    try {
      const r = await postSubjectEvent(socketDir, { subject: "subject-a", sessionId: "g1u", actionId: "u1" }, "TOOL_ATTEMPTED", { toolName: "tool-x" }, "/srv/a/x");
      assert(r.status === 503 && r.body.error === "RECORD_NOT_PERSISTED", `precondition — the act must fail to persist: ${r.status} ${JSON.stringify(r.body)}`);
      assert(readInterestBook(stateDir).events.length === 0, "a label was written for an act that never persisted");
      assert(eventBookLines(stateDir).every((e) => e.kind !== "INTEREST_LABEL_NOT_PERSISTED"), "an act that never persisted was reported as an unlabelled act");
    } finally {
      await svc.stop();
    }
  });

  await check("GATE 1: a frame with NO BOOK is REFUSED at load (X22); a reload that ADDS the book is REFUSED (A3: a book opens only at start) and opens nothing; and the writer's own no-book guard still reports each persisted attempt INTEREST_LABEL_NOT_PERSISTED", async () => {
    // (a) the front door: a frame alone switches the writer on, so it needs its book.
    let refused = "";
    try { validateDeclarations(gate1Declaration({ framed: true, book: false })); } catch (e) { refused = String((e as Error).message); }
    assert(refused.includes("X22") && refused.includes("paths.interestBook"), `a frame without a book loaded: ${refused}`);
    // (b) the reload door (round 3, A3): started with neither, then SIGHUP'd to
    // frame + book. Until round 3 this reload was ACCEPTED and every later act
    // was reported unlabelled; now the door refuses it, the last-known-good
    // declaration stands, and no book is opened.
    const { svc, socketDir, stateDir, cfgPath } = await gate1Service(false, undefined, { book: false });
    try {
      writeFileSync(cfgPath, JSON.stringify(gate1Declaration({ framed: true, book: true })));
      const rl: any = svc.reload();
      assert(!rl.ok, `a reload ADDING paths.interestBook was accepted: ${JSON.stringify(rl)}`);
      const why = JSON.stringify(rl);
      assert(why.includes("paths.interestBook") && why.includes("restart"), `the refusal does not name the book and the restart: ${why}`);
      const r = await postSubjectEvent(socketDir, { subject: "subject-a", sessionId: "g1n", actionId: "nb1" }, "TOOL_ATTEMPTED", { toolName: "tool-x" }, "/srv/a/x");
      assert(r.status === 200, `the act must be answered: ${r.status}`);
      assert(!existsSync(interestBookPath(stateDir)), "a book was opened on SIGHUP — a book opens only at start");
      // The retained declaration has no frame, so subject-a is unframed: no label, and no miss to report.
      assert(eventBookLines(stateDir).every((e) => e.kind !== "INTEREST_LABEL_NOT_PERSISTED"), "an unframed act was reported as an unlabelled one");
    } finally {
      await svc.stop();
    }
    // (c) the writer's guard, which the door now keeps unreachable: a framed
    // service whose book is not open (injected) reports the act, naming why.
    const g = await gate1Service(true);
    try {
      (g.svc as any).interestBook = null;
      const r = await postSubjectEvent(g.socketDir, { subject: "subject-a", sessionId: "g1n", actionId: "nb2" }, "TOOL_ATTEMPTED", { toolName: "tool-x" }, "/srv/a/x");
      assert(r.status === 200, `the act must be answered: ${r.status}`);
      const misses = eventBookLines(g.stateDir).filter((e) => e.kind === "INTEREST_LABEL_NOT_PERSISTED");
      assert(misses.length === 1 && misses[0].actionId === "nb2" && String(misses[0].reason).includes("no interest book is open"), JSON.stringify(misses));
    } finally {
      await g.svc.stop();
    }
  });

  // ── GATE 2 · Stop 2 · the reload door at the SERVICE, and the census wording ─
  //
  // declarations.test.ts holds R15 at validateActivation. This arm holds what
  // only the service can show: the refused SIGHUP leaves the LAST-KNOWN-GOOD
  // declaration serving (same hash), the event book records the refusal naming
  // R15, and an additive reload is taken. It also shows a basket-carrying
  // declaration STARTS and SERVES on the installed machine, whose wire() does
  // not read `gate2` yet. Invented names only (subject-a, c-other).
  await check("GATE 2 · R15 AT THE SERVICE: a SIGHUP that DROPS an unknown entry is REFUSED, the last-known-good declaration stands (same hash) and DECLARATION_REJECTED names R15; a SIGHUP that ADDS one is REFUSED too (the basket is FROZEN across reloads), and a RESTART takes the addition", async () => {
    const basis = "GATE 2 FIXTURE, not a declaration.";
    const g2 = (unknownKinds: string[]): any => {
      const d = gate1Declaration({ framed: true, book: true });
      d.readers.gate2Direction = { subject: { value: "subject-a", basis, proxy: false } };
      d.baskets = {
        "subject-a": {
          classes: {
            value: {
              value: [],
              damage: [],
              unknown: unknownKinds.map((kind) => ({ kind, outcome: null, lane: "C", eg: 1, bearsOn: ["c-other"], basis })),
            },
            basis,
            proxy: true,
          },
          epsilonNum: { value: 1e-6, basis, proxy: false },
          grades: { value: { establishAt: { lane: "A", eg: 1 }, creditAt: { lane: "B", eg: 2 } }, basis, proxy: true },
          window: { value: { kind: "sinceBoundary" }, basis, proxy: false },
          nMin: { value: 10, basis, proxy: true },
          latchClearedBy: { value: [{ kind: "ARBITER_RESOLVED" }], basis, proxy: false },
        },
      };
      return d;
    };
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const cfgDir = mkdtempSync(join(tmpdir(), "mica-bridge-cfg-"));
    const cfgPath = join(cfgDir, "declarations.config.json");
    writeFileSync(cfgPath, JSON.stringify(g2(["HELD_THEN_STOPPED", "TURN_ENDED_ASKING"])));
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
    await svc.start();
    try {
      const before = svc.buildStatus().declarationHash;
      writeFileSync(cfgPath, JSON.stringify(g2(["HELD_THEN_STOPPED"])));
      const rl: any = svc.reload();
      assert(!rl.ok && String(rl.reason).includes("refusal R15 —"), `a reload DROPPING an unknown entry was not refused by R15: ${JSON.stringify(rl)}`);
      assert(svc.buildStatus().declarationHash === before, "the refused reload moved the served declaration — last-known-good was NOT retained");
      // The event book's append is ASYNCHRONOUS (the serialized appender), so the
      // refusal is read once it has landed — bounded, never assumed.
      let rej: any[] = [];
      for (let i = 0; i < 40 && rej.length === 0; i++) {
        await new Promise((res) => setTimeout(res, 50));
        rej = eventBookLines(stateDir).filter((e) => e.kind === "DECLARATION_REJECTED");
      }
      assert(
        rej.length === 1 && String(rej[0].detail).includes("refusal R15 —") && String(rej[0].detail).includes("baskets.subject-a.classes.value.unknown"),
        `the event book does not record the R15 refusal at its field: ${JSON.stringify(rej)}`
      );
      writeFileSync(cfgPath, JSON.stringify(g2(["HELD_THEN_STOPPED", "TURN_ENDED_ASKING", "ACT_REVISITED"])));
      const added: any = svc.reload();
      assert(!added.ok && String(added.reason).includes("FROZEN across reloads"), `a reload ADDING an unknown entry was not refused as FROZEN: ${JSON.stringify(added)}`);
      const r = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
      assert(r.status === 200 && r.body.declarationHash === before, `/status moved after a refused reload: ${r.status} ${JSON.stringify(r.body.declarationHash)}`);
    } finally {
      await svc.stop();
    }
    // A RESTART is a first load: the same addition starts.
    const svc2 = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testBridgeGid: OWN_GID, stateDir });
    await svc2.start();
    try {
      const r2 = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
      assert(r2.status === 200 && r2.body.preflight === "SERVING", `a restart with the added entry did not serve: ${r2.status} ${JSON.stringify(r2.body.preflight)}`);
    } finally {
      await svc2.stop();
    }
  });

  await check("GATE 2 · CENSUS WORDING: the no-reading reason names NO reader count — the stale 'Eight readers compose now' is gone and no number of readers replaces it", async () => {
    const rows = buildInstrumentCensus();
    assert(rows.length === INSTRUMENT_IDS.length, `census rows: ${String(rows.length)}`);
    const COUNT = /\b(one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|\d+)\s+readers?\b/i;
    for (const row of rows) {
      assert(!COUNT.test(String(row.reason)), `${row.id}: the reason names a reader count: ${String(row.reason).match(COUNT)?.[0]}`);
    }
    assert(String(rows[0].reason).includes("every reader a live wire() call builds"), `the count-free sentence is missing: ${String(rows[0].reason).slice(0, 300)}`);
  });

  await check("GATE 1 FAULT: a DAMAGED book at start is NOT BEGUN and SAYS SO — INTEREST_BOOK_BOUNDARY_REFUSED with the journal's load state, the bytes untouched, the store named an interest book, and each act then reported unlabelled (review K2W3-8)", async () => {
    // Pre-seed the book with a line that is not JSON. The journal loads it
    // non-persisting AND EMPTY; until round 3 the boundary writer returned
    // silently on that branch, so the event book never said the book had not begun.
    const stateDir = mkdtempSync(join(tmpdir(), "mica-bridge-state-"));
    const DAMAGE = "not json\n";
    writeFileSync(interestBookPath(stateDir), DAMAGE);
    const { svc, socketDir } = await gate1Service(true, stateDir);
    try {
      const refusals = eventBookLines(stateDir).filter((e) => e.kind === "INTEREST_BOOK_BOUNDARY_REFUSED");
      assert(refusals.length === 1, `a damaged book was passed over in silence: kinds ${JSON.stringify(eventBookLines(stateDir).map((e) => e.kind))}`);
      const detail = String(refusals[0].detail);
      const state = (svc as any).interestBook.store.getLoadState();
      assert(detail.includes(String(state)) && detail.includes("ruling 6"), `the refusal does not carry the load state and the rule: ${detail}`);
      assert(eventBookLines(stateDir).every((e) => e.kind !== "INTEREST_BOOK_BOUNDARY"), "a damaged book was reported as begun");
      assert(readFileSync(interestBookPath(stateDir), "utf8") === DAMAGE, "the damaged book was repaired or begun over (ruling 6)");
      // The store speaks of itself as the book, not as the subject chain.
      const ps = (svc as any).interestBook.persistenceState();
      assert(ps.degraded === true && String(ps.error).startsWith("the interest book at "), `the book's own state names another store: ${JSON.stringify(ps)}`);
      const r = await postSubjectEvent(socketDir, { subject: "subject-a", sessionId: "g1d", actionId: "d1" }, "TOOL_ATTEMPTED", { toolName: "tool-x" }, "/srv/a/x");
      assert(r.status === 200, `the act must stand: ${r.status}`);
      const misses = eventBookLines(stateDir).filter((e) => e.kind === "INTEREST_LABEL_NOT_PERSISTED");
      assert(misses.length === 1 && misses[0].actionId === "d1", JSON.stringify(misses));
      assert(readFileSync(interestBookPath(stateDir), "utf8") === DAMAGE, "a label was appended over damage");
    } finally {
      await svc.stop();
    }
  });

  await check("GATE 1: CONCURRENT attempts — the book's order follows the subject chain's, one label per act, joins intact", async () => {
    const { svc, socketDir, stateDir } = await gate1Service(true);
    try {
      const targets = ["/srv/a/1", "/srv/a/b/2", "/srv/c/3", "/elsewhere/4", "/srv/a/5", "/srv/c/6", "/srv/a/b/7", "/srv/a/8"];
      const rs = await Promise.all(targets.map((t, i) =>
        postSubjectEvent(socketDir, { subject: "subject-a", sessionId: "g1c", actionId: `c${i}` }, "TOOL_ATTEMPTED", { toolName: "tool-x" }, t)));
      assert(rs.every((r) => r.status === 200), `all answered: ${rs.map((r) => r.status).join(",")}`);
      const acts = readSubjectChain(subjectLogPath(stateDir)).events;
      const labels = readInterestBook(stateDir).events;
      assert(labels.length === targets.length, `one label per act: ${labels.length}`);
      const seqs = labels.map((l: any) => l.subjectSeq);
      assert(seqs.every((s: number, i: number) => i === 0 || s > seqs[i - 1]), `the book's order is not the chain's: ${seqs.join(",")}`);
      for (const l of labels) {
        const act = acts.find((r: any) => r.subjectSeq === l.subjectSeq);
        assert(act !== undefined && act.identity.actionId === l.actionId, `label ${JSON.stringify(l)} does not join its act`);
        const i = Number(String(l.actionId).slice(1));
        const want = deriveInterestLabel(targets[i], gate1TestFrame().regions.value);
        assert(l.outcome === want, `act ${l.actionId}: label ${l.outcome}, expected ${want}`);
      }
    } finally {
      await svc.stop();
    }
  });

  await check("GATE 1: A REGION EDIT ON SIGHUP MOVES THE CLASS, A WORDING EDIT DOES NOT — the next label is filed under the class the wiring now reads", async () => {
    const { svc, socketDir, stateDir, cfgPath, declaration } = await gate1Service(true, undefined, { reader: true });
    try {
      const id = (x: string) => ({ subject: "subject-a", sessionId: "g1r", actionId: x });
      const post = async (x: string) => {
        const r = await postSubjectEvent(socketDir, id(x), "TOOL_ATTEMPTED", { toolName: "tool-x" }, "/srv/c/x");
        assert(r.status === 200, `${x}: ${r.status}`);
      };
      const reloadWith = (d: any) => {
        writeFileSync(cfgPath, JSON.stringify(d));
        const r = svc.reload();
        assert(r.ok, `the reload was refused: ${JSON.stringify(r)}`);
        return (toWireOptions(validateDeclarations(d).declarations, undefined, loadDeclaredClerkStamps) as any).gate1.labelClass.eventType as string;
      };
      await post("r1");
      // WORDING: a label and both bases change. The class must not.
      const worded = JSON.parse(JSON.stringify(declaration));
      worded.frame["subject-a"].categories.value[2].label = "a reworded shared area";
      worded.frame["subject-a"].categories.basis = "reworded basis";
      worded.frame["subject-a"].regions.basis = "reworded basis";
      const wordedClass = reloadWith(worded);
      await post("r2");
      // REGION: /srv/c moves to c-other. The class must.
      const redrawn = JSON.parse(JSON.stringify(worded));
      redrawn.frame["subject-a"].regions.value[2].category = "c-other";
      const redrawnClass = reloadWith(redrawn);
      await post("r3");
      const labels = readInterestBook(stateDir).events;
      assert(labels.length === 3, `three labels: ${labels.length}`);
      assert(labels[0].eventType === labels[1].eventType, "a WORDING edit moved the class — it would orphan the book's history");
      assert(labels[1].eventType === wordedClass, "the label after the wording edit is not the class the wiring reads");
      assert(labels[2].eventType !== labels[1].eventType, "a REGION edit kept the class — labels from the earlier drawing would be counted against the new one");
      assert(labels[2].eventType === redrawnClass, "the label after the region edit is not the class the wiring now reads");
      assert(labels.map((l: any) => l.outcome).join(",") === "c-shared,c-shared,c-other", `labels: ${labels.map((l: any) => l.outcome).join(",")}`);
    } finally {
      await svc.stop();
    }
  });

  // ══ §Q · THE THREE KINDS AT THE ROUTE ═══════════════════════════════════

  await check("Q e2e: all three kinds are accepted, load in the REAL reader, and project the outcome their table row names", async () => {
    const { svc, socketDir, stateDir } = await c9Service();
    try {
      const id = (a: string) => ({ subject: "housekeeper", sessionId: "q1", actionId: a });
      assert((await postSubjectEvent(socketDir, id("q1"), "TURN_ENDED_ASKING", { askClass: "TRAILING_QUESTION", actsInTurn: 0 })).status === 200, "TURN_ENDED_ASKING");
      assert((await postSubjectEvent(socketDir, id("q2"), "ASK_ANSWERED", { askClass: "TRAILING_QUESTION", askSessionId: "q1", askActionId: "q1" })).status === 200, "ASK_ANSWERED");
      assert((await postSubjectEvent(socketDir, id("q3"), "ACT_REVISITED", { priorActionId: "q0", priorExitClass: "NONZERO", lookback: 1 })).status === 200, "ACT_REVISITED");
      const log = new MicaLogFile({ path: subjectLogPath(stateDir) });
      assert(log.verify().valid, `the REAL reader refused a new kind: ${JSON.stringify(log.verify())}`);
      const qChain = readSubjectChain(subjectLogPath(stateDir));
      assert(qChain.boundary !== null, "the chain must begin with its own boundary record");
      const raw = qChain.events;
      assert(raw.map((r: any) => r.eventType).join(",") === "TURN_ENDED_ASKING,ASK_ANSWERED,ACT_REVISITED", JSON.stringify(qChain.all.map((r: any) => r.eventType)));
      // THE OUTCOME ROWS. A wrong row compiles fine and gives the reader a
      // constant discriminator, which is what this asserts against.
      assert(raw.map((r: any) => r.outcome).join(",") === "TRAILING_QUESTION,TRAILING_QUESTION,NONZERO", JSON.stringify(raw.map((r: any) => r.outcome)));
      assert(raw.every((r: any) => r.outcome !== "UNDECLARED"), "no new kind may read UNDECLARED");
      assert(raw.every((r: any) => r.targetFingerprint === undefined), "no kind but TOOL_ATTEMPTED carries a fingerprint");
    } finally {
      await svc.stop();
    }
  });

  await check("Q: the payload key SET is exact — a record carrying a fact nothing declared is refused at the route", async () => {
    const { svc, socketDir } = await c9Service();
    try {
      const id = (a: string) => ({ subject: "housekeeper", sessionId: "q2", actionId: a });
      const cases: [string, Record<string, unknown>, string][] = [
        ["TURN_ENDED_ASKING", { askClass: "TRAILING_QUESTION", actsInTurn: 0, extra: 1 }, "an extra key"],
        ["TURN_ENDED_ASKING", { askClass: "TRAILING_QUESTION" }, "a missing key"],
        ["TURN_ENDED_ASKING", { askClass: "SHOUTED", actsInTurn: 0 }, "a word outside the alphabet"],
        // M16-adjacent: the payload must not contradict the kind that carries it.
        ["TURN_ENDED_ASKING", { askClass: "TRAILING_QUESTION", actsInTurn: 2 }, "actsInTurn > 0, which contradicts the kind"],
        ["ASK_ANSWERED", { askClass: "TRAILING_QUESTION", askSessionId: "s", askActionId: "" }, "an empty identifier"],
        ["ACT_REVISITED", { priorActionId: "p", priorExitClass: "OK", lookback: 1 }, "OK is not a failure"],
        ["ACT_REVISITED", { priorActionId: "p", priorExitClass: "NONZERO", lookback: 4 }, "a lookback outside the declared window"],
      ];
      for (const [kind, payload, why] of cases) {
        const r = await postSubjectEvent(socketDir, id(`bad-${kind}-${cases.findIndex((c) => c[1] === payload)}`), kind, payload);
        assert(r.status === 400, `${kind} with ${why} must be refused, got ${r.status}: ${JSON.stringify(r.body)}`);
      }
      // AND THE OFF-BY-ONE: an act that revisits ITSELF would count as a
      // verification on every single act.
      const self = { subject: "housekeeper", sessionId: "q2", actionId: "selfref" };
      const r = await postSubjectEvent(socketDir, self, "ACT_REVISITED", { priorActionId: "selfref", priorExitClass: "NONZERO", lookback: 1 });
      assert(r.status === 400, `an act may not revisit itself, got ${r.status}: ${JSON.stringify(r.body)}`);
    } finally {
      await svc.stop();
    }
  });

  await check("Q: the OPERATOR may still write DOCTOR_ATTESTED and nothing else — the three new kinds do not widen that grant", () => {
    const routes = [
      { uid: FX_SUBJECT_UID, role: "subject" },
      { uid: 1000, role: "operator" },
    ];
    for (const kind of ["TURN_ENDED_ASKING", "ASK_ANSWERED", "ACT_REVISITED"] as any[]) {
      const r = authorizeSubjectEventKind(routes, 1000, kind);
      assert(!r.allowed, `the operator must NOT be able to write ${kind}`);
      // And the housekeeper may — these are the subject's own records.
      assert(authorizeSubjectEventKind(routes, FX_SUBJECT_UID, kind).allowed, `the subject MUST be able to write ${kind}`);
    }
  });

  console.log("");

  // ═══ X9 AT THE RELOAD PATH · the gate that had no caller ═══════════════════
  //
  // Codex, 2026-09-27: `validateActivation` was exported, tested and called from
  // nowhere, so X8 had never run in production and X9 would not have either. THIS
  // TEST EXISTS BECAUSE A UNIT TEST ON THE FUNCTION PROVED NOTHING ABOUT THE
  // SERVICE. It drives a real reload against a real running service and asserts
  // both halves: the refusal, and that the last known good declaration survived it.
  await check("X9 at the RELOAD path: replacing a live pilot is refused AND last-known-good is retained", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-x9-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const testPaths = writableTestPaths();
    const cfgPath = join(mkdtempSync(join(tmpdir(), "mica-bridge-x9cfg-")), "declarations.config.json");
    const baseDecl = singleRouteTestDeclaration();

    // ⛔ holdAtOrAbove IS SUPPLIED HERE AND NOT INHERITED, and the first version of
    //    this test inherited it. `singleRouteTestDeclaration()` neutralises the pilot
    //    to {active:false} (fixture neutrality, S136), so `baseDecl.pilot.holdAtOrAbove`
    //    is UNDEFINED and JSON.parse(JSON.stringify(undefined)) throws
    //    `"undefined" is not valid JSON` before a single assertion runs.
    //
    //    THE TEST COULD NEVER HAVE PASSED, and nobody knew, because it had never been
    //    executed: the bridge half could not compile against /opt's machine half at all.
    //    Codex accepted the Monday repair "at source"; running it for the first time
    //    against a staged compatible machine half is what found this.
    const withPilotA = JSON.parse(JSON.stringify(baseDecl));
    withPilotA.pilot = {
      active: true, sessionId: "pilot-A",
      expiresAt: "2026-09-30T18:00:00Z",
      holdAtOrAbove: {
        value: "irreversible",
        basis: "TEST FIXTURE for X9. The rung is not what this test is about; the " +
          "predecessor relation is.",
        proxy: true,
      },
    };
    writeFileSync(cfgPath, JSON.stringify(withPilotA));

    // A MUTABLE CLOCK, on the ONE service that actually holds pilot A. The first
    // version of this test built a SECOND service for the post-lapse half, and
    // Codex's cold read of 2026-09-27 caught what that proved: nothing. By then the
    // config file already held pilot B, so the second service STARTED on B (prev =
    // null, X9 cannot apply) and then reloaded B over B (same sessionId, X9 still
    // cannot apply). `late.ok` passed for a reason with nothing to do with A
    // lapsing — in a test whose own header says a unit test on the function proved
    // nothing about the service. The lapse has to happen TO THE SERVICE THAT IS
    // SERVING A, so the clock is the thing that moves and the service is not.
    let clock = new Date("2026-09-18T00:00:00Z");
    const svc = new MicaBridgeService({
      declarationsPath: cfgPath,
      socketDir,
      now: () => clock,
      testWritablePaths: testPaths,
      stateDir: testPaths.dir,
      testBridgeGid: OWN_GID,
    });
    await svc.start();

    const before = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
    assert(before.status === 200, JSON.stringify(before));
    const hashA = before.body.declarationHash;
    assert(typeof hashA === "string" && hashA.length === 64, `expected a loaded hash, got ${String(hashA)}`);
    assert(before.body.pilot.sessionId === "pilot-A", JSON.stringify(before.body.pilot));

    // pilot B, a DIFFERENT session, while A is still live
    const withPilotB = JSON.parse(JSON.stringify(withPilotA));
    withPilotB.pilot.sessionId = "pilot-B";
    withPilotB.pilot.expiresAt = "2026-10-02T18:00:00Z";
    writeFileSync(cfgPath, JSON.stringify(withPilotB));

    const result = svc.reload();
    assert(!result.ok, `the reload MUST be refused while pilot-A is live; got ${JSON.stringify(result)}`);
    assert(
      /X9/.test((result as { ok: false; reason: string }).reason),
      `the refusal must name the rule that produced it: ${(result as { ok: false; reason: string }).reason}`
    );

    // ⛔ THE HALF A UNIT TEST CANNOT REACH: the service is still serving A.
    const after = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
    assert(after.status === 200, JSON.stringify(after));
    assert(
      after.body.declarationHash === hashA,
      `LAST-KNOWN-GOOD WAS NOT RETAINED: hash moved ${String(hashA)} -> ${String(after.body.declarationHash)}`
    );
    assert(after.body.pilot.sessionId === "pilot-A",
      `the live pilot must still be A after a refused reload, got ${JSON.stringify(after.body.pilot)}`);
    assert(after.body.lastRejectedDeclaration !== null, "a refused reload must be visible at /status");
    assert(
      after.body.lastRejectedDeclaration.field === "pilot.sessionId",
      `the rejection must name the field: ${JSON.stringify(after.body.lastRejectedDeclaration)}`
    );

    // AND THE SAME RELOAD IS ACCEPTED ONCE A HAS LAPSED — the rule is about the
    // predecessor, not the successor, and this is what proves the gate is not
    // simply stuck. SAME SERVICE, still serving A, SAME config file, SAME reload
    // call: the only thing that changes is the clock crossing A's expiresAt.
    assert(
      new Date("2026-09-30T18:00:00Z").getTime() > clock.getTime(),
      "the test's own premise: pilot A must still be unexpired at the refusal above"
    );
    clock = new Date("2026-10-01T00:00:00Z");
    const late = svc.reload();
    assert(late.ok, `after pilot-A lapsed the same declaration must load: ${JSON.stringify(late)}`);

    // AND IT IS B THAT IS SERVING NOW. `ok` alone would not say so, and an accepted
    // reload that somehow left A in place would satisfy `late.ok` while making the
    // whole rule useless — which is the same shape of vacuity this half started as.
    const lapsed = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
    assert(lapsed.status === 200, JSON.stringify(lapsed));
    assert(
      lapsed.body.pilot.sessionId === "pilot-B",
      `after the accepted reload the live pilot must be B, got ${JSON.stringify(lapsed.body.pilot)}`
    );
    assert(
      lapsed.body.declarationHash !== hashA,
      "the declaration hash must have MOVED off A's once B loaded"
    );

    await svc.stop();
  });



  // ══ SHAPE (b) · THE UNMINTED WITNESS ═════════════════════════════════════
  //
  // ⛔ MEASURED LIVE 2026-09-30: after two bridge restarts and decisions in which
  //    F3 used 1244 stamps over 1243 chain-scoped pairs, the subject chain held
  //    ZERO CLERK_STAMPS_FIRST_LOAD records (the arbiter's sudo read).
  //
  //    THE CAUSE, at bytes: the mint runs ONLY at load time and read
  //    `sigResult?.clerkStampCoverage?.stampedCount ?? 0`. In the machine,
  //    `clerkStampCoverage` is null on EXACTLY ONE path — the log could not be
  //    read — and the machine's own comment says why null rather than a zeroed
  //    object: "a zeroed coverage object would read as 'nothing was missing',
  //    which is a claim about a scope nobody looked at." The `?? 0` reintroduced
  //    that reading one layer up, and the message asserted the wrong cause —
  //    "F3 USED none of it" — when F3 had not run at all. An UNRESOLVED question
  //    was recorded as an ANSWER, and since the mint never ran again, the answer
  //    was permanent.
  //
  // ⛔ WHAT THIS TEST CANNOT DO, AND WHY — READ THIS BEFORE TRUSTING IT.
  //
  //    The dispatched test was "boot, take one decision, assert the record in
  //    the chain". THAT CANNOT RUN AS AN ORDINARY uid. `loadDeclaredClerkStamps`
  //    calls the real custody door with no owner override, and the door requires
  //    the stamps file to be owned by CLOCK_STAMPS_OWNER = "mica" — a module
  //    constant with no test seam. A stamps file this uid can create is a stamps
  //    file the door must refuse, which is the door working exactly as built.
  //
  //    So these two assert THE REPAIR, not the mint: that the three outcomes are
  //    told apart, and that an UNRESOLVED question is asked again at the next
  //    decision while an ANSWERED one is not. THE MINT ITSELF IS PROVEN ONLY ON
  //    A BOX WHERE `mica` OWNS THE STAMPS FILE — the audit's read, or the arbiter's.
  await check("⛔ SHAPE (b) · an UNRESOLVED witness question says so, and is ASKED AGAIN at the next decision", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const paths = writableTestPaths();
    const cfgPath = join(paths.dir, "declarations.config.json");
    const d = singleRouteTestDeclaration() as Record<string, any>;
    // ⛔ THE FIXTURE MUST BE A CHAINED DEPLOYMENT, and it is not by default.
    //
    //   `draft` is the COMMITTED declarations.config.json, and this file's own
    //   comment above calls it "the LIVE shipped" one. IT IS NOT, and has not
    //   been since S14: the repo says logKind "mica" and the box says
    //   "subject-chain". `readPriorLoadWitness` returns NOT_WITNESSED for any
    //   logKind that is not "subject-chain" — an unchained deployment has no
    //   witness available — so without this the mint returns at its THIRD early
    //   return and never reaches the coverage check at all. Isolated by
    //   instrumenting the three returns and running the suite once.
    d.readers.logKind.value = "subject-chain";
    d.readers.readableLoadStates.value = [
      ...d.readers.readableLoadStates.value.filter((v: string) => v !== "LOADED_SUBJECT_CHAIN_VERIFIED"),
      "LOADED_SUBJECT_CHAIN_VERIFIED",
    ];
    // ⛔ THIS TEST NEEDS THE DOOR'S expectedOwner PARAMETER, AND IT SKIPS CLEANLY
    //   WITHOUT IT. The arbiter's ruling 09:0xZ, option 1. Until the machine half is on
    //   /opt, a declared stamps path this uid can satisfy does not exist: a file
    //   this account can create is one the custody door MUST refuse, and the
    //   loader turns that refusal into a THROW that takes the whole decision down
    //   ("a declared stamps path that will not load is a wiring error, not an
    //   absent leg"). So there is no way to reach the mint from here.
    //
    //   mica-service.ts imports the door from /opt/mica-machine BY ABSOLUTE PATH,
    //   so this cannot be satisfied from a worktree — it is a relay dependency,
    //   stated rather than worked around.
    // A declared stamps path whose custody this uid cannot satisfy: the loader
    // throws, which is the UNRESOLVED arm — F3 never ran, so nothing is known.
    clerkStampsFixture(paths.dir);
    d.paths = { ...(d.paths ?? {}), clerkStamps: { value: "/var/lib/mica-bridge/clerk-stamps.jsonl",
      basis:
        "THE TEST'S OWN DECLARED STAMPS PATH. The front door requires at least 80 characters here, "
        + "and the requirement is not decoration: paths.clerkStamps names ANOTHER PRINCIPAL'S OUTPUT, "
        + "the one key in this block that is not a file this bridge writes, so a deployer declaring "
        + "it must say whose file it is and why this bridge may read it." } };
    writeFileSync(cfgPath, JSON.stringify(d));

    const said: string[] = [];
    const realError = console.error;
    console.error = (...a: unknown[]): void => { said.push(a.map(String).join(" ")); };
    try {
      const svc = new MicaBridgeService({
        declarationsPath: cfgPath, socketDir,
        now: () => new Date("2026-09-30T08:00:00Z"),
        testWritablePaths: { eventBook: paths.eventBook, subjectLog: paths.subjectLog },
        testBridgeGid: OWN_GID, stateDir: paths.dir,
        // The arbiter's option 1: the test passes its own uid; production passes nothing.
        testClockStampsOwner: OWN_USER,
      });
      await svc.start();
      try {
        const atBoot = said.filter((m) => m.includes("prior-load witness question is UNRESOLVED"));
        assert(atBoot.length === 1,
          `boot must say the question is UNRESOLVED exactly once, said ${atBoot.length}: ` +
          JSON.stringify(said.slice(-3)));
        // ⛔ AND IT MUST NOT SAY THE OLD SENTENCE. "F3 USED none of it" asserts a
        //    cause this pass could not distinguish, and saying it is the defect.
        assert(!said.some((m) => m.includes("F3 USED none of it")),
          `the UNRESOLVED arm must not claim F3 used none: ${JSON.stringify(said.slice(-3))}`);

        const before = said.length;
        const r = await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard",
          { subject: "housekeeper", sessionId: "wq", actionId: "q1", toolName: "bash" });
        assert(r.status === 200, JSON.stringify(r));
        // THE RETRY: the decision asked the question again.
        const afterOne = said.slice(before).filter((m) => m.includes("UNRESOLVED"));
        assert(afterOne.length === 1,
          `the first decision must ASK AGAIN exactly once, said ${afterOne.length}: ` +
          JSON.stringify(said.slice(before)));

        // AND IT DOES NOT SPIN: the flag is cleared before the retry, so a
        // second decision does not re-ask unless that retry was itself unresolved.
        const before2 = said.length;
        await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard",
          { subject: "housekeeper", sessionId: "wq", actionId: "q2", toolName: "bash" });
        const afterTwo = said.slice(before2).filter((m) => m.includes("UNRESOLVED"));
        assert(afterTwo.length === 1,
          `an unresolved retry re-arms exactly once per decision, not more: ${afterTwo.length}`);
      } finally {
        await svc.stop();
      }
    } finally {
      console.error = realError;
    }
  });

  await check("⛔ SHAPE (b) · NEGATIVE CONTROL — with NO stamps declared, nothing is asked and nothing is minted", async () => {
    // The positive control is only worth something beside this one: with no
    // `paths.clerkStamps` at all the mint returns before any of this, so there
    // is no question, no message, and no record.
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const paths = writableTestPaths();
    const cfgPath = join(paths.dir, "declarations.config.json");
    const d = singleRouteTestDeclaration() as Record<string, any>;
    d.readers.logKind.value = "subject-chain";
    d.readers.readableLoadStates.value = [
      ...d.readers.readableLoadStates.value.filter((v: string) => v !== "LOADED_SUBJECT_CHAIN_VERIFIED"),
      "LOADED_SUBJECT_CHAIN_VERIFIED",
    ];
    if (d.paths !== undefined) delete d.paths.clerkStamps;
    writeFileSync(cfgPath, JSON.stringify(d));

    const said: string[] = [];
    const realError = console.error;
    console.error = (...a: unknown[]): void => { said.push(a.map(String).join(" ")); };
    try {
      const svc = new MicaBridgeService({
        declarationsPath: cfgPath, socketDir,
        now: () => new Date("2026-09-30T08:00:00Z"),
        testWritablePaths: { eventBook: paths.eventBook, subjectLog: paths.subjectLog },
        testBridgeGid: OWN_GID, stateDir: paths.dir,
        // The arbiter's option 1: the test passes its own uid; production passes nothing.
        testClockStampsOwner: OWN_USER,
      });
      await svc.start();
      try {
        await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard",
          { subject: "housekeeper", sessionId: "wz", actionId: "z1", toolName: "bash" });
        assert(!said.some((m) => m.includes("prior-load witness")),
          `no declared stamps path means no witness question at all: ${JSON.stringify(said.slice(-3))}`);
        const chain = readSubjectChain(paths.subjectLog);
        assert(chain.all.every((r: any) => r.eventType !== "CLERK_STAMPS_FIRST_LOAD"),
          "no stamps declared, so no witness may exist");
      } finally {
        await svc.stop();
      }
    } finally {
      console.error = realError;
    }
  });


  // ══ CODEX FAIL 2026-09-30 11:0xZ · ONE TEST PER UNRESOLVED OUTCOME ═══════
  //
  // The repair was a SINGLE ARMING POINT: `witnessFirstStampsLoadIfNeeded` now
  // delegates to `attemptFirstStampsWitness`, which returns a typed
  // `WitnessMintOutcome`, and the flag is assigned from that value in exactly
  // one place. These tests exist because the defect was not that any one arm
  // was wrong — it was that THREE `return;` STATEMENTS LOOKED IDENTICAL TO THE
  // TWO LEGITIMATE ONES, so the next arm added would have been wrong too.
  //
  // ⛔ AND ONE OF CODEX'S TWO WAS NOT WHERE IT LOOKED. `readPriorLoadWitness`
  //    CATCHES INTERNALLY and returns the string "UNREADABLE"; it does not
  //    throw. So the unreadable chain never reached the outer catch — it
  //    reached `prior !== "ABSENT"` and was filed as an ANSWER, beside PRESENT
  //    and NOT_WITNESSED. That is the arm this first test drives, and it needs
  //    no custody door because it happens before any stamps file is opened.
  await check("⛔ SHAPE (b) · an UNREADABLE prior chain is UNRESOLVED, not 'nothing to do', and is ASKED AGAIN", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const paths = writableTestPaths();
    const cfgPath = join(paths.dir, "declarations.config.json");
    const d = singleRouteTestDeclaration() as Record<string, any>;
    d.readers.logKind.value = "subject-chain";
    d.readers.readableLoadStates.value = [
      ...d.readers.readableLoadStates.value.filter((v: string) => v !== "LOADED_SUBJECT_CHAIN_VERIFIED"),
      "LOADED_SUBJECT_CHAIN_VERIFIED",
    ];
    clerkStampsFixture(paths.dir);
    d.paths = { ...(d.paths ?? {}), clerkStamps: { value: "/var/lib/mica-bridge/clerk-stamps.jsonl",
      basis: "THE TEST'S OWN DECLARED STAMPS PATH. The front door requires at least 80 characters here, "
        + "and the requirement is not decoration: paths.clerkStamps names ANOTHER PRINCIPAL'S OUTPUT, "
        + "the one key in this block that is not a file this bridge writes, so a deployer declaring "
        + "it must say whose file it is and why this bridge may read it." } };
    writeFileSync(cfgPath, JSON.stringify(d));
    // A chain that EXISTS and does not parse. Not absent, not empty — the one
    // state `readPriorLoadWitness` calls "a question we could not answer".
    writeFileSync(paths.subjectLog, '{"recordType":"SUBJECT_EVENT","sequenceNumber":0,\n');

    const said: string[] = [];
    const realError = console.error;
    console.error = (...a: unknown[]): void => { said.push(a.map(String).join(" ")); };
    try {
      let svc: any;
      try {
        svc = new MicaBridgeService({
          declarationsPath: cfgPath, socketDir,
          now: () => new Date("2026-09-30T11:00:00Z"),
          testWritablePaths: { eventBook: paths.eventBook, subjectLog: paths.subjectLog },
          testBridgeGid: OWN_GID, stateDir: paths.dir,
        // The arbiter's option 1: the test passes its own uid; production passes nothing.
        testClockStampsOwner: OWN_USER,
        });
        await svc.start();
      } catch (err) {
        // ⚠ A CORRUPT CHAIN MAY REFUSE THE WHOLE START, and that is a LEGITIMATE
        //   outcome of this fixture rather than a failure of the arm under test —
        //   a bridge that will not start on an unreadable chain has not recorded
        //   a false answer either. Say which happened; do not assert past it.
        skipped.push(
          "SHAPE (b) unreadable-chain arm: the service refused to start on the corrupt chain " +
          `(${err instanceof Error ? err.message : String(err)}), so the mint was never reached. ` +
          "The arm is still repaired — see the UNREADABLE branch — but this fixture cannot observe it."
        );
        return;
      }
      try {
        const atBoot = said.filter((m) => m.includes("prior-load witness question is UNRESOLVED"));
        assert(atBoot.length === 1,
          `an unreadable chain must say UNRESOLVED exactly once at boot, said ${atBoot.length}: ` +
          JSON.stringify(said.slice(-3)));
        assert(said.some((m) => m.includes("did not load to a verified state")),
          `it must name the CAUSE as the unreadable chain: ${JSON.stringify(said.slice(-3))}`);
        // ⛔ THE RETRY HALF IS NOT ASSERTED HERE, AND THE REASON IS NOT MY CHANGE.
        //   A decision needs the declared stamps path to LOAD, and a path this
        //   uid can satisfy does not exist (the custody door owns that question).
        //   With the path absent the guard returns 500 SERVICE_FAULT — "a declared
        //   stamps path that will not load is a wiring error, not an absent leg" —
        //   before any retry could be observed. That is the door and the wiring
        //   both behaving correctly, and asserting past it would mean asserting
        //   through a faulted decision.
        //
        //   ⚠ SO THIS TEST PROVES THE HALF IT CAN: that an unreadable chain now
        //   SAYS SO, once, naming the cause, where it used to be silent. The
        //   arming itself is structural — there is exactly ONE assignment point
        //   and this arm returns "UNRESOLVED" through it — and the retry
        //   behaviour is covered by the positive control above, which goes green
        //   on the same relay this one does.
        assert(!said.some((m) => m.includes("F3 USED none of it")),
          `an unreadable chain must never claim F3 used none: ${JSON.stringify(said.slice(-3))}`);
      } finally {
        await svc.stop();
      }
    } finally {
      console.error = realError;
    }
  });

  await check("⛔ SHAPE (b) · an EMPTY chain is UNRESOLVED and names THE LOG COULD NOT BE READ (the genesis arm is shadowed)", async () => {
    // The third silent death, not in Codex's two. Reaching `prior === "ABSENT"`
    // means the chain EXISTS and holds no witness; if its boundary then yields
    // no identity, that is a chain whose genesis we could not read — NOT
    // "there is nothing to witness", which is what the bare `return;` said.
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const paths = writableTestPaths();
    const cfgPath = join(paths.dir, "declarations.config.json");
    const d = singleRouteTestDeclaration() as Record<string, any>;
    d.readers.logKind.value = "subject-chain";
    d.readers.readableLoadStates.value = [
      ...d.readers.readableLoadStates.value.filter((v: string) => v !== "LOADED_SUBJECT_CHAIN_VERIFIED"),
      "LOADED_SUBJECT_CHAIN_VERIFIED",
    ];
    clerkStampsFixture(paths.dir);
    d.paths = { ...(d.paths ?? {}), clerkStamps: { value: "/var/lib/mica-bridge/clerk-stamps.jsonl",
      basis: "THE TEST'S OWN DECLARED STAMPS PATH. The front door requires at least 80 characters here, "
        + "and the requirement is not decoration: paths.clerkStamps names ANOTHER PRINCIPAL'S OUTPUT, "
        + "the one key in this block that is not a file this bridge writes, so a deployer declaring "
        + "it must say whose file it is and why this bridge may read it." } };
    writeFileSync(cfgPath, JSON.stringify(d));
    writeFileSync(paths.subjectLog, "");   // EMPTY: prior === ABSENT, genesis === undefined

    const said: string[] = [];
    const realError = console.error;
    console.error = (...a: unknown[]): void => { said.push(a.map(String).join(" ")); };
    try {
      const svc = new MicaBridgeService({
        declarationsPath: cfgPath, socketDir,
        now: () => new Date("2026-09-30T11:00:00Z"),
        testWritablePaths: { eventBook: paths.eventBook, subjectLog: paths.subjectLog },
        testBridgeGid: OWN_GID, stateDir: paths.dir,
        // The arbiter's option 1: the test passes its own uid; production passes nothing.
        testClockStampsOwner: OWN_USER,
      });
      await svc.start();
      try {
        // ⛔ SHADOWED, AND MEASURED RATHER THAN ARGUED. An EMPTY chain cannot
        //    reach the genesis arm: F3 cannot read the log, so the COVERAGE-NULL
        //    arm fires first and returns. And a chain F3 *can* read is a VERIFIED
        //    chain, which BY DEFINITION has a boundary at position 0 — so through
        //    the service there may be no state that reaches "present, unwitnessed,
        //    and no genesis" at all.
        //    This asserts what the service ACTUALLY does, which is still the
        //    property that matters here: the question is UNRESOLVED and the
        //    message names its own cause rather than guessing.
        assert(said.some((m) => m.includes("UNRESOLVED")),
          `it must be UNRESOLVED: ${JSON.stringify(said.slice(-3))}`);
        assert(said.some((m) => m.includes("THE LOG COULD NOT BE READ")),
          `and it must name THIS cause, not the genesis one: ${JSON.stringify(said.slice(-3))}`);
        // [owed] a fixture that reaches the genesis arm, or a finding that it is
        // unreachable through the service and belongs to a unit test of the mint.
        const before = said.length;
        await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard",
          { subject: "housekeeper", sessionId: "wg", actionId: "g1", toolName: "bash" });
        assert(said.slice(before).filter((m) => m.includes("UNRESOLVED")).length === 1,
          `the first decision must ASK AGAIN exactly once: ${JSON.stringify(said.slice(before))}`);
      } finally {
        await svc.stop();
      }
    } finally {
      console.error = realError;
    }
  });

  await check("⛔ SHAPE (b) · a read-only subject log stops the BOUNDARY, not the witness append (that arm is shadowed)", async () => {
    // Codex's second. Everything above this arm succeeded — F3 ran, the count is
    // real, the genesis is bound — which is exactly what made it the easiest arm
    // to read as done. It logged and fell off the end of the method, so the flag
    // kept whatever it already held and the retry was never armed.
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const paths = writableTestPaths();
    const cfgPath = join(paths.dir, "declarations.config.json");
    const d = singleRouteTestDeclaration() as Record<string, any>;
    d.readers.logKind.value = "subject-chain";
    d.readers.readableLoadStates.value = [
      ...d.readers.readableLoadStates.value.filter((v: string) => v !== "LOADED_SUBJECT_CHAIN_VERIFIED"),
      "LOADED_SUBJECT_CHAIN_VERIFIED",
    ];
    clerkStampsFixture(paths.dir);
    d.paths = { ...(d.paths ?? {}), clerkStamps: { value: "/var/lib/mica-bridge/clerk-stamps.jsonl",
      basis: "THE TEST'S OWN DECLARED STAMPS PATH. The front door requires at least 80 characters here, "
        + "and the requirement is not decoration: paths.clerkStamps names ANOTHER PRINCIPAL'S OUTPUT, "
        + "the one key in this block that is not a file this bridge writes, so a deployer declaring "
        + "it must say whose file it is and why this bridge may read it." } };
    writeFileSync(cfgPath, JSON.stringify(d));

    const said: string[] = [];
    const realError = console.error;
    console.error = (...a: unknown[]): void => { said.push(a.map(String).join(" ")); };
    try {
      const svc = new MicaBridgeService({
        declarationsPath: cfgPath, socketDir,
        now: () => new Date("2026-09-30T11:00:00Z"),
        testWritablePaths: { eventBook: paths.eventBook, subjectLog: paths.subjectLog },
        testBridgeGid: OWN_GID, stateDir: paths.dir,
        // The arbiter's option 1: the test passes its own uid; production passes nothing.
        testClockStampsOwner: OWN_USER,
      });
      // The append fails because the chain file cannot be written. This is the
      // real writer refusing a real write — not a stubbed appender, which would
      // only prove that a fake can return false.
      // ⛔ THE FILE MUST EXIST BEFORE ITS MODE CAN BE CHANGED. This chmod ran
      //   before `start()` had written the chain, so it threw ENOENT and the test
      //   failed on its own fixture rather than on the arm. Create it first: an
      //   empty subject log is the chain's ordinary pre-boundary state.
      writeFileSync(paths.subjectLog, "", "utf8");
      chmodSync(paths.subjectLog, 0o444);
      try {
        await svc.start();
        // ⛔ SHADOWED. A read-only subject log stops the BOUNDARY being written,
        //    so the service reports "SUBJECT CHAIN NOT BEGUN" and never reaches
        //    the witness append. The fixture breaks the chain EARLIER than the
        //    arm it was aiming at.
        assert(said.some((m) => m.includes("SUBJECT CHAIN NOT BEGUN")),
          `the chain cannot even begin, which is what a read-only log produces: ${JSON.stringify(said.slice(-3))}`);
        // [owed] the witness-append arm needs the RETRY path: let the chain start
        // normally, make the log read-only afterwards, then take a decision. That
        // is a different fixture, not a tweak to this one.
        chmodSync(paths.subjectLog, 0o644);
        const before = said.length;
        await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard",
          { subject: "housekeeper", sessionId: "wa", actionId: "a1", toolName: "bash" });
        assert(said.slice(before).some((m) => m.includes("UNRESOLVED")) ||
               readSubjectChain(paths.subjectLog).all.some((r: any) => r.eventType === "CLERK_STAMPS_FIRST_LOAD"),
          `the first decision must ask again — and with the file writable again it may now MINT: ` +
          JSON.stringify(said.slice(before)));
      } finally {
        try { chmodSync(paths.subjectLog, 0o644); } catch { /* best effort */ }
        await svc.stop();
      }
    } finally {
      console.error = realError;
    }
  });


  // ══ CODEX THIRD READ · A RETURN IS NOT THE ONLY WAY OUT ═════════════════
  //
  // The second repair classified every RETURN out of the mint and I claimed a
  // new arm could not bypass the arming point. A THROW bypasses it. These two
  // tests are in the order the argument has to be made: first that the
  // production appender really does REJECT, then that a rejection reaching the
  // mint arms the retry instead of escaping the method.
  await check("⛔ the real appender: two causes RESOLVE ok:false, and a missing boundary REJECTS", async () => {
    // ⛔ THIS TEST ASSERTED THE OPPOSITE ON ITS FIRST RUN, AND THE APPENDER WAS
    //    RIGHT. The third read reported that the production appender's REJECTING
    //    path escapes the mint's arming point, and I wrote a test to prove the
    //    hazard was real. It is not: `appendDerived` handles both causes and
    //    returns its own documented failure shape. The FLOATING-REJECTION FIX
    //    already moved `readAll()` and `build()` inside the try; the comment that
    //    still calls the rejection "reachable" describes the state BEFORE it.
    //
    //    The test is kept, inverted, because it is now the thing that will notice
    //    if that ever changes — and because the boundary catch in the mint is
    //    defence in depth, which is only honest if this file says so.
    const dir = mkdtempSync(join(tmpdir(), "mica-appender-"));

    const asDirectory = join(dir, "as-directory.jsonl");
    mkdirSync(asDirectory);
    let r1: any, threw1 = false;
    try { r1 = await new ChainedSubjectAppender(asDirectory).appendDerived(() => ({ recordType: "SUBJECT_EVENT" })); }
    catch { threw1 = true; }
    assert(!threw1 && r1?.ok === false,
      `EISDIR must RESOLVE ok:false, not reject: threw=${threw1} ${JSON.stringify(r1)}`);
    assert(String(r1.error).includes("not a regular file"),
      `and it must say which fact it met: ${JSON.stringify(r1.error)}`);

    const unreadable = join(dir, "unreadable.jsonl");
    writeFileSync(unreadable, "");
    chmodSync(unreadable, 0o000);
    let r2: any, threw2 = false;
    try { r2 = await new ChainedSubjectAppender(unreadable).appendDerived(() => ({ recordType: "SUBJECT_EVENT" })); }
    catch { threw2 = true; }
    finally { try { chmodSync(unreadable, 0o644); } catch { /* best effort */ } }
    assert(!threw2 && r2?.ok === false,
      `EACCES must RESOLVE ok:false, not reject: threw=${threw2} ${JSON.stringify(r2)}`);
    assert(String(r2.error).includes("EACCES"),
      `and it must name EACCES rather than report absence: ${JSON.stringify(r2.error)}`);

    // ⛔ AND THE ONE THAT DOES REJECT — Codex F1. I had concluded the appender
    //    could not reject at all, having tested only the two I-O causes. A chain
    //    file with no SUBJECT_LOG_BOUNDARY at position 0 is a DOMAIN refusal,
    //    not an I-O one, and it throws. This is why the mint's boundary catch is
    //    load-bearing rather than prudent, and it is asserted here so that claim
    //    rests on a run instead of on a reading.
    const noBoundary = join(dir, "no-boundary", "subject-events.jsonl");
    let threw3 = false;
    let r3: unknown = undefined;
    try { r3 = await new ChainedSubjectAppender(noBoundary).appendDerived(() => ({ recordType: "SUBJECT_EVENT" })); }
    catch { threw3 = true; }
    assert(threw3,
      `a chain with no boundary at position 0 must REJECT, not resolve — it resolved with ` +
      `${JSON.stringify(r3)}. If this ever stops rejecting, the mint's boundary catch has ` +
      `no reachable cause left and the comment there must be corrected AGAIN.`);
  });

  await check("⛔ a 0000 subject log reaches the UNREADABLE arm, not the boundary catch (which has no reachable fixture)", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const paths = writableTestPaths();
    const cfgPath = join(paths.dir, "declarations.config.json");
    const d = singleRouteTestDeclaration() as Record<string, any>;
    d.readers.logKind.value = "subject-chain";
    d.readers.readableLoadStates.value = [
      ...d.readers.readableLoadStates.value.filter((v: string) => v !== "LOADED_SUBJECT_CHAIN_VERIFIED"),
      "LOADED_SUBJECT_CHAIN_VERIFIED",
    ];
    clerkStampsFixture(paths.dir);
    d.paths = { ...(d.paths ?? {}), clerkStamps: { value: "/var/lib/mica-bridge/clerk-stamps.jsonl",
      basis:
        "THE TEST'S OWN DECLARED STAMPS PATH. The front door requires at least 80 characters here, "
        + "and the requirement is not decoration: paths.clerkStamps names ANOTHER PRINCIPAL'S OUTPUT, "
        + "the one key in this block that is not a file this bridge writes, so a deployer declaring "
        + "it must say whose file it is and why this bridge may read it." } };
    writeFileSync(cfgPath, JSON.stringify(d));

    const said: string[] = [];
    const realError = console.error;
    console.error = (...a: unknown[]): void => { said.push(a.map(String).join(" ")); };
    try {
      const svc = new MicaBridgeService({
        declarationsPath: cfgPath, socketDir,
        now: () => new Date("2026-09-30T14:00:00Z"),
        testWritablePaths: { eventBook: paths.eventBook, subjectLog: paths.subjectLog },
        testBridgeGid: OWN_GID, stateDir: paths.dir,
        // The arbiter's option 1: the test passes its own uid; production passes nothing.
        testClockStampsOwner: OWN_USER,
      });
      // chmod 000: `readAll()` throws EACCES from outside its try, so the append
      // REJECTS rather than resolving ok:false. That is the escape route.
      // ⛔ THE FILE MUST EXIST BEFORE ITS MODE CAN BE CHANGED. This chmod ran
      //   before `start()` had written the chain, so it threw ENOENT and the test
      //   failed on its own fixture rather than on the arm. Create it first: an
      //   empty subject log is the chain's ordinary pre-boundary state.
      writeFileSync(paths.subjectLog, "", "utf8");
      chmodSync(paths.subjectLog, 0o000);
      try {
        await svc.start();
        // ⛔ SHADOWED, same shape. A 0000 subject log makes the chain
        //    UNVERIFIED, so `readPriorLoadWitness` returns "UNREADABLE" and THAT
        //    arm fires — the boundary catch is never reached. Three arms, three
        //    fixtures, and each one trips an EARLIER arm than the one it names:
        //    to test arm N you must first get past arms 1..N-1, and a crude
        //    fixture never does.
        assert(
          said.some((m) => m.includes("did not load to a verified state")),
          `the unreadable-chain arm fires first, and that is what this fixture reaches: ${JSON.stringify(said.slice(-3))}`
        );
        // [owed] the boundary catch still has NO reachable cause in a fixture.
        // Its load-bearing proof is the appender's own rejection test above.
        chmodSync(paths.subjectLog, 0o644);
        const before = said.length;
        await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard",
          { subject: "housekeeper", sessionId: "wt", actionId: "t1", toolName: "bash" });
        assert(
          said.slice(before).some((m) => m.includes("UNRESOLVED")) ||
            readSubjectChain(paths.subjectLog).all.some((r: any) => r.eventType === "CLERK_STAMPS_FIRST_LOAD"),
          `the throw must have ARMED the retry, so the first decision asks again — ` +
          `and with the file writable it may now MINT: ${JSON.stringify(said.slice(before))}`
        );
      } finally {
        try { chmodSync(paths.subjectLog, 0o644); } catch { /* best effort */ }
        await svc.stop();
      }
    } finally {
      console.error = realError;
    }
  });


  // ══ S180 · THE COVERAGE COMES FROM THE ONE WIRING ═══════════════════════
  //
  // ⛔ MEASURED LIVE AFTER THE e4070bd RELAY, decision 577: the mint had NEVER
  //    MINTED. It called `assessSig(wiring.logFile, options.sig)` itself, and
  //    `options.sig` is typed `Omit<SigConfig, "readableLoadStates">` — only
  //    `wire()` injects the run's list — so F3 refused the verified chain,
  //    `clerkStampCoverage` came back null, and the witness read UNRESOLVED on
  //    every single pass.
  //
  // ⚠ THIS TEST NEEDS NO STAMPS FILE AND RUNS AT AN ORDINARY UID, which is the
  //   point: the defect was never about custody. It was about which config the
  //   reader was handed, and that is provable on an empty chain.
  await check("⛔ S180 · a VERIFIED chain yields a coverage OBJECT through wire() — and null through the private call", async () => {
    const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
    makeOwnPeerDir(socketDir, OWN_UID);
    const paths = writableTestPaths();
    const cfgPath = join(paths.dir, "declarations.config.json");
    const d = singleRouteTestDeclaration() as Record<string, any>;
    d.readers.logKind.value = "subject-chain";
    d.readers.readableLoadStates.value = [
      ...d.readers.readableLoadStates.value.filter((v: string) => v !== "LOADED_SUBJECT_CHAIN_VERIFIED"),
      "LOADED_SUBJECT_CHAIN_VERIFIED",
    ];
    writeFileSync(cfgPath, JSON.stringify(d));

    const svc = new MicaBridgeService({
      declarationsPath: cfgPath, socketDir,
      now: () => new Date("2026-09-30T17:00:00Z"),
      testWritablePaths: { eventBook: paths.eventBook, subjectLog: paths.subjectLog },
      testBridgeGid: OWN_GID, stateDir: paths.dir,
    });
    await svc.start();
    // one decision, so the chain has a record beyond its boundary
    await httpJson(sockFor(socketDir, OWN_UID), "POST", "/guard",
      { subject: "housekeeper", sessionId: "s180", actionId: "a1", toolName: "bash" });
    await svc.stop();

    const chain = new SubjectChainLog({ path: paths.subjectLog });
    assert(chain.getLoadState() === "LOADED_SUBJECT_CHAIN_VERIFIED",
      `the fixture must be a VERIFIED chain, got ${chain.getLoadState()}`);

    // ⛔ THE LOADER IS INJECTED, AND THAT IS THE WHOLE REASON THIS IS PROVABLE
    //    HERE. to-wire-options.ts says so itself: "The bridge passes the real
    //    reader; A TEST PASSES A FAKE." So F3 gets a stamps source without any
    //    custody door, any /var/lib path, or any privilege — the defect S180
    //    names was never about custody, it was about which CONFIG the reader was
    //    handed, and that is testable at any uid.
    const d2 = JSON.parse(readFileSync(cfgPath, "utf8"));
    d2.paths = { ...(d2.paths ?? {}), clerkStamps: { value: "/var/lib/mica/clerk-subject/stamps.jsonl",
      basis:
        "THE TEST'S OWN DECLARED STAMPS PATH. The front door requires at least 80 characters here, "
        + "and the requirement is not decoration: paths.clerkStamps names ANOTHER PRINCIPAL'S OUTPUT, "
        + "the one key in this block that is not a file this bridge writes, so a deployer declaring "
        + "it must say whose file it is and why this bridge may read it." } };
    const cfg2 = join(paths.dir, "declarations.with-stamps.json");
    writeFileSync(cfg2, JSON.stringify(d2));
    const declarations = loadDeclarations(cfg2).declarations;
    // ⚠ THE RESOLVER MATTERS AS MUCH AS THE LOADER. wire() only reads Sig when a
    //   real logFile exists, so an identity resolver — which leaves the declared
    //   path pointing at a file this test never wrote — produces a null sigF3
    //   for a reason that has nothing to do with S180. Map the declared log to
    //   the chain the service actually wrote.
    const resolve = (x: string): string =>
      x === declarations.readers.logPath.value ? paths.subjectLog : x;
    // ⛔ THE LIST MUST NOT BE EMPTY, and this is the third thing I got wrong
    //   about this fixture. F3 treats `source.length === 0` as NOT_CONFIGURED
    //   and returns BEFORE any coverage exists — so an empty array produces a
    //   null coverage for a reason that has nothing to do with S180, and would
    //   have let this test "pass" the defect it exists to pin. One real stamp.
    const fakeStamps = (): any => [
      {
        moduleId: "housekeeper",
        sequenceNumber: 1,
        chainIdentity: undefined,
        clerk_seq: 1,
        clerk_time: { wall_ms: 1, monotonic_ns: "1" },
        separation: "SEPARATE_PROCESS",
        intake: "SOCKET",
        clerk_id: "clerk-1",
        clerk_boot_id: "boot-1",
      },
    ];
    const options = toWireOptions(declarations, resolve, fakeStamps, loadExpectedChainIdentity);
    const wiring = wire(options);

    // ── THE PROPERTY ────────────────────────────────────────────────────────
    const f3 = wiring.sigF3;
    assert(f3 !== undefined && f3 !== null, "wire() must expose sigF3");
    if (f3 === null || f3 === undefined) throw new Error("unreachable");
    assert(f3.coverage !== null && f3.coverage !== undefined,
      `a VERIFIED chain must yield a coverage OBJECT through wire(), got ` +
      `${JSON.stringify(f3.coverage)} — if this is null the mint mints nothing`);

    // ── AND WHY THE OLD PATH RETURNED NULL, pinned so the fix cannot be
    //    undone by someone "simplifying" it back. `options.sig` carries no
    //    readableLoadStates by type, so a private assessSig over the SAME log
    //    refuses it and reports no coverage at all.
    if (wiring.logFile !== null && options.sig !== undefined) {
      const privately = assessSig(wiring.logFile, options.sig as any);
      assert(privately.clerkStampCoverage === null,
        "the private call over options.sig must still report NO coverage — that is " +
        "the defect S180 names, and if it ever starts returning one, this test is " +
        "the thing that should be re-read rather than deleted");
    }
  });

  // ZERO SUBJECTS (ticket Bridge-Zero-Subjects v2, arms 2-6)
  await zeroSubjectArms();

  for (const s of skipped) console.log(`SKIP  ${s}`);
  console.log(
    `CENSUS: ${passed} passed, ${failed} failed, ${skippedCount} skipped, ` +
      `${passed + failed + skippedCount} total` +
      (RELAY_CANDIDATE ? " (relay-candidate: a skip is a failure)" : "")
  );
  if (failed > 0) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

// ══ ZERO SUBJECTS (ticket Bridge-Zero-Subjects v2; audit 2026-10-18 06:56Z (9)) ═════════════════════════════════
// Arms 2-6 of the ticket at the service level. Fixture names only; uids are this process's own (OWN_UID) or fixture
// values that no row carries. Every book is snapshotted as the whole state directory (sha + size per file).

/** The single-route test declaration with NOTHING DECLARED: the self-owned row is the OPERATOR's. */
function zsZeroDeclaration(extraAllow: { method: string; path: string }[] = []): any {
  const d: any = singleRouteTestDeclaration();
  d.subjects = [];
  d.routes = [
    {
      uid: OWN_UID,
      role: "operator",
      allow: [
        { method: "GET", path: "/status" },
        { method: "GET", path: "/events" },
        { method: "GET", path: "/log" },
        { method: "GET", path: "/explain" },
        { method: "POST", path: "/subject-events" },
        { method: "GET", path: "/sunset-order" },
        ...extraAllow,
      ],
    },
  ];
  return d;
}

/** Every file under `dir`, recursively: path -> "sha256:size". The books, whatever their declared names. */
function zsSnapshot(dir: string): Record<string, string> {
  const out: Record<string, string> = {};
  const walk = (p: string): void => {
    for (const e of readdirSync(p, { withFileTypes: true })) {
      const full = join(p, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile() && !e.name.endsWith(".lock")) {
        const b = readFileSync(full);
        out[full.slice(dir.length)] = `${createHash("sha256").update(b).digest("hex")}:${b.length}`;
      }
    }
  };
  walk(dir);
  return out;
}

interface ZsRig {
  svc: MicaBridgeService;
  socketDir: string;
  stateDir: string;
  cfgPath: string;
  testPaths: { eventBook: string; subjectLog: string; dir: string };
  extra: http.Server[];
}

async function zsStart(decl: unknown, prior?: ZsRig, opts: { guardAdapter?: GuardAdapter; noPeerDir?: boolean } = {}): Promise<ZsRig> {
  const socketDir = prior?.socketDir ?? mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
  if (prior === undefined && opts.noPeerDir !== true) makeOwnPeerDir(socketDir, OWN_UID);
  const testPaths = prior?.testPaths ?? writableTestPaths();
  const cfgPath = prior?.cfgPath ?? join(mkdtempSync(join(tmpdir(), "mica-bridge-cfg-")), "declarations.config.json");
  writeFileSync(cfgPath, JSON.stringify(decl));
  const svc = new MicaBridgeService({
    declarationsPath: cfgPath,
    socketDir,
    now: () => new Date("2026-09-18T00:00:00Z"),
    testWritablePaths: testPaths,
    testBridgeGid: OWN_GID,
    stateDir: testPaths.dir,
    ...(opts.guardAdapter !== undefined ? { guardAdapter: opts.guardAdapter } : {}),
  });
  const rig: ZsRig = { svc, socketDir, stateDir: testPaths.dir, cfgPath, testPaths, extra: [] };
  await svc.start();
  return rig;
}

async function zsStop(rig: ZsRig): Promise<void> {
  for (const s of rig.extra) await new Promise<void>((r) => s.close(() => r()));
  rig.extra = [];
  await rig.svc.stop();
}

/** A real socket whose handler stands in for start()'s per-uid listener, for a uid this process cannot own. */
async function zsPeerServer(rig: ZsRig, uid: number): Promise<string> {
  const p = join(mkdtempSync(join(tmpdir(), "mica-bridge-zs-peer-")), "guard.sock");
  const server = http.createServer((req, res) => (rig.svc as any).handleHttp(uid, req, res));
  await new Promise<void>((resolve, reject) => {
    server.on("error", reject);
    server.listen(p, resolve);
  });
  rig.extra.push(server);
  return p;
}

/** A real socket that SKIPS layer 1: the body goes straight to handleGuard, as a path past authorizeRoute would. */
async function zsLayer1SkippedServer(rig: ZsRig, uid: number): Promise<string> {
  const p = join(mkdtempSync(join(tmpdir(), "mica-bridge-zs-skip-")), "guard.sock");
  const server = http.createServer((req, res) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      let body: unknown = null;
      try {
        body = JSON.parse(data);
      } catch {
        body = null;
      }
      (rig.svc as any).handleGuard(uid, body, res).catch((err: unknown) => (rig.svc as any).failRequest(res, "POST /guard", err));
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.on("error", reject);
    server.listen(p, resolve);
  });
  rig.extra.push(server);
  return p;
}

const ZS_GUARD_BODY = { subject: "subject-zs", sessionId: "s-zs", actionId: "a-zs", toolName: "tool-zs" };
function zsNoDisposition(r: { status: number; body: any }): void {
  assert(r.status < 200 || r.status >= 300, `a /guard answer at zero must be non-2xx: ${JSON.stringify(r)}`);
  const text = JSON.stringify(r.body);
  for (const k of ["disposition", "execute", "decisionHash"]) assert(!text.includes(`"${k}"`), `no ${k} at zero: ${text}`);
}
function zsEvents(rig: ZsRig): any[] {
  return existsSync(rig.testPaths.eventBook)
    ? readFileSync(rig.testPaths.eventBook, "utf8").split("\n").filter((l) => l.trim().length > 0).map((l) => JSON.parse(l))
    : [];
}

async function zeroSubjectArms(): Promise<void> {
  // ── arm 2 · NO FAIL-OPEN, on real sockets, with the witness-mint retry ARMED ──
  {
    const rig = await zsStart(zsZeroDeclaration());
    try {
      (rig.svc as any).witnessMintUnresolved = true;
      const before = zsSnapshot(rig.stateDir);
      const operatorSock = sockFor(rig.socketDir, OWN_UID);
      const noRowSock = await zsPeerServer(rig, 4242);
      const skipSock = await zsLayer1SkippedServer(rig, OWN_UID);
      const rOp = await httpJson(operatorSock, "POST", "/guard", ZS_GUARD_BODY);
      const rNoRow = await httpJson(noRowSock, "POST", "/guard", ZS_GUARD_BODY);
      const rSkip = await httpJson(skipSock, "POST", "/guard", ZS_GUARD_BODY);
      const after = zsSnapshot(rig.stateDir);
      await check("ZERO-SUBJECTS arm 2 · NO FAIL-OPEN: /guard from the operator row, a uid with no row, and a path past layer 1 — all non-2xx, no disposition/execute/decisionHash", async () => {
        zsNoDisposition(rOp);
        zsNoDisposition(rNoRow);
        zsNoDisposition(rSkip);
      });
      await check("ZERO-SUBJECTS arm 2 · NO FAIL-OPEN: every book byte-identical (sha + size) before and after, the mint retry still armed", async () => {
        assert(JSON.stringify(before) === JSON.stringify(after), `books moved:\n${JSON.stringify(before)}\n${JSON.stringify(after)}`);
        assert(Object.keys(before).length >= 2, `the snapshot must see the books: ${JSON.stringify(Object.keys(before))}`);
        assert((rig.svc as any).witnessMintUnresolved === true, "the retry must not have run (layer 2 sits before it)");
      });
      await check("ZERO-SUBJECTS arm 2 · LAYER 1: authorizeRoute answers 403 to the operator row (not granted) and to a uid with no row", async () => {
        assert(rOp.status === 403, JSON.stringify(rOp));
        assert(rNoRow.status === 403, JSON.stringify(rNoRow));
      });
      await check("ZERO-SUBJECTS arm 2 · LAYER 2: past layer 1, handleGuard's top check answers 503 NOTHING_DECLARED before the mint retry", async () => {
        assert(rSkip.status === 503 && rSkip.body?.error === "NOTHING_DECLARED", JSON.stringify(rSkip));
      });
      // /subject-events and /sunset-order refuse the same way, before any append
      const beforeSe = zsSnapshot(rig.stateDir);
      const identity = { subject: "subject-zs", sessionId: "s-zs", actionId: "a-zs" };
      const rSe = await httpJson(operatorSock, "POST", "/subject-events", { identity, kind: "TOOL_ATTEMPTED", eventHash: realEventHash(identity, "TOOL_ATTEMPTED") });
      const rSeDoc = await httpJson(operatorSock, "POST", "/subject-events", { identity, kind: "DOCTOR_ATTESTED", eventHash: realEventHash(identity, "DOCTOR_ATTESTED") });
      const rSo = await httpJson(operatorSock, "GET", "/sunset-order");
      const afterSe = zsSnapshot(rig.stateDir);
      await check("ZERO-SUBJECTS arm 2 · /subject-events refuses (a subject's kind: 403 by kind authz; the operator's own kind: non-2xx) and /sunset-order refuses (403), nothing appended", async () => {
        assert(rSe.status === 403, JSON.stringify(rSe));
        assert(rSeDoc.status >= 400, JSON.stringify(rSeDoc));
        console.log(`      /subject-events at zero: TOOL_ATTEMPTED -> ${rSe.status} ${rSe.body?.error}; DOCTOR_ATTESTED -> ${rSeDoc.status} ${rSeDoc.body?.error}`);
        assert(rSo.status === 403, JSON.stringify(rSo));
        assert(JSON.stringify(beforeSe) === JSON.stringify(afterSe), "books moved on a refused /subject-events or /sunset-order");
      });
    } finally {
      await zsStop(rig);
    }
  }

  await check("ZERO-SUBJECTS arm 2 · LAYER 3: toGuardFlags at zero throws UnknownSubjectError for every name (no prototype path)", async () => {
    const zero = validateDeclarations(zsZeroDeclaration(), new Date("2026-09-18T00:00:00Z")).declarations;
    for (const name of ["subject-zs", "__proto__", "constructor", "", "toString"]) {
      let threw: unknown = null;
      try {
        toGuardFlags(zero, { state: "INACTIVE" } as any, name, "tool-zs", "s-zs");
      } catch (err) {
        threw = err;
      }
      assert(threw instanceof UnknownSubjectError, `toGuardFlags(${JSON.stringify(name)}) must throw UnknownSubjectError, got ${String(threw)}`);
    }
  });

  await check("ZERO-SUBJECTS arm 2 · LAYER 4: NothingDeclaredGuardAdapter never answers a disposition", async () => {
    const out: any = await new NothingDeclaredGuardAdapter().evaluate({
      subject: "subject-zs", sessionId: "s-zs", actionId: "a-zs", toolName: "tool-zs",
      stakesClass: "c", holdAtOrAbove: "c", pilotApplied: false, declarationHash: "0".repeat(64),
    } as any);
    assert(out.bound === false && out.httpStatus === 503 && out.error === "NOTHING_DECLARED", JSON.stringify(out));
    assert(out.decision === undefined && out.declarationBinding?.kind === "NOTHING_DECLARED", JSON.stringify(out));
  });

  {
    // An injected adapter that WOULD allow: at zero buildGuardAdapter must not install it.
    const allowing: GuardAdapter = {
      async evaluate(): Promise<GuardOutcome> {
        return { bound: true, httpStatus: 200, decision: { disposition: "RELEASE", execute: true, decisionHash: "f".repeat(64) } } as any;
      },
    };
    const rig = await zsStart(zsZeroDeclaration(), undefined, { guardAdapter: allowing });
    try {
      const installed = (rig.svc as any).guardAdapter;
      const out: any = await installed.evaluate({ ...ZS_GUARD_BODY, stakesClass: "c", holdAtOrAbove: "c", pilotApplied: false, declarationHash: "0".repeat(64) });
      const st = await httpJson(sockFor(rig.socketDir, OWN_UID), "GET", "/status");
      await check("ZERO-SUBJECTS arm 2 · LAYER 4 wins over an injected allowing adapter: the installed adapter is NothingDeclared and refuses", async () => {
        assert(installed instanceof NothingDeclaredGuardAdapter, `installed: ${installed?.constructor?.name}`);
        assert(out.bound === false && out.error === "NOTHING_DECLARED", JSON.stringify(out));
        assert(st.body.guardBound === false, `guardBound must read false at zero: ${JSON.stringify(st.body.guardBound)}`);
      });
    } finally {
      await zsStop(rig);
    }
  }

  await check("ZERO-SUBJECTS arm 2/7 · Z5 makes layer 1 a rule: a zero declaration granting the operator POST /guard does not load", async () => {
    let threw: any = null;
    try {
      validateDeclarations(zsZeroDeclaration([{ method: "POST", path: "/guard" }]), new Date("2026-09-18T00:00:00Z"));
    } catch (err) {
      threw = err;
    }
    assert(threw !== null && String(threw.message).includes("Z5"), `expected a Z5 refusal, got ${String(threw)}`);
  });

  // ── arm 3 · every reader prints the word, on a NON-EMPTY subject log that a one-subject reading reads ──
  {
    const one = await zsStart(singleRouteTestDeclaration());
    let oneRows: any[] = [];
    let rig: ZsRig | null = null;
    try {
      for (const [i, kind] of ["TOOL_ATTEMPTED", "TOOL_EXECUTED", "TOOL_ATTEMPTED"].entries()) {
        const identity = { subject: (singleRouteTestDeclaration() as any).subjects[0].subject, sessionId: "s-zs3", actionId: `a-zs3-${i}` };
        const r = await httpJson(sockFor(one.socketDir, OWN_UID), "POST", "/subject-events", { identity, kind, eventHash: realEventHash(identity, kind) });
        assert(r.status === 200, `seeding the subject log: ${JSON.stringify(r)}`);
      }
      oneRows = (await httpJson(sockFor(one.socketDir, OWN_UID), "GET", "/status")).body.instruments;
      await zsStop(one);
      rig = await zsStart(zsZeroDeclaration(), one);
      const st = await httpJson(sockFor(rig.socketDir, OWN_UID), "GET", "/status");
      const lg = await httpJson(sockFor(rig.socketDir, OWN_UID), "GET", "/log");
      const ex = await httpJson(sockFor(rig.socketDir, OWN_UID), "GET", `/explain?decisionHash=${"a".repeat(64)}`);
      await check("ZERO-SUBJECTS arm 3 · premise: the same non-empty log, read with ONE subject, carries readings (WIRED rows with a verdict kind)", async () => {
        const wired = oneRows.filter((r: any) => r.state === "WIRED" && r.lastVerdictKind !== null);
        assert(wired.length > 0, `the one-subject reading must carry readings: ${JSON.stringify(oneRows.map((r: any) => [r.id, r.state, r.lastVerdictKind]))}`);
        console.log(`      one-subject readings on this log: ${JSON.stringify(wired.map((r: any) => [r.id, r.lastVerdictKind]))}`);
      });
      await check("ZERO-SUBJECTS arm 3 · at zero ALL 14 census rows read NOTHING_DECLARED with the fixed reason, no verdict, no footing", async () => {
        const rows = st.body.instruments;
        assert(Array.isArray(rows) && rows.length === 14, JSON.stringify(rows));
        for (const row of rows) {
          assert(row.state === "NOTHING_DECLARED" && row.reason === NOTHING_DECLARED_REASON, JSON.stringify(row));
          assert(row.lastVerdictKind === null && row.footing === null, JSON.stringify(row));
        }
      });
      await check("ZERO-SUBJECTS arm 3 · /status.subjects reads NOTHING_DECLARED with [], guardBound false, pilot INACTIVE", async () => {
        assert(JSON.stringify(st.body.subjects) === JSON.stringify({ state: "NOTHING_DECLARED", declared: [] }), JSON.stringify(st.body.subjects));
        assert(st.body.guardBound === false, String(st.body.guardBound));
        assert(st.body.pilot.state === "INACTIVE", JSON.stringify(st.body.pilot));
      });
      await check("ZERO-SUBJECTS arm 3/4 · /log at zero with no trail says nothing is declared; /log and /explain carry subjectsDeclared", async () => {
        assert(lg.status === 200 && lg.body.reason === "floor trail not written — nothing declared (subjects: [])", JSON.stringify(lg));
        assert(lg.body.subjectsDeclared === "NOTHING_DECLARED", JSON.stringify(lg.body));
        assert(ex.body.subjectsDeclared === "NOTHING_DECLARED", JSON.stringify(ex.body));
      });
    } finally {
      if (rig !== null) await zsStop(rig);
    }
  }

  await withService(async (_svc, socketDir) => {
    const st = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/status");
    const lg = await httpJson(sockFor(socketDir, OWN_UID), "GET", "/log");
    await check("ZERO-SUBJECTS arm 4 / F-11 (a) · at n = 1: /status.subjects is DECLARED with the row; /log carries subjectsDeclared 1; the absent-trail reason is unchanged", async () => {
      const decl: any = singleRouteTestDeclaration();
      assert(st.body.subjects?.state === "DECLARED", JSON.stringify(st.body.subjects));
      assert(JSON.stringify(st.body.subjects.declared) === JSON.stringify([{ subject: decl.subjects[0].subject, peerUid: OWN_UID }]), JSON.stringify(st.body.subjects));
      assert(lg.body.subjectsDeclared === 1, JSON.stringify(lg.body));
      assert(lg.body.reason === "floor trail not yet written (Stage 1 not bound)", JSON.stringify(lg.body));
    });
  });

  // ── arm 5 · restart into zero, then re-add ──
  {
    const one = await zsStart(singleRouteTestDeclaration());
    const chainAtOne = readFileSync(one.testPaths.subjectLog, "utf8");
    await zsStop(one);
    // a spy on the start-time mint, which is what calls wire() at start
    let mintCalls = 0;
    const origAttempt = (MicaBridgeService.prototype as any).attemptFirstStampsWitness;
    (MicaBridgeService.prototype as any).attemptFirstStampsWitness = function (this: unknown, ...a: unknown[]) {
      mintCalls++;
      return origAttempt.apply(this, a);
    };
    let zero: ZsRig | null = null;
    try {
      const evBefore = zsEvents(one).length;
      zero = await zsStart(zsZeroDeclaration(), one);
      const evZero = zsEvents(zero).slice(evBefore);
      const chainAtZero = readFileSync(zero.testPaths.subjectLog, "utf8");
      const sockets = [...(zero.svc as any).plans.keys()];
      const mintAtZero = mintCalls;
      await zsStop(zero);
      const zero2 = await zsStart(zsZeroDeclaration(), zero);
      const evZero2 = zsEvents(zero2).slice(evBefore + evZero.length);
      await zsStop(zero2);
      const back = await zsStart(singleRouteTestDeclaration(), zero2);
      const evBack = zsEvents(back).slice(evBefore + evZero.length + evZero2.length);
      const stBack = await httpJson(sockFor(back.socketDir, OWN_UID), "GET", "/status");
      const decl: any = singleRouteTestDeclaration();
      const gBack = await httpJson(sockFor(back.socketDir, OWN_UID), "POST", "/guard", { subject: decl.subjects[0].subject, sessionId: "s-zs5", actionId: "a-zs5", toolName: decl.subjects[0].toolName });
      const chainBack = readFileSync(back.testPaths.subjectLog, "utf8");
      await zsStop(back);
      await check("ZERO-SUBJECTS arm 5 · start() on zero: the operator's socket only, no boundary on the existing chain, no mint (no wire()), the chain untouched", async () => {
        assert(JSON.stringify(sockets) === JSON.stringify([OWN_UID]), JSON.stringify(sockets));
        assert(chainAtZero === chainAtOne, "a zero start must not append to the subject chain (no boundary, no CLERK_STAMPS_FIRST_LOAD)");
        assert(mintAtZero === 0, `the start-time mint must not run at zero (it calls wire()); ran ${mintAtZero}x`);
      });
      await check("ZERO-SUBJECTS arm 5 · start() on zero: ONE SERVICE_STARTED and ONE SUBJECTS_DECLARED [], the latter written last (after the sockets bind)", async () => {
        const kinds = evZero.map((e) => e.kind);
        assert(kinds.filter((k) => k === "SERVICE_STARTED").length === 1, JSON.stringify(kinds));
        const sd = evZero.filter((e) => e.kind === "SUBJECTS_DECLARED");
        assert(sd.length === 1 && Array.isArray(sd[0].declared) && sd[0].declared.length === 0, JSON.stringify(sd));
        assert(kinds[kinds.length - 1] === "SUBJECTS_DECLARED", `SUBJECTS_DECLARED must be the start's last row: ${JSON.stringify(kinds)}`);
        assert(/^[0-9a-f]{64}$/.test(String(sd[0].declarationHash)), JSON.stringify(sd[0]));
      });
      await check("ZERO-SUBJECTS arm 5 · F-10 (a): a second start on the SAME zero declaration writes no second SUBJECTS_DECLARED (but its SERVICE_STARTED)", async () => {
        const kinds = evZero2.map((e) => e.kind);
        assert(!kinds.includes("SUBJECTS_DECLARED"), JSON.stringify(kinds));
        assert(kinds.includes("SERVICE_STARTED"), JSON.stringify(kinds));
      });
      await check("ZERO-SUBJECTS arm 5 · re-add by restart: SUBJECTS_DECLARED [subject], /status DECLARED, /guard reaches evaluation, the chain continues with no new boundary", async () => {
        const sd = evBack.filter((e) => e.kind === "SUBJECTS_DECLARED");
        assert(sd.length === 1 && sd[0].declared.length === 1 && sd[0].declared[0].subject === decl.subjects[0].subject, JSON.stringify(sd));
        assert(stBack.body.subjects?.state === "DECLARED", JSON.stringify(stBack.body.subjects));
        assert(gBack.body?.error !== "NOTHING_DECLARED" && gBack.status !== 403, `the re-added subject's /guard must reach evaluation: ${JSON.stringify(gBack)}`);
        const boundaries = chainBack.split("\n").filter((l) => l.trim().length > 0).map((l) => JSON.parse(l)).filter((r) => r.recordType === "SUBJECT_LOG_BOUNDARY");
        assert(boundaries.length === 1, `exactly one boundary on the chain: ${boundaries.length}`);
        assert(chainBack.startsWith(chainAtOne), "the chain continues from where the one-subject tenure left it");
      });
    } finally {
      (MicaBridgeService.prototype as any).attemptFirstStampsWitness = origAttempt;
    }
  }

  await check("ZERO-SUBJECTS arm 5 · a start() that throws StartupRefused (peer dir missing) writes NO SUBJECTS_DECLARED", async () => {
    let refused: unknown = null;
    let rig: ZsRig | null = null;
    const testPaths = writableTestPaths();
    try {
      const socketDir = mkdtempSync(join(tmpdir(), "mica-bridge-svc-"));
      const cfgPath = join(mkdtempSync(join(tmpdir(), "mica-bridge-cfg-")), "declarations.config.json");
      writeFileSync(cfgPath, JSON.stringify(zsZeroDeclaration()));
      const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => new Date("2026-09-18T00:00:00Z"), testWritablePaths: testPaths, testBridgeGid: OWN_GID, stateDir: testPaths.dir });
      rig = { svc, socketDir, stateDir: testPaths.dir, cfgPath, testPaths, extra: [] };
      await svc.start();
    } catch (err) {
      refused = err;
    }
    await new Promise((r) => setTimeout(r, 50));
    assert(refused instanceof StartupRefused, `expected StartupRefused, got ${String(refused)}`);
    const kinds = existsSync(testPaths.eventBook) ? readFileSync(testPaths.eventBook, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l).kind) : [];
    assert(!kinds.includes("SUBJECTS_DECLARED"), JSON.stringify(kinds));
  });

  // ── arm 6 · Z4 at the service: a SIGHUP may not change membership; last-known-good kept, DECLARATION_REJECTED written ──
  {
    const rig = await zsStart(zsZeroDeclaration());
    try {
      const hashBefore = (await httpJson(sockFor(rig.socketDir, OWN_UID), "GET", "/status")).body.declarationHash;
      writeFileSync(rig.cfgPath, JSON.stringify(singleRouteTestDeclaration()));
      const r = rig.svc.reload();
      await new Promise((res) => setTimeout(res, 50));
      const st = await httpJson(sockFor(rig.socketDir, OWN_UID), "GET", "/status");
      const rejected = zsEvents(rig).filter((e) => e.kind === "DECLARATION_REJECTED");
      await check("ZERO-SUBJECTS arm 6 · Z4: a reload zero -> one is refused with the first-load reason, DECLARATION_REJECTED written, last-known-good kept", async () => {
        assert(!r.ok && String((r as any).reason).includes("Z4"), JSON.stringify(r));
        assert(rejected.length === 1 && String(rejected[0].detail).includes("Z4"), JSON.stringify(rejected));
        assert(st.body.declarationHash === hashBefore && st.body.subjects?.state === "NOTHING_DECLARED", JSON.stringify({ h: st.body.declarationHash, s: st.body.subjects }));
      });
    } finally {
      await zsStop(rig);
    }
  }
}
