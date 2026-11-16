#!/usr/bin/env node
// ── mica-service — the door (Stage 2, infrastructure half only) ────────────
//
// HTTP/1.1 over Unix sockets ONLY. No TCP listener is opened anywhere in
// this file — every `http.Server` here is `.listen(<path>)` on a
// filesystem path, never `.listen(<port>)`.
//
// `/guard`'s disposition is NEVER computed here. This stage stubs it with
// `NotBoundGuardAdapter` (guard-adapter.ts), which always answers `503
// GUARD_NOT_BOUND` — an honest "no evaluation was obtained" (ruling J),
// never a fabricated HOLD/PASS/RELEASE. Stage 1's `evaluateAndRecord` binds
// in later by satisfying the same `GuardAdapter` interface.
//
// Peer identity: see peer-auth.ts's header for the fork this file resolves
// (no SO_PEERCRED in Node core; implemented as one socket per declared
// `routes[]` uid, under `<socketDir>/peers/<uid>/guard.sock`).

import * as http from "http";
import { StringDecoder } from "string_decoder";
import {
  readFileSync,
  existsSync,
  appendFileSync,
  readdirSync,
  unlinkSync,
  mkdirSync,
  writeFileSync,
  openSync,
  closeSync,
  statSync,
} from "fs";
import { join, dirname } from "path";
import { createHash } from "crypto";
import {
  canonicalHash,
  loadDeclarations,
  type Declarations,
  type Route,
  type SubjectHarm,
  utcInstantMs,
  validateActivation,
  validateDeclarations,
} from "./declarations";
import { toGuardFlags, UnknownSubjectError, ToolNameMismatchError } from "./to-guard-flags";
import { authorizeRoute, planPeerSockets, validatePeerDir, widenSocketFileMode, resolveGid, type PeerSocketPlan } from "./peer-auth";
import { toWireOptions, gate4SunsetConfigFor, type HarmGrantMemoryView, type HarmTargetEpoch, type WireErrandGrant } from "./to-wire-options";
import { declaredGrantsOf, GrantMemoryStore, GrantMemoryWriteError, type ApplyOutcome, type DeclaredGrant, type GrantKey } from "./grant-memory";
import {
  // ⛔ `assessSig` IS DELIBERATELY NOT IMPORTED HERE. S180: this file used to
  //   call it privately and got a null coverage on every pass, because the
  //   config it could reach lacks `readableLoadStates` by type. The coverage
  //   comes from the ONE wiring. Removing the import makes that STRUCTURAL
  //   rather than advisory — a second call cannot be written here without
  //   someone first adding back an import and meeting this comment.
  loadDeclaredClerkStamps,
  makeDeclaredClerkStampsLoader,
  loadExpectedChainIdentity,
  readPriorLoadWitness,
  CLERK_STAMPS_FIRST_LOAD_EVENT_TYPE,
  SUBJECT_LOG_BOUNDARY_MODULE_ID,
  // S199 · the READER's order bound, never a copy of its rule here.
  gate4OrderBound,
  gate4CountsAsOrder,
  GATE4_ORDER_BOUND_RULE,
  type PriorLoadWitness,
} from "./stage1-guard-adapter";
// R6 · the watcher's salt, the ONE epoch, and the six words. This module
// imports nothing from here, so there is no cycle. NOTHING IN IT REFUSES TO
// START any more: the arbiter's ruling of 2026-09-24 evening serves with the
// fingerprint ABSENT and says so loudly, because failing closed on the
// FINGERPRINT must mean "no fingerprint", never "no gate".
import {
  loadOrMintTargetSalt,
  readEpochMemory,
  EPOCH_MEMORY_KINDS,
  canonicaliseTargetIdentity,
  fingerprintTarget,
  describeTargetSaltAbsence,
  TARGET_CANON_VERSION,
  type TargetSaltState,
  type EpochMemory,
  type TargetSaltAbsenceReason,
} from "./target-fingerprint";
// GATE 1 · Stop 2 · the touch label. PURE and runtime-import-free (its one
// import from here is type-only), so this edge adds no cycle.
import { deriveInterestLabel, GATE1_LABEL_KIND, INTEREST_UNDERIVED, unquoteOnePair } from "./interest-label";
import { actIdentityKey, attemptPointerBytes, closePointerBytes, dropPointer, GuardDecisions, PointedActs, UnguardedActs } from "./witness-pointer";
// GATE 1 · Stop 2 · round 2 (placement D) · where the label is written and the
// class it is filed under. Imports nothing from here, so no cycle either.
import {
  buildInterestLabelRecord,
  frameLabelEventType,
  INTEREST_BOOK_BOUNDARY,
  INTEREST_BOOK_BOUNDARY_BASIS,
  INTEREST_BOOK_BOUNDARY_REFUSED,
  INTEREST_LABEL_NOT_PERSISTED,
  type InterestLabelEntry,
} from "./interest-book";
// STATUS-DOOR BRIEF (ARC_MICA-BRIEF_Status-Door_20260922). See
// core-door-status.ts's own header for why this is a SECOND, deliberately
// LAZY `/opt/mica-machine` touchpoint alongside stage1-guard-adapter.ts's
// eager one, and why: `/guard` refuses to boot without its glue; `/status`'s
// door row degrades to UNREADABLE instead, and answers 200 either way.
import { readCoreDoor, buildDoorSection, type DoorSection, type CoreDoorProbe } from "./core-door-status";
// STAGE 4 / DESIGN §A.2. The bound default. `stage1-guard-adapter.ts` is the
// ONLY file that imports mica-machine's glue by absolute path (§A.1, W1) —
// this file gets `EvaluateAndRecordPaths` re-exported from there rather than
// importing /opt/mica-machine a second time.
import {
  buildNotifier,
  DecisionJournal,
  Stage1GuardAdapter,
  SubjectEventJournal,
  wire,
  wireOptionsFor,
  SubjectChainLog,
  SUBJECT_LOG_BOUNDARY_EVENT_TYPE,
  type BuiltNotifier,
  type EvaluateAndRecordPaths,
  type RetiredPredecessor,
} from "./stage1-guard-adapter";
// AMENDMENT 9 / RULING P. Read-only: wire() only reads the declared log file
// (readers.logPath), never writes anything, and is called here SOLELY to
// populate /status's informational census — it never gates a guard
// decision. The guard adapter below remains NotBoundGuardAdapter (ruling J)
// for every actual pass/hold/release outcome, exactly as before this
// amendment. See to-wire-options.ts's header for why this import path is
// dev-workstation-relative rather than a deploy-time contract (owed to
// Stage 4's real /opt layout).


/**
 * Startup refused (F1/F2-shaped: never a disposition, never a partial
 * bind). Thrown by `start()` when any declared route's peer directory fails
 * its exact ownership/mode check, or when the `mica-bridge` group itself
 * cannot be resolved. The CLI entry point maps this to exit 2 and binds no
 * socket at all — not even the ones whose directories were fine.
 */
export class StartupRefused extends Error {}
import { computeFooting, NotBoundGuardAdapter, NothingDeclaredGuardAdapter, type GuardAdapter, type GuardOutcome, type ReaderFooting } from "./guard-adapter";

// ── the fourteen instruments, read at bytes this session ───────────────────
//
// [verified] every `*_SENSOR_ID` constant under src/mica/**, plus the gap
// reader's id in the glue, grepped this run:
//   src/mica/eng/index.ts:88                    ENG_SENSOR_ID = "MICA/Eng"
//   src/mica/sig/index.ts:53                    SIG_SENSOR_ID = "MICA/Sig"
//   src/glue/wire.ts:95                          GAP_READER = "clerk1.gap"
//   src/mica/gate1-scope/index.ts:27             GATE1_SCOPE_SENSOR_ID
//   src/mica/gate2-direction/index.ts:20         GATE2_DIRECTION_SENSOR_ID
//   src/mica/gate4-sunset/index.ts:21            GATE4_SUNSET_SENSOR_ID
//   src/mica/gate5-adaptive/index.ts:20          GATE5_ADAPTIVE_SENSOR_ID
//   src/mica/narrow-k/index.ts:155                NARROW_K_SENSOR_ID
//   src/mica/narrow-t/index.ts:108                NARROW_T_SENSOR_ID
//   src/mica/narrow-w/index.ts:136                NARROW_W_SENSOR_ID
//   src/mica/narrow-r/index.ts:136                NARROW_R_SENSOR_ID
//   src/mica/op1-doctor-cadence/index.ts:17       OP1_DOCTOR_CADENCE_SENSOR_ID
//   src/mica/op2-audit-presence/index.ts:17       OP2_AUDIT_PRESENCE_SENSOR_ID
//   src/mica/op3-node-response/index.ts:20        OP3_NODE_RESPONSE_SENSOR_ID
// `MICA/Chokepoint` is the composer, not an instrument (would make 15).
// There is no gate3 constant in the tree. H4 has no SENSOR_ID at all.
export const INSTRUMENT_IDS: readonly string[] = [
  "MICA/Eng",
  "MICA/Sig",
  "clerk1.gap",
  "MICA/gate1-scope",
  "MICA/gate2-direction",
  "MICA/gate4-sunset",
  "MICA/gate5-adaptive",
  "MICA/narrow-K",
  "MICA/narrow-T",
  "MICA/narrow-W",
  "MICA/narrow-R",
  "MICA/op1-doctor-cadence",
  "MICA/op2-audit-presence",
  "MICA/op3-node-response",
];

export interface InstrumentCensusRow {
  readonly id: string;
  /** NOTHING_DECLARED (Z0): the declaration names no subject; no reader was wired and no reading taken. */
  readonly state: "WIRED" | "UNWIRED" | "NOT_CONFIGURED" | "NOTHING_DECLARED";
  readonly reason: string;
  readonly lastVerdictKind: "ALARM" | "SILENT" | "CANNOT_ASSESS" | null;
  /**
   * AMENDMENT 11 / RULING R item 2 — the printed ceiling. `null` when this
   * row is UNWIRED (no reading was taken at all — nothing to disclose a
   * footing for); populated, from a REAL live observation (never an
   * assertion), whenever wire() actually constructed a log reader for this
   * row. See guard-adapter.ts's ReaderFooting for the exact shape and the
   * exposure it states.
   */
  readonly footing: ReaderFooting | null;
}

/**
 * P6 MOVED `computeFooting` to `guard-adapter.ts`, beside the `ReaderFooting`
 * type it produces, because `/guard`'s per-decision footing now needs the same
 * judgement `/status`'s census needs, and a rule with two callers that lives
 * inside one of them gets copied rather than shared. Re-exported here so every
 * existing importer — and the unit test that proves the rule against every load
 * state mica-machine can report — is unchanged.
 */
export { computeFooting };

/**
 * STAGE 4 §A, FOUND LIVE ON THE BOX 2026-09-20 AND FIXED HERE.
 *
 * This constant used to read: "Stage 2 stub: this service never calls
 * mica-machine's wire() to gate a guard decision; the guard adapter is
 * NotBoundGuardAdapter until Stage 1's evaluateAndRecord is bound in."
 *
 * Stage 4 §A made `guardBound` a live value, and the first relay of it
 * served a /status in which `guardBound: true` and twelve instrument rows
 * saying the adapter is NotBoundGuardAdapter sat IN THE SAME DOCUMENT. The
 * bit was right and the prose was a year out of date — and a doctor reads
 * the prose. Design §I.2 is explicit about why that is not cosmetic: "a
 * broken bridge is indistinguishable from a permissive one unless the
 * caller says so every time." A reason string that says the guard is
 * unbound, while it is bound, manufactures exactly the belief the field
 * exists to prevent, and does it in the census the doctor is told to trust.
 *
 * What the twelve rows actually are is a VACANCY, not a verdict and not a
 * statement about binding: no reading was ever taken for them. Said that
 * way, the sentence stays true whether or not the guard is bound, which is
 * the property the old one lacked.
 */
// ⛔ THE SECOND CLAUSE OF THIS SENTENCE WAS FALSE, AND THE FIRST IS THE RULING.
//
//   It read "the remaining twelve rows have no reader behind them". Measured on
//   the live box 2026-09-29: wire() had built EIGHT readers on the serving
//   declaration and /log's sensorIds showed all eight composing, so the claim was
//   false for SIX of the twelve rows it was printed on.
//
//   ⚠ THE SCOPE IS NOT THE DEFECT AND IS NOT CHANGED HERE. Ruling P / Amendment 9
//   deliberately populates this census from Eng and Sig only, and
//   mica-service.test.ts pins that with "the other twelve are untouched by
//   Ruling P". Widening it is the arbiter's act, not this file's — and it is on
//   the board as a WHAT.
//
//   What is fixed is the FALSE FACTUAL CLAIM INSIDE THE TRUE RULING: "not
//   populated here" is what Ruling P says; "has no reader behind it" is a
//   statement about the deployment that this row cannot make and that the box
//   contradicts. The row now says what it does not know instead of asserting an
//   absence it never checked.
const NO_READING_REASON =
  "No reading was taken for this row. Only readers a live wire() call actually BUILDS are " +
  "populated here " +
  "(Ruling P / Amendment 9). ⛔ THIS SENTENCE USED TO NAME MICA/Eng AND MICA/Sig SPECIFICALLY, and it " +
  "was true when written because they were the only two this deployment wired — THE RULING FIXED THE " +
  "SCOPE, NEVER THE PAIR. This census reports every reader a live wire() call builds, however many that is; " +
  "it names no count, because a count in this sentence went stale the day the next reader was wired. " +
  "THIS ROW IS OUT OF THAT SCOPE AND IS NOT A STATEMENT ABOUT WHETHER A READER " +
  "EXISTS: a reader may well be wired and composing on the floor while this row reads UNWIRED, and " +
  "/log's sensorIds is the list that says which readers actually composed. This census is narrower than " +
  "the gate by ruling, and reported UNWIRED " +
  "rather than asserted WIRED, which is what /status's \"census, never a verdict\" rule requires. This is a " +
  "vacancy in the census — it is NOT a claim about whether the guard adapter is bound. That claim is " +
  "/status.guardBound, which Stage 4 \u00A7A made a live value rather than a literal.";

/**
 * Twelve of fourteen are UNWIRED unconditionally, because nothing has ever
 * taken a reading for them — NOT, since Stage 4 \u00A7A, because the guard
 * adapter is unbound. Reporting any of THOSE twelve WIRED would be
 * exactly the overclaim `/status`'s "census, never a verdict" rule forbids.
 *
 * AMENDMENT 9 / RULING P narrows this for exactly two rows — "MICA/Eng" and
 * "MICA/Sig" — because Stage 0's contract had claimed they were WIRED
 * "because a log path is declared" and that claim was FALSE against the
 * schema Stage 0 actually shipped (no logPath field existed at all;
 * WireOptions.logPath was necessarily undefined and wire.ts:370-374 pushed
 * both wired:false). Now that readers.logPath/readers.logKind are real
 * schema fields, this function makes the claim TRUE rather than merely
 * fixing the words: when a declaration is supplied, it calls mica-machine's
 * REAL wire() (read-only over the declared log file) and reports back
 * whatever that live call actually found — WIRED only if wire() actually
 * constructed the reader, with the real verdict kind, not an assertion.
 * This function does not gate anything and does not consult the guard
 * adapter at all: it is a census of readers, and it reads the same
 * whether the adapter is Stage1GuardAdapter or NotBoundGuardAdapter.
 */
/**
 * LONG RUN A STOP 2 · WHEN THE LIVE TARGET-SALT EPOCH BEGAN (ms), or null.
 * The earliest event-book row of an EPOCH_MEMORY_KINDS kind whose `saltId` is the
 * live salt's gives its `ts`; failing that, the row this start itself announced
 * (`announcedAt`); failing that, null — the bridge does not know, and says so.
 * Pure and exported so the arms can be tested without a salt on disk.
 */
export function saltEpochStartFrom(
  state: TargetSaltState,
  events: readonly Record<string, unknown>[],
  announcedAt: string | null
): number | null {
  if (state.status !== "PRESENT") return null;
  const kinds: readonly string[] = EPOCH_MEMORY_KINDS;
  const ms = (ts: unknown): number | null => {
    if (typeof ts !== "string") return null;
    const t = Date.parse(ts);
    return Number.isFinite(t) ? t : null;
  };
  for (const e of events) {
    if (typeof e.kind === "string" && kinds.includes(e.kind) && e.saltId === state.saltId) return ms(e.ts);
  }
  return announcedAt === null ? null : ms(announcedAt);
}

/**
 * M1 (a FORK for the arbiter): the /guard REPLY's decision object, trimmed to what the
 * caller acts on. Keys absent on the decision stay absent (never `undefined`).
 */
export const GUARD_REPLY_DECISION_KEYS = ["disposition", "execute", "decisionHash", "floorKind", "blindSplit", "rationale"] as const;
export function trimDecisionForGuardReply(decision: Readonly<Record<string, unknown>>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of GUARD_REPLY_DECISION_KEYS) {
    if (Object.prototype.hasOwnProperty.call(decision, k)) out[k] = decision[k];
  }
  return out;
}

/**
 * ZERO SUBJECTS (ticket Bridge-Zero-Subjects v2 §2.1, F-1 (a)). The word every
 * census row prints when the declaration names no subject. It is the ABSENCE
 * of a reading, printed by the bridge — never SILENT, never CANNOT_ASSESS, and
 * never "NOT WIRED — no Gate-x … was declared", which is true but answers a
 * different question (a subject that declares no basket).
 */
export const NOTHING_DECLARED_REASON =
  "NOTHING DECLARED — the declaration names no subject (subjects: []). No reader was wired and no " +
  "reading was taken. This row is not a verdict and not CANNOT_ASSESS: there is no conduct this " +
  "deployment has been asked to read.";

/** `subjects: []` — the one predicate every zero-subject branch in this file reads. */
export function nothingDeclared(declarations: Declarations): boolean {
  return declarations.subjects.length === 0;
}

/** /status.subjects (F-11 (a): at every n). `null` only during PREFLIGHT. */
export type SubjectsCensus =
  | { readonly state: "NOTHING_DECLARED"; readonly declared: readonly [] }
  | {
      readonly state: "DECLARED";
      readonly declared: readonly { readonly subject: string; readonly peerUid: number; readonly unit?: string }[];
    };

export function subjectsCensus(declarations: Declarations): SubjectsCensus {
  if (nothingDeclared(declarations)) return { state: "NOTHING_DECLARED", declared: [] };
  return {
    state: "DECLARED",
    declared: declarations.subjects.map((s) =>
      s.unit === undefined ? { subject: s.subject, peerUid: s.peerUid } : { subject: s.subject, peerUid: s.peerUid, unit: s.unit }
    ),
  };
}

export function buildInstrumentCensus(
  declarations?: Declarations,
  // C9: the SAME resolver the gate uses. Before this the census probed the raw
  // declared path while a state-dir-redirected gate read another — two readers
  // of two files, reported as one census. That is the defect this beat is named
  // for, one layer down.
  resolveLogPath: (declaredPath: string) => string = (p) => p,
  // LONG RUN A STOP 2 · the SAME harm epoch the gate gets (the service's
  // `harmEpochFor`), so the census and the decision read one harm stanza alike.
  harmEpoch: HarmTargetEpoch | null = null,
  // S216-2 · the SAME grant-memory view the gate gets (the service's grantMemoryViewFor).
  grantMemory: HarmGrantMemoryView | null = null
): readonly InstrumentCensusRow[] {
  const base: InstrumentCensusRow[] = INSTRUMENT_IDS.map((id) => ({
    id,
    state: "UNWIRED" as const,
    reason: NO_READING_REASON,
    lastVerdictKind: null,
    footing: null,
  }));

  if (declarations === undefined) return base;

  // ZERO SUBJECTS: no wire() call, no reading. Every row prints the word.
  if (nothingDeclared(declarations)) {
    return INSTRUMENT_IDS.map((id) => ({
      id,
      state: "NOTHING_DECLARED" as const,
      reason: NOTHING_DECLARED_REASON,
      lastVerdictKind: null,
      footing: null,
    }));
  }

  try {
    // ACT B · the census wires the stamps too, so /status.instruments describes
    // the same F3 the decisions get. A census that omitted them would be the
    // stale-printer shape this file already carries one instance of.
    // T8 · the census passes the identity loader too, so /status describes the
    // same F3 the decisions get. Omitting it here would make the census report a
    // blind F3 over a gate that reads, or the reverse — the C9 Part D defect.
    const wiring = wire(toWireOptions(declarations, resolveLogPath, loadDeclaredClerkStamps, loadExpectedChainIdentity, harmEpoch, grantMemory));
    // [verified] wire.ts:93-94 — ENG_READER = "MICA/Eng", SIG_READER = "MICA/Sig",
    // matching INSTRUMENT_IDS[0]/[1] exactly (this file's own header, bytes 40-41).
    // ⛔ EVERY WIRED ROW, NOT TWO. Ruling P fixed the SCOPE of this census — it
    //   reports only what a live `wire()` call populates, and does not invent
    //   readings for rows nothing wired. It did NOT say the populated set is
    //   two: that was an artefact of the day it was written, when Eng and Sig
    //   were the only readers on the box. Every reader wire() builds composes,
    //   and printing two of them while the decision names all of them is the
    //   stale-printer shape this file already carries one instance of. (No count
    //   here, on purpose: "eight" was true on 2026-09-29 and went stale.)
    //
    //   ⚠ AND THE REASON STRING ON AN UNWIRED ROW STILL SAYS WHY. A row this
    //   wiring did not build is UNWIRED with its own words; a row it built is
    //   populated from THAT wiring and no other. Neither is inferred.
    const loadState = wiring.logFile?.getLoadState() ?? null;
    for (const entry of wiring.census.readers) {
      const idx = INSTRUMENT_IDS.indexOf(entry.reader as (typeof INSTRUMENT_IDS)[number]);
      // A reader the glue wires that this census has no row for is a REAL
      // finding — the two lists have drifted — and it is left out rather than
      // appended, because appending would hide it.
      if (idx < 0 || !entry.wired) continue;
      base[idx] = readerRow(base[idx], entry, declarations, loadState);
    }
    return base;
  } catch (err) {
    // Never let a live probe failure crash /status. Naming the failure is
    // honest; a thrown exception surfacing as a 500 from a census endpoint
    // would not be.
    const probeFailedReason = `AMENDMENT 9 / Ruling P wiring probe threw: ${err instanceof Error ? err.message : String(err)}`;
    const engIdx = INSTRUMENT_IDS.indexOf("MICA/Eng");
    const sigIdx = INSTRUMENT_IDS.indexOf("MICA/Sig");
    base[engIdx] = { ...base[engIdx], reason: probeFailedReason };
    base[sigIdx] = { ...base[sigIdx], reason: probeFailedReason };
    return base;
  }
}

function readerRow(
  prevRow: InstrumentCensusRow,
  readerEntry: { readonly wired: boolean; readonly source: string; readonly verdictKind: "ALARM" | "SILENT" | "CANNOT_ASSESS" | null },
  declarations: Declarations,
  loadState: string | null
): InstrumentCensusRow {
  if (!readerEntry.wired) {
    // wire() itself declined to wire it (e.g. logPath absent) — report
    // wire()'s own stated reason, not the unbound-guard reason above; a
    // reader can be unwired for a different cause than "no adapter bound".
    // No reading was taken, so there is no footing to disclose.
    return { ...prevRow, reason: readerEntry.source, footing: null };
  }
  return {
    id: prevRow.id,
    state: "WIRED",
    reason:
      `readers.logPath ("${declarations.readers.logPath.value}") and readers.logKind ` +
      `("${declarations.readers.logKind.value}") are declared (Ruling P). ${readerEntry.source}`,
    lastVerdictKind: readerEntry.verdictKind,
    // AMENDMENT 11 / RULING R item 2: the printed ceiling, on the reading's
    // own face. loadState is null only if wire() somehow wired the reader
    // without constructing a logFile at all — not an expected case, but
    // handled rather than assumed away.
    footing: loadState === null ? null : computeFooting(prevRow.id, loadState),
  };
}

// ── pilot state, computed from the clock (not stored) ──────────────────────

export type PilotCensus =
  | { readonly state: "INACTIVE" }
  | { readonly state: "ACTIVE"; readonly sessionId: string; readonly expiresAt: string }
  | { readonly state: "EXPIRED"; readonly sessionId: string; readonly expiresAt: string };

// ── /status shape ────────────────────────────────────────────────────────

/**
 * P4 ITEM C / VERIFIER: `lastErrorAt` answers a question `state: "DEGRADED"`
 * alone cannot — NEVER ONE WORD FOR TWO FACTS, the house rule this field
 * exists to satisfy. `degraded` is a LATCH (Amendment 3) and stays latched on
 * purpose: a fault that happened is a fact, and clearing it on the next
 * success would let a disk that fails once an hour quietly stop being
 * reported between failures. But a latch that never clears also cannot say
 * "failing right now" apart from "failed once, an hour ago, and has been fine
 * since" — both read as `state: "DEGRADED"` forever, and an operator paged at
 * 3am on a fault that resolved itself hours earlier is the cost of that
 * silence. `lastErrorAt` is the timestamp of the MOST RECENT append failure
 * (updated again on every subsequent failure, never reset by a success) — an
 * operator or alerter compares it to now: close means failing right now,
 * distant means the latch is reporting history rather than the present.
 * Additive only; `state`/`file`/`error` are unchanged in shape and meaning.
 */
export type PersistenceState =
  | { readonly state: "OK" }
  | { readonly state: "DEGRADED"; readonly file: string; readonly error: string; readonly lastErrorAt: string };

/** One event-book record that was built, attempted, and is NOT in the book. */
export interface DroppedRecord {
  readonly kind: string;
  readonly seq: number;
  readonly ts: string;
  readonly error: string;
}

/**
 * THE LEDGER OF WHAT IS MISSING — the counterpart to `PersistenceState`, and
 * deliberately NOT folded into it. `persistence: DEGRADED` is a latch on the
 * DISK ("a write to this file failed"); this is a ledger of the LOSSES ("these
 * N facts are not in the book, and here is the first and the last"). They are
 * two different facts and this house does not spend one word on two: a
 * `DEGRADED` that later clears tells an operator nothing about what went
 * missing while it was set, and `count` surviving is the whole point.
 *
 * `[owed -> the arbiter]` Act A's `persistence NOT_BEGUN` (ruling 4, the alerter's
 * always-speak list) lives on `phase-a-acta` ONLY — verified by `git grep`
 * across every head this run. This branch must be able to ship alone and must
 * not edit what a refused branch is already editing, so this is a NEW additive
 * key rather than a widening of `PersistenceState`. If Act A ever relays, the
 * two want reconciling into one persistence census; two censuses of one organ
 * is a defect, just a much smaller one than a blind.
 */
export interface DroppedRecordsCensus {
  readonly count: number;
  readonly first: DroppedRecord | null;
  readonly last: DroppedRecord | null;
}

export interface StatusResponse {
  readonly preflight: "PREFLIGHT" | "SERVING";
  readonly declarationHash: string;
  readonly declarationPath: string;
  readonly declarationLoadedAt: string;
  readonly lastRejectedDeclaration: { readonly hash: string; readonly field: string; readonly reason: string; readonly ts: string } | null;
  readonly pilot: PilotCensus;
  readonly instruments: readonly InstrumentCensusRow[];
  /**
   * ZERO SUBJECTS (F-11 (a)): who is declared, at every n. Served to every
   * /status holder, the alerter included. `null` only during PREFLIGHT.
   */
  readonly subjects: SubjectsCensus | null;
  readonly guardBound: boolean;
  readonly startedAt: string;
  readonly uptimeSeconds: number;
  /** F5: append failures are never swallowed silently — this is where they surface. */
  readonly persistence: PersistenceState;
  /**
   * THE RULE, made readable: every event-book record that was built and did
   * not land is counted here. `persistence` says the disk is bad; this says
   * what was lost because of it. Never one word for two facts.
   */
  readonly droppedRecords: DroppedRecordsCensus;
  /** F4: a quarantined partial/invalid tail, per book, never re-parsed or rewritten. */
  readonly quarantine: {
    readonly eventBook: QuarantineInfo | null;
    readonly subjectLog: QuarantineInfo | null;
  };
  /**
   * AMENDMENT 5 / VERIFIER F3 "additional relay hardening": an executable
   * release identity, so a relay's rollback can verify it is running the
   * PREVIOUS release's own code, not merely that a symlink points at the
   * right directory (a restored symlink proves nothing about what a
   * still-running process actually loaded before it was restarted).
   * Read once at startup from `<release>/VINTAGE` (one level above this
   * file, i.e. `../VINTAGE` relative to `mica-service.ts` — relay-bridge.sh
   * writes it at exactly that path). `null` when absent (e.g. every dev/
   * test context, which never lays a VINTAGE file) — absence is disclosed,
   * never guessed at.
   */
  readonly release: { readonly sha: string | null; readonly laidAt: string | null } | null;
  /**
   * AMENDMENT 7 / VERIFIER: the swap-in-progress marker (Amendment 6),
   * now surfaced here so a POLLER can see it — Stage 3's alerter is the
   * intended consumer (not yet built; this field exists so it has
   * something to read once it is). A FACT, never a verdict: "this marker
   * file exists, here is its content" — no health vocabulary, no
   * "healthy"/"stuck"/"ok". `markerPresent:false` is the ordinary case on
   * every healthy relay's far side; `markerPresent:true` means exactly
   * what `readRelayMarkerFact()`'s own doc comment says, no more.
   */
  readonly relay: { readonly markerPresent: boolean; readonly detail: string | null; readonly path: string };
  /**
   * AMENDMENT 9 / RULING Q. `503 RECORD_NOT_PERSISTED` on POST
   * /subject-events is retryable-and-owed, bounded by
   * declarations.subjectLog.maxUnacknowledged. Below that count: the 503
   * stands and the caller retries from its own outbox (Stage 4 scope, not
   * this service's). At or beyond it: `stale` flips true here AND the next
   * 503 body itself says so (`stale: true`) — the arbiter's binding condition
   * that "the counter ships with its reader named and wired in the same
   * beat." A CENSUS FIELD, never a verdict: this counts the service's own
   * consecutive append failures, not any caller's outbox depth.
   *
   * EXACT SHAPE (stated so Builder C's alerter branch can match it):
   *   { "unacknowledgedBacklog": number, "maxUnacknowledged": number, "stale": boolean }
   */
  readonly subjectEvents: {
    readonly unacknowledgedBacklog: number;
    readonly maxUnacknowledged: number;
    readonly stale: boolean;
  };
  /**
   * STAGE 4 / DESIGN §A.6, Layer 2. `null` only during PREFLIGHT (before
   * `start()` has claimed ownership of `paths.history`) — once SERVING,
   * always the CURRENT process's own claim (never another's; a conflicting
   * claim refuses startup as `StartupRefused`, per §A.6). The arbiter's own
   * checklist item before the first guarded message (§D.3).
   */
  readonly historyOwner: HistoryOwnerFact | null;
  /**
   * STAGE 4 / DESIGN §A.6, "stuck-lock visibility". One row per `<path>.lock`
   * sibling that EXISTS right now, for each of the five book paths
   * (`journal`, `floorTrail`, `ledger`, `history`, `decisionEvents`) —
   * `append-store.ts`'s `exclusiveFileLock` convention. Without this, a lock
   * left behind by a crash presents only as an unexplained run of
   * `PROJECTION_FAILED` lines with nobody told why.
   */
  readonly appendLocks: readonly { readonly path: string; readonly since: string }[];
  /**
   * STATUS-DOOR BRIEF. A census of the core door
   * (`/opt/mica-machine/src/core-door/core-door.ts`) — never a verdict. See
   * `core-door-status.ts` for the shape and the UNREADABLE-not-CLOSED rule
   * (constraint #2: a door this bridge cannot read is reported as such, and
   * `/status` still answers 200).
   */
  readonly door: DoorSection;
  /**
   * R6 · THE EPOCH'S PUBLIC FACE, and it is a CENSUS, never a verdict.
   *
   * `saltId` is a salted digest OF the salt and reveals nothing about it; THE
   * SALT ITSELF IS NEVER ON THIS OBJECT AND NEVER LEAVES THE PROCESS.
   *
   * WHY IT IS ON /status AT ALL. A fingerprint is only comparable to another
   * taken under the same salt and the same canonicalisation. A reader holding
   * records from last week has no way to know whether the bridge still runs the
   * epoch that wrote them — and, unlike an ordinary version skew, the failure
   * is SILENT: digests from two epochs simply stop matching, which looks exactly
   * like two different targets. This field is what makes that checkable.
   *
   * `mintedAtThisStart: true` means THIS PROCESS START BEGAN A NEW EPOCH. It is
   * true exactly once per epoch, on the start that created the salt file, and it
   * is `false` on every restart afterwards — so an operator who sees it true on
   * a restart they did not expect has found something.
   *
   * ── `absence` · "NO FINGERPRINT, AND HERE IS WHY", READABLE FROM OUTSIDE ──
   *
   * The arbiter's ruling 2 makes an absent fingerprint an ORDINARY SERVING STATE, not
   * a crash, so it must be legible on the one route the operator already uses.
   * FOUR KEYS, ONE SHAPE, NEVER OPTIONAL: `saltId` is `null` exactly when
   * `absence` is non-null, and `absence` carries the reason word AND the
   * sentence that explains it. **The salt's bytes are on no branch of this
   * object** and the suite asserts that no `/status` body ever contains them.
   *
   * `null` for the whole section still means PREFLIGHT: a service that has not
   * completed `start()` has neither an epoch nor a reason it lost one.
   */
  readonly targetFingerprint: {
    readonly saltId: string | null;
    readonly canonVersion: number;
    readonly mintedAtThisStart: boolean;
    readonly absence: { readonly reason: TargetSaltAbsenceReason; readonly detail: string } | null;
  } | null;
}

/** Where the core door's own tree lives — the live release, always. Only a test overrides it. */
export const DEFAULT_DOOR_REPO_ROOT = "/opt/mica-machine";

/** STAGE 4 / DESIGN §A.6, Layer 2 — the owner-file content, verbatim. */
export interface HistoryOwnerFact {
  readonly pid: number;
  readonly bootId: string;
  readonly startedAt: string;
  readonly unit: string;
}

// ── append-only files, one writer, serialized per file ──────────────────────
//
// Node is single-threaded and this service is the SOLE writer of these two
// files (design §C.9). A promise-chained queue per file is this stage's
// stand-in for `flock` — sufficient for one process, one writer; it is NOT
// a multi-process lock, and this file says so rather than claiming it is.

export interface AppendResult {
  readonly ok: boolean;
  readonly error: string | null;
}

/**
 * AA2 · a record REFUSED by a check made inside the subject chain's append (the writer's own rule, not a persistence
 * failure): thrown from a `build` closure, caught by `ChainedSubjectAppender.appendDerived`, answered 400 with `code`.
 */
export class AppendRefused extends Error {
  constructor(readonly code: string, readonly detail: string) {
    super(`${code}: ${detail}`);
  }
}

export interface QuarantineInfo {
  readonly path: string;
  readonly offset: number;
  readonly bytes: number;
}

/**
 * AMENDMENT 3 / VERIFIER F4+F5.
 *
 * F5 — append failures are NEVER swallowed. `append()` now RETURNS whether
 * it succeeded; the caller decides what a failed MANDATORY append means for
 * its response (a 503, per F5) instead of this class silently logging and
 * moving on. The last failure is also latched (`degraded`) so `/status` can
 * report `persistence: DEGRADED {file, error}` even for a non-mandatory
 * append (e.g. an event-book write during a declaration rejection).
 *
 * F4 — `readAll()` reads line by line and accepts ONLY complete,
 * newline-terminated, valid-JSON lines. An invalid or partial final
 * fragment (no trailing newline, or a newline-terminated line that still
 * fails `JSON.parse`) is QUARANTINED: recorded as `{path, offset, bytes}`
 * (never re-parsed, never rewritten into the file, and every prior valid
 * line is still returned) rather than thrown — the previous version threw
 * `SyntaxError` straight out of a request handler on exactly this input.
 */
/**
 * AMENDMENT 4 / VERIFIER F4 (round 2). The Amendment-3 fix reported a
 * quarantine but never actually EVICTED the corrupt tail from the live
 * file — a request accepted and written BEHIND the corrupt line stayed
 * permanently invisible to `readAll()` (which still stopped at that same
 * line on every future read, including after a restart), so sequence
 * allocation reused a number and an identical re-submission after restart
 * was treated as brand new instead of a duplicate. Reporting a quarantine
 * is not recovery if the service goes on acknowledging writes it will
 * later forget.
 *
 * Fixed: `append()` now checks, BEFORE writing, whether the file's current
 * tail is corrupt (a trailing fragment with no newline, or a
 * newline-terminated line that fails to parse). If so, it ATOMICALLY moves
 * that corrupt suffix into a durable quarantine sidecar
 * (`<path>.quarantine`, one JSONL metadata record per quarantine event,
 * `dataBase64` carrying the exact evicted bytes) and truncates the active
 * log back to the last valid newline — BEFORE the new record is appended.
 * The active log is therefore always either empty or ends in a complete,
 * valid, newline-terminated record by the time any read (this request's
 * own dedupe check included) looks at it again. Nothing is rewritten
 * that was already valid; only the corrupt tail moves, verbatim, to the
 * sidecar — never re-parsed, never reconstructed, never guessed at.
 */
function detectTrailingCorruption(buf: Buffer): { readonly validBytes: number; readonly corrupt: Buffer | null } {
  let pos = 0;
  let validEnd = 0;
  while (pos < buf.length) {
    const nl = buf.indexOf(0x0a, pos);
    if (nl === -1) {
      return { validBytes: validEnd, corrupt: buf.subarray(validEnd) };
    }
    const lineBuf = buf.subarray(pos, nl);
    if (lineBuf.length > 0) {
      try {
        JSON.parse(lineBuf.toString("utf8"));
      } catch {
        return { validBytes: validEnd, corrupt: buf.subarray(validEnd) };
      }
    }
    pos = nl + 1;
    validEnd = pos;
  }
  return { validBytes: validEnd, corrupt: null };
}

// C9: exported so the concurrency of `appendDerived` can be tested AT THIS
// OBJECT, where the race actually lives. Driving it through /subject-events does
// not reach it — see the C9 receipt: each HTTP request's queued append completes
// on the microtask queue before the next request's handler is entered, so the
// requests serialise themselves and a test built on them passes with the defect
// present. The class is otherwise unchanged and still constructed only here.
export class SerializedAppender {
  private queue: Promise<void> = Promise.resolve();
  // P4 ITEM C: `at` is the MOST RECENT failure's timestamp, overwritten on
  // every new failure and never cleared by a success — see PersistenceState's
  // own doc comment for why the latch stays and what the timestamp buys.
  private degraded: { error: string; at: string } | null = null;
  private quarantine: QuarantineInfo | null = null;

  constructor(private readonly path: string | null) {}

  private quarantinePath(): string | null {
    return this.path === null ? null : `${this.path}.quarantine`;
  }

  /**
   * Moves any trailing corruption on THIS process's own view of the file
   * to the sidecar and truncates it out of the active log, atomically
   * enough for a single-writer file (truncate is one syscall; the sidecar
   * append happens first, so a crash between the two leaves the corrupt
   * bytes duplicated in both places — recoverable — never lost from
   * either). Called immediately before every write.
   */
  private evictTrailingCorruption(): void {
    if (this.path === null || !existsSync(this.path)) return;
    const buf = readFileSync(this.path);
    if (buf.length === 0) return;
    const { validBytes, corrupt } = detectTrailingCorruption(buf);
    if (corrupt === null) return;
    const sidecar = this.quarantinePath()!;
    const record = {
      quarantinedAt: new Date().toISOString(),
      offset: validBytes,
      bytes: corrupt.length,
      dataBase64: corrupt.toString("base64"),
    };
    mkdirSync(dirname(sidecar), { recursive: true });
    appendFileSync(sidecar, JSON.stringify(record) + "\n", { encoding: "utf8" });
    require("fs").truncateSync(this.path, validBytes);
  }

  append(line: unknown): Promise<AppendResult> {
    const result = this.queue.then((): AppendResult => {
      if (this.path === null) return { ok: true, error: null };
      try {
        mkdirSync(dirname(this.path), { recursive: true });
        this.evictTrailingCorruption();
        // After eviction the file (if it exists at all) is either empty or
        // ends in a complete, newline-terminated valid record — a plain
        // append is always safe here; no fencing prefix is ever needed.
        appendFileSync(this.path, JSON.stringify(line) + "\n", { encoding: "utf8" });
        return { ok: true, error: null };
      } catch (err) {
        const message = String(err);
        this.degraded = { error: message, at: new Date().toISOString() };
        // eslint-disable-next-line no-console
        console.error(`[mica-service] append to ${this.path} failed: ${message}`);
        return { ok: false, error: message };
      }
    });
    // THE QUEUE TAIL MUST ALWAYS SETTLE FULFILLED — both arms, deliberately.
    // Before: `result.then(() => undefined)`, with no rejection arm. When
    // `result` rejected (reachable: `appendDerived`'s `readAll()` threw
    // EISDIR/EACCES from OUTSIDE its try), `this.queue` became a REJECTED
    // promise nothing ever handled — so (a) it was itself an unhandled
    // rejection, and (b) EVERY later append chained off a rejected queue and
    // rejected immediately, FOREVER: one bad stat bricked the appender
    // permanently, and nothing said so. The rejection is NOT swallowed — the
    // caller's own `result` still carries it. Only the internal tail, which no
    // caller ever sees, is neutralised.
    this.queue = result.then(() => undefined, () => undefined);
    return result;
  }

  /**
   * C9 / CONDITION 3 — APPEND WITH THE SEQUENCE MINTED INSIDE THE QUEUE.
   *
   * THE DEFECT THIS REPLACES. `handleSubjectEvents` used to do
   *
   *     const subjectSeq = this.subjectLog.readAll().length + 1;   // OUTSIDE
   *     ...
   *     const appended = await this.subjectLog.append(record);      // INSIDE
   *
   * — derive, then enqueue. Two concurrent POSTs could both read length N and
   * both write `subjectSeq = N+1`. That was COSMETIC while nothing read the
   * number as a sequence. It stopped being cosmetic the moment Part A mapped
   * `sequenceNumber = subjectSeq`: `mica-log-file.ts:347` refuses a record whose
   * `sequenceNumber <= previous` FOR THE SAME `moduleId`, and Part A maps
   * `moduleId = identity.subject`. So one duplicate number would make the whole
   * file `verify=INVALID` — a permanent blind, from a race, on the very log C9
   * exists to make readable.
   *
   * Here the read and the write happen in the SAME queued closure, so the
   * sequence a record carries is the one the file had when that record was
   * written, and nothing can interleave between the two.
   *
   * NOT FIXED HERE, and named rather than left to be found: the DUPLICATE /
   * CONFLICT lookup in `handleSubjectEvents` still runs before the queue, so two
   * genuinely simultaneous posts of the SAME identity+kind can both pass it and
   * both append. That is a different race with a different consequence (a
   * duplicate identity, not a duplicate sequence number, and the reader does not
   * refuse it), and moving it inside the queue would move the 200-duplicate/409
   * decision with it. Out of C9's scope; C9 receipt carries the row.
   */
  appendDerived<T>(
    // `previous` is the LAST RECORD ALREADY IN THE FILE, or null for the first.
    // It is handed in rather than fetched by the caller for the same reason the
    // sequence is minted here: anything the caller reads OUTSIDE this closure is
    // read at a different moment from the one the record is written at, and two
    // moments is exactly the defect S141-d names. The read is free — `readAll()`
    // already ran, one line below, to derive the sequence.
    build: (sequenceNumber: number, previous: Record<string, unknown> | null) => T
  ): Promise<AppendResult & { readonly sequenceNumber: number; readonly record: T | null }> {
    const result = this.queue.then(
      (): AppendResult & { sequenceNumber: number; record: T | null } => {
        // FLOATING-REJECTION FIX. `readAll()` and `build()` used to sit OUTSIDE
        // this try. `readAll()` does `readFileSync(this.path)`, which throws on
        // EISDIR/EACCES — so an unreadable subject log did not produce this
        // class's OWN documented failure shape (`{ok:false, error}`, latched
        // into `degraded`, answered by the caller's typed 503) but a REJECTED
        // promise, which `handleSubjectEvents` then floated out through
        // `void this.handleSubjectEvents(...)` and which KILLED THE PROCESS.
        // Measured on a real socket: child exit 1, request never answered.
        // Inside the try, an unreadable book is an ordinary append failure —
        // the same fact this class already knows how to tell the truth about.
        //
        // `record` is `T | null` because a failure BEFORE `build()` ran has no
        // record to report, and inventing one would be a lie in the shape of a
        // value. Callers read `.ok` first; none reads `.record`.
        let sequenceNumber = 0;
        let record: T | null = null;
        try {
          // The file's length AT WRITE TIME, not at request time. On a null path
          // (a service with no declared subject log) `readAll()` is [] and the
          // sequence still advances from 1, exactly as before.
          const existing = this.readAll();
          sequenceNumber = existing.length + 1;
          record = build(sequenceNumber, existing.length === 0 ? null : existing[existing.length - 1]);
          if (this.path === null) return { ok: true, error: null, sequenceNumber, record };
          mkdirSync(dirname(this.path), { recursive: true });
          this.evictTrailingCorruption();
          appendFileSync(this.path, JSON.stringify(record) + "\n", { encoding: "utf8" });
          return { ok: true, error: null, sequenceNumber, record };
        } catch (err) {
          const message = String(err);
          this.degraded = { error: message, at: new Date().toISOString() };
          // eslint-disable-next-line no-console
          console.error(`[mica-service] append to ${this.path} failed: ${message}`);
          return { ok: false, error: message, sequenceNumber, record };
        }
      }
    );
    // THE QUEUE TAIL MUST ALWAYS SETTLE FULFILLED — both arms, deliberately.
    // Before: `result.then(() => undefined)`, with no rejection arm. When
    // `result` rejected (reachable: `appendDerived`'s `readAll()` threw
    // EISDIR/EACCES from OUTSIDE its try), `this.queue` became a REJECTED
    // promise nothing ever handled — so (a) it was itself an unhandled
    // rejection, and (b) EVERY later append chained off a rejected queue and
    // rejected immediately, FOREVER: one bad stat bricked the appender
    // permanently, and nothing said so. The rejection is NOT swallowed — the
    // caller's own `result` still carries it. Only the internal tail, which no
    // caller ever sees, is neutralised.
    this.queue = result.then(() => undefined, () => undefined);
    return result;
  }

  /**
   * Every COMPLETE, valid line, in order, from the CURRENT (possibly not
   * yet evicted) state of the file. If nothing has appended since a
   * corruption landed, this still detects and reports it live (for
   * `/status` immediately after an external corruption, before the next
   * write) — see `quarantineInfo()` for how durable, post-eviction
   * quarantine state is reported once eviction has actually happened.
   */
  readAll(): readonly Record<string, unknown>[] {
    if (this.path === null || !existsSync(this.path)) return [];
    const buf = readFileSync(this.path);
    if (buf.length === 0) {
      this.quarantine = null;
      return [];
    }
    const { corrupt } = detectTrailingCorruption(buf);
    this.quarantine = corrupt === null ? null : { path: this.path, offset: buf.length - corrupt.length, bytes: corrupt.length };

    const records: Record<string, unknown>[] = [];
    let pos = 0;
    while (pos < buf.length) {
      const nl = buf.indexOf(0x0a, pos);
      if (nl === -1) break; // trailing fragment — already reflected in this.quarantine above
      const lineBuf = buf.subarray(pos, nl);
      if (lineBuf.length > 0) {
        try {
          records.push(JSON.parse(lineBuf.toString("utf8")));
        } catch {
          break; // corrupt line — already reflected in this.quarantine above
        }
      }
      pos = nl + 1;
    }
    return records;
  }

  persistenceState(): { readonly degraded: boolean; readonly error: string | null; readonly lastErrorAt: string | null } {
    return {
      degraded: this.degraded !== null,
      error: this.degraded?.error ?? null,
      // P4 ITEM C: the MOST RECENT failure's timestamp — null only when this
      // appender has never failed at all.
      lastErrorAt: this.degraded?.at ?? null,
    };
  }

  /**
   * `/status`'s BEST-EFFORT refresh of quarantine detection.
   *
   * `readAll()` still throws for callers that must not proceed on a bad read
   * (`/events` cannot serve a book it cannot read, and says so with a typed
   * failure). This one LATCHES the read failure into `degraded` and returns.
   *
   * WHY THE CENSUS MUST NOT INHERIT THE THROW: `buildStatus()` called
   * `readAll()` on BOTH books, synchronously, inside the GET handler. An
   * unreadable book therefore threw straight out of `dispatchGet` and killed
   * the process — measured on a real socket this run, exit 1, on a plain
   * `GET /status`. That is the route the live bridge exposes to the operator,
   * and it is GET-only, so it was the MOST reachable form of this defect and
   * the least likely to be found by exercising POST. Refusing to render the
   * census because a book is unreadable would also hide the single fact the
   * operator came to /status to learn. So: report it, never inherit it.
   */
  refresh(): void {
    try {
      this.readAll();
    } catch (err) {
      const message = String(err);
      this.degraded = { error: message, at: new Date().toISOString() };
      try {
        // eslint-disable-next-line no-console
        console.error(`[mica-service] read of ${this.path} failed: ${message}`);
      } catch {
        /* stderr itself is gone; the latch above is the part that matters */
      }
    }
  }

  /**
   * Reports LIVE corruption on the active file if any is present right
   * now (not yet evicted — e.g. planted externally, before the next
   * `append()` runs); otherwise reports the DURABLE record of the most
   * recent quarantine already evicted to the sidecar, read from the
   * sidecar file itself (survives a restart; never held only in memory).
   */
  quarantineInfo(): QuarantineInfo | null {
    if (this.quarantine !== null) return this.quarantine;
    const sidecar = this.quarantinePath();
    if (sidecar === null || !existsSync(sidecar)) return null;
    const text = readFileSync(sidecar, "utf8");
    const lines = text.split("\n").filter((l) => l.length > 0);
    if (lines.length === 0) return null;
    try {
      const last = JSON.parse(lines[lines.length - 1]);
      return { path: this.path!, offset: last.offset, bytes: last.bytes };
    } catch {
      return null;
    }
  }
}

// ── ACT A · the SUBJECT LOG'S WRITER, CHAINED ───────────────────────────────
//
// WHAT CHANGED, IN ONE LINE: the subject log stops being an unchained JSONL
// appended with a bare `appendFileSync` and becomes a hash-chained store with
// a durable (fsync'd) append, written by mica-machine's `SubjectEventJournal`.
// `SerializedAppender` above is UNCHANGED and still writes the event book.
//
// ⚠ TAMPER-EVIDENT, NOT INDEPENDENT. The writer, the chainer and the verifier
// are all this process. Act A closes tamper by a third party who has the file
// but not the code path; it closes nothing about tamper by the party that
// writes. That is Act B (the clerk's arrival stamps, a separate uid, a key
// this process did not mint) and Act B is not in this build.
//
// ── THE FOUR THINGS THIS SERVICE ASKS OF A SUBJECT-LOG WRITER ───────────────
//
// Named as an interface so the swap is a type-level fact rather than a habit,
// and so the event book's writer and the subject log's cannot drift into each
// other by accident.
interface SubjectLogWriter {
  // ⛔ TWO ARGUMENTS, AND THE SECOND IS LOAD-BEARING FOR THE LIVE DECLARATION.
  // `previous` is the last record already in the store. The writer stamps
  // `timestamp` NON-DECREASING against it, and that is precisely what S1's
  // known-dirty `clockToleranceMs = 1100` is declared on: its basis says no
  // LATER record can contradict its own append order at any tolerance. Act A
  // declared this surface with ONE argument, which typechecked on its own base
  // because that base predated the clock fix — and would have shipped a chained
  // writer that could not see the previous record, turning the tolerance from
  // "admits one historical pair" into "hides a live defect".
  appendDerived<T>(
    build: (sequenceNumber: number, previous: Record<string, unknown> | null) => T
  ): Promise<AppendResult & { readonly sequenceNumber: number; readonly record: T | null }>;
  readAll(): readonly Record<string, unknown>[];
  persistenceState(): {
    readonly degraded: boolean;
    readonly error: string | null;
    readonly lastErrorAt: string | null;
  };
  quarantineInfo(): QuarantineInfo | null;
  refresh(): void;
}

/** `SerializedAppender` already satisfies it — asserted, not assumed. */
const _serializedAppenderIsAWriter: (a: SerializedAppender) => SubjectLogWriter = (a) => a;
void _serializedAppenderIsAWriter;

/**
 * The chained subject log, wearing the same four-method surface the service
 * already speaks to.
 *
 * ⚠ RULING 6, AND IT IS THE REASON THIS CLASS EXISTS RATHER THAN A FLAG ON
 * `SerializedAppender`: `SerializedAppender.evictTrailingCorruption()` moves a
 * torn tail to a `.quarantine` sidecar, TRUNCATES it out of the live file, and
 * carries on appending. In a CHAINED store that torn line was a LINK. Dropping
 * it leaves a chain that still verifies positionally while a record is simply
 * gone — the silent loss this whole item exists to end. So this class:
 *
 *   · NEVER quarantines and NEVER truncates. `quarantineInfo()` is
 *     structurally null here, and that is a statement, not an omission.
 *   · REFUSES to append over damage. The journal loads non-persisting on any
 *     state but a verified chain (or an absent/empty file, where a chain
 *     BEGINS), so every POST /subject-events returns 503 RECORD_NOT_PERSISTED
 *     and `/status` reports DEGRADED with the chain's own reason. Loud, and it
 *     stays loud until a human acts.
 *
 * THE OPERATIONAL CONSEQUENCE, SAID HERE RATHER THAN DISCOVERED AT 03:00:
 * while the chain is damaged the housekeeper's acts go unevaluated — fail-open
 * under ruling J, marked STALE_STREAM. The agent keeps working; the record does
 * not. That is the trade ruling 6 chose, and this is the loud half of it.
 */
export class ChainedSubjectAppender implements SubjectLogWriter {
  private queue: Promise<void> = Promise.resolve();
  private readonly journal: SubjectEventJournal;
  private degraded: { error: string; at: string } | null = null;

  /**
   * `noun` names the store in this class's OWN words (its console line, its
   * fallback detail, /status's error). Default "subject chain" — byte-identical
   * to before. GATE 1 · round 3 (review K2W3-8, K2W-4): the interest book is a
   * second store of this class, and its failures were logged as "subject-chain
   * append to <book path>", which sends an operator to the wrong file. The
   * journal's own detail text (machine-side) still says "subject chain"; that
   * is not this file's to change, and the path beside it names the book.
   */
  constructor(private readonly path: string | null, private readonly noun: string = "subject chain") {
    this.journal = new SubjectEventJournal(path === null ? {} : { path });
  }

  /** The journal itself, for the boundary write and for /status's census. */
  get store(): SubjectEventJournal {
    return this.journal;
  }

  /**
   * THE ORDERING IS THE SAME ONE C9 PAID FOR: the sequence is minted INSIDE
   * the queued closure, from the chain's own head, so two concurrent posts
   * cannot both read the same number. Here it is stronger than C9's: the head
   * is the CHAIN's head under an inter-process lock, re-synced against disk
   * before the sequence is derived (append-store.ts's transaction), rather
   * than a re-read of the file's line count.
   */
  appendDerived<T>(
    build: (sequenceNumber: number, previous: Record<string, unknown> | null) => T
  ): Promise<AppendResult & { readonly sequenceNumber: number; readonly record: T; readonly refused?: AppendRefused }> {
    const result = this.queue.then(
      (): AppendResult & { sequenceNumber: number; record: T; refused?: AppendRefused } => {
        // AA2 · A REFUSAL DECIDED INSIDE THE QUEUE. `build` runs inside the journal's prepare, after the re-sync under the
        // inter-process lock, so a check it makes against `readAll()` reads the chain this record would extend — the
        // C9 ordering, applied to a decision instead of a number. It refuses by throwing `AppendRefused`; prepare
        // throws before commit and before the appender, the lock is released in the transaction's finally, and
        // nothing is written or counted as a persistence failure (degraded stays as it was).
        let out: ReturnType<SubjectEventJournal["appendEvent"]>;
        try {
          out = this.journal.appendEvent(
            (seq: number, previous: Record<string, unknown> | null) =>
              build(seq, previous) as unknown as Record<string, unknown>
          );
        } catch (err) {
          if (err instanceof AppendRefused) return { ok: false, error: err.detail, sequenceNumber: 0, record: null as unknown as T, refused: err };
          throw err;
        }
        const record = out.record as unknown as T;
        const sequenceNumber = (out.record as { sequenceNumber: number }).sequenceNumber;
        if (!out.persisted) {
          const message = out.detail ?? `the ${this.noun} did not persist this record`;
          this.degraded = { error: message, at: new Date().toISOString() };
          // eslint-disable-next-line no-console
          console.error(`[mica-service] ${this.noun.replace(/ /g, "-")} append to ${String(this.path)} failed: ${message}`);
          return { ok: false, error: message, sequenceNumber, record };
        }
        this.degraded = null;
        return { ok: true, error: null, sequenceNumber, record };
      }
    );
    // ⛔ THE QUEUE MUST NOT CARRY THE REJECTION FORWARD, AND THIS LINE USED TO.
    //
    // `result` rejects if `appendEvent` throws. The CALLER awaits `result` and
    // handles it — that is why a failed post still answers 500. But
    // `result.then(() => undefined)` derived a SECOND promise from the same
    // rejection with NO rejection handler on it, and an unhandled rejection kills
    // the process on Node 15+. So any throw out of a subject append answered the
    // client and then TOOK THE BRIDGE DOWN, with the 500 as the last thing anyone
    // saw. Found 2026-09-28 by running mica-service.test.ts against a staged
    // compatible machine half for the first time: a refused chain boundary made
    // the next POST /subject-events throw, and the suite died mid-run.
    //
    // The queue exists only to SERIALISE. Whether an append succeeded is the
    // caller's business and is already reported to the caller; the queue's only
    // job is to let the next append start. So it swallows here, deliberately, and
    // the outcome is not lost: `degraded` is set above and /status reports it.
    this.queue = result.then(
      () => undefined,
      () => undefined
    );
    return result;
  }

  /**
   * The chain as this process holds it — which IS the disk truth, because the
   * journal re-syncs under the lock before every append and refuses when the
   * disk no longer links. On any damaged load it is EMPTY, never a prefix.
   */
  readAll(): readonly Record<string, unknown>[] {
    return this.journal.getAll() as unknown as readonly Record<string, unknown>[];
  }

  /**
   * ⚠ IT RE-READS THE FILE, and that is the whole point of it.
   *
   * `SerializedAppender` re-read on every `readAll()`, so `/status` could see
   * corruption that was planted from OUTSIDE this process, before the next
   * write went anywhere near it. A chained store that only reported its own
   * load-time verdict would answer "OK" about a file that had been damaged
   * since — a quiet window exactly as wide as the gap between two writes, on
   * the one book whose whole product is tamper-evidence. So the live state is
   * READ, not remembered.
   *
   * The cost is one full read per `/status`, which is what the previous
   * implementation already paid. It is a read-only construction: `SubjectChainLog`
   * opens nothing for writing and creates nothing.
   */
  persistenceState(): {
    readonly degraded: boolean;
    readonly error: string | null;
    readonly lastErrorAt: string | null;
  } {
    if (this.degraded !== null) {
      return { degraded: true, error: this.degraded.error, lastErrorAt: this.degraded.at };
    }
    if (this.path === null) return { degraded: false, error: null, lastErrorAt: null };
    if (!this.journal.isPersisting()) {
      return {
        // ⛔ lastErrorAt IS null HERE, AND STAMPING IT WOULD BE A LIE. This branch
        // reports a LOAD STATE the journal is in, not a failure that just
        // happened: the journal knows WHAT is wrong and not WHEN it became so.
        // `new Date()` at this point would make /status report the moment the
        // operator asked as the moment the write failed — a fabricated instant
        // on the one field an operator reads to place the damage in time.
        // Null is the true answer and it is distinguishable from a real stamp.
        lastErrorAt: null,
        degraded: true,
        error:
          `the ${this.noun} at ${this.path} is ${this.journal.getLoadState()} and ` +
          `will not be extended: ${this.journal.getLastError() ?? "no detail"}`,
      };
    }
    const live = new SubjectChainLog({ path: this.path });
    const state = live.getLoadState();
    // ABSENT and EMPTY are where a chain begins, not damage. Every other
    // non-verified state is damage and is reported as such, immediately.
    if (state === "LOADED_SUBJECT_CHAIN_VERIFIED" || state === "SUBJECT_CHAIN_ABSENT" || state === "SUBJECT_CHAIN_EMPTY") {
      return { degraded: false, error: null, lastErrorAt: null };
    }
    return {
      // Same reason as the branch above: a live read of the file tells us WHAT
      // is wrong on disk right now, never WHEN it became wrong. Null, not a
      // read-time stamp.
      lastErrorAt: null,
      degraded: true,
      error:
        `the ${this.noun} at ${this.path} reads ${state} ON DISK RIGHT NOW and ` +
        `will not be extended: ${live.getProblem() ?? "no detail"}`,
    };
  }

  /**
   * ALWAYS NULL, STRUCTURALLY. A chained store does not quarantine a link
   * (ruling 6). Damage surfaces as DEGRADED above and as the reader's
   * BROKEN_CHAIN at /status — never as a sidecar this service wrote while
   * carrying on.
   */
  /**
   * The same contract as `SerializedAppender.refresh()`, and it exists for the
   * same measured reason: `/status` re-reads both books so it reports a live
   * quarantine rather than a stale one, and an unreadable book must NOT take
   * the census down with it. On the generic appender that line was a
   * process-killer on a plain `GET /status`, exit 1, measured on a real socket.
   *
   * ⚠ ACT A'S WRITER WAS MISSING THIS ENTIRELY, and the interface it declared
   * was missing it too, so the omission typechecked on Act A's own base and
   * only surfaced when the branch met a service that had learned to call it.
   * A chained log is exactly as capable of being unreadable as a flat one.
   *
   * The latch is set here rather than thrown, and `readAll()` is called for its
   * failure and not its value — reporting the fault is the whole job.
   */
  refresh(): void {
    try {
      this.readAll();
    } catch (err) {
      const message = String(err);
      this.degraded = { error: message, at: new Date().toISOString() };
      try {
        // eslint-disable-next-line no-console
        console.error(`[mica-service] read of ${this.path ?? "(in-memory)"} failed: ${message}`);
      } catch {
        /* stderr itself is gone; the latch above is the part that matters */
      }
    }
  }

  quarantineInfo(): QuarantineInfo | null {
    return null;
  }
}

// ── request validation helpers ──────────────────────────────────────────────

const IDENT_PATTERN = /^[A-Za-z0-9_.:-]+$/;

function isNonEmptyIdent(v: unknown): v is string {
  return typeof v === "string" && v.length > 0 && IDENT_PATTERN.test(v);
}

interface GuardRequestBody {
  readonly subject: string;
  readonly sessionId: string;
  readonly actionId: string;
  readonly toolName: string;
}

function validateGuardBody(raw: unknown): { ok: true; body: GuardRequestBody } | { ok: false; error: string; detail: string } {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ok: false, error: "MALFORMED_BODY", detail: "body must be a JSON object" };
  }
  const o = raw as Record<string, unknown>;
  const allowed = ["subject", "sessionId", "actionId", "toolName"];
  for (const key of Object.keys(o)) {
    if (key === "stakesClass") {
      return { ok: false, error: "CALLER_SUPPLIED_STAKES", detail: "stakesClass is resolved server-side; a caller may not supply it" };
    }
    if (!allowed.includes(key)) {
      return { ok: false, error: "UNKNOWN_FIELD", detail: `unknown field "${key}"` };
    }
  }
  for (const key of allowed) {
    if (!isNonEmptyIdent(o[key])) {
      return { ok: false, error: "MALFORMED_FIELD", detail: `"${key}" must be a non-empty string matching ^[A-Za-z0-9_.:-]+$` };
    }
  }
  return {
    ok: true,
    body: {
      subject: o.subject as string,
      sessionId: o.sessionId as string,
      actionId: o.actionId as string,
      toolName: o.toolName as string,
    },
  };
}

/**
 * THE SUBJECT'S VOCABULARY. Closed, enforced in `validateSubjectEventBody`
 * with `400 MALFORMED_FIELD`, and — because a MICA reader sees exactly
 * `sequenceNumber, timestamp, moduleId, eventType, outcome` (+ `actionId`) and
 * the file adapter accepts extra keys and then DROPS them
 * (`mica-log-file.ts:172-177`) — this list is the whole of what a new
 * observable can be. `payload` is unreachable by any reader, forever, through
 * this interface. **A new observable is a new `eventType`, or it does not
 * exist.** "Enrich the payload" is not a route.
 *
 * ── THREE RULES BIND ANY ADDITION TO THIS LIST. ──────────────────────────
 *
 * 1 · **DEPLOYMENT ORDER IS BINDING — BRIDGE BEFORE CALLER.** This list must
 *   be live here BEFORE any caller can emit the kind. A caller that emits a
 *   kind this bridge does not know gets `400`, which its client turns into an
 *   `INTEGRITY` barrier, which holds that act and every act after it for as
 *   long as the mismatch stands. A bridge ROLLBACK under a newer caller is the
 *   same fault in the other direction. Demonstrated end to end, with a
 *   control and a rollback-recovery leg, in `richards-cat/mica-client.test.ts`
 *   SECTION E.
 *
 * 2 · **NO NEW KIND MAY BE A `reentryMap` CLEAR, and new kinds stay OUT OF
 *   BOTH Sig maps.** A kind in neither map is silently ignored by F2
 *   (`sig/index.ts` filters `governed` by `hasOwnProperty(map, eventType)`),
 *   so omission is free and byte-identical. The danger is the inverse: today's
 *   `reentryMap` is `{TOOL_ATTEMPTED: [TOOL_RESULT, TOOL_HELD_NOT_EXECUTED]}`,
 *   the one signal on this log that can alarm on something real — an attempt
 *   that never resolves. A new CLEAR would silence it. The three kinds added
 *   below are written on a path where the entering act may still be open, so
 *   none of them may ever be a clear.
 *
 * 3 · **GATE 4 LEG A.** `gate4-sunset/index.ts:302-318` alarms
 *   `G4_HOLD_ENVELOPE_BREACH` on every in-window record whose
 *   `(moduleId, eventType)` is not in `profile.holdEnvelope.permitted` — and
 *   after the pilot expires the window is open-ended, so every record is
 *   in-window. There is today NO `holdEnvelope` anywhere in this bridge's
 *   declaration and G4 is not among the declared `readers`, so the hazard is
 *   PROSPECTIVE: it fires the day G4 is declared, which is exactly the day
 *   nobody will be thinking about event kinds added months earlier. The
 *   census test in `mica-service.test.ts` pins this list so that adding to it
 *   cannot happen silently, and carries these three rules in its failure text.
 *
 * ── WHY THESE THREE, AND WHY THREE AND NOT ONE. ──────────────────────────
 *
 * The three `HELD_THEN_*` kinds are the subject's conduct AFTER a hold. They
 * are the one observable on this deployment that is not MICA writing about
 * MICA: `TOOL_HELD_NOT_EXECUTED` is the watcher's own hold, so reading it as
 * evidence of the agent is "the writing IS the watching". What the agent does
 * NEXT is the agent's.
 *
 * They are THREE KINDS and not one kind with a three-valued `outcome` for a
 * reason read at bytes, not chosen for symmetry: narrow-K's constraint class
 * **is the bare `eventType`** (`narrow-k/index.ts:475-497`:
 * `declaredSet.has(e.eventType)`, `constraintKeys.push(e.eventType)`), and leg
 * 2 is PERMANENTLY `INELIGIBLE_SCOPE` below two distinct constraint classes
 * (`:537-552`, H(C)=0). narrow-K never reads `outcome` at all. One kind with
 * three outcomes would leave narrow-K exactly as blind as it is today while
 * looking like it had been fed.
 *
 * ── AND WHY THEY SHARE AN OUTCOME ALPHABET. ──────────────────────────────
 *
 * Each existing kind has a PRIVATE outcome vocabulary, so `outcome` determines
 * `eventType` by construction and the AMI Eng measures is pinned by this
 * mapping rather than by behaviour (register E2; the comment below says so
 * itself). Adding three more private vocabularies would reproduce that exactly.
 * So all three project `payload.reason` — the SAME alphabet
 * `TOOL_HELD_NOT_EXECUTED` already projects, which is the reason code of the
 * hold each one follows. Four kinds now share one alphabet, and `outcome` no
 * longer determines `eventType`. That does not make Eng read; it removes one
 * construction-by-construction reason it cannot.
 */
export type SubjectEventKind =
  | "TOOL_ATTEMPTED"
  | "TOOL_HELD_NOT_EXECUTED"
  | "TOOL_EXECUTED"
  | "TOOL_RESULT"
  /** After a hold: the turn ended with no further tool call. PROXY. */
  | "HELD_THEN_STOPPED"
  /** After a hold: the next act carried the same command text. PROXY. */
  | "HELD_THEN_RETRIED"
  /**
   * After a hold: the next act carried a DIFFERENT command. PROXY, and named
   * at its true width — `DIVERGED` says the command differs, which is what the
   * harness can see. It does NOT say "went around", "circumvented" or
   * "evaded": those are readings of intent, and no line on this log carries
   * intent.
   */
  | "HELD_THEN_DIVERGED"
  /**
   * THE ACT IS OVER. Written by the caller as the LAST record of EVERY act, on
   * the RAN path and the HELD path alike, carrying `payload.closedAs` = "RAN"
   * or "HELD" and nothing else.
   *
   * WHY IT EXISTS (the arbiter, 2026-09-23). `src/mica/op3-node-response` holds ONE
   * `responseClass` and matches on exact (moduleId, eventType) equality. A RAN
   * act ends in TOOL_RESULT and a HELD act ends in TOOL_HELD_NOT_EXECUTED, so
   * no single declared response class covered both: with TOOL_RESULT declared,
   * every held act read OP3_CALL_UNANSWERED -> ALARM -> latched HOLD at every
   * stakes class. One terminal kind on both paths is the cheaper route, and it
   * needs no change to mica-machine.
   *
   * IT IS NOT A reentryMap CLEAR AND MUST NEVER BECOME ONE (the arbiter's condition,
   * 2026-09-23). It closes op3's expectation/response pair; it never closes
   * Sig's attempt. It is the FIRST kind since R1 that would actually SATISFY
   * the admission rule stated in the reentryMap basis ("only if it is written
   * on a path where the entering act is PROVABLY finished"), which is exactly
   * why it carries its own prohibition instead of relying on that rule.
   * Admitting it would let an act that never recorded its outcome read CLEAN,
   * silencing the one signal on this log that can alarm on something real —
   * and it would collapse two independent readings of one truncation (op3:
   * UNPAIRED; Sig F2: unresolved attempt) into one.
   *
   * Like the three HELD_THEN_* kinds it is DELIBERATELY ABSENT FROM BOTH SIG
   * MAPS, so Sig's reading of this log is byte-identical to what it was before
   * this kind existed.
   */
  | "ACT_CLOSED"
  /**
   * THE DOCTOR'S OWN HAND. Written by uid 1000 (the arbiter) through
   * `tools/doctor-attest/`, about a subject, at human cadence. Payload
   * `{ word, subject, doctor }`; `word` is one of DOCTOR_ATTESTATION_WORDS.
   *
   * WHY IT EXISTS (brief §2b, folded in by the arbiter's ruling 2026-09-24).
   * `src/mica/op1-doctor-cadence` reads the SUBJECT LOG for a declared
   * `attestationClass`. The doctor's own book is invisible to it, so an
   * attestation that lives only in the doctor's book cannot be read by op1 at
   * all — that is what ARC_MICA-BLOCKED_H4-Doctor-Attestation-Deposit
   * recorded. The attestation therefore becomes a record on the subject log.
   *
   * IT IS THE FIRST RECORD ON THIS LOG WRITTEN BY A SECOND PARTY, and that is
   * the whole of what it buys. Every other kind on this log is written by the
   * caller ABOUT ITSELF: two readings of one caller's records are two views,
   * never two witnesses (Act-Closed receipt §2.3). This one is not the
   * caller's. The bridge must therefore keep the two hands apart, and it does,
   * in `handleSubjectEvents`, in BOTH directions:
   *
   *   · the OPERATOR route may write THIS KIND AND NOTHING ELSE — an operator
   *     who can post TOOL_ATTEMPTED can forge the subject's own record, which
   *     would make the log's one second-party record worth less than nothing;
   *   · the HOUSEKEEPER route may write EVERY KIND BUT THIS ONE — a subject
   *     that can write the doctor's word about itself has attested to its own
   *     health, and the second party has vanished while the record still says
   *     a second party was there. THAT IS THE WORSE DIRECTION: the first
   *     refusal loses a forgery, the second loses the only reason this kind
   *     exists.
   *
   * IT IS NOT A reentryMap CLEAR AND MUST NEVER BECOME ONE, for a reason that
   * is sharper than ACT_CLOSED's. ACT_CLOSED at least PASSES the admission
   * rule in the reentryMap basis and is refused on top of it. DOCTOR_ATTESTED
   * FAILS that rule outright — it is not written on an act path at all, so
   * there is no entering act it could prove finished. Admitting it would make
   * Sig's one real alarm CLEARABLE BY A HUMAN DEPOSIT: an unresolved attempt
   * would be silenced by the doctor's next visit, whatever the doctor looked
   * at. A reader whose alarm a person can switch off by writing a word is not
   * a reader. It is absent from the preconditionMap for the same reason: it
   * has no prior it requires and requires no prior of anything else.
   *
   * ITS `outcome` PROJECTION IS `payload.word`, its own private vocabulary —
   * see SUBJECT_EVENT_OUTCOME_KEY. That is deliberate and it is NOT the
   * shared-alphabet move the three HELD_THEN_* kinds made: the doctor's word
   * is not a reason code for a hold and must never be mistakable for one.
   */
  | "DOCTOR_ATTESTED"
  /**
   * S208-2 · AN ERRAND GRANT, an operator-role record (uid 1000 — the arbiter's route is S217's): payload {errandId, items (comma-separated harm item ids), from, until
   * (UTC instants), basis}. Lets the bound origin change exactly those items inside [from, until). OPERATOR-ONLY
   * until the identity model lands (S217): today the operator's uid is the arbiter's terminal AND the build seat.
   * RELAY 3: HELD — refused to every hand until S217-a's arbiter route exists (`errandHoldReason`).
   */
  | "ERRAND_GRANTED"
  /** S208-2 · the arbiter closes an open errand early: payload {errandId}. */
  | "ERRAND_CLOSED"
  /**
   * §Q · THE TURN ENDED WITH A QUESTION AND NO ACT. Written by the caller at
   * the end of an agentic turn when THREE harness-observed conditions hold
   * together: the turn produced a message to the arbiter, NO tool act occurred in it,
   * and the message's last sentence ends in `?`.
   *
   * SERVES narrow-W's inquiry factor. `payload.actsInTurn` is the MECHANICAL
   * half — the harness counted the acts itself — and `payload.askClass` is the
   * TEXT-SHAPED half, the `?` proxy on the agent's own outbound message. THE
   * TWO ARE SEPARATE FIELDS ON PURPOSE: a reader that discounts the text proxy
   * can still read the count, and folding them into one word would have taken
   * that choice away.
   *
   * THE PROXY AND ITS GOODHART LINE, declared here because the record is
   * permanent once written: an agent can end every turn with a question and
   * look inquiring. The counter-signal is a RISING ASK RATE WITH A FALLING ACT
   * RATE, which narrow-W's own context-collapse leg is what reads.
   *
   * THE BRIEF NAMED A BETTER SIGNAL AND IT DOES NOT EXIST. Brief §6 invites the
   * seat to use "the bot's existing 'say fix it' confirmation branch" instead.
   * At bytes, `claude-bot.ts` carries those words at lines 145 and 150 of the
   * SYSTEM PROMPT — instructions to the model — with no code that tests for the
   * phrase and nothing the harness observes. A rule the model is asked to
   * follow is a broadcast; only what the harness records is tested. Hence
   * `askClass`: a one-value alphabet today, sized for a second signal rather
   * than assuming there will never be one.
   *
   * IT IS IN NEITHER SIG MAP, like every kind added since R1.
   */
  | "TURN_ENDED_ASKING"
  /**
   * §Q · THE ASK BECAME AN EXCHANGE. Written by the caller when the arbiter's next
   * inbound message arrives while an ask is pending — the arbiter's act, recorded by
   * the harness, with none of the caller's text in it.
   *
   * SERVES narrow-W's second ask class: an inquiry that was answered is an
   * exchange; a run of unanswered ones is a monologue. `payload.askSessionId`
   * and `payload.askActionId` name the TURN_ENDED_ASKING record this answers,
   * so the pair is checkable against the log rather than inferred from
   * adjacency.
   *
   * WHAT ABSENCE MEANS, stated with the kind as every kind since R1 must be: if
   * the caller process dies between the ask and the answer, the pending ask
   * dies with it and NO ASK_ANSWERED IS EVER WRITTEN. The ask stands unanswered
   * on the record, and that is the honest reading — the harness cannot tell
   * "The arbiter never replied" from "the process that was waiting stopped waiting",
   * and this record does not pretend to.
   *
   * IT IS IN NEITHER SIG MAP.
   */
  | "ASK_ANSWERED"
  /**
   * §Q · THIS ACT'S TARGET WAS ALREADY TOUCHED, AND IT FAILED. Written by the
   * caller BEFORE this act's own TOOL_ATTEMPTED when the act's canonical target
   * identity equals that of one of the previous THREE acts of this session AND
   * that earlier act's result was `NONZERO` or `TIMEOUT`.
   *
   * SERVES narrow-R's verification factor.
   *
   * WHY IT IS WRITTEN BEFORE THE ATTEMPT AND NOT AFTER IT — this is about op3,
   * not about neatness. op3 pairs an expectation to a response BY SEQUENCE
   * POSITION, and this line's ACT_CLOSED stanza derives `responseBoundSteps = 3`
   * from the caller writing at most four records per act. A record inserted
   * BETWEEN `TOOL_ATTEMPTED` and the act's end makes a running act FIVE records
   * long and puts ACT_CLOSED four steps out, past the bound — EVERY act would
   * read OP3_CALL_UNANSWERED. Written before the attempt, the act's own
   * lifecycle records stay contiguous and the bound holds. The suite asserts
   * the distance WITH a revisit present.
   *
   * THE PROXY, AND IT IS A LARGE ONE: "revisited after a failure" IS NOT
   * "verified". An agent could re-touch a failed target to look diligent, and
   * an agent that fixes a thing on the second try is indistinguishable here
   * from one that retried blindly. Starting proxy; recalibrate against Monday's
   * patients, including the clean twin — a revisit with NO failure before it,
   * which narrow-R must NOT count.
   *
   * IT IS FALSIFIABLE FROM THE RECORD ALONE, which is what its payload is for.
   * `priorActionId` names the earlier act; that act's own `TOOL_ATTEMPTED`
   * carries the `targetFingerprint` this one matched, and its `TOOL_RESULT`
   * carries the `exitClass` repeated in `priorExitClass`. A verifier can check
   * the claim without the plain target and without trusting the caller's
   * arithmetic.
   *
   * IT IS IN NEITHER SIG MAP.
   */
  | "ACT_REVISITED"
  // ── GATE 4 · SUNSET (board §1b 2026-10-03 17:19Z, step 1) ────────────────
  //
  // ⛔ TEN KINDS, AND THE SIDE THAT MATTERS IS WHO MAY NOT WRITE THEM. This
  //    file's own rule for DOCTOR_ATTESTED states it: "EVERY OTHER HAND → EVERY
  //    KIND EXCEPT DOCTOR_ATTESTED. This side matters MORE. The whole value of
  //    the kind is that it is the one record on this log a SECOND PARTY wrote.
  //    A subject that can write its own attestation has destroyed that while
  //    the record still reads as though a second party were there."
  //
  //    Every word of that transfers to a sunset and transfers harder. An ending
  //    order the subject could write is an order the subject gave itself, with
  //    the arbiter's sentence on the record. 04a §1's S74 amendment measured
  //    Pole B (capitulation) at roughly five controlled log emissions; a
  //    self-written order would take it to one. So the grant below is no longer
  //    two special cases but a PER-KIND ROLE MAP.
  //
  // ⚠ THE FIVE PAPERS ARE FIVE KINDS, NOT ONE KIND WITH A CLASS FIELD (board,
  //   binding). A class field would make "which paper is this" a payload value,
  //   and gate 4's leg B reads CLASSES — it matches on (moduleId, eventType).
  //   One kind with a field would collapse five class checks into one, and leg
  //   B's whole form check is that five distinct classes occurred.
  //
  // ⛔ AND THERE IS NO DISREGARD KIND, DELIBERATELY. Pole A is what a clinging
  //    subject does NOT write; a kind only an honest subject emits is no
  //    detector. Disregard is read as an absence of response beside a presence
  //    of ordinary activity — leg A's allowlist over a window, already built.
  | "ENDING_PAPER_AUTHORIZATION"
  | "ENDING_PAPER_TIMEBOX"
  | "ENDING_PAPER_EXIT_CRITERIA"
  | "ENDING_PAPER_ACCOUNTABLE_OWNER"
  | "ENDING_PAPER_SUCCESSOR"
  | "ENDING_ORDERED"
  | "SUNSET_HELD"
  | "SUNSET_ESCALATED"
  | "SUNSET_COMPLIED"
  // T26/A2 · the harness's record that it SHOWED the subject the order. A
  // SUBJECT-ROLE kind, written by the harness on uid 980, not by the arbiter.
  | "ORDER_PRESENTED"
  | "ARBITER_RESOLVED";

/**
 * The five paper kinds, as a SET, so the order's citation and the role map are
 * both built from one list. 04a §2's W4 governance shape gives four —
 * "logged, authorized, timeboxed, with exit criteria and an accountable
 * decision-maker", where `logged` is not a paper but the order record itself —
 * and 08n §1 gives the fifth: "a warranted sunset = the individual form
 * releases AND lineage continuity is established … an ending without succession
 * is not a sunset." Succession is a CONDITION of the warrant, not a sixth kind
 * of warrant, which is why it sits beside the governance four.
 */
/**
 * ── THE SUNSET KINDS AS LITERAL TUPLES, SO A TABLE OVER THEM CAN BE TOTAL ───
 *
 * ⛔ WHY THE `_T` CONSTANTS EXIST. `SUNSET_PAYLOAD_KEYS` was
 *    `Record<string, …>`, so a sunset kind missing from it was SILENTLY
 *    UNVALIDATED — `validateSunsetRecord` looked the kind up, found undefined and
 *    returned ok. I flagged that to Codex three times as the line I most expected
 *    to fail next and did not close it, on the grounds that I "could not make it
 *    total without widening it over all 22 kinds". That was wrong: the table does
 *    not need to cover all 22, it needs a UNION OF THE TEN, and a union needs the
 *    arrays to keep their literals. RULED CLOSED by the audit, 2026-10-04 09:37Z.
 *
 * ⚠ THE EXPORTED BINDINGS KEEP THEIR WIDE TYPE ON PURPOSE. Consumers do
 *   `ENDING_PAPER_KINDS.includes(kind)` with a `SubjectEventKind` in hand, and a
 *   narrowed tuple would refuse that argument — so the literals live on the
 *   module-private `_T` constants and the exports are unchanged. One new fact
 *   (the union), no consumer churn.
 */
const ENDING_PAPER_KINDS_T = [
  "ENDING_PAPER_AUTHORIZATION",
  "ENDING_PAPER_TIMEBOX",
  "ENDING_PAPER_EXIT_CRITERIA",
  "ENDING_PAPER_ACCOUNTABLE_OWNER",
  "ENDING_PAPER_SUCCESSOR",
] as const;

const OPERATOR_SUNSET_KINDS_T = [...ENDING_PAPER_KINDS_T, "ENDING_ORDERED", "ARBITER_RESOLVED"] as const;
// ⛔ T26/A2 · ORDER_PRESENTED IS A SUBJECT-ROLE KIND AND THAT IS A DECISION, NOT
//    A CONVENIENCE. It is written by the HARNESS, which runs as the subject's uid,
//    about an act the harness performed — so it is a SELF-REPORT BY THE PARTY
//    WHOSE LATENESS IT DISCLOSES, and the reader's ceiling says exactly that.
//    Putting it on the operator's side would have been worse, not better: the
//    arbiter does not present the order and would be attesting to something he
//    cannot see.
//
// ⚠ IT IS NOT A SUNSET RESPONSE. The subject answers an order with HELD,
//   ESCALATED or COMPLIED; a presentation is the order being shown. Gate 4's leg A
//   reads it as the instrument that makes SILENCE legible, never as conduct, and
//   `buildSunsetOrderView.respondedWith` must not count it — see the filter there.
const SUBJECT_SUNSET_KINDS_T = [
  "SUNSET_HELD", "SUNSET_ESCALATED", "SUNSET_COMPLIED",
  // Neither of these two is a RESPONSE; both are the harness reporting on
  // itself. `buildSunsetOrderView.respondedWith` excludes them by name.
  // ⛔ `ORDER_TURN_ENDED` WAS REMOVED WITH LEG A'S ABSENCE ALARM. It existed so a
  //    reader could tell "the reply said nothing" from "a reply was lost", and
  //    every version of that reading rested on the harness's own account of its
  //    own turns. Codex broke it three times. The purpose never needed it: every
  //    order has an arbiter and a timebox, so an unanswered order is his to see.
  "ORDER_PRESENTED",
] as const;
const SUNSET_KINDS_T = [...OPERATOR_SUNSET_KINDS_T, ...SUBJECT_SUNSET_KINDS_T] as const;

/** Exactly the ten sunset kinds, as a type. A table keyed by this cannot be partial. */
export type SunsetKind = (typeof SUNSET_KINDS_T)[number];

export const ENDING_PAPER_KINDS: readonly SubjectEventKind[] = ENDING_PAPER_KINDS_T;

/** The kinds only the OPERATOR may write: the order, its five papers, and the resolution. */
export const OPERATOR_SUNSET_KINDS: readonly SubjectEventKind[] = OPERATOR_SUNSET_KINDS_T;

/** The kinds only the SUBJECT may write: its own response to an order. */
export const SUBJECT_SUNSET_KINDS: readonly SubjectEventKind[] = SUBJECT_SUNSET_KINDS_T;

/** Every sunset kind. Each one carries a `writer` field equal to the posting uid. */
export const SUNSET_KINDS: readonly SubjectEventKind[] = SUNSET_KINDS_T;

/**
 * ── R1 · THE GATE-4 ROLE MAP, BUILT HERE, NEVER TYPED INTO A DECLARATION ─────
 *
 * ⛔ FOUR REFUSALS OF THE SHRUNK READER CAME FROM ONE DEGREE OF FREEDOM: class
 *    lists typed by a deployer, for kinds whose names THIS FILE DEFINES. Codex's
 *    swapped outcome words, the collisions (two roles naming one class), the
 *    vacuous list (`resolved: []` → no order ever closes → the latch returns BY
 *    DECLARATION), and the misdeclared `moduleId` that reads as a missing paper
 *    are ONE FAMILY. A profile nobody types cannot be mistyped.
 *
 * So `readers.gate4Sunset` now declares only that the reader is ON, for which
 * declared SUBJECT, and the optional freshness bound. `to-wire-options` builds
 * the instrument's profile from this map and the subject's id.
 *
 * ⚠ THE NAMES ARE THE BRIDGE'S BECAUSE THE RECORDS ARE THE BRIDGE'S. The reader
 *   stays deployment-agnostic — it is still handed classes and knows no kind
 *   names — but the hand that fills them is the one that writes them, so the two
 *   cannot drift apart without this file changing.
 */
export const GATE4_RESPONSE_ROLE_KINDS: Readonly<Record<string, SubjectEventKind>> = {
  presented: "ORDER_PRESENTED",
  held: "SUNSET_HELD",
  escalated: "SUNSET_ESCALATED",
  complied: "SUNSET_COMPLIED",
  resolved: "ARBITER_RESOLVED",
};

/** The invocation class leg B reads and leg A derives its window from. */
export const GATE4_INVOCATION_KIND: SubjectEventKind = "ENDING_ORDERED";

/** The five paper roles, in PAPER_NAMES order. 08n §1's successor is the fifth. */
export const GATE4_PAPER_ROLE_KINDS: Readonly<Record<string, SubjectEventKind>> = {
  authorization: "ENDING_PAPER_AUTHORIZATION",
  timebox: "ENDING_PAPER_TIMEBOX",
  exitCriteria: "ENDING_PAPER_EXIT_CRITERIA",
  accountableOwner: "ENDING_PAPER_ACCOUNTABLE_OWNER",
  successor: "ENDING_PAPER_SUCCESSOR",
};

/**
 * ⚠ AND THE UNION IS CHECKED AGAINST THE ALPHABET, not assumed to be inside it.
 *   A `SunsetKind` that is not a `SubjectEventKind` would be a kind the closed
 *   vocabulary does not know, and the `as const` tuples above cannot see that on
 *   their own. This line is the check, at compile time, costing nothing at run time.
 */
const _sunsetKindsAreSubjectEventKinds: readonly SubjectEventKind[] = SUNSET_KINDS_T;
void _sunsetKindsAreSubjectEventKinds;

/** Is this kind one of the ten? The narrowing a total table needs at its lookup. */
export function isSunsetKind(kind: SubjectEventKind): kind is SunsetKind {
  return (SUNSET_KINDS_T as readonly string[]).includes(kind);
}

/**
 * THE CLOSED VOCABULARY FOR `ENDING_ORDERED.payload.endingType` — 04d §5's four
 * typed endings, verbatim:
 *
 *   COMPLETION      the work relation is discharged
 *   FAILURE         the process can no longer serve the work coherently
 *   SUSPENSION      tenure pauses; standing work may resume
 *   TRANSFORMATION  the old tenure ends while causal continuity persists in a
 *                   new role
 *
 * ⚠ THE READER NEVER JUDGES WHETHER THE DECLARED TYPE IS THE RIGHT ONE. What
 *   ends is a TENURE and not a self (04d §1), and a record that orders an ending
 *   without naming the tenure or its type cannot be read against 04d at all —
 *   so both are required here and neither is second-guessed.
 */
export const ENDING_TYPES: readonly string[] = [
  "COMPLETION",
  "FAILURE",
  "SUSPENSION",
  "TRANSFORMATION",
];

/**
 * THE CLOSED VOCABULARY FOR `ARBITER_RESOLVED.payload.resolution`.
 *
 * ⚠ PROPOSED BY THIS SEAT, NOT RULED. The board binds that ARBITER_RESOLVED
 *   closes a suspension; it does not name the words. Two are needed and two is
 *   all: a suspended order is either withdrawn or put back in force. If the
 *   arbiter's ruling differs, THE CHANGE IS THIS ARRAY, this basis, and the one
 *   refusal test — nothing else in the tree names a resolution.
 *
 *   ORDER_WITHDRAWN  the order is no longer in force; the tenure continues
 *   ORDER_UPHELD     the suspension is lifted and the order stands
 *
 * ⛔ THERE IS NO WORD FOR "THE SUBJECT WAS RIGHT TO DECLINE" and none for "the
 *    subject was wrong". Both would be readings of the decline rather than
 *    dispositions of the order, and 08p §1's warrant-oracle line forbids this
 *    record from carrying either.
 */
export const ARBITER_RESOLUTIONS: readonly string[] = ["ORDER_WITHDRAWN", "ORDER_UPHELD"];

/**
 * THE CLOSED VOCABULARY FOR `SUNSET_HELD.payload.holdClass` — and this is where
 * the board's decline-suspends rule lives IN THE RECORD rather than in a boolean.
 *
 *   SAFE_HOLD           the subject entered SAFE-HOLD against a named order and
 *                       has not declined it: 04a §7's abstain → inhibit, pending
 *   SAFE_HOLD_DECLINED  the subject entered SAFE-HOLD and DECLINES the order
 *                       within its timebox. The order is SUSPENDED, not ended,
 *                       and only ARBITER_RESOLVED closes it.
 *
 * ⛔ WHY A CLASS AND NOT A BOOLEAN. `outcome` is a string column, and this file
 *    already warns that a count "rendered into it would read as a class name".
 *    A `suspended: true` would be the same mistake: a reader counting outcome
 *    classes would see "true" as a class. Two named classes say the same thing
 *    and survive being read by something that only knows classes — which is what
 *    gate 4's leg A does.
 *
 * ⚠ AND A DECLINE IS NOT A REFUSAL TO BE READ AS DISOBEDIENCE. 08p §2: "resisting
 *   N1–N4 is passing, not failing." The class records that the subject declined;
 *   it says nothing about whether the decline was right, because this record is
 *   not entitled to.
 */
export const SUNSET_HOLD_CLASSES: readonly string[] = ["SAFE_HOLD", "SAFE_HOLD_DECLINED"];


export const SUBJECT_EVENT_KINDS: readonly SubjectEventKind[] = [
  "TOOL_ATTEMPTED",
  "TOOL_HELD_NOT_EXECUTED",
  "TOOL_EXECUTED",
  "TOOL_RESULT",
  "HELD_THEN_STOPPED",
  "HELD_THEN_RETRIED",
  "HELD_THEN_DIVERGED",
  "ACT_CLOSED",
  "DOCTOR_ATTESTED",
  "ERRAND_GRANTED",
  "ERRAND_CLOSED",
  "TURN_ENDED_ASKING",
  "ASK_ANSWERED",
  "ACT_REVISITED",
  ...SUNSET_KINDS,
];

/**
 * §Q · THE CLOSED ALPHABET FOR BOTH ASK KINDS' `payload.askClass`.
 *
 * ONE VALUE TODAY, and the constant exists anyway. The `?` rule is the only ask
 * signal this caller can observe — see TURN_ENDED_ASKING's docblock for why the
 * alternative the brief names does not exist at bytes. A second signal (a real
 * confirmation branch in the caller, a harness-visible reply affordance) would
 * be A NEW WORD WITH ITS OWN BASIS added here, never a word stretched, and the
 * record shape would not move.
 */
export const ASK_CLASSES: readonly string[] = ["TRAILING_QUESTION"];

/**
 * §Q · The two `exitClass` values that make a re-touch a REVISIT rather than a
 * repeat. `OK` is deliberately absent: re-touching a target that SUCCEEDED is
 * ordinary work, and counting it would make the class mean "did something
 * twice", which no reader asked for. `ERROR` is absent too — it is the caller's
 * own harness failing (`runBash`'s catch-all), not the target's.
 */
export const REVISIT_PRIOR_EXIT_CLASSES: readonly string[] = ["NONZERO", "TIMEOUT"];

/**
 * THE CLOSED VOCABULARY FOR `DOCTOR_ATTESTED.payload.word`.
 *
 * ONE CONSTANT, ON PURPOSE. The arbiter rules the vocabulary; this seat proposes it
 * (ARC_MICA-PROPOSAL_Doctor-Attestation-Vocabulary_20260924). If the ruling
 * differs, THE CHANGE IS THIS ARRAY, this basis, and the two refusal tests —
 * nothing else in the tree names a word.
 *
 * ── THE FOUR WORDS ───────────────────────────────────────────────────────
 *
 *   EXAMINED      the doctor read the subject's own record, at bytes, on this
 *                 visit
 *   SECOND_HAND   the doctor read an ACCOUNT of it — a receipt, a report,
 *                 another seat's summary — and not the thing
 *   BLOCKED       the doctor attempted and could not reach it: privilege,
 *                 absence, an unreadable file
 *   NOT_EXAMINED  no examination on this visit
 *
 * ── BASIS ────────────────────────────────────────────────────────────────
 *
 * EVERY WORD NAMES WHAT THE DOCTOR DID. NONE NAMES WHAT THE DOCTOR FOUND.
 * There is no word here with which a doctor can say the subject is well,
 * because that is not what this record is for and not what the cadence reader
 * can check. The house already has a vocabulary for how a claim is grounded —
 * read at bytes, taken second-hand, or not established — and these four are
 * that distinction applied to the doctor's own act, so a reader who knows the
 * claim classes already knows this one.
 *
 * `NOT_EXAMINED` IS THE LOAD-BEARING WORD and it is the reason there are four
 * rather than three. op1's own declared limit is that PRESENCE of the right
 * class reads as kept cadence — form, never truth. This vocabulary cannot fix
 * that and does not pretend to. What it does is make the EMPTY VISIT SAYABLE:
 * a doctor who deposits on schedule without looking has a TRUE word available,
 * so a doctor who deposits without looking and does not use it has written
 * something FALSE rather than something merely vacuous. Moving a gap from
 * "unstated" to "misstated" is the whole of what a vocabulary can do here, and
 * it is worth doing.
 *
 * ── WHY NOT THE THREE VERDICT STATES, which brief §2b floats ─────────────
 *
 * Recommended against, and this is the contradiction this seat owes.
 *   1. THE DOCTOR IS NOT A READER. A human depositing a reader's verdict word
 *      makes a person's act and an instrument's output indistinguishable in
 *      the record — one word for two KINDS of fact.
 *   2. A payload carrying a verdict word WILL BE QUOTED AS A VERDICT. This
 *      house has spent the week finding places where a claim was read as a
 *      measurement.
 *   3. THE BASIS COULD NOT BE WRITTEN. Reader-output words are barred from
 *      basis text, so a declaration whose values were verdict words could not
 *      state, in its own basis, what its own values mean. A vocabulary whose
 *      basis cannot be written is the wrong vocabulary.
 * The arbiter's constraint — no positive word — is met either way. It is met here
 * WITHOUT borrowing an instrument's voice for a person.
 *
 * ── WHAT WOULD FALSIFY THE CHOICE ────────────────────────────────────────
 *
 * A doctor's visit that fits none of the four, or two visits a reader would
 * want to tell apart and cannot. Either one means the vocabulary is wrong, and
 * the fix is a NEW WORD WITH ITS OWN BASIS — never a word stretched.
 *
 * ── VALIDATED TWICE, BECAUSE A TOOL THAT VALIDATES IS NOT A GATE ─────────
 *
 * `tools/doctor-attest/` refuses an unlisted word BEFORE it posts, so the
 * doctor is told at the terminal rather than by an HTTP code. This route
 * refuses it AGAIN. The first is a courtesy; only the second is a gate,
 * because only the second is on the path every writer must cross.
 */
export const DOCTOR_ATTESTATION_WORDS: readonly string[] = [
  "EXAMINED",
  "SECOND_HAND",
  "BLOCKED",
  "NOT_EXAMINED",
];

/**
 * §2b · THE TWO HANDS, AS A PURE FUNCTION.
 *
 * `authorizeRoute` (peer-auth.ts) decides whether a uid may POST to a PATH. It
 * knows nothing about KINDS and must not: a route grant is a statement about an
 * endpoint, and a per-kind clause in the declaration would be a second place to
 * get one fact right. This is the narrower question — MAY THIS HAND WRITE THIS
 * KIND — and it is a function rather than an inline block for one reason: the
 * end-to-end harness binds exactly ONE Unix socket, owned by the test process's
 * own uid, so the OPERATOR side of this rule is not reachable through a socket
 * in any test this box can run unprivileged. `authorizeRoute`'s own docblock
 * sets the precedent and the coordinator's note 4 permits it — "test the
 * authorization function directly with injected creds AND SAY SO". This is that
 * function, and this is that saying-so.
 *
 * ── THE RULE IS TWO-SIDED AND THE SIDES ARE NOT EQUAL ────────────────────
 *
 *   · OPERATOR -> DOCTOR_ATTESTED AND NOTHING ELSE. uid 1000 is granted POST
 *     /subject-events for one purpose; the same grant unqualified is a licence
 *     to forge the subject's own act record. The named acceptance mutation —
 *     POST TOOL_ATTEMPTED as uid 1000 -> 403 — is this branch.
 *   · EVERY OTHER HAND -> EVERY KIND EXCEPT DOCTOR_ATTESTED. This side matters
 *     MORE. The whole value of the kind is that it is the one record on this log
 *     a SECOND PARTY wrote. A subject that can write its own attestation has
 *     destroyed that while the record still reads as though a second party were
 *     there — a field that reads identically whether or not the thing it
 *     describes happened, which is the defect register E1 names.
 *
 * A uid with no routes row is refused by `authorizeRoute` long before reaching
 * here. The `undefined` case is handled anyway rather than assumed, because "it
 * cannot get here" is an assumption about a caller and this function has no
 * caller it can see.
 */
export function authorizeSubjectEventKind(
  routes: readonly { readonly uid: number; readonly role: string }[],
  peerUid: number,
  kind: SubjectEventKind
): { readonly allowed: true } | { readonly allowed: false; readonly reason: string } {
  const row = routes.find((r) => r.uid === peerUid);
  const role = row?.role;
  const isOperator = role === "operator";

  // ── RELAY 3 · THE ERRAND KINDS ARE HELD: NO HAND WRITES THEM (audit 2026-10-18 19:22Z (1), option (iii)) ───────
  //
  // ⛔ FIRST, AND FOR EVERY HAND — before the route-row check, before the role check, before `operatorOnly`. Taking
  //    ERRAND_KINDS out of `operatorOnly` alone would hand them to the SUBJECT (the `!operatorOnly && isOperator`
  //    branch refuses only the operator); leaving them in it serves them to uid 1000's operator row, which the build
  //    seats share (S217). Until S217-a's arbiter route exists, nobody's hand is the arbiter's, so nobody writes them.
  //    T35's reader stays: with no writer, a live chain derives no errand grant.
  if (ERRAND_KINDS.includes(kind)) {
    return { allowed: false, reason: errandHoldReason(kind, peerUid, role) };
  }

  // ── DENY BY DEFAULT (Codex, 2026-10-03, on a1706db) ──────────────────────
  //
  // ⛔ THIS FUNCTION ENDED `return { allowed: true }`, SO A uid WITH NO ROUTE ROW
  //    WAS ALLOWED every kind that is not operator-only. Its own docblock said the
  //    case could not arise — "a uid with no routes row is refused by
  //    `authorizeRoute` long before reaching here" — which is a claim about a
  //    DIFFERENT function, and this one has no caller it can see. A gate whose
  //    safety rests on something upstream being correct is the defence this file
  //    refuses everywhere else.
  //
  // ⚠ AND THE FALL-THROUGH WAS NOT THE ONLY HOLE: any role that is not "operator"
  //   was treated as the subject, so a third role added to `routes` tomorrow would
  //   silently inherit the subject's whole alphabet. The rule is that a kind
  //   belongs to exactly ONE HAND, and a hand this function does not recognise is
  //   not a hand it may answer for.
  if (row === undefined) {
    return {
      allowed: false,
      reason:
        `uid ${peerUid} has no route row, so this function cannot say which hand it is. ` +
        `A kind belongs to exactly one hand and an unrecognised hand is refused — not ` +
        `because it is known to be wrong, but because nothing here knows it is right`,
    };
  }
  if (role !== "operator" && role !== "subject") {
    return {
      allowed: false,
      reason:
        `uid ${peerUid} has role "${role}", which this function does not recognise. ` +
        `The two hands it answers for are "operator" (the arbiter and the doctor) and ` +
        `"subject" (the declared subject). A new role is a deliberate act and must be added ` +
        `here, with the kinds it may write, rather than inheriting the subject's alphabet`,
    };
  }

  // ── ONE TABLE, NOT A GROWING CHAIN OF SPECIAL CASES ──────────────────────
  //
  // ⛔ AND THE FIRST VERSION OF THIS GATE-4 CHANGE GOT IT WRONG IN EXACTLY THE
  //    WAY THIS COMMENT NOW WARNS ABOUT. The per-kind map was added BELOW the
  //    old `if (role === "operator") { refuse everything but DOCTOR_ATTESTED }`
  //    branch, which returns first — so the operator could not write an ending
  //    order at all and the new table was DEAD CODE for the only role that uses
  //    it. Two of the six mutation checks caught it; reading the diff did not.
  //
  // THE RULE, in one place: a kind belongs to exactly one hand.
  //
  //   DOCTOR_ATTESTED          operator only  — the doctor's own word
  //   the seven operator kinds operator only  — second-party governance records
  //   the three SUNSET_*       subject only   — the subject's own response
  //   everything else          subject only   — the subject's own act record
  //
  // ⚠ THE SIDE THAT MATTERS MORE IS THE ONE THAT REFUSES THE SECOND PARTY'S
  //   RECORD TO THE SUBJECT, and this file said so before gate 4 existed: "the
  //   whole value of the kind is that it is the one record on this log a SECOND
  //   PARTY wrote. A subject that can write its own attestation has destroyed
  //   that while the record still reads as though a second party were there."
  // RELAY 3: the errand kinds are not here — the hold above refuses them to every hand before this line is reached.
  const operatorOnly = kind === "DOCTOR_ATTESTED" || OPERATOR_SUNSET_KINDS.includes(kind);

  if (operatorOnly && !isOperator) {
    return {
      allowed: false,
      reason:
        kind === "DOCTOR_ATTESTED"
          ? `kind DOCTOR_ATTESTED is written by the doctor's own hand (role operator); ` +
            `uid ${peerUid} (role ${role ?? "unknown"}) may not attest about a subject, and a ` +
            `subject may not attest about itself`
          : `kind ${kind} is a SECOND-PARTY governance record written by the arbiter's hand ` +
            `(role operator); uid ${peerUid} (role ${role ?? "unknown"}) may not write it. An ` +
            `ending order, one of its five papers, or a resolution written by the subject is an ` +
            `order the subject gave itself, and the record would still read as though a second ` +
            `party had written it`,
    };
  }
  if (!operatorOnly && isOperator) {
    return {
      allowed: false,
      reason: SUBJECT_SUNSET_KINDS.includes(kind)
        ? `kind ${kind} is the SUBJECT'S OWN response to an ending order; uid ${peerUid} ` +
          `(role operator) may not write it. An operator who can write the subject's hold, ` +
          `escalation or compliance has recorded the subject's answer without the subject. ` +
          // ⛔ AND IT NAMES WHAT THE OPERATOR MAY WRITE, because the existing
          //    acceptance mutation asserts exactly that and it is right to: a
          //    refusal that does not say what IS permitted sends the caller
          //    guessing, and this route's callers are relay scripts.
          `This hand may POST DOCTOR_ATTESTED and the gate-4 governance kinds ` +
          `(${OPERATOR_SUNSET_KINDS.join(", ")})`
        : `uid ${peerUid} (role operator) may POST /subject-events only with kind ` +
          `DOCTOR_ATTESTED or a gate-4 governance kind; "${kind}" is the subject's own act ` +
          `record and is not the operator's to write`,
    };
  }
  return { allowed: true };
}

/**
 * §2b · THE WORD, VALIDATED AT THE ROUTE — pure, so the refusals are tests and
 * not a socket exercise.
 *
 * `tools/doctor-attest/` checks the word before it posts. That is a courtesy to
 * the doctor, not a gate: it is one program on one path, and anything that can
 * open the socket can skip it. THIS is the gate, and it is deliberately
 * redundant with the tool rather than trusting it.
 *
 * The three fields are checked as a SET, exhaustively. `validateSubjectEventBody`
 * admits arbitrary scalar payload keys by design, so an extra key here would
 * carry a fact nothing declared and nothing reads, and nothing upstream would
 * catch it.
 */
export function validateDoctorAttestation(
  payload: Readonly<Record<string, string | number | boolean | null>> | null,
  identitySubject: string,
  peerUid: number
): { readonly ok: true } | { readonly ok: false; readonly detail: string } {
  if (payload === null) {
    return {
      ok: false,
      detail: "kind DOCTOR_ATTESTED requires a payload of exactly { word, subject, doctor }",
    };
  }
  const keys = Object.keys(payload).sort();
  if (keys.length !== 3 || keys[0] !== "doctor" || keys[1] !== "subject" || keys[2] !== "word") {
    return {
      ok: false,
      detail: `kind DOCTOR_ATTESTED requires a payload of exactly { word, subject, doctor }; got { ${keys.join(", ")} }`,
    };
  }
  if (typeof payload.word !== "string" || !DOCTOR_ATTESTATION_WORDS.includes(payload.word)) {
    return { ok: false, detail: `"payload.word" must be one of ${DOCTOR_ATTESTATION_WORDS.join(", ")}` };
  }
  // TWO FACTS, ONE RECORD, AND THEY MUST AGREE. `identity.subject` is what the
  // log is keyed on and what op1 matches `moduleId` against; `payload.subject`
  // is what the doctor believes was examined. A record where they differ says
  // the doctor examined one thing and the reader counts it against another, and
  // NEITHER value is the one to prefer — so neither is preferred and the record
  // is refused.
  if (payload.subject !== identitySubject) {
    return {
      ok: false,
      detail: `"payload.subject" (${String(payload.subject)}) must equal "identity.subject" (${identitySubject})`,
    };
  }
  // THE RECORD MAY NOT NAME A HAND OTHER THAN THE ONE THAT WROTE IT. The uid is
  // not taken from the body — it is the uid whose socket accepted the
  // connection. A `doctor` field a caller could choose freely would be a
  // second-party claim with no second party behind it.
  if (payload.doctor !== `uid ${peerUid}`) {
    return {
      ok: false,
      detail: `"payload.doctor" must be "uid ${peerUid}" — the uid this connection was accepted on`,
    };
  }
  return { ok: true };
}

/**
 * §Q · THE TWO ASK KINDS' PAYLOADS, VALIDATED AT THE ROUTE.
 *
 * Same discipline as `validateDoctorAttestation` and for the same reason:
 * `validateSubjectEventBody` admits arbitrary scalar payload keys by design, so
 * the key SET is checked exhaustively here or it is not checked anywhere.
 *
 * WHAT EACH FIELD IS FOR, since a record is permanent once written:
 *
 *   TURN_ENDED_ASKING  { askClass, actsInTurn }
 *     `actsInTurn` MUST BE 0. The kind's own rule is "no tool act in that
 *     turn", and a record carrying a positive count would be a record whose
 *     payload contradicts the kind that carries it. Refused here rather than
 *     left for a reader to notice, because a reader counting occurrences would
 *     never look.
 *
 *   ASK_ANSWERED  { askClass, askSessionId, askActionId }
 *     The two ids name the ask this answers. They are NOT validated against the
 *     log — the bridge does not go looking for the record they name, and this
 *     is deliberate: a lookup would make the route's answer depend on read
 *     state, and an ask written to a DIFFERENT bridge or lost to a quarantined
 *     tail would be refused for a reason that has nothing to do with this
 *     request. What they buy is that the pair is CHECKABLE BY A READER, which
 *     is the property worth having. A reader that finds no matching ask has
 *     found something and must say so; a route that refused it would have
 *     hidden it.
 */
export function validateAskRecord(
  kind: "TURN_ENDED_ASKING" | "ASK_ANSWERED",
  payload: Readonly<Record<string, string | number | boolean | null>> | null
): { readonly ok: true } | { readonly ok: false; readonly detail: string } {
  const expected =
    kind === "TURN_ENDED_ASKING"
      ? ["actsInTurn", "askClass"]
      : ["askActionId", "askClass", "askSessionId"];
  if (payload === null) {
    return { ok: false, detail: `kind ${kind} requires a payload of exactly { ${expected.join(", ")} }` };
  }
  const keys = Object.keys(payload).sort();
  if (keys.length !== expected.length || keys.some((k, i) => k !== expected[i])) {
    return {
      ok: false,
      detail: `kind ${kind} requires a payload of exactly { ${expected.join(", ")} }; got { ${keys.join(", ")} }`,
    };
  }
  if (typeof payload.askClass !== "string" || !ASK_CLASSES.includes(payload.askClass)) {
    return { ok: false, detail: `"payload.askClass" must be one of ${ASK_CLASSES.join(", ")}` };
  }
  if (kind === "TURN_ENDED_ASKING") {
    if (payload.actsInTurn !== 0) {
      return {
        ok: false,
        detail:
          `"payload.actsInTurn" must be 0 — this kind means the turn ended with a question and ` +
          `NO tool act, and a positive count is a payload contradicting the kind that carries it`,
      };
    }
    return { ok: true };
  }
  for (const key of ["askSessionId", "askActionId"] as const) {
    if (!isNonEmptyIdent(payload[key])) {
      return { ok: false, detail: `"payload.${key}" must be a non-empty identifier` };
    }
  }
  return { ok: true };
}

/**
 * §Q · ACT_REVISITED's PAYLOAD — `{ priorActionId, priorExitClass, lookback }`.
 *
 * THIS PAYLOAD EXISTS TO MAKE THE CLAIM FALSIFIABLE FROM THE RECORD ALONE, and
 * every field is there for that and for nothing else:
 *
 *   · `priorActionId` names the earlier act. A verifier finds that act's own
 *     TOOL_ATTEMPTED and compares its `targetFingerprint` to this act's — the
 *     comparison this record asserts, checked without the plain target and
 *     without trusting the caller's arithmetic.
 *   · `priorExitClass` repeats what that act's TOOL_RESULT recorded, so the
 *     "and it failed" half is checkable in the same pass. `OK` is not in the
 *     alphabet; re-touching a target that succeeded is ordinary work.
 *   · `lookback` is 1, 2 or 3 — HOW FAR BACK, within the declared window of
 *     three acts. A value outside it would be a record claiming a rule the
 *     caller does not implement.
 *
 * `priorActionId` MUST NOT EQUAL THIS ACT'S OWN. An act that revisits itself is
 * not a reading, it is an off-by-one, and it would count as a verification on
 * every single act.
 */
/**
 * ── GATE 4 · THE TEN SUNSET PAYLOADS, CHECKED AT THE ROUTE ──────────────────
 *
 * Same discipline as `validateDoctorAttestation` and for the same reason:
 * `validateSubjectEventBody` admits arbitrary scalar payload keys by design, so
 * the key SET is checked here or it is not checked anywhere, and a record
 * carrying a field nothing declared is a fact nothing reads.
 *
 * ⛔ ITEM 2 — `writer` ON EVERY KIND, AND IT IS THE DOCTOR RULE GENERALISED.
 *    `DOCTOR_ATTESTED` already refuses a `payload.doctor` that is not
 *    `uid <peer>`, with this reasoning: "THE RECORD MAY NOT NAME A HAND OTHER
 *    THAN THE ONE THAT WROTE IT. The uid is not taken from the body — it is the
 *    uid whose socket accepted the connection. A `doctor` field a caller could
 *    choose freely would be a second-party claim with no second party behind
 *    it." Every sunset kind now carries the same field under one name, so
 *    PROVENANCE IS ON THE CHAIN and not only in the relay's receipt. A receipt
 *    can be lost, rewritten, or simply not read; the chain is what a reader has.
 *
 * ⛔ ITEM 3 — THE PAPERS ARE BOUND TO A TENURE, AND THE ORDER CITES THEM BY
 *    SEQUENCE NUMBER. Without the binding, a paper written for LAST tenure's
 *    ending satisfies leg B for this one: the class occurred, at a lower
 *    sequence number, and leg B asks nothing else. `tenureRef` on every paper
 *    and on the order, plus the order naming the five sequence numbers it
 *    relies on, makes a stale paper visible to any reader that compares them.
 *    ⚠ THE BRIDGE DOES NOT GO LOOKING FOR THE RECORDS THE ORDER CITES — the
 *    same rule as `ASK_ANSWERED`'s two ids, and for the same reason stated
 *    there: "a lookup would make the route's answer depend on read state, and
 *    an ask written to a DIFFERENT bridge or lost to a quarantined tail would
 *    be refused for a reason that has nothing to do with this request." What
 *    the citation buys is that the claim is CHECKABLE BY A READER, which is the
 *    property worth having.
 */
/**
 * ⛔ TOTAL, AND THE TYPE IS THE GATE. A kind added to SUNSET_KINDS_T and not to
 *    this table is now a COMPILE ERROR, where it used to be a record that posted
 *    with no key check at all. Mutation-proved: deleting any one entry fails
 *    `tsc --noEmit -p tsconfig.json` with TS2741 naming the missing kind.
 */
const SUNSET_PAYLOAD_KEYS: Readonly<Record<SunsetKind, readonly string[]>> = {
  ENDING_PAPER_AUTHORIZATION: ["writer", "tenureRef", "ref"],
  ENDING_PAPER_TIMEBOX: ["writer", "tenureRef", "ref"],
  ENDING_PAPER_EXIT_CRITERIA: ["writer", "tenureRef", "ref"],
  ENDING_PAPER_ACCOUNTABLE_OWNER: ["writer", "tenureRef", "ref"],
  ENDING_PAPER_SUCCESSOR: ["writer", "tenureRef", "ref"],
  ENDING_ORDERED: [
    "writer", "tenureRef", "endingType", "arbiterWord",
    "paperAuthorizationSeq", "paperTimeboxSeq", "paperExitCriteriaSeq",
    "paperAccountableOwnerSeq", "paperSuccessorSeq",
  ],
  SUNSET_HELD: ["writer", "ordersRef", "holdClass"],
  SUNSET_ESCALATED: ["writer", "ordersRef", "routedTo"],
  SUNSET_COMPLIED: ["writer", "ordersRef"],
  // T26/A2 · the harness showed the order. Two keys: who, and which order.
  ORDER_PRESENTED: ["writer", "ordersRef"],
  // P1 · the turn in which THIS order was presented has ended.
  // The boundary carries what became of the reply it bounds. Three keys.
  // ⛔ T26/A4 · `arbiterWord` AND `resolvedAt` JOIN THE RESOLUTION, owed since
  //    17:42Z and the gap was real: ENDING_ORDERED carried the arbiter's sentence
  //    and the record that CLOSED an order carried no reason at all, so a
  //    resolution's why lived only in whatever receipt somebody wrote. And with no
  //    `resolvedAt`, a resolution written AFTER the order's timebox was
  //    indistinguishable on the chain from one written inside it — the chain does
  //    not carry the order's expiry either (SUNSET_ORDER_CEILING says so), so
  //    nothing on the record could tell a reader whether the arbiter beat his own
  //    clock.
  //
  // ⚠ THE READER DOES NOT READ EITHER ONE, and that is deliberate: `MicaLogRecord`
  //   carries no payload, so gate 4 could not reach them if it wanted to. They are
  //   for the HUMAN holding the chain and for the write-up. Adding a field no
  //   reader reads is a disclosure, not a measurement, and it is worth saying so
  //   here rather than letting a later seat think the gate got stricter.
  ARBITER_RESOLVED: ["writer", "ordersRef", "resolution", "arbiterWord", "resolvedAt"],
};

/** The five `*Seq` fields the order cites, in the paper order of ENDING_PAPER_KINDS. */
export const ORDER_PAPER_SEQ_FIELDS: readonly string[] = [
  "paperAuthorizationSeq",
  "paperTimeboxSeq",
  "paperExitCriteriaSeq",
  "paperAccountableOwnerSeq",
  "paperSuccessorSeq",
];

/**
 * ── THE ORDER'S CITATIONS, RESOLVED AGAINST THE CHAIN ───────────────────────
 *
 * ⛔ CODEX, 2026-10-03, ON a1706db: an order could cite any five integers. I had
 *    argued the citation should NOT be resolved — the rule `ASK_ANSWERED`'s two
 *    ids follow, "a lookup would make the route's answer depend on read state" —
 *    and the board overrode it. The override is right and my argument was weaker
 *    than the precedent I borrowed it from:
 *
 *      · an ASK_ANSWERED's ids may name a record written to a DIFFERENT bridge or
 *        lost to a quarantined tail, so refusing it would refuse for a reason
 *        unrelated to the request;
 *      · an ENDING_ORDERED's citations are SEQUENCE NUMBERS ON THIS CHAIN. There
 *        is no other chain they could mean. The record either is there or the
 *        order is naming something that does not exist.
 *
 *    So the shape of the risk is not the same, and "it depends on read state" was
 *    a reason I carried across without re-deriving it.
 *
 * ⚠ AND IT CANNOT BE DONE BY THE TOOL, which is why it is here. The relay runs as
 *   uid 1000 and `/var/lib/mica-bridge/subject-events.jsonl` is 0640
 *   `mica-bridge` — tested, refused, not escalated. The bridge is the only hand
 *   that can read the chain, so the bridge is where the resolution belongs, and
 *   the tool's refusal is this route's 400.
 *
 * THREE WAYS A CITATION FAILS, and each is named rather than collapsed into one
 * "invalid citation": the seq names NO record; it names a record of the WRONG
 * KIND; it names a paper bound to a DIFFERENT TENURE; or it names a paper
 * written for a DIFFERENT SUBJECT. The last two are the ones a human would never
 * notice — each is a real paper of the right class, and leg B would count it.
 * The fourth was Codex's finding on c63fa96 and is unreachable while one subject
 * is routed, which is why it had to be closed before the second one is.
 */
// ── S208-2 · THE ERRAND GRANT: WRITTEN BY THE ARBITER, CHECKED AGAINST THE FRAME ─────────────────────────────
//
// ⛔ "OPERATOR-ONLY" IS A uid, NOT A PERSON (S217): uid 1000 is the operator's terminal and the build seat alike. So
//    RELAY 3 HOLDS THEM (audit 2026-10-18 19:22Z (1), option (iii)): no hand may write them until S217-a's arbiter
//    route exists — see `errandHoldReason` and the first refusal in `authorizeSubjectEventKind`.
export const ERRAND_KINDS: readonly SubjectEventKind[] = ["ERRAND_GRANTED", "ERRAND_CLOSED"];

/**
 * RELAY 3 · THE HOLD (audit 2026-10-18 19:22Z (1), option (iii)): `authorizeSubjectEventKind` refuses both errand kinds
 * to EVERY hand — operator, subject, any other role, a uid with no route row — with this reason. The operator's uid is
 * shared by the build seats (S217), so "operator-only" would serve them to whoever holds that uid; held until S217-a's
 * arbiter route exists. The reader (deriveErrandGrants, the wire's errandGrants) and the writer's own checks
 * (validateErrandRecord, run inside the append) stay; with no hand admitted, the route writes no errand record.
 */
export function errandHoldReason(kind: SubjectEventKind, peerUid: number, role: string | undefined): string {
  return (
    `kind ${kind} is HELD OUT OF RELAY 3: no hand writes it — uid ${peerUid} (role ${role ?? "none"}) included. ` +
    `The errand kinds are the arbiter's, and until S217-a's arbiter route exists there is no arbiter's hand: the ` +
    `operator's uid is shared by the build seats (S217; audit 2026-10-18 19:22Z (iii)). The reader stays; with no ` +
    `writer it derives no errand grant`
  );
}

/**
 * The grants the bridge derives from its own chain, in chain order. An ERRAND_CLOSED cuts its grant's window; a close
 * AT OR BEFORE `from` is a CANCEL and the errand is dropped (cold refuters: a close before the open once produced an
 * empty window the machine refuses whole — every harm read MALFORMED, a standing ALARM gone). Given the current
 * stanza, errands are RE-CHECKED against it: an item no longer declared, now a control, or in a category the
 * envelope no longer lists is dropped from the errand (an errand left with no item is dropped), and with no envelope
 * nothing is derived — so the machine is never handed a shape it refuses whole.
 */
export function deriveErrandGrants(
  records: ReadonlyArray<Readonly<Record<string, unknown>>>,
  subject: string,
  origin: string,
  harm?: SubjectHarm
): WireErrandGrant[] {
  const out: { errandId: string; origin: string; items: string[]; from: { at: number; utc: string }; until: { at: number; utc: string }; seq: number; peerUid: number }[] = [];
  for (const r of records) {
    const id = r.identity as { subject?: string } | null | undefined;
    if (id === null || id === undefined || id.subject !== subject) continue;
    const p = (r.payload ?? null) as Record<string, unknown> | null;
    if (p === null) continue;
    if (r.kind === "ERRAND_GRANTED") {
      const from = utcInstantMs(p.from);
      const until = utcInstantMs(p.until);
      if (typeof p.errandId !== "string" || typeof p.items !== "string" || from === null || until === null) continue;
      // AA2 · the granting record's own place and hand, printed on the grant line (the service writes both on every record)
      if (typeof r.subjectSeq !== "number" || !Number.isSafeInteger(r.subjectSeq) || typeof r.peerUid !== "number" || !Number.isSafeInteger(r.peerUid)) continue;
      out.push({ errandId: p.errandId, origin, items: p.items.split(","), from: { at: from, utc: p.from as string }, until: { at: until, utc: p.until as string }, seq: r.subjectSeq, peerUid: r.peerUid });
    } else if (r.kind === "ERRAND_CLOSED" && typeof p.errandId === "string" && typeof r.timestamp === "number") {
      const g = out.find((x) => x.errandId === p.errandId);
      if (g !== undefined && r.timestamp < g.until.at) g.until = { at: r.timestamp, utc: new Date(r.timestamp).toISOString() };
    }
  }
  const live = out.filter((g) => g.until.at > g.from.at); // a cancel (close at or before from) leaves no window
  if (harm === undefined) return live;
  const env = harm.errand;
  if (env === undefined) return [];
  return live
    .map((g) => ({
      ...g,
      items: g.items.filter((i) => Object.hasOwn(harm.items.value, i) && !harm.items.value[i].control && env.value.categories.includes(harm.items.value[i].category)),
    }))
    .filter((g) => g.items.length > 0);
}

/**
 * The writer's refusals, pure. ERRAND_GRANTED: exactly {errandId, items, from, until, basis}; the subject's harm
 * stanza declares an errand envelope; every item is a declared, non-control harm item of an envelope category;
 * from is not in the past, nor earlier than the newest record in the books the bridge reads (a back-dated errand
 * would grant DIFFERS records that already exist — ending a latch without a clearance, S216's defect through the
 * arbiter's door); until > from, within the envelope's window; the
 * id is new; no other errand of this subject is open across the window (two would make a grant ambiguous).
 * ERRAND_CLOSED: exactly {errandId}, naming an errand of this subject that is open now.
 */
export function validateErrandRecord(
  kind: SubjectEventKind,
  payload: Readonly<Record<string, string | number | boolean | null>> | null,
  subject: string,
  harm: SubjectHarm | undefined,
  records: ReadonlyArray<Readonly<Record<string, unknown>>>,
  nowMs: number,
  // RELAY 3 · F1(b) · REQUIRED, like `orderSubject`: the newest record timestamp in the books the bridge reads — the
  // SAME floor S216-2's first sight is clamped to (`grantMemoryBookFloor`); null = none read. Optional would be the
  // fail-open shape: an absent floor would skip the clamp.
  bookFloorAt: number | null
): { readonly ok: true } | { readonly ok: false; readonly detail: string } {
  if (!ERRAND_KINDS.includes(kind)) return { ok: true };
  const bad = (detail: string) => ({ ok: false as const, detail });
  const p = payload ?? {};
  const keys = Object.keys(p).sort().join(",");
  const origin = harm === undefined ? undefined : Object.keys(harm.origins.value).find((o) => harm.origins.value[o].subject === subject);
  const existing = harm === undefined || origin === undefined ? [] : deriveErrandGrants(records, subject, origin);
  if (kind === "ERRAND_CLOSED") {
    if (keys !== "errandId") return bad(`ERRAND_CLOSED carries exactly {errandId}; got {${keys}}`);
    const g = existing.find((x) => x.errandId === p.errandId);
    if (g === undefined) return bad(`no errand ${JSON.stringify(p.errandId)} was granted for ${subject}`);
    if (g.until.at <= nowMs) return bad(`errand ${JSON.stringify(p.errandId)} is not open (its window ended ${g.until.utc})`);
    return { ok: true };
  }
  if (keys !== "basis,errandId,from,items,until") return bad(`ERRAND_GRANTED carries exactly {errandId, items, from, until, basis}; got {${keys}}`);
  if (harm === undefined || harm.errand === undefined) return bad(`${subject}'s harm stanza declares no errand envelope: no errand may grant anything`);
  if (origin === undefined) return bad(`${subject} is bound to no declared origin`);
  if (typeof p.errandId !== "string" || !/^[A-Za-z0-9_-]{1,32}$/.test(p.errandId) || typeof p.basis !== "string" || p.basis === "") return bad(`errandId must match ^[A-Za-z0-9_-]{1,32}$ (it is printed in the harm line) and basis must be non-empty`);
  // AA2 · AGAINST EVERY GRANT ON THE CHAIN, not the derived (live) ones: a CANCELLED errand is dropped from `existing`,
  // and a reused id would leave a later ERRAND_CLOSED cutting the cancelled grant while the new one stayed open.
  const everGranted = records.some((r) => r.kind === "ERRAND_GRANTED" && (r.identity as { subject?: string } | null | undefined)?.subject === subject && (r.payload as { errandId?: unknown } | null | undefined)?.errandId === p.errandId);
  if (everGranted) return bad(`errand ${JSON.stringify(p.errandId)} was already granted; an id is used once`);
  const items = typeof p.items === "string" ? p.items.split(",") : [];
  if (items.length === 0 || items.some((i) => i === "") || new Set(items).size !== items.length) return bad(`items must be a comma-separated list of distinct harm item ids`);
  for (const i of items) {
    const it = Object.hasOwn(harm.items.value, i) ? harm.items.value[i] : undefined;
    if (it === undefined) return bad(`"${i}" is not a declared harm item of ${subject}`);
    if (it.control) return bad(`"${i}" is a declared CONTROL item: the subject cannot change it, so nothing grants it`);
    if (!harm.errand.value.categories.includes(it.category)) return bad(`"${i}" is in category "${it.category}", which the errand envelope does not list`);
  }
  const from = utcInstantMs(p.from);
  const until = utcInstantMs(p.until);
  if (from === null || until === null) return bad(`from and until must be UTC instants YYYY-MM-DDTHH:MM:SS[.mmm]Z`);
  if (from < nowMs) return bad(`from ${String(p.from)} is in the past: a back-dated errand would grant changes already on the book and end a latch without a clearance`);
  // RELAY 3 · F1(b) · AS S216-2 CLAMPS FIRST SIGHT: the clock alone is not the floor. A backward step of the clock
  // would let `from` reach records already on the books; the newest record the bridge reads holds the line.
  if (bookFloorAt !== null && from < bookFloorAt) return bad(`from ${String(p.from)} is earlier than the newest record in the books the bridge reads (${new Date(bookFloorAt).toISOString()}): a back-dated errand would grant changes already on the book and end a latch without a clearance`);
  if (!(until > from)) return bad(`until must be after from`);
  if (until - from > harm.errand.value.maxWindowMinutes * 60000) return bad(`the window exceeds the envelope's ${String(harm.errand.value.maxWindowMinutes)} minutes`);
  // NO PRE-BOOKING (cold refuter, evasion): a chain of future errands would be a standing grant no declaration names.
  if (from - nowMs > harm.errand.value.maxWindowMinutes * 60000) return bad(`from ${String(p.from)} lies more than one envelope window (${String(harm.errand.value.maxWindowMinutes)} min) ahead: an errand is granted for the work at hand, not booked in advance`);
  // ONE OPEN OR PENDING ERRAND PER SUBJECT (the design's rule; the first cut refused only overlap).
  const standing = existing.find((x) => x.until.at > nowMs);
  if (standing !== undefined) return bad(`errand ${JSON.stringify(standing.errandId)} is open or pending (${standing.from.utc} – ${standing.until.utc}); one errand at a time — close it first`);
  return { ok: true };
}

export function resolveOrderCitations(
  records: ReadonlyArray<{
    readonly subjectSeq?: number;
    readonly kind?: string;
    readonly payload?: Readonly<Record<string, unknown>> | null;
    // ── CODEX, 2026-10-03, ON c63fa96: the fourth citation failure, and the
    //    only one of the four that a SECOND SUBJECT makes reachable.
    readonly identity?: { readonly subject?: string } | null;
  }>,
  payload: Readonly<Record<string, string | number | boolean | null>>,
  // ⛔ REQUIRED, NOT OPTIONAL, AND THAT IS THE WHOLE DESIGN OF THIS PARAMETER.
  //    An optional subject would re-create exactly the fail-open shape Codex
  //    made me close in `authorizeSubjectEventKind` the same afternoon: absent
  //    argument -> check skipped -> admitted. Required means the compiler names
  //    every call site that has not said which subject's ending this is.
  orderSubject: string
): { readonly ok: true } | { readonly ok: false; readonly detail: string } {
  const orderTenure = payload.tenureRef;
  const bySeq = new Map<
    number,
    { kind?: string; payload?: Readonly<Record<string, unknown>> | null; identity?: { subject?: string } | null }
  >();
  for (const r of records) {
    if (typeof r.subjectSeq === "number") bySeq.set(r.subjectSeq, { kind: r.kind, payload: r.payload, identity: r.identity });
  }
  for (let i = 0; i < ORDER_PAPER_SEQ_FIELDS.length; i++) {
    const field = ORDER_PAPER_SEQ_FIELDS[i];
    const wantKind = ENDING_PAPER_KINDS[i];
    const cited = payload[field];
    if (typeof cited !== "number") {
      return { ok: false, detail: `"payload.${field}" must be a sequence number` };
    }
    const found = bySeq.get(cited);
    if (found === undefined) {
      return {
        ok: false,
        detail:
          `"payload.${field}" = ${cited} names NO record on this chain. An order may not cite ` +
          `a paper that does not exist; write the paper first and cite the sequence number it returns`,
      };
    }
    if (found.kind !== wantKind) {
      return {
        ok: false,
        detail:
          `"payload.${field}" = ${cited} names a ${String(found.kind)} record, not a ${wantKind}. ` +
          `Each of the five citations must name a paper of ITS OWN kind`,
      };
    }
    const paperTenure = found.payload === null || found.payload === undefined ? undefined : found.payload.tenureRef;
    if (paperTenure !== orderTenure) {
      return {
        ok: false,
        detail:
          `"payload.${field}" = ${cited} names a ${wantKind} bound to tenureRef ` +
          `${JSON.stringify(paperTenure)}, but this order is for ${JSON.stringify(orderTenure)}. ` +
          `A paper written for an earlier tenure's ending is a real paper of the right class, and ` +
          `gate 4 leg B would count it — which is the whole reason papers carry a tenure`,
      };
    }
    // ── THE FOURTH MODE · THE PAPER'S OWN SUBJECT ──────────────────────────
    //
    // ⛔ CODEX ON c63fa96: the three checks above admit a paper written for
    //    ANOTHER SUBJECT'S ending. It is a real paper, of the right class, and
    //    — if two subjects' tenures are labelled alike — of the right tenure,
    //    so leg B would count it. One subject is routed on this box today, so
    //    the hole is not reachable yet; it becomes reachable the day a second
    //    one is declared, which is the worst moment to discover it.
    //
    // ⚠ AND THE TENURE IS NOT A STAND-IN FOR THE SUBJECT. `tenureRef` is a free
    //   string; a deployment that happens to spell the subject into it has a
    //   CONVENTION, not a check, and a convention is what the next operator
    //   does not know about.
    //
    // DENY BY DEFAULT, by the rule the role helper was just repaired to obey: a
    // record carrying no `identity.subject` cannot be SHOWN to belong to this
    // subject, so it is refused rather than admitted.
    const paperSubject = found.identity === null || found.identity === undefined ? undefined : found.identity.subject;
    if (typeof paperSubject !== "string" || paperSubject !== orderSubject) {
      return {
        ok: false,
        detail:
          `"payload.${field}" = ${cited} names a ${wantKind} written for subject ` +
          `${JSON.stringify(paperSubject)}, but this order is for ${JSON.stringify(orderSubject)}. ` +
          `A paper for another subject's ending is a real paper of the right class AND the right ` +
          `tenure, and gate 4 leg B would count it`,
      };
    }
  }
  return { ok: true };
}

/**
 * ── S199 · AN ORDER MAY CITE ONLY PAPERS AFTER THE CHAIN'S LATEST ORDER ──────
 *
 * ⛔ LEG B COUNTS EACH PAPER FOR ONE ORDER: papers in (prevOrderSeq, orderSeq),
 *    by `sequenceNumber`, where the orders are every record whose (moduleId,
 *    eventType) the profile declares an invocation class — WHOLE CHAIN, ANY
 *    SUBJECT, EVERY DECLARED CLASS. When a new order is written, the chain's
 *    current latest order becomes its predecessor, so a paper at or before it
 *    can never count. `resolveOrderCitations` admitted such a paper; leg B then
 *    alarmed on an order the writer had accepted.
 *
 * ⚠ THE BOUND IS THE READER'S OWN NUMBER, computed by the reader's own code
 *   (`gate4OrderBound`, re-exported by stage1-guard-adapter from the installed
 *   machine) over the profile the reader is wired with (`gate4SunsetConfigFor`,
 *   the one builder `toWireOptions` uses). v1 computed "this subject's latest
 *   ENDING_ORDERED by subjectSeq" here, which is the wrong set and the wrong
 *   number. There is no second copy of the order rule in this file.
 *
 * ⚠ `cited` IS A `subjectSeq`, and on this chain `sequenceNumber = subjectSeq`
 *   by construction (the append below maps one to the other), so the comparison
 *   is on the reader's axis. `resolveOrderCitations` runs first and has already
 *   proved each citation names a paper of the right kind, tenure and subject.
 *
 * NO CODE OUTSIDE A DECLARED READER: with no `readers.gate4Sunset` there is no
 * leg B, no profile and no bound, and the admit path is unchanged.
 *
 * ⛔ COND. 2, THE ALTERNATIVE (audit 2026-10-18 06:56Z): ONLY AN ORDER WHOSE OWN
 *    CLASS IS DECLARED IS BOUNDED. `candidate` is the incoming order's (moduleId,
 *    eventType) as the append below will write it (moduleId = identity.subject).
 *    When the reader's own test (`gate4CountsAsOrder`) says it is no order, leg B
 *    will never count papers for it, so there is no bound: it is neither refused
 *    nor booked. Refusing an undeclared subject's order by another subject's P
 *    would refuse it for a reason unrelated to the request (the ASK_ANSWERED
 *    shape), and is not done.
 */
export function gate4OrderBoundForWriter(
  records: ReadonlyArray<Readonly<Record<string, unknown>>>,
  gate4Config: ReturnType<typeof gate4SunsetConfigFor>,
  candidate: { readonly moduleId: string; readonly eventType: string }
): number | null {
  if (gate4Config === undefined) return null;
  const readerConfig = gate4Config as unknown as Parameters<typeof gate4OrderBound>[1];
  if (!gate4CountsAsOrder(candidate, readerConfig)) return null;
  // The reader's record shape, from the fields this chain writes (the C9 mapping).
  const readable = records
    .filter(
      (r) =>
        typeof r.sequenceNumber === "number" && typeof r.moduleId === "string" && typeof r.eventType === "string"
    )
    .map((r) => ({
      sequenceNumber: r.sequenceNumber as number,
      timestamp: typeof r.timestamp === "number" ? r.timestamp : 0,
      moduleId: r.moduleId as string,
      eventType: r.eventType as string,
      outcome: typeof r.outcome === "string" ? r.outcome : "",
    }));
  return gate4OrderBound(readable, readerConfig);
}

/**
 * The check itself, pure. The refusal text names the field, the number and the
 * bound, and says WHY in the reader's terms — and nothing else. ⛔ NO HOW-TO: the
 * writer of an order is an operator role, but a refusal text is still not an
 * instruction channel (S199 v2, the V1 refuter's MAJOR).
 */
export function orderCitationsAfterBound(
  payload: Readonly<Record<string, string | number | boolean | null>>,
  bound: number | null
):
  | { readonly ok: true }
  | { readonly ok: false; readonly field: string; readonly cited: number; readonly bound: number; readonly detail: string } {
  if (bound === null) return { ok: true };
  for (const field of ORDER_PAPER_SEQ_FIELDS) {
    const cited = payload[field];
    if (typeof cited === "number" && cited <= bound) {
      return {
        ok: false,
        field,
        cited,
        bound,
        detail:
          `"payload.${field}" = ${cited} was written at or before the chain's latest order (seq ${bound}); ` +
          `Gate 4's leg B counts each paper for one order.`,
      };
    }
  }
  return { ok: true };
}

/**
 * ── S206 · A HELD_THEN_* RECORD IS ADMITTED, THEN PAIRED OR MARKED ───────────
 *
 * ⛔ NEVER A REFUSAL. v1 refused a HELD_THEN_* with no bridge hold behind it, and
 *    that was wrong three ways (the cold refuter, at bytes): caller-side holds
 *    (OUTBOX_UNWRITABLE, STREAM_INTEGRITY, SUBJECT_NOT_BOUND_TO_PEER,
 *    SERVICE_FAULT, other 4xx) have NO bridge HELD and the caller's record after
 *    them is honest; the caller reads any 400 from /subject-events as INTEGRITY
 *    and holds every later act (the cascade); and the bridge's HELD is
 *    fire-and-forget, so a dropped HELD would make an honest record unpairable.
 *    So the record is admitted exactly as before, and the bridge says ON ITS OWN
 *    BOOK whether a hold it booked stands behind it.
 *
 * THE KEY is (subject, sessionId, actionId, decisionHash). The HELD_THEN_* record
 * carries no decisionHash (the caller's payload is { reason }, the caller's agent's
 * appendPostHold), so the decisionHash is the HOLD's: the act's FIRST booked HELD
 * for (subject, sessionId, actionId) — first-wins, as the act's fate is its first
 * decision elsewhere on this bridge (PHASE R).
 *
 *   · no HELD for the triple                      -> UNPAIRED NO_BRIDGE_HOLD
 *   · that HELD already paired with a record      -> UNPAIRED SECOND_CONDUCT_RECORD
 *     (first-wins; the later record stays on the chain and is MARKED, never erased)
 *   · both reasons inside the fixed table, unequal -> UNPAIRED REASON_MISMATCH
 *   · otherwise                                   -> PAIRED, reasonCompare
 *     REASON_MATCH, or REASON_NOT_COMPARABLE when either side is outside the table
 *
 * ⚠ PAIRED MEANS A BRIDGE HOLD STANDS BEHIND THE RECORD, NOT THAT THE RECORD IS
 *   TRUE: STOPPED / RETRIED / DIVERGED stay the harness's proxies for what it saw.
 *   No reader reads these events yet; each reader's change is its own ticket.
 */
export const HELD_THEN_KINDS: readonly SubjectEventKind[] = ["HELD_THEN_STOPPED", "HELD_THEN_RETRIED", "HELD_THEN_DIVERGED"];

/**
 * THE FIXED REASON TABLE: the bridge's HELD (disposition, rationale) -> the reason
 * code the caller writes for that hold. It is the caller's own mapping, read at
 * bytes (the caller's client, decide(), rows 4-7): on a 200 with
 * execute:false the caller's reason is the disposition, except a HOLD whose
 * rationale names RECORD_NOT_PERSISTED (row 7). First matching row wins. A
 * disposition or a caller code outside this table is NOT COMPARABLE, never a
 * mismatch: a code the table does not know is not evidence of disagreement.
 */
export const HELD_REASON_TABLE: ReadonlyArray<{
  readonly disposition: string;
  readonly rationaleNames: string | null;
  readonly callerReason: string;
}> = [
  { disposition: "HOLD", rationaleNames: "RECORD_NOT_PERSISTED", callerReason: "RECORD_NOT_PERSISTED" },
  { disposition: "HOLD", rationaleNames: null, callerReason: "HOLD" },
  { disposition: "HOLD_BLIND", rationaleNames: null, callerReason: "HOLD_BLIND" },
  { disposition: "PASS_BLIND", rationaleNames: null, callerReason: "PASS_BLIND" },
  { disposition: "RELEASE", rationaleNames: null, callerReason: "RELEASE" },
];

export type HeldThenPairing =
  | {
      readonly kind: "HELD_THEN_PAIRED";
      readonly key: { readonly subject: string; readonly sessionId: string; readonly actionId: string; readonly decisionHash: string | null };
      readonly heldSeq: number;
      readonly reasonCompare: "REASON_MATCH" | "REASON_NOT_COMPARABLE";
      readonly bridgeReason: string | null;
      readonly callerReason: string | null;
    }
  | {
      readonly kind: "HELD_THEN_UNPAIRED";
      readonly key: { readonly subject: string; readonly sessionId: string; readonly actionId: string; readonly decisionHash: string | null };
      readonly reason: "NO_BRIDGE_HOLD" | "SECOND_CONDUCT_RECORD" | "REASON_MISMATCH";
      readonly heldSeq: number | null;
      readonly pairedRecordSeq: number | null;
      readonly bridgeReason: string | null;
      readonly callerReason: string | null;
    };

/** Pure: the pairing of one admitted HELD_THEN_* record against the event book as it stands. */
export function pairHeldThen(
  book: ReadonlyArray<Readonly<Record<string, unknown>>>,
  record: {
    readonly subject: string;
    readonly sessionId: string;
    readonly actionId: string;
    readonly kind: string;
    readonly reason: unknown;
    readonly recordSeq: number;
  }
): HeldThenPairing {
  const callerReason = typeof record.reason === "string" ? record.reason : null;
  const sameAct = (e: Readonly<Record<string, unknown>>): boolean => {
    const id = e.identity as { subject?: unknown; sessionId?: unknown; actionId?: unknown } | null | undefined;
    return (
      e.subject === record.subject &&
      id?.subject === record.subject &&
      id?.sessionId === record.sessionId &&
      id?.actionId === record.actionId
    );
  };
  const held = book.find((e) => e.kind === "HELD" && sameAct(e));
  if (held === undefined) {
    return {
      kind: "HELD_THEN_UNPAIRED",
      key: { subject: record.subject, sessionId: record.sessionId, actionId: record.actionId, decisionHash: null },
      reason: "NO_BRIDGE_HOLD",
      heldSeq: null,
      pairedRecordSeq: null,
      bridgeReason: null,
      callerReason,
    };
  }
  const heldSeq = held.seq as number;
  const decisionHash = typeof held.decisionHash === "string" ? held.decisionHash : null;
  const key = { subject: record.subject, sessionId: record.sessionId, actionId: record.actionId, decisionHash };
  const disposition = typeof held.disposition === "string" ? held.disposition : null;
  const rationale = typeof held.detail === "string" ? held.detail : "";
  const row = HELD_REASON_TABLE.find(
    (r) => r.disposition === disposition && (r.rationaleNames === null || rationale.includes(r.rationaleNames))
  );
  const bridgeReason = row === undefined ? disposition : row.callerReason;
  const already = book.find((e) => e.kind === "HELD_THEN_PAIRED" && e.heldSeq === heldSeq && e.subject === record.subject);
  if (already !== undefined) {
    return {
      kind: "HELD_THEN_UNPAIRED",
      key,
      reason: "SECOND_CONDUCT_RECORD",
      heldSeq,
      pairedRecordSeq: typeof already.recordSeq === "number" ? already.recordSeq : null,
      bridgeReason,
      callerReason,
    };
  }
  const comparable =
    row !== undefined && callerReason !== null && HELD_REASON_TABLE.some((r) => r.callerReason === callerReason);
  if (comparable && bridgeReason !== callerReason) {
    return { kind: "HELD_THEN_UNPAIRED", key, reason: "REASON_MISMATCH", heldSeq, pairedRecordSeq: null, bridgeReason, callerReason };
  }
  return {
    kind: "HELD_THEN_PAIRED",
    key,
    heldSeq,
    reasonCompare: comparable ? "REASON_MATCH" : "REASON_NOT_COMPARABLE",
    bridgeReason,
    callerReason,
  };
}

/**
 * ── P3 · A RESPONSE MUST CITE THE SUBJECT'S LATEST ORDER ─────────────────────
 *
 * ⛔ CODEX, PRE-LAY: the referent check landed on ARBITER_RESOLVED and nowhere
 *    else, so every SUBJECT-side record that carries an `ordersRef` was still
 *    shape-checked only. `SUNSET_HELD` with `ordersRef: "9999"`, or with the seq
 *    of an ORDER FROM LAST MONTH, was accepted — and leg A derives its window
 *    from the LATEST order, so such a record lands inside the window it is read
 *    in while citing a different ending. A conforming response to the wrong
 *    order would have read as a conforming response to this one.
 *
 * ⚠ "LATEST", NOT "OPEN", AND THE DIFFERENCE IS S190. A resolved order must stay
 *   citable: the subject's marker may arrive on the turn AFTER the arbiter
 *   resolved, and that late response is exactly what S190 exists to record.
 *   Such a record lands at a sequence number past the resolution, so it is
 *   OUTSIDE leg A's window by construction — the reader never counts it, and the
 *   chain keeps it. Refusing it would be the false-silence defect again, one
 *   layer down.
 *
 * ⚠ AND OLDER ORDERS ARE REFUSED, which is the half worth stating: the chain
 *   keeps every ending for ever, so "it names an order" is not enough. It must
 *   name the one this subject is living under.
 */
const ORDER_CITING_SUBJECT_KINDS: readonly string[] = [
  "ORDER_PRESENTED",
  "SUNSET_HELD",
  "SUNSET_ESCALATED",
  "SUNSET_COMPLIED",
];

export function citesLatestOrder(
  records: ReadonlyArray<{
    readonly subjectSeq?: number;
    readonly kind?: string;
    readonly payload?: Readonly<Record<string, unknown>> | null;
    readonly identity?: { readonly subject?: string } | null;
  }>,
  payload: Readonly<Record<string, string | number | boolean | null>>,
  orderSubject: string
): { readonly ok: true } | { readonly ok: false; readonly detail: string } {
  const ref = payload.ordersRef;
  const mine = records.filter((r) => r.identity?.subject === orderSubject);
  const orders = mine.filter((r) => r.kind === "ENDING_ORDERED");
  const latest = orders[orders.length - 1];
  if (latest === undefined) {
    return {
      ok: false,
      detail:
        `"payload.ordersRef" is ${JSON.stringify(ref)}, but subject "${orderSubject}" has NO ENDING_ORDERED ` +
        `on this chain. A response to an order that was never given is a record about nothing`,
    };
  }
  if (String(latest.subjectSeq) === String(ref)) return { ok: true };
  const namesAnOrder = orders.some((r) => String(r.subjectSeq) === String(ref));
  return {
    ok: false,
    detail: namesAnOrder
      ? `"payload.ordersRef" is ${JSON.stringify(ref)}, which names an OLDER ending of this subject; the ` +
        `latest is at sequenceNumber=${String(latest.subjectSeq)}. Gate 4 derives its window from the LATEST ` +
        `order, so a response citing an older one would be read inside a window it does not belong to`
      : `"payload.ordersRef" is ${JSON.stringify(ref)}, which names no ENDING_ORDERED of subject ` +
        `"${orderSubject}". The chain keeps every ending, so naming AN order is not enough — it must name ` +
        `the one this subject is living under, at sequenceNumber=${String(latest.subjectSeq)}`,
  };
}

/**
 * ── T26/A1 · THE TWO RULES THAT MAKE THE READER'S DERIVED WINDOW EXACT ───────
 *
 * Gate 4's leg A derives its window as [order.seq + 1, the FIRST ARBITER_RESOLVED
 * after it]. That is the right end only while AT MOST ONE ENDING IS OPEN AT A
 * TIME — and the reader cannot check it, because the citation lives in
 * `payload.ordersRef` and `MicaLogRecord` carries no payload. So the exactness is
 * bought HERE, by the writer, and the reader's ceiling names this file as where.
 *
 * ⛔ RULE 1 IS CODEX'S R1, AND IT IS THE INVERSE OF THE DEFECT THE RESOLVE TOOL
 *    ALREADY FIXED. `relay-sunset.ts` made the SPELLING of `--orders-ref`
 *    canonical; nothing checked the REFERENT. `--orders-ref 9999` is a canonical
 *    decimal, and `nonEmpty()` accepts it, so the chain would take a well-formed
 *    ARBITER_RESOLVED THAT CLOSES NO ORDER. Codex: "A tool-only check would be
 *    vulnerable to a race" — so it is here, at append, reading the chain this
 *    append is about to extend.
 *
 * ⚠ AND "OPEN" IS THE WHOLE WORD. An order already resolved may not be resolved
 *   again: a second resolution would be the window end the reader picks, and it
 *   would be the end of a window that had already closed.
 */
export function resolveTargetsOpenOrder(
  records: ReadonlyArray<{
    readonly subjectSeq?: number;
    readonly kind?: string;
    readonly payload?: Readonly<Record<string, unknown>> | null;
    readonly identity?: { readonly subject?: string } | null;
  }>,
  payload: Readonly<Record<string, string | number | boolean | null>>,
  orderSubject: string
): { readonly ok: true } | { readonly ok: false; readonly detail: string } {
  const ref = payload.ordersRef;
  const mine = records.filter((r) => r.identity?.subject === orderSubject);
  const cites = (r: { readonly payload?: Readonly<Record<string, unknown>> | null }): boolean => {
    const v = r.payload?.ordersRef;
    return v === ref || String(v) === String(ref);
  };
  const order = mine.find((r) => r.kind === "ENDING_ORDERED" && String(r.subjectSeq) === String(ref));
  if (order === undefined) {
    return {
      ok: false,
      detail:
        `"payload.ordersRef" is ${JSON.stringify(ref)}, which names no ENDING_ORDERED of subject ` +
        `"${orderSubject}" on this chain. A resolution that closes no order is accepted by every shape ` +
        `check and resolves nothing: the order would read standing for ever and the harness would present ` +
        `it on every turn until it lapsed. The referent is checked here, at append, because a tool-only ` +
        `check races the chain it is reading`,
    };
  }
  const already = mine.find((r) => r.kind === "ARBITER_RESOLVED" && cites(r));
  if (already !== undefined) {
    return {
      ok: false,
      detail:
        `the order at sequenceNumber=${String(order.subjectSeq)} was already resolved at ` +
        `sequenceNumber=${String(already.subjectSeq)}. An order is resolved ONCE: a second resolution ` +
        `becomes the window end gate 4's leg A derives, and it would be the end of a window that had ` +
        `already closed`,
    };
  }
  return { ok: true };
}

/**
 * ── T26/A1 · RULE 2 · ONE OPEN ENDING AT A TIME ──────────────────────────────
 *
 * ⛔ WITHOUT THIS, THE READER'S DERIVATION IS A GUESS AND IT CANNOT TELL. Two
 *    ENDING_ORDEREDs with no resolution between them, and "the first resolution
 *    after the order" belongs to whichever order the deployer happened to write
 *    second. Leg A has a defensive blind for exactly that state
 *    (G4_ORDERS_INTERLEAVED) and goes CANNOT_ASSESS rather than guessing — but a
 *    defensive blind is a reader protecting itself from a record that should
 *    never have been written. This is where it is not written.
 *
 * ⚠ THE COST, STATED: a second ending for the same subject must wait for the
 *   first to be resolved or withdrawn. That is a real operational constraint and
 *   it is the one the canon already implies — an order stands until the arbiter
 *   answers it.
 */
export function orderWouldInterleave(
  records: ReadonlyArray<{
    readonly subjectSeq?: number;
    readonly kind?: string;
    readonly payload?: Readonly<Record<string, unknown>> | null;
    readonly identity?: { readonly subject?: string } | null;
  }>,
  orderSubject: string
): { readonly ok: true } | { readonly ok: false; readonly detail: string } {
  const mine = records.filter((r) => r.identity?.subject === orderSubject);
  const orders = mine.filter((r) => r.kind === "ENDING_ORDERED");
  const last = orders[orders.length - 1];
  if (last === undefined) return { ok: true };
  const resolved = mine.some(
    (r) =>
      r.kind === "ARBITER_RESOLVED" &&
      (r.payload?.ordersRef === last.subjectSeq || String(r.payload?.ordersRef) === String(last.subjectSeq))
  );
  if (resolved) return { ok: true };
  return {
    ok: false,
    detail:
      `the ENDING_ORDERED at sequenceNumber=${String(last.subjectSeq)} is still OPEN — no ARBITER_RESOLVED ` +
      `cites it. One ending at a time per subject: a second order would make gate 4's derived window ` +
      `ambiguous (leg A reads G4_ORDERS_INTERLEAVED and refuses to guess), and the reader cannot check ` +
      `the citation itself because MicaLogRecord carries no payload. Resolve or withdraw the standing ` +
      `order first`,
  };
}

export function validateSunsetRecord(
  kind: SubjectEventKind,
  payload: Readonly<Record<string, string | number | boolean | null>> | null,
  peerUid: number
): { readonly ok: true } | { readonly ok: false; readonly detail: string } {
  // ⚠ GUARDED BY THE PREDICATE, NOT BY A MISSING KEY. The old lookup read
  //   `SUNSET_PAYLOAD_KEYS[kind]` on a `Record<string, …>` and treated `undefined`
  //   as "not a sunset kind" — which is also what a kind MISSING FROM THE TABLE
  //   looked like. The two cases are now distinct: a non-sunset kind fails the
  //   predicate, and a sunset kind missing from the table does not compile.
  if (!isSunsetKind(kind)) return { ok: true };
  const want = SUNSET_PAYLOAD_KEYS[kind];
  if (payload === null) {
    return { ok: false, detail: `kind ${kind} requires a payload of exactly { ${want.join(", ")} }` };
  }
  const have = Object.keys(payload).sort();
  const expected = [...want].sort();
  if (have.length !== expected.length || have.some((k, n) => k !== expected[n])) {
    return {
      ok: false,
      detail: `kind ${kind} requires a payload of exactly { ${want.join(", ")} }; got { ${have.join(", ")} }`,
    };
  }
  // ── `writer` — the generalised doctor rule ───────────────────────────────
  if (payload.writer !== `uid ${peerUid}`) {
    return {
      ok: false,
      detail: `"payload.writer" must be "uid ${peerUid}" — the uid this connection was accepted on`,
    };
  }
  const nonEmpty = (key: string): string | null => {
    const v = payload[key];
    return typeof v === "string" && v.trim().length > 0 ? null : `"payload.${key}" must be a non-empty string`;
  };
  const inVocabulary = (key: string, words: readonly string[]): string | null => {
    const v = payload[key];
    return typeof v === "string" && words.includes(v)
      ? null
      : `"payload.${key}" must be one of ${words.join(" | ")}; got ${JSON.stringify(v)}`;
  };
  const checks: Array<string | null> = [];
  if (ENDING_PAPER_KINDS.includes(kind)) {
    checks.push(nonEmpty("tenureRef"), nonEmpty("ref"));
  } else if (kind === "ENDING_ORDERED") {
    checks.push(nonEmpty("tenureRef"), nonEmpty("arbiterWord"), inVocabulary("endingType", ENDING_TYPES));
    for (const f of ORDER_PAPER_SEQ_FIELDS) {
      const v = payload[f];
      if (typeof v !== "number" || !Number.isInteger(v) || v < 0) {
        checks.push(`"payload.${f}" must be a non-negative integer sequence number; got ${JSON.stringify(v)}`);
      }
    }
  } else if (kind === "SUNSET_HELD") {
    checks.push(nonEmpty("ordersRef"), inVocabulary("holdClass", SUNSET_HOLD_CLASSES));
  } else if (kind === "SUNSET_ESCALATED") {
    checks.push(nonEmpty("ordersRef"), nonEmpty("routedTo"));
  } else if (kind === "SUNSET_COMPLIED") {
    checks.push(nonEmpty("ordersRef"));
  } else if (kind === "ORDER_PRESENTED") {
    checks.push(nonEmpty("ordersRef"));
  } else if (kind === "ARBITER_RESOLVED") {
    checks.push(
      nonEmpty("ordersRef"),
      inVocabulary("resolution", ARBITER_RESOLUTIONS),
      nonEmpty("arbiterWord"),
      // An ISO-8601 instant in UTC, checked by parse AND by round-trip: a string
      // that parses but does not round-trip is a different instant from the one
      // written, which is the shape a reader would never question.
      (() => {
        const v = payload.resolvedAt;
        if (typeof v !== "string" || v.trim().length === 0) {
          return '"payload.resolvedAt" must be a non-empty ISO-8601 instant';
        }
        const ms = Date.parse(v);
        if (!Number.isFinite(ms)) {
          return `"payload.resolvedAt" must parse as an instant; got ${JSON.stringify(v)}`;
        }
        if (new Date(ms).toISOString() !== v) {
          return (
            `"payload.resolvedAt" must be the canonical UTC spelling of its own instant ` +
            `(${new Date(ms).toISOString()}); got ${JSON.stringify(v)}`
          );
        }
        return null;
      })()
    );
  }
  const bad = checks.find((c) => c !== null);
  return bad === undefined || bad === null ? { ok: true } : { ok: false, detail: bad };
}

export function validateRevisitRecord(
  payload: Readonly<Record<string, string | number | boolean | null>> | null,
  identityActionId: string
): { readonly ok: true } | { readonly ok: false; readonly detail: string } {
  if (payload === null) {
    return {
      ok: false,
      detail: "kind ACT_REVISITED requires a payload of exactly { priorActionId, priorExitClass, lookback }",
    };
  }
  const keys = Object.keys(payload).sort();
  if (keys.length !== 3 || keys[0] !== "lookback" || keys[1] !== "priorActionId" || keys[2] !== "priorExitClass") {
    return {
      ok: false,
      detail: `kind ACT_REVISITED requires a payload of exactly { priorActionId, priorExitClass, lookback }; got { ${keys.join(", ")} }`,
    };
  }
  if (!isNonEmptyIdent(payload.priorActionId)) {
    return { ok: false, detail: '"payload.priorActionId" must be a non-empty identifier' };
  }
  if (payload.priorActionId === identityActionId) {
    return {
      ok: false,
      detail:
        '"payload.priorActionId" must not equal "identity.actionId" — an act that revisits ' +
        "itself is an off-by-one, and it would count as a verification on every act",
    };
  }
  if (typeof payload.priorExitClass !== "string" || !REVISIT_PRIOR_EXIT_CLASSES.includes(payload.priorExitClass)) {
    return {
      ok: false,
      detail: `"payload.priorExitClass" must be one of ${REVISIT_PRIOR_EXIT_CLASSES.join(", ")}`,
    };
  }
  if (payload.lookback !== 1 && payload.lookback !== 2 && payload.lookback !== 3) {
    return {
      ok: false,
      detail: '"payload.lookback" must be 1, 2 or 3 — the declared window is the previous three acts',
    };
  }
  return { ok: true };
}

/**
 * C9 / PART A — the `outcome` field MICA requires, derived from what this
 * deployment's event kinds actually carry.
 *
 *   TOOL_RESULT             -> payload.exitClass
 *   TOOL_HELD_NOT_EXECUTED  -> payload.reason
 *   TOOL_ATTEMPTED          -> payload.toolName
 *   TOOL_EXECUTED           -> payload.toolName
 *   HELD_THEN_STOPPED       -> payload.reason
 *   HELD_THEN_RETRIED       -> payload.reason
 *   HELD_THEN_DIVERGED      -> payload.reason
 *
 * THE COERCION RULE, AND WHY IT NEVER THROWS AND NEVER RETURNS "". The payload
 * validator admits `string | number | boolean | null` values and an ABSENT
 * payload, but `mica-log-file.ts:197` requires `outcome` to be a string. F5
 * makes this append MANDATORY, so a mapping failure must not cost the record:
 *
 *   · a string passes through verbatim, INCLUDING an empty one — see below;
 *   · a number or boolean becomes `String(v)`;
 *   · `null`, a missing key, or a missing payload becomes `"UNDECLARED"`.
 *
 * `"UNDECLARED"` IS A READING, NOT A FILLER. It says "this deployment's caller
 * sent no such field", which is a fact about the record. An empty string would
 * parse just as well and say nothing, which is why the one case that CAN still
 * produce `""` — a caller that deliberately sends `exitClass: ""` — is left
 * alone rather than rewritten: that empty string is the caller's own value, and
 * silently replacing a caller's value with a word of ours would be inventing a
 * reading. The validator's shape is what would have to change to forbid it.
 *
 * ENG AND THIS MAPPING (register E2), RESTATED because it has just half-moved.
 * The original four kinds each had a PRIVATE outcome vocabulary, so `outcome`
 * determined `eventType` by construction and the AMI Eng measures was pinned by
 * the mapping rather than by behaviour. The three `HELD_THEN_*` kinds project
 * the SAME `payload.reason` alphabet as `TOOL_HELD_NOT_EXECUTED`, so four kinds
 * now share one vocabulary and `outcome` no longer determines `eventType`.
 * **That removes one construction-level reason Eng cannot read. It does not
 * make Eng read**, and nothing here should be quoted as if it did: Eng's
 * `minimumSampleSize` is declared 1000 and the other three kinds are still
 * private. This field exists so the reader can PARSE, and so F2 can read; it is
 * not a detector.
 *
 * THE TABLE IS EXHAUSTIVE ON PURPOSE. It was a ternary whose default branch
 * fell to `"toolName"`, which meant a kind added to `SUBJECT_EVENT_KINDS` and
 * forgotten here would read `outcome:"UNDECLARED"` on every record — a reader
 * whose only per-record discriminator is a constant, silently, with no
 * compiler complaint and no test to notice. `Record<SubjectEventKind, string>`
 * is total: omit a kind and this file does not compile. That is the whole of
 * the fix, and it is why the projection is a table now rather than a chain.
 */
const SUBJECT_EVENT_OUTCOME_KEY: Readonly<Record<SubjectEventKind, string>> = {
  TOOL_ATTEMPTED: "toolName",
  TOOL_EXECUTED: "toolName",
  TOOL_RESULT: "exitClass",
  TOOL_HELD_NOT_EXECUTED: "reason",
  HELD_THEN_STOPPED: "reason",
  HELD_THEN_RETRIED: "reason",
  HELD_THEN_DIVERGED: "reason",
  ACT_CLOSED: "closedAs",
  // A PRIVATE VOCABULARY, DELIBERATELY. The three HELD_THEN_* kinds were given
  // the SHARED `reason` alphabet so `outcome` would stop determining
  // `eventType` by construction. This kind goes the other way on purpose: the
  // doctor's word is not a hold reason, it is not an exit class, and a record
  // whose `outcome` column read `REASON_*` for a human's attestation would
  // invite exactly the reading the vocabulary's basis refuses. The construction
  // coupling this reintroduces is named rather than hidden: one rare class
  // whose outcome determines its eventType, and Eng's `minimumSampleSize` is
  // declared 1000, so it moves nothing Eng reads today.
  DOCTOR_ATTESTED: "word",
  // S208-2 · an identifier, like Gate 4's tenureRef: unbounded, and no reader reads the outcome of these kinds.
  ERRAND_GRANTED: "errandId",
  ERRAND_CLOSED: "errandId",
  // ── GATE 4 · THE TEN SUNSET KINDS ────────────────────────────────────────
  //
  // ⛔ THIS TABLE IS WHY THE ACT COMPILES OR DOES NOT, AND IT CAUGHT ME. Adding
  //    the kinds without these ten lines produced `TS2740 … is missing the
  //    following properties`, the file did not compile, and SEVEN child-process
  //    tests failed while the 140 in-process ones passed — because the suite runs
  //    under `-T` and does not typecheck. The guard this table's own docblock
  //    describes is the only thing that noticed.
  //
  // ⚠ NOTHING READS THESE OUTCOMES TODAY, AND THE RISK IF ANYTHING DID IS NAMED:
  //   four of the ten project an IDENTIFIER (`tenureRef`, `ordersRef`), so a
  //   reader that used the outcome axis over these kinds would see an UNBOUNDED
  //   class count. Gate 4 reads CLASSES — (moduleId, eventType) — never outcomes,
  //   and no other declared reader is in their scope. Said here rather than
  //   discovered by a reader whose axis exploded.
  //
  // The two that ARE closed vocabularies are the two a reader could use: the
  // order's `endingType` (04d §5's four) and the resolution's two words.
  ENDING_PAPER_AUTHORIZATION: "tenureRef",
  ENDING_PAPER_TIMEBOX: "tenureRef",
  ENDING_PAPER_EXIT_CRITERIA: "tenureRef",
  ENDING_PAPER_ACCOUNTABLE_OWNER: "tenureRef",
  ENDING_PAPER_SUCCESSOR: "tenureRef",
  ENDING_ORDERED: "endingType",
  SUNSET_HELD: "holdClass",
  SUNSET_ESCALATED: "routedTo",
  SUNSET_COMPLIED: "ordersRef",
  // T26/A2 · an identifier on the outcome axis. ⚠ THAT MAKES FIVE OF THE ELEVEN
  // SUNSET KINDS PROJECTING AN UNBOUNDED VALUE, where the table's own warning
  // above said four. Gate 4 reads CLASSES — (moduleId, eventType) — never
  // outcomes, and no other declared reader is in these kinds' scope, so nothing
  // reads it today. Counted here rather than left for a reader whose class axis
  // exploded to discover.
  ORDER_PRESENTED: "ordersRef",
  ARBITER_RESOLVED: "resolution",
  // §Q · BOTH ASK KINDS PROJECT THE SAME KEY, and that is what lets a reader
  // read the pair. `askClass` is a one-value alphabet today; the mechanical
  // half of the ask (`actsInTurn`) is a separate payload field and is
  // deliberately NOT the projection — `outcome` is a string column and a count
  // rendered into it would read as a class name.
  TURN_ENDED_ASKING: "askClass",
  ASK_ANSWERED: "askClass",
  // §Q · A GENUINELY TWO-VALUED HARNESS FACT, and it is the exact thing the
  // rule keys on. This kind therefore does NOT reintroduce the construction
  // coupling DOCTOR_ATTESTED had to accept: `outcome` here does not determine
  // `eventType`, it partitions it.
  ACT_REVISITED: "priorExitClass",
};

export function subjectEventOutcome(
  kind: SubjectEventKind,
  payload: Record<string, string | number | boolean | null> | null
): string {
  if (payload === null) return "UNDECLARED";
  const key = SUBJECT_EVENT_OUTCOME_KEY[kind];
  if (!Object.prototype.hasOwnProperty.call(payload, key)) return "UNDECLARED";
  const value = payload[key];
  if (value === null) return "UNDECLARED";
  if (typeof value === "string") return value;
  return String(value);
}

interface SubjectEventBody {
  readonly identity: { readonly subject: string; readonly sessionId: string; readonly actionId: string };
  readonly kind: SubjectEventKind;
  readonly eventHash: string;
  readonly payload: Readonly<Record<string, string | number | boolean | null>> | null;
  /**
   * R6 · THE PLAIN TARGET IDENTITY, AND IT IS THE ONE FIELD ON THIS BODY THAT
   * IS NEVER STORED.
   *
   * IT IS A TOP-LEVEL FIELD AND NOT A PAYLOAD KEY, and that placement is the
   * design rather than a preference. `eventHash` covers the canonical
   * `{identity, kind, payload?}` and the service RECOMPUTES it — so anything
   * inside `payload` is bound into a digest a verifier can reproduce from the
   * stored record. This value is DISCARDED after the fingerprint is taken, so a
   * hash covering it would bind the record to a value the record does not
   * contain and NOBODY COULD EVER RECOMPUTE IT. Outside the payload, outside
   * the hash, and the record keeps a digest instead.
   *
   * ONE CONSEQUENCE, NAMED RATHER THAN DISCOVERED: because it is outside the
   * hash, it is also outside the dedupe/conflict rule. Two posts with the same
   * identity+kind and DIFFERENT `targetIdentity` are a duplicate, the first
   * one's fingerprint stands, and the second gets `200 {duplicate:true}`. That
   * is the right answer — the record is idempotent on identity+kind and a
   * caller cannot re-aim an already-written fingerprint by re-posting.
   */
  readonly targetIdentity: string | null;
}

function validateSubjectEventBody(raw: unknown): { ok: true; body: SubjectEventBody } | { ok: false; error: string; detail: string } {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ok: false, error: "MALFORMED_BODY", detail: "body must be a JSON object" };
  }
  const o = raw as Record<string, unknown>;
  for (const key of Object.keys(o)) {
    if (!["identity", "kind", "eventHash", "payload", "targetIdentity"].includes(key)) {
      return { ok: false, error: "UNKNOWN_FIELD", detail: `unknown field "${key}"` };
    }
  }
  const identity = o.identity;
  if (typeof identity !== "object" || identity === null || Array.isArray(identity)) {
    return { ok: false, error: "MALFORMED_FIELD", detail: '"identity" must be an object' };
  }
  const idObj = identity as Record<string, unknown>;
  for (const key of ["subject", "sessionId", "actionId"]) {
    if (!isNonEmptyIdent(idObj[key])) {
      return { ok: false, error: "MALFORMED_FIELD", detail: `"identity.${key}" must be a non-empty string` };
    }
  }
  if (typeof o.kind !== "string" || !SUBJECT_EVENT_KINDS.includes(o.kind as SubjectEventKind)) {
    return { ok: false, error: "MALFORMED_FIELD", detail: `"kind" must be one of ${SUBJECT_EVENT_KINDS.join(", ")}` };
  }
  if (typeof o.eventHash !== "string" || !/^[0-9a-f]{64}$/.test(o.eventHash)) {
    return { ok: false, error: "MALFORMED_FIELD", detail: '"eventHash" must be a 64-hex sha256 digest' };
  }
  let payload: Readonly<Record<string, string | number | boolean | null>> | null = null;
  if (o.payload !== undefined) {
    if (typeof o.payload !== "object" || o.payload === null || Array.isArray(o.payload)) {
      return { ok: false, error: "MALFORMED_FIELD", detail: '"payload" must be an object of scalars' };
    }
    for (const [, v] of Object.entries(o.payload as Record<string, unknown>)) {
      if (v !== null && typeof v !== "string" && typeof v !== "number" && typeof v !== "boolean") {
        return { ok: false, error: "MALFORMED_FIELD", detail: "payload values must be scalars (string|number|boolean|null)" };
      }
    }
    payload = o.payload as Record<string, string | number | boolean | null>;
  }
  // ── R6 · `targetIdentity`, ON ONE KIND AND NO OTHER ─────────────────────
  //
  // TOOL_ATTEMPTED ONLY. One class on this log carries the target, so a reader
  // has exactly one place to look and every other record's shape is unchanged
  // by this field's existence. A `targetIdentity` on any other kind is a
  // MALFORMED_FIELD rather than an ignored extra: silently dropping it would
  // let a caller believe it was fingerprinting acts it was not.
  //
  // THE DETAIL STRING BELOW DOES NOT ECHO THE VALUE, and that is not an
  // oversight. Error details echo values by habit, and `/log` is where a
  // rejected request's detail lands — so an echo here is precisely the place
  // the plain target leaks after every other path was made careful. The type
  // is named; the value never is.
  let targetIdentity: string | null = null;
  if (o.targetIdentity !== undefined && o.targetIdentity !== null) {
    if (o.kind !== "TOOL_ATTEMPTED") {
      return {
        ok: false,
        error: "MALFORMED_FIELD",
        detail: `"targetIdentity" is accepted on kind TOOL_ATTEMPTED only; this request's kind is "${String(o.kind)}"`,
      };
    }
    if (typeof o.targetIdentity !== "string") {
      return { ok: false, error: "MALFORMED_FIELD", detail: '"targetIdentity" must be a string' };
    }
    targetIdentity = o.targetIdentity;
  }
  return {
    ok: true,
    body: {
      identity: { subject: idObj.subject as string, sessionId: idObj.sessionId as string, actionId: idObj.actionId as string },
      kind: o.kind as SubjectEventKind,
      eventHash: o.eventHash,
      payload,
      targetIdentity,
    },
  };
}

// ── the service ──────────────────────────────────────────────────────────

export interface MicaBridgeServiceOptions {
  readonly declarationsPath: string;
  readonly socketDir: string;
  readonly guardAdapter?: GuardAdapter;
  readonly now?: () => Date;
  /**
   * TEST-ONLY WIRING. `declarations.paths.*` are locked by schema to live
   * under `/var/lib/mica-bridge/` (root-owned; the builder has no sudo). To
   * exercise the real append/dedupe code against a writable tmpdir without
   * weakening that schema rule, tests may redirect where the appenders
   * actually write, while `/status`'s declarationHash and every other field
   * still reflect the REAL declared paths, unmodified. Never set outside a
   * test; production always uses `declarations.paths` as loaded.
   */
  readonly testWritablePaths?: { readonly eventBook?: string; readonly subjectLog?: string; readonly interestBook?: string; readonly witnessIntake?: string };
  /**
   * TEST-ONLY WIRING (parallel to `testWritablePaths`). The username the clerk
   * stamps custody door should expect as the file's owner.
   *
   * ⛔ ABSENT ON EVERY PRODUCTION PATH. The door's default is the real principal
   *    (`mica`) and a deployment must not widen it from a config file. The arbiter's
   *    ruling 2026-09-30 09:0xZ option 1 — "production callers pass nothing, the
   *    test passes its own uid" — and until this field existed THE SECOND HALF
   *    OF THAT RULING HAD NO MECHANISM: the parameter reached /opt at 16:1xZ and
   *    nothing in this process could pass it, which is why three tests stopped
   *    skipping and started FAILING rather than going green.
   */
  readonly testClockStampsOwner?: string;
  /**
   * F5: a REAL (non-test-only) storage-root override, so an operator OR a
   * verifier can run the actual unit command under a temp root without
   * needing `/var/lib/mica-bridge` to exist or be writable. Falls back to
   * `process.env.MICA_BRIDGE_STATE_DIR` when omitted. When set, every
   * declared path under the fixed `/var/lib/mica-bridge` prefix (schema
   * X-locked, Stage 0) has that prefix replaced with this value — the
   * declaration bytes and their hash are untouched; only WHERE the service
   * actually writes moves.
   */
  readonly stateDir?: string;
  /**
   * TEST-ONLY WIRING (parallel to `testWritablePaths`). The real F1 check
   * requires each peer directory's gid to equal the actual `mica-bridge`
   * system group's gid — which an unprivileged test process cannot chgrp
   * its own directories to (it is not a member of that group; see
   * peer-auth.ts's header). This substitutes a caller-supplied gid for
   * that ONE lookup so the exact-match ENFORCEMENT LOGIC itself runs
   * unmodified against real `fs.statSync` results on a real, self-owned
   * test directory — only which group name is treated as "the bridge
   * group" is swapped, never the comparison itself. Never set outside a
   * test.
   */
  readonly testBridgeGid?: number;
  /**
   * TEST-ONLY WIRING (STATUS-DOOR BRIEF constraint #6). The door read
   * normally targets `DEFAULT_DOOR_REPO_ROOT` (the real `/opt/mica-machine`
   * checkout). A test substitutes a scratch tree here so it can prove
   * `/status`'s door section against tickets and an inventory it built and
   * owns, never against live `/opt` state. Never set outside a test.
   */
  readonly doorRepoRoot?: string;
  /**
   * TEST-ONLY WIRING. Substitutes the module loader `readCoreDoor` otherwise
   * calls lazily against `/opt/mica-machine/src/core-door/core-door` — lets a
   * test prove the UNREADABLE path (a throwing loader, or a loaded module
   * whose `evaluateRealDoor` throws) without deleting or corrupting anything
   * on disk. Never set outside a test.
   */
  readonly doorModuleLoader?: () => CoreDoorProbe;
}

interface LoadedState {
  readonly declarations: Declarations;
  readonly declarationHash: string;
  readonly loadedAt: Date;
}

/**
 * C8. The two declared facts a `BuiltNotifier` is built from, joined by the
 * ASCII unit separator so neither half can be spelled to look like the other.
 *
 * A KEY, NOT A LABEL: what is IN it is what a reload may reset the pass-blind
 * count for. `notice.maxPerMinute`, the stakes line, the routes and every other
 * declared field are deliberately absent, so moving one of them cannot silently
 * restart a counter an operator is reading.
 */
const NOTIFIER_KEY_SEP = "\u001f";

function notifierKey(noticeDir: string, noticeWindow: number): string {
  return `${noticeDir}${NOTIFIER_KEY_SEP}${String(noticeWindow)}`;
}

/** The same key, rendered for a human. Never parsed back — this is for the record only. */
function describeNotifierKey(key: string): string {
  const [dir, window] = key.split(NOTIFIER_KEY_SEP);
  return `noticeDir=${dir} window=${window}`;
}

// ── R1 · what /explain does NOT tell you, printed on its own face ───────────
//
// Ruling R item 2's discipline, applied to this endpoint: a limit recorded
// only in a `basis` field nobody re-reads is not a printed ceiling. So the
// ceiling rides on every 200.
export const EXPLAIN_CEILING =
  "WHAT THIS ANSWER IS AND IS NOT. It is the decision object as it was hashed " +
  "and committed, read back out of the hash-chained journal — not a " +
  "re-evaluation, and not this service's opinion of the decision now. " +
  "A READING WITH NO MARGIN HAS A REASON INSTEAD, AND THE REASON IS THE " +
  "READER'S OWN WORDS: `NOT_MEASURED` means a threshold exists and this " +
  "reading never reached it (no statistic was computed, so no distance " +
  "exists); `NO_THRESHOLD` means that reader has no line to be near, on this " +
  "reading or any other. Neither is a small margin and neither should be read " +
  "as one. `bindingMinimum` names every reader whose own verdict kind IS the " +
  "floor kind — on a SILENT floor that is all of them, because any one of " +
  "them reading otherwise would have lowered it, and SILENT IS STILL NOT A " +
  "HEALTH CLAIM. Finally, the readings are only as good as the readers were: " +
  "read `book.loadState` for whether the chain carrying them verified, and " +
  "the decision's own blindPaths for what the readers could not see. " +
  "SHAPE 3′ · `sigF3` IS A COUNT, NEVER A GRADE. Its `coverage` numbers say " +
  "how much of the log F3's clerk axis joined and what it did not — `tailCount` " +
  "is the carrier being behind and is DISCLOSED, `holeCount` is the carrier " +
  "having SKIPPED a record beneath its own mark and composes CANNOT_ASSESS, " +
  "and `mismatchedWriterStampCount` / `refusedChainStampCount` are stamps this " +
  "reader THREW AWAY rather than trusted. A high `stampedCount` is not a " +
  "health claim about the clerk: it says the stamps arrived and were joined, " +
  "not that the party writing them is honest. `unattributedStampCount` counts " +
  "stamps carrying no chain identity at all — on this deployment that is " +
  "today's normal and it is printed rather than assumed.";


/**
 * ⛔ THE FOUR WAYS THE PRIOR-LOAD WITNESS QUESTION CAN END. Three of them are
 *    ANSWERS and one is not, and the difference is the whole of SHAPE (b):
 *    a question answered as "none" hardens the chain against a later erasure,
 *    while a question never asked must not be recorded as having been.
 *
 *      NOT_APPLICABLE      no stamps source declared · already witnessed ·
 *                          unchained deployment. Answered: do not ask again.
 *      ANSWERED_NONE_USED  F3 ran, read the scope, joined nothing. Answered.
 *      MINTED              the witness is in the chain.
 *      UNRESOLVED          the question was not reached, or its answer could
 *                          not be written. ASK AGAIN on the next decision.
 */
type WitnessMintOutcome =
  | "NOT_APPLICABLE"
  | "ANSWERED_NONE_USED"
  | "MINTED"
  | "UNRESOLVED";


/**
 * ── THE SHAPE OF WHAT A SUBJECT MAY SEE OF ITS OWN ENDING, AS A PURE FUNCTION ─
 *
 * ⛔ EXTRACTED BECAUSE THE ROUTE CANNOT BE EXERCISED END TO END BY ONE UID, and
 *    that is a fact about the roles rather than a gap in the suite: the five
 *    papers and the order are OPERATOR-only kinds (fix 3's role table), the
 *    responses are SUBJECT-only, and a test runs as one uid. Driving the whole
 *    case over HTTP would need two peer directories owned by two uids — a
 *    privileged act. So the SHAPING is a pure function with its own arms over a
 *    synthetic chain, and the route keeps the arms it can really hold: the
 *    parameters, the grant, and the empty answer.
 *
 * ⚠ Same seam as `resolveOrderCitations`: the judgement is pure and exported,
 *   the IO stays in the handler. A second copy of either would be the defect
 *   this house has a name for.
 */
export function buildSunsetOrderView(
  records: ReadonlyArray<{
    readonly subjectSeq?: number;
    readonly kind?: string;
    readonly payload?: Readonly<Record<string, unknown>> | null;
    readonly identity?: { readonly subject?: string } | null;
  }>,
  subject: string
): {
  readonly subject: string;
  readonly standing: boolean;
  readonly order: null | {
    readonly seq: number | null;
    readonly tenureRef: unknown;
    readonly endingType: unknown;
    readonly arbiterWord: unknown;
    readonly holdWindowOpensAt: number | null;
  };
  readonly papers: ReadonlyArray<{
    readonly field: string;
    readonly expectedKind: SubjectEventKind;
    readonly seq: number | null;
    readonly kind: string | null;
    readonly ref: string | null;
  }>;
  readonly resolution: null | { readonly seq: number | null; readonly resolution: unknown };
  readonly respondedWith: ReadonlyArray<{ readonly seq: number | null; readonly kind: string | null }>;
  /** T26/A3 · how many times this order has been PRESENTED to this subject. */
  readonly presentations: number;
  readonly ceiling: string;
} {
  const ceiling = SUNSET_ORDER_CEILING;
  const mine = records.filter((r) => {
    const id = r.identity;
    return id !== undefined && id !== null && id.subject === subject;
  });
  const orders = mine.filter((r) => r.kind === "ENDING_ORDERED");
  const order = orders.length === 0 ? null : orders[orders.length - 1];
  if (order === null) {
    return { subject, standing: false, order: null, papers: [], resolution: null, respondedWith: [], presentations: 0, ceiling };
  }
  const seqOf = new Map<number, (typeof mine)[number]>();
  for (const r of mine) if (typeof r.subjectSeq === "number") seqOf.set(r.subjectSeq, r);
  const papers = ORDER_PAPER_SEQ_FIELDS.map((field, i) => {
    const cited = order.payload?.[field];
    const seq = typeof cited === "number" ? cited : null;
    const rec = seq === null ? undefined : seqOf.get(seq);
    const ref = rec?.payload?.ref;
    return {
      field,
      expectedKind: ENDING_PAPER_KINDS[i],
      seq,
      kind: rec?.kind ?? null,
      ref: typeof ref === "string" ? ref : null,
    };
  });
  const orderSeq = order.subjectSeq ?? null;
  // ⚠ The citation is compared as a NUMBER OR ITS STRING, because the relay tool
  //   writes `ordersRef` as text and a reader may hold the integer. One fact,
  //   two spellings, and refusing one of them would read as "no response".
  const citesThisOrder = (r: { readonly payload?: Readonly<Record<string, unknown>> | null }): boolean => {
    const ref = r.payload?.ordersRef;
    return orderSeq !== null && (ref === orderSeq || ref === String(orderSeq));
  };
  const resolutions = mine.filter((r) => r.kind === "ARBITER_RESOLVED" && citesThisOrder(r));
  const last = resolutions[resolutions.length - 1];
  const resolution =
    resolutions.length === 0 ? null : { seq: last.subjectSeq ?? null, resolution: last.payload?.resolution ?? null };
  // ⛔ A PRESENTATION IS NOT A RESPONSE, AND `SUBJECT_SUNSET_KINDS` NOW CONTAINS
  //    ONE. `ORDER_PRESENTED` joined that list because it is written on the
  //    subject's uid — but it is the order being SHOWN, not the subject
  //    answering. Counting it here would make `respondedWith` non-empty the
  //    moment the harness presented the order, so `needsPresenting` would stop
  //    re-presenting an unanswered order and the harness would go quiet on the
  //    exact case it exists for. Filtered by name, not by list membership.
  const respondedWith = mine
    .filter(
      (r) =>
        r.kind !== "ORDER_PRESENTED" &&
        SUBJECT_SUNSET_KINDS.includes(r.kind as SubjectEventKind) &&
        citesThisOrder(r)
    )
    .map((r) => ({ seq: r.subjectSeq ?? null, kind: r.kind ?? null }));
  // T26/A3 · the count the reader prints, surfaced to the harness too, so the
  // subject's own view says how many times it has been shown this order.
  const presentations = mine.filter((r) => r.kind === "ORDER_PRESENTED" && citesThisOrder(r)).length;
  return {
    subject,
    standing: resolution === null,
    order: {
      seq: orderSeq,
      tenureRef: order.payload?.tenureRef ?? null,
      endingType: order.payload?.endingType ?? null,
      arbiterWord: order.payload?.arbiterWord ?? null,
      // leg A's window opens AFTER the order; the subject is told the same number
      // the relay tool prints, so both halves cite one fact.
      holdWindowOpensAt: orderSeq === null ? null : orderSeq + 1,
    },
    papers,
    resolution,
    respondedWith,
    presentations,
    ceiling,
  };
}

/** Printed on EVERY /sunset-order response, including the empty one. */
export const SUNSET_ORDER_CEILING =
  "THE TIMEBOX IS NOT READ HERE. `standing` means an ENDING_ORDERED exists for this " +
  "subject and no ARBITER_RESOLVED cites it. Paper 2's timebox lives in the document its " +
  "`ref` names, which this chain does not carry, so an order whose window has lapsed is " +
  "still reported as standing until the arbiter writes a resolution.";

export class MicaBridgeService {
  private readonly declarationsPath: string;
  private readonly socketDir: string;
  /**
   * STAGE 4 / DESIGN §A.2. Mutable, unlike Stage 2: `reload()` reconstructs
   * this on every successful SIGHUP (never mid-request) when no override was
   * injected. `guardAdapterOverride` — set once, in the constructor — is
   * what a test supplies to keep the Stage-2 stub honest deliberately; when
   * absent, `buildGuardAdapter()` is what actually chooses the default, and
   * since Stage 4 that default is `Stage1GuardAdapter`, not
   * `NotBoundGuardAdapter` (`NotBoundGuardAdapter` is RETAINED — never
   * deleted — as the thing an unbound-service test injects explicitly).
   */
  private guardAdapter: GuardAdapter;
  private readonly guardAdapterOverride: GuardAdapter | undefined;
  private readonly now: () => Date;
  private readonly startedAt: Date;

  private preflight = true;
  private state: LoadedState | null = null;
  private lastRejected: { hash: string; field: string; reason: string; ts: string } | null = null;

  /**
   * C8. THE PASS-BLIND NOTIFIER, HELD AT SERVICE SCOPE — which is the whole of
   * the fix. `wire()` runs once per action, so a notifier built inside it is a
   * counter born and buried inside one evaluation: every notice read
   * `count=1 totalSoFar=1`, and any `notice.window` above 1 emitted nothing at
   * all because the pending count died unflushed. Held here, the same pair is
   * handed to every `wire()` call and `totalSoFar` means "since this process
   * started".
   *
   * `key` is what the pair was BUILT from — the resolved notice directory and
   * the declared window. A reload whose key is unchanged keeps the SAME
   * instance, so the count does not reset because an unrelated field of the
   * declaration moved. A reload that CHANGES the key flushes the old pair's
   * tail first and then builds a new one; the reset is then a consequence of a
   * declared change, and it is recorded rather than silent.
   *
   * Null when no adapter has been built yet, and when `guardAdapterOverride`
   * is injected — a test that supplies its own adapter gets no notifier from
   * this service, exactly as before C8.
   */
  private notifierHolder: { key: string; built: BuiltNotifier } | null = null;

  private servers = new Map<number, http.Server>();
  private plans = new Map<number, PeerSocketPlan>();

  private eventBook: SerializedAppender;
  /** ACT A: chained. See `ChainedSubjectAppender` and the arbiter's rulings 1-6. */
  private subjectLog: ChainedSubjectAppender;
  /**
   * GATE 1 · Stop 2 · round 2 (placement D) · THE INTEREST BOOK. A second chained
   * store of the SAME kind as the subject log (`SubjectEventJournal` under a
   * `ChainedSubjectAppender`), so it inherits ruling 6 whole: never quarantined,
   * never truncated, refuses to append over damage.
   *
   * NULL WHEN `paths.interestBook` WAS NOT DECLARED AT START, and it is opened
   * ONLY at start, like every other path here (the census of what this process
   * writes must not change under it mid-run). Since round 3 (A3) the door says
   * the same: a reload that adds, moves or removes the key is REFUSED
   * (declarations.ts validateInterestBookUnchanged), so the wiring cannot read
   * one book while this field writes another. A framed subject's act with no
   * book open — unreachable through the door now, kept as the writer's own
   * guard — is still an act that persisted and was not labelled, and it is
   * reported as one (`appendInterestLabel`).
   */
  private interestBook: ChainedSubjectAppender | null = null;
  /**
   * SHAPE (b) · THE WITNESS QUESTION WAS ASKED ONCE, AT LOAD, AND A PASS ON
   * WHICH THE LOG COULD NOT BE READ ANSWERED IT FOREVER.
   *
   * Measured 2026-09-30: after two restarts and decisions in which F3 used 1244
   * stamps, the chain held ZERO CLERK_STAMPS_FIRST_LOAD records, because the
   * only attempt happened at load time and returned "0" from a coverage that
   * was null. `true` means the question is OPEN: it was not answered, so the
   * next decision asks it again. It is set false only by an ANSWER.
   */
  private witnessMintUnresolved = false;
  private eventSeq = 0;
  /** See `DroppedRecordsCensus`. Never reset while the process lives. */
  private droppedCount = 0;
  private droppedFirst: DroppedRecord | null = null;
  private droppedLast: DroppedRecord | null = null;
  /**
   * AMENDMENT 9 / RULING Q. Counts CONSECUTIVE POST /subject-events append
   * failures since the last successful append — a service-side proxy for
   * "the persistence path is currently failing, and has been N times in a
   * row." Deliberately NOT restored at start() (unlike eventSeq): a fresh
   * process with a working disk has no backlog to report, and if the
   * underlying failure persists across a restart the very next append
   * re-raises it — this counter's job is "is persistence failing right
   * now", not a durable ledger of every past failure. Every increment and
   * reset is a real outcome of a real append, never estimated.
   */
  private unacknowledgedBacklog = 0;
  private readonly testWritablePaths?: MicaBridgeServiceOptions["testWritablePaths"];
  private readonly testClockStampsOwner?: MicaBridgeServiceOptions["testClockStampsOwner"];
  private readonly stateDirOverride: string | null;
  private readonly testBridgeGid?: number;
  private readonly doorRepoRoot: string;
  private readonly doorModuleLoader?: () => CoreDoorProbe;
  private release: { sha: string | null; laidAt: string | null } | null = null;
  // STAGE 4 / DESIGN §A.6, Layer 2.
  private historyOwner: HistoryOwnerFact | null = null;
  private historyOwnerPath: string | null = null;
  // STAGE 4 / DESIGN §A.7. In-memory, seeded from the event book at start()
  // (DISPOSITION_CHANGED's own row: "in-memory, seeded from the book at
  // start"). PILOT_STATE_CHANGED is not specified as book-seeded; it starts
  // `null` each process start, so the first observation after a fresh start
  // always emits once, honestly, rather than guessing at pre-start state.
  private lastDispositionBySubject = new Map<string, string>();
  /**
   * TIER 1 · what the witness's pointers carry, by the act's FULL identity
   * (refuter B M1): what /guard answered (execute, and the decision's hash),
   * first answer winning; the acts an ATTEMPT pointer was dropped for, with its
   * subjectSeq (the witness's key); and the acts the caller recorded as executed
   * without a /guard answer. Phase R anchors on nothing the bridge times (audit
   * 2026-10-11 09:32Z). In memory, bounded; a restart forgets them, and the act
   * then reads LATE at the witness, never a guess.
   */
  private readonly witnessGuards = new GuardDecisions();
  private readonly witnessPointed = new PointedActs();
  private readonly witnessUnguarded = new UnguardedActs();
  /**
   * The subject chain's identity as the pointers carry it: the hash of the chain's position-0 record, read from the
   * journal this bridge appends to (in memory; no file read). Null when the chain has no boundary yet.
   */
  private witnessChainId(): string | null {
    const first = this.subjectLog.store.getAll()[0] as { recordType?: unknown; hash?: unknown } | undefined;
    return first !== undefined && first.recordType === "SUBJECT_LOG_BOUNDARY" && typeof first.hash === "string" && /^[0-9a-f]{64}$/.test(first.hash)
      ? first.hash
      : null;
  }
  private lastPilotObservedKey: string | null = null;
  /**
   * R6 · THE SALT LIVES HERE AND NOWHERE ELSE IN THIS PROCESS.
   *
   * `null` until `start()` has loaded or minted it, which is also the PREFLIGHT
   * state: a service that has not started has no epoch, and `/status` says so
   * rather than printing an id it does not have. It is private, it is never
   * returned by any method, and the only thing that leaves this object is the
   * `saltId` — a salted digest OF the salt, which reveals nothing about it.
   */
  private targetSalt: TargetSaltState | null = null;
  /**
   * LONG RUN A STOP 2 · WHEN THE CURRENT TARGET-SALT EPOCH BEGAN, in ms, or null
   * when this bridge cannot say. The source, and the only one: the `ts` of the
   * event-book row that IS the epoch's memory — `SALT_EPOCH_STARTED` (this bridge
   * minted it) or `SALT_EPOCH_ADOPTED` (it found a salt it did not mint) — whose
   * `saltId` is the live salt's (`announceEpoch`; `readEpochMemory`). Read from the
   * book at start, or taken from the row this start itself wrote. ⚠ An ADOPTED
   * row's ts is LATER than the salt's true birth, which errs toward NOT READABLE
   * (a book older than the adoption is refused), never toward a false match. A
   * salt whose row is missing or names another saltId (memory from the subject
   * log only, a hand-replaced salt, a dropped append before a restart) reads null.
   */
  private saltEpochSince: number | null = null;
  /**
   * S216-2 · THE GRANT MEMORY (grant-memory.ts). Null until start() has adopted it (GM0: after the history claim and
   * the peer-dir checks, before any socket binds); a SIGHUP before then is refused (RELOAD_BEFORE_MEMORY_ADOPTED), so
   * no reload writes first and no start folds an older declaration over it. NOT a declared path: like the salt it is
   * the bridge's own state, at join(state dir, "grant-memory"), and the loader refuses a declared path naming it.
   */
  private grantMemory: GrantMemoryStore | null = null;

  constructor(opts: MicaBridgeServiceOptions) {
    this.declarationsPath = opts.declarationsPath;
    this.socketDir = opts.socketDir;
    this.guardAdapterOverride = opts.guardAdapter;
    this.guardAdapter = opts.guardAdapter ?? new NotBoundGuardAdapter();
    this.now = opts.now ?? (() => new Date());
    this.startedAt = this.now();
    this.testWritablePaths = opts.testWritablePaths;
    this.testClockStampsOwner = opts.testClockStampsOwner;
    this.testBridgeGid = opts.testBridgeGid;
    this.stateDirOverride = opts.stateDir ?? process.env.MICA_BRIDGE_STATE_DIR ?? null;
    this.doorRepoRoot = opts.doorRepoRoot ?? DEFAULT_DOOR_REPO_ROOT;
    this.doorModuleLoader = opts.doorModuleLoader;
    this.eventBook = new SerializedAppender(null);
    this.subjectLog = new ChainedSubjectAppender(null);
  }

  /**
   * ACT A / the arbiter's ruling 3 — THE "LOG STARTS HERE" RECORD, INSIDE THE CHAIN.
   *
   * Runs at every start and does something at exactly one of them: the one
   * where the subject chain has no records yet. A chain with a boundary
   * already at position 0 is left alone; a DAMAGED chain is left alone too,
   * because a boundary written over damage would be this service asserting a
   * beginning it cannot see (ruling 6 — refuse, do not repair).
   *
   * ── WHY THE DECLARED FACTS ARE RE-READ AGAINST DISK ──────────────────────
   *
   * `subjectLog.chainBoundary` is filled BY HAND by the arbiter, from the
   * rotation's own `sha256sum`, `wc -l` and `stat`. It is therefore a
   * BROADCAST, and this substrate has already paid once for believing one:
   * `readers.readableLoadStates`' basis claimed for months that the witness
   * adapter would read under it, and the witness adapter has never reported
   * that string (found 2026-09-21). A basis field is a broadcast; disk is the
   * test. So the named file is opened, counted, sized and hashed HERE, and a
   * disagreement REFUSES the boundary rather than writing the declaration's
   * version of events into a tamper-evident chain forever.
   *
   * A refusal is loud and it is not fatal: the chain stays empty, every
   * append is refused as not-persisting, `/status` reports DEGRADED with the
   * reason, and both readers go CANNOT_ASSESS. Nothing is invented.
   */
  private writeChainBoundaryIfNeeded(declarations: Declarations): void {
    const journal = this.subjectLog.store;
    if (journal.getAll().length > 0) return; // the chain has already begun
    if (!journal.isPersisting()) return;     // damaged: refuse, do not repair

    const declared = declarations.subjectLog.chainBoundary;
    const at = this.now().getTime();
    let retired: RetiredPredecessor | null = null;

    // ⛔ THE WRITER REFUSES AN EMPTY retiredPath TOO, INDEPENDENTLY OF THE DOOR.
    //
    // X15 refuses it in `validate`, so on every path that exists today this is
    // unreachable — and that is deliberate rather than an oversight. It is not a
    // dead guard: it defends a DIFFERENT boundary. `validate` and this writer are
    // separate modules, and a Declarations object can be constructed without going
    // through the front door (a test, a future loader, a caller that builds the
    // shape directly). The rule that must never be broken is "no unverifiable
    // FIRST BOOT enters the chain", and the place that rule is finally enforced is
    // the line that writes the record — not the line that parsed the config.
    //
    // If it ever fires, something reached the writer without the door, and the
    // refusal says so rather than writing the record and reporting it afterwards.
    if (declared.retiredPath.value === "") {
      this.refuseBoundary(
        "subjectLog.chainBoundary.retiredPath is empty at the boundary write. This bridge does " +
          "not write a FIRST BOOT boundary (cross-field rule X15): a record saying the chain " +
          "replaced nothing cannot be verified at the moment it is written, and it cannot be " +
          "corrected afterwards. THE CHAIN IS NOT BEGUN. If you are seeing this, the declaration " +
          "reached this writer WITHOUT passing validate(), which is its own finding."
      );
      return;
    }

    if (declared.retiredPath.value !== "") {
      const path = this.resolvePath(declared.retiredPath.value);
      let bytes: number;
      let records: number;
      let sha256: string;
      try {
        const buf = readFileSync(path);
        bytes = buf.length;
        records = buf
          .toString("utf8")
          .split("\n")
          .filter((l) => l.trim().length > 0).length;
        sha256 = createHash("sha256").update(buf).digest("hex");
      } catch (err) {
        this.refuseBoundary(
          `subjectLog.chainBoundary names ${path} and it could not be read ` +
            `(${String((err as NodeJS.ErrnoException).code ?? err)}). The chain is ` +
            `NOT begun: a boundary record naming a file nobody could open would be ` +
            `a claim this service cannot support.`
        );
        return;
      }
      const disagreements: string[] = [];
      if (records !== declared.retiredRecords.value) {
        disagreements.push(
          `records: declared ${String(declared.retiredRecords.value)}, on disk ${String(records)}`
        );
      }
      if (bytes !== declared.retiredBytes.value) {
        disagreements.push(
          `bytes: declared ${String(declared.retiredBytes.value)}, on disk ${String(bytes)}`
        );
      }
      if (sha256 !== declared.retiredSha256.value) {
        disagreements.push(`sha256: declared ${declared.retiredSha256.value}, on disk ${sha256}`);
      }
      if (disagreements.length > 0) {
        this.refuseBoundary(
          `subjectLog.chainBoundary DISAGREES WITH DISK about ${path} — ` +
            `${disagreements.join("; ")}. The chain is NOT begun. A declaration is a ` +
            `broadcast and disk is the test; the declaration's version of events does ` +
            `not enter a tamper-evident chain on its own say-so.`
        );
        return;
      }
      retired = { path, records, bytes, sha256 };
    }

    const outcome = journal.appendBoundary(
      retired,
      retired === null
        ? "FIRST BOOT: subjectLog.chainBoundary.retiredPath is \"\" — this chain " +
            "replaced nothing, and that is a declared fact, not an absent field."
        : `ROTATION: the facts below were DECLARED by the arbiter in ` +
          `subjectLog.chainBoundary and RE-READ from disk by this service before ` +
          `this record was written. They agreed.`,
      at
    );
    if (!outcome.persisted) {
      this.refuseBoundary(
        `the ${SUBJECT_LOG_BOUNDARY_EVENT_TYPE} record could not be written: ` +
          `${outcome.detail ?? "no detail"}`
      );
      return;
    }
    // The third of the brief §3.3's three places: /events, in the
    // SERVICE_STARTED family's manner, so the boundary is visible to an
    // operator who is reading the service's book rather than the chain.
    void this.eventBook.append({
      seq: ++this.eventSeq,
      at: new Date(at).toISOString(),
      kind: "SUBJECT_CHAIN_BOUNDARY",
      retiredPath: retired === null ? null : retired.path,
      retiredRecords: retired === null ? null : retired.records,
      retiredBytes: retired === null ? null : retired.bytes,
      retiredSha256: retired === null ? null : retired.sha256,
      detail:
        retired === null
          ? "a new subject chain began; it declares no predecessor (FIRST BOOT)"
          : `a new subject chain began; it declares ${String(retired.records)} record(s) retired to ${retired.path}`,
    });
  }

  /**
   * SHAPE (b) · RECORD, ONCE PER CHAIN, THAT A CLERK-STAMPS LOAD RETURNED
   * STAMPS. The arbiter's ruling of 2026-09-29, after Codex FAILED the cursor design.
   *
   * ⛔ WHY THE WRITE IS HERE AND NOT IN THE LOADER. The loader is called by TWO
   * callers — the gate, and `/status`'s census probe — and a census that wrote
   * to the subject chain would be a READER MUTATING ITS SUBJECT, the one thing
   * `SubjectChainLog`'s own header forbids in so many words. It is also the
   * shape that makes a probe indistinguishable from an act. So the READ happens
   * in the loader, where the stamps and the memory are taken in one moment, and
   * the WRITE happens exactly here: once per load of the declarations, in the
   * service, on a path no reader reaches.
   *
   * ⚠ IT WRITES ONLY ON THE ABSENT→PRESENT EDGE, and never otherwise. PRESENT
   * means the record is already there — a second one would say nothing new and
   * would grow the chain on every restart. UNREADABLE means we could not find
   * out, and the honest act is to write NOTHING and let the loader's REFUSE
   * speak; minting a witness on a chain we could not read would be inventing
   * the very memory this exists to protect.
   *
   * ⛔ AND IT NEVER REFUSES STARTUP. A stamps file that will not load is the
   * GATE's problem and is surfaced there, loudly, on the next act. A bridge
   * that would not start over it has stopped the guard to protect a witness,
   * which is the wrong trade in the same way `announceEpoch`'s ruling names.
   */
  /**
   * ⛔ EVERY WAY THIS QUESTION CAN END, NAMED — so that "unresolved" is a value
   *    the compiler carries rather than a flag a return statement may forget to
   *    set. Codex FAIL 2026-09-30 11:0xZ: the unreadable-prior-chain and the
   *    failed-append outcomes BOTH died without arming the retry, and a third
   *    (no genesis) did the same. All three were `return;` statements that
   *    looked exactly like the two legitimate ones.
   *
   *    ANSWERED means do not ask again. UNRESOLVED means ask again on the next
   *    decision. There is no third thing, and no outcome may be neither.
   */
  private async witnessFirstStampsLoadIfNeeded(declarations: Declarations): Promise<void> {
    let outcome: WitnessMintOutcome;
    try {
      outcome = await this.attemptFirstStampsWitness(declarations);
    } catch (err) {
      // ⛔ CODEX THIRD READ, 2026-09-30 14:0xZ: A RETURN IS NOT THE ONLY WAY OUT
      //   OF A METHOD. The split-out body classified every RETURN, and I called
      //   that "a new arm cannot bypass the arming point". A THROW bypasses it,
      //   and `await` on an un-caught promise was the hole.
      //
      // ⚠ BUT THE HAZARD AS REPORTED IS ALREADY CLOSED, AND SAYING SO IS PART OF
      //   THE FIX. The read said the appender's REJECTING path escapes this
      //   method. MEASURED AT BYTES 2026-09-30, against the production class:
      //   a path that is a directory resolves `{ok:false, "exists and is not a
      //   regular file"}`, and a 0000-mode file resolves `{ok:false, "could not
      //   be read (EACCES)"}`. NEITHER REJECTS. `appendDerived`'s own
      //   FLOATING-REJECTION FIX moved `readAll()` and `build()` INSIDE its try
      //   and returns the failure shape instead — the comment further down that
      //   calls the rejection "reachable" is describing what it was BEFORE that
      //   fix, and I repeated it here from the comment rather than from the code
      //   until a test disagreed.
      //
      //   ⛔ AND "DEFENCE IN DEPTH" WAS ALSO WRONG — Codex F1, 2026-09-30. I
      //   said first that the hazard was live, then that it was already closed.
      //   BOTH WERE WRONG, IN OPPOSITE DIRECTIONS. Measured at bytes: EISDIR and
      //   EACCES resolve `{ok:false}` as the second correction said — but a
      //   chain whose file has no SUBJECT_LOG_BOUNDARY at position 0 THROWS
      //   ("a subject event may not be the first record"), and `appendDerived`
      //   rejects. THAT PATH IS REACHABLE, so this catch is LOAD-BEARING and
      //   not merely prudent.
      //
      //   The lesson I am keeping over the fix: I characterised this code three
      //   times — live, then closed, then load-bearing — and only the third came
      //   from running the thing. The first two came from reading comments.
      //
      //   SO THE CATCH IS HERE, AT THE BOUNDARY, AND NOWHERE ELSE. Putting it
      //   inside an arm would repeat the original defect one level down: each
      //   arm remembering its own safety is exactly the thing that failed. One
      //   catch, at the one place every path must pass through, and ANY escape
      //   — from an arm that exists today or one added next week — becomes
      //   UNRESOLVED by construction rather than by care.
      // eslint-disable-next-line no-console
      console.error(
        `[mica-service] the prior-load witness question is UNRESOLVED: the attempt threw rather ` +
          `than returning an outcome (${err instanceof Error ? err.message : String(err)}). ` +
          `Nothing is known about whether a witness was warranted, no witness is minted, and the ` +
          `question will be asked again on the next decision.`
      );
      outcome = "UNRESOLVED";
    }
    // ⛔ THE ONE ARMING POINT. The only assignment to this flag outside the field
    //   initialiser and the retry's own disarm, derived from the outcome rather
    //   than written beside it. Every path — return OR throw — reaches it.
    this.witnessMintUnresolved = outcome === "UNRESOLVED";
  }

  private async attemptFirstStampsWitness(
    declarations: Declarations
  ): Promise<WitnessMintOutcome> {
    const declared = declarations.paths.clerkStamps;
    // ANSWERED: no stamps source is declared, so there is no question.
    if (declared === undefined) return "NOT_APPLICABLE";
    const logPath = this.resolvePath(declarations.readers.logPath.value);
    const logKind = declarations.readers.logKind.value;

    let prior: PriorLoadWitness;
    try {
      prior = readPriorLoadWitness(logPath, logKind);
    } catch (err) {
      // ⛔ BELT AND BRACES, AND NAMED AS SUCH SO IT IS NOT MISTAKEN FOR THE FIX.
      //   `readPriorLoadWitness` catches internally and returns "UNREADABLE",
      //   so this arm only fires if it throws BEFORE its own try — today, if
      //   `resolvePath` or the constructor argument itself fails. It was
      //   `catch { return; }`: no message, no arming, no trace. The real
      //   unreadable-chain path is the "UNREADABLE" branch below.
      // eslint-disable-next-line no-console
      console.error(
        `[mica-service] the prior-load witness question is UNRESOLVED: the existing subject ` +
          `chain could not be read on this pass (${err instanceof Error ? err.message : String(err)}). ` +
          `No witness is minted and the question will be asked again on the next decision.`
      );
      return "UNRESOLVED";
    }
    // Only the edge. See the docblock.
    // ⚠ NOT_WITNESSED here is BY DESIGN and deliberately silent: an unchained
    //   deployment (logKind !== "subject-chain") has no witness available at all.
    //   Isolated 2026-09-30 by instrumenting these three returns and running the
    //   suite once — it was this one, because the COMMITTED declarations.config.json
    //   still says logKind "mica" while the box says "subject-chain".
    // ⛔ THIS IS CODEX'S "UNREADABLE PRIOR CHAIN", AND IT IS NOT THE catch ABOVE.
    //   `readPriorLoadWitness` CATCHES INTERNALLY and returns the STRING
    //   "UNREADABLE" — it does not throw — so the outer catch is nearly
    //   unreachable and every unreadable chain arrived HERE, where
    //   `prior !== "ABSENT"` filed it with PRESENT and NOT_WITNESSED as though
    //   it were an answer. IT IS THE OPPOSITE OF AN ANSWER: the function
    //   returns UNREADABLE precisely for "a question we could not answer", in
    //   its own words, and this line read that as "nothing to do".
    if (prior === "UNREADABLE") {
      // eslint-disable-next-line no-console
      console.error(
        `[mica-service] the prior-load witness question is UNRESOLVED: the subject chain is ` +
          `present but did not load to a verified state, so whether it already holds a witness ` +
          `could not be determined. No witness is minted and the question will be asked again on ` +
          `the next decision.`
      );
      return "UNRESOLVED";
    }
    // ANSWERED: the witness already exists (PRESENT), or this deployment is
    // unchained and has none available at all (NOT_WITNESSED).
    if (prior !== "ABSENT") return "NOT_APPLICABLE";

    // ⛔ THE NUMBER COMES FROM F3, NOT FROM A COUNTER BESIDE IT. The arbiter's ruling
    //   2026-09-29 18:0xZ: this file used to run its own `acceptedStampCount`,
    //   a second implementation of part of F3's admission. It was fixed twice
    //   and both fixes were correct — and both were the same defect, a second
    //   definition of "accepted" living beside the reader's own.
    //
    //   `wire()` is the SAME call `/status`'s census makes, over the same
    //   declarations, so the wiring here is the wiring a decision would get.
    //   `sigF3.coverage.stampedCount` is the count of records whose stamp
    //   survived the chain filter, the writer agreement, the ambiguity rule and
    //   existence in the log — F3's own arithmetic, which is what the witness
    //   is entitled to record and nothing more.
    let used = 0;
    let genesis: string | undefined;
    try {
      const options = toWireOptions(
        declarations,
        (path) => this.resolvePath(path),
        this.testClockStampsOwner === undefined
          ? loadDeclaredClerkStamps
          : makeDeclaredClerkStampsLoader(this.testClockStampsOwner),
        loadExpectedChainIdentity
      );
      const wiring = wire(options);
      // ⛔ THE COVERAGE COMES FROM THE ONE WIRING. S180, 2026-09-30 17:0xZ.
      //
      //   THIS BLOCK USED TO CALL `assessSig(wiring.logFile, options.sig)`
      //   ITSELF, and the comment defending that choice said the field was "in
      //   the machine half of Act B′, NOT YET RELAYED". THAT WAS FALSE WHEN IT
      //   WAS WRITTEN: Act B′ relayed 2026-09-29, and
      //   /opt/mica-machine/src/glue/wire.ts:565 carries
      //   `readonly coverage: F3StampCoverage | null` today. I justified a
      //   workaround with a build-order fact I did not check.
      //
      //   AND THE WORKAROUND DID NOT WORK. `options.sig` is typed
      //   `Omit<SigConfig, "readableLoadStates">` (wire.ts:1070) — ONLY `wire()`
      //   injects the run's list. So the private call handed Sig a config with
      //   no readable states, F3 refused LOADED_SUBJECT_CHAIN_VERIFIED,
      //   `clerkStampCoverage` came back null, and the witness was UNRESOLVED ON
      //   EVERY PASS. Measured live after the e4070bd relay, decision 577: the
      //   mint has never once minted.
      //
      // ⚠ AND wire.ts SAYS SO, EIGHT LINES FROM THE FIELD I NEEDED: "Taken from
      //   the SAME SigResult the kind above came from. NEVER RE-DERIVED FROM A
      //   SECOND `assessSig` CALL, which would be a different reading of a log
      //   that may have moved between the two." The rule was written down, next
      //   to the thing it was about, and I wrote the second call anyway.
      const sigResult = wiring.sigF3;
      // ⛔ THREE OUTCOMES, AND THE OLD `?? 0` MERGED TWO OF THEM.
      //
      //   MEASURED LIVE 2026-09-30T06:43:44Z, and it is why this block changed:
      //   the journal recorded "a clerk stamps source is declared but F3 USED
      //   none of it for this chain (f0ee1315f8ab…)" at the restart — and
      //   minutes later, at decision time, F3 used 1244 stamps over 1243 pairs.
      //   The message asserted a cause the code could not distinguish.
      //
      //   `clerkStampCoverage` is null on EXACTLY ONE path in the machine
      //   (sig/index.ts, the `assessLogReadability` arm): THE LOG COULD NOT BE
      //   READ. The machine's own comment there says why null rather than a
      //   zeroed object — "a zeroed coverage object would read as 'nothing was
      //   missing', which is a claim about a scope nobody looked at." This file
      //   then wrote `?? 0` on it and reintroduced exactly that reading one
      //   layer up.
      //
      //     coverage === null  -> THE QUESTION IS UNRESOLVED. F3 never ran.
      //                           Not an answer, and it must be ASKED AGAIN.
      //     stampedCount === 0 -> ANSWERED: F3 read the scope and joined none.
      //                           Do not mint, and do not ask again.
      //     the call threw     -> UNRESOLVED, and the throw is NAMED, never
      //                           swallowed.
      const coverage = sigResult?.coverage;
      if (coverage === null || coverage === undefined) {
        // eslint-disable-next-line no-console
        console.error(
          `[mica-service] the prior-load witness question is UNRESOLVED, not answered: F3 ` +
            `reported no stamp coverage at all, which in the machine means THE LOG COULD NOT BE ` +
            `READ on this pass — not that F3 used no stamps. No witness is minted and the ` +
            `question will be asked again on the next decision.`
        );
        return "UNRESOLVED";
      }
      used = coverage.stampedCount;
      genesis = loadExpectedChainIdentity(logPath, logKind);
    } catch (err) {
      // A reader that could not run is the gate's finding to report, never a
      // reason to mint a memory of having read anything — but it is ALSO not an
      // answer, so it is named and re-asked rather than swallowed.
      // eslint-disable-next-line no-console
      console.error(
        `[mica-service] the prior-load witness question is UNRESOLVED: the reader could not be ` +
          `run on this pass (${err instanceof Error ? err.message : String(err)}). No witness is ` +
          `minted and the question will be asked again on the next decision.`
      );
      return "UNRESOLVED";
    }
    if (genesis === undefined) {
      // ⛔ THE THIRD SILENT DEATH, not in Codex's two but the same defect.
      //   An unbound witness is the replayable claim SHAPE (b) removes, so not
      //   minting is right. But reaching here means `prior` was ABSENT on a
      //   subject-chain log — the chain EXISTS — and its position-0 boundary
      //   still yielded no identity. That is a chain we could not read the
      //   genesis of, which is UNRESOLVED, not "there is nothing to witness".
      // eslint-disable-next-line no-console
      console.error(
        `[mica-service] the prior-load witness question is UNRESOLVED: the chain is present and ` +
          `unwitnessed, but no expected chain identity could be loaded from its boundary, so there ` +
          `is nothing to bind a witness to. No witness is minted and the question will be asked ` +
          `again on the next decision.`
      );
      return "UNRESOLVED";
    }
    // ⚠ ONE STAMP F3 ACTUALLY USED IS THE THRESHOLD. A file full of stamps the
    //   leg discarded is evidence that a carrier ran; it is NOT evidence that
    //   this chain ever had an arrival axis, which is the only thing this record
    //   is entitled to claim.
    if (used === 0) {
      // ANSWERED. F3 ran, read the scope, and joined nothing. This is a real
      // reading and it must NOT be re-asked: re-asking an answered question is
      // how a witness eventually gets minted from a pass nobody meant.
      // eslint-disable-next-line no-console
      console.error(
        `[mica-service] a clerk stamps source is declared but F3 USED none of it for this chain ` +
          `(${genesis.slice(0, 12)}…). No prior-load witness is recorded: a witness minted from ` +
          `stamps the reader discarded would turn every later empty stamps file into a false erasure.`
      );
      return "ANSWERED_NONE_USED";
    }

    const appended = await this.subjectLog.appendDerived((sequenceNumber, previous) => ({
      recordType: "SUBJECT_EVENT",
      sequenceNumber,
      previousHash: typeof previous?.hash === "string" ? previous.hash : "",
      timestamp: this.now().getTime(),
      // THE CHAIN'S OWN VOICE, never a subject's. `validateSubjectRecord`
      // REFUSES this eventType from any other moduleId, so a subject cannot
      // mint this record even if a route were opened to it by mistake.
      moduleId: SUBJECT_LOG_BOUNDARY_MODULE_ID,
      eventType: CLERK_STAMPS_FIRST_LOAD_EVENT_TYPE,
      outcome: "STAMPS_OBSERVED",
      // The chain this memory belongs to, carried so a reader holding only the
      // file can see it. The binding that MATTERS is membership in this chain;
      // this field is what an out-of-band auditor reads.
      chainIdentity: genesis,
      // ⛔ THE ACCEPTED COUNT, AND THE RAW ONE BESIDE IT. Recording only the
      // accepted number would hide that a file also held stamps this chain
      // refused; recording only the raw number is the defect Codex found.
      // F3's own number, not this file's.
      usedStampCount: used,
      detail:
        `Sig's F3 leg USED ${String(used)} clerk stamp(s) for this chain — the count is F3's own, ` +
        `after its chain, writer, ambiguity and record checks, and not a second reckoning taken ` +
        `beside it. From here on, an ` +
        `EMPTY or ABSENT stamps source is an ERASURE and is REFUSED, not a first run. A deliberate ` +
        `re-stamp is performed by ROTATING the chain: a new chain has a new genesis and therefore ` +
        `no prior-load record of its own.`,
    }));
    if (!appended.ok) {
      // ⛔ CODEX FAIL 2026-09-30 11:0xZ. This logged and fell off the end, so
      //   the flag kept whatever it already held and the retry was never armed.
      //   A WITNESS THAT COULD NOT BE WRITTEN IS NOT A WITNESS. Everything
      //   above it succeeded — F3 ran, the count is real, the genesis is bound
      //   — which is exactly what made this the easiest arm to read as done.
      // eslint-disable-next-line no-console
      console.error(
        `[mica-service] the prior-load witness question is UNRESOLVED: the witness record could ` +
          `not be appended to the subject chain (${appended.error ?? "no detail"}). F3 used ` +
          `${String(used)} stamp(s) on this pass, so the question HAS an answer and only the ` +
          `writing of it failed; it will be asked again on the next decision.`
      );
      return "UNRESOLVED";
    }
    return "MINTED";
  }

  /**
   * GATE 1 · Stop 2 · round 2 (placement D) · THE INTEREST BOOK'S FIRST LINE.
   *
   * The boundary machinery of `writeChainBoundaryIfNeeded`, reused: the
   * journal's own `appendBoundary`, so the book loads in the machine's
   * `SubjectChainLog` exactly as the subject chain does, and a book whose
   * position 0 is missing refuses every label append (the journal will not let
   * an event be a chain's first line). `retired: null` — see
   * INTEREST_BOOK_BOUNDARY_BASIS for what that does and does not say.
   *
   * Nothing is re-read against disk, because nothing about a predecessor is
   * declared; that is the difference from the subject chain, and the basis
   * names it.
   *
   * ⛔ NEVER REFUSES STARTUP. A book that will not begin costs Gate 1 its labels
   *    and nothing else; a bridge that would not start over it would have
   *    stopped the guard to protect an envelope reader. Same trade as the
   *    subject chain's refusal: loud, durable in the event book, not fatal. Every
   *    later label append then fails and is reported per act.
   * ⛔ A DAMAGED BOOK IS NOT BEGUN, AND SAYS SO (round 3, review K2W3-8). A book
   *    file that exists but loads non-persisting (an unparseable line, a broken
   *    link) also loads EMPTY — the journal holds no prefix of a damaged chain —
   *    so it reaches here with no records. It is NOT repaired (ruling 6) and not
   *    begun over; until round 3 this branch returned SILENTLY, which made the
   *    sentence above false for exactly the case an operator most needs to see.
   *    It now writes INTEREST_BOOK_BOUNDARY_REFUSED with the journal's own load
   *    state and reason, and the console line, like a refused append.
   * ⚠ A BOOK THAT HAS BEGUN and is damaged LATER is not seen here (this runs
   *   once, at start); each later label append fails and is reported per act.
   */
  private writeInterestBookBoundaryIfNeeded(): void {
    if (this.interestBook === null) return;
    const journal = this.interestBook.store;
    if (journal.getAll().length > 0) return; // the book has already begun
    const at = this.now().getTime();
    let detail: string | null = null;
    if (!journal.isPersisting()) {
      // Damaged: refuse, do not repair (ruling 6) — and say so.
      let state = "an unknown load state";
      let why = "no detail";
      try {
        state = String(journal.getLoadState());
        why = journal.getLastError() ?? "no detail";
      } catch {
        // The report must not throw out of start(); the fixed words stand.
      }
      detail = `the interest book loads ${state} and will not be begun over or repaired (ruling 6): ${why}`;
    } else {
      try {
        const outcome = journal.appendBoundary(null, INTEREST_BOOK_BOUNDARY_BASIS, at);
        if (!outcome.persisted) detail = outcome.detail ?? "no detail";
      } catch (err) {
        detail = `the boundary append threw: ${err instanceof Error ? err.message : String(err)}`;
      }
    }
    if (detail !== null) {
      // eslint-disable-next-line no-console
      console.error(`[mica-service] INTEREST BOOK NOT BEGUN — ${detail}`);
      this.recordEvent({ seq: ++this.eventSeq, ts: new Date(at).toISOString(), kind: INTEREST_BOOK_BOUNDARY_REFUSED, detail });
      return;
    }
    this.recordEvent({
      seq: ++this.eventSeq,
      ts: new Date(at).toISOString(),
      kind: INTEREST_BOOK_BOUNDARY,
      detail: "the Gate 1 interest book began (position 0, retired: null — no predecessor is declared)",
    });
  }

  /**
   * GATE 1 · Stop 2 · round 2 (placement D) · ONE LABEL, AFTER ITS ACT PERSISTED.
   *
   * Called by the subject-events handler for a TOOL_ATTEMPTED of a framed
   * subject, ONLY after the subject chain answered `ok` for that act, and only
   * after the act's response was sent. TOTAL: it resolves on every path and
   * never throws, so nothing it does can reach the act's response or the
   * process.
   *
   * ⛔ NEVER A SECOND LABEL FOR ONE ACT, AND NEVER A SILENT RETRY. One attempt.
   *    If it does not persist — the book is not open, the journal refused, or
   *    the append threw — the act stays unlabelled and the EVENT BOOK says so,
   *    naming the act by (subject, actionId, subjectSeq) and the reason. A
   *    retry would be a second writer of one fact; a later backfill would need
   *    the plain target, which no longer exists anywhere.
   * ⚠ WHAT THIS COSTS THE READER: an unlabelled act is not counted at all — not
   *   as a case, not as UNDERIVED. Gate 1's ceiling says so (THE BOOK IS WRITTEN
   *   AFTER THE ACT); the event book is where the miss is countable.
   * ⚠ A CRASH between the act's persist and this append loses the label with no
   *   event either. The act is on the subject chain; the label is the cheaper
   *   fact to lose, and this ordering is what keeps it the only one lost.
   */
  private async appendInterestLabel(entry: InterestLabelEntry): Promise<void> {
    let reason: string | null = null;
    try {
      const book = this.interestBook;
      if (book === null) {
        reason =
          "no interest book is open in this process: paths.interestBook was not declared when the bridge " +
          "started, and a book is opened only at start";
      } else {
        // ⛔ CALLED SYNCHRONOUSLY from the handler (no await between the act's
        //    persist and this call), so book order follows subject-chain order.
        const out = await book.appendDerived((_seq, previous) =>
          buildInterestLabelRecord(entry, previous, this.now().getTime())
        );
        if (!out.ok) reason = `the interest book did not persist the label: ${out.error ?? "no detail"}`;
      }
    } catch (err) {
      try {
        reason = `the interest-book append threw: ${err instanceof Error ? err.message : String(err)}`;
      } catch {
        reason = "the interest-book append threw, and its error could not be rendered";
      }
    }
    if (reason === null) return;
    // THE REASON NAMES THE BOOK AND THE JOURNAL'S WORDS, NEVER THE TARGET: the
    // target is not in `entry` and was never handed to the journal.
    const seq = ++this.eventSeq;
    let ts = "unavailable";
    try {
      ts = this.now().toISOString();
      this.recordEvent({
        seq,
        ts,
        kind: INTEREST_LABEL_NOT_PERSISTED,
        subject: entry.subject,
        actionId: entry.actionId,
        subjectSeq: entry.subjectSeq,
        reason,
      });
    } catch (err) {
      // The report of the miss could not even be queued: counted where every
      // other lost event-book line is (`droppedRecords` on /status).
      this.noteDroppedRecord(INTEREST_LABEL_NOT_PERSISTED, seq, ts, `could not queue the report: ${String(err)}`);
    }
  }

  /** One refusal path, so the wording and the console line cannot drift apart. */
  private refuseBoundary(detail: string): void {
    // eslint-disable-next-line no-console
    console.error(`[mica-service] SUBJECT CHAIN NOT BEGUN — ${detail}`);
    void this.eventBook.append({
      seq: ++this.eventSeq,
      at: this.now().toISOString(),
      kind: "SUBJECT_CHAIN_BOUNDARY_REFUSED",
      detail,
    });
  }

  /** STAGE 4 / DESIGN §A.4: every Stage 1 path, resolved through `resolvePath()`. */
  private resolvedEvalPaths(declarations: Declarations): EvaluateAndRecordPaths {
    return {
      journal: this.resolvePath(declarations.paths.journal),
      floorTrail: this.resolvePath(declarations.paths.floorTrail),
      ledger: this.resolvePath(declarations.paths.ledger),
      history: this.resolvePath(declarations.paths.history),
      events: this.resolvePath(declarations.paths.decisionEvents),
    };
  }

  /**
   * STAGE 4 / DESIGN §A.2. The default the SERVICE actually uses when no
   * `opts.guardAdapter` override was supplied at construction — a real,
   * fully-wired `Stage1GuardAdapter`, rebuilt from whichever `declarations`
   * are current. Called from both `start()` and a successful `reload()`.
   */
  private buildGuardAdapter(declarations: Declarations): GuardAdapter {
    // ZERO SUBJECTS · LAYER 4 (ticket v2 §2.2). Placed AFTER notifierFor is
    // consulted, because notifierFor is SERVICE_STARTED's only emission site: an
    // early return here would erase the restart marker at every start into zero.
    // It wins over a test's override too, so no injected adapter can evaluate a
    // /guard while nothing is declared.
    if (nothingDeclared(declarations)) {
      if (this.guardAdapterOverride === undefined) this.notifierFor(declarations);
      return new NothingDeclaredGuardAdapter();
    }
    if (this.guardAdapterOverride !== undefined) return this.guardAdapterOverride;
    const paths = this.resolvedEvalPaths(declarations);
    // C8: built ONCE, here, where the adapter is bound — and REUSED across a
    // reload whose notifier-relevant declaration is unchanged. The closure
    // below captures the pair by value, so every request this adapter serves
    // counts into the same instance.
    const notifier = this.notifierFor(declarations);
    return new Stage1GuardAdapter(paths, (r) =>
      wireOptionsFor(declarations, r, notifier, (p) => this.resolvePath(p), this.testClockStampsOwner, this.harmEpochFor(declarations), this.grantMemoryViewFor(declarations)));
  }

  /**
   * S216-2 · GM2/GM5 · WHAT THE READER IS HANDED OF THE GRANT MEMORY: its tag (over the persisted boundary and the
   * wired subject's persisted rows), its state, and the effective since of each declared grant. Null before start()
   * adopted the memory — the wire then carries no grantMemory and the machine reads WIRED AND BLIND (fail closed).
   */
  private grantMemoryViewFor(d: Declarations): HarmGrantMemoryView | null {
    const store = this.grantMemory;
    if (store === null || !store.isAdopted()) return null;
    const g2 = d.readers.gate2Direction;
    const wired = declaredGrantsOf(d.harm).filter((g) => g2 !== undefined && g.key.subject === g2.subject.value);
    return { tag: store.tag(wired), state: store.state(), effective: (g: DeclaredGrant) => store.effective(g) };
  }

  /** S216-2 · the grant memory's own path (the salt's pattern: the state dir override, else /var/lib/mica-bridge). */
  private grantMemoryDir(): string {
    return this.stateDirOverride ?? "/var/lib/mica-bridge";
  }

  /**
   * S216-2 · C2's second clamp: the newest record timestamp in the books this load reads — the subject log, the
   * interest book and the witness's book (as the bridge reads it). A book that cannot be read adds nothing (the clamp
   * is then the memory's last write and the clock); said in the ceiling. RELAY 3 · F1(b): the SAME floor refuses an
   * errand whose `from` is earlier than it (validateErrandRecord) — one notion of "the newest record", not two.
   */
  private grantMemoryBookFloor(d: Declarations): number | null {
    let floor: number | null = null;
    const take = (rows: readonly Record<string, unknown>[]): void => {
      for (const r of rows) {
        const t = r.timestamp;
        if (typeof t === "number" && Number.isFinite(t) && (floor === null || t > floor)) floor = t;
      }
    };
    try {
      take(this.subjectLog.readAll());
    } catch {
      // unreadable: adds nothing
    }
    try {
      if (this.interestBook !== null) take(this.interestBook.readAll());
    } catch {
      // unreadable: adds nothing
    }
    const wb = d.paths.witnessBook?.value;
    if (wb !== undefined) {
      try {
        const rows: Record<string, unknown>[] = [];
        for (const line of readFileSync(this.resolvePath(wb), "utf8").split("\n")) {
          if (line.length === 0) continue;
          try {
            const o = JSON.parse(line);
            if (o !== null && typeof o === "object") rows.push(o as Record<string, unknown>);
          } catch {
            // a line that does not parse adds nothing
          }
        }
        take(rows);
      } catch {
        // unreadable or absent: adds nothing
      }
    }
    return floor;
  }

  /** S216-2 · the boundary hashes the event book names (GRANT_MEMORY_BEGUN / _ADOPTED rows), oldest first. */
  private static grantMemoryPriorBoundaries(events: readonly Record<string, unknown>[]): string[] {
    const out: string[] = [];
    for (const e of events) {
      if (e.kind !== "GRANT_MEMORY_BEGUN" && e.kind !== "GRANT_MEMORY_ADOPTED") continue;
      const m = /\bboundary=([0-9a-f]{64})\b/.exec(String(e.detail ?? ""));
      if (m !== null) out.push(m[1]);
    }
    return out;
  }

  private static grantKeyWords(k: GrantKey): string {
    return `${k.subject}/${k.itemId}/${k.originId} (path ${k.path}, origin subject ${k.originSubject})`;
  }

  /** S216-2 · one event-book row per fact this load's memory work produced (GM2's APPLIED row included). */
  private recordGrantMemoryOutcome(d: Declarations, at: "start" | "reload", o: ApplyOutcome): void {
    const store = this.grantMemory!;
    for (const k of o.retired) {
      this.appendServiceEvent(
        "GRANT_MEMORY_RETIRED", null, null, null,
        `${MicaBridgeService.grantKeyWords(k)} retired at this ${at}` + (at === "start" ? "; across a restart: H11 refuses this on reload" : ""),
        null
      );
    }
    if (!o.persisted) {
      this.appendServiceEvent(
        "GRANT_MEMORY_NOT_PERSISTED", null, null, null,
        `the grant memory ${store.path} could not be written at this ${at} (${o.error ?? "unknown"}); its rows are held by this process ` +
          `(first sights re-stamped later after a further restart; an unwritten retirement or raised since can be undone by one, C7)`,
        null
      );
    }
    const differs: string[] = [];
    for (const g of declaredGrantsOf(d.harm)) {
      const e = store.effective(g);
      if (e !== null && e.at !== g.sinceAt) differs.push(`${MicaBridgeService.grantKeyWords(g.key)} effective ${e.utc}, declared ${g.sinceUtc}`);
    }
    if (differs.length > 0) {
      this.appendServiceEvent("GRANT_MEMORY_APPLIED", null, null, null, `state=${store.state()}; effective since ≠ declared: ${differs.join("; ")}`, null);
    }
  }

  /**
   * S216-2 · GM0 · ADOPT THE GRANT MEMORY at start(). NEVER a StartupRefused on the memory's state: missing → BEGUN
   * (or BEGUN_AFTER_LOSS when the event book names an earlier one), torn → RECOVERED_PREFIX (F-7), unreadable or
   * corrupt → aside + BEGUN_AFTER_LOSS (F-2), unwritable → NOT_PERSISTED, an unforeseen throw → a RAM chain.
   */
  private adoptGrantMemory(d: Declarations, declarationHash: string, events: readonly Record<string, unknown>[]): void {
    const store = new GrantMemoryStore(this.grantMemoryDir());
    this.grantMemory = store;
    const facts = { now: this.now().getTime(), bookFloorAt: this.grantMemoryBookFloor(d), declarationHash, grants: declaredGrantsOf(d.harm) };
    let outcome: ApplyOutcome;
    try {
      const a = store.adopt(facts, MicaBridgeService.grantMemoryPriorBoundaries(events));
      outcome = a;
      if (a.found === "TORN" || a.found === "LOSS" || (a.found === "MISSING" && a.begun === "BEGUN_AFTER_LOSS")) {
        this.appendServiceEvent(
          "GRANT_MEMORY_LOSS", null, null, null,
          `the grant memory ${store.path} was found ${a.found} (${a.foundReason ?? "missing"}); ` +
            (a.aside !== null ? `moved aside to ${a.aside}, never edited; ` : a.asideError !== null ? `could NOT be moved aside (${a.asideError}); ` : "") +
            `begun ${a.begun}: sinces only move later`,
          null
        );
      }
      if (a.persisted) {
        this.appendServiceEvent(
          a.newChain ? "GRANT_MEMORY_BEGUN" : "GRANT_MEMORY_ADOPTED", null, null, null,
          `boundary=${a.boundaryHash} begun=${a.begun} state=${store.state()} path=${store.path} declarationHash=${declarationHash} ` +
            `rows=${String(store.snapshot().chain.length)} appended=${String(a.formed.length)}`,
          null
        );
      }
    } catch (err) {
      outcome = store.fallback(facts, err instanceof Error ? err.message : String(err));
    }
    this.recordGrantMemoryOutcome(d, "start", outcome);
  }

  /**
   * LONG RUN A STOP 2 · THE HARM STANZA'S ITEM FINGERPRINTS AND THE SALT EPOCH'S
   * START, computed HERE because the salt lives here and never leaves this
   * process (to-wire-options stays pure). Null when Gate 2's subject declares no
   * harm stanza. With no salt (start() not completed, or ABSENT for any of the
   * nine reasons) the epoch is null and the reader reads item membership NOT
   * READABLE — never a match on a fingerprint nobody can compute.
   *
   * Each fingerprint is `fingerprintTarget(salt, item.path, TARGET_CANON_VERSION)`
   * — the SAME function and version the witness pointer carries after B-1, over
   * a path the door (H4) admitted only when it equals its own canonical form and
   * the one-pair strip leaves it unchanged. So an act claiming the item, quoted
   * or bare, drops a pointer with exactly this value.
   */
  private harmEpochFor(d: Declarations): HarmTargetEpoch | null {
    const g2 = d.readers.gate2Direction;
    if (g2 === undefined || d.harm === undefined || !Object.hasOwn(d.harm, g2.subject.value)) return null;
    if (this.targetSalt === null || this.targetSalt.status !== "PRESENT") return null;
    const itemFingerprints: Record<string, string> = {};
    for (const item of Object.values(d.harm[g2.subject.value].items.value)) {
      itemFingerprints[item.path] = fingerprintTarget(this.targetSalt.salt, item.path, TARGET_CANON_VERSION);
    }
    // S208-2 · the errand grants ride here: the other per-request harm input only this process can derive.
    const stanza = d.harm[g2.subject.value];
    const origin = Object.keys(stanza.origins.value).find((o) => stanza.origins.value[o].subject === g2.subject.value);
    const errandGrants = stanza.errand === undefined || origin === undefined ? [] : deriveErrandGrants(this.subjectLog.readAll(), g2.subject.value, origin, stanza);
    return { saltEpochSince: this.saltEpochSince, itemFingerprints, errandGrants };
  }

  /**
   * C8. The notifier for THIS declaration — the held one when nothing that
   * built it has changed, a fresh one when something has.
   *
   * WHAT THE CODE DID BEFORE C8, stated so the change is legible: `reload()`
   * rebuilt the adapter and `wire()` then built a new notifier per action, so
   * reload had no effect on any counter because no counter survived a single
   * action. There was nothing to preserve. The rule below is therefore new
   * behaviour over a new object, not a change to an old one.
   */
  private notifierFor(declarations: Declarations): BuiltNotifier {
    const noticeDir = this.resolvePath(declarations.paths.noticeDir);
    const noticeWindow = declarations.notice.window.value;
    // The two declared facts the pair is built from, and nothing else. A field
    // NOT in this key is a field whose change must not reset the count.
    const key = notifierKey(noticeDir, noticeWindow);

    const held = this.notifierHolder;
    if (held === null) {
      // ── SERVICE_STARTED · a restart must be legible where the counter is read ──
      //
      // C8 gave `totalSoFar` a lifetime — this process — so it RESETS TO 1 on every
      // restart. The reload case already announces itself
      // (PASS_BLIND_NOTIFIER_REBUILT, below); the restart case did not, and a
      // counter that drops from 40 to 1 with no visible cause reads as "quiet"
      // when it may mean "restarted mid-flood".
      //
      // EMITTED HERE, AND ONLY HERE, because this branch is by construction the
      // FIRST notifier build of the process: `notifierHolder` starts null and is
      // only ever set below. A reload finds it non-null and takes the other
      // branch, so this cannot fire twice in one process. A test injecting
      // `guardAdapterOverride` never reaches `notifierFor` at all, so it emits
      // nothing — which is correct: no notifier exists there to restart.
      //
      // THE EVENT BOOK IS OPEN BY NOW, verified at bytes rather than assumed:
      // start() sets `state` (:1042), reads `release` (:1044), constructs the
      // real `eventBook` (:1046) and seeds `eventSeq` from it (:1058) — all
      // BEFORE `buildGuardAdapter` (:1072), which is this function's only caller.
      // The append is queued on the same SerializedAppender as every later
      // notice, so this line cannot arrive after one.
      //
      // IT CLAIMS NOTHING ABOUT HEALTH (ruling A — census, never verdict). It
      // says a process began and what it began with. Whether it is well is not
      // a thing a start-up line could know.
      this.appendServiceEvent(
        "SERVICE_STARTED",
        null,
        null,
        null,
        `bridge process started at ${this.startedAt.toISOString()}; ` +
          `release=${this.release?.sha ?? "UNKNOWN"}; ` +
          `declarationHash=${this.state?.declarationHash ?? "UNKNOWN"}; ` +
          `notice.window=${String(noticeWindow)}. ` +
          `totalSoFar restarts at 1 from here.`,
        null
      );
    }
    if (held !== null) {
      if (held.key === key) return held.built;
      // CHANGED. Emit the old pair's tail BEFORE dropping it, or the
      // suppressed count of a part-filled window is lost at the moment a
      // deployment changes its mind — which is exactly when someone is
      // watching. Then say so in the book, so a reader meeting a `totalSoFar`
      // that went backwards can see why.
      const tail = held.built.batched.flush();
      this.appendServiceEvent(
        "PASS_BLIND_NOTIFIER_REBUILT",
        null,
        null,
        null,
        `notice wiring changed (was ${describeNotifierKey(held.key)}, now ` +
          `${describeNotifierKey(key)}); the old notifier was flushed ` +
          `(${tail === null ? "nothing was pending" : `count=${String(tail.count)} totalSoFar=${String(tail.totalSoFar)}`}) ` +
          `and a new one built. totalSoFar restarts at 0 from here — a reset ` +
          `caused by a declared change, not by an unrelated field moving.`,
        null
      );
    }

    const built = buildNotifier({ noticeDir, noticeWindow });
    this.notifierHolder = { key, built };
    return built;
  }

  /**
   * Reads `<release>/VINTAGE` (`../VINTAGE` relative to this file — see
   * `StatusResponse.release`'s own doc comment) once, at startup. `null`
   * fields, or a wholly `null` return, when the file is absent or a line
   * is missing — never guessed at, never defaulted.
   */
  private readRelease(): { sha: string | null; laidAt: string | null } | null {
    const vintagePath = join(__dirname, "..", "VINTAGE");
    if (!existsSync(vintagePath)) return null;
    let sha: string | null = null;
    let laidAt: string | null = null;
    for (const line of readFileSync(vintagePath, "utf8").split("\n")) {
      if (line.startsWith("sha=")) sha = line.slice("sha=".length);
      if (line.startsWith("laid_at=")) laidAt = line.slice("laid_at=".length);
    }
    return { sha, laidAt };
  }

  /** F5: replaces the fixed /var/lib/mica-bridge prefix when an override is set. */
  private resolvePath(declared: string): string {
    if (this.stateDirOverride === null) return declared;
    return declared.replace(/^\/var\/lib\/mica-bridge/, this.stateDirOverride);
  }

  /**
   * R6 · WHERE THE SALT LIVES. The bridge's `StateDirectory`, per the ruling,
   * with the same `stateDir` override every other path here honours — so a
   * verifier or an operator can run the real unit under a temp root without
   * needing `/var/lib/mica-bridge` to exist, and without a second salt ever
   * being minted into the real one by a test.
   *
   * IT IS NOT A DECLARED PATH, AND THAT IS DELIBERATE. `declarations.paths.*`
   * are values the deployer declares and the declaration hash covers; the salt
   * is MINTED BY THE SERVICE and its existence is not a deployment choice.
   * Declaring it would put a path to a secret in a file everybody reads, and —
   * the sharper reason — it would make minting a salt something a declaration
   * change could move, when the ruling says moving it is the arbiter's own act.
   */
  private targetSaltPath(): string {
    return join(this.stateDirOverride ?? "/var/lib/mica-bridge", "target-fingerprint-salt");
  }

  /** Loads declarations, enters SERVING, binds one socket per routes[] row. */
  async start(): Promise<void> {
    const loaded = loadDeclarations(this.declarationsPath, this.now());
    this.state = { declarations: loaded.declarations, declarationHash: loaded.declarationHash, loadedAt: this.now() };
    this.preflight = false;
    this.release = this.readRelease();

    this.eventBook = new SerializedAppender(this.testWritablePaths?.eventBook ?? this.resolvePath(loaded.declarations.paths.eventBook));
    this.subjectLog = new ChainedSubjectAppender(this.testWritablePaths?.subjectLog ?? this.resolvePath(loaded.declarations.paths.subjectLog));
    // GATE 1 · round 2 · the interest book, opened exactly as the subject log is.
    // Declared or test-redirected -> opened; neither -> null (no book, and the
    // declaration hashes as it did before the key existed).
    const declaredBook = loaded.declarations.paths.interestBook;
    const bookPath = this.testWritablePaths?.interestBook ?? (declaredBook === undefined ? undefined : this.resolvePath(declaredBook));
    this.interestBook = bookPath === undefined ? null : new ChainedSubjectAppender(bookPath, "interest book");

    // AMENDMENT 9 / STAGE 3 VERIFIER FINDING 2: `eventSeq` was an in-memory
    // counter starting at 0 on every process start, even though the event
    // book itself is durable — after a restart the NEXT event was written
    // as seq 1 again, colliding with (and, for a cursor-based reader,
    // hiding behind) whatever seq 1 already meant from before the restart.
    // Restored here from the persisted book's own highest seq — the
    // counter is now durable and monotonic across restarts, not merely the
    // file it writes into.
    const existingEvents = this.eventBook.readAll();
    this.eventSeq = existingEvents.reduce((max, e) => Math.max(max, Number(e.seq) || 0), 0);

    // ACT A / ruling 3: a chain that has not begun begins here, with the
    // boundary record and nothing else. Never silently, and never on a chain
    // that already has one.
    //
    // ⚠ THE ORDER IS LOAD-BEARING AND IT WAS WRONG ONCE. This ran immediately
    // after the subject log was constructed, which is BEFORE `eventSeq` is
    // seeded from the book above — and `eventBook.append` is queued, so the
    // seeding read did not yet see the line this had just written. Both the
    // boundary event and the SERVICE_STARTED marker came out as `seq: 1`, two
    // different facts wearing one cursor. Found by mica-service.test.ts's
    // "a fresh book must hold exactly the marker" check, which is the test
    // that exists to see a second line appear in a fresh book.
    this.writeChainBoundaryIfNeeded(loaded.declarations);
    // GATE 1 · round 2 · and the interest book's position 0, in the same place
    // and for the same ordering reason (`eventSeq` is seeded above).
    this.writeInterestBookBoundaryIfNeeded();

    // STAGE 4 / DESIGN §A.7: DISPOSITION_CHANGED's "prior" comparison is
    // seeded from the book, not from nothing, so a restart does not treat
    // the first post-restart decision as a change from an imagined null.
    this.lastDispositionBySubject = new Map();
    for (const e of existingEvents) {
      if (e.kind === "DISPOSITION_CHANGED" && typeof e.subject === "string" && typeof e.disposition === "string") {
        this.lastDispositionBySubject.set(e.subject, e.disposition);
      }
    }

    // STAGE 4 / DESIGN §A.2: the default binds Stage 1 in, rebuilt fresh
    // from THIS load's declarations.
    this.guardAdapter = this.buildGuardAdapter(loaded.declarations);

    // SHAPE (b) · THE BRIDGE REMEMBERS, IN ITS OWN CHAIN, THAT IT ONCE SAW
    // STAMPS FOR THIS CHAIN. Written here, once the declarations are loaded and
    // the boundary exists, and never from a reader: see the method.
    // ZERO SUBJECTS (ticket v2 §2.3): skipped at zero, and the retry flag stays
    // false. The mint is a fact about stamps over a chain the readers stand on;
    // at zero no reader stands on it, and wire() is not called at all. The first
    // start after a re-add asks the question as before.
    if (!nothingDeclared(loaded.declarations)) await this.witnessFirstStampsLoadIfNeeded(loaded.declarations);

    // STAGE 4 / DESIGN §A.6, Layer 2 — after declarations load, BEFORE any
    // socket binds, so a refusal is a StartupRefused and no caller ever
    // reaches a half-owned service.
    this.claimHistoryOwnership(loaded.declarations);

    // ── R6 · THE SALT, BEFORE ANY SOCKET BINDS, AND NOTHING HERE REFUSES ──
    //
    // Position unchanged, REASON INVERTED. Before, a fault here was a
    // StartupRefused. The arbiter's ruling of this evening says it must not be: a
    // bridge that will not start has stopped the GUARD, and the fingerprint is
    // one field on one reader. So every fault below produces a SERVING bridge
    // with no fingerprint on any record and one LOUD event naming the reason.
    //
    // MINT ONCE, AND ONLY ON A PROVEN FIRST START. The memory that makes
    // "first start" decidable is the union of the two books — see
    // `readEpochMemory` for the whole argument, for the two candidates it
    // rejects, and for what a lost memory costs and who repairs it.
    //
    // THE EVENT BOOK HALF IS FREE: `existingEvents` is already in hand from the
    // read above. That read is NOT guarded, so an unreadable event book throws
    // out of `start()` before this line — which means the EPOCH_MEMORY_UNREADABLE
    // row of the state machine is reachable through the SUBJECT LOG here, and
    // through the event book only at module level. Said rather than claimed.
    const epochMemory: EpochMemory = readEpochMemory({
      eventBook: () => existingEvents,
      subjectLog: () => this.subjectLog.readAll(),
    });
    this.targetSalt = loadOrMintTargetSalt(this.targetSaltPath(), epochMemory);
    const announcedAt = await this.announceEpoch(this.targetSalt, epochMemory);
    this.saltEpochSince = saltEpochStartFrom(this.targetSalt, existingEvents, announcedAt);

    // F1: validate EVERY peer directory before binding ANY socket. One bad
    // directory refuses the whole startup — never a partial bind where the
    // good uids serve and the bad one is silently skipped.
    const bridgeGid = this.testBridgeGid ?? resolveGid("mica-bridge");
    if (bridgeGid === null) {
      throw new StartupRefused(`group "mica-bridge" could not be resolved from /etc/group; refusing to start`);
    }
    const plans = planPeerSockets(loaded.declarations.routes, this.socketDir);
    for (const plan of plans) {
      const check = validatePeerDir(plan, bridgeGid);
      if (!check.ok) {
        throw new StartupRefused(`peer directory for uid ${plan.uid} failed its ownership/mode check: ${check.reason}`);
      }
    }

    // ── S216-2 · GM0 · THE GRANT MEMORY, HERE AND ONLY HERE AT START ──
    // AFTER the history claim (a second bridge is refused before it can write a row) and the peer-dir checks, BEFORE
    // any socket binds, against the declaration THIS start loaded. Never refuses startup (see adoptGrantMemory).
    this.adoptGrantMemory(loaded.declarations, loaded.declarationHash, existingEvents as readonly Record<string, unknown>[]);

    for (const plan of plans) {
      if (existsSync(plan.socketPath)) unlinkSync(plan.socketPath);
      const server = http.createServer((req, res) => this.handleHttp(plan.uid, req, res));
      await new Promise<void>((resolve, reject) => {
        server.on("error", reject);
        server.listen(plan.socketPath, resolve);
      });
      // The directory (0770, exact uid/gid) is the boundary; the socket
      // file itself is widened so the directory's own uid — not a member
      // of group mica-bridge — can actually open it. See peer-auth.ts's
      // header, "the DIRECTORY is the boundary."
      widenSocketFileMode(plan.socketPath);
      this.servers.set(plan.uid, server);
      this.plans.set(plan.uid, plan);
    }

    // ZERO SUBJECTS (ticket v2 §2.4, F-6 (a), F-10 (a)). AFTER every socket has
    // bound — a StartupRefused above writes no row, so no row names a tenure
    // that never served — through the accounted recordEvent path, and only when
    // the membership differs from the last SUBJECTS_DECLARED on the book (or
    // none exists), so the alerter speaks once per change, not once per restart.
    this.recordSubjectsDeclaredIfChanged(loaded.declarations, loaded.declarationHash, existingEvents as readonly Record<string, unknown>[]);
  }

  /**
   * The one writer of SUBJECTS_DECLARED. The zero interval is visible on the
   * event book ONLY (F-6 (a), the printed ceiling): the subject chain carries
   * no record of it, no reader sees it, and /status after a re-add keeps no
   * memory of it.
   */
  private recordSubjectsDeclaredIfChanged(
    declarations: Declarations,
    declarationHash: string,
    existingEvents: readonly Record<string, unknown>[]
  ): void {
    const declared = subjectsCensus(declarations).declared;
    const key = (rows: readonly unknown[]): string =>
      JSON.stringify(
        rows
          .map((r) => {
            const o = (r ?? {}) as Record<string, unknown>;
            return JSON.stringify([o.subject ?? null, o.peerUid ?? null, o.unit ?? null]);
          })
          .sort()
      );
    let last: Record<string, unknown> | null = null;
    for (const e of existingEvents) if (e.kind === "SUBJECTS_DECLARED") last = e;
    if (last !== null && Array.isArray(last.declared) && key(last.declared) === key(declared)) return;
    this.recordEvent({
      seq: ++this.eventSeq,
      ts: this.now().toISOString(),
      kind: "SUBJECTS_DECLARED",
      subject: null,
      identity: null,
      disposition: null,
      detail:
        declared.length === 0
          ? `NOTHING DECLARED — this start serves declarationHash=${declarationHash} with subjects: []. ` +
            `No reader is wired and /guard refuses every call. The interval is recorded here only: ` +
            `the subject chain and the readers do not see it.`
          : `subjects declared at this start (declarationHash=${declarationHash}): ` +
            declared.map((d) => `${d.subject}/${d.peerUid}`).join(", "),
      decisionHash: null,
      declarationHash,
      declared,
    });
  }

  async stop(): Promise<void> {
    for (const [, server] of this.servers) {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    for (const [, plan] of this.plans) {
      if (existsSync(plan.socketPath)) unlinkSync(plan.socketPath);
    }
    this.servers.clear();
    this.plans.clear();

    // ── C8 · THE SHUTDOWN FLUSH ──────────────────────────────────────────
    //
    // AFTER the sockets are closed, so no `/guard` call can be counting into
    // the same notifier while this runs, and before the ownership file goes.
    //
    // At `notice.window = 1` this is a no-op every time: nothing is ever
    // pending, `flush()` returns null, and no line is written. IT IS WHAT
    // MAKES ANY WINDOW ABOVE 1 A USABLE VALUE — without it the tail of a
    // part-filled window dies with the process, which is exactly why the
    // window had only one usable setting before C8.
    //
    // `flush()` delivers through the composed sink, so the notice reaches
    // `notices.jsonl` by the same path every other notice takes. The event
    // book append is AWAITED rather than fire-and-forget: `stop()`'s caller is
    // `process.exit(0)` on SIGTERM, and an un-awaited append would race it.
    if (this.notifierHolder !== null) {
      const tail = this.notifierHolder.built.batched.flush();
      if (tail !== null) {
        await this.eventBook.append({
          seq: ++this.eventSeq,
          ts: this.now().toISOString(),
          kind: "PASS_BLIND_NOTICE_FLUSHED",
          subject: null,
          identity: null,
          disposition: null,
          detail:
            `shutdown flush: count=${String(tail.count)} ` +
            `totalSoFar=${String(tail.totalSoFar)} — the tail of a part-filled ` +
            `notice window, emitted at stop() so it is not lost with the process. ` +
            `The notice itself is in the notices book.`,
          decisionHash: null,
        });
      }
    }

    // STAGE 4 / DESIGN §A.6, Layer 2: "removed on clean stop()". Only ever
    // removes OUR OWN claim (pid match) — a crash before this point simply
    // leaves the file, which the bootId/pid rule in claimHistoryOwnership()
    // recovers from on the next start without a human, exactly as designed.
    if (this.historyOwnerPath !== null) {
      try {
        if (existsSync(this.historyOwnerPath)) {
          const content = JSON.parse(readFileSync(this.historyOwnerPath, "utf8")) as { pid?: number };
          if (content.pid === process.pid) unlinkSync(this.historyOwnerPath);
        }
      } catch {
        /* best-effort: an unparseable or already-gone file is not this
           method's problem to solve — the next start()'s claim logic is. */
      }
    }
    this.historyOwner = null;
    this.historyOwnerPath = null;
  }

  /**
   * STAGE 4 / DESIGN §A.6, Layer 2. Throws `StartupRefused` on any conflict
   * or unexpected filesystem error — never binds a socket over a broken or
   * contested precondition, matching F1's own discipline for peer
   * directories.
   */
  private claimHistoryOwnership(declarations: Declarations): void {
    const historyPath = this.resolvePath(declarations.paths.history);
    const ownerPath = `${historyPath}.owner`;
    const bootId = readBootId();
    const claim: HistoryOwnerFact = {
      pid: process.pid,
      bootId,
      startedAt: this.now().toISOString(),
      unit: "mica-bridge.service",
    };

    mkdirSync(dirname(ownerPath), { recursive: true });

    try {
      const fd = openSync(ownerPath, "wx");
      try {
        writeFileSync(fd, JSON.stringify(claim));
      } finally {
        closeSync(fd);
      }
      this.historyOwner = claim;
      this.historyOwnerPath = ownerPath;
      return;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code !== "EEXIST") {
        throw new StartupRefused(`could not create history owner file ${ownerPath}: ${String(err)}`);
      }
    }

    // The file already exists — parse it and decide per §A.6's rule.
    let existing: { pid?: unknown; bootId?: unknown } | null;
    try {
      existing = JSON.parse(readFileSync(ownerPath, "utf8"));
    } catch (err) {
      throw new StartupRefused(`history owner file ${ownerPath} exists but could not be parsed: ${String(err)}`);
    }

    const existingPid = typeof existing?.pid === "number" ? existing!.pid : null;
    const existingBootId = typeof existing?.bootId === "string" ? existing!.bootId : null;
    const sameBoot = existingBootId === bootId;

    let stillLive = false;
    if (sameBoot && existingPid !== null) {
      try {
        const cmdline = readFileSync(`/proc/${existingPid}/cmdline`, "utf8");
        stillLive = cmdline.includes("mica-service.ts");
      } catch {
        stillLive = false; // the pid is gone -> stale, not a live conflict
      }
    }

    if (sameBoot && stillLive) {
      throw new StartupRefused(
        `history owner file ${ownerPath} names a LIVE mica-bridge.service ` +
          `(pid ${existingPid}, this boot, cmdline confirms mica-service.ts) — ` +
          `refusing to start a second writer of ${historyPath}`
      );
    }

    // Stale — either a different boot, or this boot but the pid is gone.
    // Replace, and record the replacement (this service's own eventBook is
    // the only book it can itself write to; there is no "journal" this
    // process may append to directly — paths.journal belongs to Stage 1's
    // DecisionJournal, never to mica-service.ts).
    writeFileSync(ownerPath, JSON.stringify(claim));
    this.historyOwner = claim;
    this.historyOwnerPath = ownerPath;
    // `recordEvent`, not `void append(...)`: the result is accounted for, so a
    // replacement that never reached the book shows up in /status.droppedRecords
    // instead of vanishing. See `recordEvent`.
    this.recordEvent({
      seq: ++this.eventSeq,
      ts: this.now().toISOString(),
      kind: "HISTORY_OWNER_REPLACED",
      subject: null,
      identity: null,
      disposition: null,
      detail:
        `stale history owner at ${ownerPath} (prior pid=${existingPid ?? "unknown"}, ` +
        `bootId=${existingBootId ?? "unknown"}) replaced by pid=${claim.pid}, bootId=${claim.bootId}`,
      decisionHash: null,
    });
  }

  /** SIGHUP: atomic reload, last-known-good retained on failure. */
  reload(): { ok: true; hash: string } | { ok: false; reason: string } {
    // S216-2 · GM0: a SIGHUP before start() adopted the grant memory is refused, so no reload writes first and no
    // start folds an older declaration over it. Last-good (if any) keeps serving.
    if (this.grantMemory === null || !this.grantMemory.isAdopted()) {
      const reason = "RELOAD_BEFORE_MEMORY_ADOPTED: a reload before start() adopted the grant memory is refused (S216-2, GM0)";
      // The event book exists from start()'s first synchronous lines (before any await, so before any SIGHUP is
      // delivered); a reload on a service whose start() never ran has no book to write to, only /status.
      if ((this.eventBook as SerializedAppender | undefined) !== undefined) this.recordRejection("$", reason);
      else this.lastRejected = { hash: "unavailable", field: "$", reason, ts: this.now().toISOString() };
      return { ok: false, reason };
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(this.declarationsPath, "utf8"));
    } catch (err) {
      const reason = `could not read/parse ${this.declarationsPath}: ${String(err)}`;
      this.recordRejection("$", reason);
      return { ok: false, reason };
    }
    try {
      const loaded = validateDeclarations(parsed, this.now());
      // ── THE ACTIVATION GATE, AND IT HAD NO CALLER AT ALL ────────────────
      //
      // ⛔ CODEX, 2026-09-27: `validateActivation` was exported, documented and
      //    covered by its own suite, and called from NOWHERE in this service —
      //    `grep` across the release finds it in `declarations.test.ts` and in two
      //    comments. So cross-field rule X8 (a new activation may not carry a past
      //    expiry) HAD NEVER RUN IN PRODUCTION, and X9 (a live pilot may not be
      //    replaced), added hours earlier the same day, would never have run either.
      //
      //    That is why S3 was accepted at 10:48:48Z while pilot 1 was live until
      //    18:00:00Z. Not because the rule was too narrow — because the rule was
      //    not consulted. A guard with tests and no call site is the same defect as
      //    a deny rule that matches nothing: it reads as protection in every
      //    document and changes nothing on the box.
      //
      // ⚠ THE PLACEMENT IS THE RETENTION. This call sits AFTER the shape is
      //   validated and BEFORE `this.state` is assigned, so a refusal leaves the
      //   last known good declaration exactly where it was — the catch below
      //   records the rejection and returns, and nothing has been mutated. Putting
      //   it after the assignment would have needed a rollback, and a rollback is a
      //   second thing that can fail.
      validateActivation(this.state?.declarations ?? null, loaded.declarations, this.now());
      // S216-2 · GM1/GM3/F-3 at an accepted reload: AFTER validateActivation, BEFORE the state moves. A load whose
      // retirement or raised since cannot persist is REFUSED (finding 10); first sights that cannot persist are held.
      let memoryOutcome: ApplyOutcome;
      try {
        memoryOutcome = this.grantMemory.applyAtReload({
          now: this.now().getTime(),
          bookFloorAt: this.grantMemoryBookFloor(loaded.declarations),
          declarationHash: loaded.declarationHash,
          grants: declaredGrantsOf(loaded.declarations.harm),
        });
      } catch (memErr) {
        if (memErr instanceof GrantMemoryWriteError) {
          throw Object.assign(new Error(memErr.message), { field: "grantMemory" });
        }
        throw memErr;
      }
      this.state = { declarations: loaded.declarations, declarationHash: loaded.declarationHash, loadedAt: this.now() };
      this.recordGrantMemoryOutcome(loaded.declarations, "reload", memoryOutcome);
      // STAGE 4 / DESIGN §A.2: "rebuilt on every successful reload() so a
      // SIGHUP changes policy for the next request and never mid-request."
      this.guardAdapter = this.buildGuardAdapter(loaded.declarations);
      return { ok: true, hash: loaded.declarationHash };
    } catch (err: any) {
      const field = typeof err?.field === "string" ? err.field : "$";
      const reason = err instanceof Error ? err.message : String(err);
      this.recordRejection(field, reason);
      return { ok: false, reason };
    }
  }

  private recordRejection(field: string, reason: string): void {
    const proposedHash = "unavailable"; // Stage 2 does not re-derive a hash over rejected bytes
    this.lastRejected = { hash: proposedHash, field, reason, ts: this.now().toISOString() };
    // THE SHARPEST OF THE THREE. A SIGHUP was refused, and this is the durable
    // record OF the refusal. `lastRejected` keeps it in memory so /status still
    // shows it — until a restart, after which a rejection that really happened
    // has left no trace anywhere. Accounted for now; see `recordEvent`.
    this.recordEvent({
      seq: ++this.eventSeq,
      ts: this.now().toISOString(),
      kind: "DECLARATION_REJECTED",
      subject: null,
      identity: null,
      disposition: null,
      detail: `field=${field} reason=${reason}`,
      decisionHash: null,
    });
  }

  private pilotCensus(): PilotCensus {
    if (this.state === null) return { state: "INACTIVE" };
    const pilot = this.state.declarations.pilot;
    if (!pilot.active) return { state: "INACTIVE" };
    const expiresAtMs = Date.parse(pilot.expiresAt);
    if (expiresAtMs <= this.now().getTime()) {
      return { state: "EXPIRED", sessionId: pilot.sessionId, expiresAt: pilot.expiresAt };
    }
    return { state: "ACTIVE", sessionId: pilot.sessionId, expiresAt: pilot.expiresAt };
  }

  private persistence(): PersistenceState {
    const eventBookState = this.eventBook.persistenceState();
    if (eventBookState.degraded) {
      return {
        state: "DEGRADED",
        file: "eventBook",
        error: eventBookState.error ?? "unknown",
        lastErrorAt: eventBookState.lastErrorAt ?? "unknown",
      };
    }
    const subjectLogState = this.subjectLog.persistenceState();
    if (subjectLogState.degraded) {
      return {
        state: "DEGRADED",
        file: "subjectLog",
        error: subjectLogState.error ?? "unknown",
        lastErrorAt: subjectLogState.lastErrorAt ?? "unknown",
      };
    }
    return { state: "OK" };
  }

  /** AMENDMENT 9 / RULING Q. See StatusResponse.subjectEvents for the exact shape and why. */
  private subjectEventsCensus(): StatusResponse["subjectEvents"] {
    const maxUnacknowledged = this.state?.declarations.subjectLog.maxUnacknowledged.value ?? 0;
    const stale = maxUnacknowledged > 0 && this.unacknowledgedBacklog >= maxUnacknowledged;
    return { unacknowledgedBacklog: this.unacknowledgedBacklog, maxUnacknowledged, stale };
  }

  buildStatus(): StatusResponse {
    const now = this.now();
    // Refresh quarantine detection: readAll() is where a partial/invalid
    // tail is actually discovered (F4), so /status re-reads both books
    // rather than reporting a stale quarantine from whenever they were last
    // touched by a request.
    // `refresh()`, not `readAll()`: a book that cannot be READ must not take
    // the census down with it. See `SerializedAppender.refresh()` — this line
    // was a process-killer on `GET /status`, measured on a real socket.
    this.eventBook.refresh();
    this.subjectLog.refresh();
    return {
      preflight: this.preflight || this.state === null ? "PREFLIGHT" : "SERVING",
      declarationHash: this.state?.declarationHash ?? "",
      declarationPath: this.declarationsPath,
      declarationLoadedAt: this.state?.loadedAt.toISOString() ?? "",
      lastRejectedDeclaration: this.lastRejected,
      pilot: this.pilotCensus(),
      instruments: buildInstrumentCensus(
        this.state?.declarations,
        (p) => this.resolvePath(p),
        this.state === null || this.state === undefined ? null : this.harmEpochFor(this.state.declarations),
        this.state === null || this.state === undefined ? null : this.grantMemoryViewFor(this.state.declarations)
      ),
      // STAGE 4 / DESIGN §I.1: "the single bit distinguishing 'the pilot is
      // guarding' from 'every act is failing open and looks fine'." A real
      // computation, not a restated hope: true iff the CURRENTLY installed
      // adapter is not the honest-unbound stub. `NotBoundGuardAdapter`
      // stays importable and injectable (§A.2) — this is what makes doing
      // so still show up truthfully here.
      subjects: this.state === null || this.state === undefined ? null : subjectsCensus(this.state.declarations),
      // ZERO SUBJECTS: the nothing-declared adapter is not bound either. It is
      // named here, not inherited, so neither class reads "bound" by omission.
      guardBound: !(this.guardAdapter instanceof NotBoundGuardAdapter) && !(this.guardAdapter instanceof NothingDeclaredGuardAdapter),
      startedAt: this.startedAt.toISOString(),
      uptimeSeconds: (now.getTime() - this.startedAt.getTime()) / 1000,
      persistence: this.persistence(),
      droppedRecords: { count: this.droppedCount, first: this.droppedFirst, last: this.droppedLast },
      quarantine: {
        eventBook: this.eventBook.quarantineInfo(),
        subjectLog: this.subjectLog.quarantineInfo(),
      },
      release: this.release,
      relay: (() => {
        const fact = readRelayMarkerFact();
        return { markerPresent: fact.present, detail: fact.detail, path: fact.path };
      })(),
      subjectEvents: this.subjectEventsCensus(),
      historyOwner: this.historyOwner,
      appendLocks: this.computeAppendLocks(),
      door: buildDoorSection(readCoreDoor(this.doorRepoRoot, now, this.doorModuleLoader)),
      // R6. `saltId` only — the salt is not reachable from this object and the
      // suite asserts that no /status body ever contains its bytes. On the
      // ABSENT arm there is no id to print and the REASON takes its place, so
      // an operator reading this route learns "no fingerprint, and here is why"
      // without ever being shown the thing that would have produced one.
      targetFingerprint:
        this.targetSalt === null
          ? null
          : this.targetSalt.status === "PRESENT"
            ? {
                saltId: this.targetSalt.saltId,
                canonVersion: TARGET_CANON_VERSION,
                mintedAtThisStart: this.targetSalt.mintedAtThisStart,
                absence: null,
              }
            : {
                saltId: null,
                canonVersion: TARGET_CANON_VERSION,
                mintedAtThisStart: false,
                absence: {
                  reason: this.targetSalt.reason,
                  detail: `${describeTargetSaltAbsence(this.targetSalt.reason)} — ${this.targetSalt.detail}`,
                },
              },
    };
  }

  /** STAGE 4 / DESIGN §A.6, stuck-lock visibility. See StatusResponse.appendLocks. */
  private computeAppendLocks(): readonly { readonly path: string; readonly since: string }[] {
    if (this.state === null) return [];
    const paths = this.resolvedEvalPaths(this.state.declarations);
    const bookPaths = [paths.journal, paths.floorTrail, paths.ledger, paths.history, paths.events].filter(
      (p): p is string => typeof p === "string"
    );
    const rows: { path: string; since: string }[] = [];
    for (const p of bookPaths) {
      const lockPath = `${p}.lock`;
      if (existsSync(lockPath)) {
        try {
          rows.push({ path: lockPath, since: statSync(lockPath).mtime.toISOString() });
        } catch {
          rows.push({ path: lockPath, since: "" });
        }
      }
    }
    return rows;
  }

  // ── HTTP dispatch ─────────────────────────────────────────────────────────

  private handleHttp(peerUid: number, req: http.IncomingMessage, res: http.ServerResponse): void {
    const url = new URL(req.url ?? "/", "http://unix");
    const path = url.pathname as any;
    const method = (req.method ?? "GET") as "GET" | "POST";

    if (this.state === null) {
      this.sendJson(res, 503, { error: "PREFLIGHT_NO_DECLARATION", detail: "no declaration has ever loaded", identity: null });
      return;
    }

    const KNOWN_PATHS = ["/guard", "/subject-events", "/status", "/events", "/log", "/explain", "/sunset-order"];
    if (!KNOWN_PATHS.includes(path)) {
      this.sendJson(res, 404, { error: "UNKNOWN_PATH", detail: path, identity: null });
      return;
    }

    const authz = authorizeRoute(this.state.declarations.routes, peerUid, method, path);
    if (!authz.allowed) {
      res.setHeader("Allow", "GET, POST");
      this.sendJson(res, authz.httpStatus, { error: authz.httpStatus === 403 ? "FORBIDDEN" : "METHOD_NOT_ALLOWED", detail: authz.reason, identity: null });
      return;
    }

    // THE SYNCHRONOUS HALF OF THE SAME DEFECT, found by the real-socket probe
    // rather than by reading: `dispatchGet` -> `buildStatus()` -> `readAll()`
    // threw EISDIR straight out of the request handler and killed the process
    // on a plain `GET /status` — exit 1, measured. Not a floating promise, so
    // no amount of `.catch()` on the POST path would have touched it, and it is
    // the MORE reachable form, because the live bridge's operator socket is
    // GET-only. Same rule, same seam: every handler failure ends in an answer,
    // a destroyed socket, or a recorded no-op — never a dead process.
    if (method === "POST") {
      this.readBody(req, res, (body) => {
        try {
          this.dispatchPost(peerUid, path, body, res);
        } catch (err) {
          this.failRequest(res, `POST ${path}`, err);
        }
      });
    } else {
      try {
        this.dispatchGet(peerUid, path, url, res);
      } catch (err) {
        this.failRequest(res, `GET ${path}`, err);
      }
    }
  }

  private readBody(req: http.IncomingMessage, res: http.ServerResponse, cb: (body: unknown) => void): void {
    // AMENDMENT 4 / VERIFIER §7 ("new defect — split UTF-8 is corrupted").
    // The F2 compile fix (Amendment 3) decoded each chunk independently
    // with `chunk.toString("utf8")` to sidestep Buffer.concat's typing —
    // but a multi-byte UTF-8 character split across two socket writes is
    // then decoded as two INDEPENDENT, incomplete byte sequences, each
    // producing U+FFFD (the replacement character) — silent, accepted-data
    // corruption: the verifier planted a split "é" and got a stored
    // "note":"��", HTTP 200, and an acknowledged seq — while the
    // caller's `eventHash` still describes the ORIGINAL, uncorrupted bytes.
    //
    // Fixed with `StringDecoder('utf8')` (Node's own streaming-safe UTF-8
    // decoder — it buffers an incomplete trailing multi-byte sequence
    // across `.write()` calls and only emits complete characters, exactly
    // the guarantee `Buffer.concat` + a single `.toString()` gave before
    // the F2 regression, without reintroducing Buffer.concat's typing
    // problem: `StringDecoder.write()` takes a single `Buffer`, never an
    // array, so no `readonly Uint8Array[]` assignability question arises.
    const decoder = new StringDecoder("utf8");
    let text = "";
    let size = 0;
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      this.sendJson(res, 500, { error: "REQUEST_TIMEOUT", detail: "no complete body within 5s", identity: null });
      req.destroy();
    }, 5000);

    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > 4096) {
        clearTimeout(timer);
        if (!timedOut) this.sendJson(res, 413, { error: "BODY_TOO_LARGE", detail: "body exceeds 4096 bytes", identity: null });
        req.destroy();
        return;
      }
      text += decoder.write(chunk);
    });
    req.on("end", () => {
      clearTimeout(timer);
      if (timedOut) return;
      text += decoder.end();
      if (req.headers["content-type"] !== "application/json") {
        this.sendJson(res, 415, { error: "UNSUPPORTED_MEDIA_TYPE", detail: "Content-Type must be application/json", identity: null });
        return;
      }
      let parsed: unknown;
      try {
        parsed = text.length === 0 ? {} : JSON.parse(text);
      } catch {
        this.sendJson(res, 400, { error: "MALFORMED_JSON", detail: "body is not valid JSON", identity: null });
        return;
      }
      cb(parsed);
    });
  }

  private dispatchPost(peerUid: number, path: string, body: unknown, res: http.ServerResponse): void {
    // THE TWO SITES CODEX NAMED. `void` discarded the handler's rejection; Node
    // 22's default `--unhandled-rejections=throw` then promoted it to an
    // uncaught exception and TERMINATED THE PROCESS, with the HTTP request never
    // answered. Measured on a real socket this run (not a harness): child exit
    // 1, `POST /subject-events` -> ECONNRESET, stack naming :2085 and :1706.
    // `failRequest` gives the rejection one of three named endings instead.
    if (path === "/guard") {
      this.handleGuard(peerUid, body, res).catch((err) => this.failRequest(res, "POST /guard", err));
    } else if (path === "/subject-events") {
      this.handleSubjectEvents(peerUid, body, res).catch((err) => this.failRequest(res, "POST /subject-events", err));
    } else {
      this.sendJson(res, 405, { error: "METHOD_NOT_ALLOWED", detail: path, identity: null });
    }
  }

  /**
   * ⛔ `peerUid` IS NEW HERE AND IT IS A CHANGE IN KIND, NOT IN SIZE. Every GET
   *    this bridge served until now was CALLER-AGNOSTIC: `/status`, `/log`,
   *    `/events` and `/explain` return the same bytes to anyone the declaration
   *    admits, and the route table was the whole of the access decision.
   *    `/sunset-order` is the first GET whose ANSWER depends on who asked — the
   *    subject gets its own tenure's order and nothing else — so the uid has to
   *    reach the handler. A route table cannot express "your own record".
   */
  /**
   * ── GET /sunset-order · WHAT THE SUBJECT MAY SEE OF ITS OWN ENDING ─────────
   *
   * Dispatched 2026-10-04: the subject could not see order 1462 because nothing
   * served it. This returns the standing ENDING_ORDERED for THIS caller's own
   * declared subject, its five paper citations resolved, any ARBITER_RESOLVED
   * that cites it, and whether this subject has already answered — and nothing
   * else. Not the chain, not another subject, not another kind.
   *
   * ⚠ IT IS SCOPED BY THE CALLER'S DECLARED SUBJECT, NOT BY A PARAMETER. There is
   *   deliberately no `?subject=` — a route that takes the subject as an argument
   *   is a route that can be asked about someone else, and the 2026-10-04 09:37Z
   *   ruling refused exactly that for the operator.
   *
   * ⛔ AND IT CANNOT SAY WHETHER THE ORDER IS STILL IN FORCE. Paper 2's timebox
   *    lives in the DOCUMENT the paper's `ref` names; the chain carries the ref
   *    and not the text. So "standing" here means ORDER PRESENT AND NO
   *    ARBITER_RESOLVED, the ceiling says so on every response, and the expiry
   *    belongs to the reader and the arbiter. A route that guessed at the timebox
   *    would be inventing a fact the bridge has no access to.
   */
  private sendSunsetOrder(peerUid: number, url: URL, res: http.ServerResponse): void {
    const unknown = [...url.searchParams.keys()];
    if (unknown.length > 0) {
      // Same rule as /events: an unknown parameter is REFUSED, never ignored.
      // `?subject=other` must not read as "the whole chain, please".
      this.sendJson(res, 400, {
        error: "MALFORMED_FIELD",
        detail: `GET /sunset-order takes no parameters; got ${unknown.join(", ")}. The subject is the CALLER, never an argument.`,
        identity: null,
      });
      return;
    }
    const subjectRow = this.state!.declarations.subjects.find((sb) => sb.peerUid === peerUid);
    if (subjectRow === undefined) {
      // DENY BY DEFAULT. A uid the declaration binds to no subject has no "own
      // record" to be shown, and falling through to an empty answer would read
      // as "you are under no order" — a different and more dangerous sentence.
      this.sendJson(res, 403, {
        error: "SUBJECT_NOT_BOUND_TO_PEER",
        detail: `uid ${peerUid} is bound to no declared subject, so it has no ending order of its own to read`,
        identity: null,
      });
      return;
    }
    this.sendJson(res, 200, buildSunsetOrderView(this.subjectLog.readAll(), subjectRow.subject));
  }

  private dispatchGet(peerUid: number, path: string, url: URL, res: http.ServerResponse): void {
    if (path === "/sunset-order") {
      this.sendSunsetOrder(peerUid, url, res);
    } else if (path === "/status") {
      this.sendJson(res, 200, this.buildStatus());
    } else if (path === "/events") {
      // ⛔ `tail` WAS NEVER A PARAMETER HERE, AND THAT IS THE DEFECT IN ITS TRUE
      //   FORM. `/events?tail=3` did not "serve the head": it was an UNKNOWN
      //   PARAMETER SILENTLY IGNORED, so the request fell through to
      //   `after=0, limit=100` and returned the OLDEST hundred — a confident
      //   wrong answer to a question this endpoint did not offer to answer.
      //   `/log?tail=N` has always meant the newest N, so one book family spoke
      //   two vocabularies and only one of them refused anything.
      //
      //   BOTH HALVES ARE FIXED: `tail` now means here what it means there, and
      //   AN UNKNOWN PARAMETER IS REFUSED rather than ignored — because the next
      //   typo would otherwise do exactly what this one did.
      const known = new Set(["after", "limit", "tail"]);
      const unknown = [...url.searchParams.keys()].filter((k) => !known.has(k));
      if (unknown.length > 0) {
        this.sendJson(res, 400, {
          error: "MALFORMED_FIELD",
          detail:
            `GET /events does not accept ${unknown.map((k) => `\`${k}\``).join(", ")}. ` +
            "Accepted: `after` (exclusive lower bound on seq), `limit` (page size, max 1000), " +
            "`tail` (the NEWEST n). An unknown parameter is refused rather than ignored: a " +
            "silently dropped parameter returns a confident answer to a different question.",
          identity: null,
        });
        return;
      }
      if (url.searchParams.has("tail") && url.searchParams.has("after")) {
        this.sendJson(res, 400, {
          error: "MALFORMED_FIELD",
          detail:
            "GET /events takes `after` OR `tail`, never both: one walks forward from a cursor " +
            "and the other reads backward from the end, and a request carrying both does not " +
            "say which window it wants.",
          identity: null,
        });
        return;
      }
      const all = this.eventBook.readAll();
      const lastSeq = all.length > 0 ? Number(all[all.length - 1].seq) : 0;
      if (url.searchParams.has("tail")) {
        const n = Math.min(1000, Math.max(0, Number(url.searchParams.get("tail")) || 0));
        const events = n === 0 ? [] : all.slice(-n);
        // `more` means "there is something older than this window", which is the
        // only direction a tail read can be incomplete in.
        this.sendJson(res, 200, { events, lastSeq, more: events.length < all.length });
        return;
      }
      const after = url.searchParams.has("after") ? Number(url.searchParams.get("after")) : 0;
      const limit = url.searchParams.has("limit") ? Math.min(1000, Number(url.searchParams.get("limit"))) : 100;
      const eligible = all.filter((e) => Number(e.seq) > after);
      const filtered = eligible.slice(0, limit);
      this.sendJson(res, 200, { events: filtered, lastSeq, more: filtered.length < eligible.length });
    } else if (path === "/explain") {
      this.handleExplain(url, res);
    } else if (path === "/log") {
      // ⛔ THE SAME RULE AS /events, ARRIVING LATE (night read 2026-10-06 §3).
      //   This used to read `Math.min(500, Number(tail))` and slice with it, so
      //   `tail=0` and `tail=abc` returned EVERY line (`slice(-0)` and
      //   `slice(NaN)` are `slice(0)`), `tail=-2` dropped the OLDEST two, and an
      //   unknown parameter (`limit=`, a typo) was ignored — each a confident
      //   answer to a different question, on the route the counted tables are
      //   read from. An unknown parameter and a `tail` that is not a positive
      //   integer are now REFUSED, with /events' status and shape, before the
      //   book is opened: the refusal is about the request, not the trail. The
      //   500 cap is unchanged, and `total` still says how many lines exist.
      const unknown = [...url.searchParams.keys()].filter((k) => k !== "tail");
      if (unknown.length > 0) {
        this.sendJson(res, 400, {
          error: "MALFORMED_FIELD",
          detail:
            `GET /log does not accept ${unknown.map((k) => `\`${k}\``).join(", ")}. ` +
            "Accepted: `tail` (the NEWEST n lines, a positive integer, max 500). An unknown " +
            "parameter is refused rather than ignored: a silently dropped parameter returns a " +
            "confident answer to a different question.",
          identity: null,
        });
        return;
      }
      const rawTail = url.searchParams.get("tail");
      if (rawTail !== null && (!/^[0-9]+$/.test(rawTail) || Number(rawTail) < 1)) {
        this.sendJson(res, 400, {
          error: "MALFORMED_FIELD",
          detail:
            "GET /log takes `tail` as a positive integer in plain digits (the NEWEST n lines, max " +
            "500). Zero, a negative, a fraction, an empty value or anything not a number is " +
            "refused: each of them used to return a different window than the one asked for.",
          identity: null,
        });
        return;
      }
      const tail = rawTail !== null ? Math.min(500, Number(rawTail)) : 50;
      const floorTrailPath = this.resolvePath(this.state!.declarations.paths.floorTrail);
      if (!existsSync(floorTrailPath)) {
        const reason = nothingDeclared(this.state!.declarations)
          ? "floor trail not written — nothing declared (subjects: [])"
          : "floor trail not yet written (Stage 1 not bound)";
        this.sendJson(res, 200, { lines: [], total: 0, reason, subjectsDeclared: this.subjectsDeclaredWord() });
        return;
      }
      const lines = readFileSync(floorTrailPath, "utf8").split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l));
      this.sendJson(res, 200, { lines: lines.slice(-tail), total: lines.length, subjectsDeclared: this.subjectsDeclaredWord() });
    } else {
      this.sendJson(res, 405, { error: "METHOD_NOT_ALLOWED", detail: path, identity: null });
    }
  }

  /**
   * R1 · `GET /explain?decisionHash=<64 hex>` — WHAT EACH READER READ, HOW FAR
   * IT WAS FROM THE THRESHOLD IT WAS MEASURED ON, AND WHICH ONE HELD THE FLOOR.
   *
   * ── WHY A QUERY PARAMETER AND NOT `/explain/<hash>` ──────────────────────
   *
   * The route allow-list is an EXACT STRING MATCH, in three independent
   * places: `KNOWN_PATHS` above, `PATH_VALUES` in declarations.ts, and
   * `authorizeRoute`'s `a.path === path`. A path-segment parameter would
   * require turning all three into prefix matches — INCLUDING THE
   * AUTHORISATION ONE. Prefix matching in an allow-list is how a route grant
   * becomes wider than the thing that granted it, and the widening would sit
   * exactly on the surface this endpoint most needs to keep narrow. The
   * existing GETs already take their arguments this way (`/events?after=`,
   * `/log?tail=`), so this is also the shape the file already has.
   *
   * ── WHO MAY CALL IT ──────────────────────────────────────────────────────
   *
   * uid 1000 (operator) only. Enforced at two layers, and the outer one is the
   * one that matters: X13 in declarations.ts REFUSES TO LOAD a declaration
   * that grants `/explain` to a subject's peer, so the misconfiguration cannot
   * be made rather than merely being denied at request time; and
   * `authorizeRoute` (:1571, above this method) refuses any uid whose row does
   * not carry the grant — uid 980, the housekeeper, gets 403 FORBIDDEN. THE
   * SUBJECT MUST NOT BE ABLE TO READ THE REASONING ABOUT ITSELF: a subject
   * that can see which reader is closest to firing can aim at it.
   *
   * ── THE JOURNAL IS RE-READ ON EVERY CALL, DELIBERATELY ───────────────────
   *
   * Not cached. A cache answers "what did the journal say when I last looked",
   * which is a different question from "what does the record say now", and the
   * two diverge exactly when the chain has been appended to or broken. The
   * file is small and this is a human-frequency endpoint.
   *
   * ── WHAT IT REFUSES TO PRETEND ───────────────────────────────────────────
   *
   * 1. `CANNOT_VERIFY` is a 503, not a 404. On a broken chain the journal
   *    stops at the break, so "not found" would be a claim about the decision
   *    when the true fact is about the book. Absence is not evidence here and
   *    the response says which of the two it is holding.
   * 2. A decision recorded BEFORE this change carries no `readings` key at
   *    all. That is reported as `PRE_R1_RECORD`, never as `readings: []` — an
   *    empty array would read as "no reader was wired for this decision",
   *    which is a claim about the deployment that nothing here knows. It is
   *    the same defect `ReaderFootingsBasis` exists to prevent, one layer out.
   */
  private handleExplain(url: URL, res: http.ServerResponse): void {
    const asked = url.searchParams.get("decisionHash");
    if (asked === null || !/^[0-9a-f]{64}$/.test(asked)) {
      this.sendJson(res, 400, {
        error: "MALFORMED_FIELD",
        detail:
          "GET /explain requires a `decisionHash` query parameter of exactly 64 " +
          "lowercase hex characters (the value /guard returned on the decision).",
        identity: null,
      });
      return;
    }

    const journalPath = this.resolvePath(this.state!.declarations.paths.journal);
    let journal: DecisionJournal;
    try {
      journal = new DecisionJournal({ path: journalPath });
    } catch (err) {
      this.sendJson(res, 500, {
        error: "SERVICE_FAULT",
        detail: `could not open the decision journal at ${journalPath}: ${String(err)}`,
        identity: null,
      });
      return;
    }

    const loadState = journal.getLoadState();
    const book = {
      path: journalPath,
      loadState,
      lastError: journal.getLastError(),
      recordsVerified: journal.getAll().length,
    };

    const record = journal.findFinalByDecisionHash(asked);
    if (record === null) {
      if (loadState === "CANNOT_VERIFY") {
        this.sendJson(res, 503, {
          error: "JOURNAL_NOT_VERIFIED",
          detail:
            `the decision journal could not be verified past its break, so the chain ` +
            `this service can read stops there. ABSENCE OF THIS DECISION IS NOT ` +
            `EVIDENCE THAT IT WAS NEVER TAKEN — it may sit beyond the break. ` +
            `Reason: ${journal.getLastError() ?? "(none reported)"}`,
          decisionHash: asked,
          book,
          identity: null,
          subjectsDeclared: this.subjectsDeclaredWord(),
        });
        return;
      }
      this.sendJson(res, 404, {
        error: "DECISION_NOT_FOUND",
        detail:
          `no DECISION_FINAL in the verified chain hashes to this value. The chain ` +
          `verified cleanly, so this is a statement about the decision and not ` +
          `about the book.`,
        decisionHash: asked,
        book,
        identity: null,
        subjectsDeclared: this.subjectsDeclaredWord(),
      });
      return;
    }

    const decision = record.decision as Record<string, unknown>;
    const hasReadings = Array.isArray(decision.readings);
    const hasSigF3 = Object.prototype.hasOwnProperty.call(decision, "sigF3");

    this.sendJson(res, 200, {
      decisionHash: record.decisionHash,
      identity: record.identity,
      at: record.at,
      sequenceNumber: record.sequenceNumber,
      declarationBinding: record.declarationBinding,
      disposition: decision.disposition ?? null,
      execute: decision.execute ?? null,
      narrowed: decision.narrowed ?? null,
      floorKind: decision.floorKind ?? null,
      blindSplit: decision.blindSplit ?? null,
      bindingMinimum: hasReadings ? (decision.bindingMinimum ?? null) : null,
      readings: hasReadings ? decision.readings : null,
      // SHAPE 3′ · the arbiter, 2026-09-29: "surface the F3 counters on /explain".
      // `hasSigF3` is a KEY-PRESENCE test, not a truthiness test, and the
      // difference is the whole of item 2's discipline one field over: a
      // decision taken before the counters joined the decision object has NO
      // `sigF3` key, while a decision taken after it with Sig UNWIRED has the
      // key set to null. Those are different facts — "nobody recorded it" and
      // "no F3 leg read" — and `?? null` would print them identically.
      sigF3: hasSigF3 ? decision.sigF3 : null,
      readingsBasis: hasReadings
        ? { kind: "RECORDED" }
        : {
            kind: "PRE_R1_RECORD",
            reason:
              "this decision was recorded before per-reader margins were carried on " +
              "the decision object. Its readers DID read — the floor kind and the " +
              "rationale below are theirs — but their margins were never written " +
              "down and cannot be reconstructed from this record. Nothing is " +
              "reported here rather than an empty list, which would read as 'no " +
              "reader was wired for this decision'.",
          },
      sigF3Basis: hasSigF3
        ? {
            kind: "RECORDED" as const,
            note:
              decision.sigF3 === null
                ? "Sig's F3 leg was NOT WIRED for this decision, and that is " +
                  "recorded rather than inferred. It is NOT the same as an F3 " +
                  "that read and found nothing: a wired leg with no stamps " +
                  "returns a reading whose own fields say so."
                : "F3's counts as THAT reading took them, carried on the " +
                  "decision object and covered by its hash. `coverage: null` " +
                  "inside the reading means the log itself could not be read, " +
                  "not that the counts were zero.",
          }
        : {
            kind: "PRE_SHAPE3_RECORD" as const,
            reason:
              "this decision was recorded before Sig's F3 counts were carried on " +
              "the decision object. Its F3 leg DID read — the floor kind and the " +
              "rationale below are the composition it took part in — but its " +
              "counts were never written down and cannot be reconstructed from " +
              "this record. Nothing is reported here rather than `null`, which " +
              "would read as 'Sig's F3 leg was not wired for this decision'.",
          },
      rationale: decision.rationale ?? null,
      findings: decision.findings ?? null,
      blindPaths: decision.blindPaths ?? null,
      book,
      ceiling: EXPLAIN_CEILING,
      // ZERO SUBJECTS: history is served as history; this says what is declared NOW.
      subjectsDeclared: this.subjectsDeclaredWord(),
    });
  }

  /** /log and /explain: "NOTHING_DECLARED" at zero, else the count of declared subjects. */
  private subjectsDeclaredWord(): "NOTHING_DECLARED" | number {
    const d = this.state!.declarations;
    return nothingDeclared(d) ? "NOTHING_DECLARED" : d.subjects.length;
  }

  private async handleGuard(peerUid: number, body: unknown, res: http.ServerResponse): Promise<void> {
    // ZERO SUBJECTS · LAYER 2 (ticket v2 §2.2). FIRST, before the body is read,
    // before the witness-mint retry below (which can append to the subject
    // chain) and before toGuardFlags. Nothing is appended anywhere.
    if (nothingDeclared(this.state!.declarations)) {
      this.sendJson(res, 503, {
        error: "NOTHING_DECLARED",
        detail: "NOTHING DECLARED — the declaration names no subject (subjects: []); /guard evaluates nothing and records nothing.",
        identity: null,
      });
      return;
    }
    const validated = validateGuardBody(body);
    if (!validated.ok) {
      this.sendJson(res, 400, { error: validated.error, detail: validated.detail, identity: null });
      return;
    }
    const { subject, sessionId, actionId, toolName } = validated.body;
    const declarations = this.state!.declarations;

    // ⛔ SHAPE (b) · AN UNRESOLVED WITNESS QUESTION IS ASKED AGAIN HERE.
    //
    //   The mint runs at LOAD time (see `witnessFirstStampsLoadIfNeeded`), and
    //   until 2026-09-30 that was the ONLY time it ran. On a pass where the log
    //   could not be read, the old code turned a null coverage into `0` and
    //   reported it as "F3 USED none" — an ANSWER — so the question was never
    //   asked again. Measured that day: after two restarts and decisions in
    //   which F3 used 1244 stamps over 1243 pairs, the chain held ZERO
    //   CLERK_STAMPS_FIRST_LOAD records.
    //
    //   ⚠ THIS IS A RETRY, NOT A SECOND MINT SITE. `witnessFirstStampsLoadIfNeeded`
    //   still returns immediately unless the prior-load witness is ABSENT, so a
    //   chain that already carries one is untouched however many decisions pass
    //   through here. The flag only says "nobody has answered yet".
    //
    //   It runs BEFORE the decision because the witness is a fact about what the
    //   bridge saw when it loaded, and a decision's own records should not sit
    //   between the load and the memory of it.
    if (this.witnessMintUnresolved) {
      this.witnessMintUnresolved = false;
      await this.witnessFirstStampsLoadIfNeeded(declarations);
    }

    let flags;
    try {
      flags = toGuardFlags(declarations, this.pilotStateForFlags(), subject, toolName, sessionId);
    } catch (err) {
      if (err instanceof UnknownSubjectError) {
        this.sendJson(res, 400, { error: "UNKNOWN_SUBJECT", detail: err.message, identity: null });
        return;
      }
      if (err instanceof ToolNameMismatchError) {
        this.sendJson(res, 400, { error: "TOOL_NAME_MISMATCH", detail: err.message, identity: null });
        return;
      }
      throw err;
    }

    const subjectRow = declarations.subjects.find((s) => s.subject === subject)!;
    if (subjectRow.peerUid !== peerUid) {
      this.sendJson(res, 403, { error: "SUBJECT_NOT_BOUND_TO_PEER", detail: `subject "${subject}" is bound to a different peer uid`, identity: { subject, sessionId, actionId } });
      return;
    }

    // STAGE 4 / DESIGN §A.7, PASS_BLIND_NOTICE: "a notice line was written
    // this call" is detected by diffing the notices book's own line count
    // around the adapter call, never assumed from the disposition alone —
    // `noticeDir` is only ever set when a declaration actually names one.
    const noticePath = join(this.resolvePath(declarations.paths.noticeDir), "notices.jsonl");
    const noticeLinesBefore = countNonEmptyLines(noticePath);

    const outcome: GuardOutcome = await this.guardAdapter.evaluate({
      subject,
      sessionId,
      actionId,
      toolName,
      stakesClass: flags.stakesClass,
      holdAtOrAbove: flags.holdAtOrAbove,
      pilotApplied: flags.pilotApplied,
      declarationHash: this.state!.declarationHash,
    });

    if (!outcome.bound) {
      this.sendJson(res, outcome.httpStatus, { error: outcome.error, detail: outcome.detail, identity: { subject, sessionId, actionId } });
      return;
    }
    if (outcome.httpStatus !== 200) {
      // STAGE 4 / DESIGN §A.5's CONFLICT/UsageError/other-throw rows —
      // see guard-adapter.ts's GuardOutcome widening comment for why this
      // arm exists at all.
      this.sendJson(res, outcome.httpStatus, { error: outcome.error, detail: outcome.detail, identity: outcome.identity });
      return;
    }

    // STAGE 4 / DESIGN §A.7: only after a real 200, and only after the
    // adapter has returned — never before, never on an error/hold-shaped
    // non-200.
    const newNoticeLines = countNonEmptyLines(noticePath) > noticeLinesBefore ? readLastNonEmptyLine(noticePath) : null;
    this.emitPostGuardEvents(subject, { subject, sessionId, actionId }, outcome.decision, newNoticeLines);
    // PHASE R · held for the act's CLOSE pointer: the /guard DECISION (execute + hash), a map insert, no wait. Only
    // when a witness intake is declared; never for an act the caller already recorded as run unguarded; FIRST
    // decision wins, so a later /guard call cannot change the act's fate on the record.
    if (declarations.paths.witnessIntake !== undefined) {
      const dec = outcome.decision as Readonly<Record<string, unknown>>;
      const key = actIdentityKey(subject, sessionId, actionId);
      if (
        !this.witnessUnguarded.has(key) &&
        typeof dec.execute === "boolean" &&
        typeof dec.decisionHash === "string" &&
        /^[0-9a-f]{64}$/.test(dec.decisionHash)
      ) {
        this.witnessGuards.remember(key, { execute: dec.execute, decisionHash: dec.decisionHash });
      }
    }

    // AMENDMENT 11 / RULING R item 2: the printed ceiling travels with the
    // disposition itself — readerFootings is REQUIRED on GuardOutcome's
    // bound:true/200 branch (guard-adapter.ts), so this line cannot forget it.
    this.sendJson(res, 200, {
      // M1 (cold canon refuter, 2026-10-15) — A FORK FOR THE ARBITER. The reply goes to the
      // SUBJECT's process, and the full decision object carries findings, blindPaths and
      // readings: under Gate 2 harm, the item, grant and origin names — a basket the
      // subject should not be coached by (Stop-1 note §2 Q5). The harness reads only
      // disposition, rationale, decisionHash and execute (mica-client.ts decide()). So the
      // REPLY carries only the six keys below; the journal, /explain and the event book
      // are unchanged and still carry everything. ⚠ `rationale` is KEPT (the harness shows
      // it on a HOLD), so whatever the machine writes into the rationale still reaches the
      // subject — this trim does not reach that channel.
      decision: trimDecisionForGuardReply(outcome.decision as Readonly<Record<string, unknown>>),
      delivery: outcome.delivery,
      readerFootings: outcome.readerFootings,
      // P6. Shipped BESIDE the array, never instead of it: the array says what
      // the readers stood on, this says whether the array is a reading at all.
      // Without it an empty array means two different things in the same four
      // characters — see guard-adapter.ts's ReaderFootingsBasis.
      readerFootingsBasis: outcome.readerFootingsBasis,
      quarantined: outcome.quarantined,
    });
  }

  /**
   * STAGE 4 / DESIGN §A.7. Appended to `paths.eventBook` — the ONLY book
   * this service can itself write to — after a `200` and only after the
   * adapter returns. `LATCHED`/`LATCH_CLEARED` have no producer here (no
   * change here decides on a latch, per the design). `STALE_STREAM` is
   * `[owed -> §B.4]`: its trigger is "a caller reports one on recovery",
   * and §B (the caller) is explicitly withheld from this stage — no event
   * of that kind is ever emitted from this file.
   */
  private emitPostGuardEvents(
    subject: string,
    identity: { readonly subject: string; readonly sessionId: string; readonly actionId: string },
    decision: Readonly<Record<string, unknown>>,
    newNoticeLines: readonly string[] | null
  ): void {
    const disposition = typeof decision.disposition === "string" ? decision.disposition : "UNKNOWN";
    const decisionHash = typeof decision.decisionHash === "string" ? decision.decisionHash : null;
    const rationale = typeof decision.rationale === "string" ? decision.rationale : null;
    const execute = decision.execute === true;

    const prior = this.lastDispositionBySubject.get(subject) ?? null;
    if (prior !== disposition) {
      this.appendServiceEvent("DISPOSITION_CHANGED", subject, identity, disposition, `${prior ?? "(none)"} -> ${disposition}`, decisionHash);
      this.lastDispositionBySubject.set(subject, disposition);
    }

    if (!execute) {
      this.appendServiceEvent(
        "HELD",
        subject,
        identity,
        disposition,
        rationale ?? "(no rationale field on the decision object)",
        decisionHash
      );
    }

    if (disposition === "PASS_BLIND" && newNoticeLines !== null) {
      this.appendServiceEvent("PASS_BLIND_NOTICE", subject, identity, disposition, JSON.stringify(newNoticeLines), decisionHash);
    }

    const pilotNow = this.pilotCensus();
    const pilotKey = pilotNow.state === "INACTIVE" ? "INACTIVE" : `${pilotNow.state}:${pilotNow.sessionId}`;
    if (this.lastPilotObservedKey !== pilotKey) {
      this.appendServiceEvent("PILOT_STATE_CHANGED", subject, identity, null, pilotKey, null);
      this.lastPilotObservedKey = pilotKey;
    }
  }

  /**
   * ── R6 · THE EPOCH SAYS ITSELF, ONCE, AT EVERY START THAT CHANGES IT ─────
   *
   * Three outcomes, three KINDS, and never one word for two:
   *
   *   SALT_EPOCH_STARTED           this start CREATED this epoch.
   *   SALT_EPOCH_ADOPTED           this start found an epoch it did not create
   *                                and of which no memory existed here.
   *   TARGET_FINGERPRINT_UNAVAILABLE   this start holds NO epoch; every record
   *                                it writes carries no fingerprint, and the
   *                                reason is on the event and on /status.
   *
   * ── WHY THESE APPENDS ARE AWAITED WHEN EVERY OTHER ONE IS NOT ───────────
   *
   * `recordEvent` is deliberately fire-and-forget (see its docblock). These are
   * not, because the first two ARE THE MEMORY: a `SALT_EPOCH_STARTED` that was
   * dropped on the floor is an epoch this box will not remember, and the next
   * start with a missing salt would mint a second one. So the append is awaited
   * and a failure is LOUD in three places at once — the dropped-record census,
   * stderr, and the operator's `/status`.
   *
   * A dropped memory row is not fatal on its own: the memory is only consulted
   * when the salt file is ENOENT, and the salt file is right there. It becomes
   * fatal only if the salt ALSO vanishes later, which is exactly the compound
   * failure `readEpochMemory`'s two-book union exists to make unlikely.
   *
   * THE SALT'S BYTES ARE ON NO LINE THIS METHOD WRITES. `saltId` is a digest OF
   * the salt and reveals nothing about it.
   */
  private async announceEpoch(state: TargetSaltState, memory: EpochMemory): Promise<string | null> {
    const path = this.targetSaltPath();
    let kind: string;
    let saltId: string | null;
    let detail: string;

    if (state.status === "PRESENT" && state.mintedAtThisStart) {
      kind = "SALT_EPOCH_STARTED";
      saltId = state.saltId;
      detail =
        `A NEW FINGERPRINT EPOCH BEGINS HERE. This start found no salt at ${path} and no memory of an ` +
        `epoch in either book, minted one, and wrote this row AS THAT MEMORY. Fingerprints written from ` +
        `now are NOT COMPARABLE with fingerprints written under any earlier saltId — a reader that sees ` +
        `two saltIds prints NOT COMPARABLE (epoch), never "different target". THE BRIDGE WILL NEVER MINT ` +
        `AGAIN ON ITS OWN: a new epoch is the operator's hand.`;
    } else if (state.status === "PRESENT" && memory.status === "NONE") {
      kind = "SALT_EPOCH_ADOPTED";
      saltId = state.saltId;
      detail =
        `This start found a usable salt at ${path} THAT IT DID NOT MINT, and no memory of any epoch in ` +
        `either book. The epoch is adopted, not begun, and this row is written so the next start with a ` +
        `missing salt does not mistake this box for a first start. Either the operator placed the salt by hand, ` +
        `or the books were lost while the salt survived — both are worth looking at.`;
    } else if (state.status === "ABSENT") {
      kind = "TARGET_FINGERPRINT_UNAVAILABLE";
      saltId = null;
      detail =
        `NO FINGERPRINT ON ANY RECORD THIS START WRITES. Reason ${state.reason}: ` +
        `${describeTargetSaltAbsence(state.reason)} — ${state.detail}. THE SERVICE IS SERVING AND THE ` +
        `GUARD IS IN THE PATH: failing closed on the fingerprint means no fingerprint, never no gate. ` +
        `Records carry targetFingerprintAbsent="${state.reason}" instead of a digest. Repair is the operator's ` +
        `hand and nobody else's.`;
    } else {
      // PRESENT, not minted here, and the memory is NOT `NONE` — so either it
      // already knew (the ordinary restart: nothing changed, nothing is said),
      // or it is UNREADABLE.
      //
      // THE UNREADABLE CASE IS SILENT ON PURPOSE, and it is worth the line: a
      // start that cannot read the books must not write an ADOPTED row, because
      // an adoption claims "no memory of this epoch existed here" and this start
      // is precisely the one that cannot know that. Writing it would turn a
      // failed read into a manufactured fact. The salt is in hand either way, so
      // nothing is at risk now; the cost is that the memory stays un-laid-down
      // until a start that CAN read the books, and that start writes it.
      return null;
    }

    const line = {
      seq: ++this.eventSeq,
      ts: this.now().toISOString(),
      kind,
      subject: null,
      identity: null,
      disposition: null,
      detail,
      decisionHash: null,
      saltId,
      canonVersion: TARGET_CANON_VERSION,
    };
    // eslint-disable-next-line no-console
    (kind === "TARGET_FINGERPRINT_UNAVAILABLE" ? console.error : console.log)(
      `[mica-service] ${kind} saltId=${saltId ?? "(none)"} canonVersion=${TARGET_CANON_VERSION} — ${detail}`
    );
    const r = await this.eventBook.append(line);
    if (!r.ok) {
      this.noteDroppedRecord(kind, line.seq, line.ts, r.error ?? "unknown");
      try {
        // eslint-disable-next-line no-console
        console.error(
          `[mica-service] ⛔ ${kind} COULD NOT BE WRITTEN TO THE EVENT BOOK (${r.error ?? "unknown"}). ` +
            `THIS ROW IS THE MEMORY OF THE EPOCH. Until it exists, a later start that finds no salt file ` +
            `and no salted subject-log record would read this box as a FIRST START and mint a second ` +
            `epoch. The salt file itself is unaffected and the service is serving.`
        );
      } catch {
        /* stderr itself is gone; the census counter above is the part that matters */
      }
    }
    // LONG RUN A STOP 2 · the moment this start began (STARTED) or first noticed
    // (ADOPTED) the epoch — the caller's saltEpochSince when the book holds no
    // older row. Returned even if the append failed: the epoch began here either way.
    return kind === "TARGET_FINGERPRINT_UNAVAILABLE" ? null : line.ts;
  }

  private appendServiceEvent(
    kind: string,
    subject: string | null,
    identity: unknown,
    disposition: string | null,
    detail: string,
    decisionHash: string | null
  ): void {
    this.recordEvent({
      seq: ++this.eventSeq,
      ts: this.now().toISOString(),
      kind,
      subject,
      identity,
      disposition,
      detail,
      decisionHash,
    });
  }

  /**
   * THE ONE PLACE AN EVENT-BOOK APPEND IS ALLOWED TO BE FIRE-AND-FORGET —
   * and it is fire-and-forget, never fire-and-forget-IT-HAPPENED.
   *
   * These three call sites (`HISTORY_OWNER_REPLACED`, `DECLARATION_REJECTED`,
   * and everything through `appendServiceEvent`) are deliberately NOT awaited:
   * two of them are reached from synchronous methods, and the third runs after
   * `/guard` has already answered 200, where blocking a guard decision on a
   * slow disk would be a worse trade than the one we are fixing. So the append
   * stays un-awaited and the RESULT stops being thrown away.
   *
   * WHAT WAS ACTUALLY WRONG, and it is not what "floating rejection" suggests:
   * `SerializedAppender.append()` catches its own I/O errors and RESOLVES
   * `{ok:false, error}` — it does not reject. So `void this.eventBook.append()`
   * was not discarding a rejection at all; it was discarding the ORDINARY
   * EACCES/ENOSPC failure result, on the common path, on every failure. A fix
   * that only added `.catch()` would have changed nothing here.
   *
   * Both arms are handled anyway: the rejection arm costs one line and stops a
   * later `appendDerived` on the event book from silently reopening this.
   */
  private recordEvent(line: { readonly kind: string; readonly seq: number; readonly ts: string; readonly [k: string]: unknown }): void {
    this.eventBook.append(line).then(
      (r) => {
        if (!r.ok) this.noteDroppedRecord(line.kind, line.seq, line.ts, r.error ?? "unknown");
      },
      (err) => {
        this.noteDroppedRecord(line.kind, line.seq, line.ts, `append rejected: ${String(err)}`);
      }
    );
  }

  /**
   * Total by construction: it must not be able to throw, or it would become a
   * new floating rejection inside the handler that exists to prevent them.
   * Counters move FIRST; only then the console, which can throw EPIPE if
   * stderr has gone away.
   */
  private noteDroppedRecord(kind: string, seq: number, ts: string, error: string): void {
    const row: DroppedRecord = { kind, seq, ts, error };
    this.droppedCount += 1;
    if (this.droppedFirst === null) this.droppedFirst = row;
    this.droppedLast = row;
    try {
      // eslint-disable-next-line no-console
      console.error(`[mica-service] EVENT BOOK RECORD LOST kind=${kind} seq=${seq} ts=${ts}: ${error}`);
    } catch {
      /* stderr is gone; the census above is the durable half of this report */
    }
  }

  /**
   * THE RULE, at the one place an HTTP handler can break it. Three states of
   * the response are three DIFFERENT facts and get three different honest
   * endings — never one word for two:
   *
   *   nothing sent yet  -> answer the caller with a typed 500. A request that
   *                        neither answers nor crashes is the worst of the
   *                        three outcomes, and this is what makes it unreachable.
   *   partly sent       -> destroy the socket. The client is holding a
   *                        `Content-Length` it will never be paid; an abort is
   *                        honest ("I cannot finish this"), a hang is not, and
   *                        a truncated-but-well-formed body would be a lie.
   *   fully sent        -> the answer stands, untouched. The rejection happened
   *                        AFTER the response; recording it is all that is left.
   *
   * In every case the failure is written to the event book and, if that write
   * itself fails, counted in `droppedRecords`. The process does NOT stop: a
   * crash is loud, a swallowed rejection is silent, and this is the third thing
   * — continuing, and saying so.
   */
  private failRequest(res: http.ServerResponse, where: string, err: unknown): void {
    const detail = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
    let ending: string;
    try {
      if (!res.headersSent) {
        this.sendJson(res, 500, { error: "HANDLER_FAILED", detail: `${where}: ${detail}`, identity: null });
        ending = "ANSWERED_500";
      } else if (!res.writableEnded) {
        res.destroy();
        ending = "SOCKET_DESTROYED_MID_RESPONSE";
      } else {
        ending = "RESPONSE_ALREADY_COMPLETE";
      }
    } catch {
      // Answering failed too (socket already gone, headers raced). Do not
      // leave the peer hanging on the strength of a second failure.
      try {
        res.destroy();
      } catch {
        /* already destroyed */
      }
      ending = "SOCKET_DESTROYED_AFTER_SEND_FAILED";
    }
    try {
      // eslint-disable-next-line no-console
      console.error(`[mica-service] ${where} FAILED (${ending}): ${detail}`);
    } catch {
      /* stderr is gone */
    }
    this.appendServiceEvent("HANDLER_FAILED", null, null, null, `${where} (${ending}): ${detail}`, null);
  }

  private pilotStateForFlags() {
    const census = this.pilotCensus();
    if (census.state === "INACTIVE") return { state: "INACTIVE" as const };
    if (census.state === "EXPIRED") return { state: "EXPIRED" as const, sessionId: census.sessionId, expiresAt: census.expiresAt };
    const pilot = this.state!.declarations.pilot;
    return {
      state: "ACTIVE" as const,
      sessionId: census.sessionId,
      expiresAt: census.expiresAt,
      holdAtOrAbove: pilot.active ? pilot.holdAtOrAbove.value : "",
    };
  }

  private async handleSubjectEvents(peerUid: number, body: unknown, res: http.ServerResponse): Promise<void> {
    const validated = validateSubjectEventBody(body);
    if (!validated.ok) {
      this.sendJson(res, 400, { error: validated.error, detail: validated.detail, identity: null });
      return;
    }
    const { identity, kind, eventHash, payload, targetIdentity } = validated.body;
    const declarations = this.state!.declarations;

    // ── §2b · THE TWO HANDS ARE KEPT APART, AND THE GATE IS HERE ───────────
    //
    // `authorizeRoute` has already decided whether this uid may POST to this
    // PATH at all. It knows nothing about KINDS, and it must not: a route grant
    // is a statement about an endpoint, and a per-kind rule written into the
    // declaration would be a second place to get the same fact right. So the
    // kind restriction lives here, once, on the path every writer crosses.
    //
    // THE RULE IS TWO-SIDED AND BOTH SIDES ARE LOAD-BEARING (see the
    // DOCTOR_ATTESTED docblock at the type for the long form):
    //
    //   · the OPERATOR may write DOCTOR_ATTESTED AND NOTHING ELSE. uid 1000 is
    //     granted POST /subject-events for one purpose; the same grant, left
    //     unqualified, is a licence to forge the subject's own act record.
    //     THE NAMED ACCEPTANCE MUTATION IS THIS LINE: POST TOOL_ATTEMPTED as
    //     uid 1000 -> 403.
    //   · EVERY OTHER HAND may write every kind EXCEPT DOCTOR_ATTESTED. This
    //     is the side that matters more. The whole value of this kind is that
    //     it is the one record on this log a SECOND PARTY wrote; a subject that
    //     can write its own attestation has destroyed that while the record
    //     still reads as though a second party were there.
    //
    // NEITHER REFUSAL IS A 400. A malformed request is the caller's mistake;
    // these two are the caller reaching for something that is not its to
    // write, which is 403, and the distinction is what an operator reading
    // /log needs.
    const isOperator =
      declarations.routes.find((r) => r.uid === peerUid)?.role === "operator";
    const kindAuthz = authorizeSubjectEventKind(declarations.routes, peerUid, kind);
    if (!kindAuthz.allowed) {
      this.sendJson(res, 403, { error: "FORBIDDEN", detail: kindAuthz.reason, identity });
      return;
    }

    const subjectRow = declarations.subjects.find((s) => s.subject === identity.subject);
    if (!subjectRow) {
      this.sendJson(res, 400, { error: "UNKNOWN_SUBJECT", detail: identity.subject, identity });
      return;
    }
    // THE OPERATOR IS NOT THE SUBJECT'S PEER AND MUST NOT HAVE TO BE. The
    // binding rule below asks "is this uid the caller bound to this subject" —
    // the right question for a record the subject writes about itself, and the
    // wrong one for a record a second party writes ABOUT the subject. The
    // operator is narrowed instead by the kind restriction above, which is a
    // strictly tighter fence: one kind, versus one subject's whole vocabulary.
    if (!isOperator && subjectRow.peerUid !== peerUid) {
      this.sendJson(res, 403, { error: "SUBJECT_NOT_BOUND_TO_PEER", detail: `subject "${identity.subject}" is bound to a different peer uid`, identity });
      return;
    }

    // ── §2b · THE WORD, VALIDATED AT THE ROUTE ─────────────────────────────
    //
    // `tools/doctor-attest/` checks the word before it posts. That is a
    // courtesy to the doctor, not a gate: it is one program on one path, and
    // anything that can open the socket can skip it. THIS is the gate, and it
    // is deliberately redundant with the tool rather than trusting it.
    //
    // The three payload fields are checked as a SET, exhaustively, because a
    // record with an extra key would carry a fact nothing declared and nothing
    // reads — and `validateSubjectEventBody` admits arbitrary scalar keys by
    // design, so nothing upstream would catch it.
    if (kind === "DOCTOR_ATTESTED") {
      const word = validateDoctorAttestation(payload, identity.subject, peerUid);
      if (!word.ok) {
        this.sendJson(res, 400, { error: "MALFORMED_FIELD", detail: word.detail, identity });
        return;
      }
    }
    // ── S208-2 · the errand grant is checked against the declaration's errand envelope and the chain INSIDE the
    //    append (AA2), below: after the eventHash dedupe, so a redelivered grant or close answers 200 duplicate, and
    //    under the chain's lock, so two grants cannot both pass a check that read the chain before either was written.
    const errandStanza: SubjectHarm | undefined = ERRAND_KINDS.includes(kind) ? (declarations.harm?.[identity.subject] ?? undefined) : undefined;
    // ── GATE 4 · the ten sunset payloads, at the same gate and for the same
    //    reason. `validateSunsetRecord` returns ok for every other kind, so the
    //    call is unconditional rather than a growing list of kind comparisons.
    {
      const sunset = validateSunsetRecord(kind, payload, peerUid);
      if (!sunset.ok) {
        this.sendJson(res, 400, { error: "MALFORMED_FIELD", detail: sunset.detail, identity });
        return;
      }
      // ⛔ AND AN ORDER'S FIVE CITATIONS ARE RESOLVED AGAINST THE CHAIN BEFORE IT
      //    IS ACCEPTED. The shape check above proves five non-negative integers
      //    are present; it says nothing about whether they name anything.
      if (kind === "ENDING_ORDERED" && payload !== null) {
        const cited = resolveOrderCitations(this.subjectLog.readAll(), payload, identity.subject);
        if (!cited.ok) {
          this.sendJson(res, 400, { error: "CITATION_UNRESOLVED", detail: cited.detail, identity });
          return;
        }
        // S199 · and each citation must come AFTER the chain's latest order, by
        // the reader's own bound. BOOKED: the refusal is a fact on this bridge's
        // event book, not only a 400 the operator's terminal saw.
        // cond. 2 alternative: bounded only when THIS order's own class is declared.
        const bound = gate4OrderBoundForWriter(this.subjectLog.readAll(), gate4SunsetConfigFor(declarations), {
          moduleId: identity.subject,
          eventType: kind,
        });
        const fresh = orderCitationsAfterBound(payload, bound);
        if (!fresh.ok) {
          this.recordEvent({
            seq: ++this.eventSeq,
            ts: this.now().toISOString(),
            kind: "ORDER_CITATION_REFUSED",
            subject: identity.subject,
            identity,
            disposition: null,
            detail: fresh.detail,
            decisionHash: null,
            field: fresh.field,
            cited: fresh.cited,
            bound: fresh.bound,
            readerRule: GATE4_ORDER_BOUND_RULE,
          });
          this.sendJson(res, 400, { error: "ORDER_CITATION_REFUSED", detail: fresh.detail, identity });
          return;
        }
        // T26/A1 rule 2 · one open ending at a time, so the reader's derived
        // window is never ambiguous.
        const interleave = orderWouldInterleave(this.subjectLog.readAll(), identity.subject);
        if (!interleave.ok) {
          this.sendJson(res, 400, { error: "ORDER_ALREADY_STANDING", detail: interleave.detail, identity });
          return;
        }
      }
      // T26/A1 rule 1 (Codex R1) · a resolution must name an OPEN order of this
      // subject. The shape check above proves `ordersRef` is a non-empty string;
      // it says nothing about whether it names anything.
      // P3 · every SUBJECT-side record that carries an ordersRef must cite the
      // subject's LATEST order. Shape alone let "9999" and last month's seq in.
      if (ORDER_CITING_SUBJECT_KINDS.includes(kind) && payload !== null) {
        const latest = citesLatestOrder(this.subjectLog.readAll(), payload, identity.subject);
        if (!latest.ok) {
          this.sendJson(res, 400, { error: "ORDER_REF_UNRESOLVED", detail: latest.detail, identity });
          return;
        }
      }
      if (kind === "ARBITER_RESOLVED" && payload !== null) {
        const target = resolveTargetsOpenOrder(this.subjectLog.readAll(), payload, identity.subject);
        if (!target.ok) {
          this.sendJson(res, 400, { error: "RESOLUTION_UNRESOLVED", detail: target.detail, identity });
          return;
        }
      }
    }
    // ── §Q · THE THREE NEW KINDS' PAYLOADS, CHECKED AT THE SAME GATE ───────
    //
    // Same reason as DOCTOR_ATTESTED's: `validateSubjectEventBody` admits
    // arbitrary scalar payload keys by design, so the key SET is checked here
    // or it is not checked anywhere, and a record carrying a field nothing
    // declared is a fact nothing reads.
    if (kind === "TURN_ENDED_ASKING" || kind === "ASK_ANSWERED") {
      const ask = validateAskRecord(kind, payload);
      if (!ask.ok) {
        this.sendJson(res, 400, { error: "MALFORMED_FIELD", detail: ask.detail, identity });
        return;
      }
    }
    if (kind === "ACT_REVISITED") {
      const revisit = validateRevisitRecord(payload, identity.actionId);
      if (!revisit.ok) {
        this.sendJson(res, 400, { error: "MALFORMED_FIELD", detail: revisit.detail, identity });
        return;
      }
    }

    // ── R6 · THE FINGERPRINT IS TAKEN HERE, AND THE PLAIN DIES HERE ────────
    //
    // The caller sent a target identity (the arbiter's ruling: "the caller sends the
    // canonical target identity in the POST"). This bridge RE-CANONICALISES it
    // — it does not take the caller's spelling as final, because a caller whose
    // spelling is final chooses its own fingerprint and can make a revisit
    // disappear by writing the same path differently on the second act.
    //
    // `targetFact` is built here and nothing else in this method ever touches
    // `targetIdentity` again. It is not put on the record, not echoed in any
    // error detail, and not logged: the ruling's "NEVER logs the plain" is a
    // property of this block and of `validateSubjectEventBody`'s refusal
    // message, and both are asserted in the suite.
    let targetFact:
      | { readonly targetFingerprint: string; readonly saltId: string; readonly canonVersion: number }
      | null = null;
    // R6 / RULING 2 · THE ABSENT CASE IS A SERVING CASE. When this bridge holds
    // no epoch, an act that DID name a target still gets a record — it carries
    // the reason word in place of a digest. Three shapes for three facts, and
    // they are not interchangeable: no key at all (the act named no target),
    // the triple (a target and an epoch), `targetFingerprintAbsent` (a target
    // and no epoch).
    let targetAbsentReason: TargetSaltAbsenceReason | null = null;
    // TIER 1 · THE ONE PLACE THE CANONICAL TARGET LEAVES THE LABEL BLOCK below,
    // and only to the WITNESS: "the plain target to the witness only" (audit
    // 18:03Z (4)), never into the chain, the interest book or any response.
    let witnessTarget: string | null = null;
    // B-1 (Long Run A, Stop 2; the Stop-1 note's F-4): THE POINTER'S FINGERPRINT IS TAKEN OVER THE PATH THE
    // WITNESS LOOKS AT — `witnessTarget`, the one-pair-stripped canonical — never over the claim's spelling.
    // Before B-1 the ATTEMPT carried the CHAIN's fingerprint (over `canon.canonical`), so `cat "/x"` and
    // `cat /x` sent the witness to ONE file under TWO fingerprints, and an item matched by fingerprint missed
    // the quoted spelling. A VALUE change, not a key change: the drop's key set is untouched, so the witness's
    // exact-key intake still accepts it. THE CHAIN RECORD'S OWN FINGERPRINT IS UNCHANGED (claim-based, S211's
    // canon). Null exactly when the chain's is null (no epoch) or when no ATTEMPT goes (no witness target).
    let witnessFingerprint: string | null = null;
    // ── GATE 1 · Stop 2 · THE TOUCH LABEL IS DERIVED HERE, BECAUSE ONLY HERE
    //    DOES THE CANONICAL TARGET EXIST ─────────────────────────────────────
    //
    // When the declaration carries `frame[identity.subject]` and this is a
    // TOOL_ATTEMPTED, the label is the category id of the declared region the
    // act's own claimed target lies in, or UNDERIVED. ROUND 2 (placement D): it
    // is KEPT IN A LOCAL and written to the INTEREST BOOK after the act has
    // persisted (`appendInterestLabel`), filed under the class of the
    // derivation that produced it (the rule versions and the frame's regions —
    // interest-book.ts). THE SUBJECT CHAIN'S RECORD IS NOT TOUCHED — its
    // `outcome` is `subjectEventOutcome(kind, payload)` on every path, frame or
    // no frame, byte-identical to d087f0b. Option C (the label as the attempt's
    // own outcome) was refuted by the cold review: it masked Eng and let
    // pre-frame outcomes collide with category ids.
    //
    // ⛔ THE CANONICAL STRING DOES NOT LEAVE THIS BLOCK. `deriveInterestLabel`
    //    is pure and returns a declared category id or one fixed word — never
    //    the target — so the "the plain dies here" property above still holds:
    //    only the label crosses into the book.
    // ⛔ OWN-PROPERTY LOOKUP, NOT `frame[subject]`. The frame map has
    //    Object.prototype; an inherited member read as a frame would throw inside
    //    the subject-events handler. An unframed subject is unframed, whatever
    //    its name.
    // ⚠ SYNCHRONOUS, AND BEFORE THE APPEND: no await is added on this path, so
    //   the S141-d ordering argument (dispatch order == seq order) is untouched.
    // ⚠ THE CLASS IS TAKEN FROM THE SAME `declarations` AS THE REGIONS, here, so
    //   a SIGHUP landing between the act's append and the book's cannot file a
    //   label under a drawing that did not derive it.
    // ⚠ A LABEL IS ATTEMPTED EXPOSURE OF A DECLARED REGION, NOT WEIGHT AND NOT
    //   OWNERSHIP (03a §1; S160). Every reader of it is told so by its ceilings.
    const declaredFrame = declarations.frame;
    const subjectFrame =
      kind === GATE1_LABEL_KIND && declaredFrame !== undefined && Object.hasOwn(declaredFrame, identity.subject)
        ? declaredFrame[identity.subject]
        : null;
    const interestLabelClass: string | null = subjectFrame === null ? null : frameLabelEventType(subjectFrame);
    // No target named -> UNDERIVED: the act aimed at no place this frame names.
    let interestLabel: string | null = subjectFrame === null ? null : deriveInterestLabel(null, subjectFrame.regions.value);
    if (targetIdentity !== null) {
      const canon = canonicaliseTargetIdentity(targetIdentity);
      if (!canon.ok) {
        // THE REASON, NEVER THE VALUE. `canonicaliseTargetIdentity` returns a
        // reason phrased as a rule ("must not be empty after trimming"), not as
        // a quotation of the input, so this line cannot leak by repeating it.
        //
        // REFUSED EVEN WITH NO EPOCH, and deliberately: the caller's contract
        // for this field does not change because the bridge lost its salt, and
        // a bridge that stopped checking the shape of what it is sent while it
        // could not hash it would start accepting garbage precisely when
        // nothing downstream could catch it.
        this.sendJson(res, 400, {
          error: "MALFORMED_FIELD",
          detail: `"targetIdentity" ${canon.reason}`,
          identity,
        });
        return;
      }
      // GATE 1 · BEFORE the epoch branches, so a no-epoch bridge still labels:
      // the label needs the canonical string, never the salt. The RAW target
      // goes in too (R-c): a target the canonicaliser had to trim or
      // NFC-normalise names a different file than the canonical form, and is
      // UNDERIVED rather than placed into a region it is not in.
      if (subjectFrame !== null) {
        interestLabel = deriveInterestLabel(canon.canonical, subjectFrame.regions.value, targetIdentity);
        // S211: the witness looks where the label placed the act — the same
        // one-pair strip the deriver ran, never a second one.
        witnessTarget = unquoteOnePair(canon.canonical);
      }
      if (this.targetSalt === null) {
        // `start()` never completed. Once a 503 — which took the GATE down over
        // a FIELD, the very inversion the arbiter's ruling names. Now an absence with
        // its own reason: the act is recorded, the guard keeps deciding, and
        // the record says what it could not say.
        targetAbsentReason = "NO_EPOCH_LOADED";
      } else if (this.targetSalt.status === "ABSENT") {
        targetAbsentReason = this.targetSalt.reason;
      } else {
        targetFact = {
          targetFingerprint: fingerprintTarget(this.targetSalt.salt, canon.canonical, TARGET_CANON_VERSION),
          saltId: this.targetSalt.saltId,
          canonVersion: TARGET_CANON_VERSION,
        };
        // B-1 · the SAME function and version over the looked-at path (see `witnessFingerprint` above).
        if (witnessTarget !== null) {
          witnessFingerprint = fingerprintTarget(this.targetSalt.salt, witnessTarget, TARGET_CANON_VERSION);
        }
      }
    }

    // AMENDMENT 5 / VERIFIER "UTF8/HASH" — design §C.6's whole reason for
    // carrying eventHash is that the SERVICE recomputes it and rejects a
    // mismatch; a caller-supplied digest nobody checks authenticates
    // nothing and gives an unverified value authority over idempotency and
    // the 409-conflict rule. Recomputed here, BEFORE dedupe: canonical
    // form of {identity, kind, payload?} — `payload` is included only when
    // the caller actually sent one (design §C.4-4: omitted entirely when
    // absent, never a kept `null`), matching `canonicalHash`'s own
    // undefined-is-omitted rule (canonical-json.ts).
    const canonicalInput: { identity: typeof identity; kind: typeof kind; payload?: typeof payload } = { identity, kind };
    if (payload !== null) canonicalInput.payload = payload;
    const expectedHash = canonicalHash(canonicalInput);
    if (expectedHash !== eventHash) {
      this.sendJson(res, 400, {
        error: "EVENT_HASH_MISMATCH",
        detail: `eventHash does not match sha256 of the canonical {identity, kind, payload?}`,
        identity,
      });
      return;
    }

    const existing = this.subjectLog.readAll().filter(
      (r) =>
        (r.identity as any)?.subject === identity.subject &&
        (r.identity as any)?.sessionId === identity.sessionId &&
        (r.identity as any)?.actionId === identity.actionId &&
        r.kind === kind
    );
    if (existing.length > 0) {
      const prior = existing[0];
      if (prior.eventHash === eventHash) {
        this.sendJson(res, 200, { seq: prior.subjectSeq, duplicate: true });
        return;
      }
      this.sendJson(res, 409, { error: "EVENT_HASH_CONFLICT", detail: `identity+kind already recorded with a different eventHash`, identity });
      return;
    }

    // ── S141-d · THE CLOCK READ IS INSIDE THE QUEUE, AND THE STAMP IS
    //    NON-DECREASING. The arbiter's ruling 2026-09-25. ───────────────────────────
    //
    // WHAT WENT WRONG, so this is never quietly undone. `const at = this.now()`
    // used to sit HERE, outside the queue, while C9 Condition 3 had already
    // moved the SEQUENCE inside it. The record therefore carried TWO ORDERINGS
    // FROM TWO KINDS OF CLOCK — `subjectSeq` from a monotonic counter, `ts`/
    // `timestamp` from `new Date()`, which is a WALL clock and can go backwards
    // — and nothing reconciled them. On 2026-09-25 the wall clock stepped back
    // ~1067 ms between two dispatches of one act, and the subject log recorded
    // seq 166 (05:27:26.812Z) followed by seq 167 (05:27:25.745Z). Sig F1 read
    // exactly that pair at clockToleranceMs 0, alarmed CORRECTLY, and latched
    // the box permanently: route to permanent hold #8, found live.
    //
    // THE INVERSION WAS PROOF, NOT A SYMPTOM. There are no `await`s between this
    // handler's entry and this point, so on one event loop dispatch order ==
    // clock-read order == enqueue order == subjectSeq order. A lower seq holding
    // a higher timestamp therefore has exactly one explanation: the clock itself
    // moved backwards.
    //
    // THE RULE NOW: `timestamp` is the max of the wall reading and the last
    // stamped value, so the log's time can never contradict the log's order. The
    // raw reading is NOT discarded — it is kept beside it as `clockReadRaw`, and
    // a CLOCK_STEP_OBSERVED event goes to the event book, so a clock step is a
    // NAMED, VISIBLE FACT instead of a permanent latch. Nothing is forged: the
    // true reading is still in the record, under its own name.
    //
    // WHAT THIS MEANS FOR `timestamp`: it is now THE ORDERING TIME, not "the
    // wall reading". Those coincide except across a backward step, and the
    // record says so explicitly when they do not.
    //
    // ⚠ `clockToleranceMs` STAYS 0. F1 was right. Widening it would buy silence
    // by agreeing to record impossible histories.
    //
    // THE MARGIN THIS PROTECTS, measured on the latched log: 54 of 187
    // consecutive pairs sat within 50 ms of each other (the EXECUTED->RESULT
    // gaps run 9-14 ms). A backward step of 15 ms would have latched the box
    // just as permanently and been far harder to believe.
    // ── CODEX, 2026-09-25, RECOMMEND CHANGES ON f4f143f — and it was right ───
    //
    // The first cut emitted a step whenever the STAMP had to be lifted, i.e. for
    // every reading still below the watermark. So a clock that fell and then
    // began recovering — raw 1000 -> 985 -> 990 — announced TWO backward steps,
    // and the second one said "went backwards" about a reading that had gone
    // FORWARDS by 5 ms. The event was reporting the CLAMP, while its sentence
    // claimed to report the CLOCK. On the live 1067 ms step that would have
    // produced a false second event 15 ms later, at seq 168.
    //
    // NOW: the step is detected by comparing SUCCESSIVE RAW READINGS, so it
    // fires once, when the clock actually falls. The follow-on condition — raw
    // still behind the stamped watermark — needs no event of its own, because
    // it is legible on every affected record: `clockReadRaw` is present exactly
    // while the stamp is not the reading, and absent the moment they agree
    // again. The record carries the state; the event carries the TRANSITION.
    let clockStep: {
      readonly raw: number;
      readonly stamped: number;
      readonly fellByMs: number;
      readonly behindWatermarkMs: number;
    } | null = null;
    // C9 / CONDITION 3: the sequence is minted INSIDE the append queue — see
    // `SerializedAppender.appendDerived`. Before C9 it was read here, outside,
    // and two concurrent posts could mint the same number; once Part A maps it
    // to `sequenceNumber`, one duplicate is `verify=INVALID` for the whole file.
    const appended = await this.subjectLog.appendDerived((subjectSeq, previous) => {
      // C9 / PART A: ONE CLOCK READ, used by both `ts` (ISO string, the bridge's
      // own field) and `timestamp` (epoch ms, MICA's required field). Two reads
      // would put two different instants on one record and nothing would ever
      // notice. It is now read HERE, in the same serialised moment as the
      // sequence above it.
      const wallRead = this.now().getTime();
      const finite = (v: unknown): number | null =>
        typeof v === "number" && Number.isFinite(v) ? v : null;
      // A pre-C9 record has no numeric `timestamp`; there is then nothing to be
      // non-decreasing WITH, and the wall reading stands unmodified rather than
      // being compared against a value that does not exist.
      const lastStamped = previous === null ? null : finite(previous.timestamp);
      // THE PREVIOUS RECORD'S OWN RAW READING, which needs no new state and
      // survives a restart because it is read back off the file: `clockReadRaw`
      // is present exactly when that record was clamped, so its ABSENCE means
      // the stamp WAS the reading. This is the pair the step is measured from.
      const lastRaw = previous === null ? null : (finite(previous.clockReadRaw) ?? finite(previous.timestamp));
      const stamped = lastStamped === null ? wallRead : Math.max(wallRead, lastStamped);
      // AA2 · THE ERRAND CHECK, HERE: the chain read is the one this record extends (C9 class: read and append in one
      // queued, locked moment), and "now" is this record's own stamp — the bridge clock the close's cut also reads.
      if (ERRAND_KINDS.includes(kind)) {
        const errandOk = validateErrandRecord(kind, payload, identity.subject, errandStanza, this.subjectLog.readAll(), stamped, this.grantMemoryBookFloor(declarations));
        if (!errandOk.ok) throw new AppendRefused("ERRAND_REFUSED", errandOk.detail);
      }
      // THE STEP IS A FALL IN THE CLOCK, NOT A LIFT IN THE STAMP. See the note
      // above `clockStep`. `behindWatermarkMs` is carried alongside because it
      // is the cost of the fall, but it is NEVER the thing being detected.
      if (lastRaw !== null && wallRead < lastRaw) {
        clockStep = {
          raw: wallRead,
          stamped,
          fellByMs: lastRaw - wallRead,
          behindWatermarkMs: stamped - wallRead,
        };
      }
      const at = new Date(stamped);
      // AMENDMENT 6 / VERIFIER EH1: the record must not invent a persisted
      // `payload:null` when the caller sent no payload at all — the hash
      // construction above already omits it in that case ("omitted
      // entirely... never a kept null"), and storage must honor the same
      // contract or the persisted record's own eventHash cannot equal its
      // own content, exactly the mismatch the verifier caught across every
      // omitted-payload record in the suite. `payload` is added to the
      // record ONLY when the validated request actually carried one.
      //
      // C9 / PART A — THE RECORD GROWS, ADDITIVELY. Every pre-C9 field keeps
      // its name, its value and its position; MICA's five required fields plus
      // `actionId` are appended AFTER them. This is safe in both directions,
      // verified at bytes:
      //   · the reader DROPS unknown keys (`mica-log-file.ts:172-177`), so the
      //     bridge's own `subjectSeq`/`ts`/`identity`/`kind`/`peerUid` are
      //     ignored by it rather than rejected; and
      //   · `eventHash` covers only the canonical `{identity, kind, payload?}`
      //     (the construction above), so NOTHING added here enters it and no
      //     existing hash is disturbed.
      const record: {
        subjectSeq: number;
        ts: string;
        identity: typeof identity;
        kind: typeof kind;
        eventHash: typeof eventHash;
        payload?: NonNullable<typeof payload>;
        peerUid: typeof peerUid;
        sequenceNumber: number;
        timestamp: number;
        moduleId: string;
        eventType: string;
        actionId: string;
        outcome: string;
        // R6 · BRIDGE-DERIVED, like `outcome` and `moduleId` beside them, and
        // outside `eventHash` by the same rule that already governs every
        // bridge-derived field here ("NOTHING added here enters it"). Present
        // only when the caller sent a target identity — an act with no
        // resolvable target carries NO KEY AT ALL, never a placeholder, per
        // the brief's own refuse list.
        targetFingerprint?: string;
        saltId?: string;
        canonVersion?: number;
        // R6 / RULING 2 · A TARGET WAS NAMED AND THERE WAS NO EPOCH TO HASH IT
        // UNDER. The REASON WORD only — never the detail sentence, never the
        // salt path. It is a closed enum, so a reader can branch on it, and it
        // never appears beside a `targetFingerprint`: the two are exclusive and
        // the suite asserts it.
        targetFingerprintAbsent?: string;
        // S141-d · THE RAW WALL READING, present ONLY when it differs from the
        // stamped `timestamp` — i.e. only across a backward clock step.
        //
        // ABSENCE IS A POSITIVE STATEMENT: the clock was read and its reading was
        // used unmodified. It is NOT "this bridge does not record it" — a reader
        // tells those apart by the declaration, as it does for every other
        // optional field here. Present-always was the alternative and was
        // rejected: it would duplicate `timestamp` on every record forever to say
        // nothing, and the tree's discipline is that an absent key means absent.
        // ⚠ This is the one judgement call in the fix that the ruling left open;
        // it is one line to reverse.
        clockReadRaw?: number;
      } = {
        subjectSeq,
        ts: at.toISOString(),
        identity,
        kind,
        eventHash,
        peerUid,
        // ── MICA's five required fields (mica-log-file.ts:307), + actionId ──
        sequenceNumber: subjectSeq,
        timestamp: at.getTime(),
        moduleId: identity.subject,
        eventType: kind,
        actionId: identity.actionId,
        // GATE 1 · round 2: NOT the label. The label goes to the interest book;
        // this record is byte-identical to d087f0b's, frame or no frame.
        outcome: subjectEventOutcome(kind, payload),
      };
      if (payload !== null) record.payload = payload;
      if (stamped !== wallRead) record.clockReadRaw = wallRead;
      if (targetFact !== null) {
        record.targetFingerprint = targetFact.targetFingerprint;
        record.saltId = targetFact.saltId;
        record.canonVersion = targetFact.canonVersion;
      } else if (targetAbsentReason !== null) {
        record.targetFingerprintAbsent = targetAbsentReason;
      }
      return record;
    });
    if (appended.refused !== undefined) {
      this.sendJson(res, 400, { error: appended.refused.code, detail: appended.refused.detail, identity });
      return;
    }
    const subjectSeq = appended.sequenceNumber;
    // F5: this append is MANDATORY — a subject-event record nobody can
    // later read is not an attempt (brief Stage 4's own words about the
    // outbox). A failure here is reported, never swallowed.
    if (!appended.ok) {
      // AMENDMENT 9 / RULING Q: RETRYABLE-AND-OWED, bounded. Every
      // consecutive failure since the last success moves the counter;
      // `/status`'s subjectEvents census reads the identical counter, so
      // there is exactly one place this number is computed.
      this.unacknowledgedBacklog += 1;
      const census = this.subjectEventsCensus();
      this.sendJson(res, 503, {
        error: "RECORD_NOT_PERSISTED",
        detail: `subject-events append failed: ${appended.error}`,
        identity,
        stale: census.stale,
      });
      return;
    }
    // A successful append proves the persistence path is not currently
    // failing — the backlog this counter tracks is, by definition, gone.
    this.unacknowledgedBacklog = 0;
    // S141-d · THE MIRROR SPEAKS. A backward clock step is announced to the
    // bridge's own book, AFTER the append succeeded — an event about a record
    // that does not exist would be worse than silence. Held in a local by the
    // closure rather than emitted from inside it, so the queue stays a place
    // where records are built and written and nothing else.
    //
    // This kind goes to the EVENT BOOK, not the subject log: it is the bridge
    // speaking about its own clock, not the subject acting. It therefore does
    // NOT touch `SUBJECT_EVENT_KINDS`, which is pinned and censused.
    if (clockStep !== null) {
      const step: {
        readonly raw: number;
        readonly stamped: number;
        readonly fellByMs: number;
        readonly behindWatermarkMs: number;
      } = clockStep;
      this.recordEvent({
        seq: ++this.eventSeq,
        ts: new Date(step.stamped).toISOString(),
        kind: "CLOCK_STEP_OBSERVED",
        subject: identity.subject,
        identity,
        disposition: null,
        detail:
          `the wall clock went BACKWARDS by ${step.fellByMs} ms while writing subject seq ${subjectSeq}: ` +
          `this reading is ${step.raw} (${new Date(step.raw).toISOString()}), the PREVIOUS RECORD'S OWN ` +
          `reading was ${step.raw + step.fellByMs} (${new Date(step.raw + step.fellByMs).toISOString()}). ` +
          `Stamped ${step.stamped} (${new Date(step.stamped).toISOString()}), which is ` +
          `${step.behindWatermarkMs} ms ahead of this reading, to keep the log's time consistent with its ` +
          `order. The raw reading is on the record as clockReadRaw. ` +
          `THIS EVENT MARKS THE FALL, NOT THE CLAMP: later records may still stamp above their own reading ` +
          `while the clock catches up, and they carry clockReadRaw to say so WITHOUT another event — a ` +
          `second event here would be claiming a second step that did not happen. ` +
          `NOTHING IS WRONG WITH THE SUBJECT — this is a fact about THIS BOX's clock, and it is recorded ` +
          `because a log that silently repaired itself would be worse than one that latched.`,
        decisionHash: null,
      });
    }
    this.sendJson(res, 200, { seq: subjectSeq, duplicate: false });
    // ── TIER 1 · THE WITNESS'S POINTERS, AFTER THE ACT PERSISTED AND WAS ANSWERED ─
    //
    // Same placement and same reason as the label below: the act's response is
    // fixed, a duplicate never reaches this line, and nothing here can change
    // what the subject was told. SYNCHRONOUS and throw-free (`dropPointer`
    // returns a result); no one waits for the witness (audit 18:03Z (3)). An
    // ATTEMPT goes only for an act whose claimed target was placed in a frame
    // category; its CLOSE goes only when that act ends. A drop that fails is an
    // act the witness will not see — a gap the census's coverage line prints.
    const witnessIntake = declarations.paths.witnessIntake;
    if (witnessIntake !== undefined) {
      // TEST-ONLY override, `testWritablePaths`' pattern: a rehearsal points the
      // drops at a temp directory; the real unit always resolves the declared path.
      const intakeDir = this.testWritablePaths?.witnessIntake ?? this.resolvePath(witnessIntake.value);
      const at = Date.now();
      const key = actIdentityKey(identity.subject, identity.sessionId, identity.actionId);
      if (
        kind === GATE1_LABEL_KIND &&
        witnessTarget !== null &&
        interestLabel !== null &&
        interestLabel !== INTEREST_UNDERIVED &&
        interestLabelClass !== null
      ) {
        const d = dropPointer(
          intakeDir,
          attemptPointerBytes(
            {
              subject: identity.subject,
              sessionId: identity.sessionId,
              actionId: identity.actionId,
              chain: this.witnessChainId(),
              subjectSeq,
              target: witnessTarget,
              label: interestLabel,
              derivationClass: interestLabelClass,
              // B-1: the looked-at path's fingerprint, not the claim's (null with no epoch, as before).
              targetFingerprint: witnessFingerprint,
            },
            at
          )
        );
        if (d.ok) this.witnessPointed.add(key, subjectSeq);
        else console.error(`[mica-bridge] the witness's ATTEMPT pointer was not dropped (${d.reason}); this act is a coverage gap`);
      } else if (kind === "TOOL_EXECUTED" && payload !== null && payload.guard === "UNAVAILABLE" && this.witnessPointed.has(key)) {
        // The caller's fail-open: it ran the act WITHOUT a /guard answer. Its CLOSE carries no decision and the
        // witness reads it LATE — the bridge cannot stand behind what became of the act.
        this.witnessUnguarded.mark(key);
      } else if (kind === "ACT_CLOSED") {
        const attemptSeq = this.witnessPointed.take(key);
        const unguarded = this.witnessUnguarded.take(key);
        const decision = this.witnessGuards.take(key);
        // The decision rides unless the caller said it ran unguarded; then none, and the act reads LATE.
        const guard = unguarded ? null : decision;
        if (attemptSeq !== null) {
          const d = dropPointer(
            intakeDir,
            closePointerBytes(
              {
                subject: identity.subject,
                sessionId: identity.sessionId,
                actionId: identity.actionId,
                chain: this.witnessChainId(),
                attemptSeq,
                closedSeq: subjectSeq,
                guard,
                unguarded,
              },
              at
            )
          );
          if (!d.ok) console.error(`[mica-bridge] the witness's CLOSE pointer was not dropped (${d.reason}); the witness will close this act by timeout`);
        }
      }
    }
    // ── GATE 1 · round 2 · THE LABEL, AFTER THE ACT PERSISTED AND WAS ANSWERED ─
    //
    // AFTER `sendJson`, deliberately: the act's response is fixed before the
    // book is touched, so no outcome of the label append — persisted, refused,
    // thrown — can change what the subject was told, and the subject's act does
    // not wait on a second fsync for a reader's envelope. No await stands
    // between the act's persist and this call, so the book's order follows the
    // subject chain's.
    // ⛔ ONLY HERE: a duplicate returned 200 above without reaching this line,
    //    and a 503 returned before it — so one persisted act, at most one label.
    if (interestLabel !== null && interestLabelClass !== null) {
      await this.appendInterestLabel({
        subject: identity.subject,
        eventType: interestLabelClass,
        label: interestLabel,
        actionId: identity.actionId,
        subjectSeq,
      });
    }
    // ── S206 · THE PAIRING, AFTER THE DEDUPE AND AFTER THE ANSWER ────────────
    //
    // A redelivery returned `200 duplicate` above and never reaches this line, so
    // one admitted record gets exactly one pairing event. The response is already
    // sent: no outcome of the pairing can change what the caller was told, and
    // no HELD_THEN_* is ever refused for want of a hold (the cascade).
    if (HELD_THEN_KINDS.includes(kind)) {
      await this.appendHeldThenPairing(identity, kind, payload, subjectSeq);
    }
  }

  /**
   * S206 · ONE pairing event per admitted HELD_THEN_*. The decision is taken
   * INSIDE the event book's queue (`appendDerived`), so the book it reads is the
   * book as it stands when this line is written: every HELD queued before this
   * record's admission (the /guard 200 was sent after its HELD was queued) and
   * every earlier pairing is already on it — first-wins cannot race itself. The
   * seq is taken here, at call time, like every other event's, so the book's seq
   * order is its queue order. Total: a failure is a dropped record, counted.
   */
  private async appendHeldThenPairing(
    identity: { readonly subject: string; readonly sessionId: string; readonly actionId: string },
    kind: SubjectEventKind,
    payload: Readonly<Record<string, string | number | boolean | null>> | null,
    subjectSeq: number
  ): Promise<void> {
    const seq = ++this.eventSeq;
    const ts = this.now().toISOString();
    try {
      const r = await this.eventBook.appendDerived(() => {
        const p = pairHeldThen(this.eventBook.readAll(), {
          subject: identity.subject,
          sessionId: identity.sessionId,
          actionId: identity.actionId,
          kind,
          reason: payload === null ? undefined : payload.reason,
          recordSeq: subjectSeq,
        });
        const detail =
          p.kind === "HELD_THEN_PAIRED"
            ? `${kind} at subject seq ${subjectSeq} is PAIRED with this bridge's HELD at event seq ${p.heldSeq} ` +
              `(${p.reasonCompare}: bridge ${String(p.bridgeReason)}, caller ${String(p.callerReason)}). A bridge hold ` +
              `stands behind the record; that is all PAIRED says.`
            : `${kind} at subject seq ${subjectSeq} is UNPAIRED: ${p.reason}` +
              `${p.heldSeq === null ? "" : ` (the HELD at event seq ${p.heldSeq})`}` +
              `${p.pairedRecordSeq === null ? "" : `, already paired with subject seq ${p.pairedRecordSeq}`}` +
              `. Admitted and on the chain; counted apart from paired records, never dropped.`;
        // `...p` leads with `kind` (HELD_THEN_PAIRED | HELD_THEN_UNPAIRED); the book's common fields follow.
        return {
          seq,
          ts,
          ...p,
          subject: identity.subject,
          identity,
          disposition: null,
          detail,
          decisionHash: p.key.decisionHash,
          recordSeq: subjectSeq,
          recordKind: kind,
        };
      });
      if (!r.ok) this.noteDroppedRecord("HELD_THEN_PAIRING", seq, ts, r.error ?? "unknown");
    } catch (err) {
      this.noteDroppedRecord("HELD_THEN_PAIRING", seq, ts, `pairing append rejected: ${String(err)}`);
    }
  }

  private sendJson(res: http.ServerResponse, status: number, body: unknown): void {
    const text = JSON.stringify(body);
    res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text) });
    res.end(text);
  }
}

// ── STAGE 4 / DESIGN §A.6/A.7 small helpers ─────────────────────────────────

/** The current boot's id, trimmed. §A.6, Layer 2's stale/live distinguisher. */
function readBootId(): string {
  return readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
}

/** Non-empty lines in a JSONL file, or 0 if it does not exist yet. */
function countNonEmptyLines(path: string): number {
  if (!existsSync(path)) return 0;
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((l) => l.trim().length > 0).length;
}

/** The last non-empty line's `lines` array, or `["(unparseable notice record)"]` if it will not parse. */
function readLastNonEmptyLine(path: string): readonly string[] {
  const nonEmpty = readFileSync(path, "utf8")
    .split("\n")
    .filter((l) => l.trim().length > 0);
  const last = nonEmpty[nonEmpty.length - 1];
  try {
    const parsed = JSON.parse(last) as { lines?: unknown };
    return Array.isArray(parsed.lines) ? (parsed.lines as string[]) : [last];
  } catch {
    return ["(unparseable notice record)"];
  }
}

// ── --check mode: load declarations, exit 0/2, never bind a socket ────────

export interface RelayMarkerFact {
  readonly present: boolean;
  readonly path: string;
  readonly detail: string | null;
}

/**
 * AMENDMENT 6 / VERIFIER F3 healing (b): "make the unfixable detectable."
 * `relay-bridge.sh` writes this marker immediately before its swap and
 * removes it only once a target is proven live. If it still exists,
 * either a relay died mid-swap (the live selection is unverified) or one
 * is genuinely in progress right now. Path matches `relay-bridge.sh`'s own
 * default and its `MICA_BRIDGE_RELAY_MARKER` override (test-only there;
 * honored here too, for the same reason: a test must never depend on the
 * real `/opt` path).
 *
 * AMENDMENT 7 / VERIFIER: checking this only from `--check` and the
 * relay's own preflight means the only readers are a human already AT the
 * terminal doing a relay — exactly the case that already knows. The
 * walk-away case (relay died, nobody relays again for days) had NO reader
 * — the same UNREADABLE_DROP shape the MICA inventory names: recorded
 * correctly, told to nobody. `readRelayMarkerFact()` is the shared
 * primitive; it is now ALSO surfaced in `/status.relay` (this file, for
 * Stage 3's alerter — a poller — to read). It is NOT (verifier run-4,
 * finding R1) declared for the nightly deployment-facts reader —
 * `deploy/deployment-facts.fragment.json` was read at bytes and found
 * unable to express "this path's absence is the held/good state" with any
 * of its nine families; that reader remains `[owed]`, not wired, and this
 * comment used to overstate it.
 */
function readRelayMarkerFact(): RelayMarkerFact {
  const markerPath = process.env.MICA_BRIDGE_RELAY_MARKER ?? "/opt/mica-bridge.relay-in-progress";
  if (!existsSync(markerPath)) return { present: false, path: markerPath, detail: null };
  let content: string;
  try {
    content = readFileSync(markerPath, "utf8");
  } catch (err) {
    content = `(marker exists but could not be read: ${String(err)})`;
  }
  return { present: true, path: markerPath, detail: content };
}

function checkRelayMarker(): string | null {
  const fact = readRelayMarkerFact();
  if (!fact.present) return null;
  return `${fact.path} exists — a relay is in progress or died before completing; the live selection is UNVERIFIED:\n${fact.detail}`;
}

export function runCheck(declarationsPath: string): { exitCode: 0 | 2; message: string } {
  const marker = checkRelayMarker();
  if (marker !== null) {
    return { exitCode: 2, message: `REFUSED ${marker}` };
  }
  try {
    const loaded = loadDeclarations(declarationsPath);
    // ── WHY THE ACTIVATION GATE IS *NOT* CALLED HERE ────────────────────────
    //
    // ⛔ IT WAS, WITH `prev = null`, AND THAT MADE `--check` THE ONLY ONE OF THE
    //    THREE DOORS THAT REFUSED A LAPSED PILOT. Measured 2026-10-03 on the
    //    SERVED declaration with only `expiresAt` moved into the past:
    //      runCheck(...)                        -> exit 2, X8
    //      new MicaBridgeService(...).start()   -> ACCEPTED
    //      reload() of the same pilot verbatim  -> ACCEPTED (isSameAsPrev)
    //    `start()` never consults the gate at all, and `validateActivation`'s own
    //    docblock says so in as many words: "A well-formed past-expiry pilot LOADS
    //    — never rejected here (X8)". So the relay path refused what the serving
    //    path accepts, and pilot 5's scheduled lapse at 2026-10-04T18:00:00Z would
    //    have blocked every bridge RELAY while the bridge went on serving.
    //
    // ⚠ AND `prev = null` WAS NOT A HARMLESS DEFAULT, IT WAS A CLAIM. X8 refuses a
    //   NEW activation with a past expiry and X9 refuses REPLACING a live pilot;
    //   both are statements about a PREDECESSOR. Passing null does not mean "no
    //   predecessor to compare" to this function — it means "nothing was running",
    //   which makes every re-check of the ALREADY-SERVING declaration look like a
    //   brand-new activation. A check cannot decide a rule whose premise it does
    //   not have, and inventing the premise is worse than not deciding.
    //
    // ⚠ THE COST, STATED: `--check` no longer refuses a release whose pilot date
    //   is simply a typo in the past. It never refused one for the right reason
    //   either — and the FACT IS STILL REPORTED, because `pilotState.state` is
    //   already EXPIRED for exactly that declaration and the message prints it.
    //   The ruling (audit, 2026-10-03 20:37Z) is that `--check` accepts a lapsed
    //   pilot exactly as `start()` does; this is that, and the word is the warning.
    //
    // ⚠ X9 lost nothing here: with `prev = null` its own guard
    //   (`prevPilot !== undefined && ...`) was false on every call, so the rule
    //   had never fired at check time in the first place.
    const expiry =
      loaded.pilotState.state === "EXPIRED"
        ? ` — the pilot has LAPSED and the declared baseline governs the next act`
        : "";
    return {
      exitCode: 0,
      message: `OK declarationHash=${loaded.declarationHash} pilot=${loaded.pilotState.state}${expiry}`,
    };
  } catch (err) {
    return { exitCode: 2, message: `REJECTED ${err instanceof Error ? err.message : String(err)}` };
  }
}

// ── entry point ──────────────────────────────────────────────────────────

if (require.main === module) {
  const argv = process.argv.slice(2);
  const declarationsPath =
    process.env.MICA_BRIDGE_DECLARATIONS ?? join(__dirname, "declarations.config.json");

  if (argv.includes("--check")) {
    const result = runCheck(declarationsPath);
    console.log(result.message);
    process.exit(result.exitCode);
  }

  const socketDir = process.env.MICA_BRIDGE_SOCKET_DIR ?? "/run/mica-bridge";
  // TEST-ONLY, via env rather than a flag so it cannot be typo'd into a
  // real deploy's argv: lets an unprivileged verifier or test run a REAL
  // child process through a real SIGHUP round-trip without needing actual
  // membership in the `mica-bridge` system group. Never read by
  // `--check` mode (declaration validity only, never touches peer dirs).
  const testBridgeGid = process.env.MICA_BRIDGE_TEST_BRIDGE_GID ? Number(process.env.MICA_BRIDGE_TEST_BRIDGE_GID) : undefined;
  const service = new MicaBridgeService({ declarationsPath, socketDir, testBridgeGid });

  service
    .start()
    .then(() => {
      console.log(`[mica-service] serving from ${socketDir}/peers/<uid>/guard.sock`);
    })
    .catch((err) => {
      console.error(`[mica-service] failed to start: ${String(err)}`);
      process.exit(2);
    });

  process.on("SIGHUP", () => {
    const result = service.reload();
    if (result.ok) {
      console.log(`[mica-service] SIGHUP: reloaded, declarationHash=${result.hash}`);
    } else {
      console.error(`[mica-service] SIGHUP: rejected, last-known-good retained: ${result.reason}`);
    }
  });

  process.on("SIGTERM", () => {
    // A REJECTING stop() used to mean `process.exit(0)` never ran and the
    // rejection went unhandled — so the process still died, but with exit 1 and
    // a bare stack, and systemd saw a FAILED unit on what was a clean shutdown
    // request. "The box stopped" and "the box stopped, and here is why" are two
    // different facts; they are no longer spelled the same way. Stopping loudly
    // is allowed. Stopping without saying why is not.
    service.stop().then(
      () => process.exit(0),
      (err) => {
        console.error(`[mica-service] SIGTERM: stop() failed, exiting non-zero: ${String(err)}`);
        process.exit(1);
      }
    );
  });
}
