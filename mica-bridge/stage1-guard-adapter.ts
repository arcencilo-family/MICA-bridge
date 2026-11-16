// ── stage1-guard-adapter — Stage 1's evaluateAndRecord, bound into the door ─
//
// DESIGN §A.1/A.2/A.3/A.5 (ARC_MICA-DESIGN_Phase-A-Stage-4-Pilot_20260919).
// This is Stage 4's whole point: the ONE file that imports mica-machine's
// glue by absolute path (W1 — no symlink, no dynamic require()) and turns
// its synchronous `evaluateAndRecord` into the `GuardAdapter` interface
// `guard-adapter.ts` already declared at Stage 2, unchanged.
//
// Import at module top level, never lazily inside `evaluate()` — a TSError
// here must stop the unit at ExecStart, never surface as a 500 in the
// middle of a real guarded message (§A.1).
import { evaluateAndRecord, EvaluateAndRecordUsageError } from "/opt/mica-machine/src/glue/evaluate-and-record";
import type {
  EvaluateAndRecordPaths,
  EvaluateAndRecordResult,
} from "/opt/mica-machine/src/glue/evaluate-and-record";
import { buildNotifier, wire } from "/opt/mica-machine/src/glue/wire";
import type { BuiltNotifier, WireOptions } from "/opt/mica-machine/src/glue/wire";

import { lstatSync } from "fs";
import { readClockStampsFile } from "/opt/mica-machine/src/glue/clerk-clock-stamps-file";
// T8 · the chain-aware reader, IMPORTED as well as re-exported below: the
// re-export makes the name available to this package, not to this module.
import {
  SubjectChainLog,
  LOADED_SUBJECT_CHAIN_VERIFIED,
  SUBJECT_LOG_BOUNDARY_MODULE_ID,
} from "/opt/mica-machine/src/glue/subject-event-journal";

/**
 * SHAPE (b) · THE WITNESS RECORD'S eventType — A SECOND COPY, ON PURPOSE.
 *
 * ⛔ THIS IS NOT AN IMPORT AND THE REASON IS THE ONE THIS TREE ALREADY WROTE
 * DOWN ONCE. `subject-event-journal.ts` keeps its own copy of the canonical-JSON
 * rule rather than importing it, with the sentence: *"a second copy on purpose
 * rather than an import: a store's hash preimage is the one thing that must
 * never move because a neighbour refactored."* This word is part of a hash
 * preimage in exactly that sense — it is written into a chained record — and it
 * is needed on BOTH sides of a relay boundary: the BRIDGE mints the record, the
 * MACHINE's validator refuses the word from any writer but the chain's own
 * voice.
 *
 * ⚠ AND THE PRACTICAL HALF, WHICH IS WHY AN IMPORT IS NOT MERELY UNTIDY BUT
 * IMPOSSIBLE TODAY: this file imports from `/opt/mica-machine`, the INSTALLED
 * machine. Importing the constant would make the bridge fail to COMPILE until
 * the machine half is relayed — a build-order coupling on a string literal.
 *
 * THE COST IS REAL AND IS NAMED RATHER THAN HIDDEN: two literals that must
 * agree. Each side pins its own with a test, and once both are in one tree a
 * cross-check is owed. If they ever disagree, the bridge writes a record the
 * machine's validator rejects — which surfaces as a chain that will not load,
 * loudly, on the first witness write. `[owed → board]`
 */
export const CLERK_STAMPS_FIRST_LOAD_EVENT_TYPE = "CLERK_STAMPS_FIRST_LOAD";
import { toWireOptions, type HarmGrantMemoryView, type HarmTargetEpoch } from "./to-wire-options";

// ── ACT B · THE ONE PLACE THE CLERK STAMPS ARE READ ─────────────────────────
//
//   `toWireOptions` maps a declaration and does no IO, so the reader is injected
//   — the same discipline `resolveLogPath` already follows. This is that reader,
//   and it is deliberately the MACHINE's own door (`readClockStampsFile`,
//   /opt/mica-machine/src/glue/clerk-clock-stamps-file.ts) rather than a second
//   parser written here: two parsers for one file is how a gate and a census
//   drift apart, which is the scar `toSensorConfig` already carries.
//
//   ⛔ A REFUSAL IS A WIRING ERROR, NOT A CAUTIOUS DISPOSITION, and mica-guard.ts
//   says so in the same words for the same door. If a path IS declared and the
//   file will not load, this THROWS rather than quietly handing F3 no source —
//   because "no stamps" and "stamps that would not load" must not read alike.
//   An ABSENT declaration is the quiet case, and it never reaches here.
/**
 * ⛔ WHAT EACH DOOR STATE MEANS FOR THE BRIDGE — ONE PURE FUNCTION, SO THE RULE IS
 *    TESTABLE WITHOUT A FILE THE TEST CANNOT CREATE.
 *
 *    The machine's door requires the stamps file to be owned by the clerk
 *    principal, so no test running as an ordinary uid can construct a real
 *    FILE_EMPTY_OR_ERASED. Keeping the decision in a pure function means the RULE
 *    is pinned even where the FILE cannot be.
 *
 *    "USE"          — LOADED. The only clean state.
 *    "EMPTY_SOURCE" — FILE_EMPTY_OR_ERASED. The carrier's DESIGNED FIRST STATE: the
 *                     unit creates the file empty and it stays empty until the first
 *                     successful carry. F3 is handed an EMPTY source and says so in
 *                     its own words ("an EMPTY clerkClockSource was injected. An
 *                     empty source is nothing to read"), which is DISTINCT from the
 *                     absent-path reading ("no clerkClockSource was injected"). Blind
 *                     and disclosed — it does not take the decision path down.
 *    "REFUSE"       — everything else. Not a first state: somebody's mistake or
 *                     somebody's tampering, and it must be loud.
 */
/**
 * SHAPE 3′ · what the CURSOR says, which is the only thing that can tell an
 * ERASURE from a FIRST RUN.
 *
 *   "PRESENT"    — the carrier has completed at least one carry and written how
 *                  far it got. An empty stamps file beside it means the stamps
 *                  are GONE.
 *   "ABSENT"     — no cursor. The carrier has never completed a carry, so an
 *                  empty stamps file is exactly what should be there.
 *   "UNREADABLE" — the cursor is declared and something other than absence
 *                  stopped us reading it. We cannot tell the two cases apart,
 *                  and the whole point of this witness is telling them apart.
 *   "NOT_DECLARED" — no cursor path in the declaration. The erasure test is not
 *                  available; an empty stamps file is treated as a first run and
 *                  disclosed as such. This is today's behaviour, kept so the
 *                  bridge half can land before the declaration act.
 */
/**
 * SHAPE (b) · WHO SAW THE STAMPS BEFORE, AND WHERE THAT MEMORY LIVES.
 *
 * ⛔ WHY THE CURSOR IS GONE, AND IT WAS A REAL HOLE RATHER THAN A STYLE CHANGE.
 * The first version of this witness `lstat`ed the CARRIER'S cursor file: the
 * carrier writes it only after a successful carry, so its presence was a claim
 * that stamps once existed. Codex FAILED that on 2026-09-29, correctly. The
 * cursor and the stamps file sit in ONE directory under ONE principal, so they
 * are CO-DELETABLE: erase both and the pair presents as
 * `FILE_EMPTY_OR_ERASED + ABSENT`, which is exactly what a genuine first run
 * presents. The witness was inside the reach of the thing it was watching.
 *
 * SHAPE (b), the arbiter's ruling 2026-09-29: the witness is a record the BRIDGE
 * writes in its OWN HASH-CHAINED BOOK. The bridge is a different principal from
 * the carrier, and the book is the subject chain — so erasing the witness is
 * not a delete, it is a CHAIN BREAK, which every reader on this box already
 * detects and reports by name. The memory has moved out of the attacker's
 * custody and into a container that cannot be quietly edited.
 */
export type PriorLoadWitness =
  /** This chain HAS a recorded first successful stamps load. */
  | "PRESENT"
  /** This chain has none — nothing has ever loaded stamps for it. */
  | "ABSENT"
  /**
   * The book could not be read to find out. ⚠ NOT "absent": a book this
   * process cannot read is a question unanswered, and it refuses.
   */
  | "UNREADABLE"
  /** No witness source was injected at all — today's behaviour before SHAPE (b). */
  | "NOT_WITNESSED";

export function clerkStampsDisposition(
  loadState: string,
  prior: PriorLoadWitness = "NOT_WITNESSED"
): "USE" | "EMPTY_SOURCE" | "REFUSE" {
  if (loadState === "LOADED") return "USE";
  if (loadState !== "FILE_EMPTY_OR_ERASED") return "REFUSE";

  // ⛔ THE FILE LOOKS IDENTICAL IN BOTH CASES, AND THAT IS THE WHOLE PROBLEM.
  //
  //   An empty stamps file is either "the carrier has never run" — its designed
  //   first state, which must go blind and say so — or "somebody emptied it",
  //   which is tampering and must refuse. Zero bytes is zero bytes; the stamps
  //   file cannot answer the question about itself.
  //
  //   THE BRIDGE'S OWN BOOK IS THE WITNESS. It records, once per chain, that a
  //   stamps load for THIS chain genesis once returned stamps. That record is
  //   written by the bridge, into the hash-chained subject log, and it names the
  //   chain it belongs to — so it cannot be moved to another chain, and it
  //   cannot be removed without breaking the chain.
  switch (prior) {
    case "PRESENT":
      // Stamps were here, on THIS chain, and this bridge saw them. They are
      // not here now. That is an erasure and it is not survivable by reading
      // the stamps file harder.
      return "REFUSE";
    case "ABSENT":
      // Nothing has ever loaded stamps for this chain. The designed first
      // state. Blind, disclosed, and the box keeps deciding.
      return "EMPTY_SOURCE";
    case "UNREADABLE":
      // FAIL CLOSED. "I could not check whether stamps were here before" is
      // not "they were not". A broken or unreadable book is itself a finding.
      return "REFUSE";
    case "NOT_WITNESSED":
      // No witness injected: exactly the behaviour before SHAPE (b), so this
      // code can land before the service wires the book.
      return "EMPTY_SOURCE";
  }
}

/**
 * SHAPE (b) · HAS THIS CHAIN EVER HAD A NON-EMPTY STAMPS LOAD?
 *
 * Read from the SAME file `loadExpectedChainIdentity` reads — the log the
 * readers actually stand on — because the question is about THAT chain and no
 * other. The record is one the bridge minted itself (`moduleId` is the chain's
 * own voice, never a subject's), so a subject cannot answer this question about
 * itself; `validateSubjectRecord` refuses the eventType from any other writer.
 *
 * ⚠ THE MEMBERSHIP IS THE ATTRIBUTION. A prior-load record is bound to this
 * chain by being IN it, hash-covered, after the genesis it follows — not by a
 * field this function compares. The record also CARRIES the genesis hash, which
 * is what lets a reader outside this process (an auditor with the file and
 * nothing else) see which chain it belongs to; nothing here needs that copy, and
 * checking it would be checking the chain against itself.
 *
 * ⛔ UNREADABLE IS NOT ABSENT, and this is the whole fail-closed hinge. A chain
 * that did not verify, a file this process cannot open, a reader that throws —
 * every one of them means "I could not find out whether stamps were here
 * before", and the disposition function turns that into a REFUSE. An erasure
 * that also broke the chain must not read as a first run.
 */
export function readPriorLoadWitness(
  resolvedLogPath: string,
  logKind: string
): PriorLoadWitness {
  // Only a chained log can hold this record. An unchained deployment has no
  // witness available and gets today's behaviour, stated rather than implied.
  if (logKind !== "subject-chain") return "NOT_WITNESSED";
  try {
    const chain = new SubjectChainLog({ path: resolvedLogPath });
    const state = chain.getLoadState();
    // A chain that is genuinely ABSENT or EMPTY has no boundary and no history:
    // there is nothing to have witnessed, and that is ABSENT rather than
    // UNREADABLE. Any OTHER non-verified state is a question we could not
    // answer, and it refuses.
    if (state === "SUBJECT_CHAIN_ABSENT" || state === "SUBJECT_CHAIN_EMPTY") return "ABSENT";
    if (state !== LOADED_SUBJECT_CHAIN_VERIFIED) return "UNREADABLE";
    const found = chain
      .getAll()
      .some(
        (r) =>
          r.eventType === CLERK_STAMPS_FIRST_LOAD_EVENT_TYPE &&
          r.moduleId === SUBJECT_LOG_BOUNDARY_MODULE_ID
      );
    return found ? "PRESENT" : "ABSENT";
  } catch {
    return "UNREADABLE";
  }
}

/**
 * SHAPE (b) · ⛔ THE PARALLEL COUNTER IS GONE, AND THAT IS THE WHOLE OF THIS
 * CHANGE. The arbiter's ruling, 2026-09-29 18:0xZ.
 *
 * This file carried `acceptedStampCount`, a second implementation of part of
 * F3's admission. It was fixed twice — once because it counted raw lines, once
 * because it ignored the writer check — and both fixes were correct and both
 * were the same defect: A SECOND DEFINITION OF "ACCEPTED" LIVING BESIDE THE
 * READER'S OWN. Every fix made the copy closer to F3 without making it F3, and
 * the next divergence was already implied by the ones before it.
 *
 * ⚠ THE LESSON IS NOT "THE COPY WAS WRONG". It is that a copy of a judgement
 * cannot be made right by iteration, because the thing it copies keeps moving:
 * T6 added the writer check, T7 the rejected-tail rule, T8 the chain identity,
 * and each one silently widened the gap between F3 and anything reproducing it.
 *
 * SO THE WITNESS NOW READS F3's OWN NUMBER. `F3StampCoverage.stampedCount` is
 * the count of records whose stamp survived EVERY check the leg applies — the
 * chain filter, the writer agreement, the ambiguity rule, and existence in the
 * log at all (it is built from the entries, so a stamp for a sequence that does
 * not exist can never appear in it). That is precisely "stamps F3 actually
 * used", and there is nothing left here to keep in step.
 *
 * ⚠ A NOTE ON THE NAME, because the ruling says `usedStampCount` and the field
 * is called `stampedCount`. They are the same number: with ambiguity excluded
 * there is at most one stamp per record, so records-joined equals stamps-used.
 * Renaming it would touch `src/mica/sig/index.ts`, which is settled and whose
 * tickets are spent — A SIGNATURE FOR A NAME. Not spent. Stated instead.
 */

export function loadExpectedChainIdentity(
  resolvedLogPath: string,
  logKind: string
): string | undefined {
  // Only a chained log HAS an identity. Asking a plain JSONL log for one would
  // be asking a file that never declared where it began.
  if (logKind !== "subject-chain") return undefined;
  try {
    const chain = new SubjectChainLog({ path: resolvedLogPath });
    if (chain.getLoadState() !== LOADED_SUBJECT_CHAIN_VERIFIED) return undefined;
    const boundary = chain.getBoundary();
    return boundary === null ? undefined : boundary.hash;
  } catch {
    // A reader that throws while being asked "what chain is this?" has answered
    // "I do not know", which is exactly `undefined`. It must not take the
    // decision path down: F3 discloses the absence in its own words.
    return undefined;
  }
}

/**
 * SHAPE (b) · The stamps, and the bridge's own memory of having seen them.
 *
 * ⚠ THE WITNESS IS READ HERE RATHER THAN PASSED IN, and that is deliberate: the
 * two facts must come from ONE moment. A caller that read the witness, then did
 * something, then called this, would be comparing a stamps file against a
 * memory taken at a different instant — which is the drift `footingsFromWiring`
 * exists to prevent one layer down.
 *
 * `resolvedLogPath`/`logKind` describe the log the READERS stand on, which is
 * the chain the question is about. Omitted, there is no witness and the
 * behaviour is exactly what it was before SHAPE (b).
 */
/**
 * ⛔ THE LOADER, WITH THE OWNER THE DOOR SHOULD EXPECT.
 *
 *   The arbiter's ruling 2026-09-30 09:0xZ, option 1: "the custody door takes an
 *   expected-owner parameter, default `mica`, PRODUCTION CALLERS PASS NOTHING,
 *   THE TEST PASSES ITS OWN UID." The door gained the parameter and relayed at
 *   16:1xZ (b661cdf) — and NOTHING COULD PASS IT, because this loader has no
 *   way to take one and `mica-service.ts` mentions `expectedOwner` zero times.
 *
 *   MEASURED 2026-09-30 16:4xZ, and it is why this exists: with the parameter on
 *   /opt, three witness tests stopped SKIPPING and started FAILING, because the
 *   production path still calls the door with no override, gets the strict
 *   default, and refuses a file uid 1000 owns — exactly as before the relay. The
 *   ruling's second half had no mechanism.
 *
 * ⚠ `loadDeclaredClerkStamps` below is this factory with NO owner, so every
 *   production caller keeps the strict default by construction rather than by
 *   remembering to omit an argument.
 */
export function makeDeclaredClerkStampsLoader(expectedOwner?: string) {
  return (resolvedPath: string, resolvedLogPath?: string, logKind?: string) =>
    loadDeclaredClerkStampsWithOwner(expectedOwner, resolvedPath, resolvedLogPath, logKind);
}

export function loadDeclaredClerkStamps(
  resolvedPath: string,
  resolvedLogPath?: string,
  logKind?: string
) {
  return loadDeclaredClerkStampsWithOwner(undefined, resolvedPath, resolvedLogPath, logKind);
}

function loadDeclaredClerkStampsWithOwner(
  expectedOwner: string | undefined,
  resolvedPath: string,
  resolvedLogPath?: string,
  logKind?: string
) {
  const prior: PriorLoadWitness =
    resolvedLogPath === undefined || logKind === undefined
      ? "NOT_WITNESSED"
      : readPriorLoadWitness(resolvedLogPath, logKind);
  const g = process.getuid;
  const gg = process.getgroups;
  const read = readClockStampsFile(resolvedPath, {
    uid: typeof g === "function" ? g.call(process) : undefined,
    gids: typeof gg === "function" ? gg.call(process) : [],
    // Absent on every production path; only a test ever names one.
    ...(expectedOwner === undefined ? {} : { expectedOwner }),
  });
  // ⛔ FILE_EMPTY_OR_ERASED IS THE ONE NON-LOADED STATE THAT MUST NOT THROW.
  //
  //   An empty stamps file is the carrier's DESIGNED FIRST STATE: the unit creates
  //   it empty, and it stays empty between creation and the first successful carry.
  //   Treating it as a wiring error would mean `paths.clerkStamps` cannot be
  //   declared until after a successful run — an ordering constraint nobody stated
  //   — and worse, it would take the DECISION PATH down rather than blinding one
  //   leg. An instrument whose evidence is momentarily absent goes blind and says
  //   so; it does not stop the box from deciding.
  //
  //   ⚠ AND IT IS NOT SILENT, BECAUSE THE MACHINE ALREADY HAS THE WORDS. Injecting
  //   an EMPTY source makes F3 report "an EMPTY clerkClockSource was injected. An
  //   empty source is nothing to read", which is DISTINCT from the absent-path
  //   reading, "no clerkClockSource was injected". Same kind, different sentence:
  //   a reader can tell "nobody configured this" from "it is configured and the
  //   file is empty" without any new vocabulary, kind, or reader change.
  //
  //   Every OTHER non-LOADED state still throws: CUSTODY_REFUSED, FILE_MALFORMED,
  //   FILE_UNREADABLE, WRONG_OWNER, INVOKER_WRITABLE. Those are not first states —
  //   they are somebody's mistake or somebody's tampering, and they must be loud.
  const disposition = clerkStampsDisposition(read.loadState, prior);
  if (disposition === "EMPTY_SOURCE") {
    return [];
  }
  if (disposition !== "USE") {
    const named =
      read.doorRefusal !== null
        ? `${read.doorRefusal.refusal}: ${read.doorRefusal.detail}`
        : `${read.loadState}: ${read.problem?.detail ?? "no stamps present"}`;
    if (read.loadState === "FILE_EMPTY_OR_ERASED") {
      throw new Error(
        `paths.clerkStamps is declared as ${resolvedPath} and is EMPTY, while this bridge's own ` +
          `hash-chained book says a stamps load for THIS CHAIN once returned stamps (witness: ` +
          `${prior}). ⛔ STAMPS WERE HERE AND THEY ARE GONE. An empty stamps file is identical to a ` +
          `first run when read by itself; the bridge's own record is what tells them apart, and it ` +
          `is not in the carrier's custody. If this was deliberate — a re-stamp — ARCHIVE THE STAMPS ` +
          `AND ROTATE THE CHAIN, because a new chain has a new genesis and therefore no prior-load ` +
          `record. If it was not, the stamps file was emptied under a live chain and that is the ` +
          `event this witness exists to make visible.`
      );
    }
    throw new Error(
      `paths.clerkStamps is declared as ${resolvedPath} and REFUSED: ${named}. ` +
        `A declared stamps path that will not load is a wiring error, not an absent leg.`
    );
  }
  return read.stamps;
}

import type { Declarations } from "./declarations";
import { canonicalHash } from "./canonical-json";
import { computeFooting } from "./guard-adapter";
import type { GuardAdapter, GuardEvaluationRequest, GuardOutcome, ReaderFooting, ReaderFootingsBasis } from "./guard-adapter";

// Re-exported so mica-service.ts never needs its own absolute /opt import —
// A.1's "no symlink, absolute path" discipline stays confined to this one
// file, which is the file the verifier's source-hash check covers for it.
export type { EvaluateAndRecordPaths };

// C8/C9. Re-exported for the same reason `EvaluateAndRecordPaths` is: A.1's
// "absolute path into /opt, in ONE file" discipline holds, and every other file
// in this directory gets the machine surface without an import of its own.
//
// C9 ADDS `wire` AND `WireOptions` TO THAT LIST, and it is not cosmetic. Before
// this beat, `mica-service.ts`, `to-wire-options.ts` and `declarations.test.ts`
// each reached mica-machine by the RELATIVE path `../../../mica-machine/...`,
// which resolves to `/opt/mica-machine` from the release tree but to
// `~/mica-machine` from the dev worktree — a tree three commits older that does
// not have `floorTrailOverride`/`ledgerOverride` at all. Production was right by
// accident of the release layout; the SUITE was validating against code that
// never runs. Register E8 / C8 receipt §E.1. One root, named once, here.
export { buildNotifier, wire };
export type { BuiltNotifier, WireOptions };

// C9. The READER and the Sig assessor, re-exported through the same single
// root. The C9 suite proves Part A's record against the REAL deployed reader
// rather than against a local re-implementation of its rules — "the reader
// accepts it" is the only claim worth making, and it has to be the reader that
// actually runs. Letting the test reach /opt on its own would rebuild the very
// multi-root problem Part D just removed, one file further out.
export { MicaLogFile } from "/opt/mica-machine/src/glue/mica-log-file";
// R1 / `/explain`. Re-exported here for the SAME reason `EvaluateAndRecordPaths`
// is (design §A.1, W1): this file is the only one that names
// `/opt/mica-machine` by absolute path, and mica-service.ts takes what it needs
// through this seam rather than opening a second one.
//
// READ-ONLY AT THE CALL SITE. `mica-service.ts` constructs a `DecisionJournal`
// over `paths.journal` with a path and NOTHING ELSE — no appender, no lock
// acquirer — so it can replay and index the chain and cannot append to it. The
// standing rule in mica-service.ts (":1402") is that `paths.journal` belongs to
// Stage 1's DecisionJournal and this service may not APPEND to it; reading the
// book it already wrote is not that, and `/explain` is a read.
export { DecisionJournal } from "/opt/mica-machine/src/glue/decision-journal";
// ── ACT A · the chained subject log ─────────────────────────────────────────
//
// Re-exported HERE, through the ONE file that imports mica-machine by absolute
// path (design §A.1, W1), for the same reason `DecisionJournal` is: a second
// absolute-path import elsewhere is a second place the machine root can be got
// wrong, and `to-wire-options.ts`'s header records what that cost last time
// (a relative specifier that resolved to two different trees).
export {
  SubjectChainLog,
  SubjectEventJournal,
  LOADED_SUBJECT_CHAIN_VERIFIED,
  // SHAPE (b) · the chain's own voice, re-exported so mica-service can write a
  // witness record in it without a second absolute-path import.
  SUBJECT_LOG_BOUNDARY_MODULE_ID,
  SUBJECT_CHAIN_ATTESTS,
  SUBJECT_LOG_BOUNDARY_EVENT_TYPE,
} from "/opt/mica-machine/src/glue/subject-event-journal";
export type {
  RetiredPredecessor,
  SubjectChainLoadState,
} from "/opt/mica-machine/src/glue/subject-event-journal";
export type {
  DecisionFinalRecord,
  JournalLoadState,
} from "/opt/mica-machine/src/glue/decision-journal";
export { assessSig } from "/opt/mica-machine/src/mica/sig";
export { assessEng } from "/opt/mica-machine/src/mica/eng";
// S199 · the reader's own order bound, for the ENDING_ORDERED admit path. EAGER,
// like every import in this file: a machine without the export (anything before
// the S199 machine relay) stops this bridge at ExecStart, never at the first order.
// RELAY ORDER: the S199 machine half FIRST, then this bridge. gate4CountsAsOrder (cond. 2 alternative, audit
// 2026-10-18 06:56Z): the reader's own per-record order test, so only an order whose OWN class is declared is bounded.
export { gate4OrderBound, gate4CountsAsOrder, GATE4_ORDER_BOUND_RULE } from "/opt/mica-machine/src/mica/gate4-sunset";


/**
 * DESIGN §A.3. Built fresh per request from the loaded declaration plus the
 * already-resolved `GuardEvaluationRequest` (`handleGuard` fills it from
 * `toGuardFlags`). Three notes the design calls out, preserved here:
 *
 * 1. `readableLoadStates` comes from the top-level field, never repeated
 *    inside `eng`/`sig` — `to-sensor-config.ts` already refuses to emit it
 *    there ([verified] wire.ts:198-206, ignored on the per-reader configs).
 * 2. `floorTrailPath`/`ledgerPath` are NEVER passed — `evaluateAndRecord`
 *    injects journal-backed overrides and `wire()` prefers an override over
 *    a path; passing them would only let a future reader think two writers
 *    exist ([verified] wire.ts:444-453 — the override-not-path comment name
 *    lives beside `floorTrailOverride`/`ledgerOverride` in that file).
 * 3. C8, CHANGED: `noticeDir`/`noticeWindow` are NO LONGER PASSED. The service
 *    builds the notifier ONCE, at the point it binds this adapter, and hands
 *    the pair in as `notifierOverride`. Passing either alongside an override is
 *    REFUSED by `wire()` (`WireUsageError`), not silently preferred — so this
 *    function cannot drift back into the old shape without a loud failure on
 *    the first guarded act.
 *
 *    WHY THE CHANGE EXISTS AT ALL. `wire()` runs once per action, and
 *    `BatchedNotifier` keeps `sinceLastNotice`/`total` as instance fields, so a
 *    per-action notifier was a counter that could not rise: the three real acts
 *    of 2026-09-20 each reported `count=1 totalSoFar=1`, and `notice.window`
 *    had exactly one usable value because at 2 or more the pending count died
 *    unflushed and no notice was ever emitted. The notice asks the operator to
 *    check whether the count is HIGHER THAN EXPECTED; pinned at 1 it never
 *    could be. With a service-lifetime pair, `totalSoFar` means "since this
 *    process started" — which is the first meaning it has ever had.
 *
 *    RESIDUAL, NOT FIXED HERE: `totalSoFar` still RESETS ON RESTART. Seeding it
 *    from the pass-blind ledger's length needs a private field on
 *    `notifier.ts`, a chokepoint file — the arbiter's ruling, not this build.
 *
 * 4. C9 / PART D, THE BIG ONE: `logPath`/`logKind` ARE NOW PASSED, because
 *    this function now BUILDS ON `toWireOptions(d)` — the same option builder
 *    `/status`'s instrument census uses. Register A2 closes here.
 *
 *    THE COMMENT THIS REPLACES SAID THE OPPOSITE, and it was right when it was
 *    written. Its reasoning was: wiring `logPath` would change an UNWIRED census
 *    line to a CANNOT_ASSESS one on every real decision and gain no invariant,
 *    because the declared log is not in `MicaLogRecord` grammar. PART A REMOVES
 *    THAT REASON — the persisted subject-event record now carries MICA's five
 *    required fields, so the reader parses it, and with Part B's two Sig maps
 *    F2 can actually read. ALARM becomes reachable on the live gate for the
 *    first time.
 *
 *    WHY ONE BUILDER AND NOT TWO SETS OF FIELDS: the auditor's finding
 *    (Abgleich §0.3) was that `/status` ran `wire(toWireOptions(d))` WITH a log
 *    while the gate ran `wireOptionsFor()` WITHOUT one — so the census
 *    described a reading the gate never took, and said "2 WIRED" over three
 *    decisions that composed zero sensors. Two builders is how that happens.
 *    One builder is how it cannot.
 *
 *    THE GATE-ONLY FIELDS, and they are the whole of what this function adds:
 *    `line`, `stakesClass`, `notifierOverride`, `decisionClock`. None of them
 *    belongs in a read-only census, and `toWireOptions` must never grow one —
 *    see its header for why `noticeDir`/`noticeWindow`/`witnessIntake`/
 *    `transport` in particular would now THROW rather than be ignored.
 */
export function wireOptionsFor(
  d: Declarations,
  resolved: GuardEvaluationRequest,
  notifier: BuiltNotifier,
  // C9: the service's own `resolvePath`. NOT optional in practice — the service
  // always passes it — but defaulted to the identity so a unit test can build
  // options without a service. See to-wire-options.ts for what a raw declared
  // logPath cost, and how quietly it cost it.
  resolveLogPath: (declaredPath: string) => string = (p) => p,
  // ⛔ TEST-ONLY, AND IT MUST REACH THE DECISION PATH TOO. The mint had this
  //   seam and the guard did not, so a fixture whose stamps file this uid owns
  //   passed the mint and then 500'd the very next decision with WRONG_OWNER.
  //   One seam wired into one of two paths is not a seam; it is a trap that
  //   lets half a test pass. Absent on every production call.
  clerkStampsOwner?: string,
  // LONG RUN A STOP 2 · the service's target-salt epoch (item fingerprints and the
  // epoch's start), passed through to the ONE builder so /status's census and the
  // gate hand Gate 2 the same harm reading (the C9 Part D rule).
  harmEpoch?: HarmTargetEpoch | null,
  // S216-2 · the service's grant memory, through the same one builder.
  grantMemory?: HarmGrantMemoryView | null
): WireOptions {
  const base = toWireOptions(
    d,
    resolveLogPath,
    clerkStampsOwner === undefined
      ? loadDeclaredClerkStamps
      : makeDeclaredClerkStampsLoader(clerkStampsOwner),
    loadExpectedChainIdentity,
    harmEpoch,
    grantMemory
  );
  return {
    // C9 / Part D: the readers come from THE one builder — logPath, logKind,
    // readableLoadStates, eng, sig (both maps). Spread first so the gate-only
    // fields below read as the addition they are.
    // T8 · the expected chain identity rides the SAME builder as the stamps.
    // A gate that loaded the stamps and not the identity would refuse every one
    // of them.
    ...base,
    // LONG RUN A STOP 2 · THE DECIDING ACT, PER /guard (Stop-1 note F-7; contract
    // B2). `wire()` is called once per act here, so this is the one place the act
    // being decided is known: its actionId. Only in harm mode (the key exists only
    // when `gate2Harm` does); the census (`toWireOptions` alone) carries null — a
    // status read decides no act. The installed machine ignores the key (verified
    // at bytes; see to-wire-options.ts).
    ...("gate2Harm" in base ? { gate2DecidingActionId: resolved.actionId } : {}),
    line: { classes: d.stakes.lineClasses, holdAtOrAbove: resolved.holdAtOrAbove },
    stakesClass: resolved.stakesClass,
    // C8: the pair, not the path. `d.notice.window` was consumed when the
    // service BUILT this notifier and is deliberately not repeated here — the
    // window belongs to the object's construction, and a second copy of it on
    // this object would be a number that changes nothing.
    notifierOverride: notifier,
    decisionClock: () => Date.now(),
  };
}

/**
 * DESIGN §A.5. Maps a real `EvaluateAndRecordResult` to `GuardOutcome`.
 * Exported and pure (no I/O) so the OK/OK-recordNotPersisted/CONFLICT rows
 * of the design's table are unit-testable without a real evaluateAndRecord
 * call. The two thrown-error rows (`EvaluateAndRecordUsageError` -> 400,
 * any other throw -> 500) are handled in `evaluate()`'s own try/catch,
 * because they never reach this function as a return value.
 *
 * P6 CLOSED THE DISCLOSURE GAP THIS COMMENT USED TO NAME. What stood here is
 * kept in outline because the shape of the defect is worth keeping, not the
 * defect:
 *
 *   BEFORE Part D, `wireOptionsFor` passed no `logPath`, so `wire()` internal to
 *   this call constructed no Eng/Sig reader at all. `[]` was the TRUE answer,
 *   exactly per Ruling R item 2 ("null when this row is UNWIRED, nothing to
 *   disclose a footing for").
 *
 *   AFTER Part D, two readers really do run on every guarded act, and `[]` no
 *   longer meant "none were wired" — it meant "two were wired and this response
 *   tells you nothing about their footing". The same shape of silence the
 *   census-vs-gate defect was (register E1): a field that reads identically
 *   whether or not the thing it describes happened.
 *
 *   C9 LEFT IT `[]` because `evaluateAndRecord` did not return `wire()`'s census
 *   to its caller, and the alternative on offer — a footing read off the
 *   `/status` probe — was worse: A DIFFERENT `wire()` CALL'S READING, PRESENTED
 *   AS THIS DECISION'S.
 *
 * P6 MADE THE MICA-MACHINE CHANGE instead, and the fix is the shape of the
 * thing rather than a promise about it. `EvaluateAndRecordResult` now carries
 * `readerFootings`, derived by mica-machine's `footingsFromWiring(wiring)` from
 * THE WIRING THAT DECIDED — a pure function of one argument, so there is no
 * other reading it could have returned, and `evaluate-and-record.ts` has a
 * source fence holding it to exactly one `wire()` call.
 *
 * SO THIS FUNCTION STAYS PURE AND STAYS DUMB, and that is the load-bearing part
 * of it. It reads `result` and nothing else. It does not call `wire()`, it does
 * not call `buildInstrumentCensus()`, and it never consults `/status` — every
 * one of those answers "what is the log's state NOW?", which is a different
 * question from "what did the reader that produced THIS decision stand on?".
 * They agree on a quiet box and diverge exactly when the log changed, which is
 * the only moment the field matters.
 *
 * THE ONE JUDGEMENT ADDED HERE is `computeFooting` — mica-machine reports the
 * load state it observed and nothing more; whether that state is the
 * chain-verified one is this layer's call, made in one place (guard-adapter.ts)
 * for both `/status` and `/guard`.
 */
export function mapEvaluateAndRecordResult(
  result: EvaluateAndRecordResult,
  identity: { readonly subject: string; readonly sessionId: string; readonly actionId: string }
): GuardOutcome {
  if (result.kind === "CONFLICT") {
    return {
      bound: true,
      httpStatus: 409,
      error: "IDENTITY_HASH_CONFLICT",
      detail:
        `identity (subject=${result.identity.subject}, sessionId=${result.identity.sessionId}, ` +
        `actionId=${result.identity.actionId}) already has a DECISION_FINAL recorded under a ` +
        `different requestHash than this call computed.`,
      identity: { subject: result.identity.subject, sessionId: result.identity.sessionId, actionId: result.identity.actionId },
    };
  }
  // P6. Read off `result` — the value this decision came back in — and nothing
  // else. The two arms are mica-machine's own distinction and are preserved
  // rather than flattened: THIS_CALL's empty array ("this wiring built no log
  // reader") and NO_READING_TAKEN ("this call evaluated nothing; it replayed a
  // recorded FINAL") are different facts, and `[]` alone cannot tell them
  // apart. That is the whole defect.
  const report = result.readerFootings;
  const readerFootings: readonly ReaderFooting[] =
    report.kind === "THIS_CALL" ? report.readers.map((r) => computeFooting(r.reader, r.loadState)) : [];
  const readerFootingsBasis: ReaderFootingsBasis =
    report.kind === "THIS_CALL" ? { kind: "THIS_CALL" } : { kind: "NO_READING_TAKEN", reason: report.reason };

  return {
    bound: true,
    httpStatus: 200,
    decision: result.decision,
    // `DeliveryStatus`/the quarantined record types are mica-machine's own
    // named interfaces, not index-signed — GuardOutcome's fields are typed
    // `Readonly<Record<string, unknown>>` deliberately (design §A.5: "Code
    // shapes, not the contract's") so guard-adapter.ts never has to import
    // mica-machine's types. The values themselves are untouched, structural
    // JSON-shaped objects; only the static type is widened here.
    delivery: result.delivery as unknown as Readonly<Record<string, unknown>>,
    readerFootings,
    readerFootingsBasis,
    quarantined: result.quarantined as unknown as readonly Readonly<Record<string, unknown>>[],
  };
}

/**
 * DESIGN §A.2. `guard-adapter.ts`'s `GuardAdapter` interface and
 * `GuardEvaluationRequest` are kept exactly. `NotBoundGuardAdapter` stays
 * the honest thing to inject in a test that wants an unbound service; this
 * class is the one Stage 4 makes the SERVICE's default when no adapter is
 * injected (mica-service.ts's `buildGuardAdapter`, not this file — this
 * class itself has no opinion about defaults).
 *
 * Takes `paths` and `wireOptionsFor` by constructor, rebuilt on every
 * successful `reload()` so a SIGHUP changes policy for the next request
 * and never mid-request (mica-service.ts does the rebuilding; this class
 * is simply reconstructed with fresh, closed-over declarations).
 */
export class Stage1GuardAdapter implements GuardAdapter {
  constructor(
    private readonly paths: EvaluateAndRecordPaths,
    private readonly wireOptionsFor: (r: GuardEvaluationRequest) => WireOptions
  ) {}

  async evaluate(request: GuardEvaluationRequest): Promise<GuardOutcome> {
    // DESIGN §A.5, verbatim: unreachable by construction (mica-service.ts's
    // preflight guard means `handleGuard` never dispatches without a real
    // declarationHash) — asserted here rather than assumed, so a future
    // change to that preflight guard fails loud, at this line, rather than
    // silently binding a fabricated digest.
    if (!/^[0-9a-f]{64}$/.test(request.declarationHash)) {
      throw new Error(
        "declarationHash absent at the adapter — unreachable by construction; " +
          "if this throws, mica-service.ts's preflight guard has been changed."
      );
    }

    const identity = { subject: request.subject, sessionId: request.sessionId, actionId: request.actionId };

    try {
      const result = evaluateAndRecord(
        {
          identity,
          subject: request.subject,
          toolName: request.toolName,
          stakesClass: request.stakesClass, // server-resolved, never caller-supplied
          requestHash: canonicalHash({
            actionId: request.actionId,
            sessionId: request.sessionId,
            subject: request.subject,
            toolName: request.toolName,
          }),
        },
        this.paths,
        this.wireOptionsFor(request),
        { declarationBinding: { kind: "HASH", sha256: request.declarationHash } }
      );
      return mapEvaluateAndRecordResult(result, identity);
    } catch (err) {
      if (err instanceof EvaluateAndRecordUsageError) {
        return { bound: true, httpStatus: 400, error: "MALFORMED_FIELD", detail: err.message, identity };
      }
      return {
        bound: true,
        httpStatus: 500,
        error: "SERVICE_FAULT",
        detail: err instanceof Error ? `${err.name}: ${err.message}` : String(err),
        identity,
      };
    }
  }
}
