// ── interest-book — where Gate 1's labels are WRITTEN, and under which class ──
//
// GATE 1 · Stop 2 · round 2 (placement D). `interest-label.ts` decides WHICH
// declared region an act's claimed target lies in. This file decides where that
// answer goes and what it is filed under:
//
//   · a SEPARATE chained file, the INTEREST BOOK (`paths.interestBook`), written
//     by the bridge. Nothing in this code but Gate 1 reads it — a fact about
//     this code, not a rule anything enforces beyond the loader's X23, which
//     refuses readers.logPath naming the book (review K2W3-7); a sibling reader
//     pointed at it by some other route would read it. The subject chain's TOOL_ATTEMPTED
//     keeps `outcome = toolName` exactly as at d087f0b, so no sibling reader
//     (Eng, Sig, op3, the gate-4 reader) sees anything new. Option C — the label
//     riding the attempt's own outcome — was measured by the cold review to move
//     Eng's AMI by up to ±0.2 on the real record shape and to hide the very
//     TOOL_RESULT flattening Eng exists to catch; it also let a subject-supplied
//     pre-frame outcome collide with a category id. Neither can happen here: the
//     book holds ONLY records the bridge derived.
//   · one record per TOOL_ATTEMPTED that PERSISTED on the subject chain, for a
//     subject that declares a frame, written AFTER that persist.
//   · filed under a FRAME-SCOPED class: `frameLabelEventType(frame)`.
//
// ⛔ THE PLAIN TARGET IS NOT AN INPUT TO ANYTHING HERE. The record builder takes
//    the derived label (a declared category id or the underived word) and the
//    act's identity; it is never handed the target, so it cannot write it.
//
// Not under interest-label.ts's purity fence: the class needs a digest, and a
// digest is a runtime import. This file still does no fs, no clock read of its
// own and no I/O — the caller passes `nowMs`. Its other two imports are the two
// VERSION CONSTANTS the class names (round 3, B1); `target-fingerprint` loads
// fs for its salt, which this file never calls.

import { createHash } from "crypto";
import { INTEREST_DERIVATION_VERSION } from "./interest-label";
import { TARGET_CANON_VERSION } from "./target-fingerprint";

// ── THE CLASS ────────────────────────────────────────────────────────────────

/** The fixed head of every label class. The 16 hex after it name the derivation: rules, canonicaliser, regions. */
export const INTEREST_LABEL_CLASS_HEAD = "INTEREST_LABEL@";

/**
 * Structurally `SubjectFrame` (declarations.ts), reduced to what DECIDES
 * DERIVATION: the regions, and nothing else. Declared here rather than imported
 * so a caller that holds only regions (a test, the wiring) can name a class
 * without building a whole declaration — and so the compiler shows that the
 * category list, labels, groundings, bases, proxy flags and the `self` flag are
 * not read. (Round 3, B1: category ids no longer enter; see below.)
 */
export interface FrameDrawing {
  readonly regions: { readonly value: readonly { readonly prefix: string; readonly category: string }[] };
}

/** The two rule versions a class names. Defaulted to this build's; a test passes others to show they move it. */
export interface LabelRuleVersions {
  /** interest-label.ts's INTEREST_DERIVATION_VERSION — what deriveInterestLabel does with a canonical target. */
  readonly derivation: number;
  /** target-fingerprint.ts's TARGET_CANON_VERSION — how a raw target becomes the canonical one. */
  readonly canon: number;
}

/**
 * The label class for one DERIVATION — the rules that turn a target into a
 * label, and the drawing they turn it against:
 *   "INTEREST_LABEL@" + the first 16 hex of sha256 over the JSON text of
 *   [ INTEREST_DERIVATION_VERSION, TARGET_CANON_VERSION,
 *     [[prefix, category] per region, sorted by prefix, then category] ].
 *
 * WHY FRAME-SCOPED (review C2-2, C2-3, C4-2). The reader counts labels against
 * the frame it is handed TODAY, and regions may move on a SIGHUP (X21 refuses
 * only a narrowing of M). A label derived under an earlier drawing is a true
 * statement about THAT drawing and a false one about this: an act placed in
 * c-other under v1 would count as c-other under a v2 that no longer maps any
 * region there, and the envelope would print reach above its own derivable
 * ceiling. Filing each label under the derivation that produced it makes the
 * reader — which asks for exactly `frameLabelEventType(today's frame)` through
 * to-wire-options — count only labels today's rules AND today's drawing would
 * also have produced. Labels from an earlier derivation are a different class
 * and are not counted; they are not deleted, re-labelled or re-read.
 *
 * WHY THE RULE VERSIONS ENTER (round 3, B1; reviews K1R1-N2, K2W3-5, K1R3-5,
 *   K2W-6, K3D2-9). The drawing alone did not name the DERIVER. Round 3 itself
 *   changed deriveInterestLabel (a ":" anywhere in a segment is not a path), so
 *   under one unchanged drawing `<home>/localhost:8080/api` was c-home before
 *   and is UNDERIVED after; without the version, old and new labels would share
 *   a class and be summed as one derivation. The canonicaliser's version enters
 *   for the same reason the fingerprint binds it: it decides which canonical
 *   string the rules see. ⚠ The versions are only as good as their bumping —
 *   a rule change that forgets to move INTEREST_DERIVATION_VERSION files new
 *   labels under the old class; the exact-class arm in interest-book.test.ts
 *   pins the current pair so a bump is a deliberate re-pin.
 *
 * WHAT ENTERS, AND WHY NOTHING ELSE DOES. Only what changes WHICH label an act
 * gets: the two rule versions and the regions as (prefix, category) pairs — a
 * moved, added or removed prefix places acts differently, and a reassigned
 * region gives them another word. CATEGORY IDS DO NOT ENTER ON THEIR OWN (round
 * 3, B1; reviews K2W-4, K2W-5, K2W3-6): every id an act can be labelled with
 * already rides in a pair, so a renamed id that has a region moves the class
 * through its pairs, and a category with NO region places nothing. Hashing the
 * id list made the one widening canon wants — a new category, admitted by X21
 * on SIGHUP — orphan the whole book although no act's label changed.
 * Labels, groundings, bases, proxy flags and `self` do not change any act's
 * label either, so a wording edit must not orphan the book's history.
 * ⚠ THE CLASS IS OVER THE DECLARED PAIRS, NOT THEIR EFFECTIVE MAP (review K2W-5,
 *   disclosed, not fixed): a region added UNDER another region of the SAME
 *   category places no act differently and still moves the class, so that edit
 *   restarts the envelope. It errs toward a separate class.
 * ORDER IS NOT IN THE DIGEST (seat, round 2, overriding the R2 spec's "declared
 *   order" after BRIDGE-2 pinned its cost). On a loaded declaration a reorder
 *   places no act differently: prefixes are unique (the loader refuses a
 *   duplicate) and the longest wins. So a pure reorder must not orphan history,
 *   and the pairs are sorted by UTF-16 code unit before hashing. ⚠ Without the
 *   loader, duplicate prefixes tie-break on declared order, which sorting
 *   hides; that drawing never reaches a book.
 *
 * ⚠ PLAIN JSON.stringify, NOT canonical-json. canonical-json NFC-normalises
 *   every string before hashing; two drawings whose prefixes differ only in
 *   normal form MATCH DIFFERENT TARGETS (the label compares bytes) and must not
 *   share a class. The front door refuses non-NFC prefixes (R-b), so on a
 *   loaded declaration the two agree — this choice matters only without it, and
 *   there it errs toward a separate class. Arrays only, so no key order enters.
 *
 * ⚠ 64 BITS OF DIGEST. Two derivations sharing a class by collision would merge
 *   their histories; at 2^-64 per pair this is not a threat this deployment
 *   can meet by accident, and a deliberate collision would need a deployer to
 *   declare it — who could simply declare the drawing instead.
 */
export function frameLabelEventType(
  frame: FrameDrawing,
  versions: LabelRuleVersions = { derivation: INTEREST_DERIVATION_VERSION, canon: TARGET_CANON_VERSION }
): string {
  const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
  const pairs = frame.regions.value
    .map((r) => [r.prefix, r.category] as const)
    .sort((a, b) => cmp(a[0], b[0]) || cmp(a[1], b[1]));
  const input = JSON.stringify([versions.derivation, versions.canon, pairs]);
  const digest = createHash("sha256").update(input, "utf8").digest("hex");
  return INTEREST_LABEL_CLASS_HEAD + digest.slice(0, 16);
}

// ── THE RECORD ───────────────────────────────────────────────────────────────

/** What the writer knows about one label at the moment it appends it. */
export interface InterestLabelEntry {
  /** `identity.subject` — the label class's moduleId, as the reader asks for it. */
  readonly subject: string;
  /** `frameLabelEventType(frame)` for the rules and frame that DERIVED `label`. */
  readonly eventType: string;
  /** A declared category id or INTEREST_UNDERIVED. Never the target. */
  readonly label: string;
  /** `identity.actionId` of the TOOL_ATTEMPTED. */
  readonly actionId: string;
  /** The TOOL_ATTEMPTED's own `subjectSeq` on the subject chain — the join back to the act. */
  readonly subjectSeq: number;
}

/**
 * The book record body. The journal adds `recordType`, `sequenceNumber`,
 * `previousHash` and `hash`; MICA's five declared fields (with `sequenceNumber`)
 * plus `actionId` are what `SubjectChainLog` projects for a reader, and
 * `subjectSeq` rides alongside, hashed, unread by the reader.
 *
 * `timestamp` is NON-DECREASING against the previous book record (the S141-d
 * rule, for the same reason: a chain whose time contradicts its order is one a
 * reader may latch on). It is the moment the LABEL was written, not the act's:
 * the act's own time is on the subject chain at `subjectSeq`.
 */
export function buildInterestLabelRecord(
  entry: InterestLabelEntry,
  previous: Record<string, unknown> | null,
  nowMs: number
): {
  readonly subjectSeq: number;
  readonly timestamp: number;
  readonly moduleId: string;
  readonly eventType: string;
  readonly actionId: string;
  readonly outcome: string;
} {
  const prev = previous === null ? null : previous.timestamp;
  const last = typeof prev === "number" && Number.isFinite(prev) ? prev : null;
  return {
    subjectSeq: entry.subjectSeq,
    timestamp: last === null ? nowMs : Math.max(nowMs, last),
    moduleId: entry.subject,
    eventType: entry.eventType,
    actionId: entry.actionId,
    outcome: entry.label,
  };
}

// ── THE BOOK'S OWN WORDS ─────────────────────────────────────────────────────

/**
 * The basis on the book's position-0 boundary (`retired: null`).
 * ⚠ A BOOK WITH NO PREDECESSOR CANNOT PROVE IT HAS NONE. Unlike the subject
 *   chain (X15 refuses a FIRST BOOT there), nothing is declared about a retired
 *   interest book, so a deleted book begins again with this same line at the
 *   next start. What that loses is labels, and they are NOT re-derivable: the
 *   plain target that derived them was never stored anywhere. The subject chain,
 *   which holds the acts, is not touched. Said here so the boundary is not read
 *   as more than it is.
 */
export const INTEREST_BOOK_BOUNDARY_BASIS =
  "INTEREST BOOK · FIRST LINE. This chain is the bridge's Gate 1 interest book: one label record per " +
  "TOOL_ATTEMPTED that persisted on the subject chain, for a subject that declares a frame, written after " +
  "that act and filed under the derivation (rule versions and frame regions) that produced it. It is NOT the subject chain and declares no " +
  "rotation of it. retired is null because no predecessor of this book is declared anywhere — not because one " +
  "was verified absent.";

/**
 * The EVENT-BOOK kind for an act that persisted and could not be labelled.
 * Event-book kinds are the bridge speaking about itself, a vocabulary separate
 * from SUBJECT_EVENT_KINDS, which this does not touch.
 */
export const INTEREST_LABEL_NOT_PERSISTED = "INTEREST_LABEL_NOT_PERSISTED";
/** The event-book kinds for the book's position-0 line, written and refused. */
export const INTEREST_BOOK_BOUNDARY = "INTEREST_BOOK_BOUNDARY";
export const INTEREST_BOOK_BOUNDARY_REFUSED = "INTEREST_BOOK_BOUNDARY_REFUSED";
