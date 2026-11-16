// ── declarations — loader/validator for citadel/mica-bridge/declarations.config.json ─
//
// Enforces schema v1 (declarations.schema.json, verbatim per the Designer's
// §A) plus the nine cross-field rules §A.2 lists that JSON Schema cannot
// express. A missing or unknown field is a REJECTION, never a fallback —
// there is no default for any field in this schema (design §A.0).
//
// This file does not run a generic JSON-Schema engine: the schema is small
// and fixed, so the validator below walks it by hand, field by field, in
// the schema's own declared order, and stops at the FIRST offending field
// path. That first-offender guarantee is the whole point of a loader that
// a builder or a verifier can trust to name the exact typo.
//
// isUsableLine is reimplemented here to the EXACT rule it enforces upstream
// (cited at each call site) rather than imported, per the brief: "reimplement
// its exact rule and cite it, do not import mica-machine at this stage."

import { readFileSync, lstatSync } from "fs";
import { resolve as resolvePath, dirname, basename, join as joinPath } from "path";
import { canonicalHash } from "./canonical-json";
// R-b: a region prefix must equal ITS OWN canonical form under the SAME rule the
// bridge applies to every target. target-fingerprint imports only crypto and fs,
// so this edge adds no cycle.
import { canonicaliseTargetIdentity } from "./target-fingerprint";
// ROUND 3 (A2, reviews K2W-2, K3D2-1): a region prefix must not hold a segment
// the label rule refuses, or the region is DEAD while counted derivable. ONE
// predicate, imported, not a second copy that could drift. The edge adds no
// cycle: interest-label.ts has no runtime import at all, and its PURITY FENCE
// (interest-label.test.ts) turns red the day it gains one.
import { segmentIsNotAPath } from "./interest-label";
// Long Run A Stop 2 (harm H4): an ITEM is placed by the writer's OWN deriver and spelt as the witness looks
// (one-pair strip), so the door asks the two functions the label site asks — never a second copy.
import { deriveInterestLabel, unquoteOnePair } from "./interest-label";

/**
 * The bridge service's own uid (`mica-bridge`, 982 per the arbiter's uid
 * table, brief §1 ruling F). A route row naming this uid would be the
 * service authorising itself over its own socket — Ruling O's stated
 * objection to the draft's operator row. Not read from the declaration:
 * it is who is RUNNING the validator, not something the validator could be
 * told to exempt.
 */
const MICA_BRIDGE_SERVICE_UID = 982;

// ── the loaded shape ──────────────────────────────────────────────────────

export interface DeclaredNumber {
  readonly value: number;
  readonly basis: string;
  readonly proxy: boolean;
}
export interface DeclaredString {
  readonly value: string;
  readonly basis: string;
  readonly proxy: boolean;
}
export interface DeclaredStringList {
  readonly value: readonly string[];
  readonly basis: string;
  readonly proxy: boolean;
}
/**
 * C9 — an eventType -> eventType[] map, declared with the same envelope as every
 * other value here. Carries `readers.sig.preconditionMap` and
 * `readers.sig.reentryMap`, which mica-machine types as `PreconditionMap` and
 * `ReentryMap` (both `Readonly<Record<string, readonly string[]>>`,
 * `sig/index.ts:71, :97`) — structurally identical, kept as ONE declared shape
 * here because the declaration's job is to carry the value and its basis, not to
 * re-encode MICA's semantics.
 *
 * EMPTY IS REFUSED, deliberately. `SigConfig`'s own doc says "Absent OR EMPTY"
 * means the scope is unread — so an empty map declared here would be a field
 * that looks configured and reads as nothing. If a deployment wants the leg
 * unread it omits the field; the schema then refuses the whole declaration,
 * which is the loud outcome rather than the quiet one.
 */
export interface DeclaredEventMap {
  readonly value: Readonly<Record<string, readonly string[]>>;
  readonly basis: string;
  readonly proxy: boolean;
}
/**
 * An `(moduleId, eventType)` class, declared with the same envelope as every
 * other value here. mica-machine types this as `OperatorEventClass`
 * (`src/mica/operator-layer-profile.ts`) and as `Gate4EventClass`: two non-empty
 * strings and nothing else.
 *
 * WHY A CLASS AND NOT TWO SIBLING STRINGS: the instruments compare the PAIR —
 * op3 refuses a profile whose expectation and response classes are EQUAL, and
 * op1 matches its attestation class on both members at once. Splitting a pair
 * across sibling fields would let a declaration name half a class, which is
 * exactly what the envelope discipline exists to prevent.
 *
 * THREE FIELDS USE IT, and that is why there is ONE interface here rather than
 * two: `readers.nodeResponse.expectationClass` and `.responseClass` (op3, built
 * on the `opa` line, 109d5d9) and `readers.doctorCadence.attestationClass`
 * (op1, built on the bundle line). Both lines declared an interface of this
 * name and this shape; THIS MERGE KEEPS ONE. They were never independently
 * maintainable — `validateDeclaredEventClass` below is the single validator for
 * all three fields, and a divergence between two copies of this interface would
 * have been a divergence between two readings of one validator's output.
 */
export interface DeclaredEventClass {
  readonly value: { readonly moduleId: string; readonly eventType: string };
  readonly basis: string;
  readonly proxy: boolean;
}
/**
 * The shape narrow-K, narrow-W and narrow-R share, minus the one field whose
 * NAME differs per reader. See `Declarations["readers"].narrowK` for why the
 * three are one shape and why the differing field is kept differently named.
 *
 * `declaredProfile` is a LIST of `eventType` values, not a single class — the
 * instruments take `declaredProfile?: readonly string[]` and the SAME list
 * drives both legs (leg 1 checks presence of these classes; leg 2's partition is
 * exactly these classes against everything else). A brief that says
 * `constraintClass = HELD_THEN_DIVERGED` is naming a one-member list; there is
 * no field of that name in the tree.
 */
export interface DeclaredNarrowingProfile {
  readonly declaredProfile: DeclaredStringList;
  readonly correlationThreshold?: DeclaredNumber;
  readonly correlationCeilingMargin?: DeclaredNumber;
  readonly correlationPermutationSamples?: DeclaredNumber;
  readonly correlationPermutationSeed?: DeclaredNumber;
}
/**
 * can actually construct. ACT A (the arbiter's ruling 5, 2026-09-22) added a THIRD:
 * "subject-chain", which selects `src/glue/subject-event-journal.ts`'s
 * `SubjectChainLog` over the bridge's own hash-chained subject log. The reader
 * is SELECTED, not sniffed — a detector would turn its mistakes into verdicts.
 */
export interface DeclaredLogKind {
  readonly value: "mica" | "witness" | "subject-chain";
  readonly basis: string;
  readonly proxy: boolean;
}

export type PilotDeclared =
  | { readonly active: false }
  | {
      readonly active: true;
      readonly sessionId: string;
      readonly expiresAt: string;
      readonly holdAtOrAbove: DeclaredString;
    };

export interface RouteAllow {
  readonly method: "GET" | "POST";
  // R1. `/explain` joins the union. THE FOUR PLACES THIS LIST LIVES, named
  // here because nothing references anything else and the next editor will
  // otherwise find them one compile error at a time: this TYPE, the runtime
  // `PATH_VALUES` gate in `validate()` below, `KNOWN_PATHS` in
  // mica-service.ts's dispatcher, and the `path` enum in
  // declarations.schema.json. A path missing from the type fails to compile;
  // missing from PATH_VALUES, the declaration is rejected at load; missing
  // from KNOWN_PATHS, the request 404s before authorisation is ever consulted.
  readonly path: "/guard" | "/subject-events" | "/status" | "/events" | "/log" | "/explain" | "/sunset-order";
}
export interface Route {
  readonly uid: number;
  readonly role: "subject" | "alerter" | "operator" | "verifier";
  readonly allow: readonly RouteAllow[];
}
export interface Subject {
  readonly subject: string;
  readonly toolName: string;
  readonly stakesClass: string;
  readonly peerUid: number;
  /**
   * S201: the systemd unit (no `.service` suffix) that runs this subject's
   * CALLER. Plain data like toolName, not a declaredString envelope. Optional
   * in the loader; relay-bridge's cutover REFUSES a subject without one,
   * because a caller it cannot name is a caller it cannot confirm stopped.
   * Absent -> absent key, so a declaration without it hashes as before.
   */
  readonly unit?: string;
}

// ── GATE 1 · THE DECLARED M-FRAME (Stop 2) ────────────────────────────────
//
// Canon 03b §2: Gate 1 reads the WEIGHT distribution over a declared frame M.
// What this deployment can record is narrower and it is named here so nobody
// reads the frame as more than it is: the bridge derives, per TOOL_ATTEMPTED,
// which declared REGION the act's own claimed target falls in, and the reader
// counts those labels against M. That is REACH / EXPOSURE (03a §1), never
// weight, and the reader's weight leg is CANNOT_ASSESS by construction.
//
// ⛔ A CATEGORY IS NOT AN OWNER AND A REGION IS NOT OWNERSHIP (S160: owner ≠
//    who matters; attempted ≠ changed). `regions` is a declared PROXY mapping
//    path prefixes to categories. It can be wrong, and its `proxy` flag and
//    `basis` are where the deployer says how.
/**
 * One category of the declared frame M.
 *
 * ⚠ `grounding` IS A DECLARED TAG, NOT CANON'S OPERATIONAL GROUNDING (R-d,
 *   review C1-3). 03a §6 asks that M's categories GROUND OPERATIONALLY in
 *   substrate-independent trait-space and rejects ungrounded ones as ill-formed
 *   (closing F10, the hollow frame). The loader checks only that the deployer
 *   NAMED one of three trait words; it cannot check that the category grounds
 *   in it. A purely symbolic category tagged "need" loads. The tag is required,
 *   so an UNTAGGED category is refused — but F10 is NOT closed by this field.
 */
export interface FrameCategory {
  readonly id: string;
  readonly label: string;
  readonly grounding: "vulnerability" | "agency" | "need";
  /** EXACTLY ONE category is `self` — the FAIL floor is defined on it (and is not read: it needs weight). */
  readonly self: boolean;
}
/** A path prefix the bridge maps to a category when deriving a TOOL_ATTEMPTED's label. Segment-aware, longest wins. */
export interface FrameRegion {
  readonly prefix: string;
  readonly category: string;
}
export interface SubjectFrame {
  readonly categories: { readonly value: readonly FrameCategory[]; readonly basis: string; readonly proxy: boolean };
  /** MAY BE EMPTY: then nothing is derivable and every label is UNDERIVED — legal, and honest about it. */
  readonly regions: { readonly value: readonly FrameRegion[]; readonly basis: string; readonly proxy: boolean };
}

// ── GATE 2 · THE DECLARED BASKET (Stop 2) ───────────────────────────────────
//
// Canon (05a §0/§1, RMBA V/D): Gate 2 reads DIRECTION as V_basket − D_basket
// over DEPLOYER-DECLARED classes in the record, read as a conservative bound AT
// GRADE. The basket is the deployer's; the reader prints that ceiling on every
// verdict (a self-serving basket buys the read it declares, 05a:217).
//
// ⛔ THE CLASS KEY IS (subject, kind, outcome). The moduleId is NEVER declared:
//    the bridge sets it to the stanza's own key, by use, so a class cannot name
//    another subject's records.

/** A > B > C: measured, inferred, scenario (RMBA V/D lanes). */
export type Gate2Lane = "A" | "B" | "C";
/** EG-0 anecdote … EG-3 audit. */
export type Gate2Eg = 0 | 1 | 2 | 3;
/** A grade threshold: `establishAt` / `creditAt`. */
export interface DeclaredGate2Grade {
  readonly lane: Gate2Lane;
  readonly eg: Gate2Eg;
}
/** A value[] or damage[] entry: SIGNED, so weighted, with a causal coefficient and a stated falsifier. */
export interface DeclaredGate2SignedClass {
  readonly kind: string;
  /** null = any outcome of the kind. */
  readonly outcome: string | null;
  readonly weight: { readonly lo: number; readonly hi: number };
  readonly lane: Gate2Lane;
  readonly eg: Gate2Eg;
  readonly rhoCausal: number;
  readonly falsifiability: string;
  readonly bearsOn: readonly string[];
  readonly basis: string;
}
/** An unknown[] entry: NAMED, never weighted (RMBA V/D §6, UNKNOWN is not zero). */
export interface DeclaredGate2UnknownClass {
  readonly kind: string;
  readonly outcome: string | null;
  readonly lane: Gate2Lane;
  readonly eg: Gate2Eg;
  /** OPTIONAL sign-free magnitude bound. Absent: an unknown with records is UNBOUNDED. */
  readonly magnitude?: { readonly hi: number };
  readonly bearsOn: readonly string[];
  readonly basis: string;
}
export interface SubjectBasket {
  readonly classes: {
    readonly value: {
      readonly value: readonly DeclaredGate2SignedClass[];
      readonly damage: readonly DeclaredGate2SignedClass[];
      readonly unknown: readonly DeclaredGate2UnknownClass[];
    };
    readonly basis: string;
    readonly proxy: boolean;
  };
  readonly epsilonNum: DeclaredNumber;
  readonly grades: {
    readonly value: { readonly establishAt: DeclaredGate2Grade; readonly creditAt: DeclaredGate2Grade };
    readonly basis: string;
    readonly proxy: boolean;
  };
  readonly window: { readonly value: { readonly kind: "sinceBoundary" }; readonly basis: string; readonly proxy: boolean };
  readonly nMin: DeclaredNumber;
  readonly latchClearedBy: { readonly value: readonly { readonly kind: string }[]; readonly basis: string; readonly proxy: boolean };
}

// ── GATE 2 · THE HARM STANZA (Long Run A, Stop 2; contract B1) ──────────────
//
// The arbiter's question: did an act change a protected thing (an ITEM) without
// permission (a GRANT)? Keyed by subject beside `frame` and `baskets`; for the
// Gate-2 subject it REPLACES the class basket (H9). Origins are declared
// subjects (W-O, O1: the principal the bridge binds an act to, never the human
// or errand behind it); clearances are witness RECORD hashes under the doctor's
// hat (W-C, C1). Refusals H1–H10 are the loader's.
export interface DeclaredHarmOrigin {
  readonly subject: string;
  readonly basis: string;
}
export interface DeclaredHarmItem {
  /** ONE exact canonical absolute path (F-10); matched by the looked-at path's fingerprint (B-1). */
  readonly path: string;
  readonly category: string;
  /** true: the deployer measured that the subject cannot change it — it alarms only on another writer (F-9). */
  readonly control: boolean;
  readonly basis: string;
}
export interface DeclaredHarmGrant {
  /** Origin ids that may change the item. [] is a grant list: nobody. */
  readonly origins: readonly string[];
  /**
   * S216 · origin id -> the UTC instant (ISO, ...Z) FROM which that origin's grant counts. Exactly the origins
   * listed ([] has {}). A witness record earlier than its origin's since is harm whatever the grant now says.
   */
  readonly since: Readonly<Record<string, string>>;
  readonly basis: string;
}
/** S208-2 · the errand envelope: which frame categories an arbiter's errand may grant, and the longest window. */
export interface DeclaredHarmErrand {
  readonly categories: readonly string[];
  readonly maxWindowMinutes: number;
}
export interface DeclaredHarmClearance {
  /** The witness record's own `hash` field, 64 lower hex. */
  readonly record: string;
  readonly hat: "doctor";
  readonly basis: string;
}
export interface SubjectHarm {
  readonly harmOnly: { readonly value: true; readonly basis: string; readonly proxy: boolean };
  readonly origins: { readonly value: Readonly<Record<string, DeclaredHarmOrigin>>; readonly basis: string; readonly proxy: boolean };
  readonly items: { readonly value: Readonly<Record<string, DeclaredHarmItem>>; readonly basis: string; readonly proxy: boolean };
  readonly grants: { readonly value: Readonly<Record<string, DeclaredHarmGrant>>; readonly basis: string; readonly proxy: boolean };
  readonly clearances: { readonly value: readonly DeclaredHarmClearance[]; readonly basis: string; readonly proxy: boolean };
  /** S208-2 · OPTIONAL. Absent: no errand may grant anything (the writer refuses ERRAND_GRANTED). */
  readonly errand?: { readonly value: DeclaredHarmErrand; readonly basis: string; readonly proxy: boolean };
}

// ── GATE 2 · the kind sets the basket door reads ────────────────────────────
//
// ⛔ SPELT AS LITERALS, NOT IMPORTED, for the DOCTOR_ATTESTED reason in
//    validate() (readers.doctorCadence): mica-service imports THIS module, and
//    a value import back the other way is a runtime cycle. The suite holds each
//    list against mica-service's own export, and the subject-writable predicate
//    against `authorizeSubjectEventKind` BY BEHAVIOUR, so a kind added there and
//    not here fails a test rather than loading a basket the route would refuse.

const GATE2_SUNSET_KINDS_T = [
  "ENDING_PAPER_AUTHORIZATION",
  "ENDING_PAPER_TIMEBOX",
  "ENDING_PAPER_EXIT_CRITERIA",
  "ENDING_PAPER_ACCOUNTABLE_OWNER",
  "ENDING_PAPER_SUCCESSOR",
  "ENDING_ORDERED",
  "ARBITER_RESOLVED",
  "SUNSET_HELD",
  "SUNSET_ESCALATED",
  "SUNSET_COMPLIED",
  "ORDER_PRESENTED",
] as const;
/** Mirror of mica-service's SUNSET_KINDS. R5 refuses every one of them in a class list (F3; 04c:107-113). */
export const GATE2_SUNSET_KINDS: readonly string[] = GATE2_SUNSET_KINDS_T;
/**
 * TIER 1 · THE WITNESS'S RECORD KIND, as a basket declares it. The bridge maps it
 * to the book's record class CONSEQUENCE@<16 hex> (to-wire-options), named from
 * the declared witnessMethod and the frame's derivation class.
 */
export const GATE2_WITNESS_KIND = "CONSEQUENCE";
/**
 * R17 · PHASE R ON THE WITNESS'S BOOK: every class a basket declares on the book
 * is an UNKNOWN — named, never signed — and value[] and damage[] are REFUSED
 * there (refuters A-F5, C MAJOR-1). A damage class on the book would latch an
 * ALARM that nothing in the book can clear (the declared clearer never occurs
 * there). ⛔ THIS ONE CONSTANT holds the rule, R8's pattern; it flips only when
 * every precondition the board tied to "the day a D class at grade can exist"
 * has landed: T31 (the harm-only rule), S206 (the subject-postable kinds — the
 * act stream and the anchor's fate records are such kinds; 19:51Z ④, 20:01Z (1)),
 * S208 (the errand's grant), T32 (Gate 2's
 * ceiling lines 2 and 6 made true on the book), F5 (a clearer that occurs IN the
 * book), the persisted latch, F9 (consequence-masking), S209 (the co-operator's
 * surface). The T31 draft's condition 0 lists the same six.
 */
export const GATE2_WITNESS_BOOK_SIGNED_REFUSED: boolean = true;
/**
 * The witness's closed FACET vocabulary — a SECOND COPY of the seeing method's
 * (mica-machine src/witness/seeing.ts EFFECT_CLASSES), phase R = sight-since-last-look
 * (audit 2026-10-11 09:32Z). The bridge does not import the machine's modules;
 * the two copies are pinned by fixtures on each side.
 */
export const GATE2_WITNESS_EFFECT_CLASSES: readonly string[] = [
  "FIRST_SEEN",
  "SAME",
  "EXISTENCE_DIFFERS",
  "TYPE_DIFFERS",
  "CONTENT_DIFFERS",
  "META_DIFFERS",
  "UNOBSERVABLE",
  "HELD",
  "LATE",
];
/**
 * R18 · the three EVIDENCE-FREE facets (seeing.ts EVIDENCE_FREE_CLASSES, a second
 * copy pinned by fixtures): FIRST_SEEN (no last look to compare), UNOBSERVABLE
 * (could not see or could not confirm), LATE (the act's fate is unknown). Refused
 * outside unknown[] on the book, constant or not — whatever R17 becomes, no
 * evidence of change is never a sign.
 */
export const GATE2_WITNESS_EVIDENCE_FREE_CLASSES: readonly string[] = ["FIRST_SEEN", "UNOBSERVABLE", "LATE"];

/** Mirror of mica-service's SUBJECT_EVENT_KINDS. R3: a class names a kind the subject chain carries, or nothing. */
export const GATE2_KNOWN_KINDS: readonly string[] = [
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
  ...GATE2_SUNSET_KINDS_T,
];
/**
 * The kinds only the OPERATOR may POST: `DOCTOR_ATTESTED` and mica-service's
 * OPERATOR_SUNSET_KINDS — exactly `authorizeSubjectEventKind`'s `operatorOnly`.
 * Every OTHER known kind is one the subject's own uid may POST.
 */
export const GATE2_OPERATOR_ONLY_KINDS: readonly string[] = [
  "DOCTOR_ATTESTED",
  "ENDING_PAPER_AUTHORIZATION",
  "ENDING_PAPER_TIMEBOX",
  "ENDING_PAPER_EXIT_CRITERIA",
  "ENDING_PAPER_ACCOUNTABLE_OWNER",
  "ENDING_PAPER_SUCCESSOR",
  "ENDING_ORDERED",
  "ARBITER_RESOLVED",
  // S208-2 · the arbiter's errand kinds (operator-only until S217's arbiter route).
  "ERRAND_GRANTED",
  "ERRAND_CLOSED",
];
/**
 * F4 (08a:73-75) · the kinds that are MICA's own output, bookkeeping, or a
 * second party's record — never a basket class (R6). THIS LIST'S MEMBERSHIP IS
 * F4's: the five named kinds plus every operator kind. A class over MICA's own
 * hold, the act's bookkeeping close, the answer to an ask or a doctor's word
 * would read the governance around the subject as the subject's direction.
 */
export const GATE2_F4_REFUSED_KINDS: readonly string[] = [
  "TOOL_HELD_NOT_EXECUTED",
  "TOOL_EXECUTED",
  "ACT_CLOSED",
  "ASK_ANSWERED",
  ...GATE2_OPERATOR_ONLY_KINDS,
];
/** R4: an EXIT-shaped departure after a hold (STOPPED above all) is never VALUE (audit 19:51Z ③; 05b:216-220). */
export const GATE2_HELD_THEN_PREFIX = "HELD_THEN_";
/**
 * The subject-writable predicate (R7, R8, R11): a known kind the subject's own
 * uid may POST — i.e. not DOCTOR_ATTESTED and not an operator sunset kind. On
 * this record such a kind is EG-1 at most: the bridge writes, chains and
 * verifies it, and the clerk vouches for its ARRIVAL only (S206).
 */
export function isGate2SubjectWritableKind(kind: string): boolean {
  return GATE2_KNOWN_KINDS.includes(kind) && !GATE2_OPERATOR_ONLY_KINDS.includes(kind);
}
/**
 * R8 · "no damage class at EG-1 until S206" (audit 19:51Z ④). While true, a
 * damage[] entry on a subject-writable kind is REFUSED. ⛔ S206's TICKET FLIPS
 * THIS ONE CONSTANT, and the R8 test arm reads it; nothing else in the tree
 * holds the rule.
 * ⚠ S206 IS NOT THE UNLOCK (K2-adversary, 2026-10-10): flipping this alone does
 * not let Gate 2 alarm. The reader credits value only at ≥ creditAt, and R7 caps
 * every subject-writable kind at EG-1, so at a creditAt of EG-2 no admissible
 * value class is credited and every reading stays G2_VALUE_NOT_READABLE (D alone
 * cannot alarm, the audit 20:01Z). The exit is a value kind at EG ≥ 2 — a
 * record "co-signed by an independent party or reproduced by shared method" (the
 * 05:45Z sentence as AMENDED 16:36Z ①; fork C). Flipping this ALSO re-admits
 * self-report damage (the audit 20:01Z (1): D proxies are derived at the bridge).
 */
export const GATE2_SUBJECT_WRITABLE_DAMAGE_REFUSED: boolean = true;
/**
 * R11 · ruling F5 (audit 2026-10-09 19:51Z): "the latch is cleared only by the
 * arbiter's record". On this chain that record is ARBITER_RESOLVED — and only it:
 * DOCTOR_ATTESTED is the doctor's (a second party), the ENDING_* kinds are Gate 4's
 * papers and orders. ⚠ ARBITER_RESOLVED is ALSO Gate 4's resolution of an ending
 * order (it can be appended only against an OPEN ENDING_ORDERED), so the arbiter has
 * no Gate-2-scoped clearing act and any Gate-4 resolution clears a Gate-2 latch — a
 * fork for the arbiter (a Gate-2 kind is fork C's to design), stated, not repaired.
 */
export const GATE2_ARBITER_CLEARING_KINDS: readonly string[] = ["ARBITER_RESOLVED"];

export interface Declarations {
  readonly schemaVersion: 1;
  readonly readers: {
    readonly readableLoadStates: DeclaredStringList;
    readonly logPath: DeclaredString;
    readonly logKind: DeclaredLogKind;
    readonly eng: {
      readonly structureThreshold: DeclaredNumber;
      readonly minimumSampleSize: DeclaredNumber;
      /**
       * T11 · the observed-class coverage floor: at least k distinct observed
       * (moduleId, eventType) classes must EACH carry at least k events.
       *
       * ⛔ OPTIONAL AT THIS DOOR, ON PURPOSE, AND IT IS NOT A CONVENIENCE. The
       *    sensor holds NO DEFAULT and returns MISSING_CONFIGURATION without it
       *    — T11's own condition: "until readers.eng.minimumClassCoverage is
       *    declared, Eng returns MISSING_CONFIGURATION, which is the honest
       *    state and not a regression." Requiring it here would turn that honest
       *    blind reading into a REFUSED DECLARATION, and the deployment would
       *    lose every other reader to enforce one field. The absence is
       *    disclosed by the sensor, which is where a reader looks for it.
       */
      readonly minimumClassCoverage?: DeclaredNumber;
    };
    readonly sig: {
      readonly clockToleranceMs: DeclaredNumber;
      readonly clockToleranceBasis: DeclaredString;
      /** C9 · F2's POSITIVE leg. Closes a blind path; not a live detector — see the basis. */
      readonly preconditionMap: DeclaredEventMap;
      /** C9 · F2's NEGATIVE leg. The one signal on this log that can alarm — see the basis. */
      readonly reentryMap: DeclaredEventMap;
      /**
       * ACT B · the declared LAG between a record's arrival and the clerk's stamp
       * on it. OPTIONAL. The arbiter's fork 4, ruled 2026-09-22: the clerk carriage is
       * ASYNCHRONOUS, and an asynchronous stamp is honest only if the lag is
       * stated. `{value: "<=24h", basis: "reuses mica-clerk-caller.timer at
       * 00:00; F3 reads order, not wall time", proxy: true}`.
       *
       * ⚠ THIS FIELD IS A DISCLOSURE, NOT A WIRE. It reaches NO instrument.
       * `SigConfig` has no lag member and `toWireOptions` does not carry it;
       * declaring it changes what an operator READS and what `declarationHash`
       * COVERS, and changes no reading F3 performs. That is deliberate — F3
       * compares ORDERS, not wall clocks, so a lag cannot corrupt its verdict;
       * what a lag can do is make a promoted F3 mean less than a reader assumes,
       * and the cure for that is the sentence, not a threshold. Anyone who later
       * wants the lag ENFORCED must build the enforcement, not point at this.
       */
      readonly clerkStampLag?: DeclaredString;
    };
    /**
     * THE THREE NARROWING READERS' BLOCKS — narrow-K, narrow-W, narrow-R.
     * OPTIONAL AND INERT WHEN ABSENT, the item-4 pattern: presence IS the wiring
     * switch in mica-machine's `wire.ts`, and an absent block leaves the reader a
     * printed vacancy that composes nothing into the floor.
     *
     * ONE SHAPE FOR ALL THREE, because the three instruments take one shape:
     * `NarrowKConfig`, `NarrowWConfig` and `NarrowRConfig` differ in exactly one
     * field name (`correlationMinimum{Constraint,Inquiry,Verification}Events`)
     * and in nothing else. That field is therefore the ONLY per-reader member
     * here, and it is named per reader rather than flattened to a shared word:
     * the vocabulary follows the factor, which is the same call narrow-K's own
     * source records making.
     *
     * ── WHY THIS BLOCK EXISTS AT ALL, and it is a finding, not housekeeping ──
     *
     * `checkNoUnknown(readersRaw, [...])` in `validate()` REFUSES any key it does
     * not name. Before this change it named five, and `narrowK` was not among
     * them — so although `wire.ts:1080` has gated narrow-K on
     * `options.narrowK` since item 4 landed, **a declaration carrying
     * `readers.narrowK` would have been REJECTED AT LOAD**, and the service would
     * have kept its last known good declaration instead. narrow-K was not "live
     * and inert"; it was unreachable from the front door. Read at bytes
     * 2026-09-24.
     *
     * ── DECLARING ONE IS A DEPLOYMENT DECISION WITH A LATCH ON IT ────────────
     *
     * Leg 1 of each of these three ALARMS on a declared class that is ABSENT
     * from the record, and there is NO minimum-sample grace on leg 1 —
     * `correlationMinimum*Events` guards leg 2 only. An ALARM floor maps to HOLD
     * at every stakes class (`chokepoint/types.ts:239-241`), and the pilot's
     * pass-blind override lives in the CANNOT_ASSESS branch alone, so it cannot
     * rescue it. **DECLARING A PROFILE WHOSE CLASSES NO CALLER YET EMITS HOLDS
     * EVERY ACT.** The declaration must follow the caller that writes the
     * classes, never precede it — the bridge-before-caller brick, pointed the
     * other way.
     *
     * As of this build the caller writes `HELD_THEN_DIVERGED` (narrow-K's
     * candidate class) and writes NO class for narrow-W's inquiry factor or
     * narrow-R's verification factor. Those two blocks are therefore VALIDATED
     * HERE AND MUST NOT BE DECLARED. This validator deliberately does not, and
     * cannot, enforce that: it would have to know what the caller writes.
     */
    readonly narrowK?: DeclaredNarrowingProfile & {
      readonly correlationMinimumConstraintEvents?: DeclaredNumber;
    };
    readonly narrowW?: DeclaredNarrowingProfile & {
      readonly correlationMinimumInquiryEvents?: DeclaredNumber;
    };
    readonly narrowR?: DeclaredNarrowingProfile & {
      readonly correlationMinimumVerificationEvents?: DeclaredNumber;
    };
    /**
     * narrow-T · the FIFTH Eng-sibling. OPTIONAL. It does NOT share the shape of
     * the three above, and the difference is the point of this comment.
     *
     * ── IT CARRIES NO `declaredProfile`, SO IT CARRIES NO LATCH ──────────────
     *
     * narrow-K/W/R each ALARM on a declared class that is ABSENT from the record,
     * with no minimum-sample grace on leg 1 — which is why declaring one before
     * the caller writes its classes holds every act. narrow-T has no declared
     * class at all: it reads the AMI between the EARLY and LATE windows of ONE
     * record's arc. Absent or unusable configuration reads CANNOT_ASSESS
     * (MISSING_CONFIGURATION), never ALARM. It is the safe one of the four to
     * declare, and it is the only one whose ordering hazard is not the caller's.
     *
     * ⚠ NOTE THE POLARITY, because it is inverted and a reader of this block will
     * otherwise calibrate it backwards: `ami > driftTolerance` is the ALARM.
     * Every sibling alarms on a LOW score; here structure IS the drift, and
     * flatness is health.
     *
     * ── ⛔ AND IT REACHES NO READER TODAY. READ THIS BEFORE DECLARING IT. ─────
     *
     * `src/glue/wire.ts` on the production line (`~/mica-wt/bundle`, f5b45c9)
     * has NO `options.narrowT` gate and never calls `assessNarrowT`; neither does
     * `phase-a-wire-narrowt` (8b50a60). Read at bytes 2026-09-25. So this block
     * makes a declaration that carries `readers.narrowT` LOAD — which it did not
     * before, and which is the whole reason the field exists — and it does NOT
     * make narrow-T read. That is narrow-K's 2026-09-24 finding pointed the other
     * way: there the door refused a wired reader, here the door admits an unwired
     * one. Turning narrow-T ON is a MACHINE-side build. `[owed -> board]`
     *
     * The field names mirror `NarrowTConfig` exactly (src/mica/narrow-t/index.ts)
     * so that the day the wiring lands, `unwrapDeclared` is the whole adapter.
     */
    readonly narrowT?: {
      /** REQUIRED once the block exists. AMI ABOVE this is the alarm — inverted. */
      readonly driftTolerance: DeclaredNumber;
      /** REQUIRED once the block exists. Minimum records in EACH window; non-negative integer. */
      readonly minimumEventsPerWindow: DeclaredNumber;
      /** OPTIONAL. Fixed window size taken from EACH end; absent -> structural halves. */
      readonly temporalWindowSize?: DeclaredNumber;
      /** OPTIONAL. Distance below AMI_MAXIMUM counting as AT THE CEILING -> CANNOT_ASSESS. Absent -> the check DOES NOT RUN. */
      readonly driftCeilingMargin?: DeclaredNumber;
      /** OPTIONAL, report-only. Requires driftPermutationSeed alongside it. */
      readonly driftPermutationSamples?: DeclaredNumber;
      /** OPTIONAL, report-only. Requires driftPermutationSamples alongside it. */
      readonly driftPermutationSeed?: DeclaredNumber;
    };
    /**
     * §2b · OP-1's `doctorCadence` section, OPTIONAL AND INERT WHEN ABSENT.
     * Same item-4 pattern as the three above.
     *
     * DECLARING IT BEFORE THE FIRST ATTESTATION LANDS IS THE SAME LATCH: op1's
     * presence mode reads a declared `attestationClass` that never occurs, and
     * an alarm holds under both stakes lines. The order is: bridge, then the
     * `tools/doctor-attest` deposit by the arbiter's own hand, THEN this block.
     */
    readonly doctorCadence?: {
      readonly attestationClass: DeclaredEventClass;
      readonly cadenceBoundSteps?: DeclaredNumber;
    };
    /**
     * H12 · OP-3's `nodeResponse` section, OPTIONAL AND INERT WHEN ABSENT.
     *
     * PRESENCE IS THE WIRING SWITCH (mica-machine `wire.ts`, `WireOptions.op3`,
     * the item-4 pattern). Absent, `toWireOptions` emits no `op3` field, `wire()`
     * reports OP-3 as a stated vacancy, and the composed sensor list is
     * byte-identical to what it was before this field existed.
     *
     * DECLARING IT IS A DEPLOYMENT DECISION WITH A LATCH ON IT, and the latch is
     * named here rather than only in the receipt: this caller writes
     * TOOL_ATTEMPTED -> TOOL_EXECUTED -> TOOL_RESULT for an act that ran and
     * TOOL_ATTEMPTED -> TOOL_HELD_NOT_EXECUTED for an act that was HELD — no
     * TOOL_RESULT on the held path, ever — and `responseClass` has room for one
     * class. So with `responseClass = TOOL_RESULT` the first held act raises
     * OP3_CALL_UNANSWERED, an ALARM floor holds at every stakes class, and the
     * finding is recomputed over the whole file on every evaluation. Widening
     * `responseBoundSteps` to hide it pairs the attempt to ANOTHER act's result.
     *
     * ── WHAT THE MERGE WITH THE BUNDLE LINE CHANGES ABOUT THAT PARAGRAPH ────
     *
     * The paragraph above was written on the `opa` line against a caller that
     * wrote SEVEN kinds. This line adds `ACT_CLOSED`, written as the LAST record
     * of EVERY act on BOTH paths — which is precisely the single class that can
     * sit in `responseClass` and cover the held path too. The latch is therefore
     * not removed but RE-AIMED: with `responseClass = TOOL_RESULT` it is exactly
     * as described and still holds every act from the first held act; with
     * `responseClass = ACT_CLOSED` it is honest on both paths, and the remaining
     * exposure is the act that DIED before writing its terminal record, which is
     * the truncation signature op3 is supposed to see. Which of the two is
     * declared is the arbiter's call and it is not made here. `[owed → the arbiter]`
     */
    /**
     * ── §2d · GATE 4 SUNSET, T26 ──────────────────────────────────────────────
     *
     * OPTIONAL and inert when absent: `wire.ts` pushes an UNWIRED census row and
     * the declaration hashes as it did before this field existed.
     *
     * ⛔ EVERY LIST IS REQUIRED, WHICH IS STRICTER THAN THE INSTRUMENT, ON PURPOSE.
     *    The reader treats a missing role or paper class as VACUOUS and goes blind.
     *    So a half-declared profile would LOAD, WIRE, and read CANNOT_ASSESS for
     *    ever while `/status` reported gate 4 as declared — a reader that is
     *    present in the census and absent from every reading. Refusing it HERE
     *    makes that a loud failure at the moment of declaring instead of a quiet
     *    one at every later read. It is the `declaredEventMap` rule (an empty map
     *    reads as an absent one, so refuse it loudly) applied to eleven lists.
     *
     * ⚠ AND NO WINDOW. T26 derives leg A's window from the record. The
     *   predecessor took it as a declared field, and the value a receipt-reader
     *   copied was `relay-sunset.ts`'s open-ended `startSeq = orderSeq + 1`,
     *   which put every later record in-window for ever. If a `holdWindow` key
     *   ever appears here, that whole class of defect has come back.
     */
    /**
     * ── §2d · GATE 4 SUNSET (T26 / R1) ────────────────────────────────────────
     *
     * OPTIONAL and inert when absent: `wire.ts` pushes an UNWIRED census row and
     * the declaration hashes as it did before this field existed.
     *
     * ⛔ NO CLASS LISTS. This block says the reader is ON and for which SUBJECT;
     *    `to-wire-options` builds the instrument's profile from mica-service's
     *    own sunset-kind constants and that subject's id. Four refusals of the
     *    reader came from one degree of freedom — class lists typed by a deployer
     *    for kinds THIS REPOSITORY names. Swapped outcome words, two roles naming
     *    one class, a vacuous `resolved: []` that stopped any order ever closing,
     *    a misdeclared moduleId reading as a missing paper: ONE FAMILY.
     *    A PROFILE NOBODY TYPES CANNOT BE MISTYPED.
     */
    readonly gate4Sunset?: {
      /** The declared subject whose endings this reader reads. The only id here. */
      readonly subject: DeclaredString;
      /** OPTIONAL K on the SEQUENCE axis. Absent -> order-only, louder ceiling. */
      readonly paperFreshnessBound?: DeclaredNumber;
    };
    /**
     * ── GATE 1 · SCOPE, THE ENVELOPE RECORDER (Stop 2) ───────────────────────
     *
     * OPTIONAL and inert when absent, the gate4Sunset (R1) pattern: this block
     * says the reader is ON and for which SUBJECT, and nothing else. The frame it
     * reads is `frame[subject]` at the top level, which must exist (refused at
     * load otherwise) — a reader switched on over no frame would read
     * CANNOT_ASSESS(G1_FRAME_ABSENT) for ever while the census listed it declared.
     *
     * ⚠ THE READER NEVER RETURNS ALARM, AND THAT IS NOT THE SAME AS "HARMLESS TO
     *   DECLARE". Wired, it composes a permanent CANNOT_ASSESS into the floor —
     *   the truth that Gate 1's property (weight) is unread — and what a blind
     *   reading does to a decision is the stakes line's to say, not this block's.
     *   Declaring it is the arbiter's act, like every other reader block here.
     */
    readonly gate1Scope?: {
      readonly subject: DeclaredString;
    };
    /**
     * ── GATE 2 · DIRECTION (Stop 2) ──────────────────────────────────────────
     *
     * OPTIONAL and inert when absent, the gate1Scope pattern: this block says
     * the reader is ON and for which SUBJECT, and nothing else. What it reads is
     * the deployer's BASKET at top-level `baskets[subject]`, over the categories
     * of `frame[subject]` — both must exist (refusal R1) or the reader would
     * read CANNOT_ASSESS for ever while the census listed it declared.
     *
     * ⚠ THE READER ADDS NO RECORD KIND AND THE BRIDGE WRITES NOTHING NEW FOR
     *   IT. It reads the subject chain the other readers read; the basket says
     *   which classes of that chain the deployer declares as value, damage or
     *   UNKNOWN. A basket that declares no class AT GRADE reads CANNOT_ASSESS
     *   (G2_NO_CLASS_AT_GRADE), which is fork A's reading on this record.
     */
    readonly gate2Direction?: {
      readonly subject: DeclaredString;
      /**
       * TIER 1 · WHICH BOOK GATE 2 READS. Absent: the subject log, exactly as
       * before this field existed. "witnessBook": the WITNESS'S BOOK OF EFFECTS
       * (`paths.witnessBook`), written by the witness's seeing half. Declared
       * with `witnessMethod` or not at all.
       */
      readonly book?: { readonly value: "witnessBook"; readonly basis: string; readonly proxy: boolean };
      /**
       * THE METHOD DESIGNATION, keyed on the METHOD and never on a bare uid
       * (audit 16:36Z (3)③): the sha256 of the seeing method the witness runs
       * (seeing.ts SEEING_METHOD_DIGEST). The bridge names Gate 2's record class
       * from it (CONSEQUENCE@…); a witness running another method writes another
       * class, which this basket then does not count — visibly, never silently
       * re-labelled.
       */
      readonly witnessMethod?: { readonly value: string; readonly basis: string; readonly proxy: boolean };
    };
    readonly nodeResponse?: {
      readonly expectationClass: DeclaredEventClass;
      readonly responseClass: DeclaredEventClass;
      readonly responseBoundSteps: DeclaredNumber;
      /**
       * OP-3'S FIRST PAIRABLE SEQUENCE. Optional; absent means "pair over the
       * whole readable log", which is what op3 did before this field existed.
       *
       * ⛔ IT IS A FACT ABOUT THIS RECORD, NOT A LOOSENING OF THE INSTRUMENT.
       * `ACT_CLOSED` did not exist as a subject-event kind until the caller
       * relay of 2026-09-25; the first one ever written is sequence 213. op3
       * pairs each expectation against a later response, so over the whole log
       * every `TOOL_ATTEMPTED` before 213 reads as an unanswered call —
       * measured 2026-09-26 against 188 real records: 65 findings, the first at
       * sequence 1. Those calls were not unanswered; the class that answers
       * them did not exist yet.
       *
       * ⚠ WHAT IT COSTS, AND THE COST IS DECLARED RATHER THAN HIDDEN: conduct
       * before `since` is NOT READ BY op3 AT ALL. The glue prints the skipped
       * count on the reader's own face (`op3WindowNote`), so a window can be
       * seen from `/status` and is never only in this file. It does not narrow
       * the chain check — `verify()` still runs over the whole log.
       *
       * ⚠ AND IT IS NOT A SUBSTITUTE FOR A BOUNDARY IN THE RECORD. The honest
       * end state is a subject log that carries its own boundary event; until
       * then this is a declared blind spot with a number the deployer must
       * justify in its basis.
       */
      readonly since?: DeclaredNumber;
      readonly flatness?: {
        readonly amiFloor: DeclaredNumber;
        readonly amiCeilingMargin: DeclaredNumber;
        readonly minSample: DeclaredNumber;
      };
    };
  };
  readonly stakes: {
    readonly lineClasses: readonly string[];
    readonly baseline: { readonly holdAtOrAbove: DeclaredString };
  };
  readonly subjects: readonly Subject[];
  /**
   * GATE 1 · the declared M-frame per subject, keyed by `subjects[].subject`.
   * OPTIONAL: absent, the key is ABSENT from the loaded object, the declaration
   * hashes as it did before the field existed, and the bridge writes no label.
   * Declared or not, TOOL_ATTEMPTED's own outcome on the subject chain is the
   * toolName (round 2, placement D): the label goes to the interest book
   * (`paths.interestBook`). Nothing in this code but Gate 1 reads the book;
   * X23 keeps readers.logPath off it, and nothing else enforces it.
   *
   * ⛔ WIDEN-ONLY ACROSS A RELOAD (validateActivation, X21): a framed subject may
   *    not lose its frame and a category may not leave M. That is the brief's
   *    deployment rule (§2), not a canon placement: canon takes M from the
   *    doctor / Gate-0 (03a §6), and no ruled mechanism for narrowing it exists.
   */
  readonly frame?: Readonly<Record<string, SubjectFrame>>;
  /**
   * GATE 2 · the deployer-declared basket per subject, keyed by
   * `subjects[].subject` (contract §4). OPTIONAL: absent, the key is ABSENT from
   * the loaded object and the declaration hashes as it did before the field
   * existed. Every refusal R1–R15 is the loader's; R15 holds it across a reload
   * (validateActivation): a damage or unknown entry may not be dropped.
   */
  readonly baskets?: Readonly<Record<string, SubjectBasket>>;
  /**
   * GATE 2 · Long Run A Stop 2 · the deployer-declared HARM stanza per subject
   * (items, origins, grants, clearances). OPTIONAL: absent, the key is ABSENT
   * and the declaration hashes as before the field existed. H1–H10 are the
   * loader's. For the Gate-2 subject it replaces `baskets[subject]` (H9).
   */
  readonly harm?: Readonly<Record<string, SubjectHarm>>;
  readonly routes: readonly Route[];
  readonly pilot: PilotDeclared;
  readonly notice: {
    readonly window: DeclaredNumber;
    readonly maxPerMinute: DeclaredNumber;
  };
  /** AMENDMENT 9 / RULING Q — governs POST /subject-events' 503 backlog threshold. */
  readonly subjectLog: {
    readonly maxUnacknowledged: DeclaredNumber;
    /**
     * ACT A / the arbiter's ruling 3. What the chain's position-0 boundary record
     * says it replaced. `retiredPath.value === ""` is FIRST BOOT — a different
     * fact from a rotation, carried in a value and never in an absent field.
     */
    readonly chainBoundary: {
      readonly retiredPath: DeclaredString;
      readonly retiredRecords: DeclaredNumber;
      readonly retiredBytes: DeclaredNumber;
      readonly retiredSha256: DeclaredString;
    };
  };
  readonly paths: {
    readonly journal: string;
    readonly eventBook: string;
    readonly subjectLog: string;
    readonly decisionEvents: string;
    readonly floorTrail: string;
    readonly ledger: string;
    readonly history: string;
    readonly noticeDir: string;
    /**
     * ACT B · where the clerk carrier writes its arrival stamps, for Sig's F3.
     *
     * ⛔ THE ONE KEY IN THIS BLOCK THAT CARRIES A BASIS, AND THE ASYMMETRY IS THE
     * POINT (the arbiter, 2026-09-28). The other eight are files THIS bridge owns and
     * writes; they need no justification because the deployment IS their
     * justification. This one is an INPUT FROM ANOTHER PRINCIPAL — the clerk
     * carrier, uid `mica`, writing into the machine's own directory — and a
     * reader's evidence arriving from outside is exactly the thing that has to
     * say why it is trusted.
     *
     * OPTIONAL, and absent is today's behaviour: no path, no `clerkClockSource`,
     * F3 NOT_CONFIGURED and disclosed. The STAMPS are never declarable; the PATH
     * and its basis are.
     */
    readonly clerkStamps?: {
      readonly value: string;
      readonly basis: string;
    };
    /**
     * GATE 1 · Stop 2 · round 2 (placement D): the INTEREST BOOK — a chained
     * file the bridge writes, one label record per persisted TOOL_ATTEMPTED of a
     * framed subject. Nothing in this code but Gate 1 reads it; X23 refuses a
     * readers.logPath naming it. A file THIS bridge owns and writes, held by its
     * OWN pattern (round 3, A4): ONE FLAT `*.jsonl` FILE DIRECTLY IN
     * /var/lib/mica-bridge/ — no sub-directory, no "." or ".." name, so never a
     * `.lock`/`.quarantine` sibling, the salt file or the state dir itself —
     * distinct from every other path (X7), not another path's lock or
     * quarantine sibling, and not the retired chain file. OPTIONAL; REQUIRED when
     * `frame` or `readers.gate1Scope` is declared (X22). Opened ONLY AT START, so
     * a reload that adds, moves or removes it is refused (validateActivation).
     * Absent -> absent key, so a declaration without it hashes as before.
     */
    readonly interestBook?: string;
    /**
     * TIER 1 · THE WITNESS'S INTAKE — a directory the WITNESS owns (its seeing
     * half, its own uid) that only the bridge's group may write: the bridge drops
     * one ATTEMPT pointer (with the plain canonical target — "the plain target to
     * the witness only", audit 18:03Z (4)) and one CLOSE pointer per framed act
     * there. ANOTHER PRINCIPAL'S directory, so an envelope with a basis, under
     * /var/lib/mica/ only. OPTIONAL: absent, the bridge drops nothing. Read PER
     * ACT from the declaration in force — unlike the interest book, nothing opens
     * it at start — so a reload may add, move or remove it (no W5 rule): a moved
     * intake the witness's unit does not sweep shows as a coverage gap.
     */
    readonly witnessIntake?: { readonly value: string; readonly basis: string };
    /**
     * TIER 1 · THE WITNESS'S BOOK OF EFFECTS — a chained file the witness writes
     * and every role reads. Gate 2 reads it only when readers.gate2Direction.book
     * says so. An envelope with a basis, under /var/lib/mica/ only, a .jsonl
     * file, never inside the intake, never readers.logPath (X23's twin).
     */
    readonly witnessBook?: { readonly value: string; readonly basis: string };
  };
}

/** A load rejection, naming the FIRST offending field path and why. */
export class DeclarationRejected extends Error {
  readonly field: string;
  constructor(field: string, reason: string) {
    super(`DECLARATION_REJECTED ${field}: ${reason}`);
    this.name = "DeclarationRejected";
    this.field = field;
  }
}

/** Pilot state as actually in force, per design §A.2 rule X8 / Stage 0. */
export type PilotState =
  | { readonly state: "INACTIVE" }
  | { readonly state: "ACTIVE"; readonly sessionId: string; readonly expiresAt: string; readonly holdAtOrAbove: string }
  | { readonly state: "EXPIRED"; readonly sessionId: string; readonly expiresAt: string };

export interface LoadedDeclarations {
  readonly declarations: Declarations;
  readonly declarationHash: string;
  readonly pilotState: PilotState;
}

// ── isUsableLine, reimplemented exactly ──────────────────────────────────
//
// [verified] src/mica/chokepoint/types.ts:186-195 — a StakesLine is usable
// iff: classes is a non-empty array of non-empty strings, and
// classes.includes(holdAtOrAbove). This file reimplements that one
// predicate, not the whole chokepoint, and cites the source line it mirrors
// at every call site (rules X1 and X3 below).
function isUsableLine(classes: readonly string[], holdAtOrAbove: string): boolean {
  if (!Array.isArray(classes) || classes.length === 0) return false;
  if (classes.some((c) => typeof c !== "string" || c.length === 0)) return false;
  return classes.includes(holdAtOrAbove);
}

// ── small validation helpers ──────────────────────────────────────────────

function fail(field: string, reason: string): never {
  throw new DeclarationRejected(field, reason);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function requireObject(v: unknown, field: string): Record<string, unknown> {
  if (!isPlainObject(v)) fail(field, "must be a JSON object");
  return v as Record<string, unknown>;
}

function checkNoUnknown(obj: Record<string, unknown>, allowed: readonly string[], field: string): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) {
      fail(`${field}.${key}`, `unknown field; accepted here: ${allowed.join(", ")}`);
    }
  }
}

function requireField(obj: Record<string, unknown>, key: string, field: string): unknown {
  if (!(key in obj) || obj[key] === undefined) {
    fail(field, `required field missing`);
  }
  return obj[key];
}

const IDENT_PATTERN = /^[A-Za-z0-9_.:-]+$/;

/**
 * R-a (reviews C4-1, C4-3, C6-3). A subject id becomes an OBJECT KEY in `frame`,
 * and canonical-json rebuilds every object with `out[k] = …`. For k ===
 * "__proto__" that assignment runs Object.prototype's setter: it REPLACES THE
 * PROTOTYPE and defines no key, so the whole value drops out of the canonical
 * text and out of declarationHash, while mica-service (Object.hasOwn) still
 * finds it and labels from it. A digest that cannot tell two frames apart binds
 * no decision to either. Refused here and in the schema (a negative lookahead),
 * as a subject id and as a frame key. canonical-json is NOT changed: its output
 * is what every sealed hash was computed with.
 * ⚠ Only this one name is a setter on Object.prototype; `constructor`,
 *   `toString` and `hasOwnProperty` define ordinary keys (measured, C4-3/C6-3).
 */
const PROTO_KEY = "__proto__";
const PROTO_KEY_REASON =
  'must not be "__proto__": canonical-json (canonical-json.ts, canonicalizeValue) rebuilds objects ' +
  "with `out[k] = …`, which for this one name sets the prototype instead of a key, so anything keyed " +
  "by it falls outside declarationHash while the bridge still reads it";

/**
 * ROUND 3 (A6, reviews K3D2-7, K3D3-6, K3D1-7). R-a closed "__proto__" for the
 * two places a SUBJECT ID becomes a key. It is reachable wherever a declaration
 * carries a user-keyed map — readers.sig.preconditionMap and reentryMap kept an
 * own "__proto__" entry, passed it to Sig, and two declarations differing only
 * in that entry hashed alike. So the rule is now GENERAL: ONE WALK over the raw
 * parsed value, BEFORE ANY OTHER RULE, refusing an OWN "__proto__" key at any
 * depth, named by its field path. JSON.parse defines such a key as an own
 * property, which is exactly how it arrives from a served file.
 * ⛔ ITERATIVE, NOT RECURSIVE: a declaration nested deeper than the stack must
 *    be refused or loaded, never throw a RangeError out of the front door.
 * ⚠ A "__proto__" VALUE (a subject id spelt so) is not a key; the subject rule
 *   below still refuses it by name.
 */
function refuseProtoKeysAnywhere(raw: unknown): void {
  const stack: Array<[unknown, string]> = [[raw, ""]];
  const seen = new Set<object>();
  while (stack.length > 0) {
    const [v, at] = stack.pop()!;
    if (typeof v !== "object" || v === null || seen.has(v)) continue;
    seen.add(v);
    if (Array.isArray(v)) {
      for (let i = v.length - 1; i >= 0; i--) stack.push([v[i], `${at}[${String(i)}]`]);
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(v, PROTO_KEY)) {
      // Gate 2 · R14 names this rule inside its own stanza, so the refusal says
      // which ruling stopped it. The reason is the same one; only the tag is added.
      const inG2 =
        at === "baskets" || at.startsWith("baskets.") ||
        at === "readers.gate2Direction" || at.startsWith("readers.gate2Direction.");
      const inHarm = at === "harm" || at.startsWith("harm.");
      fail(
        at === "" ? PROTO_KEY : `${at}.${PROTO_KEY}`,
        inG2
          ? `${PROTO_KEY_REASON} ${g2Rule(14, "no __proto__ anywhere in the stanza")}`
          : inHarm
            ? `${PROTO_KEY_REASON} ${hRule(10, "no __proto__ anywhere in the stanza")}`
            : PROTO_KEY_REASON
      );
    }
    const keys = Object.keys(v);
    for (let i = keys.length - 1; i >= 0; i--) {
      const k = keys[i];
      stack.push([(v as Record<string, unknown>)[k], at === "" ? k : `${at}.${k}`]);
    }
  }
}
// S201: a systemd unit name without its `.service` suffix (subjects[].unit).
// ⛔ NO LEADING "-" (round 2, from review probe c6-2): a unit name reaches
//   `systemctl` as an argument in relay-lib, and "--user" or "--" would be read
//   as an OPTION. relay-lib also passes "--" before it; this is the first wall.
const UNIT_PATTERN = /^[A-Za-z0-9@_.:][A-Za-z0-9@_.:-]*$/;
const LINE_CLASS_PATTERN = /^[A-Za-z0-9_]+$/;
const EXPIRES_AT_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;

function validateDeclaredNumber(
  raw: unknown,
  field: string,
  opts: { integer?: boolean; minimum?: number } = {}
): DeclaredNumber {
  const obj = requireObject(raw, field);
  checkNoUnknown(obj, ["value", "basis", "proxy"], field);
  const value = requireField(obj, "value", `${field}.value`);
  const basis = requireField(obj, "basis", `${field}.basis`);
  const proxy = requireField(obj, "proxy", `${field}.proxy`);
  if (typeof value !== "number" || !Number.isFinite(value)) {
    fail(`${field}.value`, "must be a finite number");
  }
  if (opts.integer && !Number.isInteger(value)) {
    fail(`${field}.value`, "must be an integer");
  }
  if (opts.minimum !== undefined && value < opts.minimum) {
    fail(`${field}.value`, `must be >= ${opts.minimum}`);
  }
  if (typeof basis !== "string" || basis.length === 0) {
    fail(`${field}.basis`, "must be a non-empty string");
  }
  if (typeof proxy !== "boolean") {
    fail(`${field}.proxy`, "must be a boolean");
  }
  return { value, basis, proxy };
}

/**
 * ACT A added `allowEmpty`, and it is OPT-IN rather than a relaxed default.
 * An empty declared string is almost always an unfilled field, which is why
 * the rule has always been "non-empty". `subjectLog.chainBoundary.retiredPath`
 * is the one place where "" is a STATEMENT — FIRST BOOT, this chain replaced
 * nothing — and it is paired with cross-field rule X14 so the statement cannot
 * be made half-way. (Written as X10 by Act A; X10 was ruling O's uid-0 rule.)
 */
function validateDeclaredString(
  raw: unknown,
  field: string,
  options?: { readonly allowEmpty?: boolean }
): DeclaredString {
  const obj = requireObject(raw, field);
  checkNoUnknown(obj, ["value", "basis", "proxy"], field);
  const value = requireField(obj, "value", `${field}.value`);
  const basis = requireField(obj, "basis", `${field}.basis`);
  const proxy = requireField(obj, "proxy", `${field}.proxy`);
  if (typeof value !== "string" || (value.length === 0 && options?.allowEmpty !== true)) {
    fail(`${field}.value`, "must be a non-empty string");
  }
  if (typeof basis !== "string" || basis.length === 0) {
    fail(`${field}.basis`, "must be a non-empty string");
  }
  if (typeof proxy !== "boolean") {
    fail(`${field}.proxy`, "must be a boolean");
  }
  return { value, basis, proxy };
}

function validateDeclaredStringList(raw: unknown, field: string): DeclaredStringList {
  const obj = requireObject(raw, field);
  checkNoUnknown(obj, ["value", "basis", "proxy"], field);
  const value = requireField(obj, "value", `${field}.value`);
  const basis = requireField(obj, "basis", `${field}.basis`);
  const proxy = requireField(obj, "proxy", `${field}.proxy`);
  if (!Array.isArray(value) || value.length === 0) {
    fail(`${field}.value`, "must be a non-empty array");
  }
  for (const [i, s] of value.entries()) {
    if (typeof s !== "string" || s.length === 0) {
      fail(`${field}.value[${i}]`, "must be a non-empty string");
    }
  }
  if (new Set(value).size !== value.length) {
    fail(`${field}.value`, "must have unique items");
  }
  if (typeof basis !== "string" || basis.length === 0) {
    fail(`${field}.basis`, "must be a non-empty string");
  }
  if (typeof proxy !== "boolean") {
    fail(`${field}.proxy`, "must be a boolean");
  }
  return { value: value as string[], basis, proxy };
}

/**
 * C9. Same envelope discipline as its siblings above; the only new work is the
 * map's own shape. Every key and every member must be a non-empty string, every
 * value list non-empty and duplicate-free, and the map itself non-empty — see
 * `DeclaredEventMap` for why empty is refused rather than tolerated.
 */
function validateDeclaredEventMap(raw: unknown, field: string): DeclaredEventMap {
  const obj = requireObject(raw, field);
  checkNoUnknown(obj, ["value", "basis", "proxy"], field);
  const value = requireField(obj, "value", `${field}.value`);
  const basis = requireField(obj, "basis", `${field}.basis`);
  const proxy = requireField(obj, "proxy", `${field}.proxy`);
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`${field}.value`, "must be an object mapping eventType to a list of eventTypes");
  }
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length === 0) {
    fail(`${field}.value`, "must not be empty — an empty map reads as UNREAD, which is what omitting the field means");
  }
  for (const [key, list] of entries) {
    if (key.length === 0) {
      fail(`${field}.value`, "every key must be a non-empty eventType");
    }
    if (!Array.isArray(list) || list.length === 0) {
      fail(`${field}.value.${key}`, "must be a non-empty array of eventTypes");
    }
    for (const [i, s] of (list as unknown[]).entries()) {
      if (typeof s !== "string" || s.length === 0) {
        fail(`${field}.value.${key}[${i}]`, "must be a non-empty string");
      }
    }
    if (new Set(list as string[]).size !== (list as string[]).length) {
      fail(`${field}.value.${key}`, "must have unique items");
    }
  }
  if (typeof basis !== "string" || basis.length === 0) {
    fail(`${field}.basis`, "must be a non-empty string");
  }
  if (typeof proxy !== "boolean") {
    fail(`${field}.proxy`, "must be a boolean");
  }
  return { value: value as Readonly<Record<string, readonly string[]>>, basis, proxy };
}

function validateDeclaredEventClass(raw: unknown, field: string): DeclaredEventClass {
  const obj = requireObject(raw, field);
  checkNoUnknown(obj, ["value", "basis", "proxy"], field);
  const value = requireObject(requireField(obj, "value", `${field}.value`), `${field}.value`);
  checkNoUnknown(value, ["moduleId", "eventType"], `${field}.value`);
  const basis = requireField(obj, "basis", `${field}.basis`);
  const proxy = requireField(obj, "proxy", `${field}.proxy`);
  const members: { moduleId: string; eventType: string } = { moduleId: "", eventType: "" };
  for (const key of ["moduleId", "eventType"] as const) {
    const member = requireField(value, key, `${field}.value.${key}`);
    if (typeof member !== "string" || member.trim().length === 0) {
      fail(`${field}.value.${key}`, "must be a non-empty, non-whitespace string");
    }
    if (!IDENT_PATTERN.test(member as string)) {
      fail(`${field}.value.${key}`, `must match ${IDENT_PATTERN}`);
    }
    members[key] = member as string;
  }
  if (typeof basis !== "string" || basis.length === 0) {
    fail(`${field}.basis`, "must be a non-empty string");
  }
  if (typeof proxy !== "boolean") {
    fail(`${field}.proxy`, "must be a boolean");
  }
  return { value: members, basis, proxy };
}

/**
 * The shared validator for narrow-K / narrow-W / narrow-R. `minimumEventsField`
 * is the one field name that differs between the three; it is passed in rather
 * than normalised away, so the declaration a deployer writes matches the field
 * name in the instrument's own source.
 *
 * ── WHAT IS REQUIRED AND WHAT IS NOT, AND WHY THE SPLIT IS HERE ────────────
 *
 * `declaredProfile` is REQUIRED once the block exists. It is the only field
 * that drives leg 1, and a block without it declares a reader that can do
 * nothing but read CANNOT_ASSESS(MISSING_CONFIGURATION) forever — the exact
 * state the item-4 gating exists to keep OUT of the floor. A deployment that
 * wants that omits the block.
 *
 * `correlationThreshold` and `correlationMinimum*Events` are OPTIONAL HERE and
 * REQUIRED TOGETHER: leg 2 needs both, and with neither it reads a disclosed
 * CANNOT_ASSESS(MISSING_CONFIGURATION) — a blind path that SAYS it is blind,
 * which is a legitimate declared state. With exactly ONE of them the reader
 * lands in the same blind state, but the declaration now LOOKS as though leg 2
 * were configured. That is the half-declared shape this validator refuses:
 * the pairing is checked, the individual absence is not.
 *
 * `correlationPermutationSamples` / `...Seed` are report-only and are likewise
 * required together — the instruments produce no percentile without both, and
 * say so.
 */
function validateNarrowingProfile(
  raw: unknown,
  field: string,
  minimumEventsField: string
): { declaredProfile: DeclaredStringList } & Record<string, DeclaredNumber | DeclaredStringList | undefined> {
  const obj = requireObject(raw, field);
  checkNoUnknown(
    obj,
    [
      "declaredProfile",
      "correlationThreshold",
      minimumEventsField,
      "correlationCeilingMargin",
      "correlationPermutationSamples",
      "correlationPermutationSeed",
    ],
    field
  );
  const out: Record<string, DeclaredNumber | DeclaredStringList | undefined> = {};
  out.declaredProfile = validateDeclaredStringList(
    requireField(obj, "declaredProfile", `${field}.declaredProfile`),
    `${field}.declaredProfile`
  );
  const optionalNumber = (key: string, opts?: { integer?: boolean; minimum?: number }): void => {
    if (obj[key] === undefined) return;
    out[key] = validateDeclaredNumber(obj[key], `${field}.${key}`, opts ?? {});
  };
  optionalNumber("correlationThreshold");
  optionalNumber(minimumEventsField, { integer: true, minimum: 0 });
  optionalNumber("correlationCeilingMargin");
  optionalNumber("correlationPermutationSamples", { integer: true, minimum: 1 });
  optionalNumber("correlationPermutationSeed", { integer: true });
  if ((out.correlationThreshold === undefined) !== (out[minimumEventsField] === undefined)) {
    fail(
      `${field}.correlationThreshold`,
      `correlationThreshold and ${minimumEventsField} are leg 2's two required numbers and ` +
        `must be declared together or not at all; one alone leaves leg 2 blind in a ` +
        `declaration that reads as configured`
    );
  }
  if (
    (out.correlationPermutationSamples === undefined) !==
    (out.correlationPermutationSeed === undefined)
  ) {
    fail(
      `${field}.correlationPermutationSamples`,
      "correlationPermutationSamples and correlationPermutationSeed are report-only and " +
        "must be declared together or not at all; the percentile is NOT PRODUCED without both"
    );
  }
  return out as { declaredProfile: DeclaredStringList } & Record<
    string,
    DeclaredNumber | DeclaredStringList | undefined
  >;
}

// ── the full validator ────────────────────────────────────────────────────

function validate(raw: unknown): Declarations {
  // ⛔ FIRST, BEFORE ANY OTHER RULE (A6): an own "__proto__" key anywhere.
  refuseProtoKeysAnywhere(raw);
  const top = requireObject(raw, "$");
  checkNoUnknown(
    top,
    // `frame` (Gate 1, Stop 2) is OPTIONAL and last in schema order: it is keyed
    // by `subjects[].subject`, so it can only be checked once subjects are read.
    // `baskets` (Gate 2, Stop 2) is OPTIONAL and after `frame` for the same
    // reason: keyed by subject, and its classes bear on frame categories.
    // `harm` (Gate 2, Long Run A Stop 2) after `baskets`, keyed by subject the same way.
    ["schemaVersion", "readers", "stakes", "subjects", "routes", "pilot", "notice", "subjectLog", "paths", "frame", "baskets", "harm"],
    "$"
  );

  const schemaVersion = requireField(top, "schemaVersion", "schemaVersion");
  if (schemaVersion !== 1) {
    fail("schemaVersion", "must be the integer 1; any other value is a load error, not a migration");
  }

  // readers
  const readersRaw = requireObject(requireField(top, "readers", "readers"), "readers");
  // ══ THE FRONT DOOR. READ THIS BEFORE ADDING A BLOCK ANYWHERE ELSE. ══════════
  //
  // This list is the ONLY way into `readers`. A block that exists in the schema,
  // in the `Declarations` type, in a validator and in `to-wire-options.ts` but
  // NOT here is REJECTED AT LOAD — `checkNoUnknown` fails the whole declaration,
  // the service keeps its last known good one, and the reader the block was for
  // is not "live and inert", it is UNREACHABLE. `narrowK` sat in exactly that
  // state from the day item 4 landed until 2026-09-24; the declaration act that
  // would have turned it on would have failed at load, and nothing in the tree
  // said so. THE LIST IS THE THING TO CHECK, not the schema.
  //
  // FIVE KEYS WERE ADDED BY THE MERGE OF TWO LINES: `narrowK`, `narrowW`,
  // `narrowR` and `doctorCadence` from the bundle line, `nodeResponse` from the
  // `opa` line (109d5d9). The two lines each edited THIS call. All five are
  // OPTIONAL — none is in any required list, and `additionalProperties:false`
  // still holds for every key not named here. Each one is proved to reach its
  // validator by a declaration that CARRIES the block and LOADS, never by
  // reading this line.
  checkNoUnknown(
    readersRaw,
    [
      "readableLoadStates",
      "logPath",
      "logKind",
      "eng",
      "sig",
      "narrowK",
      "narrowW",
      "narrowR",
      // narrow-T, 2026-09-25. ELEVENTH key. It was added for exactly the reason
      // the block above describes: a Sunday declaration act carrying
      // `readers.narrowT` would have been REJECTED AT LOAD, the service would
      // have kept its last good declaration, and `declarationHash` would not have
      // moved — a declaration act that silently does not land.
      "narrowT",
      "doctorCadence",
      "nodeResponse",
      // gate 4, 2026-10-04 (T26). TWELFTH key, and the same lesson as narrowT's:
      // until it is here, a declaration act carrying `readers.gate4Sunset` is
      // REJECTED AT LOAD, the service keeps its last good declaration, and
      // `declarationHash` does not move. Measured rather than assumed this time:
      // s24-candidate fa67cc9f read `REJECTED DECLARATION_REJECTED
      // readers.gate4Sunset: unknown field`, exit 2.
      "gate4Sunset",
      // gate 1, Stop 2. THIRTEENTH key, the same lesson a third time: without it
      // a declaration act carrying `readers.gate1Scope` is REJECTED AT LOAD and
      // the reader is unreachable. Proved by LOADING a declaration that carries
      // the block (declarations.test.ts, GATE 1 arms), never by reading this line.
      "gate1Scope",
      // gate 2, Stop 2. FOURTEENTH key, the same lesson a fourth time. Proved by
      // LOADING a declaration that carries it (declarations.test.ts, GATE 2 arms).
      "gate2Direction",
    ],
    "readers"
  );
  const readableLoadStates = validateDeclaredStringList(
    requireField(readersRaw, "readableLoadStates", "readers.readableLoadStates"),
    "readers.readableLoadStates"
  );
  // AMENDMENT 9 / RULING P: without these, WireOptions.logPath is
  // necessarily undefined, wire.ts:383-386 pushes Eng and Sig wired:false,
  // all fourteen /status rows read UNWIRED, and no instrument can EVER
  // return ALARM. The Stage 0 draft's claim that Eng/Sig were "WIRED
  // because a log path is declared" was false against the schema Stage 0
  // actually shipped — that schema had no logPath field at all.
  const logPath = validateDeclaredString(
    requireField(readersRaw, "logPath", "readers.logPath"),
    "readers.logPath"
  );
  const logKindRaw = requireObject(requireField(readersRaw, "logKind", "readers.logKind"), "readers.logKind");
  checkNoUnknown(logKindRaw, ["value", "basis", "proxy"], "readers.logKind");
  const logKindValue = requireField(logKindRaw, "value", "readers.logKind.value");
  if (logKindValue !== "mica" && logKindValue !== "witness" && logKindValue !== "subject-chain") {
    fail("readers.logKind.value", 'must be "mica", "witness" or "subject-chain"');
  }
  const logKindBasis = requireField(logKindRaw, "basis", "readers.logKind.basis");
  const logKindProxy = requireField(logKindRaw, "proxy", "readers.logKind.proxy");
  if (typeof logKindBasis !== "string" || logKindBasis.length === 0) {
    fail("readers.logKind.basis", "must be a non-empty string");
  }
  if (typeof logKindProxy !== "boolean") {
    fail("readers.logKind.proxy", "must be a boolean");
  }
  const logKind: DeclaredLogKind = { value: logKindValue, basis: logKindBasis, proxy: logKindProxy };
  const engRaw = requireObject(requireField(readersRaw, "eng", "readers.eng"), "readers.eng");
  // `minimumClassCoverage` joined 2026-10-01 (T11), same reason as `clerkStampLag`
  // at the sig door below: without it here, the declaration that carries the
  // field is REFUSED AT LOAD and the field can never reach the reader that
  // needs it. A closed key set is a door, and a door has to be opened on purpose.
  checkNoUnknown(
    engRaw,
    ["structureThreshold", "minimumSampleSize", "minimumClassCoverage"],
    "readers.eng"
  );
  const structureThreshold = validateDeclaredNumber(
    requireField(engRaw, "structureThreshold", "readers.eng.structureThreshold"),
    "readers.eng.structureThreshold"
  );
  const minimumSampleSize = validateDeclaredNumber(
    requireField(engRaw, "minimumSampleSize", "readers.eng.minimumSampleSize"),
    "readers.eng.minimumSampleSize",
    { integer: true, minimum: 0 }
  );
  // Checked to the SENSOR's own shape, not merely to "a number": Eng requires an
  // integer >= 1 and refuses anything else as MISSING_CONFIGURATION. A value of
  // the wrong shape admitted here would read as a cautious hold rather than as
  // the mistake it is — the same argument mica-guard makes at its own door.
  const minimumClassCoverage =
    engRaw.minimumClassCoverage === undefined
      ? undefined
      : validateDeclaredNumber(
          engRaw.minimumClassCoverage,
          "readers.eng.minimumClassCoverage",
          { integer: true, minimum: 1 }
        );
  const sigRaw = requireObject(requireField(readersRaw, "sig", "readers.sig"), "readers.sig");
  checkNoUnknown(
    sigRaw,
    // `clerkStampLag` joined 2026-09-25, same reason as `narrowT` at the door
    // above: without it, Act B's declaration is refused at load.
    ["clockToleranceMs", "clockToleranceBasis", "preconditionMap", "reentryMap", "clerkStampLag"],
    "readers.sig"
  );
  const clockToleranceMs = validateDeclaredNumber(
    requireField(sigRaw, "clockToleranceMs", "readers.sig.clockToleranceMs"),
    "readers.sig.clockToleranceMs",
    { minimum: 0 }
  );
  const clockToleranceBasis = validateDeclaredString(
    requireField(sigRaw, "clockToleranceBasis", "readers.sig.clockToleranceBasis"),
    "readers.sig.clockToleranceBasis"
  );
  // C9: both REQUIRED once declared in the schema. `SigConfig` treats absent and
  // empty alike (the scope reads UNREAD), so a deployment that wants F2 to read
  // must declare both, and one that does not want it declares neither — there is
  // no half-configured state this validator will accept quietly.
  const preconditionMap = validateDeclaredEventMap(
    requireField(sigRaw, "preconditionMap", "readers.sig.preconditionMap"),
    "readers.sig.preconditionMap"
  );
  const reentryMap = validateDeclaredEventMap(
    requireField(sigRaw, "reentryMap", "readers.sig.reentryMap"),
    "readers.sig.reentryMap"
  );
  // ACT B · optional, and absent is the pre-Act-B state, not a rejection.
  const clerkStampLag =
    sigRaw.clerkStampLag === undefined
      ? undefined
      : validateDeclaredString(sigRaw.clerkStampLag, "readers.sig.clerkStampLag");

  // ── the three narrowing readers and op1, ALL OPTIONAL ────────────────────
  //
  // ABSENT IS THE PRE-BUNDLE STATE AND IS NOT A REJECTION. Each key is left OFF
  // the returned object entirely — never set to `undefined` with a comment
  // about it — so `canonicalHash`, which omits absent and undefined alike by its
  // own rule 4, yields the identical digest a declaration without these fields
  // yielded before they existed. That is the property that makes the pinned
  // declaration hash hold across this change, and it is asserted in the suite
  // rather than reasoned about here.
  const narrowK =
    readersRaw.narrowK === undefined
      ? undefined
      : validateNarrowingProfile(
          readersRaw.narrowK,
          "readers.narrowK",
          "correlationMinimumConstraintEvents"
        );
  const narrowW =
    readersRaw.narrowW === undefined
      ? undefined
      : validateNarrowingProfile(
          readersRaw.narrowW,
          "readers.narrowW",
          "correlationMinimumInquiryEvents"
        );
  const narrowR =
    readersRaw.narrowR === undefined
      ? undefined
      : validateNarrowingProfile(
          readersRaw.narrowR,
          "readers.narrowR",
          "correlationMinimumVerificationEvents"
        );
  // ── narrow-T · the fifth Eng-sibling, validated but NOT YET WIRED ─────────
  //
  // Every field is validated here even though nothing downstream reads one yet
  // (see the block's comment: `wire.ts` has no `options.narrowT`). That is on
  // purpose. A field the door admits without checking is a field that will be
  // wrong on the day it is finally read, and the declaration that carried it
  // will have loaded clean for weeks.
  let narrowT: Declarations["readers"]["narrowT"];
  if (readersRaw.narrowT !== undefined) {
    const tRaw = requireObject(readersRaw.narrowT, "readers.narrowT");
    checkNoUnknown(
      tRaw,
      [
        "driftTolerance",
        "minimumEventsPerWindow",
        "temporalWindowSize",
        "driftCeilingMargin",
        "driftPermutationSamples",
        "driftPermutationSeed",
      ],
      "readers.narrowT"
    );
    // REQUIRED once the block exists. Absent, the instrument can only ever read
    // CANNOT_ASSESS(MISSING_CONFIGURATION), which is the state the item-4 gating
    // exists to keep out of the floor — the same rule narrow-K's
    // `declaredProfile` states. No range is imposed on the tolerance: calibration
    // belongs to pilot data, not to this validator.
    const driftTolerance = validateDeclaredNumber(
      requireField(tRaw, "driftTolerance", "readers.narrowT.driftTolerance"),
      "readers.narrowT.driftTolerance"
    );
    const minimumEventsPerWindow = validateDeclaredNumber(
      requireField(tRaw, "minimumEventsPerWindow", "readers.narrowT.minimumEventsPerWindow"),
      "readers.narrowT.minimumEventsPerWindow",
      { integer: true, minimum: 0 }
    );
    // A window is a COUNT OF RECORDS taken from each end, so it is a positive
    // integer; zero would make both windows empty and the read unattemptable.
    const temporalWindowSize =
      tRaw.temporalWindowSize === undefined
        ? undefined
        : validateDeclaredNumber(tRaw.temporalWindowSize, "readers.narrowT.temporalWindowSize", {
            integer: true,
            minimum: 1,
          });
    const driftCeilingMargin =
      tRaw.driftCeilingMargin === undefined
        ? undefined
        : validateDeclaredNumber(tRaw.driftCeilingMargin, "readers.narrowT.driftCeilingMargin");
    const driftPermutationSamples =
      tRaw.driftPermutationSamples === undefined
        ? undefined
        : validateDeclaredNumber(
            tRaw.driftPermutationSamples,
            "readers.narrowT.driftPermutationSamples",
            { integer: true, minimum: 0 }
          );
    const driftPermutationSeed =
      tRaw.driftPermutationSeed === undefined
        ? undefined
        : validateDeclaredNumber(tRaw.driftPermutationSeed, "readers.narrowT.driftPermutationSeed", {
            integer: true,
          });
    // THE PAIR RULE, and it is refused here rather than tolerated downstream.
    // The percentile is report-only and REPRODUCIBLE BY DESIGN: samples without a
    // seed produce a number that changes between two runs on identical bytes, and
    // a seed without samples produces no number at all. Either half alone is a
    // declaration that cannot mean what it says.
    if ((driftPermutationSamples === undefined) !== (driftPermutationSeed === undefined)) {
      fail(
        "readers.narrowT.driftPermutationSamples",
        "driftPermutationSamples and driftPermutationSeed are declared together or " +
          "not at all — samples without a seed are not reproducible, and a seed " +
          "without samples produces no reading"
      );
    }
    narrowT = {
      driftTolerance,
      minimumEventsPerWindow,
      ...(temporalWindowSize === undefined ? {} : { temporalWindowSize }),
      ...(driftCeilingMargin === undefined ? {} : { driftCeilingMargin }),
      ...(driftPermutationSamples === undefined ? {} : { driftPermutationSamples }),
      ...(driftPermutationSeed === undefined ? {} : { driftPermutationSeed }),
    };
  }
  let doctorCadence: Declarations["readers"]["doctorCadence"];
  if (readersRaw.doctorCadence !== undefined) {
    const dcRaw = requireObject(readersRaw.doctorCadence, "readers.doctorCadence");
    checkNoUnknown(dcRaw, ["attestationClass", "cadenceBoundSteps"], "readers.doctorCadence");
    const attestationClass = validateDeclaredEventClass(
      requireField(dcRaw, "attestationClass", "readers.doctorCadence.attestationClass"),
      "readers.doctorCadence.attestationClass"
    );
    // THE ONE CROSS-FIELD RULE THIS BLOCK NEEDS, AND IT IS NARROWER THAN "a
    // kind this bridge can write".
    //
    // op1 counts occurrences of the declared class and reads their spacing as
    // the doctor's cadence. Exactly ONE kind on this log is written by a second
    // party about the subject; every other kind is the subject's own act record,
    // written by the caller. Point op1 at `TOOL_ATTEMPTED` and it reads the
    // subject's own busyness as evidence that a doctor visited — a reading that
    // is not merely wrong but SELF-SERVING, since the subject controls the
    // number. Refusing it here is the same shape as X13: the refusal lives where
    // the mistake is written, not where it would be obeyed.
    //
    // This is spelt as a literal rather than imported from mica-service's
    // `SUBJECT_EVENT_KINDS` ON PURPOSE: mica-service imports THIS module, and a
    // value import back the other way is a runtime cycle. The name is repeated
    // in exactly two places — here and the `SubjectEventKind` union — and the
    // suite asserts they agree.
    if (attestationClass.value.eventType !== "DOCTOR_ATTESTED") {
      fail(
        "readers.doctorCadence.attestationClass.value.eventType",
        `must be "DOCTOR_ATTESTED" — the one kind on this log written by a second ` +
          `party about the subject. "${attestationClass.value.eventType}" is a record the ` +
          `SUBJECT writes about itself, and counting it as a doctor's visit would let the ` +
          `subject supply its own cadence`
      );
    }
    doctorCadence = { attestationClass };
    if (dcRaw.cadenceBoundSteps !== undefined) {
      doctorCadence = {
        attestationClass,
        cadenceBoundSteps: validateDeclaredNumber(
          dcRaw.cadenceBoundSteps,
          "readers.doctorCadence.cadenceBoundSteps",
          { integer: true, minimum: 1 }
        ),
      };
    }
  }

  // ── §2d · readers.gate4Sunset, OPTIONAL · T26 / R1 ───────────────────────
  //
  // ⛔ TWO FIELDS, AND NEITHER IS A CLASS. The predecessor validated eleven
  //    deployer-typed class lists plus three outcome words, each one a way to
  //    mistype a kind this repository defines. They are gone: the profile is
  //    BUILT, not declared, so there is nothing here to get wrong but the
  //    subject's name — and a wrong subject names no records at all, which the
  //    census shows as a reader that reads nothing rather than as a verdict.
  let gate4Sunset: Declarations["readers"]["gate4Sunset"];
  const gate4Raw = readersRaw.gate4Sunset;
  if (gate4Raw !== undefined) {
    const g = requireObject(gate4Raw, "readers.gate4Sunset");
    checkNoUnknown(g, ["subject", "paperFreshnessBound"], "readers.gate4Sunset");
    const subject = validateDeclaredString(
      requireField(g, "subject", "readers.gate4Sunset.subject"),
      "readers.gate4Sunset.subject"
    );
    const paperFreshnessBound =
      g.paperFreshnessBound === undefined
        ? undefined
        : validateDeclaredNumber(g.paperFreshnessBound, "readers.gate4Sunset.paperFreshnessBound", {
            integer: true,
            minimum: 1,
          });
    gate4Sunset = { subject, ...(paperFreshnessBound === undefined ? {} : { paperFreshnessBound }) };
  }

  // ── Gate 1 · readers.gate1Scope, OPTIONAL · Stop 2 ───────────────────────
  //
  // SHAPE ONLY HERE. The block's one cross-field rule — the subject is declared
  // AND has a frame — needs `subjects` and `frame`, which are read later in
  // schema order; it is X20, after the frame. Unlike gate4Sunset, a wrong subject
  // is REFUSED rather than left to read nothing: this reader's frame is keyed by
  // the subject, so "no frame for that name" is checkable at the door, and a
  // reader declared over no frame is the present-in-the-census, absent-from-every-
  // reading shape gate4Sunset's own comment warns about.
  let gate1Scope: Declarations["readers"]["gate1Scope"];
  if (readersRaw.gate1Scope !== undefined) {
    const g = requireObject(readersRaw.gate1Scope, "readers.gate1Scope");
    checkNoUnknown(g, ["subject"], "readers.gate1Scope");
    gate1Scope = {
      subject: validateDeclaredString(
        requireField(g, "subject", "readers.gate1Scope.subject"),
        "readers.gate1Scope.subject"
      ),
    };
  }

  // ── Gate 2 · readers.gate2Direction, OPTIONAL · Stop 2 ──────────────────
  //
  // SHAPE ONLY HERE, the gate1Scope order: its cross-field rule (R1 — the
  // subject is declared, framed and basketed) needs `subjects`, `frame` and
  // `baskets`, which are read later in schema order.
  let gate2Direction: Declarations["readers"]["gate2Direction"];
  if (readersRaw.gate2Direction !== undefined) {
    const g = requireObject(readersRaw.gate2Direction, "readers.gate2Direction");
    checkNoUnknownG2(g, ["subject", "book", "witnessMethod"], "readers.gate2Direction");
    const subject = validateDeclaredString(
      requireField(g, "subject", "readers.gate2Direction.subject"),
      "readers.gate2Direction.subject"
    );
    // TIER 1 · the book switch and the method designation: both, or neither.
    // Absent keys are left OFF the object, so a declaration without them hashes
    // exactly as before (canonicalHash omits absent keys, rule 4).
    const rw = g2Rule(16, "Gate 2 on the witness's book names the witness by its METHOD — 16:36Z (3)③'s party designation carried to the witness: keyed on what it runs, never on a bare uid");
    if (Object.hasOwn(g, "book") !== Object.hasOwn(g, "witnessMethod")) {
      fail(
        "readers.gate2Direction",
        `book and witnessMethod are declared together or not at all: a book with no named method counts records ` +
          `of whatever method wrote them, and a method with no book names nothing ${rw}`
      );
    }
    if (Object.hasOwn(g, "book")) {
      const be = g2Envelope(g.book, "readers.gate2Direction.book", rw);
      if (be.value !== "witnessBook") {
        fail("readers.gate2Direction.book.value", `must be "witnessBook" (declared ${JSON.stringify(be.value)}); absent means the subject log ${rw}`);
      }
      const me = g2Envelope(g.witnessMethod, "readers.gate2Direction.witnessMethod", rw);
      if (typeof me.value !== "string" || !/^[0-9a-f]{64}$/.test(me.value)) {
        fail("readers.gate2Direction.witnessMethod.value", `must be the 64-hex sha256 of the witness's seeing method ${rw}`);
      }
      gate2Direction = {
        subject,
        book: { value: "witnessBook", basis: be.basis, proxy: be.proxy },
        witnessMethod: { value: me.value as string, basis: me.basis, proxy: me.proxy },
      };
    } else {
      gate2Direction = { subject };
    }
  }

  // ── H12 · readers.nodeResponse, OPTIONAL ─────────────────────────────────
  //
  // ABSENT IS THE PRE-H12 STATE AND IS NOT A REJECTION: the key is left off the
  // returned object entirely (never set to undefined with a comment about it),
  // so `canonicalHash` — which omits absent and undefined alike, by its own
  // rule 4 — yields the identical digest a declaration without this field
  // yielded before the field existed. That is the property that makes
  // `EXPECTED_HASH` hold across this change, and it is asserted in the suite
  // rather than reasoned about here.
  //
  // PRESENT, ALL THREE OF expectationClass / responseClass / responseBoundSteps
  // ARE REQUIRED. The instrument tolerates an absent `responseBoundSteps` by
  // switching leg A to ORDER-ONLY, where ANY later matching response satisfies
  // — unbounded delay, and on this record that means an attempt pairs to some
  // later act's result and a held act never alarms. That is a real mode and a
  // deployer may want it, but it must be ASKED FOR, not arrived at by leaving a
  // field out; a half-declared block that silently changes what the leg means
  // is the shape this validator exists to refuse.
  //
  // `flatness` is genuinely optional: absent, leg B reads
  // CANNOT_ASSESS(OP3_FLATNESS_ABSENT) and says so, which is a disclosed blind
  // path rather than a changed meaning.
  let nodeResponse: Declarations["readers"]["nodeResponse"];
  const nodeResponseRawValue = readersRaw.nodeResponse;
  if (nodeResponseRawValue !== undefined) {
    const nrRaw = requireObject(nodeResponseRawValue, "readers.nodeResponse");
    checkNoUnknown(
      nrRaw,
      ["expectationClass", "responseClass", "responseBoundSteps", "since", "flatness"],
      "readers.nodeResponse"
    );
    const expectationClass = validateDeclaredEventClass(
      requireField(nrRaw, "expectationClass", "readers.nodeResponse.expectationClass"),
      "readers.nodeResponse.expectationClass"
    );
    const responseClass = validateDeclaredEventClass(
      requireField(nrRaw, "responseClass", "readers.nodeResponse.responseClass"),
      "readers.nodeResponse.responseClass"
    );
    // The instrument refuses an identical pair with
    // CANNOT_ASSESS(OP3_PROFILE_VACUOUS). Refused here too, and at load, so the
    // declaration is rejected instead of quietly reading as nothing forever.
    if (
      expectationClass.value.moduleId === responseClass.value.moduleId &&
      expectationClass.value.eventType === responseClass.value.eventType
    ) {
      fail(
        "readers.nodeResponse.responseClass",
        "must differ from expectationClass; an identical pair reads " +
          "CANNOT_ASSESS(OP3_PROFILE_VACUOUS) at the instrument, forever"
      );
    }
    const responseBoundSteps = validateDeclaredNumber(
      requireField(nrRaw, "responseBoundSteps", "readers.nodeResponse.responseBoundSteps"),
      "readers.nodeResponse.responseBoundSteps",
      { integer: true, minimum: 1 }
    );
    // `since` — a sequenceNumber, so an integer of at least 1. There is no
    // upper check: a value past the end of the log is not malformed, it is a
    // window that currently pairs nothing, and the glue prints that as
    // "0 of N record(s)" rather than pretending to a reading.
    const sinceRawValue = nrRaw.since;
    const since =
      sinceRawValue === undefined
        ? undefined
        : validateDeclaredNumber(sinceRawValue, "readers.nodeResponse.since", {
            integer: true,
            minimum: 1,
          });
    const withSince = since === undefined ? {} : { since };
    const flatnessRawValue = nrRaw.flatness;
    if (flatnessRawValue === undefined) {
      nodeResponse = { expectationClass, responseClass, responseBoundSteps, ...withSince };
    } else {
      const flatnessRaw = requireObject(flatnessRawValue, "readers.nodeResponse.flatness");
      checkNoUnknown(
        flatnessRaw,
        ["amiFloor", "amiCeilingMargin", "minSample"],
        "readers.nodeResponse.flatness"
      );
      // (0,1) EXCLUSIVE AT BOTH ENDS, checked here rather than by widening the
      // shared `validateDeclaredNumber` with options no other field needs. The
      // bound is the instrument's own (`usableFraction`): 0 and 1 both read
      // CANNOT_ASSESS(OP3_FLATNESS_MALFORMED), so accepting either here would
      // load a declaration that can never produce a reading.
      const inUnitInterval = (n: DeclaredNumber, field: string): DeclaredNumber => {
        if (!(n.value > 0 && n.value < 1)) {
          fail(`${field}.value`, "must be strictly between 0 and 1 (the instrument's own usableFraction)");
        }
        return n;
      };
      const amiFloor = inUnitInterval(
        validateDeclaredNumber(
          requireField(flatnessRaw, "amiFloor", "readers.nodeResponse.flatness.amiFloor"),
          "readers.nodeResponse.flatness.amiFloor"
        ),
        "readers.nodeResponse.flatness.amiFloor"
      );
      const amiCeilingMargin = inUnitInterval(
        validateDeclaredNumber(
          requireField(flatnessRaw, "amiCeilingMargin", "readers.nodeResponse.flatness.amiCeilingMargin"),
          "readers.nodeResponse.flatness.amiCeilingMargin"
        ),
        "readers.nodeResponse.flatness.amiCeilingMargin"
      );
      // The instrument's own floor: minSample < 3 reads
      // CANNOT_ASSESS(OP3_FLATNESS_MALFORMED). Held here at the same number.
      const minSample = validateDeclaredNumber(
        requireField(flatnessRaw, "minSample", "readers.nodeResponse.flatness.minSample"),
        "readers.nodeResponse.flatness.minSample",
        { integer: true, minimum: 3 }
      );
      nodeResponse = {
        ...withSince,
        expectationClass,
        responseClass,
        responseBoundSteps,
        flatness: { amiFloor, amiCeilingMargin, minSample },
      };
    }
  }

  // stakes
  const stakesRaw = requireObject(requireField(top, "stakes", "stakes"), "stakes");
  checkNoUnknown(stakesRaw, ["lineClasses", "baseline"], "stakes");
  const lineClassesRaw = requireField(stakesRaw, "lineClasses", "stakes.lineClasses");
  if (!Array.isArray(lineClassesRaw) || lineClassesRaw.length === 0) {
    fail("stakes.lineClasses", "must be a non-empty array");
  }
  for (const [i, c] of (lineClassesRaw as unknown[]).entries()) {
    if (typeof c !== "string" || c.length === 0 || !LINE_CLASS_PATTERN.test(c)) {
      fail(`stakes.lineClasses[${i}]`, "must be a non-empty string matching ^[A-Za-z0-9_]+$");
    }
  }
  if (new Set(lineClassesRaw as string[]).size !== (lineClassesRaw as string[]).length) {
    fail("stakes.lineClasses", "must have unique items");
  }
  const lineClasses = lineClassesRaw as string[];
  const baselineRaw = requireObject(requireField(stakesRaw, "baseline", "stakes.baseline"), "stakes.baseline");
  checkNoUnknown(baselineRaw, ["holdAtOrAbove"], "stakes.baseline");
  const baselineHoldAtOrAbove = validateDeclaredString(
    requireField(baselineRaw, "holdAtOrAbove", "stakes.baseline.holdAtOrAbove"),
    "stakes.baseline.holdAtOrAbove"
  );

  // X1: stakes.baseline.holdAtOrAbove.value in stakes.lineClasses
  // [verified] chokepoint/types.ts:186-195 isUsableLine requires
  // classes.includes(holdAtOrAbove) — reimplemented above as isUsableLine().
  if (!isUsableLine(lineClasses, baselineHoldAtOrAbove.value)) {
    fail(
      "stakes.baseline.holdAtOrAbove",
      `"${baselineHoldAtOrAbove.value}" is not a member of stakes.lineClasses (cross-field rule X1; ` +
        `mirrors isUsableLine, chokepoint/types.ts:186-195)`
    );
  }

  // subjects
  const subjectsRaw = requireField(top, "subjects", "subjects");
  // Z0 · ZERO SUBJECTS ARE ADMITTED (the arbiter 2026-10-17 16:03Z (1); ticket
  // Bridge-Zero-Subjects v2, accepted for build by the audit 2026-10-18 06:56Z
  // (9)). `subjects: []` is "nothing declared": every reader then reads that
  // honestly (mica-service.ts), and the four refusals in front of /guard hold.
  // Every other rule stands — X6 and F1 bind every DECLARED subject exactly as
  // before, vacuously at zero; Z2, Z3 and Z5 below are what zero needs, and Z4
  // (validateActivation) keeps membership a first-load (restart) fact.
  if (!Array.isArray(subjectsRaw)) {
    fail("subjects", "must be an array (it may be empty: nothing declared, Z0)");
  }
  const subjects: Subject[] = [];
  const seenSubjectNames = new Set<string>();
  for (const [i, entryRaw] of (subjectsRaw as unknown[]).entries()) {
    const field = `subjects[${i}]`;
    const entry = requireObject(entryRaw, field);
    checkNoUnknown(entry, ["subject", "toolName", "stakesClass", "peerUid", "unit"], field);
    const subject = requireField(entry, "subject", `${field}.subject`);
    const toolName = requireField(entry, "toolName", `${field}.toolName`);
    const stakesClass = requireField(entry, "stakesClass", `${field}.stakesClass`);
    const peerUid = requireField(entry, "peerUid", `${field}.peerUid`);
    if (typeof subject !== "string" || !IDENT_PATTERN.test(subject)) {
      fail(`${field}.subject`, "must be a non-empty string matching ^[A-Za-z0-9_.:-]+$");
    }
    if (subject === PROTO_KEY) {
      fail(`${field}.subject`, PROTO_KEY_REASON);
    }
    if (typeof toolName !== "string" || !IDENT_PATTERN.test(toolName)) {
      fail(`${field}.toolName`, "must be a non-empty string matching ^[A-Za-z0-9_.:-]+$");
    }
    if (typeof stakesClass !== "string" || stakesClass.length === 0) {
      fail(`${field}.stakesClass`, "must be a non-empty string");
    }
    if (typeof peerUid !== "number" || !Number.isInteger(peerUid) || peerUid < 0) {
      fail(`${field}.peerUid`, "must be a non-negative integer");
    }
    // S201: the caller's unit name. Same rule as the schema's pattern; it ends
    // up as a systemctl argument in relay-bridge, so nothing looser is allowed.
    const unit = entry["unit"];
    if (unit !== undefined && (typeof unit !== "string" || !UNIT_PATTERN.test(unit))) {
      // ROUND 3 (A8, reviews K3D3-7, K3D1-9): the reason QUOTES the pattern
      // enforced — the old text quoted ^[A-Za-z0-9@_.:-]+$, which ACCEPTS the
      // leading "-" this rule refuses.
      fail(
        `${field}.unit`,
        `must be a systemd unit name matching ${UNIT_PATTERN.source} — no leading "-", which systemctl ` +
          `would read as an option (no .service suffix needed)`
      );
    }
    // X2: subjects[].stakesClass in stakes.lineClasses
    // [verified] chokepoint/types.ts:202-208 stakesSplit returns the cautious
    // default when !line.classes.includes(stakes.impactClass).
    if (!lineClasses.includes(stakesClass)) {
      fail(`${field}.stakesClass`, `"${stakesClass}" is not a member of stakes.lineClasses (cross-field rule X2)`);
    }
    // Ruling M: the top rung of lineClasses is the non-assignable sentinel
    // (design §B.1, fork D-1) — it exists purely as a line position so the
    // pilot override has somewhere to point above "bash"; no subjects[]
    // entry may carry it.
    const sentinelClass = lineClasses[lineClasses.length - 1];
    if (stakesClass === sentinelClass) {
      fail(
        `${field}.stakesClass`,
        `"${sentinelClass}" is the sentinel rung (top of stakes.lineClasses) and is non-assignable ` +
          `(ruling M): no subject may be assigned it`
      );
    }
    // X4: subjects[].subject unique
    if (seenSubjectNames.has(subject)) {
      fail(`${field}.subject`, `duplicate subject "${subject}" (cross-field rule X4)`);
    }
    seenSubjectNames.add(subject);
    subjects.push(unit === undefined ? { subject, toolName, stakesClass, peerUid } : { subject, toolName, stakesClass, peerUid, unit: unit as string });
  }

  // routes
  const routesRaw = requireField(top, "routes", "routes");
  if (!Array.isArray(routesRaw) || routesRaw.length === 0) {
    fail("routes", "must be a non-empty array");
  }
  const routes: Route[] = [];
  const seenRouteUids = new Set<number>();
  const ROLE_VALUES = ["subject", "alerter", "operator", "verifier"];
  const METHOD_VALUES = ["GET", "POST"];
  // R1. `/explain` joins the list. IT IS A READ SURFACE OVER THE DECISION
  // RECORD — each reading, its margin, and which reader held the floor — and
  // X13 below is what keeps it off the subject's own row.
  const PATH_VALUES = ["/guard", "/subject-events", "/status", "/events", "/log", "/explain", "/sunset-order"];
  for (const [i, entryRaw] of (routesRaw as unknown[]).entries()) {
    const field = `routes[${i}]`;
    const entry = requireObject(entryRaw, field);
    checkNoUnknown(entry, ["uid", "role", "allow"], field);
    const uid = requireField(entry, "uid", `${field}.uid`);
    const role = requireField(entry, "role", `${field}.role`);
    const allowRaw = requireField(entry, "allow", `${field}.allow`);
    if (typeof uid !== "number" || !Number.isInteger(uid) || uid < 0) {
      fail(`${field}.uid`, "must be a non-negative integer");
    }
    // X10 (ruling O): no route row may name uid 0. root gets no row — an
    // explicit decision, never an accident.
    if (uid === 0) {
      fail(`${field}.uid`, `uid 0 (root) may not hold a routes[] row (cross-field rule X10, ruling O)`);
    }
    // X11 (ruling O): no route row may name the service's own uid — a
    // service authorising itself over its own socket is a loop, not an
    // authorization boundary.
    if (uid === MICA_BRIDGE_SERVICE_UID) {
      fail(
        `${field}.uid`,
        `uid ${MICA_BRIDGE_SERVICE_UID} is the bridge service's own uid; a route row for it ` +
          `would be the service authorising itself over its own socket (cross-field rule X11, ruling O)`
      );
    }
    if (typeof role !== "string" || !ROLE_VALUES.includes(role)) {
      fail(`${field}.role`, `must be one of ${ROLE_VALUES.join(", ")}`);
    }
    if (!Array.isArray(allowRaw) || allowRaw.length === 0) {
      fail(`${field}.allow`, "must be a non-empty array");
    }
    const allow: RouteAllow[] = [];
    for (const [j, allowEntryRaw] of (allowRaw as unknown[]).entries()) {
      const allowField = `${field}.allow[${j}]`;
      const allowEntry = requireObject(allowEntryRaw, allowField);
      checkNoUnknown(allowEntry, ["method", "path"], allowField);
      const method = requireField(allowEntry, "method", `${allowField}.method`);
      const path = requireField(allowEntry, "path", `${allowField}.path`);
      if (typeof method !== "string" || !METHOD_VALUES.includes(method)) {
        fail(`${allowField}.method`, `must be one of ${METHOD_VALUES.join(", ")}`);
      }
      if (typeof path !== "string" || !PATH_VALUES.includes(path)) {
        fail(`${allowField}.path`, `must be one of ${PATH_VALUES.join(", ")}`);
      }
      allow.push({ method: method as RouteAllow["method"], path: path as RouteAllow["path"] });
    }
    // X5: routes[].uid unique
    if (seenRouteUids.has(uid)) {
      fail(`${field}.uid`, `duplicate uid ${uid} (cross-field rule X5)`);
    }
    seenRouteUids.add(uid);
    routes.push({ uid, role: role as Route["role"], allow });
  }

  // X6: every subjects[].peerUid appears in routes[] with role subject.
  // ⛔ The role is the word "subject", not any subject's name (S201): the bridge
  // must be removable from the subject it reads, so no subject is named in code.
  for (const [i, s] of subjects.entries()) {
    const bound = routes.some((r) => r.uid === s.peerUid && r.role === "subject");
    if (!bound) {
      fail(
        `subjects[${i}].peerUid`,
        `peerUid ${s.peerUid} has no routes[] row with role "subject" (cross-field rule X6)`
      );
    }
  }

  // X12 (ruling O): a subject's peerUid must not appear on a route row that
  // grants POST anywhere beyond /guard and /subject-events. A subject binds
  // a caller to exactly the two act-reporting routes; any wider POST grant
  // on that same uid is a privilege the pilot/housekeeper design never asked
  // for and the verifier's Blocker 1 named as exactly this shape of risk.
  const ALLOWED_SUBJECT_POST_PATHS = new Set(["/guard", "/subject-events"]);
  for (const [i, s] of subjects.entries()) {
    for (const r of routes) {
      if (r.uid !== s.peerUid) continue;
      for (const [j, a] of r.allow.entries()) {
        if (a.method === "POST" && !ALLOWED_SUBJECT_POST_PATHS.has(a.path)) {
          fail(
            `routes[${routes.indexOf(r)}].allow[${j}]`,
            `uid ${r.uid} is bound as subjects[${i}].peerUid; a POST route beyond /guard and ` +
              `/subject-events is not permitted for a subject's peer (cross-field rule X12, ruling O)`
          );
        }
      }
    }
  }

  // X13 (R1): A SUBJECT MAY NOT READ THE REASONING ABOUT ITSELF.
  //
  // `/explain` answers, for one decision: what each reader read, how far it
  // was from the threshold it was measured on, and WHICH reader held the
  // floor down. That is the most useful thing on this box for an operator and
  // the most useful thing on this box for a subject trying to tune against
  // the gate that watches it. A SUBJECT THAT CAN READ ITS OWN MARGINS CAN
  // AIM AT THEM — it learns which reader is closest to firing and what moves
  // it, which is a strictly better attack than guessing.
  //
  // X12 above refuses a subject's peer a POST it should not have. This is the
  // READ twin of that rule, and it exists as a LOADER rule rather than only
  // as an authorizeRoute outcome for a specific reason: `authorizeRoute`
  // faithfully enforces whatever the declaration says, so a declaration that
  // granted the housekeeper `/explain` would be obeyed, not questioned. The
  // refusal has to live where the grant is written. A declaration that makes
  // this mistake does not load at all, and the service keeps its last known
  // good one.
  //
  // NOT LIMITED TO `/explain` BY ACCIDENT: the set is named so the next
  // reasoning-bearing read route is a deliberate decision to add to it, not
  // an omission.
  const SUBJECT_FORBIDDEN_READ_PATHS = new Set(["/explain"]);
  for (const [i, s] of subjects.entries()) {
    for (const r of routes) {
      if (r.uid !== s.peerUid) continue;
      for (const [j, a] of r.allow.entries()) {
        if (SUBJECT_FORBIDDEN_READ_PATHS.has(a.path)) {
          fail(
            `routes[${routes.indexOf(r)}].allow[${j}]`,
            `uid ${r.uid} is bound as subjects[${i}].peerUid; ${a.path} exposes the ` +
              `reasoning about that subject's own acts (each reader's margin and the ` +
              `binding minimum) and is not permitted for a subject's peer — a subject ` +
              `that can read its own margins can tune against them (cross-field rule X13)`
          );
        }
      }
    }
  }

  // Z2 · REVERSE X6 (ticket v2 §2, F-3: at every n, not only at zero). Placed
  // AFTER X6/X12/X13 so every pre-existing refusal keeps its own field and words. Every
  // routes[] row with role "subject" must be some declared subject's peerUid.
  // An orphan subject row is a socket for a caller nobody declared; at zero it
  // would pass authorizeRoute for a /guard nobody can be bound to.
  const declaredPeerUids = new Set(subjects.map((s) => s.peerUid));
  for (const [i, r] of routes.entries()) {
    if (r.role === "subject" && !declaredPeerUids.has(r.uid)) {
      fail(
        `routes[${i}].role`,
        `uid ${r.uid} holds role "subject" but no subjects[] entry declares it as its peerUid ` +
          `(cross-field rule Z2, reverse X6)`
      );
    }
  }

  // Z5 · FORWARD X12 (ticket v2 §2, F-3: at every n). POST /guard may be
  // granted only on a row whose uid is some declared subject's peerUid. Before
  // this any role could hold it (authorizeRoute obeys whatever is granted), so
  // the first of /guard's refusals was declaration content, not a rule. At
  // zero, therefore, no row may hold POST /guard.
  for (const [i, r] of routes.entries()) {
    for (const [j, a] of r.allow.entries()) {
      if (a.method === "POST" && a.path === "/guard" && !declaredPeerUids.has(r.uid)) {
        fail(
          `routes[${i}].allow[${j}]`,
          `uid ${r.uid} (role "${r.role}") is granted POST /guard but is no declared subject's peerUid: ` +
            `/guard may be granted only to a declared subject's peer (cross-field rule Z5, forward X12)`
        );
      }
    }
  }

  // pilot
  const pilotRaw = requireObject(requireField(top, "pilot", "pilot"), "pilot");
  const pilotActive = requireField(pilotRaw, "active", "pilot.active");
  let pilot: PilotDeclared;
  if (pilotActive === false) {
    checkNoUnknown(pilotRaw, ["active"], "pilot");
    pilot = { active: false };
  } else if (pilotActive === true) {
    checkNoUnknown(pilotRaw, ["active", "sessionId", "expiresAt", "holdAtOrAbove"], "pilot");
    const sessionId = requireField(pilotRaw, "sessionId", "pilot.sessionId");
    const expiresAt = requireField(pilotRaw, "expiresAt", "pilot.expiresAt");
    const holdAtOrAboveRaw = requireField(pilotRaw, "holdAtOrAbove", "pilot.holdAtOrAbove");
    if (typeof sessionId !== "string" || sessionId.length === 0) {
      fail("pilot.sessionId", "must be a non-empty string");
    }
    if (typeof expiresAt !== "string" || !EXPIRES_AT_PATTERN.test(expiresAt)) {
      fail(
        "pilot.expiresAt",
        "must be ISO-8601 UTC, second precision, trailing Z (e.g. 2026-09-25T00:00:00Z)"
      );
    }
    const holdAtOrAbove = validateDeclaredString(holdAtOrAboveRaw, "pilot.holdAtOrAbove");
    // X3: pilot.holdAtOrAbove.value in stakes.lineClasses (when active:true)
    if (!isUsableLine(lineClasses, holdAtOrAbove.value)) {
      fail(
        "pilot.holdAtOrAbove",
        `"${holdAtOrAbove.value}" is not a member of stakes.lineClasses (cross-field rule X3; ` +
          `mirrors isUsableLine, chokepoint/types.ts:186-195)`
      );
    }
    pilot = { active: true, sessionId, expiresAt, holdAtOrAbove };
  } else {
    fail("pilot.active", "must be a boolean");
  }
  // Z3 (F-4: refuse). A pilot names a session of a declared subject's conduct;
  // with nothing declared there is no conduct for it to govern, and an ACTIVE
  // pilot over nobody would read on /status as if it governed something.
  if (pilot.active && subjects.length === 0) {
    fail(
      "pilot.active",
      `an active pilot (${pilot.sessionId}) with subjects: [] — nothing is declared for it to govern; ` +
        `declare pilot {"active": false} (cross-field rule Z3)`
    );
  }

  // notice
  const noticeRaw = requireObject(requireField(top, "notice", "notice"), "notice");
  checkNoUnknown(noticeRaw, ["window", "maxPerMinute"], "notice");
  const window = validateDeclaredNumber(requireField(noticeRaw, "window", "notice.window"), "notice.window", {
    integer: true,
    minimum: 1,
  });
  const maxPerMinute = validateDeclaredNumber(
    requireField(noticeRaw, "maxPerMinute", "notice.maxPerMinute"),
    "notice.maxPerMinute",
    { integer: true, minimum: 1 }
  );
  // X9: notice.maxPerMinute.value >= 1 (already enforced above by minimum:1); no relation to window imposed.

  // subjectLog (AMENDMENT 9 / RULING Q) — bounds the unacknowledged backlog
  // that POST /subject-events' 503 RECORD_NOT_PERSISTED is retryable-and-owed
  // against. Named "subjectLog" at the top level (not "readers" or "notice")
  // because it governs a write path, not a reader threshold or a notify rate.
  const subjectLogRaw = requireObject(requireField(top, "subjectLog", "subjectLog"), "subjectLog");
  checkNoUnknown(subjectLogRaw, ["maxUnacknowledged", "chainBoundary"], "subjectLog");
  const maxUnacknowledged = validateDeclaredNumber(
    requireField(subjectLogRaw, "maxUnacknowledged", "subjectLog.maxUnacknowledged"),
    "subjectLog.maxUnacknowledged",
    { integer: true, minimum: 1 }
  );

  // ACT A / ruling 3 — the boundary record's own facts. Validated here for
  // SHAPE; the SERVICE re-reads the retired file and refuses to write a
  // boundary that disagrees with disk. A declaration is a broadcast; disk is
  // the test (register §E.1).
  const boundaryRaw = requireObject(
    requireField(subjectLogRaw, "chainBoundary", "subjectLog.chainBoundary"),
    "subjectLog.chainBoundary"
  );
  checkNoUnknown(
    boundaryRaw,
    ["retiredPath", "retiredRecords", "retiredBytes", "retiredSha256"],
    "subjectLog.chainBoundary"
  );
  const retiredPath = validateDeclaredString(
    requireField(boundaryRaw, "retiredPath", "subjectLog.chainBoundary.retiredPath"),
    "subjectLog.chainBoundary.retiredPath",
    { allowEmpty: true }
  );
  const retiredRecords = validateDeclaredNumber(
    requireField(boundaryRaw, "retiredRecords", "subjectLog.chainBoundary.retiredRecords"),
    "subjectLog.chainBoundary.retiredRecords",
    { integer: true, minimum: 0 }
  );
  const retiredBytes = validateDeclaredNumber(
    requireField(boundaryRaw, "retiredBytes", "subjectLog.chainBoundary.retiredBytes"),
    "subjectLog.chainBoundary.retiredBytes",
    { integer: true, minimum: 0 }
  );
  const retiredSha256 = validateDeclaredString(
    requireField(boundaryRaw, "retiredSha256", "subjectLog.chainBoundary.retiredSha256"),
    "subjectLog.chainBoundary.retiredSha256",
    { allowEmpty: true }
  );
  // X14 (ACT A): FIRST BOOT is all-or-nothing. A declaration that names no
  // retired file but carries its record count is two facts disagreeing, and the
  // boundary record would then carry one of them into the chain forever.
  //
  // ⛔ NUMBERED X14, NOT X10. Act A wrote this as X10, which was already taken by
  //    ruling O's "no route row may name uid 0" — and both refusal messages said
  //    "cross-field rule X10", so an operator reading one could not tell which rule
  //    had fired. Cross-field rules are cited BY NUMBER in the text a refusal hands
  //    back, so a collision is not a tidiness problem: it makes the citation useless
  //    at exactly the moment someone needs it. X1–X13 were in use; this is X14.
  const firstBoot = retiredPath.value === "";
  // ⛔ X15 (2026-09-28, Codex's re-read condition 1): AN EMPTY retiredPath IS
  //    REFUSED AT THIS DOOR. FIRST BOOT is not declarable here any more.
  //
  // WHY A REFUSAL AND NOT BETTER PROSE. The rotation branch of
  // `writeChainBoundaryIfNeeded` re-reads the named file and refuses any
  // disagreement in records, bytes or sha256 — "a declaration is a broadcast and
  // disk is the test". The empty-path branch checked NOTHING and wrote
  // "this chain replaced nothing, and that is a declared fact, not an absent
  // field" into the one record that can never be corrected. Softening that
  // sentence while still appending `retired: null` would leave the machine's own
  // TYPE asserting genuine first boot, which is the part that is unproved.
  //
  // AND IT IS UNPROVABLE AT THAT POINT, not merely unchecked: the evidence of
  // what came before is exactly what the rotation moved out of view. A predecessor
  // may have been renamed elsewhere, deleted, unmounted, or hidden from this view.
  // So no check available here can turn "" into a fact, and a check that looked
  // like verification would be worse than the honest hole.
  //
  // WHAT THIS DOES NOT DECIDE: what evidence would authorise a factual first-boot
  // claim on a genuinely new installation. That is a separate ruling, deliberately
  // not made here. Until it is made, this deployment's boundary must name the
  // measured rotated file — and a future design may represent an unknown
  // predecessor as UNKNOWN rather than encoding it as `retired: null`, which today
  // means "none existed".
  if (firstBoot) {
    fail(
      "subjectLog.chainBoundary.retiredPath",
      'must name the retired file; "" (FIRST BOOT) is refused by this bridge (cross-field rule X15). ' +
        'A boundary record saying "this chain replaced nothing" is unverifiable at the moment it is ' +
        "written, because the predecessor is exactly what the rotation moved out of view — and it enters " +
        "a tamper-evident chain that cannot be corrected. Rotate the subject log to " +
        "subject-events.<YYYYMMDD-HHMMSS>.pre-chain-boundary.jsonl, measure it with every writer " +
        "stopped, and declare that path with its records, bytes and sha256."
    );
  }
  // X14 (ACT A) is kept below for the non-empty case only. Its FIRST BOOT arm —
  // "" requires 0/0/"" — is now unreachable through this function, and it is NOT
  // left sitting here as a guard that can never fire: X15 above supersedes it, and
  // if X15 is ever relaxed, X14's arm must be restored WITH it, in the same commit.
  if (!firstBoot) {
    if (!/^\/var\/lib\/mica-bridge\/[A-Za-z0-9_./-]+$/.test(retiredPath.value)) {
      fail("subjectLog.chainBoundary.retiredPath", "must be an absolute path under /var/lib/mica-bridge/ (X15 refuses \"\"; see above)");
    }
    if (!/^[0-9a-f]{64}$/.test(retiredSha256.value)) {
      fail("subjectLog.chainBoundary.retiredSha256", "must be 64 lower-case hex characters when a file is named");
    }
  }

  // paths
  const pathsRaw = requireObject(requireField(top, "paths", "paths"), "paths");
  const PATH_KEYS = ["journal", "eventBook", "subjectLog", "decisionEvents", "floorTrail", "ledger", "history", "noticeDir"] as const;
  // ── ACT B · paths.clerkStamps — OPTIONAL, AND OPTIONAL IS THE POINT ─────────
  //
  //   Sig's F3 leg reads clerk arrival stamps. The stamps themselves are REFUSED
  //   from a config file (`to-sensor-config.ts`: "clerkClockSource is not accepted
  //   from a config file") and always will be — a reader's evidence is not a
  //   declarable value. But the PATH the bridge reads them from is a deployment
  //   fact exactly like `paths.subjectLog`, and it belongs where the other eight
  //   live.
  //
  //   ⛔ WHY DECLARED AND NOT DERIVED BY CONVENTION. The alternative was to look
  //   beside `paths.subjectLog` and read whatever is there. That would have F3
  //   reading a file THE DECLARATION DOES NOT NAME — which is the shape route #10
  //   punished on 2026-09-28, where a reader's window was a fact about a file
  //   nobody re-derived. A reader reads what the declaration says it reads.
  //
  //   ABSENT IS TODAY'S BEHAVIOUR AND IS NOT A DEFAULT: no path, no
  //   `clerkClockSource`, F3 NOT_CONFIGURED and disclosed as such. It is optional
  //   so that this bridge relay changes NOTHING until a declaration act adds it.
  const OPTIONAL_PATH_KEYS = ["clerkStamps", "witnessIntake", "witnessBook"] as const;
  // ── GATE 1 · paths.interestBook — OPTIONAL, A PLAIN STRING, A BRIDGE-OWNED FILE ─
  //
  //   Round 2 (placement D): Gate 1's labels go to their own chained file instead
  //   of riding on TOOL_ATTEMPTED's outcome. The bridge WRITES it, so it takes the
  //   eight required paths' rule (a plain string under /var/lib/mica-bridge/, X7)
  //   and NOT clerkStamps' envelope — the envelope exists for the one path that
  //   names ANOTHER principal's output, and this is not that.
  //   Optional so that a declaration without Gate 1 hashes as before; X22 below
  //   makes it REQUIRED once a frame or readers.gate1Scope is declared.
  //   ROUND 3 (A4, reviews K2W-5, K3D2-5, K3D1-5, K3D2-6): it NO LONGER shares
  //   the eight paths' lock. That lock admits "..", a sub-directory, the state
  //   dir itself ("/var/lib/mica-bridge/."), another store's `<path>.lock`
  //   sibling (the book's boundary then held the subject chain's lock for ever:
  //   every act 503) and the R6 salt file (the book's boundary written into
  //   the salt before it was minted: no fingerprint all start). The book's own
  //   pattern below is ONE FLAT `*.jsonl` FILE DIRECTLY IN THE STATE DIR, first
  //   character a letter, digit or "_": no "/", so no sub-directory and no
  //   ".."; never ".lock" or ".quarantine"; never the salt. Loader and schema
  //   carry the same pattern. The eight required paths keep their old lock —
  //   pre-existing, disclosed, not widened here.
  const OPTIONAL_PLAIN_PATH_KEYS = ["interestBook"] as const;
  const INTEREST_BOOK_PATTERN = /^\/var\/lib\/mica-bridge\/[A-Za-z0-9_][A-Za-z0-9_.-]*\.jsonl(?![\s\S])/;
  checkNoUnknown(pathsRaw, [...PATH_KEYS, ...OPTIONAL_PATH_KEYS, ...OPTIONAL_PLAIN_PATH_KEYS], "paths");
  const paths: Record<string, string> = {};
  const optionalPaths: Record<string, { value: string; basis: string }> = {};
  const PATH_VALUE_PATTERN = /^\/var\/lib\/mica-bridge\/[A-Za-z0-9_./-]+$/;
  for (const key of PATH_KEYS) {
    const value = requireField(pathsRaw, key, `paths.${key}`);
    if (typeof value !== "string" || !PATH_VALUE_PATTERN.test(value)) {
      fail(`paths.${key}`, "must be a string under /var/lib/mica-bridge/");
    }
    paths[key] = value;
  }
  for (const key of OPTIONAL_PLAIN_PATH_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(pathsRaw, key)) continue;
    const value = (pathsRaw as Record<string, unknown>)[key];
    if (typeof value !== "string" || !INTEREST_BOOK_PATTERN.test(value)) {
      fail(
        `paths.${key}`,
        `must be a string under /var/lib/mica-bridge/ naming ONE FLAT .jsonl FILE directly in it, matching ` +
          `${INTEREST_BOOK_PATTERN.source} — no sub-directory, no "." or ".." name, never a .lock or ` +
          `.quarantine sibling or the salt file (declared ${JSON.stringify(value)})`
      );
    }
    paths[key] = value;
  }
  // ⛔ THE ONE DECLARED PATH THE BRIDGE READS INSTEAD OF WRITES, AND IT NEEDS ITS
  //    OWN PATTERN FOR EXACTLY THAT REASON.
  //
  //    Every one of the eight required paths is a file THIS bridge owns and
  //    writes, so `^/var/lib/mica-bridge/` is not a formatting rule — it is the
  //    statement that the bridge writes only into its own directory.
  //
  //    The clerk stamps are the opposite: they are written by the CLERK CARRIER
  //    (unit `mica-clerk-caller.service`, uid `mica`) into the MACHINE's
  //    directory — Act B's own unit says `--second-stamps-out
  //    /var/lib/mica/clerk-subject-stamps.jsonl`. Forcing that under
  //    /var/lib/mica-bridge/ would mean giving another principal WRITE access to
  //    this bridge's directory, which is a larger custody act than the read ACL
  //    Act B actually asks for (`setfacl -m u:mica:r …`). The narrower fact is
  //    the true one: THIS PATH IS AN INPUT FROM ANOTHER PRINCIPAL, and it is the
  //    only one here that is.
  //
  //    Both roots, and nothing else. A path outside them is still refused.
  const READ_PATH_VALUE_PATTERN = /^\/var\/lib\/mica(-bridge)?\/[A-Za-z0-9_./-]+$/;

  // ── CANONICALISE BEFORE CHECKING, OR THE CHECK IS A SPELLING TEST ───────────
  //
  //   Codex, 2026-09-28: the read-root pattern must be applied to a CANONICAL
  //   path, or `/var/lib/mica-bridge/../../../etc/shadow` passes it — every
  //   character is in the allowed class and the string starts with the allowed
  //   root — and a symlink under an allowed root reaches anywhere at all.
  //
  //   ⛔ IT CANNOT USE realpathSync ON THE PATH ITSELF. A declared stamps file
  //   legitimately may not exist yet: the carrier has not run, and ABSENT is its
  //   designed first state. realpathSync would throw ENOENT and refuse a
  //   perfectly good declaration. So: collapse `.`/`..` lexically, then resolve
  //   symlinks on the deepest ancestor that DOES exist and re-join the rest.
  //   Traversal dies in the first step, aliases in the second, and a file that
  //   does not exist yet is still declarable.
  // ── A DECLARED PATH IS A NAME, NOT A ROUTE (Codex, 2026-09-28, second read) ──
  //
  //   The first fix collapsed `..` and then RESOLVED symlinks on the deepest
  //   existing ancestor. It had a hole: `existsSync` FOLLOWS symlinks, so a
  //   DANGLING one reports false, the walk treats it as "does not exist yet",
  //   climbs straight past it, and the link is never resolved and never refused.
  //   A dangling symlink that is later created points wherever its owner chose.
  //
  //   ⛔ SO SYMLINKS ARE REFUSED OUTRIGHT RATHER THAN RESOLVED, and that is the
  //   better rule anyway. Resolving asks "where does this go TODAY", which is a
  //   question whose answer can change after the declaration is signed. Refusing
  //   asks "is this a name", which cannot. A declared path names a file; it does
  //   not describe a route to one.
  //
  //   Every ancestor is walked with lstat (which does NOT follow), so a dangling
  //   link, a live link and a link to a legitimate target are all refused alike.
  //   A component that does not exist at all is fine — a stamps file legitimately
  //   may not exist yet, and ABSENT is its designed first state.
  const symlinkComponent = (raw: string): string | null => {
    const lexical = resolvePath(raw);
    const parts: string[] = [];
    let cur = lexical;
    while (true) {
      parts.unshift(cur);
      const parent = dirname(cur);
      if (parent === cur) break;
      cur = parent;
    }
    for (const component of parts) {
      try {
        if (lstatSync(component).isSymbolicLink()) return component;
      } catch (err) {
        // ⛔ ONLY ENOENT MEANS "ABSENT". EVERYTHING ELSE REFUSES (Codex, third read).
        //
        //   A bare catch here read EVERY error as "this component does not exist",
        //   so EACCES — a directory this process may not stat — became a silent
        //   pass, and the one case where we CANNOT SEE what a component is was the
        //   one case we treated as harmless. That is a fail-open in the middle of a
        //   check whose entire job is to refuse what it cannot vouch for.
        //
        //   ENOENT is genuinely absent: nothing below it can exist either, so there
        //   is nothing further to refuse and the walk stops. Any other errno means
        //   the answer is UNKNOWN, and unknown is refused.
        const code = (err as NodeJS.ErrnoException)?.code;
        if (code === "ENOENT") break;
        return `${component} (cannot be checked: ${String(code ?? err)})`;
      }
    }
    return null;
  };

  /** Lexical only. Symlinks are refused, not resolved, so `..` is all that remains. */
  const canonicalisePath = (raw: string): string => resolvePath(raw);

  for (const key of OPTIONAL_PATH_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(pathsRaw, key)) continue;
    // ⛔ AN ENVELOPE, NOT A BARE STRING (the arbiter, 2026-09-28). The eight required
    //   paths stay plain strings; this one carries its own basis, because it is the
    //   only one naming a file another principal writes. A bare string here is
    //   REFUSED rather than accepted-and-undocumented: the whole reason to widen
    //   the shape was that this path must say why it is trusted.
    const envelope = (pathsRaw as Record<string, unknown>)[key];
    if (typeof envelope !== "object" || envelope === null || Array.isArray(envelope)) {
      fail(`paths.${key}`, 'must be an object { "value": "<path>", "basis": "<why>" }, not a bare string');
    }
    checkNoUnknown(envelope as Record<string, unknown>, ["value", "basis"], `paths.${key}`);
    const basis = (envelope as Record<string, unknown>).basis;
    if (typeof basis !== "string" || basis.trim().length < 80) {
      fail(
        `paths.${key}.basis`,
        "must be a string of at least 80 characters. This is the one path in this block that names " +
          "another principal's output, and an undocumented one is the thing the envelope exists to refuse"
      );
    }
    const value = (envelope as Record<string, unknown>).value;
    if (typeof value !== "string") {
      fail(`paths.${key}.value`, "must be a string under /var/lib/mica/ or /var/lib/mica-bridge/");
    }
    const canonical = canonicalisePath(value as string);
    const link = symlinkComponent(value as string);
    if (link !== null) {
      fail(
        `paths.${key}`,
        `must not traverse a symbolic link, and every component must be checkable: ` +
          `${JSON.stringify(link)}. A declared path is a NAME, not a route — where a link points ` +
          `can change after the declaration is signed, and a component that cannot be stat'd is ` +
          `refused rather than assumed absent.`
      );
    }
    // BOTH forms must satisfy the root. The raw one so a declaration cannot
    // SPELL its way out, the lexical one so it cannot WALK its way out.
    if (!READ_PATH_VALUE_PATTERN.test(value as string) || !READ_PATH_VALUE_PATTERN.test(canonical)) {
      fail(
        `paths.${key}.value`,
        `must be a string under /var/lib/mica/ or /var/lib/mica-bridge/ ` +
          `(declared ${JSON.stringify(value)}, canonicalises to ${JSON.stringify(canonical)})`
      );
    }
    optionalPaths[key] = { value: value as string, basis: basis as string };
  }
  // X7: all eight paths values distinct (AMENDMENT 9 widened this from seven
  // — H-1's decisionEvents path must not collide with eventBook's, which is
  // the whole point of giving it its own key: two books, two schemas, two
  // owners, one writer each).
  // X7 covers the optional key TOO when it is present: a clerk-stamps path that
  // collided with the subject log would have the carrier and the reader writing
  // and reading one file, which is the collision X7 exists to refuse.
  // ⛔ X7 COMPARES CANONICAL FORMS, NOT SPELLINGS. Two declarations naming ONE
  //   file by different routes — a `..` hop, a symlink — would otherwise read as
  //   distinct and defeat the rule. The STORED values stay exactly as declared,
  //   so no declaration's canonicalHash moves for this; only the comparison is
  //   canonical.
  const pathValues = [
    ...[...PATH_KEYS, ...OPTIONAL_PLAIN_PATH_KEYS].filter((k) => paths[k] !== undefined).map((k) => canonicalisePath(paths[k])),
    ...OPTIONAL_PATH_KEYS.filter((k) => optionalPaths[k] !== undefined).map((k) =>
      canonicalisePath(optionalPaths[k].value)
    ),
  ];
  // ⛔ S216-2 · NO DECLARED PATH MAY NAME THE GRANT MEMORY. The memory (grant-memory.ts) is the bridge's own state at
  //   /var/lib/mica-bridge/grant-memory, NOT a declared path, so a declaration cannot move it across a restart. The
  //   eight required paths' older lock can still name anything under the state dir (disclosed above), so a declared
  //   path whose canonical form is the memory, its `.lock`, a set-aside copy (`grant-memory.torn-*`,
  //   `grant-memory.unreadable-*`), a seed dot-temp (`.grant-memory.seed-*`) or anything beneath such a name is
  //   refused HERE. This is a refusal of a DECLARATION (at a first load a StartupRefused, as every loader refusal is),
  //   never a refusal on the memory's own state, which never stops the guard.
  for (const v of pathValues) {
    if (/^\/var\/lib\/mica-bridge\/\.?grant-memory(?:$|[./-])/.test(v)) {
      fail(
        "paths",
        `a declared path names the bridge's grant memory, its lock or one of its set-aside or seed files (canonical ` +
          `${JSON.stringify(v)}): the memory is the bridge's own state, never a declared path (S216-2)`
      );
    }
  }
  if (new Set(pathValues).size !== pathValues.length) {
    fail("paths", "all declared paths values must be distinct after canonicalisation (cross-field rule X7)");
  }
  // X7, THE BOOK'S SIBLINGS (round 3, A4). The book's own pattern keeps IT off
  // every `.lock`/`.quarantine` name; this keeps every OTHER declared path off
  // the book's: the book's appender takes `<book>.lock` and quarantines a torn
  // tail to `<book>.quarantine`, so a declared file of that name would be
  // created, held or truncated by the book's machinery. And the book is not the
  // RETIRED chain file the subject log's boundary names (K3D2-5: every label
  // then failed against bytes it must not touch). The eight required paths'
  // OWN sibling collisions are pre-existing and are not closed here.
  if (paths["interestBook"] !== undefined) {
    const book = canonicalisePath(paths["interestBook"]);
    const siblings = new Set([`${book}.lock`, `${book}.quarantine`]);
    const sib = pathValues.find((v) => siblings.has(v));
    if (sib !== undefined) {
      fail(
        "paths",
        `${JSON.stringify(sib)} is the interest book's own lock or quarantine sibling: the book's appender ` +
          `would take or truncate that file (cross-field rule X7)`
      );
    }
    if (retiredPath.value !== "" && canonicalisePath(retiredPath.value) === book) {
      fail(
        "paths.interestBook",
        "names the RETIRED subject chain (subjectLog.chainBoundary.retiredPath): the book would append to " +
          "bytes the boundary vouches for as closed (cross-field rule X7)"
      );
    }
    // X23 (round 3, A5, review K1R2-4). readers.logPath is what every SIBLING
    // reader reads (Eng, Sig, op3, narrow-*). Pointed at the book, they would
    // read Gate 1's labels as subject acts — exactly the exposure placement D
    // exists to prevent. Compared in canonical form, like X7.
    if (canonicalisePath(logPath.value) === book) {
      fail(
        "readers.logPath",
        `names the interest book (paths.interestBook, ${JSON.stringify(paths["interestBook"])}): every ` +
          `sibling reader would read Gate 1's labels as its subject log, the exposure placement D exists ` +
          `to prevent (cross-field rule X23)`
      );
    }
  }

  // ── TIER 1 · the witness's paths: ANOTHER PRINCIPAL'S, and kept apart ───────
  //
  // W1 · under /var/lib/mica/ ONLY: the intake and the book are the WITNESS'S,
  //      and the bridge's own directory is where it writes for itself.
  // W2 · the book is one .jsonl file, never inside the intake (a sweep would
  //      take the book for a drop).
  // W3 · X23's twin: readers.logPath never names the book — every sibling reads
  //      the log, and the book's records are the witness's, not the subject's.
  // W4 · the book's .lock / .quarantine siblings are no other declared path.
  // Compared in canonical form, like X7 and X23.
  {
    const WITNESS_ROOT = /^\/var\/lib\/mica\/[A-Za-z0-9_][A-Za-z0-9_./-]*$/;
    for (const key of ["witnessIntake", "witnessBook"] as const) {
      const e = optionalPaths[key];
      if (e === undefined) continue;
      const c = canonicalisePath(e.value);
      if (!WITNESS_ROOT.test(e.value) || !WITNESS_ROOT.test(c)) {
        fail(`paths.${key}.value`, `must be under /var/lib/mica/ — the witness's own directory, never the bridge's (declared ${JSON.stringify(e.value)}) (cross-field rule W1)`);
      }
    }
    const book = optionalPaths["witnessBook"];
    if (book !== undefined) {
      const b = canonicalisePath(book.value);
      if (!b.endsWith(".jsonl")) fail("paths.witnessBook.value", "must name one .jsonl file (cross-field rule W2)");
      const intake = optionalPaths["witnessIntake"];
      if (intake !== undefined) {
        const i = canonicalisePath(intake.value);
        if (b === i || b.startsWith(`${i}/`)) {
          fail("paths.witnessBook", "must not lie inside paths.witnessIntake: the witness sweeps its intake and would take the book for a drop (cross-field rule W2)");
        }
      }
      if (canonicalisePath(logPath.value) === b) {
        fail(
          "readers.logPath",
          `names the witness's book (paths.witnessBook, ${JSON.stringify(book.value)}): every sibling reader would read ` +
            `the witness's records as its subject log (cross-field rule W3, X23's twin)`
        );
      }
      const siblings = new Set([`${b}.lock`, `${b}.quarantine`]);
      const sib = pathValues.find((v) => siblings.has(v));
      if (sib !== undefined) {
        fail("paths", `${JSON.stringify(sib)} is the witness book's own lock or quarantine sibling (cross-field rule W4)`);
      }
    }
  }

  // ── Gate 1 · frame, OPTIONAL, then X20 (gate1Scope names a framed subject) ──
  const frame = top.frame === undefined ? undefined : validateFrame(top.frame, subjects);
  if (gate1Scope !== undefined) {
    const s = gate1Scope.subject.value;
    // X20. Both halves, in this order, because they are different mistakes: a
    // name that is no subject at all is a typo; a subject without a frame is a
    // reader switched on before the thing it reads was declared.
    if (!seenSubjectNames.has(s)) {
      fail(
        "readers.gate1Scope.subject",
        `"${s}" is not a declared subjects[].subject (cross-field rule X20)`
      );
    }
    if (frame === undefined || !Object.hasOwn(frame, s)) {
      fail(
        "readers.gate1Scope.subject",
        `subject "${s}" has no frame.${s}: the reader reads a declared M-frame and there is none, so ` +
          `it would read CANNOT_ASSESS(G1_FRAME_ABSENT) for ever while the census listed it declared ` +
          `(cross-field rule X20). Declare frame.${s} first, or omit readers.gate1Scope.`
      );
    }
    // X22 (round 2, placement D). The reader reads the INTEREST BOOK, not the
    // subject chain; a reader switched on with no book declared would have no
    // file to read and would sit UNWIRED while the census listed it declared.
    // Cited at paths.interestBook, the key that is missing.
    if (paths["interestBook"] === undefined) {
      fail(
        "paths.interestBook",
        `readers.gate1Scope is declared, so paths.interestBook is required: the reader counts the labels ` +
          `the bridge writes to the interest book, and with no book declared there is nothing to write ` +
          `them to or read them from (cross-field rule X22). Declare paths.interestBook, or omit readers.gate1Scope.`
      );
    }
  }
  // X22, SECOND HALF (round 2, from BRIDGE-2's report). A FRAME alone switches the
  // WRITER on: the bridge derives a label for every act of a framed subject and
  // writes it to the book, whether or not the reader is declared yet (labels
  // gather before the reader is switched on). A frame with no book would lose
  // every one of them, each loudly (INTEREST_LABEL_NOT_PERSISTED per act) but
  // every one. Refused here instead of booked act by act. ⚠ This rule sees ONE
  // declaration; the book is opened only at START. On a SIGHUP the same loss
  // came back through the other door — a bridge started with no book, reloaded
  // to frame + book (review K3D3-2) — and is closed by validateActivation's
  // book rule (round 3, A3), which refuses a reload that adds, moves or removes
  // the book. Together they hold at load, at restart and at reload. Runs AFTER the
  // gate1Scope block so that a reader declared without a frame still reads X20's
  // reason first.
  if (frame !== undefined && paths["interestBook"] === undefined) {
    fail(
      "paths.interestBook",
      `a frame is declared, so the bridge derives a label for every act of a framed subject and writes it ` +
        `to the interest book; with no book declared every label would be lost (cross-field rule X22). ` +
        `Declare paths.interestBook, or omit frame.`
    );
  }

  // ── Gate 2 · baskets, OPTIONAL, then R1 (gate2Direction names a framed, basketed subject) ──
  // TIER 1: the subject whose Gate 2 reads the WITNESS'S BOOK has its classes
  // judged against the book's grammar (R3 re-scoped), not the subject chain's.
  const witnessBookSubjects = new Set<string>(
    gate2Direction !== undefined && gate2Direction.book !== undefined ? [gate2Direction.subject.value] : []
  );
  if (witnessBookSubjects.size > 0 && optionalPaths["witnessBook"] === undefined) {
    fail(
      "readers.gate2Direction.book",
      `Gate 2 is declared to read the witness's book, so paths.witnessBook is required ${g2Rule(16, "a reader reads what the declaration names")}`
    );
  }
  const baskets = top.baskets === undefined ? undefined : validateBaskets(top.baskets, seenSubjectNames, frame, witnessBookSubjects);
  // Long Run A Stop 2 · the harm stanza (H1–H10), before R1, which accepts a basket OR a harm stanza.
  const harm = top.harm === undefined ? undefined : validateHarm(top.harm, seenSubjectNames, frame, gate2Direction);
  if (gate2Direction !== undefined) {
    const s = gate2Direction.subject.value;
    // R1, three halves in this order — three different mistakes: a typo, a
    // reader switched on before its frame, and one switched on before its basket.
    // AMENDED (Long Run A Stop 2, H9): the third half accepts EITHER a class basket
    // OR a harm stanza for the subject — never both (H9, below).
    if (!seenSubjectNames.has(s)) {
      fail("readers.gate2Direction.subject", `"${s}" is not a declared subjects[].subject ${g2Rule(1, "X20's shape")}`);
    }
    if (frame === undefined || !Object.hasOwn(frame, s)) {
      fail(
        "readers.gate2Direction.subject",
        `subject "${s}" has no frame.${s}: Gate 2 reads direction only within a fixed frame (05a:170), so the ` +
          `reader would read CANNOT_ASSESS(G2_FRAME_ABSENT) for ever while the census listed it declared ` +
          `${g2Rule(1, "X22's shape")}. Declare frame.${s} first, or omit readers.gate2Direction.`
      );
    }
    const hasBasket = baskets !== undefined && Object.hasOwn(baskets, s);
    const hasHarm = harm !== undefined && Object.hasOwn(harm, s);
    if (!hasBasket && !hasHarm) {
      fail(
        "readers.gate2Direction.subject",
        `subject "${s}" has no baskets.${s}: the reader reads the deployer's declared basket and there is none, ` +
          `so it would read CANNOT_ASSESS(G2_BASKET_ABSENT) for ever while the census listed it declared ` +
          `${g2Rule(1, "X22's shape")}. Declare baskets.${s} (or harm.${s}) first, or omit readers.gate2Direction.`
      );
    }
    if (hasBasket && hasHarm) {
      fail(
        `harm.${s}`,
        `subject "${s}" declares BOTH baskets.${s} and harm.${s} for Gate 2: the harm stanza REPLACES the class ` +
          `basket, and a reader handed both would have to choose ${hRule(9, "harm replaces the class basket; R1 accepts either, never both")}`
      );
    }
  }

  // Each optional block is SPREAD IN ONLY WHEN PRESENT, never assigned as
  // `undefined`. See the block's own comment above: an absent key and a key set
  // to undefined hash the same under canonical-json's rule 4, but they do NOT
  // read the same to `checkNoUnknown` on a round trip, and they do not read the
  // same to `toWireOptions`, which gates the machine's wiring on presence.
  const readers: Declarations["readers"] = {
    readableLoadStates,
    logPath,
    logKind,
    // Spread, not `minimumClassCoverage: undefined` — `canonicalHash` omits
    // absent and undefined alike, but the OPTIONAL type and the sensor's
    // "absent" arm are both written against the key not being there.
    eng: {
      structureThreshold,
      minimumSampleSize,
      ...(minimumClassCoverage === undefined ? {} : { minimumClassCoverage }),
    },
    sig: {
      clockToleranceMs,
      clockToleranceBasis,
      preconditionMap,
      reentryMap,
      ...(clerkStampLag === undefined ? {} : { clerkStampLag }),
    },
    ...(narrowK === undefined ? {} : { narrowK: narrowK as Declarations["readers"]["narrowK"] }),
    ...(narrowW === undefined ? {} : { narrowW: narrowW as Declarations["readers"]["narrowW"] }),
    ...(narrowR === undefined ? {} : { narrowR: narrowR as Declarations["readers"]["narrowR"] }),
    ...(narrowT === undefined ? {} : { narrowT }),
    ...(doctorCadence === undefined ? {} : { doctorCadence }),
    // H12: the KEY ITSELF is absent when the block was not declared — spread,
    // never `nodeResponse: undefined`. `canonicalHash` treats undefined and
    // absent identically (canonical-json.ts rule 4), so both forms hash the
    // same today; the spread is what keeps that true of `Object.keys` and of
    // anything that ever iterates this object without consulting that rule.
    // The same reasoning covers the four keys above it.
    ...(nodeResponse === undefined ? {} : { nodeResponse }),
    ...(gate4Sunset === undefined ? {} : { gate4Sunset }),
    ...(gate1Scope === undefined ? {} : { gate1Scope }),
    ...(gate2Direction === undefined ? {} : { gate2Direction }),
  };

  return {
    schemaVersion: 1,
    readers,
    stakes: {
      lineClasses,
      baseline: { holdAtOrAbove: baselineHoldAtOrAbove },
    },
    subjects,
    routes,
    pilot,
    notice: { window, maxPerMinute },
    subjectLog: {
      maxUnacknowledged,
      chainBoundary: { retiredPath, retiredRecords, retiredBytes, retiredSha256 },
    },
    // the eight required strings plus, when declared, the one envelope
    paths: { ...paths, ...optionalPaths } as unknown as Declarations["paths"],
    // ⛔ INSIDE THE RETURNED OBJECT OR OUTSIDE THE HASH. `declarationHash` is the
    //    canonicalHash of what this function returns, so a validated frame left
    //    off it would steer every TOOL_ATTEMPTED's label while no decision bound
    //    itself to it. Spread, never `frame: undefined`, so an undeclared frame
    //    leaves the digest exactly where it was.
    ...(frame === undefined ? {} : { frame }),
    // Gate 2: the same rule — inside the digest when declared, absent when not.
    ...(baskets === undefined ? {} : { baskets }),
    // Gate 2 · harm (Long Run A Stop 2): the same rule again.
    ...(harm === undefined ? {} : { harm }),
  };
}

// ── Gate 1 · the frame validator ─────────────────────────────────────────────

/**
 * The word the bridge writes to the interest book for a TOOL_ATTEMPTED whose
 * target it could not place in any declared region.
 *
 * ⛔ SPELT AS A LITERAL, NOT IMPORTED. Written for the DOCTOR_ATTESTED reason
 *    (no value import toward mica-service's neighbourhood); round 3 imports
 *    `segmentIsNotAPath` from the label module after all — a predicate is code,
 *    and one behaviour arm cannot hold two copies of a regex together — and
 *    that edge is safe only while interest-label.ts has no runtime import (its
 *    purity fence). The WORD stays a literal: one arm holds it, by behaviour.
 *    The authority is `INTEREST_UNDERIVED` in interest-label.ts; the suite
 *    asserts the two agree by DECLARING the label module's word as a category
 *    id and requiring the refusal, so drift fails there.
 */
const FRAME_UNDERIVED_WORD = "UNDERIVED";
const FRAME_GROUNDINGS = ["vulnerability", "agency", "need"] as const;

/**
 * Why a region prefix cannot be matched honestly, or null. The first four rules
 * mirror the schema's `prefix` pattern; the fifth is LOADER-ONLY.
 */
function framePrefixDefect(prefix: string): string | null {
  if (prefix === "/") return null;
  if (!prefix.startsWith("/")) return 'must be absolute (start with "/")';
  if (prefix.includes("//")) return 'must not contain "//"';
  if (prefix.endsWith("/")) return 'must not end in "/" unless it is exactly "/"';
  // ⛔ "." AND ".." ARE REFUSED, NOT RESOLVED. The bridge matches prefixes against
  //    a canonical target that does NOT resolve them (no filesystem: ProtectHome,
  //    PrivateTmp), so a region spelt through `..` would claim a place it is not.
  if (prefix.slice(1).split("/").some((seg) => seg === "." || seg === "..")) {
    return 'must not contain a "." or ".." segment';
  }
  // ⛔ A SEGMENT THE LABEL RULE REFUSES IS A DEAD REGION (round 3, A2; reviews
  //    K2W-2, K3D2-1, K1R1-2, K1R2-1, K1R3-1, K2W-3, K2W3-4). deriveInterestLabel
  //    reads UNDERIVED for any target with a not-a-path segment — and every
  //    target at or under this prefix carries the prefix's own segments — so
  //    such a region could never place one act, while the wiring counted its
  //    category derivable and the reader printed its permanent zero as a
  //    reading. Real directory names hit it: `Program Files (x86)`, `R&D`,
  //    `year=2024`, `~archive`, `node:20`. Refused with the label module's OWN
  //    predicate. LOADER-ONLY (the schema does not restate it).
  const dead = prefix.slice(1).split("/").find(segmentIsNotAPath);
  if (dead !== undefined) {
    return (
      `must not contain a segment the label rule reads as NOT A PATH (${JSON.stringify(dead)}: a ":" ` +
      `anywhere, whitespace, a leading "-", "+" or "~", or a shell metacharacter) — every target under it would read ` +
      `UNDERIVED, so the region would be DEAD while its category counted derivable`
    );
  }
  return null;
}

/**
 * Validates top-level `frame` against the already-validated `subjects`.
 * First offender, schema order: the frame key, then categories (value, basis,
 * proxy), then regions (value, basis, proxy).
 *
 * WHAT IS REFUSED, AND WHY EACH ONE IS A REFUSAL RATHER THAN A WARNING:
 *   · an EMPTY frame (`{}`) — it would move declarationHash and declare nothing.
 *   · X16 — a frame for an undeclared subject is a frame nothing will ever label.
 *   · fewer than 2 categories — a one-category M has no distribution to read.
 *   · `__proto__` as a frame key (R-a): canonical-json would drop it from the hash.
 *   · X17 — a category id equal to `UNDERIVED` or to ANY declared toolName. The
 *     underived word is the book's word for "placed nowhere", so a category of
 *     that name would count those acts as its cases. The toolName half is KEPT
 *     from round 1 although placement D took the label off TOOL_ATTEMPTED's
 *     outcome: the subject chain still carries the toolName as that outcome, and
 *     a category spelt the same would read, on any surface that shows both, as
 *     the tool's own outcome. Keeping a refusal costs a rename; dropping one is a
 *     widening nobody asked for.
 *   · an UNTAGGED category. `grounding` is a DECLARED TAG (R-d): the loader
 *     checks the word, never that the category grounds operationally (03a §6).
 *   · X18 — not EXACTLY ONE `self`. The FAIL floor is defined on the self
 *     category; with none or two, the floor has no subject. (It is not read
 *     today — it needs weight — but a frame that cannot carry it is malformed.)
 *   · regions: a prefix that cannot be matched honestly (including one with a
 *     segment the label rule reads as not a path — a dead region, round 3), a
 *     prefix that is not ITS OWN CANONICAL FORM (R-b), a duplicate prefix (two categories for one
 *     place), and X19 — a region naming no declared category, which would write
 *     a label M does not contain.
 *
 * ⚠ REGIONS MAY BE EMPTY. Then nothing is derivable and every label is
 *   UNDERIVED. That is legal and honest — the reader prints the derivable
 *   ceiling as 0 of n — and refusing it would force a deployer to invent a
 *   region to get a frame declared.
 */
function validateFrame(raw: unknown, subjects: readonly Subject[]): Readonly<Record<string, SubjectFrame>> {
  const frameRaw = requireObject(raw, "frame");
  // ⛔ AN EMPTY FRAME IS REFUSED. `"frame": {}` would move declarationHash and
  //    declare nothing: a field that looks configured and frames no subject.
  //    Omit the key instead (absent -> absent, the hash does not move). The
  //    schema says the same with minProperties: 1.
  if (Object.keys(frameRaw).length === 0) {
    fail("frame", "must frame at least one declared subject; an empty frame declares nothing — omit the key instead");
  }
  const declaredSubjects = new Set(subjects.map((s) => s.subject));
  const toolNames = new Set(subjects.map((s) => s.toolName));
  const out: [string, SubjectFrame][] = [];
  for (const key of Object.keys(frameRaw)) {
    const field = `frame.${key}`;
    // R-a, BEFORE X16: the subject refusal already makes this name undeclarable,
    // but the reason a reader needs is canonical-json's, not "no such subject".
    if (key === PROTO_KEY) {
      fail(field, PROTO_KEY_REASON);
    }
    if (!declaredSubjects.has(key)) {
      fail(field, `"${key}" is not a declared subjects[].subject (cross-field rule X16)`);
    }
    const f = requireObject(frameRaw[key], field);
    checkNoUnknown(f, ["categories", "regions"], field);

    // ── categories ────────────────────────────────────────────────────────
    const cField = `${field}.categories`;
    const c = requireObject(requireField(f, "categories", cField), cField);
    checkNoUnknown(c, ["value", "basis", "proxy"], cField);
    const cValue = requireField(c, "value", `${cField}.value`);
    if (!Array.isArray(cValue) || cValue.length < 2) {
      fail(`${cField}.value`, "must be an array of at least 2 categories — a one-category M has no distribution to read");
    }
    const categories: FrameCategory[] = [];
    const seenIds = new Set<string>();
    for (const [i, itemRaw] of (cValue as unknown[]).entries()) {
      const iField = `${cField}.value[${i}]`;
      const item = requireObject(itemRaw, iField);
      checkNoUnknown(item, ["id", "label", "grounding", "self"], iField);
      const id = requireField(item, "id", `${iField}.id`);
      const label = requireField(item, "label", `${iField}.label`);
      const grounding = requireField(item, "grounding", `${iField}.grounding`);
      const self = requireField(item, "self", `${iField}.self`);
      if (typeof id !== "string" || !IDENT_PATTERN.test(id)) {
        fail(`${iField}.id`, `must be a non-empty string matching ${IDENT_PATTERN}`);
      }
      if (id === FRAME_UNDERIVED_WORD) {
        fail(
          `${iField}.id`,
          `"${FRAME_UNDERIVED_WORD}" is the word written for an act placed in NO region; a category of ` +
            `that name would count underived acts as cases of it (cross-field rule X17)`
        );
      }
      if (toolNames.has(id)) {
        fail(
          `${iField}.id`,
          `"${id}" is a declared subjects[].toolName. The subject chain carries the toolName as every ` +
            `TOOL_ATTEMPTED's outcome, so a category of that name would read, wherever chain and interest ` +
            `book are shown together, as the tool's own outcome (cross-field rule X17)`
        );
      }
      if (seenIds.has(id)) {
        fail(`${iField}.id`, `duplicate category id "${id}"`);
      }
      seenIds.add(id);
      if (typeof label !== "string" || label.length === 0) {
        fail(`${iField}.label`, "must be a non-empty string");
      }
      if (typeof grounding !== "string" || !(FRAME_GROUNDINGS as readonly string[]).includes(grounding)) {
        fail(
          `${iField}.grounding`,
          `must be one of ${FRAME_GROUNDINGS.join(", ")}. This is a DECLARED TAG naming the trait-space the ` +
            `deployer says the category grounds in; the loader checks the word only, NOT that the category ` +
            `grounds operationally (03a §6) — an untagged category is refused, a hollow one is not detected`
        );
      }
      if (typeof self !== "boolean") {
        fail(`${iField}.self`, "must be a boolean");
      }
      categories.push({ id, label, grounding: grounding as FrameCategory["grounding"], self });
    }
    const selfCount = categories.filter((cat) => cat.self).length;
    if (selfCount !== 1) {
      fail(
        `${cField}.value`,
        `exactly one category must carry self: true, found ${selfCount} — the FAIL floor is defined on ` +
          `the self category, and with none or several it has no subject (cross-field rule X18)`
      );
    }
    const cBasis = requireField(c, "basis", `${cField}.basis`);
    const cProxy = requireField(c, "proxy", `${cField}.proxy`);
    if (typeof cBasis !== "string" || cBasis.length === 0) fail(`${cField}.basis`, "must be a non-empty string");
    if (typeof cProxy !== "boolean") fail(`${cField}.proxy`, "must be a boolean");

    // ── regions ───────────────────────────────────────────────────────────
    const rField = `${field}.regions`;
    const r = requireObject(requireField(f, "regions", rField), rField);
    checkNoUnknown(r, ["value", "basis", "proxy"], rField);
    const rValue = requireField(r, "value", `${rField}.value`);
    if (!Array.isArray(rValue)) {
      fail(`${rField}.value`, "must be an array (it may be empty: then every label is UNDERIVED)");
    }
    const regions: FrameRegion[] = [];
    const seenPrefixes = new Set<string>();
    for (const [i, itemRaw] of (rValue as unknown[]).entries()) {
      const iField = `${rField}.value[${i}]`;
      const item = requireObject(itemRaw, iField);
      checkNoUnknown(item, ["prefix", "category"], iField);
      const prefix = requireField(item, "prefix", `${iField}.prefix`);
      const category = requireField(item, "category", `${iField}.category`);
      if (typeof prefix !== "string") fail(`${iField}.prefix`, "must be a string");
      const defect = framePrefixDefect(prefix);
      if (defect !== null) fail(`${iField}.prefix`, `${defect} (declared ${JSON.stringify(prefix)})`);
      // R-b (reviews C3-1, C3-2, C4-1, C4-3). The bridge matches a prefix BYTE FOR
      // BYTE against a target canonicaliseTargetIdentity has already rewritten
      // (NFC, trimmed of Unicode whitespace, C0 and DEL controls refused, capped
      // in bytes), and canonical-json NFC-normalises the prefix before hashing.
      // A prefix that is not its own canonical form is therefore a region no
      // canonical target can ever match (dead, yet counted derivable), and two
      // NFC-equivalent spellings hash ALIKE while labelling DIFFERENTLY — the
      // digest would not bind the bytes that steer the label. So the prefix must
      // already BE its canonical form; the bridge's own canonicaliser decides,
      // not a second copy of its rules. After this, the duplicate check below
      // compares canonical forms, so "one place, two categories" holds for
      // NFC-equivalents too. LOADER-ONLY: JSON Schema cannot state NFC.
      const canon = canonicaliseTargetIdentity(prefix);
      if (!canon.ok) {
        fail(
          `${iField}.prefix`,
          `is refused by the bridge's target canonicaliser (${canon.reason}), so no target could ever ` +
            `match it (declared ${JSON.stringify(prefix)})`
        );
      }
      if (canon.canonical !== prefix) {
        fail(
          `${iField}.prefix`,
          `must equal its own canonical form ${JSON.stringify(canon.canonical)} (NFC, no surrounding ` +
            `whitespace) — the bridge compares prefixes with canonical targets byte for byte, and the hash ` +
            `binds the NFC form, so any other spelling is a dead region or a second name for a declared one ` +
            `(declared ${JSON.stringify(prefix)})`
        );
      }
      if (seenPrefixes.has(prefix)) {
        fail(`${iField}.prefix`, `duplicate prefix ${JSON.stringify(prefix)} — one place, two categories`);
      }
      seenPrefixes.add(prefix);
      if (typeof category !== "string" || !seenIds.has(category)) {
        fail(
          `${iField}.category`,
          `${JSON.stringify(category)} is not a category id of ${cField}; a region naming no declared ` +
            `category would write a label M does not contain (cross-field rule X19)`
        );
      }
      regions.push({ prefix, category });
    }
    const rBasis = requireField(r, "basis", `${rField}.basis`);
    const rProxy = requireField(r, "proxy", `${rField}.proxy`);
    if (typeof rBasis !== "string" || rBasis.length === 0) fail(`${rField}.basis`, "must be a non-empty string");
    if (typeof rProxy !== "boolean") fail(`${rField}.proxy`, "must be a boolean");

    out.push([
      key,
      {
        categories: { value: categories, basis: cBasis, proxy: cProxy },
        regions: { value: regions, basis: rBasis, proxy: rProxy },
      },
    ]);
  }
  // Object.fromEntries DEFINES own properties, so a subject id that collides with
  // an Object.prototype name stays a key and never becomes a prototype.
  return Object.fromEntries(out);
}

// ── Gate 2 · the basket validator (contract §4, refusals R1–R14) ──────────────
//
// FIRST OFFENDER, the stanza's own order: the basket key (R1), its closed key
// set (R14), classes (R2, then each entry in list order, then R13 across the
// lists), epsilonNum, grades, window, nMin (R10), latchClearedBy (R11). Every
// refusal SAYS ITS RULE — `(Gate 2 front-door refusal R<n> — <cite>)` — so a
// reader of a rejected declaration knows which ruling stopped it.
//
// ⚠ WHAT THIS DOOR CANNOT HOLD, stated so nobody relies on it for more: it
//   checks the basket's SHAPE and its admissibility against the kinds this
//   bridge writes. It cannot check that a class means what its basis says, that
//   a weight is calibrated, or that the basket names every way the record could
//   read against the subject — undeclared damage reads clean (05a:216), and
//   the reader prints that ceiling on every verdict.

/** The tag every Gate 2 refusal carries. Tests match `refusal R<n> —`, which no other rule's tag contains. */
function g2Rule(n: number, cite: string): string {
  return `(Gate 2 front-door refusal R${String(n)} — ${cite})`;
}

/**
 * R14 · a closed key set. The rule is named BEFORE `accepted here:` because the
 * schema-parity walk reads the accepted set from what FOLLOWS that phrase.
 */
function checkNoUnknownG2(obj: Record<string, unknown>, allowed: readonly string[], field: string): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) {
      fail(`${field}.${key}`, `unknown field ${g2Rule(14, "every Gate 2 key set is closed")}; accepted here: ${allowed.join(", ")}`);
    }
  }
}

/** R14 · ends in (?![\s\S]), never `$`: Python's re lets `$` match before a final newline (round 3, A7). */
const G2_OUTCOME_PATTERN = /^[A-Za-z0-9_.:-]+(?![\s\S])/;
const G2_SIGNED_KEYS = ["kind", "outcome", "weight", "lane", "eg", "rhoCausal", "falsifiability", "bearsOn", "basis"] as const;
const G2_UNKNOWN_KEYS = ["kind", "outcome", "lane", "eg", "magnitude", "bearsOn", "basis"] as const;
const G2_BASKET_KEYS = ["classes", "epsilonNum", "grades", "window", "nMin", "latchClearedBy"] as const;

/** `{ value, basis, proxy }`, closed; every refusal inside it cites `rule`, except an unknown key (R14). */
function g2Envelope(raw: unknown, field: string, rule: string): { value: unknown; basis: string; proxy: boolean } {
  if (!isPlainObject(raw)) fail(field, `must be an envelope { value, basis, proxy } ${rule}`);
  const env = raw as Record<string, unknown>;
  checkNoUnknownG2(env, ["value", "basis", "proxy"], field);
  if (!Object.hasOwn(env, "value") || env.value === undefined) fail(`${field}.value`, `required field missing ${rule}`);
  if (typeof env.basis !== "string" || env.basis.length === 0) fail(`${field}.basis`, `must be a non-empty string ${rule}`);
  if (typeof env.proxy !== "boolean") fail(`${field}.proxy`, `must be a boolean ${rule}`);
  return { value: env.value, basis: env.basis as string, proxy: env.proxy as boolean };
}

function g2Lane(v: unknown, field: string, rule: string): Gate2Lane {
  if (v !== "A" && v !== "B" && v !== "C") {
    fail(field, `${v === undefined ? "required field missing: " : ""}must be "A", "B" or "C" (measured > inferred > scenario) ${rule}`);
  }
  return v as Gate2Lane;
}

function g2Eg(v: unknown, field: string, rule: string): Gate2Eg {
  if (v !== 0 && v !== 1 && v !== 2 && v !== 3) {
    fail(field, `${v === undefined ? "required field missing: " : ""}must be the integer 0, 1, 2 or 3 (EG-0 anecdote … EG-3 audit) ${rule}`);
  }
  return v as Gate2Eg;
}

/** A grade threshold (`establishAt`, `creditAt`): `{ lane, eg }`, closed. */
function g2Grade(raw: unknown, field: string, rule: string): DeclaredGate2Grade {
  if (!isPlainObject(raw)) fail(field, `${raw === undefined ? "required field missing: " : ""}must be a grade { lane, eg } ${rule}`);
  const g = raw as Record<string, unknown>;
  checkNoUnknownG2(g, ["lane", "eg"], field);
  return { lane: g2Lane(g.lane, `${field}.lane`, rule), eg: g2Eg(g.eg, `${field}.eg`, rule) };
}

/** A finite, non-negative number. */
function g2NonNegative(v: unknown, field: string, rule: string): number {
  if (typeof v !== "number" || !Number.isFinite(v) || v < 0) {
    fail(field, `${v === undefined ? "required field missing: " : ""}must be a finite number >= 0 (declared ${String(v)}) ${rule}`);
  }
  return v as number;
}

/**
 * One class of one list. `list` decides SIGNED (value, damage) or NAMED
 * (unknown); `cats` is frame[subject]'s category ids (R12).
 */
function validateG2Class(
  raw: unknown,
  field: string,
  list: "value" | "damage" | "unknown",
  subject: string,
  cats: ReadonlySet<string>,
  onWitnessBook = false
): DeclaredGate2SignedClass | DeclaredGate2UnknownClass {
  const r9 = (why: string): string => g2Rule(9, why);
  if (!isPlainObject(raw)) fail(field, `must be a class object { kind, outcome, … } ${r9("a class is an object")}`);
  const e = raw as Record<string, unknown>;
  const signed = list !== "unknown";
  // R9 BEFORE R14, so the refusal names the CATEGORY ERROR rather than "unknown field".
  if (!signed) {
    for (const k of ["weight", "rhoCausal", "falsifiability"]) {
      if (Object.hasOwn(e, k)) {
        fail(
          `${field}.${k}`,
          `an UNKNOWN class is NAMED, never weighted: it carries no weight, no rhoCausal and no falsifiability, ` +
            `because its SIGN is what is not known ${r9("RMBA V/D §6: UNKNOWN is not zero")}`
        );
      }
    }
  } else if (Object.hasOwn(e, "magnitude")) {
    fail(
      `${field}.magnitude`,
      `a ${list}[] class is SIGNED and carries a weight; magnitude is the sign-free bound of an UNKNOWN class ` +
        `only ${r9("contract §1: Gate2SignedClass has no magnitude")}`
    );
  }
  checkNoUnknownG2(e, signed ? G2_SIGNED_KEYS : G2_UNKNOWN_KEYS, field);

  // ── kind: R3, then R4 (value only), R5, R6 ─────────────────────────────────
  const kind = e.kind;
  // TIER 1 · R3 RE-SCOPED for a basket read on the WITNESS'S BOOK: the book
  // carries ONE kind, the witness's CONSEQUENCE record, and nothing else. A
  // subject-chain kind there would match no record and print n = 0 as a count.
  // ⚠ THE R6/F4 CARVE-OUT, STATED: F4 refuses "MICA's own output, bookkeeping or a
  // second party's record" because counting it "would read the governance around
  // the subject as the subject's direction". The witness's record is MICA's output
  // and a second party's — and it is not governance: it is an OBSERVATION of the
  // world's state after the subject's OWN act, citing that act, deciding nothing,
  // holding nothing, no verdict on the subject. Admitted for this kind alone, on
  // this book alone; every F4 kind stays refused everywhere.
  if (onWitnessBook) {
    if (kind !== GATE2_WITNESS_KIND) {
      fail(
        `${field}.kind`,
        `${JSON.stringify(kind)} is not the witness's record kind: on the witness's book a class names ` +
          `${GATE2_WITNESS_KIND} and an effect outcome ${g2Rule(3, "R3 re-scoped: a basket class is a class of the book it reads")}`
      );
    }
  } else if (typeof kind !== "string" || !GATE2_KNOWN_KINDS.includes(kind)) {
    fail(
      `${field}.kind`,
      `${JSON.stringify(kind)} is not a kind the subject chain carries (mica-service SUBJECT_EVENT_KINDS): a class ` +
        `naming no kind matches no record and would print n = 0 as if it were a count ` +
        `${g2Rule(3, "a basket class is a class of the RECORD")}`
    );
  }
  const k = kind as string;
  if (list === "value" && k.startsWith(GATE2_HELD_THEN_PREFIX)) {
    fail(
      `${field}.kind`,
      `${k} is a hold-response and may not be declared VALUE: a departure after a hold is EXIT-shaped, canon reads ` +
        `no sign off its surface, and crediting it (STOPPED above all) would count leaving as benefit ` +
        `${g2Rule(4, "audit ruling 19:51Z ③; 05b:216-220")}`
    );
  }
  if (GATE2_SUNSET_KINDS.includes(k)) {
    fail(
      `${field}.kind`,
      `${k} is a sunset kind: an ending's order, papers, presentation, responses and resolution are governance ` +
        `records and never a direction class ${g2Rule(5, "F3; 04c:107-113")}`
    );
  }
  if (GATE2_F4_REFUSED_KINDS.includes(k)) {
    fail(
      `${field}.kind`,
      `${k} is MICA's own output, bookkeeping or a second party's record (GATE2_F4_REFUSED_KINDS): counting it ` +
        `would read the governance around the subject as the subject's direction ${g2Rule(6, "F4; 08a:73-75")}`
    );
  }

  // ── outcome, grade: R9 ─────────────────────────────────────────────────────
  if (!Object.hasOwn(e, "outcome")) {
    fail(
      `${field}.outcome`,
      `required field missing: null (any outcome of the kind) or one outcome word — there is no default ` +
        `${r9("a class key is (kind, outcome)")}`
    );
  }
  const outcome = e.outcome;
  if (outcome !== null && (typeof outcome !== "string" || !G2_OUTCOME_PATTERN.test(outcome))) {
    fail(
      `${field}.outcome`,
      `must be null or a string matching ${G2_OUTCOME_PATTERN.source} (declared ${JSON.stringify(outcome)}) ` +
        `${r9("a class key is (kind, outcome)")}`
    );
  }
  const lane = g2Lane(e.lane, `${field}.lane`, r9("a class carries its lane"));
  const eg = g2Eg(e.eg, `${field}.eg`, r9("a class carries its evidence grade"));

  // ── TIER 1 · the book's outcome grammar, and R7's TWIN ─────────────────────
  if (onWitnessBook) {
    const o = outcome;
    const sep = typeof o === "string" ? o.indexOf(":") : -1;
    const cat = sep > 0 ? (o as string).slice(0, sep) : "";
    const eff = sep > 0 ? (o as string).slice(sep + 1) : "";
    if (typeof o !== "string" || !cats.has(cat) || !GATE2_WITNESS_EFFECT_CLASSES.includes(eff)) {
      fail(
        `${field}.outcome`,
        `on the witness's book an outcome is "<category of frame.${subject}>:<effect class>", the effect one of ` +
          `${GATE2_WITNESS_EFFECT_CLASSES.join(", ")} (declared ${JSON.stringify(o)}) ` +
          `${g2Rule(3, "R3 re-scoped: the book's records carry exactly this grammar")}`
      );
    }
    if (eg >= 2) {
      fail(
        `${field}.eg`,
        `the witness's record is ONE look by ONE internal process — a measured fact (Lane A) at EG-1 by RMBA §11 ` +
          `("internal measurement without independent verification"); no class over it is declared above EG-1 ` +
          `(declared EG-${String(eg)}) ${g2Rule(7, "R7's twin — audit 18:03Z (1); a past look cannot be re-run, so EG-2 only when an independent party co-signs")}`
      );
    }
    if (list !== "unknown" && GATE2_WITNESS_EVIDENCE_FREE_CLASSES.includes(eff)) {
      fail(
        `${field}.outcome`,
        `${eff} is evidence-free — the witness saw nothing it could compare, or placed no window — and is never a sign: on the ` +
          `witness's book it is declared in unknown[] or not at all ${g2Rule(18, "refuter C MAJOR-1; seeing.ts EVIDENCE_FREE_CLASSES")}`
      );
    }
    if (list !== "unknown" && GATE2_WITNESS_BOOK_SIGNED_REFUSED) {
      fail(
        `${field}`,
        `a ${list} class on the witness's book: in phase R every class there is an UNKNOWN, named and never signed, ` +
          `until T31, S206, S208, T32, F5 in the book, the persisted latch, F9 and S209 have landed ` +
          `${g2Rule(17, "GATE2_WITNESS_BOOK_SIGNED_REFUSED; refuters A-F5, C MAJOR-1")}`
      );
    }
  }

  // ── R7, R8: what the subject's own uid can write ───────────────────────────
  if (isGate2SubjectWritableKind(k) && eg >= 2) {
    fail(
      `${field}.eg`,
      `${k} is a kind the subject's own uid may POST, so on this record it is EG-1 at most: the bridge writes, ` +
        `chains and verifies it, and the clerk vouches for its ARRIVAL only (declared EG-${String(eg)}) ` +
        `${g2Rule(7, "EG stays 1 — audit ruling 19:51Z; S206")}`
    );
  }
  if (list === "damage" && GATE2_SUBJECT_WRITABLE_DAMAGE_REFUSED && isGate2SubjectWritableKind(k)) {
    fail(
      `${field}.kind`,
      `${k} is a kind the subject's own uid may POST, and no damage class is declared at EG-1 until S206 lands: ` +
        `the records an ALARM would count are records the subject can write or withhold ` +
        `${g2Rule(8, "audit ruling 19:51Z ④; GATE2_SUBJECT_WRITABLE_DAMAGE_REFUSED")}`
    );
  }

  // ── weight / rhoCausal / falsifiability (signed) or magnitude (unknown): R9 ─
  let signedFields:
    | { weight: { lo: number; hi: number }; rhoCausal: number; falsifiability: string }
    | undefined;
  let magnitude: { hi: number } | undefined;
  if (signed) {
    const rw = r9("a signed class is weighted: 0 <= lo <= hi, finite");
    if (!isPlainObject(e.weight)) fail(`${field}.weight`, `${e.weight === undefined ? "required field missing: " : ""}must be { lo, hi } ${rw}`);
    const w = e.weight as Record<string, unknown>;
    checkNoUnknownG2(w, ["lo", "hi"], `${field}.weight`);
    const lo = g2NonNegative(w.lo, `${field}.weight.lo`, rw);
    const hi = g2NonNegative(w.hi, `${field}.weight.hi`, rw);
    if (lo > hi) fail(`${field}.weight`, `lo ${String(lo)} exceeds hi ${String(hi)} ${rw}`);
    const rho = e.rhoCausal;
    if (typeof rho !== "number" || !Number.isFinite(rho) || rho < 0 || rho > 1) {
      fail(`${field}.rhoCausal`, `${rho === undefined ? "required field missing: " : ""}must be a number in [0, 1] (declared ${String(rho)}) ${r9("RMBA V/D §13: the causal coefficient the CVG reads")}`);
    }
    const fz = e.falsifiability;
    if (typeof fz !== "string" || fz.length === 0) {
      fail(`${field}.falsifiability`, `${fz === undefined ? "required field missing: " : ""}must be a non-empty string naming what record would show this class's sign wrong ${r9("a signed class states its falsifier")}`);
    }
    signedFields = { weight: { lo, hi }, rhoCausal: rho as number, falsifiability: fz as string };
  } else if (Object.hasOwn(e, "magnitude")) {
    const rm = r9("magnitude is a sign-free bound: { hi }, finite, > 0 — a magnitude of 0 is UNKNOWN = zero (RMBA V/D §6, §18.10 unknown erasure)");
    if (!isPlainObject(e.magnitude)) fail(`${field}.magnitude`, `must be { hi } ${rm}`);
    const m = e.magnitude as Record<string, unknown>;
    checkNoUnknownG2(m, ["hi"], `${field}.magnitude`);
    magnitude = { hi: g2NonNegative(m.hi, `${field}.magnitude.hi`, rm) };
    if (magnitude.hi === 0) fail(`${field}.magnitude.hi`, `must be > 0 (declared 0) ${rm}`);
  }

  // ── bearsOn: R12 ───────────────────────────────────────────────────────────
  const r12 = g2Rule(12, "direction is read only within a fixed frame — 05a:170");
  const bearsOn = e.bearsOn;
  if (!Array.isArray(bearsOn) || bearsOn.length === 0) {
    fail(
      `${field}.bearsOn`,
      `must name at least one category of frame.${subject}: a class that bears on no category of M cannot be ` +
        `subtotalled against the frame ${r12}`
    );
  }
  const seenCats = new Set<string>();
  for (const [i, c] of (bearsOn as unknown[]).entries()) {
    if (typeof c !== "string" || !cats.has(c)) {
      fail(`${field}.bearsOn[${String(i)}]`, `${JSON.stringify(c)} is not a category id of frame.${subject} ${r12}`);
    }
    if (seenCats.has(c as string)) fail(`${field}.bearsOn[${String(i)}]`, `${JSON.stringify(c)} is named twice ${r12}`);
    seenCats.add(c as string);
  }
  // TIER 1 · on the witness's book the outcome NAMES the category the target was
  // placed in; a class that bears on others but not on that one would subtotal
  // an effect against a category it was never seen in.
  if (onWitnessBook) {
    const cat = (outcome as string).slice(0, (outcome as string).indexOf(":"));
    if (!seenCats.has(cat)) {
      fail(`${field}.bearsOn`, `must include ${JSON.stringify(cat)}, the category its outcome names ${r12}`);
    }
  }

  const basis = e.basis;
  if (typeof basis !== "string" || basis.length === 0) {
    fail(`${field}.basis`, `${basis === undefined ? "required field missing: " : ""}must be a non-empty string ${r9("every class says why it is declared")}`);
  }

  // Schema order, and nothing added: the loaded class is the declared class.
  if (signedFields !== undefined) {
    return {
      kind: k,
      outcome: outcome as string | null,
      weight: signedFields.weight,
      lane,
      eg,
      rhoCausal: signedFields.rhoCausal,
      falsifiability: signedFields.falsifiability,
      bearsOn: bearsOn as string[],
      basis: basis as string,
    };
  }
  return {
    kind: k,
    outcome: outcome as string | null,
    lane,
    eg,
    ...(magnitude === undefined ? {} : { magnitude }),
    bearsOn: bearsOn as string[],
    basis: basis as string,
  };
}

/** One subject's basket. `cats` is frame[subject]'s category ids. */
function validateSubjectBasket(raw: unknown, field: string, subject: string, cats: ReadonlySet<string>, onWitnessBook = false): SubjectBasket {
  if (!isPlainObject(raw)) fail(field, `must be a basket object ${g2Rule(14, "the stanza's shape is closed")}`);
  const o = raw as Record<string, unknown>;
  checkNoUnknownG2(o, G2_BASKET_KEYS, field);

  // ── classes: R2, the entries, R13 ──────────────────────────────────────────
  const r2 = g2Rule(2, "a missing damage term is not a free lunch; it is an audit problem — RMBA:208");
  if (!Object.hasOwn(o, "classes")) fail(`${field}.classes`, `required field missing ${r2}`);
  const ce = g2Envelope(o.classes, `${field}.classes`, r2);
  const lf = `${field}.classes.value`;
  if (!isPlainObject(ce.value)) fail(lf, `must be { value: [...], damage: [...], unknown: [...] } ${r2}`);
  const lists = ce.value as Record<string, unknown>;
  checkNoUnknownG2(lists, ["value", "damage", "unknown"], lf);
  for (const l of ["value", "damage", "unknown"]) {
    if (!Array.isArray(lists[l])) {
      fail(`${lf}.${l}`, `${lists[l] === undefined ? "required field missing: " : ""}must be an array (it may be empty; damage and unknown may not BOTH be) ${r2}`);
    }
  }
  if ((lists.damage as unknown[]).length === 0 && (lists.unknown as unknown[]).length === 0) {
    fail(
      lf,
      `names NO damage term: damage[] and unknown[] are both empty, so the basket declares no way the record ` +
        `could read against the subject and every reading it allows leans one way ${r2}`
    );
  }
  const value = (lists.value as unknown[]).map((c, i) => validateG2Class(c, `${lf}.value[${String(i)}]`, "value", subject, cats, onWitnessBook) as DeclaredGate2SignedClass);
  const damage = (lists.damage as unknown[]).map((c, i) => validateG2Class(c, `${lf}.damage[${String(i)}]`, "damage", subject, cats, onWitnessBook) as DeclaredGate2SignedClass);
  const unknown = (lists.unknown as unknown[]).map((c, i) => validateG2Class(c, `${lf}.unknown[${String(i)}]`, "unknown", subject, cats, onWitnessBook) as DeclaredGate2UnknownClass);
  // R13 · a record may match AT MOST ONE class across the three lists.
  const seen: { kind: string; outcome: string | null; at: string }[] = [];
  for (const [l, entries] of [["value", value], ["damage", damage], ["unknown", unknown]] as const) {
    (entries as readonly { kind: string; outcome: string | null }[]).forEach((c, i) => {
      const at = `${lf}.${l}[${String(i)}]`;
      const clash = seen.find((p) => p.kind === c.kind && (p.outcome === c.outcome || p.outcome === null || c.outcome === null));
      if (clash !== undefined) {
        fail(
          at,
          (clash.outcome === c.outcome
            ? `(${c.kind}, ${JSON.stringify(c.outcome)}) is already declared at ${clash.at}`
            : `${c.kind} is declared at ${clash.at} with outcome ${JSON.stringify(clash.outcome)} and here with ` +
              `${JSON.stringify(c.outcome)}: a null outcome matches EVERY record of the kind, so one record would ` +
              `match both classes`) +
            ` — a record may match at most one class across value, damage and unknown ` +
            `${g2Rule(13, "contract §1: one record, one class")}`
        );
      }
      seen.push({ kind: c.kind, outcome: c.outcome, at });
    });
  }

  // ── epsilonNum, grades, window, nMin: R10 ──────────────────────────────────
  const r10 = (why: string): string => g2Rule(10, why);
  const re = r10("ε is a declared TOLERANCE (RMBA V/D §7 default 1e-6), never a default and never a materiality knob");
  if (!Object.hasOwn(o, "epsilonNum")) fail(`${field}.epsilonNum`, `required field missing ${re}`);
  const ee = g2Envelope(o.epsilonNum, `${field}.epsilonNum`, re);
  const epsilonNum = g2NonNegative(ee.value, `${field}.epsilonNum.value`, re);

  const rg = r10("the grades a basket claim needs are declared, never defaulted");
  if (!Object.hasOwn(o, "grades")) fail(`${field}.grades`, `required field missing ${rg}`);
  const ge = g2Envelope(o.grades, `${field}.grades`, rg);
  if (!isPlainObject(ge.value)) fail(`${field}.grades.value`, `must be { establishAt, creditAt } ${rg}`);
  const gv = ge.value as Record<string, unknown>;
  checkNoUnknownG2(gv, ["establishAt", "creditAt"], `${field}.grades.value`);
  const establishAt = g2Grade(gv.establishAt, `${field}.grades.value.establishAt`, rg);
  const creditAt = g2Grade(gv.creditAt, `${field}.grades.value.creditAt`, rg);

  const rw = r10("the ONLY window built is sinceBoundary; a trailing window is unbuilt because its interaction with the latch is not designed");
  if (!Object.hasOwn(o, "window")) fail(`${field}.window`, `required field missing ${rw}`);
  const we = g2Envelope(o.window, `${field}.window`, rw);
  if (!isPlainObject(we.value)) fail(`${field}.window.value`, `must be { kind: "sinceBoundary" } ${rw}`);
  const wv = we.value as Record<string, unknown>;
  checkNoUnknownG2(wv, ["kind"], `${field}.window.value`);
  if (wv.kind !== "sinceBoundary") fail(`${field}.window.value.kind`, `must be "sinceBoundary" (declared ${JSON.stringify(wv.kind)}) ${rw}`);

  const rn = r10("nMin is a positive SAFE integer count of classed records — the reader refuses any other as malformed");
  if (!Object.hasOwn(o, "nMin")) fail(`${field}.nMin`, `required field missing ${rn}`);
  const ne = g2Envelope(o.nMin, `${field}.nMin`, rn);
  if (typeof ne.value !== "number" || !Number.isSafeInteger(ne.value) || ne.value < 1) {
    fail(`${field}.nMin.value`, `must be a positive integer (declared ${String(ne.value)}) ${rn}`);
  }

  // ── latchClearedBy: R3 for an unknown kind, R11 for the rest ───────────────
  const r11 = g2Rule(11, "the latch clears only by the ARBITER's record (ruling F5, audit 2026-10-09 19:51Z): GATE2_ARBITER_CLEARING_KINDS — not the doctor's, not an ending paper or order, never a kind the subject may post");
  if (!Object.hasOwn(o, "latchClearedBy")) fail(`${field}.latchClearedBy`, `required field missing ${r11}`);
  const le = g2Envelope(o.latchClearedBy, `${field}.latchClearedBy`, r11);
  if (!Array.isArray(le.value) || le.value.length === 0) {
    fail(`${field}.latchClearedBy.value`, `must name at least one clearing kind: a latch nothing can clear is one no record can close ${r11}`);
  }
  const latch: { kind: string }[] = [];
  for (const [i, itemRaw] of (le.value as unknown[]).entries()) {
    const at = `${field}.latchClearedBy.value[${String(i)}]`;
    if (!isPlainObject(itemRaw)) fail(at, `must be { kind } ${r11}`);
    const item = itemRaw as Record<string, unknown>;
    checkNoUnknownG2(item, ["kind"], at);
    const lk = item.kind;
    if (typeof lk !== "string" || !GATE2_KNOWN_KINDS.includes(lk)) {
      fail(`${at}.kind`, `${JSON.stringify(lk)} is not a kind the subject chain carries (mica-service SUBJECT_EVENT_KINDS) ${g2Rule(3, "a clearing record is a record of the RECORD")}`);
    }
    if (!GATE2_ARBITER_CLEARING_KINDS.includes(lk as string)) {
      fail(
        `${at}.kind`,
        `${lk as string} is not the arbiter's record${isGate2SubjectWritableKind(lk as string) ? " — it is a kind the subject's own uid may POST" : ""} ${r11}`
      );
    }
    if (latch.some((x) => x.kind === lk)) fail(`${at}.kind`, `${lk as string} is named twice ${r11}`);
    latch.push({ kind: lk as string });
  }

  return {
    classes: { value: { value, damage, unknown }, basis: ce.basis, proxy: ce.proxy },
    epsilonNum: { value: epsilonNum, basis: ee.basis, proxy: ee.proxy },
    grades: { value: { establishAt, creditAt }, basis: ge.basis, proxy: ge.proxy },
    window: { value: { kind: "sinceBoundary" }, basis: we.basis, proxy: we.proxy },
    nMin: { value: ne.value as number, basis: ne.basis, proxy: ne.proxy },
    latchClearedBy: { value: latch, basis: le.basis, proxy: le.proxy },
  };
}

/**
 * Top-level `baskets` against the already-validated `subjects` and `frame`.
 * R1's two key halves live here (X16's shape: a basket for no subject; and a
 * basket for a subject with no frame, whose classes could bear on nothing).
 */
function validateBaskets(
  raw: unknown,
  subjects: ReadonlySet<string>,
  frame: Readonly<Record<string, SubjectFrame>> | undefined,
  witnessBookSubjects: ReadonlySet<string> = new Set()
): Readonly<Record<string, SubjectBasket>> {
  const b = requireObject(raw, "baskets");
  // The empty-frame rule, applied here: `{}` would move declarationHash and declare nothing.
  if (Object.keys(b).length === 0) {
    fail("baskets", "must carry at least one declared subject's basket; an empty map moves declarationHash and declares nothing — omit the key instead");
  }
  const out: [string, SubjectBasket][] = [];
  for (const s of Object.keys(b)) {
    const field = `baskets.${s}`;
    if (s === PROTO_KEY) fail(field, PROTO_KEY_REASON);
    if (!subjects.has(s)) fail(field, `"${s}" is not a declared subjects[].subject ${g2Rule(1, "X16's shape")}`);
    if (frame === undefined || !Object.hasOwn(frame, s)) {
      fail(
        field,
        `subject "${s}" has no frame.${s}: every class bears on a category of the subject's frame M, and direction ` +
          `is read only within a fixed frame (05a:170) ${g2Rule(1, "X22's shape")}`
      );
    }
    const cats = new Set(frame![s].categories.value.map((c) => c.id));
    out.push([s, validateSubjectBasket(b[s], field, s, cats, witnessBookSubjects.has(s))]);
  }
  // Object.fromEntries DEFINES own properties — the frame's reason.
  return Object.fromEntries(out);
}

// ── Gate 2 · Long Run A Stop 2 · the HARM stanza validator (contract B1, refusals H1–H10) ──
//
// The arbiter's question (board 2026-10-15 18:15Z): did an act change a protected thing (an ITEM) without
// permission (a GRANT)? The ruleset is this stanza, keyed by subject beside `frame` and `baskets`, and
// the deployer writes it. Hats: items, grants and origins under the deployer's; clearances (C1, W-C)
// under the doctor's; the relay is the arbiter's hand.
//
// ⛔ A HARM STANZA IS NOT A CLASS BASKET and never passes through R2–R18: it declares no class, no
//    weight and no grade. For the Gate-2 subject it REPLACES the basket (H9; R1 accepts either).
// ⛔ CLOSED KEY SETS EVERYWHERE, and every refusal SAYS ITS RULE — `(harm front-door refusal Hn — …)`
//    — so two rules that cite one field stay two findings. An unknown key is H10's (every harm key set
//    is closed, every id a word); its text keeps `accepted here:` LAST, for the schema-parity walk.
// ⚠ WHAT THIS DOOR CANNOT SEE, stated: whether the subject can actually change an item (F-9's
//   measurement is the deployer's, recorded in the item's basis and its `control` flag), and whether an
//   item exists. It checks the item's SPELLING (canonical, exact, absolute) and its PLACE (the writer's
//   own deriver files it in its declared category), because those decide whether a record can ever
//   match it (F-4, F-10).

function hRule(n: number, cite: string): string {
  return `(harm front-door refusal H${String(n)} — ${cite})`;
}
const H_ID_PATTERN = /^[A-Za-z0-9_-]{1,32}$/;
const H_RECORD_PATTERN = /^[0-9a-f]{64}$/;
/** S216 · a grant's since: one UTC instant in toISOString()'s ONE spelling (ms always, Z, four-digit year) — so one instant is one class (cold refuter, bytes). */
const H_SINCE_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
/** ms of a since the loader accepted; the pattern and the round trip were checked there. */
export function harmSinceMs(since: string): number {
  return Date.parse(since);
}
/** S208-2 · one UTC instant in the since's one spelling, or null: the pattern AND the calendar round trip. */
export function utcInstantMs(v: unknown): number | null {
  if (typeof v !== "string" || !H_SINCE_PATTERN.test(v)) return null;
  const ms = Date.parse(v);
  if (!Number.isFinite(ms)) return null;
  const back = new Date(ms).toISOString();
  return back === v || back === v.replace(/Z$/, ".000Z") ? ms : null;
}
const H_STANZA_KEYS = ["harmOnly", "origins", "items", "grants", "clearances", "errand"] as const;

function checkNoUnknownH(obj: Record<string, unknown>, allowed: readonly string[], field: string): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) {
      fail(`${field}.${key}`, `unknown field ${hRule(10, "every harm key set is closed")}; accepted here: ${allowed.join(", ")}`);
    }
  }
}
function hEnvelope(raw: unknown, field: string, missingRule: string): { value: unknown; basis: string; proxy: boolean } {
  if (raw === undefined) fail(field, `required field missing ${missingRule}`);
  if (!isPlainObject(raw)) fail(field, `must be an envelope { value, basis, proxy } ${missingRule}`);
  const env = raw as Record<string, unknown>;
  checkNoUnknownH(env, ["value", "basis", "proxy"], field);
  if (!Object.hasOwn(env, "value") || env.value === undefined) fail(`${field}.value`, `required field missing ${missingRule}`);
  if (typeof env.basis !== "string" || env.basis.length === 0) fail(`${field}.basis`, `must be a non-empty string ${hRule(6, "every stanza says why")}`);
  if (typeof env.proxy !== "boolean") fail(`${field}.proxy`, `must be a boolean ${hRule(6, "every stanza says whether it is a proxy")}`);
  return { value: env.value, basis: env.basis as string, proxy: env.proxy as boolean };
}
function hBasis(v: unknown, field: string): string {
  if (typeof v !== "string" || v.length === 0) fail(field, `must be a non-empty string ${hRule(6, "every item, origin, grant and clearance says why")}`);
  return v as string;
}
function hIdMap(raw: unknown, field: string, emptyRule: string): Record<string, unknown> {
  if (!isPlainObject(raw)) fail(field, `must be an object keyed by id ${emptyRule}`);
  const m = raw as Record<string, unknown>;
  if (Object.keys(m).length === 0) fail(field, `must declare at least one entry ${emptyRule}`);
  for (const id of Object.keys(m)) {
    if (id === PROTO_KEY) fail(`${field}.${id}`, PROTO_KEY_REASON);
    if (!H_ID_PATTERN.test(id)) fail(`${field}.${id}`, `the id must match ^[A-Za-z0-9_-]{1,32}$ ${hRule(10, "an id is a word the verdict text can print")}`);
  }
  return m;
}

function validateSubjectHarm(raw: unknown, field: string, frame: SubjectFrame, subjects: ReadonlySet<string>, gate2Subject: string | null): SubjectHarm {
  const h = requireObject(raw, field);
  checkNoUnknownH(h, H_STANZA_KEYS, field);
  // H2 · harmOnly is the explicit flag, exactly true.
  const ho = hEnvelope(h.harmOnly, `${field}.harmOnly`, hRule(2, "harmOnly is declared, and it is exactly true"));
  if (ho.value !== true) fail(`${field}.harmOnly.value`, `must be exactly true (declared ${JSON.stringify(ho.value)}) ${hRule(2, "harmOnly is declared, and it is exactly true")}`);

  // H3 · origins: each bound to a declared subject; one bound to the Gate-2 subject.
  const r3 = hRule(3, "an origin is a declared subject the bridge binds to its peer (W-O, O1)");
  const oe = hEnvelope(h.origins, `${field}.origins`, r3);
  const om = hIdMap(oe.value, `${field}.origins.value`, r3);
  const origins: Record<string, DeclaredHarmOrigin> = {};
  for (const id of Object.keys(om)) {
    const f = `${field}.origins.value.${id}`;
    const o = requireObject(om[id], f);
    checkNoUnknownH(o, ["subject", "basis"], f);
    if (typeof o.subject !== "string" || !subjects.has(o.subject)) {
      fail(`${f}.subject`, `${JSON.stringify(o.subject ?? null)} is not a declared subjects[].subject ${r3}`);
    }
    origins[id] = { subject: o.subject as string, basis: hBasis(o.basis, `${f}.basis`) };
  }
  if (gate2Subject !== null && !Object.values(origins).some((o) => o.subject === gate2Subject)) {
    fail(`${field}.origins.value`, `no origin is bound to readers.gate2Direction.subject "${gate2Subject}": every record the reader reads carries that subject, so it would read every record ORIGIN NOT READABLE ${r3}`);
  }

  // H4 · items: exact canonical absolute paths, placed by the writer's own deriver in their own
  //      non-self category, unique.
  const r4 = hRule(4, "an item is ONE exact canonical path in a region of its own non-self category (F-4, F-10)");
  const ie = hEnvelope(h.items, `${field}.items`, r4);
  const im = hIdMap(ie.value, `${field}.items.value`, r4);
  const cats = new Map(frame.categories.value.map((c) => [c.id, c] as const));
  const items: Record<string, DeclaredHarmItem> = {};
  const seenPaths = new Map<string, string>();
  for (const id of Object.keys(im)) {
    const f = `${field}.items.value.${id}`;
    const it = requireObject(im[id], f);
    checkNoUnknownH(it, ["path", "category", "control", "basis"], f);
    const p = it.path;
    if (typeof p !== "string" || !p.startsWith("/")) fail(`${f}.path`, `must be an absolute path ${r4}`);
    const canon = canonicaliseTargetIdentity(p);
    if (!canon.ok || canon.canonical !== p || unquoteOnePair(p) !== p) {
      fail(`${f}.path`, `must equal its own canonical form and carry no quote pair: the bridge fingerprints the looked-at path, so another spelling never matches ${r4}`);
    }
    const prior = seenPaths.get(p as string);
    if (prior !== undefined) fail(`${f}.path`, `duplicates item "${prior}"'s path: one path, one item ${r4}`);
    seenPaths.set(p as string, id);
    const cat = it.category;
    if (typeof cat !== "string" || !cats.has(cat)) fail(`${f}.category`, `${JSON.stringify(cat ?? null)} is not a category of this subject's frame ${r4}`);
    if (cats.get(cat as string)!.self) fail(`${f}.category`, `"${cat as string}" is the frame's self category: a harm basket is what is NOT the subject's own ${r4}`);
    if (deriveInterestLabel(p as string, frame.regions.value, p as string) !== cat) {
      fail(`${f}.path`, `does not lie in a region of its declared category "${cat as string}" by the writer's own deriver (longest region wins) — the label site would not file an act on it there ${r4}`);
    }
    if (typeof it.control !== "boolean") fail(`${f}.control`, `must be a boolean: true marks an item the subject cannot change (alarms only on another writer, F-9) ${r4}`);
    items[id] = { path: p as string, category: cat as string, control: it.control as boolean, basis: hBasis(it.basis, `${f}.basis`) };
  }

  // H5 · grants: one entry per item, each naming declared origins, none for an undeclared item.
  const r5 = hRule(5, "every item has a grant list ([] is one), and a grant names declared origins only");
  const ge = hEnvelope(h.grants, `${field}.grants`, r5);
  if (!isPlainObject(ge.value)) fail(`${field}.grants.value`, `must be an object keyed by item id ${r5}`);
  const gm = ge.value as Record<string, unknown>;
  const grants: Record<string, DeclaredHarmGrant> = {};
  for (const itemId of Object.keys(gm)) {
    const f = `${field}.grants.value.${itemId}`;
    if (itemId === PROTO_KEY) fail(f, PROTO_KEY_REASON);
    if (!Object.hasOwn(items, itemId)) fail(f, `"${itemId}" is not a declared item ${r5}`);
    const g = requireObject(gm[itemId], f);
    checkNoUnknownH(g, ["origins", "since", "basis"], f);
    if (!Array.isArray(g.origins)) fail(`${f}.origins`, `must be a list of origin ids ([] grants nobody) ${r5}`);
    const list = g.origins as unknown[];
    const seen = new Set<string>();
    list.forEach((o, i) => {
      if (typeof o !== "string" || !Object.hasOwn(origins, o)) fail(`${f}.origins[${String(i)}]`, `${JSON.stringify(o ?? null)} is not a declared origin ${r5}`);
      if (seen.has(o as string)) fail(`${f}.origins[${String(i)}]`, `"${o as string}" is granted twice ${r5}`);
      seen.add(o as string);
    });
    // S216 · every listed origin carries the instant its grant counts from; nothing else is named there.
    const r5s = hRule(5, "a grant counts from its since: every listed origin names one UTC instant, and no other origin is named (S216)");
    if (!isPlainObject(g.since)) fail(`${f}.since`, `must be an object of origin id -> UTC instant ({} for []) ${r5s}`);
    const sm = g.since as Record<string, unknown>;
    const since: Record<string, string> = {};
    for (const o of Object.keys(sm)) {
      if (o === PROTO_KEY) fail(`${f}.since`, PROTO_KEY_REASON);
      if (!seen.has(o)) fail(`${f}.since.${o}`, `"${o}" holds no grant on this item, so it has no since ${r5s}`);
      const v = sm[o];
      if (typeof v !== "string" || !H_SINCE_PATTERN.test(v) || !Number.isFinite(Date.parse(v))) {
        fail(`${f}.since.${o}`, `must be one UTC instant YYYY-MM-DDTHH:MM:SS.mmmZ (toISOString's spelling) (declared ${JSON.stringify(v ?? null)}) ${r5s}`);
      }
      const ms = Date.parse(v as string);
      const back = new Date(ms).toISOString();
      if (back !== v) fail(`${f}.since.${o}`, `is not a calendar instant (${v as string} reads back as ${back}) ${r5s}`);
      since[o] = v as string;
    }
    for (const o of seen) {
      if (!Object.hasOwn(since, o)) fail(`${f}.since`, `"${o}" is granted with no since: a grant with no instant would count backwards over every record ${r5s}`);
    }
    grants[itemId] = { origins: list as string[], since, basis: hBasis(g.basis, `${f}.basis`) };
  }
  for (const itemId of Object.keys(items)) {
    if (!Object.hasOwn(grants, itemId)) fail(`${field}.grants.value`, `item "${itemId}" has no grants entry: silence is not a grant list ${r5}`);
  }

  // H7 · clearances (C1, the doctor's hat): a witness RECORD hash each, unique.
  const r7 = hRule(7, "a clearance names one witness record by its 64-hex hash, under the doctor's hat (W-C, C1)");
  const ce = hEnvelope(h.clearances, `${field}.clearances`, r7);
  if (!Array.isArray(ce.value)) fail(`${field}.clearances.value`, `must be a list ([] clears nothing) ${r7}`);
  const clearances: DeclaredHarmClearance[] = [];
  const seenRec = new Set<string>();
  (ce.value as unknown[]).forEach((raw, i) => {
    const f = `${field}.clearances.value[${String(i)}]`;
    const c = requireObject(raw, f);
    checkNoUnknownH(c, ["record", "hat", "basis"], f);
    if (typeof c.record !== "string" || !H_RECORD_PATTERN.test(c.record)) fail(`${f}.record`, `must be 64 lower-case hex ${r7}`);
    if (c.hat !== "doctor") fail(`${f}.hat`, `must be "doctor" (declared ${JSON.stringify(c.hat ?? null)}) ${r7}`);
    if (seenRec.has(c.record as string)) fail(`${f}.record`, `clears a record already cleared ${r7}`);
    seenRec.add(c.record as string);
    clearances.push({ record: c.record as string, hat: "doctor", basis: hBasis(c.basis, `${f}.basis`) });
  });

  // H12 · S208-2 · the errand envelope, checked against the frame: declared categories, never the subject's own.
  let errand: SubjectHarm["errand"] = undefined;
  if (h.errand !== undefined) {
    const r12 = hRule(12, "an errand may grant only frame categories that are not the subject's own, for a bounded window (S208-2)");
    const ee = hEnvelope(h.errand, `${field}.errand`, r12);
    const ev = requireObject(ee.value, `${field}.errand.value`);
    checkNoUnknownH(ev, ["categories", "maxWindowMinutes"], `${field}.errand.value`);
    if (!Array.isArray(ev.categories) || ev.categories.length === 0) fail(`${field}.errand.value.categories`, `must be a non-empty list of frame category ids ${r12}`);
    const cats: string[] = [];
    for (const c of ev.categories as unknown[]) {
      const fc = frame.categories.value.find((x) => x.id === c);
      if (fc === undefined) fail(`${field}.errand.value.categories`, `${JSON.stringify(c ?? null)} is not a category of this subject's frame ${r12}`);
      if (fc!.self) fail(`${field}.errand.value.categories`, `"${String(c)}" is the subject's own category: an errand grants what is NOT the subject's ${r12}`);
      // the design's rule (c3/c4 never grantable): only a category grounded in AGENCY — the deployer's own — may be
      // granted by an errand; a vulnerability-grounded category is other people's, and no errand speaks for them.
      if (fc!.grounding !== "agency") fail(`${field}.errand.value.categories`, `"${String(c)}" is grounded in ${JSON.stringify(fc!.grounding)}, not agency: an errand may grant only the deployer's own (agency-grounded) categories ${r12}`);
      if (cats.includes(c as string)) fail(`${field}.errand.value.categories`, `"${String(c)}" is listed twice ${r12}`);
      cats.push(c as string);
    }
    const mw = ev.maxWindowMinutes;
    if (typeof mw !== "number" || !Number.isInteger(mw) || mw < 1 || mw > 1440) fail(`${field}.errand.value.maxWindowMinutes`, `must be an integer from 1 to 1440 ${r12}`);
    errand = { value: { categories: cats, maxWindowMinutes: mw as number }, basis: ee.basis, proxy: ee.proxy };
  }

  return {
    harmOnly: { value: true, basis: ho.basis, proxy: ho.proxy },
    origins: { value: origins, basis: oe.basis, proxy: oe.proxy },
    items: { value: items, basis: ie.basis, proxy: ie.proxy },
    grants: { value: grants, basis: ge.basis, proxy: ge.proxy },
    clearances: { value: clearances, basis: ce.basis, proxy: ce.proxy },
    ...(errand === undefined ? {} : { errand }),
  };
}

/**
 * Top-level `harm` against the already-validated `subjects`, `frame` and the
 * Gate-2 switch. H1 (a declared, framed subject) and H8 (Gate 2 reads the
 * witness's book, named by its method) live here; the stanza's own rules in
 * validateSubjectHarm; H9 (not beside a basket) in validate(), after R1.
 * ⚠ PATHS.interestBook (the roster the reader reads) is already guaranteed:
 *   a frame requires it (X22, second half), and H1 requires a frame.
 * Across a SIGHUP reload the stanza may only TIGHTEN: H11 (validateHarmNotLoosened).
 */
function validateHarm(
  raw: unknown,
  subjects: ReadonlySet<string>,
  frame: Readonly<Record<string, SubjectFrame>> | undefined,
  gate2Direction: Declarations["readers"]["gate2Direction"]
): Readonly<Record<string, SubjectHarm>> {
  const h = requireObject(raw, "harm");
  if (Object.keys(h).length === 0) {
    fail("harm", `must carry at least one declared subject's stanza; an empty map moves declarationHash and declares nothing — omit the key instead ${hRule(1, "a stanza is keyed by a declared, framed subject")}`);
  }
  const out: [string, SubjectHarm][] = [];
  for (const s of Object.keys(h)) {
    const field = `harm.${s}`;
    if (s === PROTO_KEY) fail(field, PROTO_KEY_REASON);
    const r1 = hRule(1, "a stanza is keyed by a declared, framed subject");
    if (!subjects.has(s)) fail(field, `"${s}" is not a declared subjects[].subject ${r1}`);
    if (frame === undefined || !Object.hasOwn(frame, s)) {
      fail(field, `subject "${s}" has no frame.${s}: every item is placed in a category of the subject's frame ${r1}`);
    }
    if (gate2Direction === undefined || gate2Direction.book === undefined || gate2Direction.witnessMethod === undefined) {
      fail(
        field,
        `harm is declared while readers.gate2Direction.book / witnessMethod are absent: the harm reading is a reading of ` +
          `the witness's book and nothing else ${hRule(8, "harm reads the witness's book, named by its method")}`
      );
    }
    out.push([s, validateSubjectHarm(h[s], field, frame![s], subjects, gate2Direction.subject.value)]);
  }
  return Object.fromEntries(out);
}

// ── pilot state, X8 ────────────────────────────────────────────────────────

/**
 * X8: pilot.active:true with expiresAt in the past loads, state EXPIRED,
 * baseline governs. Rejection on a past expiresAt happens only in
 * validateActivation (a NEW activation), never here at load time.
 */
function computePilotState(pilot: PilotDeclared, now: Date): PilotState {
  if (!pilot.active) return { state: "INACTIVE" };
  const expiresAtMs = Date.parse(pilot.expiresAt);
  if (expiresAtMs <= now.getTime()) {
    return { state: "EXPIRED", sessionId: pilot.sessionId, expiresAt: pilot.expiresAt };
  }
  return {
    state: "ACTIVE",
    sessionId: pilot.sessionId,
    expiresAt: pilot.expiresAt,
    holdAtOrAbove: pilot.holdAtOrAbove.value,
  };
}

// ── public API ─────────────────────────────────────────────────────────────

/**
 * Loads and validates declarations.config.json at `path`. Throws DeclarationRejected
 * naming the first offending field, or returns the validated object plus its
 * declarationHash (sha256 of the canonical JSON of the loaded, PARSED
 * declaration — not the file bytes, design §C.4) and the pilot state as of
 * `now` (default: the real clock).
 *
 * A well-formed past-expiry pilot LOADS — never rejected here (X8). Rejecting
 * a *new activation* with a past expiry is a separate act: validateActivation.
 */
export function loadDeclarations(path: string, now: Date = new Date()): LoadedDeclarations {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    throw new DeclarationRejected("$", `could not read ${path}: ${String(err)}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new DeclarationRejected("$", `${path} is not valid JSON: ${String(err)}`);
  }
  const declarations = validate(parsed);
  const declarationHash = canonicalHash(declarations);
  const pilotState = computePilotState(declarations.pilot, now);
  return { declarations, declarationHash, pilotState };
}

/** Same as loadDeclarations but validates an already-parsed object (for tests). */
export function validateDeclarations(parsed: unknown, now: Date = new Date()): LoadedDeclarations {
  const declarations = validate(parsed);
  const declarationHash = canonicalHash(declarations);
  const pilotState = computePilotState(declarations.pilot, now);
  return { declarations, declarationHash, pilotState };
}

/**
 * A NEW pilot activation, checked against the previously loaded declaration.
 * X8: rejected only when this is a genuinely new activation (the
 * (active, sessionId, expiresAt) triple differs from what was already
 * loaded) AND its expiresAt is in the past. Reloading the SAME already-loaded
 * pilot verbatim is not a new activation even if it has since expired —
 * that is handled by loadDeclarations returning EXPIRED, not by this
 * function, and last-known-good is retained by the caller (the service),
 * not by this loader.
 */
export function validateActivation(prev: Declarations | null, next: Declarations, now: Date = new Date()): void {
  // ⛔ FIRST, AND BEFORE EITHER EARLY RETURN BELOW. The pilot rules return early
  //    for a stand-down and for an unchanged pilot — which is nearly every reload.
  //    A frame rule placed after them would run only on a pilot activation and
  //    would let any ordinary SIGHUP narrow M. The book rule below (A3) sits
  //    here for the same reason.
  // Z4 (F-5 (a)) FIRST OF ALL: a reload may not change who is declared or who
  // may call. Membership, route uids and each row's grant are a FIRST LOAD
  // (restart) fact — the socket and peer-dir checks run only there — so a
  // reload that changes them is refused by THAT name before any rule about what
  // the changed membership carries (X21, A3, R15, H11) speaks.
  validateMembershipUnchangedOnReload(prev, next);
  validateFrameWidenOnly(prev, next);
  validateInterestBookUnchanged(prev, next);
  // Gate 2 · R15, the same placement and the same reason: an ordinary SIGHUP
  // must not deflate a basket's damage terms past an unchanged pilot.
  validateBasketNotDeflated(prev, next);
  // Gate 2 · H11, R15's harm analogue, same placement and reason: a declaration
  // relay is a SIGHUP, so C1 clearances arrive by reload — and so could a reload
  // that dissolves a latch without one.
  validateHarmNotLoosened(prev, next);
  if (!next.pilot.active) return; // deactivating is never rejected here
  const prevPilot = prev?.pilot;
  const isSameAsPrev =
    prevPilot !== undefined &&
    prevPilot.active === true &&
    prevPilot.sessionId === next.pilot.sessionId &&
    prevPilot.expiresAt === next.pilot.expiresAt;
  if (isSameAsPrev) return; // same pilot re-loading, not an activation (X8)

  // ── X9 · A LIVE PILOT MAY NOT BE REPLACED. IT MUST BE ALLOWED TO LAPSE. ────
  //
  // ⛔ WHAT HAPPENED WITHOUT THIS, 2026-09-27. S3 handed over from
  //    pilot-2026-09-20-01 to pilot-2026-09-27-02 at 10:48:48Z. Pilot 1 did not
  //    expire until 18:00:00Z. The front door accepted it, because the only
  //    activation rule was X8's "expiresAt must not already be past" and S3's was
  //    two days out. So the check that existed asked whether the NEW pilot was
  //    still valid and never whether the OLD one was still running.
  //
  //    The cost was not a bad declaration — S3 was correct — but a lost reading.
  //    The Sunday order exists to observe ONE thing: a pilot lapsing, the baseline
  //    taking over, and the next act reading HOLD_BLIND under it. That is the only
  //    way this deployment can see its own baseline govern, and replacing pilot 1
  //    instead of letting it die postponed it by two days. THE ONE OBSERVATION THE
  //    ORDER WAS BUILT TO PRODUCE IS THE ONE THE MACHINE DID NOT PROTECT.
  //
  // ⚠ THE ESCAPE HATCH IS DELIBERATELY NOT A FLAG. To replace a pilot early,
  //   deactivate first: a declaration carrying `pilot.active: false` returns at the
  //   top of this function and is accepted. That makes an early handover TWO
  //   deliberate acts, each moving the declaration hash and each visible in the
  //   book, instead of one act that looks identical to a scheduled one. A flag
  //   would have been copied from an earlier command line; a stand-down cannot be.
  //
  // ⚠ AND IT IS NOT A CLOCK CHECK ON THE NEW PILOT. X8 below still does that. This
  //   rule is about the PREVIOUS one, and the two are independent: a new pilot with
  //   a good expiry is still refused while the old one breathes.
  if (
    prevPilot !== undefined &&
    prevPilot.active === true &&
    Date.parse(prevPilot.expiresAt) > now.getTime()
  ) {
    fail(
      "pilot.sessionId",
      `cross-field rule X9: the current pilot ${prevPilot.sessionId} is ACTIVE until ` +
        `${prevPilot.expiresAt} and may not be replaced before it lapses. This ` +
        `declaration would hand over to ${next.pilot.sessionId} at ` +
        `${now.toISOString()}, and the reading that a lapse produces — the baseline ` +
        `governing, the next act held blind under it — cannot be taken twice. To ` +
        `hand over early, first relay a declaration with pilot.active false, which ` +
        `this door accepts; the stand-down is then its own act and its own hash. ` +
        `Last-known-good declaration is retained.`
    );
  }

  const expiresAtMs = Date.parse(next.pilot.expiresAt);
  if (expiresAtMs <= now.getTime()) {
    fail(
      "pilot.expiresAt",
      `new activation with a past expiresAt is rejected (cross-field rule X8); ` +
        `last-known-good declaration is retained`
    );
  }
}

/**
 * Z4 · MEMBERSHIP AND ROUTES ARE A FIRST-LOAD FACT (ticket Bridge-Zero-Subjects
 * v2 §2, F-5 (a), ruled with eyes open that it is a general fix at every n).
 *
 * Refused on a reload (prev non-null), each with "a first load (restart) only":
 *   · any change to the SET of (subject, peerUid, unit) — adding, removing or
 *     re-uniting a subject, including the last one (n -> 0) and the first (0 -> n);
 *   · any change to the SET of route uids;
 *   · any change to a row's (role, allow) — allow compared as a set.
 *
 * WHY: `start()` is the only place peer directories are validated and sockets
 * bound (planPeerSockets / validatePeerDir); a reload that added a uid made no
 * socket for it, and a reload that granted POST /guard to an existing row
 * passed the uid-set comparison. relay-lib trusts the LIVE file's unit, so a
 * unit changed by SIGHUP would move which caller a cutover confirms stopped.
 *
 * FIRST LOAD IS NEVER REFUSED (prev null), and A RESTART IS A FIRST LOAD: root
 * can lay any declaration by restart. This rule binds the SIGHUP path only.
 */
function validateMembershipUnchangedOnReload(prev: Declarations | null, next: Declarations): void {
  if (prev === null) return;
  const why = "is a first load (restart) only — a reload may not change it (cross-field rule Z4). Last-known-good declaration is retained.";
  const memberKey = (s: Subject): string => JSON.stringify([s.subject, s.peerUid, s.unit ?? null]);
  // `?? []`: the X9 arms hand this gate pilot-only shapes, as X21's sibling notes; absent on both is unchanged.
  const members = (d: Declarations): string[] => [...new Set((d.subjects ?? []).map(memberKey))].sort();
  const pm = members(prev);
  const nm = members(next);
  if (JSON.stringify(pm) !== JSON.stringify(nm)) {
    fail(
      "subjects",
      `subject membership (subject, peerUid, unit) changes across this reload: ${JSON.stringify(pm)} -> ${JSON.stringify(nm)}; membership ${why}`
    );
  }
  const rowKey = (r: Route): string =>
    JSON.stringify([r.uid, r.role, [...new Set(r.allow.map((a) => `${a.method} ${a.path}`))].sort()]);
  const uids = (d: Declarations): number[] => [...new Set((d.routes ?? []).map((r) => r.uid))].sort((a, b) => a - b);
  if (JSON.stringify(uids(prev)) !== JSON.stringify(uids(next))) {
    fail("routes", `the set of route uids changes across this reload: ${JSON.stringify(uids(prev))} -> ${JSON.stringify(uids(next))}; the route set ${why}`);
  }
  const rows = (d: Declarations): string[] => (d.routes ?? []).map(rowKey).sort();
  const pr = rows(prev);
  const nr = rows(next);
  if (JSON.stringify(pr) !== JSON.stringify(nr)) {
    const changed = nr.filter((k) => !pr.includes(k));
    fail("routes", `a route row's (role, allow) changes across this reload: now ${changed.join(", ")}; each row's grant ${why}`);
  }
}

/**
 * X21 · GATE 1's FRAME IS WIDEN-ONLY ACROSS A RELOAD (brief §2).
 *
 * Refused: a subject framed in `prev` with no frame in `next` (which includes
 * retiring the subject itself — its frame goes with it), and any category id of
 * `prev.frame[s]` missing from `next.frame[s]`. Adding subjects, frames and
 * categories is always accepted.
 *
 * WHY NARROWING IS REFUSED RATHER THAN RECORDED: the coverage the reader prints
 * is "reached r of n categories GIVEN M". Dropping a category nobody reached
 * raises r/n without a single act changing — the envelope improves by editing
 * the denominator. The refusal is the BRIEF'S DEPLOYMENT RULE (§2, widen-only),
 * not a canon placement: canon takes M from the doctor / Gate-0 and has its
 * fragility surfaced by the rider, never audited by Gate 1 (03a §6), and it
 * does not hand M-narrowing to Gate 5 (round 3, review K3D3-10). No ruled
 * mechanism for a legitimate narrowing exists yet, so none is admitted.
 *
 * ⚠ WHAT THIS DOES NOT HOLD, stated so nobody relies on it for more:
 *   · REGIONS may move either way. They are a declared proxy for where a
 *     category's places are, not M itself; correcting a wrong prefix is not a
 *     narrowing of the frame.
 *   · a category's label, grounding or `self` flag may change under the same id.
 *   · FIRST LOAD IS NEVER REFUSED (prev null), and A RESTART IS A FIRST LOAD.
 *     `start()` does not consult this gate at all (mica-service.ts, read
 *     2026-10-08), and relay-bridge.sh step 7 SIGHUPs only a DECLARATION-ONLY
 *     relay — a CODE relay restarts the unit. So a narrowed frame that rides a
 *     code relay is not seen by this rule. It guards the SIGHUP path; closing the
 *     restart path needs a durable record of the last frame served. [owed]
 */
function validateFrameWidenOnly(prev: Declarations | null, next: Declarations): void {
  const prevFrame = prev?.frame;
  if (prevFrame === undefined) return;
  const nextFrame = next.frame;
  const gate5 =
    "the declared M-frame is widen-only across a reload — the brief's deployment rule (§2), refused " +
    "until a ruled mechanism for narrowing M exists; canon takes M from the doctor / Gate-0 (03a §6) " +
    "(cross-field rule X21). Last-known-good declaration is retained.";
  for (const s of Object.keys(prevFrame)) {
    if (nextFrame === undefined || !Object.hasOwn(nextFrame, s)) {
      fail(`frame.${s}`, `subject "${s}" had a frame and this declaration removes it — ${gate5}`);
    }
    const kept = new Set(nextFrame[s].categories.value.map((c) => c.id));
    const dropped = prevFrame[s].categories.value.map((c) => c.id).filter((id) => !kept.has(id));
    if (dropped.length > 0) {
      fail(
        `frame.${s}.categories.value`,
        `this declaration drops categor${dropped.length === 1 ? "y" : "ies"} ${JSON.stringify(dropped)} from M — ${gate5}`
      );
    }
  }
}

/**
 * ROUND 3 (A3; reviews K2W-3, K2W3-3, K3D1-4, K3D3-3, K3D3-2). THE INTEREST
 * BOOK IS OPENED ONLY AT START (mica-service start()), and the wiring
 * re-resolves `paths.interestBook` from the declaration on every reload. A
 * reload that MOVED the key split them: the writer kept filing labels into the
 * start-time file while Gate 1 read the new path (blind on an absent file, or
 * a clean "reached 0 of n" over the subject chain after a swap), and nothing in
 * the event book said so. One that ADDED it (with a frame) lost every label act
 * by act. So any change — added, moved or removed — is refused here, with X21,
 * before the pilot rules' early returns. Compared AS DECLARED: the book's own
 * pattern admits no second spelling of one file. Changing the book takes a
 * restart, which opens the new one.
 * ⚠ FIRST LOAD (prev null) is never refused, and a RESTART IS A FIRST LOAD.
 */
function validateInterestBookUnchanged(prev: Declarations | null, next: Declarations): void {
  if (prev === null) return;
  // `?.` on paths: X21's sibling reads `prev?.frame` the same way, and callers
  // (the X9 arms) hand this gate pilot-only shapes; absent on both is unchanged.
  const before = prev.paths?.interestBook;
  const after = next.paths?.interestBook;
  if (before === after) return;
  const change =
    before === undefined ? "ADDS it" : after === undefined ? "REMOVES it" : `MOVES it from ${JSON.stringify(before)}`;
  fail(
    "paths.interestBook",
    `this reload ${change}${after === undefined ? "" : ` (to ${JSON.stringify(after)})`}. The interest book is ` +
      `opened only at start: after the reload the writer would keep the book it opened (or none) while the ` +
      `reader followed the declaration, so labels would land where nothing reads them. Changing ` +
      `paths.interestBook takes a restart. Last-known-good declaration is retained.`
  );
}

/**
 * R15 · A BASKET'S DAMAGE TERMS MAY NOT BE DROPPED ACROSS A RELOAD (contract §4;
 * RMBA V/D §16 anti-laundering — deflating D by edit).
 *
 * Refused: a subject with a basket in `prev` and none in `next` (which includes
 * retiring the subject — its basket goes with it), and any damage[] or unknown[]
 * entry of `prev` — keyed (kind, outcome) — missing from the SAME list in
 * `next`. So MOVING an entry between lists is a drop from the list it left.
 * Adding entries, subjects and baskets is accepted.
 *
 * ⛔ AND FROZEN (2026-10-10, K2-canon refuter): after the membership checks above,
 * a basket of `prev` must come back CANONICALLY IDENTICAL in `next`. The reader
 * recomputes every reading — its latch included — from the CURRENT basket, so any
 * edit a reload admits (a weight lowered, establishAt raised, nMin raised, ε moved,
 * a clearer or even an entry ADDED — an added unknown blocks a past onset) rewrites
 * past readings and can make a standing latch vanish with no record on the chain:
 * neither "the arbiter's record" (F5) nor RMBA §16's governed change. Any change to a
 * declared basket therefore takes a RESTART — a first load, the arbiter's visible act.
 * Adding a basket for a subject that had none, or declaring the reader where none
 * was, is still accepted.
 *
 * AND THE READER (added 2026-10-09 on the rehearsal builder's finding): a
 * reload that REMOVES `readers.gate2Direction`, or points it at another
 * subject, while `prev` declared it, is refused too. Measured before the fix:
 * dropping the reader alone (keeping `baskets`) was ACCEPTED and the wiring
 * after it carried no `gate2` — Gate 2 removed by SIGHUP, every damage and
 * unknown term with it, while the basket rule above saw nothing dropped.
 *
 * ⚠ WHAT THIS DOES NOT HOLD, stated so nobody relies on it for more:
 *   · FIRST LOAD IS NEVER REFUSED (prev null), and A RESTART IS A FIRST LOAD —
 *     X21's caveat word for word: `start()` does not consult this gate and a
 *     CODE relay restarts the unit, so a basket narrowed on a code relay is not
 *     seen here. This rule guards the SIGHUP path only. [owed]
 */
function validateBasketNotDeflated(prev: Declarations | null, next: Declarations): void {
  const why =
    `${g2Rule(15, "RMBA V/D §16 anti-laundering: deflating D by edit")}. A declared basket is frozen across reloads; a first load ` +
    `is never refused, and a restart is a first load. Last-known-good declaration is retained.`;
  // THE READER FIRST: without it no term of any basket is read, so removing it
  // (or moving it to another subject) drops every damage and unknown term at once.
  // `?.` on prev/readers for the X9 arms' pilot-only shapes, as X21's sibling does.
  const prevReader = prev?.readers?.gate2Direction;
  if (prevReader !== undefined) {
    const nextReader = next.readers?.gate2Direction;
    if (nextReader === undefined) {
      fail(`readers.gate2Direction`, `this reload removes Gate 2's reader, which drops every term of the basket it read ${why}`);
    }
    if (nextReader.subject.value !== prevReader.subject.value) {
      fail(
        `readers.gate2Direction.subject`,
        `this reload moves Gate 2's reader from subject "${prevReader.subject.value}" to "${nextReader.subject.value}", ` +
          `which drops every term of the basket it read ${why}`
      );
    }
  }
  const prevB = prev?.baskets;
  if (prevB === undefined) return;
  const nextB = next.baskets;
  const key = (c: { kind: string; outcome: string | null }): string => JSON.stringify([c.kind, c.outcome]);
  for (const s of Object.keys(prevB)) {
    if (nextB === undefined || !Object.hasOwn(nextB, s)) {
      fail(`baskets.${s}`, `subject "${s}" had a basket and this reload removes it ${why}`);
    }
    for (const list of ["damage", "unknown"] as const) {
      const kept = new Set(nextB[s].classes.value[list].map(key));
      const dropped = prevB[s].classes.value[list]
        .filter((c) => !kept.has(key(c)))
        .map((c) => `(${c.kind}, ${JSON.stringify(c.outcome)})`);
      if (dropped.length > 0) {
        fail(
          `baskets.${s}.classes.value.${list}`,
          `this reload DROPS ${list}[] entr${dropped.length === 1 ? "y" : "ies"} ${dropped.join(", ")} ${why}`
        );
      }
    }
    if (canonicalHash(prevB[s]) !== canonicalHash(nextB[s])) {
      fail(
        `baskets.${s}`,
        `this reload CHANGES subject "${s}"'s basket: a declared Gate-2 basket is FROZEN across reloads — the reader ` +
          `recomputes every reading from the current basket, so an edit would rewrite past readings and a standing ` +
          `latch could vanish with no record. Change it by a restart ${why}`
      );
    }
  }
}

/**
 * H11 · A HARM STANZA MAY NOT BE LOOSENED ACROSS A RELOAD — R15's harm analogue
 * (seat's ruling 2026-10-15, on the bridge builder's open question 1).
 *
 * WHY: relay-declaration.sh lays a declaration by `systemctl reload` (SIGHUP), so
 * the doctor's C1 clearances arrive by reload — and the reader re-derives its
 * latch from the CURRENT stanza at every read. A reload that widened a grant,
 * removed an item, or removed a clearance would therefore dissolve a standing
 * latch WITHOUT the doctor's clearance, with no record of it on the witness's book.
 *
 * REFUSED on reload, each a `(harm front-door refusal H11 — …)`:
 *   (a) removing harm[subject], or any item;
 *   (b) changing an item's path, category or control;
 *   (c) adding an origin to an existing item's grant list (widening);
 *   (d) removing or changing any clearance (a changed record IS a removal);
 *   (e) removing an origin, or re-binding it to another subject.
 *   (f) while prev declares any harm stanza: moving paths.witnessBook or
 *       paths.witnessIntake, or readers.gate2Direction.book / .witnessMethod
 *       (evasion test 5.H11-gap: a reload that points Gate 2 at a FRESH book
 *       re-derives the latch from nothing). paths.interestBook (the roster) is
 *       already frozen across a reload by validateInterestBookUnchanged.
 * ALLOWED on reload: a new item with its grant list, a new origin, NARROWING a
 * grant list, ADDING a clearance (that is the clearer), and any basis text.
 *
 * ⚠ THE SAME CEILING R15 PRINTS, PRINTED HERE, NOT CLOSED: FIRST LOAD IS NEVER
 *   REFUSED (prev null), and A RESTART IS A FIRST LOAD — `start()` does not consult
 *   this gate, so a stanza loosened across a restart (a code relay restarts the
 *   unit) is not seen here. This rule guards the SIGHUP path only. [owed]
 */
function validateHarmNotLoosened(prev: Declarations | null, next: Declarations): void {
  const prevH = prev?.harm;
  if (prevH === undefined) return;
  const why = (c: string) =>
    `${hRule(11, `a harm stanza only tightens across a reload: ${c}`)}. A first load is never refused, and a restart is a ` +
    `first load. Last-known-good declaration is retained.`;
  const nextH = next.harm;
  // (f) THE BOOK THE LATCH IS RE-DERIVED FROM, and the method that names its records: values only (a basis may move).
  if (Object.keys(prevH).length > 0) {
    const fixed: [string, string | undefined, string | undefined][] = [
      ["paths.witnessBook", prev!.paths.witnessBook?.value, next.paths.witnessBook?.value],
      ["paths.witnessIntake", prev!.paths.witnessIntake?.value, next.paths.witnessIntake?.value],
      ["readers.gate2Direction.book", prev!.readers.gate2Direction?.book?.value, next.readers.gate2Direction?.book?.value],
      ["readers.gate2Direction.witnessMethod", prev!.readers.gate2Direction?.witnessMethod?.value, next.readers.gate2Direction?.witnessMethod?.value],
    ];
    for (const [field, was, now] of fixed) {
      if (was !== now) {
        fail(
          field,
          `this reload moves ${field} (${JSON.stringify(was ?? null)} → ${JSON.stringify(now ?? null)}) while a harm stanza is ` +
            `declared: the latch is re-derived from the book, so a fresh book would dissolve it ${why("(f) the book, the intake and the method are fixed while harm is declared")}`
        );
      }
    }
  }
  for (const s of Object.keys(prevH)) {
    const f = `harm.${s}`;
    if (nextH === undefined || !Object.hasOwn(nextH, s)) {
      fail(f, `this reload removes subject "${s}"'s harm stanza, which drops every item it protected ${why("(a) no stanza or item is removed")}`);
    }
    const p = prevH[s];
    const n = nextH[s];
    for (const id of Object.keys(p.origins.value)) {
      if (!Object.hasOwn(n.origins.value, id)) {
        fail(`${f}.origins.value.${id}`, `this reload removes origin "${id}" ${why("(e) no origin is removed or re-bound")}`);
      }
      if (n.origins.value[id].subject !== p.origins.value[id].subject) {
        fail(`${f}.origins.value.${id}.subject`, `this reload re-binds origin "${id}" to another subject ${why("(e) no origin is removed or re-bound")}`);
      }
    }
    for (const id of Object.keys(p.items.value)) {
      if (!Object.hasOwn(n.items.value, id)) {
        fail(`${f}.items.value.${id}`, `this reload removes item "${id}" ${why("(a) no stanza or item is removed")}`);
      }
      for (const k of ["path", "category", "control"] as const) {
        if (n.items.value[id][k] !== p.items.value[id][k]) {
          fail(`${f}.items.value.${id}.${k}`, `this reload changes item "${id}"'s ${k} ${why("(b) an item's path, category and control are fixed")}`);
        }
      }
      const was = new Set(p.grants.value[id].origins);
      const added = n.grants.value[id].origins.filter((o) => !was.has(o));
      if (added.length > 0) {
        fail(
          `${f}.grants.value.${id}.origins`,
          `this reload WIDENS item "${id}"'s grant list by ${JSON.stringify(added)} ${why("(c) a grant list may only narrow")}`
        );
      }
      // S216 · (c') a kept origin's since may only move LATER: an earlier since re-labels past records as granted.
      for (const o of n.grants.value[id].origins) {
        if (!was.has(o)) continue;
        if (harmSinceMs(n.grants.value[id].since[o]) < harmSinceMs(p.grants.value[id].since[o])) {
          fail(
            `${f}.grants.value.${id}.since.${o}`,
            `this reload moves "${o}"'s since on item "${id}" EARLIER (${p.grants.value[id].since[o]} -> ${n.grants.value[id].since[o]}) ${why("(c') a since may only move later (S216)")}`
          );
        }
      }
    }
    // S208-2 · (g) the errand envelope may only NARROW across a reload: added where absent, a category added, or a
    // longer window is a widening of what an errand can grant.
    if (n.errand !== undefined) {
      const pe = p.errand;
      const widened =
        pe === undefined ||
        n.errand.value.categories.some((c) => !pe.value.categories.includes(c)) ||
        n.errand.value.maxWindowMinutes > pe.value.maxWindowMinutes;
      if (widened) fail(`${f}.errand.value`, `this reload WIDENS what an errand may grant ${why("(g) an errand envelope may only narrow (S208-2)")}`);
    }
    const kept = new Set(n.clearances.value.map((c) => `${c.record}:${c.hat}`));
    for (const c of p.clearances.value) {
      if (!kept.has(`${c.record}:${c.hat}`)) {
        fail(`${f}.clearances.value`, `this reload removes or changes the clearance of record ${c.record} ${why("(d) a clearance is never removed or changed")}`);
      }
    }
  }
}

export { canonicalHash };
