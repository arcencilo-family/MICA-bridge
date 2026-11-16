// ── guard-adapter — the seam Stage 1's evaluateAndRecord binds into ────────
//
// Stage 2 is infrastructure only. `/guard` must never fabricate a
// disposition before Stage 1 lands — so the adapter interface is typed now,
// and the ONLY implementation shipped in Stage 2 is one that says, honestly,
// that no evaluation is bound yet. This matches the design amendment's
// PREPARED/FINAL model at the type level (a GuardOutcome carries a
// `declarationBinding`, mirroring `ARC_MICA-DESIGN_Phase-A-Stage-1-Amendment-1`
// §"Declaration binding") without importing anything from mica-machine or
// executing any of its code — that is Stage 1's wiring, not this stage's.

export interface GuardEvaluationRequest {
  readonly subject: string;
  readonly sessionId: string;
  readonly actionId: string;
  readonly toolName: string;
  readonly stakesClass: string;
  readonly holdAtOrAbove: string;
  readonly pilotApplied: boolean;
  readonly declarationHash: string;
}

export type DeclarationBinding =
  | { readonly kind: "HASH"; readonly sha256: string }
  | { readonly kind: "UNBOUND_STAGE_1" }
  // ZERO SUBJECTS (Z0, layer 4): the declaration names no subject, so no evaluator exists to bind.
  | { readonly kind: "NOTHING_DECLARED" };

/**
 * AMENDMENT 11 / RULING R, item 2 (the orchestrator's addition, not the arbiter's
 * ruling): the printed ceiling. A concession recorded only in a `basis`
 * field nobody re-reads is not a printed ceiling — so whenever a reading is
 * taken under a load state that is not `LOADED_VERIFIED`, that fact must
 * appear on the reading's OWN FACE, in both `GET /status` and here, in the
 * `/guard` response, so a consumer of a disposition can see the footing it
 * stands on without going to look for it. A CENSUS FIELD: it states the
 * fact (which load state was actually observed, and whether it was the
 * chain-verified one), never a verdict and never reassurance. It does NOT
 * mean the log IS tampered — only that, below `LOADED_VERIFIED`, nothing
 * here would know either way.
 */
export interface ReaderFooting {
  readonly reader: string;
  readonly loadState: string;
  readonly verifiedChain: boolean;
}

/**
 * AMENDMENT 11 / RULING R item 2. Pure, and deliberately so: this is the
 * one place "is this load state the chain-verified one" is decided, and
 * keeping it pure means it can be unit-tested directly against every load
 * state mica-machine's readers can report, without needing a live wire()
 * call to exercise the verified branch (which MicaLogFile itself can never
 * produce — see the Amendment 10 survey).
 *
 * ACT A widened the judgement from `=== "LOADED_VERIFIED"` to membership of
 * `VERIFIED_CHAIN_LOAD_STATES` below. It is still ONE place, and still pure.
 *
 * P6 MOVED IT HERE from `mica-service.ts` (which re-exports it, so nothing
 * that imported it from there changes). It now has TWO callers — `/status`'s
 * instrument census and `/guard`'s per-decision footing — and a judgement
 * with two callers that lives inside one of them is a judgement waiting to be
 * copied. It sits beside the type it produces instead.
 */
/**
 * ACT A / the arbiter's ruling 2, 2026-09-22. THE DECLARED LIST.
 *
 * THE DEFECT THIS ENDS, found 2026-09-21 and load-bearing: `verifiedChain` was
 * a STRING EQUALITY AGAINST ONE LITERAL, and the only chained adapters that
 * exist deliberately do not use that literal. `witness-log-file.ts:126-131`
 * says why, by name: "a store that verified is not the same fact as a JSONL
 * that merely parsed, and the two must not share a string." So a correct,
 * genuinely chained subject log, routed through a correct adapter, printed
 * `verifiedChain: false` — the acceptance test would have failed a build that
 * had done everything right, because of one `===`.
 *
 * ⚠ IT IS DECLARED HERE, IN CODE, AND DELIBERATELY NOT IN
 * `declarations.config.json`. "Which load states MEAN a verified chain" is a
 * fact about the ADAPTERS — each of these strings is a constant exported by the
 * adapter that earns it. "Which load states this deployment ACCEPTS" is a
 * different question and it already has a declaration field,
 * `readers.readableLoadStates`. Making this one a deployment knob would let an
 * operator declare `LOADED_UNVERIFIED_FILE` verified and have `/status` print
 * `verifiedChain: true` about a file with no chain in it — a census field
 * lying on its own face, which is the disclaimer engineering canon 02c
 * refuses.
 *
 * ⚠ THE RESIDUAL, NAMED RATHER THAN DISCOVERED: this list lives in the bridge
 * and the adapters live in mica-machine. A machine-side adapter that earns a
 * chain and is not added here reads `verifiedChain: false` — which is the SAFE
 * direction (it under-claims, never over-claims), and it is still drift. Each
 * entry therefore names the file it came from, so the census is checkable by
 * reading two files rather than by remembering.
 */
export const VERIFIED_CHAIN_LOAD_STATES: readonly string[] = [
  // src/mica/fixture-log.ts, src/mica/chokepoint/floor-trail.ts,
  // src/glue/decision-journal.ts — chained, hashes recomputed at load.
  "LOADED_VERIFIED",
  // src/glue/witness-log-file.ts — a witness store, chained by the WITNESS,
  // which is a different principal from the submitters it is about.
  "LOADED_WITNESS_CHAIN_VERIFIED",
  // src/glue/subject-event-journal.ts (Act A) — the bridge's own subject log,
  // hash-chained. TAMPER-EVIDENT, NOT INDEPENDENT: the writer, the chainer and
  // the verifier are all `mica-bridge`. `verifiedChain: true` here means the
  // chain held, never that a second party attested it. Act B is what would.
  "LOADED_SUBJECT_CHAIN_VERIFIED",
];

export function computeFooting(reader: string, loadState: string): ReaderFooting {
  return {
    reader,
    loadState,
    verifiedChain: VERIFIED_CHAIN_LOAD_STATES.includes(loadState),
  };
}

/**
 * P6. WHOSE READING `readerFootings` IS — and the reason this field exists at
 * all rather than the array being left to speak for itself.
 *
 * THE DEFECT IT CLOSES (register E1, named against this codebase by
 * `stage1-guard-adapter.ts` before it was fixed): a field that reads
 * identically whether or not the thing it describes happened. `readerFootings:
 * []` is exactly that shape. It can mean:
 *
 *   (a) this decision's `wire()` call built no log reader — nothing read, and
 *       the empty array is the whole truth; or
 *   (b) this call never took a reading at all, because it did not evaluate
 *       anything: it REPLAYED an existing DECISION_FINAL. The footing that
 *       decision was taken under belongs to the original call and is not
 *       recorded anywhere.
 *
 * Those are different facts and they now carry different values. (b) is the
 * one that must never be dressed as (a): a consumer reading `[]` on a replay
 * would conclude "no reader was wired for this decision", which is a claim
 * about the deployment that nothing here knows.
 *
 * WHAT IT IS NOT: a quality signal. `THIS_CALL` says a reading was taken by
 * the call that produced this disposition. It says nothing about whether that
 * reading was adequate — `ReaderFooting.verifiedChain` is where that exposure
 * is stated, and it is a fact too, not reassurance.
 */
export type ReaderFootingsBasis =
  | { readonly kind: "THIS_CALL" }
  | { readonly kind: "NO_READING_TAKEN"; readonly reason: string };

/**
 * What `/guard` returns to the caller. Never fabricated when `bound:false`.
 *
 * STAGE 4 / DESIGN §A.5 WIDENING, flagged here rather than silently done:
 * the design doc's own §A.5 mapping table requires a bound adapter to be
 * able to report `409 IDENTITY_HASH_CONFLICT`, `400 MALFORMED_FIELD`, and
 * `500 SERVICE_FAULT` — three rows that do NOT fit the type as Stage 2
 * shipped it (a `bound:true` arm hard-typed to `httpStatus: 200`). The SAME
 * paragraph of the design claims "guard-adapter.ts needs no type change" —
 * that claim is false against this file as it stood at Stage 4 dispatch;
 * it could only have been true of a `GuardOutcome` that did not yet exist.
 * Reported as a design/code contradiction in the Stage 4 receipt, not
 * silently corrected: the alternative (leave the extra rows unrepresentable
 * and let `Stage1GuardAdapter` throw instead) is worse — an uncaught throw
 * inside `evaluate()` propagates out of `handleGuard`'s un-caught `await`
 * and leaves the caller's HTTP request hanging with no response ever sent,
 * which is a strictly worse failure mode than a widened, honestly-typed
 * union. The 200 and 503 arms below are BYTE-FOR-BYTE what Stage 2/11
 * shipped; only a new middle arm was added.
 */
export type GuardOutcome =
  | {
      readonly bound: true;
      readonly httpStatus: 200;
      readonly decision: Readonly<Record<string, unknown>>;
      readonly delivery: Readonly<Record<string, unknown>>;
      /**
       * AMENDMENT 11 / RULING R item 2. REQUIRED, not optional — the type
       * itself forces whichever adapter eventually returns `bound:true`
       * (Stage 1's evaluateAndRecord) to supply the footing every reader
       * that contributed to this disposition actually read under. Never
       * populated by anything in Stage 2: `NotBoundGuardAdapter` never
       * returns `bound:true` at all.
       */
      readonly readerFootings: readonly ReaderFooting[];
      /**
       * P6. REQUIRED beside the array, never optional, for the reason
       * `ReaderFootingsBasis` gives: an empty `readerFootings` is ambiguous
       * on its own, and an optional disambiguator is one a caller forgets
       * exactly when it matters. Making it required means the type itself
       * forces every adapter to say which empty it means.
       */
      readonly readerFootingsBasis: ReaderFootingsBasis;
      /**
       * STAGE 4 / DESIGN §A.5: "quarantined is passed through as an array
       * (possibly empty) — it is the orphan-PREPARED report and a caller
       * that ignores it loses the only evidence that a prior evaluation
       * died between phases." Named in the design's prose but absent from
       * the Stage 2 type; added here for the same reason as the arm above.
       */
      readonly quarantined: readonly Readonly<Record<string, unknown>>[];
    }
  | {
      /**
       * STAGE 4 / DESIGN §A.5's CONFLICT / UsageError / other-throw rows.
       * `bound:true` because an evaluation WAS obtained from a real,
       * bound adapter — this is not the "no evaluation was obtained"
       * shape ruling J's `bound:false` arm exists for. Only the outcome
       * of that evaluation was an error rather than a disposition.
       */
      readonly bound: true;
      readonly httpStatus: 409 | 400 | 500;
      readonly error: string;
      readonly detail: string;
      readonly identity: { readonly subject: string; readonly sessionId: string; readonly actionId: string };
    }
  | {
      readonly bound: false;
      readonly httpStatus: 503;
      readonly error: "GUARD_NOT_BOUND" | "NOTHING_DECLARED";
      readonly detail: string;
      readonly declarationBinding: DeclarationBinding;
    };

export interface GuardAdapter {
  evaluate(request: GuardEvaluationRequest): Promise<GuardOutcome>;
}

/**
 * The only adapter Stage 2 ships. It never returns a disposition — HOLD,
 * HOLD_BLIND, PASS_BLIND, or RELEASE are all Stage 1's evaluated outcomes,
 * and none of them is honestly available until `evaluateAndRecord` is wired
 * in. `503 GUARD_NOT_BOUND` is a preflight-shaped failure (ruling J: no
 * evaluation was obtained), never dressed up as a computed HOLD.
 */
export class NotBoundGuardAdapter implements GuardAdapter {
  async evaluate(request: GuardEvaluationRequest): Promise<GuardOutcome> {
    return {
      bound: false,
      httpStatus: 503,
      error: "GUARD_NOT_BOUND",
      detail:
        `Stage 1's evaluateAndRecord is not yet bound into this service. ` +
        `identity=(${request.subject},${request.sessionId},${request.actionId}) was received ` +
        `and NOT evaluated — no disposition exists for it.`,
      declarationBinding: { kind: "UNBOUND_STAGE_1" },
    };
  }
}

/**
 * ZERO SUBJECTS · LAYER 4 OF FOUR (ticket Bridge-Zero-Subjects v2 §2.2, F-1 (a)).
 *
 * Bound by `buildGuardAdapter` whenever the declaration names NO subject
 * (`subjects: []`). It never returns a disposition and never reaches an
 * evaluator: there is no conduct this deployment has been asked to read, so
 * there is nothing to evaluate. `503 NOTHING_DECLARED` is the absence of a
 * reading, not a fourth verdict and not CANNOT_ASSESS.
 *
 * It is the LAST of four independent refusals in front of `/guard` at zero
 * (authorizeRoute + Z5, handleGuard's top check, toGuardFlags, this). A path
 * that skipped the first three still reaches no evaluator here.
 *
 * NOT a subclass of NotBoundGuardAdapter on purpose: `/status.guardBound`
 * names both classes, so neither reads as "bound" by inheritance or by its
 * absence.
 */
export class NothingDeclaredGuardAdapter implements GuardAdapter {
  async evaluate(request: GuardEvaluationRequest): Promise<GuardOutcome> {
    return {
      bound: false,
      httpStatus: 503,
      error: "NOTHING_DECLARED",
      detail:
        `NOTHING DECLARED — the declaration names no subject (subjects: []). ` +
        `identity=(${request.subject},${request.sessionId},${request.actionId}) was received ` +
        `and NOT evaluated — no reader is wired and no disposition exists for it.`,
      declarationBinding: { kind: "NOTHING_DECLARED" },
    };
  }
}
