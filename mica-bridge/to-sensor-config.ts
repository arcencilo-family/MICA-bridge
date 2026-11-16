// ── to-sensor-config — declaration -> `mica-guard --sensor-config` body ─────
//
// TWO DIFFERENT KEY SETS, AND THIS HEADER USED TO CONFLATE THEM. What this
// function EMITS is narrow; what mica-guard ACCEPTS is wider. Codex's cold read
// of the Eng key-set act (2026-10-01, finding F2) caught the conflation: the old
// line named three eng keys and said "nothing else", which is true of this
// projection and FALSE of the guard.
//
// (1) WHAT THIS FUNCTION EMITS — the whole contract of this file:
//       eng: structureThreshold, minimumSampleSize, minimumClassCoverage
//       sig: clockToleranceMs, clockToleranceBasis, preconditionMap, reentryMap
//
//     ⛔ THE SIG LINE SAID TWO AND THE FUNCTION EMITS FOUR. Codex, Key-Set-2
//        read, finding F2: the refreshed header still understated this file's own
//        output, having been corrected once already for understating the GUARD's.
//        `preconditionMap` and `reentryMap` are projected here exactly like the
//        other two and were simply left out of the sentence.
//
//     ⚠ AND THE LIST ABOVE IS NO LONGER THE AUTHORITY — a comment that restates
//       a key set is a copy, and this one has now been wrong twice. The authority
//       is the check "EMITTED FIELDS: toSensorConfig's output key sets are
//       exactly these" in declarations.test.ts, which asserts the sets against
//       the real output. If this comment drifts from the function again, that
//       check fails; if the function gains a field, that check fails until
//       somebody decides whether it belongs here. The comment is a courtesy to a
//       reader, not a contract.
//     Nothing else, ever. Every declaration envelope is stripped to its bare
//     `value`, and a key absent from the declaration is ABSENT from the output
//     rather than present-and-undefined — the sensor's "absent" arm is written
//     against the key not being there.
//
// (2) WHAT mica-guard ACCEPTS — wider, and not this file's contract to state.
//     [verified 2026-10-01 · /opt/mica-machine VINTAGE dcee6563 · BY SYMBOL]
//       readSensorConfig           top-level "eng" and "sig" ONLY; throws
//                                  GuardInvocationError on any other key
//       ENG_NUMERIC_KEYS           structureThreshold, minimumSampleSize,
//                                  ceilingMargin, windowSize,
//                                  permutationSamples, permutationSeed
//       ENG_POSITIVE_INTEGER_KEYS  minimumClassCoverage (integer >= 1)
//       SIG_NUMERIC_KEYS           clockToleranceMs
//       SIG_TEXT_KEYS              clockToleranceBasis
//       SIG_MAP_KEYS               preconditionMap, reentryMap
//     Phase A never sets ceilingMargin/windowSize/permutationSamples/
//     permutationSeed (design §A.3) — THAT is why the projection is narrower,
//     not because the guard would refuse them.
//
// (3) THREE KEYS THE GUARD NAMES AND REFUSES OUTRIGHT inside an eng/sig block —
//     readableLoadStates, probeSource, clerkClockSource — each with its own
//     refusal message in validateReaderConfig. This function never emits them
//     there; readableLoadStates goes to --readable-load-state instead
//     (to-guard-flags.ts).
//
// ⛔ NO `:NNN` REFERENCES INTO mica-machine — ON PURPOSE, AND NOW ACTUALLY DONE.
//    The previous header SAID it had dropped them and had not: it still carried
//    `mica-guard.ts:271-277 (readSensorConfig)` and `(:197-232)`, and when Codex
//    checked, BOTH already pointed at the wrong lines — readSensorConfig and the
//    three named refusals had each moved. Those two quoted numbers are the
//    DEFECT BEING DESCRIBED, not references to rely on, and this header mints no
//    replacements for them on purpose: a fresh line number is the same trap with
//    a newer date on it. A line number into a repo this file does not own points
//    at the wrong line after the next edit there, and NOTHING HERE FAILS WHEN IT
//    DOES. Symbols and a date instead, so the next reader can price the claim's
//    age rather than trust the word [verified].

import type { Declarations } from "./declarations";

export interface SensorConfig {
  readonly eng: {
    readonly structureThreshold: number;
    readonly minimumSampleSize: number;
    /** T11. Absent when the declaration does not carry it — the sensor then says so. */
    readonly minimumClassCoverage?: number;
  };
  readonly sig: {
    readonly clockToleranceMs: number;
    readonly clockToleranceBasis: string;
    /**
     * C9. Both maps are `Readonly<Record<string, readonly string[]>>` —
     * structurally exactly mica-machine's `PreconditionMap` / `ReentryMap`
     * (`sig/index.ts:71, :97`), declared structurally here rather than imported
     * so this file keeps taking NO import edge into mica-machine at all, which
     * is what its header has always claimed.
     *
     * They travel as OBJECTS, in process. There is no flag encoding to invent:
     * `to-guard-flags.ts` resolves the stakes line, never sensor config, and the
     * gate has not used the `mica-guard` CLI subprocess since Stage 4 §A bound
     * `evaluateAndRecord` in directly.
     */
    readonly preconditionMap: Readonly<Record<string, readonly string[]>>;
    readonly reentryMap: Readonly<Record<string, readonly string[]>>;
  };
}

export function toSensorConfig(declarations: Declarations): SensorConfig {
  return {
    eng: {
      structureThreshold: declarations.readers.eng.structureThreshold.value,
      minimumSampleSize: declarations.readers.eng.minimumSampleSize.value,
      // Omitted entirely when undeclared: mica-guard REFUSES a wrong-shaped
      // value and the sensor's "absent" arm is written against a missing key,
      // so emitting `undefined` here would be a third shape neither handles.
      ...(declarations.readers.eng.minimumClassCoverage === undefined
        ? {}
        : { minimumClassCoverage: declarations.readers.eng.minimumClassCoverage.value }),
    },
    sig: {
      clockToleranceMs: declarations.readers.sig.clockToleranceMs.value,
      clockToleranceBasis: declarations.readers.sig.clockToleranceBasis.value,
      preconditionMap: declarations.readers.sig.preconditionMap.value,
      reentryMap: declarations.readers.sig.reentryMap.value,
    },
  };
}
