// ── to-guard-flags — declaration (+ resolved subject) -> mica-guard CLI flags ─
//
// Server-side resolution only (design §A.4, brief Stage 0): the caller never
// supplies its own stakesClass; toGuardFlags looks the subject up in
// declarations.subjects[] and refuses a subject/toolName it does not find.
// The pilot override applies only when pilotState is ACTIVE for the session
// that is asking — never merely because the declaration carries an active
// pilot for a different session (design §B.2 Case 2 vs the ALARM invariant,
// Stage 4).
//
// [verified] citations for the mapping, one per flag:
//   --readable-load-state   src/glue/wire.ts:205 (WireOptions.readableLoadStates)
//   --line-classes          chokepoint/types.ts:147-152 (StakesLine.classes); wire.ts:212
//   --hold-at-or-above      chokepoint/types.ts:157 (StakesLine.holdAtOrAbove); wire.ts:212
//   --stakes-class          chokepoint/types.ts:160-167 (Stakes.impactClass); wire.ts:214-219
//   --log                   src/glue/wire.ts:183 (WireOptions.logPath); mica-guard.ts:340-341.
//                           AMENDMENT 9 / RULING P — absent, wire.ts:370-374 leaves Eng and Sig
//                           wired:false and no instrument can ever return ALARM.
//   --log-kind              src/glue/wire.ts:196 (WireOptions.logKind); mica-guard.ts:343-349.
//                           Named explicitly (mica|witness), never sniffed.

import type { Declarations, PilotState, Subject } from "./declarations";

export class UnknownSubjectError extends Error {
  constructor(subject: string) {
    super(`unknown subject "${subject}"`);
    this.name = "UnknownSubjectError";
  }
}
export class ToolNameMismatchError extends Error {
  constructor(subject: string, expected: string, got: string) {
    super(`subject "${subject}" is bound to toolName "${expected}", got "${got}"`);
    this.name = "ToolNameMismatchError";
  }
}

export interface GuardFlagsResult {
  /** One flag per array element, --readable-load-state repeated as declared. */
  readonly flags: readonly string[];
  readonly stakesClass: string;
  readonly holdAtOrAbove: string;
  readonly pilotApplied: boolean;
}

function resolveSubject(declarations: Declarations, subject: string, toolName: string): Subject {
  const row = declarations.subjects.find((s) => s.subject === subject);
  if (!row) throw new UnknownSubjectError(subject);
  if (row.toolName !== toolName) {
    throw new ToolNameMismatchError(subject, row.toolName, toolName);
  }
  return row;
}

/**
 * `sessionId` is the caller's asserted session (from the request), used only
 * to decide whether an ACTIVE pilot's override applies to THIS call. An
 * EXPIRED or INACTIVE pilot, or a mismatched sessionId, always falls back to
 * the baseline line — the override never widens by accident.
 */
export function toGuardFlags(
  declarations: Declarations,
  pilotState: PilotState,
  subject: string,
  toolName: string,
  sessionId: string | null
): GuardFlagsResult {
  const subjectRow = resolveSubject(declarations, subject, toolName);

  const pilotApplied = pilotState.state === "ACTIVE" && sessionId !== null && pilotState.sessionId === sessionId;
  const holdAtOrAbove = pilotApplied
    ? (pilotState as { holdAtOrAbove: string }).holdAtOrAbove
    : declarations.stakes.baseline.holdAtOrAbove.value;

  const flags: string[] = [];
  for (const state of declarations.readers.readableLoadStates.value) {
    flags.push("--readable-load-state", state);
  }
  flags.push("--line-classes", declarations.stakes.lineClasses.join(","));
  flags.push("--hold-at-or-above", holdAtOrAbove);
  flags.push("--stakes-class", subjectRow.stakesClass);
  flags.push("--log", declarations.readers.logPath.value);
  flags.push("--log-kind", declarations.readers.logKind.value);

  return { flags, stakesClass: subjectRow.stakesClass, holdAtOrAbove, pilotApplied };
}
