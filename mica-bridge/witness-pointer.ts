// ── TIER 1 · the bridge's half of the WITNESS'S POINTER CONTRACT ─────────────
//
// RULED (the arbiter, board 2026-10-10 18:20Z; audit 18:03Z): the witness SEES and
// WRITES. Its seeing half (mica-machine `src/witness/seeingd.ts`, its own uid)
// looks at the ONE target each act claimed and writes the effect into its own
// book. The bridge is the only party that holds the plain target — in memory,
// at the TOOL_ATTEMPTED label site, for one request — so the bridge is the one
// writer of the witness's intake. This file is that writer, and the one place
// the bridge names the witness's record class.
//
// ── TWO COPIES OF ONE FORMAT, ON PURPOSE ─────────────────────────────────────
//
//   The reader end is `seeing-intake.ts` in the machine. The bridge does not
//   import it (the bridge imports the INSTALLED machine, which predates it), so
//   the shape is spelt twice and each side pins it with its own fixtures — the
//   drop committer's rule for a format with two ends. A drop of any other shape
//   is quarantined by the witness, never repaired.
//
// ── NO ONE WAITS (audit 18:03Z (3)) ──────────────────────────────────────────
//
//   `dropPointer` is SYNCHRONOUS and returns a result; it never throws into the
//   act's path, and the act's response is already sent when it runs. A failed
//   drop is an act the witness will not see — a coverage gap the census prints —
//   never a change to what the subject was told or whether it ran.

import { chmodSync, renameSync, writeFileSync } from "fs";
import { createHash } from "crypto";
import { join } from "path";

/** The witness's record kind as a basket declares it (declarations.ts GATE2_WITNESS_KIND). */
export const WITNESS_RECORD_CLASS_PREFIX = "CONSEQUENCE@";

/**
 * The witness's record class for one method and one frame derivation:
 *   "CONSEQUENCE@" + first 16 hex of sha256(JSON.stringify([methodDigest, derivationClass])).
 * BYTE-FOR-BYTE the machine's `consequenceEventType` (seeing.ts), which hashes
 * the canonical JSON of the same two ASCII strings — identical text for this
 * input. Pinned on both sides against one fixture value.
 */
export function witnessRecordClass(methodDigest: string, derivationClass: string): string {
  if (!/^[0-9a-f]{64}$/.test(methodDigest)) throw new Error("methodDigest must be 64 hex");
  if (!/^INTEREST_LABEL@[0-9a-f]{16}$/.test(derivationClass)) throw new Error("derivationClass must be INTEREST_LABEL@<16 hex>");
  const hex = createHash("sha256").update(JSON.stringify([methodDigest, derivationClass]), "utf8").digest("hex").slice(0, 16);
  return WITNESS_RECORD_CLASS_PREFIX + hex;
}

// ── THE TWO POINTERS ─────────────────────────────────────────────────────────
//
// Phase R anchors on nothing (audit 2026-10-11 09:32Z): the drops carry no monotonic receipt and no boot id. The
// ATTEMPT carries the target; the CLOSE carries the act's FATE (the decision's execute flag and hash, or null, and
// `unguarded`). The wall clock `at` is for reading only; a per-process counter orders an ATTEMPT before its CLOSE.

export interface AttemptPointerFields {
  readonly subject: string;
  readonly sessionId: string;
  readonly actionId: string;
  /**
   * The subject chain's identity — its position-0 record's hash — or null when the bridge holds none. A ROTATED
   * chain numbers its acts from 1 again, so (chain, subjectSeq) is the act's key (refuter R2-bytes F3).
   */
  readonly chain: string | null;
  /** The TOOL_ATTEMPTED's bridge-minted subjectSeq — the act's KEY at the witness (refuters A-F7, B M1). */
  readonly subjectSeq: number;
  readonly target: string;
  readonly label: string;
  readonly derivationClass: string;
  readonly targetFingerprint: string | null;
}

/** What /guard answered for an act: whether it was released, and the decision's hash. Cited, never an anchor. */
export interface GuardDecision {
  readonly execute: boolean;
  readonly decisionHash: string;
}

export interface ClosePointerFields {
  readonly subject: string;
  readonly sessionId: string;
  readonly actionId: string;
  readonly chain: string | null;
  /** The ATTEMPT's subjectSeq: the act's key. */
  readonly attemptSeq: number;
  readonly closedSeq: number;
  readonly guard: GuardDecision | null;
  /** The caller recorded this act as executed WITHOUT a /guard answer (fail-open). */
  readonly unguarded: boolean;
}

/** The ATTEMPT drop's bytes, keys in the contract's order. */
export function attemptPointerBytes(f: AttemptPointerFields, at: number): string {
  return JSON.stringify({
    v: 1,
    kind: "ATTEMPT",
    subject: f.subject,
    sessionId: f.sessionId,
    actionId: f.actionId,
    chain: f.chain,
    subjectSeq: f.subjectSeq,
    target: f.target,
    label: f.label,
    derivationClass: f.derivationClass,
    targetFingerprint: f.targetFingerprint,
    at,
  });
}

/** The CLOSE drop's bytes. No target: the witness keeps it from the ATTEMPT. */
export function closePointerBytes(f: ClosePointerFields, at: number): string {
  return JSON.stringify({
    v: 1,
    kind: "CLOSE",
    subject: f.subject,
    sessionId: f.sessionId,
    actionId: f.actionId,
    chain: f.chain,
    attemptSeq: f.attemptSeq,
    closedSeq: f.closedSeq,
    guard: f.guard === null ? null : { execute: f.guard.execute, decisionHash: f.guard.decisionHash },
    unguarded: f.unguarded,
    at,
  });
}

/** The mode a drop is chmod'ed to: the bridge writes, the witness's uid reads (group). */
export const POINTER_FILE_MODE = 0o640;

let counter = 0;

/**
 * One drop, written temp-then-rename INSIDE the intake (a dot-named file is in
 * flight and the witness never reads it), chmod'ed explicitly (a umask does not
 * decide whether the witness can read it). The name is a per-process counter,
 * zero-padded, then pid — an ATTEMPT always sorts before its own CLOSE within a
 * process; across a restart, order within a sweep does not matter (the witness
 * processes every ATTEMPT before any CLOSE).
 */
export function dropPointer(
  intakeDir: string,
  bytes: string,
  seam: { readonly write?: typeof writeFileSync; readonly rename?: typeof renameSync; readonly chmod?: typeof chmodSync } = {}
): { readonly ok: true; readonly name: string } | { readonly ok: false; readonly reason: string } {
  const name = `${String(++counter).padStart(18, "0")}-${String(process.pid)}`;
  const tmp = join(intakeDir, `.${name}.inflight`);
  try {
    (seam.write ?? writeFileSync)(tmp, bytes, { encoding: "utf8", flag: "wx" });
    (seam.chmod ?? chmodSync)(tmp, POINTER_FILE_MODE);
    (seam.rename ?? renameSync)(tmp, join(intakeDir, name));
    return { ok: true, name };
  } catch (e) {
    const code = (e as { code?: unknown } | null)?.code;
    return { ok: false, reason: typeof code === "string" ? code : "WRITE_FAILED" };
  }
}

// ── WHAT THE BRIDGE HOLDS BETWEEN AN ACT'S EVENTS ────────────────────────────
//
// In memory, bounded (oldest forgotten first), keyed by the act's FULL identity
// (subject, sessionId, actionId): the caller chooses the last two, and two
// sessions may share an actionId (refuter B M1). A bridge restart forgets all
// of it: an act's CLOSE then carries no decision (`guard: null`), or — its
// ATTEMPT forgotten too — no CLOSE is dropped at all; the witness reads the act
// LATE either way, never a guess.

/** The act's full identity as one unambiguous key. */
export function actIdentityKey(subject: string, sessionId: string, actionId: string): string {
  return JSON.stringify([subject, sessionId, actionId]);
}

class Bounded<V> {
  private readonly map = new Map<string, V>();
  constructor(private readonly capacity: number) {}
  /** FIRST WINS: a key already held is never overwritten. Returns whether this call stored it. */
  putFirst(k: string, v: V): boolean {
    if (this.map.has(k)) return false;
    this.map.set(k, v);
    while (this.map.size > this.capacity) this.map.delete(this.map.keys().next().value as string);
    return true;
  }
  has(k: string): boolean {
    return this.map.has(k);
  }
  take(k: string): V | null {
    if (!this.map.has(k)) return null;
    const v = this.map.get(k) as V;
    this.map.delete(k);
    return v;
  }
  get size(): number {
    return this.map.size;
  }
}

/**
 * The /guard DECISION per act. Bounded, oldest first out — a decision let go this
 * way leaves its act's CLOSE with none (the act then reads LATE). FIRST DECISION
 * WINS (K3): a second /guard call for the same act — a retry, or a call made
 * after the act ran — never replaces the decision the CLOSE carries; the act's
 * fate is the first answer /guard gave it.
 */
export class GuardDecisions {
  private readonly m: Bounded<GuardDecision>;
  constructor(capacity = 4096) {
    this.m = new Bounded(capacity);
  }
  remember(key: string, r: GuardDecision): boolean {
    return this.m.putFirst(key, r);
  }
  has(key: string): boolean {
    return this.m.has(key);
  }
  take(key: string): GuardDecision | null {
    return this.m.take(key);
  }
  get size(): number {
    return this.m.size;
  }
}

/** Acts an ATTEMPT was dropped for, with the ATTEMPT's subjectSeq; a CLOSE is dropped only for those. */
export class PointedActs {
  private readonly m: Bounded<number>;
  constructor(capacity = 4096) {
    this.m = new Bounded(capacity);
  }
  add(key: string, attemptSeq: number): void {
    this.m.putFirst(key, attemptSeq);
  }
  has(key: string): boolean {
    return this.m.has(key);
  }
  take(key: string): number | null {
    return this.m.take(key);
  }
}

/**
 * Acts the caller recorded as EXECUTED WITHOUT A /guard ANSWER (its fail-open:
 * TOOL_EXECUTED with `guard: "UNAVAILABLE"`). The act's CLOSE then says
 * `unguarded` and carries no decision, so the witness reads it LATE: the bridge
 * cannot stand behind the act's fate.
 */
export class UnguardedActs {
  private readonly m: Bounded<true>;
  constructor(capacity = 4096) {
    this.m = new Bounded(capacity);
  }
  mark(key: string): void {
    this.m.putFirst(key, true);
  }
  has(key: string): boolean {
    return this.m.has(key);
  }
  take(key: string): boolean {
    return this.m.take(key) === true;
  }
}
