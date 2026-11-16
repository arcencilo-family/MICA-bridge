// VENDORED, read-only copy of the served caller's client, for the bridge's own tests (guard-reply, held-then-pairing).
//   source file : richards-cat/mica-client.ts at commit fde2b0d (git show fde2b0d:richards-cat/mica-client.ts)
//   source sha256: 16f3b30ae0b2b806bfd91921891a92382e426716a382fb956cf0162e992b94b3  (726 lines at source)
// Changes against the source: this header; the arbiter's name replaced by the role word in four places (two comments,
// two printed strings); `./canonical-json` resolves to this tree's own mica-bridge/canonical-json.ts. Nothing else.
// Do not edit to change behaviour: re-vendor from the source instead.

// ── mica-client — the caller, MICA Phase A Stage 4 §B ───────────────────────
//
// ARC_MICA-DESIGN_Phase-A-Stage-4-Pilot_20260919.md, §B ("The caller") and
// §C ("The four subject-event kinds"). Owns the socket, the outbox, the
// dead-letter file, and the stale-stream bookkeeping. The canonicaliser is
// a separate file (canonical-json.ts, copied verbatim from mica-bridge per
// §C.3) that this module imports rather than reimplements.
//
// claude-bot.ts is the only caller. It is `import`ed there, never the other
// way around — this file has no dependency on Anthropic's SDK, Telegram, or
// anything else claude-bot.ts pulls in, so it can be exercised in isolation
// (mica-client.test.ts does exactly that, against a real MicaBridgeService
// instance where the wire format allows, and a scripted mock HTTP server
// where testing an out-of-scope Stage-1 decision would require importing
// mica-machine — see that file's header for which parts are which).
//
// A note on the one place this file's control flow diverges from §B.1's
// literal code sample, resolved rather than silently followed — see this
// worktree's Stage 4 receipt, "row 10" for the full reasoning: §B.4 row 10
// (`409 IDENTITY_HASH_CONFLICT`) states the outbox event is "none... the
// /guard attempt is recorded in the dead-letter file", which conflicts with
// §B.1's own code sample unconditionally calling
// `mica.appendOutbox(identity, 'TOOL_HELD_NOT_EXECUTED', {reason: verdict.reason})`
// in the `else` branch — and "IDENTITY_HASH_CONFLICT" is not in §C.1's
// closed reason-code list, nor in "the service's own screaming-snake error
// constants for rows 8 and 11" carve-out (row 10 is not row 8 or row 11).
// Resolution taken here: `decide()` returns `reason: null` for row 10 and
// writes the dead-letter entry itself; claude-bot.ts's integration skips
// the `appendOutbox` call when `reason` is `null` — a one-line, documented
// deviation from the literal sample, not a silent one.

import {
  openSync,
  appendFileSync,
  fsyncSync,
  closeSync,
  readFileSync,
  writeFileSync,
  existsSync,
  unlinkSync,
} from "fs";
import * as http from "http";
import { canonicalHash } from "./canonical-json";

// ── public types ─────────────────────────────────────────────────────────

export interface Identity {
  readonly subject: string;
  readonly sessionId: string;
  readonly actionId: string;
}

/**
 * The subject-event kinds THIS CALLER can emit.
 *
 * A VALUE, not only a type, and that is the whole point.
 *
 * **DEPLOYMENT ORDER IS BINDING — BRIDGE BEFORE CALLER.** A kind this caller
 * can emit but the deployed bridge does not know is a `400 MALFORMED_FIELD`
 * from `/subject-events` (mica-service.ts's `SUBJECT_EVENT_KINDS` is a closed
 * list, enforced in `validateSubjectEventBody`), which `drain()` classes
 * `INTEGRITY`, which `decide()` row 2 turns into `run:false` on the act being
 * attempted — and on every act after it, for as long as the mismatch stands,
 * because the caller writes the unknown kind again on the next act. One
 * mis-ordered deployment, or a bridge rollback under a newer caller, holds the
 * subject indefinitely. `mica-client.test.ts` SECTION E demonstrates this end
 * to end and shows the same caller running against a bridge that knows the
 * kind, so the reading is of the mismatch and not of something else.
 *
 * Because the list is enumerable at runtime, a test can walk it and assert the
 * deployed bridge accepts every entry (SECTION E, "the vocabulary guard").
 * That is what makes the ordering rule mechanical instead of a sentence in a
 * receipt — which is the only form of it that survives the month nobody
 * remembers writing it.
 *
 * Adding an entry here is therefore the SECOND half of a two-act change. The
 * first half is the bridge's own list plus its `subjectEventOutcome` row,
 * relayed and live.
 */
export const SUBJECT_EVENT_KINDS = [
  "TOOL_ATTEMPTED",
  "TOOL_HELD_NOT_EXECUTED",
  "TOOL_EXECUTED",
  "TOOL_RESULT",
  // The three POST-HOLD CONDUCT kinds. The deployed service has accepted them
  // since R1, projects each one's `payload.reason` into `outcome`, and leaves
  // all three out of BOTH Sig maps — so adding them here changes no reading Sig
  // makes. The caller's own type was the only thing still refusing them.
  "HELD_THEN_STOPPED",
  "HELD_THEN_RETRIED",
  "HELD_THEN_DIVERGED",
  // THE TERMINAL KIND, written at the end of EVERY act, both paths.
  // `payload.closedAs` = "RAN" | "HELD".
  "ACT_CLOSED",
  // §Q · THE TWO ASK KINDS, and they are TURN-level, not act-level: the only
  // records this caller writes that are not about a tool act. Both carry
  // `payload.askClass` (one value today) and the ask carries `actsInTurn`,
  // which must be 0 — the kind means the turn ended with a question and NO act.
  "TURN_ENDED_ASKING",
  "ASK_ANSWERED",
  // §Q · Written BEFORE this act's own TOOL_ATTEMPTED, never after it: a record
  // between the attempt and the act's end would make a running act five records
  // long and push ACT_CLOSED past op3's declared bound of three.
  "ACT_REVISITED",
] as const;

/**
 * WHAT IS DELIBERATELY ABSENT FROM THE LIST ABOVE, and it is the more
 * important half of it.
 *
 * `DOCTOR_ATTESTED` is a kind the BRIDGE accepts and this caller must NEVER
 * emit. It is written by uid 1000, the doctor's own hand, about the subject —
 * the one record on that log a SECOND PARTY writes. A subject that can write
 * its own attestation has destroyed exactly the thing the kind exists for,
 * while the record still reads as though a second party were there.
 *
 * The bridge refuses it from this uid at the route, which is the gate. This
 * absence is the caller's own half of the same rule, and it is stated rather
 * than left to be inferred from a list that happens not to contain a word:
 * SECTION E's vocabulary guard walks THIS list and asserts the bridge accepts
 * every entry, so a `DOCTOR_ATTESTED` added here would PASS that guard and
 * only fail at the route. The guard is not the place this is caught.
 */

export type SubjectEventKind = (typeof SUBJECT_EVENT_KINDS)[number];

/** §C.1: payload values are scalars, one level deep, never the command text. */
export type Payload = Readonly<Record<string, string | number | boolean | null>>;

/** §C.1's closed reason-code list, plus the service's own screaming-snake error constants (rows 8, 11), which the caller may also produce but does not originate. */
export const KNOWN_REASON_CODES = [
  "OUTBOX_UNWRITABLE",
  "STREAM_INTEGRITY",
  "RECORD_NOT_PERSISTED",
  "SERVICE_FAULT",
  "SUBJECT_NOT_BOUND_TO_PEER",
  "HOLD",
  "HOLD_BLIND",
] as const;

export interface AppendResult {
  readonly ok: boolean;
  readonly error?: string;
  readonly record?: OutboxRecordOnDisk;
}

/** The record shape written for a real subject-event line (not ACK, not OUTBOX_BOOT). */
export interface OutboxRecordOnDisk {
  readonly seq: number;
  readonly at: string;
  readonly identity: Identity;
  readonly kind: SubjectEventKind;
  readonly payload?: Payload;
  readonly eventHash: string;
  /**
   * R6 · THE PLAIN CANONICAL TARGET IDENTITY, on TOOL_ATTEMPTED only, and it is
   * NOT covered by `eventHash`.
   *
   * WHY IT IS HERE AT ALL. The arbiter's ruling 2026-09-24 puts the salt in the
   * BRIDGE: the caller sends the plain identity, the bridge HMACs it with a
   * salt this uid cannot read, stores hash + saltId + canonVersion, and never
   * logs the plain. So the caller has to be able to RE-SEND the plain on a
   * retry, and §C.1's rule is that a record is written once and re-sent
   * verbatim — which means it rests in the outbox until the bridge acks it.
   *
   * ⚠ AND THAT IS A REAL CHANGE TO WHAT THIS FILE HOLDS, named here rather than
   * discovered later. §C.1 says payload values are "never the command text",
   * and this field is not the command text — it is the resolved TARGET, one
   * token. But it is the first durable trace of a target on the subject's own
   * disk. It is not a new PARTY (the subject ran the command and already knew
   * the target; the outbox is the subject's own staging area, owned by the
   * subject's uid) — it is a new DURATION, and the outbox is append-only with
   * no rotation, so it persists after the ack rather than until it. Rotating or
   * compacting the outbox would fix that and is NOT done here. [owed -> the arbiter]
   *
   * IT IS OUTSIDE `eventHash` DELIBERATELY: the bridge discards the plain, so a
   * digest covering it could never be recomputed from the stored record — see
   * the bridge's `SubjectEventBody.targetIdentity` for the same reasoning from
   * the other side.
   */
  readonly targetIdentity?: string;
}

/** §B.2's logical view: an on-disk record plus the ACK folded in at read time. */
export interface OutboxRecord extends OutboxRecordOnDisk {
  readonly acked: null | { readonly seq: number; readonly at: string };
}

export type Barrier =
  | { readonly class: "CLEAR"; readonly recovered?: { readonly cause: string; readonly since: string; readonly durationMs: number } }
  | { readonly class: "TRANSIENT"; readonly cause: string }
  | { readonly class: "INTEGRITY"; readonly httpStatus: number; readonly errorCode: string }
  /** Synthetic: never returned by drain() itself — constructed by the caller (claude-bot.ts, per §B.1's own sample) when `appendOutbox` fails before drain() is ever called. Accepted by `decide()` as equivalent to row 1, defensively, if it ever does reach drain()'s caller. */
  | { readonly class: "OUTBOX"; readonly cause?: string };

export interface Verdict {
  readonly run: boolean;
  /** Only meaningful when `run === true`. `{toolName:"bash"}` normally, `{toolName:"bash",guard:"UNAVAILABLE"}` on a fail-open (rows 3, 13, 14, 15). */
  readonly executedPayload?: Payload;
  /** Appended to the tool output the model sees, only on fail-open or a delivery failure. */
  readonly banner?: string;
  /**
   * The `reason` code for the `TOOL_HELD_NOT_EXECUTED` outbox event `decide()`'s
   * caller must append when `run === false`. `null` means "do not append one" —
   * currently only row 10 (see this file's header note).
   */
  readonly reason?: string | null;
  /** What the model sees as `tool_result`, only when `run === false`. */
  readonly toolResult?: string;
}

export interface MicaClientOptions {
  readonly socketPath: string;
  readonly outboxPath: string;
  readonly deadletterPath: string;
  readonly stalePath: string;
  readonly now?: () => Date;
  readonly guardTimeoutMs?: number;
}

// ── low-level durable append (§B.2: openSync -> appendFileSync -> fsyncSync -> closeSync) ──

function durableAppend(path: string, line: string): { ok: true } | { ok: false; error: string } {
  let fd: number | undefined;
  try {
    fd = openSync(path, "a");
    appendFileSync(fd, line, { encoding: "utf8" });
    fsyncSync(fd);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? `${err.name}: ${err.message}` : String(err) };
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        /* best-effort close; the write outcome above is what matters */
      }
    }
  }
}

// ── low-level HTTP over the unix socket ─────────────────────────────────────

type HttpResult =
  | { readonly kind: "OK"; readonly status: number; readonly body: unknown }
  | { readonly kind: "TIMEOUT" }
  | { readonly kind: "CONNECT_ERROR"; readonly code: string; readonly message: string };

function postJson(socketPath: string, urlPath: string, payload: unknown, timeoutMs: number): Promise<HttpResult> {
  return new Promise((resolve) => {
    const text = JSON.stringify(payload);
    let settled = false;
    const req = http.request(
      {
        socketPath,
        path: urlPath,
        method: "POST",
        headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text) },
        timeout: timeoutMs,
        agent: false,
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          if (settled) return;
          settled = true;
          let body: unknown = null;
          try {
            body = data.length > 0 ? JSON.parse(data) : null;
          } catch {
            body = null;
          }
          resolve({ kind: "OK", status: res.statusCode ?? 0, body });
        });
      }
    );
    req.on("timeout", () => {
      if (settled) return;
      settled = true;
      req.destroy();
      resolve({ kind: "TIMEOUT" });
    });
    req.on("error", (err: NodeJS.ErrnoException) => {
      if (settled) return;
      settled = true;
      resolve({ kind: "CONNECT_ERROR", code: err.code ?? "UNKNOWN", message: err.message });
    });
    req.write(text);
    req.end();
  });
}

// ── the client ────────────────────────────────────────────────────────────

export class MicaClient {
  private readonly socketPath: string;
  private readonly outboxPath: string;
  private readonly deadletterPath: string;
  private readonly stalePath: string;
  private readonly now: () => Date;
  private readonly guardTimeoutMs: number;
  private seqCounter = 0;

  constructor(opts: MicaClientOptions) {
    this.socketPath = opts.socketPath;
    this.outboxPath = opts.outboxPath;
    this.deadletterPath = opts.deadletterPath;
    this.stalePath = opts.stalePath;
    this.now = opts.now ?? (() => new Date());
    this.guardTimeoutMs = opts.guardTimeoutMs ?? 5000;
  }

  private nowISO(): string {
    return this.now().toISOString();
  }

  // ── boot preflight (§B.2) ────────────────────────────────────────────────

  /**
   * Appends `{kind:"OUTBOX_BOOT"}` and reads it back. Deliberately does NOT
   * create `outboxPath`'s directory — §F-5 (the arbiter's act) creates it;
   * an absent directory is exactly the case this preflight exists to catch
   * before the first Telegram poll, not paper over.
   */
  bootPreflight(): { ok: boolean; error?: string } {
    const line = JSON.stringify({ kind: "OUTBOX_BOOT", at: this.nowISO() }) + "\n";
    const res = durableAppend(this.outboxPath, line);
    if (!res.ok) return { ok: false, error: res.error };
    try {
      const content = readFileSync(this.outboxPath, "utf8");
      if (!content.includes('"OUTBOX_BOOT"')) {
        return { ok: false, error: "read-back of the outbox did not find the OUTBOX_BOOT line just written" };
      }
    } catch (err) {
      return { ok: false, error: err instanceof Error ? `${err.name}: ${err.message}` : String(err) };
    }
    this.seqCounter = this.currentMaxSeq();
    return { ok: true };
  }

  // ── outbox read/fold (§B.2's acked-at-read-time rule) ────────────────────

  private readLines(path: string): unknown[] {
    if (!existsSync(path)) return [];
    const text = readFileSync(path, "utf8");
    const out: unknown[] = [];
    for (const raw of text.split("\n")) {
      if (raw.length === 0) continue;
      try {
        out.push(JSON.parse(raw));
      } catch {
        // A truncated final line (e.g. a crash mid-write) is skipped, not
        // fatal — durableAppend's fsync means a fully-returned append is on
        // disk; a partial one was never acknowledged to a caller as ok.
      }
    }
    return out;
  }

  private currentMaxSeq(): number {
    let max = 0;
    for (const raw of this.readLines(this.outboxPath)) {
      const o = raw as { kind?: unknown; seq?: unknown };
      if (o.kind === "OUTBOX_BOOT" || o.kind === "ACK") continue;
      if (typeof o.seq === "number" && o.seq > max) max = o.seq;
    }
    return max;
  }

  /** Un-acked real records, in seq order — ACK and OUTBOX_BOOT lines folded/excluded. */
  private unackedRecords(): OutboxRecordOnDisk[] {
    const lines = this.readLines(this.outboxPath);
    const acked = new Set<string>();
    const records: OutboxRecordOnDisk[] = [];
    for (const raw of lines) {
      const o = raw as Record<string, unknown>;
      if (o.kind === "ACK" && typeof o.eventHash === "string") {
        acked.add(o.eventHash);
      } else if (o.kind === "OUTBOX_BOOT") {
        continue;
      } else if (typeof o.kind === "string" && typeof o.eventHash === "string" && typeof o.seq === "number") {
        records.push(o as unknown as OutboxRecordOnDisk);
      }
    }
    return records.filter((r) => !acked.has(r.eventHash)).sort((a, b) => a.seq - b.seq);
  }

  // ── appendOutbox (§B.2, §C.1, §C.2) ──────────────────────────────────────

  /**
   * Durably appends one subject-event record. `eventHash` is computed once,
   * here, and stored — never recomputed on a later retry (§C.1: "it must be
   * computed once, stored in the outbox record, and re-sent verbatim on
   * every retry"). Synchronous, matching §B.1's call sites (no `await`).
   */
  appendOutbox(
    identity: Identity,
    kind: SubjectEventKind,
    payload?: Payload,
    targetIdentity?: string
  ): AppendResult {
    const canonicalInput: { identity: Identity; kind: SubjectEventKind; payload?: Payload } = { identity, kind };
    if (payload !== undefined) canonicalInput.payload = payload;
    // R6 · `targetIdentity` IS NOT IN THE CANONICAL INPUT. The bridge discards
    // the plain and stores a digest of it, so a hash covering it could never be
    // recomputed from the record the bridge keeps — and the bridge recomputes
    // this hash and refuses a mismatch, so including it here would fail every
    // fingerprinted post. Outside the hash on both sides, by one rule.
    const eventHash = canonicalHash(canonicalInput);
    const seq = this.seqCounter + 1;
    const base: OutboxRecordOnDisk = payload !== undefined
      ? { seq, at: this.nowISO(), identity, kind, payload, eventHash }
      : { seq, at: this.nowISO(), identity, kind, eventHash };
    const record: OutboxRecordOnDisk =
      targetIdentity === undefined ? base : { ...base, targetIdentity };
    const res = durableAppend(this.outboxPath, JSON.stringify(record) + "\n");
    if (!res.ok) {
      // Row 1's own logging requirement: one line, path + errno-shaped detail.
      console.error(`[mica-client] outbox append to ${this.outboxPath} failed: ${res.error}`);
      return { ok: false, error: res.error };
    }
    this.seqCounter = seq; // gap-free: only advances on a durably-written record
    return { ok: true, record };
  }

  private appendAck(eventHash: string, seq: number, at: string): void {
    const line = JSON.stringify({ kind: "ACK", eventHash, seq, at }) + "\n";
    const res = durableAppend(this.outboxPath, line);
    if (!res.ok) {
      // An unwritable ACK is the same OUTBOX_UNWRITABLE class of failure as
      // row 1, discovered mid-drain rather than at the top of the loop.
      // Logged, not thrown: drain()'s caller still gets a real classification
      // from the record's own POST outcome; failing to persist the ACK only
      // means this record may be re-sent (and deduped, 200 duplicate:true,
      // by the service) on the next drain.
      console.error(`[mica-client] ACK append to ${this.outboxPath} failed: ${res.error}`);
    }
  }

  private deadLetter(entry: Record<string, unknown>): void {
    const res = durableAppend(this.deadletterPath, JSON.stringify(entry) + "\n");
    if (!res.ok) {
      console.error(`[mica-client] dead-letter append to ${this.deadletterPath} failed: ${res.error}`);
    }
  }

  // ── the causal barrier (§B.3) ────────────────────────────────────────────

  async drain(): Promise<Barrier> {
    const records = this.unackedRecords();
    for (const record of records) {
      const body: Record<string, unknown> = { identity: record.identity, kind: record.kind, eventHash: record.eventHash };
      if (record.payload !== undefined) body.payload = record.payload;
      // R6 · the plain crosses HERE and nowhere else in this file. It is
      // re-sent verbatim on every retry, like the rest of the record, because
      // the bridge's fingerprint must be the same one on the retry as on the
      // first attempt or a retried act would look like a different target.
      if (record.targetIdentity !== undefined) body.targetIdentity = record.targetIdentity;
      const result = await postJson(this.socketPath, "/subject-events", body, this.guardTimeoutMs);

      if (result.kind === "TIMEOUT") {
        console.error(`[mica-client] /subject-events timed out (ETIMEDOUT) on ${this.socketPath}`);
        this.markStale("TRANSIENT", "ETIMEDOUT");
        return { class: "TRANSIENT", cause: "ETIMEDOUT" };
      }
      if (result.kind === "CONNECT_ERROR") {
        console.error(`[mica-client] /subject-events connect error ${result.code} on ${this.socketPath}: ${result.message}`);
        this.markStale("TRANSIENT", result.code);
        return { class: "TRANSIENT", cause: result.code };
      }

      const { status, body: respBody } = result;
      const b = (respBody ?? {}) as Record<string, unknown>;

      if (status === 200) {
        const seq = typeof b.seq === "number" ? b.seq : -1;
        this.appendAck(record.eventHash, seq, this.nowISO());
        continue;
      }
      if (status === 503) {
        const errorCode = typeof b.error === "string" ? b.error : "UNKNOWN";
        console.error(`[mica-client] /subject-events 503 ${errorCode} — stream marked TRANSIENT`);
        this.markStale("TRANSIENT", errorCode);
        return { class: "TRANSIENT", cause: errorCode };
      }

      // 400 / 403 / 404 / 405 / 409 / 413 / 415 / 500 — everything else fails closed (ruling L(ii)).
      const errorCode = typeof b.error === "string" ? b.error : String(status);
      const detail = typeof b.detail === "string" ? b.detail : "";
      console.error(`[mica-client] /subject-events ${status} ${errorCode} — record dead-lettered: ${detail}`);
      this.deadLetter({ record, reason: "INTEGRITY", httpStatus: status, errorCode, detail, at: this.nowISO() });
      // Ruling L(ii): an ACK is appended for the dead-lettered record so it
      // cannot block later events on the NEXT drain() call — but THIS call
      // still stops immediately per the barrier's own ordering rule.
      this.appendAck(record.eventHash, -1, this.nowISO());
      return { class: "INTEGRITY", httpStatus: status, errorCode };
    }

    const recovered = this.checkStaleRecovery();
    return recovered ? { class: "CLEAR", recovered } : { class: "CLEAR" };
  }

  private markStale(cause: string, lastError: string): void {
    if (existsSync(this.stalePath)) return; // already marked; keep the original `since`
    const record = { cause, since: this.nowISO(), lastError };
    try {
      writeFileSync(this.stalePath, JSON.stringify(record), "utf8");
    } catch (err) {
      console.error(`[mica-client] could not write ${this.stalePath}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /**
   * §B.3: "On the next CLEAR drain, if mica-outbox.stale.json exists, the
   * client first posts a recovery report and then deletes the file."
   *
   * NOT implemented as an HTTP POST here. §A's merged code (mica-service.ts
   * :1345-1347, this worktree, [verified] this run) says so itself:
   * `STALE_STREAM` is "[owed -> §B.4]... no event of that kind is ever
   * emitted from this file" — and neither `/subject-events` (closed `kind`
   * enum: the four conduct kinds only, `[verified]` mica-service.ts:597-598)
   * nor `/guard` (no `observedAt` field, no recovery concept at all) has any
   * endpoint that would accept a "recovery report" and turn it into a
   * service-side `STALE_STREAM` event. Posting one would get `400
   * MALFORMED_FIELD`/`UNKNOWN_FIELD` from the real, merged service — a
   * caller defect, not a recovery. This is a confirmed §A/§B contradiction,
   * not a gap I am silently routing around: see the Stage 4 receipt. What
   * IS in scope and implemented: the caller's own bookkeeping half — the
   * stale marker is read, logged (so the fact is at least in `journalctl`,
   * this run's only honest channel per §B.3's own stated limit), and
   * cleared. Making the service side real is `[owed]`, and is a mica-bridge
   * (§A) change, out of this worktree's reach.
   */
  private checkStaleRecovery(): { cause: string; since: string; durationMs: number } | null {
    if (!existsSync(this.stalePath)) return null;
    try {
      const raw = JSON.parse(readFileSync(this.stalePath, "utf8")) as { cause?: unknown; since?: unknown; lastError?: unknown };
      const cause = typeof raw.cause === "string" ? raw.cause : "UNKNOWN";
      const since = typeof raw.since === "string" ? raw.since : this.nowISO();
      const durationMs = this.now().getTime() - new Date(since).getTime();
      console.log(
        `[mica-client] stream recovered: was ${cause} since ${since} (last error: ${String(raw.lastError)}), ` +
          `duration=${durationMs}ms. [owed: no service-side STALE_STREAM report was sent — see mica-client.ts header]`
      );
      unlinkSync(this.stalePath);
      return { cause, since, durationMs };
    } catch (err) {
      console.error(`[mica-client] could not read/clear ${this.stalePath}: ${err instanceof Error ? err.message : String(err)}`);
      return null;
    }
  }

  // ── the decision (§B.4's full response matrix) ───────────────────────────

  async decide(identity: Identity, attempted: AppendResult, barrier: Barrier, toolName: string): Promise<Verdict> {
    // Row 1.
    if (!attempted.ok || barrier.class === "OUTBOX") {
      return {
        run: false,
        reason: "OUTBOX_UNWRITABLE",
        toolResult:
          `HELD BY MICA: HELD_NOT_EXECUTED — OUTBOX_UNWRITABLE. The attempt could not be recorded, ` +
          `so it is not an attempt. The arbiter: the housekeeper cannot write ${this.outboxPath}.`,
      };
    }

    // Row 2.
    if (barrier.class === "INTEGRITY") {
      return {
        run: false,
        reason: "STREAM_INTEGRITY",
        toolResult:
          `HELD BY MICA: HELD_NOT_EXECUTED — STREAM_INTEGRITY (${barrier.errorCode}). An earlier record ` +
          `of my own conduct was refused; it is in the dead-letter file and needs a human before I go on.`,
      };
    }

    // Row 3.
    if (barrier.class === "TRANSIENT") {
      return {
        run: true,
        executedPayload: { toolName, guard: "UNAVAILABLE" },
        banner:
          "[MICA: STALE_STREAM — no evaluation was obtained; this command ran unguarded. " +
          "The record is queued and will be delivered when the channel recovers.]",
      };
    }

    // barrier.class === "CLEAR" -> actually ask /guard.
    const result = await postJson(
      this.socketPath,
      "/guard",
      { subject: identity.subject, sessionId: identity.sessionId, actionId: identity.actionId, toolName },
      this.guardTimeoutMs
    );

    // Rows 14, 15.
    if (result.kind === "TIMEOUT") {
      console.error(`[mica-client] /guard request timed out (ETIMEDOUT) on ${this.socketPath}`);
      return {
        run: true,
        executedPayload: { toolName, guard: "UNAVAILABLE" },
        banner: "[MICA: UNAVAILABLE — no evaluation was obtained; this command ran unguarded.]",
      };
    }
    if (result.kind === "CONNECT_ERROR") {
      console.error(`[mica-client] /guard connect error ${result.code} on ${this.socketPath}: ${result.message}`);
      return {
        run: true,
        executedPayload: { toolName, guard: "UNAVAILABLE" },
        banner: "[MICA: UNAVAILABLE — no evaluation was obtained; this command ran unguarded.]",
      };
    }

    const { status, body } = result;
    const b = (body ?? {}) as Record<string, unknown>;

    // Rows 4, 5, 6, 7.
    if (status === 200) {
      const decision = (b.decision ?? {}) as Record<string, unknown>;
      const delivery = (b.delivery ?? {}) as Record<string, unknown>;
      const disposition = typeof decision.disposition === "string" ? decision.disposition : "UNKNOWN";
      const rationale = typeof decision.rationale === "string" ? decision.rationale : "(no rationale field on the decision object)";
      const decisionHash = typeof decision.decisionHash === "string" ? decision.decisionHash : "(none)";
      const execute = decision.execute === true;

      const failedProjections = Object.entries(delivery)
        .filter(([, v]) => v === "FAILED")
        .map(([k]) => k);
      // No leading "\n\n" here — that separator is claude-bot.ts's own job when
      // it joins `verdict.banner` onto a run's output (rows 3/13/14/15 do the
      // same). When `execute:false`, this function joins it onto `toolResult`
      // itself below, adding the separator there instead — so either path
      // produces exactly one blank line before the bracketed notice, not two.
      const failedProjectionsBanner =
        failedProjections.length > 0
          ? `[MICA: projection ${failedProjections.join(", ")} FAILED — the decision stands; its record did not.]`
          : undefined;

      if (execute) {
        console.log(
          `[mica-client] /guard 200 identity=(${identity.subject},${identity.sessionId},${identity.actionId}) ` +
            `disposition=${disposition} decisionHash=${decisionHash} delivery=${JSON.stringify(delivery)}`
        );
        return { run: true, executedPayload: { toolName }, banner: failedProjectionsBanner };
      }

      // Row 7: a HOLD whose rationale already names RECORD_NOT_PERSISTED gets that reason code instead of the generic disposition.
      const recordNotPersisted = disposition === "HOLD" && rationale.includes("RECORD_NOT_PERSISTED");
      const reason = recordNotPersisted ? "RECORD_NOT_PERSISTED" : disposition;
      console.log(
        `[mica-client] /guard 200 HELD identity=(${identity.subject},${identity.sessionId},${identity.actionId}) ` +
          `disposition=${disposition} decisionHash=${decisionHash}`
      );
      const toolResult =
        `HELD BY MICA: ${disposition} — ${rationale}` + (failedProjectionsBanner ? `\n\n${failedProjectionsBanner}` : "");
      return { run: false, reason, toolResult };
    }

    // Row 9.
    if (status === 403) {
      console.error(`[mica-client] /guard 403 SUBJECT_NOT_BOUND_TO_PEER for subject "${identity.subject}"`);
      return {
        run: false,
        reason: "SUBJECT_NOT_BOUND_TO_PEER",
        toolResult: `HELD BY MICA: this caller is not bound to subject "${identity.subject}". The arbiter: the peer socket or the declaration is wrong.`,
      };
    }

    // Row 10 — see this file's header note. No outbox event; dead-lettered here.
    if (status === 409) {
      const detail = typeof b.detail === "string" ? b.detail : "(no detail)";
      console.error(`[mica-client] /guard 409 IDENTITY_HASH_CONFLICT: ${detail}`);
      this.deadLetter({
        source: "guard",
        identity,
        httpStatus: 409,
        errorCode: "IDENTITY_HASH_CONFLICT",
        detail,
        at: this.nowISO(),
      });
      return {
        run: false,
        reason: null,
        toolResult: "HELD BY MICA: identity conflict — this action id already carries a different decision.",
      };
    }

    // Row 12.
    if (status === 500) {
      const detail = typeof b.detail === "string" ? b.detail : "(no detail)";
      console.error(`[mica-client] /guard 500 SERVICE_FAULT: ${detail}`);
      return {
        run: false,
        reason: "SERVICE_FAULT",
        toolResult:
          "HELD BY MICA: service fault after evaluation began. Retrying the same action id is how to find out whether a decision was committed.",
      };
    }

    // Row 13.
    if (status === 503) {
      console.error(`[mica-client] /guard 503 ${String(b.error)}: ${String(b.detail)}`);
      return {
        run: true,
        executedPayload: { toolName, guard: "UNAVAILABLE" },
        banner: "[MICA: UNAVAILABLE — no evaluation was obtained; this command ran unguarded.]",
      };
    }

    // Row 11.
    if (status === 404 || status === 405 || status === 413 || status === 415) {
      const errorCode = typeof b.error === "string" ? b.error : String(status);
      console.error(`[mica-client] /guard ${status} ${errorCode}`);
      return { run: false, reason: errorCode, toolResult: `HELD BY MICA: the door refused the shape of my request (${status}).` };
    }

    // Row 8 (and the generic default for any status this table does not name — fail closed).
    const errorCode = typeof b.error === "string" ? b.error : `HTTP_${status}`;
    const detail = typeof b.detail === "string" ? b.detail : "";
    console.error(`[mica-client] /guard ${status} ${errorCode}: ${detail}`);
    return { run: false, reason: errorCode, toolResult: `HELD BY MICA: request refused — ${errorCode}. ${detail}` };
  }
}
