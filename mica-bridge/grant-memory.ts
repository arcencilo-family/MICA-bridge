// ── S216-2 · THE BRIDGE'S GRANT MEMORY ──────────────────────────────────────────
//
// The arbiter's ruling 2026-10-17 15:35Z ("Yes"): a durable grant memory in the bridge's
// state directory, effective since = max(declared, first-seen), seeded by the arbiter at
// the relay that lands it; a SECOND MEMORY beside the witness, accepted as such and
// printed as one. The audit's acceptance 2026-10-18 06:56Z adds, as ruled:
//   F-3 YES · the high-water since: GRANT_SINCE_RAISED rows; effective takes the max
//             over them, so a since moved later by one restart and earlier by the
//             next never ends a latch;
//   F-2 (a) · an unreadable or corrupt memory is moved aside (never edited) and a new
//             chain begins BEGUN_AFTER_LOSS;
//   F-7 (a) · a torn last line over a verified prefix: the file is moved aside and the
//             prefix is carried forward with its first sights (RECOVERED_PREFIX);
// and accepts as design: GM0 placement, GM3 retirement, the states, event-book loss
// detection, the loader's refusal of a declared path naming the memory.
//
// WHY IT EXISTS. The machine's reader is stateless: after a restart it receives a
// harm stanza byte-identical to an honest one, so a since BACK-DATED ACROSS A
// RESTART (H11 refuses it on a SIGHUP only) would end a latch. The memory is the
// instant the bridge itself FIRST CARRIED each grant; the reader is handed the
// effective since, never this file.
//
// SHAPE. One file, `<state dir>/grant-memory` (no .jsonl suffix, so the interest
// book's pattern can never name it), append-only JSON lines, hash-chained from a
// position-0 boundary. Written under an O_EXCL sibling `.lock` with fsync, and a
// failed write is truncated back to the size it found (no torn tail by ENOSPC).
// Created with an EXPLICIT mode 0640 (open mode + fchmod): the live directory
// carries a default ACL, which disables the umask (BB2 finding 6, at bytes).
// Read WITHOUT the lock (one writer; the history claim excludes a second).
//
// WHAT IT NEVER DOES. It never refuses startup on its own state (the guard is not
// stopped by evidence state, R6's trade); it never edits or deletes a file it
// found; it never self-seeds (a missing memory begins with first sights NOW —
// sinces only move later). The seed is the arbiter's act (tools/grant-memory-seed.ts
// builds the candidate; deploy/seed-grant-memory.sh lays it, by the arbiter's hand).
//
// No dependency on mica-machine: the lock-and-fsync discipline is copied from
// append-store.ts's exclusiveFileLock pattern (no cross-repo rule, the arbiter S94).

import { createHash } from "crypto";
import {
  closeSync,
  fchmodSync,
  fsyncSync,
  ftruncateSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeSync,
  constants as fsConstants,
} from "fs";
import { dirname, join } from "path";
import { canonicalStringify } from "./canonical-json";
import type { SubjectHarm } from "./declarations";

export const GRANT_MEMORY_FILE = "grant-memory";
export const GRANT_MEMORY_SCHEMA = "mica-bridge/grant-memory/1";
/** The version tag inside the memory tag's digest. A change to WHAT the digest covers bumps it. */
export const GRANT_MEMORY_TAG_VERSION = "G2_GRANT_MEMORY_V1";
export const GRANT_MEMORY_MODE = 0o640;

/** The word a chain began with (its boundary's `begun`). */
export type GrantMemoryBegun = "SEEDED" | "BEGUN" | "BEGUN_AFTER_LOSS" | "RECOVERED_PREFIX";
/** The six states the reader prints (GM5). */
export type GrantMemoryState = GrantMemoryBegun | "RESEEDED" | "NOT_PERSISTED";
export const GRANT_MEMORY_BEGUN_WORDS: readonly GrantMemoryBegun[] = Object.freeze(["SEEDED", "BEGUN", "BEGUN_AFTER_LOSS", "RECOVERED_PREFIX"]);

/** A grant's identity: a changed path or a re-bound origin is a DIFFERENT grant (draft §2 "key"). */
export interface GrantKey {
  readonly subject: string;
  readonly itemId: string;
  readonly path: string;
  readonly originId: string;
  readonly originSubject: string;
}

/** One grant as the CURRENT declaration states it. */
export interface DeclaredGrant {
  readonly key: GrantKey;
  readonly sinceAt: number;
  readonly sinceUtc: string;
}

export interface BoundaryRecord {
  readonly kind: "GRANT_MEMORY_BOUNDARY";
  readonly schema: string;
  readonly begun: GrantMemoryBegun;
  readonly declarationHash: string;
  readonly ticket: string | null;
  readonly aside: { readonly path: string; readonly sha256: string | null; readonly reason: string } | null;
  readonly prefixHead: string | null;
  readonly timestamp: number;
  readonly previousHash: null;
  readonly hash: string;
}
export interface FirstSeenRecord {
  readonly kind: "GRANT_FIRST_SEEN";
  readonly key: GrantKey;
  readonly declaredSinceAt: number;
  readonly declaredSinceUtc: string;
  readonly firstSeenAt: number;
  readonly firstSeenUtc: string;
  readonly timestamp: number;
  readonly previousHash: string;
  readonly hash: string;
}
export interface RaisedRecord {
  readonly kind: "GRANT_SINCE_RAISED";
  readonly key: GrantKey;
  readonly sinceAt: number;
  readonly sinceUtc: string;
  readonly timestamp: number;
  readonly previousHash: string;
  readonly hash: string;
}
export interface RetiredRecord {
  readonly kind: "GRANT_RETIRED";
  readonly key: GrantKey;
  readonly reason: string;
  readonly timestamp: number;
  readonly previousHash: string;
  readonly hash: string;
}
export type GrantMemoryRecord = BoundaryRecord | FirstSeenRecord | RaisedRecord | RetiredRecord;

const KEYS_BY_KIND: Readonly<Record<string, readonly string[]>> = Object.freeze({
  GRANT_MEMORY_BOUNDARY: ["kind", "schema", "begun", "declarationHash", "ticket", "aside", "prefixHead", "timestamp", "previousHash", "hash"],
  GRANT_FIRST_SEEN: ["kind", "key", "declaredSinceAt", "declaredSinceUtc", "firstSeenAt", "firstSeenUtc", "timestamp", "previousHash", "hash"],
  GRANT_SINCE_RAISED: ["kind", "key", "sinceAt", "sinceUtc", "timestamp", "previousHash", "hash"],
  GRANT_RETIRED: ["kind", "key", "reason", "timestamp", "previousHash", "hash"],
});
const GRANT_KEY_KEYS = ["subject", "itemId", "path", "originId", "originSubject"];

/** One live entry of the fold. */
export interface GrantEntry {
  readonly key: GrantKey;
  readonly firstSeenAt: number;
  /** F-3 · the highest declared since this memory carried for the grant (starts at the since declared at first sight). */
  readonly highAt: number;
}

export function grantKeyString(k: GrantKey): string {
  return JSON.stringify([k.subject, k.itemId, k.path, k.originId, k.originSubject]);
}

export function isoOf(ms: number): string {
  return new Date(ms).toISOString();
}

function sha256(text: string | Buffer): string {
  return createHash("sha256").update(text).digest("hex");
}

/** The record's hash: sha256 over its canonical form without `hash`. */
export function recordHash(r: Omit<GrantMemoryRecord, "hash"> | GrantMemoryRecord): string {
  const copy: Record<string, unknown> = { ...(r as Record<string, unknown>) };
  delete copy.hash;
  return sha256(canonicalStringify(copy));
}

function sealed<T extends GrantMemoryRecord>(r: Omit<T, "hash">): T {
  return Object.freeze({ ...(r as object), hash: recordHash(r as Omit<GrantMemoryRecord, "hash">) }) as T;
}

export function boundaryRecord(x: {
  begun: GrantMemoryBegun;
  declarationHash: string;
  ticket: string | null;
  aside: BoundaryRecord["aside"];
  prefixHead: string | null;
  timestamp: number;
}): BoundaryRecord {
  return sealed<BoundaryRecord>({
    kind: "GRANT_MEMORY_BOUNDARY",
    schema: GRANT_MEMORY_SCHEMA,
    begun: x.begun,
    declarationHash: x.declarationHash,
    ticket: x.ticket,
    aside: x.aside,
    prefixHead: x.prefixHead,
    timestamp: x.timestamp,
    previousHash: null,
  });
}

export function firstSeenRecord(prev: string, key: GrantKey, declaredSinceAt: number, firstSeenAt: number, timestamp: number): FirstSeenRecord {
  return sealed<FirstSeenRecord>({
    kind: "GRANT_FIRST_SEEN",
    key: { ...key },
    declaredSinceAt,
    declaredSinceUtc: isoOf(declaredSinceAt),
    firstSeenAt,
    firstSeenUtc: isoOf(firstSeenAt),
    timestamp,
    previousHash: prev,
  });
}

export function raisedRecord(prev: string, key: GrantKey, sinceAt: number, timestamp: number): RaisedRecord {
  return sealed<RaisedRecord>({ kind: "GRANT_SINCE_RAISED", key: { ...key }, sinceAt, sinceUtc: isoOf(sinceAt), timestamp, previousHash: prev });
}

export function retiredRecord(prev: string, key: GrantKey, reason: string, timestamp: number): RetiredRecord {
  return sealed<RetiredRecord>({ kind: "GRANT_RETIRED", key: { ...key }, reason, timestamp, previousHash: prev });
}

class Corrupt extends Error {}

function isPlain(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}
function exact(o: Record<string, unknown>, keys: readonly string[], where: string): void {
  const have = Object.keys(o);
  if (have.length !== keys.length || !keys.every((k) => Object.prototype.hasOwnProperty.call(o, k))) {
    throw new Corrupt(`${where} carries keys [${have.sort().join(", ")}], not exactly [${[...keys].sort().join(", ")}]`);
  }
}
function nonEmpty(v: unknown): v is string {
  return typeof v === "string" && v.length > 0;
}
function msOk(v: unknown): v is number {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
}
function spelled(at: unknown, utc: unknown, where: string): void {
  if (!msOk(at) || typeof utc !== "string" || isoOf(at) !== utc) throw new Corrupt(`${where}: an instant and its spelling disagree`);
}
function grantKeyOf(v: unknown, where: string): GrantKey {
  if (!isPlain(v)) throw new Corrupt(`${where}.key is not an object`);
  exact(v, GRANT_KEY_KEYS, `${where}.key`);
  for (const k of GRANT_KEY_KEYS) if (!nonEmpty(v[k])) throw new Corrupt(`${where}.key.${k} is not a non-empty string`);
  return v as unknown as GrantKey;
}

/** Verify ONE parsed line at position `pos` against the previous hash; returns the typed record. */
function verifyRecord(raw: unknown, pos: number, prev: string | null): GrantMemoryRecord {
  const where = `line ${pos + 1}`;
  if (!isPlain(raw)) throw new Corrupt(`${where} is not an object`);
  const kind = raw.kind;
  if (typeof kind !== "string" || !Object.prototype.hasOwnProperty.call(KEYS_BY_KIND, kind)) throw new Corrupt(`${where} has an unknown kind`);
  exact(raw, KEYS_BY_KIND[kind], where);
  if (!msOk(raw.timestamp)) throw new Corrupt(`${where}.timestamp is not a ms instant`);
  if (pos === 0) {
    if (kind !== "GRANT_MEMORY_BOUNDARY") throw new Corrupt("position 0 is not the boundary");
    if (raw.previousHash !== null) throw new Corrupt("the boundary names a previous hash");
    if (raw.schema !== GRANT_MEMORY_SCHEMA) throw new Corrupt("the boundary names another schema");
    if (typeof raw.begun !== "string" || !GRANT_MEMORY_BEGUN_WORDS.includes(raw.begun as GrantMemoryBegun)) throw new Corrupt("the boundary's begun word is unknown");
    if (!/^[0-9a-f]{64}$/.test(String(raw.declarationHash))) throw new Corrupt("the boundary's declarationHash is not 64 hex");
    if (raw.ticket !== null && !nonEmpty(raw.ticket)) throw new Corrupt("the boundary's ticket is malformed");
    if (raw.prefixHead !== null && !/^[0-9a-f]{64}$/.test(String(raw.prefixHead))) throw new Corrupt("the boundary's prefixHead is malformed");
    if (raw.aside !== null) {
      if (!isPlain(raw.aside)) throw new Corrupt("the boundary's aside is malformed");
      exact(raw.aside, ["path", "sha256", "reason"], "the boundary's aside");
      if (!nonEmpty(raw.aside.path) || !nonEmpty(raw.aside.reason) || (raw.aside.sha256 !== null && !/^[0-9a-f]{64}$/.test(String(raw.aside.sha256)))) {
        throw new Corrupt("the boundary's aside is malformed");
      }
    }
  } else {
    if (kind === "GRANT_MEMORY_BOUNDARY") throw new Corrupt(`${where} is a second boundary`);
    if (raw.previousHash !== prev) throw new Corrupt(`${where} breaks the chain`);
    grantKeyOf(raw.key, where);
    if (kind === "GRANT_FIRST_SEEN") {
      spelled(raw.declaredSinceAt, raw.declaredSinceUtc, `${where} declared since`);
      spelled(raw.firstSeenAt, raw.firstSeenUtc, `${where} first sight`);
    } else if (kind === "GRANT_SINCE_RAISED") {
      spelled(raw.sinceAt, raw.sinceUtc, `${where} raised since`);
    } else if (!nonEmpty(raw.reason)) {
      throw new Corrupt(`${where}.reason is empty`);
    }
  }
  if (typeof raw.hash !== "string" || raw.hash !== recordHash(raw as unknown as GrantMemoryRecord)) throw new Corrupt(`${where}'s hash does not match its content`);
  return raw as unknown as GrantMemoryRecord;
}

/** The in-force view: a fold over the chain. A row that contradicts the fold is corruption. */
export function foldChain(records: readonly GrantMemoryRecord[]): Map<string, GrantEntry> {
  const live = new Map<string, GrantEntry>();
  for (let i = 1; i < records.length; i++) {
    const r = records[i];
    if (r.kind === "GRANT_MEMORY_BOUNDARY") throw new Corrupt(`line ${i + 1} is a second boundary`);
    const ks = grantKeyString(r.key);
    const cur = live.get(ks);
    if (r.kind === "GRANT_FIRST_SEEN") {
      if (cur !== undefined) throw new Corrupt(`line ${i + 1} first-sees a grant already live`);
      live.set(ks, { key: r.key, firstSeenAt: r.firstSeenAt, highAt: r.declaredSinceAt });
    } else if (r.kind === "GRANT_SINCE_RAISED") {
      if (cur === undefined) throw new Corrupt(`line ${i + 1} raises a grant that is not live`);
      if (r.sinceAt <= cur.highAt) throw new Corrupt(`line ${i + 1} raises a since to no higher than it was`);
      live.set(ks, { ...cur, highAt: r.sinceAt });
    } else {
      if (cur === undefined) throw new Corrupt(`line ${i + 1} retires a grant that is not live`);
      live.delete(ks);
    }
  }
  return live;
}

/** What a read of the file found. */
export type GrantMemoryRead =
  | { readonly kind: "MISSING" }
  | { readonly kind: "OK"; readonly records: readonly GrantMemoryRecord[]; readonly size: number }
  | { readonly kind: "TORN"; readonly records: readonly GrantMemoryRecord[]; readonly tornBytes: number; readonly bytes: Buffer }
  | { readonly kind: "LOSS"; readonly reason: string; readonly bytes: Buffer | null };

/** Read and verify the file, WITHOUT the lock. Never throws. */
export function readGrantMemory(path: string): GrantMemoryRead {
  let bytes: Buffer;
  try {
    bytes = readFileSync(path);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return { kind: "MISSING" };
    return { kind: "LOSS", reason: `unreadable (${code ?? String(e)})`, bytes: null };
  }
  const text = bytes.toString("utf8");
  const lastNl = text.lastIndexOf("\n");
  const complete = lastNl < 0 ? "" : text.slice(0, lastNl);
  const tail = lastNl < 0 ? text : text.slice(lastNl + 1);
  const lines = complete.length === 0 ? [] : complete.split("\n");
  const records: GrantMemoryRecord[] = [];
  try {
    let prev: string | null = null;
    for (let i = 0; i < lines.length; i++) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(lines[i]);
      } catch {
        throw new Corrupt(`line ${i + 1} is not JSON`);
      }
      const r = verifyRecord(parsed, i, prev);
      records.push(r);
      prev = r.hash;
    }
    foldChain(records);
  } catch (e) {
    if (e instanceof Corrupt) return { kind: "LOSS", reason: `corrupt (${e.message})`, bytes };
    return { kind: "LOSS", reason: `corrupt (${String(e)})`, bytes };
  }
  if (tail.length > 0) {
    // F-7 · an UNTERMINATED last line is a row that never landed (one write of line + "\n"; a tear is a prefix of it).
    if (records.length === 0) return { kind: "LOSS", reason: "torn with no verified prefix (no boundary landed)", bytes };
    return { kind: "TORN", records, tornBytes: Buffer.byteLength(tail, "utf8"), bytes };
  }
  if (records.length === 0) return { kind: "LOSS", reason: "empty (no boundary landed)", bytes };
  return { kind: "OK", records, size: bytes.length };
}

/** Thrown by a write that could not land; the caller decides (reload: refuse; start: NOT_PERSISTED). */
export class GrantMemoryWriteError extends Error {}

export interface GrantMemoryFs {
  openSync: typeof openSync;
  writeSync: typeof writeSync;
  fsyncSync: typeof fsyncSync;
}
const REAL_FS: GrantMemoryFs = { openSync, writeSync, fsyncSync };

/**
 * Append `rows` to the file at `path` (creating it if `create`), under the O_EXCL sibling lock. Inside the lock the
 * chain on disk is re-read and must end at `expectHead` (null = the file must not exist). On any write or fsync
 * error the file is truncated back to the size found and the error is rethrown typed; the lock is always released.
 */
export function appendGrantMemory(path: string, rows: readonly GrantMemoryRecord[], expectHead: string | null, fsx: GrantMemoryFs = REAL_FS): void {
  if (rows.length === 0) return;
  const lockPath = `${path}.lock`;
  let lockFd: number;
  try {
    lockFd = fsx.openSync(lockPath, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY, GRANT_MEMORY_MODE);
  } catch (e) {
    throw new GrantMemoryWriteError(`the lock ${lockPath} could not be taken (${(e as NodeJS.ErrnoException).code ?? String(e)}); a lock left by a crash never expires (root removes it)`);
  }
  try {
    try {
      fchmodSync(lockFd, GRANT_MEMORY_MODE);
      fsx.writeSync(lockFd, `${process.pid}\n`);
    } finally {
      closeSync(lockFd);
    }
    const found = readGrantMemory(path);
    if (expectHead === null) {
      if (found.kind !== "MISSING") throw new GrantMemoryWriteError(`${path} appeared while a new chain was being begun (${found.kind})`);
    } else if (found.kind !== "OK" || found.records[found.records.length - 1].hash !== expectHead) {
      throw new GrantMemoryWriteError(`${path} on disk no longer ends at the chain this process adopted (${found.kind}); nothing written`);
    }
    const create = expectHead === null;
    let fd: number;
    try {
      fd = create
        ? fsx.openSync(path, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY, GRANT_MEMORY_MODE)
        : fsx.openSync(path, fsConstants.O_WRONLY | fsConstants.O_APPEND);
    } catch (e) {
      throw new GrantMemoryWriteError(`${path} could not be opened for writing (${(e as NodeJS.ErrnoException).code ?? String(e)})`);
    }
    let size = 0;
    try {
      if (create) fchmodSync(fd, GRANT_MEMORY_MODE);
      size = fstatSync(fd).size;
      const text = rows.map((r) => JSON.stringify(r)).join("\n") + "\n";
      const buf = Buffer.from(text, "utf8");
      let off = 0;
      while (off < buf.length) off += fsx.writeSync(fd, buf, off, buf.length - off);
      fsx.fsyncSync(fd);
    } catch (e) {
      // NO TORN TAIL: back to the size found, inside the lock, over bytes this call wrote only.
      try {
        ftruncateSync(fd, size);
        fsx.fsyncSync(fd);
      } catch {
        // the truncate-back itself failed: the next read finds a torn tail (F-7) — said, not hidden
      }
      throw new GrantMemoryWriteError(`${path}: the write did not land (${(e as NodeJS.ErrnoException).code ?? String(e)}); truncated back to ${size} bytes`);
    } finally {
      closeSync(fd);
    }
    if (create) {
      try {
        const dfd = openSync(dirname(path), fsConstants.O_RDONLY);
        try {
          fsyncSync(dfd);
        } finally {
          closeSync(dfd);
        }
      } catch {
        // a directory fsync refused (some filesystems): the file itself is fsynced
      }
    }
  } finally {
    try {
      unlinkSync(lockPath);
    } catch {
      // the lock vanished under us: nothing to release
    }
  }
}

/** Move a found file aside under a run-stamped name (never edited, never deleted). Returns the aside path. */
export function moveAside(path: string, label: "torn" | "unreadable", at: number): string {
  let aside = `${path}.${label}-${at}`;
  for (let i = 1; taken(aside); i++) aside = `${path}.${label}-${at}-${i}`;
  renameSync(path, aside);
  return aside;
}

function taken(p: string): boolean {
  try {
    lstatSync(p);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code !== "ENOENT";
  }
}

// ── THE STORE: adopt at start, apply at every accepted load ─────────────────────

export interface LoadFacts {
  /** this.now() at the load, ms. */
  readonly now: number;
  /** The newest record timestamp in the books the load reads (the clamp's second half, C2); null = none read. */
  readonly bookFloorAt: number | null;
  readonly declarationHash: string;
  readonly grants: readonly DeclaredGrant[];
}

export interface ApplyOutcome {
  /** Rows this load formed (written, or held pending). */
  readonly formed: readonly GrantMemoryRecord[];
  readonly persisted: boolean;
  readonly error: string | null;
  readonly retired: readonly GrantKey[];
  readonly raised: readonly GrantKey[];
  readonly firstSeen: readonly GrantKey[];
}

export interface AdoptOutcome extends ApplyOutcome {
  /** What the read found, in words for the event book. */
  readonly found: "MISSING" | "OK" | "TORN" | "LOSS";
  readonly foundReason: string | null;
  readonly aside: string | null;
  readonly asideError: string | null;
  readonly begun: GrantMemoryBegun;
  readonly boundaryHash: string;
  /** True when the boundary was written by this load (a new chain). */
  readonly newChain: boolean;
}

/**
 * The bridge's grant memory, as one process holds it. `chain` is every row this process knows, in order; the first
 * `persistedCount` of them are on disk (the rest are PENDING: formed, not yet written, kept for the process's life).
 */
export class GrantMemoryStore {
  readonly path: string;
  private chain: GrantMemoryRecord[] = [];
  private persistedCount = 0;
  private live = new Map<string, GrantEntry>();
  private persistedLive = new Map<string, GrantEntry>();
  private adoptedState: GrantMemoryBegun | "RESEEDED" = "BEGUN";
  private adopted = false;
  private readonly fsx: GrantMemoryFs;

  constructor(stateDir: string, fsx: GrantMemoryFs = REAL_FS) {
    this.path = join(stateDir, GRANT_MEMORY_FILE);
    this.fsx = fsx;
  }

  isAdopted(): boolean {
    return this.adopted;
  }

  /** The state the reader prints: NOT_PERSISTED while any row is pending, else the chain's word (or RESEEDED). */
  state(): GrantMemoryState {
    if (this.persistedCount < this.chain.length) return "NOT_PERSISTED";
    return this.adoptedState;
  }

  boundaryHash(): string | null {
    return this.chain.length === 0 ? null : this.chain[0].hash;
  }

  /** The newest write timestamp this process knows (the clamp's first half). */
  private lastWriteAt(): number | null {
    let m: number | null = null;
    for (const r of this.chain) if (m === null || r.timestamp > m) m = r.timestamp;
    return m;
  }

  /** GM1's clamp: a first sight is no earlier than now, the memory's last write, or the newest book record. */
  firstSightAt(now: number, bookFloorAt: number | null): number {
    let f = now;
    const w = this.lastWriteAt();
    if (w !== null && w > f) f = w;
    if (bookFloorAt !== null && bookFloorAt > f) f = bookFloorAt;
    return f;
  }

  /**
   * AT start() (GM0: after the history claim and the peer-dir checks, before any socket binds). Never throws on the
   * memory's state: a fault anywhere ends in a RAM chain and NOT_PERSISTED.
   * `priorBoundaries`: the boundary hashes the event book names (GRANT_MEMORY_BEGUN / _ADOPTED), oldest first.
   */
  adopt(facts: LoadFacts, priorBoundaries: readonly string[]): AdoptOutcome {
    const read = readGrantMemory(this.path);
    let aside: string | null = null;
    let asideError: string | null = null;
    let carried: GrantMemoryRecord[] | null = null;
    let begun: GrantMemoryBegun;
    let foundReason: string | null = null;
    let asideInfo: BoundaryRecord["aside"] = null;
    let prefixHead: string | null = null;
    if (read.kind === "OK") {
      this.chain = [...read.records];
      this.persistedCount = this.chain.length;
      this.live = foldChain(this.chain);
      this.persistedLive = new Map(this.live);
      begun = (this.chain[0] as BoundaryRecord).begun;
      const last = priorBoundaries.length === 0 ? null : priorBoundaries[priorBoundaries.length - 1];
      // RESEEDED: the event book remembers another boundary as the last one this bridge adopted or began.
      this.adoptedState = last !== null && last !== this.chain[0].hash ? "RESEEDED" : begun;
      this.adopted = true;
      const applied = this.applyInternal(facts, "start");
      return { ...applied, found: "OK", foundReason: null, aside: null, asideError: null, begun, boundaryHash: this.chain[0].hash, newChain: false };
    }
    if (read.kind === "MISSING") {
      begun = priorBoundaries.length > 0 ? "BEGUN_AFTER_LOSS" : "BEGUN";
      foundReason = priorBoundaries.length > 0 ? "missing, while the event book names an earlier memory" : null;
      if (priorBoundaries.length > 0) asideInfo = { path: this.path, sha256: null, reason: "missing at start; the event book names an earlier boundary" };
    } else if (read.kind === "TORN") {
      // F-7 (a) · aside the file; carry the verified, fsynced prefix forward with its first sights.
      begun = "RECOVERED_PREFIX";
      foundReason = `torn last line (${read.tornBytes} bytes after the last newline)`;
      prefixHead = read.records[read.records.length - 1].hash;
      try {
        aside = moveAside(this.path, "torn", facts.now);
      } catch (e) {
        asideError = String(e);
      }
      asideInfo = { path: aside ?? this.path, sha256: sha256(read.bytes), reason: foundReason };
      carried = [...read.records];
    } else {
      // F-2 (a) · unreadable or corrupt: aside, never edited; begin after loss.
      begun = "BEGUN_AFTER_LOSS";
      foundReason = read.reason;
      try {
        aside = moveAside(this.path, "unreadable", facts.now);
      } catch (e) {
        asideError = String(e);
      }
      asideInfo = { path: aside ?? this.path, sha256: read.bytes === null ? null : sha256(read.bytes), reason: read.reason };
    }
    const b = boundaryRecord({ begun, declarationHash: facts.declarationHash, ticket: null, aside: asideInfo, prefixHead, timestamp: facts.now });
    this.chain = [b];
    this.persistedCount = 0;
    this.live = new Map();
    this.persistedLive = new Map();
    this.adoptedState = begun;
    if (carried !== null) {
      // the prefix's in-force fold, row for row, with its ORIGINAL first sights and high-water sinces
      const fold = foldChain(carried);
      for (const e of [...fold.values()].sort((x, y) => (grantKeyString(x.key) < grantKeyString(y.key) ? -1 : 1))) {
        const firstDeclared = firstDeclaredOf(carried, e.key);
        const fs = firstSeenRecord(this.head(), e.key, firstDeclared, e.firstSeenAt, facts.now);
        this.chain.push(fs);
        this.live.set(grantKeyString(e.key), { key: e.key, firstSeenAt: e.firstSeenAt, highAt: firstDeclared });
        if (e.highAt > firstDeclared) {
          const rr = raisedRecord(this.head(), e.key, e.highAt, facts.now);
          this.chain.push(rr);
          this.live.set(grantKeyString(e.key), { key: e.key, firstSeenAt: e.firstSeenAt, highAt: e.highAt });
        }
      }
    }
    // a found file that could not be set aside cannot be replaced without editing it: everything stays in RAM.
    const blocked = (read.kind === "TORN" || read.kind === "LOSS") && aside === null;
    this.adopted = true;
    const applied = this.applyInternal(facts, "start", blocked ? `the found memory could not be moved aside (${asideError ?? "unknown"}); nothing is written over it` : null);
    return { ...applied, found: read.kind, foundReason, aside, asideError, begun, boundaryHash: b.hash, newChain: true };
  }

  /**
   * The last resort at start(): an unforeseen throw while adopting. A RAM chain begun after loss, nothing written over
   * whatever is on disk, every grant first seen now (clamped): NOT_PERSISTED, and the guard still starts.
   */
  fallback(facts: LoadFacts, reason: string): ApplyOutcome {
    this.chain = [boundaryRecord({ begun: "BEGUN_AFTER_LOSS", declarationHash: facts.declarationHash, ticket: null, aside: { path: this.path, sha256: null, reason }, prefixHead: null, timestamp: facts.now })];
    this.persistedCount = 0;
    this.live = new Map();
    this.persistedLive = new Map();
    this.adoptedState = "BEGUN_AFTER_LOSS";
    this.adopted = true;
    return this.applyInternal(facts, "start", `adoption threw (${reason}); nothing is written`);
  }

  /** AT reload() (after validateActivation): GM1, GM3, F-3; throws GrantMemoryWriteError when a retire/raise cannot persist. */
  applyAtReload(facts: LoadFacts): ApplyOutcome {
    if (!this.adopted) throw new GrantMemoryWriteError("RELOAD_BEFORE_MEMORY_ADOPTED");
    return this.applyInternal(facts, "reload");
  }

  private head(): string {
    return this.chain[this.chain.length - 1].hash;
  }

  private applyInternal(facts: LoadFacts, at: "start" | "reload", blocked: string | null = null): ApplyOutcome {
    const want = new Map<string, DeclaredGrant>();
    for (const g of facts.grants) want.set(grantKeyString(g.key), g);
    const rows: GrantMemoryRecord[] = [];
    let prev = this.head();
    const nextLive = new Map(this.live);
    const retired: GrantKey[] = [];
    const raised: GrantKey[] = [];
    const firstSeen: GrantKey[] = [];
    // GM3 · retirement: a live entry the declaration no longer carries (origin ungranted, item removed, path changed,
    // origin re-bound, stanza removed — each is a key that no longer occurs).
    for (const ks of [...this.live.keys()].sort()) {
      if (want.has(ks)) continue;
      const e = this.live.get(ks)!;
      const r = retiredRecord(prev, e.key, at === "start" ? "not declared at this start (across a restart: H11 refuses this on reload)" : "not declared at this reload", facts.now);
      rows.push(r);
      prev = r.hash;
      nextLive.delete(ks);
      retired.push(e.key);
    }
    const sight = this.firstSightAt(facts.now, facts.bookFloorAt);
    for (const ks of [...want.keys()].sort()) {
      const g = want.get(ks)!;
      const cur = nextLive.get(ks);
      if (cur === undefined) {
        // GM1 · first sight: at this load's instant, clamped.
        const r = firstSeenRecord(prev, g.key, g.sinceAt, sight, facts.now);
        rows.push(r);
        prev = r.hash;
        nextLive.set(ks, { key: g.key, firstSeenAt: sight, highAt: g.sinceAt });
        firstSeen.push(g.key);
      } else if (g.sinceAt > cur.highAt) {
        // F-3 · the high-water since.
        const r = raisedRecord(prev, g.key, g.sinceAt, facts.now);
        rows.push(r);
        prev = r.hash;
        nextLive.set(ks, { ...cur, highAt: g.sinceAt });
        raised.push(g.key);
      }
    }
    const pendingBefore = this.chain.slice(this.persistedCount);
    const toWrite = [...pendingBefore, ...rows];
    let error: string | null = blocked;
    if (toWrite.length > 0 && blocked === null) {
      try {
        appendGrantMemory(this.path, toWrite, this.persistedCount === 0 ? null : this.chain[this.persistedCount - 1].hash, this.fsx);
      } catch (e) {
        error = e instanceof Error ? e.message : String(e);
      }
    }
    const persisted = error === null;
    if (!persisted && at === "reload" && (retired.length > 0 || raised.length > 0)) {
      // finding 10: a retirement or raise that cannot persist would let a later restart restore the old since.
      throw new GrantMemoryWriteError(`GRANT_MEMORY_NOT_PERSISTED: ${error}`);
    }
    this.chain.push(...rows);
    this.live = nextLive;
    if (persisted) {
      this.persistedCount = this.chain.length;
      this.persistedLive = new Map(this.live);
    }
    return { formed: rows, persisted: persisted || toWrite.length === 0, error: toWrite.length === 0 ? null : error, retired, raised, firstSeen };
  }

  /** GM2 · the effective since of a declared grant (RAM view: pending rows count). Null = the memory has no entry. */
  effective(g: DeclaredGrant): { at: number; utc: string } | null {
    const e = this.live.get(grantKeyString(g.key));
    if (e === undefined) return null;
    let at = g.sinceAt;
    if (e.firstSeenAt > at) at = e.firstSeenAt;
    if (e.highAt > at) at = e.highAt;
    return { at, utc: isoOf(at) };
  }

  /**
   * The memory TAG: "G2_GRANT_MEMORY@" + 16 hex of sha256 over [version, the PERSISTED boundary's hash, rows], rows =
   * [itemId, originId, effectiveUtc, declaredUtc] for the given grants that have a PERSISTED live entry, sorted. The
   * state is printed beside the tag, never digested (finding 12): a write that fails and later lands does not move it.
   */
  tag(grants: readonly DeclaredGrant[]): string {
    const boundary = this.persistedCount === 0 ? null : this.chain[0].hash;
    const rows: [string, string, string, string][] = [];
    for (const g of grants) {
      const e = this.persistedLive.get(grantKeyString(g.key));
      if (e === undefined) continue;
      let at = g.sinceAt;
      if (e.firstSeenAt > at) at = e.firstSeenAt;
      if (e.highAt > at) at = e.highAt;
      rows.push([g.key.itemId, g.key.originId, isoOf(at), g.sinceUtc]);
    }
    rows.sort((a, b) => (JSON.stringify(a) < JSON.stringify(b) ? -1 : 1));
    return `G2_GRANT_MEMORY@${sha256(JSON.stringify([GRANT_MEMORY_TAG_VERSION, boundary, rows])).slice(0, 16)}`;
  }

  /** For tests and the census: the chain this process holds, and how much of it is on disk. */
  snapshot(): { readonly chain: readonly GrantMemoryRecord[]; readonly persistedCount: number } {
    return { chain: [...this.chain], persistedCount: this.persistedCount };
  }
}

function firstDeclaredOf(records: readonly GrantMemoryRecord[], key: GrantKey): number {
  const ks = grantKeyString(key);
  let at: number | null = null;
  for (const r of records) if (r.kind === "GRANT_FIRST_SEEN" && grantKeyString(r.key) === ks) at = r.declaredSinceAt;
  if (at === null) throw new Corrupt("a carried grant has no first-seen row");
  return at;
}

/**
 * The SEED (the arbiter's act, draft §4): every grant in the served declaration, first seen AT ITS DECLARED SINCE, under a
 * SEEDED boundary naming the declarationHash and the ticket. Built by tools/grant-memory-seed.ts at uid 1000; laid by
 * deploy/seed-grant-memory.sh. The bridge never calls this.
 */
export function seedChain(declarationHash: string, ticket: string, grants: readonly DeclaredGrant[], now: number): GrantMemoryRecord[] {
  const out: GrantMemoryRecord[] = [boundaryRecord({ begun: "SEEDED", declarationHash, ticket, aside: null, prefixHead: null, timestamp: now })];
  for (const g of [...grants].sort((a, b) => (grantKeyString(a.key) < grantKeyString(b.key) ? -1 : 1))) {
    out.push(firstSeenRecord(out[out.length - 1].hash, g.key, g.sinceAt, g.sinceAt, now));
  }
  return out;
}

/** Verify a candidate file's bytes as the store would read them (the seed's chain verifier). */
export function verifyGrantMemoryBytes(bytes: Buffer): { ok: true; records: readonly GrantMemoryRecord[] } | { ok: false; reason: string } {
  const text = bytes.toString("utf8");
  if (!text.endsWith("\n")) return { ok: false, reason: "the candidate does not end with a newline (torn)" };
  const lines = text.slice(0, -1).split("\n");
  const records: GrantMemoryRecord[] = [];
  try {
    let prev: string | null = null;
    for (let i = 0; i < lines.length; i++) {
      const r = verifyRecord(JSON.parse(lines[i]), i, prev);
      records.push(r);
      prev = r.hash;
    }
    foldChain(records);
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : String(e) };
  }
  return { ok: true, records };
}

/** Every grant the declaration carries, in every harm stanza (the memory keys on the stanza's subject). */
export function declaredGrantsOf(harm: Readonly<Record<string, SubjectHarm>> | undefined): DeclaredGrant[] {
  const out: DeclaredGrant[] = [];
  if (harm === undefined) return out;
  for (const subject of Object.keys(harm).sort()) {
    const h = harm[subject];
    for (const itemId of Object.keys(h.grants.value).sort()) {
      const g = h.grants.value[itemId];
      const item = h.items.value[itemId];
      for (const originId of [...g.origins].sort()) {
        const sinceUtc = g.since[originId];
        out.push({
          key: { subject, itemId, path: item.path, originId, originSubject: h.origins.value[originId].subject },
          sinceAt: Date.parse(sinceUtc),
          sinceUtc,
        });
      }
    }
  }
  return out;
}
