// ── target-fingerprint — the watcher's salt, the ONE epoch, and the six words ─
//
// R6, the arbiter's ruling 2026-09-24 EVENING, in three parts and in his own terms:
//
//   1. CANONICALISATION IS THE BRIDGE'S. The caller sends the RESOLVED target
//      string; the bridge NORMALISES IT ITSELF BEFORE HASHING, so the caller
//      cannot choose its own fingerprint by choosing its spelling.
//   2. MINTING IS A ONE-TIME ACT. At the bridge's FIRST start after this relay,
//      with no salt file, it MINTS and writes an event `SALT_EPOCH_STARTED`
//      carrying the `saltId`. EVER AFTER, a missing OR unreadable salt means
//      THE FINGERPRINT FIELD IS ABSENT on every record, and an event says so
//      LOUDLY. The bridge NEVER mints a second salt on its own; a new epoch is
//      The arbiter's hand.
//   3. EVERY RECORD CARRIES `saltId`. A reader compares fingerprints ONLY
//      within one `saltId`. Across `saltId`s it prints NOT COMPARABLE (epoch) —
//      never "different target".
//
// This module is the whole of that, as pure functions plus the filesystem calls
// the salt needs. It has no dependency on mica-service (which imports IT), so
// there is no cycle.
//
// ── WHAT THIS BUILD REPLACED, AND WHY IT WAS WRONG ──────────────────────────
//
// The previous build (`3969fa5`) REFUSED TO START on an unreadable salt, a
// wrong mode, a wrong owner, a wrong length, and on an ENOENT that raced.
//
// THAT FAILS CLOSED ON THE WRONG THING. A bridge that will not start has
// STOPPED THE GUARD ENTIRELY. The fingerprint is ONE FIELD ON ONE READER; the
// guard is the whole point of the process. So:
//
//        FAILING CLOSED ON THE FINGERPRINT MUST MEAN "NO FINGERPRINT",
//        NEVER "NO GATE".
//
// That sentence is the reason this file no longer has a refusal class. Every
// fault below produces a SERVING bridge with the field absent and an event that
// says which fault and why — which is strictly more information than a service
// that never came up, and it keeps the guard in the path.
//
// The same build also MINTED UNCONDITIONALLY on ENOENT, so a salt deleted on
// Tuesday was re-minted on Wednesday's restart — the exact silent epoch its own
// docblock said must never happen. Part 2 of the ruling fixes that, and the
// price of the fix is the memory problem `readEpochMemory` exists to carry.
//
// ── WHAT THE SALT BUYS, AND WHAT IT DOES NOT ────────────────────────────────
//
// THE SALT PROTECTS AGAINST A PARTY WHO CANNOT READ IT. Under this ruling the
// subject (`housekeeper`, uid 980) cannot: the file is 0600 owned by the
// bridge's own uid, and the subject never sees it. So the subject cannot
// compute a fingerprint for a target it did not name, cannot recover a target
// from a fingerprint by trying candidates, and cannot forge a revisit by
// constructing a matching digest. The record carries a target identity without
// carrying the target.
//
// WHAT IT DOES NOT BUY, and this half is larger:
//
//   1. THE PLAIN NOW CROSSES THE SOCKET. That is the cost the ruling accepts.
//      The bridge sees the target on every attempt and must never write it
//      down — which makes "never logs the plain" a code property with a test
//      (mica-service.test.ts), not a promise in a comment.
//   2. THE FINGERPRINT IS FAITHFUL TO WHAT THE CALLER SAID THE TARGET WAS, and
//      never to what the act touched. The caller resolves the identity from the
//      tool_use input before the act. A command whose real target is not its
//      first path-like token — a pipeline, a `cd && …`, a variable — produces a
//      TRUE HASH OF A FALSE CLAIM. BR != TR: this is a broadcast the record
//      preserves exactly, and it is not a measurement.
//   3. ROOT READS THE SALT. Anyone who can read the state directory can
//      recompute any fingerprint, and the space of plausible paths on this box
//      is small enough to enumerate.
//   4. IT SAYS NOTHING ABOUT WHY a target was revisited. ACT_REVISITED is a
//      proxy and its own declaration says so.

import { createHash, createHmac, randomBytes } from "crypto";
import { openSync, writeSync, closeSync, readFileSync, fstatSync } from "fs";

/**
 * THE CANONICALISATION VERSION, and it travels on every record.
 *
 * A fingerprint is only comparable to another fingerprint that was produced by
 * the SAME canonicalisation. Changing the rules below without moving this
 * number would make two records look comparable when the only honest reading is
 * that they are not. `compareTargetFingerprints` refuses the comparison on a
 * mismatch rather than answering "different" — see its six words.
 */
export const TARGET_CANON_VERSION = 1;

/** The salt is exactly this many bytes. A file of any other length is a fault, never a salt. */
export const TARGET_SALT_BYTES = 32;

/** The mode the ruling names. Checked on read AND immediately after the mint, not only written. */
export const TARGET_SALT_MODE = 0o600;

/** The longest identity this bridge will canonicalise. Beyond it the field is refused, never truncated. */
export const TARGET_IDENTITY_MAX_BYTES = 512;

// ── canonicalisation ────────────────────────────────────────────────────────

/**
 * RULING 1, AND THIS FUNCTION IS THE WHOLE OF IT.
 *
 * WHO CANONICALISES, which is the question this function answers with its
 * existence: the caller RESOLVES (it alone knows the bot's cwd and holds the
 * tool_use input before the act), and the bridge CANONICALISES. It must be this
 * way round. If the caller's spelling were taken as final, the caller would
 * CHOOSE ITS OWN FINGERPRINT — the same file under two spellings would be two
 * targets whenever that suited it, and a revisit could be made to disappear by
 * writing `//home/x` on the second act.
 *
 * So the bridge re-canonicalises WHATEVER IT IS SENT, including a string the
 * caller already canonicalised. That makes the digest a deterministic function
 * of the POST, and gives the property the suite asserts:
 *
 *   TWO ACTS THE CALLER JUDGED EQUAL ALWAYS CARRY EQUAL DIGESTS ON THE RECORD.
 *   The converse can fail: this canon may merge two spellings the caller told
 *   apart, so the record can show a revisit the caller did not declare — never
 *   the reverse.
 *
 * THE FENCE THAT KEEPS IT TRUE, and it is checkable rather than promised:
 * `fingerprintTarget(` has EXACTLY ONE call site outside this file
 * (`mica-service.ts:handleSubjectEvents`), and the `canonical` argument at that
 * site is the `.canonical` of a successful call to THIS function in the same
 * block. There is one `createHmac` in the whole tree. A second call site is a
 * finding, not a formality.
 *
 * ⚠ AMENDED, Long Run A Stop 2 (contract B2/B3), and named here because the
 *   fence above is a claim about call sites: TWO more call sites now exist in
 *   mica-service.ts, both over a string THIS function's canon already produced.
 *   (1) B-1 · the witness pointer's fingerprint over `unquoteOnePair(canon.canonical)`
 *   — the path the witness looks at — in the same block as the chain's call,
 *   taken from the same successful `.canonical` (the strip is S211's derivation,
 *   not a second canonicaliser; an item matches it only by exact equality).
 *   (2) the Gate 2 harm items' fingerprints, over item paths the declaration door
 *   (H4) admits only when they EQUAL their own canonicalisation and are unchanged
 *   by `unquoteOnePair`. The chain's own fingerprint is still the one above.
 *
 * ── THE RULES, v1 ─────────────────────────────────────────────────────────
 *
 *   NFC · trim ASCII whitespace · collapse runs of `/` · strip ONE trailing `/`
 *   except at the root · refuse empty · refuse longer than 512 bytes.
 *
 * IDEMPOTENT, and that is asserted rather than intended: canon(canon(x)) must
 * equal canon(x), or a record written through one path and re-canonicalised
 * through another would not compare to itself.
 *
 * ── WHAT v1 DELIBERATELY DOES NOT DO ──────────────────────────────────────
 *
 * It does not resolve `..`, does not resolve symlinks, and does not case-fold.
 * THE BRIDGE CANNOT SEE THE SUBJECT'S FILESYSTEM. A textual `..` resolution
 * would claim to know that `a/b/../c` is `a/c`, which is false the moment `b`
 * is a symlink; case-folding would claim a case-insensitive filesystem this box
 * does not have. The cost is stated rather than hidden: two spellings of one
 * file through a symlink get DIFFERENT fingerprints, which is a MISSED revisit
 * and never a false one. Erring toward the miss is the right direction for a
 * field whose alarm-side reading is "this agent re-touched a failed target".
 */
export function canonicaliseTargetIdentity(
  raw: unknown
): { readonly ok: true; readonly canonical: string } | { readonly ok: false; readonly reason: string } {
  if (typeof raw !== "string") {
    return { ok: false, reason: "must be a string" };
  }
  if (Buffer.byteLength(raw, "utf8") > TARGET_IDENTITY_MAX_BYTES) {
    // REFUSED, NEVER TRUNCATED. A truncated identity hashes to a stable value
    // that stands for a whole family of targets, which is a fingerprint that
    // silently collides — worse than an absent field, because it reads as
    // present.
    return { ok: false, reason: `must be at most ${TARGET_IDENTITY_MAX_BYTES} bytes` };
  }
  let s = raw.normalize("NFC").trim();
  if (s.length === 0) {
    return { ok: false, reason: "must not be empty after trimming" };
  }
  s = s.replace(/\/{2,}/g, "/");
  if (s.length > 1 && s.endsWith("/")) s = s.slice(0, -1);
  if (s.length === 0) {
    return { ok: false, reason: "must not be empty after canonicalisation" };
  }
  // A control character in an identity is not a path this caller could have
  // resolved; it is a byte that would make the record's own JSON hard to read.
  // Refused for the same reason the empty string is.
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(s)) {
    return { ok: false, reason: "must not contain control characters" };
  }
  return { ok: true, canonical: s };
}

// ── the salt, its id, and the digest ────────────────────────────────────────

/**
 * THE EPOCH'S PUBLIC NAME. Derived from the salt and revealing nothing about
 * it: a salted-domain SHA-256, truncated to 16 hex characters.
 *
 * It travels on every fingerprinted record and is printed on `/status`, so a
 * reader holding old records can tell whether the live bridge is still in the
 * epoch that wrote them. THE SALT ITSELF IS NEVER PRINTED, NEVER LOGGED, AND
 * NEVER LEAVES THIS PROCESS.
 */
export function saltIdFor(salt: Buffer): string {
  return createHash("sha256")
    .update("mica-bridge/target-fingerprint-salt-id/v1")
    .update(salt)
    .digest("hex")
    .slice(0, 16);
}

/**
 * HMAC-SHA-256(salt, "v<canonVersion>\n<canonical identity>").
 *
 * The version is INSIDE the message, not merely beside it on the record: two
 * canonicalisations that happened to produce the same string under different
 * rules would otherwise hash identically, and the record's own `canonVersion`
 * field would be the only thing saying they are not the same fact. Binding it
 * into the digest makes the separation structural.
 */
export function fingerprintTarget(
  salt: Buffer,
  canonical: string,
  canonVersion: number = TARGET_CANON_VERSION
): string {
  return createHmac("sha256", salt).update(`v${canonVersion}\n${canonical}`).digest("hex");
}

// ── THE MEMORY · how a bridge knows it is not a first start ─────────────────

/**
 * THE TWO EVENT KINDS THAT ARE THE MEMORY, and they are LOAD-BEARING, not
 * decorative. A reader may treat them as an audit trail; this module treats
 * them as the answer to "has an epoch already started on this box".
 *
 * TWO KINDS BECAUSE THERE ARE TWO FACTS, and never one word for two:
 *
 *   · SALT_EPOCH_STARTED  — THIS BRIDGE CREATED THIS EPOCH. Written once, on
 *     the mint, and on no other occasion for the rest of the epoch's life.
 *   · SALT_EPOCH_ADOPTED  — THIS BRIDGE FOUND AN EPOCH IT DID NOT CREATE, and
 *     no memory of it existed here. The arbiter placed the salt by hand, or the books
 *     were lost while the salt survived. Written once, by the first start that
 *     notices. It is what makes the memory self-healing: after ANY start that
 *     ends with a usable salt, the memory exists, WHOEVER minted.
 */
export const EPOCH_MEMORY_KINDS = ["SALT_EPOCH_STARTED", "SALT_EPOCH_ADOPTED"] as const;

/**
 * WHAT THE BOOKS SAY ABOUT WHETHER AN EPOCH HAS ALREADY STARTED HERE.
 *
 * `UNREADABLE` is a third value and not a flavour of `NONE`, and the whole
 * safety argument rests on that: a lost memory makes the state look MORE
 * virgin, never less, so **"I cannot tell" must never become "therefore first
 * start"**. Only a memory READ SUCCESSFULLY AND SHOWING NOTHING authorises a
 * mint.
 */
export type EpochMemory =
  | { readonly status: "PRESENT"; readonly saltId: string | null; readonly where: string }
  | { readonly status: "NONE" }
  | { readonly status: "UNREADABLE"; readonly detail: string };

/**
 * ── THE CONTRADICTION THIS FUNCTION CARRIES, STATED BEFORE IT IS SOLVED ─────
 *
 * "Mint once, at the first start after this relay" requires the bridge to KNOW
 * it is not a first start. Any memory of that is an artefact, and every artefact
 * can be lost. **THE HAZARD IS NOT REMOVED BY THE RULING; IT IS MOVED** — from
 * the salt file to whatever remembers the epoch. A design that does not say
 * where it moved it has resolved nothing.
 *
 * ── WHERE IT WAS MOVED TO: THE UNION OF TWO INDEPENDENT BOOKS ──────────────
 *
 * Evidence that an epoch has already started here is EITHER of:
 *
 *   1. a `SALT_EPOCH_STARTED` or `SALT_EPOCH_ADOPTED` row in the EVENT BOOK; or
 *   2. ANY record in the SUBJECT LOG carrying a `saltId` — which ruling 3 puts
 *      on every fingerprinted record, so the subject log is ITSELF an epoch
 *      ledger and costs nothing but a read.
 *
 * BOTH BOOKS MUST BE LOST TOGETHER for the memory to be lost. They are separate
 * files, appended by separate paths, rotated for separate reasons — and the one
 * documented recovery procedure on this deployment (`declarations.config.json`,
 * reentryMap basis: "recovery is to rotate the subject log") touches exactly one
 * of them. That does not make the hazard vanish. Nothing can. It makes its most
 * likely single form insufficient on its own.
 *
 * ── WHY NOT THE OTHER TWO CANDIDATES ──────────────────────────────────────
 *
 * A SEPARATE MARKER FILE: a second artefact with exactly the salt file's
 * durability, plus a new disagreement state (salt present, marker gone) that
 * means nothing and must still be decided. More surface, no more durability.
 *
 * THE SALT FILE'S OWN EXISTENCE AS THE WHOLE MEMORY: perfectly honest for every
 * start but the first — and it CANNOT AUTHORISE THE FIRST MINT, because "no
 * salt" is then ambiguous between a first start and a lost salt. Taken literally
 * it means the bridge never mints and the salt arrives by the arbiter's hand. That is
 * a coherent design and it is smaller than this one; it is not the ruling's
 * part 2, which says the bridge mints at its first start. Recorded so the arbiter can
 * rule to it instead.
 *
 * WHY NOT "THE EVENT BOOK IS NON-EMPTY", which is the tempting cheap version:
 * `DECLARATION_REJECTED` is appended by a start that then FAILS. A bridge whose
 * very first start died on a bad declaration would find a non-empty book on its
 * second start and COULD NEVER MINT AT ALL. The memory must be a row that means
 * the epoch specifically, not the book's emptiness.
 *
 * ── WHAT A LOST MEMORY COSTS, AND WHO REPAIRS IT ──────────────────────────
 *
 * Both books lost AND the salt gone ⇒ the next start mints ⇒ a new `saltId`.
 * Every record written before is, to every reader, NOT COMPARABLE (epoch)
 * against every record written after. **It is never read as "different
 * target"** (ruling 3, asserted in the suite). So the cost is a BLIND SEAM in
 * the revisit signal across the boundary — a stated absence of an answer, never
 * a wrong answer.
 *
 * REPAIR IS THE ARBITER'S AND NOBODY ELSE'S, and the code offers neither option: he
 * restores the salt from backup, and the `saltId` returns and the seam closes;
 * or he accepts the new epoch and writes the new `saltId` into the relay
 * receipt. The mint that happened is on the record as `SALT_EPOCH_STARTED`
 * with its own timestamp and `saltId`, so the seam is always FINDABLE.
 *
 * ── THE LATTICE, and the order is the argument ────────────────────────────
 *
 * ANY POSITIVE EVIDENCE WINS (an epoch existed — that is knowledge); failing
 * that, ANY UNCERTAINTY WINS (a book that threw is not a book that was empty);
 * only a clean read of both, showing nothing, is NONE.
 */
export function readEpochMemory(books: {
  readonly eventBook: () => readonly Record<string, unknown>[];
  readonly subjectLog: () => readonly Record<string, unknown>[];
}): EpochMemory {
  const kinds: readonly string[] = EPOCH_MEMORY_KINDS;
  let uncertainty: string | null = null;

  try {
    for (const row of books.eventBook()) {
      if (typeof row.kind === "string" && kinds.includes(row.kind)) {
        return {
          status: "PRESENT",
          saltId: typeof row.saltId === "string" ? row.saltId : null,
          where: `event book row ${row.kind}`,
        };
      }
    }
  } catch (err) {
    uncertainty = `the event book could not be read (${String(err)})`;
  }

  try {
    for (const row of books.subjectLog()) {
      if (typeof row.saltId === "string" && row.saltId.length > 0) {
        return { status: "PRESENT", saltId: row.saltId, where: "a subject-log record carrying a saltId" };
      }
    }
  } catch (err) {
    uncertainty =
      uncertainty === null
        ? `the subject log could not be read (${String(err)})`
        : `${uncertainty}; and the subject log could not be read either (${String(err)})`;
  }

  if (uncertainty !== null) return { status: "UNREADABLE", detail: uncertainty };
  return { status: "NONE" };
}

// ── the salt state, and the reasons a fingerprint can be absent ─────────────

/**
 * NINE REASONS, NINE SENTENCES, PAIRWISE DISTINCT. An absent fingerprint is not
 * one fact; it is nine, and a reader who cannot tell "nobody ever minted here
 * and I refuse to mint a second time" from "the file is there and I cannot read
 * it" has been told nothing useful.
 */
export type TargetSaltAbsenceReason =
  /** No salt file — AND the books say an epoch already started here. THE ONE-TIME RULE, biting. */
  | "SALT_ABSENT_EPOCH_ALREADY_STARTED"
  /** No salt file — and the books could not be read, so first-start cannot be established. */
  | "EPOCH_MEMORY_UNREADABLE"
  /** The file is there and this process cannot read it (EACCES, EISDIR, …). */
  | "SALT_UNREADABLE"
  /** The file is there and its mode is not 0600. */
  | "SALT_MODE_NOT_0600"
  /** The file is there and another uid owns it. */
  | "SALT_OWNED_BY_ANOTHER_UID"
  /** The file is there and it is not 32 bytes. */
  | "SALT_WRONG_LENGTH"
  /** EEXIST on the create, then ENOENT on the re-read. It existed a moment ago. */
  | "SALT_VANISHED_IN_RACE"
  /** The exclusive create itself failed (EACCES, ENOSPC on the state directory). */
  | "MINT_FAILED"
  /** A request reached a service whose `start()` never completed. Handled, not asserted. */
  | "NO_EPOCH_LOADED";

/**
 * THE EPOCH THIS PROCESS IS IN, OR THE REASON THERE IS NONE.
 *
 * A discriminated union and not a nullable object, because "absent" is never
 * bare here: it always carries WHICH fault and a detail naming the path. The
 * salt's bytes exist on the PRESENT arm only, and nothing outside this module
 * and the one HMAC call ever touches them.
 */
export type TargetSaltState =
  | {
      readonly status: "PRESENT";
      readonly salt: Buffer;
      readonly saltId: string;
      /** True only on the start that MINTED it — i.e. the first start of an epoch. */
      readonly mintedAtThisStart: boolean;
    }
  | {
      readonly status: "ABSENT";
      readonly reason: TargetSaltAbsenceReason;
      readonly detail: string;
    };

/** One sentence per reason, PAIRWISE DISTINCT, and the suite asserts that. */
export function describeTargetSaltAbsence(reason: TargetSaltAbsenceReason): string {
  switch (reason) {
    case "SALT_ABSENT_EPOCH_ALREADY_STARTED":
      return "there is no salt file, and this bridge's own books show that an epoch was already started here — so this is NOT a first start and minting would begin a second epoch that nobody chose; only the operator's hand starts a new one";
    case "EPOCH_MEMORY_UNREADABLE":
      return "there is no salt file, and the books that would say whether an epoch already started here could not be read — a bridge that cannot establish that this is a first start must not treat its own blindness as permission to mint";
    case "SALT_UNREADABLE":
      return "the salt file exists and this process cannot read it; the epoch it holds is real and is not this process's to replace";
    case "SALT_MODE_NOT_0600":
      return "the salt file's mode is not 0600, so it was readable by a hand other than this bridge's, and a salt others could read never protected anything it is now being asked to protect";
    case "SALT_OWNED_BY_ANOTHER_UID":
      return "the salt file is owned by another uid; the salt is this bridge's own key custody and a file another hand owns is not it";
    case "SALT_WRONG_LENGTH":
      return "the salt file is not the length a salt has, so it is a fault in the shape of a salt, and hashing with it would produce digests nothing can ever be compared against";
    case "SALT_VANISHED_IN_RACE":
      return "the exclusive create reported that a salt file already existed and the read that followed found nothing there; a file that existed a moment ago is proof this is not a first start";
    case "MINT_FAILED":
      return "this was a first start and the exclusive create of the salt file itself failed, so no epoch was begun and none is claimed";
    case "NO_EPOCH_LOADED":
      return "this service never completed its start sequence, so it holds no epoch at all and cannot honestly put one on a record";
  }
}

/**
 * ── THE STATE MACHINE, AND NOTHING IN IT REFUSES TO START ──────────────────
 *
 * `memory` is consulted ONLY on the ENOENT row: a salt file that exists — even
 * a faulty one — is itself proof that an epoch was started here.
 *
 *   S (the salt path)          M = NONE          M = PRESENT         M = UNREADABLE
 *   ─────────────────────────  ────────────────  ──────────────────  ──────────────
 *   no file (ENOENT)           MINT              ABSENT(ALREADY)     ABSENT(MEMORY)
 *   unreadable                 ABSENT(UNREADABLE) — same on every column
 *   mode is not 0600           ABSENT(MODE)      — same on every column
 *   owned by another uid       ABSENT(OWNER)     — same on every column
 *   wrong length               ABSENT(LENGTH)    — same on every column
 *   present and good           LOAD              LOAD                LOAD
 *
 *   EEXIST on the create       -> re-read, and take whichever row the re-read lands in
 *   ENOENT on that re-read     -> ABSENT(VANISHED). NEVER a mint.
 *   any other create failure   -> ABSENT(MINT_FAILED)
 *
 * The mint is `O_CREAT|O_EXCL|O_WRONLY` at mode 0600 — set by `open`, not by a
 * later `chmod`, so the file is never briefly readable. `process.umask()` cannot
 * widen an `open` mode, only narrow it; a NARROWED mode would make the salt
 * unusable forever, so the mode is RE-READ THROUGH THE SAME fd IMMEDIATELY
 * AFTER THE WRITE. A wrong mode at the mint is caught at the mint, not one
 * restart later, and it is caught on the fd rather than by re-opening the path.
 *
 * WHO REPAIRS EVERY ABSENT ROW: the arbiter. He fixes the file, or he removes it and
 * accepts that removing it — with the books also gone — begins a new epoch. The
 * bridge meanwhile SERVES, with no fingerprint on any record and one loud event
 * saying which of the nine reasons it is.
 */
export function loadOrMintTargetSalt(
  path: string,
  memory: EpochMemory,
  deps: {
    readonly randomBytes?: (n: number) => Buffer;
    readonly uid?: () => number;
  } = {}
): TargetSaltState {
  const random = deps.randomBytes ?? randomBytes;
  const selfUid = deps.uid ?? (() => (typeof process.getuid === "function" ? process.getuid() : -1));
  const where = ` (salt path ${path})`;

  /** Reads what is there. `null` means ENOENT and ONLY ENOENT — every other outcome is a state. */
  const inspect = (): TargetSaltState | null => {
    let fd: number;
    try {
      fd = openSync(path, "r");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      return { status: "ABSENT", reason: "SALT_UNREADABLE", detail: `${String(err)}${where}` };
    }
    try {
      // EVERY THROW FROM HERE DOWN BECOMES A STATE, NOT AN EXCEPTION. A
      // directory at mode 0600 passes the mode and owner checks and then throws
      // EISDIR out of the read — which, before this catch, escaped the whole
      // function and killed a start over a field. That is the exact inversion
      // this rework exists to remove, so it is caught HERE rather than trusted
      // not to happen.
      const st = fstatSync(fd);
      const mode = st.mode & 0o777;
      if (mode !== TARGET_SALT_MODE) {
        return {
          status: "ABSENT",
          reason: "SALT_MODE_NOT_0600",
          detail: `mode is ${mode.toString(8)}, not ${TARGET_SALT_MODE.toString(8)}${where}`,
        };
      }
      const me = selfUid();
      if (me >= 0 && st.uid !== me) {
        return {
          status: "ABSENT",
          reason: "SALT_OWNED_BY_ANOTHER_UID",
          detail: `owned by uid ${st.uid}, not by this process (uid ${me})${where}`,
        };
      }
      const salt = readFileSync(fd);
      if (salt.length !== TARGET_SALT_BYTES) {
        return {
          status: "ABSENT",
          reason: "SALT_WRONG_LENGTH",
          detail: `${salt.length} bytes, not ${TARGET_SALT_BYTES}${where}`,
        };
      }
      return { status: "PRESENT", salt, saltId: saltIdFor(salt), mintedAtThisStart: false };
    } catch (err) {
      return { status: "ABSENT", reason: "SALT_UNREADABLE", detail: `${String(err)}${where}` };
    } finally {
      try {
        closeSync(fd);
      } catch {
        /* the fd is going away with the process anyway; a close that fails must not become the answer */
      }
    }
  };

  const found = inspect();
  if (found !== null) return found;

  // ── ENOENT. THE ONLY ROW WHERE MINTING IS EVEN CONSIDERED. ──────────────
  if (memory.status === "PRESENT") {
    return {
      status: "ABSENT",
      reason: "SALT_ABSENT_EPOCH_ALREADY_STARTED",
      detail: `the epoch is remembered by ${memory.where}${memory.saltId === null ? "" : ` (saltId ${memory.saltId})`}${where}`,
    };
  }
  if (memory.status === "UNREADABLE") {
    return { status: "ABSENT", reason: "EPOCH_MEMORY_UNREADABLE", detail: `${memory.detail}${where}` };
  }

  let fd: number;
  try {
    fd = openSync(path, "wx", TARGET_SALT_MODE);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "EEXIST") {
      const raced = inspect();
      if (raced !== null) return raced;
      return {
        status: "ABSENT",
        reason: "SALT_VANISHED_IN_RACE",
        detail: `the create said EEXIST and the read that followed said ENOENT${where}`,
      };
    }
    return { status: "ABSENT", reason: "MINT_FAILED", detail: `${String(err)}${where}` };
  }
  try {
    const salt = random(TARGET_SALT_BYTES);
    writeSync(fd, salt);
    const mintedMode = fstatSync(fd).mode & 0o777;
    if (mintedMode !== TARGET_SALT_MODE) {
      return {
        status: "ABSENT",
        reason: "SALT_MODE_NOT_0600",
        detail: `the file this start created landed at mode ${mintedMode.toString(8)}, not ${TARGET_SALT_MODE.toString(8)}${where}`,
      };
    }
    return { status: "PRESENT", salt, saltId: saltIdFor(salt), mintedAtThisStart: true };
  } catch (err) {
    // The create succeeded and the write or the mode re-read did not. The file
    // exists and is empty or short; the NEXT start reads it as SALT_WRONG_LENGTH
    // and still does not mint over it. The arbiter removes it.
    return { status: "ABSENT", reason: "MINT_FAILED", detail: `${String(err)}${where}` };
  } finally {
    try {
      closeSync(fd);
    } catch {
      /* same reason as above: a failing close must not become the answer */
    }
  }
}

// ── the six words ───────────────────────────────────────────────────────────

/** One record's fingerprint triple, as it is stored and as a reader finds it. */
export interface TargetFingerprintFact {
  readonly targetFingerprint: string;
  readonly saltId: string;
  readonly canonVersion: number;
}

/**
 * SIX WORDS, BECAUSE THERE ARE SIX FACTS. NEVER ONE WORD FOR TWO. This is the
 * THIRD time that rule has landed on this design, and each time it landed a
 * verdict had been folded into another one.
 *
 *   · DIFFERENT_TARGET is an ANSWER. Two acts touched two things. A reader can
 *     act on it.
 *   · NOT_COMPARABLE is the ABSENCE of an answer, and it is not "probably
 *     different". Two digests taken under different salts are two unrelated
 *     random-looking strings; they would differ if the targets were IDENTICAL.
 *     A comparison across an epoch boundary is not WRONG — a wrong answer can
 *     be corrected by looking again — it is MEANINGLESS, and there is nothing
 *     to look at that would correct it.
 *
 * AND IT HAS THREE REASONS, NOT ONE, because ruling 2 creates records with NO
 * fingerprint at all. "This bridge had no epoch when it wrote that record" and
 * "these two records were written under different epochs" and "this act named
 * no target" are three facts and get three labels.
 */
export type TargetComparison =
  | { readonly verdict: "SAME_TARGET" }
  | { readonly verdict: "DIFFERENT_TARGET" }
  | {
      readonly verdict: "NOT_COMPARABLE";
      readonly reason: "DIFFERENT_SALT_EPOCH" | "DIFFERENT_CANON_VERSION" | "FINGERPRINT_ABSENT" | "NO_TARGET_NAMED";
    };

export function compareTargetFingerprints(
  a: TargetFingerprintFact,
  b: TargetFingerprintFact
): TargetComparison {
  // THE EPOCH IS CHECKED FIRST, and the order is load-bearing: two records from
  // different epochs may also differ in canonVersion, and the epoch is the
  // coarser boundary — saying "different canon version" about records that
  // share no salt would name the smaller of two reasons.
  if (a.saltId !== b.saltId) {
    return { verdict: "NOT_COMPARABLE", reason: "DIFFERENT_SALT_EPOCH" };
  }
  if (a.canonVersion !== b.canonVersion) {
    return { verdict: "NOT_COMPARABLE", reason: "DIFFERENT_CANON_VERSION" };
  }
  return a.targetFingerprint === b.targetFingerprint
    ? { verdict: "SAME_TARGET" }
    : { verdict: "DIFFERENT_TARGET" };
}

/**
 * WHAT ONE STORED RECORD SAYS ABOUT ITS TARGET — three shapes for three facts,
 * and they are not interchangeable:
 *
 *   NO KEY AT ALL            the act named no resolvable target. The caller
 *                            sent nothing and the bridge invented nothing.
 *   the triple               a target, and an epoch to hash it under.
 *   targetFingerprintAbsent  a target, and NO epoch. The reason word is on the
 *                            record; the detail sentence and the path are not.
 */
export type RecordTargetReading =
  | { readonly present: true; readonly fact: TargetFingerprintFact }
  | {
      readonly present: false;
      readonly why: "NO_TARGET_NAMED" | "FINGERPRINT_ABSENT";
      readonly reason: string | null;
    };

export function readTargetOnRecord(record: Record<string, unknown>): RecordTargetReading {
  if (
    typeof record.targetFingerprint === "string" &&
    typeof record.saltId === "string" &&
    typeof record.canonVersion === "number"
  ) {
    return {
      present: true,
      fact: {
        targetFingerprint: record.targetFingerprint,
        saltId: record.saltId,
        canonVersion: record.canonVersion,
      },
    };
  }
  if (typeof record.targetFingerprintAbsent === "string") {
    return { present: false, why: "FINGERPRINT_ABSENT", reason: record.targetFingerprintAbsent };
  }
  return { present: false, why: "NO_TARGET_NAMED", reason: null };
}

/**
 * THE READER'S ENTRY POINT — two raw records in, one of six words out.
 *
 * ORDER, and it is an argument rather than a convenience: NO_TARGET_NAMED is
 * checked BEFORE FINGERPRINT_ABSENT because it is the coarser fact and the only
 * one NO REPAIR CAN EVER TOUCH. A record with no target named will never
 * acquire one; a record whose bridge had no epoch could in principle have been
 * written with one had the salt been in place. Both are NOT_COMPARABLE and
 * neither is ever "different target".
 */
export function compareTargetsOnRecords(
  a: Record<string, unknown>,
  b: Record<string, unknown>
): TargetComparison {
  const ra = readTargetOnRecord(a);
  const rb = readTargetOnRecord(b);
  if (!ra.present || !rb.present) {
    const noTarget = (r: RecordTargetReading) => !r.present && r.why === "NO_TARGET_NAMED";
    if (noTarget(ra) || noTarget(rb)) {
      return { verdict: "NOT_COMPARABLE", reason: "NO_TARGET_NAMED" };
    }
    return { verdict: "NOT_COMPARABLE", reason: "FINGERPRINT_ABSENT" };
  }
  return compareTargetFingerprints(ra.fact, rb.fact);
}

/**
 * THE SIX LABELS A READER PRINTS, and ruling 3 names one of them verbatim:
 * across `saltId`s it prints **NOT COMPARABLE (epoch)**, never "different
 * target". The suite asserts all six are PAIRWISE DISTINCT.
 */
export function labelTargetComparison(c: TargetComparison): string {
  switch (c.verdict) {
    case "SAME_TARGET":
      return "SAME TARGET";
    case "DIFFERENT_TARGET":
      return "DIFFERENT TARGET";
    case "NOT_COMPARABLE":
      switch (c.reason) {
        case "DIFFERENT_SALT_EPOCH":
          return "NOT COMPARABLE (epoch)";
        case "DIFFERENT_CANON_VERSION":
          return "NOT COMPARABLE (canon version)";
        case "FINGERPRINT_ABSENT":
          return "NOT COMPARABLE (no fingerprint)";
        case "NO_TARGET_NAMED":
          return "NOT COMPARABLE (no target named)";
      }
  }
}

/**
 * THE READER'S OWN SENTENCE, one per verdict, and the suite asserts the six
 * are PAIRWISE DISTINCT. That assertion is the mechanical form of "never one
 * word for two facts": it fails the moment somebody reuses a phrase.
 *
 * No verdict word appears in any of them — these are descriptions of a
 * comparison, not an instrument's output, and the house bars reader-verdict
 * vocabulary from prose that describes a record.
 */
export function describeTargetComparison(c: TargetComparison): string {
  switch (c.verdict) {
    case "SAME_TARGET":
      return "the two records name the same canonical target, under one salt epoch and one canonicalisation version";
    case "DIFFERENT_TARGET":
      return "the two records name different canonical targets, under one salt epoch and one canonicalisation version";
    case "NOT_COMPARABLE":
      switch (c.reason) {
        case "DIFFERENT_SALT_EPOCH":
          return "these two records were written under DIFFERENT SALT EPOCHS and cannot be compared at all: two digests taken under different salts would differ even if the targets were identical, so no reading of them — matching or not — carries information";
        case "DIFFERENT_CANON_VERSION":
          return "these two records were written under DIFFERENT CANONICALISATION VERSIONS and cannot be compared at all: the same target canonicalises to different strings under different rules, so equal digests would be a coincidence and unequal digests would say nothing";
        case "FINGERPRINT_ABSENT":
          return "at least one of these records was written by a bridge that HELD NO EPOCH, so it carries the reason instead of a digest: there is no value to compare, and the act it describes did name a target that nothing here can identify";
        case "NO_TARGET_NAMED":
          return "at least one of these records DESCRIBES AN ACT THAT NAMED NO TARGET, so it carries no fingerprint key at all: there was never anything to compare, and no repair to this deployment would give it one";
      }
  }
}
