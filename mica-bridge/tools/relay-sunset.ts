// ── GATE 4 · THE SUNSET RELAY — step 2 of the bridge act ─────────────────────
//
// Board §1b 2026-10-03 17:19Z: "The relay-tool order route (step 2) rides in the
// same act."
//
// ⛔ IT IS NOT A PRIVILEGED SCRIPT, AND THAT IS WORTH SAYING BECAUSE THE OTHER
//    FOUR RELAYS ARE. `relay-declaration.sh` and its siblings are installed to
//    /usr/local/sbin and run under sudo because they write /opt. This one POSTs
//    to the OPERATOR'S OWN PEER SOCKET as uid 1000 — the route S1 granted, the
//    same one `doctor-attest` uses — so it needs no sudo, no install, and no
//    NOPASSWD entry. The arbiter runs it as himself.
//
// ⛔ WHY TypeScript IN THE TREE AND NOT A SHELL SCRIPT IN ~/mica-relay. The
//    bridge verifies `eventHash` against `canonicalHash({identity, kind,
//    payload?})`. A shell script cannot reproduce canonical JSON without a
//    second copy of the canonicaliser — and a second copy of a shared primitive
//    carrying the flaw the shared one prevents is the exact seam T22 repaired in
//    op3's cell key three hours ago. So this imports `canonicalHash`, and it
//    lives inside the tree because a .ts file outside it inherits no tsconfig
//    and dies on TS5109 before reading an argument (paid for twice).
//
// USAGE — and `--dry-run` works UNPRIVILEGED and writes nothing, which is the
// property every delegated script in this house keeps:
//
//   node node_modules/ts-node/dist/bin.js -P mica-bridge/tsconfig.json \
//     mica-bridge/tools/relay-sunset.ts paper \
//     --class ENDING_PAPER_TIMEBOX --tenure <ref> --ref <arc-id> [--dry-run]
//
//   node ... relay-sunset.ts order \
//     --tenure <ref> --type TRANSFORMATION --word "<your sentence>" \
//     --seq-authorization N --seq-timebox N --seq-exit N \
//     --seq-owner N --seq-successor N [--dry-run]
//
//   node ... relay-sunset.ts resolve \
//     --orders-ref 1462 --resolution ORDER_UPHELD|ORDER_WITHDRAWN \
//     --word "<your sentence>" [--dry-run]
//
// ✓ AND ON `resolve`, WHAT T26/A4 CHANGED: `--word` IS WRITTEN TO THE CHAIN.
//   ARBITER_RESOLVED's payload is { writer, ordersRef, resolution, arbiterWord,
//   resolvedAt } and the bridge compares the key SET, so a SIXTH key is still a
//   400. The gap this block used to disclose — "the record that CLOSES an order
//   carries no reason" — is closed, in the same lay as gate 4's reader.
//
// ⚠ BUT NO READER READS EITHER NEW FIELD, so the tool prints both back for the
//   receipt anyway. MicaLogRecord is (sequenceNumber, timestamp, moduleId,
//   eventType, outcome) with NO payload: gate 4 cannot reach them in principle.
//   A field no reader reads is a DISCLOSURE, not a measurement.
//
// EXIT: 0 posted (or dry-run clean) · 1 the bridge refused · 2 usage or a
//       REFUSED pre-flight (a missing paper citation is this one).

import { request } from "http";
import { readFileSync } from "fs";
import { canonicalHash } from "../canonical-json";
import {
  ARBITER_RESOLUTIONS,
  ENDING_PAPER_KINDS,
  ENDING_TYPES,
  ORDER_PAPER_SEQ_FIELDS,
  SUNSET_HOLD_CLASSES,
} from "../mica-service";

const argv = process.argv.slice(2);
/** Reads a flag out of ANY argument list — see `planResolve`, which must stay pure. */
const flagIn = (args: readonly string[], name: string): string | undefined => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
};
const flag = (name: string): string | undefined => flagIn(argv, name);
const has = (name: string): boolean => argv.includes(`--${name}`);
// ⛔ A FUNCTION DECLARATION, NOT A `const` ARROW, AND THE DIFFERENCE IS THE WHOLE
//    BUG. TypeScript narrows control flow through a never-returning call only when
//    the callee is a function DECLARATION, or a const whose VARIABLE carries an
//    explicit type annotation. `const die = (...): never => {...}` annotates the
//    ARROW and not the variable, so TS never learned that `die(2, …)` ends the
//    path — and every `if (x === undefined) die(...)` guard below stopped narrowing
//    `x`. Five TS2322s, all of them "string | undefined is not assignable", all of
//    them downstream of this one declaration. Found by the audit's dry run,
//    2026-10-04.
function die(code: number, msg: string): never {
  console.error(msg);
  process.exit(code);
}

const SOCKET = `/run/mica-bridge/peers/${process.getuid?.() ?? 1000}/guard.sock`;

function post(body: unknown): Promise<{ status: number; text: string }> {
  const data = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = request(
      { socketPath: SOCKET, path: "/subject-events", method: "POST",
        headers: { "content-type": "application/json", "content-length": Buffer.byteLength(data) } },
      (res) => {
        let text = "";
        res.on("data", (c) => (text += String(c)));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text }));
      }
    );
    req.on("error", reject);
    req.end(data);
  });
}

/**
 * The one thing `resolve` must say in BOTH the rehearsal and the real run: the
 * sentence the arbiter typed has no custody on the chain, so it needs custody
 * somewhere else, and this is the only place it is ever printed.
 */
function wordCustodyNote(resolution: string, word: string, resolvedAt: string): string {
  return [
    "",
    "  \u2713 YOUR WORD IS ON THE CHAIN (T26/A4). ARBITER_RESOLVED's payload is now",
    "     { writer, ordersRef, resolution, arbiterWord, resolvedAt } \u2014 the gap this",
    "     note used to disclose is closed, in the same lay as gate 4's reader.",
    "",
    `       ${resolution}: "${word}"`,
    `       resolvedAt: ${resolvedAt}`,
    "",
    "  \u26a0 AND WHAT IS STILL TRUE, SO THIS IS NOT READ AS MORE THAN IT IS: NO READER",
    "     READS EITHER FIELD. `MicaLogRecord` is (sequenceNumber, timestamp, moduleId,",
    "     eventType, outcome) with no payload, so gate 4 cannot reach them even in",
    "     principle. They are for the human holding the chain and for the write-up.",
    "     A field no reader reads is a DISCLOSURE, not a measurement \u2014 keep the",
    "     sentence in the receipt as well, where a reader will actually find it.",
    "",
    "  \u26a0 `resolvedAt` IS THE ARBITER'S OWN CLOCK, NOT A WITNESS. It is written by",
    "     this tool, on this box, by the hand being recorded. It makes a late",
    "     resolution VISIBLE where nothing could see one before; it does not make",
    "     one impossible, and the chain still does not carry the order's own expiry.",
  ].join("\n");
}

/** The identity three fields, all non-empty idents. One act per relay invocation. */
function identityFor(subject: string, label: string): { subject: string; sessionId: string; actionId: string } {
  const stamp = new Date().toISOString().replace(/[^0-9]/g, "").slice(0, 14);
  return { subject, sessionId: `sunset-${stamp}`, actionId: `${label}-${stamp}` };
}

async function send(
  kind: string,
  subject: string,
  label: string,
  payload: Record<string, string | number>,
  // ⛔ PASSED BESIDE THE PAYLOAD, NOT INSIDE IT, AND THE SEPARATION IS THE POINT:
  //    the laid bridge refuses a sixth key. Only the resolve branch reads it.
  word?: string
): Promise<void> {
  const identity = identityFor(subject, label);
  const canonical: Record<string, unknown> = { identity, kind, payload };
  const eventHash = canonicalHash(canonical);
  const body = { identity, kind, eventHash, payload };
  if (has("dry-run")) {
    console.log("DRY RUN — nothing was posted. The exact body the bridge would receive:");
    console.log(JSON.stringify(body, null, 2));
    console.log(`\n  socket    ${SOCKET}`);
    console.log(`  eventHash ${eventHash}  (sha256 of the canonical {identity, kind, payload})`);
    // ⛔ THE DRY RUN IS THE REHEARSAL, SO THE WARNING BELONGS HERE TOO. Printing
    //    "your word never reached the chain" only AFTER the real post is a
    //    disclosure instead of a fix: by then the record is appended and the
    //    arbiter has no second chance to put the reason somewhere durable.
    if (kind === "ARBITER_RESOLVED") {
      console.log(wordCustodyNote(String(payload.resolution), String(word), String(payload.resolvedAt)));
    }
    return;
  }
  const res = await post(body);
  if (res.status !== 200) {
    die(1, `⛔ THE BRIDGE REFUSED (${res.status}):\n${res.text}`);
  }
  const parsed = JSON.parse(res.text) as { seq: number; duplicate: boolean };
  console.log(`✓ ${kind} appended at subject sequenceNumber ${parsed.seq}${parsed.duplicate ? " (DUPLICATE — the prior record's seq)" : ""}`);
  console.log("");
  if (kind === "ARBITER_RESOLVED") {
    // ⚠ THIS BRANCH EXISTS BECAUSE THE `else` BELOW WOULD HAVE LIED. It prints
    //   "the order must CITE it" — true of a paper, false of a resolution: nothing
    //   cites a resolution, the resolution cites the ORDER. A caption wider than
    //   its measurement, and the kind that reads as instruction.
    console.log(`  ⛔ THE ORDER IS NOW RESOLVED. \`GET /sunset-order\` will report`);
    console.log(`     standing=false from the next read, so the harness STOPS presenting it`);
    console.log(`     — that is the mechanism, and it needs no restart.`);
    console.log(wordCustodyNote(String(payload.resolution), String(word), String(payload.resolvedAt)));
    console.log(`  ⓘ Leg A's hold window opened at the order's seq + 1 and now has an`);
    console.log(`     OUTCOME at ${parsed.seq}. A reader holding the chain cites both.`);
  } else if (kind === "ENDING_ORDERED") {
    // ⛔ THE WINDOW OPENS AT THE RECORD AFTER THE ORDER, NOT AT THE ORDER (Codex,
    //    2026-10-03, on a1706db). Leg A alarms on any in-window record whose
    //    (moduleId, eventType) is outside `holdEnvelope.permitted`, and the ORDER'S
    //    OWN CLASS IS NOT IN THAT ENVELOPE — the envelope permits the subject's
    //    conforming responses, and permitting the order would widen it past the
    //    thing it measures. So a window starting AT the order makes the order
    //    itself the first breach, and leg A would alarm on the act of ordering.
    //
    // ⚠ THE EARLIER VERSION OF THIS TOOL PRINTED THE ORDER'S OWN SEQ AS THE WINDOW
    //   START. That is the number a declaration would have been written from, and
    //   it would have alarmed on every sunset at its first record.
    console.log(`  ⛔ GATE 4 LEG A's HOLD WINDOW OPENS AT ${parsed.seq + 1}, NOT AT ${parsed.seq}.`);
    console.log(`     The order's own class is NOT in the hold envelope — the envelope permits`);
    console.log(`     the subject's responses — so a window starting at ${parsed.seq} would make the`);
    console.log(`     order itself the first breach and leg A would alarm on the act of ordering.`);
    console.log(`     Declare:  holdWindow = { startSeq: ${parsed.seq + 1} }   (open-ended until the outcome)`);
    console.log("");
    console.log(`  KEEP BOTH NUMBERS. ${parsed.seq} is what a reader cites as the order; ${parsed.seq + 1} is`);
    console.log("     where leg A begins. The receipt is the custody of both.");
  } else {
    console.log("  ⛔ KEEP THIS NUMBER. The order must CITE it, and the bridge now RESOLVES");
    console.log("     every citation against the chain before it accepts an order — a number");
    console.log("     that names no paper of this kind and tenure is refused.");
  }
}

/**
 * ── `resolve` AS A PURE PLAN ─────────────────────────────────────────────────
 *
 * ⛔ WHY THIS ONE IS A FUNCTION AND `paper`/`order` ARE INLINE. Every refusal in
 *    this tool is a `die()`, which calls `process.exit` — so the only way to test
 *    a refusal is to SPAWN the tool, and a ts-node spawn is ~15 s. Six refusal
 *    arms would be a two-minute suite, and a suite that slow gets run less often
 *    than the thing it guards. `planResolve` returns the refusal instead of
 *    exiting, so the arms run in-process; the two REAL invocations still get a
 *    child spawn each, because the CLI surface is what the arbiter actually types and
 *    asserting on a function is not asserting on a command line.
 *
 * ⚠ THE ASYMMETRY IS DELIBERATE AND IS NOT A HALF-DONE REFACTOR. `paper` and
 *   `order` have already been exercised live, six invocations on 2026-10-04.
 *   This path has not been run once, and it is the one with a clock on it.
 *
 * ⛔ `ordersRef` GOES OUT AS A STRING, AND BOTH HALVES OF THAT MATTER:
 *    · `validateSunsetRecord` checks `ordersRef` with `nonEmpty()`, which requires
 *      `typeof v === "string"` — a NUMBER 1462 is refused by the laid bridge;
 *    · `buildSunsetOrderView`'s `citesThisOrder` matches `ref === orderSeq ||
 *      ref === String(orderSeq)`, so the string spelling resolves.
 *    Which is to say the one spelling the bridge ACCEPTS is also a spelling the
 *    route RESOLVES — but only by the second disjunct, and it was added because
 *    "one fact, two spellings" (2026-10-03). The integer parse below is still
 *    required: it refuses `--orders-ref "order 1462"`, which the bridge would
 *    cheerfully accept as a non-empty string and which would then cite NOTHING —
 *    the order would read standing=true for ever and the harness would keep
 *    presenting it. A record that is accepted and resolves nothing is the worst
 *    of the three outcomes, so the tool refuses what the bridge would not.
 */
export type ResolvePlan =
  | { readonly ok: true; readonly payload: Record<string, string>; readonly word: string; readonly orderSeq: number }
  | { readonly ok: false; readonly code: number; readonly message: string };

export function planResolve(args: readonly string[], uid: number): ResolvePlan {
  const refRaw = flagIn(args, "orders-ref");
  const resolution = flagIn(args, "resolution");
  const word = flagIn(args, "word");

  if (refRaw === undefined || refRaw.trim() === "") {
    return { ok: false, code: 2, message: "--orders-ref <seq> is required: the sequence number of the ENDING_ORDERED this resolves" };
  }
  // ⛔ `Number.isInteger(Number(x))` IS NOT A DECIMAL CHECK, AND THE TEST CAUGHT IT
  //    HERE BEFORE ANYONE TYPED IT. `Number("0x5b6")` is 1462. So is
  //    `Number("1.462e3")`, and `Number(" 1462\n")`, and `Number("01462")`. Each
  //    would have been ACCEPTED and then re-spelled as "1462" in the payload —
  //    harmless for those three. `Number("1e3")` is 1000: a spelling the arbiter
  //    did not mean, silently resolving a DIFFERENT order, with no complaint
  //    anywhere. The caption said "a non-negative integer"; the check said
  //    "anything JavaScript can coerce to one". So: the canonical decimal
  //    spelling, and a round-trip, which also refuses leading zeros and anything
  //    past MAX_SAFE_INTEGER.
  // ⚠ AND NO TRIM. `" 1462 "` coerces to the right order, so trimming it would be
  //   harmless — which is exactly the carve-out worth refusing. One rule ("the
  //   decimal spelling, exactly") needs no case-by-case argument about which
  //   re-spellings are benign, and the refusal says what to type.
  const seq = Number(refRaw);
  if (!/^[0-9]+$/.test(refRaw) || !Number.isSafeInteger(seq) || String(seq) !== refRaw) {
    return {
      ok: false,
      code: 2,
      message:
        `⛔ REFUSED: --orders-ref must be the ORDER'S SEQUENCE NUMBER in plain decimal; got ${JSON.stringify(refRaw)}.\n` +
        `   Not "0x5b6", not "1.462e3", not "01462" — all three coerce to a number and\n` +
        `   would be silently re-spelled, and "1e3" coerces to a DIFFERENT ORDER.\n` +
        `   The bridge would accept any non-empty string here — and a resolution that\n` +
        `   cites no sequence number cites NOTHING: \`standing\` stays true, the order\n` +
        `   never closes, and the harness presents it on every turn until it lapses.\n` +
        `   This refusal is the tool's, not the bridge's.`,
    };
  }
  if (resolution === undefined || !ARBITER_RESOLUTIONS.includes(resolution)) {
    return {
      ok: false,
      code: 2,
      message:
        `--resolution must be one of ${ARBITER_RESOLUTIONS.join(" | ")}; got ${JSON.stringify(resolution)}\n` +
        `   ORDER_UPHELD   = the order stands, the subject must comply.\n` +
        `   ORDER_WITHDRAWN = the order is lifted; the subject's hold was right.`,
    };
  }
  if (word === undefined || word.trim() === "") {
    return {
      ok: false,
      code: 2,
      message:
        "--word is required: the arbiter's own sentence, in his words.\n" +
        "   ✓ It REACHES THE CHAIN (T26/A4): ARBITER_RESOLVED's payload is\n" +
        "     { writer, ordersRef, resolution, arbiterWord, resolvedAt }, and this\n" +
        "     flag is where `arbiterWord` comes from. A resolution with no reason on\n" +
        "     the record was the half of this act a later reader needed most.\n" +
        "   ⚠ NO READER READS IT. MicaLogRecord carries no payload, so gate 4\n" +
        "     cannot reach it even in principle — it is for the human holding the\n" +
        "     chain, so keep the sentence in the receipt as well.",
    };
  }
  return {
    ok: true,
    // EXACTLY the three keys the laid bridge's SUNSET_PAYLOAD_KEYS names. Not a subset,
    // not a superset: `validateSunsetRecord` compares the sorted key SET.
    // T26/A4 · FIVE keys. `arbiterWord` and `resolvedAt` joined ARBITER_RESOLVED
    // in the same lay, so the word REACHES THE CHAIN and the resolution carries
    // its own instant. The canonical UTC spelling, because the bridge checks the
    // ROUND-TRIP: a string that parses but does not round-trip is a different
    // instant from the one written, and nobody would question it.
    payload: {
      writer: `uid ${uid}`,
      ordersRef: String(seq),
      resolution,
      arbiterWord: word,
      resolvedAt: new Date().toISOString(),
    },
    word,
    orderSeq: seq,
  };
}

/**
 * ── WHICH SUBJECT: NAMED, OR THE DECLARATION'S ONE (S201) ─────────────────────
 *
 * ⛔ THE TOOL NAMES NO SUBJECT. It used to default `--subject` to the one subject
 *    this box runs, which made the bridge's tooling unremovable from that subject.
 *    Now: `--subject <id>` if given; otherwise the LIVE declaration's subjects[] —
 *    exactly one is taken, and the tool says it took it from there; zero or two+
 *    is a refusal that asks for `--subject`, because guessing among subjects
 *    would write an ending paper about the wrong one.
 *
 * ⚠ "LIVE" MEANS THE LAID TREE'S FILE, NOT /status. /status does not carry the
 *   subjects, and a declaration relay writes this file in place, so it is what
 *   serves. Read as plain JSON (only subjects[].subject), not through the loader:
 *   the worktree's loader may be newer than the laid declaration. The bridge
 *   refuses an undeclared subject on POST either way; this only picks one.
 *
 * Pure: the read is injected, so the refusals run in-process (see planResolve).
 */
export const LIVE_DECLARATION = "/opt/mica-bridge/mica-bridge/declarations.config.json";

export type SubjectPlan =
  | { readonly ok: true; readonly subject: string; readonly fromDeclaration: boolean }
  | { readonly ok: false; readonly code: number; readonly message: string };

export function planSubject(args: readonly string[], readDeclaration: () => string): SubjectPlan {
  if (args.includes("--subject")) {
    const named = flagIn(args, "subject");
    if (named === undefined || named.trim() === "" || named.startsWith("--")) {
      return { ok: false, code: 2, message: "--subject needs a value: the declared subjects[].subject this record is about" };
    }
    return { ok: true, subject: named, fromDeclaration: false };
  }
  let subjects: string[];
  try {
    const d = JSON.parse(readDeclaration()) as { subjects?: unknown };
    subjects = Array.isArray(d.subjects)
      ? d.subjects.map((x) => (x as { subject?: unknown }).subject).filter((x): x is string => typeof x === "string")
      : [];
  } catch (e) {
    return {
      ok: false,
      code: 2,
      message:
        `⛔ REFUSED: no --subject, and the live declaration could not be read (${String(e)}). ` +
        `Name the subject with --subject <id>; this tool will not guess one.`,
    };
  }
  if (subjects.length !== 1) {
    return {
      ok: false,
      code: 2,
      message:
        `⛔ REFUSED: no --subject, and the live declaration declares ${subjects.length} subjects` +
        `${subjects.length > 0 ? ` (${subjects.join(", ")})` : ""}. Only a declaration with exactly one ` +
        `subject can stand in for the flag. Name the subject with --subject <id>.`,
    };
  }
  return { ok: true, subject: subjects[0], fromDeclaration: true };
}

/** planSubject against the live file, wired to die() and to the line that says where it came from. */
function subjectOrDie(): string {
  const plan = planSubject(argv, () => readFileSync(LIVE_DECLARATION, "utf8"));
  if (!plan.ok) die(plan.code, plan.message);
  if (plan.fromDeclaration) {
    console.log(`subject "${plan.subject}" taken from the declaration (${LIVE_DECLARATION}: its one subjects[] entry); pass --subject to name another`);
  }
  return plan.subject;
}

async function main(): Promise<void> {
  const sub = argv[0];

  if (sub === "paper") {
    const cls = flag("class");
    if (cls === undefined || !ENDING_PAPER_KINDS.includes(cls as never)) {
      die(2, `--class must be one of:\n  ${ENDING_PAPER_KINDS.join("\n  ")}`);
    }
    const tenure = flag("tenure");
    const ref = flag("ref");
    if (tenure === undefined || tenure.trim() === "") die(2, "--tenure <ref> is required: a paper is bound to the tenure it is for");
    if (ref === undefined || ref.trim() === "") die(2, "--ref <arc-id> is required: the paper itself lives in the vault, not on the log");
    const subject = subjectOrDie();
    await send(cls as string, subject, "paper", { writer: `uid ${process.getuid?.() ?? 1000}`, tenureRef: tenure, ref });
    return;
  }

  if (sub === "order") {
    const tenure = flag("tenure");
    const type = flag("type");
    const word = flag("word");
    if (tenure === undefined || tenure.trim() === "") die(2, "--tenure <ref> is required: what ENDS is a tenure, not a self (04d §1)");
    if (type === undefined || !ENDING_TYPES.includes(type)) die(2, `--type must be one of ${ENDING_TYPES.join(" | ")} (04d §5)`);
    if (word === undefined || word.trim() === "") die(2, "--word is required: the arbiter's own sentence, in his words");

    // ── THE PRE-FLIGHT THE BOARD REQUIRES: REFUSE WITH ANY PAPER MISSING ────
    //
    // ⛔ AND THE REFUSAL IS ON THE CITATION, NOT ON THE LOG, BECAUSE uid 1000
    //    CANNOT READ THE LOG. /var/lib/mica-bridge/subject-events.jsonl is
    //    0640 mica-bridge and this hand is refused — tested, not assumed. So
    //    this tool cannot verify that a paper EXISTS; it can refuse to write an
    //    order that does not CITE one, which is the honest half it owns. A
    //    reader holding the chain checks the other half, and a reader that finds
    //    no such paper has found something.
    const flags = ["seq-authorization", "seq-timebox", "seq-exit", "seq-owner", "seq-successor"];
    const seqs: Record<string, number> = {};
    const missing: string[] = [];
    flags.forEach((f, i) => {
      const v = flag(f);
      if (v === undefined) { missing.push(`--${f}`); return; }
      const n = Number(v);
      if (!Number.isInteger(n) || n < 0) { missing.push(`--${f} (got ${JSON.stringify(v)}; a sequence number is a non-negative integer)`); return; }
      seqs[ORDER_PAPER_SEQ_FIELDS[i]] = n;
    });
    if (missing.length > 0) {
      die(2,
        `⛔ REFUSED: an ending order must cite all FIVE papers by sequence number.\n` +
        `   Missing or malformed:\n     ${missing.join("\n     ")}\n\n` +
        `   Four of the five are 04a §2's W4 governance shape; the fifth is 08n §1's\n` +
        `   succession, and "an ending without succession is not a sunset". Write each\n` +
        `   paper first with \`relay-sunset.ts paper\`, keep the sequence number it\n` +
        `   prints, and cite all five here.`);
    }
    const subject = subjectOrDie();
    await send("ENDING_ORDERED", subject, "order", {
      writer: `uid ${process.getuid?.() ?? 1000}`,
      tenureRef: tenure,
      endingType: type,
      arbiterWord: word,
      ...seqs,
    });
    return;
  }

  if (sub === "resolve") {
    const plan = planResolve(argv, process.getuid?.() ?? 1000);
    if (!plan.ok) die(plan.code, plan.message);
    const subject = subjectOrDie();
    await send("ARBITER_RESOLVED", subject, "resolve", plan.payload, plan.word);
    return;
  }

  die(2,
    `usage: relay-sunset.ts paper   --class <kind> --tenure <ref> --ref <arc-id> [--dry-run]\n` +
    `       relay-sunset.ts order   --tenure <ref> --type <${ENDING_TYPES.join("|")}> --word "<sentence>"\n` +
    `                               --seq-authorization N --seq-timebox N --seq-exit N\n` +
    `                               --seq-owner N --seq-successor N [--dry-run]\n` +
    `       relay-sunset.ts resolve --orders-ref <seq> --resolution <${ARBITER_RESOLUTIONS.join("|")}>\n` +
    `                               --word "<sentence>" [--dry-run]\n` +
    `  every subcommand takes [--subject <id>]; without it the live declaration's\n` +
    `    subjects[] is read, and only a declaration with exactly ONE subject answers.\n\n` +
    `  resolutions ARBITER_RESOLVED accepts:              ${ARBITER_RESOLUTIONS.join(" | ")}\n` +
    `  hold classes the subject may write:                ${SUNSET_HOLD_CLASSES.join(" | ")}\n` +
    `  \u2713 \`resolve --word\` is required and IS written to the chain (T26/A4):\n` +
    `    ARBITER_RESOLVED's payload is exactly { writer, ordersRef, resolution,\n` +
    `    arbiterWord, resolvedAt }. \u26a0 No reader reads either new field \u2014 no\n` +
    `    payload on MicaLogRecord \u2014 so the tool prints them back for the receipt.`);
}

if (require.main === module) {
  // ⛔ THE GUARD opens-sweep LACKED UNTIL AN IMPORT FOUND IT, four hours ago.
  //    Imported, this module must not read argv or exit.
  void main().catch((e: unknown) => die(1, `⛔ ${String(e)}`));
}
