#!/usr/bin/env ts-node
// ── tools/doctor-attest — the doctor deposits ONE word, by their own hand ────
//
// Brief §2b, folded in by the arbiter's ruling 2026-09-24. `src/mica/op1-doctor-cadence`
// reads the SUBJECT LOG for a declared `attestationClass`; the doctor's own book
// is invisible to it. So the attestation becomes a record ON that log, written by
// uid 1000 — the first record on this box written by a SECOND PARTY, which is
// what Tier 2 needs and what nothing else on this log supplies.
//
// ── WHAT THIS PROGRAM IS, AND WHAT IT IS NOT ────────────────────────────────
//
// IT IS NOT A GATE. It checks the word before it posts, and that check is a
// COURTESY to the doctor: it is one program on one path, and anything that can
// open the socket can skip it. The gate is `mica-service.ts`'s route, which
// refuses an unlisted word AGAIN, and refuses this kind from any uid whose
// declared role is not `operator`. If this file and that route ever disagree,
// THE ROUTE IS RIGHT.
//
// IT IS OUTSIDE `src/` and has its own runner, per §2b. It imports exactly one
// thing from the bridge — `DOCTOR_ATTESTATION_WORDS` — so the vocabulary lives
// in ONE place and the arbiter's ruling costs one constant rather than two lists that
// drift.
//
// ── THE LANDING PROOF IS A CHAIN POSITION, NOT A FILE ───────────────────────
//
// On success this prints the record's `sequenceNumber`. That number is the
// record's position in an append-only chain the bridge mints inside its own
// serialized appender — so it cannot be produced by writing a file, and it
// cannot be produced twice for one deposit. A file's mtime would prove that
// SOMETHING touched a path; this proves THIS RECORD IS IN THAT BOOK, at that
// position. That is the distinction the H4 BLOCKED note was about.
//
// ── WHOSE HAND ──────────────────────────────────────────────────────────────
//
// THE ARBITER'S. The audit seat never posts, the build seat never posts, and this
// program has no way to post on anyone's behalf: the bridge takes the uid from
// the socket the connection arrived on, never from the body, and refuses a
// `payload.doctor` that names any other uid. A seat running this as its own uid
// gets 403 and no record.
//
// ── USAGE ───────────────────────────────────────────────────────────────────
//
//   doctor-attest --subject <name> --word <WORD> [--session <id>] [--socket <path>]
//
// `--session` defaults to a date-stamped visit id, because a visit is the unit
// the cadence reader counts and two words on one visit would be two visits in
// the record. It is settable so a doctor can correct a mistyped one by
// re-posting the SAME (subject, session, word) — the bridge dedupes on
// eventHash and returns the original sequenceNumber with `duplicate: true`,
// which is why this program prints that flag rather than hiding it.

import { createHash } from "crypto";
import * as http from "http";
import { DOCTOR_ATTESTATION_WORDS } from "../../mica-bridge/mica-service";

/** The bridge's own canonical form, reimplemented here for the same reason the
 *  caller reimplements it: this tool must not depend on the bridge's internals
 *  beyond the ONE exported constant above. Keys sorted, no whitespace, and an
 *  absent `payload` omitted entirely rather than kept as null — the rule
 *  `canonical-json.ts` states and `mica-service.ts` recomputes against. */
function canonicalize(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function canonicalHash(value: unknown): string {
  return createHash("sha256").update(canonicalize(value), "utf8").digest("hex");
}

interface Args {
  subject: string;
  word: string;
  session: string;
  socket: string;
}

/**
 * THE ARGUMENTS ARE PARSED STRICTLY AND NOTHING IS DEFAULTED THAT CARRIES
 * MEANING. `--subject` and `--word` have no defaults: a doctor who forgets one
 * is told, never given one. `--session` has a default because a visit id is
 * bookkeeping, not a claim. `--socket` has a default because it is a fact about
 * this box, not about this visit.
 */
export function parseArgs(argv: readonly string[], today: () => Date): Args | { error: string } {
  const out: Record<string, string> = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    const value = argv[i + 1];
    if (!key.startsWith("--")) return { error: `expected a --flag, got "${key}"` };
    if (value === undefined) return { error: `"${key}" has no value` };
    const name = key.slice(2);
    if (!["subject", "word", "session", "socket"].includes(name)) {
      return { error: `unknown flag "${key}"` };
    }
    if (out[name] !== undefined) return { error: `"${key}" given twice` };
    out[name] = value;
  }
  if (out.subject === undefined) return { error: "--subject is required; there is no default subject" };
  if (out.word === undefined) return { error: "--word is required; there is no default word" };
  // THE COURTESY CHECK. Not the gate — see this file's header.
  if (!DOCTOR_ATTESTATION_WORDS.includes(out.word)) {
    return {
      error:
        `"${out.word}" is not a word this vocabulary has.\n` +
        `  The four words, and each one names WHAT THE DOCTOR DID, never what the doctor FOUND:\n` +
        `    EXAMINED      you read the subject's own record, at bytes, on this visit\n` +
        `    SECOND_HAND   you read an account of it — a receipt, a report, a summary — not the thing\n` +
        `    BLOCKED       you tried and could not reach it: privilege, absence, an unreadable file\n` +
        `    NOT_EXAMINED  no examination on this visit\n` +
        `  There is no word here for "the subject is well", and that is deliberate: this record\n` +
        `  cannot carry that claim and the cadence reader could not check it if it did.`,
    };
  }
  const d = today();
  const stamp = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}-${String(d.getUTCDate()).padStart(2, "0")}`;
  return {
    subject: out.subject,
    word: out.word,
    session: out.session ?? `doctor-visit-${stamp}`,
    socket: out.socket ?? "/run/mica-bridge/peers/1000/guard.sock",
  };
}

/**
 * The actionId. ONE PER (subject, session), so a doctor who runs this twice in
 * one visit with the same word gets a dedupe rather than a second visit in the
 * record, and one who runs it twice with DIFFERENT words gets a 409 rather than
 * two contradictory attestations both standing. The bridge enforces both; this
 * shape is what hands it the question.
 */
export function actionIdFor(subject: string, session: string): string {
  return `doctor-${subject}-${session}`;
}

export function buildBody(args: Args): unknown {
  const identity = {
    subject: args.subject,
    sessionId: args.session,
    actionId: actionIdFor(args.subject, args.session),
  };
  // `doctor` names the uid THIS PROCESS runs as. The bridge refuses a value
  // that is not the uid its socket accepted the connection on, so this cannot
  // claim a hand it does not have — it can only get itself refused.
  const uid = process.getuid ? process.getuid() : -1;
  const payload = { word: args.word, subject: args.subject, doctor: `uid ${uid}` };
  return { identity, kind: "DOCTOR_ATTESTED", eventHash: canonicalHash({ identity, kind: "DOCTOR_ATTESTED", payload }), payload };
}

function post(socketPath: string, body: unknown): Promise<{ status: number; body: any }> {
  const text = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        socketPath,
        path: "/subject-events",
        method: "POST",
        headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text) },
      },
      (res) => {
        let out = "";
        res.setEncoding("utf8");
        res.on("data", (c) => (out += c));
        res.on("end", () => {
          try {
            resolve({ status: res.statusCode ?? 0, body: out.length === 0 ? null : JSON.parse(out) });
          } catch {
            resolve({ status: res.statusCode ?? 0, body: out });
          }
        });
      }
    );
    req.on("error", reject);
    req.write(text);
    req.end();
  });
}

export async function main(argv: readonly string[]): Promise<number> {
  const args = parseArgs(argv, () => new Date());
  if ("error" in args) {
    console.error(`doctor-attest: ${args.error}`);
    console.error("usage: doctor-attest --subject <name> --word <WORD> [--session <id>] [--socket <path>]");
    return 2;
  }
  const body = buildBody(args);
  let res: { status: number; body: any };
  try {
    res = await post(args.socket, body);
  } catch (err) {
    // A CONNECTION FAILURE IS NOT A DEPOSIT THAT MIGHT HAVE LANDED. Nothing was
    // acknowledged, so nothing is claimed — and there is no retry here, because
    // a retry after an unknown outcome is how one visit becomes two records.
    console.error(`doctor-attest: could not reach the bridge at ${args.socket}: ${String(err)}`);
    console.error("NOTHING WAS DEPOSITED. No record was acknowledged, so none is claimed.");
    return 1;
  }
  if (res.status !== 200) {
    console.error(`doctor-attest: the bridge REFUSED this attestation — HTTP ${res.status}`);
    console.error(`  ${JSON.stringify(res.body)}`);
    if (res.status === 403) {
      console.error(
        "  403 means this uid is not the doctor's hand. The bridge takes the uid from the\n" +
          "  socket, never from the body: only a route row with role `operator` may write\n" +
          "  DOCTOR_ATTESTED, and it may write nothing else."
      );
    }
    console.error("NOTHING WAS DEPOSITED.");
    return 1;
  }
  // THE LANDING PROOF. Printed as the chain position it is, and `duplicate` is
  // printed rather than hidden: a doctor who reruns one visit should SEE that
  // the record did not move, not be shown a number that looks new.
  console.log(`DEPOSITED  subject=${args.subject}  word=${args.word}  visit=${args.session}`);
  console.log(`sequenceNumber=${res.body.seq}  duplicate=${res.body.duplicate}`);
  console.log(
    "This number is this record's position in the bridge's append-only chain. It is the\n" +
      "landing proof; a file's mtime is not."
  );
  return 0;
}

if (require.main === module) {
  void main(process.argv.slice(2)).then((code) => process.exit(code));
}
