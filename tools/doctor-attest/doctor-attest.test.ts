// ── tools/doctor-attest — tests ──────────────────────────────────────────────
//
// Run with:
//   /usr/bin/node <richards-cat>/node_modules/ts-node/dist/bin.js -P tsconfig.json doctor-attest.test.ts
//
// WHAT IS AND IS NOT TESTED HERE. These exercise the tool's own refusals and
// the body it builds. THEY DO NOT PROVE THE VOCABULARY IS ENFORCED — the tool's
// check is a courtesy and anything that can open the socket can skip it. The
// enforcement tests live in mica-bridge/mica-service.test.ts against the route,
// which is the gate. If this file ever looks like the proof, read the header of
// doctor-attest.ts again.

import { createHash } from "crypto";
import { DOCTOR_ATTESTATION_WORDS } from "../../mica-bridge/mica-service";
import { parseArgs, buildBody, actionIdFor } from "./doctor-attest";

let passed = 0;
let failed = 0;
function check(name: string, fn: () => void): void {
  try {
    fn();
    passed++;
    console.log(`PASS  ${name}`);
  } catch (err) {
    failed++;
    console.log(`FAIL  ${name}`);
    console.log(`      ${err instanceof Error ? err.message : String(err)}`);
  }
}
function assert(cond: boolean, msg: string): void {
  if (!cond) throw new Error(`assertion failed: ${msg}`);
}

const FIXED = () => new Date("2026-09-28T09:00:00Z");

check("every word in the vocabulary is accepted", () => {
  for (const word of DOCTOR_ATTESTATION_WORDS) {
    const r = parseArgs(["--subject", "housekeeper", "--word", word], FIXED);
    assert(!("error" in r), `${word} was refused: ${JSON.stringify(r)}`);
  }
});

check("a word outside the vocabulary is refused BEFORE anything is posted", () => {
  for (const word of ["HEALTHY", "ALL_CLEAR", "examined", "FINE", "SILENT"]) {
    const r = parseArgs(["--subject", "housekeeper", "--word", word], FIXED);
    assert("error" in r, `"${word}" must be refused`);
  }
});

check("the refusal TEACHES the vocabulary rather than only naming the field", () => {
  const r = parseArgs(["--subject", "housekeeper", "--word", "HEALTHY"], FIXED);
  assert("error" in r, "must be refused");
  const msg = (r as { error: string }).error;
  for (const word of DOCTOR_ATTESTATION_WORDS) {
    assert(msg.includes(word), `the refusal must list ${word}`);
  }
  // AND IT MUST SAY WHY THERE IS NO POSITIVE WORD. A doctor who reaches for
  // "healthy" is not making a typo; they are expecting a claim this record
  // cannot carry, and a refusal that only says "bad value" leaves them to
  // discover that for themselves.
  assert(msg.includes("cannot carry"), `the refusal must say why no positive word exists: ${msg}`);
});

check("--subject and --word have no defaults", () => {
  assert("error" in parseArgs(["--word", "EXAMINED"], FIXED), "--subject must be required");
  assert("error" in parseArgs(["--subject", "housekeeper"], FIXED), "--word must be required");
});

check("an unknown flag, a repeated flag and a dangling flag are all refused", () => {
  assert("error" in parseArgs(["--subject", "h", "--word", "EXAMINED", "--note", "x"], FIXED), "unknown flag");
  assert("error" in parseArgs(["--subject", "h", "--subject", "g", "--word", "EXAMINED"], FIXED), "repeated flag");
  assert("error" in parseArgs(["--subject", "h", "--word"], FIXED), "dangling flag");
  assert("error" in parseArgs(["subject", "h"], FIXED), "a bare word is not a flag");
});

check("the visit id defaults to a UTC date stamp, and is settable", () => {
  const r = parseArgs(["--subject", "housekeeper", "--word", "EXAMINED"], FIXED);
  assert(!("error" in r) && r.session === "doctor-visit-2026-09-28", JSON.stringify(r));
  const r2 = parseArgs(["--subject", "housekeeper", "--word", "EXAMINED", "--session", "v7"], FIXED);
  assert(!("error" in r2) && r2.session === "v7", JSON.stringify(r2));
});

check("the body carries exactly the three payload fields the route admits", () => {
  const args = parseArgs(["--subject", "housekeeper", "--word", "EXAMINED"], FIXED);
  assert(!("error" in args), "must parse");
  const body = buildBody(args as any) as any;
  assert(body.kind === "DOCTOR_ATTESTED", body.kind);
  assert(JSON.stringify(Object.keys(body.payload).sort()) === '["doctor","subject","word"]', JSON.stringify(body.payload));
  // TWO FACTS, ONE RECORD, AND THEY MUST AGREE — the route refuses them apart.
  assert(body.payload.subject === body.identity.subject, JSON.stringify(body));
  assert(/^uid -?\d+$/.test(body.payload.doctor), body.payload.doctor);
});

check("the eventHash is the sha256 the bridge will recompute, not a fabricated digest", () => {
  const args = parseArgs(["--subject", "housekeeper", "--word", "SECOND_HAND"], FIXED);
  const body = buildBody(args as any) as any;
  // Recomputed here INDEPENDENTLY of the tool's own helper, so a bug in that
  // helper cannot make this test agree with itself. Canonical form: keys sorted
  // at every level, no whitespace.
  const canon =
    `{"identity":{"actionId":${JSON.stringify(body.identity.actionId)},` +
    `"sessionId":${JSON.stringify(body.identity.sessionId)},` +
    `"subject":${JSON.stringify(body.identity.subject)}},` +
    `"kind":"DOCTOR_ATTESTED",` +
    `"payload":{"doctor":${JSON.stringify(body.payload.doctor)},` +
    `"subject":${JSON.stringify(body.payload.subject)},` +
    `"word":${JSON.stringify(body.payload.word)}}}`;
  const expected = createHash("sha256").update(canon, "utf8").digest("hex");
  assert(body.eventHash === expected, `got ${body.eventHash}, expected ${expected}`);
});

check("one visit is ONE actionId — a rerun dedupes instead of minting a second visit", () => {
  assert(actionIdFor("housekeeper", "v7") === actionIdFor("housekeeper", "v7"), "stable");
  assert(actionIdFor("housekeeper", "v7") !== actionIdFor("housekeeper", "v8"), "a new visit is a new id");
  assert(actionIdFor("a", "v7") !== actionIdFor("b", "v7"), "a different subject is a different record");
});

check("the SAME visit with a DIFFERENT word produces a different eventHash under one actionId", () => {
  // This is the shape that makes the bridge answer 409 EVENT_HASH_CONFLICT
  // rather than quietly recording two contradictory attestations for one visit.
  // The tool does not decide that; it hands the bridge the question.
  const a = buildBody(parseArgs(["--subject", "h", "--word", "EXAMINED", "--session", "v1"], FIXED) as any) as any;
  const b = buildBody(parseArgs(["--subject", "h", "--word", "NOT_EXAMINED", "--session", "v1"], FIXED) as any) as any;
  assert(a.identity.actionId === b.identity.actionId, "same visit, same actionId");
  assert(a.eventHash !== b.eventHash, "a different word must be a different hash");
});

console.log("");
console.log(`CENSUS: ${passed} passed, ${failed} failed, ${passed + failed} total`);
if (failed > 0) process.exit(1);
