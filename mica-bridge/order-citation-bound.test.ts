// S199 (DRAFT, for signature) · an order may cite only papers AFTER the chain's latest order, by the READER's bound.
//   node -r <redirect to the S199 machine> <ts-node bin.js> -P mica-bridge/tsconfig.json mica-bridge/order-citation-bound.test.ts
//
// ⚠ THIS SUITE NEEDS THE S199 MACHINE. The bridge imports `gate4OrderBound` from /opt/mica-machine (via
//   stage1-guard-adapter.ts); a machine without the export fails at import, loudly. Until the machine half is
//   relayed, the paired run redirects /opt/mica-machine/… to the S199 machine worktree (a -r shim), as earlier
//   paired drafts did.
//
// PROVEN HERE, with the REAL admit path (`handleSubjectEvents`), each arm resolving the FIRST order before the
// second so ORDER_ALREADY_STANDING cannot mask a mutant (cond. 4):
//   (a) a second order citing the first's papers -> 400 ORDER_CITATION_REFUSED, BOOKED with field, cited, P and
//       the reader's rule, and the refusal text carries no instruction;
//   (b) five papers written after the first order -> accepted;
//   (c) a paper at exactly P+1 -> accepted; at the pure check, cited = P refused and P+1 admitted;
//   (d) COND. 2, THE ALTERNATIVE (audit 2026-10-18 06:56Z): an order whose own class is NOT declared is not
//       bounded and not refused (200, nothing booked), even citing papers before the declared subject's order;
//       on the same chain the DECLARED subject's order citing papers before P -> 400 naming P;
//   (d') (ticket 4(d), reworded) a subject the served profile does NOT declare: its order is no order to the
//       reader and does not move P;
//   (e) a second declared invocation class counts, and the candidate's own class decides whether there is a
//       bound at all (pure, a two-class profile: the served builder has one);
//   (f) no gate4 reader declared -> no bound, the admit path unchanged.
// NOT PROVEN: that a fresh paper is a true one (cond. 5: leg B reads FORM).
// Fixture names only: subject-a, subject-b, tool-x, tool-y.
import { shippedDraft } from "./example-draft";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "fs";
import { createHash } from "crypto";
import { tmpdir } from "os";
import { join } from "path";

import {
  MicaBridgeService,
  gate4OrderBoundForWriter,
  orderCitationsAfterBound,
  ORDER_PAPER_SEQ_FIELDS,
} from "./mica-service";
import { canonicalHash } from "./canonical-json";
import { gate4SunsetConfigFor } from "./to-wire-options";
import { GATE4_ORDER_BOUND_RULE } from "./stage1-guard-adapter";

let passed = 0;
let failed = 0;
async function check(name: string, fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
    console.log(`PASS  ${name}`);
    passed++;
  } catch (e) {
    console.log(`FAIL  ${name}\n      ${(e as Error).stack ?? String(e)}`);
    failed++;
  }
}
function assert(c: boolean, m: string): void {
  if (!c) throw new Error(`assertion failed: ${m}`);
}

const OWN_UID = process.getuid ? process.getuid() : 0;
const OWN_GID = process.getgid ? process.getgid() : 0;
const draft = shippedDraft();
const A = "subject-a";
const B = "subject-b";
const RETIRED_NAME = "subject-events.TESTFIXTURE.pre-chain-boundary.jsonl";
const RETIRED_BODY = JSON.stringify({ sequenceNumber: 1, timestamp: 1, moduleId: A, eventType: "TOOL_ATTEMPTED", outcome: "tool-x" }) + "\n";
const PAPERS = [
  "ENDING_PAPER_AUTHORIZATION",
  "ENDING_PAPER_TIMEBOX",
  "ENDING_PAPER_EXIT_CRITERIA",
  "ENDING_PAPER_ACCOUNTABLE_OWNER",
  "ENDING_PAPER_SUCCESSOR",
] as const;

/** The tree's declaration, narrowed: the operator (this uid) writes; gate 4 reads `gate4Subject`, or nothing. */
function declaration(gate4Subject: string | null): any {
  const d = JSON.parse(JSON.stringify(draft));
  d.pilot = { active: false };
  delete d.readers.gate1Scope;
  delete d.readers.gate2Direction;
  delete d.baskets;
  delete d.harm;
  delete d.frame;
  delete d.paths.witnessIntake;
  delete d.paths.witnessBook;
  d.subjectLog.chainBoundary.retiredPath.value = `/var/lib/mica-bridge/${RETIRED_NAME}`;
  d.subjectLog.chainBoundary.retiredRecords.value = 1;
  d.subjectLog.chainBoundary.retiredBytes.value = Buffer.byteLength(RETIRED_BODY, "utf8");
  d.subjectLog.chainBoundary.retiredSha256.value = createHash("sha256").update(RETIRED_BODY, "utf8").digest("hex");
  const s0 = d.subjects[0];
  delete s0.unit;
  // Both subjects bound to this uid so the loader's X6 (every subject's peerUid has a SUBJECT route) and the
  // startup peer-directory check (owned by that uid) both pass; `asOperator` then makes this uid the operator.
  d.subjects = [
    { ...s0, subject: A, toolName: "tool-x", peerUid: OWN_UID },
    { ...s0, subject: B, toolName: "tool-y", peerUid: OWN_UID },
  ];
  d.routes = [{ uid: OWN_UID, role: "subject", allow: [{ method: "POST", path: "/guard" }, { method: "POST", path: "/subject-events" }] }];
  if (gate4Subject === null) delete d.readers.gate4Sunset;
  else d.readers.gate4Sunset = { subject: { value: gate4Subject, basis: "TEST FIXTURE: the example declares no Gate 4 reader; this block supplies the stanza the S199 arms are about.", proxy: false } };
  return d;
}

/**
 * ⚠ A TEST SEAM, NAMED: the papers, the orders and the resolutions are OPERATOR kinds, and a route's uid must own
 * its peer directory at start — so the loaded declaration's ONE route row is re-roled to "operator" in memory
 * after start. Nothing else in the loaded declaration is touched; the handler reads `state.declarations` per call.
 */
function asOperator(svc: MicaBridgeService): void {
  const s = svc as any;
  const d = s.state.declarations;
  s.state = { ...s.state, declarations: { ...d, routes: d.routes.map((r: any) => ({ ...r, role: "operator" })) } };
}

interface Rig {
  readonly svc: MicaBridgeService;
  n: number;
}

async function rig(gate4Subject: string | null): Promise<Rig> {
  const socketDir = mkdtempSync(join(tmpdir(), "mica-s199-svc-"));
  const peer = join(socketDir, "peers", String(OWN_UID));
  mkdirSync(peer, { recursive: true });
  chmodSync(peer, 0o770);
  const dir = mkdtempSync(join(tmpdir(), "mica-s199-cfg-"));
  const cfgPath = join(dir, "declarations.config.json");
  writeFileSync(cfgPath, JSON.stringify(declaration(gate4Subject)));
  const stateDir = mkdtempSync(join(tmpdir(), "mica-s199-state-"));
  writeFileSync(join(stateDir, RETIRED_NAME), RETIRED_BODY);
  const svc = new MicaBridgeService({
    declarationsPath: cfgPath,
    socketDir,
    now: () => new Date("2026-10-17T00:00:00Z"),
    testBridgeGid: OWN_GID,
    stateDir,
  });
  await svc.start();
  asOperator(svc);
  return { svc, n: 0 };
}

/** One POST /subject-events through the REAL handler, as the operator. Returns the status and body it sent. */
async function post(r: Rig, subject: string, kind: string, payload: Record<string, string | number>): Promise<{ status: number; body: any }> {
  const identity = { subject, sessionId: "sess-1", actionId: `act-${++r.n}` };
  const body = { identity, kind, payload, eventHash: canonicalHash({ identity, kind, payload }) };
  const s = r.svc as any;
  let got: { status: number; body: any } | null = null;
  const orig = s.sendJson;
  s.sendJson = (_res: unknown, status: number, b: unknown) => {
    got = { status, body: b };
  };
  try {
    await s.handleSubjectEvents(OWN_UID, body, {});
  } finally {
    s.sendJson = orig;
  }
  if (got === null) throw new Error(`no answer to ${kind}`);
  return got;
}

const WRITER = `uid ${OWN_UID}`;
/** Five papers for (subject, tenure); returns their seqs in ORDER_PAPER_SEQ_FIELDS order. */
async function papers(r: Rig, subject: string, tenureRef: string): Promise<number[]> {
  const seqs: number[] = [];
  for (const kind of PAPERS) {
    const res = await post(r, subject, kind, { writer: WRITER, tenureRef, ref: `${kind.toLowerCase()} for ${tenureRef}` });
    assert(res.status === 200, `${kind}: ${JSON.stringify(res)}`);
    seqs.push(res.body.seq);
  }
  return seqs;
}
async function order(r: Rig, subject: string, tenureRef: string, cite: number[]): Promise<{ status: number; body: any }> {
  const p: Record<string, string | number> = { writer: WRITER, tenureRef, endingType: "TRANSFORMATION", arbiterWord: "fixture word" };
  ORDER_PAPER_SEQ_FIELDS.forEach((f, i) => (p[f] = cite[i]));
  return post(r, subject, "ENDING_ORDERED", p);
}
async function resolve(r: Rig, subject: string, orderSeq: number): Promise<void> {
  const res = await post(r, subject, "ARBITER_RESOLVED", {
    writer: WRITER,
    ordersRef: String(orderSeq),
    resolution: "ORDER_WITHDRAWN",
    arbiterWord: "fixture resolution",
    resolvedAt: "2026-10-17T00:00:00.000Z",
  });
  assert(res.status === 200, `resolve ${orderSeq}: ${JSON.stringify(res)}`);
}
async function book(r: Rig): Promise<any[]> {
  const s = r.svc as any;
  await s.eventBook.queue;
  return s.eventBook.readAll();
}

async function main(): Promise<void> {
  await check("S199-(a) · a SECOND order citing the FIRST order's papers -> 400 ORDER_CITATION_REFUSED, booked naming P; no instruction in the text", async () => {
    const r = await rig(A);
    try {
      const p1 = await papers(r, A, "t/1");
      const o1 = await order(r, A, "t/1", p1);
      assert(o1.status === 200, `the FIRST order (no order on the chain, no bound) is admitted: ${JSON.stringify(o1)}`);
      await resolve(r, A, o1.body.seq); // so ORDER_ALREADY_STANDING cannot answer instead
      const before = (await book(r)).length;
      const o2 = await order(r, A, "t/1", p1);
      assert(o2.status === 400 && o2.body.error === "ORDER_CITATION_REFUSED", JSON.stringify(o2));
      const want =
        `"payload.paperAuthorizationSeq" = ${p1[0]} was written at or before the chain's latest order (seq ${o1.body.seq}); ` +
        `Gate 4's leg B counts each paper for one order.`;
      assert(o2.body.detail === want, `detail\n      got  ${o2.body.detail}\n      want ${want}`);
      const events = (await book(r)).slice(before);
      const refused = events.filter((e) => e.kind === "ORDER_CITATION_REFUSED");
      assert(refused.length === 1, `exactly one booked refusal, got ${JSON.stringify(events)}`);
      const e = refused[0];
      assert(e.subject === A && e.field === "paperAuthorizationSeq" && e.cited === p1[0] && e.bound === o1.body.seq, JSON.stringify(e));
      assert(e.readerRule === GATE4_ORDER_BOUND_RULE && e.readerRule === "G4_ORDER_BOUND_V1", JSON.stringify(e));
      assert(e.detail === want, "the booked detail is the 400's");
      // nothing was appended to the subject chain for the refused order
      const chain = (r.svc as any).subjectLog.readAll();
      assert(chain.filter((x: any) => x.kind === "ENDING_ORDERED").length === 1, "the refused order reached the chain");
    } finally {
      await r.svc.stop();
    }
  });

  await check("S199-(b) · five papers written AFTER the first order -> the second order is accepted", async () => {
    const r = await rig(A);
    try {
      const o1 = await order(r, A, "t/1", await papers(r, A, "t/1"));
      assert(o1.status === 200, JSON.stringify(o1));
      await resolve(r, A, o1.body.seq);
      const p2 = await papers(r, A, "t/2");
      const o2 = await order(r, A, "t/2", p2);
      assert(o2.status === 200, JSON.stringify(o2));
      assert((await book(r)).every((e) => e.kind !== "ORDER_CITATION_REFUSED"), "an admitted order booked a refusal");
    } finally {
      await r.svc.stop();
    }
  });

  await check("S199-(c) · a paper at exactly P+1 -> accepted; the pure check refuses cited = P and admits P+1", async () => {
    const r = await rig(A);
    try {
      const o1 = await order(r, A, "t/1", await papers(r, A, "t/1"));
      assert(o1.status === 200, JSON.stringify(o1));
      const P = o1.body.seq as number;
      // the very next record on the chain is the new authorization paper
      const auth = await post(r, A, "ENDING_PAPER_AUTHORIZATION", { writer: WRITER, tenureRef: "t/2", ref: "auth t/2" });
      assert(auth.status === 200 && auth.body.seq === P + 1, `the paper is at P+1: ${JSON.stringify(auth)} P=${P}`);
      await resolve(r, A, P);
      const rest: number[] = [];
      for (const kind of PAPERS.slice(1)) {
        const res = await post(r, A, kind, { writer: WRITER, tenureRef: "t/2", ref: `${kind} t/2` });
        assert(res.status === 200, JSON.stringify(res));
        rest.push(res.body.seq);
      }
      const o2 = await order(r, A, "t/2", [auth.body.seq, ...rest]);
      assert(o2.status === 200, `P+1 is after the bound: ${JSON.stringify(o2)}`);
    } finally {
      await r.svc.stop();
    }
    // ⚠ cited = P cannot be reached through the route: seq P IS the order, and resolveOrderCitations refuses it
    //   first (wrong kind). The edge is therefore pinned on the pure check.
    const at = Object.fromEntries(ORDER_PAPER_SEQ_FIELDS.map((f) => [f, 20])) as Record<string, number>;
    const onP = orderCitationsAfterBound({ ...at, paperSuccessorSeq: 10 }, 10);
    assert(!onP.ok && onP.field === "paperSuccessorSeq" && onP.cited === 10 && onP.bound === 10, JSON.stringify(onP));
    assert(orderCitationsAfterBound({ ...at, paperSuccessorSeq: 11 }, 10).ok, "P+1 must be admitted");
    assert(orderCitationsAfterBound({ ...at, paperSuccessorSeq: 1 }, null).ok, "no bound: unchanged");
  });

  await check("S199-(d) · cond. 2 ALTERNATIVE: an UNDECLARED subject's order is not bounded and not refused; the DECLARED subject's order on the same chain is", async () => {
    // The served profile declares subject-a's ENDING_ORDERED only. subject-b's papers come first, then
    // subject-a's order; subject-b's order then cites papers written before subject-a's order.
    const r = await rig(A);
    try {
      const pb = await papers(r, B, "t/b");
      const pa = await papers(r, A, "t/a");
      const oa = await order(r, A, "t/a", pa);
      assert(oa.status === 200, JSON.stringify(oa));
      const before = (await book(r)).length;
      const ob = await order(r, B, "t/b", pb);
      assert(ob.status === 200, `an undeclared subject's order was bounded by another subject's P: ${JSON.stringify(ob)}`);
      const after = (await book(r)).slice(before);
      assert(after.every((e) => e.kind !== "ORDER_CITATION_REFUSED"), `an undeclared order booked a refusal: ${JSON.stringify(after)}`);
      const chain = (r.svc as any).subjectLog.readAll();
      assert(chain.some((x: any) => x.kind === "ENDING_ORDERED" && x.identity?.subject === B), "subject-b's order is on the chain");
      // ...and the DECLARED class is still bounded on this very chain: subject-a's second order citing its first
      // order's papers is refused by P = subject-a's order (subject-b's later order is no order to the reader).
      await resolve(r, A, oa.body.seq);
      const oa2 = await order(r, A, "t/a", pa);
      assert(oa2.status === 400 && oa2.body.error === "ORDER_CITATION_REFUSED", JSON.stringify(oa2));
      assert(String(oa2.body.detail).includes(`(seq ${oa.body.seq})`), `P is subject-a's order: ${oa2.body.detail}`);
      const refused = (await book(r)).filter((e) => e.kind === "ORDER_CITATION_REFUSED");
      assert(refused.length === 1 && refused[0].subject === A && refused[0].bound === oa.body.seq, JSON.stringify(refused));
    } finally {
      await r.svc.stop();
    }
  });

  await check("S199-(d') · a subject the served profile does NOT declare: its order is no order to the reader and does not move P", async () => {
    const r = await rig(A);
    try {
      const oa1 = await order(r, A, "t/a1", await papers(r, A, "t/a1"));
      assert(oa1.status === 200, JSON.stringify(oa1));
      await resolve(r, A, oa1.body.seq);
      const pa2 = await papers(r, A, "t/a2"); // after subject-a's first order
      const ob = await order(r, B, "t/b", await papers(r, B, "t/b")); // subject-b's order, LATER on the chain
      assert(ob.status === 200, JSON.stringify(ob));
      // subject-a's second order cites papers written BEFORE subject-b's order and AFTER its own first: the
      // reader's P is subject-a's first order (subject-b's class is not declared), so they count.
      const oa2 = await order(r, A, "t/a2", pa2);
      assert(oa2.status === 200, `an undeclared subject's order moved the bound: ${JSON.stringify(oa2)}`);
    } finally {
      await r.svc.stop();
    }
  });

  await check("S199-(e) · a SECOND declared invocation class counts (pure, two-class profile) — and the served builder declares ONE", async () => {
    const served = gate4SunsetConfigFor(declaration(A) as never);
    assert(served !== undefined && served.profile.warrantForm.invocation.length === 1, JSON.stringify(served?.profile.warrantForm.invocation));
    assert(JSON.stringify(served!.profile.warrantForm.invocation[0]) === JSON.stringify({ moduleId: A, eventType: "ENDING_ORDERED" }), "served class");
    const rec = (sequenceNumber: number, moduleId: string, eventType: string) => ({ sequenceNumber, timestamp: 0, moduleId, eventType, outcome: "x" });
    const chain = [rec(1, A, "ENDING_PAPER_AUTHORIZATION"), rec(2, A, "ENDING_ORDERED"), rec(3, A, "ENDING_PAPER_AUTHORIZATION"), rec(4, B, "ENDING_ORDERED"), rec(5, A, "ENDING_PAPER_AUTHORIZATION")];
    const ORD_A = { moduleId: A, eventType: "ENDING_ORDERED" };
    const ORD_B = { moduleId: B, eventType: "ENDING_ORDERED" };
    assert(gate4OrderBoundForWriter(chain, served, ORD_A) === 2, "served: subject-b's order is not an order");
    // cond. 2 alternative: the candidate's OWN class decides whether there is a bound at all.
    assert(gate4OrderBoundForWriter(chain, served, ORD_B) === null, "served: an undeclared candidate is not bounded");
    assert(gate4OrderBoundForWriter(chain, served, { moduleId: A, eventType: "ENDING_PAPER_AUTHORIZATION" }) === null, "a non-order candidate");
    const two = { ...served!, profile: { ...served!.profile, warrantForm: { ...served!.profile.warrantForm, invocation: [...served!.profile.warrantForm.invocation, { moduleId: B, eventType: "ENDING_ORDERED" }] } } };
    assert(gate4OrderBoundForWriter(chain, two, ORD_A) === 4, "two declared classes: the later class's order is the bound");
    assert(gate4OrderBoundForWriter(chain, two, ORD_B) === 4, "two declared classes: subject-b's order is bounded too");
    const cite = Object.fromEntries(ORDER_PAPER_SEQ_FIELDS.map((f) => [f, 3])) as Record<string, number>;
    assert(orderCitationsAfterBound(cite, gate4OrderBoundForWriter(chain, served, ORD_A)).ok, "3 > 2 under the served profile");
    assert(!orderCitationsAfterBound(cite, gate4OrderBoundForWriter(chain, two, ORD_A)).ok, "3 <= 4 under the two-class profile");
    // a record without the reader's fields cannot be an order and is not counted
    assert(gate4OrderBoundForWriter([{ subjectSeq: 9, kind: "ENDING_ORDERED" }], served, ORD_A) === null, "a record with no sequenceNumber/moduleId/eventType");
  });

  await check("S199-(f) · no gate4 reader declared -> no bound: the second order citing the first's papers is admitted, as before S199", async () => {
    assert(gate4SunsetConfigFor(declaration(null) as never) === undefined, "no readers.gate4Sunset -> no config");
    const r = await rig(null);
    try {
      const p1 = await papers(r, A, "t/1");
      const o1 = await order(r, A, "t/1", p1);
      assert(o1.status === 200, JSON.stringify(o1));
      await resolve(r, A, o1.body.seq);
      const o2 = await order(r, A, "t/1", p1);
      assert(o2.status === 200, `no reader, no bound: ${JSON.stringify(o2)}`);
    } finally {
      await r.svc.stop();
    }
  });

  console.log(`CENSUS: ${passed} passed, ${failed} failed, ${passed + failed} total`);
  if (failed > 0) process.exit(1);
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
