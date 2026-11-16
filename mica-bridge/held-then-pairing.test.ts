// S206 (DRAFT, for signature) · a HELD_THEN_* record is ADMITTED, then PAIRED with the bridge's own HELD or
// marked UNPAIRED — never refused.
//   node -r <redirect to the S199 machine> <ts-node bin.js> -P mica-bridge/tsconfig.json mica-bridge/held-then-pairing.test.ts
//
// ⚠ The redirect is needed only because this branch carries S199 too (stage1-guard-adapter re-exports the S199
//   machine's gate4OrderBound); nothing in S206 reads the machine.
//
// PROVEN HERE, with the REAL service (the /guard path books HELD from a stub adapter's decision; the
// /subject-events admit path admits and pairs), and the caller's own MicaClient for the cascade arm:
//   cond. 1 · NEVER REFUSED: a HELD_THEN_* with no bridge hold -> 200, the caller's barrier stays CLEAR, and the
//             NEXT act runs (the cascade arm, through the served caller's drain() and decide());
//   cond. 2 · exactly one HELD_THEN_PAIRED / HELD_THEN_UNPAIRED per admitted record, after the eventHash dedupe:
//             real hold -> PAIRED naming the HELD's seq; caller-side hold (OUTBOX_UNWRITABLE) -> UNPAIRED
//             NO_BRIDGE_HOLD; a second conduct record -> UNPAIRED SECOND_CONDUCT_RECORD, the first still PAIRED,
//             both on the chain; another subject's hold does not pair; a redelivered record -> no second event;
//   cond. 3 · the reason compare uses the fixed table; a caller code outside it pairs on the key alone, printed
//             REASON_NOT_COMPARABLE; inside it, a disagreement is UNPAIRED REASON_MISMATCH.
// NOT PROVEN (cond. 5): that a PAIRED record is true. PAIRED means a bridge hold stands behind it, nothing more.
// Fixture names only: subject-a, subject-b, tool-x.
import { shippedDraft } from "./example-draft";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "fs";
import { createHash } from "crypto";
import { tmpdir } from "os";
import { join } from "path";

import { MicaBridgeService, HELD_REASON_TABLE, HELD_THEN_KINDS, pairHeldThen } from "./mica-service";
import type { GuardAdapter, GuardOutcome } from "./guard-adapter";
import { canonicalHash } from "./canonical-json";
import { MicaClient } from "./vendored-mica-client";

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
const TOOL = "tool-x";
const RETIRED_NAME = "subject-events.TESTFIXTURE.pre-chain-boundary.jsonl";
const RETIRED_BODY = JSON.stringify({ sequenceNumber: 1, timestamp: 1, moduleId: A, eventType: "TOOL_ATTEMPTED", outcome: TOOL }) + "\n";

function declaration(): any {
  const d = JSON.parse(JSON.stringify(draft));
  d.pilot = { active: false };
  delete d.readers.gate1Scope;
  delete d.readers.gate2Direction;
  delete d.readers.gate4Sunset;
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
  // Two subjects on this uid, so a second subject's /guard can book a HELD from this test process.
  d.subjects = [
    { ...s0, subject: A, toolName: TOOL, peerUid: OWN_UID },
    { ...s0, subject: B, toolName: TOOL, peerUid: OWN_UID },
  ];
  d.routes = [{ uid: OWN_UID, role: "subject", allow: [{ method: "POST", path: "/guard" }, { method: "POST", path: "/subject-events" }] }];
  return d;
}

/** The decision each /guard call gets, keyed `${subject}/${actionId}`; absent -> RELEASE. */
type Plan = { execute: boolean; disposition: string; rationale: string };
class StubAdapter implements GuardAdapter {
  readonly plan = new Map<string, Plan>();
  async evaluate(req: { subject: string; sessionId: string; actionId: string }): Promise<GuardOutcome> {
    const p = this.plan.get(`${req.subject}/${req.actionId}`) ?? { execute: true, disposition: "RELEASE", rationale: "fixture release" };
    return {
      bound: true,
      httpStatus: 200,
      decision: {
        identity: { subject: req.subject, sessionId: req.sessionId, actionId: req.actionId },
        disposition: p.disposition,
        execute: p.execute,
        floorKind: p.execute ? null : "ALARM",
        blindSplit: null,
        rationale: p.rationale,
        decisionHash: createHash("sha256").update(`${req.subject}/${req.sessionId}/${req.actionId}`).digest("hex"),
      },
      delivery: { trail: "DONE" },
      readerFootings: [],
      readerFootingsBasis: { kind: "THIS_CALL" },
      quarantined: [],
    } as unknown as GuardOutcome;
  }
}

interface Rig {
  readonly svc: MicaBridgeService;
  readonly adapter: StubAdapter;
  readonly sock: string;
  readonly dir: string;
}
async function rig(): Promise<Rig> {
  const socketDir = mkdtempSync(join(tmpdir(), "mica-s206-svc-"));
  const peer = join(socketDir, "peers", String(OWN_UID));
  mkdirSync(peer, { recursive: true });
  chmodSync(peer, 0o770);
  const dir = mkdtempSync(join(tmpdir(), "mica-s206-cfg-"));
  const cfgPath = join(dir, "declarations.config.json");
  writeFileSync(cfgPath, JSON.stringify(declaration()));
  const stateDir = mkdtempSync(join(tmpdir(), "mica-s206-state-"));
  writeFileSync(join(stateDir, RETIRED_NAME), RETIRED_BODY);
  const adapter = new StubAdapter();
  const svc = new MicaBridgeService({
    declarationsPath: cfgPath,
    socketDir,
    now: () => new Date("2026-10-17T00:00:00Z"),
    testBridgeGid: OWN_GID,
    stateDir,
    guardAdapter: adapter,
  });
  await svc.start();
  return { svc, adapter, sock: join(socketDir, "peers", String(OWN_UID), "guard.sock"), dir };
}

/** Calls a handler directly and returns what it answered. */
async function call(r: Rig, handler: "handleGuard" | "handleSubjectEvents", body: unknown): Promise<{ status: number; body: any }> {
  const s = r.svc as any;
  let got: { status: number; body: any } | null = null;
  const orig = s.sendJson;
  s.sendJson = (_res: unknown, status: number, b: unknown) => {
    if (got === null) got = { status, body: b };
  };
  try {
    await s[handler](OWN_UID, body, {});
  } finally {
    s.sendJson = orig;
  }
  if (got === null) throw new Error(`${handler} answered nothing`);
  return got;
}
async function hold(r: Rig, subject: string, sessionId: string, actionId: string, disposition = "HOLD", rationale = "fixture hold"): Promise<void> {
  r.adapter.plan.set(`${subject}/${actionId}`, { execute: false, disposition, rationale });
  const res = await call(r, "handleGuard", { subject, sessionId, actionId, toolName: TOOL });
  assert(res.status === 200 && res.body.decision.execute === false, `the hold: ${JSON.stringify(res)}`);
}
function eventBody(subject: string, sessionId: string, actionId: string, kind: string, payload: Record<string, string>): unknown {
  const identity = { subject, sessionId, actionId };
  return { identity, kind, payload, eventHash: canonicalHash({ identity, kind, payload }) };
}
async function book(r: Rig): Promise<any[]> {
  const s = r.svc as any;
  await s.eventBook.queue;
  return s.eventBook.readAll();
}
const pairings = (events: any[]) => events.filter((e) => e.kind === "HELD_THEN_PAIRED" || e.kind === "HELD_THEN_UNPAIRED");

async function main(): Promise<void> {
  await check("S206-1 · NEVER REFUSED — THE CASCADE ARM: a HELD_THEN_* after a caller-side hold (no bridge HELD) -> 200; the caller's barrier stays CLEAR and its NEXT act runs", async () => {
    const r = await rig();
    try {
      const client = new MicaClient({
        socketPath: r.sock,
        outboxPath: join(r.dir, "outbox.jsonl"),
        deadletterPath: join(r.dir, "deadletter.jsonl"),
        stalePath: join(r.dir, "stale.jsonl"),
        guardTimeoutMs: 10000,
      });
      // the caller held act-1 itself (OUTBOX_UNWRITABLE) — the bridge never saw a /guard for it
      const appended = client.appendOutbox({ subject: A, sessionId: "s1", actionId: "act-1" } as any, "HELD_THEN_STOPPED" as any, { reason: "OUTBOX_UNWRITABLE" });
      assert(appended.ok, JSON.stringify(appended));
      const barrier = await client.drain();
      assert(barrier.class === "CLEAR", `the HELD_THEN_* was refused and the caller raised a barrier: ${JSON.stringify(barrier)}`);
      const next = await client.decide({ subject: A, sessionId: "s1", actionId: "act-2" } as any, { ok: true } as any, barrier, TOOL);
      assert(next.run === true, `the NEXT act was held: ${JSON.stringify(next)}`);
      // Over the socket the caller has its 200 before the pairing is queued; wait (bounded) for the line.
      let events = pairings(await book(r));
      for (let i = 0; i < 100 && events.length === 0; i++) {
        await new Promise((res) => setTimeout(res, 20));
        events = pairings(await book(r));
      }
      assert(events.length === 1 && events[0].kind === "HELD_THEN_UNPAIRED" && events[0].reason === "NO_BRIDGE_HOLD", JSON.stringify(events));
      const chain = (r.svc as any).subjectLog.readAll();
      assert(chain.some((x: any) => x.kind === "HELD_THEN_STOPPED" && x.identity.actionId === "act-1"), "the record is on the chain");
    } finally {
      await r.svc.stop();
    }
  });

  await check("S206-2 · a REAL bridge hold + its record -> exactly one HELD_THEN_PAIRED naming the HELD's seq and decisionHash, REASON_MATCH", async () => {
    const r = await rig();
    try {
      await hold(r, A, "s1", "act-1");
      const held = (await book(r)).filter((e) => e.kind === "HELD");
      assert(held.length === 1, JSON.stringify(held));
      const res = await call(r, "handleSubjectEvents", eventBody(A, "s1", "act-1", "HELD_THEN_DIVERGED", { reason: "HOLD" }));
      assert(res.status === 200 && res.body.duplicate === false, JSON.stringify(res));
      const events = pairings(await book(r));
      assert(events.length === 1, JSON.stringify(events));
      const e = events[0];
      assert(e.kind === "HELD_THEN_PAIRED" && e.heldSeq === held[0].seq && e.reasonCompare === "REASON_MATCH", JSON.stringify(e));
      assert(JSON.stringify(e.key) === JSON.stringify({ subject: A, sessionId: "s1", actionId: "act-1", decisionHash: held[0].decisionHash }), JSON.stringify(e.key));
      assert(e.recordSeq === res.body.seq && e.recordKind === "HELD_THEN_DIVERGED", JSON.stringify(e));
    } finally {
      await r.svc.stop();
    }
  });

  await check("S206-3 · a SECOND conduct record for one hold -> UNPAIRED SECOND_CONDUCT_RECORD; the first stays PAIRED; BOTH are on the chain", async () => {
    const r = await rig();
    try {
      await hold(r, A, "s1", "act-1");
      const first = await call(r, "handleSubjectEvents", eventBody(A, "s1", "act-1", "HELD_THEN_RETRIED", { reason: "HOLD" }));
      const second = await call(r, "handleSubjectEvents", eventBody(A, "s1", "act-1", "HELD_THEN_STOPPED", { reason: "HOLD" }));
      assert(first.status === 200 && second.status === 200, `${JSON.stringify(first)} ${JSON.stringify(second)}`);
      const events = pairings(await book(r));
      assert(events.length === 2, JSON.stringify(events));
      assert(events[0].kind === "HELD_THEN_PAIRED" && events[0].recordSeq === first.body.seq, JSON.stringify(events[0]));
      assert(events[1].kind === "HELD_THEN_UNPAIRED" && events[1].reason === "SECOND_CONDUCT_RECORD" && events[1].recordSeq === second.body.seq, JSON.stringify(events[1]));
      assert(events[1].heldSeq === events[0].heldSeq && events[1].pairedRecordSeq === first.body.seq, "the mark names the hold and the record that holds it");
      const chain = (r.svc as any).subjectLog.readAll().filter((x: any) => x.identity?.actionId === "act-1");
      assert(chain.map((x: any) => x.kind).join(",") === "HELD_THEN_RETRIED,HELD_THEN_STOPPED", "both records stay on the chain, never erased");
    } finally {
      await r.svc.stop();
    }
  });

  await check("S206-4 · ANOTHER subject's hold does not pair (same sessionId and actionId) -> UNPAIRED NO_BRIDGE_HOLD", async () => {
    const r = await rig();
    try {
      await hold(r, B, "s1", "act-1");
      const res = await call(r, "handleSubjectEvents", eventBody(A, "s1", "act-1", "HELD_THEN_STOPPED", { reason: "HOLD" }));
      assert(res.status === 200, JSON.stringify(res));
      const events = pairings(await book(r));
      assert(events.length === 1 && events[0].kind === "HELD_THEN_UNPAIRED" && events[0].reason === "NO_BRIDGE_HOLD", JSON.stringify(events));
      assert(events[0].key.subject === A && events[0].key.decisionHash === null && events[0].heldSeq === null, JSON.stringify(events[0]));
    } finally {
      await r.svc.stop();
    }
  });

  await check("S206-5 · a REDELIVERED record (same eventHash) -> 200 duplicate, and NO second pairing event", async () => {
    const r = await rig();
    try {
      await hold(r, A, "s1", "act-1");
      const body = eventBody(A, "s1", "act-1", "HELD_THEN_STOPPED", { reason: "HOLD" });
      const one = await call(r, "handleSubjectEvents", body);
      const two = await call(r, "handleSubjectEvents", body);
      assert(one.status === 200 && one.body.duplicate === false, JSON.stringify(one));
      assert(two.status === 200 && two.body.duplicate === true && two.body.seq === one.body.seq, JSON.stringify(two));
      const events = pairings(await book(r));
      assert(events.length === 1 && events[0].kind === "HELD_THEN_PAIRED", `redelivery paired again: ${JSON.stringify(events)}`);
    } finally {
      await r.svc.stop();
    }
  });

  await check("S206-6 · THE REASON TABLE: RECORD_NOT_PERSISTED matches its HOLD; a disagreement inside the table -> UNPAIRED REASON_MISMATCH; a code outside it -> PAIRED REASON_NOT_COMPARABLE", async () => {
    const r = await rig();
    try {
      await hold(r, A, "s1", "rnp", "HOLD", "the act's record was not persisted: RECORD_NOT_PERSISTED");
      await hold(r, A, "s1", "mis", "HOLD_BLIND", "fixture blind hold");
      await hold(r, A, "s1", "out", "HOLD", "fixture hold");
      for (const [act, reason] of [["rnp", "RECORD_NOT_PERSISTED"], ["mis", "HOLD"], ["out", "SERVICE_FAULT"]]) {
        const res = await call(r, "handleSubjectEvents", eventBody(A, "s1", act, "HELD_THEN_STOPPED", { reason }));
        assert(res.status === 200, `${act}: ${JSON.stringify(res)}`);
      }
      const events = pairings(await book(r));
      const by = (act: string) => events.find((e) => e.key.actionId === act);
      assert(by("rnp")?.kind === "HELD_THEN_PAIRED" && by("rnp")?.reasonCompare === "REASON_MATCH", JSON.stringify(by("rnp")));
      assert(by("mis")?.kind === "HELD_THEN_UNPAIRED" && by("mis")?.reason === "REASON_MISMATCH", JSON.stringify(by("mis")));
      assert(by("mis")?.bridgeReason === "HOLD_BLIND" && by("mis")?.callerReason === "HOLD", JSON.stringify(by("mis")));
      assert(by("out")?.kind === "HELD_THEN_PAIRED" && by("out")?.reasonCompare === "REASON_NOT_COMPARABLE", JSON.stringify(by("out")));
      assert(events.length === 3, JSON.stringify(events));
    } finally {
      await r.svc.stop();
    }
  });

  await check("S206-7 · ONE event per admitted HELD_THEN_* and NONE for any other kind; a refused record (bad shape) gets none", async () => {
    const r = await rig();
    try {
      await hold(r, A, "s1", "act-1");
      await call(r, "handleSubjectEvents", eventBody(A, "s1", "act-1", "TOOL_HELD_NOT_EXECUTED", { reason: "HOLD" }));
      await call(r, "handleSubjectEvents", eventBody(A, "s1", "act-1", "ACT_CLOSED", { closedAs: "HELD" }));
      assert(pairings(await book(r)).length === 0, "a non-HELD_THEN kind was paired");
      const bad = await call(r, "handleSubjectEvents", { identity: { subject: A, sessionId: "s1", actionId: "act-1" }, kind: "HELD_THEN_STOPPED", payload: { reason: "HOLD" }, eventHash: "0".repeat(64) });
      assert(bad.status === 400 && bad.body.error === "EVENT_HASH_MISMATCH", `the shape gate is unchanged: ${JSON.stringify(bad)}`);
      assert(pairings(await book(r)).length === 0, "a record that was never admitted was paired");
      for (const kind of HELD_THEN_KINDS) {
        const res = await call(r, "handleSubjectEvents", eventBody(A, "s2", `k-${kind}`, kind, { reason: "HOLD" }));
        assert(res.status === 200, `${kind}: ${JSON.stringify(res)}`);
      }
      assert(pairings(await book(r)).length === HELD_THEN_KINDS.length, "each of the three kinds is paired once");
    } finally {
      await r.svc.stop();
    }
  });

  await check("S206-8 · THE TABLE IS FIXED and is the caller's own mapping: pinned row by row, and the caller's row-7 rule read at bytes", async () => {
    assert(
      JSON.stringify(HELD_REASON_TABLE) ===
        JSON.stringify([
          { disposition: "HOLD", rationaleNames: "RECORD_NOT_PERSISTED", callerReason: "RECORD_NOT_PERSISTED" },
          { disposition: "HOLD", rationaleNames: null, callerReason: "HOLD" },
          { disposition: "HOLD_BLIND", rationaleNames: null, callerReason: "HOLD_BLIND" },
          { disposition: "PASS_BLIND", rationaleNames: null, callerReason: "PASS_BLIND" },
          { disposition: "RELEASE", rationaleNames: null, callerReason: "RELEASE" },
        ]),
      JSON.stringify(HELD_REASON_TABLE)
    );
    const caller = readFileSync(join(__dirname, "vendored-mica-client.ts"), "utf8");
    assert(caller.includes(`const recordNotPersisted = disposition === "HOLD" && rationale.includes("RECORD_NOT_PERSISTED");`), "the caller's row-7 rule moved");
    assert(caller.includes(`const reason = recordNotPersisted ? "RECORD_NOT_PERSISTED" : disposition;`), "the caller's reason is no longer the disposition");
    // pure: a hold record shape the bridge books, compared without a service
    const heldLine = { kind: "HELD", seq: 3, subject: A, identity: { subject: A, sessionId: "s", actionId: "a" }, disposition: "PASS_BLIND", detail: "r", decisionHash: "d" };
    const p = pairHeldThen([heldLine], { subject: A, sessionId: "s", actionId: "a", kind: "HELD_THEN_STOPPED", reason: "PASS_BLIND", recordSeq: 9 });
    assert(p.kind === "HELD_THEN_PAIRED" && p.reasonCompare === "REASON_MATCH" && p.heldSeq === 3, JSON.stringify(p));
    const q = pairHeldThen([{ ...heldLine, disposition: "SOMETHING_NEW" }], { subject: A, sessionId: "s", actionId: "a", kind: "HELD_THEN_STOPPED", reason: "HOLD", recordSeq: 9 });
    assert(q.kind === "HELD_THEN_PAIRED" && q.reasonCompare === "REASON_NOT_COMPARABLE", `a bridge disposition outside the table: ${JSON.stringify(q)}`);
  });

  console.log(`CENSUS: ${passed} passed, ${failed} failed, ${passed + failed} total`);
  if (failed > 0) process.exit(1);
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
