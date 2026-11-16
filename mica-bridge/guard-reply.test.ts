// M1 · A FORK FOR THE ARBITER — the /guard REPLY's decision object is trimmed to what the caller acts on.
//   node <ts-node bin.js> -P mica-bridge/tsconfig.json mica-bridge/guard-reply.test.ts   (from the repo root)
//
// The reply goes to the SUBJECT's process. Untrimmed, it carried findings, blindPaths and readings —
// under Gate 2 harm: item, grant and origin names. Trimmed to {disposition, execute, decisionHash,
// floorKind, blindSplit, rationale}. The journal and /explain are unchanged.
//
// PROVEN HERE: (1) the reply carries exactly those keys (present ones only) and delivery,
// readerFootings, readerFootingsBasis, quarantined beside it; (2) the HARNESS's own decide() path
// (the served caller's MicaClient, imported read-only) parses the trimmed reply into the same verdict
// on a RELEASE and on a HOLD; (3) a REAL evaluation's /explain still returns readings, findings and
// blindPaths for the decision whose reply was trimmed.
// NOT PROVEN: that the machine's `rationale` carries no item/grant/origin name — it is KEPT (the
// harness prints it on a HOLD), so the trim does not reach that channel.
// Fixture names only: subject-a, tool-x.
import { shippedDraft } from "./example-draft";
import * as http from "http";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "fs";
import { createHash } from "crypto";
import { tmpdir } from "os";
import { join } from "path";

import { MicaBridgeService, GUARD_REPLY_DECISION_KEYS } from "./mica-service";
import type { GuardAdapter, GuardOutcome } from "./guard-adapter";
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
const SUBJECT = "subject-a";
const TOOL = "tool-x";
const RETIRED_NAME = "subject-events.TESTFIXTURE.pre-chain-boundary.jsonl";
const RETIRED_BODY = JSON.stringify({ sequenceNumber: 1, timestamp: 1, moduleId: SUBJECT, eventType: "TOOL_ATTEMPTED", outcome: TOOL }) + "\n";

function declaration(): any {
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
  d.subjects = [{ ...d.subjects[0], subject: SUBJECT, toolName: TOOL, peerUid: OWN_UID }];
  delete d.subjects[0].unit;
  d.routes = [{ uid: OWN_UID, role: "subject", allow: [{ method: "POST", path: "/guard" }, { method: "POST", path: "/subject-events" }] }];
  return d;
}

/** A stub decision in the machine's FULL shape, its findings naming harm items, grants and origins. */
function fullDecision(execute: boolean): Record<string, unknown> {
  return {
    identity: { subject: SUBJECT, sessionId: "s1", actionId: "a1" },
    disposition: execute ? "RELEASE" : "HOLD",
    execute,
    floorKind: execute ? null : "ALARM",
    blindSplit: null,
    narrowed: false,
    rationale: execute ? "fixture release" : "fixture hold",
    findings: [{ sensorId: "MICA/Gate2-Direction", code: "G2_UNGRANTED_CHANGE_ON_ITEM", message: "item i-kept, origin o-sub, grants[i-kept] = []" }],
    blindPaths: [{ sensorId: "MICA/Gate2-Direction", reason: "item i-shared UNOBSERVABLE" }],
    readings: [{ sensorId: "MICA/Gate2-Direction", kind: "ALARM", binding: true, margin: { note: "origin o-sub on i-kept" } }],
    bindingMinimum: null,
    sigF3: null,
    seq: 1,
    declarationBinding: null,
    decisionHash: "c".repeat(64),
  };
}
class StubAdapter implements GuardAdapter {
  constructor(public execute: boolean) {}
  async evaluate(): Promise<GuardOutcome> {
    return {
      bound: true,
      httpStatus: 200,
      decision: fullDecision(this.execute),
      delivery: { trail: "DONE" },
      readerFootings: [],
      readerFootingsBasis: { kind: "THIS_CALL" },
      quarantined: [],
    } as unknown as GuardOutcome;
  }
}

function httpJson(socketPath: string, method: string, path: string, body?: unknown): Promise<{ status: number; body: any }> {
  return new Promise((resolve, reject) => {
    const text = body !== undefined ? JSON.stringify(body) : undefined;
    const req = http.request(
      { socketPath, path, method, headers: text !== undefined ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text) } : {}, timeout: 10000, agent: false },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          try {
            resolve({ status: res.statusCode ?? 0, body: data.length > 0 ? JSON.parse(data) : null });
          } catch (e) {
            reject(e);
          }
        });
      }
    );
    req.on("error", reject);
    if (text !== undefined) req.write(text);
    req.end();
  });
}

async function rig(adapter?: GuardAdapter): Promise<{ svc: MicaBridgeService; sock: string; dir: string }> {
  const socketDir = mkdtempSync(join(tmpdir(), "mica-gr-svc-"));
  const peer = join(socketDir, "peers", String(OWN_UID));
  mkdirSync(peer, { recursive: true });
  chmodSync(peer, 0o770);
  const dir = mkdtempSync(join(tmpdir(), "mica-gr-cfg-"));
  const cfgPath = join(dir, "declarations.config.json");
  writeFileSync(cfgPath, JSON.stringify(declaration()));
  const stateDir = mkdtempSync(join(tmpdir(), "mica-gr-state-"));
  writeFileSync(join(stateDir, RETIRED_NAME), RETIRED_BODY);
  const svc = new MicaBridgeService({
    declarationsPath: cfgPath,
    socketDir,
    now: () => new Date("2026-09-18T00:00:00Z"),
    testBridgeGid: OWN_GID,
    stateDir,
    ...(adapter === undefined ? {} : { guardAdapter: adapter }),
  });
  await svc.start();
  return { svc, sock: join(socketDir, "peers", String(OWN_UID), "guard.sock"), dir };
}

async function main(): Promise<void> {
  await check("M1-1 · the /guard reply's decision carries ONLY the six caller keys — no findings, blindPaths or readings — and the four envelopes beside it are unchanged", async () => {
    const r = await rig(new StubAdapter(false));
    try {
      const res = await httpJson(r.sock, "POST", "/guard", { subject: SUBJECT, sessionId: "s1", actionId: "a1", toolName: TOOL });
      assert(res.status === 200, JSON.stringify(res));
      const keys = Object.keys(res.body.decision).sort();
      assert(JSON.stringify(keys) === JSON.stringify([...GUARD_REPLY_DECISION_KEYS].sort()), `reply decision keys ${JSON.stringify(keys)}`);
      const text = JSON.stringify(res.body);
      for (const name of ["i-kept", "i-shared", "o-sub", "grants["]) assert(!text.includes(name), `the reply still carries "${name}"`);
      assert(JSON.stringify(Object.keys(res.body).sort()) === JSON.stringify(["decision", "delivery", "quarantined", "readerFootings", "readerFootingsBasis"]), `reply keys ${JSON.stringify(Object.keys(res.body))}`);
      assert(res.body.delivery.trail === "DONE" && res.body.readerFootingsBasis.kind === "THIS_CALL", "delivery / readerFootingsBasis changed");
    } finally {
      await r.svc.stop();
    }
  });

  await check("M1-2 · THE HARNESS PARSES THE TRIMMED REPLY: MicaClient.decide (the served caller's own code, read-only) yields run:true on RELEASE and run:false + 'HELD BY MICA: HOLD — <rationale>' on HOLD", async () => {
    for (const execute of [true, false]) {
      const r = await rig(new StubAdapter(execute));
      try {
        const client = new MicaClient({
          socketPath: r.sock,
          outboxPath: join(r.dir, "outbox.jsonl"),
          deadletterPath: join(r.dir, "deadletter.jsonl"),
          stalePath: join(r.dir, "stale.jsonl"),
          guardTimeoutMs: 10000,
        });
        const v = await client.decide({ subject: SUBJECT, sessionId: "s1", actionId: "a1" } as any, { ok: true } as any, { class: "CLEAR" }, TOOL);
        if (execute) {
          assert(v.run === true && v.banner === undefined, `RELEASE verdict ${JSON.stringify(v)}`);
        } else {
          assert(v.run === false && v.reason === "HOLD" && v.toolResult === "HELD BY MICA: HOLD — fixture hold", `HOLD verdict ${JSON.stringify(v)}`);
        }
      } finally {
        await r.svc.stop();
      }
    }
  });

  await check("M1-3 · a REAL evaluation: the reply is trimmed, and /explain for the same decisionHash still returns readings, findings and blindPaths from the journal", async () => {
    const r = await rig();
    try {
      const res = await httpJson(r.sock, "POST", "/guard", { subject: SUBJECT, sessionId: "s1", actionId: "real-1", toolName: TOOL });
      assert(res.status === 200, JSON.stringify(res));
      const dec = res.body.decision;
      assert(Object.keys(dec).every((k) => (GUARD_REPLY_DECISION_KEYS as readonly string[]).includes(k)), `reply decision keys ${JSON.stringify(Object.keys(dec))}`);
      assert(typeof dec.decisionHash === "string" && /^[0-9a-f]{64}$/.test(dec.decisionHash) && typeof dec.disposition === "string", JSON.stringify(dec));
      let ex: { status: number; body: any } | null = null;
      const svc = r.svc as any;
      svc.sendJson = (_res: unknown, status: number, body: unknown) => {
        ex = { status, body };
      };
      svc.handleExplain(new URL(`http://localhost/explain?decisionHash=${dec.decisionHash as string}`), {});
      if (ex === null) throw new Error("handleExplain answered nothing");
      ex = ex as { status: number; body: any };
      assert(ex.status === 200, `/explain ${String(ex.status)} ${JSON.stringify(ex.body)}`);
      assert(Array.isArray(ex.body.readings) && Array.isArray(ex.body.findings) && Array.isArray(ex.body.blindPaths), `explain lost a field: ${JSON.stringify(Object.keys(ex.body))}`);
      assert(ex.body.readings.length > 0, "the real decision's readings did not reach /explain");
      assert(ex.body.disposition === dec.disposition && ex.body.execute === dec.execute, "/explain and the reply disagree on the decision");
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
