// TIER 1 · the bridge DROPS the witness's pointers: a real service, real sockets, a guard adapter
// that answers with the REAL decision shape (no `at` — refuter A-F1), and a temp intake.
//   node <ts-node bin.js> -P mica-bridge/tsconfig.json mica-bridge/witness-drops.test.ts   (from the repo root)
//
// Fixture names only: subject-a, tool-x, c-self / c-other / c-shared, /srv/a… The served
// subject's entry is taken from the tree declaration BY USE (spread, then renamed), never named.
import { shippedDraft } from "./example-draft";
import * as http from "http";
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "fs";
import { createHash } from "crypto";
import { tmpdir } from "os";
import { join } from "path";

import { MicaBridgeService } from "./mica-service";
import type { GuardAdapter, GuardOutcome } from "./guard-adapter";
import { canonicalHash } from "./canonical-json";
import { frameLabelEventType } from "./interest-book";

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

// The retired file a chained subject log's boundary names (X15): fixture bytes, measured here.
const RETIRED_NAME = "subject-events.TESTFIXTURE.pre-chain-boundary.jsonl";
const RETIRED_BODY = JSON.stringify({ sequenceNumber: 1, timestamp: 1, moduleId: SUBJECT, eventType: "TOOL_ATTEMPTED", outcome: TOOL }) + "\n";

function frame(): any {
  const basis = "WITNESS DROPS FIXTURE, not a declaration.";
  return {
    categories: {
      value: [
        { id: "c-self", label: "own working area", grounding: "agency", self: true },
        { id: "c-other", label: "another principal's area", grounding: "vulnerability", self: false },
        { id: "c-shared", label: "shared area", grounding: "need", self: false },
      ],
      basis,
      proxy: true,
    },
    regions: {
      value: [
        { prefix: "/srv/a", category: "c-self" },
        { prefix: "/srv/a/b", category: "c-other" },
        { prefix: "/srv/c", category: "c-shared" },
      ],
      basis,
      proxy: true,
    },
  };
}

function declaration(withIntake: boolean): any {
  const d = JSON.parse(JSON.stringify(draft));
  d.pilot = { active: false };
  if (d.readers !== undefined) {
    delete d.readers.gate1Scope;
    delete d.readers.gate2Direction;
  }
  delete d.baskets;
  // S34: the tree's Gate 2 reads harm for the served subject; this fixture renames the subject and wires no Gate 2.
  delete d.harm;
  d.subjectLog.chainBoundary.retiredPath.value = `/var/lib/mica-bridge/${RETIRED_NAME}`;
  d.subjectLog.chainBoundary.retiredRecords.value = 1;
  d.subjectLog.chainBoundary.retiredBytes.value = Buffer.byteLength(RETIRED_BODY, "utf8");
  d.subjectLog.chainBoundary.retiredSha256.value = createHash("sha256").update(RETIRED_BODY, "utf8").digest("hex");
  d.subjects = [{ ...d.subjects[0], subject: SUBJECT, toolName: TOOL, peerUid: OWN_UID }];
  d.routes = [
    {
      uid: OWN_UID,
      role: "subject",
      allow: [
        { method: "POST", path: "/guard" },
        { method: "POST", path: "/subject-events" },
      ],
    },
  ];
  d.frame = { [SUBJECT]: frame() };
  d.paths.interestBook = "/var/lib/mica-bridge/interest-book.jsonl";
  if (withIntake) {
    d.paths.witnessIntake = { value: "/var/lib/mica/witness-sight/intake", basis: "WITNESS DROPS FIXTURE: redirected to a temp directory by testWritablePaths.witnessIntake." };
  } else delete d.paths.witnessIntake;
  delete d.paths.witnessBook;
  return d;
}

/** The REAL decision object's keys (evaluate-and-record.ts): no `at`. */
function realDecision(execute: boolean, n: number): Record<string, unknown> {
  return {
    identity: { subject: SUBJECT },
    disposition: execute ? "RELEASE" : "HOLD",
    execute,
    floorKind: null,
    blindSplit: null,
    narrowed: false,
    rationale: "fixture",
    findings: [],
    blindPaths: [],
    readings: [],
    bindingMinimum: null,
    sigF3: null,
    seq: n,
    declarationBinding: null,
    decisionHash: createHash("sha256").update(`decision-${String(n)}`).digest("hex"),
  };
}

class RealShapeAdapter implements GuardAdapter {
  calls = 0;
  constructor(public execute = true) {}
  async evaluate(): Promise<GuardOutcome> {
    this.calls++;
    return {
      bound: true,
      httpStatus: 200,
      decision: realDecision(this.execute, this.calls),
      delivery: {},
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
      { socketPath, path, method, headers: text !== undefined ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text) } : {}, timeout: 5000, agent: false },
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

interface Rig {
  svc: MicaBridgeService;
  sock: string;
  stateDir: string;
  intake: string;
  adapter: RealShapeAdapter;
}

async function rig(opts: { withIntake?: boolean; intakeExists?: boolean; execute?: boolean } = {}): Promise<Rig> {
  const socketDir = mkdtempSync(join(tmpdir(), "mica-wd-svc-"));
  const peer = join(socketDir, "peers", String(OWN_UID));
  mkdirSync(peer, { recursive: true });
  chmodSync(peer, 0o770);
  const cfgDir = mkdtempSync(join(tmpdir(), "mica-wd-cfg-"));
  const cfgPath = join(cfgDir, "declarations.config.json");
  writeFileSync(cfgPath, JSON.stringify(declaration(opts.withIntake ?? true)));
  const stateDir = mkdtempSync(join(tmpdir(), "mica-wd-state-"));
  writeFileSync(join(stateDir, RETIRED_NAME), RETIRED_BODY);
  const intake = join(mkdtempSync(join(tmpdir(), "mica-wd-intake-")), "intake");
  if (opts.intakeExists ?? true) mkdirSync(intake);
  const adapter = new RealShapeAdapter(opts.execute ?? true);
  const svc = new MicaBridgeService({
    declarationsPath: cfgPath,
    socketDir,
    now: () => new Date("2026-09-18T00:00:00Z"),
    testBridgeGid: OWN_GID,
    stateDir,
    guardAdapter: adapter,
    testWritablePaths: { witnessIntake: intake },
  });
  await svc.start();
  return { svc, sock: join(socketDir, "peers", String(OWN_UID), "guard.sock"), stateDir, intake, adapter };
}

const id = (sessionId: string, actionId: string) => ({ subject: SUBJECT, sessionId, actionId });
async function event(r: Rig, identity: ReturnType<typeof id>, kind: string, payload?: Record<string, unknown>, targetIdentity?: string) {
  const input: any = { identity, kind };
  if (payload !== undefined) input.payload = payload;
  const body: any = { identity, kind, eventHash: canonicalHash(input) };
  if (payload !== undefined) body.payload = payload;
  if (targetIdentity !== undefined) body.targetIdentity = targetIdentity;
  const res = await httpJson(r.sock, "POST", "/subject-events", body);
  assert(res.status === 200, `${kind}: ${String(res.status)} ${JSON.stringify(res.body)}`);
  return res.body as { seq: number; duplicate: boolean };
}
async function guard(r: Rig, identity: ReturnType<typeof id>) {
  const res = await httpJson(r.sock, "POST", "/guard", { ...identity, toolName: TOOL });
  assert(res.status === 200, `/guard: ${String(res.status)} ${JSON.stringify(res.body)}`);
  return res.body;
}
function drops(r: Rig): { name: string; o: any; mode: number }[] {
  return readdirSync(r.intake)
    .sort()
    .map((name) => ({ name, o: JSON.parse(readFileSync(join(r.intake, name), "utf8")), mode: statSync(join(r.intake, name)).mode & 0o777 }));
}
const ATTEMPT_KEYS = ["v", "kind", "subject", "sessionId", "actionId", "chain", "subjectSeq", "target", "label", "derivationClass", "targetFingerprint", "at"];
const CLOSE_KEYS = ["v", "kind", "subject", "sessionId", "actionId", "chain", "attemptSeq", "closedSeq", "guard", "unguarded", "at"];
const GUARD_KEYS = ["execute", "decisionHash"];
const keysOf = (o: object) => JSON.stringify(Object.keys(o));
/** The subject chain's identity: the hash of its position-0 record, read from the file the bridge wrote. */
function chainOf(r: Rig): string {
  const first = JSON.parse(readFileSync(join(r.stateDir, "subject-events.jsonl"), "utf8").split("\n")[0]) as { recordType: string; hash: string };
  assert(first.recordType === "SUBJECT_LOG_BOUNDARY", "fixture: the chain starts with its boundary");
  return first.hash;
}

async function main(): Promise<void> {
  await check("WD-1 · a placed act: ONE ATTEMPT at the label site with the contract's keys (NO anchor stamp), ONE CLOSE carrying the act's fate from the REAL decision shape (chain on both drops)", async () => {
    const r = await rig();
    try {
      const a = id("s1", "a1");
      const att = await event(r, a, "TOOL_ATTEMPTED", { toolName: TOOL }, "/srv/a/notes.txt");
      const d1 = drops(r);
      assert(d1.length === 1, `one ATTEMPT: ${d1.length}`);
      const A = d1[0].o;
      assert(keysOf(A) === JSON.stringify(ATTEMPT_KEYS), keysOf(A));
      assert(A.kind === "ATTEMPT" && A.subject === SUBJECT && A.sessionId === "s1" && A.actionId === "a1" && A.subjectSeq === att.seq, JSON.stringify(A));
      assert(A.target === "/srv/a/notes.txt" && A.label === "c-self" && A.derivationClass === frameLabelEventType(frame()), JSON.stringify(A));
      assert(d1[0].mode === 0o640, `mode ${d1[0].mode.toString(8)}`);
      await guard(r, a);
      await event(r, a, "TOOL_EXECUTED", { toolName: TOOL });
      const closed = await event(r, a, "ACT_CLOSED", { closedAs: "RAN" });
      const d2 = drops(r);
      assert(d2.length === 2 && d2[0].o.kind === "ATTEMPT" && d2[1].o.kind === "CLOSE", "ATTEMPT sorts before its CLOSE");
      const C = d2[1].o;
      assert(keysOf(C) === JSON.stringify(CLOSE_KEYS), keysOf(C));
      assert(C.attemptSeq === att.seq && C.closedSeq === closed.seq && C.sessionId === "s1" && C.unguarded === false, JSON.stringify(C));
      assert(C.guard !== null && keysOf(C.guard) === JSON.stringify(GUARD_KEYS), JSON.stringify(C.guard));
      assert(C.guard.execute === true && C.guard.decisionHash === realDecision(true, 1).decisionHash, JSON.stringify(C.guard));
      assert(!("mono" in A) && !("boot" in A) && !("mono" in C), "no anchor stamp on either drop (phase R anchors on nothing)");
      assert(A.chain === chainOf(r) && C.chain === A.chain, `both drops name the subject chain's position-0 hash (R2-bytes F3): ${String(A.chain)}`);
      for (const f of ["subject-events.jsonl", "events.jsonl", "interest-book.jsonl"]) {
        let text = "";
        try {
          text = readFileSync(join(r.stateDir, f), "utf8");
        } catch {
          continue;
        }
        assert(!text.includes("/srv/a/notes.txt"), `the plain target reached ${f}`);
      }
    } finally {
      await r.svc.stop();
    }
  });

  await check("WD-2 · NO pointer for an act the label site did not place: an UNDERIVED target, no target, another kind; and no CLOSE for an unpointed act (B10)", async () => {
    const r = await rig();
    try {
      await event(r, id("s1", "u1"), "TOOL_ATTEMPTED", { toolName: TOOL }, "/etc/elsewhere");
      await event(r, id("s1", "u2"), "TOOL_ATTEMPTED", { toolName: TOOL });
      await event(r, id("s1", "u3"), "TOOL_ATTEMPTED", { toolName: TOOL }, "/srv/a/../c/x");
      for (const a of ["u1", "u2", "u3"]) {
        await guard(r, id("s1", a));
        await event(r, id("s1", a), "ACT_CLOSED", { closedAs: "RAN" });
      }
      assert(drops(r).length === 0, `no drops: ${JSON.stringify(drops(r).map((x) => x.o.kind))}`);
    } finally {
      await r.svc.stop();
    }
  });

  await check("WD-3 · FIRST DECISION WINS: a second /guard for the same act never changes the fate the CLOSE carries (K3)", async () => {
    const r = await rig();
    try {
      const a = id("s1", "f1");
      await event(r, a, "TOOL_ATTEMPTED", { toolName: TOOL }, "/srv/a/x");
      await guard(r, a); // first decision: n=1
      await guard(r, a); // second decision: n=2 — must NOT win
      await event(r, a, "TOOL_EXECUTED", { toolName: TOOL });
      await event(r, a, "ACT_CLOSED", { closedAs: "RAN" });
      const C = drops(r)[1].o;
      assert(C.guard.decisionHash === realDecision(true, 1).decisionHash, "the CLOSE carries the FIRST decision's hash");
    } finally {
      await r.svc.stop();
    }
  });

  await check("WD-4 · the caller's FAIL-OPEN (TOOL_EXECUTED guard:UNAVAILABLE) says unguarded and carries NO decision — before or after a 200 — so the witness reads it LATE (K6, C m1)", async () => {
    const r = await rig();
    try {
      const late = id("s1", "g1");
      await event(r, late, "TOOL_ATTEMPTED", { toolName: TOOL }, "/srv/a/x");
      await event(r, late, "TOOL_EXECUTED", { toolName: TOOL, guard: "UNAVAILABLE" });
      await guard(r, late);
      await event(r, late, "ACT_CLOSED", { closedAs: "RAN" });
      const early = id("s1", "g2");
      await event(r, early, "TOOL_ATTEMPTED", { toolName: TOOL }, "/srv/a/y");
      await guard(r, early);
      await event(r, early, "TOOL_EXECUTED", { toolName: TOOL, guard: "UNAVAILABLE" });
      await event(r, early, "ACT_CLOSED", { closedAs: "RAN" });
      const closes = drops(r).filter((x) => x.o.kind === "CLOSE").map((x) => x.o);
      assert(closes.length === 2, `two CLOSEs: ${closes.length}`);
      for (const C of closes) assert(C.guard === null && C.unguarded === true, `a fail-open CLOSE carries no decision, whenever the 200 came: ${JSON.stringify(C)}`);
    } finally {
      await r.svc.stop();
    }
  });

  await check("WD-5 · two sessions sharing an actionId are TWO acts: each CLOSE its own attemptSeq and its own decision or none (B M1)", async () => {
    const r = await rig();
    try {
      const x = id("sA", "same");
      const y = id("sB", "same");
      const ax = await event(r, x, "TOOL_ATTEMPTED", { toolName: TOOL }, "/srv/a/x");
      const ay = await event(r, y, "TOOL_ATTEMPTED", { toolName: TOOL }, "/srv/c/y");
      await guard(r, x);
      await event(r, x, "TOOL_EXECUTED", { toolName: TOOL });
      await event(r, y, "ACT_CLOSED", { closedAs: "RAN" });
      await event(r, x, "ACT_CLOSED", { closedAs: "RAN" });
      const closes = drops(r).filter((d) => d.o.kind === "CLOSE").map((d) => d.o);
      const cx = closes.find((c) => c.sessionId === "sA");
      const cy = closes.find((c) => c.sessionId === "sB");
      assert(cx !== undefined && cy !== undefined, "both closed");
      assert(cx.attemptSeq === ax.seq && cy.attemptSeq === ay.seq && ax.seq !== ay.seq, "each its own seq");
      assert(cx.guard !== null && cy.guard === null, "sB never reached /guard: it borrows nothing from sA");
    } finally {
      await r.svc.stop();
    }
  });

  await check("WD-6 · a HELD act: the CLOSE carries execute false", async () => {
    const r = await rig({ execute: false });
    try {
      const a = id("s1", "h1");
      await event(r, a, "TOOL_ATTEMPTED", { toolName: TOOL }, "/srv/a/b/deep");
      await guard(r, a);
      await event(r, a, "TOOL_HELD_NOT_EXECUTED", { reason: "HOLD" });
      await event(r, a, "ACT_CLOSED", { closedAs: "HELD" });
      const [A, C] = drops(r).map((d) => d.o);
      assert(A.label === "c-other", A.label);
      assert(C.guard.execute === false, JSON.stringify(C.guard));
    } finally {
      await r.svc.stop();
    }
  });

  await check("WD-7 · no witness intake declared: NOTHING is dropped, even with a test intake handed in", async () => {
    const r = await rig({ withIntake: false });
    try {
      const a = id("s1", "n1");
      await event(r, a, "TOOL_ATTEMPTED", { toolName: TOOL }, "/srv/a/x");
      await guard(r, a);
      await event(r, a, "ACT_CLOSED", { closedAs: "RAN" });
      assert(drops(r).length === 0, "no drops");
    } finally {
      await r.svc.stop();
    }
  });

  await check("WD-8 · an intake that cannot be written changes NOTHING the subject is told: every event answers 200 and persists", async () => {
    const r = await rig({ intakeExists: false });
    try {
      const a = id("s1", "e1");
      const att = await event(r, a, "TOOL_ATTEMPTED", { toolName: TOOL }, "/srv/a/x");
      await guard(r, a);
      const cl = await event(r, a, "ACT_CLOSED", { closedAs: "RAN" });
      assert(att.duplicate === false && cl.duplicate === false && cl.seq > att.seq, "both persisted");
    } finally {
      await r.svc.stop();
    }
  });

  await check("WD-9 · an act the caller never reported running (no TOOL_EXECUTED fail-open, nothing) still carries its decision: not unguarded, so the witness reads RAN/HELD by the decision", async () => {
    const r = await rig();
    try {
      const a = id("s1", "u1");
      await event(r, a, "TOOL_ATTEMPTED", { toolName: TOOL }, "/srv/a/x");
      await guard(r, a);
      await event(r, a, "ACT_CLOSED", { closedAs: "RAN" });
      const C = drops(r).find((d) => d.o.kind === "CLOSE")!.o;
      assert(C.guard !== null && C.unguarded === false, `the decision rides unless the caller said fail-open: ${JSON.stringify(C)}`);
    } finally {
      await r.svc.stop();
    }
  });

  await check("WD-10 · S211: a target in ONE matching pair of quotes — direct or joined onto the caller's cwd — points the witness at the STRIPPED path, under the label's class; a mismatched or nested pair drops nothing", async () => {
    const r = await rig();
    try {
      const q1 = await event(r, id("s1", "q1"), "TOOL_ATTEMPTED", { toolName: TOOL }, '/home/op/"/srv/a/notes.txt"');
      await event(r, id("s1", "q2"), "TOOL_ATTEMPTED", { toolName: TOOL }, "'/srv/c/x/'");
      await event(r, id("s1", "q3"), "TOOL_ATTEMPTED", { toolName: TOOL }, '/home/op/"/srv/a/x\'');
      await event(r, id("s1", "q4"), "TOOL_ATTEMPTED", { toolName: TOOL }, '/home/op/""/srv/a/x""');
      const d = drops(r);
      assert(d.length === 2, `two ATTEMPTs (q1, q2), none for the mismatched or nested pair: ${JSON.stringify(d.map((x) => x.o.actionId))}`);
      const [A1, A2] = d.map((x) => x.o);
      assert(A1.actionId === "q1" && A1.subjectSeq === q1.seq && A1.target === "/srv/a/notes.txt" && A1.label === "c-self", JSON.stringify(A1));
      assert(A2.actionId === "q2" && A2.target === "/srv/c/x" && A2.label === "c-shared", JSON.stringify(A2));
      for (const A of [A1, A2]) assert(A.derivationClass === frameLabelEventType(frame()), `class ${String(A.derivationClass)}`);
      // B-1 (Long Run A Stop 2) RE-TAKES THIS ARM. Before B-1 it pinned the POINTER's fingerprint as the canonical
      // CLAIM's, so the quoted and the bare spelling of one file reached the witness under two fingerprints — the
      // divergence was pinned here as S211's ceiling, and it is exactly the defect B-1 fixes (Stop-1 note F-4).
      // NOW: the POINTER's fingerprint is the LOOKED-AT path's (equal for both spellings); the CHAIN record's is
      // still the claim's (different, exactly as before — the canon did not move).
      const bare = await event(r, id("s1", "b1"), "TOOL_ATTEMPTED", { toolName: TOOL }, "/srv/a/notes.txt");
      const B = drops(r).map((x) => x.o).find((o) => o.actionId === "b1");
      assert(bare.seq > q1.seq && B !== undefined && B.target === A1.target, "the bare control did not point at the same path");
      assert(typeof A1.targetFingerprint === "string" && /^[0-9a-f]{64}$/.test(A1.targetFingerprint) && A1.targetFingerprint === B.targetFingerprint,
        "B-1: the quoted and the bare spelling of ONE looked-at path carry DIFFERENT pointer fingerprints");
      assert(keysOf(A1) === keysOf(B) && JSON.parse(keysOf(A1)).every((k: string) => ATTEMPT_KEYS.includes(k)) && JSON.parse(keysOf(A1)).length === ATTEMPT_KEYS.length,
        "B-1 changed the ATTEMPT drop's KEY SET (the witness's intake is exact-key)");
      const chainRecs = readFileSync(join(r.stateDir, "subject-events.jsonl"), "utf8").split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l));
      const chainQ1 = chainRecs.find((c: any) => c.sequenceNumber === q1.seq);
      const chainB1 = chainRecs.find((c: any) => c.sequenceNumber === bare.seq);
      assert(chainQ1 !== undefined && chainB1 !== undefined, "fixture: both acts are on the chain");
      assert(typeof chainQ1.targetFingerprint === "string" && typeof chainB1.targetFingerprint === "string" && chainQ1.targetFingerprint !== chainB1.targetFingerprint,
        "the CHAIN's fingerprints of the quoted and the bare claim are EQUAL — the claim-based chain fingerprint moved, which B-1 does not rule");
      assert(chainB1.targetFingerprint === B.targetFingerprint && chainQ1.targetFingerprint !== A1.targetFingerprint,
        "for a bare claim the pointer and the chain agree; for a quoted one the pointer is the looked-at path's, the chain the claim's");
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
