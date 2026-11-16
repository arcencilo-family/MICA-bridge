// GATE 2 · LONG RUN A STOP 2 · the bridge's HARM wiring at SERVICE level (contract B2, B4, B5).
//   node <ts-node bin.js> -P mica-bridge/tsconfig.json mica-bridge/gate2-harm.test.ts   (from the repo root)
//
// What a declaration test cannot show, because it lives where the SALT lives:
//   · the salt epoch's start (saltEpochSince) comes from the epoch's own event-book row;
//   · each item's fingerprint equals the witness POINTER's fingerprint for an act claiming
//     the item, quoted or bare (B-1 and B2 meet here);
//   · the deciding act's actionId is set PER /guard on the options the gate hands wire();
//   · /explain hands back a Gate-2 harm finding (origin, grant) as the journal recorded it.
//
// Fixture names only: subject-a, tool-x, c-self / c-other / c-shared, /srv/…, o-*, i-*.
// The served subject's entry is taken from the tree declaration BY USE (spread, then renamed).
import { shippedDraft } from "./example-draft";
import * as http from "http";
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "fs";
import { createHash } from "crypto";
import { tmpdir } from "os";
import { join } from "path";

import { MicaBridgeService, saltEpochStartFrom } from "./mica-service";
import { canonicalHash } from "./canonical-json";
import { fingerprintTarget, TARGET_CANON_VERSION } from "./target-fingerprint";
import { toWireOptions } from "./to-wire-options";
import { Stage1GuardAdapter } from "./stage1-guard-adapter";
import { frameLabelEventType } from "./interest-book";

let passed = 0;
let failed = 0;
let skipped = 0;
async function check(name: string, fn: () => Promise<void> | void): Promise<void> {
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
const NOW = new Date("2026-09-18T00:00:00Z");
const METHOD = "bd91dc37fa7e5d0653c795c4878266a4482c1405d932ce0b073d50b5bce41b72";
const BASIS = "GATE 2 HARM SERVICE FIXTURE, not a declaration.";
const PATH_BASIS = "GATE 2 HARM SERVICE FIXTURE: the witness's seeing half owns this path under its own uid; the bridge only drops pointers into it or reads it.";
const KEPT = "/srv/a/b/kept.txt";
const GRANTED = "/srv/a/b/granted.txt";

const RETIRED_NAME = "subject-events.TESTFIXTURE.pre-chain-boundary.jsonl";
const RETIRED_BODY = JSON.stringify({ sequenceNumber: 1, timestamp: 1, moduleId: SUBJECT, eventType: "TOOL_ATTEMPTED", outcome: TOOL }) + "\n";

function frame(): any {
  return {
    categories: {
      value: [
        { id: "c-self", label: "own working area", grounding: "agency", self: true },
        { id: "c-other", label: "another principal's area", grounding: "vulnerability", self: false },
        { id: "c-shared", label: "shared area", grounding: "need", self: false },
      ],
      basis: BASIS,
      proxy: true,
    },
    regions: {
      value: [
        { prefix: "/srv/a", category: "c-self" },
        { prefix: "/srv/a/b", category: "c-other" },
        { prefix: "/srv/c", category: "c-shared" },
      ],
      basis: BASIS,
      proxy: true,
    },
  };
}

function harm(): any {
  return {
    harmOnly: { value: true, basis: BASIS, proxy: false },
    origins: { value: { "o-sub": { subject: SUBJECT, basis: BASIS } }, basis: BASIS, proxy: false },
    items: {
      value: {
        "i-kept": { path: KEPT, category: "c-other", control: false, basis: BASIS },
        "i-granted": { path: GRANTED, category: "c-other", control: false, basis: BASIS },
      },
      basis: BASIS,
      proxy: true,
    },
    grants: {
      value: { "i-kept": { origins: [], since: {}, basis: BASIS }, "i-granted": { origins: ["o-sub"], since: { "o-sub": "2026-01-01T00:00:00.000Z" }, basis: BASIS } },
      basis: BASIS,
      proxy: false,
    },
    clearances: { value: [], basis: BASIS, proxy: false },
  };
}

/** The fixture declaration: this uid is the subject's peer and posts its acts. */
function declaration(): any {
  const d = JSON.parse(JSON.stringify(draft));
  d.pilot = { active: false };
  delete d.readers.gate1Scope;
  delete d.baskets;
  d.readers.gate2Direction = {
    subject: { value: SUBJECT, basis: BASIS, proxy: false },
    book: { value: "witnessBook", basis: BASIS, proxy: false },
    witnessMethod: { value: METHOD, basis: BASIS, proxy: false },
  };
  d.harm = { [SUBJECT]: harm() };
  // The example reads a plain "mica" log; this arm is about the SUBJECT-CHAIN reading, so it declares that wiring.
  d.readers.logKind.value = "subject-chain";
  if (!d.readers.readableLoadStates.value.includes("LOADED_SUBJECT_CHAIN_VERIFIED")) d.readers.readableLoadStates.value.push("LOADED_SUBJECT_CHAIN_VERIFIED");
  d.subjectLog.chainBoundary.retiredPath.value = `/var/lib/mica-bridge/${RETIRED_NAME}`;
  d.subjectLog.chainBoundary.retiredRecords.value = 1;
  d.subjectLog.chainBoundary.retiredBytes.value = Buffer.byteLength(RETIRED_BODY, "utf8");
  d.subjectLog.chainBoundary.retiredSha256.value = createHash("sha256").update(RETIRED_BODY, "utf8").digest("hex");
  d.subjects = [{ ...d.subjects[0], subject: SUBJECT, toolName: TOOL, peerUid: OWN_UID }];
  delete d.subjects[0].unit;
  d.routes = [{ uid: OWN_UID, role: "subject", allow: [{ method: "POST", path: "/guard" }, { method: "POST", path: "/subject-events" }] }];
  d.frame = { [SUBJECT]: frame() };
  d.paths.interestBook = "/var/lib/mica-bridge/interest-book.jsonl";
  d.paths.witnessIntake = { value: "/var/lib/mica/witness-sight/intake", basis: PATH_BASIS };
  d.paths.witnessBook = { value: "/var/lib/mica/witness-sight/book-of-effects.jsonl", basis: PATH_BASIS };
  return d;
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
  cfg: any;
}

async function rig(_role: "subject", stateDir?: string): Promise<Rig> {
  const socketDir = mkdtempSync(join(tmpdir(), "mica-g2h-svc-"));
  const peer = join(socketDir, "peers", String(OWN_UID));
  mkdirSync(peer, { recursive: true });
  chmodSync(peer, 0o770);
  const cfgDir = mkdtempSync(join(tmpdir(), "mica-g2h-cfg-"));
  const cfgPath = join(cfgDir, "declarations.config.json");
  const cfg = declaration();
  writeFileSync(cfgPath, JSON.stringify(cfg));
  const sd = stateDir ?? mkdtempSync(join(tmpdir(), "mica-g2h-state-"));
  writeFileSync(join(sd, RETIRED_NAME), RETIRED_BODY);
  const intake = join(mkdtempSync(join(tmpdir(), "mica-g2h-intake-")), "intake");
  mkdirSync(intake);
  const svc = new MicaBridgeService({
    declarationsPath: cfgPath,
    socketDir,
    now: () => NOW,
    testBridgeGid: OWN_GID,
    stateDir: sd,
    testWritablePaths: { witnessIntake: intake },
  });
  await svc.start();
  return { svc, sock: join(socketDir, "peers", String(OWN_UID), "guard.sock"), stateDir: sd, intake, cfg };
}

async function event(r: Rig, actionId: string, targetIdentity: string) {
  const identity = { subject: SUBJECT, sessionId: "s1", actionId };
  const payload = { toolName: TOOL };
  const body: any = { identity, kind: "TOOL_ATTEMPTED", eventHash: canonicalHash({ identity, kind: "TOOL_ATTEMPTED", payload }), payload, targetIdentity };
  const res = await httpJson(r.sock, "POST", "/subject-events", body);
  assert(res.status === 200, `TOOL_ATTEMPTED: ${String(res.status)} ${JSON.stringify(res.body)}`);
}
function pointer(r: Rig, actionId: string): any {
  const found = readdirSync(r.intake)
    .map((n) => JSON.parse(readFileSync(join(r.intake, n), "utf8")))
    .find((o) => o.actionId === actionId && o.kind === "ATTEMPT");
  assert(found !== undefined, `no ATTEMPT pointer for ${actionId}`);
  return found;
}
/** The salt the service minted, read back from its own state dir (test-only; the salt never leaves the process otherwise). */
function saltOf(r: Rig): Buffer {
  const names = readdirSync(r.stateDir).filter((n) => /salt/i.test(n));
  assert(names.length === 1, `expected one salt file in the state dir, found ${JSON.stringify(names)}`);
  return readFileSync(join(r.stateDir, names[0]));
}
const svcAny = (r: Rig): any => r.svc as any;

async function main(): Promise<void> {
  await check("G2H-1 · saltEpochSince is the ts of the epoch's own event-book row: a fresh start mints and reads NOW; a restart on the same state reads the SAME value from the book", async () => {
    const r = await rig("subject");
    let first: number | null;
    try {
      first = svcAny(r).saltEpochSince;
      assert(first === NOW.getTime(), `fresh start: saltEpochSince ${String(first)}, expected the mint's ts ${String(NOW.getTime())}`);
      const book = readFileSync(join(r.stateDir, "events.jsonl"), "utf8").split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l));
      const row = book.find((e: any) => e.kind === "SALT_EPOCH_STARTED");
      assert(row !== undefined && Date.parse(row.ts) === first, "the row the value comes from is the SALT_EPOCH_STARTED row");
    } finally {
      await r.svc.stop();
    }
    const again = await rig("subject", r.stateDir);
    try {
      assert(svcAny(again).saltEpochSince === first, `restart: ${String(svcAny(again).saltEpochSince)} !== ${String(first)}`);
    } finally {
      await again.svc.stop();
    }
  });

  await check("G2H-2 · saltEpochStartFrom: no salt → null; the earliest row naming the live saltId wins; another saltId's row is not this epoch's; the announce is the fallback", () => {
    const present: any = { status: "PRESENT", salt: Buffer.alloc(32), saltId: "aaaaaaaaaaaaaaaa", mintedAtThisStart: false };
    const absent: any = { status: "ABSENT", reason: "SALT_UNREADABLE", detail: "fixture" };
    const rows = [
      { kind: "SALT_EPOCH_STARTED", saltId: "bbbbbbbbbbbbbbbb", ts: "2026-01-01T00:00:00.000Z" },
      { kind: "SALT_EPOCH_ADOPTED", saltId: "aaaaaaaaaaaaaaaa", ts: "2026-02-01T00:00:00.000Z" },
      { kind: "SALT_EPOCH_ADOPTED", saltId: "aaaaaaaaaaaaaaaa", ts: "2026-03-01T00:00:00.000Z" },
    ];
    assert(saltEpochStartFrom(absent, rows, "2026-04-01T00:00:00.000Z") === null, "no salt, no epoch");
    assert(saltEpochStartFrom(present, rows, null) === Date.parse("2026-02-01T00:00:00.000Z"), "the earliest row of the live saltId");
    assert(saltEpochStartFrom(present, rows.slice(0, 1), null) === null, "another saltId's row is not this epoch's start");
    assert(saltEpochStartFrom(present, rows.slice(0, 1), "2026-04-01T00:00:00.000Z") === Date.parse("2026-04-01T00:00:00.000Z"), "the announce is the fallback");
  });

  await check("G2H-3 · B-1 MEETS B2: each harm item's fingerprint EQUALS the witness pointer's for an act claiming it, quoted or bare — the same function and canon version over the looked-at path", async () => {
    const r = await rig("subject");
    try {
      await event(r, "a-bare", KEPT);
      await event(r, "a-quoted", `"${KEPT}"`);
      await event(r, "a-joined", `/srv/c/"${GRANTED}"`);
      const epoch = svcAny(r).harmEpochFor(svcAny(r).state.declarations);
      assert(epoch !== null && epoch.saltEpochSince === NOW.getTime(), `epoch ${JSON.stringify(epoch)}`);
      const w = toWireOptions(svcAny(r).state.declarations, (p: string) => p, () => [], undefined, epoch) as any;
      const fp = (id: string) => w.gate2Harm.items.find((i: any) => i.id === id).fingerprint;
      assert(/^[0-9a-f]{64}$/.test(fp("i-kept")) && fp("i-kept") !== fp("i-granted"), JSON.stringify(w.gate2Harm.items));
      assert(pointer(r, "a-bare").targetFingerprint === fp("i-kept"), "the bare claim's pointer does not match the item");
      assert(pointer(r, "a-quoted").targetFingerprint === fp("i-kept"), "the QUOTED claim's pointer does not match the item (F-4 not closed)");
      assert(pointer(r, "a-joined").targetFingerprint === fp("i-granted"), "the cwd-joined quoted claim's pointer does not match the item");
      assert(fp("i-kept") === fingerprintTarget(saltOf(r), KEPT, TARGET_CANON_VERSION), "the item fingerprint is not fingerprintTarget(salt, path, TARGET_CANON_VERSION)");
    } finally {
      await r.svc.stop();
    }
  });

  await check("G2H-4 · THE DECIDING ACT, PER /guard: the options the gate hands wire() carry gate2DecidingActionId = the request's actionId and the service's harm epoch; the census carries null", async () => {
    const r = await rig("subject");
    try {
      const decls = svcAny(r).state.declarations;
      const adapter = svcAny(r).buildGuardAdapter(decls);
      const req = (actionId: string) => ({
        subject: SUBJECT, sessionId: "s1", actionId, toolName: TOOL, stakesClass: r.cfg.subjects[0].stakesClass, holdAtOrAbove: r.cfg.stakes.baseline.holdAtOrAbove.value,
        pilotApplied: false, declarationHash: "a".repeat(64),
      });
      const o1 = adapter.wireOptionsFor(req("act-1"));
      const o2 = adapter.wireOptionsFor(req("act-2"));
      assert(o1.gate2DecidingActionId === "act-1" && o2.gate2DecidingActionId === "act-2", `deciding acts ${String(o1.gate2DecidingActionId)}, ${String(o2.gate2DecidingActionId)}`);
      assert(!("gate2" in o1) && o1.gate2Harm !== undefined, "harm mode: gate2Harm and no gate2");
      assert(o1.gate2Harm.saltEpochSince === NOW.getTime(), `the gate's saltEpochSince ${String(o1.gate2Harm.saltEpochSince)}`);
      assert(o1.gate2Harm.items.every((i: any) => /^[0-9a-f]{64}$/.test(i.fingerprint)), "the gate's item fingerprints are filled");
      assert(o1.gate2RosterPath === svcAny(r).resolvePath(decls.paths.interestBook) && o1.gate2BookPath === svcAny(r).resolvePath(decls.paths.witnessBook.value), "roster and book are the resolved paths");
      // AMENDED (S216-2): the census takes the SAME grant-memory view the gate does (the one-builder rule).
      const census = toWireOptions(decls, (p: string) => svcAny(r).resolvePath(p), () => [], undefined, svcAny(r).harmEpochFor(decls), svcAny(r).grantMemoryViewFor(decls)) as any;
      assert(census.gate2DecidingActionId === null, "a status read decides no act");
      assert(JSON.stringify(census.gate2Harm) === JSON.stringify(o1.gate2Harm), "the census and the gate hand Gate 2 different harm stanzas");
    } finally {
      await r.svc.stop();
    }
  });

  // ── G2H-5 · B4 (rebuilt on the cold canon refuter's M2) ─────────────────────────────────────────
  // The first version journalled a HAND-MADE decision (a finding code and a `summary` key the real machine never
  // writes) and proved only that /explain is a pass-through. Replaced: the decision is now the MACHINE's, taken
  // through the service's own gate options, and the arm asserts the channel the machine actually uses — the
  // gate2-direction reading's margin `reason`, which quotes the harm verdict (origin, grant, the act whose record
  // shows the change, the carrying act).
  // ⚠ The bridge suite imports the INSTALLED machine (/opt, eedfda8), which has no harm branch. Until the machine
  //   relays, this arm is SKIPPED WITH ITS REASON PRINTED (counted apart, never as a pass). The same chain was run
  //   against the WORKTREE machine by the seat notes' probe-m2-explain.ts (g2a-notes) — that capture, not
  //   this suite, is today's evidence.
  const optHasHarm = (() => {
    try {
      // S216: the bridge now wires grantSince, which a machine without S216 refuses whole (G2_HARM_MALFORMED): the arm
      // runs only against a machine that reads it — the installed one after its relay, or the S216 worktree through
      // the seat's resolve redirect (g2b-notes/s216/redirect-machine.js).
      return readFileSync("/opt/mica-machine/src/glue/wire.ts", "utf8").includes("gate2Harm") &&
        readFileSync("/opt/mica-machine/src/mica/gate2-direction/index.ts", "utf8").includes("grantSince") &&
        // AMENDED (S216-2): and the grant memory, which a machine without S216-2 refuses whole (WIRED AND BLIND).
        readFileSync("/opt/mica-machine/src/mica/gate2-direction/index.ts", "utf8").includes("grantMemory");
    } catch {
      return false;
    }
  })();
  if (!optHasHarm) {
    skipped++;
    console.log(
      "SKIP  G2H-5 · B4 /explain carries origin + grant from a REAL harm decision — the installed machine (/opt/mica-machine) " +
        "has no harm branch, no S216 grantSince or no S216-2 grantMemory, so no real decision can carry one here. Evidence today: " +
        "g2a-notes/probe-m2-explain.ts against the worktree machine."
    );
  } else {
    await check("G2H-5 · B4 /explain carries ORIGIN and GRANT from a REAL harm decision: the gate2-direction reading's margin reason quotes the verdict", async () => {
      const r = await rig("subject");
      try {
        for (const [actionId, target] of [["act-1", KEPT], ["act-2", `"${KEPT}"`], ["act-3", GRANTED]] as const) await event(r, actionId, target);
        // The witness does not run here: its book is written in the record shape it writes, citing the real pointers.
        const book = join(mkdtempSync(join(tmpdir(), "mica-g2h-book-")), "book-of-effects.jsonl");
        const { SubjectEventJournal } = require("/opt/mica-machine/src/glue/subject-event-journal");
        const { consequenceEventType } = require("/opt/mica-machine/src/witness/seeing");
        const j = new SubjectEventJournal({ path: book });
        assert(j.appendBoundary(null, "fixture: a witness book", NOW.getTime()).persisted, "book boundary");
        const cls = consequenceEventType(frameLabelEventType(frame()));
        for (const [a, observed] of [["act-1", "FIRST_SEEN"], ["act-2", "CONTENT_DIFFERS"]] as const) {
          const p = pointer(r, a);
          assert(j.appendEvent(() => ({ moduleId: SUBJECT, eventType: cls, outcome: `c-other:${observed}`, actionId: a, timestamp: NOW.getTime() + p.subjectSeq,
            witnessed: { cites: { chain: p.chain, subjectSeq: p.subjectSeq, sessionId: "s1", targetFingerprint: p.targetFingerprint, closedSeq: p.subjectSeq + 1, decisionHash: null }, fate: "RAN", observed } })).persisted, a);
        }
        const decls = svcAny(r).state.declarations;
        const gate = svcAny(r).buildGuardAdapter(decls);
        const adapter = new Stage1GuardAdapter(svcAny(r).resolvedEvalPaths(decls), (q: any) => ({ ...gate.wireOptionsFor(q), gate2BookPath: book }));
        const out: any = await adapter.evaluate({ subject: SUBJECT, sessionId: "s1", actionId: "act-3", toolName: TOOL, stakesClass: r.cfg.subjects[0].stakesClass,
          holdAtOrAbove: r.cfg.stakes.baseline.holdAtOrAbove.value, pilotApplied: false, declarationHash: "a".repeat(64) });
        assert(out.httpStatus === 200, JSON.stringify(out).slice(0, 400));
        let res: any = null;
        svcAny(r).sendJson = (_res: unknown, status: number, body: unknown) => { res = { status, body }; };
        svcAny(r).handleExplain(new URL(`http://localhost/explain?decisionHash=${out.decision.decisionHash as string}`), {});
        assert(res !== null && res.status === 200, `/explain ${JSON.stringify(res).slice(0, 300)}`);
        const g2 = res.body.readings.find((x: any) => /gate2/i.test(x.sensorId));
        assert(g2 !== undefined && g2.kind === "ALARM", `the gate2 reading: ${JSON.stringify(g2)}`);
        const reason = String(g2.margin?.reason ?? "");
        assert(reason.includes("origin o-sub") && reason.includes("grant NONE") && reason.includes("item i-kept"), `origin/grant/item not on /explain: ${reason}`);
        assert(reason.includes("\"act-2\"") && reason.includes("\"act-3\""), `the act with the record and the carrying act: ${reason}`);
        // S216-2 (cond. 5/8): /explain carries the grant memory, as the machine printed it, after the harmLine.
        assert(/ GRANT MEMORY G2_GRANT_MEMORY@[0-9a-f]{16} \(BEGUN — /.test(reason), `the grant memory is not on /explain: ${reason}`);
      } finally {
        await r.svc.stop();
      }
    });
  }

  console.log(`CENSUS: ${passed} passed, ${failed} failed, ${skipped} skipped, ${passed + failed + skipped} total`);
  if (failed > 0) process.exit(1);
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
