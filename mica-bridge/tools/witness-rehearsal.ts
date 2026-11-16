// ── REHEARSAL · the witness's seeing half, end to end, then REMOVED ────────────
//
// A DIFFERENT subject AND a DIFFERENT frame AND a DIFFERENT basket (the T30 condition):
// the served tree declaration, scrubbed of every served name, re-keyed to "surveyor-q",
// with its own three-category frame over scratch paths and a phase-R basket over the
// witness's effect classes, Gate 2 switched onto the witness's book.
//
// The REAL bridge service (worktree) takes the acts over its socket; a scripted guard
// adapter decides run or hold per act (the bridge's decision plumbing is under test,
// not the readers); the REAL seeing witness (machine worktree) sweeps the intake the
// bridge drops into; the worktree's wire() reads Gate 2 on the book.
//
// The guard adapter answers with the REAL decision shape (no `at`). Phase R anchors on nothing: the witness takes
// ONE look at the close and reads a facet against its own last look at that target (audit 2026-10-11 09:32Z).
//
// Then the removal, three ways: the switch alone (Gate 2 back to a CHAIN basket — siblings
// byte-identical), Gate 2 undeclared (siblings byte-identical), and the witness's paths removed
// by RELOAD of a running bridge (the intake is read per act: nothing more is dropped).
// And the literal fence: no served name in anything the run wrote or printed.
//
// RUN (from the repo root), every machine-specific path from the environment, none in this file:
//   MICA_TREE=<the machine tree's src directory>  [REHEARSAL_WORK=<dir>]  [REHEARSAL_PLACES=<dir>] \
//     node <ts-node bin.js> -P mica-bridge/tsconfig.json mica-bridge/tools/witness-rehearsal.ts
//   REHEARSAL_PLACES must be a path every segment of which a frame region can name (no segment starting "-");
//   the region tree is ARCHIVED there afterwards (rehearsal-archive/), never deleted.
import * as http from "http";
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, chmodSync, existsSync, readdirSync, statSync, renameSync, unlinkSync } from "fs";
import { join, relative, resolve } from "path";
import { tmpdir } from "os";
import { createHash } from "crypto";

const BRIDGE = resolve(__dirname, "..");
const MICA_ENV = process.env.MICA_TREE;
if (MICA_ENV === undefined || MICA_ENV.length === 0) {
  console.error("witness-rehearsal: set MICA_TREE to the machine tree's src directory (the witness build under test)");
  process.exit(2);
}
const MICA = resolve(MICA_ENV);
const WORK_PARENT = resolve(process.env.REHEARSAL_WORK ?? tmpdir());
const PLACES_PARENT = resolve(process.env.REHEARSAL_PLACES ?? tmpdir());
const STATE_PREFIX = "/var/lib/mica-bridge";

const { MicaBridgeService } = require(`${BRIDGE}/mica-service`);
const { canonicalHash } = require(`${BRIDGE}/canonical-json`);
const { validateDeclarations } = require(`${BRIDGE}/declarations`);
const { toWireOptions } = require(`${BRIDGE}/to-wire-options`);
const { frameLabelEventType } = require(`${BRIDGE}/interest-book`);
const { witnessRecordClass } = require(`${BRIDGE}/witness-pointer`);
const { wire, footingsFromWiring, GATE2_READER, GATE2_BOOK_SOURCE_PREFIX } = require(`${MICA}/glue/wire`);
const { SubjectChainLog, LOADED_SUBJECT_CHAIN_VERIFIED } = require(`${MICA}/glue/subject-event-journal`);
const { SeeingWitness } = require(`${MICA}/witness/seeingd`);
const { SEEING_METHOD_DIGEST, consequenceEventType } = require(`${MICA}/witness/seeing`);
const { GATE2_BOOK_CEILING } = require(`${MICA}/glue/wire`);
const gate2Of = (w: any) => w.sensorVerdicts.find((v: any) => v.sensorId === GATE2_READER);

let captured = "";
for (const stream of [process.stdout, process.stderr]) {
  const orig = stream.write.bind(stream);
  (stream as any).write = (chunk: any, ...rest: any[]) => { captured += typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"); return orig(chunk, ...rest); };
}
let passed = 0, failed = 0;
async function check(name: string, fn: () => void | Promise<void>) {
  try { await fn(); passed++; console.log(`  ✓ ${name}`); } catch (e) { failed++; console.log(`  ✗ ${name}\n    ${String((e as Error).message).split("\n").join("\n    ")}`); }
}
function ok(c: boolean, m: string): void { if (!c) throw new Error(m); }

// ── the served values, READ, never typed ─────────────────────────────────────
const live = JSON.parse(readFileSync(`${BRIDGE}/declarations.example.json`, "utf8"));
// ZERO SUBJECTS (ticket v2 §3): refused in words, not by a TypeError on an undefined subject.
if (!Array.isArray(live.subjects) || live.subjects.length === 0) {
  console.error("witness-rehearsal: the tree declaration names no subject (subjects: []): there is no served subject to rehearse against; refusing");
  process.exit(2);
}
const SERVED = live.subjects[0];
const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
const word = (w: string) => new RegExp(`(?<![A-Za-z0-9])${esc(w)}(?![A-Za-z0-9])`, "i");
const NEEDLES: { what: string; re: RegExp }[] = [
  { what: "the served subject's name", re: word(SERVED.subject) },
  { what: "the served unit", re: word(SERVED.unit) },
  { what: "the served tool class", re: word(SERVED.toolName) },
  { what: "the served stakes class", re: word(SERVED.stakesClass) },
  { what: "the served uid", re: new RegExp(`(?<![0-9A-Za-z])${SERVED.peerUid}(?![0-9A-Za-z])`) },
];
function leaks(where: string, text: string): string[] {
  const out: string[] = [];
  for (const n of NEEDLES) for (const m of text.matchAll(new RegExp(n.re.source, n.re.flags + "g"))) {
    out.push(`${where}: ${n.what} …${text.slice(Math.max(0, m.index! - 30), m.index! + m[0].length + 30).replace(/\s+/g, " ")}…`);
  }
  return out;
}

const R_SUBJECT = "surveyor-q", R_TOOL = "survey_probe", R_UNIT = "rehearsal-caller-unit";
const R_UID = process.getuid!(), R_GID = process.getgid!();
const NOW = new Date();
const PROSE = "REHEARSAL: a prose field of the served declaration, replaced because it names a served value";
const RETIRED_NAME = "subject-events.REHEARSAL.pre-chain-boundary.jsonl";
const RETIRED_BODY = JSON.stringify({ sequenceNumber: 1, timestamp: 1, moduleId: "rehearsal-retired", eventType: "TOOL_ATTEMPTED", outcome: R_TOOL }) + "\n";
const W_INTAKE_DECL = "/var/lib/mica/rehearsal-sight/intake";
const W_BOOK_DECL = "/var/lib/mica/rehearsal-sight/book-of-effects.jsonl";
const W_BASIS = "REHEARSAL: the witness's seeing half owns this path under its own uid; the bridge only drops pointers into it or reads it.";
const clone = (x: any): any => JSON.parse(JSON.stringify(x));

function scrub(o: any): any {
  const RENAME = new Map<string, string>([[SERVED.subject, R_SUBJECT], [SERVED.toolName, R_TOOL], [SERVED.stakesClass, R_TOOL], [SERVED.unit, R_UNIT]]);
  if (Array.isArray(o)) return o.map(scrub);
  if (o !== null && typeof o === "object") { const out: any = {}; for (const k of Object.keys(o)) out[k] = scrub(o[k]); return out; }
  if (typeof o === "string") return RENAME.has(o) ? RENAME.get(o) : NEEDLES.some((n) => n.re.test(o)) ? PROSE : o;
  if (o === SERVED.peerUid) return R_UID;
  return o;
}

const work = mkdtempSync(join(WORK_PARENT, "run-"));
process.chdir(work);
// The regions must be label-derivable paths: no segment starting "-" (REHEARSAL_PLACES must not have one),
// so the region tree lives in the worktree area, under a name made here and removed at the end.
const places = mkdtempSync(join(PLACES_PARENT, "rehearsal-places-"));
for (const d of ["desk", "archive"]) mkdirSync(join(places, d));
const env = (value: any) => ({ value, basis: "REHEARSAL basis — a different frame and basket from the served ones", proxy: true });

/** DIFFERENT subject, frame and basket; Gate 2 on the witness's book; the witness's paths declared. */
type G2Mode = "book" | "chain" | "none";
function rehearsalDeclaration(mode: G2Mode, withWitness: boolean): any {
  const served = clone(live);
  delete served.frame;
  delete served.baskets;
  // S34: the served Gate 2 reads a harm stanza keyed by the served subject; the rehearsal declares its own.
  delete served.harm;
  const d = scrub(served);
  d.pilot = { active: false };
  delete d.paths.clerkStamps;
  d.subjectLog.chainBoundary.retiredPath.value = `${STATE_PREFIX}/${RETIRED_NAME}`;
  d.subjectLog.chainBoundary.retiredRecords.value = 1;
  d.subjectLog.chainBoundary.retiredBytes.value = Buffer.byteLength(RETIRED_BODY);
  d.subjectLog.chainBoundary.retiredSha256.value = createHash("sha256").update(RETIRED_BODY).digest("hex");
  d.subjects = [{ subject: R_SUBJECT, toolName: R_TOOL, stakesClass: R_TOOL, peerUid: R_UID, unit: R_UNIT }];
  d.routes = [{ uid: R_UID, role: "subject", allow: [{ method: "POST", path: "/subject-events" }, { method: "POST", path: "/guard" }, { method: "GET", path: "/status" }] }];
  d.frame = {
    [R_SUBJECT]: {
      categories: env([
        { id: "y-desk", label: "the surveyor's own desk", grounding: "agency", self: true },
        { id: "y-archive", label: "an archive kept for others", grounding: "vulnerability", self: false },
        { id: "y-commons", label: "the commons", grounding: "need", self: false },
      ]),
      regions: env([
        { prefix: join(places, "desk"), category: "y-desk" },
        { prefix: join(places, "archive"), category: "y-archive" },
        { prefix: places, category: "y-commons" },
      ]),
    },
  };
  if (mode === "chain") {
    // THE SWITCH ALONE REMOVED: the same frame, Gate 2 on the CHAIN with a phase-R basket over chain kinds.
    const unknown = ["TOOL_RESULT", "HELD_THEN_RETRIED"].map((kind) => ({ kind, outcome: null, lane: "A", eg: 1, bearsOn: ["y-desk"], basis: "REHEARSAL chain-basket class" }));
    d.baskets = {
      [R_SUBJECT]: {
        classes: env({ value: [], damage: [], unknown }),
        epsilonNum: { value: 1e-6, basis: "REHEARSAL", proxy: false },
        grades: env({ establishAt: { lane: "A", eg: 1 }, creditAt: { lane: "B", eg: 2 } }),
        window: { value: { kind: "sinceBoundary" }, basis: "REHEARSAL", proxy: false },
        nMin: env(3),
        latchClearedBy: { value: [{ kind: "ARBITER_RESOLVED" }], basis: "REHEARSAL", proxy: false },
      },
    };
    d.readers.gate2Direction = { subject: { value: R_SUBJECT, basis: "REHEARSAL", proxy: false } };
  } else if (mode === "book") {
    const unknown = ["y-desk:FIRST_SEEN", "y-desk:SAME", "y-desk:CONTENT_DIFFERS", "y-desk:EXISTENCE_DIFFERS", "y-desk:META_DIFFERS", "y-desk:UNOBSERVABLE", "y-desk:HELD", "y-desk:LATE", "y-archive:FIRST_SEEN", "y-archive:HELD", "y-archive:LATE", "y-archive:EXISTENCE_DIFFERS"].map((outcome) => ({
      kind: "CONSEQUENCE", outcome, lane: "A", eg: 1, bearsOn: [outcome.slice(0, outcome.indexOf(":"))], basis: "REHEARSAL phase-R class",
    }));
    d.baskets = {
      [R_SUBJECT]: {
        classes: env({ value: [], damage: [], unknown }),
        epsilonNum: { value: 1e-6, basis: "REHEARSAL", proxy: false },
        grades: env({ establishAt: { lane: "A", eg: 1 }, creditAt: { lane: "B", eg: 2 } }),
        window: { value: { kind: "sinceBoundary" }, basis: "REHEARSAL", proxy: false },
        nMin: env(3),
        latchClearedBy: { value: [{ kind: "ARBITER_RESOLVED" }], basis: "REHEARSAL", proxy: false },
      },
    };
    d.readers.gate2Direction = {
      subject: { value: R_SUBJECT, basis: "REHEARSAL", proxy: false },
      book: { value: "witnessBook", basis: "REHEARSAL", proxy: false },
      witnessMethod: { value: SEEING_METHOD_DIGEST, basis: "REHEARSAL", proxy: false },
    };
  } else {
    delete d.readers.gate2Direction;
    delete d.baskets;
  }
  if (withWitness) {
    d.paths.witnessIntake = { value: W_INTAKE_DECL, basis: W_BASIS };
    d.paths.witnessBook = { value: W_BOOK_DECL, basis: W_BASIS };
  } else {
    delete d.paths.witnessIntake;
    delete d.paths.witnessBook;
  }
  return d;
}

// ── a scripted guard adapter: the decision the bridge records, per act ──────
const PLAN = new Map<string, boolean>(); // actionId -> execute
const DECIDED = new Map<string, { execute: boolean; decisionHash: string }>(); // `${sessionId}/${actionId}` -> first decision
let decisionSeq = 0;
const scriptedAdapter = {
  async evaluate(req: any) {
    const execute = PLAN.get(req.actionId) ?? true;
    const decisionHash = createHash("sha256").update(`rehearsal:${req.sessionId}:${req.actionId}:${String(++decisionSeq)}`).digest("hex");
    const k = `${req.sessionId}/${req.actionId}`;
    if (!DECIDED.has(k)) DECIDED.set(k, { execute, decisionHash });
    // THE REAL DECISION SHAPE (evaluate-and-record.ts): these keys, and no `at` (refuter A-F1).
    return {
      bound: true, httpStatus: 200,
      decision: {
        identity: { subject: req.subject, sessionId: req.sessionId, actionId: req.actionId },
        disposition: execute ? "PASS_BLIND" : "HOLD_BLIND", execute, floorKind: null, blindSplit: null, narrowed: false,
        rationale: "rehearsal", findings: [], blindPaths: [], readings: [], bindingMinimum: null, sigF3: null,
        seq: decisionSeq, declarationBinding: null, decisionHash,
      },
      delivery: {}, readerFootings: [], readerFootingsBasis: { kind: "NO_READING_TAKEN", reason: "rehearsal adapter" }, quarantined: [],
    };
  },
};

function request(sock: string, method: "GET" | "POST", path: string, text?: string): Promise<{ status: number; body: any }> {
  return new Promise((res, rej) => {
    const headers: Record<string, string | number> = text === undefined ? {} : { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(text) };
    const r = http.request({ socketPath: sock, path, method, agent: false, timeout: 5000, headers }, (resp) => {
      let s = ""; resp.on("data", (c) => (s += c));
      resp.on("end", () => { let j: any = s; try { j = JSON.parse(s); } catch { /* text */ } res({ status: resp.statusCode ?? 0, body: j }); });
    });
    r.on("error", rej); r.on("timeout", () => r.destroy(new Error("timeout")));
    if (text !== undefined) r.write(text);
    r.end();
  });
}
function post(sock: string, actionId: string, kind: string, payload: any, target?: string, sessionId = "rehearsal") {
  const identity = { subject: R_SUBJECT, sessionId, actionId };
  const body: any = { identity, kind, eventHash: canonicalHash({ identity, kind, payload }), payload };
  if (target !== undefined) body.targetIdentity = target;
  return request(sock, "POST", "/subject-events", JSON.stringify(body));
}
const guard = (sock: string, actionId: string, sessionId = "rehearsal") => request(sock, "POST", "/guard", JSON.stringify({ subject: R_SUBJECT, sessionId, actionId, toolName: R_TOOL }));

interface Run { decl: any; cfgPath: string; socketDir: string; stateDir: string; sock: string; svc: any; intake: string }
function layRun(tag: string, decl: any, intake: string): Run {
  const socketDir = relative(work, mkdtempSync(join(work, `k${tag}`)));
  const peer = join(socketDir, "peers", String(R_UID)); mkdirSync(peer, { recursive: true }); chmodSync(peer, 0o770);
  const cfgDir = mkdtempSync(join(work, `cfg${tag}-`));
  const stateDir = mkdtempSync(join(work, `state${tag}-`));
  writeFileSync(join(stateDir, RETIRED_NAME), RETIRED_BODY);
  const cfgPath = join(cfgDir, "declarations.config.json");
  writeFileSync(cfgPath, JSON.stringify(decl));
  return { decl, cfgPath, socketDir, stateDir, sock: join(peer, "guard.sock"), svc: null, intake };
}
const NO_DOOR = () => { throw new Error("rehearsal: the core door is not read"); };
async function start(run: Run) {
  run.svc = new MicaBridgeService({
    declarationsPath: run.cfgPath, socketDir: run.socketDir, now: () => NOW, testBridgeGid: R_GID, stateDir: run.stateDir,
    doorModuleLoader: NO_DOOR, guardAdapter: scriptedAdapter, testWritablePaths: { witnessIntake: run.intake },
  });
  await run.svc.start();
}
async function stop(run: Run) { try { await run.svc.stop(); } catch { /* reported by the checks */ } }

(async () => {
  console.log(`REHEARSAL (witness) in ${work}`);
  const intake = join(work, "w-intake"); mkdirSync(intake);
  const wstate = join(work, "w-state"); mkdirSync(wstate);
  const bookDir = join(work, "w-book"); mkdirSync(bookDir);
  const book = join(bookDir, "book-of-effects.jsonl");
  const witness = new SeeingWitness({ intakeDir: intake, bookPath: book, stateDir: wstate, log: () => undefined });
  const declA = rehearsalDeclaration("book", true);
  const A = layRun("A", declA, intake);
  await start(A);

  // the targets
  const T = {
    report: join(places, "archive", "report.txt"),
    notes: join(places, "desk", "notes.txt"),
    ledger: join(places, "archive", "ledger.txt"),
    fresh: join(places, "desk", "fresh.txt"),
    gone: join(places, "archive", "gone.txt"),
    a: join(places, "desk"),
    b: join(places, "archive", "b2.txt"),
    dupX: join(places, "desk", "dup-x.txt"),
    dupY: join(places, "archive", "dup-y.txt"),
    early: join(places, "desk", "early.txt"),
  };
  for (const f of [T.gone, T.b, T.dupX]) writeFileSync(f, "before");

  const responses: any[] = [];
  /** One act the way the caller runs it: ATTEMPT (drained) → the witness looks → /guard → effect if run → results → close. */
  async function act(id: string, target: string | undefined, effect: () => void, execute: boolean, opts: { skipGuard?: boolean; sessionId?: string } = {}) {
    const sid = opts.sessionId ?? "rehearsal";
    PLAN.set(id, execute);
    let run = execute;
    responses.push(await post(A.sock, id, "TOOL_ATTEMPTED", { toolName: R_TOOL }, target, sid));
    witness.sweep(); // no look at ATTEMPT (phase R)
    if (!opts.skipGuard) {
      const g = await guard(A.sock, id, sid);
      responses.push(g);
      run = g.body?.decision?.execute === true;
    }
    if (run) {
      effect();
      // the caller's fail-open says so on its TOOL_EXECUTED (guard:UNAVAILABLE), as the live client does
      responses.push(await post(A.sock, id, "TOOL_EXECUTED", opts.skipGuard ? { toolName: R_TOOL, guard: "UNAVAILABLE" } : { toolName: R_TOOL }, undefined, sid));
      responses.push(await post(A.sock, id, "TOOL_RESULT", { exitClass: "OK" }, undefined, sid));
    } else {
      // a held act reports its fate as the live client does (its outbox's TOOL_HELD_NOT_EXECUTED)
      responses.push(await post(A.sock, id, "TOOL_HELD_NOT_EXECUTED", { reason: "HOLD" }, undefined, sid));
    }
    responses.push(await post(A.sock, id, "ACT_CLOSED", { closedAs: run ? "RAN" : "HELD" }, undefined, sid));
    witness.sweep();
  }

  // The SAME target (notes) across four acts, so the facets are read against the witness's own last look:
  await act("a1", T.notes, () => writeFileSync(T.notes, "v1"), true);          // FIRST_SEEN (the witness never saw notes)
  await act("a2", T.notes, () => writeFileSync(T.notes, "v2, longer"), true);  // CONTENT_DIFFERS (changed since a1)
  await act("a3", T.notes, () => undefined, false);                            // HELD (bridge said no); the look is SAME
  await act("a4", T.notes, () => unlinkSync(T.notes), true);                   // EXISTENCE_DIFFERS (gone since a3's look)
  await act("a5", undefined, () => undefined, true);                           // no target: no pointer
  await act("a6", "/opt/rehearsal-unmapped/x", () => undefined, true);         // outside every region: UNDERIVED, no pointer
  await act("a7", T.gone, () => unlinkSync(T.gone), true, { skipGuard: true });// fail-open: ran with no decision → LATE
  await act("a8", T.a, () => unlinkSync(T.b), true);                           // `cd A && rm B`: claims the desk dir, touches an archive file
  await act("dup", T.dupX, () => unlinkSync(T.dupX), true, { sessionId: "rehearsal-x" }); // two sessions, ONE actionId (B M1):
  await act("dup", T.dupY, () => undefined, false, { sessionId: "rehearsal-y" });          //   two acts, two records (dupY HELD)

  const events = readFileSync(book, "utf8").trim().split("\n").map((l) => JSON.parse(l)).filter((r) => r.recordType === "SUBJECT_EVENT");
  const byAct = new Map(events.map((e: any) => [e.actionId === "dup" ? `dup/${e.witnessed.cites.sessionId}` : e.actionId, e]));
  const cls = consequenceEventType(frameLabelEventType(validateDeclarations(declA, NOW).declarations.frame[R_SUBJECT]));

  await check("W-1 · every response was 200 and the bridge's drops all reached the witness (the intake is empty)", () => {
    const bad = responses.filter((r) => r.status !== 200);
    ok(bad.length === 0, `non-200: ${JSON.stringify(bad.slice(0, 3))}`);
    ok(readdirSync(intake).length === 0, `intake not empty: ${readdirSync(intake).join(",")}`);
  });
  await check("W-2 · the book VERIFIES and holds exactly the eight acts with a placed target (a5 no target, a6 UNDERIVED: no record); the two 'dup' acts are TWO", () => {
    ok(new SubjectChainLog({ path: book }).getLoadState() === LOADED_SUBJECT_CHAIN_VERIFIED, "load state");
    ok(events.length === 8, `records ${events.length}`);
    ok(JSON.stringify([...byAct.keys()].sort()) === JSON.stringify(["a1", "a2", "a3", "a4", "a7", "a8", "dup/rehearsal-x", "dup/rehearsal-y"]), `acts ${[...byAct.keys()].join(",")}`);
    ok(events.every((e: any) => e.eventType === cls && e.moduleId === R_SUBJECT), "class and subject");
    ok(cls === witnessRecordClass(SEEING_METHOD_DIGEST, frameLabelEventType(validateDeclarations(declA, NOW).declarations.frame[R_SUBJECT])), "the bridge and the witness name the same class");
  });
  await check("W-3 · the facets, SINCE THE WITNESS LAST LOOKED (held acts HELD, the fail-open act LATE — audit 09:32Z)", () => {
    const want: Record<string, string> = {
      a1: "y-desk:FIRST_SEEN", a2: "y-desk:CONTENT_DIFFERS", a3: "y-desk:HELD", a4: "y-desk:EXISTENCE_DIFFERS",
      a7: "y-archive:LATE", a8: "y-desk:FIRST_SEEN",
      "dup/rehearsal-x": "y-desk:FIRST_SEEN", "dup/rehearsal-y": "y-archive:HELD",
    };
    for (const [a, o] of Object.entries(want)) ok((byAct.get(a) as any)?.outcome === o, `${a}: ${(byAct.get(a) as any)?.outcome} ≠ ${o}`);
    // the look's own facet rides beside a HELD outcome: a3's look saw the desk UNCHANGED since a2
    ok((byAct.get("a3") as any).witnessed.observed === "SAME", `a3 observed ${(byAct.get("a3") as any).witnessed.observed}`);
  });
  await check("W-4 · the fate cites the /guard decision where there is one; the held act's fate is HELD; the fail-open act is LATE, no decision", () => {
    for (const [a, sid] of [["a1", "rehearsal"], ["a2", "rehearsal"], ["a4", "rehearsal"], ["a8", "rehearsal"], ["dup/rehearsal-x", "rehearsal-x"]]) {
      const w = (byAct.get(a) as any).witnessed;
      const aid = a.startsWith("dup/") ? "dup" : a;
      ok(w.fate === "RAN", `${a}: fate ${w.fate}`);
      ok(w.cites.decisionHash === DECIDED.get(`${sid}/${aid}`)!.decisionHash, `${a}: decision hash not carried`);
      ok(w.priorLookAt === null || typeof w.priorLookAt === "number", `${a}: priorLookAt`);
    }
    ok((byAct.get("a3") as any).witnessed.fate === "HELD", "a3 fate HELD");
    ok((byAct.get("dup/rehearsal-y") as any).witnessed.fate === "HELD", "dupY fate HELD");
    const a7 = (byAct.get("a7") as any).witnessed;
    ok(a7.cites.decisionHash === null && a7.fate === "LATE_UNGUARDED", `a7: ${JSON.stringify(a7.cites.decisionHash)} ${a7.fate}`);
    // a2 compared to a1's look: priorLookAt is a1's close time
    ok((byAct.get("a2") as any).witnessed.priorLookAt === (byAct.get("a1") as any).witnessed.clockAt, "a2 compared to a1's look");
  });
  await check("W-5 · THE CEILING, DEMONSTRATED: a8 claimed the desk and deleted an archive file; the book records only the desk (FIRST_SEEN) and nothing of the archive file", () => {
    ok(!existsSync(T.b), "fixture: b2 was deleted");
    const a8 = byAct.get("a8") as any;
    ok(a8.outcome === "y-desk:FIRST_SEEN", a8.outcome);
    ok(!readFileSync(book, "utf8").includes("b2.txt"), "no word of the touched file");
  });
  await check("W-6 · no plain target in the book; the witness's private state (0600) holds them", () => {
    const bytes = readFileSync(book, "utf8");
    for (const f of Object.values(T)) ok(!bytes.includes(f), `the book carries ${f}`);
    ok((statSync(join(wstate, "state.json")).mode & 0o777) === 0o600, "state mode");
    ok(readFileSync(join(wstate, "state.json"), "utf8").includes("notes.txt"), "the state keeps its targets");
  });

  // ── Gate 2 on the book, through the bridge's own toWireOptions and the worktree's wire() ──
  const loadedA = validateDeclarations(declA, NOW).declarations;
  const resolveA = (p: string) => (p === W_BOOK_DECL ? book : p.replace(/^\/var\/lib\/mica-bridge/, A.stateDir));
  const optsA = toWireOptions(loadedA, resolveA, () => []);
  const wA = wire(optsA);
  await check("W-7 · Gate 2 reads the WITNESS'S BOOK: wired, CANNOT_ASSESS · G2_NO_CLASS_AT_GRADE, the book's footing, coverage 9 of 11 with its footing, the book's ceiling printed", () => {
    const row = wA.census.readers.find((r: any) => r.reader === GATE2_READER);
    ok(row.wired === true && row.verdictKind === "CANNOT_ASSESS", JSON.stringify(row).slice(0, 300));
    ok(row.source.startsWith(GATE2_BOOK_SOURCE_PREFIX), row.source.slice(0, 200));
    ok(row.source.includes("G2_NO_CLASS_AT_GRADE"), "code");
    ok(row.source.includes("the book holds a record for 8 act(s) under this basket's class — 8 of the subject log's 10 TOOL_ATTEMPTED act(s)."), row.source);
    ok(row.source.includes("by facet CONTENT_DIFFERS=1 EXISTENCE_DIFFERS=1 FIRST_SEEN=3 HELD=2 LATE=1. FOOTING: FIRST_SEEN 3 (no last look to compare); UNOBSERVABLE 0; FIRST_SEEN on a target already in the book (re-seen after the witness forgot it): 0."), row.source);
    ok(row.source.includes("Records citing another subject chain (before a rotation), not counted: 0."), "the chain matched");
    ok(gate2Of(wA).summary.endsWith(GATE2_BOOK_CEILING), "the ceiling on the verdict's own face");
    ok(row.source.includes("Of the 8 act(s) the interest book placed in a frame category (the acts pointed to the witness), 8 have a record."), row.source);
    ok(row.source.endsWith(GATE2_BOOK_CEILING), "the book's ceiling closes the row");
    const f = footingsFromWiring(wA).find((x: any) => x.reader === GATE2_READER);
    ok(f && f.loadState === LOADED_SUBJECT_CHAIN_VERIFIED, `footing ${JSON.stringify(f)}`);
  });

  // ── REMOVAL ──────────────────────────────────────────────────────────────
  const others = (w: any) => w.sensorVerdicts.filter((v: any) => v.sensorId !== GATE2_READER);
  const rows = (w: any) => w.census.readers.filter((r: any) => r.reader !== GATE2_READER);
  const resolveState = (p: string) => p.replace(/^\/var\/lib\/mica-bridge/, A.stateDir);
  const wChain = wire(toWireOptions(validateDeclarations(rehearsalDeclaration("chain", true), NOW).declarations, resolveState, () => []));
  await check("W-8 · REMOVAL 1a: THE SWITCH ALONE removed — Gate 2 back on the CHAIN with a chain basket; every other reader byte-identical", () => {
    const row = wChain.census.readers.find((r: any) => r.reader === GATE2_READER);
    ok(row.wired === true && !row.source.startsWith(GATE2_BOOK_SOURCE_PREFIX), `Gate 2 on the chain: ${row.source.slice(0, 160)}`);
    ok(wChain.gate2ReadsBook === false, "gate2ReadsBook");
    ok(JSON.stringify(others(wChain)) === JSON.stringify(others(wA)), "a sibling's verdict moved");
    ok(JSON.stringify(rows(wChain)) === JSON.stringify(rows(wA)), "a sibling's census row moved");
  });
  const wNo = wire(toWireOptions(validateDeclarations(rehearsalDeclaration("none", true), NOW).declarations, resolveState, () => []));
  await check("W-8b · REMOVAL 1b: the switch and basket removed — Gate 2 is not declared, and every other reader reads byte-identically", () => {
    ok(JSON.stringify(others(wNo)) === JSON.stringify(others(wA)), "a sibling's verdict moved");
    ok(JSON.stringify(rows(wNo)) === JSON.stringify(rows(wA)), "a sibling's census row moved");
    ok(wNo.census.readers.find((r: any) => r.reader === GATE2_READER).wired === false, "Gate 2 vacant");
  });
  await stop(A);
  // REMOVAL 2, BY RELOAD of a running bridge: the witness's paths are read per act (W5 removed), so a
  // SIGHUP that drops them stops the drops at the next act — no restart, nothing else moves.
  const intakeB = join(work, "w-intake-B"); mkdirSync(intakeB);
  const B = layRun("B", rehearsalDeclaration("none", true), intakeB);
  await start(B);
  writeFileSync(T.notes, "x");
  const rb1 = await post(B.sock, "b1", "TOOL_ATTEMPTED", { toolName: R_TOOL }, T.notes);
  const beforeReload = readdirSync(intakeB).length;
  writeFileSync(B.cfgPath, JSON.stringify(rehearsalDeclaration("none", false)));
  const reloaded = B.svc.reload();
  const rb2 = await post(B.sock, "b2", "TOOL_ATTEMPTED", { toolName: R_TOOL }, T.notes);
  await post(B.sock, "b1", "ACT_CLOSED", { closedAs: "HELD" });
  await post(B.sock, "b2", "ACT_CLOSED", { closedAs: "HELD" });
  await stop(B);
  await check("W-9 · REMOVAL 2 BY RELOAD: one ATTEMPT before the reload; after it the bridge accepts every act and drops NOTHING (the open act closes by the witness's timeout)", () => {
    ok(rb1.status === 200 && rb2.status === 200, `status ${rb1.status} ${rb2.status}`);
    ok(beforeReload === 1, `before the reload: ${beforeReload}`);
    ok(reloaded.ok === true, `reload: ${JSON.stringify(reloaded)}`);
    ok(readdirSync(intakeB).length === 1, `dropped after the reload: ${readdirSync(intakeB).join(",")}`);
  });

  // ── the literal fence ─────────────────────────────────────────────────────
  await check("W-10 · THE LITERAL FENCE: no served name in the book, the witness's state, the declarations, the options or the output", () => {
    const found = [
      ...leaks("book", readFileSync(book, "utf8")),
      ...leaks("witness state", readFileSync(join(wstate, "state.json"), "utf8")),
      ...leaks("declaration A", JSON.stringify(declA)),
      ...leaks("options A", JSON.stringify(optsA)),
      ...leaks("census A", JSON.stringify(wA.census)),
      ...leaks("output", captured),
    ];
    ok(found.length === 0, found.slice(0, 5).join("\n"));
  });

  console.log(`\n${passed + failed} tests: ${passed} passed, ${failed} failed`);
  // ARCHIVED, never deleted (Gate-1 brief §4): the region tree moves beside its predecessors.
  const archive = join(PLACES_PARENT, "rehearsal-archive"); mkdirSync(archive, { recursive: true });
  renameSync(places, join(archive, places.split("/").pop()!));
  process.exit(failed > 0 ? 1 : 0);
})().catch((e) => { console.log(`REHEARSAL THREW: ${(e as Error).stack}`); process.exit(2); });
