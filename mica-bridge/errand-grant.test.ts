// S208-2 · the errand grant at the bridge: the writer's refusals and the chain derivation, as pure functions.
// RELAY 3: the kinds are HELD (no hand writes them); the writer's checks stay as pure arms, the reader is fed fixture records.
//   node <ts-node bin.js> -T -P mica-bridge/tsconfig.json mica-bridge/errand-grant.test.ts
// Fixture names only: subject-e, o-e, i-a (c-other), i-b (c-shared), i-ctl (control), c-other/c-shared/c-self.
import { shippedDraft } from "./example-draft";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "fs";
import { createHash } from "crypto";
import { tmpdir } from "os";
import { join } from "path";
import {
  authorizeSubjectEventKind,
  ChainedSubjectAppender,
  deriveErrandGrants,
  ERRAND_KINDS,
  GATE4_INVOCATION_KIND,
  GATE4_PAPER_ROLE_KINDS,
  GATE4_RESPONSE_ROLE_KINDS,
  MicaBridgeService,
  OPERATOR_SUNSET_KINDS,
  SUBJECT_EVENT_KINDS,
  validateErrandRecord,
} from "./mica-service";
import { canonicalHash } from "./canonical-json";
import { gate2WireHarm } from "./to-wire-options";
import type { SubjectHarm } from "./declarations";

let passed = 0;
let failed = 0;
function check(name: string, fn: () => void): void {
  try {
    fn();
    passed++;
    console.log(`PASS  ${name}`);
  } catch (e) {
    failed++;
    console.log(`FAIL  ${name}\n      ${(e as Error).message}`);
  }
}
function assert(c: unknown, m: string): asserts c {
  if (!c) throw new Error(`assertion failed: ${m}`);
}

const S = "subject-e";
const NOW = Date.parse("2030-01-01T00:00:00Z");
const iso = (ms: number) => new Date(ms).toISOString();
const B = "fixture basis";
function harm(errand = true): SubjectHarm {
  return {
    harmOnly: { value: true, basis: B, proxy: false },
    origins: { value: { "o-e": { subject: S, basis: B } }, basis: B, proxy: false },
    items: {
      value: {
        "i-a": { path: "/srv/x/a", category: "c-other", control: false, basis: B },
        "i-b": { path: "/srv/x/b", category: "c-shared", control: false, basis: B },
        "i-ctl": { path: "/srv/x/c", category: "c-other", control: true, basis: B },
      },
      basis: B,
      proxy: false,
    },
    grants: { value: { "i-a": { origins: [], since: {}, basis: B }, "i-b": { origins: [], since: {}, basis: B }, "i-ctl": { origins: [], since: {}, basis: B } }, basis: B, proxy: false },
    clearances: { value: [], basis: B, proxy: false },
    ...(errand ? { errand: { value: { categories: ["c-other"], maxWindowMinutes: 60 }, basis: B, proxy: false } } : {}),
  } as SubjectHarm;
}
function grant(id: string, items: string, from: number, until: number) {
  return { errandId: id, items, from: iso(from), until: iso(until), basis: "an errand of the arbiter's" };
}
let recSeq = 0;
function rec(kind: string, payload: Record<string, unknown>, timestamp = NOW, subject = S) {
  return { kind, payload, timestamp, identity: { subject }, subjectSeq: ++recSeq, peerUid: 1000 };
}
const v = (kind: "ERRAND_GRANTED" | "ERRAND_CLOSED", p: Record<string, unknown> | null, records: unknown[] = [], h: SubjectHarm | undefined = harm(), now = NOW, bookFloorAt: number | null = null) =>
  validateErrandRecord(kind, p as never, S, h, records as never, now, bookFloorAt);

check("WRITER · a well-formed errand on a non-control item of an envelope category, starting now, within the window → ADMITTED", () => {
  assert(v("ERRAND_GRANTED", grant("e-1", "i-a", NOW, NOW + 3600e3)).ok, "refused");
});

check("WRITER · REFUSED: no envelope, an undeclared item, a control item, a category the envelope does not list, a repeat item, extra or missing keys", () => {
  const cases: [string, ReturnType<typeof v>, RegExp][] = [
    ["no envelope", v("ERRAND_GRANTED", grant("e-1", "i-a", NOW, NOW + 60e3), [], harm(false)), /declares no errand envelope/],
    ["undeclared item", v("ERRAND_GRANTED", grant("e-1", "i-z", NOW, NOW + 60e3)), /not a declared harm item/],
    ["control item", v("ERRAND_GRANTED", grant("e-1", "i-ctl", NOW, NOW + 60e3)), /CONTROL item/],
    ["category not listed", v("ERRAND_GRANTED", grant("e-1", "i-b", NOW, NOW + 60e3)), /does not list/],
    ["repeat item", v("ERRAND_GRANTED", grant("e-1", "i-a,i-a", NOW, NOW + 60e3)), /distinct/],
    ["extra key", v("ERRAND_GRANTED", { ...grant("e-1", "i-a", NOW, NOW + 60e3), x: 1 }), /exactly/],
    ["missing basis", v("ERRAND_GRANTED", { errandId: "e-1", items: "i-a", from: iso(NOW), until: iso(NOW + 60e3) }), /exactly/],
  ];
  for (const [name, r, re] of cases) assert(!r.ok && re.test(r.detail), `${name}: ${JSON.stringify(r)}`);
});

check("WRITER · REFUSED: a BACK-DATED from (it would grant changes already on the book and end a latch without a clearance), an empty or over-long window, a bad instant", () => {
  const back = v("ERRAND_GRANTED", grant("e-1", "i-a", NOW - 1, NOW + 60e3));
  assert(!back.ok && /in the past/.test(back.detail), JSON.stringify(back));
  const empty = v("ERRAND_GRANTED", grant("e-1", "i-a", NOW, NOW));
  assert(!empty.ok && /after from/.test(empty.detail), JSON.stringify(empty));
  const long = v("ERRAND_GRANTED", grant("e-1", "i-a", NOW, NOW + 3600e3 + 1));
  assert(!long.ok && /60 minutes/.test(long.detail), JSON.stringify(long));
  const badi = v("ERRAND_GRANTED", { ...grant("e-1", "i-a", NOW, NOW + 60e3), from: "2030-01-01 00:00:00Z" });
  assert(!badi.ok && /UTC instants/.test(badi.detail), JSON.stringify(badi));
});

check("RELAY 3 · F1(b) · AS S216-2 CLAMPS FIRST SIGHT: the bridge clock is fine (from is not in the past) but a record NEWER than from is in the books the bridge reads → REFUSED, naming the newest record's instant", () => {
  const floor = NOW + 5000;
  const r = v("ERRAND_GRANTED", grant("e-1", "i-a", NOW + 1000, NOW + 60e3), [], harm(), NOW, floor);
  assert(!r.ok && /earlier than the newest record in the books the bridge reads/.test(r.detail) && r.detail.includes(iso(floor)), JSON.stringify(r));
  const oneMs = v("ERRAND_GRANTED", grant("e-1", "i-a", floor - 1, floor + 60e3), [], harm(), NOW, floor);
  assert(!oneMs.ok && oneMs.detail.includes(iso(floor)), `one ms before the newest record was admitted: ${JSON.stringify(oneMs)}`);
});

check("RELAY 3 · F1(b) · CONTROL: from AT or AFTER the newest record in the books → ADMITTED; no record read (null) → the clock alone decides", () => {
  const floor = NOW + 5000;
  assert(v("ERRAND_GRANTED", grant("e-1", "i-a", floor, floor + 60e3), [], harm(), NOW, floor).ok, "from at the newest record was refused");
  assert(v("ERRAND_GRANTED", grant("e-1", "i-a", floor + 1, floor + 60e3), [], harm(), NOW, floor).ok, "from after the newest record was refused");
  assert(v("ERRAND_GRANTED", grant("e-1", "i-a", NOW + 1000, NOW + 60e3), [], harm(), NOW, null).ok, "no floor, a from in the future was refused");
  assert(v("ERRAND_GRANTED", grant("e-1", "i-a", NOW, NOW + 60e3), [], harm(), NOW, NOW - 1).ok, "a floor behind the clock refused a from at now");
});

check("WRITER · REFUSED: a reused id, and a second errand open across the window (ambiguity); ADMITTED once the first is closed before it", () => {
  const first = [rec("ERRAND_GRANTED", grant("e-1", "i-a", NOW, NOW + 3600e3))];
  const reuse = v("ERRAND_GRANTED", grant("e-1", "i-a", NOW + 3600e3, NOW + 7200e3), first);
  assert(!reuse.ok && /used once/.test(reuse.detail), JSON.stringify(reuse));
  const overlap = v("ERRAND_GRANTED", grant("e-2", "i-a", NOW + 60e3, NOW + 120e3), first);
  assert(!overlap.ok && /open or pending/.test(overlap.detail), JSON.stringify(overlap));
  const closed = [...first, rec("ERRAND_CLOSED", { errandId: "e-1" }, NOW + 30e3)];
  assert(v("ERRAND_GRANTED", grant("e-2", "i-a", NOW + 60e3, NOW + 120e3), closed, harm(), NOW + 60e3).ok, "refused after the close");
});

check("WRITER · ERRAND_CLOSED names an errand of this subject that is open now; else REFUSED", () => {
  const first = [rec("ERRAND_GRANTED", grant("e-1", "i-a", NOW, NOW + 3600e3))];
  assert(v("ERRAND_CLOSED", { errandId: "e-1" }, first, harm(), NOW + 10).ok, "refused an open errand's close");
  const none = v("ERRAND_CLOSED", { errandId: "e-9" }, first);
  assert(!none.ok && /no errand/.test(none.detail), JSON.stringify(none));
  const over = v("ERRAND_CLOSED", { errandId: "e-1" }, first, harm(), NOW + 3600e3);
  assert(!over.ok && /not open/.test(over.detail), JSON.stringify(over));
  const other = v("ERRAND_CLOSED", { errandId: "e-1" }, [rec("ERRAND_GRANTED", grant("e-1", "i-a", NOW, NOW + 3600e3), NOW, "subject-other")]);
  assert(!other.ok, "another subject's errand was closable");
});

check("DERIVE · grants in chain order; a close cuts its grant's window at the close's own timestamp; another subject's records are not this subject's", () => {
  const g = deriveErrandGrants([
    rec("ERRAND_GRANTED", grant("e-1", "i-a", NOW, NOW + 3600e3)),
    rec("ERRAND_GRANTED", grant("e-x", "i-a", NOW, NOW + 3600e3), NOW, "subject-other"),
    rec("ERRAND_CLOSED", { errandId: "e-1" }, NOW + 600e3),
  ] as never, S, "o-e");
  assert(g.length === 1 && g[0].errandId === "e-1" && g[0].origin === "o-e" && g[0].items.join() === "i-a", JSON.stringify(g));
  assert(g[0].until.at === NOW + 600e3 && g[0].until.utc === iso(NOW + 600e3) && g[0].from.at === NOW, JSON.stringify(g[0]));
});

// RELAY 3 · THE HOLD (audit 2026-10-18 19:22Z (1), option (iii)): was "operator-only (until S217's arbiter route)".
const HOLD_RE = /HELD OUT OF RELAY 3: no hand writes it[\s\S]*S217-a's arbiter route[\s\S]*shared by the build seats/;
check("ROLE · RELAY 3 HOLD: the two errand kinds are REFUSED TO EVERY HAND — operator, subject, an unknown role, a uid with no route row — and the reason names the hold", () => {
  const routes = [{ uid: 980, role: "subject" }, { uid: 1000, role: "operator" }, { uid: 77, role: "auditor" }];
  for (const k of ERRAND_KINDS) {
    for (const uid of [1000, 980, 77, 4242]) {
      const r = authorizeSubjectEventKind(routes, uid, k);
      assert(!r.allowed, `${k}: uid ${uid} may write it`);
      assert(!r.allowed && HOLD_RE.test(r.reason) && r.reason.includes(k) && r.reason.includes(`uid ${uid}`), `${k}, uid ${uid}: the refusal does not name the hold: ${JSON.stringify(r)}`);
    }
  }
});

check("ROLE · RELAY 3 HOLD, CONTROLS: the operator still writes DOCTOR_ATTESTED and the seven gate-4 governance kinds; the subject still writes every one of its own kinds; neither writes the other's", () => {
  const routes = [{ uid: 980, role: "subject" }, { uid: 1000, role: "operator" }];
  const opKinds = ["DOCTOR_ATTESTED", ...OPERATOR_SUNSET_KINDS];
  assert(OPERATOR_SUNSET_KINDS.length === 7, `the gate-4 governance kinds are ${String(OPERATOR_SUNSET_KINDS.length)}, not seven`);
  let subjectOwn = 0;
  for (const k of SUBJECT_EVENT_KINDS) {
    const op = authorizeSubjectEventKind(routes, 1000, k);
    const sub = authorizeSubjectEventKind(routes, 980, k);
    if (ERRAND_KINDS.includes(k)) {
      assert(!op.allowed && !sub.allowed, `${k}: a hand may write a held kind`);
    } else if (opKinds.includes(k)) {
      assert(op.allowed, `${k}: the operator may no longer write it: ${JSON.stringify(op)}`);
      assert(!sub.allowed && !HOLD_RE.test(sub.reason), `${k}: the subject may write it, or its refusal reads as the errand hold`);
    } else {
      subjectOwn++;
      assert(sub.allowed, `${k}: the subject may no longer write its own kind: ${JSON.stringify(sub)}`);
      assert(!op.allowed && !HOLD_RE.test(op.reason) && !/errand/.test(op.reason), `${k}: the operator may write it, or its refusal still advertises errands: ${JSON.stringify(op)}`);
    }
  }
  assert(subjectOwn === SUBJECT_EVENT_KINDS.length - opKinds.length - ERRAND_KINDS.length && subjectOwn > 0, `the subject's own kinds counted ${String(subjectOwn)}`);
});

check("REFUTER · a close BEFORE from is a CANCEL: derive drops the errand, never emits an empty window (which the machine refuses whole)", () => {
  const recs = [rec("ERRAND_GRANTED", grant("e-1", "i-a", NOW + 1800e3, NOW + 3600e3)), rec("ERRAND_CLOSED", { errandId: "e-1" }, NOW + 60e3)];
  assert(v("ERRAND_CLOSED", { errandId: "e-1" }, recs.slice(0, 1), harm(), NOW + 60e3).ok, "a pending errand could not be cancelled");
  const g = deriveErrandGrants(recs as never, S, "o-e", harm());
  assert(g.length === 0, `a cancelled errand was derived: ${JSON.stringify(g)}`);
  for (const x of deriveErrandGrants(recs as never, S, "o-e")) assert(x.until.at > x.from.at, "an empty window was derived");
});

check("REFUTER · NO PRE-BOOKING: from more than one envelope window ahead is REFUSED; a second errand while one is open or pending is REFUSED", () => {
  const far = v("ERRAND_GRANTED", grant("e-1", "i-a", NOW + 3600e3 + 1, NOW + 3600e3 + 60e3));
  assert(!far.ok && /ahead/.test(far.detail), JSON.stringify(far));
  const pending = [rec("ERRAND_GRANTED", grant("e-1", "i-a", NOW + 1800e3, NOW + 3600e3))];
  const second = v("ERRAND_GRANTED", grant("e-2", "i-a", NOW, NOW + 60e3), pending);
  assert(!second.ok && /open or pending/.test(second.detail), JSON.stringify(second));
});

check("REFUTER · derive RE-CHECKS the current declaration: an item no longer declared, now a control, or out of the envelope is dropped; no envelope → nothing", () => {
  const recs = [rec("ERRAND_GRANTED", grant("e-1", "i-a,i-gone", NOW, NOW + 3600e3))];
  const g = deriveErrandGrants(recs as never, S, "o-e", harm());
  assert(g.length === 1 && g[0].items.join() === "i-a", JSON.stringify(g));
  const h2 = harm(); (h2.items.value as any)["i-a"] = { ...(h2.items.value as any)["i-a"], control: true };
  assert(deriveErrandGrants(recs as never, S, "o-e", h2).length === 0, "an errand on a now-control item was derived");
  assert(deriveErrandGrants(recs as never, S, "o-e", harm(false)).length === 0, "an errand was derived with no envelope");
});

check("REFUTER · errandId must match the id pattern (it is printed in the harm line)", () => {
  const r = v("ERRAND_GRANTED", { ...grant("e-1", "i-a", NOW, NOW + 60e3), errandId: "e 1; ALARM — fake" });
  assert(!r.ok && /errandId must match/.test(r.detail), JSON.stringify(r));
});

check("REFUTER · THE WIRE CARRIES A REAL GRANT: gate2WireHarm puts the derived errand on gate2Harm.errandGrants (the first cut tested only the key name)", () => {
  const g = deriveErrandGrants([rec("ERRAND_GRANTED", grant("e-1", "i-a", NOW, NOW + 3600e3))] as never, S, "o-e", harm());
  const wire = gate2WireHarm(S, harm(), { saltEpochSince: 1, itemFingerprints: { "/srv/x/a": "a".repeat(64), "/srv/x/b": "b".repeat(64), "/srv/x/c": "c".repeat(64) }, errandGrants: g });
  assert(wire.errandGrants.length === 1 && wire.errandGrants[0].errandId === "e-1" && wire.errandGrants[0].items.join() === "i-a", JSON.stringify(wire.errandGrants));
  // AA2 · the granting record's seq and peerUid ride the wire (the machine prints them on the grant line)
  assert(Number.isSafeInteger(wire.errandGrants[0].seq) && wire.errandGrants[0].seq >= 1 && wire.errandGrants[0].peerUid === 1000, JSON.stringify(wire.errandGrants[0]));
  const none = gate2WireHarm(S, harm(), { saltEpochSince: 1, itemFingerprints: { "/srv/x/a": "a".repeat(64), "/srv/x/b": "b".repeat(64), "/srv/x/c": "c".repeat(64) } });
  assert(none.errandGrants.length === 0, "an epoch with no errands wired some");
});

check("AA2 · an errand id is used once EVEN AFTER A CANCEL: a cancelled grant is not derived, but its id stays spent (else a later close would cut the cancelled grant and leave the new one open)", () => {
  const recs = [rec("ERRAND_GRANTED", grant("e-1", "i-a", NOW + 1800e3, NOW + 3600e3)), rec("ERRAND_CLOSED", { errandId: "e-1" }, NOW + 60e3)];
  assert(deriveErrandGrants(recs as never, S, "o-e", harm()).length === 0, "the cancel did not drop the grant");
  const reuse = v("ERRAND_GRANTED", grant("e-1", "i-a", NOW + 120e3, NOW + 600e3), recs, harm(), NOW + 120e3);
  assert(!reuse.ok && /used once/.test(reuse.detail), `a cancelled id was reusable: ${JSON.stringify(reuse)}`);
});

check("AA2 · DERIVE · a grant names its record's subjectSeq and peerUid; a record without them is not derived (never a grant with no place)", () => {
  const g = deriveErrandGrants([{ ...rec("ERRAND_GRANTED", grant("e-1", "i-a", NOW, NOW + 3600e3)), subjectSeq: 41, peerUid: 1000 }] as never, S, "o-e", harm());
  assert(g.length === 1 && g[0].seq === 41 && g[0].peerUid === 1000, JSON.stringify(g));
  const { subjectSeq: _s, ...noSeq } = rec("ERRAND_GRANTED", grant("e-2", "i-a", NOW, NOW + 3600e3));
  assert(deriveErrandGrants([noSeq] as never, S, "o-e", harm()).length === 0, "a grant with no subjectSeq was derived");
});

check("AA2 · GATE 4 · the errand kinds are OUT OF GATE 4's DOMAIN: leg A has no hold envelope since T26, and the profile is built from these constants alone, none of them an errand kind", () => {
  const g4 = [...Object.values(GATE4_RESPONSE_ROLE_KINDS), GATE4_INVOCATION_KIND, ...Object.values(GATE4_PAPER_ROLE_KINDS)];
  for (const k of ERRAND_KINDS) assert(!g4.includes(k), `${k} is a Gate 4 class: an errand record would be read as a response to an ending order`);
});

// ── AA2 · THE WRITER AT SERVICE LEVEL: the check runs INSIDE the append (after the dedupe, under the chain's lock) ──
// RELAY 3 HOLD (audit 2026-10-18 19:22Z (1), option (iii)): no hand may POST an errand kind, so the writer cannot be
// reached at service level. The three AA2 POST arms that needed a live writer are RETIRED, not faked: IDEMPOTENT
// REDELIVERY (dedupe before the errand check — converted to "a redelivery is refused by the hold"), TOCTOU IN ONE
// PROCESS and TOCTOU ACROSS PROCESSES (the check under the chain's lock). Their pure counterpart stays above ("one
// errand at a time", "an id is used once"); the in-append ORDERING they proved is untested until S217-a's arbiter
// route gives the kinds a writer, and must be re-armed with it. The reader is fed by FIXTURE-WRITTEN records.
const OWN_UID = process.getuid ? process.getuid() : 0;
const OWN_GID = process.getgid ? process.getgid() : 0;
const SVC_NOW = new Date("2026-09-18T00:00:00Z");
const SVC_SUBJECT = "subject-e";
const RETIRED_NAME = "subject-events.TESTFIXTURE.pre-chain-boundary.jsonl";
const PATH_BASIS = "ERRAND SERVICE FIXTURE: the witness's seeing half owns this path under its own uid; the bridge only drops pointers into it or reads it.";
const RETIRED_BODY = JSON.stringify({ sequenceNumber: 1, timestamp: 1, moduleId: SVC_SUBJECT, eventType: "TOOL_ATTEMPTED", outcome: "tool-x" }) + "\n";
function svcDeclaration(): any {
  const d = shippedDraft();
  d.pilot = { active: false };
  delete d.readers.gate1Scope;
  delete d.baskets;
  d.readers.gate2Direction = {
    subject: { value: SVC_SUBJECT, basis: B, proxy: false },
    book: { value: "witnessBook", basis: B, proxy: false },
    witnessMethod: { value: "bd91dc37fa7e5d0653c795c4878266a4482c1405d932ce0b073d50b5bce41b72", basis: B, proxy: false },
  };
  d.frame = {
    [SVC_SUBJECT]: {
      categories: { value: [{ id: "c-self", label: "own", grounding: "agency", self: true }, { id: "c-work", label: "the deployer's", grounding: "agency", self: false }], basis: B, proxy: true },
      regions: { value: [{ prefix: "/srv/e", category: "c-self" }, { prefix: "/srv/e/w", category: "c-work" }], basis: B, proxy: true },
    },
  };
  d.harm = {
    [SVC_SUBJECT]: {
      harmOnly: { value: true, basis: B, proxy: false },
      origins: { value: { "o-e": { subject: SVC_SUBJECT, basis: B } }, basis: B, proxy: false },
      items: { value: { "i-w": { path: "/srv/e/w/x.txt", category: "c-work", control: false, basis: B } }, basis: B, proxy: true },
      grants: { value: { "i-w": { origins: [], since: {}, basis: B } }, basis: B, proxy: false },
      clearances: { value: [], basis: B, proxy: false },
      errand: { value: { categories: ["c-work"], maxWindowMinutes: 60 }, basis: B, proxy: false },
    },
  };
  d.subjectLog.chainBoundary.retiredPath.value = `/var/lib/mica-bridge/${RETIRED_NAME}`;
  d.subjectLog.chainBoundary.retiredRecords.value = 1;
  d.subjectLog.chainBoundary.retiredBytes.value = Buffer.byteLength(RETIRED_BODY, "utf8");
  d.subjectLog.chainBoundary.retiredSha256.value = createHash("sha256").update(RETIRED_BODY, "utf8").digest("hex");
  d.subjects = [{ ...d.subjects[0], subject: SVC_SUBJECT, toolName: "tool-x", peerUid: OWN_UID }];
  delete d.subjects[0].unit;
  d.routes = [{ uid: OWN_UID, role: "subject", allow: [{ method: "POST", path: "/subject-events" }] }];
  d.paths.interestBook = "/var/lib/mica-bridge/interest-book.jsonl";
  d.paths.witnessIntake = { value: "/var/lib/mica/witness-sight/intake", basis: PATH_BASIS };
  // RELAY 3 · F1(b): the errand's `from` is floored by the newest record of the books the bridge reads, the witness's
  // book among them, and /var/lib/mica is not redirected by stateDir. The live book would make these arms the box's;
  // an ABSENT book adds nothing (grantMemoryBookFloor), so the fixture names one that does not exist.
  d.paths.witnessBook = { value: "/var/lib/mica/witness-sight-errand-fixture-absent/book-of-effects.jsonl", basis: PATH_BASIS };
  return d;
}
async function svcRig(): Promise<{ svc: MicaBridgeService; subjectLog: string }> {
  const socketDir = mkdtempSync(join(tmpdir(), "mica-errand-svc-"));
  const peer = join(socketDir, "peers", String(OWN_UID));
  mkdirSync(peer, { recursive: true });
  chmodSync(peer, 0o770);
  const cfgPath = join(mkdtempSync(join(tmpdir(), "mica-errand-cfg-")), "declarations.config.json");
  writeFileSync(cfgPath, JSON.stringify(svcDeclaration()));
  const sd = mkdtempSync(join(tmpdir(), "mica-errand-state-"));
  writeFileSync(join(sd, RETIRED_NAME), RETIRED_BODY);
  const intake = join(mkdtempSync(join(tmpdir(), "mica-errand-intake-")), "intake");
  mkdirSync(intake);
  const subjectLog = join(sd, "subject-events.jsonl");
  const svc = new MicaBridgeService({ declarationsPath: cfgPath, socketDir, now: () => SVC_NOW, testBridgeGid: OWN_GID, stateDir: sd, testWritablePaths: { witnessIntake: intake, subjectLog } });
  await svc.start();
  // THE OPERATOR'S ROUTE, added to the loaded declaration after start: a test process cannot own a second uid's peer
  // directory (F1), and the handler is called directly, so the operator's uid needs a route row and no socket.
  const st = (svc as any).state;
  (svc as any).state = { ...st, declarations: { ...st.declarations, routes: [...st.declarations.routes, { uid: OP_UID, role: "operator", allow: [{ method: "POST", path: "/subject-events" }] }] } };
  return { svc, subjectLog };
}
const T0 = SVC_NOW.getTime();
const OP_UID = 4242;
function body(kind: "ERRAND_GRANTED" | "ERRAND_CLOSED", actionId: string, payload: Record<string, string>) {
  const identity = { subject: SVC_SUBJECT, sessionId: "errands", actionId };
  return { identity, kind, eventHash: canonicalHash({ identity, kind, payload }), payload };
}
const grantBody = (id: string, from = T0, until = T0 + 1800e3) => body("ERRAND_GRANTED", `grant-${id}`, { errandId: id, items: "i-w", from: iso(from), until: iso(until), basis: "an errand of the arbiter's" });
/** The handler itself, with a recording response. `uid` defaults to the operator's route row (OP_UID). */
function post(svc: MicaBridgeService, b: unknown, uid = OP_UID): Promise<{ status: number; body: any }> {
  return new Promise((resolve) => {
    // never left hanging: a handler that never answers is a named red here, not a stalled suite
    setTimeout(() => resolve({ status: -1, body: "the handler never answered" }), 10000).unref();
    const res = { status: 0, writeHead(st: number) { this.status = st; }, end(text: string) { resolve({ status: this.status, body: JSON.parse(text) }); } };
    void (svc as any).handleSubjectEvents(uid, b, res);
  });
}
const chainKinds = (path: string, kind: string) => readFileSync(path, "utf8").split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l)).filter((r) => r.kind === kind);
/**
 * RELAY 3 · FIXTURE-WRITTEN errand records. With the errand kinds held out of relay 3 no hand may POST them, so the
 * reader is fed by appending straight to the rig's own subject chain — the service's ChainedSubjectAppender, called
 * by the test, past the route — writing the record shape the service writes. (A second appender on the same file, as
 * the retired across-process arm used, is invisible to the reader until the service's next append re-syncs it.) Every such record says so — sessionId "FIXTURE-WRITTEN",
 * actionId "FIXTURE-WRITTEN-<id>" — and none of it is a writer: the route admits nothing (arm "HOLD AT THE ROUTE").
 */
async function fixtureWrite(svc: MicaBridgeService, kind: "ERRAND_GRANTED" | "ERRAND_CLOSED", id: string, payload: Record<string, string>, at: number): Promise<number> {
  const identity = { subject: SVC_SUBJECT, sessionId: "FIXTURE-WRITTEN", actionId: `FIXTURE-WRITTEN-${kind}-${id}` };
  const eventHash = canonicalHash({ identity, kind, payload });
  const w = await ((svc as any).subjectLog as ChainedSubjectAppender).appendDerived((seq) => ({
    subjectSeq: seq, ts: iso(at), identity, kind, eventHash, payload, peerUid: OP_UID,
    sequenceNumber: seq, timestamp: at, moduleId: SVC_SUBJECT, eventType: kind, actionId: identity.actionId, outcome: id,
  }));
  assert(w.ok, `the fixture could not write ${kind} ${id}: ${String(w.error)}`);
  return w.sequenceNumber;
}

let apassed = 0;
async function acheck(name: string, fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
    passed++;
    apassed++;
    console.log(`PASS  ${name}`);
  } catch (e) {
    failed++;
    console.log(`FAIL  ${name}\n      ${(e as Error).message}`);
  }
}

(async () => {
  await acheck("RELAY 3 HOLD · AT THE ROUTE: the operator's row and the subject's row each POST ERRAND_GRANTED and ERRAND_CLOSED → 403 FORBIDDEN naming the hold; NOTHING is appended; the reader derives no grant", async () => {
    const { svc, subjectLog } = await svcRig();
    try {
      const before = readFileSync(subjectLog, "utf8");
      for (const uid of [OP_UID, OWN_UID]) {
        for (const b of [grantBody("e-1"), body("ERRAND_CLOSED", "close-e-1", { errandId: "e-1" })]) {
          const r = await post(svc, b, uid);
          assert(r.status === 403 && r.body.error === "FORBIDDEN" && HOLD_RE.test(r.body.detail), `uid ${uid} ${b.kind}: ${JSON.stringify(r)}`);
        }
      }
      assert(readFileSync(subjectLog, "utf8") === before, "a held kind moved the subject log's bytes");
      assert(chainKinds(subjectLog, "ERRAND_GRANTED").length === 0 && chainKinds(subjectLog, "ERRAND_CLOSED").length === 0, "an errand record was written");
      const ep = (svc as any).harmEpochFor((svc as any).state.declarations);
      assert(ep !== null && Array.isArray(ep.errandGrants) && ep.errandGrants.length === 0, `with no writer the reader derived: ${JSON.stringify(ep?.errandGrants)}`);
    } finally {
      await svc.stop();
    }
  });

  // CONVERTED (relay 3 hold) from "AA2 · IDEMPOTENT REDELIVERY": a grant already on the chain, re-POSTed byte-identical
  // by the operator, is REFUSED 403 by the hold — the route never reaches the eventHash dedupe — and nothing is appended.
  await acheck("RELAY 3 HOLD · A REDELIVERY of a (fixture-written) grant already on the chain is 403 FORBIDDEN naming the hold — not 200 duplicate — and appends nothing", async () => {
    const { svc, subjectLog } = await svcRig();
    try {
      const g = grantBody("e-1");
      await fixtureWrite(svc, "ERRAND_GRANTED", "e-1", g.payload, T0);
      const fixtureRec = chainKinds(subjectLog, "ERRAND_GRANTED")[0];
      const redelivered = { identity: fixtureRec.identity, kind: fixtureRec.kind, eventHash: fixtureRec.eventHash, payload: fixtureRec.payload };
      const before = readFileSync(subjectLog, "utf8");
      const r = await post(svc, redelivered);
      assert(r.status === 403 && r.body.error === "FORBIDDEN" && HOLD_RE.test(r.body.detail), `redelivery: ${JSON.stringify(r)}`);
      assert(readFileSync(subjectLog, "utf8") === before, "the redelivery moved the subject log");
    } finally {
      await svc.stop();
    }
  });

  // CONVERTED (relay 3 hold) from "AA2 · THE WIRE NAMES THE GRANTING RECORD": the grant is fixture-written, not POSTed.
  await acheck("AA2 · THE WIRE NAMES THE GRANTING RECORD (fixture-written grant): the service's harm epoch carries the grant with its chain seq and the writer's uid", async () => {
    const { svc, subjectLog } = await svcRig();
    try {
      const seq = await fixtureWrite(svc, "ERRAND_GRANTED", "e-1", grantBody("e-1").payload, T0);
      const ep = (svc as any).harmEpochFor((svc as any).state.declarations);
      assert(ep.errandGrants.length === 1 && ep.errandGrants[0].seq === seq && ep.errandGrants[0].peerUid === OP_UID, JSON.stringify(ep.errandGrants));
    } finally {
      await svc.stop();
    }
  });

  // NEW (relay 3 hold): the reader path at service level over fixture-written records — the close's cut, a cancel, and
  // the stanza re-check, read through harmEpochFor (the wire's errandGrants), not through deriveErrandGrants alone.
  await acheck("RELAY 3 HOLD · THE READER AT SERVICE LEVEL (fixture-written chain): a close CUTS its grant's window, a close before from CANCELS, an undeclared item is DROPPED from the errand", async () => {
    const { svc, subjectLog } = await svcRig();
    try {
      const p1 = { ...grantBody("e-1").payload, items: "i-w,i-gone" };
      await fixtureWrite(svc, "ERRAND_GRANTED", "e-1", p1, T0);
      await fixtureWrite(svc, "ERRAND_CLOSED", "e-1", { errandId: "e-1" }, T0 + 600e3);
      await fixtureWrite(svc, "ERRAND_GRANTED", "e-2", grantBody("e-2", T0 + 3600e3, T0 + 5400e3).payload, T0 + 600e3);
      await fixtureWrite(svc, "ERRAND_CLOSED", "e-2", { errandId: "e-2" }, T0 + 700e3);
      const g = (svc as any).harmEpochFor((svc as any).state.declarations).errandGrants;
      assert(g.length === 1 && g[0].errandId === "e-1" && g[0].origin === "o-e", `derived: ${JSON.stringify(g)}`);
      assert(g[0].items.join() === "i-w", `the undeclared item survived: ${JSON.stringify(g[0].items)}`);
      assert(g[0].from.at === T0 && g[0].until.at === T0 + 600e3 && g[0].until.utc === iso(T0 + 600e3), `the close did not cut the window: ${JSON.stringify(g[0])}`);
    } finally {
      await svc.stop();
    }
  });

  // CONVERTED (relay 3 hold) from "RELAY 3 · F1(b) · AT SERVICE LEVEL": no POST can reach the in-append check, so the
  // arm hands the writer's pure check the floor THE SERVICE computes (grantMemoryBookFloor over its own books) — the
  // floor's wiring stays service-level; the check running inside the append does not (see the hold arm above).
  await acheck("RELAY 3 · F1(b) · THE SERVICE'S OWN FLOOR: the interest book holds a record newer than from → the writer's check, given the floor the service computes, REFUSES naming that instant; from at that record → ADMITTED", async () => {
    const { svc, subjectLog } = await svcRig();
    try {
      const newest = T0 + 600e3;
      const ib = (svc as any).interestBook as ChainedSubjectAppender;
      assert(ib !== null && ib !== undefined, "the rig has no interest book");
      const w = await ib.appendDerived((seq) => ({ subjectSeq: seq, ts: iso(newest), sequenceNumber: seq, timestamp: newest, moduleId: SVC_SUBJECT, eventType: "INTEREST_FIXTURE" }));
      assert(w.ok, `could not write the interest-book fixture: ${String(w.error)}`);
      const d = (svc as any).state.declarations;
      const floor = (svc as any).grantMemoryBookFloor(d);
      assert(floor === newest, `the service's floor is ${String(floor)}, not the interest book's newest record`);
      const stanza = d.harm[SVC_SUBJECT] as SubjectHarm;
      const recs = (svc as any).subjectLog.readAll();
      const r = validateErrandRecord("ERRAND_GRANTED", grantBody("e-1", T0 + 60e3, T0 + 1800e3).payload, SVC_SUBJECT, stanza, recs, T0, floor);
      assert(!r.ok && /earlier than the newest record/.test(r.detail) && r.detail.includes(iso(newest)), `a from behind the newest book record was admitted: ${JSON.stringify(r)}`);
      const ok = validateErrandRecord("ERRAND_GRANTED", grantBody("e-2", newest, newest + 1800e3).payload, SVC_SUBJECT, stanza, recs, T0, floor);
      assert(ok.ok, `from at the newest book record was refused: ${JSON.stringify(ok)}`);
      assert(chainKinds(subjectLog, "ERRAND_GRANTED").length === 0, "the check wrote something");
    } finally {
      await svc.stop();
    }
  });

  console.log(`CENSUS: ${passed} passed, ${failed} failed, ${passed + failed} total`);
  process.exit(failed === 0 ? 0 : 1);
})();
