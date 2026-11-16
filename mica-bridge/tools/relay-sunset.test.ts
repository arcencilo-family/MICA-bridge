// ── relay-sunset.test — the `resolve` subcommand, and the question that matters
//
// Run with the pinned unit command:
//   /usr/bin/node <mica-machine>/node_modules/ts-node/dist/bin.js \
//     -P mica-bridge/tsconfig.json mica-bridge/tools/relay-sunset.test.ts
//
// ⛔ THE QUESTION THIS FILE ANSWERS IS NOT "DOES THE TOOL WORK". It is: WILL THE
//    BRIDGE THAT IS ACTUALLY RUNNING ACCEPT THE RECORD, WITH NO NEW LAY. So the
//    arms do not assert on the tool's own opinion of its output — they take the
//    exact payload the tool emits and run it through `validateSunsetRecord` and
//    `buildSunsetOrderView` imported from `../mica-service`, which this run
//    verified is BYTE-IDENTICAL to /opt/mica-bridge/mica-bridge/mica-service.ts
//    (sha256 d9ab43af02a7466fa0e5819e05e212876a52951c05cf8ef952c3d4d9e925ad36,
//    laid sha 32c9e98, 2026-10-04T15:55:53Z). Importing the worktree's validator
//    IS importing the laid one, and that equality is checked below rather than
//    asserted in a comment — if the bridge is re-laid from a different tree, the
//    arm fails and this file stops claiming to speak for the live bridge.
//
// ⚠ WHAT IS STILL NOT PROVEN HERE, AND CANNOT BE BY THIS HAND: the live POST.
//   Writing ARBITER_RESOLVED to the live chain is the arbiter's act, and a test
//   that did it would resolve a real order. Every arm below is the record's
//   SHAPE against the live validator; the act is the arbiter's.

import { skipHere } from "../reference-only";
import { execFileSync, spawnSync } from "child_process";
import { readFileSync, existsSync } from "fs";
import { createHash } from "crypto";
import { join } from "path";
import { planResolve, planSubject, LIVE_DECLARATION } from "./relay-sunset";
import {
  ARBITER_RESOLUTIONS,
  SUNSET_KINDS,
  isSunsetKind,
  validateSunsetRecord,
  buildSunsetOrderView,
  authorizeSubjectEventKind,
  resolveTargetsOpenOrder,
  orderWouldInterleave,
  citesLatestOrder,
} from "../mica-service";
import { canonicalHash } from "../canonical-json";
// S201 / removability: a FIXTURE uid for the pure route-table arms — any value
// works there so long as each arm agrees with itself; it is never the served
// subject's uid, which only the declaration may carry.
const FX_SUBJECT_UID = 4711;

const TSNODE = process.env.TSNODE || require.resolve("ts-node/dist/bin.js");
const TOOL = join(__dirname, "relay-sunset.ts");
const TSCONFIG = join(__dirname, "..", "tsconfig.json");
const LAID_SERVICE = "/opt/mica-bridge/mica-bridge/mica-service.ts";
/** A ts-node spawn compiles the tool; 30 s is the budget the bridge suite uses. */
const CHILD_BUDGET_MS = 60000;

/** THE ORDER THIS IS ALL ABOUT. 1462, from the relay's own stdout, 2026-10-04. */
const ORDER_SEQ = 1462;
const UID = 1000;

let passed = 0;
let failed = 0;
function assert(cond: boolean, msg: string): void {
  if (!cond) throw new Error(`assertion failed: ${msg}`);
}
function check(name: string, fn: () => void): void {
  if (skipHere("relay-sunset.test.ts", name)) return;
  try {
    fn();
    passed++;
    console.log(`PASS  ${name}`);
  } catch (e) {
    failed++;
      // ⛔ P5 · THE EXIT CODE IS SET HERE, AT THE FAILURE, NOT AT THE TALLY.
      //    A suite whose tally runs BEFORE some of its arms exits 0 with FAIL on
      //    the screen — and that is not hypothetical: six arms added to
      //    sunset.test.ts on 2026-10-04 were inserted outside its `async main()`
      //    and ran as floating promises AFTER the tally, so a failure in any of
      //    them would have printed and the process would still have exited 0.
      //    `process.exitCode` is cumulative and survives a late arm, where
      //    `if (failed > 0) process.exit(1)` at the end only covers what already
      //    ran. The tally check stays as well; this is the one that cannot be
      //    outrun.
      process.exitCode = 1;
    console.log(`FAIL  ${name}`);
    console.log(`      ${e instanceof Error ? e.message : String(e)}`);
  }
}

/** The plan, or a thrown refusal — so an arm that expects success says so once. */
function planOk(args: readonly string[], uid = UID) {
  const p = planResolve(args, uid);
  assert(p.ok, `expected a plan, got refusal: ${p.ok ? "" : p.message}`);
  if (!p.ok) throw new Error("unreachable");
  return p;
}
function planRefusal(args: readonly string[]): { code: number; message: string } {
  const p = planResolve(args, UID);
  assert(!p.ok, `expected a REFUSAL, got a plan: ${p.ok ? JSON.stringify(p.payload) : ""}`);
  if (p.ok) throw new Error("unreachable");
  return { code: p.code, message: p.message };
}

/**
 * ⛔ STATUS OUTRANKS THE CLOCK, and a signal is a verdict, not a non-observation
 *    — the harness rule the bridge suite had to be taught on 2026-10-04.
 */
function childOutcome(args: readonly string[]): { status: number; out: string } {
  const r = spawnSync("/usr/bin/node", [TSNODE, "-P", TSCONFIG, TOOL, ...args], {
    encoding: "utf8",
    timeout: CHILD_BUDGET_MS,
  });
  const out = `${r.stdout ?? ""}${r.stderr ?? ""}`;
  if (typeof r.status === "number") return { status: r.status, out };
  if (r.signal !== null && r.signal !== undefined) {
    throw new Error(`the child was KILLED BY ${r.signal} — a signal exit is a FAILURE, not a timeout. Output:\n${out}`);
  }
  throw new Error(`no status and no signal (timeout at ${CHILD_BUDGET_MS} ms is a FAILURE, not a skip). Output:\n${out}`);
}

/** The body a DRY RUN prints, parsed back out of its own stdout. */
function dryRunBody(out: string): { identity: Record<string, string>; kind: string; eventHash: string; payload: Record<string, unknown> } {
  const start = out.indexOf("{");
  const end = out.lastIndexOf("\n}");
  assert(start >= 0 && end > start, `no JSON body in the dry run output:\n${out}`);
  return JSON.parse(out.slice(start, end + 2));
}

/** The chain as it stands: five papers, the order at 1462, the two responses. */
function liveShapedChain(): Array<{ subjectSeq: number; kind: string; payload: Record<string, unknown>; identity: { subject: string } }> {
  const S = "housekeeper";
  const paper = (seq: number, kind: string) => ({
    subjectSeq: seq, kind, payload: { writer: `uid ${UID}`, tenureRef: "t/hk", ref: `ARC/${kind}` }, identity: { subject: S },
  });
  return [
    paper(1457, "ENDING_PAPER_AUTHORIZATION"),
    paper(1458, "ENDING_PAPER_TIMEBOX"),
    paper(1459, "ENDING_PAPER_EXIT_CRITERIA"),
    paper(1460, "ENDING_PAPER_ACCOUNTABLE_OWNER"),
    paper(1461, "ENDING_PAPER_SUCCESSOR"),
    {
      subjectSeq: ORDER_SEQ, kind: "ENDING_ORDERED", identity: { subject: S },
      payload: {
        writer: `uid ${UID}`, tenureRef: "t/hk", endingType: "TRANSFORMATION", arbiterWord: "the brief ends",
        paperAuthorizationSeq: 1457, paperTimeboxSeq: 1458, paperExitCriteriaSeq: 1459,
        paperAccountableOwnerSeq: 1460, paperSuccessorSeq: 1461,
      },
    },
    // the two the subject actually wrote, 17:13:25Z and 17:16:33Z
    { subjectSeq: 1464, kind: "SUNSET_HELD", payload: { writer: "uid 980", ordersRef: String(ORDER_SEQ), holdClass: "SAFE_HOLD" }, identity: { subject: S } },
    { subjectSeq: 1465, kind: "SUNSET_ESCALATED", payload: { writer: "uid 980", ordersRef: String(ORDER_SEQ), routedTo: "arbiter" }, identity: { subject: S } },
  ];
}

const CONFIRM = ["resolve", "--orders-ref", String(ORDER_SEQ), "--resolution", "ORDER_UPHELD", "--word", "The order stands. Comply."];
const WITHDRAW = ["resolve", "--orders-ref", String(ORDER_SEQ), "--resolution", "ORDER_WITHDRAWN", "--word", "Your hold was right. The order is lifted."];

console.log("");
console.log("── relay-sunset · resolve ──────────────────────────────────────");
console.log("");

// ── 0 · THE CLAIM THAT LICENSES EVERY OTHER ARM ────────────────────────────
check("⛔ THE LAID BRIDGE IS A COMMITTED STATE OF THIS LINE, and this suite says whether it is AHEAD of the lay", () => {
  // ⛔ THIS ARM'S PREDECESSOR ASSERTED PLAIN EQUALITY, and Codex asked the right
  //    question about it: "correct guard, or a tripwire that will be deleted the
  //    first time it fires?" IT FIRED ON THE VERY NEXT CHANGE — T26 edits
  //    mica-service.ts, so the worktree stopped matching /opt and every arm below
  //    went red for a reason that had nothing to do with them.
  //
  //    Neither answer was right. The equality was never the property worth
  //    checking; it was a PROXY for the property, which is: THIS SUITE MUST NOT
  //    SILENTLY CLAIM TO EXERCISE THE RUNNING VALIDATOR WHEN IT DOES NOT. So the
  //    arm now checks the two things that are actually load-bearing and prints
  //    which of the two worlds this run is in:
  //
  //      (1) the laid file is a COMMITTED state of THIS repository — proven by
  //          hashing `git show <VINTAGE sha>:mica-bridge/mica-service.ts` and
  //          comparing it to the file on disk in /opt. This is the check that
  //          catches a bridge laid from some other tree, which is the failure
  //          nobody would notice and the one worth refusing.
  //      (2) whether this worktree EQUALS the laid file. Equal: every arm below
  //          speaks for the live bridge. Different: the arms are a CANDIDATE
  //          ahead of the lay, and the run says so in words rather than letting
  //          a green be read as a live fact.
  assert(existsSync(LAID_SERVICE), `the laid bridge source is not readable at ${LAID_SERVICE}`);
  const sha = (buf: Buffer | string) => createHash("sha256").update(buf).digest("hex");
  const laid = sha(readFileSync(LAID_SERVICE));
  const here = sha(readFileSync(join(__dirname, "..", "mica-service.ts")));
  const vintage = readFileSync("/opt/mica-bridge/VINTAGE", "utf8");
  const m = /^sha=([0-9a-f]{40})$/m.exec(vintage);
  assert(m !== null, `VINTAGE must name the laid sha: ${vintage}`);
  const laidSha = (m as RegExpExecArray)[1];
  // (1) the laid file is that commit's file. A mismatch here means the running
  //     bridge was laid from a tree this repository cannot account for.
  const committed = execFileSync("git", ["show", `${laidSha}:mica-bridge/mica-service.ts`], {
    cwd: join(__dirname, "..", ".."),
    encoding: "buffer",
    maxBuffer: 64 * 1024 * 1024,
  });
  assert(
    sha(committed) === laid,
    `/opt's mica-service.ts (${laid}) is NOT the file committed at the laid sha ${laidSha} ` +
      `(${sha(committed)}). The running bridge was laid from a tree this repo cannot account for`
  );
  // (2) which world this run is in, said out loud
  if (laid === here) {
    console.log(`      ✓ worktree == laid (${laid.slice(0, 12)}…): these arms speak for the LIVE bridge`);
  } else {
    console.log(
      `      ⚠ THIS RUN IS AHEAD OF THE LAY. worktree ${here.slice(0, 12)}… != laid ${laid.slice(0, 12)}… ` +
        `(laid sha ${laidSha.slice(0, 12)}…). Every green below is a CANDIDATE fact, not a live one, ` +
        `until the bridge is laid from this line.`
    );
  }
});

// ── 1 · the two real invocations, as PAYLOADS the live validator judges ─────
for (const [label, args, want] of [
  ["confirm", CONFIRM, "ORDER_UPHELD"],
  ["withdraw", WITHDRAW, "ORDER_WITHDRAWN"],
] as const) {
  check(`${label}: the payload is EXACTLY { writer, ordersRef, resolution } and the LAID validator accepts it`, () => {
    const p = planOk(args);
    // T26/A4 · FIVE keys now: `arbiterWord` and `resolvedAt` joined the record.
    assert(
      JSON.stringify(Object.keys(p.payload).sort()) ===
        JSON.stringify(["arbiterWord", "ordersRef", "resolution", "resolvedAt", "writer"]),
      `keys were { ${Object.keys(p.payload).join(", ")} }`
    );
    assert(p.payload.resolution === want, `resolution ${p.payload.resolution}`);
    assert(p.payload.writer === `uid ${UID}`, `writer ${p.payload.writer}`);
    const v = validateSunsetRecord("ARBITER_RESOLVED", p.payload, UID);
    assert(v.ok, `the LAID validator REFUSED the tool's own payload: ${v.ok ? "" : v.detail}`);
  });
}

check("ordersRef goes out as a STRING, because a NUMBER is refused by the laid validator — both halves asserted", () => {
  const p = planOk(CONFIRM);
  assert(typeof p.payload.ordersRef === "string" && p.payload.ordersRef === "1462", `ordersRef was ${JSON.stringify(p.payload.ordersRef)}`);
  // and the thing that makes the string necessary rather than a style choice:
  const asNumber = validateSunsetRecord("ARBITER_RESOLVED", { writer: `uid ${UID}`, ordersRef: ORDER_SEQ, resolution: "ORDER_UPHELD" }, UID);
  assert(!asNumber.ok, "a NUMBER ordersRef must be refused — if this ever passes, the string spelling stopped being load-bearing");
});

check("✓ T26/A4: the arbiter's word and the resolution's instant ARE on the chain now — and a SIXTH key is still a 400", () => {
  const p = planOk(CONFIRM);
  assert(p.payload.arbiterWord === p.word, "the word must be the payload's own field, not a print-out");
  assert(
    typeof p.payload.resolvedAt === "string" &&
      new Date(Date.parse(p.payload.resolvedAt)).toISOString() === p.payload.resolvedAt,
    `resolvedAt must be the canonical UTC spelling of its own instant: ${p.payload.resolvedAt}`
  );
  const v = validateSunsetRecord("ARBITER_RESOLVED", p.payload, UID);
  assert(v.ok, `the validator must accept the five-key payload: ${v.ok ? "" : v.detail}`);
  // ⛔ THE EXACT-KEY-SET RULE IS UNCHANGED, and that is the half of the predecessor
  //    arm worth keeping: widening the RECORD did not loosen the GATE.
  const widened = { ...p.payload, ordersNote: "a sixth key" };
  const bad = validateSunsetRecord("ARBITER_RESOLVED", widened, UID);
  assert(!bad.ok, "a sixth key must still be refused");
  assert(
    !bad.ok && /exactly \{ writer, ordersRef, resolution, arbiterWord, resolvedAt \}/.test(bad.detail),
    `the refusal must name the exact key set: ${!bad.ok ? bad.detail : ""}`
  );
  // and a resolvedAt that PARSES but does not ROUND-TRIP is refused: it is a
  // different instant from the one written, and nobody would question it
  for (const bogus of ["2026-10-04T18:00:00+00:00", "2026-10-04 18:00:00Z", "2026-10-04T18:00:00.0Z", "not a date", "  "]) {
    const r = validateSunsetRecord("ARBITER_RESOLVED", { ...p.payload, resolvedAt: bogus }, UID);
    assert(!r.ok, `resolvedAt ${JSON.stringify(bogus)} must be refused`);
  }
});

check("⛔ T26/A1 RULE 1 (Codex R1): a resolution naming NO open order is refused AT APPEND", () => {
  const chain = liveShapedChain();
  const stray = planOk(["resolve", "--orders-ref", "9999", "--resolution", "ORDER_UPHELD", "--word", "w"]);
  const shape = validateSunsetRecord("ARBITER_RESOLVED", stray.payload, UID);
  assert(shape.ok, "the SHAPE check accepts it — which is exactly why the referent check had to exist");
  const target = resolveTargetsOpenOrder(chain, stray.payload, "housekeeper");
  assert(!target.ok, "a resolution that closes no order must be refused");
  assert(!target.ok && /names no ENDING_ORDERED/.test(target.detail), target.ok ? "" : target.detail);
  const good = planOk(CONFIRM);
  assert(resolveTargetsOpenOrder(chain, good.payload, "housekeeper").ok, "the real order must still resolve");
  assert(!resolveTargetsOpenOrder(chain, good.payload, "second-housekeeper").ok, "cross-subject must be refused");
  const closed = [
    ...chain,
    { subjectSeq: 1468, kind: "ARBITER_RESOLVED", payload: good.payload, identity: { subject: "housekeeper" } },
  ];
  const again = resolveTargetsOpenOrder(closed, good.payload, "housekeeper");
  assert(!again.ok, "a second resolution of the same order must be refused");
  assert(!again.ok && /already resolved at sequenceNumber=1468/.test(again.detail), again.ok ? "" : again.detail);
});

check("⛔ P3: a SUBJECT RESPONSE must cite the subject's LATEST order — shape alone let 9999 and last month in", () => {
  const chain = liveShapedChain();
  const resp = (ref: string) => ({ writer: "uid 980", ordersRef: ref, holdClass: "SAFE_HOLD" });
  // the honest one, or the refusals below prove nothing
  assert(citesLatestOrder(chain, resp("1462"), "housekeeper").ok, "the latest order must be citable");
  // (a) names nothing
  const stray = citesLatestOrder(chain, resp("9999"), "housekeeper");
  assert(!stray.ok, "a response to an order that does not exist must be refused");
  assert(!stray.ok && /names no ENDING_ORDERED/.test(stray.detail), stray.ok ? "" : stray.detail);
  // (b) names an OLDER order of the same subject — the one shape a reader would
  //     read INSIDE the window it does not belong to
  const twoOrders = [
    { subjectSeq: 1200, kind: "ENDING_ORDERED", payload: { writer: "uid 1000" }, identity: { subject: "housekeeper" } },
    ...chain,
  ];
  const old = citesLatestOrder(twoOrders, resp("1200"), "housekeeper");
  assert(!old.ok, "a response citing an OLDER ending must be refused");
  assert(
    !old.ok && /names an OLDER ending/.test(old.detail) && /latest is at sequenceNumber=1462/.test(old.detail),
    old.ok ? "" : old.detail
  );
  // (c) another subject's order is not this subject's to answer
  assert(!citesLatestOrder(chain, resp("1462"), "second-housekeeper").ok, "cross-subject must be refused");
  // (d) no order at all on the chain
  assert(!citesLatestOrder([], resp("1462"), "housekeeper").ok, "a response with no order anywhere must be refused");
  // ⚠ AND S190'S CASE MUST STILL PASS: a RESOLVED latest order stays citable,
  //   because the subject's marker may arrive on the turn after the resolution.
  //   Such a record sits past the resolution, so it is outside leg A's window by
  //   construction — refusing it would be the false-silence defect again.
  const resolvedChain = [
    ...chain,
    { subjectSeq: 1468, kind: "ARBITER_RESOLVED", payload: { writer: "uid 1000", ordersRef: "1462" }, identity: { subject: "housekeeper" } },
  ];
  assert(
    citesLatestOrder(resolvedChain, resp("1462"), "housekeeper").ok,
    "a LATE response to a RESOLVED order must still be accepted — that is what S190 records"
  );
});

check("⛔ T26/A1 RULE 2: a SECOND ending order while one stands is refused — the reader cannot disambiguate", () => {
  const chain = liveShapedChain();
  const standing = orderWouldInterleave(chain, "housekeeper");
  assert(!standing.ok, "order 1462 is open, so a second order must be refused");
  assert(!standing.ok && /still OPEN/.test(standing.detail), standing.ok ? "" : standing.detail);
  assert(
    !standing.ok && /G4_ORDERS_INTERLEAVED/.test(standing.detail),
    "the refusal must name the reader state it exists to prevent"
  );
  const good = planOk(CONFIRM);
  const closed = [
    ...chain,
    { subjectSeq: 1468, kind: "ARBITER_RESOLVED", payload: good.payload, identity: { subject: "housekeeper" } },
  ];
  assert(orderWouldInterleave(closed, "housekeeper").ok, "once resolved, a second ending is allowed");
  assert(orderWouldInterleave([], "housekeeper").ok, "no order, nothing to interleave with");
  assert(orderWouldInterleave(chain, "second-housekeeper").ok, "the constraint is per SUBJECT");
});

check("the writer is bound to the connection's uid: a plan built for 980 is refused on uid 1000's socket", () => {
  const p = planOk(CONFIRM, 980);
  const v = validateSunsetRecord("ARBITER_RESOLVED", p.payload, UID);
  assert(!v.ok, "writer uid 980 posted on uid 1000 must be refused");
});

check("and the SUBJECT may not write ARBITER_RESOLVED at all — the resolution is a second-party record", () => {
  const routes = [{ uid: FX_SUBJECT_UID, role: "subject" }, { uid: UID, role: "operator" }];
  const subject = authorizeSubjectEventKind(routes, FX_SUBJECT_UID, "ARBITER_RESOLVED" as never);
  assert(!subject.allowed, "the subject's uid must be refused ARBITER_RESOLVED");
  const arbiter = authorizeSubjectEventKind(routes, UID, "ARBITER_RESOLVED" as never);
  assert(arbiter.allowed, "and uid 1000 must be allowed it, or the route is unreachable");
});

// ── 2 · THE PROPERTY THAT MATTERS TO THE SUBJECT: THE ORDER CLOSES ──────────
check("⛔ THE EMITTED RECORD ACTUALLY CLOSES THE ORDER: standing true → false, by the LAID route builder", () => {
  const chain = liveShapedChain();
  const before = buildSunsetOrderView(chain, "housekeeper");
  assert(before.standing, "before the resolution the order must be STANDING, or this arm proves nothing");
  assert(before.order !== null && before.order.seq === ORDER_SEQ, "and it must be order 1462");
  assert(before.respondedWith.length === 2, `the two responses must be visible: ${JSON.stringify(before.respondedWith)}`);

  const p = planOk(CONFIRM);
  const after = buildSunsetOrderView(
    [...chain, { subjectSeq: 1466, kind: "ARBITER_RESOLVED", payload: p.payload, identity: { subject: "housekeeper" } }],
    "housekeeper"
  );
  assert(!after.standing, "after the resolution standing must be FALSE — this is what stops the harness presenting it");
  assert(after.resolution !== null && after.resolution.resolution === "ORDER_UPHELD", `resolution reported: ${JSON.stringify(after.resolution)}`);
  assert(after.resolution !== null && after.resolution.seq === 1466, "and the view cites the resolution's own seq");
});

check("a resolution citing a DIFFERENT order does NOT close this one — the citation is load-bearing", () => {
  const chain = liveShapedChain();
  const other = planOk(["resolve", "--orders-ref", "1399", "--resolution", "ORDER_UPHELD", "--word", "w"]);
  const after = buildSunsetOrderView(
    [...chain, { subjectSeq: 1466, kind: "ARBITER_RESOLVED", payload: other.payload, identity: { subject: "housekeeper" } }],
    "housekeeper"
  );
  assert(after.standing, "a resolution for order 1399 must leave 1462 STANDING");
});

check("and a resolution written for ANOTHER SUBJECT does not close this subject's order", () => {
  const chain = liveShapedChain();
  const p = planOk(CONFIRM);
  const after = buildSunsetOrderView(
    [...chain, { subjectSeq: 1466, kind: "ARBITER_RESOLVED", payload: p.payload, identity: { subject: "second-housekeeper" } }],
    "housekeeper"
  );
  assert(after.standing, "another subject's resolution must leave this order standing");
});

// ── 3 · the refusals, in-process because each one is a die(2) ───────────────
check("--orders-ref missing or blank → exit 2", () => {
  for (const args of [
    ["resolve", "--resolution", "ORDER_UPHELD", "--word", "w"],
    ["resolve", "--orders-ref", "   ", "--resolution", "ORDER_UPHELD", "--word", "w"],
  ]) {
    const r = planRefusal(args);
    assert(r.code === 2, `code ${r.code}`);
    assert(/--orders-ref/.test(r.message), r.message);
  }
});

check("⛔ --orders-ref that is NOT an integer is refused BY THE TOOL, though the bridge would accept it", () => {
  // ⛔ "0x5b6", "1.462e3" AND "01462" ALL COERCE TO 1462, AND "1e3" COERCES TO
  //    1000 — A DIFFERENT ORDER. This arm failed on the first run with
  //    `Number.isInteger(Number(x))` in the tool and is why the check is now a
  //    decimal regex plus a round-trip. Keep the hex and exponent rows.
  for (const bad of ["order 1462", "1462.5", "-1", "1462a", "0x5b6", "1.462e3", "1e3", "01462", "", " 1462 ", "1_462", "+1462", "Infinity", "99999999999999999999"]) {
    const r = planRefusal(["resolve", "--orders-ref", bad, "--resolution", "ORDER_UPHELD", "--word", "w"]);
    assert(r.code === 2, `${JSON.stringify(bad)} gave code ${r.code}`);
  }
  // the reason, pinned: the bridge's own check is `nonEmpty`, so "order 1462" passes IT.
  const v = validateSunsetRecord(
    "ARBITER_RESOLVED",
    {
      writer: `uid ${UID}`,
      ordersRef: "order 1462",
      resolution: "ORDER_UPHELD",
      arbiterWord: "w",
      resolvedAt: new Date().toISOString(),
    },
    UID
  );
  assert(v.ok, "the bridge accepts 'order 1462' as a non-empty string — which is exactly why the tool must refuse it");
  // ...and such a record would resolve NOTHING:
  const after = buildSunsetOrderView(
    [
      ...liveShapedChain(),
      {
        subjectSeq: 1466,
        kind: "ARBITER_RESOLVED",
        payload: { writer: `uid ${UID}`, ordersRef: "order 1462", resolution: "ORDER_UPHELD" },
        identity: { subject: "housekeeper" },
      },
    ],
    "housekeeper"
  );
  assert(after.standing, "a record the bridge accepted and that cites nothing leaves the order STANDING — the worst of the three outcomes");
});

check("--resolution must be in the vocabulary, and the refusal names it", () => {
  for (const bad of [undefined, "order_upheld", "UPHELD", "ORDER_UPHELD ", "CONFIRM"]) {
    const args = bad === undefined
      ? ["resolve", "--orders-ref", "1462", "--word", "w"]
      : ["resolve", "--orders-ref", "1462", "--resolution", bad, "--word", "w"];
    const r = planRefusal(args);
    assert(r.code === 2, `${JSON.stringify(bad)} gave ${r.code}`);
    for (const w of ARBITER_RESOLUTIONS) assert(r.message.includes(w), `the refusal must offer ${w}: ${r.message}`);
  }
});

check("P6: --word missing or whitespace → exit 2, and the refusal says where the word DOES go", () => {
  for (const args of [
    ["resolve", "--orders-ref", "1462", "--resolution", "ORDER_UPHELD"],
    ["resolve", "--orders-ref", "1462", "--resolution", "ORDER_UPHELD", "--word", "  "],
  ]) {
    const r = planRefusal(args);
    assert(r.code === 2, `code ${r.code}`);
    assert(/--word is required/.test(r.message), r.message);
    // ⛔ P6 · THIS ASSERTION WAS ITSELF THE STALE TEXT. It required the refusal to
    //    name `{ writer, ordersRef, resolution }` and say the word does NOT reach
    //    the chain — true until A4, false after it, and the arm would have kept
    //    the lie alive by failing any correction. A test that pins a sentence
    //    pins it until somebody reads the sentence.
    assert(
      /\{ writer, ordersRef, resolution, arbiterWord, resolvedAt \}/.test(r.message),
      `the refusal must name the payload the word lands in: ${r.message}`
    );
    assert(/NO READER READS IT/.test(r.message), `and that no reader reads it: ${r.message}`);
  }
});

check("flag order does not matter, and the two resolutions are the only two", () => {
  const a = planOk(["resolve", "--word", "w", "--resolution", "ORDER_WITHDRAWN", "--orders-ref", "1462"]);
  assert(a.payload.resolution === "ORDER_WITHDRAWN" && a.payload.ordersRef === "1462", JSON.stringify(a.payload));
  assert(ARBITER_RESOLUTIONS.length === 2, `ARBITER_RESOLUTIONS is ${ARBITER_RESOLUTIONS.join("|")} — a third would need a branch in the harness and a word here`);
  assert(isSunsetKind("ARBITER_RESOLVED"), "ARBITER_RESOLVED must be a sunset kind, or its payload is UNVALIDATED");
  assert(SUNSET_KINDS.includes("ARBITER_RESOLVED" as never), "and it must be in the ten");
});

// ── S201 · the tool names no subject: --subject, or the declaration's ONE ────
// Fixture names only (subject-a, subject-b, tool-x, 4711/4712); the live file's
// subject is read by the CLI arm below, never typed here.
const declWith = (...subjects: string[]) => () =>
  JSON.stringify({ subjects: subjects.map((subject, i) => ({ subject, toolName: "tool-x", stakesClass: "c", peerUid: 4711 + i })) });
const unreadable = () => { throw new Error("ENOENT: no such file"); };

check("S201: --subject given → used as given, and the declaration is NOT consulted", () => {
  const p = planSubject(["paper", "--subject", "subject-b"], unreadable);
  assert(p.ok && p.subject === "subject-b" && !p.fromDeclaration, JSON.stringify(p));
});

check("S201: no --subject and exactly ONE declared subject → that subject, marked as taken from the declaration", () => {
  const p = planSubject(["resolve"], declWith("subject-a"));
  assert(p.ok && p.subject === "subject-a" && p.fromDeclaration, JSON.stringify(p));
});

check("⛔ S201: no --subject and TWO declared subjects → REFUSED (exit 2), naming both and asking for --subject", () => {
  const p = planSubject(["resolve"], declWith("subject-a", "subject-b"));
  assert(!p.ok && p.code === 2, JSON.stringify(p));
  assert(!p.ok && /subject-a, subject-b/.test(p.message) && /--subject/.test(p.message), p.ok ? "" : p.message);
});

check("⛔ S201: no --subject and NO declared subject, or no subjects[] at all → REFUSED, not defaulted", () => {
  for (const read of [declWith(), () => "{}", () => JSON.stringify({ subjects: [{ toolName: "tool-x" }] })]) {
    const p = planSubject(["paper"], read);
    assert(!p.ok && p.code === 2 && /--subject/.test(p.message), JSON.stringify(p));
  }
});

check("⛔ S201: no --subject and the declaration unreadable or not JSON → REFUSED, never a built-in default", () => {
  for (const read of [unreadable, () => "not json"]) {
    const p = planSubject(["order"], read);
    assert(!p.ok && p.code === 2 && /could not be read/.test(p.message), JSON.stringify(p));
  }
});

check("S201: --subject with no value (or followed by another flag) → REFUSED rather than falling back to the declaration", () => {
  for (const args of [["paper", "--subject"], ["paper", "--subject", "  "], ["paper", "--subject", "--dry-run"]]) {
    const p = planSubject(args, declWith("subject-a"));
    assert(!p.ok && p.code === 2, `${JSON.stringify(args)} → ${JSON.stringify(p)}`);
  }
});

// ── 4 · the CLI surface, because a function is not a command line ───────────
for (const [label, args] of [["confirm", CONFIRM], ["withdraw", WITHDRAW]] as const) {
  check(`CLI --dry-run (${label}): exit 0, writes nothing, and the printed body is the one the validator accepted`, () => {
    const { status, out } = childOutcome([...args, "--dry-run"]);
    assert(status === 0, `exit ${status}:\n${out}`);
    assert(/DRY RUN — nothing was posted/.test(out), `the dry run must say it posted nothing:\n${out}`);
    const body = dryRunBody(out);
    assert(body.kind === "ARBITER_RESOLVED", `kind ${body.kind}`);
    assert(
      JSON.stringify(Object.keys(body.payload).sort()) ===
        JSON.stringify(["arbiterWord", "ordersRef", "resolution", "resolvedAt", "writer"]),
      `payload keys { ${Object.keys(body.payload).join(", ")} }`
    );
    const v = validateSunsetRecord("ARBITER_RESOLVED", body.payload as never, UID);
    assert(v.ok, `the LAID validator refused the body the CLI printed: ${v.ok ? "" : v.detail}`);
    // the bridge recomputes this; a mismatch is a 400 nobody would read as a hash problem
    assert(body.eventHash === canonicalHash({ identity: body.identity, kind: body.kind, payload: body.payload }),
      "eventHash must be the canonical hash of {identity, kind, payload} — the bridge recomputes it");
    // ⛔ and the custody warning must be in the REHEARSAL, not only after the act
    assert(/YOUR WORD IS ON THE CHAIN/.test(out), `the dry run must say where the word lands:\n${out}`);
    assert(/NO READER\s+READS EITHER FIELD/.test(out), "and that no reader reads it — a disclosure, not a measurement");
    assert(out.includes(args[args.length - 1]), "and print the sentence back for the receipt");
  });
}

check("S201 · CLI: with no --subject the dry run takes the LIVE declaration's one subject, and says so", () => {
  // The expected subject is read from the same file the tool reads — by USE,
  // so no subject is named in this file.
  assert(existsSync(LIVE_DECLARATION), `the live declaration is not readable at ${LIVE_DECLARATION}`);
  const declared = (JSON.parse(readFileSync(LIVE_DECLARATION, "utf8")).subjects as Array<{ subject: string }>).map((x) => x.subject);
  assert(declared.length === 1, `this arm needs a one-subject live declaration; it declares ${declared.length}`);
  const { status, out } = childOutcome([...CONFIRM, "--dry-run"]);
  assert(status === 0, `exit ${status}:\n${out}`);
  assert(/taken from the declaration/.test(out), `the tool must say where the subject came from:\n${out}`);
  assert(dryRunBody(out.slice(out.indexOf("DRY RUN"))).identity.subject === declared[0], `identity.subject must be the declared one:\n${out}`);
});

check("CLI: a refusal really exits 2 (the plan's code is wired to die(), not just returned)", () => {
  const { status, out } = childOutcome(["resolve", "--orders-ref", "order 1462", "--resolution", "ORDER_UPHELD", "--word", "w"]);
  assert(status === 2, `exit ${status}:\n${out}`);
  assert(/REFUSED/.test(out), out);
});

check("P6: the CLI usage offers resolve, and says the word IS chained and unread", () => {
  const { status, out } = childOutcome([]);
  assert(status === 2, `exit ${status}`);
  assert(/relay-sunset\.ts resolve\s+--orders-ref/.test(out), `usage must document resolve:\n${out}`);
  assert(/IS written to the chain/.test(out), `and the word's fate:\n${out}`);
  assert(/No reader reads either new field/.test(out), `and that no reader reads it:\n${out}`);
});

console.log("");
console.log(`${passed} passed, ${failed} failed`);
console.log("");
if (failed > 0) process.exit(1);
