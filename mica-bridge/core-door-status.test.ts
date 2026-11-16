// ── core-door-status.test — pure-function coverage, plus one real-door run ─
// ── against a scratch tree this file owns (constraint #6: never the live ──
// ── /opt state as the only fixture). ───────────────────────────────────────
//
// Run with the pinned unit command, same convention as mica-service.test.ts:
//   <home>/mica-machine/node_modules/ts-node/dist/bin.js \
//     -P tsconfig.json core-door-status.test.ts

import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import {
  readCoreDoor,
  buildDoorSection,
  type CoreDoorProbe,
  type DoorReadResult,
} from "./core-door-status";
import {
  evaluateDoor,
  hashCore,
  baselineDigest,
  parseInventory,
  AUTHORSHIP_NOT_VERIFIED,
  INVENTORY_REL,
  TICKETS_REL,
  type DoorResult,
} from "/opt/mica-machine/src/core-door/core-door";

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

// ── buildDoorSection: pure shaping, one fixture per DoorResult kind ────────

const fakeAuthorship = "TEST: ticket authorship is not verified";

function readOf(door: DoorResult, peek: { commit: string; pinnedOn: string; repins: number } | null = null): DoorReadResult {
  return { kind: "READ", door, authorshipNotVerified: fakeAuthorship, inventoryPeek: peek, readMs: 1.23 };
}

check("buildDoorSection: CLOSED carries pinned count, shippable true, empty lists, authorship line", () => {
  const door: DoorResult = { kind: "CLOSED", pinned: 81, states: [], lines: ["core CLOSED, 81 files pinned"], shippable: true };
  const s = buildDoorSection(readOf(door, { commit: "abc1234", pinnedOn: "2026-09-22", repins: 0 }));
  assert(s.state === "CLOSED", s.state);
  assert(s.pinnedFileCount === 81, String(s.pinnedFileCount));
  assert(s.shippable === true, String(s.shippable));
  assert(s.baseline !== null && s.baseline.commit === "abc1234", JSON.stringify(s.baseline));
  assert(s.repinCount === 0, String(s.repinCount));
  assert(s.liveTickets.length === 0, "CLOSED must carry no live tickets");
  assert(s.unpinnedDrift.length === 0, "CLOSED must carry no drift");
  assert(s.refused.length === 0, "CLOSED must carry no refusal reasons");
  assert(s.authorshipNotVerified === fakeAuthorship, "authorship line must be carried verbatim");
  assert(s.detail === null, "CLOSED must not carry an UNREADABLE detail");
});

check("buildDoorSection: OPEN carries every live ticket's id/opens/expiresAt, and unpinned drift as lines", () => {
  const door: DoorResult = {
    kind: "OPEN",
    pinned: 81,
    states: [],
    live: [
      {
        schema: "mica-core-door/ticket/1",
        id: "T9-example",
        opens: ["src/mica/x.ts", "src/mica/y.ts"],
        defect: { summary: "s", ground: "g" },
        expiresAt: "2026-09-29T18:00:00Z",
        arbiter: { word: "w", date: "2026-09-22" },
        conditions: [],
      },
    ],
    unpinnedDrift: [{ path: "src/mica/x.ts", pinned: "aaaa", onDisk: "bbbb" }],
    lines: ["..."],
    shippable: false,
  };
  const s = buildDoorSection(readOf(door));
  assert(s.state === "OPEN", s.state);
  assert(s.shippable === false, String(s.shippable));
  assert(s.liveTickets.length === 1, JSON.stringify(s.liveTickets));
  assert(s.liveTickets[0].id === "T9-example", s.liveTickets[0].id);
  assert(JSON.stringify(s.liveTickets[0].opens) === JSON.stringify(["src/mica/x.ts", "src/mica/y.ts"]), JSON.stringify(s.liveTickets[0].opens));
  assert(s.liveTickets[0].expiresAt === "2026-09-29T18:00:00Z", s.liveTickets[0].expiresAt);
  assert(s.unpinnedDrift.length === 1 && s.unpinnedDrift[0].includes("src/mica/x.ts"), JSON.stringify(s.unpinnedDrift));
  assert(s.refused.length === 0, "OPEN must not populate `refused` (that is REFUSED-only)");
});

check("buildDoorSection: REFUSED carries the door's own reasons verbatim, including drift ones, and no pinned count", () => {
  const door: DoorResult = {
    kind: "REFUSED",
    reasons: ["DRIFT src/mica/z.ts drifted: pinned aaaa…, on disk cccc… — no ticket covers it: there are no tickets"],
    lines: ["CORE DOOR REFUSED — 1 reason(s)"],
    shippable: false,
  };
  const s = buildDoorSection(readOf(door));
  assert(s.state === "REFUSED", s.state);
  assert(s.pinnedFileCount === null, "REFUSED has no pin count to report");
  assert(s.shippable === false, String(s.shippable));
  assert(s.refused.length === 1 && s.refused[0].includes("src/mica/z.ts"), JSON.stringify(s.refused));
});

check("buildDoorSection: UNREADABLE never claims CLOSED or any other door word — distinct state, distinct shape", () => {
  const s = buildDoorSection({ kind: "UNREADABLE", reason: "evaluateRealDoor threw: boom", readMs: 4.5 });
  assert(s.state === "UNREADABLE", s.state);
  assert(s.state !== "CLOSED", "UNREADABLE must never print as CLOSED (register rule S139-12, brief constraint #2)");
  assert(s.pinnedFileCount === null && s.repinCount === null && s.baseline === null, "UNREADABLE carries no pin facts");
  assert(s.liveTickets.length === 0 && s.unpinnedDrift.length === 0 && s.refused.length === 0, "UNREADABLE carries no door content");
  assert(s.authorshipNotVerified === null, "nothing was read, so nothing is carried");
  assert(s.detail === "evaluateRealDoor threw: boom", s.detail ?? "(null)");
  assert(s.readMs === 4.5, String(s.readMs));
});

// ── readCoreDoor: the loader/evaluator seam, killing the two named mutants ─

check("readCoreDoor: a throwing loader (module missing/unparseable) is UNREADABLE, never CLOSED", () => {
  const r = readCoreDoor("/anywhere", new Date(), () => {
    throw new Error("Cannot find module '/opt/mica-machine/src/core-door/core-door'");
  });
  assert(r.kind === "UNREADABLE", JSON.stringify(r));
  if (r.kind === "UNREADABLE") {
    assert(r.reason.includes("core-door module unavailable"), r.reason);
    assert(r.reason.includes("Cannot find module"), r.reason);
  }
});

check("MUTANT KILLER 1 — a door that THROWS is reported UNREADABLE, not fabricated as CLOSED", () => {
  const probe: CoreDoorProbe = {
    evaluateRealDoor: () => {
      throw new Error("inventory corrupt");
    },
    parseInventory: () => ({ baseline: { commit: "x", pinnedOn: "2026-01-01" }, repins: [] }),
    AUTHORSHIP_NOT_VERIFIED: fakeAuthorship,
    INVENTORY_REL: "src/core-door/core-inventory.json",
  };
  const r = readCoreDoor("/anywhere", new Date(), () => probe);
  assert(r.kind === "UNREADABLE", `a throwing door must not produce a READ result: ${JSON.stringify(r)}`);
  if (r.kind === "UNREADABLE") assert(r.reason.includes("evaluateRealDoor threw"), r.reason);
  const section = buildDoorSection(r);
  assert(section.state === "UNREADABLE", `the shaped section must say UNREADABLE, not CLOSED: ${JSON.stringify(section)}`);
});

check("readCoreDoor: a failing inventory peek does not downgrade a real READ result", () => {
  const probe: CoreDoorProbe = {
    evaluateRealDoor: () => ({ kind: "CLOSED", pinned: 3, states: [], lines: [], shippable: true }),
    parseInventory: () => {
      throw new Error("peek unavailable");
    },
    AUTHORSHIP_NOT_VERIFIED: fakeAuthorship,
    INVENTORY_REL: "src/core-door/core-inventory.json",
  };
  const r = readCoreDoor("/anywhere", new Date(), () => probe);
  assert(r.kind === "READ", JSON.stringify(r));
  if (r.kind === "READ") {
    assert(r.door.kind === "CLOSED", r.door.kind);
    assert(r.inventoryPeek === null, "a failed peek must be null, not thrown out to the caller");
  }
});

check("MUTANT KILLER 2 — the door is re-read fresh on every call; no caching survives a clock change", () => {
  // A fake door whose OWN answer depends on the `now` it is handed, exactly
  // the shape evaluateDoor's real isLive() gives a ticket. If readCoreDoor
  // ever memoized a result (or dropped the `now` argument on the floor and
  // reused a fixed clock), the second call below would still say OPEN.
  const cutoff = Date.parse("2026-09-29T18:00:00Z");
  const probe: CoreDoorProbe = {
    evaluateRealDoor: (_repoRoot: string, now?: Date) => {
      const nowMs = (now ?? new Date()).getTime();
      if (nowMs <= cutoff) {
        return {
          kind: "OPEN",
          pinned: 1,
          states: [],
          live: [
            {
              schema: "mica-core-door/ticket/1",
              id: "T-fake",
              opens: ["src/mica/f.ts"],
              defect: { summary: "s", ground: "g" },
              expiresAt: "2026-09-29T18:00:00Z",
              arbiter: { word: "w", date: "2026-09-22" },
              conditions: [],
            },
          ],
          unpinnedDrift: [],
          lines: [],
          shippable: true,
        };
      }
      return { kind: "CLOSED", pinned: 1, states: [], lines: [], shippable: true };
    },
    parseInventory: () => ({ baseline: { commit: "x", pinnedOn: "2026-09-22" }, repins: [] }),
    AUTHORSHIP_NOT_VERIFIED: fakeAuthorship,
    INVENTORY_REL: "src/core-door/core-inventory.json",
  };
  const before = readCoreDoor("/anywhere", new Date("2026-09-22T12:00:00Z"), () => probe);
  const after = readCoreDoor("/anywhere", new Date("2026-09-29T18:00:01Z"), () => probe);
  assert(before.kind === "READ" && before.door.kind === "OPEN", JSON.stringify(before));
  assert(after.kind === "READ" && after.door.kind === "CLOSED", `expired ticket must close the door, not stay OPEN: ${JSON.stringify(after)}`);
});

// ── one real, end-to-end run — the ACTUAL evaluateDoor from mica-machine, ──
// ── over a scratch tree this test builds and owns, never live /opt state ──

function buildScratchTree(): { dir: string; expectedBaselineDigest: string } {
  const dir = mkdtempSync(join(tmpdir(), "core-door-status-scratch-"));
  mkdirSync(join(dir, "src", "mica", "sample"), { recursive: true });
  mkdirSync(join(dir, "src", "core-door", "tickets"), { recursive: true });
  writeFileSync(join(dir, "src", "mica", "sample", "a.ts"), "export const original = 1;\n");

  const { files } = hashCore(dir);
  const baselineFiles = Object.fromEntries([...files.entries()]);
  const expectedBaselineDigest = baselineDigest(baselineFiles);

  writeFileSync(
    join(dir, INVENTORY_REL),
    JSON.stringify(
      {
        schema: "mica-core-door/inventory/1",
        scope: "src/mica",
        baseline: { commit: "0000000scratch0000000000000000000000000", pinnedOn: "2026-01-01", files: baselineFiles },
        repins: [],
      },
      null,
      2
    )
  );

  const ticket = {
    schema: "mica-core-door/ticket/1",
    id: "SCRATCH-T1",
    opens: ["src/mica/sample/a.ts"],
    defect: { summary: "a scratch defect for core-door-status.test.ts", ground: "this test file" },
    expiresAt: "2026-01-01T12:00:00Z",
    arbiter: { word: "scratch arbiter word, not a placeholder", date: "2026-01-01" },
    conditions: [],
  };
  writeFileSync(join(dir, TICKETS_REL, "SCRATCH-T1.json"), JSON.stringify(ticket, null, 2));

  return { dir, expectedBaselineDigest };
}

check("real evaluateDoor over a scratch tree: OPEN before the ticket's expiry, REFUSED (uncovered drift) after — never CLOSED either side", () => {
  const { dir, expectedBaselineDigest } = buildScratchTree();
  try {
    // Drift the pinned file ONCE — disk state is identical for both reads
    // below, so only the clock differs, isolating exactly what constraint
    // #3's "the door's reading depends on the clock" is about.
    writeFileSync(join(dir, "src", "mica", "sample", "a.ts"), "export const original = 2; // drifted\n");

    const probe: CoreDoorProbe = {
      evaluateRealDoor: (repoRoot: string, now?: Date) =>
        evaluateDoor({ repoRoot, now: now ?? new Date(), expectedBaselineDigest, realTickets: true }),
      parseInventory,
      AUTHORSHIP_NOT_VERIFIED,
      INVENTORY_REL,
    };

    const beforeExpiry = readCoreDoor(dir, new Date("2026-01-01T06:00:00Z"), () => probe);
    const afterExpiry = readCoreDoor(dir, new Date("2026-01-01T18:00:00Z"), () => probe);

    assert(beforeExpiry.kind === "READ", JSON.stringify(beforeExpiry));
    if (beforeExpiry.kind === "READ") {
      assert(beforeExpiry.door.kind === "OPEN", `drift under a live ticket must read OPEN: ${JSON.stringify(beforeExpiry.door)}`);
      const section = buildDoorSection(beforeExpiry);
      assert(section.liveTickets.length === 1 && section.liveTickets[0].id === "SCRATCH-T1", JSON.stringify(section.liveTickets));
      assert(section.authorshipNotVerified === AUTHORSHIP_NOT_VERIFIED, "must carry the door's real, live authorship line");
    }

    assert(afterExpiry.kind === "READ", JSON.stringify(afterExpiry));
    if (afterExpiry.kind === "READ") {
      assert(
        afterExpiry.door.kind === "REFUSED",
        `the SAME drift, past the ticket's expiresAt, must read REFUSED (uncovered) — ` +
          `NEVER OPEN (the mutant this kills) and NEVER CLOSED (drift still on disk): ${JSON.stringify(afterExpiry.door)}`
      );
      const section = buildDoorSection(afterExpiry);
      assert(section.state === "REFUSED", section.state);
      assert(
        section.refused.some((r) => r.includes("src/mica/sample/a.ts") && /EXPIRED/.test(r)),
        JSON.stringify(section.refused)
      );
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

console.log("");
console.log(`CENSUS: ${passed} passed, ${failed} failed, ${passed + failed} total`);
if (failed > 0) process.exit(1);
