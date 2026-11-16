// S216-2 · THE BRIDGE'S GRANT MEMORY — store, rules GM0-GM5, the effective since, the seed, the loader refusal.
//   node <ts-node bin.js> -P mica-bridge/tsconfig.json mica-bridge/grant-memory.test.ts   (from the repo root)
//
// Ticket: ARC_MICA-TICKET_S216-2-Grant-Memory_DRAFT_v2_20261017.md (accepted for build, audit 2026-10-18 06:56Z:
// F-3 yes, F-2 (a), F-7 (a); the seat's design items accepted as design). Cond. 9's arm list, one check each, plus
// the service-level placement (GM0) and the wire (GM2). Fixture names only: subject-a, i-*, o-*, /srv/…
// No served literal beyond the state dir's name, which is the path under test.

import { shippedDraft } from "./example-draft";
import { execFileSync } from "child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync, writeSync as realWriteSync } from "fs";
import { createHash } from "crypto";
import { tmpdir } from "os";
import { join } from "path";

import {
  appendGrantMemory,
  boundaryRecord,
  declaredGrantsOf,
  firstSeenRecord,
  GRANT_MEMORY_FILE,
  GrantMemoryStore,
  GrantMemoryWriteError,
  isoOf,
  readGrantMemory,
  seedChain,
  verifyGrantMemoryBytes,
  type DeclaredGrant,
  type GrantKey,
  type GrantMemoryFs,
} from "./grant-memory";
import { gate2HarmClass, gate2WireHarm } from "./to-wire-options";
import { MicaBridgeService } from "./mica-service";
import { validateDeclarations } from "./declarations";

let passed = 0;
let failed = 0;
let skipped = 0;
async function check(name: string, fn: () => Promise<void> | void): Promise<void> {
  try {
    const r = await fn();
    if ((r as unknown) === "SKIP") {
      console.log(`SKIP  ${name}`);
      skipped++;
      return;
    }
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

const DH = "d".repeat(64);
const DH2 = "e".repeat(64);
const T0 = Date.parse("2026-10-16T06:13:54.692Z");
const KEY: GrantKey = { subject: "subject-a", itemId: "i-g", path: "/srv/a/g.txt", originId: "o-a", originSubject: "subject-a" };
const KEY2: GrantKey = { subject: "subject-a", itemId: "i-h", path: "/srv/a/h.txt", originId: "o-a", originSubject: "subject-a" };
function grant(key: GrantKey, sinceAt: number): DeclaredGrant {
  return { key, sinceAt, sinceUtc: isoOf(sinceAt) };
}
function dir(tag: string): string {
  return mkdtempSync(join(tmpdir(), `mica-gm-${tag}-`));
}
function rowsOf(d: string): any[] {
  const p = join(d, GRANT_MEMORY_FILE);
  if (!existsSync(p)) return [];
  return readFileSync(p, "utf8").split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l));
}
function facts(now: number, grants: DeclaredGrant[], bookFloorAt: number | null = null, declarationHash = DH) {
  return { now, bookFloorAt, declarationHash, grants };
}
/** A fresh store over `d`, adopted at `now` with `grants`; returns [store, outcome]. */
function start(d: string, now: number, grants: DeclaredGrant[], prior: string[] = [], bookFloorAt: number | null = null, fsx?: GrantMemoryFs) {
  const s = new GrantMemoryStore(d, fsx);
  const o = s.adopt(facts(now, grants, bookFloorAt), prior);
  return [s, o] as const;
}
function sha(b: Buffer): string {
  return createHash("sha256").update(b).digest("hex");
}

async function main(): Promise<void> {
  // ── the store ──────────────────────────────────────────────────────────────
  await check("GM-1 · MISSING → BEGUN: the chain is begun with the boundary and one first sight per grant AT THE LOAD (never the declared since); the file is 0640", () => {
    const d = dir("missing");
    const [s, o] = start(d, T0 + 5000, [grant(KEY, T0)]);
    assert(o.found === "MISSING" && o.begun === "BEGUN" && o.newChain && o.persisted, JSON.stringify(o));
    assert(s.state() === "BEGUN", s.state());
    const rows = rowsOf(d);
    assert(rows.length === 2 && rows[0].kind === "GRANT_MEMORY_BOUNDARY" && rows[1].kind === "GRANT_FIRST_SEEN", JSON.stringify(rows));
    assert(rows[1].firstSeenAt === T0 + 5000 && rows[1].declaredSinceAt === T0, "first sight is the load instant");
    assert(s.effective(grant(KEY, T0))!.at === T0 + 5000, "effective = first sight");
    assert((statSync(join(d, GRANT_MEMORY_FILE)).mode & 0o777) === 0o640, `mode ${(statSync(join(d, GRANT_MEMORY_FILE)).mode & 0o777).toString(8)}`);
    assert(!existsSync(join(d, `${GRANT_MEMORY_FILE}.lock`)), "the lock was left behind");
  });

  await check("GM-2 · THE MODE IS EXPLICIT: under a directory DEFAULT ACL that disables the umask (the live shape, BB2 finding 6) a begun memory is still 0640, other::---", () => {
    const d = dir("acl");
    try {
      execFileSync("setfacl", ["-d", "-m", "u::rwx,g::r-x,o::r-x,m::r-x", d], { stdio: "ignore" });
      execFileSync("setfacl", ["-d", "-m", `u:${String(process.getuid!())}:r--`, d], { stdio: "ignore" });
    } catch {
      console.log("      (setfacl unavailable: the ACL half is not armed here)");
      return "SKIP" as never;
    }
    // control: a plain create in that dir is world-readable (the umask is disabled by the default ACL)
    writeFileSync(join(d, "control"), "x");
    const ctl = statSync(join(d, "control")).mode & 0o777;
    assert((ctl & 0o004) !== 0, `control: the default ACL did not widen a plain create (${ctl.toString(8)}); the arm proves nothing`);
    start(d, T0, [grant(KEY, T0)]);
    const mode = statSync(join(d, GRANT_MEMORY_FILE)).mode & 0o777;
    assert(mode === 0o640, `begun memory mode ${mode.toString(8)} under a default ACL`);
    const acl = execFileSync("getfacl", ["-p", join(d, GRANT_MEMORY_FILE)], { encoding: "utf8" });
    assert(/^other::---$/m.test(acl), acl);
  });

  await check("GM-3 · MISSING while the event book names an earlier boundary → BEGUN_AFTER_LOSS (a root deletion is not a fresh start)", () => {
    const d = dir("lost");
    const [s, o] = start(d, T0 + 10, [grant(KEY, T0)], ["a".repeat(64)]);
    assert(o.begun === "BEGUN_AFTER_LOSS" && s.state() === "BEGUN_AFTER_LOSS", s.state());
    assert(s.effective(grant(KEY, T0))!.at === T0 + 10, "every grant re-first-seen now (only later)");
  });

  await check("GM-4 · SEEDED adopt appends NOTHING; effective = declared; a later start names the same boundary and stays SEEDED; another boundary than the book's last → RESEEDED", () => {
    const d = dir("seed");
    const chain = seedChain(DH, "S216-2-grant-memory", [grant(KEY, T0)], T0 + 100);
    writeFileSync(join(d, GRANT_MEMORY_FILE), chain.map((r) => JSON.stringify(r)).join("\n") + "\n", { mode: 0o640 });
    const before = readFileSync(join(d, GRANT_MEMORY_FILE));
    const [s, o] = start(d, T0 + 99999, [grant(KEY, T0)]);
    assert(o.found === "OK" && o.formed.length === 0 && s.state() === "SEEDED", JSON.stringify({ o, st: s.state() }));
    assert(sha(readFileSync(join(d, GRANT_MEMORY_FILE))) === sha(before), "the seeded file changed");
    assert(s.effective(grant(KEY, T0))!.at === T0, "effective = declared on a seeded grant");
    const [s2] = start(d, T0 + 199999, [grant(KEY, T0)], [chain[0].hash]);
    assert(s2.state() === "SEEDED", s2.state());
    const [s3] = start(d, T0 + 299999, [grant(KEY, T0)], [chain[0].hash, "b".repeat(64)]);
    assert(s3.state() === "RESEEDED", s3.state());
  });

  for (const [name, corrupt] of [
    ["a flipped byte", (b: Buffer) => { const c = Buffer.from(b); const i = c.indexOf("firstSeenAt") + 14; c[i] = c[i] === 0x31 ? 0x32 : 0x31; return c; }],
    ["an extra key", (b: Buffer) => Buffer.from(b.toString("utf8").replace('"kind":"GRANT_FIRST_SEEN"', '"kind":"GRANT_FIRST_SEEN","x":1'))],
    ["a broken chain", (b: Buffer) => { const lines = b.toString("utf8").split("\n"); const r = JSON.parse(lines[1]); r.previousHash = "0".repeat(64); return Buffer.from([lines[0], JSON.stringify(r), ...lines.slice(2)].join("\n")); }],
    ["a line that is not JSON", (b: Buffer) => Buffer.from(b.toString("utf8").replace("\n", "\n{not json\n"))],
  ] as const) {
    await check(`GM-5 · CORRUPT (${name}) → F-2 (a): moved aside BYTE-FOR-BYTE (never edited), a new chain BEGUN_AFTER_LOSS naming the aside and its sha256; startup never refused`, () => {
      const d = dir("corrupt");
      start(d, T0, [grant(KEY, T0)]);
      const bad = corrupt(readFileSync(join(d, GRANT_MEMORY_FILE)));
      writeFileSync(join(d, GRANT_MEMORY_FILE), bad);
      const [s, o] = start(d, T0 + 50, [grant(KEY, T0)]);
      assert(o.found === "LOSS" && o.begun === "BEGUN_AFTER_LOSS" && o.aside !== null, JSON.stringify(o));
      assert(sha(readFileSync(o.aside!)) === sha(bad), "the aside is not the found bytes");
      const rows = rowsOf(d);
      assert(rows[0].begun === "BEGUN_AFTER_LOSS" && rows[0].aside.path === o.aside && rows[0].aside.sha256 === sha(bad), JSON.stringify(rows[0]));
      assert(s.effective(grant(KEY, T0))!.at === T0 + 50, "a loss only moves the since later");
      assert(s.state() === "BEGUN_AFTER_LOSS", s.state());
    });
  }

  await check("GM-6 · UNREADABLE (EACCES on the file) → aside + BEGUN_AFTER_LOSS, sha256 null; startup never refused", () => {
    if (process.getuid!() === 0) return "SKIP" as never;
    const d = dir("eacces");
    start(d, T0, [grant(KEY, T0)]);
    chmodSync(join(d, GRANT_MEMORY_FILE), 0o000);
    const [s, o] = start(d, T0 + 7, [grant(KEY, T0)]);
    assert(o.found === "LOSS" && /unreadable \(EACCES\)/.test(o.foundReason ?? ""), JSON.stringify(o));
    assert(o.aside !== null && existsSync(o.aside), "not moved aside");
    assert(rowsOf(d)[0].aside.sha256 === null, "an unreadable file has no sha here");
    assert(s.state() === "BEGUN_AFTER_LOSS", s.state());
  });

  await check("GM-7 · TORN LAST LINE → F-7 (a) RECOVERED_PREFIX: aside, the verified prefix carried with its ORIGINAL first sights and high-water, the torn row never landed", () => {
    const d = dir("torn");
    start(d, T0 + 1, [grant(KEY, T0)]);
    const [, o2] = start(d, T0 + 2, [grant(KEY, T0 + 1), grant(KEY2, T0)]); // raise KEY (F-3) and first-see KEY2
    assert(o2.raised.length === 1 && o2.firstSeen.length === 1, JSON.stringify(o2));
    const whole = readFileSync(join(d, GRANT_MEMORY_FILE));
    const torn = Buffer.concat([whole, Buffer.from('{"kind":"GRANT_RETIRED","key":{"subj')]);
    writeFileSync(join(d, GRANT_MEMORY_FILE), torn);
    const [s, o] = start(d, T0 + 900, [grant(KEY, T0), grant(KEY2, T0)]);
    assert(o.found === "TORN" && o.begun === "RECOVERED_PREFIX" && o.aside !== null, JSON.stringify(o));
    assert(sha(readFileSync(o.aside!)) === sha(torn), "the aside is not the found bytes");
    const rows = rowsOf(d);
    assert(rows[0].begun === "RECOVERED_PREFIX" && rows[0].prefixHead === JSON.parse(whole.toString("utf8").trim().split("\n").pop()!).hash, JSON.stringify(rows[0]));
    assert(s.effective(grant(KEY, T0))!.at === T0 + 1, `KEY keeps its first sight and high-water: ${JSON.stringify(s.effective(grant(KEY, T0)))}`);
    assert(s.effective(grant(KEY2, T0))!.at === T0 + 2, "KEY2 keeps its first sight");
    assert(s.state() === "RECOVERED_PREFIX", s.state());
  });

  await check("GM-8 · LOCK HELD AT START (a crash's leftover): the chain is ADOPTED (read without the lock), nothing re-stamped, state NOT_PERSISTED; the new grant is held in RAM at its first sight and written with that value once the lock is gone", () => {
    const d = dir("lock");
    start(d, T0, [grant(KEY, T0)]);
    const before = readFileSync(join(d, GRANT_MEMORY_FILE));
    writeFileSync(join(d, `${GRANT_MEMORY_FILE}.lock`), "999999\n");
    const [s, o] = start(d, T0 + 3000, [grant(KEY, T0), grant(KEY2, T0)]);
    assert(o.found === "OK" && !o.persisted && s.state() === "NOT_PERSISTED", JSON.stringify(o));
    assert(sha(readFileSync(join(d, GRANT_MEMORY_FILE))) === sha(before), "a held lock did not stop the write");
    assert(s.effective(grant(KEY, T0))!.at === T0, "an existing entry was re-stamped");
    assert(s.effective(grant(KEY2, T0))!.at === T0 + 3000, "the RAM first sight");
    const tagHeld = s.tag([grant(KEY, T0), grant(KEY2, T0)]);
    require("fs").unlinkSync(join(d, `${GRANT_MEMORY_FILE}.lock`));
    const later = s.applyAtReload(facts(T0 + 9000, [grant(KEY, T0), grant(KEY2, T0)]));
    assert(later.persisted && s.state() === "BEGUN", `${JSON.stringify(later)} ${s.state()}`);
    const rows = rowsOf(d);
    assert(rows.some((r) => r.kind === "GRANT_FIRST_SEEN" && r.key.itemId === "i-h" && r.firstSeenAt === T0 + 3000), "written with its ORIGINAL first sight");
    assert(s.tag([grant(KEY, T0), grant(KEY2, T0)]) !== tagHeld, "the tag moves when the held row lands (it covers written rows only)");
  });

  await check("GM-9 · EACCES ON THE DIRECTORY at the first start → NOT_PERSISTED, RAM chain, startup never refused; the tag carries no boundary", () => {
    if (process.getuid!() === 0) return "SKIP" as never;
    const d = dir("rodir");
    chmodSync(d, 0o555);
    try {
      const [s, o] = start(d, T0 + 1, [grant(KEY, T0)]);
      assert(!o.persisted && s.state() === "NOT_PERSISTED" && /EACCES/.test(o.error ?? ""), JSON.stringify(o));
      assert(s.effective(grant(KEY, T0))!.at === T0 + 1, "the RAM first sight governs");
    } finally {
      chmodSync(d, 0o755);
    }
  });

  await check("GM-10 · ENOSPC (a short write, then the error): the file is truncated back to the size found — NO TORN TAIL — and the next start reads it OK", () => {
    const d = dir("enospc");
    start(d, T0, [grant(KEY, T0)]);
    const size = statSync(join(d, GRANT_MEMORY_FILE)).size;
    let calls = 0;
    const fsx: GrantMemoryFs = {
      openSync: require("fs").openSync,
      fsyncSync: require("fs").fsyncSync,
      writeSync: ((fd: number, buf: any, off?: number, len?: number) => {
        if (typeof buf === "string") return realWriteSync(fd, buf);
        calls++;
        if (calls === 1) return realWriteSync(fd, buf, off, Math.max(1, Math.floor((len ?? buf.length) / 2)));
        throw Object.assign(new Error("ENOSPC: no space left on device"), { code: "ENOSPC" });
      }) as never,
    };
    const [s, o] = start(d, T0 + 10, [grant(KEY, T0), grant(KEY2, T0)], [], null, fsx);
    assert(!o.persisted && /ENOSPC/.test(o.error ?? "") && s.state() === "NOT_PERSISTED", JSON.stringify(o));
    assert(statSync(join(d, GRANT_MEMORY_FILE)).size === size, `size ${statSync(join(d, GRANT_MEMORY_FILE)).size} !== ${size}: a torn tail was left`);
    assert(readGrantMemory(join(d, GRANT_MEMORY_FILE)).kind === "OK", "the file does not read OK after the failed write");
  });

  await check("GM-11 · GM3 + GM1 · REMOVE THEN RE-ADD ACROSS TWO RESTARTS: the re-add is a NEW first sight (the gap's changes are not re-granted by a back-dated since)", () => {
    const d = dir("readd");
    start(d, T0, [grant(KEY, T0)]);
    const [, o2] = start(d, T0 + 100, []);
    assert(o2.retired.length === 1, "not retired");
    const [s3] = start(d, T0 + 200, [grant(KEY, T0)]);
    assert(s3.effective(grant(KEY, T0))!.at === T0 + 200, `re-add: ${JSON.stringify(s3.effective(grant(KEY, T0)))}`);
  });

  await check("GM-12 · A CHANGED PATH under one item id, and a RE-BOUND origin, are different grants → new first sights (the old ones retired)", () => {
    const d = dir("rekey");
    start(d, T0, [grant(KEY, T0)]);
    const moved: GrantKey = { ...KEY, path: "/srv/a/moved.txt" };
    const [s2, o2] = start(d, T0 + 10, [grant(moved, T0)]);
    assert(o2.retired.length === 1 && s2.effective(grant(moved, T0))!.at === T0 + 10, "path change");
    const rebound: GrantKey = { ...moved, originSubject: "subject-b" };
    const [s3, o3] = start(d, T0 + 20, [grant(rebound, T0)]);
    assert(o3.retired.length === 1 && s3.effective(grant(rebound, T0))!.at === T0 + 20, "origin re-bound");
  });

  await check("GM-13 · THE CLAMP (C2): a clock stepped BACK reads no earlier than the memory's last write, and no earlier than the newest record in the books the load reads", () => {
    const d = dir("clamp");
    start(d, T0 + 5000, [grant(KEY, T0)]);
    const [s2] = start(d, T0 + 2400, [grant(KEY, T0), grant(KEY2, T0)]); // stepped back 2.6 s
    assert(s2.effective(grant(KEY2, T0))!.at === T0 + 5000, `memory clamp: ${JSON.stringify(s2.effective(grant(KEY2, T0)))}`);
    const d2 = dir("clamp2");
    const [s3] = start(d2, T0 + 2400, [grant(KEY, T0)], [], T0 + 2600);
    assert(s3.effective(grant(KEY, T0))!.at === T0 + 2600, `book clamp: ${JSON.stringify(s3.effective(grant(KEY, T0)))}`);
  });

  await check("GM-14 · F-3 HIGH-WATER: a since raised by one restart and lowered by the next holds the raised one (records in [S0′, S1) never become granted)", () => {
    const d = dir("hw");
    start(d, T0, [grant(KEY, T0)]);
    const [, o2] = start(d, T0 + 50, [grant(KEY, T0 + 40)]);
    assert(o2.raised.length === 1, "no GRANT_SINCE_RAISED");
    const [s3, o3] = start(d, T0 + 60, [grant(KEY, T0 + 10)]);
    assert(o3.formed.length === 0, "a lowered since wrote a row");
    assert(s3.effective(grant(KEY, T0 + 10))!.at === T0 + 40, `high-water: ${JSON.stringify(s3.effective(grant(KEY, T0 + 10)))}`);
  });

  await check("GM-15 · AN HONEST LATER DECLARED SINCE GOVERNS: declared after the first sight → effective = declared (not the first sight)", () => {
    const d = dir("later");
    const [s] = start(d, T0, [grant(KEY, T0 + 7000)]);
    assert(s.effective(grant(KEY, T0 + 7000))!.at === T0 + 7000, JSON.stringify(s.effective(grant(KEY, T0 + 7000))));
  });

  await check("GM-16 · cond. 1 at the bridge: a since BACK-DATED ACROSS A RESTART to before the latched record counts from the memory's first sight; the wire carries effective at/utc and the declared since beside it; the class does not move", () => {
    const d = dir("backdate");
    const [s1] = start(d, T0 + 1000, [grant(KEY, T0 + 500)]);
    void s1;
    const [s2] = start(d, T0 + 9000, [grant(KEY, T0 + 500), grant(KEY2, T0 + 100)]); // KEY2 new, back-dated to T0+100
    const e = s2.effective(grant(KEY2, T0 + 100))!;
    assert(e.at === T0 + 9000, `effective ${JSON.stringify(e)}`);
    const h: any = harmStanza({ "i-g": ["o-a"], "i-h": ["o-a"] }, { "i-g": isoOf(T0 + 500), "i-h": isoOf(T0 + 100) });
    const view = { tag: s2.tag(declaredGrantsOf({ "subject-a": h })), state: s2.state(), effective: (g: DeclaredGrant) => s2.effective(g) };
    const w = gate2WireHarm("subject-a", h, null, view);
    assert(w.grantSince["i-h"]["o-a"].at === T0 + 9000 && w.grantSince["i-h"]["o-a"].utc === isoOf(T0 + 9000), JSON.stringify(w.grantSince));
    assert(w.grantSince["i-h"]["o-a"].declaredAt === T0 + 100 && w.grantSince["i-h"]["o-a"].declaredUtc === isoOf(T0 + 100), JSON.stringify(w.grantSince));
    assert(w.grantSince["i-g"]["o-a"].at === T0 + 1000, "i-g's first sight");
    assert(/^G2_GRANT_MEMORY@[0-9a-f]{16}$/.test(w.grantMemory.tag) && w.grantMemory.state === s2.state(), JSON.stringify(w.grantMemory));
    assert(w.harmClass === gate2HarmClass("subject-a", h), "the class moved");
    const bare = gate2WireHarm("subject-a", h, null, null) as any;
    assert(bare.grantMemory === undefined && bare.grantSince["i-h"]["o-a"].at === T0 + 100, "no view: no grantMemory key (the machine reads BLIND), declared since only");
  });

  await check("GM-17 · THE TAG: the boundary is digested (a memory begun afresh with identical rows moves it); the state is NOT (a NOT_PERSISTED flip does not move it); rows are the persisted ones", () => {
    const g = [grant(KEY, T0)];
    const a = dir("tagA");
    const b = dir("tagB");
    const seedA = seedChain(DH, "t", g, T0 + 1);
    const seedB = seedChain(DH2, "t", g, T0 + 1);
    writeFileSync(join(a, GRANT_MEMORY_FILE), seedA.map((r) => JSON.stringify(r)).join("\n") + "\n");
    writeFileSync(join(b, GRANT_MEMORY_FILE), seedB.map((r) => JSON.stringify(r)).join("\n") + "\n");
    const [sa] = start(a, T0 + 2, g);
    const [sb] = start(b, T0 + 2, g);
    assert(sa.effective(g[0])!.at === sb.effective(g[0])!.at, "control: identical effective sinces");
    assert(sa.tag(g) !== sb.tag(g), "tag-without-boundary: two boundaries, one tag");
    writeFileSync(join(a, `${GRANT_MEMORY_FILE}.lock`), "1\n");
    const [sa2] = start(a, T0 + 3, g); // nothing to write: state stays SEEDED, tag same
    const [sa3] = start(a, T0 + 4, [...g, grant(KEY2, T0)]); // a held row: NOT_PERSISTED
    assert(sa3.state() === "NOT_PERSISTED" && sa2.state() === "SEEDED", `${sa2.state()} ${sa3.state()}`);
    assert(sa3.tag(g) === sa.tag(g), "state-in-digest: NOT_PERSISTED moved the tag over the same written rows");
  });

  await check("GM-18 · RELOAD: a retirement or a raised since that cannot persist REFUSES the reload (memory unchanged); a first sight that cannot persist is held (NOT_PERSISTED) and the reload stands", () => {
    const d = dir("reload");
    const [s] = start(d, T0, [grant(KEY, T0), grant(KEY2, T0)]);
    writeFileSync(join(d, `${GRANT_MEMORY_FILE}.lock`), "1\n");
    let threw = "";
    try {
      s.applyAtReload(facts(T0 + 10, [grant(KEY, T0)]));
    } catch (e) {
      threw = e instanceof GrantMemoryWriteError ? e.message : `other: ${String(e)}`;
    }
    assert(/GRANT_MEMORY_NOT_PERSISTED/.test(threw), `retire not refused: ${threw}`);
    assert(s.effective(grant(KEY2, T0)) !== null && s.state() === "BEGUN", "a refused reload changed the memory");
    threw = "";
    try {
      s.applyAtReload(facts(T0 + 10, [grant(KEY, T0 + 5), grant(KEY2, T0)]));
    } catch (e) {
      threw = e instanceof GrantMemoryWriteError ? e.message : `other: ${String(e)}`;
    }
    assert(/GRANT_MEMORY_NOT_PERSISTED/.test(threw), `raise not refused: ${threw}`);
    const third: GrantKey = { ...KEY, itemId: "i-k", path: "/srv/a/k.txt" };
    const o = s.applyAtReload(facts(T0 + 20, [grant(KEY, T0), grant(KEY2, T0), grant(third, T0)]));
    assert(!o.persisted && s.state() === "NOT_PERSISTED" && s.effective(grant(third, T0))!.at === T0 + 20, JSON.stringify(o));
  });

  await check("GM-19 · AT START an unpersistable retirement is honoured in RAM (C7) and printed NOT_PERSISTED; never refused", () => {
    const d = dir("c7");
    start(d, T0, [grant(KEY, T0)]);
    writeFileSync(join(d, `${GRANT_MEMORY_FILE}.lock`), "1\n");
    const [s, o] = start(d, T0 + 5, []);
    assert(o.retired.length === 1 && !o.persisted && s.state() === "NOT_PERSISTED", JSON.stringify(o));
    assert(s.effective(grant(KEY, T0)) === null, "the RAM retirement does not govern this process");
  });

  await check("GM-20 · applyAtReload before adopt throws RELOAD_BEFORE_MEMORY_ADOPTED; a found file the bridge cannot move aside is never written over (RAM only)", () => {
    const s = new GrantMemoryStore(dir("early"));
    let msg = "";
    try {
      s.applyAtReload(facts(T0, []));
    } catch (e) {
      msg = String(e);
    }
    assert(/RELOAD_BEFORE_MEMORY_ADOPTED/.test(msg), msg);
    if (process.getuid!() === 0) return;
    const d = dir("stuck");
    start(d, T0, [grant(KEY, T0)]);
    writeFileSync(join(d, GRANT_MEMORY_FILE), "garbage\n");
    chmodSync(d, 0o555);
    try {
      const [s2, o2] = start(d, T0 + 1, [grant(KEY, T0)]);
      assert(o2.found === "LOSS" && o2.aside === null && o2.asideError !== null && !o2.persisted && s2.state() === "NOT_PERSISTED", JSON.stringify(o2));
      assert(readFileSync(join(d, GRANT_MEMORY_FILE), "utf8") === "garbage\n", "the found file was edited");
    } finally {
      chmodSync(d, 0o755);
    }
  });

  await check("GM-21 · THE SEED: the builder's chain verifies; a flipped byte does not; adopted it appends nothing and its predicted tag is the bridge's", () => {
    const g = [grant(KEY, T0)];
    const chain = seedChain(DH, "S216-2-grant-memory", g, T0 + 1);
    const bytes = Buffer.from(chain.map((r) => JSON.stringify(r)).join("\n") + "\n");
    const v = verifyGrantMemoryBytes(bytes);
    assert(v.ok, JSON.stringify(v));
    const flipped = Buffer.from(bytes);
    flipped[bytes.indexOf("subject-a") + 2] ^= 1;
    assert(!verifyGrantMemoryBytes(flipped).ok, "a flipped byte verified");
    assert(!verifyGrantMemoryBytes(bytes.subarray(0, bytes.length - 3)).ok, "a torn candidate verified");
    const d = dir("seedtag");
    writeFileSync(join(d, GRANT_MEMORY_FILE), bytes);
    const [s, o] = start(d, T0 + 1e6, g);
    assert(o.formed.length === 0 && s.state() === "SEEDED", JSON.stringify(o));
    const predicted = `G2_GRANT_MEMORY@${createHash("sha256").update(JSON.stringify(["G2_GRANT_MEMORY_V1", chain[0].hash, [["i-g", "o-a", isoOf(T0), isoOf(T0)]]])).digest("hex").slice(0, 16)}`;
    assert(s.tag(g) === predicted, `${s.tag(g)} !== ${predicted}`);
  });

  await check("GM-22 · appendGrantMemory refuses a chain that moved under it (a second writer) and leaves no lock", () => {
    const d = dir("moved");
    start(d, T0, [grant(KEY, T0)]);
    const b = boundaryRecord({ begun: "BEGUN", declarationHash: DH, ticket: null, aside: null, prefixHead: null, timestamp: T0 });
    let msg = "";
    try {
      appendGrantMemory(join(d, GRANT_MEMORY_FILE), [firstSeenRecord(b.hash, KEY2, T0, T0, T0)], b.hash);
    } catch (e) {
      msg = String(e);
    }
    assert(/no longer ends at the chain/.test(msg), msg);
    assert(!existsSync(join(d, `${GRANT_MEMORY_FILE}.lock`)), "lock left");
  });

  // ── the loader (cond. 9: the refusal of a declared path naming the memory) ──
  await check("GM-23 · THE LOADER refuses a declared path whose canonical form names the memory, its lock, an aside or a seed temp — a refusal of the DECLARATION", () => {
    const base = shippedDraft();
    const ok = validateDeclarations(JSON.parse(JSON.stringify(base)), new Date("2026-10-17T00:00:00Z"));
    assert(ok.declarationHash.length === 64, "control: the tree declaration loads");
    for (const v of ["/var/lib/mica-bridge/grant-memory", "/var/lib/mica-bridge/grant-memory.lock", "/var/lib/mica-bridge/x/../grant-memory", "/var/lib/mica-bridge/grant-memory.torn-1", "/var/lib/mica-bridge/.grant-memory.seed-2"]) {
      const d = JSON.parse(JSON.stringify(base));
      d.paths.ledger = v;
      let msg = "";
      try {
        validateDeclarations(d, new Date("2026-10-17T00:00:00Z"));
      } catch (e) {
        msg = String((e as Error).message);
      }
      assert(/names the bridge's grant memory/.test(msg), `${v}: ${msg || "accepted"}`);
    }
  });

  // ── the service: GM0 placement, the event book, the reload gate ──────────────
  await check("GM-24 · SERVICE · start() adopts the memory after the history claim (GRANT_MEMORY_BEGUN row naming the boundary, the file 0640); a restart ADOPTS it (state BEGUN, nothing appended); the wire carries tag + state", async () => {
    const r = await serviceRig();
    let boundary = "";
    try {
      await new Promise((res) => setTimeout(res, 100)); // the event book's appends are queued
      const book = events(r.stateDir);
      const begun = book.find((e) => e.kind === "GRANT_MEMORY_BEGUN");
      assert(begun !== undefined && /boundary=[0-9a-f]{64}/.test(begun.detail), JSON.stringify(book.map((e) => e.kind)));
      boundary = /boundary=([0-9a-f]{64})/.exec(begun.detail)![1];
      const claim = book.findIndex((e) => e.kind === "GRANT_MEMORY_BEGUN");
      assert(claim >= 0, "no begun row");
      assert((statSync(join(r.stateDir, GRANT_MEMORY_FILE)).mode & 0o777) === 0o640, "mode");
      const view = (r.svc as any).grantMemoryViewFor((r.svc as any).state.declarations);
      assert(view !== null && view.state === "BEGUN" && /^G2_GRANT_MEMORY@[0-9a-f]{16}$/.test(view.tag), JSON.stringify(view));
    } finally {
      await r.svc.stop();
    }
    const size = statSync(join(r.stateDir, GRANT_MEMORY_FILE)).size;
    const again = await serviceRig(r.stateDir);
    try {
      await new Promise((res) => setTimeout(res, 100));
      const adopted = events(again.stateDir).filter((e) => e.kind === "GRANT_MEMORY_ADOPTED");
      assert(adopted.length === 1 && adopted[0].detail.includes(`boundary=${boundary}`) && adopted[0].detail.includes("appended=0"), JSON.stringify(adopted));
      assert(statSync(join(again.stateDir, GRANT_MEMORY_FILE)).size === size, "a restart appended");
    } finally {
      await again.svc.stop();
    }
  });

  await check("GM-25 · SERVICE · GM0: a reload before start() adopted the memory is REFUSED (RELOAD_BEFORE_MEMORY_ADOPTED), and writes nothing", async () => {
    const r = await serviceRig(undefined, false);
    const out = r.svc.reload();
    assert(!out.ok && /RELOAD_BEFORE_MEMORY_ADOPTED/.test((out as any).reason), JSON.stringify(out));
    assert(!existsSync(join(r.stateDir, GRANT_MEMORY_FILE)), "the refused reload wrote the memory");
  });

  await check("GM-26 · SERVICE · a SIGHUP reload that narrows a grant while the memory cannot be written is REFUSED: last-good keeps serving, DECLARATION_REJECTED names grantMemory", async () => {
    const r = await serviceRig();
    try {
      const hashBefore = (r.svc as any).state.declarationHash;
      writeFileSync(join(r.stateDir, `${GRANT_MEMORY_FILE}.lock`), "1\n");
      const narrowed = JSON.parse(JSON.stringify(r.cfg));
      narrowed.harm["subject-a"].grants.value["i-granted"] = { origins: [], since: {}, basis: BASIS };
      writeFileSync(r.cfgPath, JSON.stringify(narrowed));
      const out = r.svc.reload();
      assert(!out.ok && /GRANT_MEMORY_NOT_PERSISTED/.test((out as any).reason), JSON.stringify(out));
      assert((r.svc as any).state.declarationHash === hashBefore, "last-good was replaced");
      await new Promise((res) => setTimeout(res, 50));
      const rej = events(r.stateDir).filter((e) => e.kind === "DECLARATION_REJECTED");
      assert(rej.some((e) => /field=grantMemory/.test(e.detail)), JSON.stringify(rej));
    } finally {
      await r.svc.stop();
    }
  });

  await check("GM-27 · SERVICE · a CORRUPT memory at start never refuses startup: SERVING, the file set aside byte-for-byte, BEGUN_AFTER_LOSS, a GRANT_MEMORY_LOSS row naming the aside", async () => {
    const sd = mkdtempSync(join(tmpdir(), "mica-gm-state-"));
    writeFileSync(join(sd, GRANT_MEMORY_FILE), "{\"kind\":\"not a boundary\"}\n");
    const r = await serviceRig(sd);
    try {
      await new Promise((res) => setTimeout(res, 100));
      const loss = events(sd).filter((e) => e.kind === "GRANT_MEMORY_LOSS");
      assert(loss.length === 1 && /moved aside to /.test(loss[0].detail), JSON.stringify(events(sd).map((e) => e.kind)));
      const aside = readdirSync(sd).filter((n) => n.startsWith(`${GRANT_MEMORY_FILE}.unreadable-`));
      assert(aside.length === 1 && readFileSync(join(sd, aside[0]), "utf8") === "{\"kind\":\"not a boundary\"}\n", JSON.stringify(aside));
      const view = (r.svc as any).grantMemoryViewFor((r.svc as any).state.declarations);
      assert(view !== null && view.state === "BEGUN_AFTER_LOSS", JSON.stringify(view));
      assert((r.svc as any).buildStatus().preflight === "SERVING", "not serving");
    } finally {
      await r.svc.stop();
    }
  });

  console.log(`CENSUS: ${passed} passed, ${failed} failed, ${skipped} skipped, ${passed + failed + skipped} total`);
  if (failed > 0) process.exit(1);
  process.exit(0);
}

// ── service rig (the gate2-harm suite's shape; fixture names only) ───────────────
const BASIS = "S216-2 GRANT MEMORY FIXTURE, not a declaration.";
const PATH_BASIS = "S216-2 GRANT MEMORY FIXTURE: the witness's seeing half owns this path under its own uid; the bridge only drops pointers into it or reads it.";
const OWN_UID = process.getuid ? process.getuid() : 0;
const OWN_GID = process.getgid ? process.getgid() : 0;
const RETIRED_NAME = "subject-events.TESTFIXTURE.pre-chain-boundary.jsonl";
const RETIRED_BODY = JSON.stringify({ sequenceNumber: 1, timestamp: 1, moduleId: "subject-a", eventType: "TOOL_ATTEMPTED", outcome: "tool-x" }) + "\n";
const METHOD = "bd91dc37fa7e5d0653c795c4878266a4482c1405d932ce0b073d50b5bce41b72";

function harmStanza(grants: Record<string, string[]>, since: Record<string, string>): any {
  const items: any = {};
  const g: any = {};
  for (const id of Object.keys(grants)) {
    items[id] = { path: id === "i-g" ? KEY.path : id === "i-h" ? KEY2.path : `/srv/a/b/${id}.txt`, category: "c-other", control: false, basis: BASIS };
    g[id] = { origins: grants[id], since: grants[id].length === 0 ? {} : { [grants[id][0]]: since[id] }, basis: BASIS };
  }
  return {
    harmOnly: { value: true, basis: BASIS, proxy: false },
    origins: { value: { "o-a": { subject: "subject-a", basis: BASIS } }, basis: BASIS, proxy: false },
    items: { value: items, basis: BASIS, proxy: true },
    grants: { value: g, basis: BASIS, proxy: false },
    clearances: { value: [], basis: BASIS, proxy: false },
  };
}

function serviceDeclaration(): any {
  const d = shippedDraft();
  d.pilot = { active: false };
  delete d.readers.gate1Scope;
  delete d.baskets;
  d.readers.gate2Direction = {
    subject: { value: "subject-a", basis: BASIS, proxy: false },
    book: { value: "witnessBook", basis: BASIS, proxy: false },
    witnessMethod: { value: METHOD, basis: BASIS, proxy: false },
  };
  const frame = {
    categories: {
      value: [
        { id: "c-self", label: "own working area", grounding: "agency", self: true },
        { id: "c-other", label: "another principal's area", grounding: "vulnerability", self: false },
      ],
      basis: BASIS,
      proxy: true,
    },
    regions: { value: [{ prefix: "/srv/a", category: "c-self" }, { prefix: "/srv/a/b", category: "c-other" }], basis: BASIS, proxy: true },
  };
  d.harm = { "subject-a": harmStanza({ "i-kept": [], "i-granted": ["o-a"] }, { "i-granted": "2026-01-01T00:00:00.000Z" }) };
  d.subjectLog.chainBoundary.retiredPath.value = `/var/lib/mica-bridge/${RETIRED_NAME}`;
  d.subjectLog.chainBoundary.retiredRecords.value = 1;
  d.subjectLog.chainBoundary.retiredBytes.value = Buffer.byteLength(RETIRED_BODY, "utf8");
  d.subjectLog.chainBoundary.retiredSha256.value = createHash("sha256").update(RETIRED_BODY, "utf8").digest("hex");
  d.subjects = [{ ...d.subjects[0], subject: "subject-a", toolName: "tool-x", peerUid: OWN_UID }];
  delete d.subjects[0].unit;
  d.routes = [{ uid: OWN_UID, role: "subject", allow: [{ method: "POST", path: "/guard" }, { method: "POST", path: "/subject-events" }] }];
  d.frame = { "subject-a": frame };
  d.paths.interestBook = "/var/lib/mica-bridge/interest-book.jsonl";
  d.paths.witnessIntake = { value: "/var/lib/mica/witness-sight/intake", basis: PATH_BASIS };
  d.paths.witnessBook = { value: "/var/lib/mica/witness-sight/book-of-effects.jsonl", basis: PATH_BASIS };
  return d;
}

async function serviceRig(stateDir?: string, doStart = true): Promise<{ svc: MicaBridgeService; stateDir: string; cfg: any; cfgPath: string }> {
  const socketDir = mkdtempSync(join(tmpdir(), "mica-gm-svc-"));
  const peer = join(socketDir, "peers", String(OWN_UID));
  mkdirSync(peer, { recursive: true });
  chmodSync(peer, 0o770);
  const cfgDir = mkdtempSync(join(tmpdir(), "mica-gm-cfg-"));
  const cfgPath = join(cfgDir, "declarations.config.json");
  const cfg = serviceDeclaration();
  writeFileSync(cfgPath, JSON.stringify(cfg));
  const sd = stateDir ?? mkdtempSync(join(tmpdir(), "mica-gm-state-"));
  writeFileSync(join(sd, RETIRED_NAME), RETIRED_BODY);
  const intake = join(mkdtempSync(join(tmpdir(), "mica-gm-intake-")), "intake");
  mkdirSync(intake);
  const svc = new MicaBridgeService({
    declarationsPath: cfgPath,
    socketDir,
    now: () => new Date("2026-10-17T00:00:00Z"),
    testBridgeGid: OWN_GID,
    stateDir: sd,
    testWritablePaths: { witnessIntake: intake },
  });
  if (doStart) await svc.start();
  return { svc, stateDir: sd, cfg, cfgPath };
}

function events(stateDir: string): any[] {
  const p = join(stateDir, "events.jsonl");
  if (!existsSync(p)) return [];
  return readFileSync(p, "utf8").split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
