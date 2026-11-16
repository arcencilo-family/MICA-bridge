// S216-2 · THE SEED'S BUILDER AND VERIFIER (draft §4 step 1; cond. 10). Run at uid 1000 by the seat, and by
// deploy/seed-grant-memory.sh at the arbiter's hand — never by the bridge (a bridge that seeded itself would turn "delete the
// file and restart" into the very back-dating S216-2 closes).
//
//   node <ts-node bin.js> -P mica-bridge/tsconfig.json mica-bridge/tools/grant-memory-seed.ts hash   --declaration P
//   node <ts-node bin.js> -P mica-bridge/tsconfig.json mica-bridge/tools/grant-memory-seed.ts build  --declaration P --out P [--ticket ID]
//   node <ts-node bin.js> -P mica-bridge/tsconfig.json mica-bridge/tools/grant-memory-seed.ts verify --declaration P --candidate P
//
// build: every grant in the declaration (every harm stanza), first seen AT ITS DECLARED SINCE, under a SEEDED
//   boundary naming the canonical declarationHash (loadDeclarations', as relay-bridge.sh computes it) and the ticket.
//   Refuses an existing --out. Writes 0640.
// verify: the release's chain verifier on the candidate's bytes; the boundary is SEEDED and names the declaration's
//   hash; its rows are EXACTLY the declaration's grants, each first seen at its declared since.
// Both print KEY=value lines (the seed script reads them) and the rows, and exit non-zero on any refusal.

import { createHash } from "crypto";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

import { loadDeclarations } from "../declarations";
import {
  declaredGrantsOf,
  GRANT_MEMORY_FILE,
  grantKeyString,
  GrantMemoryStore,
  seedChain,
  verifyGrantMemoryBytes,
  type BoundaryRecord,
  type DeclaredGrant,
  type FirstSeenRecord,
} from "../grant-memory";

function arg(name: string): string | null {
  const i = process.argv.indexOf(name);
  if (i < 0) return null;
  const v = process.argv[i + 1];
  if (v === undefined || v.startsWith("--")) refuse(`${name} needs a value`);
  return v;
}
function refuse(why: string): never {
  console.log(`REFUSE=${why}`);
  process.exit(2);
}
function sha(b: Buffer): string {
  return createHash("sha256").update(b).digest("hex");
}

/** The tag the bridge will print once it adopts these bytes for this declaration (the real store, on a scratch copy). */
function predictedTag(bytes: Buffer, declarationHash: string, all: readonly DeclaredGrant[], wiredSubject: string | null): { tag: string; state: string; appended: number } {
  const d = mkdtempSync(join(tmpdir(), "grant-memory-predict-"));
  writeFileSync(join(d, GRANT_MEMORY_FILE), bytes, { mode: 0o640 });
  const s = new GrantMemoryStore(d);
  const o = s.adopt({ now: Date.now(), bookFloorAt: null, declarationHash, grants: all }, []);
  return { tag: s.tag(all.filter((g) => g.key.subject === wiredSubject)), state: s.state(), appended: o.formed.length };
}

function main(): void {
  const mode = process.argv[2];
  const declPath = arg("--declaration");
  if (declPath === null) refuse("--declaration is required");
  const loaded = loadDeclarations(declPath, new Date());
  const declarationHash = loaded.declarationHash;
  const grants = declaredGrantsOf(loaded.declarations.harm);
  const wired = loaded.declarations.readers.gate2Direction?.subject.value ?? null;
  console.log(`DECLARATION=${declPath}`);
  console.log(`DECLARATION_SHA256=${sha(readFileSync(declPath))}`);
  console.log(`DECLARATION_HASH=${declarationHash}`);
  console.log(`GRANTS=${String(grants.length)}`);
  for (const g of grants) console.log(`GRANT ${grantKeyString(g.key)} since ${g.sinceUtc}`);
  if (mode === "hash") return;

  if (mode === "build") {
    const out = arg("--out");
    if (out === null) refuse("--out is required");
    if (existsSync(out)) refuse(`--out exists: ${out} (a candidate is never overwritten)`);
    const ticket = arg("--ticket") ?? "S216-2-grant-memory";
    const chain = seedChain(declarationHash, ticket, grants, Date.now());
    const bytes = Buffer.from(chain.map((r) => JSON.stringify(r)).join("\n") + "\n", "utf8");
    writeFileSync(out, bytes, { mode: 0o640, flag: "wx" });
    report(out, readFileSync(out), declarationHash, grants, wired);
    return;
  }
  if (mode === "verify") {
    const cand = arg("--candidate");
    if (cand === null) refuse("--candidate is required");
    // read ONCE; every check below is on these bytes
    const bytes = readFileSync(cand);
    report(cand, bytes, declarationHash, grants, wired);
    return;
  }
  refuse(`unknown mode ${String(mode)} (hash | build | verify)`);
}

function report(path: string, bytes: Buffer, declarationHash: string, grants: readonly DeclaredGrant[], wired: string | null): void {
  console.log(`CANDIDATE=${path}`);
  console.log(`CANDIDATE_SHA256=${sha(bytes)}`);
  console.log(`CANDIDATE_BYTES=${String(bytes.length)}`);
  const v = verifyGrantMemoryBytes(bytes);
  if (!v.ok) refuse(`the release's chain verifier rejects the candidate: ${v.reason}`);
  const b = v.records[0] as BoundaryRecord;
  console.log(`BOUNDARY_BEGUN=${b.begun}`);
  console.log(`BOUNDARY_HASH=${b.hash}`);
  console.log(`BOUNDARY_DECLARATION_HASH=${b.declarationHash}`);
  console.log(`BOUNDARY_TICKET=${String(b.ticket)}`);
  console.log(`ROWS=${String(v.records.length - 1)}`);
  for (const r of v.records.slice(1)) {
    if (r.kind !== "GRANT_FIRST_SEEN") refuse(`a seed carries only GRANT_FIRST_SEEN rows; found ${r.kind}`);
    const f = r as FirstSeenRecord;
    console.log(`ROW ${grantKeyString(f.key)} firstSeen ${f.firstSeenUtc} declared ${f.declaredSinceUtc}`);
  }
  if (b.begun !== "SEEDED") refuse(`the boundary is ${b.begun}, not SEEDED`);
  if (b.declarationHash !== declarationHash) refuse(`the boundary names declarationHash ${b.declarationHash}, the declaration hashes ${declarationHash}`);
  const want = new Map(grants.map((g) => [grantKeyString(g.key), g]));
  const rows = v.records.slice(1) as FirstSeenRecord[];
  if (rows.length !== want.size) refuse(`the candidate carries ${String(rows.length)} rows, the declaration ${String(want.size)} grants`);
  for (const r of rows) {
    const g = want.get(grantKeyString(r.key));
    if (g === undefined) refuse(`the candidate seeds a grant the declaration does not carry: ${grantKeyString(r.key)}`);
    if (r.firstSeenAt !== g.sinceAt || r.declaredSinceAt !== g.sinceAt) refuse(`the candidate's first sight of ${grantKeyString(r.key)} is not its declared since`);
  }
  const p = predictedTag(bytes, declarationHash, grants, wired);
  if (p.appended !== 0 || p.state !== "SEEDED") refuse(`adopted on a scratch copy the candidate appended ${String(p.appended)} rows and reads ${p.state}`);
  console.log(`PREDICTED_TAG=${p.tag}`);
  console.log(`PREDICTED_STATE=${p.state}`);
  console.log("VERIFY=OK");
}

main();
