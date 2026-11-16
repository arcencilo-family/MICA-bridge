#!/usr/bin/env node
// ── render-tmpfiles — generate mica-bridge.tmpfiles.conf FROM the declaration ─
//
// `/run` is tmpfs: every per-uid peer-socket directory
// (`/run/mica-bridge/peers/<uid>/`, ruling K amended) must be recreated on
// every boot, owned `<uid>:mica-bridge` mode 0770, before mica-bridge.service
// starts. Hand-writing that list would drift from `declarations.config.json`
// the first time a `routes[]` row changes — so this script IS the only
// place the list is written, and the committed `.conf` is checked (by
// `mica-service.test.ts`) to equal this script's own output, run fresh.
//
// POST-CLOSURE FIX 1 (Stage 2 closed at `f66c297`; found during Stage 4's
// real-box install, not by any test — see the receipt for why nothing
// caught it): the two PARENT directories (`/run/mica-bridge`,
// `/run/mica-bridge/peers`) were `0750 mica-bridge mica-bridge` — group
// `mica-bridge` (gid 972), which NO caller uid is a member of. The leaves
// were exactly right (`0770 <uid> mica-bridge`, owner-exact) but nothing
// could ever traverse the corridor leading to them: `ls`/`cd` through a
// `0750` directory you are neither the owner nor a group member of fails
// outright. Ruled (the arbiter, option (a)): the two parents are now `0711 root
// root` — world-TRAVERSABLE (the execute/search bit, `x`), never
// world-READABLE (no `r`, so nobody can `ls` to enumerate who else has a
// peer directory) — root-owned since no single caller uid should own the
// corridor either. The leaf is UNCHANGED: `0770 <uid> mica-bridge`, still
// exactly one uid. Ruling K(b) itself is untouched — the boundary this
// project draws was never the parents, it is, and remains, the leaf.
//
// The rejected alternative was adding every caller uid to group
// `mica-bridge` instead of widening the parents' mode — that would have
// also handed every caller READ access to `/var/lib/mica-bridge` itself
// (0750, the SAME group), which holds the decision journal, event book,
// and subject log. A real widening of what callers can read, to buy a
// traversal bit that `0711` buys for free without touching group
// membership at all. Refused.
//
// Usage: ts-node deploy/render-tmpfiles.ts > deploy/mica-bridge.tmpfiles.conf

import { execFileSync } from "child_process";
import { join } from "path";
import { validateDeclarations } from "../declarations";
import { readFileSync } from "fs";

function uidToUsername(uid: number): string {
  try {
    return execFileSync("id", ["-nu", String(uid)], { encoding: "utf8" }).trim();
  } catch {
    return `uid-${uid}`; // host has no such account; named literally rather than guessed
  }
}

export function renderTmpfiles(declarationsPath: string): string {
  const declarations = validateDeclarations(JSON.parse(readFileSync(declarationsPath, "utf8"))).declarations;
  const lines: string[] = [
    "# ─────────────────────────────────────────────────────────────────────────",
    "# mica-bridge.tmpfiles.conf — GENERATED. Do not hand-edit.",
    "#",
    "# Rendered by deploy/render-tmpfiles.ts FROM declarations.config.json's",
    "# routes[] — never hand-typed, so this file cannot drift from the ruled",
    "# uids (Stage 0 X10/X11/X12 already forbid uid 0 and the service's own",
    "# uid from appearing here at all, transitively, since they cannot appear",
    "# in routes[]).",
    "#",
    "# Install (the arbiter's act):",
    "#   sudo install -m 0644 deploy/mica-bridge.tmpfiles.conf /etc/tmpfiles.d/mica-bridge.conf",
    "#   sudo systemd-tmpfiles --create /etc/tmpfiles.d/mica-bridge.conf",
    "#",
    "# Re-render after any change to declarations.config.json's routes[]:",
    "#   ts-node deploy/render-tmpfiles.ts > deploy/mica-bridge.tmpfiles.conf",
    "# mica-service.test.ts asserts the committed file still matches.",
    "# ─────────────────────────────────────────────────────────────────────────",
    "d /run/mica-bridge 0711 root root -",
    "d /run/mica-bridge/peers 0711 root root -",
  ];
  for (const route of declarations.routes) {
    const username = uidToUsername(route.uid);
    lines.push(`d /run/mica-bridge/peers/${route.uid} 0770 ${username} mica-bridge -`);
  }
  return lines.join("\n") + "\n";
}

if (require.main === module) {
  const declarationsPath = process.argv[2] ?? join(__dirname, "..", "declarations.config.json");
  process.stdout.write(renderTmpfiles(declarationsPath));
}
