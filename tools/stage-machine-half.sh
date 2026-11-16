#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# stage-machine-half.sh — run the bridge's checks against a machine tree, without root.
#
# The bridge imports the machine by an absolute path (`/opt/mica-machine/src/...`,
# in stage1-guard-adapter.ts and a few other files), and its tsconfig.json points
# `typeRoots` there. Placing a machine at /opt needs root.
#
# WHAT THIS DOES: it copies both trees, from commits, into one scratch folder and
# rewrites exactly one thing in the bridge copy: the absolute prefix
# `/opt/mica-machine` becomes the staged machine tree. Nothing else changes: the
# same bridge sources, the same machine sources, the same node_modules and the
# same tsconfig options. A pass here is a real run of this code against that
# machine; it says nothing about what /opt holds on any box.
#
# It writes only into its own scratch folder. It touches no repository, no /opt
# and no service, and needs no privilege.
#
# SETTINGS (environment):
#   MACHINE_REPO   a git checkout of the machine tree. Required.
#   MACHINE_SHA    the machine commit to stage (default HEAD).
#   BRIDGE_REPO    the bridge repository (default: the one this script stands in).
#   BRIDGE_SHA     the bridge commit to stage (default HEAD; "worktree" stages
#                  the uncommitted tree).
#   NODE_MODULES   a node_modules with ts-node and typescript
#                  (default: the machine checkout's own, $MACHINE_REPO/node_modules).
#
#   bash tools/stage-machine-half.sh [suite.test.ts ...]
#
# It type-checks the staged bridge, then runs each suite named on the command
# line (file names under mica-bridge/). The stage folder is kept and printed.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

if [ -z "${MACHINE_REPO:-}" ]; then
  echo "REFUSED: set MACHINE_REPO to a git checkout of the machine tree." >&2
  exit 2
fi
BRIDGE_REPO=${BRIDGE_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
NODE_MODULES=${NODE_MODULES:-$MACHINE_REPO/node_modules}
MACHINE_SHA=${MACHINE_SHA:-HEAD}

STAGE=$(mktemp -d "${TMPDIR:-/tmp}/mica-stage-XXXXXX")
trap 'echo "  (stage kept at $STAGE)"' EXIT
echo "=== staging into $STAGE ==="

# ── the machine half, from a COMMIT and not from the dirty worktree ──────────
mkdir -p "$STAGE/mica-machine"
git -C "$MACHINE_REPO" archive "$MACHINE_SHA" | tar -x -C "$STAGE/mica-machine"
echo "  machine : $(git -C "$MACHINE_REPO" rev-parse "$MACHINE_SHA")"
ln -s "$NODE_MODULES" "$STAGE/mica-machine/node_modules"

# the Act A module must actually be there, or the stage proves nothing
[ -f "$STAGE/mica-machine/src/glue/subject-event-journal.ts" ] \
  || { echo "REFUSED: the staged machine half has no subject-event-journal.ts — wrong commit?"; exit 2; }

# ── the bridge half, from a COMMIT, with the one prefix rewritten ────────────
# BRIDGE_SHA=worktree stages the UNCOMMITTED tree, for iterating. Anything else is
# a commit. The mode is printed, because "it passed" means nothing without knowing
# which bytes passed.
mkdir -p "$STAGE/bridge"
BRIDGE_SHA=${BRIDGE_SHA:-HEAD}
if [ "$BRIDGE_SHA" = "worktree" ]; then
  tar -C "$BRIDGE_REPO" --exclude=.git --exclude=node_modules -cf - . | tar -x -C "$STAGE/bridge"
  echo "  bridge  : WORKTREE (uncommitted; $(git -C "$BRIDGE_REPO" status --porcelain | wc -l) modified paths)"
else
  git -C "$BRIDGE_REPO" archive "$BRIDGE_SHA" | tar -x -C "$STAGE/bridge"
  echo "  bridge  : $(git -C "$BRIDGE_REPO" rev-parse "$BRIDGE_SHA")"
fi

REWROTE=$(grep -rl "/opt/mica-machine" "$STAGE/bridge/mica-bridge" 2>/dev/null | wc -l)
grep -rl "/opt/mica-machine" "$STAGE/bridge/mica-bridge" 2>/dev/null \
  | xargs -r sed -i "s#/opt/mica-machine#$STAGE/mica-machine#g"
echo "  rewrote the absolute prefix in $REWROTE file(s)"

# prove the rewrite is total: nothing may still point at /opt
if grep -rn "/opt/mica-machine" "$STAGE/bridge/mica-bridge" 2>/dev/null | grep -q .; then
  echo "REFUSED: a reference to /opt/mica-machine survived the rewrite:"
  grep -rn "/opt/mica-machine" "$STAGE/bridge/mica-bridge" | head -5
  exit 2
fi

ln -s "$NODE_MODULES" "$STAGE/bridge/node_modules"

# ── typecheck, then run whatever suites were named ───────────────────────────
TSC="$NODE_MODULES/.bin/tsc"
TSNODE="$NODE_MODULES/.bin/ts-node"
cd "$STAGE/bridge"

echo
echo "=== tsc --noEmit -p mica-bridge/tsconfig.json ==="
if "$TSC" --noEmit -p mica-bridge/tsconfig.json; then
  echo "  tsc: CLEAN (0 errors)"
else
  echo "  ⛔ tsc reported errors (above)"
fi

for suite in "$@"; do
  echo
  echo "=== $suite ==="
  "$TSNODE" -P mica-bridge/tsconfig.json "mica-bridge/$suite" || echo "  ⛔ $suite exited non-zero"
done
