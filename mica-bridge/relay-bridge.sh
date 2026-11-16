#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# relay-bridge.sh — lay a Stage-0/1/2 mica-bridge/ tree at /opt, run by the arbiter
# with sudo. READ THIS BEFORE RUNNING IT. Short, commented, no cleverness.
#
# Usage:
#   sudo ./relay-bridge.sh <src-worktree> <sha> [--accept-declaration-change <hash>]
#   sudo ./relay-bridge.sh --capture-cutover        # while old bridge is LIVE
#   sudo ./relay-bridge.sh <src-worktree> <sha> --cutover \
#       --accept-declaration-change <new-hash>      # after BOTH writers stop
#
# CUTOVER IS TWO COMMANDS IN ONE STOPPED-WRITER ACT. The first captures the
# serving declarationHash AND executable release sha over the live operator
# socket into a root:root 0600 receipt under /run. The second accepts only that
# receipt, then rechecks selected release, config bytes, stopped units, and the
# renamed subject-log inode before it uses the captured hash at Amendment 11's
# original comparison. It cannot accept an offered old hash on the command line.
# The ordinary live-relay path below is unchanged. On cutover rollback the
# script STOPS the candidate and restores only the release link; it leaves the
# bridge stopped and marker standing until the operator restores the old log.
#
# ── THE ACTUAL CONTRACT (AMENDMENT 6 — retired, not re-attempted) ───────────
#
# A prior version of this file, and its receipt, claimed "every exit edge
# after the swap ends at a verified new target or a verified rollback
# target." An independent adversarial read (verifier, run 3) built the exact
# per-edge table and showed this claim false for the ordinary, non-exotic
# case of a failed `rm`/`ln`/`mv` inside the rollback path itself — not just
# for SIGKILL. The claim was past what a bash script mutating one symlink
# can actually guarantee, and this project's own discipline is to never
# claim past a mechanism's ceiling. So the claim is RETIRED here, not
# patched into looking true:
#
#   THIS SCRIPT PROVIDES BEST-EFFORT RECOVERY WITH CHECKED MUTATIONS, LOUD
#   NAMED FAILURE ON ANYTHING IT CANNOT FIX ITSELF, AND A PERSISTENT MARKER
#   THAT MAKES AN INTERRUPTED SWAP DETECTABLE ON THE NEXT RUN. IT DOES NOT,
#   AND CANNOT, GUARANTEE EVERY EXIT EDGE ENDS AT A PROVEN-SAFE TARGET.
#
# What IS still true, and load-bearing:
#   - every mutation this script performs has its own exit status checked
#     explicitly, never left to `set -e` inside a function called as an `if`
#     condition (which suspends `errexit` for everything inside it);
#   - a failed rollback mutation is retried once, then — for the
#     previous-release path — the script escalates to UNPUBLISHING (removing
#     the live link outright) rather than leaving it pointed at an unproven
#     state; for first-install, the candidate UNIT is stopped and verified
#     inactive before the link is ever removed, so removing the link cannot
#     leave candidate code still running behind a vanished symlink;
#   - a `swap-in-progress` MARKER FILE is written, naming the candidate and
#     previous sha and a timestamp, immediately before the swap, and removed
#     ONLY once a target (candidate or previous) is actually verified live.
#     Every future invocation of this script, AND the service's own
#     `--check`, refuse to proceed while that marker exists — so a death
#     between swap and verification is LOUD on the next run, never silent.
#
# The STATED RESIDUAL, not hidden: `SIGKILL`, a host crash, or a power loss
# between the forward `mv -T` and the marker's removal leaves the candidate
# link published with NO completed verification, and leaves the marker file
# in place. No trap in this process can run through any of those. Detecting
# that state (the marker) is what this script does; RECOVERING from it
# automatically is not — that is Phase B `[owed]`, not a Phase A claim: an
# external supervisor or boot-time verifier that inspects the marker and
# restores a known-good live selection after this script's own death. This
# script only refuses to compound the problem by relaying on top of it.
#
# Steps, in order, printing every step:
#   0. if the swap-in-progress marker already exists, REFUSE outright — a
#      previous relay died mid-swap and the live selection is unverified;
#      a human must resolve that before this script will touch anything.
#   1. source custody: HEAD == <sha>, worktree clean.
#   2. lay the release at /opt/mica-bridge.releases/<sha>/, chown root:root,
#      write VINTAGE.
#   3. compute EXPECTED_HASH from the LAID release, BEFORE any swap.
#   4. start check as mica-bridge (--check; binds no socket; also refuses on
#      the marker, same as step 0 — belt and braces, since `--check` is the
#      thing an operator might also run by hand).
#   5. decide DECLARATION-ONLY vs CODE relay by diffing the laid release
#      against the current one; if a previous release exists, compute its
#      declarationHash NOW too — a rollback target whose hash cannot be
#      proven is a precondition failure, refused BEFORE any swap.
#   6. define `do_rollback`/`on_exit`, INSTALL THE TRAP, write the marker —
#      all before the swap, with NOTHING executed between arming and the
#      swap itself. Prepare the temp symlink, arm rollback, THEN `mv -T`.
#   7. DECLARATION-ONLY: SIGHUP, read /status, compare its declarationHash
#      to EXPECTED_HASH for EXACT string equality. CODE: restart the unit,
#      confirm it is active, verify the live declarationHash AND the
#      running release's own sha (from /status.release, sourced from the
#      RUNNING process's own VINTAGE, not merely the filesystem symlink).
#      On success: remove the marker, disarm rollback.
#   8. On ANY verification miss: the trap fires. `do_rollback` attempts to
#      restore the previous release (checked, retried once per mutation,
#      escalating to unpublish on the previous-release path / stop-then-
#      remove on first-install) and, if and only if it can PROVE the
#      restored target is live and correct, removes the marker too. Any
#      unresolved failure leaves the marker in place, on purpose.
#
# curl output and JSON parsing NEVER run inside `$(...)` directly under
# `set -e` — a failure there would be swallowed by command substitution and
# the script would carry on past a swap it never verified. Every such call
# is captured to a file first, then its exit status is checked in an
# explicit `if`, then the file's content is parsed in a second explicit
# step.
#
# What this script does NOT do: install or enable any systemd unit; create
# per-uid peer-socket directories under /run/mica-bridge/peers/<uid>/ (a
# root/tmpfiles act — see deploy/mica-bridge.tmpfiles.conf and
# peer-auth.ts's header: THIS SERVICE NEVER CREATES THEM EITHER, per F1);
# touch any .env or secret file.
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# The capture is made while the old bridge is live. The later --cutover relay
# can use only this root-owned receipt, never caller-supplied hash strings.
CUTOVER_CAPTURE=0
CUTOVER_APPLY=0
if [[ "${1:-}" == "--capture-cutover" ]]; then
  [[ $# -eq 1 ]] || { echo "REFUSED: --capture-cutover takes no other arguments" >&2; exit 2; }
  CUTOVER_CAPTURE=1
  SRC_WORKTREE=""
  SHA=""
  shift
else
  SRC_WORKTREE="${1:-}"
  SHA="${2:-}"
  shift 2 || true
fi

# AMENDMENT 11 (the arbiter, 2026-09-27): --accept-declaration-change <hash>.
# See the declaration-hash gate below for what it is for and why it is not a
# boolean. It names the hash the caller EXPECTS the box to end up on, so an
# unintended declaration change cannot be waved through by a flag somebody
# copied off an earlier command line.
ACCEPT_DECL_CHANGE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cutover)
      CUTOVER_APPLY=1
      shift
      ;;
    --accept-declaration-change)
      ACCEPT_DECL_CHANGE="${2:-}"
      if [[ -z "$ACCEPT_DECL_CHANGE" ]]; then
        echo "REFUSED: --accept-declaration-change requires the expected new declarationHash" >&2
        exit 2
      fi
      shift 2
      ;;
    *)
      echo "REFUSED: unknown argument: $1" >&2
      echo "usage: relay-bridge.sh <src-worktree> <sha> [--accept-declaration-change <hash>] [--cutover]" >&2
      exit 2
      ;;
  esac
done

if [[ "$CUTOVER_CAPTURE" -eq 0 && ( -z "$SRC_WORKTREE" || -z "$SHA" ) ]]; then
  echo "usage: relay-bridge.sh <src-worktree> <sha> [--accept-declaration-change <hash>] [--cutover]" >&2
  exit 2
fi

RELEASES_DIR="/opt/mica-bridge.releases"
LIVE_LINK="/opt/mica-bridge"
NEW_RELEASE="${RELEASES_DIR}/${SHA}"
OPERATOR_SOCKET_ROLE="operator"
RUN_SOCKET_DIR="/run/mica-bridge/peers"
NODE_BIN="/usr/bin/node"
TS_NODE_BIN="/opt/mica-machine/node_modules/ts-node/dist/bin.js"
# AMENDMENT 6: the swap-in-progress marker. A sibling of LIVE_LINK, not
# inside any release directory (so it survives a release being deleted) and
# not inside /var/lib/mica-bridge (owned by mica-bridge, not this script's
# to manage). `MICA_BRIDGE_RELAY_MARKER` overrides it — used by tests only,
# so a dev/test run never touches the real path.
MARKER_FILE="${MICA_BRIDGE_RELAY_MARKER:-/opt/mica-bridge.relay-in-progress}"
# A single, root-owned capture in /run: no arbitrary path or offered hash can
# substitute for the live process's answer. It expires with this boot.
CUTOVER_FILE=/run/mica-relay/acta-cutover.capture
WORKDIR="$(mktemp -d /tmp/relay-bridge.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

# shellcheck source=relay-lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/relay-lib.sh"

# ── operator-uid resolver, used identically before and after every swap ──
resolve_operator_uid() {
  # $1 = declarations.config.json path to read; writes the uid to stdout.
  "$NODE_BIN" -e '
    const fs = require("fs");
    const d = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const row = d.routes.find((r) => r.role === process.argv[2]);
    if (!row) { process.exit(1); }
    console.log(row.uid);
  ' "$1" "$OPERATOR_SOCKET_ROLE"
}

# ── read_live_status: curl + parse, both checked explicitly, never in
#    `$(...)` under `set -e`. Writes BOTH the declarationHash AND the
#    executable release identity — /status.release.sha is read from the
#    RUNNING process's own `VINTAGE`, not the filesystem symlink. ────────
read_live_status() {
  # $1 = declarations path to resolve the operator uid from (the LIVE one,
  # by construction, since this always runs after a swap). $2 = output
  # file for the declarationHash. $3 = output file for the release sha
  # (may be the literal string "null" if the running process has none —
  # e.g. a dev/test context; the caller decides whether that is acceptable).
  # Returns nonzero on ANY failure, printing which step failed; writes
  # nothing to $2/$3 on failure.
  local decl_path="$1"
  local hash_out_file="$2"
  local sha_out_file="$3"
  local uid_file="${WORKDIR}/$$-op-uid.txt"
  if ! resolve_operator_uid "$decl_path" > "$uid_file" 2>/dev/null; then
    echo "   could not resolve the operator uid from ${decl_path}" >&2
    return 1
  fi
  local uid
  uid="$(cat "$uid_file")"
  local sock="${RUN_SOCKET_DIR}/${uid}/guard.sock"
  local status_file="${WORKDIR}/$$-status.json"
  if ! curl -s --unix-socket "$sock" "http://unix/status" > "$status_file" 2>"${WORKDIR}/$$-curl.err"; then
    echo "   /status unreachable over ${sock}" >&2
    return 1
  fi
  if ! "$NODE_BIN" -e '
      let s = "";
      process.stdin.on("data", (d) => (s += d));
      process.stdin.on("end", () => console.log(JSON.parse(s).declarationHash));
    ' < "$status_file" > "$hash_out_file" 2>/dev/null; then
    echo "   /status body did not parse as JSON" >&2
    return 1
  fi
  if ! "$NODE_BIN" -e '
      let s = "";
      process.stdin.on("data", (d) => (s += d));
      process.stdin.on("end", () => {
        const body = JSON.parse(s);
        console.log(body.release && body.release.sha ? body.release.sha : "null");
      });
    ' < "$status_file" > "$sha_out_file" 2>/dev/null; then
    echo "   /status body's release field did not parse" >&2
    return 1
  fi
  return 0
}

# A capture is data, never shell code: read exactly one key without sourcing it.
cutover_field() {
  local key="$1" count
  count=$(grep -c "^${key}=" "$CUTOVER_FILE" || true)
  [[ "$count" == 1 ]] || return 1
  sed -n "s/^${key}=//p" "$CUTOVER_FILE"
}

declaration_hash_at() {
  local release="$1"
  "$NODE_BIN" "$TS_NODE_BIN" -P "${release}/mica-bridge/tsconfig.json" -e '
    const { loadDeclarations } = require(process.argv[1]);
    console.log(loadDeclarations(process.argv[2]).declarationHash);
  ' "${release}/mica-bridge/declarations" "${release}/mica-bridge/declarations.config.json"
}

capture_cutover() {
  [[ ! -e "$CUTOVER_FILE" ]] || { echo "REFUSED: ${CUTOVER_FILE} already exists; resolve it before a new capture" >&2; exit 1; }
  [[ -L "$LIVE_LINK" ]] || { echo "REFUSED: no live bridge release link" >&2; exit 1; }
  systemctl is-active --quiet mica-bridge || { echo "REFUSED: bridge must be live at capture" >&2; exit 1; }
  local target config live_hash live_sha disk_hash vintage_sha subject_path subject_inode raw_hash boot now tmp
  target=$(readlink -f "$LIVE_LINK") || exit 1
  [[ "$target" == "${RELEASES_DIR}/"* ]] || { echo "REFUSED: unexpected live target ${target}" >&2; exit 1; }
  config="${target}/mica-bridge/declarations.config.json"
  read_live_status "$config" "${WORKDIR}/capture-hash" "${WORKDIR}/capture-sha" || exit 1
  live_hash=$(cat "${WORKDIR}/capture-hash")
  live_sha=$(cat "${WORKDIR}/capture-sha")
  [[ "$live_hash" =~ ^[0-9a-f]{64}$ && "$live_sha" =~ ^[0-9a-f]{40}$ ]] || {
    echo "REFUSED: live status has no valid declaration hash and release sha" >&2; exit 1;
  }
  vintage_sha=$(sed -n 's/^sha=//p' "${target}/VINTAGE")
  [[ "$vintage_sha" == "$live_sha" && "$(basename "$target")" == "$live_sha" ]] || {
    echo "REFUSED: running release identity disagrees with the selected release" >&2; exit 1;
  }
  disk_hash=$(declaration_hash_at "$target") || exit 1
  [[ "$disk_hash" == "$live_hash" ]] || { echo "REFUSED: serving declaration differs from selected release's file" >&2; exit 1; }
  raw_hash=$(sha256sum "$config" | cut -d' ' -f1)
  subject_path=$("$NODE_BIN" -e '
    const d = require(process.argv[1]); console.log(d.paths.subjectLog);
  ' "$config") || exit 1
  [[ "$subject_path" == /var/lib/mica-bridge/* && -f "$subject_path" ]] || {
    echo "REFUSED: live subject-log path is absent or outside its store" >&2; exit 1;
  }
  subject_inode=$(stat -c '%d:%i' "$subject_path") || exit 1
  # A second live read brackets the file reads; a concurrent reload cannot
  # silently turn the first status into a receipt for different serving bytes.
  read_live_status "$config" "${WORKDIR}/capture-hash-2" "${WORKDIR}/capture-sha-2" || exit 1
  [[ "$(cat "${WORKDIR}/capture-hash-2")" == "$live_hash" && "$(cat "${WORKDIR}/capture-sha-2")" == "$live_sha" ]] || {
    echo "REFUSED: bridge identity changed during capture" >&2; exit 1;
  }
  systemctl is-active --quiet mica-bridge || { echo "REFUSED: bridge stopped during capture" >&2; exit 1; }
  boot=$(cat /proc/sys/kernel/random/boot_id)
  now=$(date +%s)
  tmp=$(mktemp "${MICA_RELAY_LOCK_DIR}/acta-cutover.XXXXXX")
  chmod 600 "$tmp"
  printf 'boot=%s\nat=%s\ntarget=%s\nlive_hash=%s\nlive_sha=%s\nconfig_sha256=%s\nsubject_path=%s\nsubject_inode=%s\n' \
    "$boot" "$now" "$target" "$live_hash" "$live_sha" "$raw_hash" "$subject_path" "$subject_inode" > "$tmp"
  mv -T "$tmp" "$CUTOVER_FILE"
  echo "CAPTURED serving declaration ${live_hash} and release ${live_sha} while bridge was live."
  echo "Receipt: ${CUTOVER_FILE} (root:root 600). Stop bot and bridge before measurement; use --cutover for the code relay."
}

verify_cutover() {
  [[ -f "$CUTOVER_FILE" && ! -L "$CUTOVER_FILE" ]] || { echo "REFUSED: no regular cutover capture" >&2; exit 1; }
  [[ "$(stat -c '%U:%G %a' "$CUTOVER_FILE")" == 'root:root 600' ]] || {
    echo "REFUSED: cutover capture is not root:root 600" >&2; exit 1;
  }
  local boot at target live_hash live_sha config_sha subject_path subject_inode now retired_path
  boot=$(cutover_field boot) || exit 1
  at=$(cutover_field at) || exit 1
  target=$(cutover_field target) || exit 1
  live_hash=$(cutover_field live_hash) || exit 1
  live_sha=$(cutover_field live_sha) || exit 1
  config_sha=$(cutover_field config_sha256) || exit 1
  subject_path=$(cutover_field subject_path) || exit 1
  subject_inode=$(cutover_field subject_inode) || exit 1
  [[ "$boot" == "$(cat /proc/sys/kernel/random/boot_id)" && "$at" =~ ^[0-9]+$ ]] || {
    echo "REFUSED: cutover capture is from another boot or malformed" >&2; exit 1;
  }
  now=$(date +%s)
  (( now >= at && now - at <= 14400 )) || { echo "REFUSED: cutover capture is older than four hours" >&2; exit 1; }
  [[ "$live_hash" =~ ^[0-9a-f]{64}$ && "$live_sha" =~ ^[0-9a-f]{40}$ && "$config_sha" =~ ^[0-9a-f]{64}$ ]] || {
    echo "REFUSED: cutover capture has malformed identity fields" >&2; exit 1;
  }
  [[ "$target" == "$PREVIOUS_RELEASE" && "$(basename "$target")" == "$live_sha" ]] || {
    echo "REFUSED: selected release changed since capture" >&2; exit 1;
  }
  [[ "$PREVIOUS_HASH" == "$live_hash" && "$(sha256sum "${target}/mica-bridge/declarations.config.json" | cut -d' ' -f1)" == "$config_sha" ]] || {
    echo "REFUSED: selected declaration changed since the live capture" >&2; exit 1;
  }
  # S201: the subject's caller unit is the declaration's to name, not this script's.
  # R-e: the UNION of the candidate's units and the LIVE declaration's (the one
  # serving now, at the captured target) — the running writers are the live ones.
  unit_confirmed_inactive mica-bridge \
    && subject_units_confirmed_inactive "${NEW_RELEASE}/mica-bridge/declarations.config.json" \
         "${target}/mica-bridge/declarations.config.json" || {
    echo "REFUSED: the bridge and every declared subject's caller unit must be confirmed inactive for cutover" >&2; exit 1;
  }
  [[ "$subject_path" == /var/lib/mica-bridge/* && ! -e "$subject_path" && ! -L "$subject_path" && "$subject_inode" =~ ^[0-9]+:[0-9]+$ ]] || {
    echo "REFUSED: old subject-log name is not vacant or capture is malformed" >&2; exit 1;
  }
  retired_path=$("$NODE_BIN" -e '
    const d = require(process.argv[1]); console.log(d.subjectLog.chainBoundary.retiredPath.value);
  ' "${NEW_RELEASE}/mica-bridge/declarations.config.json") || exit 1
  [[ "$retired_path" == /var/lib/mica-bridge/* && "$retired_path" != "$subject_path" && -f "$retired_path" ]] || {
    echo "REFUSED: candidate has no actual rotated predecessor file" >&2; exit 1;
  }
  [[ "$(stat -c '%d:%i' "$retired_path")" == "$subject_inode" ]] || {
    echo "REFUSED: candidate's retired file is not the file observed live at capture" >&2; exit 1;
  }
  [[ "$DECLARATION_ONLY" -eq 0 ]] || { echo "REFUSED: Act A cutover requires a code relay" >&2; exit 1; }
  echo "   CUTOVER CAPTURE SEALED: live hash ${live_hash}, running sha ${live_sha}, same selected config and retired inode; bridge and every declared subject caller stopped."
  LIVE_HASH="$live_hash"
}

echo "== relay-bridge.sh: ${SRC_WORKTREE} @ ${SHA} =="

# ⚠ TAKEN HERE, BEFORE THE MARKER CHECK, AND THE TWO ARE NOT THE SAME GATE.
#   `marker_acquire` (step 6, Amendment 10) is the exclusivity gate for the SWAP and
#   guards two BRIDGE relays against each other. This lock is one level up: it is the
#   only thing that stops a DECLARATION relay or a MACHINE relay running alongside
#   this one, and those are different scripts that never saw each other's marker.
#   It is taken before the marker is even read, because two relays reading one marker
#   is the race, not the swap.

# ── THE SHARED RELAY LOCK · ONE RELAY ACT AT A TIME, OF ANY KIND ─────────────
#
# ⛔ WHAT THIS PREVENTS, AND IT NEARLY HAPPENED ON 2026-09-27. `relay-bridge.sh` and
#    `relay-declaration.sh` shared no lock. The bridge script has a marker mutex, but
#    that guards TWO BRIDGE RELAYS racing each other — nothing stopped a DECLARATION
#    relay writing `declarations.config.json` while a bridge relay was mid-swap. On
#    2026-09-27 a code relay overwrote a declaration laid forty minutes earlier and the
#    box re-held; forty seconds apart the two would have interleaved, and Amendment 11's
#    gate would have read a live hash that was already stale by the time it swapped.
#
# ⚠ THE LOCK LIVES UNDER /run/mica-relay AND NOT IN /run/lock, FOR THE SAME REASON THE
#   SUDOERS PATHS LIVE IN /usr/local/sbin AND NOT IN $HOME. /run/lock is 1777: any user
#   can create a name there first, and a root `exec 9>` onto a symlink they planted would
#   truncate whatever it points at. /run is root:root 755, so a directory created directly
#   under it can only be made by root. The mode is asserted before the lock is used —
#   a lock file is only as trustworthy as the directory holding it.
#
# ⚠ AND IT REFUSES RATHER THAN WAITS. `flock -n`, never a blocking acquire. A relay that
#   queues silently behind another looks identical to a relay that is working, and the
#   operator learns the difference minutes later. The holder's identity is written into
#   the file so the refusal can name who has it.
MICA_RELAY_LOCK_DIR=/run/mica-relay
[[ $(id -u) -eq 0 ]] || { echo "REFUSED: relay and cutover capture require root" >&2; exit 2; }
MICA_RELAY_LOCK="${MICA_RELAY_LOCK_DIR}/relay.lock"
mkdir -p "$MICA_RELAY_LOCK_DIR"
chmod 700 "$MICA_RELAY_LOCK_DIR"
chown root:root "$MICA_RELAY_LOCK_DIR"
_lock_dir_mode=$(stat -c '%U:%G %a' "$MICA_RELAY_LOCK_DIR")
if [ "$_lock_dir_mode" != "root:root 700" ]; then
  echo "REFUSED: ${MICA_RELAY_LOCK_DIR} is '${_lock_dir_mode}', not 'root:root 700'." >&2
  echo "         A lock in a directory someone else can write is not a lock. Nothing was done." >&2
  exit 1
fi
exec 9>>"$MICA_RELAY_LOCK"
if ! flock -n 9; then
  echo "" >&2
  echo "############################################################" >&2
  echo "REFUSED: ANOTHER RELAY ACT HOLDS THE SHARED LOCK." >&2
  echo "############################################################" >&2
  echo "  holder, as it recorded itself:" >&2
  sed 's/^/    /' "$MICA_RELAY_LOCK" >&2 || echo "    (the lock file says nothing — a holder that did not record itself)" >&2
  echo "" >&2
  echo "  Two relay acts at once is how a declaration gets overwritten by a code relay," >&2
  echo "  and how a hash read before a swap is stale by the time it swaps. This script" >&2
  echo "  refuses rather than queueing, so the wait is visible instead of silent." >&2
  echo "  Wait for the holder to finish, or establish by hand that it died and remove" >&2
  echo "  ${MICA_RELAY_LOCK}." >&2
  exit 1
fi
# Only now that the lock is HELD is it safe to describe ourselves in it.
printf 'script  %s\npid     %s\nstarted %s\ncaller  uid=%s user=%s\n' \
  "$0" "$$" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${SUDO_UID:-$(id -u)}" "${SUDO_USER:-$(id -un)}" > "$MICA_RELAY_LOCK"
echo "-- shared relay lock HELD (${MICA_RELAY_LOCK}, pid $$)"

# ── 0. fast-fail if a previous relay died mid-swap — INFORMATIVE ONLY.
#      This is a plain existence check, not the exclusivity gate (that is
#      `marker_acquire`, right before the swap, step 6). AMENDMENT 10 /
#      VERIFIER run 5 F3.2-A/B: the real gate is now a persistent
#      `flock`(1) mutex plus an unguessable ownership token (relay-lib.sh),
#      not a bare, deletable `mkdir` — two relays racing THIS check can
#      still both pass it (it is a snapshot, not itself synchronized), but
#      whichever one then loses the real `marker_acquire` race is refused
#      there, correctly, every time. This check exists only so an
#      obviously-stuck relay fails fast, before doing all the laying-out
#      work below, with a clear message. ────────────────────────────────────
if marker_present "$MARKER_FILE"; then
  echo "REFUSED: ${MARKER_FILE} exists — a previous relay appears to be running, or to have died between its swap and its verification. The live selection at ${LIVE_LINK} is UNVERIFIED. A human must read the marker, establish the actual state by hand, and clear ownership (remove ${MARKER_FILE} and ${MARKER_FILE}.lock/owner) before this script will run again:" >&2
  cat "$MARKER_FILE" >&2
  exit 1
fi

if [[ "$CUTOVER_CAPTURE" -eq 1 ]]; then
  capture_cutover
  exit 0
fi

# ── 1. source custody ────────────────────────────────────────────────────
echo "-- verifying source custody"
ACTUAL_HEAD="$(git -C "$SRC_WORKTREE" rev-parse HEAD)"
if [[ "$ACTUAL_HEAD" != "$SHA" ]]; then
  echo "REFUSED: HEAD is ${ACTUAL_HEAD}, not the named ${SHA}" >&2
  exit 1
fi
PORCELAIN="$(git -C "$SRC_WORKTREE" status --porcelain=v1 --untracked-files=all)"
if [[ -n "$PORCELAIN" ]]; then
  echo "REFUSED: worktree is not clean:" >&2
  echo "$PORCELAIN" >&2
  exit 1
fi
echo "   HEAD == ${SHA}, worktree clean"

# ── 2. lay the release ───────────────────────────────────────────────────
# ── AMENDMENT 12 · THE TARGET GATE, BEFORE ANYTHING IS CREATED ──────────
#
# ⛔ WHAT THE NEXT TWO LINES USED TO DO WITHOUT LOOKING: `mkdir -p` followed by
#    `rsync -a --delete` INTO the release directory. If that directory is the one
#    the live symlink already points at, those two lines REWRITE THE RUNNING
#    RELEASE IN PLACE — deleting whatever the running tree has that the source
#    does not — before a single check has been made, before the start check, and
#    before the declaration-hash gate below. A relay of an already-live sha, or a
#    re-run after a rollback, would have done it.
#
#    No incident yet; Codex found it reading the 2026-09-27 commit. It is the same
#    shape as the declaration revert: a step that is correct for the case it was
#    written for and destructive for a case nobody enumerated.
#
# ⚠ REFUSED RATHER THAN STAGED FRESH, deliberately. Staging into a sibling and
#   moving it in would make re-relays work, and that is the better end state; but
#   it also makes this script delete a directory it did not create, and the
#   conservative move today is to stop and let the arbiter remove it by hand.
#   `[owed]` stage-fresh, if re-relaying the same sha ever becomes routine.
if [[ -e "$NEW_RELEASE" ]]; then
  CURRENT_TARGET=""
  if [[ -L "$LIVE_LINK" ]]; then
    CURRENT_TARGET="$(readlink -f "$LIVE_LINK" || true)"
  fi
  if [[ -n "$CURRENT_TARGET" && "$CURRENT_TARGET" == "$(readlink -f "$NEW_RELEASE" || echo "$NEW_RELEASE")" ]]; then
    echo "REFUSED: ${NEW_RELEASE} IS THE RELEASE THAT IS CURRENTLY LIVE." >&2
    echo "         Laying into it would rsync --delete over the running tree before any check." >&2
    echo "         If you mean to re-lay this sha, stop the unit and remove the directory by hand," >&2
    echo "         or relay a different sha. Nothing was created and nothing was touched." >&2
    exit 1
  fi
  echo "REFUSED: ${NEW_RELEASE} already exists and is NOT the live target." >&2
  echo "         It is probably a leftover from an earlier or rolled-back relay. This script will" >&2
  echo "         not rsync --delete into a directory it did not create, because it cannot tell a" >&2
  echo "         half-built tree from a complete one. Remove it by hand and re-run." >&2
  exit 1
fi

# ⚠ OWED, AND NAMED HERE BECAUSE IT IS THE NEXT THING TO GO WRONG: THIS SCRIPT AND
#   relay-declaration.sh SHARE NO LOCK. The marker file below makes two concurrent
#   BRIDGE relays detectable, but nothing stops a declaration relay from writing
#   declarations.config.json while this one is mid-swap, and the declaration-hash
#   gate below reads /status at one instant and swaps at another. On 2026-09-27
#   those two acts ran forty minutes apart and the second undid the first; running
#   them forty seconds apart would interleave. One lock file, taken by both.
#   `[owed → the arbiter]`

echo "-- laying release ${NEW_RELEASE}"
mkdir -p "$NEW_RELEASE"
rsync -a --delete "${SRC_WORKTREE}/mica-bridge/" "${NEW_RELEASE}/mica-bridge/"
chown -R root:root "$NEW_RELEASE"
{
  echo "sha=${SHA}"
  echo "laid_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "source=${SRC_WORKTREE}"
} > "${NEW_RELEASE}/VINTAGE"
echo "   laid, chowned root:root, VINTAGE written"

# ── 3. expected hash, from the LAID release, BEFORE any swap ────────────
echo "-- computing expected declarationHash from the laid release"
EXPECTED_HASH_FILE="${WORKDIR}/expected-hash.txt"
if ! "$NODE_BIN" "$TS_NODE_BIN" -P "${NEW_RELEASE}/mica-bridge/tsconfig.json" -e '
    const { loadDeclarations } = require(process.argv[1]);
    console.log(loadDeclarations(process.argv[2]).declarationHash);
  ' "${NEW_RELEASE}/mica-bridge/declarations" "${NEW_RELEASE}/mica-bridge/declarations.config.json" \
  > "$EXPECTED_HASH_FILE" 2> "${WORKDIR}/expected-hash.err"; then
  echo "REFUSED: could not compute declarationHash from the laid release:" >&2
  cat "${WORKDIR}/expected-hash.err" >&2
  exit 1
fi
EXPECTED_HASH="$(cat "$EXPECTED_HASH_FILE")"
if [[ -z "$EXPECTED_HASH" ]]; then
  echo "REFUSED: expected declarationHash came back empty" >&2
  exit 1
fi
echo "   expected declarationHash: ${EXPECTED_HASH}"

# ── 4. start check as mica-bridge (also refuses on the marker) ──────────
echo "-- start check as mica-bridge"
CHECK_OUTPUT_FILE="${WORKDIR}/check-output.txt"
if ! sudo -u mica-bridge env "MICA_BRIDGE_RELAY_MARKER=${MARKER_FILE}" "$NODE_BIN" "$TS_NODE_BIN" \
    -P "${NEW_RELEASE}/mica-bridge/tsconfig.json" \
    "${NEW_RELEASE}/mica-bridge/mica-service.ts" --check \
    > "$CHECK_OUTPUT_FILE" 2>&1; then
  echo "REFUSED: start check failed; release ${SHA} left un-linked:" >&2
  cat "$CHECK_OUTPUT_FILE" >&2
  exit 1
fi
echo "   $(cat "$CHECK_OUTPUT_FILE")"

# ── 5. declaration-only vs code relay, and the previous release's PROVEN
#      hash — a precondition, refused before any swap if it cannot be
#      established (AMENDMENT 4 / VERIFIER §9.2) ────────────────────────
DECLARATION_ONLY=0
FORWARD_WAS_CODE=1
PREVIOUS_RELEASE=""
if [[ -L "$LIVE_LINK" ]]; then
  PREVIOUS_RELEASE="$(readlink -f "$LIVE_LINK")"
  echo "-- diffing against current release ${PREVIOUS_RELEASE}"
  if diff -rq -x declarations.config.json \
      "${PREVIOUS_RELEASE}/mica-bridge" "${NEW_RELEASE}/mica-bridge" > /dev/null 2>&1; then
    DECLARATION_ONLY=1
    FORWARD_WAS_CODE=0
    echo "   only declarations.config.json differs -> DECLARATION-ONLY relay"
  else
    echo "   code differs -> CODE relay (unit restart required)"
  fi
else
  echo "-- no current release symlink; treating as a CODE relay (first install)"
fi

PREVIOUS_HASH=""
if [[ -n "$PREVIOUS_RELEASE" ]]; then
  PREVIOUS_HASH_FILE="${WORKDIR}/previous-hash.txt"
  if ! "$NODE_BIN" "$TS_NODE_BIN" -P "${PREVIOUS_RELEASE}/mica-bridge/tsconfig.json" -e '
      const { loadDeclarations } = require(process.argv[1]);
      console.log(loadDeclarations(process.argv[2]).declarationHash);
    ' "${PREVIOUS_RELEASE}/mica-bridge/declarations" "${PREVIOUS_RELEASE}/mica-bridge/declarations.config.json" \
    > "$PREVIOUS_HASH_FILE" 2> "${WORKDIR}/previous-hash.err"; then
    echo "REFUSED: could not compute the PREVIOUS release's declarationHash — refusing to swap forward without a provable rollback target:" >&2
    cat "${WORKDIR}/previous-hash.err" >&2
    exit 1
  fi
  PREVIOUS_HASH="$(cat "$PREVIOUS_HASH_FILE")"
  if [[ -z "$PREVIOUS_HASH" ]]; then
    echo "REFUSED: the previous release's declarationHash came back empty — refusing to swap forward" >&2
    exit 1
  fi
  echo "   previous declarationHash (rollback target, proven before any swap): ${PREVIOUS_HASH}"
fi

if [[ "$CUTOVER_APPLY" -eq 1 && -z "$PREVIOUS_RELEASE" ]]; then
  echo "REFUSED: cutover requires an existing serving release to have been captured" >&2
  exit 1
fi

# ── AMENDMENT 11 · THE DECLARATION-HASH GATE ────────────────────────────
#
# ⛔ WHAT THIS EXISTS TO PREVENT, AND IT HAPPENED: 2026-09-27 05:16:40Z. This
#    script lays a release from a commit's TREE, and
#    `mica-bridge/declarations.config.json` IS IN THAT TREE. The commit relayed
#    that morning carried the PRE-S1 config, because it had been branched before
#    S1 was declared. So a CODE relay silently replaced the live declaration:
#    declarationHash fell from 24b87890 back to 4568d808, Sig went from SILENT to
#    alarming, and two acts held before a human noticed. Nothing in this script
#    looked. The release verified perfectly — because it WAS the release that was
#    asked for. The declaration was collateral.
#
# ⚠ WHY THE LIVE HASH CANNOT BE TAKEN FROM THE PREVIOUS RELEASE'S FILE: a
#   declaration relay writes `declarations.config.json` IN PLACE, so the serving
#   declaration routinely differs from what ANY release committed. That is exactly
#   the state this box was in. The comparison therefore reads /status — the
#   running process's own answer — and not a file on disk.
#
# ⚠ AND IT IS NOT A BOOLEAN. `--accept-declaration-change <hash>` must NAME the
#   hash the caller expects to end up on, so that a flag copied off an earlier
#   command line cannot wave a different change through. A relay that intends to
#   move the declaration says which declaration.
if [[ -n "${PREVIOUS_RELEASE:-}" ]]; then
  echo "-- declaration-hash gate: comparing the LIVE hash against the laid release's"
  LIVE_DECL_PATH="${LIVE_LINK}/mica-bridge/declarations.config.json"
  GATE_HASH_FILE="${WORKDIR}/gate-live-hash.txt"
  GATE_SHA_FILE="${WORKDIR}/gate-live-sha.txt"
  if [[ "$CUTOVER_APPLY" -eq 1 ]]; then
    # The live read was made before the stop, into a root-owned capture. The
    # identity, selected config, stopped units and renamed inode are rechecked
    # NOW; no caller-supplied hash may stand in for the serving process.
    verify_cutover
  else
    if ! read_live_status "$LIVE_DECL_PATH" "$GATE_HASH_FILE" "$GATE_SHA_FILE"; then
      echo "REFUSED: could not read the LIVE declarationHash from /status before the swap." >&2
      echo "         This gate is not optional and its failure is not a pass: a relay that cannot" >&2
      echo "         see what is serving cannot promise not to replace it. Release ${SHA} left un-linked." >&2
      exit 1
    fi
    LIVE_HASH="$(cat "$GATE_HASH_FILE")"
  fi
  if [[ -z "$LIVE_HASH" ]]; then
    echo "REFUSED: the live declarationHash came back empty; refusing to swap blind" >&2
    exit 1
  fi
  echo "   live declarationHash    : ${LIVE_HASH}"
  echo "   laid release would load : ${EXPECTED_HASH}"
  if [[ "$LIVE_HASH" == "$EXPECTED_HASH" ]]; then
    echo "   MATCH — this relay carries the declaration that is already serving. Proceeding."
  elif [[ -n "$ACCEPT_DECL_CHANGE" ]]; then
    if [[ "$ACCEPT_DECL_CHANGE" != "$EXPECTED_HASH" ]]; then
      echo "REFUSED: --accept-declaration-change names ${ACCEPT_DECL_CHANGE}" >&2
      echo "         but the laid release would load ${EXPECTED_HASH}." >&2
      echo "         The flag must name the hash you are actually going to get. Release ${SHA} left un-linked." >&2
      exit 1
    fi
    echo "   CHANGE ACCEPTED: ${LIVE_HASH} -> ${EXPECTED_HASH}, named explicitly by --accept-declaration-change."
  else
    echo "REFUSED: THIS RELAY WOULD REPLACE THE LIVE DECLARATION." >&2
    echo "         live declarationHash    : ${LIVE_HASH}" >&2
    echo "         laid release would load : ${EXPECTED_HASH}" >&2
    echo "" >&2
    echo "         The release's own mica-bridge/declarations.config.json differs from what is" >&2
    echo "         serving. On 2026-09-27 that erased a declaration relayed forty minutes earlier" >&2
    echo "         and re-held the box, silently, because a CODE relay carries the config file too." >&2
    echo "" >&2
    echo "         Almost always the fix is in the SOURCE, not here: commit the live declaration" >&2
    echo "         into the bridge line (the arbiter's rule, 2026-09-27 — every declaration act's" >&2
    echo "         candidate is committed the same day) and re-lay. Only if you MEAN to change the" >&2
    echo "         declaration with this relay, say so and name the result:" >&2
    echo "" >&2
    echo "           relay-bridge.sh ${SRC_WORKTREE} ${SHA} --accept-declaration-change ${EXPECTED_HASH}" >&2
    echo "" >&2
    echo "         Release ${SHA} is laid at ${NEW_RELEASE} and NOT linked. Nothing was swapped." >&2
    exit 1
  fi
else
  echo "-- declaration-hash gate: no previous release, so there is no live declaration to replace"
fi

# ── do_rollback / on_exit: DEFINED AND ARMED BEFORE THE SWAP. Every
#    mutation inside do_rollback is checked explicitly — `if do_rollback;
#    then` suspends `errexit` for everything the function runs, so nothing
#    in here may rely on it — retried once, and escalated (never merely
#    reported) on the second failure. See the header: this is BEST-EFFORT
#    recovery, not a proof, and it removes the marker ONLY on a proven
#    outcome. ───────────────────────────────────────────────────────────
ROLLBACK_ARMED=0

remove_marker() {
  # Best-effort: a failure to remove the marker is named but does not
  # change the caller's own verified/unverified verdict — the marker
  # existing when it need not is a false alarm on the NEXT run (loud,
  # safe); the marker MISSING when it should exist would be the
  # dangerous direction, and this function never causes that.
  # AMENDMENT 8, REDESIGNED AMENDMENT 10 / VERIFIER F3.2: delegates to
  # `marker_release` (relay-lib.sh), which revalidates this process's own
  # unguessable acquisition token against the owner record — held under a
  # persistent flock mutex for the whole check-then-delete sequence, so
  # there is no window for a stale process to delete a marker a DIFFERENT
  # process has since legitimately acquired.
  if ! marker_release "$MARKER_FILE"; then
    echo "   NOTE: could not remove ${MARKER_FILE} — the next relay will refuse until a human clears it, even though this outcome was verified" >&2
  fi
}

do_rollback() {
  echo "ROLLING BACK (candidate ${SHA} did not verify)" >&2

  # On cutover the old log has already been renamed. The candidate may have
  # started and written a new chain, so stop it BEFORE restoring the old link.
  # The rotated log is restored by the operator; no automatic old-code restart
  # may run against an absent or newly chained subject-log path.
  if [[ "$CUTOVER_APPLY" -eq 1 ]]; then
    systemctl stop mica-bridge || { echo "   FAILED: could not stop candidate bridge; marker retained" >&2; return 1; }
    unit_confirmed_inactive mica-bridge || { echo "   FAILED: candidate bridge is not confirmed inactive; marker retained" >&2; return 1; }
  fi

  if [[ -z "$PREVIOUS_RELEASE" ]]; then
    # First install: no previous release to restore.
    #
    # AMENDMENT 10 / VERIFIER run 5 F3.2-C: this branch used to be inlined
    # here AND separately hand-mirrored inside relay-lib.test.sh — two
    # copies that could silently drift. Factored into
    # `relay_rollback_first_install()` (relay-lib.sh) so the test invokes
    # the EXACT same production logic this line does. See that function's
    # own header for the AMENDMENT 6 / VERIFIER run-3 §4 and AMENDMENT 8 /
    # VERIFIER F3.1 reasoning it carries forward unchanged.
    relay_rollback_first_install "mica-bridge" "$LIVE_LINK" "$MARKER_FILE"
    return $?
  fi

  # Previous-release rollback: prepare + swap, retried once each; on a
  # SECOND failure, escalate to unpublishing rather than leaving the link
  # in an unproven state.
  local restore_tmp="${WORKDIR}/live-link-restore"
  local ln_rc=0
  ln -s "$PREVIOUS_RELEASE" "$restore_tmp" || ln_rc=$?
  if [[ "$ln_rc" -ne 0 ]]; then
    echo "   could not create the rollback symlink at ${restore_tmp}; retrying once" >&2
    rm -f "$restore_tmp"
    ln_rc=0
    ln -s "$PREVIOUS_RELEASE" "$restore_tmp" || ln_rc=$?
  fi
  if [[ "$ln_rc" -ne 0 ]]; then
    echo "   FAILED (twice): could not prepare the rollback symlink. Escalating: attempting to unpublish (${LIVE_LINK} removed) rather than leave the candidate selected." >&2
    rm -f "$LIVE_LINK" || echo "   escalation ALSO failed: could not remove ${LIVE_LINK}; state UNKNOWN" >&2
    return 1
  fi

  local mv_rc=0
  mv -T "$restore_tmp" "$LIVE_LINK" || mv_rc=$?
  if [[ "$mv_rc" -ne 0 ]]; then
    echo "   mv -T could not restore ${LIVE_LINK} -> ${PREVIOUS_RELEASE} on first attempt; retrying once" >&2
    mv_rc=0
    mv -T "$restore_tmp" "$LIVE_LINK" || mv_rc=$?
  fi
  if [[ "$mv_rc" -ne 0 ]]; then
    echo "   FAILED (twice): mv -T could not restore the previous release. Escalating: attempting to unpublish (${LIVE_LINK} removed) rather than leave live-link state unknown/candidate-selected." >&2
    rm -f "$LIVE_LINK" || echo "   escalation ALSO failed: could not remove ${LIVE_LINK}; state UNKNOWN" >&2
    return 1
  fi

  local restored_target
  if ! restored_target="$(readlink -f "$LIVE_LINK")"; then
    echo "   FAILED: could not read back ${LIVE_LINK} after restoring it" >&2
    return 1
  fi
  if [[ "$restored_target" != "$PREVIOUS_RELEASE" ]]; then
    echo "   FAILED: ${LIVE_LINK} resolves to ${restored_target}, expected ${PREVIOUS_RELEASE}" >&2
    return 1
  fi

  # A cutover has already renamed the old subject log. Restarting the old
  # bridge now would open the vacant live name. Restore the selected link, keep
  # BOTH services stopped and the marker standing, and require the operator to
  # restore the retired file before any old-service restart. No false rollback
  # success can be inferred from a symlink alone.
  if [[ "$CUTOVER_APPLY" -eq 1 ]]; then
    echo "   CUTOVER ROLLBACK INCOMPLETE: previous release selected, bridge left STOPPED." >&2
    echo "   Restore the retired subject log to its live name while stopped, then verify the old service by hand. Marker retained." >&2
    return 1
  fi

  # A CODE forward relay rolls back with `restart` — a symlink swap alone
  # does not replace code a running process already loaded, coming back
  # out exactly as going in (the forward code-relay path's own rule).
  # A declaration-only forward relay rolls back with `reload` (SIGHUP).
  local reload_rc=0
  if [[ "$FORWARD_WAS_CODE" -eq 1 ]]; then
    systemctl restart mica-bridge || reload_rc=$?
  else
    systemctl reload mica-bridge || reload_rc=$?
  fi
  if [[ "$reload_rc" -ne 0 ]]; then
    echo "   systemctl $([[ "$FORWARD_WAS_CODE" -eq 1 ]] && echo restart || echo reload) mica-bridge exited ${reload_rc}; retrying once" >&2
    reload_rc=0
    if [[ "$FORWARD_WAS_CODE" -eq 1 ]]; then
      systemctl restart mica-bridge || reload_rc=$?
    else
      systemctl reload mica-bridge || reload_rc=$?
    fi
    if [[ "$reload_rc" -ne 0 ]]; then
      echo "   systemctl $([[ "$FORWARD_WAS_CODE" -eq 1 ]] && echo restart || echo reload) mica-bridge failed twice; continuing to status re-verification, which is the actual gate — it will correctly report FAILURE if the unit is not actually serving the restored release" >&2
    fi
  fi
  local restored_hash_file="${WORKDIR}/restored-hash.txt"
  local restored_sha_file="${WORKDIR}/restored-sha.txt"
  # S136: was `sleep 1` + one probe. See wait_for_live_status's header — this
  # site is the one where that defect could have cost an outage.
  if ! wait_for_live_status "${LIVE_LINK}/mica-bridge/declarations.config.json" "$restored_hash_file" "$restored_sha_file"; then
    echo "   ROLLBACK NOT VERIFIED: could not read the live status after rollback" >&2
    return 1
  fi
  local restored_hash
  restored_hash="$(cat "$restored_hash_file")"
  if [[ "$restored_hash" != "$PREVIOUS_HASH" ]]; then
    echo "   ROLLBACK NOT VERIFIED: got hash ${restored_hash}, expected ${PREVIOUS_HASH}" >&2
    return 1
  fi
  if [[ "$FORWARD_WAS_CODE" -eq 1 ]]; then
    # A CODE rollback must prove the RUNNING PROCESS's own executable
    # identity, not merely that the symlink points at the right directory
    # — the restart above is what makes this provable at all.
    local restored_sha
    restored_sha="$(cat "$restored_sha_file")"
    local previous_sha
    previous_sha="$(basename "$PREVIOUS_RELEASE")"
    if [[ "$restored_sha" != "$previous_sha" ]]; then
      echo "   ROLLBACK NOT VERIFIED: running release sha is ${restored_sha}, expected ${previous_sha} (declaration hash matched, but the executable identity did not)" >&2
      return 1
    fi
    echo "   rollback verified: symlink target, live declarationHash, AND running release sha all match the previous release" >&2
  else
    echo "   rollback verified: symlink target and live declarationHash both match the previous release (${PREVIOUS_HASH})" >&2
  fi
  remove_marker
  return 0
}

on_exit() {
  local ec=$?
  if [[ "$ROLLBACK_ARMED" -eq 1 ]]; then
    if do_rollback; then
      # A verified rollback still means THIS relay failed; never report 0.
      if [[ "$ec" -eq 0 ]]; then ec=1; fi
    else
      ec=1
    fi
  fi
  rm -rf "$WORKDIR"
  exit "$ec"
}
trap on_exit EXIT

# ── 6. prepare the temp symlink, THEN acquire the marker EXCLUSIVELY,
#      THEN arm, THEN swap — nothing else between arming and the swap.
#      AMENDMENT 8 / VERIFIER F3.2: the temp symlink is prepared FIRST
#      (per the verifier's own healing suggestion) because a failure there
#      cannot alter the live selection at all, so it need not hold the
#      lock. Marker ACQUISITION is exclusive (a persistent `flock`(1) mutex
#      plus an unguessable ownership token, relay-lib.sh, AMENDMENT 10) —
#      a second relay racing this one loses outright and refuses, ALWAYS
#      naming the real holder (never "(unreadable)"), rather than silently
#      overwriting the same marker. ─────────────────────────────────────────
TEMP_LINK="${WORKDIR}/live-link-tmp"
ln -s "$NEW_RELEASE" "$TEMP_LINK"
MARKER_CONTENT="$(
  echo "candidate_sha=${SHA}"
  echo "previous_sha=$([[ -n "$PREVIOUS_RELEASE" ]] && basename "$PREVIOUS_RELEASE" || echo none)"
  echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
)"
if ! marker_acquire "$MARKER_FILE" "$MARKER_CONTENT"; then
  exit 1
fi
ROLLBACK_ARMED=1
mv -T "$TEMP_LINK" "$LIVE_LINK"
echo "-- atomic swap complete: ${LIVE_LINK} -> ${NEW_RELEASE} (previous: ${PREVIOUS_RELEASE:-none, first install})"

if [[ "$DECLARATION_ONLY" -eq 1 ]]; then
  # ── 7a. declaration-only: SIGHUP, then compare the live hash for EXACT
  #        equality with EXPECTED_HASH ──────────────────────────────────
  echo "-- declaration-only relay: SIGHUP, then verify the new hash is live"
  systemctl reload mica-bridge

  LIVE_HASH_FILE="${WORKDIR}/live-hash.txt"
  LIVE_SHA_FILE="${WORKDIR}/live-sha.txt"
  # S136: was `sleep 1` + one probe. See wait_for_live_status's header.
  if ! wait_for_live_status "${LIVE_LINK}/mica-bridge/declarations.config.json" "$LIVE_HASH_FILE" "$LIVE_SHA_FILE"; then
    echo "REFUSED: could not read the live status after reload" >&2
    exit 1
  fi
  LIVE_HASH="$(cat "$LIVE_HASH_FILE")"
  echo "   live hash: ${LIVE_HASH}"
  echo "   expected:  ${EXPECTED_HASH}"

  if [[ "$LIVE_HASH" != "$EXPECTED_HASH" ]]; then
    echo "REFUSED: live declarationHash does not exactly equal the expected hash" >&2
    exit 1
    # trap fires on this non-zero exit -> rollback runs and verifies itself.
  fi
  echo "   declaration-only relay verified live: exact hash match"
else
  # ── 7b. code relay: restart, confirm active, AND verify the live hash
  #        AND the running release's OWN executable identity too —
  #        `systemctl is-active` alone proves the process is running,
  #        never that it is serving the candidate's own declaration OR
  #        running the candidate's own code ──────────────────────────
  echo "-- code relay: restarting the unit"
  if ! systemctl restart mica-bridge; then
    echo "REFUSED: systemctl restart mica-bridge failed" >&2
    exit 1
  fi
  CODE_HASH_FILE="${WORKDIR}/code-hash.txt"
  CODE_SHA_FILE="${WORKDIR}/code-sha.txt"
  # S136: was `sleep 1`, then one `is-active` check, then one probe. The
  # is-active check is NOT gone — it moved inside wait_for_live_status,
  # where it runs every second and can abort early instead of once, at the
  # one instant least likely to be informative. See that header.
  echo "   waiting for mica-bridge.service to serve /status"
  if ! wait_for_live_status "${LIVE_LINK}/mica-bridge/declarations.config.json" "$CODE_HASH_FILE" "$CODE_SHA_FILE"; then
    echo "REFUSED: could not read the live status after restart" >&2
    exit 1
  fi
  CODE_LIVE_HASH="$(cat "$CODE_HASH_FILE")"
  CODE_LIVE_SHA="$(cat "$CODE_SHA_FILE")"
  echo "   live hash after restart: ${CODE_LIVE_HASH}"
  echo "   expected:                ${EXPECTED_HASH}"
  echo "   live release sha:        ${CODE_LIVE_SHA}"
  echo "   expected release sha:    ${SHA}"
  if [[ "$CODE_LIVE_HASH" != "$EXPECTED_HASH" ]]; then
    echo "REFUSED: live declarationHash after the code restart does not exactly equal the expected hash" >&2
    exit 1
  fi
  if [[ "$CODE_LIVE_SHA" != "$SHA" ]]; then
    echo "REFUSED: the running process's own release sha (${CODE_LIVE_SHA}) does not equal the candidate sha (${SHA}) — declarationHash matched, but the executable identity did not" >&2
    exit 1
  fi
  echo "   code relay verified live: active, and exact hash match"
fi

remove_marker
ROLLBACK_ARMED=0
if [[ "$CUTOVER_APPLY" -eq 1 ]]; then
  rm -f "$CUTOVER_FILE" || echo "NOTE: cutover capture could not be removed; the next cutover will refuse until resolved" >&2
fi
echo "== relay complete: ${LIVE_LINK} -> ${NEW_RELEASE} =="
