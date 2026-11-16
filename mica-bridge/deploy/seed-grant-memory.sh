#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# seed-grant-memory.sh — S216-2 · THE SEED OF THE BRIDGE'S GRANT MEMORY. THE ARBITER'S HAND.
#
# Ticket ARC_MICA-TICKET_S216-2-Grant-Memory_DRAFT_v2_20261017.md §4 (cond. 10). The ticket names the act's copy
# at ~/mica-relay/s216-2/seed-grant-memory.sh; this file is its source in the release tree.
#
# WHAT IT DOES: lays ONE file, /var/lib/mica-bridge/grant-memory (mica-bridge:mica-bridge 0640), from a candidate
#   the seat built with the S216-2 release's own builder (tools/grant-memory-seed.ts) and posted (path, sha256, rows,
#   boundary declarationHash, predicted tag). Every grant in the served declaration, first seen AT ITS DECLARED
#   SINCE, under a SEEDED boundary: the arbiter's attestation, printed SEEDED for as long as the chain lives.
# WHAT IT NEVER DOES: overwrite or edit a memory, its lock or a leftover dot-temp; restart, reload or signal the
#   bridge; touch any other file. The running pre-S216-2 bridge does not know the file, so seeding while it runs is
#   safe; the S216-2 bridge adopts it at its relay's restart and appends nothing.
#
# S215 SHAPE: DRY BY DEFAULT (every check, nothing laid); --go only from the arbiter's own terminal (a tty, checked
#   before anything privileged); the run record (this run's tee'd log, run-stamped, written as the caller) exists
#   before the first sudo; NO SIGNAL TRAPS (S205) — the dot-temp is removed explicitly on every exit path after it
#   exists. Order of the --go half (draft §4 step 3): tty · run record · the refusals · install to a run-stamped
#   dot-temp · the dot-temp hashed AS ROOT against --expect-seed (closes the TOCTOU on the uid-1000 candidate) ·
#   sync · mv -n gated on its rc AND on the dot-temp's absence (coreutils >= 9.2 exits 1 on "not replacing";
#   older exits 0 silently) · sync · the final file's sha read back as root and COMPARED.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 077

STATE_DIR=/var/lib/mica-bridge
TARGET="$STATE_DIR/grant-memory"
SOCK=/run/mica-bridge/peers/1000/guard.sock
NODE_BIN=/usr/bin/node
TS_NODE_BIN=/opt/mica-machine/node_modules/ts-node/dist/bin.js
STAMP=$(date -u +%Y%m%dT%H%M%SZ)

CANDIDATE=""; EXPECT_SEED=""; EXPECT_DECL=""; RELEASE=""; RUN_DIR="${HOME}/mica-relay/s216-2"; GO=0; DOT=""

say()  { printf '%s\n' "$*"; }
# Explicit cleanup, called on every exit path once the dot-temp may exist. Never fails the caller; a removal that
# does not take is SAID with its path.
drop_dot() {
  if [ -n "$DOT" ]; then
    if sudo test -e "$DOT"; then sudo rm -f -- "$DOT" || say "  ⚠ could not remove the dot-temp $DOT — remove it by hand"; fi
    DOT=""
  fi
}
refuse() { say ""; say "REFUSED: $*"; say "NOTHING WAS LAID (or what was half-laid is named above)."; drop_dot; exit 2; }
need_value() {
  case "${2-}" in
    "") refuse "$1 needs a value and none was given" ;;
    -*) refuse "$1 needs a value, and the next argument is another flag ($2): a missing value would have eaten it" ;;
  esac
}
usage() {
  cat <<'USAGE'
usage: seed-grant-memory.sh --candidate PATH --expect-seed SHA256 --expect-declaration HASH --release DIR [--run-dir DIR] [--go]

  --candidate PATH          the candidate seed the seat built and posted
  --expect-seed SHA256      the candidate's sha256 as posted (checked as the caller, then the laid dot-temp as root)
  --expect-declaration HASH the CANONICAL declarationHash of the served declaration (loadDeclarations'), which the
                            file, live /status and the candidate's boundary must all name
  --release DIR             the S216-2 release tree whose tools/grant-memory-seed.ts verifies the candidate
  --run-dir DIR             where the run-stamped record goes (default ~/mica-relay/s216-2)
  --go                      lay it (the arbiter's own terminal only). Without --go: every check, nothing laid.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --candidate)          need_value "$1" "${2-}"; CANDIDATE=$2; shift 2 ;;
    --expect-seed)        need_value "$1" "${2-}"; EXPECT_SEED=$2; shift 2 ;;
    --expect-declaration) need_value "$1" "${2-}"; EXPECT_DECL=$2; shift 2 ;;
    --release)            need_value "$1" "${2-}"; RELEASE=$2; shift 2 ;;
    --run-dir)            need_value "$1" "${2-}"; RUN_DIR=$2; shift 2 ;;
    --go)                 GO=1; shift ;;
    -h|--help)            usage; exit 0 ;;
    *)                    usage; refuse "unknown argument: $1" ;;
  esac
done

# ── THE DRY RIG (uid 1000, no sudo) may point the checks at a fixture dir, socket and node; --go never may: a GO
#    run with any SEED_RIG_* set is refused, so the act reads only the constants above.
if [ -n "${SEED_RIG_STATE_DIR:-}${SEED_RIG_SOCK:-}${SEED_RIG_NODE_BIN:-}${SEED_RIG_TS_NODE_BIN:-}" ]; then
  [ "$GO" = "0" ] || { say "REFUSE: a SEED_RIG_* override is set: --go reads only the fixed paths"; exit 2; }
  STATE_DIR=${SEED_RIG_STATE_DIR:-$STATE_DIR}; TARGET="$STATE_DIR/grant-memory"
  SOCK=${SEED_RIG_SOCK:-$SOCK}; NODE_BIN=${SEED_RIG_NODE_BIN:-$NODE_BIN}; TS_NODE_BIN=${SEED_RIG_TS_NODE_BIN:-$TS_NODE_BIN}
  say "RIG        : state dir $STATE_DIR, socket $SOCK (dry only)"
fi

# ── 1 · the tty, BEFORE anything privileged and before the log takes stdout ──
if [ "$GO" = "1" ] && { [ ! -t 0 ] || [ ! -t 1 ]; }; then
  say "REFUSE: no tty: --go is the arbiter's own terminal only (S215)"; exit 2
fi
[ "$(id -u)" != "0" ] || refuse "run as yourself, not as root: the run record is the caller's, and sudo is asked step by step"

# ── 2 · the run record, run-stamped, before the first sudo ──
mkdir -p -- "$RUN_DIR" || refuse "could not make the run dir $RUN_DIR"
MODE=$([ "$GO" = "1" ] && echo GO || echo DRY)
LOG="$RUN_DIR/seed-grant-memory-$STAMP-$$-$MODE.txt"
[ ! -e "$LOG" ] || refuse "the run record $LOG already exists (run-stamped names are never reused)"
: > "$LOG" || refuse "could not write the run record $LOG"
exec > >(tee -a "$LOG") 2>&1
say "run        : $STAMP user=$(id -un) uid=$(id -u) mode=$MODE"
say "record     : $LOG"
say "script     : $0 sha256 $(sha256sum "$0" | cut -d' ' -f1)"

# ── 3 · the refusals, each printed ──
[ -n "$CANDIDATE" ] && [ -n "$EXPECT_SEED" ] && [ -n "$EXPECT_DECL" ] && [ -n "$RELEASE" ] || { usage; refuse "--candidate, --expect-seed, --expect-declaration and --release are all required"; }
[[ "$EXPECT_SEED" =~ ^[0-9a-f]{64}$ ]] || refuse "--expect-seed is not 64 lower-case hex: $EXPECT_SEED"
[[ "$EXPECT_DECL" =~ ^[0-9a-f]{64}$ ]] || refuse "--expect-declaration is not 64 lower-case hex: $EXPECT_DECL"
[ -f "$CANDIDATE" ] && [ -r "$CANDIDATE" ] || refuse "the candidate is not a readable regular file: $CANDIDATE"
TOOL="$RELEASE/mica-bridge/tools/grant-memory-seed.ts"
[ -f "$TOOL" ] || refuse "the release has no seed tool: $TOOL"
say "release    : $RELEASE ($(git -C "$RELEASE" rev-parse HEAD 2>/dev/null || echo 'not a git tree'))"

CAND_SHA=$(sha256sum -- "$CANDIDATE" | cut -d' ' -f1)
say "check      : candidate sha256 $CAND_SHA (as $(id -un)) vs --expect-seed $EXPECT_SEED"
[ "$CAND_SHA" = "$EXPECT_SEED" ] || refuse "the candidate is not the one posted"

say "check      : no memory, no lock, no leftover dot-temp in $STATE_DIR"
for p in "$TARGET" "$TARGET.lock"; do
  if [ -e "$p" ] || [ -L "$p" ]; then refuse "$p exists: a memory is never overwritten (a re-seed is a separate act, F-6)"; fi
done
LEFT=$(find "$STATE_DIR" -maxdepth 1 -name '.grant-memory.seed-*' -print 2>&1) || refuse "could not list $STATE_DIR for leftovers: $LEFT"
[ -z "$LEFT" ] || refuse "a leftover dot-temp exists (never reused): $LEFT"

DECL="$RELEASE/mica-bridge/declarations.config.json"
VER=$("$NODE_BIN" "$TS_NODE_BIN" -P "$RELEASE/mica-bridge/tsconfig.json" "$TOOL" verify --declaration "$DECL" --candidate "$CANDIDATE" 2>&1)
VRC=$?
say "$VER" | sed 's/^/  tool | /'
[ "$VRC" = "0" ] && grep -qx 'VERIFY=OK' <<<"$VER" || refuse "the release's chain verifier rejects the candidate (rc=$VRC)"
FILE_HASH=$(sed -n 's/^DECLARATION_HASH=//p' <<<"$VER")
BOUND_HASH=$(sed -n 's/^BOUNDARY_DECLARATION_HASH=//p' <<<"$VER")
TOOL_SHA=$(sed -n 's/^CANDIDATE_SHA256=//p' <<<"$VER")
PRED_TAG=$(sed -n 's/^PREDICTED_TAG=//p' <<<"$VER")
say "check      : the release's declaration file hashes $FILE_HASH; the candidate's boundary names $BOUND_HASH; --expect-declaration $EXPECT_DECL"
[ "$FILE_HASH" = "$EXPECT_DECL" ] || refuse "the declaration file's canonical hash is not --expect-declaration"
[ "$BOUND_HASH" = "$EXPECT_DECL" ] || refuse "the candidate's boundary does not name --expect-declaration"
[ "$TOOL_SHA" = "$EXPECT_SEED" ] || refuse "the tool read other bytes than the posted candidate ($TOOL_SHA)"

STATUS=$(curl -s --max-time 10 --unix-socket "$SOCK" http://localhost/status) || refuse "live /status could not be read on $SOCK"
LIVE=$("$NODE_BIN" -e 'const s=JSON.parse(process.argv[1]); console.log(`${s.declarationHash} ${s.lastRejectedDeclaration===null?"null":"SET"} ${s.preflight}`)' "$STATUS") || refuse "live /status did not parse"
read -r LIVE_HASH LIVE_REJ LIVE_PRE <<<"$LIVE"
say "check      : live /status declarationHash $LIVE_HASH, lastRejectedDeclaration $LIVE_REJ, $LIVE_PRE"
[ "$LIVE_HASH" = "$EXPECT_DECL" ] || refuse "the SERVED declaration is not --expect-declaration (the file is what is served, or this is not the act)"
[ "$LIVE_REJ" = "null" ] || refuse "/status.lastRejectedDeclaration is set: a refused SIGHUP (H11 c') can leave a back-dated since in the file while last-good is served; seeding from it would attest the back-dating"
say "predicted  : the S216-2 bridge adopts SEEDED, appends nothing, and prints $PRED_TAG"

if [ "$GO" = "0" ]; then
  say ""
  say "DRY: every check passed; nothing laid. --go would: sudo install -o mica-bridge -g mica-bridge -m 0640 the candidate"
  say "     to $STATE_DIR/.grant-memory.seed-$STAMP, hash it as root, sync, sudo mv -n it to $TARGET, sync, read it back."
  exit 0
fi

# ── 4 · the act (the arbiter's hand) ──
DOT="$STATE_DIR/.grant-memory.seed-$STAMP"
say "act        : sudo install -> $DOT"
sudo install -o mica-bridge -g mica-bridge -m 0640 -- "$CANDIDATE" "$DOT" || refuse "install to the dot-temp failed"
ROOT_SHA=$(sudo sha256sum -- "$DOT" | cut -d' ' -f1)
say "check      : the dot-temp hashed as root: $ROOT_SHA"
[ "$ROOT_SHA" = "$EXPECT_SEED" ] || refuse "the laid dot-temp is not the posted candidate (a swap between check and install)"
sudo sync || refuse "sync failed"
if sudo test -e "$TARGET"; then refuse "$TARGET appeared during the act"; fi
say "act        : sudo mv -n $DOT -> $TARGET"
sudo mv -n -- "$DOT" "$TARGET"
MVRC=$?
[ "$MVRC" = "0" ] || refuse "mv -n exited $MVRC (coreutils >= 9.2: 'not replacing' exits 1)"
if sudo test -e "$DOT"; then refuse "mv -n left the dot-temp in place: it did not replace (older coreutils exit 0 here)"; fi
DOT=""
sudo sync || say "  ⚠ the final sync failed; the read-back below is the gate"
FINAL_SHA=$(sudo sha256sum -- "$TARGET" | cut -d' ' -f1)
FINAL_STAT=$(sudo stat -c '%U:%G %a %s' -- "$TARGET")
say "read-back  : $TARGET sha256 $FINAL_SHA ($FINAL_STAT)"
[ "$FINAL_SHA" = "$EXPECT_SEED" ] || { say "REFUSED: THE LAID MEMORY IS NOT THE CANDIDATE. It is left in place for the arbiter's decision; do not relay the bridge."; exit 3; }
case "$FINAL_STAT" in
  "mica-bridge:mica-bridge 640 "*) ;;
  *) say "REFUSED: owner/mode is $FINAL_STAT, not mica-bridge:mica-bridge 640. Left in place for the arbiter's decision."; exit 3 ;;
esac
say ""
say "SEEDED $STAMP: $TARGET sha256 $FINAL_SHA, boundary declarationHash $EXPECT_DECL, predicted tag $PRED_TAG. Next: relay the S216-2 bridge (relay-bridge.sh), then read the tag back on the operator socket."
exit 0
