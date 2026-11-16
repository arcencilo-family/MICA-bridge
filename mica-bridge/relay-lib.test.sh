#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# relay-lib.test.sh — check()-style tests for relay-lib.sh's two primitives,
# run without root, without /opt, and without a real relay. Injects a fake
# `systemctl` onto PATH; relay-lib.sh calls it by bare name (never an
# absolute path), so shadowing it here is the same mechanism a real deploy
# would use, not a mock of different code.
#
# Run: bash mica-bridge/relay-lib.test.sh
# ─────────────────────────────────────────────────────────────────────────────

set -uo pipefail  # NOT -e: individual checks report failure themselves.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=relay-lib.sh
source "$HERE/relay-lib.sh"

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "PASS  $1"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL  $1"; [[ -n "${2:-}" ]] && echo "      $2"; }

FAKEBIN="$(mktemp -d /tmp/relay-lib-test-fakebin.XXXXXX)"
ORIG_PATH="$PATH"
export PATH="${FAKEBIN}:${ORIG_PATH}"

write_fake_systemctl() {
  # $1 = script body (the whole fake systemctl executable's content)
  cat > "${FAKEBIN}/systemctl" <<SCRIPT
#!/usr/bin/env bash
$1
SCRIPT
  chmod +x "${FAKEBIN}/systemctl"
}

# ── unit_confirmed_inactive ─────────────────────────────────────────────────

write_fake_systemctl '
if [[ "$1" == "show" ]]; then
  echo "LoadState=loaded"
  echo "ActiveState=inactive"
  echo "SubState=dead"
  echo "MainPID=0"
  exit 0
fi
exit 0
'
if unit_confirmed_inactive "mica-bridge" 2>/tmp/relay-lib-test-out.$$; then
  pass "unit_confirmed_inactive: ActiveState=inactive, MainPID=0 -> confirmed (rc 0)"
else
  fail "unit_confirmed_inactive: ActiveState=inactive, MainPID=0 -> confirmed (rc 0)" "$(cat /tmp/relay-lib-test-out.$$)"
fi

write_fake_systemctl '
if [[ "$1" == "show" ]]; then
  echo "cannot contact systemd" >&2
  exit 1
fi
exit 1
'
if ! unit_confirmed_inactive "mica-bridge" 2>/tmp/relay-lib-test-out.$$; then
  pass "unit_confirmed_inactive: systemctl show itself fails -> NOT confirmed (fail-closed, rc 1)"
else
  fail "unit_confirmed_inactive: systemctl show itself fails -> NOT confirmed (fail-closed, rc 1)"
fi

write_fake_systemctl '
if [[ "$1" == "show" ]]; then
  echo "LoadState=loaded"
  echo "ActiveState=active"
  echo "SubState=running"
  echo "MainPID=4242"
  exit 0
fi
exit 0
'
if ! unit_confirmed_inactive "mica-bridge" 2>/tmp/relay-lib-test-out.$$; then
  pass "unit_confirmed_inactive: ActiveState=active, MainPID nonzero -> NOT confirmed"
else
  fail "unit_confirmed_inactive: ActiveState=active, MainPID nonzero -> NOT confirmed"
fi

write_fake_systemctl '
if [[ "$1" == "show" ]]; then
  echo "LoadState=loaded"
  echo "ActiveState=inactive"
  echo "SubState=dead"
  echo "MainPID=9999"
  exit 0
fi
exit 0
'
if ! unit_confirmed_inactive "mica-bridge" 2>/tmp/relay-lib-test-out.$$; then
  pass "unit_confirmed_inactive: ActiveState=inactive but MainPID nonzero (stale) -> NOT confirmed"
else
  fail "unit_confirmed_inactive: ActiveState=inactive but MainPID nonzero (stale) -> NOT confirmed"
fi

# A missing unit may still return inactive/dead/0; its LoadState is decisive.
write_fake_systemctl '
if [[ "$1" == "show" ]]; then
  echo "LoadState=not-found"
  echo "ActiveState=inactive"
  echo "SubState=dead"
  echo "MainPID=0"
  exit 0
fi
exit 0
'
if ! unit_confirmed_inactive "missing-mica-bridge" 2>/tmp/relay-lib-test-out.$$; then
  pass "unit_confirmed_inactive: LoadState=not-found, inactive, MainPID=0 -> NOT confirmed"
else
  fail "unit_confirmed_inactive: LoadState=not-found, inactive, MainPID=0 -> NOT confirmed"
fi

write_fake_systemctl '
if [[ "$1" == "show" ]]; then
  echo "ActiveState=inactive"
  echo "SubState=dead"
  echo "MainPID=0"
  exit 0
fi
exit 0
'
if ! unit_confirmed_inactive "mica-bridge" 2>/tmp/relay-lib-test-out.$$; then
  pass "unit_confirmed_inactive: missing LoadState, inactive, MainPID=0 -> NOT confirmed"
else
  fail "unit_confirmed_inactive: missing LoadState, inactive, MainPID=0 -> NOT confirmed"
fi

# ── the verifier's exact regression (run-4, F3.1 healing suggestion):
# both `stop` attempts fail AND the activity query fails, while a
# candidate sentinel process is still alive -> assert no unlink and no
# marker removal. AMENDMENT 10 / VERIFIER run 5 F3.2-C: this now invokes
# the REAL `relay_rollback_first_install()` (relay-lib.sh) directly —
# the exact function `do_rollback`'s first-install branch calls — instead
# of a hand-mirrored local copy that could silently drift from it. ────────

SENTINEL_TESTDIR="$(mktemp -d /tmp/relay-lib-test-sentinel.XXXXXX)"
sleep 300 &
SENTINEL_PID=$!
# A real, currently-alive process this test can prove is still alive
# afterward — standing in for "candidate code may still be running."

TEST_LIVE_LINK="${SENTINEL_TESTDIR}/live-link"
TEST_RELEASE_DIR="${SENTINEL_TESTDIR}/release"
mkdir -p "$TEST_RELEASE_DIR"
ln -s "$TEST_RELEASE_DIR" "$TEST_LIVE_LINK"
TEST_MARKER="${SENTINEL_TESTDIR}/marker"
marker_acquire "$TEST_MARKER" "candidate_sha=deadbeef
previous_sha=none
started_at=2026-09-19T00:00:00Z
" > /dev/null

write_fake_systemctl '
if [[ "$1" == "stop" ]]; then
  echo "fake systemctl: cannot stop (simulated failure)" >&2
  exit 1
fi
if [[ "$1" == "show" ]]; then
  echo "fake systemctl: cannot query (simulated failure)" >&2
  exit 1
fi
exit 1
'

if ! relay_rollback_first_install "mica-bridge" "$TEST_LIVE_LINK" "$TEST_MARKER" >/dev/null 2>&1; then
  RESULT_OK=1
else
  RESULT_OK=0
fi

LINK_STILL_PRESENT=0
[[ -L "$TEST_LIVE_LINK" ]] && LINK_STILL_PRESENT=1
MARKER_STILL_PRESENT=0
marker_present "$TEST_MARKER" && MARKER_STILL_PRESENT=1
SENTINEL_STILL_ALIVE=0
kill -0 "$SENTINEL_PID" 2>/dev/null && SENTINEL_STILL_ALIVE=1

if [[ "$RESULT_OK" -eq 1 && "$LINK_STILL_PRESENT" -eq 1 && "$MARKER_STILL_PRESENT" -eq 1 && "$SENTINEL_STILL_ALIVE" -eq 1 ]]; then
  pass "F3.1 regression (via the REAL relay_rollback_first_install, not a mirror): both stop attempts fail + activity query fails + sentinel alive -> rollback refuses, link NOT removed, marker NOT removed"
else
  fail "F3.1 regression (via the REAL relay_rollback_first_install, not a mirror): both stop attempts fail + activity query fails + sentinel alive -> rollback refuses, link NOT removed, marker NOT removed" \
    "rollback_refused=${RESULT_OK} link_present=${LINK_STILL_PRESENT} marker_present=${MARKER_STILL_PRESENT} sentinel_alive=${SENTINEL_STILL_ALIVE}"
fi

kill "$SENTINEL_PID" 2>/dev/null
wait "$SENTINEL_PID" 2>/dev/null
rm -rf "$SENTINEL_TESTDIR"

# ── AMENDMENT 10 / VERIFIER run 5 — F3.2-A, F3.2-B, F3.2-C ─────────────────
#
# Every test below uses INDEPENDENT `bash -c` processes, never `( ... ) &`
# subshells — the verifier's own finding was that `(...)` retains the
# PARENT's `$$` in bash, so two subshells racing each other write the SAME
# pid into their holder records and the test cannot actually distinguish
# them. `bash -c '...' &` forks a genuinely separate interpreter with its
# own real pid, which is what `relay_lib.sh`'s `$$` then reports.

# None of the F3.2 tests below call systemctl (marker_acquire/release never
# touch it) — reset the fake to an inert "healthy" default anyway, purely so
# no state leaks from the F3.1 regression's "everything fails" systemctl.
write_fake_systemctl '
if [[ "$1" == "show" ]]; then
  echo "LoadState=loaded"
  echo "ActiveState=inactive"
  echo "SubState=dead"
  echo "MainPID=0"
  exit 0
fi
exit 0
'

# ── F3.2 / named-holder: two independent processes race one marker;
# exactly one acquires; the LOSER's refusal names the WINNER's real pid —
# never "(unreadable)" (the verifier's F3.2-B finding). ─────────────────────

NAMED_DIR="$(mktemp -d /tmp/relay-lib-test-named.XXXXXX)"
NAMED_MARKER="${NAMED_DIR}/marker"
BARRIER="${NAMED_DIR}/barrier"

for who in A B; do
  bash -c '
    source "'"$HERE"'/relay-lib.sh"
    while [[ ! -e "'"$BARRIER"'" ]]; do sleep 0.01; done
    if marker_acquire "'"$NAMED_MARKER"'" "holder='"$who"'"; then
      echo "acquired pid=$$ token=${MARKER_TOKEN}" > "'"$NAMED_DIR"'/result-'"$who"'"
    else
      echo "refused pid=$$" > "'"$NAMED_DIR"'/result-'"$who"'"
    fi
  ' 2> "${NAMED_DIR}/stderr-${who}" &
done
sleep 0.2
touch "$BARRIER"
wait

RESULT_A="$(cat "${NAMED_DIR}/result-A" 2>/dev/null || echo missing)"
RESULT_B="$(cat "${NAMED_DIR}/result-B" 2>/dev/null || echo missing)"
WINNER_STDERR="${NAMED_DIR}/stderr-A"
LOSER_LABEL="A"
if [[ "$RESULT_A" == acquired* ]]; then
  WINNER_PID="$(echo "$RESULT_A" | grep -o 'pid=[0-9]*' | cut -d= -f2)"
  LOSER_STDERR="${NAMED_DIR}/stderr-B"
  LOSER_LABEL="B"
elif [[ "$RESULT_B" == acquired* ]]; then
  WINNER_PID="$(echo "$RESULT_B" | grep -o 'pid=[0-9]*' | cut -d= -f2)"
  LOSER_STDERR="${NAMED_DIR}/stderr-A"
  LOSER_LABEL="A"
else
  WINNER_PID=""
  LOSER_STDERR=""
fi

EXACTLY_ONE_WON=0
{ [[ "$RESULT_A" == acquired* && "$RESULT_B" == refused* ]] || [[ "$RESULT_A" == refused* && "$RESULT_B" == acquired* ]]; } && EXACTLY_ONE_WON=1
LOSER_NAMES_REAL_HOLDER=0
if [[ -n "$WINNER_PID" && -s "$LOSER_STDERR" ]] && grep -q "pid=${WINNER_PID}" "$LOSER_STDERR" 2>/dev/null; then
  LOSER_NAMES_REAL_HOLDER=1
fi
LOSER_NEVER_UNREADABLE=1
[[ -n "$LOSER_STDERR" ]] && grep -q '(unreadable)' "$LOSER_STDERR" 2>/dev/null && LOSER_NEVER_UNREADABLE=0

if [[ "$EXACTLY_ONE_WON" -eq 1 && "$LOSER_NAMES_REAL_HOLDER" -eq 1 && "$LOSER_NEVER_UNREADABLE" -eq 1 ]]; then
  pass "F3.2-B healed: two independent bash -c processes (distinct real pids) race one marker -> exactly one acquires, the loser (${LOSER_LABEL}) names the real winner's pid ${WINNER_PID}, never (unreadable)"
else
  fail "F3.2-B healed: two independent bash -c processes race one marker -> exactly one acquires, loser names the real holder" \
    "A=${RESULT_A} B=${RESULT_B} winner_pid=${WINNER_PID} exactly_one_won=${EXACTLY_ONE_WON} loser_names_real_holder=${LOSER_NAMES_REAL_HOLDER} loser_never_unreadable=${LOSER_NEVER_UNREADABLE} loser_stderr=$(cat "$LOSER_STDERR" 2>/dev/null)"
fi

rm -rf "$NAMED_DIR"

# ── F3.2-A / ABA proof: process A acquires, then begins releasing but is
# PAUSED mid-critical-section (an interposed `rm` wraps the real one, still
# INSIDE marker_release, so the flock mutex is still held throughout the
# pause — this is the exact scenario the verifier demonstrated broke the
# OLD design). While A is paused, independent process C attempts
# marker_acquire. Asserted: C does NOT complete while A is paused (real
# mutual exclusion, not a race any interleaving could win); once A resumes
# and finishes releasing, C's acquire succeeds cleanly with a FRESH token,
# and C's own marker/owner are never subsequently touched by A (A has
# already fully finished by the time C could even start). ──────────────────

ABA_DIR="$(mktemp -d /tmp/relay-lib-test-aba.XXXXXX)"
ABA_MARKER="${ABA_DIR}/marker"
PAUSE_SIGNAL="${ABA_DIR}/paused"
RESUME_SIGNAL="${ABA_DIR}/resume"

bash -c '
  source "'"$HERE"'/relay-lib.sh"
  marker_acquire "'"$ABA_MARKER"'" "holder=A" > /dev/null
  rm() {
    touch "'"$PAUSE_SIGNAL"'"
    local waited=0
    while [[ ! -e "'"$RESUME_SIGNAL"'" ]]; do
      sleep 0.05
      waited=$((waited + 1))
      [[ "$waited" -gt 200 ]] && break   # 10s safety cap, never hang the suite
    done
    command rm "$@"
  }
  marker_release "'"$ABA_MARKER"'" > "'"$ABA_DIR"'/a-release.log" 2>&1
  echo "release_rc=$?" >> "'"$ABA_DIR"'/a-release.log"
' &
PID_A=$!

WAITED=0
while [[ ! -e "$PAUSE_SIGNAL" && "$WAITED" -lt 100 ]]; do sleep 0.05; WAITED=$((WAITED + 1)); done
A_PAUSED=0
[[ -e "$PAUSE_SIGNAL" ]] && A_PAUSED=1

bash -c '
  source "'"$HERE"'/relay-lib.sh"
  if marker_acquire "'"$ABA_MARKER"'" "holder=C"; then
    echo "acquired token=${MARKER_TOKEN}" > "'"$ABA_DIR"'/c-acquire.log"
  else
    echo "refused" > "'"$ABA_DIR"'/c-acquire.log"
  fi
' &
PID_C=$!

sleep 1
C_COMPLETED_WHILE_A_PAUSED=0
[[ -f "${ABA_DIR}/c-acquire.log" ]] && C_COMPLETED_WHILE_A_PAUSED=1

touch "$RESUME_SIGNAL"
wait "$PID_A"
wait "$PID_C"

A_RELEASE_OK=0
grep -q '^release_rc=0$' "${ABA_DIR}/a-release.log" 2>/dev/null && A_RELEASE_OK=1
C_ACQUIRED_AFTER_RESUME=0
grep -q '^acquired' "${ABA_DIR}/c-acquire.log" 2>/dev/null && C_ACQUIRED_AFTER_RESUME=1
FINAL_CONTENT="$(cat "$ABA_MARKER" 2>/dev/null || echo "(absent)")"
C_MARKER_SURVIVED_UNMOLESTED=0
[[ "$FINAL_CONTENT" == "holder=C" ]] && C_MARKER_SURVIVED_UNMOLESTED=1

if [[ "$A_PAUSED" -eq 1 && "$C_COMPLETED_WHILE_A_PAUSED" -eq 0 && "$A_RELEASE_OK" -eq 1 && \
      "$C_ACQUIRED_AFTER_RESUME" -eq 1 && "$C_MARKER_SURVIVED_UNMOLESTED" -eq 1 ]]; then
  pass "F3.2-A healed (ABA falsification, verifier run 5): A releases with an injected pause INSIDE the held flock -> C's concurrent acquire genuinely blocks (not completed after 1s), only proceeds once A finishes, and C's own marker/owner are never subsequently deleted by A"
else
  fail "F3.2-A healed (ABA falsification, verifier run 5)" \
    "a_paused=${A_PAUSED} c_completed_while_paused=${C_COMPLETED_WHILE_A_PAUSED} a_release_ok=${A_RELEASE_OK} c_acquired_after_resume=${C_ACQUIRED_AFTER_RESUME} final_marker=${FINAL_CONTENT}"
fi

rm -rf "$ABA_DIR"

# ── token revalidation, unit-level: a release attempt with the WRONG
# token must be refused even with no concurrency involved at all — the
# verifier's own words, "revalidated while holding the synchronisation
# primitive," is a claim about WHAT is checked, testable on its own. ───────

TOKEN_DIR="$(mktemp -d /tmp/relay-lib-test-token.XXXXXX)"
TOKEN_MARKER="${TOKEN_DIR}/marker"
marker_acquire "$TOKEN_MARKER" "holder=self" > /dev/null
REAL_TOKEN="$MARKER_TOKEN"
MARKER_TOKEN="0000000000000000deadbeefdeadbeef"
WRONG_TOKEN_RC=1
marker_release "$TOKEN_MARKER" >/dev/null 2>&1 && WRONG_TOKEN_RC=0
WRONG_TOKEN_MARKER_SURVIVED=0
marker_present "$TOKEN_MARKER" && WRONG_TOKEN_MARKER_SURVIVED=1
MARKER_TOKEN="$REAL_TOKEN"
CORRECT_TOKEN_RC=1
marker_release "$TOKEN_MARKER" >/dev/null 2>&1 && CORRECT_TOKEN_RC=0
CORRECT_TOKEN_MARKER_GONE=0
marker_present "$TOKEN_MARKER" || CORRECT_TOKEN_MARKER_GONE=1

if [[ "$WRONG_TOKEN_RC" -eq 1 && "$WRONG_TOKEN_MARKER_SURVIVED" -eq 1 && \
      "$CORRECT_TOKEN_RC" -eq 0 && "$CORRECT_TOKEN_MARKER_GONE" -eq 1 ]]; then
  pass "token revalidation: marker_release with a WRONG token is refused and the marker survives; with the CORRECT token it succeeds and the marker is gone"
else
  fail "token revalidation" \
    "wrong_token_rc=${WRONG_TOKEN_RC} wrong_token_survived=${WRONG_TOKEN_MARKER_SURVIVED} correct_token_rc=${CORRECT_TOKEN_RC} correct_token_gone=${CORRECT_TOKEN_MARKER_GONE}"
fi

rm -rf "$TOKEN_DIR"

# ── double-release is safely refused, never a crash, never a false success ─

DOUBLE_DIR="$(mktemp -d /tmp/relay-lib-test-double.XXXXXX)"
DOUBLE_MARKER="${DOUBLE_DIR}/marker"
marker_acquire "$DOUBLE_MARKER" "holder=self" > /dev/null
marker_release "$DOUBLE_MARKER" > /dev/null 2>&1
FIRST_RELEASE_RC=$?
marker_release "$DOUBLE_MARKER" > /dev/null 2>&1
SECOND_RELEASE_RC=$?

if [[ "$FIRST_RELEASE_RC" -eq 0 && "$SECOND_RELEASE_RC" -eq 1 ]]; then
  pass "double-release: first release succeeds, second is refused (no token held) rather than crashing or falsely succeeding"
else
  fail "double-release" "first_rc=${FIRST_RELEASE_RC} second_rc=${SECOND_RELEASE_RC}"
fi

rm -rf "$DOUBLE_DIR"

# ── wait_for_live_status (S136) ─────────────────────────────────────────────
#
# THE DEFECT UNDER TEST. relay-bridge.sh had three probe sites, each reading
# `sleep 1` followed by ONE read_live_status. mica-service.ts needs ~12 s to
# come up under ts-node on the deploy box, so that probe always fired against
# a service that had not yet bound a socket: at F-4 the code-relay site rolled
# back a healthy deployment twice because of it.
#
# `read_live_status` is defined in relay-bridge.sh, not here. These tests
# define their own; wait_for_live_status binds it at CALL time, the same
# late binding it uses for `systemctl`. So what runs below is the real
# function, not a mirror of it.

READY_CALLS="$(mktemp)"
READY_HASH_OUT="$(mktemp)"
READY_SHA_OUT="$(mktemp)"
READY_SUCCEED_ON=1

read_live_status() {
  local n
  n=$(( $(cat "$READY_CALLS") + 1 ))
  echo "$n" > "$READY_CALLS"
  if [[ "$n" -ge "$READY_SUCCEED_ON" ]]; then
    echo "fake-hash" > "$2"
    echo "fake-sha"  > "$3"
    return 0
  fi
  echo "   /status unreachable over fake.sock (attempt ${n})" >&2
  return 1
}

fake_systemctl_reporting() {
  # $1 = what `systemctl is-active` should print; $2 = its exit code
  write_fake_systemctl '
if [[ "$1" == "is-active" ]]; then echo "'"$1"'"; exit '"$2"'; fi
exit 0
'
}

# 1. THE BUG ITSELF: a service that is alive but still starting. Answers on
#    the third probe. The replaced code could not pass this by construction.
fake_systemctl_reporting "active" 0
echo "0" > "$READY_CALLS"
READY_SUCCEED_ON=3
MICA_BRIDGE_RELAY_READY_TIMEOUT=30 \
  wait_for_live_status "/dev/null" "$READY_HASH_OUT" "$READY_SHA_OUT" \
  >/tmp/relay-lib-test-out.$$ 2>&1
WAIT_RC=$?
if [[ "$WAIT_RC" -eq 0 ]] \
   && [[ "$(cat "$READY_CALLS")" -eq 3 ]] \
   && [[ "$(cat "$READY_HASH_OUT")" == "fake-hash" ]] \
   && [[ "$(cat "$READY_SHA_OUT")" == "fake-sha" ]]; then
  pass "wait_for_live_status: unit active, /status answers on probe 3 (the ~12s ts-node start) -> waits, succeeds, writes BOTH out-files. The replaced 'sleep 1 + one probe' fails this by construction."
else
  fail "wait_for_live_status: slow start should be waited out" \
       "rc=${WAIT_RC} probes=$(cat "$READY_CALLS") hash=$(cat "$READY_HASH_OUT") sha=$(cat "$READY_SHA_OUT") out=$(cat /tmp/relay-lib-test-out.$$)"
fi

# 2. A DEAD unit must NOT be waited out: the is-active check moved inside the
#    loop precisely so this fails fast rather than at the deadline.
fake_systemctl_reporting "failed" 3
echo "0" > "$READY_CALLS"
READY_SUCCEED_ON=999
SECONDS=0
MICA_BRIDGE_RELAY_READY_TIMEOUT=30 \
  wait_for_live_status "/dev/null" "$READY_HASH_OUT" "$READY_SHA_OUT" \
  >/tmp/relay-lib-test-out.$$ 2>&1
WAIT_RC=$?
DEAD_ELAPSED=$SECONDS
if [[ "$WAIT_RC" -ne 0 ]] \
   && [[ "$DEAD_ELAPSED" -lt 5 ]] \
   && grep -q "not waiting out the readiness deadline" /tmp/relay-lib-test-out.$$ \
   && grep -q 'is "failed"' /tmp/relay-lib-test-out.$$; then
  pass "wait_for_live_status: unit reports \"failed\" -> aborts after ${DEAD_ELAPSED}s naming the state, instead of sitting out the 30s deadline"
else
  fail "wait_for_live_status: dead unit should abort early" \
       "rc=${WAIT_RC} elapsed=${DEAD_ELAPSED}s out=$(cat /tmp/relay-lib-test-out.$$)"
fi

# 3. Unit stays in play but never answers: must time out AND replay the last
#    attempt's own diagnostics, so the failure is as specific as it ever was.
fake_systemctl_reporting "active" 0
echo "0" > "$READY_CALLS"
READY_SUCCEED_ON=999
MICA_BRIDGE_RELAY_READY_TIMEOUT=2 \
  wait_for_live_status "/dev/null" "$READY_HASH_OUT" "$READY_SHA_OUT" \
  >/tmp/relay-lib-test-out.$$ 2>&1
WAIT_RC=$?
if [[ "$WAIT_RC" -ne 0 ]] \
   && grep -q "did not answer within 2s" /tmp/relay-lib-test-out.$$ \
   && grep -q "/status unreachable over fake.sock" /tmp/relay-lib-test-out.$$; then
  pass "wait_for_live_status: unit active but /status never answers -> times out at the deadline AND replays the last probe's own diagnostics (failure stays loud, not swallowed by the poll)"
else
  fail "wait_for_live_status: timeout should replay diagnostics" \
       "rc=${WAIT_RC} out=$(cat /tmp/relay-lib-test-out.$$)"
fi

# 4. Fast path unchanged: answering immediately costs exactly one probe and
#    no waiting line, so the healthy case is not slowed by the fix.
fake_systemctl_reporting "active" 0
echo "0" > "$READY_CALLS"
READY_SUCCEED_ON=1
SECONDS=0
MICA_BRIDGE_RELAY_READY_TIMEOUT=30 \
  wait_for_live_status "/dev/null" "$READY_HASH_OUT" "$READY_SHA_OUT" \
  >/tmp/relay-lib-test-out.$$ 2>&1
WAIT_RC=$?
FAST_ELAPSED=$SECONDS
if [[ "$WAIT_RC" -eq 0 ]] \
   && [[ "$(cat "$READY_CALLS")" -eq 1 ]] \
   && [[ "$FAST_ELAPSED" -lt 2 ]] \
   && ! grep -q "answered after" /tmp/relay-lib-test-out.$$; then
  pass "wait_for_live_status: /status answers at once -> one probe, ${FAST_ELAPSED}s, no waiting line; the healthy relay is not slowed by the fix"
else
  fail "wait_for_live_status: fast path should stay fast and quiet" \
       "rc=${WAIT_RC} probes=$(cat "$READY_CALLS") elapsed=${FAST_ELAPSED}s out=$(cat /tmp/relay-lib-test-out.$$)"
fi

unset -f read_live_status
rm -f "$READY_CALLS" "$READY_HASH_OUT" "$READY_SHA_OUT"

# ── subject_units_confirmed_inactive (S201) ─────────────────────────────────
# The subject's caller unit comes from the declaration. Fixture names only:
# subject-a / subject-b, units unit-a / unit-b. The fake systemctl reports a
# unit ACTIVE iff its name is listed in $UNITS_ACTIVE_FILE, and logs every
# unit it was asked about, so "every declared unit was checked" is measured.
NODE_BIN="${NODE_BIN:-$(command -v node)}"
SU_DIR="$(mktemp -d /tmp/relay-lib-test-units.XXXXXX)"
UNITS_ACTIVE_FILE="${SU_DIR}/active"
UNITS_ASKED_FILE="${SU_DIR}/asked"
: > "$UNITS_ACTIVE_FILE"
write_fake_systemctl '
if [[ "$1" == "show" ]]; then
  u="${@: -1}"   # the unit is the LAST argument: relay-lib passes "--" before it
  [[ "${@: -2:1}" == "--" ]] || { echo "unit not after --" >&2; exit 9; }
  echo "$u" >> "'"$UNITS_ASKED_FILE"'"
  echo "LoadState=loaded"
  if grep -qxF "$u" "'"$UNITS_ACTIVE_FILE"'"; then
    echo "ActiveState=active"; echo "SubState=running"; echo "MainPID=4242"
  else
    echo "ActiveState=inactive"; echo "SubState=dead"; echo "MainPID=0"
  fi
  exit 0
fi
exit 0
'
write_units_config() {
  # $1 = JSON for subjects[]
  printf '{"subjects": %s}\n' "$1" > "${SU_DIR}/config.json"
}
TWO_DECLARED='[{"subject":"subject-a","toolName":"tool-x","stakesClass":"c","peerUid":4711,"unit":"unit-a"},{"subject":"subject-b","toolName":"tool-x","stakesClass":"c","peerUid":4712,"unit":"unit-b"}]'

write_units_config "$TWO_DECLARED"; : > "$UNITS_ASKED_FILE"; : > "$UNITS_ACTIVE_FILE"
if subject_units_confirmed_inactive "${SU_DIR}/config.json" 2>/tmp/relay-lib-test-out.$$ \
   && [[ "$(sort "$UNITS_ASKED_FILE" | tr '\n' ' ')" == "unit-a unit-b " ]]; then
  pass "subject_units_confirmed_inactive: two declared units, both inactive -> rc 0, and BOTH were queried"
else
  fail "subject_units_confirmed_inactive: two declared units, both inactive -> rc 0, both queried" \
       "asked=$(tr '\n' ' ' < "$UNITS_ASKED_FILE") out=$(cat /tmp/relay-lib-test-out.$$)"
fi

write_units_config "$TWO_DECLARED"; : > "$UNITS_ASKED_FILE"; echo "unit-b" > "$UNITS_ACTIVE_FILE"
if ! subject_units_confirmed_inactive "${SU_DIR}/config.json" 2>/tmp/relay-lib-test-out.$$ \
   && grep -q "unit-b is NOT confirmed inactive" /tmp/relay-lib-test-out.$$; then
  pass "subject_units_confirmed_inactive: the SECOND declared unit is active -> refused, naming it"
else
  fail "subject_units_confirmed_inactive: second unit active -> refused" "$(cat /tmp/relay-lib-test-out.$$)"
fi

write_units_config '[{"subject":"subject-a","toolName":"tool-x","stakesClass":"c","peerUid":4711,"unit":"unit-a"},{"subject":"subject-b","toolName":"tool-x","stakesClass":"c","peerUid":4712}]'
: > "$UNITS_ASKED_FILE"; : > "$UNITS_ACTIVE_FILE"
if ! subject_units_confirmed_inactive "${SU_DIR}/config.json" 2>/tmp/relay-lib-test-out.$$ \
   && grep -q '"subject-b" declares no unit: its caller cannot be confirmed stopped' /tmp/relay-lib-test-out.$$ \
   && [[ ! -s "$UNITS_ASKED_FILE" ]]; then
  pass "subject_units_confirmed_inactive: a subject with NO declared unit -> REFUSED (not skipped), before any unit is queried"
else
  fail "subject_units_confirmed_inactive: undeclared unit must refuse, not skip" \
       "asked=$(tr '\n' ' ' < "$UNITS_ASKED_FILE") out=$(cat /tmp/relay-lib-test-out.$$)"
fi

write_units_config '[{"subject":"subject-a","toolName":"tool-x","stakesClass":"c","peerUid":4711,"unit":"unit-a; true"}]'
: > "$UNITS_ASKED_FILE"; : > "$UNITS_ACTIVE_FILE"
if ! subject_units_confirmed_inactive "${SU_DIR}/config.json" 2>/tmp/relay-lib-test-out.$$ \
   && grep -q "which is not a unit name" /tmp/relay-lib-test-out.$$ && [[ ! -s "$UNITS_ASKED_FILE" ]]; then
  pass "subject_units_confirmed_inactive: a unit outside the name pattern -> refused, never passed to systemctl"
else
  fail "subject_units_confirmed_inactive: malformed unit must refuse" "$(cat /tmp/relay-lib-test-out.$$)"
fi

write_units_config '[]'; : > "$UNITS_ASKED_FILE"
if ! subject_units_confirmed_inactive "${SU_DIR}/config.json" 2>/tmp/relay-lib-test-out.$$; then
  pass "subject_units_confirmed_inactive: no subjects[] at all -> refused (nothing confirmed is not everything confirmed)"
else
  fail "subject_units_confirmed_inactive: empty subjects must refuse" "$(cat /tmp/relay-lib-test-out.$$)"
fi

if ! subject_units_confirmed_inactive "${SU_DIR}/no-such-config.json" 2>/tmp/relay-lib-test-out.$$; then
  pass "subject_units_confirmed_inactive: unreadable declaration -> refused (fail-closed)"
else
  fail "subject_units_confirmed_inactive: unreadable declaration must refuse"
fi

# ── R-e (round 2): the UNION of candidate and LIVE units; stdout-only list ───
# Review C6-1/C6-2. The running writers are the ones the LIVE declaration
# names, so its units are checked too; and node's stderr must never become a
# unit name. Fixture names only (unit-a, unit-b, unit-c).
write_live_config() {
  # $1 = JSON for the live file's subjects[]
  printf '{"subjects": %s}\n' "$1" > "${SU_DIR}/live.json"
}
ONE_DECLARED='[{"subject":"subject-a","toolName":"tool-x","stakesClass":"c","peerUid":4711,"unit":"unit-a"}]'

write_units_config "$ONE_DECLARED"
write_live_config '[{"subject":"subject-a","unit":"unit-a"},{"subject":"subject-b","unit":"unit-c"}]'
: > "$UNITS_ASKED_FILE"; echo "unit-c" > "$UNITS_ACTIVE_FILE"
if ! subject_units_confirmed_inactive "${SU_DIR}/config.json" "${SU_DIR}/live.json" 2>/tmp/relay-lib-test-out.$$ \
   && grep -q "unit-c is NOT confirmed inactive" /tmp/relay-lib-test-out.$$; then
  pass "R-e: a unit only the LIVE declaration names is ACTIVE -> refused, naming it (the candidate dropped that caller)"
else
  fail "R-e: a live-only active unit must refuse" "asked=$(tr '\n' ' ' < "$UNITS_ASKED_FILE") out=$(cat /tmp/relay-lib-test-out.$$)"
fi

: > "$UNITS_ASKED_FILE"; : > "$UNITS_ACTIVE_FILE"
if subject_units_confirmed_inactive "${SU_DIR}/config.json" "${SU_DIR}/live.json" 2>/tmp/relay-lib-test-out.$$ \
   && [[ "$(tr '\n' ' ' < "$UNITS_ASKED_FILE")" == "unit-a unit-c " ]]; then
  pass "R-e: candidate and live units all inactive -> rc 0; the UNION was queried, a shared unit once"
else
  fail "R-e: union all inactive -> rc 0, each unit once" "asked=$(tr '\n' ' ' < "$UNITS_ASKED_FILE") out=$(cat /tmp/relay-lib-test-out.$$)"
fi

write_live_config '[{"subject":"subject-a","toolName":"tool-x"}]'
: > "$UNITS_ASKED_FILE"; : > "$UNITS_ACTIVE_FILE"
if subject_units_confirmed_inactive "${SU_DIR}/config.json" "${SU_DIR}/live.json" 2>/tmp/relay-lib-test-out.$$ \
   && [[ "$(tr '\n' ' ' < "$UNITS_ASKED_FILE")" == "unit-a " ]] \
   && grep -q "the live declaration declares no unit" /tmp/relay-lib-test-out.$$; then
  pass "R-e: a live declaration that declares NO unit adds nothing, and says so — the candidate's units are checked"
else
  fail "R-e: unit-less live declaration -> candidate only, disclosed" "asked=$(tr '\n' ' ' < "$UNITS_ASKED_FILE") out=$(cat /tmp/relay-lib-test-out.$$)"
fi

# ROUND 3 (A10, reviews K3D1-8, K3D3-8): a live subject with no unit, beside one
# that declares a unit, was skipped SILENTLY. Each one is now NAMED on stderr.
write_live_config '[{"subject":"subject-a","unit":"unit-a"},{"subject":"subject-b"}]'
: > "$UNITS_ASKED_FILE"; : > "$UNITS_ACTIVE_FILE"
if subject_units_confirmed_inactive "${SU_DIR}/config.json" "${SU_DIR}/live.json" 2>/tmp/relay-lib-test-out.$$ \
   && [[ "$(tr '\n' ' ' < "$UNITS_ASKED_FILE")" == "unit-a " ]] \
   && grep -q "subject \"subject-b\" declares no unit: the candidate does not declare it, so its running caller (if any) is NOT confirmed stopped" /tmp/relay-lib-test-out.$$; then
  pass "A10: a LIVE subject with no unit, beside one with a unit, is NAMED on stderr — dropped by the candidate, it says nobody confirmed its caller stopped"
else
  fail "A10: a unit-less live subject must be named, never skipped silently" "asked=$(tr '\n' ' ' < "$UNITS_ASKED_FILE") out=$(cat /tmp/relay-lib-test-out.$$)"
fi

write_live_config '[{"subject":"subject-a"}]'
: > "$UNITS_ASKED_FILE"; : > "$UNITS_ACTIVE_FILE"
if subject_units_confirmed_inactive "${SU_DIR}/config.json" "${SU_DIR}/live.json" 2>/tmp/relay-lib-test-out.$$ \
   && [[ "$(tr '\n' ' ' < "$UNITS_ASKED_FILE")" == "unit-a " ]] \
   && grep -q "subject \"subject-a\" declares no unit: the candidate declares unit \"unit-a\" for it, and that unit is checked" /tmp/relay-lib-test-out.$$; then
  pass "A10: a unit-less live subject that the CANDIDATE covers is named too, with the candidate's unit that IS checked"
else
  fail "A10: a covered unit-less live subject must be named with the candidate's unit" "asked=$(tr '\n' ' ' < "$UNITS_ASKED_FILE") out=$(cat /tmp/relay-lib-test-out.$$)"
fi

: > "$UNITS_ASKED_FILE"; : > "$UNITS_ACTIVE_FILE"
if subject_units_confirmed_inactive "${SU_DIR}/config.json" "${SU_DIR}/no-such-live.json" 2>/tmp/relay-lib-test-out.$$ \
   && [[ "$(tr '\n' ' ' < "$UNITS_ASKED_FILE")" == "unit-a " ]] \
   && grep -q "is not readable" /tmp/relay-lib-test-out.$$; then
  pass "R-e: an UNREADABLE live declaration is disclosed on stderr, and the candidate's units are still checked"
else
  fail "R-e: unreadable live declaration -> candidate only, disclosed" "asked=$(tr '\n' ' ' < "$UNITS_ASKED_FILE") out=$(cat /tmp/relay-lib-test-out.$$)"
fi

write_units_config '[{"subject":"subject-a","toolName":"tool-x","stakesClass":"c","peerUid":4711}]'
write_live_config '[{"subject":"subject-a","unit":"unit-a"}]'
: > "$UNITS_ASKED_FILE"; : > "$UNITS_ACTIVE_FILE"
if ! subject_units_confirmed_inactive "${SU_DIR}/config.json" "${SU_DIR}/live.json" 2>/tmp/relay-lib-test-out.$$ \
   && grep -q '"subject-a" declares no unit' /tmp/relay-lib-test-out.$$ && [[ ! -s "$UNITS_ASKED_FILE" ]]; then
  pass "R-e: a CANDIDATE subject with no unit still REFUSES, even when the live file names one — the candidate runs next"
else
  fail "R-e: candidate without unit must refuse whatever the live file says" "asked=$(tr '\n' ' ' < "$UNITS_ASKED_FILE") out=$(cat /tmp/relay-lib-test-out.$$)"
fi

write_units_config "$ONE_DECLARED"
printf 'not json\n' > "${SU_DIR}/live.json"
: > "$UNITS_ASKED_FILE"
if ! subject_units_confirmed_inactive "${SU_DIR}/config.json" "${SU_DIR}/live.json" 2>/tmp/relay-lib-test-out.$$ \
   && [[ ! -s "$UNITS_ASKED_FILE" ]]; then
  pass "R-e: a READABLE live declaration that is not JSON REFUSES (what it declares cannot be known), before any query"
else
  fail "R-e: unparseable live declaration must refuse" "asked=$(tr '\n' ' ' < "$UNITS_ASKED_FILE") out=$(cat /tmp/relay-lib-test-out.$$)"
fi

write_live_config '[{"subject":"subject-a","unit":"unit-a; true"}]'
: > "$UNITS_ASKED_FILE"
if ! subject_units_confirmed_inactive "${SU_DIR}/config.json" "${SU_DIR}/live.json" 2>/tmp/relay-lib-test-out.$$ \
   && grep -q "the live declaration names unit" /tmp/relay-lib-test-out.$$ && [[ ! -s "$UNITS_ASKED_FILE" ]]; then
  pass "R-e: a LIVE unit outside the name pattern REFUSES, never passed to systemctl"
else
  fail "R-e: malformed live unit must refuse" "asked=$(tr '\n' ' ' < "$UNITS_ASKED_FILE") out=$(cat /tmp/relay-lib-test-out.$$)"
fi

# ── ZERO SUBJECTS · F-7 (a) (ticket Bridge-Zero-Subjects v2 §3, arm 9) ─────────
# An EMPTY candidate is admitted only under the four clauses; the empty union
# never reaches systemctl with an empty name. Fixture names only.
write_units_config '[]'
write_live_config '[{"subject":"subject-a","unit":"unit-a"}]'
: > "$UNITS_ASKED_FILE"; : > "$UNITS_ACTIVE_FILE"
if subject_units_confirmed_inactive "${SU_DIR}/config.json" "${SU_DIR}/live.json" 2>/tmp/relay-lib-test-out.$$ \
   && [[ "$(tr '\n' ' ' < "$UNITS_ASKED_FILE")" == "unit-a " ]]; then
  pass "ZERO-SUBJECTS (i): empty candidate, readable live whose unit is INACTIVE -> rc 0, and that unit WAS queried"
else
  fail "ZERO-SUBJECTS (i): empty candidate + inactive live unit -> rc 0, queried" "asked=$(tr '\n' ' ' < "$UNITS_ASKED_FILE") out=$(cat /tmp/relay-lib-test-out.$$)"
fi

: > "$UNITS_ASKED_FILE"; echo "unit-a" > "$UNITS_ACTIVE_FILE"
if ! subject_units_confirmed_inactive "${SU_DIR}/config.json" "${SU_DIR}/live.json" 2>/tmp/relay-lib-test-out.$$ \
   && grep -q "unit-a is NOT confirmed inactive" /tmp/relay-lib-test-out.$$; then
  pass "ZERO-SUBJECTS (i): empty candidate, the live unit is ACTIVE -> rc 1, naming it"
else
  fail "ZERO-SUBJECTS (i): empty candidate + active live unit must refuse" "asked=$(tr '\n' ' ' < "$UNITS_ASKED_FILE") out=$(cat /tmp/relay-lib-test-out.$$)"
fi

: > "$UNITS_ASKED_FILE"; : > "$UNITS_ACTIVE_FILE"
if ! subject_units_confirmed_inactive "${SU_DIR}/config.json" "${SU_DIR}/no-such-live.json" 2>/tmp/relay-lib-test-out.$$ \
   && grep -q "is not readable" /tmp/relay-lib-test-out.$$ && [[ ! -s "$UNITS_ASKED_FILE" ]]; then
  pass "ZERO-SUBJECTS (iv): empty candidate, UNREADABLE live -> rc 1, before any query"
else
  fail "ZERO-SUBJECTS (iv): empty candidate + unreadable live must refuse" "asked=$(tr '\n' ' ' < "$UNITS_ASKED_FILE") out=$(cat /tmp/relay-lib-test-out.$$)"
fi

write_live_config '[]'
: > "$UNITS_ASKED_FILE"; : > "$UNITS_ACTIVE_FILE"
if subject_units_confirmed_inactive "${SU_DIR}/config.json" "${SU_DIR}/live.json" 2>/tmp/relay-lib-test-out.$$ \
   && [[ ! -e "$UNITS_ASKED_FILE" || ! -s "$UNITS_ASKED_FILE" ]] \
   && grep -q "no declared caller on either side" /tmp/relay-lib-test-out.$$; then
  pass "ZERO-SUBJECTS (iii): empty candidate, live declares NO subject (zero -> zero) -> rc 0, systemctl NEVER called with an empty name, and it says so"
else
  fail "ZERO-SUBJECTS (iii): the empty union must return 0 without querying systemctl" "asked=[$(cat "$UNITS_ASKED_FILE")] out=$(cat /tmp/relay-lib-test-out.$$)"
fi

write_live_config '[{"subject":"subject-a"}]'
: > "$UNITS_ASKED_FILE"; : > "$UNITS_ACTIVE_FILE"
if ! subject_units_confirmed_inactive "${SU_DIR}/config.json" "${SU_DIR}/live.json" 2>/tmp/relay-lib-test-out.$$ \
   && grep -q 'subject "subject-a" declares no unit: its running caller cannot be confirmed stopped' /tmp/relay-lib-test-out.$$ \
   && [[ ! -s "$UNITS_ASKED_FILE" ]]; then
  pass "ZERO-SUBJECTS (ii): empty candidate, a LIVE subject with no unit -> rc 1 (was: a stderr line and a vacuous admit)"
else
  fail "ZERO-SUBJECTS (ii): empty candidate + unit-less live subject must refuse" "asked=$(tr '\n' ' ' < "$UNITS_ASKED_FILE") out=$(cat /tmp/relay-lib-test-out.$$)"
fi

write_live_config '[{"subject":"subject-a","unit":"unit-a"}]'
: > "$UNITS_ASKED_FILE"
if ! subject_units_confirmed_inactive "${SU_DIR}/config.json" 2>/tmp/relay-lib-test-out.$$ \
   && grep -q "no live declaration was named" /tmp/relay-lib-test-out.$$ && [[ ! -s "$UNITS_ASKED_FILE" ]]; then
  pass "ZERO-SUBJECTS (i)/(iv): empty candidate and NO live file named -> rc 1, in words"
else
  fail "ZERO-SUBJECTS: empty candidate without a live file must refuse in words" "out=$(cat /tmp/relay-lib-test-out.$$)"
fi

write_units_config "$ONE_DECLARED"

# stderr isolation (C6-2): a NODE_OPTIONS preload writes a line to node's stderr
# that is SHAPED LIKE A UNIT NAME. Merged into the list, it would be queried.
STDERR_PRELOAD="${SU_DIR}/stderr-preload.js"
printf 'process.stderr.write("unit-ghost\\n");\n' > "$STDERR_PRELOAD"
: > "$UNITS_ASKED_FILE"; : > "$UNITS_ACTIVE_FILE"
if NODE_OPTIONS="--require ${STDERR_PRELOAD}" subject_units_confirmed_inactive "${SU_DIR}/config.json" 2>/tmp/relay-lib-test-out.$$ \
   && [[ "$(tr '\n' ' ' < "$UNITS_ASKED_FILE")" == "unit-a " ]] \
   && grep -qx "unit-ghost" /tmp/relay-lib-test-out.$$; then
  pass "R-e: node's STDERR on a successful read reaches our stderr and NEVER the unit list (only unit-a was queried)"
else
  fail "R-e: node stderr must not become a unit name" "asked=$(tr '\n' ' ' < "$UNITS_ASKED_FILE") out=$(cat /tmp/relay-lib-test-out.$$)"
fi

: > "$UNITS_ASKED_FILE"
if ! NODE_BIN=/bin/false subject_units_confirmed_inactive "${SU_DIR}/config.json" 2>/tmp/relay-lib-test-out.$$ \
   && grep -q "could not be listed" /tmp/relay-lib-test-out.$$ && [[ ! -s "$UNITS_ASKED_FILE" ]]; then
  pass "R-e: the unit lister itself FAILING still refuses, before any query (fail-closed)"
else
  fail "R-e: a failing lister must refuse" "asked=$(tr '\n' ' ' < "$UNITS_ASKED_FILE") out=$(cat /tmp/relay-lib-test-out.$$)"
fi

# The served tree config declares a unit for every subject, so the cutover can
# name its caller; read by USE (the helper itself), not by grepping a name.
write_fake_systemctl '
if [[ "$1" == "show" ]]; then
  echo "LoadState=loaded"; echo "ActiveState=inactive"; echo "SubState=dead"; echo "MainPID=0"; exit 0
fi
exit 0
'
# REFERENCE-DEPLOYMENT-ONLY (see reference-only.ts): a fact of the reference box (a unit per subject); the example
# declares none. Runs only with MICA_BRIDGE_REFERENCE_SET=1.
if [[ "${MICA_BRIDGE_REFERENCE_SET:-}" != "1" ]]; then
  echo "SKIP-REF subject_units_confirmed_inactive: the tree config must declare every subject's unit (reference deployment only)"
elif subject_units_confirmed_inactive "$HERE/declarations.example.json" 2>/tmp/relay-lib-test-out.$$; then
  pass "subject_units_confirmed_inactive: the tree's declaration declares a unit for every subject"
else
  fail "subject_units_confirmed_inactive: the tree config must declare every subject's unit" "$(cat /tmp/relay-lib-test-out.$$)"
fi
rm -rf "$SU_DIR"

rm -f /tmp/relay-lib-test-out.$$
rm -rf "$FAKEBIN"
export PATH="$ORIG_PATH"

echo ""
echo "CENSUS: ${PASS} passed, ${FAIL} failed, $((PASS + FAIL)) total"
[[ "$FAIL" -eq 0 ]] || exit 1
