#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# relay-lib.sh — the primitives Amendment 8 pulled out of relay-bridge.sh so
# they can be sourced and tested in isolation (neither needs root, /opt, or a
# real relay to exercise): the positive-state inactivity check (F3.1) and the
# exclusive marker lock (F3.2, REDESIGNED in Amendment 10 — see below).
# `relay-bridge.sh` sources this file; `relay-lib.test.sh` sources it
# directly against fake `systemctl` and real independent processes, without
# touching anything under /opt.
# ─────────────────────────────────────────────────────────────────────────────

# ── unit_confirmed_inactive — AMENDMENT 8 / VERIFIER F3.1 ───────────────────
#
# The prior check was `systemctl is-active --quiet <unit>`, whose nonzero
# exit means "not active" (rc 3), "no such unit" (rc 4), OR "could not
# contact/query the manager at all" — all three collapse to the same
# boolean. Amendment 6's rollback treated that boolean as PROOF of a safe
# absence and went on to remove the live link and the marker — so a failure
# to READ the unit's state became proof the unit was gone. That is the
# exact fail-open inversion this project refuses everywhere else.
#
# Fixed: query a POSITIVE fact — `systemctl show --property=ActiveState
# --property=SubState --property=MainPID --property=LoadState` — and require the query ITSELF to
# succeed, LoadState to be exactly `loaded`, then ActiveState to be an allowed TERMINAL state
# (`inactive` or `failed` — never `activating`/`deactivating`/`active`/
# `reloading`) AND MainPID to be exactly `0`. Any query failure, any other
# LoadState, ActiveState, or a nonzero MainPID returns FAILURE — meaning the caller
# must NOT proceed to remove the link or the marker. Silence, in this
# function, is never treated as safety.
#
# Fourth-read repair: an absent unit can report ActiveState=inactive and
# MainPID=0. Require LoadState=loaded before treating it as stopped.
unit_confirmed_inactive() {
  local unit="$1"
  local show_output
  if ! show_output="$(systemctl show --property=LoadState --property=ActiveState --property=SubState --property=MainPID -- "$unit" 2>&1)"; then
    echo "   could not query systemctl show for ${unit} — cannot confirm inactive; treating as STILL ACTIVE (fail-closed): ${show_output}" >&2
    return 1
  fi
  local load_state active_state sub_state main_pid
  load_state="$(printf '%s\n' "$show_output" | sed -n 's/^LoadState=//p')"
  active_state="$(printf '%s\n' "$show_output" | grep '^ActiveState=' | cut -d= -f2-)"
  sub_state="$(printf '%s\n' "$show_output" | grep '^SubState=' | cut -d= -f2-)"
  main_pid="$(printf '%s\n' "$show_output" | grep '^MainPID=' | cut -d= -f2-)"
  echo "   ${unit}: LoadState=${load_state:-<missing>} ActiveState=${active_state:-<missing>} SubState=${sub_state:-<missing>} MainPID=${main_pid:-<missing>}" >&2
  if [[ "$load_state" != "loaded" ]]; then
    echo "   NOT confirmed inactive: LoadState=${load_state:-<missing>} (expected loaded) — treating as STILL ACTIVE (fail-closed)" >&2
    return 1
  fi
  if [[ -z "$active_state" || -z "$main_pid" ]]; then
    echo "   NOT confirmed inactive: systemctl show did not report ActiveState/MainPID — treating as STILL ACTIVE (fail-closed)" >&2
    return 1
  fi
  if [[ "$active_state" != "inactive" && "$active_state" != "failed" ]]; then
    echo "   NOT confirmed inactive: ActiveState=${active_state} (only 'inactive' or 'failed' are accepted terminal states)" >&2
    return 1
  fi
  if [[ "$main_pid" != "0" ]]; then
    echo "   NOT confirmed inactive: MainPID=${main_pid} (expected 0)" >&2
    return 1
  fi
  return 0
}

# ── subject_units_confirmed_inactive — S201, round 2 (R-e) ──────────────────
#
# The cutover must know every writer of the subject log is stopped. The bridge
# is its own unit; the subject's CALLER is not the bridge's to name, so its unit
# comes from the declaration (`subjects[].unit`), never from this script (S201
# removability rule: no subject, uid or unit is named in bridge code).
#
# $1 = the CANDIDATE declarations.config.json (the declaration this cutover
#      lays). Every subject in it must declare a unit.
# $2 = OPTIONAL, the LIVE declarations.config.json (the one serving now).
#
# ⛔ THE UNION, NOT THE CANDIDATE ALONE (review C6-1/C6-2). The writers actually
#    running are the ones the OUTGOING declaration names. Checking only the
#    candidate let a candidate that renamed or dropped a caller pass while the
#    live caller was still active and never queried. So every unit the live file
#    declares is checked too — when that file is readable and declares any.
#    ⚠ CEILING: a live declaration that declares NO unit (the served config
#    before S201 relays) adds nothing, and an UNREADABLE live file is disclosed
#    on stderr and adds nothing; in both cases only the candidate's units are
#    queried. A live file that is readable but not JSON, or names a unit outside
#    the pattern, REFUSES — it is readable, so what it declares must be known.
#    ⚠ A LIVE SUBJECT WITHOUT A UNIT adds nothing to the query either, whether
#    or not its neighbours declare one — but it is NAMED on stderr, one line per
#    subject, saying whether the candidate covers it (round 3, A10). It is a
#    disclosure, not a refusal: the live file predates the unit rule, and the
#    candidate is what will run next.
# ⛔ A CANDIDATE subject that declares NO unit is a REFUSAL, never a skip: a
#    caller this script cannot name is a caller it cannot confirm stopped, and
#    skipping it would turn "not declared" into "confirmed inactive" — the same
#    fail-open inversion unit_confirmed_inactive exists to refuse. A live file
#    cannot excuse it: the candidate is what will run next.
# ⛔ ONLY node's STDOUT IS THE UNIT LIST (review C6-2). The old `2>&1` made
#    anything node wrote to stderr on a SUCCESSFUL read (NODE_DEBUG, a
#    NODE_OPTIONS preload, a deprecation warning) a "unit name" handed to
#    systemctl. stderr now passes straight through to ours, where an operator
#    reads it; it never reaches the list. A node failure (non-zero exit) still
#    refuses.
# ⚠ The unit name is re-checked against the loader's pattern here too, because
#   it becomes a systemctl argument; a mismatch refuses rather than quoting it.
# Requires NODE_BIN. Returns 0 only when every candidate subject declares a
# unit and every unit in the union is confirmed inactive.
# ZERO SUBJECTS (ticket Bridge-Zero-Subjects v2 §3, F-7 (a)) — an EMPTY candidate
# (subjects: []) is admitted only under all four clauses:
#   (i)   the live file is named and readable (what runs now must be known);
#   (iv)  an unreadable or unnamed live file with an empty candidate REFUSES;
#   (ii)  a live subject that declares no unit REFUSES (nobody could confirm its
#         caller stopped, and the candidate names nobody to cover it);
#   (iii) an EMPTY UNION (empty candidate, live declares no subject) returns 0
#         WITHOUT querying systemctl with an empty name, and says so on stderr.
#         Before this the loop ran once with unit="" and `systemctl show ""`
#         failed — a refusal by accident, not in words.
subject_units_confirmed_inactive() {
  local config="$1"
  local live="${2:-}"
  local units
  if ! units="$("${NODE_BIN:?NODE_BIN must be set}" -e '
      const fs = require("fs");
      const UNIT = /^[A-Za-z0-9@_.:][A-Za-z0-9@_.:-]*$/;
      const candidatePath = process.argv[1];
      const livePath = process.argv[2] || "";
      const d = JSON.parse(fs.readFileSync(candidatePath, "utf8"));
      const subjects = Array.isArray(d.subjects) ? d.subjects : [];
      const emptyCandidate = subjects.length === 0;
      if (emptyCandidate && livePath === "") {
        console.error("the candidate declaration lists no subjects[] and no live declaration was named: what runs now cannot be known, so no caller can be confirmed stopped");
        process.exit(1);
      }
      const out = [];
      for (const s of subjects) {
        if (s === null || typeof s !== "object" || typeof s.unit !== "string") {
          console.error("subject " + JSON.stringify(s && s.subject) + " declares no unit: its caller cannot be confirmed stopped");
          process.exit(1);
        }
        if (!UNIT.test(s.unit)) {
          console.error("subject " + JSON.stringify(s.subject) + " declares unit " + JSON.stringify(s.unit) + ", which is not a unit name");
          process.exit(1);
        }
        if (!out.includes(s.unit)) out.push(s.unit);
      }
      if (livePath !== "") {
        let text = null;
        try {
          text = fs.readFileSync(livePath, "utf8");
        } catch (err) {
          if (emptyCandidate) {
            console.error("the candidate declaration lists no subjects[] and the live declaration " + JSON.stringify(livePath) + " is not readable (" + String(err && err.code) + "): no caller can be confirmed stopped");
            process.exit(1);
          }
          console.error("the live declaration " + JSON.stringify(livePath) + " is not readable (" + String(err && err.code) + "): only the candidate declaration'\''s units are checked");
        }
        if (text !== null) {
          const live = JSON.parse(text);
          const liveSubjects = Array.isArray(live.subjects) ? live.subjects : [];
          let declared = 0;
          for (const s of liveSubjects) {
            if (emptyCandidate && (s === null || typeof s !== "object" || s.unit === undefined)) {
              console.error("the candidate declaration lists no subjects[] and the live declaration'\''s subject " + JSON.stringify(s && s.subject) + " declares no unit: its running caller cannot be confirmed stopped");
              process.exit(1);
            }
            if (s !== null && typeof s === "object" && s.unit === undefined) {
              // ROUND 3 (A10, reviews K3D1-8, K3D3-8): a live subject with no
              // unit is NAMED, never skipped silently — when the candidate
              // drops it too, its running caller is queried by nobody.
              const cand = subjects.find((c) => c !== null && typeof c === "object" && c.subject === s.subject);
              console.error(
                "the live declaration'\''s subject " + JSON.stringify(s.subject) + " declares no unit: " +
                  (cand !== undefined
                    ? "the candidate declares unit " + JSON.stringify(cand.unit) + " for it, and that unit is checked"
                    : "the candidate does not declare it, so its running caller (if any) is NOT confirmed stopped by this check")
              );
            }
            if (s === null || typeof s !== "object" || s.unit === undefined) continue;
            if (typeof s.unit !== "string" || !UNIT.test(s.unit)) {
              console.error("the live declaration names unit " + JSON.stringify(s.unit) + " for subject " + JSON.stringify(s.subject) + ", which is not a unit name");
              process.exit(1);
            }
            declared++;
            if (!out.includes(s.unit)) out.push(s.unit);
          }
          if (declared === 0) {
            console.error("the live declaration declares no unit: only the candidate declaration'\''s units are checked");
          }
        }
      }
      console.log(out.join("\n"));
    ' "$config" "$live")"; then
    echo "   REFUSED: the declared caller units could not be listed (node's reason, if any, is on the line(s) above)" >&2
    return 1
  fi
  # (iii) the empty union. node exits 0 with no unit only when the candidate is
  # empty AND the readable live file declares no subject: nothing to confirm.
  if [[ -z "$units" ]]; then
    echo "   no declared caller on either side (candidate and live declare no subject); nothing to confirm" >&2
    return 0
  fi
  local unit
  while IFS= read -r unit; do
    if ! unit_confirmed_inactive "$unit"; then
      echo "   subject caller unit ${unit} is NOT confirmed inactive" >&2
      return 1
    fi
  done <<< "$units"
  return 0
}

# ── relay_rollback_first_install — AMENDMENT 10 / VERIFIER run 5 F3.2-C ────
#
# Factored OUT of relay-bridge.sh's do_rollback() first-install branch so
# relay-lib.test.sh's F3.1 regression can invoke the EXACT production logic
# instead of a hand-mirrored copy — the verifier's own finding was that the
# prior test's `simulate_first_install_rollback` mirrored this branch
# locally, so the two could silently drift. Parametrized on the unit name,
# live-link path, and marker path (rather than reading relay-bridge.sh's own
# globals), so it is genuinely sourceable and testable standalone; called
# from relay-bridge.sh with exactly those same values. Returns 0 having
# stopped the candidate unit, confirmed it inactive, removed the live link,
# and released the marker (a confirmed-safe first-install rollback); returns
# 1, having left the link AND the marker in place, on any uncertainty —
# uncertainty must never be allowed to look like cleanliness.
relay_rollback_first_install() {
  local unit="$1"
  local live_link="$2"
  local marker_file="$3"

  local stop_rc=0
  systemctl stop "$unit" || stop_rc=$?
  if [[ "$stop_rc" -ne 0 ]]; then
    echo "   systemctl stop ${unit} exited ${stop_rc} on first attempt; retrying once" >&2
    stop_rc=0
    systemctl stop "$unit" || stop_rc=$?
  fi
  sleep 1
  if ! unit_confirmed_inactive "$unit"; then
    echo "   FAILED: could not confirm ${unit}.service inactive after stop (and one retry) — candidate code may still be running (or its state is simply unknown); NOT removing the live link or the marker, since either would hide that uncertainty behind an apparently-clean state" >&2
    return 1
  fi
  echo "   candidate unit confirmed inactive (positive ActiveState/MainPID check)" >&2

  local rm_rc=0
  rm -f "$live_link" || rm_rc=$?
  if [[ "$rm_rc" -ne 0 ]]; then
    echo "   rm -f ${live_link} failed once; retrying" >&2
    rm_rc=0
    rm -f "$live_link" || rm_rc=$?
  fi
  if [[ "$rm_rc" -ne 0 || -L "$live_link" || -e "$live_link" ]]; then
    echo "   FAILED to remove the live link after the unit was confirmed inactive — state is UNKNOWN; the marker is left in place for the next run/operator to find" >&2
    return 1
  fi
  echo "   first install: candidate unit stopped and confirmed inactive, live link removed; no candidate is selected (this is still a FAILED relay — there is no verified target to declare, only a confirmed-safe absence)" >&2
  if ! marker_release "$marker_file"; then
    echo "   NOTE: could not remove ${marker_file} — the next relay will refuse until a human clears it, even though this outcome was verified" >&2
  fi
  return 0
}

# ── marker_acquire / marker_release — AMENDMENT 8, REDESIGNED AMENDMENT 10 ─
# ── (VERIFIER run 5, findings F3.2-A and F3.2-B) ────────────────────────────
#
# AMENDMENT 8's design used `mkdir <marker>.lock` as BOTH the exclusivity
# signal AND the ownership record, and `marker_release` deleted that same
# directory as its last act. Verifier run 5 falsified the source's own claim
# that a process "can never delete a marker it does not actually hold":
#
#   F3.2-A (ABA) — `marker_release` READ the holder pid, then, separately,
#   DELETED by path name. Between the read and the delete there was no
#   synchronization object held — so if the paused old winner's holder
#   record was gone and RE-ACQUIRED by an independent process C in that
#   window, the old winner's delayed `rm` calls deleted C's marker and
#   C's lock, unconditionally, because they targeted a PATH, not the
#   specific generation of ownership that had actually been validated.
#
#   F3.2-B (publication gap) — `mkdir <marker>.lock` (the exclusivity
#   signal) and writing `<marker>.lock/holder` (the ownership record) were
#   TWO separate steps. A loser that lost the `mkdir` race but read
#   `holder` before the winner had written it saw an empty/absent file and
#   printed "Holder: (unreadable)" — a real gap between "the name is taken"
#   and "the name means something a reader can act on."
#
# REDESIGNED:
#
#   - The lock directory (`<marker>.lock`) is now a PERSISTENT container,
#     created once (idempotent `mkdir -p`) and NEVER removed by ordinary
#     acquire/release — closing the verifier's explicit instruction "do not
#     delete/recreate the synchronization object as part of ordinary
#     release." Only the files INSIDE it (the owner record, the marker
#     itself) are created/removed.
#   - A single persistent `flock`(1)-backed mutex file
#     (`<marker>.lock/sync`) SERIALIZES the entire read-check-act sequence
#     of BOTH `marker_acquire` and `marker_release` — closing F3.2-A
#     structurally: no third party can observe or mutate ownership state
#     while either function is mid-decision, because both hold the SAME
#     exclusive lock for their entire critical section, and `flock` is a
#     real kernel-held lock (not a deletable/re-creatable filesystem
#     object) that survives a paused holder and is only released when that
#     holder's own fd is closed (explicitly, or by process exit/crash —
#     never silently reassignable to a third party mid-section).
#   - Ownership is an UNGUESSABLE TOKEN (16 random bytes from
#     `/dev/urandom`, hex-encoded), not merely a pid. `marker_acquire`
#     records it in `<marker>.lock/owner` AND in this process's own
#     `MARKER_TOKEN` shell global; `marker_release` REVALIDATES that token
#     — read fresh, WHILE HOLDING the same flock mutex — against
#     `MARKER_TOKEN`, and deletes the marker and the owner record ONLY on
#     an exact match. A process whose view of ownership is stale (wrong or
#     missing token) is refused, even if nothing else has gone wrong.
#   - `<marker>.lock/owner`'s full content (token, pid, start time) is
#     written to a uniquely-named temp file FIRST, then the file itself is
#     what gets read by a loser — but because BOTH the writer and every
#     reader are serialized by the same flock mutex, a loser can only ever
#     observe `owner` in one of two states: absent (no one holds it yet) or
#     fully written (the winner's ENTIRE critical section, write included,
#     completed before the loser was allowed past the lock) — closing
#     F3.2-B structurally, the same way F3.2-A was closed, rather than by a
#     separate filesystem trick.
#
# The human-readable MARKER FILE itself is unchanged in shape (still a
# plain file `mica-service.ts` reads as before).

marker_lock_dir() {
  echo "${1}.lock"
}

# 16 random bytes, hex-encoded — unguessable in the sense the verifier
# asked for (not a small monotonic pid, not derivable from time+pid alone).
# Falls back to a clearly-labeled, weaker mix only if /dev/urandom is
# somehow unreadable (never expected on this project's Linux-only boxes,
# ruling S84) — the FALLBACK- prefix makes a fallback firing visible in any
# holder record it appears in, rather than silently indistinguishable from
# the real thing.
marker_generate_token() {
  if [[ -r /dev/urandom ]]; then
    od -An -tx1 -N16 /dev/urandom | tr -d ' \n'
  else
    echo "FALLBACK-$$-$(date +%s%N)-${RANDOM}${RANDOM}"
  fi
}

# Acquires the flock(1) mutex for marker_path's critical section into the
# CURRENT shell (no subshell — a bash function, not `flock -c`, so that
# variables set inside the critical section are visible to the caller).
# Ensures the persistent lock_dir/sync file exist first (idempotent).
# Sets MARKER_SYNC_FD; caller MUST call marker_sync_unlock when done, even
# on a failure path.
marker_sync_lock() {
  local marker_path="$1"
  local lock_dir sync_file
  lock_dir="$(marker_lock_dir "$marker_path")"
  if ! mkdir -p "$lock_dir" 2>/dev/null; then
    return 1
  fi
  sync_file="${lock_dir}/sync"
  # Idempotent: creates the persistent sync file if absent, never truncates
  # an existing one (content is never read — flock locks the inode/fd, not
  # the bytes — so there is nothing to preserve, but `touch` over `: >`
  # avoids even a momentary, unnecessary truncate of a file another process
  # may have concurrently opened).
  touch "$sync_file" 2>/dev/null || return 1
  if ! command -v flock >/dev/null 2>&1; then
    echo "   flock(1) not found — cannot safely serialize marker acquisition; refusing rather than proceeding unlocked" >&2
    return 1
  fi
  exec {MARKER_SYNC_FD}>"$sync_file" || return 1
  if ! flock -x "$MARKER_SYNC_FD"; then
    exec {MARKER_SYNC_FD}>&-
    unset MARKER_SYNC_FD
    return 1
  fi
  return 0
}

marker_sync_unlock() {
  if [[ -n "${MARKER_SYNC_FD:-}" ]]; then
    flock -u "$MARKER_SYNC_FD" 2>/dev/null
    exec {MARKER_SYNC_FD}>&- 2>/dev/null
    unset MARKER_SYNC_FD
  fi
}

# Returns 0 and WRITES the marker file's content ($2) if this process
# acquired the lock — and sets MARKER_TOKEN to this acquisition's own
# unguessable token, which `marker_release` later revalidates. Returns 1,
# printing who (if determinable — and now, ALWAYS determinable once the
# lock name is actually taken, per F3.2-B's fix) already holds it, if it
# did not.
marker_acquire() {
  local marker_path="$1"
  local content="$2"
  local lock_dir owner_file tmp_owner token

  lock_dir="$(marker_lock_dir "$marker_path")"
  owner_file="${lock_dir}/owner"

  if ! marker_sync_lock "$marker_path"; then
    echo "REFUSED: could not obtain the synchronization lock for ${marker_path}" >&2
    return 1
  fi

  if [[ -e "$owner_file" ]]; then
    local holder
    holder="$(cat "$owner_file" 2>/dev/null || echo "(unreadable)")"
    echo "REFUSED: another relay already holds ${marker_path} — refusing to race it. Holder: ${holder}" >&2
    marker_sync_unlock
    return 1
  fi

  token="$(marker_generate_token)"
  if ! tmp_owner="$(mktemp "${lock_dir}/.owner.XXXXXX" 2>/dev/null)"; then
    echo "REFUSED: could not create a temp owner record under ${lock_dir}" >&2
    marker_sync_unlock
    return 1
  fi
  {
    echo "token=${token}"
    echo "pid=$$"
    echo "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } > "$tmp_owner"
  # The full record above is written BEFORE this file is ever visible under
  # the name `owner_file` a loser would read — and every possible reader
  # (another marker_acquire call) is itself blocked on the SAME flock mutex
  # this process still holds, so there is no window in which anyone reads
  # owner_file in a partial state (F3.2-B).
  mv -T "$tmp_owner" "$owner_file"
  printf '%s' "$content" > "$marker_path"
  MARKER_TOKEN="$token"
  marker_sync_unlock
  return 0
}

# Removes the marker AND its owner record — never the persistent lock_dir
# or sync file (AMENDMENT 10: ordinary release no longer deletes/recreates
# the synchronization object at all) — but ONLY if, freshly read WHILE
# HOLDING the same flock mutex `marker_acquire` used, the owner record's
# token still matches THIS process's own `MARKER_TOKEN` (set by this
# process's own prior `marker_acquire` call). Safe to call even if this
# process never held the lock, or has already released it — it simply
# refuses in that case, rather than assuming ownership.
marker_release() {
  local marker_path="$1"
  local lock_dir owner_file

  lock_dir="$(marker_lock_dir "$marker_path")"
  owner_file="${lock_dir}/owner"

  if [[ -z "${MARKER_TOKEN:-}" ]]; then
    echo "   NOTE: not removing ${marker_path} — this process holds no acquisition token (marker_acquire was never called, or this marker was already released)" >&2
    return 1
  fi

  if ! marker_sync_lock "$marker_path"; then
    echo "   NOTE: could not obtain the synchronization lock to release ${marker_path}" >&2
    return 1
  fi

  if [[ ! -e "$owner_file" ]]; then
    echo "   NOTE: not removing ${marker_path} — no owner record exists (already released, or never actually held)" >&2
    marker_sync_unlock
    return 1
  fi

  local recorded_token
  recorded_token="$(grep '^token=' "$owner_file" 2>/dev/null | cut -d= -f2-)"
  if [[ "$recorded_token" != "$MARKER_TOKEN" ]]; then
    echo "   NOTE: not removing ${marker_path} — its recorded token does not match this process's own acquisition token; ownership has moved on since this process last held it" >&2
    marker_sync_unlock
    return 1
  fi

  rm -f "$marker_path"
  rm -f "$owner_file"
  unset MARKER_TOKEN
  marker_sync_unlock
  return 0
}

# Read-only: true (rc 0) iff the marker is CURRENTLY held/present. This is
# a plain, non-locking existence check on the marker file itself (the same
# file mica-service.ts's poller and a human operator both read) — not the
# exclusivity gate (that is `marker_acquire`'s own flock+token protocol).
# AMENDMENT 10: no longer also checks the lock directory's existence — that
# directory is now PERMANENT once ever created (see above), so its mere
# presence would no longer mean "held."
marker_present() {
  local marker_path="$1"
  [[ -e "$marker_path" ]]
}

# ── wait_for_live_status ─ poll until the service actually serves, or until
#    a deadline. NEVER a bare `sleep`. ─────────────────────────────
#
# S136 (2026-09-20, ruled by the arbiter at the terminal: "salvatorische Klausel
# wirksam"). relay-bridge.sh had THREE probe sites — rollback verification,
# declaration-only relay, code relay — and every one of them read `sleep 1`
# followed by a SINGLE read_live_status. On this box a cold `ts-node` start
# of mica-service.ts takes 11.7–14.3 s wall (measured three times against the
# laid release under /usr/bin/node v18.19.1), so that one probe fired at
# t+1s against a service that had not yet bound a socket. The code-relay
# site rolled back a healthy deployment twice on exactly this, at F-4.
#
# `sleep` is not a readiness check. It encodes a guess about TIMING as if it
# were a fact about STATE — the same error class this script refuses
# everywhere else, sitting unnoticed in its own control flow.
#
# The rollback site carried the identical defect and was the most dangerous
# of the three: a rollback that cannot verify itself ESCALATES TO
# UNPUBLISHING, so one second of sleep could have converted a recoverable
# swap into an outage.
#
# Strictly better than what it replaces, in BOTH directions:
#
#   SLOWER when the unit is alive but not yet answering — it waits, instead
#   of reporting a failure that has not happened.
#
#   FASTER when the unit is genuinely dead — the `is-active` check has NOT
#   been dropped. It moved INSIDE the loop, where it runs every second and
#   aborts the moment the unit leaves play, rather than firing once at the
#   single instant least likely to be informative.
#
# On timeout it replays the LAST attempt's own diagnostics, so the failure
# stays exactly as loud and as specific as it was before.
#
# TWO LATE-BOUND DEPENDENCIES, both deliberate and both the same mechanism
# relay-lib.sh already uses for `systemctl`: this function calls
# `read_live_status` and `systemctl` BY BARE NAME. read_live_status is
# defined in relay-bridge.sh, which sources this file; relay-lib.test.sh
# defines its own and shadows `systemctl` on PATH. So the tests exercise
# THIS function, not a mirror of it — the point of AMENDMENT 10.
#
# MICA_BRIDGE_RELAY_READY_TIMEOUT overrides the deadline. Tests only.
wait_for_live_status() {
  local decl_path="$1"
  local hash_out_file="$2"
  local sha_out_file="$3"
  local timeout="${MICA_BRIDGE_RELAY_READY_TIMEOUT:-90}"

  local err_file
  if ! err_file="$(mktemp)"; then
    echo "   could not create a temp file for readiness diagnostics" >&2
    return 1
  fi

  local waited=0
  local rc=0
  local state=""
  local result=1

  while :; do
    rc=0
    read_live_status "$decl_path" "$hash_out_file" "$sha_out_file" 2>"$err_file" || rc=$?
    if [[ "$rc" -eq 0 ]]; then
      if [[ "$waited" -gt 0 ]]; then
        echo "   /status answered after ${waited}s"
      fi
      result=0
      break
    fi

    # A unit that has DIED is a different outcome from a unit that is merely
    # SLOW, and it is knowable right now — so do not wait out the deadline
    # for it. `systemctl is-active` exits non-zero for every state that is
    # not exactly "active"; the STATE STRING on stdout is what is wanted
    # here, so the exit code is discarded while the string is read. This is
    # NOT a `|| true` on a gate — the gate is the `case` below, and it is
    # evaluated on the string.
    state="$(systemctl is-active mica-bridge 2>/dev/null || :)"
    case "$state" in
      active|activating|reloading|refreshing)
        : # still in play; keep waiting
        ;;
      *)
        echo "   mica-bridge.service is \"${state:-unknown}\" after ${waited}s, not active — not waiting out the readiness deadline" >&2
        cat "$err_file" >&2
        break
        ;;
    esac

    if [[ "$waited" -ge "$timeout" ]]; then
      echo "   /status did not answer within ${timeout}s, with the unit in play throughout; the last attempt reported:" >&2
      cat "$err_file" >&2
      break
    fi

    sleep 1
    waited=$((waited + 1))
  done

  rm -f "$err_file"
  return "$result"
}
