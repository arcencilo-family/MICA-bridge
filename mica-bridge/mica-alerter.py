#!/usr/bin/env python3
"""
mica-alerter.py — polls mica-bridge's event book and status census over its
Unix socket and posts Telegram alerts on real events. Census and events
only — never periodic, never "all fine". No health vocabulary anywhere.

Pattern mirrored from memu-bridge/ilas-alerter.py (Q-Alert); adapted for a
Unix-socket transport, a persisted cursor, a rate limit, and a second
poll target (`/status.relay.markerPresent`).

Event kinds handled, read at bytes this build (mica-service.ts, base
c2b8bb3 = Stage 2 Amendment 7):
  - DECLARATION_REJECTED — the ONLY kind this bridge actually appends to its
    event book today. `recordRejection()` (mica-service.ts:647-660) is the
    sole call site that writes to `eventBook`; every other kind named in the
    dispatch brief (DISPOSITION_CHANGED, PASS_BLIND_NOTICE, HELD) has NO
    producer in this checkout because `/guard` is still bound to
    `NotBoundGuardAdapter` (mica-service.ts:538; guard-adapter.ts:52-65) —
    it always answers 503 GUARD_NOT_BOUND and never appends a decision to
    the event book. Those three kinds are therefore handled by the generic
    fallback below (verbatim report), not a bespoke branch, since inventing
    their field shape ahead of a real producer would be exactly the
    speculative move this build is told not to make.
  - LATCHED / LATCH_CLEARED — per the brief's 2026-09-19 amendment, NO
    producer exists anywhere in either tree. Left as an explicit,
    unreachable, commented branch below so a later amendment has a named
    home instead of inventing behaviour now.
  - anything else — reported verbatim using the event book's own common
    record shape `{seq, ts, kind, subject, identity, disposition, detail,
    decisionHash}` (mica-service.ts:650-659 is the literal object built for
    DECLARATION_REJECTED; every field in it is real, not invented).

Required environment (no defaults — absent means refuse to start, naming
the variable):
  MICA_BRIDGE_SOCKET        - path to this alerter's own peer socket
                               (per-caller UDS, ruling K(b); e.g.
                               /run/mica-bridge/peers/981/guard.sock)
  MICA_ALERTER_POLL_SECONDS - poll interval, seconds (float > 0)
  MICA_ALERTER_STATE_DIR    - directory holding alerter-cursor.json
                               (StateDirectory=mica-alerter supplies this)
  MICA_ALERTER_MAX_PER_MINUTE - notice.maxPerMinute, read as an env var
                               (this alerter's choice — see brief §"Rate
                               limit"; declarations.config.json's own
                               notice.maxPerMinute.value is 6 today, and the
                               deployer is responsible for keeping the two
                               in sync)
  MICA_TG_TOKEN              - Telegram bot token (EnvironmentFile only;
                               never logged, never printed, redacted from
                               every error) — required unless a stdout
                               transport is selected
  MICA_TG_CHAT_ID            - Telegram chat id — required unless a stdout
                               transport is selected

Transport selection: `--dry-run` on the command line, or
`MICA_ALERTER_TRANSPORT=stdout`, prints what would be sent instead of
calling Telegram, and MICA_TG_TOKEN / MICA_TG_CHAT_ID are not required in
that mode.

Delivery contract — AT-LEAST-ONCE, NEVER AT-MOST-ONCE (Amendment 1, verifier
finding 3). A successful `send_fn(message)` call happens BEFORE the cursor
is persisted to disk. If this process is killed (SIGKILL, power loss, OOM)
after Telegram (or the fake receiver in tests) has accepted a message but
before `save_cursor()` runs, the same event — or the same relay-marker
transition — is sent again on restart. This window is real and is not
closed by persisting after every single send (which this code does): the
gap between "the remote side durably has it" and "we durably know that" is
exactly the gap `relay-bridge.sh`'s own header names for its rollback trap,
and it is not obtainable here for the same reason — Telegram gives no
receiver-side idempotency key this alerter can use to de-duplicate itself
out of the window. The deliberate choice: never lose an alert, accept that
one may occasionally repeat. Every event message carries the event's own
`seq` (e.g. "seq 5"); every relay-marker message carries a `transition` id —
a human seeing the same seq or the same transition id twice knows it is a
repeat of one incident, not a second one.

Transition identity (Amendment 3, verifier finding 4 — supersedes the
Amendment 1 description above, which hashed only the marker's own (path,
detail) and so gave two SEPARATE false→true edges with identical content
the SAME id). The `transition` id is now `{counter:04d}-{fingerprint}`:
`counter` is `markerTransitionSeq`, a monotonically increasing integer
persisted in the cursor, incremented once per NEWLY DETECTED false→true
edge and committed to disk in the same save as `relayMarkerLastPresent` —
so a crash-and-retry resend of one edge reuses the same counter (same id),
while a later, genuinely separate edge — even with byte-identical marker
path and detail — gets the next integer (a different id). `fingerprint` is
the old content hash, kept only so a human can eyeball "does this look like
the same underlying failure" — it plays no role in the identity itself.
See `relay_marker_transition_id()`.

Cursor-corruption policy (Amendment 1, verifier finding 1; Amendment 2,
verifier gaps 1-2; Amendment 3 extends it to `markerTransitionSeq`). A persisted
cursor that is not valid JSON, not an object, or whose `afterSeq` /
`relayMarkerLastPresent` fields are the wrong type or out of range is NEVER
used as-is — `load_cursor()` logs loudly, by name, exactly what was wrong,
and falls back to the fresh-cursor rule (as if no cursor existed). A cursor
that is well-typed but implausible relative to the bridge's own state (an
`afterSeq` higher than the bridge has ever issued — whether from a
corrupted file or from the bridge's own event sequence having been reset,
e.g. by a restart) cannot be caught by type-checking the file alone;
`poll_once()` catches it live, by comparing `afterSeq` against the bridge's
own reported `lastSeq` on every poll, and re-primes the same way. Either
path is logged loudly before it happens — never a silent skip.
"""
from __future__ import annotations

import collections
import hashlib
import http.client
import json
import math
import queue
import threading
import os
import socket
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

import requests

TELEGRAM_BASE_URL = "https://api.telegram.org"

# Amendment 1, verifier finding 6: the deploy template ships a placeholder
# so an un-edited unit fails loudly rather than silently doing nothing.
# "Present but never a real chat id" is refused the same way "absent" is —
# named, at startup — never left to surface later as a 400 nobody reads.
PLACEHOLDER_CHAT_IDS = {"CHANGEME"}


class ConfigError(Exception):
    """A required environment variable was absent. Refuse to start."""


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ConfigError(f"{name} is not set — refusing to start")
    return value


def require_env_float(name: str) -> float:
    raw = require_env(name)
    try:
        value = float(raw)
    except ValueError:
        raise ConfigError(f"{name}={raw!r} is not a number — refusing to start")
    if value <= 0:
        raise ConfigError(f"{name}={raw!r} must be > 0 — refusing to start")
    # ⛔ FINITE AND BOUNDED, AND BEFORE THIS IT WAS NEITHER. Codex,
    #   alerter-heartbeat-2 read, finding 2: MICA_ALERTER_POLL_SECONDS=1e308 with a
    #   LEGAL cadence of 1_000_000 exited 1 with
    #   "OverflowError: cannot convert float infinity to integer" at
    #   `round(hb_every * poll_seconds)`, before the first poll.
    #
    #   I had bounded ONE FACTOR of that product and called the result safe. The
    #   first repair's own comment said "hb_every is bounded above, so this cannot
    #   overflow". It could: the other factor was unbounded. Bounding one input of
    #   an arithmetic expression and declaring the expression safe is the same error
    #   as the one it was repairing.
    if not math.isfinite(value):
        raise ConfigError(f"{name}={raw!r} is not finite - refusing to start")
    if value > ENV_FLOAT_MAX:
        raise ConfigError(
            f"{name}={raw!r} exceeds {ENV_FLOAT_MAX} - refusing to start. A poll "
            "interval beyond this is not an interval, and an unbounded one made the "
            "startup estimate overflow."
        )
    return value


def require_env_int(name: str) -> int:
    raw = require_env(name)
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name}={raw!r} is not an integer — refusing to start")
    if value <= 0:
        raise ConfigError(f"{name}={raw!r} must be > 0 — refusing to start")
    return value


def ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(message: str) -> None:
    print(f"{ts()} {message}", flush=True)


def redact(text: str, secret: Optional[str]) -> str:
    """Strip a secret out of any string before it is logged or returned."""
    if not secret:
        return text
    return text.replace(secret, "***REDACTED***")


# ── HTTP-over-Unix-socket transport (stdlib only) ───────────────────────────


class UnixSocketHTTPConnection(http.client.HTTPConnection):
    """`http.client.HTTPConnection` pointed at a Unix socket path instead of
    a TCP host:port. `connect()` is the only method that needs overriding —
    everything else (request framing, response parsing) is stock stdlib."""

    def __init__(self, socket_path: str, timeout: float = 5.0):
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
        self.sock = sock


def http_get_json(socket_path: str, path: str, timeout: float = 5.0) -> dict:
    conn = UnixSocketHTTPConnection(socket_path, timeout=timeout)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        if resp.status != 200:
            raise RuntimeError(f"{path} -> HTTP {resp.status}: {body[:200]!r}")
        return json.loads(body)
    finally:
        conn.close()


# ── transports for outgoing alerts ──────────────────────────────────────────


def send_stdout(message: str) -> bool:
    print(f"[mica-alerter] DRY-RUN would send:\n{message}\n", flush=True)
    return True


def send_telegram(
    token: str,
    chat_id: str,
    message: str,
    base_url: str = TELEGRAM_BASE_URL,
    timeout: float = 10.0,
    post_fn: Optional[Callable[..., "requests.Response"]] = None,
) -> bool:
    """`post_fn` defaults to `requests.post` but is injectable (Amendment 1,
    verifier finding 5) so a test can exercise a send failure — and the
    redaction it must trigger — with an injected fake that raises, instead
    of a real (even if loopback, even if refused) TCP attempt.

    Amendment 3, verifier finding 5: `except Exception` does NOT catch
    `KeyboardInterrupt`, `SystemExit`, `GeneratorExit`, or any other direct
    `BaseException` subclass. If the poster raises one of those and its
    message embeds this token-bearing `url`, Python's default
    uncaught-exception printer would write it to stderr, unredacted, the
    moment it escapes this function uncaught — the `except Exception` clause
    below simply never sees it. These ARE real control-flow signals (Ctrl-C,
    `sys.exit()`) and MUST keep propagating — turning them into an ordinary
    `return False` here would be its own bug, silently eating a shutdown
    request. So the second `except` clause below never swallows them: it
    redacts the message, logs that redacted form, and re-raises — same
    exception type where construction allows it, `from None` so the
    original (potentially unredacted) exception object is dropped from the
    chain Python would otherwise print alongside it."""
    poster = post_fn if post_fn is not None else requests.post
    url = f"{base_url}/bot{token}/sendMessage"
    try:
        r = poster(url, json={"chat_id": chat_id, "text": message}, timeout=timeout)
        r.raise_for_status()
        return True
    except Exception as e:  # noqa: BLE001 - a failed send must never crash the loop
        # `e` may echo the request URL, which contains the token — redact
        # before this ever reaches a log line.
        log(redact(f"[mica-alerter] telegram send failed: {e}", token))
        return False
    except BaseException as e:  # noqa: BLE001 - see the docstring above
        redacted_message = redact(str(e), token)
        log(f"[mica-alerter] telegram send interrupted by {type(e).__name__}: {redacted_message}")
        try:
            sanitized: BaseException = type(e)(redacted_message)
        except Exception:  # noqa: BLE001 - an exotic constructor; fall back rather than risk the raw message
            sanitized = RuntimeError(redacted_message)
        raise sanitized from None


def build_send_fn(use_stdout: bool, token: Optional[str], chat_id: Optional[str]) -> Callable[[str], bool]:
    if use_stdout:
        return send_stdout
    return lambda message: send_telegram(token, chat_id, message)


# ── rate limiting — sliding 60s window; delay, never drop ──────────────────


class RateLimiter:
    def __init__(self, max_per_minute: int, now_fn: Callable[[], float] = time.monotonic):
        self.max_per_minute = max_per_minute
        self._now = now_fn
        self._sent: "collections.deque[float]" = collections.deque()

    def _evict(self) -> None:
        cutoff = self._now() - 60.0
        while self._sent and self._sent[0] < cutoff:
            self._sent.popleft()

    def allow(self) -> bool:
        self._evict()
        return len(self._sent) < self.max_per_minute

    def record(self) -> None:
        self._sent.append(self._now())


# ── liveness — because 968 successful polls and a dead process looked alike ──
#
# ⛔ THE DEFECT THIS FIXES WAS FOUND BY BEING UNABLE TO ANSWER A QUESTION ABOUT
#    IT. Board slate 2026-10-02 (n2) asked whether the back-off was "stuck since
#    10:49Z". The journal showed `rate limit reached; delaying seq 678 and later`
#    at 10:48:59Z and again at 10:49:29Z — and then NOTHING for eight hours.
#
#    It was NOT stuck, and the proof is in the logging rather than the limiter:
#    RateLimiter is a sliding 60s window that evicts, so it cannot wedge, and a
#    back-off that really was stuck would have logged that same line on EVERY
#    30-second poll — roughly 968 of them. It logged twice and stopped, which
#    means the window drained and the queue was sent.
#
# ⛔ BUT NOTHING IN THE JOURNAL SAID SO, AND THAT IS THE REAL DEFECT. No success
#    path logs. So 968 healthy polls and a crashed process produce the IDENTICAL
#    record: silence. The only reason the question could be answered at all was
#    the cursor file's mtime, which is a side effect of writing state and not a
#    signal anyone designed. A signal that cannot distinguish "working" from
#    "dead" is the shape this house keeps paying for.
#
# ⚠ AND IT STAYS QUIET ON PURPOSE. A line per poll would be 2880 a day and would
#   bury the lines that matter; the heartbeat says the things that DISTINGUISH
#   alive-and-idle from wedged — where the cursor stands, how long since anything
#   moved, and how full the rate-limit window is — and says them rarely.
# ⛔ THE HEARTBEAT IS OFF UNLESS ASKED FOR, by ruling (board 2026-10-03 08:07Z,
#   The arbiter's concern, shared): the delivery fixes and the overflow guard ship NOW so
#   notifications return, and the heartbeat — whose own correctness took four Codex
#   rounds — ships inert. ONE env var is the flag: MICA_ALERTER_HEARTBEAT_POLLS.
#   Unset, 0, or unusable => disabled, and the startup line says which.
#
#   AN UNUSABLE OPT-IN IS NOT AN OPT-IN. Before this a bad value defaulted to 60,
#   i.e. ON — which under an off-by-default rule would turn a typo into an enabled
#   feature. Every rejected value now DISABLES and is named.
HEARTBEAT_POLLS_DEFAULT = 0
# The largest cadence that is a cadence rather than a typo. At the 30s default poll
# that is ~347 days, so nothing legitimate is refused — the bound exists because an
# unbounded value crashed startup (Codex F1), not to express a preference.
HEARTBEAT_POLLS_MAX = 1_000_000
# The largest float any numeric env var may carry. One year in seconds is ~3.15e7,
# so this admits every operational value and refuses the ones that are not values.
# It exists because `round(hb_every * poll_seconds)` overflowed on 1e308 (Codex,
# heartbeat-2 finding 2) - a bound on ONE factor of a product is not a bound on the
# product.
ENV_FLOAT_MAX = 1e9
# How many heartbeat lines may wait for a blocked sink. Small on purpose: these are
# liveness lines, so a BACKLOG of them is worth less than the count of how many were
# dropped, which rides the next line that gets through.
HEARTBEAT_QUEUE_MAX = 16
"""Every 60th poll. At the deployed 30s interval that is one line per 30 minutes.

NOT a required env like the others in this module: a log cadence is not a
calibration constant — it cannot change a reading, only whether a reader can see
one — and making it required would mean the running unit FAILS TO START the next
time this file is deployed, because its drop-in does not set it. It is overridable
by MICA_ALERTER_HEARTBEAT_POLLS, 0 disables it, and the startup line always states
the cadence actually in force so it is never a mystery which applied.
"""


class HeartbeatSink:
    """A BOUNDED, NON-BLOCKING channel for heartbeat lines.

    ⛔ WHY THIS EXISTS. Codex, alerter-heartbeat-2 finding 1: the heartbeat write
       still sat on the delivery loop's critical path. The previous repair caught a
       sink that RAISES; a sink that BLOCKS does not raise, so neither `except`
       fired. Measured: a sink sleeping 0.45s only on the `alive -` line produced
       `first-to-second-poll-seconds 0.45`. A `try/except` cannot fix a blocking
       write, so the write leaves the loop entirely.

       `put()` NEVER blocks and NEVER raises. It enqueues or it counts a drop. A
       daemon thread does the writing, so a sink that blocks for an hour delays
       nothing but itself.

    ⛔ AND NOTHING HERE EVER WRITES ON THE CALLER'S THREAD. Codex FAILED the first
       version of this class for exactly that: `put()` returned False on a full
       queue or a dead drain and the caller then wrote inline, so the two worst
       cases took the path the class exists to remove. A dead drain is now
       REPAIRED -- `_revive()` starts a new thread, which does not block -- and a
       refused beat is dropped and COUNTED, with the count carried by the next
       beat that gets through. A shortfall is visible in the journal instead of
       being inferred from gaps, and it is visible without anything blocking.

    ⚠ WHAT IT DOES NOT BUY, stated: queued lines are lost if the process exits,
      because the thread is a daemon. For telemetry that is the right trade -- a
      non-daemon thread would make a blocked sink prevent SHUTDOWN, which is the
      same defect wearing a different hat.
    """

    def __init__(self, write: "Callable[[str], None]", maxsize: int = HEARTBEAT_QUEUE_MAX) -> None:
        self._write = write
        self._q: "queue.Queue[str]" = queue.Queue(maxsize=maxsize)
        self._dropped = 0
        self._revivals = 0
        self._thread = threading.Thread(
            target=self._drain, name="mica-alerter-heartbeat", daemon=True
        )
        self._thread.start()

    def _drain(self) -> None:
        while True:
            line = self._q.get()
            try:
                self._write(line)
            except Exception:  # noqa: BLE001 - the sink is what fails; the drain stays alive
                pass

    def alive(self) -> bool:
        return self._thread.is_alive()

    def dropped(self) -> int:
        return self._dropped

    def _revive(self) -> None:
        """Start a new drain thread. Never blocks, never raises.

        ⛔ WHY A DEAD DRAIN IS REPAIRED RATHER THAN REPORTED. The rule is that a
           refused beat is dropped and counted and THE NEXT BEAT CARRIES THE COUNT.
           With a dead drain no beat ever gets through, so the count would
           accumulate forever and be carried by nothing -- permanent silence with
           an invisible counter, which is the defect the heartbeat exists to
           prevent. Starting a thread does not block, so the repair is legal under
           the rule where an inline write is not.

           If the start itself fails, this is still only a drop and a count: the
           loop is not told and nothing is written here.
        """
        try:
            self._thread = threading.Thread(
                target=self._drain, name="mica-alerter-heartbeat", daemon=True
            )
            self._thread.start()
            self._revivals += 1
        except Exception:  # noqa: BLE001 - a failed revival is a drop, not an exception
            pass

    def put(self, line: str) -> bool:
        """Hand off a line.

        NEVER blocks. NEVER raises. NEVER writes. Returns False when the beat was
        dropped, which the caller is expected to ignore -- the count is carried by
        the next beat that gets through.
        """
        if not self._thread.is_alive():
            self._dropped += 1
            self._revive()
            return False
        carried = line if self._dropped == 0 else f"{line} {self._carry()}"
        try:
            self._q.put_nowait(carried)
        except queue.Full:
            self._dropped += 1
            return False
        self._dropped = 0
        return True

    def _carry(self) -> str:
        """The note a surviving beat carries about the ones that did not."""
        revived = f", drain revived {self._revivals}x" if self._revivals else ""
        return f"[{self._dropped} heartbeat line(s) dropped before this one{revived}]"


class HeartbeatTicker:
    """Counts polls and decides when liveness should be stated out loud.

    Separated from the poll loop so it can be tested: the loop itself is
    `while True`, and logic that can only be exercised by an infinite loop is
    logic nobody checks.
    """

    def __init__(self, every: int, now_fn: Callable[[], float] = time.monotonic):
        self.every = every
        self._now = now_fn
        self.polls = 0
        self.polls_since_change = 0
        self._last_change_at = now_fn()

    def note_poll(self, changed: bool) -> None:
        self.polls += 1
        if changed:
            self.polls_since_change = 0
            self._last_change_at = self._now()
        else:
            self.polls_since_change += 1

    def due(self) -> bool:
        if self.every <= 0:
            return False
        return self.polls > 0 and self.polls % self.every == 0

    def line(self, cursor: dict, rate_limiter: "RateLimiter") -> str:
        after = cursor.get("afterSeq")
        quiet_for = self._now() - self._last_change_at
        # ⚠ reads the limiter's depth THROUGH its own eviction, so the number is
        #   what `allow()` would see and not a stale count.
        rate_limiter._evict()  # noqa: SLF001 - deliberate: the honest depth
        # ⛔ THE TAIL IS CHOSEN FROM STATE. Codex, alerter-heartbeat read, F3: it
        #   was the fixed sentence "Nothing needed saying", printed unconditionally
        #   — so a line reporting `0 poll(s) since anything changed` ALSO claimed
        #   nothing needed saying, and the same line could follow a poll that sent
        #   an alert. A caption that contradicts the numbers beside it is this
        #   project's own most-repeated defect; here it was in the one line whose
        #   whole job is to be believed.
        # ⛔ THE FALSE BRANCH NO LONGER CLAIMS IDLENESS IT CANNOT SEE. Codex,
        #   alerter-heartbeat-2 read, finding 3: `changed` is the PERSISTED-CURSOR
        #   bit only. A send that FAILED and a send the limiter REFUSED both break
        #   without setting it, so `note_poll(False)` - and therefore the word
        #   "Idle" - could describe a poll with a pending alert. The number beside
        #   it is accurate for cursor state; the adjective was not.
        #
        #   The tail now says exactly what the bit means and nothing more. If
        #   delivery-idleness is ever wanted it needs its own bit, which this does
        #   not invent. [owed]
        tail = (
            "The cursor just moved, so this is liveness AND persisted progress."
            if self.polls_since_change == 0
            else "No cursor movement since the last heartbeat - alive, which is all "
            "this line claims. A pending or refused send does not move the cursor."
        )
        return (
            f"[mica-alerter] alive — {self.polls} poll(s); cursor afterSeq="
            f"{'none' if after is None else after}; "
            f"{self.polls_since_change} poll(s) since anything changed "
            f"({quiet_for:.0f}s); rate-limit window {len(rate_limiter._sent)}/"
            f"{rate_limiter.max_per_minute}. {tail}"
        )


# ── cursor persistence ──────────────────────────────────────────────────────


def load_cursor(path: Path, log_fn: Callable[[str], None] = log) -> dict:
    """Load the persisted cursor. A cursor this alerter cannot justify is
    NEVER used silently (Amendment 1, verifier finding 1; Amendment 2,
    verifier gap 1): malformed JSON, a non-object, a MISSING key that has
    existed since the first version (a file that exists but was not written
    by this program's own save_cursor(), which always writes both `afterSeq`
    and `relayMarkerLastPresent`), or either of those two fields being the
    wrong type or out of range is logged loudly, by name, and treated as if
    no cursor existed — the fresh-cursor rule then re-primes from the
    bridge's real tail on the next poll, rather than silently skipping
    whatever the bad value would have hidden. A cursor file that legitimately
    does not exist at all is NOT logged — that is the ordinary first-start
    case, not corruption. `markerTransitionSeq` (Amendment 3, verifier
    finding 4) is versioned separately: it is a NEWER field, so a MISSING
    `markerTransitionSeq` is a legitimate upgrade from an older cursor file
    and defaults to 0 silently; only a present-but-wrong-typed value is
    logged. A well-typed, in-range but IMPLAUSIBLE afterSeq (higher than the
    bridge has ever issued, or naming a seq that was never actually issued)
    cannot be caught here — it needs a live bridge to compare against — so
    `poll_once()` catches both cases separately (Amendment 1 finding 1's
    "beyond lastSeq" check, and Amendment 2 gap 2's "no event with that
    exact seq" check)."""
    if not path.exists():
        return {
            "afterSeq": None,
            "relayMarkerLastPresent": False,
            "markerTransitionSeq": 0,
            # A fresh cursor holds no run. Every fresh-cursor path returns
            # this same shape, so a coalescer can never meet a cursor that
            # lacks the key it reads.
            "pendingRun": None,
        }

    try:
        raw = json.loads(path.read_text())
    except Exception as e:  # noqa: BLE001 - any parse failure, not just JSONDecodeError
        log_fn(
            f"[mica-alerter] cursor at {path} is not valid JSON ({e}); refusing "
            "to trust it — falling back to the fresh-cursor rule."
        )
        return {
            "afterSeq": None,
            "relayMarkerLastPresent": False,
            "markerTransitionSeq": 0,
            # A fresh cursor holds no run. Every fresh-cursor path returns
            # this same shape, so a coalescer can never meet a cursor that
            # lacks the key it reads.
            "pendingRun": None,
        }

    if not isinstance(raw, dict):
        log_fn(
            f"[mica-alerter] cursor at {path} is valid JSON but not an object "
            f"({raw!r}); refusing to trust it — falling back to the fresh-cursor rule."
        )
        return {
            "afterSeq": None,
            "relayMarkerLastPresent": False,
            "markerTransitionSeq": 0,
            # A fresh cursor holds no run. Every fresh-cursor path returns
            # this same shape, so a coalescer can never meet a cursor that
            # lacks the key it reads.
            "pendingRun": None,
        }

    # Amendment 2, verifier gap 1: a cursor file that EXISTS but is missing
    # a key entirely is a DIFFERENT case from no file existing at all — this
    # program's own save_cursor() always writes both keys (afterSeq may be
    # an explicit `null` mid-priming, but the key itself is always present).
    # A present file missing a key was written by something else, or lost
    # bytes, and is UNKNOWN under the ruling: refuse loudly, or fall back
    # and say which — never accept it in silence the way a merely-absent
    # file legitimately is.
    problems = []
    if "afterSeq" not in raw:
        problems.append("afterSeq key is missing")
        after_seq = None
    else:
        after_seq = raw["afterSeq"]
        if after_seq is not None:
            # bool is a subclass of int in Python — must be excluded
            # explicitly, or {"afterSeq": true} would silently become
            # afterSeq=1.
            if isinstance(after_seq, bool) or not isinstance(after_seq, int) or after_seq < 0:
                problems.append(f"afterSeq={after_seq!r} is not a non-negative integer")
                after_seq = None

    if "relayMarkerLastPresent" not in raw:
        problems.append("relayMarkerLastPresent key is missing")
        marker = False
    else:
        marker = raw["relayMarkerLastPresent"]
        if not isinstance(marker, bool):
            problems.append(f"relayMarkerLastPresent={marker!r} is not a boolean")
            marker = False

    # markerTransitionSeq (Amendment 3, verifier finding 4) is treated
    # DIFFERENTLY from the two fields above: it did not exist before this
    # amendment, so a cursor file written by an earlier version of this
    # program legitimately lacks it — that is a version upgrade, not
    # corruption, and must not be logged as one. Only a PRESENT but
    # wrong-typed value is a real problem.
    transition_seq_raw = raw.get("markerTransitionSeq", 0)
    if isinstance(transition_seq_raw, bool) or not isinstance(transition_seq_raw, int) or transition_seq_raw < 0:
        problems.append(f"markerTransitionSeq={transition_seq_raw!r} is not a non-negative integer")
        transition_seq = 0
    else:
        transition_seq = transition_seq_raw

    if problems:
        log_fn(
            f"[mica-alerter] cursor at {path} is valid JSON but semantically invalid "
            f"({'; '.join(problems)}); refusing to trust it — falling back to the "
            "fresh-cursor rule rather than silently skip whatever it would have hidden."
        )

    # `pendingRun` is NEWER STILL, and follows markerTransitionSeq's rule
    # exactly: MISSING is a legitimate upgrade from an older cursor and defaults
    # to None silently; PRESENT-but-malformed is a real problem and is dropped
    # LOUDLY. ⚠ Dropping it loses a count, never an event — every member of the
    # run is already in the bridge's own log, and `afterSeq` still says which
    # ones were consumed.
    run_raw = raw.get("pendingRun", None)
    pending_run = None
    if run_raw is not None:
        ok = (
            isinstance(run_raw, dict)
            and isinstance(run_raw.get("key"), str)
            and isinstance(run_raw.get("count"), int)
            and not isinstance(run_raw.get("count"), bool)
            and run_raw.get("count", 0) > 0
            and isinstance(run_raw.get("firstSeq"), int)
            and isinstance(run_raw.get("lastSeq"), int)
            and isinstance(run_raw.get("startedAt"), (int, float))
        )
        if ok:
            pending_run = run_raw
        else:
            log_fn(
                f"[mica-alerter] cursor at {path} has a malformed pendingRun "
                f"({run_raw!r}); dropping the held repeat-count. No event is lost — "
                "every one is in the bridge's event log and afterSeq is unaffected — "
                "but the count of one run will not be reported."
            )

    return {
        "afterSeq": after_seq,
        "relayMarkerLastPresent": marker,
        "markerTransitionSeq": transition_seq,
        "pendingRun": pending_run,
    }


def save_cursor(path: Path, cursor: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(cursor))
    tmp.replace(path)


# ── message formatting ──────────────────────────────────────────────────────


# ── CONSECUTIVE-RUN COALESCING ───────────────────────────────────────────────
#
# ⛔ WHY, AND IT IS A MEASURED INCIDENT NOT A TIDINESS WISH. Route #10, 2026-09-28:
#    op3 alarmed SEVEN TIMES on a coordinate that had quietly stopped describing
#    its record. Seven messages, one incident, and the seventh told an operator
#    nothing the first had not. The failure mode of a noisy alerter is not noise
#    — it is that the reader stops reading it, and a real alert then arrives in a
#    stream nobody looks at any more.
#
# ⛔ THE ONE RULE THAT MAKES THIS SAFE: THE FIRST OF A RUN IS ALWAYS SENT
#    IMMEDIATELY AND UNCHANGED. Coalescing can only ever suppress the SECOND and
#    later members of an identical run, so no incident's first notice is delayed
#    by even one poll.
#
# ⚠ NO SUPPRESSED EVENT IS LOST. The pending run lives in the CURSOR, persisted
#   exactly as `afterSeq` is, so a restart mid-run flushes what it held.
#
# ⚠ A RUN CANNOT GO SILENT FOREVER. It flushes when the key CHANGES, at MAX_RUN,
#   or after MAX_RUN_SECONDS. A coalescer without those bounds is an alerter that
#   stops alerting during exactly the incident it exists for.
MAX_RUN = 25
MAX_RUN_SECONDS = 900.0


def run_key(event: dict) -> str:
    """What makes two consecutive events THE SAME INCIDENT.

    ⛔ EVERYTHING THAT DESCRIBES THE CONDITION, AND NOTHING THAT MERELY COUNTS
       IT. `seq` and `decisionHash` differ on every event by construction, so
       including them would make every run a run of one. Every OTHER field is in
       the key: if the subject, the disposition, or one character of the detail
       changes, IT IS A DIFFERENT INCIDENT and the run breaks.

    ⚠ A key that is too WIDE loses alerts; one that is too NARROW only loses
      compression. Those costs are not symmetric, so this errs NARROW.
    """
    return json.dumps(
        {k: v for k, v in sorted(event.items()) if k not in ("seq", "decisionHash")},
        sort_keys=True,
        default=str,
    )


def format_run_summary(run: dict) -> str:
    """The message a finished run of suppressed repeats produces."""
    n = int(run["count"])
    return (
        f"MICA bridge: the previous alert repeated {n} more time"
        f"{'' if n == 1 else 's'}, identically (seq {run['firstSeq']}..{run['lastSeq']}).\n"
        "Same kind, subject, disposition and detail every time — one condition, "
        f"not {n + 1} incidents. The first was sent when it happened; these were "
        "held so the run would read as one thing.\n"
        "Every suppressed event is still in the bridge's own event log at the "
        "sequence numbers above."
    )


def format_event_message(event: dict) -> str:
    kind = event.get("kind", "UNKNOWN")
    seq = event.get("seq")
    subject = event.get("subject")
    identity = event.get("identity")
    disposition = event.get("disposition")
    detail = event.get("detail")
    decision_hash = event.get("decisionHash")

    if kind == "DECLARATION_REJECTED":
        return (
            f"MICA bridge: declaration reload REJECTED (seq {seq}).\n"
            f"{detail}\n"
            "Last-known-good declaration is still the one in force."
        )

    # ------------------------------------------------------------------
    # LATCHED / LATCH_CLEARED — brief §3 Stage 3 AMENDMENT, 2026-09-19:
    # neither kind has a producer in mica-machine or citadel/mica-bridge as
    # of this build. `SubstrateHistory` is written and never read back;
    # nothing computes or clears a latch, and no caller exists that could.
    # This branch is DEAD CODE TODAY — `event["kind"]` cannot equal either
    # literal while no such producer exists. Kept, unreachable, so the
    # later amendment that adds the read-only history reader (per-factor
    # latch state in GET /status) has a named home here rather than this
    # alerter inventing a shape for it speculatively now.
    # ------------------------------------------------------------------
    if kind == "LATCHED":  # pragma: no cover — no producer exists (see above)
        return (
            f"MICA bridge: LATCHED (seq {seq}) — {detail or '(no detail)'}\n"
            "No live producer for this kind exists yet in this build; "
            "this branch is unreachable today."
        )
    if kind == "LATCH_CLEARED":  # pragma: no cover — no producer exists (see above)
        return (
            f"MICA bridge: LATCH_CLEARED (seq {seq}) — {detail or '(no detail)'}\n"
            "No live producer for this kind exists yet in this build; "
            "this branch is unreachable today."
        )

    # Generic fallback: every other kind, including DISPOSITION_CHANGED,
    # PASS_BLIND_NOTICE and HELD (briefed but not yet produced — see module
    # docstring), and anything genuinely unrecognised. Reported verbatim
    # from the event book's own common fields — never dropped.
    lines = [f"MICA bridge: {kind} (seq {seq})"]
    if subject:
        lines.append(f"subject: {subject}")
    if identity:
        lines.append(f"identity: {identity}")
    if disposition:
        lines.append(f"disposition: {disposition}")
    if detail:
        lines.append(f"detail: {detail}")
    if decision_hash:
        lines.append(f"decisionHash: {decision_hash}")
    return "\n".join(lines)


def relay_marker_content_fingerprint(path: str, detail: Optional[str]) -> str:
    """A short hash of the marker's own (path, detail) — for HUMAN
    DEBUGGING ONLY (e.g. "does this look like the same underlying failure as
    last time"). Amendment 3, verifier finding 4: this is NOT, by itself,
    a transition identity — two textually-identical but SEPARATE incidents
    (marker clears, then reappears with the exact same path and detail)
    hash to the same fingerprint. `relay_marker_transition_id()` is what
    actually distinguishes them; this function is one ingredient of it,
    kept separate and named honestly as a fingerprint, not an id."""
    basis = f"{path}\n{detail or ''}".encode("utf-8")
    return hashlib.sha256(basis).hexdigest()[:12]


def relay_marker_transition_id(path: str, detail: Optional[str], transition_seq: int) -> str:
    """The actual identity of ONE marker transition (Amendment 3, verifier
    finding 4 — replaces the Amendment-1 version, which hashed only
    (path, detail) and so gave two SEPARATE false→true edges with identical
    content the SAME id, contradicting the "same id means same incident"
    claim). `transition_seq` is a monotonically increasing counter, owned
    and persisted by the caller (`poll_once()`, in the cursor's
    `markerTransitionSeq` field) — incremented once per NEWLY DETECTED
    false→true edge, and persisted ONLY once that edge's alert is
    confirmed sent, in the exact same commit as `relayMarkerLastPresent`
    (see `poll_once()`). That is what makes the two guarantees compatible
    at once: a crash-and-retry resend of the SAME edge recomputes and
    reuses the SAME `transition_seq` (because the persisted counter never
    advanced), while a genuinely NEW edge — even with byte-identical path
    and detail — gets the next integer and therefore a different id.
    The content fingerprint is appended only so a human can also eyeball
    "does this look like the same failure" — it plays no role in identity."""
    fingerprint = relay_marker_content_fingerprint(path, detail)
    return f"{transition_seq:04d}-{fingerprint}"


def format_relay_marker_message(relay: dict, transition_seq: int) -> str:
    path = relay.get("path", "?")
    detail = relay.get("detail") or "(no detail provided)"
    transition = relay_marker_transition_id(path, relay.get("detail"), transition_seq)
    return (
        "MICA bridge: relay marker PRESENT — a relay died mid-swap, or one is "
        "in progress right now. The live release selection is UNVERIFIED.\n"
        f"transition: {transition}\n"
        f"marker path: {path}\n"
        f"marker detail: {detail}\n"
        "\n"
        "What to do, if you are not at a terminal:\n"
        "1. Do not restart the mica-bridge unit yet.\n"
        "2. Find whoever last ran relay-bridge.sh and ask if it is still running.\n"
        f"3. When you are at a terminal: cat {path}\n"
        "4. If the process is gone and the marker is stale, someone with sudo\n"
        "   must confirm which release is actually live (systemctl status\n"
        "   mica-bridge, GET /status .release.sha) before touching anything.\n"
        "5. This message repeats only if the marker clears and then reappears —\n"
        "   or if this alerter was killed after sending but before recording\n"
        "   delivery. Under the at-least-once contract, the SAME `transition`\n"
        "   id above means a repeat of THIS incident (the 4-digit prefix is a\n"
        "   counter that only advances for a genuinely new false→true edge);\n"
        "   a DIFFERENT id — even with identical marker path/detail below —\n"
        "   means a separate incident, not a repeat."
    )


# ── one poll cycle ───────────────────────────────────────────────────────────


def _prime_after_seq(socket_path: str, timeout: float, log_fn: Callable[[str], None]) -> Optional[int]:
    """Probe the bridge's own tail and return the `afterSeq` boundary that
    will deliver exactly the latest existing event on the next fetch (or 0
    if the book is empty). Returns None if the probe itself failed (bridge
    down) — the caller leaves `afterSeq` unset and retries next cycle."""
    try:
        probe = http_get_json(socket_path, "/events?after=0&limit=1", timeout)
        last_seq = int(probe.get("lastSeq", 0))
        return max(last_seq - 1, 0)
    except Exception as e:  # noqa: BLE001 - bridge may simply be down
        log_fn(f"[mica-alerter] priming probe failed, will retry: {e}")
        return None


def _reprime_and_refetch(
    socket_path: str, timeout: float, log_fn: Callable[[str], None]
) -> "tuple[Optional[int], list]":
    """Re-run the fresh-cursor rule and immediately re-fetch from the
    corrected boundary, in one step. Used whenever a previously-trusted
    `afterSeq` (loaded from disk, or reached by normal tailing) is found
    mid-poll to be untrustworthy — the same recovery for either reason
    (Amendment 1 finding 1's "beyond the bridge's lastSeq", or Amendment 2
    gap 2's "no event with that exact seq")."""
    new_after_seq = _prime_after_seq(socket_path, timeout, log_fn)
    events: list = []
    if new_after_seq is not None:
        try:
            page = http_get_json(socket_path, f"/events?after={new_after_seq}&limit=100", timeout)
            events = page.get("events", [])
        except Exception as e:  # noqa: BLE001
            log_fn(f"[mica-alerter] events poll failed after re-priming: {e}")
    return new_after_seq, events


def _cursor_seq_exists(socket_path: str, seq: int, timeout: float) -> Optional[bool]:
    """Amendment 2, verifier gap 2: ask the bridge whether an event with
    EXACTLY this seq was ever issued — an in-range `afterSeq` (not caught by
    the "beyond lastSeq" check) can still name a number the book never
    actually assigned (e.g. a hand-tampered value, or a quarantined/skipped
    number). Fetching the first event strictly after `seq - 1` and checking
    its seq equals `seq` answers this with the existing `/events` endpoint —
    no new bridge API needed. Returns None (inconclusive — NOT "false") if
    the bridge could not be reached for this specific check; an unreachable
    bridge must never itself be read as proof of corruption.

    Stated limit, not solved by this function: it identifies THIS bridge
    life's event numbering, not identity across a restart. If the bridge's
    own event sequence was reset (Finding 2, Builder B's tree, not this
    alerter's) and later organically regrows to reuse the same integer for a
    genuinely different event, this check cannot tell the two apart — no
    epoch/generation id exists in the API to distinguish them. That deeper
    problem is out of scope here; this function only catches a seq that was
    never assigned at all in the bridge's current life."""
    try:
        page = http_get_json(socket_path, f"/events?after={seq - 1}&limit=1", timeout)
    except Exception:  # noqa: BLE001 - bridge may simply be down; inconclusive, not false
        return None
    events = page.get("events", [])
    if not events:
        return False
    return int(events[0]["seq"]) == seq


def poll_once(
    socket_path: str,
    cursor: dict,
    rate_limiter: RateLimiter,
    send_fn: Callable[[str], bool],
    cursor_path: Path,
    timeout: float = 5.0,
    log_fn: Callable[[str], None] = log,
    now_fn: Callable[[], float] = time.monotonic,
) -> bool:
    """One iteration: prime the cursor if needed, drain deliverable events
    in order, check the relay marker. Returns True if the cursor changed
    (and was persisted). Never advances the cursor past an event that was
    not actually sent — a rate-limit hit or a send failure stops delivery
    for this cycle and leaves the rest for the next one."""
    changed = False

    # Fresh cursor rule: on first start (no persisted afterSeq), emit the
    # latest existing event ONCE, then tail — never replay the whole book.
    # There is no "neutral" event kind in the book's current shape (every
    # kind actually produced, or briefed, is itself news), so this is
    # simply "skip straight to the last event, then continue from there".
    if cursor["afterSeq"] is None:
        primed = _prime_after_seq(socket_path, timeout, log_fn)
        if primed is not None:
            cursor["afterSeq"] = primed
            changed = True

    events: list = []
    if cursor["afterSeq"] is not None:
        bridge_last_seq: Optional[int] = None
        try:
            page = http_get_json(
                socket_path, f"/events?after={cursor['afterSeq']}&limit=100", timeout
            )
            events = page.get("events", [])
            if "lastSeq" in page:
                bridge_last_seq = int(page["lastSeq"])
        except Exception as e:  # noqa: BLE001 - routine poll failure, not fatal
            log_fn(f"[mica-alerter] events poll failed: {e}")
            events = []

        # A cursor cannot legitimately point past every event the bridge has
        # ever issued, and (separately) an in-range afterSeq can still name a
        # number the book never actually assigned. Either way the cursor is
        # not trustworthy — whether from local corruption (a tampered/
        # hand-edited file) or from the bridge's own event sequence having
        # been reset (e.g. a restart) — and staying at it means silently
        # never delivering some or all events again. Refuse it the same way
        # load_cursor() refuses a structurally invalid file: log loudly,
        # fall back to the fresh-cursor rule, re-fetch from the corrected
        # boundary. Checked in order — "beyond" implies "nonexistent" too,
        # so there is no need to ask the bridge twice.
        if bridge_last_seq is not None and bridge_last_seq < cursor["afterSeq"]:
            log_fn(
                f"[mica-alerter] cursor afterSeq={cursor['afterSeq']} is beyond "
                f"the bridge's own lastSeq={bridge_last_seq} — impossible under "
                "normal operation. Refusing to trust the persisted cursor: "
                "falling back to the fresh-cursor rule instead of staying "
                "silently stuck."
            )
            cursor["afterSeq"], events = _reprime_and_refetch(socket_path, timeout, log_fn)
            changed = True
        elif cursor["afterSeq"] > 0:
            exists = _cursor_seq_exists(socket_path, cursor["afterSeq"], timeout)
            if exists is False:
                log_fn(
                    f"[mica-alerter] cursor afterSeq={cursor['afterSeq']} does "
                    "not correspond to any event this bridge has ever issued "
                    "(no event with that exact seq exists) — refusing to "
                    "trust it: falling back to the fresh-cursor rule instead "
                    "of silently skipping whatever a wrong boundary would hide."
                )
                cursor["afterSeq"], events = _reprime_and_refetch(socket_path, timeout, log_fn)
                changed = True

        for event in sorted(events, key=lambda e: int(e["seq"])):
            seq = int(event["seq"])
            if cursor["afterSeq"] is None or seq <= cursor["afterSeq"]:
                continue

            key = run_key(event)
            run = cursor.get("pendingRun")

            # ── A CONTINUING RUN: count it, send nothing, advance the cursor ──
            # The cursor MUST advance here. If it did not, a restart would
            # re-deliver every suppressed member as a fresh alert, which is the
            # opposite of what this is for. The count rides in the cursor beside
            # it, so the two move together or not at all.
            if run is not None and run["key"] == key and int(run["count"]) < MAX_RUN:
                if now_fn() - float(run["startedAt"]) < MAX_RUN_SECONDS:
                    run["count"] = int(run["count"]) + 1
                    run["lastSeq"] = seq
                    cursor["afterSeq"] = seq
                    changed = True
                    continue

            # ── THE RUN ENDS: flush its summary FIRST, in order ──────────────
            # Before the new event, so a reader sees "…repeated 6 more times"
            # and then the thing that was different, in the order they happened.
            # ⛔ A RUN OF ONE HAS NOTHING TO SUMMARISE, and saying so anyway was
            #    a real defect: the first version flushed unconditionally and
            #    emitted "the previous alert repeated 0 more times" before EVERY
            #    distinct event — turning one message per event into two, in a
            #    change whose entire purpose is fewer. Caught by the existing
            #    suite, which pins one message per distinct event; the events in
            #    that fixture differ in `detail`, so the key correctly told them
            #    apart and the bug was in what I did with the answer.
            if run is not None and int(run["count"]) == 0:
                cursor["pendingRun"] = None
                run = None
            if run is not None:
                if not rate_limiter.allow():
                    log_fn(f"[mica-alerter] rate limit reached; holding the run summary and seq {seq}")
                    break
                if not send_fn(format_run_summary(run)):
                    log_fn("[mica-alerter] send failed for the run summary; will retry next poll")
                    break
                rate_limiter.record()
                cursor["pendingRun"] = None
                run = None
                changed = True

            # ── THE FIRST OF A RUN: ALWAYS SENT, IMMEDIATELY, UNCHANGED ──────
            if not rate_limiter.allow():
                log_fn(f"[mica-alerter] rate limit reached; delaying seq {seq} and later")
                break
            message = format_event_message(event)
            if not send_fn(message):
                log_fn(f"[mica-alerter] send failed for seq {seq}; will retry next poll")
                break
            rate_limiter.record()
            cursor["afterSeq"] = seq
            cursor["pendingRun"] = {
                "key": key,
                "count": 0,
                "firstSeq": seq,
                "lastSeq": seq,
                "startedAt": now_fn(),
            }
            changed = True

    try:
        status = http_get_json(socket_path, "/status", timeout)
    except Exception as e:  # noqa: BLE001 - routine poll failure, not fatal
        log_fn(f"[mica-alerter] status poll failed: {e}")
        status = None

    if status is not None:
        relay = status.get("relay", {}) or {}
        marker_present = bool(relay.get("markerPresent"))
        if marker_present and not cursor["relayMarkerLastPresent"]:
            if rate_limiter.allow():
                # Amendment 3, verifier finding 4: computed fresh every
                # attempt from the last PERSISTED counter, but only ever
                # written into `cursor` (and thus persisted) after a
                # successful send — same discipline as `afterSeq`. A
                # crash-and-retry resend of THIS edge recomputes the same
                # next_transition_seq (the persisted base never moved) and
                # so reuses the same id; a genuinely new edge, later, starts
                # from a base that DID advance and gets a new one.
                next_transition_seq = cursor.get("markerTransitionSeq", 0) + 1
                message = format_relay_marker_message(relay, next_transition_seq)
                if send_fn(message):
                    rate_limiter.record()
                    cursor["relayMarkerLastPresent"] = True
                    cursor["markerTransitionSeq"] = next_transition_seq
                    changed = True
                else:
                    log_fn("[mica-alerter] relay marker alert send failed; will retry next poll")
            else:
                log_fn("[mica-alerter] rate limit reached; relay marker alert delayed")
        elif not marker_present and cursor["relayMarkerLastPresent"]:
            # Silently reset the latch so a future flip can fire again. No
            # "all clear" message — that is health vocabulary, forbidden.
            cursor["relayMarkerLastPresent"] = False
            changed = True

    # ── ⛔ A RUN THAT SIMPLY STOPS MUST STILL REPORT ITSELF ──────────────────
    #
    #   Everything above flushes a run when the NEXT event breaks it. A run whose
    #   condition just ceases has no next event, and without this block its count
    #   would sit in the cursor forever and the operator would never learn that
    #   the alert they saw once had actually fired nine times.
    #
    #   THIS IS THE ARM THAT MAKES COALESCING HONEST rather than merely quieter,
    #   and it is the one I would have forgotten: the happy path is the run that
    #   ends because something else happened, and the silent end is the one that
    #   looks like nothing needing doing.
    run = cursor.get("pendingRun")
    if run is not None and int(run["count"]) > 0:
        stale = now_fn() - float(run["startedAt"]) >= MAX_RUN_SECONDS
        full = int(run["count"]) >= MAX_RUN
        if stale or full:
            if rate_limiter.allow():
                if send_fn(format_run_summary(run)):
                    rate_limiter.record()
                    cursor["pendingRun"] = None
                    changed = True
                else:
                    log_fn("[mica-alerter] run summary send failed; will retry next poll")
            else:
                log_fn("[mica-alerter] rate limit reached; run summary delayed")

    if changed:
        save_cursor(cursor_path, cursor)
    return changed


# ── entry point ──────────────────────────────────────────────────────────


def main(argv: list) -> int:
    dry_run = "--dry-run" in argv
    transport_env = os.environ.get("MICA_ALERTER_TRANSPORT", "")
    use_stdout = dry_run or transport_env == "stdout"

    try:
        socket_path = require_env("MICA_BRIDGE_SOCKET")
        poll_seconds = require_env_float("MICA_ALERTER_POLL_SECONDS")
        state_dir = Path(require_env("MICA_ALERTER_STATE_DIR"))
        max_per_minute = require_env_int("MICA_ALERTER_MAX_PER_MINUTE")
        if use_stdout:
            token, chat_id = None, None
        else:
            token = require_env("MICA_TG_TOKEN")
            chat_id = require_env("MICA_TG_CHAT_ID")
            if chat_id in PLACEHOLDER_CHAT_IDS:
                raise ConfigError(
                    f"MICA_TG_CHAT_ID is still the placeholder value {chat_id!r} "
                    "— refusing to start"
                )
    except ConfigError as e:
        print(f"[mica-alerter] {e}", file=sys.stderr, flush=True)
        return 2

    send_fn = build_send_fn(use_stdout, token, chat_id)
    cursor_path = state_dir / "alerter-cursor.json"
    cursor = load_cursor(cursor_path)
    rate_limiter = RateLimiter(max_per_minute)

    # ⚠ THE CADENCE IS STATED AT STARTUP, including when it is disabled, so a
    #   reader of the journal never has to guess which value was in force for the
    #   silence they are looking at.
    # ⛔ THE CADENCE IS BOUNDED AND NON-NEGATIVE, AND BEFORE THIS IT WAS NEITHER.
    #   Codex, alerter-heartbeat read, F1: the `try` caught only ValueError from
    #   `int()`, and Python integers are unbounded — so
    #   MICA_ALERTER_HEARTBEAT_POLLS=<400 nines> EXITED 1 with
    #   `OverflowError: int too large to convert to float` in `hb_every *
    #   poll_seconds`, BEFORE the first poll. A logging-only knob took the service
    #   down. And `-1` started and silently disabled the heartbeat, although the
    #   documented disabling value is 0.
    #
    #   The claim that was wrong was mine: "a bad value is reported and defaulted
    #   rather than refusing to start — it cannot change a reading." Two values
    #   changed availability. The rule is unchanged in intent and now actually
    #   holds: EVERY unusable value is named and defaulted, and 0 — and only 0 —
    #   disables.
    hb_raw = os.environ.get("MICA_ALERTER_HEARTBEAT_POLLS", "")
    hb_every = HEARTBEAT_POLLS_DEFAULT
    if hb_raw.strip() != "":
        why = None
        try:
            parsed = int(hb_raw)
        except ValueError:
            parsed = None
            why = "is not an integer"
        if parsed is not None:
            if parsed < 0:
                why = f"is negative (use 0 to disable, not {parsed})"
            elif parsed > HEARTBEAT_POLLS_MAX:
                why = f"exceeds the maximum {HEARTBEAT_POLLS_MAX}"
            else:
                hb_every = parsed
        if why is not None:
            log(
                f"[mica-alerter] MICA_ALERTER_HEARTBEAT_POLLS={hb_raw!r} {why}; "
                "so the heartbeat is DISABLED. This is a log cadence, so an unusable value "
                "is named and the feature left off rather than refusing to start — and it is "
                "BOUNDED, because an unbounded value used to crash startup in the seconds "
                "estimate below. Set it to a positive integer to enable the heartbeat."
            )
    ticker = HeartbeatTicker(hb_every)
    # The heartbeat's own channel, so its write is never on the loop. Created even
    # when the cadence is 0: an unused sink costs one idle daemon thread, and
    # branching on the cadence here would give the disabled path a different
    # code shape from the enabled one for no gain.
    hb_sink = HeartbeatSink(log)

    log(
        f"[mica-alerter] started — polling {socket_path} every {poll_seconds}s, "
        f"rate limit {max_per_minute}/min, "
        f"transport={'stdout' if use_stdout else 'telegram'}, "
        + (
            # int arithmetic, rounded without a float conversion: the crash in F1
            # was `hb_every * poll_seconds` widening to float. hb_every is bounded
            # above, so this cannot overflow — but it does not rely on that alone.
            f"heartbeat every {hb_every} poll(s) (~{round(hb_every * poll_seconds)}s)"
            if hb_every > 0
            else "heartbeat DISABLED (default) — silence will not distinguish alive from "
            "dead; set MICA_ALERTER_HEARTBEAT_POLLS to a positive integer to enable it"
        )
    )

    while True:
        changed = poll_once(socket_path, cursor, rate_limiter, send_fn, cursor_path)
        ticker.note_poll(bool(changed))
        if ticker.due():
            # ⛔ THE HEARTBEAT NEVER WRITES ON THIS LOOP. Board rule, 2026-10-03,
            #   after Codex FAILED Heartbeat-3: my own two fallbacks -- a full
            #   queue and a dead drain -- wrote inline, which is the exact thing
            #   the commit claimed to close. I had named both as DELIBERATE
            #   concessions in the brief, and naming a hole is not closing it.
            #
            #   THE RULE, verbatim: on a full queue or a dead drain the beat is
            #   DROPPED and COUNTED, and the next beat carries the count. There is
            #   no third option and no case that writes here.
            #
            #   Building the LINE is still synchronous -- it formats and reads the
            #   limiter's depth -- so it stays inside a boundary. A failure to
            #   build becomes a line about that failure, handed to the same sink.
            try:
                line = ticker.line(cursor, rate_limiter)
            except Exception as exc:  # noqa: BLE001 - the heartbeat must never be the reason
                line = f"[mica-alerter] heartbeat line could not be built ({exc!r}); polling continues"
            # The result is deliberately unused: a refused beat is counted inside
            # the sink and carried by the next one. Branching on it here is how the
            # inline write got in.
            hb_sink.put(line)
        time.sleep(poll_seconds)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
