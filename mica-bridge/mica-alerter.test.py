#!/usr/bin/env python3
"""
mica-alerter.test.py — check()-style tests for mica-alerter.py, matching the
census discipline of mica-service.test.ts / declarations.test.ts: one PASS/
FAIL line per check, a `CENSUS: N passed, M failed, N+M total` line, exit
non-zero on any failure.

Runs a real fake bridge — a stdlib `http.server` over a Unix stream socket,
in a background thread — so mica-alerter.py's real UDS HTTP client is
exercised end to end. No live mica-bridge service, no sudo. Claimed at its
true width (Amendment 4, verifier run 3 finding 2): no DNS resolution, no
outbound connection, no contact with any external host. Importing
`requests`/`urllib3` itself creates one unconnected IPv6 capability-probe
socket at import time — that socket is never connected and nothing is
sent or received on it, but "no network" would overclaim if read as "zero
sockets"; it is not.

Run:
  python3 mica-bridge/mica-alerter.test.py
"""
from __future__ import annotations

import http.server
import importlib.util
import json
import math
import os
import shutil
import socketserver
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

# The module under test is `mica-alerter.py` — a hyphenated filename, so it
# cannot be `import`ed by name. Load it by path instead.
_ALERTER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mica-alerter.py")
_spec = importlib.util.spec_from_file_location("mica_alerter_under_test", _ALERTER_PATH)
alerter = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
assert _spec is not None and _spec.loader is not None
_spec.loader.exec_module(alerter)


# ── fake bridge: a real UDS HTTP server, controllable state ────────────────


class _FakeBridgeHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:  # keep test output quiet
        pass

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        parsed = urlsplit(self.path)
        qs = parse_qs(parsed.query)
        state = self.server.state  # type: ignore[attr-defined]

        if parsed.path == "/events":
            after = int(qs.get("after", ["0"])[0])
            limit = int(qs.get("limit", ["100"])[0])
            events = state["events"]
            filtered = [e for e in events if e["seq"] > after][:limit]
            last_seq = events[-1]["seq"] if events else 0
            body = json.dumps({"events": filtered, "lastSeq": last_seq, "more": False}).encode()
            self._send(200, body)
        elif parsed.path == "/status":
            body = json.dumps({"relay": state["relay"]}).encode()
            self._send(200, body)
        else:
            self._send(404, json.dumps({"error": "UNKNOWN_PATH"}).encode())

    def _send(self, code: int, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _UnixHTTPServer(socketserver.UnixStreamServer):
    allow_reuse_address = True
    daemon_threads = True


class FakeBridge:
    def __init__(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="mica-alerter-test-")
        self.socket_path = os.path.join(self.dir, "guard.sock")
        self.state = {
            "events": [],
            "relay": {"markerPresent": False, "detail": None, "path": "/opt/mica-bridge.relay-in-progress"},
        }
        self.httpd = _UnixHTTPServer(self.socket_path, _FakeBridgeHandler)
        self.httpd.state = self.state  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def add_event(self, kind: str, **fields) -> dict:
        seq = len(self.state["events"]) + 1
        event = {
            "seq": seq,
            "ts": "2026-09-19T00:00:00Z",
            "kind": kind,
            "subject": None,
            "identity": None,
            "disposition": None,
            "detail": None,
            "decisionHash": None,
        }
        event.update(fields)
        self.state["events"].append(event)
        return event

    def set_relay(self, present: bool, detail=None, path="/opt/mica-bridge.relay-in-progress") -> None:
        self.state["relay"] = {"markerPresent": present, "detail": detail, "path": path}


# ── check() harness ─────────────────────────────────────────────────────────

passed = 0
failed = 0


def check(name: str, fn) -> None:
    global passed, failed
    try:
        fn()
        passed += 1
        print(f"PASS  {name}")
    except Exception as e:  # noqa: BLE001
        failed += 1
        print(f"FAIL  {name}")
        print(f"      {e}")


def assert_true(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(f"assertion failed: {msg}")


class RecordingTransport:
    """A fake send_fn that records every message and can be told to fail the
    next N sends (to test the backlog / never-advance-past-unsent rule)."""

    def __init__(self, fail_next: int = 0):
        self.sent: list = []
        self.fail_next = fail_next

    def __call__(self, message: str) -> bool:
        if self.fail_next > 0:
            self.fail_next -= 1
            return False
        self.sent.append(message)
        return True


def fresh_state_dir() -> Path:
    d = Path(tempfile.mkdtemp(prefix="mica-alerter-state-"))
    return d


class FakeClock:
    def __init__(self, start: float = 0.0):
        self.t = start

    def now(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


# ── checks ───────────────────────────────────────────────────────────────


def check_fresh_cursor_emits_latest_once_then_tails() -> None:
    bridge = FakeBridge()
    try:
        bridge.add_event("DECLARATION_REJECTED", detail="field=$ reason=first")
        bridge.add_event("DECLARATION_REJECTED", detail="field=$ reason=second")
        state_dir = fresh_state_dir()
        cursor_path = state_dir / "alerter-cursor.json"
        cursor = alerter.load_cursor(cursor_path)
        assert_true(cursor["afterSeq"] is None, "cursor starts unprimed")
        tx = RecordingTransport()
        rl = alerter.RateLimiter(60)

        alerter.poll_once(bridge.socket_path, cursor, rl, tx, cursor_path)
        assert_true(len(tx.sent) == 1, f"exactly one message on fresh start, got {len(tx.sent)}")
        assert_true("second" in tx.sent[0], "the ONE emitted message is the latest event, not the first")
        assert_true(cursor["afterSeq"] == 2, f"cursor now at seq 2, got {cursor['afterSeq']}")

        # tail: no new events -> no new sends
        alerter.poll_once(bridge.socket_path, cursor, rl, tx, cursor_path)
        assert_true(len(tx.sent) == 1, "no new events -> no new sends")

        # tail: a genuinely new event is delivered
        bridge.add_event("DECLARATION_REJECTED", detail="field=$ reason=third")
        alerter.poll_once(bridge.socket_path, cursor, rl, tx, cursor_path)
        assert_true(len(tx.sent) == 2, "new event after priming is delivered")
        assert_true("third" in tx.sent[1], "the new message is the third event")

        # cursor survived a reload from disk
        reloaded = alerter.load_cursor(cursor_path)
        assert_true(reloaded["afterSeq"] == 3, "persisted cursor reloads correctly")
    finally:
        bridge.stop()


def check_fresh_cursor_on_empty_book_emits_nothing() -> None:
    bridge = FakeBridge()
    try:
        state_dir = fresh_state_dir()
        cursor_path = state_dir / "alerter-cursor.json"
        cursor = alerter.load_cursor(cursor_path)
        tx = RecordingTransport()
        rl = alerter.RateLimiter(60)
        alerter.poll_once(bridge.socket_path, cursor, rl, tx, cursor_path)
        assert_true(len(tx.sent) == 0, "empty book at fresh start sends nothing")
        assert_true(cursor["afterSeq"] == 0, "cursor primed to 0 on empty book")
    finally:
        bridge.stop()


def check_cursor_never_advances_past_unsent_event() -> None:
    bridge = FakeBridge()
    try:
        bridge.add_event("DECLARATION_REJECTED", detail="reason=alpha")
        state_dir = fresh_state_dir()
        cursor_path = state_dir / "alerter-cursor.json"
        cursor = {"afterSeq": 0, "relayMarkerLastPresent": False}
        rl = alerter.RateLimiter(60)

        bridge.add_event("DECLARATION_REJECTED", detail="reason=beta")
        # send_fn fails for both events on this poll
        failing_tx = RecordingTransport(fail_next=2)
        alerter.poll_once(bridge.socket_path, cursor, rl, failing_tx, cursor_path)
        assert_true(cursor["afterSeq"] == 0, f"cursor must not advance past an unsent event, got {cursor['afterSeq']}")
        assert_true(len(failing_tx.sent) == 0, "nothing was actually recorded as sent")

        # now sending works: both events are delivered in order, cursor catches up
        working_tx = RecordingTransport()
        alerter.poll_once(bridge.socket_path, cursor, rl, working_tx, cursor_path)
        assert_true(cursor["afterSeq"] == 2, f"cursor now caught up to 2, got {cursor['afterSeq']}")
        assert_true(len(working_tx.sent) == 2, "both previously-unsent events delivered")
        assert_true("alpha" in working_tx.sent[0] and "beta" in working_tx.sent[1], "delivered in order")
    finally:
        bridge.stop()


def check_rate_limit_delays_rather_than_drops() -> None:
    bridge = FakeBridge()
    try:
        for i in range(3):
            bridge.add_event("DECLARATION_REJECTED", detail=f"reason={i}")
        state_dir = fresh_state_dir()
        cursor_path = state_dir / "alerter-cursor.json"
        cursor = {"afterSeq": 0, "relayMarkerLastPresent": False}
        clock = FakeClock(0.0)
        rl = alerter.RateLimiter(1, now_fn=clock.now)
        tx = RecordingTransport()

        alerter.poll_once(bridge.socket_path, cursor, rl, tx, cursor_path)
        assert_true(len(tx.sent) == 1, f"only 1 sent this cycle under a 1/min limit, got {len(tx.sent)}")
        assert_true(cursor["afterSeq"] == 1, f"cursor stops exactly at the delivered event, got {cursor['afterSeq']}")

        # same minute: still rate-limited, nothing new sent, cursor unmoved
        alerter.poll_once(bridge.socket_path, cursor, rl, tx, cursor_path)
        assert_true(len(tx.sent) == 1, "still rate-limited within the same window")
        assert_true(cursor["afterSeq"] == 1, "cursor still has not advanced past the unsent event")

        # window rolls over: delivery resumes, nothing was lost
        clock.advance(61.0)
        alerter.poll_once(bridge.socket_path, cursor, rl, tx, cursor_path)
        assert_true(len(tx.sent) == 2, "next event delivered once the window rolls over")
        assert_true(cursor["afterSeq"] == 2, "cursor advances to match")

        clock.advance(61.0)
        alerter.poll_once(bridge.socket_path, cursor, rl, tx, cursor_path)
        assert_true(len(tx.sent) == 3, "third event eventually delivered — delayed, never dropped")
        assert_true(cursor["afterSeq"] == 3, "cursor fully caught up")
    finally:
        bridge.stop()


def check_unknown_event_kind_reported_verbatim() -> None:
    bridge = FakeBridge()
    try:
        bridge.add_event(
            "SOMETHING_NOBODY_NAMED_YET",
            subject="housekeeper",
            identity={"subject": "housekeeper", "sessionId": "s1", "actionId": "a1"},
            disposition="HOLD",
            detail="unrecognised, on purpose, for this test",
            decisionHash="deadbeef",
        )
        state_dir = fresh_state_dir()
        cursor_path = state_dir / "alerter-cursor.json"
        cursor = {"afterSeq": 0, "relayMarkerLastPresent": False}
        tx = RecordingTransport()
        rl = alerter.RateLimiter(60)

        alerter.poll_once(bridge.socket_path, cursor, rl, tx, cursor_path)
        assert_true(len(tx.sent) == 1, "unknown kind is still delivered, not dropped")
        msg = tx.sent[0]
        assert_true("SOMETHING_NOBODY_NAMED_YET" in msg, "kind is reported verbatim")
        assert_true("housekeeper" in msg, "subject is carried through")
        assert_true("unrecognised, on purpose, for this test" in msg, "detail is carried through")
        assert_true("deadbeef" in msg, "decisionHash is carried through")

        # briefed-but-not-yet-produced kinds also fall through the generic
        # branch, verbatim, exactly like a truly unknown kind.
        for briefed_kind in ("DISPOSITION_CHANGED", "PASS_BLIND_NOTICE", "HELD"):
            event = {
                "seq": 999,
                "kind": briefed_kind,
                "subject": None,
                "identity": None,
                "disposition": None,
                "detail": "synthetic — no real producer exists for this kind today",
                "decisionHash": None,
            }
            msg2 = alerter.format_event_message(event)
            assert_true(briefed_kind in msg2, f"{briefed_kind} reported verbatim by the generic branch")
    finally:
        bridge.stop()


def check_latched_and_latch_cleared_are_unreachable_but_present() -> None:
    # Not reachable through poll_once today (no producer emits these kinds),
    # but the branches exist and format correctly if ever called directly —
    # proving they are real code, not a stub that would crash.
    for kind in ("LATCHED", "LATCH_CLEARED"):
        event = {"seq": 1, "kind": kind, "detail": "synthetic, direct call only"}
        msg = alerter.format_event_message(event)
        assert_true(kind in msg, f"{kind} branch formats its own kind")
        assert_true("unreachable today" in msg, f"{kind} branch documents that it has no live producer")


def check_disposition_changed_renders_disposition_word() -> None:
    # Why this matters: the operator learns of a gate closing through
    # Telegram. HELD fires on every held act; DISPOSITION_CHANGED marks the
    # PASS_BLIND -> HOLD edge once. Both fall through format_event_message's
    # generic branch (see module: kind != DECLARATION_REJECTED / LATCHED /
    # LATCH_CLEARED), which only emits "disposition: {disposition}" if the
    # `disposition` field is truthy. Line 318's loop passes disposition=None
    # for exactly these kinds and asserts only that the KIND string appears
    # — it never proves the disposition VALUE reaches the rendered message.
    # This check closes that gap: without it, "the disposition reaches the
    # alerter" is a read of the code, not a tested fact.
    event = {
        "seq": 42,
        "kind": "DISPOSITION_CHANGED",
        "subject": "housekeeper",
        "identity": None,
        "disposition": "HOLD",
        "detail": "synthetic — PASS_BLIND -> HOLD edge",
        "decisionHash": None,
    }
    msg = alerter.format_event_message(event)
    assert_true("disposition: HOLD" in msg, "the disposition VALUE, not just the kind or detail, reaches the rendered message")


def check_service_started_reaches_the_generic_branch() -> None:
    # Why this matters: SERVICE_STARTED exists so a `totalSoFar` that drops from
    # 40 to 1 has a visible cause. That only works if the line REACHES THE ARBITER —
    # and the alerter is the only thing that carries it. The bridge emits it with
    # no alerter change because the generic branch takes every unrecognised kind
    # verbatim; this check is what makes "no alerter change needed" a tested fact
    # rather than a reasonable-sounding one.
    #
    # Asserted on the VALUES in the detail, not on the kind: a check that only
    # looked for "SERVICE_STARTED" would pass over a message that carried the
    # kind and dropped the sentence the operator actually needs.
    event = {
        "seq": 1,
        "kind": "SERVICE_STARTED",
        "subject": None,
        "identity": None,
        "disposition": None,
        "detail": (
            "bridge process started at 2026-09-20T21:45:00.000Z; "
            "release=c80ce3f; declarationHash=75c429cf; notice.window=1. "
            "totalSoFar restarts at 1 from here."
        ),
        "decisionHash": None,
    }
    msg = alerter.format_event_message(event)
    assert_true("SERVICE_STARTED" in msg, "the kind is reported verbatim")
    assert_true(
        "totalSoFar restarts at 1 from here" in msg,
        "the RESTART SENTENCE must reach the message — it is the whole reason the line exists",
    )
    assert_true("release=c80ce3f" in msg, "the release sha reaches the message")
    assert_true("notice.window=1" in msg, "the declared window reaches the message")


def check_relay_marker_edge_triggers_once() -> None:
    bridge = FakeBridge()
    try:
        state_dir = fresh_state_dir()
        cursor_path = state_dir / "alerter-cursor.json"
        cursor = {"afterSeq": 0, "relayMarkerLastPresent": False}
        tx = RecordingTransport()
        rl = alerter.RateLimiter(60)

        # stays false: no alert
        alerter.poll_once(bridge.socket_path, cursor, rl, tx, cursor_path)
        assert_true(len(tx.sent) == 0, "markerPresent:false generates no alert")

        # flips to true: exactly one alert
        bridge.set_relay(True, detail="relay died mid-swap, synthetic")
        alerter.poll_once(bridge.socket_path, cursor, rl, tx, cursor_path)
        assert_true(len(tx.sent) == 1, "flip to true fires exactly one alert")
        assert_true("UNVERIFIED" in tx.sent[0], "message names the marker's meaning")
        assert_true("relay died mid-swap, synthetic" in tx.sent[0], "message carries the marker detail")

        # stays true: no re-fire, repeatedly
        for _ in range(3):
            alerter.poll_once(bridge.socket_path, cursor, rl, tx, cursor_path)
        assert_true(len(tx.sent) == 1, "marker staying true does not re-fire")

        # clears, then flips true again: fires again (edge, not level)
        bridge.set_relay(False)
        alerter.poll_once(bridge.socket_path, cursor, rl, tx, cursor_path)
        assert_true(len(tx.sent) == 1, "clearing the marker sends nothing (no health/'all clear' message)")
        bridge.set_relay(True, detail="second incident, synthetic")
        alerter.poll_once(bridge.socket_path, cursor, rl, tx, cursor_path)
        assert_true(len(tx.sent) == 2, "a second true edge fires again")
    finally:
        bridge.stop()


def check_token_never_appears_in_any_output() -> None:
    # Amendment 1, verifier finding 5: this check used to point send_telegram
    # at a closed loopback port to force a failure — a real TCP attempt,
    # which violates a no-network test rule even though it reaches no
    # external host. Fixed by injecting the HTTP post function itself: the
    # fake raises, and its error text echoes the full request URL (which
    # embeds the token) exactly the way a real requests exception can —
    # same security coverage, no DNS resolution and no outbound connection
    # (Amendment 4, verifier run 3 finding 2: "zero sockets opened" was
    # itself an overclaim — importing `requests`/`urllib3` creates one
    # unconnected IPv6 capability-probe socket at import time regardless of
    # what this test does; it is never connected, but it exists).
    token = "SECRET-TOKEN-1234567890"
    chat_id = "999"
    logged: list = []
    original_log = alerter.log
    alerter.log = lambda msg: logged.append(msg)  # type: ignore[assignment]

    def fake_post_that_raises(url, **kwargs):
        raise RuntimeError(f"simulated network failure while POSTing {url}")

    try:
        ok = alerter.send_telegram(token, chat_id, "hello", post_fn=fake_post_that_raises)
        assert_true(ok is False, "send fails cleanly when the injected transport raises")
        joined = "\n".join(logged)
        assert_true(token not in joined, "token never appears in any logged output")
        assert_true("REDACTED" in joined, "failure is logged with the token redacted")
    finally:
        alerter.log = original_log  # type: ignore[assignment]


def check_base_exception_from_poster_is_redacted_before_propagating() -> None:
    # Amendment 3, verifier finding 5: `except Exception` (the clause the
    # test above exercises) does NOT catch KeyboardInterrupt / SystemExit /
    # GeneratorExit or any other direct BaseException subclass. If the
    # poster raises one of those carrying the token-bearing URL in its
    # message, Python's default uncaught-exception printer would write it
    # to stderr unredacted the moment it escapes uncaught.
    #
    # This test does not let it actually reach that real top-level printer
    # (that would mean letting a real interrupt-shaped exception escape the
    # test process, which is reckless) — it catches what PROPAGATES OUT of
    # send_telegram itself and asserts THAT is already redacted. That is
    # the exact mechanism that keeps stderr clean if this ever does
    # propagate all the way to an uncaught top level: nothing downstream of
    # send_telegram can redact a message that already contains the raw
    # token, so the propagated exception object is the right place to check.
    token = "SECRET-BASEEXC-TOKEN-9999999999"
    chat_id = "42"

    class FakeInterrupt(BaseException):
        """A direct BaseException subclass — NOT an Exception — the exact
        shape `except Exception` cannot catch."""

    def poster_raises_base_exception(url, **kwargs):
        raise FakeInterrupt(f"interrupted while POSTing {url}")

    logged: list = []
    original_log = alerter.log
    alerter.log = lambda msg: logged.append(msg)  # type: ignore[assignment]
    try:
        propagated: "Optional[BaseException]" = None
        raised_assertion = False
        try:
            alerter.send_telegram(token, chat_id, "hello", post_fn=poster_raises_base_exception)
            raised_assertion = True
        except FakeInterrupt as e:
            propagated = e
        except BaseException as e:  # noqa: BLE001 - catch-all so this test itself never crashes the suite
            propagated = e

        assert_true(not raised_assertion, "send_telegram must re-raise the interrupt, not swallow it and return normally")
        assert_true(propagated is not None, "something propagated out of send_telegram, as it must for a real interrupt")
        assert_true(
            token not in str(propagated),
            f"the exception that ESCAPES send_telegram must not carry the raw token, got: {propagated!r}",
        )
        joined_logs = "\n".join(logged)
        assert_true(token not in joined_logs, "nothing logged along the way carries the raw token either")
        assert_true("REDACTED" in str(propagated), "the propagated exception's own message shows the redaction happened, not just silence")
    finally:
        alerter.log = original_log  # type: ignore[assignment]


def check_dry_run_sends_nothing_to_telegram() -> None:
    calls: list = []
    import requests  # local import so a monkeypatch failure can't affect other checks

    original_post = requests.post

    def guard_post(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("requests.post must never be called in dry-run mode")

    requests.post = guard_post  # type: ignore[assignment]
    try:
        send_fn = alerter.build_send_fn(True, None, None)
        ok = send_fn("this should only print")
        assert_true(ok is True, "dry-run send reports success")
        assert_true(len(calls) == 0, "requests.post was never invoked in dry-run mode")
    finally:
        requests.post = original_post  # type: ignore[assignment]


def check_corrupt_cursor_shapes_are_never_trusted_silently() -> None:
    # Amendment 1, verifier finding 1: a valid-JSON-but-semantically-wrong
    # cursor used to be accepted at face value and silently dropped every
    # pending event forever. Every shape below must be refused loudly and
    # replaced with the fresh-cursor state, never accepted as-is.
    cases = {
        "malformed_json": "{not valid json",
        "not_an_object": "[1, 2, 3]",
        "negative_afterSeq": json.dumps({"afterSeq": -5}),
        "string_afterSeq": json.dumps({"afterSeq": "3"}),
        "bool_afterSeq": json.dumps({"afterSeq": True}),
        "float_afterSeq": json.dumps({"afterSeq": 3.5}),
    }
    for name, content in cases.items():
        logged: list = []
        d = fresh_state_dir()
        p = d / "alerter-cursor.json"
        p.write_text(content)
        cursor = alerter.load_cursor(p, log_fn=lambda m: logged.append(m))
        assert_true(cursor["afterSeq"] is None, f"[{name}] corrupt afterSeq is never trusted; falls back to fresh")
        assert_true(cursor["relayMarkerLastPresent"] is False, f"[{name}] fresh fallback also resets the marker latch")
        assert_true(len(logged) >= 1, f"[{name}] corruption is logged loudly, never silently swallowed")

    # A bad marker field alone doesn't need to poison a good afterSeq.
    logged2: list = []
    d = fresh_state_dir()
    p = d / "alerter-cursor.json"
    p.write_text(json.dumps({"afterSeq": 2, "relayMarkerLastPresent": "yes"}))
    cursor = alerter.load_cursor(p, log_fn=lambda m: logged2.append(m))
    assert_true(cursor["afterSeq"] == 2, "a valid afterSeq is kept even when the marker field alone is bad")
    assert_true(cursor["relayMarkerLastPresent"] is False, "a non-boolean marker falls back to False")
    assert_true(len(logged2) >= 1, "the bad marker field is still logged loudly")

    # A FILE THAT DOES NOT EXIST AT ALL is the legitimate fresh-start case —
    # not logged, because this program's own save_cursor() simply never ran
    # yet. This is the control case for the missing-key tests below: same
    # resulting values (afterSeq=None), but no file means no anomaly.
    logged3: list = []
    d = fresh_state_dir()
    p = d / "alerter-cursor.json"  # deliberately never written
    cursor = alerter.load_cursor(p, log_fn=lambda m: logged3.append(m))
    assert_true(cursor["afterSeq"] is None, "a genuinely-absent cursor file is a legitimate fresh cursor")
    assert_true(len(logged3) == 0, "a genuinely-absent file is not treated as corruption")


def check_missing_cursor_keys_are_logged_not_silently_accepted() -> None:
    # Amendment 2, verifier gap 1: a cursor file that EXISTS but is missing
    # a key was silently accepted before this fix — raw.get("afterSeq")
    # (or .get("relayMarkerLastPresent", False)) simply returned the same
    # default a genuinely-absent file would, with NO log line, indistin-
    # guishable from the legitimate case above. This is the test that would
    # FAIL against the pre-fix code: it asserts a log line exists, which
    # the old `raw.get(key, default)` pattern never produced for this shape.
    logged_missing_afterSeq: list = []
    d = fresh_state_dir()
    p = d / "alerter-cursor.json"
    p.write_text(json.dumps({"relayMarkerLastPresent": True}))  # afterSeq key absent
    cursor = alerter.load_cursor(p, log_fn=lambda m: logged_missing_afterSeq.append(m))
    assert_true(cursor["afterSeq"] is None, "a missing afterSeq key falls back to the fresh state")
    assert_true(
        len(logged_missing_afterSeq) >= 1,
        "an EXISTING file missing afterSeq must be logged — this is exactly what silent acceptance looked like",
    )
    assert_true(
        any("afterSeq" in m and "missing" in m for m in logged_missing_afterSeq),
        "the log line names which key was missing",
    )

    logged_missing_marker: list = []
    d2 = fresh_state_dir()
    p2 = d2 / "alerter-cursor.json"
    p2.write_text(json.dumps({"afterSeq": 5}))  # relayMarkerLastPresent key absent
    cursor2 = alerter.load_cursor(p2, log_fn=lambda m: logged_missing_marker.append(m))
    assert_true(cursor2["afterSeq"] == 5, "a valid afterSeq is kept even when the marker key alone is missing")
    assert_true(cursor2["relayMarkerLastPresent"] is False, "a missing marker key falls back to False")
    assert_true(
        len(logged_missing_marker) >= 1,
        "an EXISTING file missing relayMarkerLastPresent must be logged too",
    )

    # Sanity / no false positives: a cursor complete for the ORIGINAL
    # (Amendment 1/2) schema — no markerTransitionSeq key at all — logs
    # nothing. This is the realistic upgrade case: an existing on-disk
    # cursor written before Amendment 3 legitimately lacks the new field,
    # and defaults to 0 silently rather than being flagged as corrupt.
    logged_complete: list = []
    d3 = fresh_state_dir()
    p3 = d3 / "alerter-cursor.json"
    p3.write_text(json.dumps({"afterSeq": 7, "relayMarkerLastPresent": True}))
    cursor3 = alerter.load_cursor(p3, log_fn=lambda m: logged_complete.append(m))
    assert_true(
        cursor3
        == {
            "afterSeq": 7,
            "relayMarkerLastPresent": True,
            "markerTransitionSeq": 0,
            # Coalescing, 2026-09-30: `pendingRun` follows markerTransitionSeq's
            # rule exactly — a cursor written before it legitimately lacks it and
            # defaults to None SILENTLY. This assertion is an equality against
            # the WHOLE dict on purpose, so a field added without thinking about
            # the upgrade path fails here rather than in production.
            "pendingRun": None,
        },
        "a pre-Amendment-3 cursor is used as-is, with the new fields defaulted",
    )
    assert_true(len(logged_complete) == 0, "an upgrade from an older cursor schema is not logged as corruption")
    assert_true(len(logged_complete) == 0, "a complete, valid cursor is never logged as a problem")


def check_impossible_cursor_nonexistent_in_range_seq_is_caught() -> None:
    # Amendment 2, verifier gap 2: an afterSeq that is IN RANGE (not beyond
    # the bridge's own lastSeq — that shape is the Amendment-1 test above)
    # but was never actually assigned as a real event's seq. Simulated here
    # as a gap in the book's numbering — a shape the "beyond" check alone
    # cannot catch, since cursor.afterSeq=2 is not beyond a bridge whose
    # real lastSeq is 3. This is the test that would FAIL if gap 2's fix
    # were absent: the pre-fix code took afterSeq at face value whenever it
    # was merely <= lastSeq, and would have delivered nothing here either
    # (event 3 IS > 2, so it happens to still get through under the OLD
    # filter-only logic) — the real distinguishing assertion is that this
    # is now DETECTED AND LOGGED as untrustworthy, not delivered silently
    # as if afterSeq=2 had always been legitimate.
    bridge = FakeBridge()
    try:
        bridge.add_event("DECLARATION_REJECTED", detail="reason=one")
        bridge.add_event("DECLARATION_REJECTED", detail="reason=two")
        bridge.add_event("DECLARATION_REJECTED", detail="reason=three")
        # Open a gap at seq 2 — seq 1 and 3 remain. afterSeq=2 below now
        # names a sequence number that never existed in this book.
        bridge.state["events"] = [e for e in bridge.state["events"] if e["seq"] != 2]

        d = fresh_state_dir()
        p = d / "alerter-cursor.json"
        cursor = {"afterSeq": 2, "relayMarkerLastPresent": False}
        tx = RecordingTransport()
        rl = alerter.RateLimiter(60)
        logged: list = []

        alerter.poll_once(bridge.socket_path, cursor, rl, tx, p, log_fn=lambda m: logged.append(m))

        assert_true(
            any("does not correspond" in m and "afterSeq=2" in m for m in logged),
            "the refusal is logged loudly, naming the nonexistent seq — THIS is what gap 2's fix adds",
        )
        assert_true(cursor["afterSeq"] == 3, "cursor is corrected to the bridge's real latest seq, not left at 2")
    finally:
        bridge.stop()


def check_impossible_cursor_is_caught_live_against_the_bridge() -> None:
    # The exact shape of the verifier's own probe: a well-typed, in-range
    # afterSeq that is nevertheless impossible — far beyond anything the
    # bridge has ever issued. load_cursor() alone cannot catch this (it
    # never talks to the bridge); poll_once() must, by comparing against
    # the bridge's own reported lastSeq on every poll.
    bridge = FakeBridge()
    try:
        bridge.add_event("DECLARATION_REJECTED", detail="reason=alpha")
        bridge.add_event("DECLARATION_REJECTED", detail="reason=beta")
        d = fresh_state_dir()
        p = d / "alerter-cursor.json"
        cursor = {"afterSeq": 999999, "relayMarkerLastPresent": False}
        tx = RecordingTransport()
        rl = alerter.RateLimiter(60)
        logged: list = []

        alerter.poll_once(bridge.socket_path, cursor, rl, tx, p, log_fn=lambda m: logged.append(m))
        assert_true(len(tx.sent) == 1, "an impossible cursor is refused and re-primed, not left silently stuck")
        assert_true("beta" in tx.sent[0], "re-priming lands on the bridge's actual latest event, not event 1")
        assert_true(
            any("beyond" in m.lower() and "999999" in m for m in logged),
            "the refusal is logged loudly, naming the impossible value",
        )
        assert_true(cursor["afterSeq"] == 2, "cursor is corrected to the bridge's real state, not left at 999999")
    finally:
        bridge.stop()


def check_at_least_once_event_duplicate_carries_same_seq() -> None:
    # Amendment 1, verifier finding 3: mica-alerter.py calls send_fn BEFORE
    # persisting the cursor (save_cursor runs once, at the end of a
    # successful poll_once). If the process is killed in that window, the
    # event was durably delivered but this process never durably recorded
    # that fact — so a restart resends it. This simulates exactly that
    # window by never letting the "first" delivery reach save_cursor, then
    # restarting from the on-disk (still-fresh) cursor, matching the module
    # docstring's stated "Delivery contract".
    bridge = FakeBridge()
    try:
        bridge.add_event("DECLARATION_REJECTED", detail="reason=only")
        state_dir = fresh_state_dir()
        cursor_path = state_dir / "alerter-cursor.json"
        tx = RecordingTransport()
        rl = alerter.RateLimiter(60)

        # The "kill before persist" window: deliver once by calling the
        # same send path poll_once would use, but never touch cursor_path —
        # exactly what a SIGKILL between a successful send_fn() and the
        # trailing save_cursor() leaves behind on disk.
        event = bridge.state["events"][0]
        assert_true(tx(alerter.format_event_message(event)), "simulated first (pre-crash) delivery succeeds")
        assert_true(not cursor_path.exists(), "nothing was persisted before the simulated crash")

        # "Restart": load whatever is actually on disk (nothing), then run
        # a real poll cycle.
        restarted_cursor = alerter.load_cursor(cursor_path)
        alerter.poll_once(bridge.socket_path, restarted_cursor, rl, tx, cursor_path)

        assert_true(len(tx.sent) == 2, "at-least-once: the event is delivered again after the simulated crash, never lost")
        assert_true(tx.sent[0] == tx.sent[1], "a repeat is byte-identical to the original, not a confusing near-duplicate")
        assert_true("seq 1" in tx.sent[0] and "seq 1" in tx.sent[1], "both copies carry the same seq — recognisable as one incident")
    finally:
        bridge.stop()


def check_at_least_once_marker_duplicate_carries_same_transition_id() -> None:
    bridge = FakeBridge()
    try:
        bridge.set_relay(True, detail="synthetic incident for this test")
        state_dir = fresh_state_dir()
        cursor_path = state_dir / "alerter-cursor.json"
        tx = RecordingTransport()
        rl = alerter.RateLimiter(60)

        relay = bridge.state["relay"]
        # What poll_once itself would compute for this first attempt: the
        # cursor's markerTransitionSeq starts at 0 (never persisted), so
        # next_transition_seq = 1 — the manual simulation below uses the
        # same value an honest first attempt would, not an arbitrary one.
        first_transition_seq = 1
        assert_true(
            tx(alerter.format_relay_marker_message(relay, first_transition_seq)),
            "simulated first (pre-crash) marker delivery succeeds",
        )
        assert_true(not cursor_path.exists(), "nothing was persisted before the simulated crash")

        restarted_cursor = alerter.load_cursor(cursor_path)
        assert_true(restarted_cursor["relayMarkerLastPresent"] is False, "restart sees no recorded latch — the crash window is real")
        assert_true(restarted_cursor["markerTransitionSeq"] == 0, "restart sees no recorded counter advance either — same crash window")
        alerter.poll_once(bridge.socket_path, restarted_cursor, rl, tx, cursor_path)

        assert_true(len(tx.sent) == 2, "at-least-once: the marker alert is sent again after the simulated crash")
        tid = alerter.relay_marker_transition_id(relay["path"], relay["detail"], first_transition_seq)
        assert_true(f"transition: {tid}" in tx.sent[0], "first message carries the transition id")
        assert_true(f"transition: {tid}" in tx.sent[1], "duplicate carries the SAME transition id — recognisable as a repeat")
        assert_true(restarted_cursor["markerTransitionSeq"] == 1, "the counter is now persisted at 1 after the (re)send actually succeeded")
    finally:
        bridge.stop()


def check_marker_transition_id_distinguishes_separate_identical_incidents() -> None:
    # Amendment 3, verifier finding 4: the Amendment-1 transition id hashed
    # only (path, detail) — so two SEPARATE false->true edges with
    # byte-identical content got the SAME id, contradicting the documented
    # "same id means same incident" claim. Reproduces the verifier's own
    # probe shape exactly: false->true, true->false, false->true, with
    # identical path/detail throughout.
    bridge = FakeBridge()
    try:
        state_dir = fresh_state_dir()
        cursor_path = state_dir / "alerter-cursor.json"
        cursor = {"afterSeq": 0, "relayMarkerLastPresent": False}
        tx = RecordingTransport()
        rl = alerter.RateLimiter(60)

        bridge.set_relay(True, detail="identical detail every time")
        alerter.poll_once(bridge.socket_path, cursor, rl, tx, cursor_path)
        bridge.set_relay(False)
        alerter.poll_once(bridge.socket_path, cursor, rl, tx, cursor_path)
        bridge.set_relay(True, detail="identical detail every time")
        alerter.poll_once(bridge.socket_path, cursor, rl, tx, cursor_path)

        assert_true(len(tx.sent) == 2, "two separate edges produce two alerts")

        def extract_transition(msg: str) -> str:
            for line in msg.splitlines():
                if line.startswith("transition: "):
                    return line[len("transition: "):]
            raise AssertionError(f"no transition line found in message: {msg!r}")

        id1 = extract_transition(tx.sent[0])
        id2 = extract_transition(tx.sent[1])
        assert_true(
            id1 != id2,
            f"two SEPARATE edges with identical path/detail must get DIFFERENT transition ids, both were {id1!r}",
        )
        # The fingerprint half (after the counter prefix) IS expected to
        # match — same content — only the counter prefix should differ.
        fp1 = id1.split("-", 1)[1]
        fp2 = id2.split("-", 1)[1]
        assert_true(fp1 == fp2, "the content fingerprint half is still shared (same underlying failure text)")
        assert_true(id1.split("-", 1)[0] != id2.split("-", 1)[0], "the counter half is what actually differs")
        assert_true(cursor["markerTransitionSeq"] == 2, "the persisted counter advances once per edge, not once per send")
    finally:
        bridge.stop()


def check_script_is_committed_executable() -> None:
    # Amendment 1, verifier finding 4: deploy/mica-alerter.service's
    # ExecStart invokes mica-alerter.py directly, with no interpreter named
    # — a non-executable file fails every start. Checks both the working
    # tree's current mode and, more importantly, the mode actually recorded
    # in git's index/HEAD (what a fresh clone or deploy checkout gets).
    import stat as stat_module
    import subprocess

    st = os.stat(_ALERTER_PATH)
    assert_true(bool(st.st_mode & stat_module.S_IXUSR), "mica-alerter.py must be owner-executable on disk")

    mica_bridge_dir = os.path.dirname(_ALERTER_PATH)
    repo_root = subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"], cwd=mica_bridge_dir
    ).decode().strip()
    out = subprocess.check_output(
        ["git", "ls-files", "-s", "mica-bridge/mica-alerter.py"], cwd=repo_root
    ).decode().strip()
    assert_true(out.startswith("100755"), f"git must record mica-alerter.py as mode 100755, got: {out!r}")


def check_placeholder_chat_id_is_refused_by_name() -> None:
    # Amendment 1, verifier finding 6: CHANGEME is non-empty, so a bare
    # require_env() would have accepted it and only failed later, at
    # Telegram, as an opaque 400. It must be refused at startup, by name,
    # the same way a missing value is.
    #
    # Run on a thread with a hard join timeout, not called inline: if this
    # check were ever regressed (the placeholder check removed), main()
    # would sail past config validation into its `while True: poll_once();
    # time.sleep(30)` loop — which never raises and never returns, so a
    # naive inline call would HANG the test suite instead of failing it.
    # A hang is not a passing test and not a reported failure either; it is
    # silence, which is worse. Bounding it turns a regression into a clean,
    # visible FAIL.
    import threading

    env_backup = dict(os.environ)
    try:
        os.environ["MICA_BRIDGE_SOCKET"] = "/tmp/does-not-matter.sock"
        os.environ["MICA_ALERTER_POLL_SECONDS"] = "30"
        os.environ["MICA_ALERTER_STATE_DIR"] = str(fresh_state_dir())
        os.environ["MICA_ALERTER_MAX_PER_MINUTE"] = "6"
        os.environ["MICA_TG_TOKEN"] = "some-token"
        os.environ["MICA_TG_CHAT_ID"] = "CHANGEME"
        os.environ.pop("MICA_ALERTER_TRANSPORT", None)

        result: dict = {}
        t = threading.Thread(target=lambda: result.__setitem__("rc", alerter.main([])), daemon=True)
        t.start()
        t.join(timeout=5.0)
        assert_true(
            not t.is_alive(),
            "main() did not return within 5s — a regression here would enter the poll loop, "
            "not raise, so this is the failure mode a removed placeholder check produces",
        )
        assert_true(result.get("rc") == 2, f"a placeholder chat id must refuse to start (exit 2), got {result.get('rc')!r}")
    finally:
        os.environ.clear()
        os.environ.update(env_backup)


def check_required_env_vars_refuse_to_start_by_name() -> None:
    env_backup = dict(os.environ)
    try:
        for key in (
            "MICA_BRIDGE_SOCKET",
            "MICA_ALERTER_POLL_SECONDS",
            "MICA_ALERTER_STATE_DIR",
            "MICA_ALERTER_MAX_PER_MINUTE",
            "MICA_TG_TOKEN",
            "MICA_TG_CHAT_ID",
            "MICA_ALERTER_TRANSPORT",
        ):
            os.environ.pop(key, None)

        rc = alerter.main([])
        assert_true(rc == 2, "missing everything -> exit 2")

        os.environ["MICA_BRIDGE_SOCKET"] = "/tmp/does-not-matter.sock"
        try:
            alerter.require_env_float("MICA_ALERTER_POLL_SECONDS")
            raise AssertionError("should have raised ConfigError")
        except alerter.ConfigError as e:
            assert_true("MICA_ALERTER_POLL_SECONDS" in str(e), "error names the missing variable")
    finally:
        os.environ.clear()
        os.environ.update(env_backup)


def check_identical_run_sends_the_first_and_counts_the_rest() -> None:
    """⛔ THE FIRST IS ALWAYS SENT. That is the property that makes coalescing
    safe, and it is asserted before anything about compression."""
    bridge = FakeBridge()
    try:
        for _ in range(4):
            bridge.add_event("DECLARATION_REJECTED", detail="field=$ reason=same")
        d = fresh_state_dir()
        cp = d / "alerter-cursor.json"
        cursor = alerter.load_cursor(cp)
        tx = RecordingTransport()
        rl = alerter.RateLimiter(60)
        # Fresh-cursor rule primes to the tail, so only the LAST is deliverable;
        # prime explicitly to 0 so all four are in scope for this test.
        cursor["afterSeq"] = 0
        alerter.poll_once(bridge.socket_path, cursor, rl, tx, cp)
        assert_true(len(tx.sent) == 1, f"exactly ONE message for four identical events, got {len(tx.sent)}")
        assert_true(cursor["afterSeq"] == 4, f"cursor consumed all four, got {cursor['afterSeq']}")
        run = cursor["pendingRun"]
        assert_true(run is not None and run["count"] == 3, f"three held, got {run}")
        assert_true(run["firstSeq"] == 1 and run["lastSeq"] == 4, f"run spans 1..4, got {run}")
        # and the count SURVIVES a reload — a restart must not forget it
        assert_true(alerter.load_cursor(cp)["pendingRun"]["count"] == 3, "the held count is persisted")
    finally:
        bridge.stop()


def check_a_different_event_flushes_the_run_first_in_order() -> None:
    bridge = FakeBridge()
    try:
        for _ in range(3):
            bridge.add_event("DECLARATION_REJECTED", detail="field=$ reason=same")
        bridge.add_event("DECLARATION_REJECTED", detail="field=$ reason=DIFFERENT")
        d = fresh_state_dir()
        cp = d / "alerter-cursor.json"
        cursor = alerter.load_cursor(cp)
        cursor["afterSeq"] = 0
        tx = RecordingTransport()
        alerter.poll_once(bridge.socket_path, cursor, alerter.RateLimiter(60), tx, cp)
        assert_true(len(tx.sent) == 3, f"first + summary + the different one, got {len(tx.sent)}")
        assert_true("repeated 2 more times" in tx.sent[1], f"summary names the count: {tx.sent[1]}")
        assert_true("seq 1..3" in tx.sent[1], f"summary names the span: {tx.sent[1]}")
        # ORDER MATTERS: the summary comes BEFORE the thing that was different,
        # so a reader sees the run close and then the change, as they happened.
        assert_true("DIFFERENT" in tx.sent[2], f"the different event is last: {tx.sent[2]}")
    finally:
        bridge.stop()


def check_a_run_of_one_produces_no_summary() -> None:
    """The first version flushed unconditionally and said 'repeated 0 more
    times' before every distinct event — two messages where there had been
    one, in a change whose whole purpose is fewer."""
    bridge = FakeBridge()
    try:
        bridge.add_event("DECLARATION_REJECTED", detail="field=$ reason=a")
        bridge.add_event("DECLARATION_REJECTED", detail="field=$ reason=b")
        d = fresh_state_dir()
        cp = d / "alerter-cursor.json"
        cursor = alerter.load_cursor(cp)
        cursor["afterSeq"] = 0
        tx = RecordingTransport()
        alerter.poll_once(bridge.socket_path, cursor, alerter.RateLimiter(60), tx, cp)
        assert_true(len(tx.sent) == 2, f"two distinct events, two messages, got {len(tx.sent)}")
        assert_true(not any("repeated 0" in m for m in tx.sent), f"no empty summary: {tx.sent}")
    finally:
        bridge.stop()


def check_a_run_that_stops_still_reports_itself() -> None:
    """⛔ THE ARM THAT MAKES COALESCING HONEST. A run whose condition simply
    ceases has no next event to break it, and without the age flush its count
    would sit in the cursor forever — the operator seeing one alert and never
    learning it had fired four times."""
    bridge = FakeBridge()
    try:
        for _ in range(4):
            bridge.add_event("DECLARATION_REJECTED", detail="field=$ reason=same")
        d = fresh_state_dir()
        cp = d / "alerter-cursor.json"
        cursor = alerter.load_cursor(cp)
        cursor["afterSeq"] = 0
        tx = RecordingTransport()
        rl = alerter.RateLimiter(60)
        clock = [1000.0]
        alerter.poll_once(bridge.socket_path, cursor, rl, tx, cp, now_fn=lambda: clock[0])
        assert_true(len(tx.sent) == 1, "the first, and three held")
        # no new events at all — only time passes
        clock[0] += alerter.MAX_RUN_SECONDS + 1
        alerter.poll_once(bridge.socket_path, cursor, rl, tx, cp, now_fn=lambda: clock[0])
        assert_true(len(tx.sent) == 2, f"the stale run reported itself, got {len(tx.sent)}")
        assert_true("repeated 3 more times" in tx.sent[1], tx.sent[1])
        assert_true(cursor["pendingRun"] is None, "and the run is cleared once reported")
    finally:
        bridge.stop()


def check_run_key_splits_on_every_describing_field() -> None:
    """A key too WIDE loses alerts; too NARROW only loses compression. These
    costs are not symmetric, so the key errs narrow."""
    base = {"seq": 1, "kind": "X", "subject": "s", "disposition": "d", "detail": "t"}
    same_incident = dict(base, seq=2, decisionHash="different")
    assert_true(alerter.run_key(base) == alerter.run_key(same_incident),
                "seq and decisionHash are incidental — they must NOT split a run")
    for field in ("kind", "subject", "disposition", "detail"):
        other = dict(base, **{field: "CHANGED"})
        assert_true(alerter.run_key(base) != alerter.run_key(other),
                    f"a change in {field} is a DIFFERENT incident and must split the run")



# ── liveness · HeartbeatTicker ───────────────────────────────────────────────
#
# ⛔ THESE EXIST BECAUSE A QUESTION ABOUT THIS SERVICE COULD NOT BE ANSWERED FROM
#    ITS OWN RECORD. Slate (n2), 2026-10-02: "say whether the back-off is stuck
#    since 10:49Z". The journal held `rate limit reached; delaying seq 678 and
#    later` at 10:48:59Z and 10:49:29Z and then eight hours of nothing. It was NOT
#    stuck — RateLimiter is a sliding 60s window that evicts, and a genuinely
#    stuck back-off would have logged that line on all ~968 polls rather than
#    twice — but nothing in the journal SAID so, because no success path logs. The
#    only reason the question was answerable at all was the cursor file's mtime,
#    which is a side effect of saving state and not a signal anyone designed.


def check_heartbeat_fires_only_every_nth_poll() -> None:
    t = alerter.HeartbeatTicker(3, now_fn=lambda: 0.0)
    due = []
    for _ in range(7):
        t.note_poll(False)
        due.append(t.due())
    assert due == [False, False, True, False, False, True, False], due


def check_heartbeat_zero_disables_and_says_nothing() -> None:
    t = alerter.HeartbeatTicker(0, now_fn=lambda: 0.0)
    for _ in range(200):
        t.note_poll(False)
        assert t.due() is False, "every<=0 must never be due"


def check_heartbeat_counts_quiet_polls_and_resets_on_change() -> None:
    t = alerter.HeartbeatTicker(10, now_fn=lambda: 0.0)
    for _ in range(5):
        t.note_poll(False)
    assert t.polls_since_change == 5, t.polls_since_change
    t.note_poll(True)
    assert t.polls_since_change == 0, "a change must reset the quiet counter"
    t.note_poll(False)
    assert t.polls_since_change == 1, t.polls_since_change


def check_heartbeat_line_names_what_distinguishes_alive_from_dead() -> None:
    clock = [1000.0]
    t = alerter.HeartbeatTicker(2, now_fn=lambda: clock[0])
    rl = alerter.RateLimiter(6, now_fn=lambda: clock[0])
    rl.record()
    rl.record()
    for _ in range(4):
        t.note_poll(False)
    clock[0] = 1000.0 + 120.0
    line = t.line({"afterSeq": 683}, rl)
    # the cursor position, so a reader can tell WHERE it is stuck if it is
    assert "afterSeq=683" in line, line
    # how long it has been quiet, so silence has a duration rather than being bare
    assert "4 poll(s) since anything changed" in line, line
    assert "120s" in line, line
    # ⛔ AND THE LIMITER DEPTH THROUGH ITS OWN EVICTION: both records are now more
    #    than 60s old, so the honest depth is 0/6 and NOT 2/6. A heartbeat that
    #    reported a stale window would be the exact defect it exists to prevent.
    assert "rate-limit window 0/6" in line, line


def check_heartbeat_line_shows_a_full_window_when_it_is_full() -> None:
    clock = [500.0]
    t = alerter.HeartbeatTicker(1, now_fn=lambda: clock[0])
    rl = alerter.RateLimiter(6, now_fn=lambda: clock[0])
    for _ in range(6):
        rl.record()
    t.note_poll(False)
    line = t.line({"afterSeq": None}, rl)
    assert "rate-limit window 6/6" in line, line
    assert "afterSeq=none" in line, line
    assert rl.allow() is False, "a full window must also be refusing, or the line lies"


def check_heartbeat_distinguishes_the_968_poll_silence() -> None:
    # The exact case from the journal: ~968 quiet polls. Before this ticker that
    # produced NO record at all; now it produces a line that says so.
    clock = [0.0]
    t = alerter.HeartbeatTicker(60, now_fn=lambda: clock[0])
    rl = alerter.RateLimiter(6, now_fn=lambda: clock[0])
    lines = []
    for _ in range(968):
        clock[0] += 30.0
        t.note_poll(False)
        if t.due():
            lines.append(t.line({"afterSeq": 683}, rl))
    assert len(lines) == 16, f"968 polls at every-60 should emit 16 lines, got {len(lines)}"
    # ⚠ THE LAST LINE SAYS 960, NOT 968, and that is the cadence's own cost: the
    #   heartbeat fires on multiples of `every`, so the most recent polls are
    #   unreported until the next multiple — up to 59 polls, ~30 minutes at the
    #   deployed interval. A reader must take a heartbeat as "alive as of poll N",
    #   never "alive now". The first draft of this test asserted "968" and failed;
    #   the assertion was wrong, not the ticker.
    assert "960 poll(s)" in lines[-1], lines[-1]
    assert "afterSeq=683" in lines[-1], lines[-1]
    assert "28800s" in lines[-1], f"the quiet duration must be the real elapsed time: {lines[-1]}"


# ── the four Codex findings, each with the check that was missing ────────────
#
# ARC_MICA-VERIFY_Alerter-Heartbeat_20261002: PASS-WITH-FINDINGS. Every repair
# below is tested by the edge Codex actually ran, not by a restatement of it.


def _hb_startup_lines(value: str | None) -> list[str]:
    """Run main()'s startup far enough to capture its cadence lines, no polling.

    ⛔ The crash in F1 happened BEFORE the first poll, so the probe must reach
       startup and stop there. `poll_once` is replaced by one that raises a
       sentinel, so the loop cannot run and nothing touches a socket.
    """
    lines: list[str] = []
    env_backup = dict(os.environ)
    real_poll = alerter.poll_once
    real_log = alerter.log

    class _Stop(Exception):
        pass

    try:
        os.environ.update(
            {
                "MICA_BRIDGE_SOCKET": "/tmp/mica-alerter-no-such.sock",
                "MICA_ALERTER_POLL_SECONDS": "30",
                "MICA_ALERTER_STATE_DIR": tempfile.mkdtemp(prefix="hb-f1-"),
                "MICA_ALERTER_MAX_PER_MINUTE": "6",
                "MICA_ALERTER_TRANSPORT": "stdout",
            }
        )
        os.environ.pop("MICA_ALERTER_HEARTBEAT_POLLS", None)
        if value is not None:
            os.environ["MICA_ALERTER_HEARTBEAT_POLLS"] = value
        alerter.log = lambda m: lines.append(m)  # type: ignore[assignment]

        def _no_polling(*_a, **_k):
            raise _Stop()

        alerter.poll_once = _no_polling  # type: ignore[assignment]
        try:
            alerter.main(["--dry-run"])
        except _Stop:
            pass
    finally:
        alerter.poll_once = real_poll  # type: ignore[assignment]
        alerter.log = real_log  # type: ignore[assignment]
        os.environ.clear()
        os.environ.update(env_backup)
    return lines


def check_f1_an_unbounded_cadence_no_longer_crashes_startup() -> None:
    # Codex's own value: 400 decimal nines. It exited 1 with
    # "OverflowError: int too large to convert to float" before the first poll.
    #
    # ⚠ THE OUTCOME CHANGED WITH THE OFF-BY-DEFAULT RULING (board 08:07Z), and the
    #   FINDING did not: an unusable value must be NAMED and must not stop the
    #   service. It used to fall back to 60 and run; under an opt-in heartbeat it
    #   falls back to DISABLED, because an unusable opt-in is not an opt-in.
    lines = _hb_startup_lines("9" * 400)
    joined = "\n".join(lines)
    assert "exceeds the maximum" in joined, joined
    assert "the heartbeat is DISABLED" in joined, joined
    assert "heartbeat DISABLED" in joined, joined
    # and it STARTED -- the whole point of the finding
    assert "started —" in joined, joined


def check_f1_a_negative_cadence_is_named_and_leaves_it_off() -> None:
    # -1 used to start and silently disable. It still disables -- and now says so.
    lines = _hb_startup_lines("-1")
    joined = "\n".join(lines)
    assert "is negative (use 0 to disable, not -1)" in joined, joined
    assert "the heartbeat is DISABLED" in joined, joined
    assert "started —" in joined, joined


def check_f1_the_heartbeat_is_OFF_unless_a_positive_integer_asks_for_it() -> None:
    # unset: off, and the line says how to turn it on
    unset = "\n".join(_hb_startup_lines(None))
    assert "heartbeat DISABLED (default)" in unset, unset
    assert "set MICA_ALERTER_HEARTBEAT_POLLS to a positive integer" in unset, unset
    # 0: off
    assert "heartbeat DISABLED" in "\n".join(_hb_startup_lines("0"))
    # a bad string: named, and off
    bad = "\n".join(_hb_startup_lines("bad"))
    assert "is not an integer" in bad, bad
    assert "the heartbeat is DISABLED" in bad, bad
    # ⛔ AND A POSITIVE INTEGER STILL ENABLES IT, with the seconds estimate as an
    #    int -- the arithmetic half of finding 2 must survive the ruling.
    on = "\n".join(_hb_startup_lines("60"))
    assert "heartbeat every 60 poll(s) (~1800s)" in on, on


def check_f2_a_raising_log_sink_does_not_stop_the_polling_loop() -> None:
    """Codex F2: an OSError raised only for the `alive —` line reached polls=1."""
    env_backup = dict(os.environ)
    real_poll = alerter.poll_once
    real_log = alerter.log
    real_sleep = time.sleep
    polls = [0]
    fallbacks: list[str] = []

    class _Enough(Exception):
        pass

    try:
        os.environ.update(
            {
                "MICA_BRIDGE_SOCKET": "/tmp/mica-alerter-no-such.sock",
                "MICA_ALERTER_POLL_SECONDS": "30",
                "MICA_ALERTER_STATE_DIR": tempfile.mkdtemp(prefix="hb-f2-"),
                "MICA_ALERTER_MAX_PER_MINUTE": "6",
                "MICA_ALERTER_TRANSPORT": "stdout",
                "MICA_ALERTER_HEARTBEAT_POLLS": "1",
            }
        )

        def _counting_poll(*_a, **_k):
            polls[0] += 1
            if polls[0] >= 4:
                raise _Enough()
            return False

        def _hostile_log(msg: str) -> None:
            if "alive —" in msg:
                raise OSError("injected log sink failure")
            if "heartbeat line failed" in msg:
                fallbacks.append(msg)

        alerter.poll_once = _counting_poll  # type: ignore[assignment]
        alerter.log = _hostile_log  # type: ignore[assignment]
        time.sleep = lambda _s: None  # type: ignore[assignment]
        try:
            alerter.main(["--dry-run"])
        except _Enough:
            pass
    finally:
        alerter.poll_once = real_poll  # type: ignore[assignment]
        alerter.log = real_log  # type: ignore[assignment]
        time.sleep = real_sleep  # type: ignore[assignment]
        os.environ.clear()
        os.environ.update(env_backup)

    # ⛔ THE WHOLE POINT: the loop kept polling through a heartbeat that raised.
    assert polls[0] >= 4, f"the loop stopped after {polls[0]} poll(s)"
    # ⚠ AND THE FALLBACK COUNT IS DELIBERATELY NOT ASSERTED ANY MORE. The first
    #   version of this check required one "heartbeat line failed" line per failed
    #   heartbeat -- which encoded the MECHANISM of the first repair (a loop-side
    #   try/except) rather than the FINDING (the loop must keep polling). Once the
    #   write moved to the bounded sink's drain thread the loop stopped writing at
    #   all, the raise happened off-loop, and this assertion failed on a STRICTLY
    #   BETTER implementation. A test that pins how a thing is done fails when it
    #   is done better; the finding is what belongs here.
    assert isinstance(fallbacks, list), fallbacks


def check_f3_the_tail_is_chosen_from_state_and_never_contradicts_the_line() -> None:
    clock = [10.0]
    rl = alerter.RateLimiter(6, now_fn=lambda: clock[0])

    # a poll that moved the cursor: the line must not claim nothing happened
    t = alerter.HeartbeatTicker(1, now_fn=lambda: clock[0])
    t.note_poll(True)
    changed = t.line({"afterSeq": 678}, rl)
    assert "0 poll(s) since anything changed" in changed, changed
    assert "cursor just moved" in changed, changed
    assert "Nothing needed saying" not in changed, changed

    # ⛔ AND THE FALSE BRANCH MUST SPEAK ONLY ABOUT THE CURSOR. Codex,
    #    heartbeat-2 finding 3: `changed` is the PERSISTED-CURSOR bit, and a send
    #    that failed or that the limiter refused breaks without setting it — so the
    #    word "Idle" could describe a poll with a pending alert. The tail may claim
    #    liveness and cursor stillness; it may NOT claim idleness.
    t2 = alerter.HeartbeatTicker(1, now_fn=lambda: clock[0])
    t2.note_poll(False)
    idle = t2.line({"afterSeq": 678}, rl)
    assert "1 poll(s) since anything changed" in idle, idle
    assert "No cursor movement" in idle, idle
    assert "cursor just moved" not in idle, idle
    # the adjective the finding was about, in any casing, must be gone
    assert "idle" not in idle.lower(), idle
    # and it must say so explicitly, so a reader is not left to infer it
    assert "does not move the cursor" in idle, idle


def check_a2_an_unbounded_poll_interval_is_refused_not_overflowed() -> None:
    """Codex, heartbeat-2 finding 2: 1e308 x a legal cadence overflowed at startup."""
    env_backup = dict(os.environ)
    try:
        # ⚠ `nan` lands on the FINITE check, not on `> 0`: `nan <= 0` is False, so
        #    it falls through. The code is right and this expectation was wrong on
        #    its first draft — NaN is refused, with the accurate reason.
        for raw_value, expect in (("1e308", "exceeds"), ("inf", "is not finite"), ("nan", "is not finite")):
            os.environ["MICA_ALERTER_POLL_SECONDS"] = raw_value
            try:
                alerter.require_env_float("MICA_ALERTER_POLL_SECONDS")
                raise AssertionError(f"{raw_value!r} should have been refused")
            except alerter.ConfigError as e:
                assert expect in str(e), f"{raw_value!r}: {e}"
        # and an ordinary interval still passes, untouched
        os.environ["MICA_ALERTER_POLL_SECONDS"] = "30"
        assert alerter.require_env_float("MICA_ALERTER_POLL_SECONDS") == 30.0
    finally:
        os.environ.clear()
        os.environ.update(env_backup)


def check_a2_the_startup_estimate_cannot_overflow_at_both_bounds() -> None:
    # ⛔ THE PRODUCT, not one factor of it. The first repair bounded hb_every and
    #    its own comment claimed the multiply "cannot overflow"; the other factor
    #    was unbounded. Both are bounded now, so assert the product at the corner.
    worst = alerter.HEARTBEAT_POLLS_MAX * alerter.ENV_FLOAT_MAX
    assert math.isfinite(worst), worst
    assert isinstance(round(worst), int), worst


def check_a1_a_STALLED_sink_does_not_delay_the_polling_loop() -> None:
    """Codex, heartbeat-2 finding 1: a sink sleeping 0.45s delayed the next poll by 0.45s.

    A blocking sink does not raise, so no `except` can catch it. This asserts the
    loop's own pace is unaffected -- the measurement Codex took, inverted.
    """
    env_backup = dict(os.environ)
    real_poll = alerter.poll_once
    real_log = alerter.log
    real_sleep = time.sleep
    stamps: list[float] = []
    STALL = 0.6

    class _Enough(Exception):
        pass

    try:
        os.environ.update(
            {
                "MICA_BRIDGE_SOCKET": "/tmp/mica-alerter-no-such.sock",
                "MICA_ALERTER_POLL_SECONDS": "30",
                "MICA_ALERTER_STATE_DIR": tempfile.mkdtemp(prefix="hb-a1-"),
                "MICA_ALERTER_MAX_PER_MINUTE": "6",
                "MICA_ALERTER_TRANSPORT": "stdout",
                "MICA_ALERTER_HEARTBEAT_POLLS": "1",
            }
        )

        def _timed_poll(*_a, **_k):
            stamps.append(time.monotonic())
            if len(stamps) >= 4:
                raise _Enough()
            return False

        def _stalling_log(msg: str) -> None:
            if "alive" in msg:
                real_sleep(STALL)

        alerter.poll_once = _timed_poll  # type: ignore[assignment]
        alerter.log = _stalling_log  # type: ignore[assignment]
        time.sleep = lambda _s: None  # type: ignore[assignment]
        try:
            alerter.main(["--dry-run"])
        except _Enough:
            pass
    finally:
        alerter.poll_once = real_poll  # type: ignore[assignment]
        alerter.log = real_log  # type: ignore[assignment]
        time.sleep = real_sleep  # type: ignore[assignment]
        os.environ.clear()
        os.environ.update(env_backup)

    assert len(stamps) >= 4, f"the loop reached only {len(stamps)} poll(s)"
    gaps = [b - a for a, b in zip(stamps, stamps[1:])]
    worst = max(gaps)
    # ⛔ THE NUMBER THAT MATTERS. Every heartbeat here stalls for 0.6s on a cadence
    #    of 1, so under the old inline write EVERY gap would be >= 0.6s. Off the
    #    loop, the gaps are bounded by the test's own no-op sleep.
    assert worst < STALL / 2, f"a stalled sink delayed the loop: gaps={gaps}"


def check_a1_the_sink_is_bounded_and_counts_what_it_drops() -> None:
    """A full queue must drop and COUNT, never block and never raise."""
    gate = threading.Event()
    written: list[str] = []

    def _blocked_write(msg: str) -> None:
        gate.wait(5.0)
        written.append(msg)

    sink = alerter.HeartbeatSink(_blocked_write, maxsize=2)
    try:
        # the drain takes one and blocks on it; the queue then holds at most 2
        accepted = [sink.put(f"line {i}") for i in range(12)]
        assert accepted[0] is True, accepted
        assert any(a is False for a in accepted), f"a bounded queue must refuse: {accepted}"
        assert sink.dropped() > 0, sink.dropped()
        # put() never blocks: twelve calls against a stalled writer returned at once
        assert sink.alive(), "the drain thread must still be alive"
    finally:
        gate.set()


def check_a1_a_dead_drain_is_reported_rather_than_silent() -> None:
    """⛔ A dead drain must not become the silence the heartbeat exists to break."""
    sink = alerter.HeartbeatSink(lambda _m: None, maxsize=4)
    sink._thread.join(0)  # noqa: SLF001 - deliberate: inspect the real thread
    assert sink.alive(), "sanity: the drain should be running"
    # simulate the thread being gone
    sink._thread = threading.Thread(target=lambda: None)  # noqa: SLF001
    sink._thread.start()
    sink._thread.join()
    assert not sink.alive(), "the stand-in thread should have exited"
    assert sink.put("x") is False, "a dead drain must REPORT, not accept"
    assert sink.dropped() == 1, sink.dropped()


def check_a1_the_drop_count_rides_the_next_line_that_gets_through() -> None:
    seen: list[str] = []
    gate = threading.Event()

    def _write(msg: str) -> None:
        gate.wait(5.0)
        seen.append(msg)

    sink = alerter.HeartbeatSink(_write, maxsize=1)
    sink.put("first")          # taken by the drain, which blocks
    while sink.dropped() == 0:  # fill and overflow
        if not sink.put("filler"):
            break
    assert sink.dropped() > 0, "expected at least one drop"
    gate.set()
    for _ in range(100):       # let the drain empty
        if not sink._q.unfinished_tasks:  # noqa: SLF001
            break
        time.sleep(0.01)
    dropped_then = sink.dropped()
    assert sink.put("after the drops") is True
    time.sleep(0.2)
    carried = [m for m in seen if "after the drops" in m]
    assert carried, f"the line after a drop must get through: {seen}"
    assert f"{dropped_then} heartbeat line(s) dropped" in carried[0], carried[0]


def _loop_with_sink(make_sink, polls_wanted: int = 4):
    """Drive main()'s loop with a chosen HeartbeatSink, recording WHO logs what.

    ⛔ The rule is about the POLL LOOP's thread. So every log call records the
       thread that made it: the loop is MainThread, the drain is named
       `mica-alerter-heartbeat`. A heartbeat line logged from MainThread is an
       inline write, which is what Codex FAILED Heartbeat-3 for.
    """
    env_backup = dict(os.environ)
    real_poll = alerter.poll_once
    real_log = alerter.log
    real_sink = alerter.HeartbeatSink
    real_sleep = time.sleep
    stamps: list[float] = []
    logged: list[tuple[str, str]] = []
    STALL = 0.6

    class _Enough(Exception):
        pass

    try:
        os.environ.update(
            {
                "MICA_BRIDGE_SOCKET": "/tmp/mica-alerter-no-such.sock",
                "MICA_ALERTER_POLL_SECONDS": "30",
                "MICA_ALERTER_STATE_DIR": tempfile.mkdtemp(prefix="hb-h4-"),
                "MICA_ALERTER_MAX_PER_MINUTE": "6",
                "MICA_ALERTER_TRANSPORT": "stdout",
                "MICA_ALERTER_HEARTBEAT_POLLS": "1",
            }
        )

        def _timed_poll(*_a, **_k):
            stamps.append(time.monotonic())
            if len(stamps) >= polls_wanted:
                raise _Enough()
            return False

        def _recording_log(msg: str) -> None:
            logged.append((threading.current_thread().name, msg))
            if "] alive" in msg or "heartbeat line could not be built" in msg:
                real_sleep(STALL)

        alerter.poll_once = _timed_poll  # type: ignore[assignment]
        alerter.log = _recording_log  # type: ignore[assignment]
        alerter.HeartbeatSink = make_sink  # type: ignore[assignment]
        time.sleep = lambda _s: None  # type: ignore[assignment]
        try:
            alerter.main(["--dry-run"])
        except _Enough:
            pass
    finally:
        alerter.poll_once = real_poll  # type: ignore[assignment]
        alerter.log = real_log  # type: ignore[assignment]
        alerter.HeartbeatSink = real_sink  # type: ignore[assignment]
        time.sleep = real_sleep  # type: ignore[assignment]
        os.environ.clear()
        os.environ.update(env_backup)

    gaps = [b - a for a, b in zip(stamps, stamps[1:])]
    # ⛔ A BEAT, not every line containing the word. The first version of this
    #    filter matched "heartbeat" and caught the STARTUP CADENCE LINE
    #    ("heartbeat every 1 poll(s) (~30s)"), which MainThread logs legitimately
    #    before the loop begins. A detector that cannot tell the beat from the
    #    sentence announcing the beat is the shape this whole file is about.
    def _is_beat(m: str) -> bool:
        return "] alive" in m or "heartbeat line could not be built" in m
    from_loop = [m for who, m in logged if who == "MainThread" and _is_beat(m)]
    return stamps, gaps, from_loop, STALL


def check_h4_a_FULL_QUEUE_neither_writes_on_the_loop_nor_delays_it() -> None:
    gate = threading.Event()
    # ⛔ CAPTURE THE REAL CLASS FIRST. `_loop_with_sink` PATCHES
    #    `alerter.HeartbeatSink` to this factory, so referring to
    #    `alerter.HeartbeatSink` inside it calls the factory again — the first
    #    version of this test died on "maximum recursion depth exceeded".
    real_class = alerter.HeartbeatSink

    def make(write, maxsize=1):  # noqa: ARG001 - the bound is the point
        def _blocked(m: str) -> None:
            gate.wait(30.0)
            write(m)

        return real_class(_blocked, maxsize=1)

    try:
        stamps, gaps, from_loop, STALL = _loop_with_sink(make)
    finally:
        gate.set()
    assert len(stamps) >= 4, f"the loop reached only {len(stamps)} poll(s)"
    assert from_loop == [], f"a heartbeat line was written ON THE LOOP: {from_loop}"
    assert max(gaps) < STALL / 2, f"a full queue delayed the loop: gaps={gaps}"


def check_h4_a_DEAD_DRAIN_neither_writes_on_the_loop_nor_delays_it() -> None:
    class _DeadDrain(alerter.HeartbeatSink):
        """A sink whose drain is gone and cannot come back.

        Neutering `_revive` is deliberate: the production class repairs a dead
        drain, and this holds the UNREPAIRED state so the rule can be tested at
        its worst -- every beat refused, forever.
        """

        def __init__(self, write, maxsize=16):
            super().__init__(write, maxsize=maxsize)
            self._thread = threading.Thread(target=lambda: None)
            self._thread.start()
            self._thread.join()

        def _revive(self) -> None:
            return None

    stamps, gaps, from_loop, STALL = _loop_with_sink(_DeadDrain)
    assert len(stamps) >= 4, f"the loop reached only {len(stamps)} poll(s)"
    assert from_loop == [], f"a heartbeat line was written ON THE LOOP: {from_loop}"
    assert max(gaps) < STALL / 2, f"a dead drain delayed the loop: gaps={gaps}"


def check_h4_a_dead_drain_is_revived_so_the_count_can_be_carried() -> None:
    """The rule says the NEXT beat carries the count — which needs a next beat."""
    seen: list[str] = []
    sink = alerter.HeartbeatSink(seen.append, maxsize=8)
    # kill the drain without telling the sink
    sink._thread = threading.Thread(target=lambda: None)  # noqa: SLF001
    sink._thread.start()
    sink._thread.join()
    assert not sink.alive(), "sanity: the stand-in thread has exited"

    assert sink.put("dropped one") is False, "a dead drain must refuse"
    assert sink.dropped() == 1, sink.dropped()
    # ⛔ and it must have been REPAIRED, or the count is carried by nothing
    for _ in range(200):
        if sink.alive():
            break
        time.sleep(0.01)
    assert sink.alive(), "a dead drain must be revived, or the count never gets out"

    assert sink.put("the next beat") is True
    for _ in range(200):
        if any("the next beat" in m for m in seen):
            break
        time.sleep(0.01)
    carried = [m for m in seen if "the next beat" in m]
    assert carried, f"the next beat must get through: {seen}"
    assert "1 heartbeat line(s) dropped before this one" in carried[0], carried[0]
    assert "drain revived 1x" in carried[0], carried[0]


def main() -> int:
    check("fresh cursor emits latest non-neutral event once, then tails", check_fresh_cursor_emits_latest_once_then_tails)
    check("fresh cursor on an empty book emits nothing and primes to 0", check_fresh_cursor_on_empty_book_emits_nothing)
    check("cursor never advances past an unsent event; recovers in order", check_cursor_never_advances_past_unsent_event)
    check("rate limit delays delivery rather than dropping events", check_rate_limit_delays_rather_than_drops)
    check("unknown / briefed-but-unproduced event kinds are reported verbatim", check_unknown_event_kind_reported_verbatim)
    check("LATCHED / LATCH_CLEARED branches exist, unreachable, self-documenting", check_latched_and_latch_cleared_are_unreachable_but_present)
    check("DISPOSITION_CHANGED renders the disposition word itself, not just the kind", check_disposition_changed_renders_disposition_word)
    check("SERVICE_STARTED reaches the generic branch with its restart sentence intact", check_service_started_reaches_the_generic_branch)
    check("relay.markerPresent false->true fires exactly one alert, no re-fire while true", check_relay_marker_edge_triggers_once)
    check("Telegram token never appears in any output, including on error", check_token_never_appears_in_any_output)
    check("a BaseException from the poster is redacted before propagating (Amendment 3, finding 5)", check_base_exception_from_poster_is_redacted_before_propagating)
    check("--dry-run transport never calls Telegram", check_dry_run_sends_nothing_to_telegram)
    check("required env vars are refused by name, not defaulted", check_required_env_vars_refuse_to_start_by_name)
    check("corrupt cursor shapes are never trusted silently (Amendment 1, finding 1)", check_corrupt_cursor_shapes_are_never_trusted_silently)
    check("an impossible cursor is caught live against the bridge's lastSeq (Amendment 1, finding 1)", check_impossible_cursor_is_caught_live_against_the_bridge)
    check("a cursor file missing a key is logged, not silently accepted (Amendment 2, gap 1)", check_missing_cursor_keys_are_logged_not_silently_accepted)
    check("an in-range but nonexistent cursor seq is caught live (Amendment 2, gap 2)", check_impossible_cursor_nonexistent_in_range_seq_is_caught)
    check("at-least-once: an event duplicate carries the same seq (Amendment 1, finding 3)", check_at_least_once_event_duplicate_carries_same_seq)
    check("at-least-once: a marker duplicate carries the same transition id (Amendment 1, finding 3)", check_at_least_once_marker_duplicate_carries_same_transition_id)
    check("marker transition id distinguishes separate identical incidents (Amendment 3, finding 4)", check_marker_transition_id_distinguishes_separate_identical_incidents)
    check("mica-alerter.py is committed executable, mode 100755 (Amendment 1, finding 4)", check_script_is_committed_executable)
    check("a placeholder chat id is refused by name, not silently started (Amendment 1, finding 6)", check_placeholder_chat_id_is_refused_by_name)

    check("a run of identical events sends the FIRST and counts the rest", check_identical_run_sends_the_first_and_counts_the_rest)
    check("a different event flushes the run summary first, in order", check_a_different_event_flushes_the_run_first_in_order)
    check("a run of one produces no summary", check_a_run_of_one_produces_no_summary)
    check("a run that STOPS still reports itself (the honest arm)", check_a_run_that_stops_still_reports_itself)
    check("run_key splits on every describing field, not on seq", check_run_key_splits_on_every_describing_field)
    check("heartbeat: due only every Nth poll", check_heartbeat_fires_only_every_nth_poll)
    check("heartbeat: 0 disables it entirely", check_heartbeat_zero_disables_and_says_nothing)
    check("heartbeat: quiet polls counted, reset by a change", check_heartbeat_counts_quiet_polls_and_resets_on_change)
    check("heartbeat: the line names cursor, quiet duration and the EVICTED window depth", check_heartbeat_line_names_what_distinguishes_alive_from_dead)
    check("heartbeat: a full window reads 6/6 and is really refusing", check_heartbeat_line_shows_a_full_window_when_it_is_full)
    check("heartbeat: the 968-poll silence from the journal now leaves 16 lines", check_heartbeat_distinguishes_the_968_poll_silence)
    check("F1: an unbounded cadence is named and defaulted, not a startup crash", check_f1_an_unbounded_cadence_no_longer_crashes_startup)
    check("F1: a negative cadence is NAMED and leaves the heartbeat off", check_f1_a_negative_cadence_is_named_and_leaves_it_off)
    check("F1: the heartbeat is OFF unless a positive integer asks for it", check_f1_the_heartbeat_is_OFF_unless_a_positive_integer_asks_for_it)
    check("F2: a raising log sink does NOT stop the polling loop", check_f2_a_raising_log_sink_does_not_stop_the_polling_loop)
    check("F3: the tail is chosen from state and never contradicts the line", check_f3_the_tail_is_chosen_from_state_and_never_contradicts_the_line)
    check("A2: an unbounded or non-finite poll interval is REFUSED, not overflowed", check_a2_an_unbounded_poll_interval_is_refused_not_overflowed)
    check("A2: the startup estimate cannot overflow at BOTH bounds, not just one", check_a2_the_startup_estimate_cannot_overflow_at_both_bounds)
    check("A1: a STALLED sink does not delay the polling loop", check_a1_a_STALLED_sink_does_not_delay_the_polling_loop)
    check("A1: the sink is BOUNDED and counts what it drops", check_a1_the_sink_is_bounded_and_counts_what_it_drops)
    check("A1: a dead drain is REPORTED rather than silent", check_a1_a_dead_drain_is_reported_rather_than_silent)
    check("A1: the drop count rides the next line that gets through", check_a1_the_drop_count_rides_the_next_line_that_gets_through)
    check("H4: a FULL QUEUE neither writes on the loop nor delays it", check_h4_a_FULL_QUEUE_neither_writes_on_the_loop_nor_delays_it)
    check("H4: a DEAD DRAIN neither writes on the loop nor delays it", check_h4_a_DEAD_DRAIN_neither_writes_on_the_loop_nor_delays_it)
    check("H4: a dead drain is revived so the count can be carried", check_h4_a_dead_drain_is_revived_so_the_count_can_be_carried)

    print(f"CENSUS: {passed} passed, {failed} failed, {passed + failed} total")
    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
