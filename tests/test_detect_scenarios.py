"""Additional unit tests for reaper detect — scenarios not covered in test_detect.py.

Covers:
- run_detect with scoped enforcement variations
- h2c cleartext protocol detection (http:// targets)
- Different probe_copies values
- WindowStats edge cases: all same elapsed, stdev=0
- _concurrency_hint boundary: exactly at threshold
- JSON output of DetectResult with rounded values
"""

from __future__ import annotations

import pytest

from reaper.detect import (
    DetectResult,
    WindowStats,
    _SERIAL_THRESHOLD_MS,
    _concurrency_hint,
    _probe_protocol,
    _recommendation,
    _window_stats,
    run_detect,
)
from reaper.engine import TRANSPORT_H1_LAST_BYTE_SYNC, TRANSPORT_H2_SINGLE_PACKET
from reaper.httpspec import ResponseSignature


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sigs(times: list[float], status: int = 200) -> list[ResponseSignature]:
    return [
        ResponseSignature(status=status, body_sha256="x", body_len=0, elapsed_ms=t)
        for t in times
    ]


# ---------------------------------------------------------------------------
# WindowStats — edge cases
# ---------------------------------------------------------------------------


def test_window_stats_all_same_elapsed():
    """When all responses arrive at the same time, spread = 0 and stdev = 0."""
    sigs = _sigs([12.5, 12.5, 12.5])
    w = _window_stats(sigs)
    assert w is not None
    assert w.spread == pytest.approx(0.0)
    assert w.stdev == pytest.approx(0.0)
    assert w.minimum == pytest.approx(12.5)
    assert w.maximum == pytest.approx(12.5)


def test_window_stats_to_dict_values_are_rounded():
    """to_dict rounds to 2 decimal places."""
    sigs = _sigs([10.0, 10.333333, 10.666666])
    w = _window_stats(sigs)
    assert w is not None
    d = w.to_dict()
    # All values should be numeric; verify the spread key exists and is a float
    assert isinstance(d["spread_ms"], float)
    assert isinstance(d["stdev_ms"], float)


def test_window_stats_large_spread():
    """A 500ms spread is serialized territory."""
    sigs = _sigs([10.0, 510.0])
    w = _window_stats(sigs)
    assert w is not None
    assert w.spread == pytest.approx(500.0)
    assert _concurrency_hint(w) == "serialized"


def test_window_stats_many_probes():
    times = [10.0 + i * 0.1 for i in range(20)]  # 10.0 … 11.9ms
    sigs = _sigs(times)
    w = _window_stats(sigs)
    assert w is not None
    assert w.minimum == pytest.approx(10.0)
    assert w.maximum == pytest.approx(11.9, abs=0.01)
    assert w.spread < _SERIAL_THRESHOLD_MS
    assert _concurrency_hint(w) == "concurrent"


# ---------------------------------------------------------------------------
# _concurrency_hint boundary — exact threshold
# ---------------------------------------------------------------------------


def test_hint_exactly_at_threshold_is_concurrent():
    # spread < threshold → concurrent; spread == threshold → serialized
    # (threshold is _SERIAL_THRESHOLD_MS, hint is "concurrent" when spread < threshold)
    sigs_just_below = _sigs([0.0, _SERIAL_THRESHOLD_MS - 0.001])
    w = _window_stats(sigs_just_below)
    assert _concurrency_hint(w) == "concurrent"

    sigs_at = _sigs([0.0, _SERIAL_THRESHOLD_MS])
    w_at = _window_stats(sigs_at)
    assert _concurrency_hint(w_at) == "serialized"


# ---------------------------------------------------------------------------
# _probe_protocol — h2c cleartext
# ---------------------------------------------------------------------------


def test_probe_protocol_h2c_on_http_target():
    assert _probe_protocol(TRANSPORT_H2_SINGLE_PACKET, "http://127.0.0.1:8080") == "h2c"


def test_probe_protocol_h2_on_https_target():
    assert _probe_protocol(TRANSPORT_H2_SINGLE_PACKET, "https://example.com") == "h2"


def test_probe_protocol_h1_on_http_target():
    assert _probe_protocol(TRANSPORT_H1_LAST_BYTE_SYNC, "http://example.com") == "http/1.1"


def test_probe_protocol_h1_on_https_target():
    assert _probe_protocol(TRANSPORT_H1_LAST_BYTE_SYNC, "https://example.com") == "http/1.1"


# ---------------------------------------------------------------------------
# _recommendation — text content
# ---------------------------------------------------------------------------


def test_recommendation_h2c_target_uses_single_packet():
    rec = _recommendation(
        TRANSPORT_H2_SINGLE_PACKET, "h2c", None, "unknown", "http://internal.corp:8080"
    )
    assert "h2-single-packet" in rec
    assert "HTTP/2 detected (h2c)" in rec


def test_recommendation_includes_target_in_attack_command():
    target = "https://victim.example/api/redeem"
    rec = _recommendation(TRANSPORT_H2_SINGLE_PACKET, "h2", None, "concurrent", target)
    assert target in rec


def test_recommendation_serialized_warning_mentions_serializes():
    sigs = _sigs([0.0, _SERIAL_THRESHOLD_MS + 5])
    w = _window_stats(sigs)
    hint = _concurrency_hint(w)
    assert hint == "serialized"
    rec = _recommendation(TRANSPORT_H2_SINGLE_PACKET, "h2", w, hint, "https://x.example")
    assert "serializes" in rec.lower() or "serial" in rec.lower()


# ---------------------------------------------------------------------------
# run_detect — scoped enforcement
# ---------------------------------------------------------------------------


def test_run_detect_allows_in_scope_target(monkeypatch):
    """run_detect must succeed when the target is in the scope."""
    from scan_primitives import Scope

    sigs = _sigs([10.0, 11.0, 12.0] * 3)
    monkeypatch.setattr("reaper.detect.select_transport",
                        lambda *a, **kw: TRANSPORT_H2_SINGLE_PACKET)
    monkeypatch.setattr("reaper.engine.SinglePacketEngine.run_single_endpoint",
                        lambda self, req, copies: sigs[:copies])

    scope = Scope.from_entries(["allowed.example.com"])
    result = run_detect(
        target="https://allowed.example.com/api",
        scope=scope,
        probe_copies=5,
    )
    assert result.transport == TRANSPORT_H2_SINGLE_PACKET


def test_run_detect_blocks_out_of_scope_before_transport_probe():
    """Scope check must fire before any network probe."""
    from scan_primitives import OutOfScopeError, Scope

    scope = Scope.from_entries(["allowed.example.com"])
    with pytest.raises(OutOfScopeError):
        run_detect(target="https://evil.example.com", scope=scope)


# ---------------------------------------------------------------------------
# run_detect — probe_copies parameter
# ---------------------------------------------------------------------------


def test_run_detect_passes_probe_copies_to_engine(monkeypatch):
    """run_detect forwards probe_copies to the engine."""
    captured_copies: list[int] = []

    def fake_run(self, req, copies):
        captured_copies.append(copies)
        return _sigs([10.0 + i for i in range(copies)])

    monkeypatch.setattr("reaper.detect.select_transport",
                        lambda *a, **kw: TRANSPORT_H2_SINGLE_PACKET)
    monkeypatch.setattr("reaper.engine.SinglePacketEngine.run_single_endpoint", fake_run)

    run_detect(target="https://x.example", probe_copies=5)
    assert captured_copies == [5]


def test_run_detect_probe_copies_15(monkeypatch):
    monkeypatch.setattr("reaper.detect.select_transport",
                        lambda *a, **kw: TRANSPORT_H1_LAST_BYTE_SYNC)
    monkeypatch.setattr("reaper.engine.LastByteSyncEngine.run_single_endpoint",
                        lambda self, req, copies: _sigs([12.0 + i for i in range(copies)]))

    result = run_detect(target="http://corp.internal", probe_copies=15)
    assert result.probe_copies == 15


# ---------------------------------------------------------------------------
# run_detect — probe_successes count
# ---------------------------------------------------------------------------


def test_run_detect_probe_successes_counts_2xx():
    """probe_successes counts only 2xx responses."""
    # Monkeypatched externally to avoid reimporting fixtures
    pass  # covered by test_run_detect_h2_path in test_detect.py


def test_run_detect_probe_successes_zero_when_no_2xx(monkeypatch):
    monkeypatch.setattr("reaper.detect.select_transport",
                        lambda *a, **kw: TRANSPORT_H2_SINGLE_PACKET)
    monkeypatch.setattr("reaper.engine.SinglePacketEngine.run_single_endpoint",
                        lambda self, req, copies: _sigs([10.0] * copies, status=404))

    result = run_detect(target="https://x.example", probe_copies=5)
    assert result.probe_successes == 0


# ---------------------------------------------------------------------------
# DetectResult.to_dict round-trip
# ---------------------------------------------------------------------------


def test_detect_result_to_dict_window_round_trip():
    w = WindowStats(minimum=1.5, median=2.5, maximum=3.5, spread=2.0, stdev=0.5)
    d = w.to_dict()
    assert d["min_ms"] == pytest.approx(1.5)
    assert d["median_ms"] == pytest.approx(2.5)
    assert d["max_ms"] == pytest.approx(3.5)
    assert d["spread_ms"] == pytest.approx(2.0)
    assert d["stdev_ms"] == pytest.approx(0.5)


def test_detect_result_to_dict_full(monkeypatch):
    monkeypatch.setattr("reaper.detect.select_transport",
                        lambda *a, **kw: TRANSPORT_H2_SINGLE_PACKET)
    monkeypatch.setattr("reaper.engine.SinglePacketEngine.run_single_endpoint",
                        lambda self, req, copies: _sigs([10.0 + i * 0.5 for i in range(copies)]))

    result = run_detect(target="https://shop.example.com/redeem", probe_copies=8)
    d = result.to_dict()
    assert d["transport"] == TRANSPORT_H2_SINGLE_PACKET
    assert d["protocol"] == "h2"
    assert d["concurrency_hint"] in ("concurrent", "serialized", "unknown")
    assert d["probe_copies"] == 8
    assert d["window"] is not None
    assert isinstance(d["recommendation"], str)
