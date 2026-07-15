"""Unit tests for ``reaper detect`` -- no network required.

Tests the pure-logic helpers (WindowStats, _window_stats, _concurrency_hint,
_recommendation) and the CLI argument plumbing. ``run_detect`` network paths
are exercised by monkeypatching ``select_transport`` and the engine.
"""

from __future__ import annotations

import json
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
from reaper.httpspec import ResponseSignature


# ---------------------------------------------------------------------------
# WindowStats helpers
# ---------------------------------------------------------------------------


def _make_sigs(elapsed_ms_list: list[float]) -> list[ResponseSignature]:
    return [
        ResponseSignature(status=200, body_sha256="abc", body_len=3, elapsed_ms=t)
        for t in elapsed_ms_list
    ]


def test_window_stats_basic():
    sigs = _make_sigs([10.0, 12.0, 11.0, 13.0, 10.5])
    w = _window_stats(sigs)
    assert w is not None
    assert w.minimum == pytest.approx(10.0)
    assert w.maximum == pytest.approx(13.0)
    assert w.spread == pytest.approx(3.0)
    assert w.median == pytest.approx(11.0)


def test_window_stats_none_for_single_sig():
    assert _window_stats(_make_sigs([10.0])) is None


def test_window_stats_none_for_empty():
    assert _window_stats([]) is None


def test_window_stats_two_sigs():
    sigs = _make_sigs([5.0, 15.0])
    w = _window_stats(sigs)
    assert w is not None
    assert w.minimum == 5.0
    assert w.maximum == 15.0
    assert w.spread == 10.0
    assert w.median == pytest.approx(10.0)


def test_window_stats_to_dict_keys():
    sigs = _make_sigs([10.0, 20.0])
    d = _window_stats(sigs).to_dict()
    assert set(d.keys()) == {"min_ms", "median_ms", "max_ms", "spread_ms", "stdev_ms"}


# ---------------------------------------------------------------------------
# _concurrency_hint
# ---------------------------------------------------------------------------


def test_hint_concurrent_tight_spread():
    sigs = _make_sigs([10.0, 11.0, 12.0])
    w = _window_stats(sigs)
    assert _concurrency_hint(w) == "concurrent"


def test_hint_serialized_large_spread():
    sigs = _make_sigs([10.0, 10.0 + _SERIAL_THRESHOLD_MS + 1])
    w = _window_stats(sigs)
    assert _concurrency_hint(w) == "serialized"


def test_hint_unknown_for_none():
    assert _concurrency_hint(None) == "unknown"


def test_hint_boundary_is_concurrent():
    # exactly at threshold → concurrent (< not <=)
    sigs = _make_sigs([0.0, _SERIAL_THRESHOLD_MS - 0.001])
    w = _window_stats(sigs)
    assert _concurrency_hint(w) == "concurrent"


# ---------------------------------------------------------------------------
# _probe_protocol
# ---------------------------------------------------------------------------


def test_probe_protocol_h2_https():
    assert _probe_protocol("h2-single-packet", "https://example.com") == "h2"


def test_probe_protocol_h2c_http():
    assert _probe_protocol("h2-single-packet", "http://127.0.0.1:8080") == "h2c"


def test_probe_protocol_h1():
    assert _probe_protocol("h1-last-byte-sync", "https://example.com") == "http/1.1"


# ---------------------------------------------------------------------------
# _recommendation
# ---------------------------------------------------------------------------


def test_recommendation_h2_concurrent(capsys):
    sigs = _make_sigs([10.0, 11.0])
    w = _window_stats(sigs)
    hint = _concurrency_hint(w)
    rec = _recommendation("h2-single-packet", "h2", w, hint, "https://example.com")
    assert "HTTP/2 detected (h2)" in rec
    assert "single-packet attack available" in rec
    assert "h2-single-packet" in rec
    assert "serialized" not in rec


def test_recommendation_h2_serialized_includes_warning():
    sigs = _make_sigs([0.0, _SERIAL_THRESHOLD_MS + 10])
    w = _window_stats(sigs)
    hint = _concurrency_hint(w)
    rec = _recommendation("h2-single-packet", "h2", w, hint, "https://example.com")
    assert "serializes" in rec


def test_recommendation_h1():
    rec = _recommendation("h1-last-byte-sync", "http/1.1", None, "unknown", "http://x.example")
    assert "HTTP/1.1 only" in rec
    assert "h1-last-byte-sync" in rec


def test_recommendation_no_window():
    rec = _recommendation("h2-single-packet", "h2", None, "unknown", "https://x.example")
    assert "no responses received" in rec


# ---------------------------------------------------------------------------
# DetectResult.to_dict
# ---------------------------------------------------------------------------


def test_detect_result_to_dict_with_window():
    w = WindowStats(minimum=5.0, median=7.5, maximum=10.0, spread=5.0, stdev=1.5)
    result = DetectResult(
        transport="h2-single-packet",
        protocol="h2",
        window=w,
        concurrency_hint="concurrent",
        probe_copies=10,
        probe_successes=8,
        recommendation="do the thing",
    )
    d = result.to_dict()
    assert d["transport"] == "h2-single-packet"
    assert d["protocol"] == "h2"
    assert d["window"]["spread_ms"] == pytest.approx(5.0)
    assert d["concurrency_hint"] == "concurrent"
    assert d["probe_copies"] == 10
    assert d["probe_successes"] == 8
    assert d["recommendation"] == "do the thing"


def test_detect_result_to_dict_no_window():
    result = DetectResult(
        transport="h1-last-byte-sync",
        protocol="http/1.1",
        window=None,
        concurrency_hint="unknown",
        probe_copies=10,
        probe_successes=0,
        recommendation="x",
    )
    assert result.to_dict()["window"] is None


# ---------------------------------------------------------------------------
# run_detect — monkeypatched (no network)
# ---------------------------------------------------------------------------


def test_run_detect_h2_path(monkeypatch):
    """run_detect selects H2, fires SinglePacketEngine, returns DetectResult."""
    from reaper.httpspec import ResponseSignature

    sigs = [ResponseSignature(status=200, body_sha256="x", body_len=0, elapsed_ms=t)
            for t in [10.0, 11.0, 12.0, 10.5, 11.5, 10.0, 12.0, 11.0, 10.0, 10.5]]

    monkeypatch.setattr("reaper.detect.select_transport",
                        lambda *a, **kw: "h2-single-packet")

    def fake_run(self, req, copies):
        return sigs

    monkeypatch.setattr("reaper.engine.SinglePacketEngine.run_single_endpoint", fake_run)

    result = run_detect(target="https://shop.example.com", probe_copies=10)

    assert result.transport == "h2-single-packet"
    assert result.protocol == "h2"
    assert result.window is not None
    assert result.concurrency_hint == "concurrent"
    assert result.probe_successes == 10
    assert "HTTP/2 detected" in result.recommendation


def test_run_detect_h1_path(monkeypatch):
    """run_detect selects H1.1, fires LastByteSyncEngine, returns DetectResult."""
    sigs = [ResponseSignature(status=200, body_sha256="x", body_len=0, elapsed_ms=t)
            for t in [20.0, 80.0, 150.0, 200.0, 250.0, 300.0, 350.0, 400.0, 450.0, 500.0]]

    monkeypatch.setattr("reaper.detect.select_transport",
                        lambda *a, **kw: "h1-last-byte-sync")

    def fake_run(self, req, copies):
        return sigs

    monkeypatch.setattr("reaper.engine.LastByteSyncEngine.run_single_endpoint", fake_run)

    result = run_detect(target="http://internal.corp", probe_copies=10)

    assert result.transport == "h1-last-byte-sync"
    assert result.protocol == "http/1.1"
    assert result.concurrency_hint == "serialized"  # 480ms spread > 50ms threshold
    assert "HTTP/1.1 only" in result.recommendation


def test_run_detect_probe_failure_still_returns_transport(monkeypatch):
    """If the probe burst raises an exception, transport detection is still returned."""
    monkeypatch.setattr("reaper.detect.select_transport",
                        lambda *a, **kw: "h2-single-packet")

    def fail_run(self, req, copies):
        raise OSError("connection refused")

    monkeypatch.setattr("reaper.engine.SinglePacketEngine.run_single_endpoint", fail_run)

    result = run_detect(target="https://dead.example.com", probe_copies=10)

    assert result.transport == "h2-single-packet"
    assert result.window is None
    assert result.concurrency_hint == "unknown"
    assert result.probe_successes == 0


def test_run_detect_scope_blocks_out_of_scope():
    from scan_primitives import OutOfScopeError, Scope

    scope = Scope.from_entries(["allowed.example.com"])
    with pytest.raises(OutOfScopeError):
        run_detect(target="https://evil.com", scope=scope)


# ---------------------------------------------------------------------------
# CLI argument plumbing
# ---------------------------------------------------------------------------


def test_cli_detect_defaults():
    from reaper.cli import build_parser

    p = build_parser()
    args = p.parse_args(["detect", "--target", "https://example.com"])
    assert args.target == "https://example.com"
    assert args.probe_copies == 10
    assert args.timeout == pytest.approx(10.0)
    assert args.insecure is False
    assert args.output_format == "text"
    assert args.scope_file is None
    assert args.proxy is None


def test_cli_detect_json_format():
    from reaper.cli import build_parser

    p = build_parser()
    args = p.parse_args(["detect", "--target", "https://x.example", "--format", "json"])
    assert args.output_format == "json"


def test_cli_detect_probe_copies_override():
    from reaper.cli import build_parser

    p = build_parser()
    args = p.parse_args(["detect", "--target", "https://x.example", "--probe-copies", "5"])
    assert args.probe_copies == 5


def test_cli_detect_insecure_flag():
    from reaper.cli import build_parser

    p = build_parser()
    args = p.parse_args(["detect", "--target", "https://x.example", "--insecure"])
    assert args.insecure is True


def test_cli_detect_handler_rejects_probe_copies_1(monkeypatch):
    """probe-copies=1 is not a valid burst; CLI must reject it."""
    from reaper.cli import main

    rc = main(["detect", "--target", "https://x.example", "--probe-copies", "1"])
    assert rc == 3  # _EXIT_RUNTIME


def test_cli_detect_text_output(monkeypatch, capsys):
    """Text output contains all expected fields."""
    from reaper.detect import DetectResult, WindowStats

    fake_result = DetectResult(
        transport="h2-single-packet",
        protocol="h2",
        window=WindowStats(minimum=10.0, median=11.0, maximum=12.0, spread=2.0, stdev=0.5),
        concurrency_hint="concurrent",
        probe_copies=10,
        probe_successes=9,
        recommendation="HTTP/2 detected (h2) -- single-packet attack available.",
    )

    monkeypatch.setattr("reaper.detect.run_detect", lambda **kw: fake_result)

    from reaper.cli import main

    rc = main(["detect", "--target", "https://example.com"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "h2-single-packet" in out
    assert "concurrent" in out
    assert "spread=" in out


def test_cli_detect_json_output(monkeypatch, capsys):
    """JSON output is valid and contains expected keys."""
    from reaper.detect import DetectResult

    fake_result = DetectResult(
        transport="h1-last-byte-sync",
        protocol="http/1.1",
        window=None,
        concurrency_hint="unknown",
        probe_copies=10,
        probe_successes=0,
        recommendation="HTTP/1.1 only.",
    )
    monkeypatch.setattr("reaper.detect.run_detect", lambda **kw: fake_result)

    from reaper.cli import main

    rc = main(["detect", "--target", "http://x.example", "--format", "json"])
    assert rc == 0
    out = capsys.readouterr().out
    d = json.loads(out)
    assert d["transport"] == "h1-last-byte-sync"
    assert d["window"] is None
