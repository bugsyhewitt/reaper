"""Focused unit tests for the single-endpoint attack path.

Covers the interaction between cli._run_single(), runner.run_single_scenario(),
and the analysis layer for the dominant "coupon over-redeem" use-case.
No network. No integration marker.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from reaper.engine import TRANSPORT_H2_SINGLE_PACKET
from reaper.httpspec import ResponseSignature
from reaper.runner import run_single_scenario

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sig(status: int = 200, elapsed: float = 2.0, body: bytes = b"ok") -> ResponseSignature:
    return ResponseSignature.from_bytes(status, body, elapsed)


def _make_request(path="/redeem"):
    req = MagicMock()
    req.path = path
    req.delay = 0.0
    return req


class _Scope:
    def __init__(self):
        self.calls = []

    def assert_in_scope(self, url):
        self.calls.append(url)


def _scope():
    return _Scope()


def _engine_with_burst(burst):
    e = MagicMock()
    e.run_single_endpoint.return_value = burst
    return e


# ---------------------------------------------------------------------------
# Single-endpoint: clean server (no race)
# ---------------------------------------------------------------------------

class TestSingleCleanServer:
    """Server correctly limits to one success — no finding expected."""

    def test_exactly_one_success_no_finding(self):
        burst = [_sig(200)] + [_sig(409)] * 19
        engine = _engine_with_burst(burst)

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=engine),
            patch("reaper.runner.LastByteSyncEngine", return_value=engine),
        ):
            result = run_single_scenario(
                target="https://example.com/redeem",
                scope=_scope(),
                request=_make_request(),
                copies=20,
                expected_max_successes=1,
            )
        assert result.findings == []
        assert result.transport == TRANSPORT_H2_SINGLE_PACKET

    def test_all_failures_no_finding(self):
        burst = [_sig(409)] * 20
        engine = _engine_with_burst(burst)

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=engine),
            patch("reaper.runner.LastByteSyncEngine", return_value=engine),
        ):
            result = run_single_scenario(
                target="https://example.com/redeem",
                scope=_scope(),
                request=_make_request(),
                copies=20,
                expected_max_successes=1,
            )
        assert result.findings == []


# ---------------------------------------------------------------------------
# Single-endpoint: vulnerable server (race confirmed)
# ---------------------------------------------------------------------------

class TestSingleRaceConfirmed:
    """Burst yields more successes than the resource limit — finding expected."""

    def test_two_successes_produces_finding(self):
        burst = [_sig(200)] * 2 + [_sig(409)] * 18
        engine = _engine_with_burst(burst)

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=engine),
            patch("reaper.runner.LastByteSyncEngine", return_value=engine),
        ):
            result = run_single_scenario(
                target="https://example.com/redeem",
                scope=_scope(),
                request=_make_request(),
                copies=20,
                expected_max_successes=1,
            )
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.tool == "reaper"
        assert f.cwe_id == 362

    def test_finding_severity_is_high(self):
        burst = [_sig(200)] * 3 + [_sig(409)] * 17
        engine = _engine_with_burst(burst)

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=engine),
            patch("reaper.runner.LastByteSyncEngine", return_value=engine),
        ):
            result = run_single_scenario(
                target="https://example.com/redeem",
                scope=_scope(),
                request=_make_request(),
                copies=20,
                expected_max_successes=1,
            )
        assert result.findings[0].severity == "high"

    def test_finding_target_matches_target_arg(self):
        burst = [_sig(200)] * 2 + [_sig(409)] * 3
        engine = _engine_with_burst(burst)

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=engine),
            patch("reaper.runner.LastByteSyncEngine", return_value=engine),
        ):
            result = run_single_scenario(
                target="https://shop.example.com/redeem",
                scope=_scope(),
                request=_make_request(),
                copies=5,
                expected_max_successes=1,
            )
        assert result.findings[0].target == "https://shop.example.com/redeem"

    def test_finding_vector_contains_path(self):
        burst = [_sig(200)] * 2 + [_sig(409)] * 3
        engine = _engine_with_burst(burst)

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=engine),
            patch("reaper.runner.LastByteSyncEngine", return_value=engine),
        ):
            result = run_single_scenario(
                target="https://example.com/coupon",
                scope=_scope(),
                request=_make_request("/coupon"),
                copies=5,
                expected_max_successes=1,
            )
        assert "/coupon" in result.findings[0].vector

    def test_finding_id_default(self):
        burst = [_sig(200)] * 2 + [_sig(409)] * 3
        engine = _engine_with_burst(burst)

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=engine),
            patch("reaper.runner.LastByteSyncEngine", return_value=engine),
        ):
            result = run_single_scenario(
                target="https://example.com/",
                scope=_scope(),
                request=_make_request("/"),
                copies=5,
                expected_max_successes=1,
            )
        assert result.findings[0].id == "reaper-0001"

    def test_custom_finding_id(self):
        burst = [_sig(200)] * 2 + [_sig(409)] * 3
        engine = _engine_with_burst(burst)

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=engine),
            patch("reaper.runner.LastByteSyncEngine", return_value=engine),
        ):
            result = run_single_scenario(
                target="https://example.com/",
                scope=_scope(),
                request=_make_request("/"),
                copies=5,
                expected_max_successes=1,
                finding_id="reaper-9999",
            )
        assert result.findings[0].id == "reaper-9999"


# ---------------------------------------------------------------------------
# Single-endpoint: final-state guard
# ---------------------------------------------------------------------------

class TestSingleFinalStateGuard:
    """final_state_success_count suppresses false positives when <= limit."""

    def test_final_state_within_limit_suppresses_finding(self):
        burst = [_sig(200)] * 3 + [_sig(409)] * 17
        engine = _engine_with_burst(burst)

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=engine),
            patch("reaper.runner.LastByteSyncEngine", return_value=engine),
        ):
            result = run_single_scenario(
                target="https://example.com/redeem",
                scope=_scope(),
                request=_make_request(),
                copies=20,
                expected_max_successes=1,
                final_state_success_count=1,
            )
        assert result.findings == []


# ---------------------------------------------------------------------------
# Single-endpoint: result structure
# ---------------------------------------------------------------------------

class TestSingleResultStructure:
    def test_result_burst_matches_engine_output(self):
        burst = [_sig(200), _sig(409), _sig(409)]
        engine = _engine_with_burst(burst)

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=engine),
            patch("reaper.runner.LastByteSyncEngine", return_value=engine),
        ):
            result = run_single_scenario(
                target="https://example.com/",
                scope=_scope(),
                request=_make_request("/"),
                copies=3,
            )
        assert result.burst == burst

    def test_result_baseline_empty_when_no_samples(self):
        burst = [_sig(200)]
        engine = _engine_with_burst(burst)

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=engine),
            patch("reaper.runner.LastByteSyncEngine", return_value=engine),
        ):
            result = run_single_scenario(
                target="https://example.com/",
                scope=_scope(),
                request=_make_request("/"),
                copies=5,
                baseline_samples=0,
            )
        assert result.baseline == []

    def test_analysis_is_not_none(self):
        burst = [_sig(200)] * 2 + [_sig(409)] * 3
        engine = _engine_with_burst(burst)

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=engine),
            patch("reaper.runner.LastByteSyncEngine", return_value=engine),
        ):
            result = run_single_scenario(
                target="https://example.com/",
                scope=_scope(),
                request=_make_request("/"),
                copies=5,
            )
        assert result.analysis is not None


# ---------------------------------------------------------------------------
# Single-endpoint via CLI integration (no network)
# ---------------------------------------------------------------------------

class TestSingleViaCLI:
    """Drive the full CLI -> runner path to verify wiring."""

    def test_cli_single_calls_run_single_scenario(self, tmp_path):
        from reaper.cli import main

        req_file = tmp_path / "r.http"
        req_file.write_bytes(b"GET /redeem HTTP/1.1\r\nHost: example.com\r\n\r\n")

        mock_result = MagicMock()
        mock_result.findings = []
        mock_result.transport = "h2-single-packet"
        mock_result.analysis = None

        with (
            patch("reaper.cli._load_scope"),
            patch("reaper.httpspec.parse_request_file", return_value=MagicMock(path="/redeem")),
            patch("reaper.runner.run_single_scenario", return_value=mock_result) as mock_run,
        ):
            rc = main([
                "single",
                "--target", "https://example.com/redeem",
                "--request", str(req_file),
                "--copies", "20",
                "--format", "json",
            ])
        assert rc == 0
        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["copies"] == 20

    def test_cli_single_text_format_output(self, tmp_path, capsys):
        from reaper.cli import main

        req_file = tmp_path / "r.http"
        req_file.write_bytes(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

        mock_result = MagicMock()
        mock_result.findings = []
        mock_result.transport = "h2-single-packet"
        mock_result.analysis = None

        with (
            patch("reaper.cli._load_scope"),
            patch("reaper.httpspec.parse_request_file", return_value=MagicMock(path="/")),
            patch("reaper.runner.run_single_scenario", return_value=mock_result),
        ):
            main([
                "single",
                "--target", "https://example.com/",
                "--request", str(req_file),
                "--copies", "5",
                "--format", "text",
            ])
        out = capsys.readouterr().out
        assert "h2-single-packet" in out
        assert "confirmed findings: 0" in out
