"""Unit tests for reaper.cli — arg parsing, subcommand dispatch, error handling.

All tests are fixture-free (no network, no integration marker). The strategy is:
- Parser construction and argument defaults via build_parser().
- Handler dispatch via main() with monkeypatching of the heavy runner/detect
  callables so no I/O happens.
- Error path coverage: out-of-scope, transport errors, missing args.
"""

from __future__ import annotations

import argparse
import json
from unittest.mock import MagicMock, patch

import pytest

from reaper.cli import (
    _EXIT_FINDING,
    _EXIT_OK,
    _EXIT_RUNTIME,
    _emit,
    build_parser,
    main,
)
from reaper.findings import Finding

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(**kwargs) -> Finding:
    defaults = dict(
        id="reaper-0001",
        tool="reaper",
        title="Test race",
        severity="high",
        confidence="high",
        target="https://example.com/redeem",
        vector="single-packet:/redeem",
        variant="single-endpoint",
        cwe_id=362,
        evidence={},
        references=[],
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _make_scenario_result(findings=None):
    result = MagicMock()
    result.findings = findings if findings is not None else []
    result.transport = "h2-single-packet"
    result.analysis = MagicMock()
    result.analysis.baseline_summary = {"success_count": 1}
    result.analysis.burst_success_count = 3
    result.analysis.expected_max_successes = 1
    result.analysis.timing = {"min": 1.0, "max": 2.0}
    result.analysis.reason = "over-limit"
    return result


# ---------------------------------------------------------------------------
# Parser construction
# ---------------------------------------------------------------------------

class TestBuildParser:
    def test_returns_argument_parser(self):
        p = build_parser()
        assert isinstance(p, argparse.ArgumentParser)

    def test_version_flag_raises_system_exit(self):
        p = build_parser()
        with pytest.raises(SystemExit) as exc:
            p.parse_args(["--version"])
        assert exc.value.code == 0

    def test_no_subcommand_does_not_crash_parse(self):
        p = build_parser()
        args = p.parse_args([])
        assert args.scenario is None
        assert not hasattr(args, "handler")

    def test_single_required_args(self):
        p = build_parser()
        args = p.parse_args([
            "single",
            "--target", "https://example.com/redeem",
            "--request", "redeem.http",
            "--copies", "20",
        ])
        assert args.scenario == "single"
        assert args.target == "https://example.com/redeem"
        assert args.request == "redeem.http"
        assert args.copies == 20

    def test_single_defaults(self):
        p = build_parser()
        args = p.parse_args([
            "single",
            "--target", "https://example.com/redeem",
            "--request", "r.http",
            "--copies", "10",
        ])
        assert args.output_format == "json"
        assert args.baseline_samples == 0
        assert args.transport == "auto"
        assert args.timeout == 10.0
        assert args.insecure is False
        assert args.proxy is None

    def test_single_optional_flags(self):
        p = build_parser()
        args = p.parse_args([
            "single",
            "--target", "https://example.com/",
            "--request", "r.http",
            "--copies", "5",
            "--format", "sarif",
            "--transport", "h2-single-packet",
            "--baseline-samples", "3",
            "--proxy", "socks5://127.0.0.1:1080",
            "--timeout", "30",
            "--insecure",
        ])
        assert args.output_format == "sarif"
        assert args.transport == "h2-single-packet"
        assert args.baseline_samples == 3
        assert args.proxy == "socks5://127.0.0.1:1080"
        assert args.timeout == 30.0
        assert args.insecure is True

    def test_group_requires_group_file_or_state_chain(self):
        p = build_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["group", "--target", "https://example.com"])

    def test_group_with_group_file(self):
        p = build_parser()
        args = p.parse_args([
            "group",
            "--target", "https://example.com",
            "--group-file", "scenario.group",
        ])
        assert args.group_file == "scenario.group"
        assert args.state_chain is None

    def test_group_with_state_chain(self):
        p = build_parser()
        args = p.parse_args([
            "group",
            "--target", "https://example.com",
            "--state-chain", "a.http,b.http",
        ])
        assert args.state_chain == "a.http,b.http"

    def test_group_auto_delay_default_false(self):
        p = build_parser()
        args = p.parse_args([
            "group",
            "--target", "https://example.com",
            "--group-file", "f.group",
        ])
        assert args.auto_delay is False
        assert args.auto_delay_samples == 3

    def test_detect_required_target(self):
        p = build_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["detect"])

    def test_detect_defaults(self):
        p = build_parser()
        args = p.parse_args(["detect", "--target", "https://example.com"])
        assert args.probe_copies == 10
        assert args.output_format == "text"
        assert args.proxy is None

    def test_detect_format_choices(self):
        p = build_parser()
        args = p.parse_args(["detect", "--target", "https://x.com", "--format", "json"])
        assert args.output_format == "json"

    def test_invalid_format_rejected(self):
        p = build_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["single", "--target", "https://x.com",
                          "--request", "r.http", "--copies", "5",
                          "--format", "notaformat"])

    def test_invalid_transport_rejected(self):
        p = build_parser()
        with pytest.raises(SystemExit):
            p.parse_args(["single", "--target", "https://x.com",
                          "--request", "r.http", "--copies", "5",
                          "--transport", "badtransport"])


# ---------------------------------------------------------------------------
# main() dispatch — no-subcommand path
# ---------------------------------------------------------------------------

class TestMainDispatch:
    def test_no_subcommand_returns_2(self, capsys):
        rc = main([])
        assert rc == 2
        captured = capsys.readouterr()
        assert "usage" in captured.out.lower() or "reaper" in captured.out.lower()

    def test_single_dispatch_calls_runner(self, tmp_path):
        req_file = tmp_path / "r.http"
        req_file.write_bytes(b"GET /redeem HTTP/1.1\r\nHost: example.com\r\n\r\n")

        result = _make_scenario_result(findings=[])
        with (
            patch("reaper.cli._load_scope") as mock_scope,
            patch("reaper.httpspec.parse_request_file", return_value=MagicMock(path="/redeem")),
            patch("reaper.runner.run_single_scenario", return_value=result) as mock_run,
        ):
            mock_scope.return_value = MagicMock()
            rc = main([
                "single",
                "--target", "https://example.com/redeem",
                "--request", str(req_file),
                "--copies", "10",
            ])
        assert rc == _EXIT_OK
        mock_run.assert_called_once()

    def test_single_returns_finding_exit_when_findings(self, tmp_path):
        req_file = tmp_path / "r.http"
        req_file.write_bytes(b"GET /redeem HTTP/1.1\r\nHost: example.com\r\n\r\n")

        finding = _make_finding()
        result = _make_scenario_result(findings=[finding])
        with (
            patch("reaper.cli._load_scope"),
            patch("reaper.httpspec.parse_request_file", return_value=MagicMock(path="/")),
            patch("reaper.runner.run_single_scenario", return_value=result),
        ):
            rc = main([
                "single",
                "--target", "https://example.com/redeem",
                "--request", str(req_file),
                "--copies", "5",
            ])
        assert rc == _EXIT_FINDING

    def test_detect_dispatch_calls_run_detect(self):
        detect_result = MagicMock()
        detect_result.transport = "h2-single-packet"
        detect_result.protocol = "h2"
        detect_result.window = None
        detect_result.concurrency_hint = "concurrent"
        detect_result.probe_successes = 8
        detect_result.probe_copies = 10
        detect_result.recommendation = "reaper single ..."

        with (
            patch("reaper.cli._load_scope"),
            patch("reaper.detect.run_detect", return_value=detect_result) as mock_detect,
        ):
            rc = main(["detect", "--target", "https://example.com"])
        assert rc == _EXIT_OK
        mock_detect.assert_called_once()

    def test_detect_probe_copies_lt_2_returns_runtime(self):
        with patch("reaper.cli._load_scope"):
            rc = main(["detect", "--target", "https://example.com", "--probe-copies", "1"])
        assert rc == _EXIT_RUNTIME


# ---------------------------------------------------------------------------
# Error handling paths
# ---------------------------------------------------------------------------

class TestErrorHandling:
    def test_single_out_of_scope_returns_runtime(self, tmp_path, capsys):
        from scan_primitives import OutOfScopeError

        req_file = tmp_path / "r.http"
        req_file.write_bytes(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

        with (
            patch("reaper.cli._load_scope"),
            patch("reaper.httpspec.parse_request_file", return_value=MagicMock(path="/")),
            patch("reaper.runner.run_single_scenario",
                  side_effect=OutOfScopeError("out of scope")),
        ):
            rc = main([
                "single", "--target", "https://example.com/", "--request",
                str(req_file), "--copies", "5",
            ])
        assert rc == _EXIT_RUNTIME
        assert "error" in capsys.readouterr().err.lower()

    def test_single_transport_error_returns_runtime(self, tmp_path, capsys):
        from reaper.engine import TransportError

        req_file = tmp_path / "r.http"
        req_file.write_bytes(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

        with (
            patch("reaper.cli._load_scope"),
            patch("reaper.httpspec.parse_request_file", return_value=MagicMock(path="/")),
            patch("reaper.runner.run_single_scenario",
                  side_effect=TransportError("h2 refused")),
        ):
            rc = main([
                "single", "--target", "https://example.com/", "--request",
                str(req_file), "--copies", "5",
            ])
        assert rc == _EXIT_RUNTIME

    def test_single_oserror_returns_runtime(self, tmp_path, capsys):
        req_file = tmp_path / "r.http"
        req_file.write_bytes(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

        with (
            patch("reaper.cli._load_scope"),
            patch("reaper.httpspec.parse_request_file", return_value=MagicMock(path="/")),
            patch("reaper.runner.run_single_scenario",
                  side_effect=OSError("connection refused")),
        ):
            rc = main([
                "single", "--target", "https://example.com/", "--request",
                str(req_file), "--copies", "5",
            ])
        assert rc == _EXIT_RUNTIME

    def test_group_out_of_scope_returns_runtime(self, tmp_path, capsys):
        from scan_primitives import OutOfScopeError

        group_file = tmp_path / "s.group"
        group_file.write_text("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n")

        with (
            patch("reaper.cli._load_scope"),
            patch("reaper.httpspec.parse_group_file", return_value=[MagicMock(path="/a")]),
            patch("reaper.runner.run_group_scenario",
                  side_effect=OutOfScopeError("nope")),
        ):
            rc = main([
                "group", "--target", "https://example.com",
                "--group-file", str(group_file),
            ])
        assert rc == _EXIT_RUNTIME

    def test_detect_out_of_scope_returns_runtime(self, capsys):
        from scan_primitives import OutOfScopeError

        with (
            patch("reaper.cli._load_scope"),
            patch("reaper.detect.run_detect", side_effect=OutOfScopeError("nope")),
        ):
            rc = main(["detect", "--target", "https://example.com"])
        assert rc == _EXIT_RUNTIME

    def test_state_chain_too_few_files_returns_runtime(self, capsys):
        with patch("reaper.cli._load_scope"):
            rc = main([
                "group", "--target", "https://example.com",
                "--state-chain", "only_one.http",
            ])
        assert rc == _EXIT_RUNTIME


# ---------------------------------------------------------------------------
# _emit() output format tests
# ---------------------------------------------------------------------------

class TestEmit:
    def _make_result(self, findings=None):
        result = MagicMock()
        result.findings = findings if findings is not None else []
        result.transport = "h2-single-packet"
        result.analysis = MagicMock()
        result.analysis.baseline_summary = {"success_count": 1}
        result.analysis.burst_success_count = 3
        result.analysis.expected_max_successes = 1
        result.analysis.timing = {"min": 1.0, "max": 2.0}
        result.analysis.reason = "over-limit"
        return result

    def test_emit_json_no_findings(self, capsys):
        result = self._make_result()
        _emit(result, "json")
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed == []

    def test_emit_json_with_finding(self, capsys):
        f = _make_finding()
        result = self._make_result(findings=[f])
        _emit(result, "json")
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert len(parsed) == 1
        assert parsed[0]["id"] == "reaper-0001"

    def test_emit_text_prints_transport(self, capsys):
        result = self._make_result()
        _emit(result, "text")
        out = capsys.readouterr().out
        assert "h2-single-packet" in out

    def test_emit_text_no_analysis_is_graceful(self, capsys):
        result = self._make_result()
        result.analysis = None
        _emit(result, "text")
        out = capsys.readouterr().out
        assert "confirmed findings: 0" in out

    def test_emit_h1md_no_findings(self, capsys):
        result = self._make_result()
        _emit(result, "h1md")
        out = capsys.readouterr().out
        assert "_No confirmed race findings._" in out

    def test_emit_sarif_produces_valid_json(self, capsys):
        result = self._make_result()
        _emit(result, "sarif")
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert "runs" in parsed
        assert parsed["version"] == "2.1.0"
