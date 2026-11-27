"""Advanced CLI tests — state-chain dispatch, group paths, output edge cases.

Covers code paths not exercised by test_cli.py:
- group --state-chain: dispatch, findings, error paths
- group --group-file error paths (TransportError, ValueError)
- detect: proxy, insecure, various output combinations
- _emit: h1md with finding, sarif with multiple findings
- main() chain_window argument
"""

from __future__ import annotations

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


def _make_state_chain_result(findings=None):
    result = MagicMock()
    result.findings = findings if findings is not None else []
    result.transport = "h2-single-packet"
    result.chain_results = [MagicMock(), MagicMock()]
    analysis = MagicMock()
    analysis.spread_ms = 3.5
    analysis.within_window = True
    analysis.window_ms = 10.0
    analysis.differential_found = bool(findings)
    analysis.reason = "chain fired 2 endpoints within 3.5ms"
    analysis.per_endpoint = [
        {"label": "a.http", "path": "/transfer", "status": 200,
         "elapsed_ms": 10.0, "differential": False},
        {"label": "b.http", "path": "/balance", "status": 200,
         "elapsed_ms": 13.5, "differential": False},
    ]
    analysis.timing = {"unit": "ms", "samples": 2, "spread": 3.5}
    result.analysis = analysis
    return result


# ---------------------------------------------------------------------------
# state-chain argument parsing
# ---------------------------------------------------------------------------


class TestStatechainParsing:
    def test_state_chain_two_files(self):
        p = build_parser()
        args = p.parse_args([
            "group", "--target", "https://example.com",
            "--state-chain", "a.http,b.http",
        ])
        assert args.state_chain == "a.http,b.http"
        assert args.group_file is None

    def test_state_chain_three_files(self):
        p = build_parser()
        args = p.parse_args([
            "group", "--target", "https://example.com",
            "--state-chain", "a.http,b.http,c.http",
        ])
        assert args.state_chain == "a.http,b.http,c.http"

    def test_chain_window_default(self):
        p = build_parser()
        args = p.parse_args([
            "group", "--target", "https://example.com",
            "--state-chain", "a.http,b.http",
        ])
        assert args.chain_window == pytest.approx(10.0)

    def test_chain_window_custom(self):
        p = build_parser()
        args = p.parse_args([
            "group", "--target", "https://example.com",
            "--state-chain", "a.http,b.http",
            "--chain-window", "5.0",
        ])
        assert args.chain_window == pytest.approx(5.0)

    def test_state_chain_mutually_exclusive_with_group_file(self):
        p = build_parser()
        with pytest.raises(SystemExit):
            p.parse_args([
                "group", "--target", "https://example.com",
                "--state-chain", "a.http,b.http",
                "--group-file", "scenario.group",
            ])

    def test_state_chain_single_file_returns_runtime(self, capsys):
        with patch("reaper.cli._load_scope"):
            rc = main([
                "group", "--target", "https://example.com",
                "--state-chain", "only_one.http",
            ])
        assert rc == _EXIT_RUNTIME
        err = capsys.readouterr().err
        assert "error" in err.lower() or rc == _EXIT_RUNTIME


# ---------------------------------------------------------------------------
# state-chain dispatch — main() calls run_state_chain_scenario
# ---------------------------------------------------------------------------


class TestStatechainDispatch:
    def test_state_chain_calls_runner(self, tmp_path):
        a = tmp_path / "a.http"
        b = tmp_path / "b.http"
        a.write_bytes(b"POST /transfer HTTP/1.1\r\nHost: example.com\r\n\r\n")
        b.write_bytes(b"POST /balance HTTP/1.1\r\nHost: example.com\r\n\r\n")

        result = _make_state_chain_result(findings=[])
        with (
            patch("reaper.cli._load_scope"),
            patch("reaper.httpspec.parse_request_file", return_value=MagicMock(path="/")),
            patch("reaper.runner.run_state_chain_scenario", return_value=result) as mock_run,
        ):
            rc = main([
                "group", "--target", "https://example.com",
                "--state-chain", f"{a},{b}",
            ])
        assert rc == _EXIT_OK
        mock_run.assert_called_once()

    def test_state_chain_returns_finding_exit_on_findings(self, tmp_path):
        a = tmp_path / "a.http"
        b = tmp_path / "b.http"
        a.write_bytes(b"POST /transfer HTTP/1.1\r\nHost: example.com\r\n\r\n")
        b.write_bytes(b"POST /balance HTTP/1.1\r\nHost: example.com\r\n\r\n")

        finding = _make_finding(variant="state-chain")
        result = _make_state_chain_result(findings=[finding])
        with (
            patch("reaper.cli._load_scope"),
            patch("reaper.httpspec.parse_request_file", return_value=MagicMock(path="/")),
            patch("reaper.runner.run_state_chain_scenario", return_value=result),
        ):
            rc = main([
                "group", "--target", "https://example.com",
                "--state-chain", f"{a},{b}",
            ])
        assert rc == _EXIT_FINDING

    def test_state_chain_text_output(self, tmp_path, capsys):
        a = tmp_path / "a.http"
        b = tmp_path / "b.http"
        a.write_bytes(b"POST /transfer HTTP/1.1\r\nHost: example.com\r\n\r\n")
        b.write_bytes(b"POST /balance HTTP/1.1\r\nHost: example.com\r\n\r\n")

        result = _make_state_chain_result(findings=[])
        with (
            patch("reaper.cli._load_scope"),
            patch("reaper.httpspec.parse_request_file", return_value=MagicMock(path="/")),
            patch("reaper.runner.run_state_chain_scenario", return_value=result),
        ):
            rc = main([
                "group", "--target", "https://example.com",
                "--state-chain", f"{a},{b}",
                "--format", "text",
            ])
        assert rc == _EXIT_OK
        out = capsys.readouterr().out
        assert "transport" in out
        assert "spread" in out

    def test_state_chain_json_output(self, tmp_path, capsys):
        a = tmp_path / "a.http"
        b = tmp_path / "b.http"
        a.write_bytes(b"POST /transfer HTTP/1.1\r\nHost: example.com\r\n\r\n")
        b.write_bytes(b"POST /balance HTTP/1.1\r\nHost: example.com\r\n\r\n")

        result = _make_state_chain_result(findings=[])
        with (
            patch("reaper.cli._load_scope"),
            patch("reaper.httpspec.parse_request_file", return_value=MagicMock(path="/")),
            patch("reaper.runner.run_state_chain_scenario", return_value=result),
        ):
            rc = main([
                "group", "--target", "https://example.com",
                "--state-chain", f"{a},{b}",
                "--format", "json",
            ])
        assert rc == _EXIT_OK
        out = capsys.readouterr().out
        d = json.loads(out)
        assert "transport" in d
        assert "findings" in d
        assert "analysis" in d

    def test_state_chain_out_of_scope_returns_runtime(self, tmp_path, capsys):
        from scan_primitives import OutOfScopeError

        a = tmp_path / "a.http"
        b = tmp_path / "b.http"
        a.write_bytes(b"POST /transfer HTTP/1.1\r\nHost: example.com\r\n\r\n")
        b.write_bytes(b"POST /balance HTTP/1.1\r\nHost: example.com\r\n\r\n")

        with (
            patch("reaper.cli._load_scope"),
            patch("reaper.httpspec.parse_request_file", return_value=MagicMock(path="/")),
            patch("reaper.runner.run_state_chain_scenario",
                  side_effect=OutOfScopeError("not in scope")),
        ):
            rc = main([
                "group", "--target", "https://example.com",
                "--state-chain", f"{a},{b}",
            ])
        assert rc == _EXIT_RUNTIME


# ---------------------------------------------------------------------------
# group --group-file error paths not covered by test_cli.py
# ---------------------------------------------------------------------------


class TestGroupFilePaths:
    def test_group_transport_error_returns_runtime(self, tmp_path, capsys):
        from reaper.engine import TransportError

        gf = tmp_path / "s.group"
        gf.write_text("POST /a HTTP/1.1\r\nHost: example.com\r\n\r\n%%%POST /b HTTP/1.1\r\nHost: example.com\r\n\r\n")

        with (
            patch("reaper.cli._load_scope"),
            patch("reaper.httpspec.parse_group_file", return_value=[MagicMock(path="/a")]),
            patch("reaper.runner.run_group_scenario",
                  side_effect=TransportError("h2 not supported")),
        ):
            rc = main([
                "group", "--target", "https://example.com",
                "--group-file", str(gf),
            ])
        assert rc == _EXIT_RUNTIME

    def test_group_oserror_returns_runtime(self, tmp_path, capsys):
        gf = tmp_path / "s.group"
        gf.write_text("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n%%%GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n")

        with (
            patch("reaper.cli._load_scope"),
            patch("reaper.httpspec.parse_group_file", return_value=[MagicMock(path="/a")]),
            patch("reaper.runner.run_group_scenario",
                  side_effect=OSError("connection refused")),
        ):
            rc = main([
                "group", "--target", "https://example.com",
                "--group-file", str(gf),
            ])
        assert rc == _EXIT_RUNTIME


# ---------------------------------------------------------------------------
# detect: proxy + insecure argument wiring
# ---------------------------------------------------------------------------


class TestDetectArgWiring:
    def test_detect_proxy_flag(self):
        p = build_parser()
        args = p.parse_args([
            "detect", "--target", "https://example.com",
            "--proxy", "socks5://127.0.0.1:1080",
        ])
        assert args.proxy == "socks5://127.0.0.1:1080"

    def test_detect_insecure_flag(self):
        p = build_parser()
        args = p.parse_args([
            "detect", "--target", "https://example.com", "--insecure",
        ])
        assert args.insecure is True

    def test_detect_timeout_flag(self):
        p = build_parser()
        args = p.parse_args([
            "detect", "--target", "https://example.com", "--timeout", "30",
        ])
        assert args.timeout == pytest.approx(30.0)

    def test_detect_passes_insecure_to_run_detect(self):
        captured: dict = {}

        def fake_detect(**kw):
            captured.update(kw)
            from reaper.detect import DetectResult
            return DetectResult(
                transport="h2-single-packet",
                protocol="h2",
                window=None,
                concurrency_hint="unknown",
                probe_copies=10,
                probe_successes=0,
                recommendation="x",
            )

        with (
            patch("reaper.cli._load_scope"),
            patch("reaper.detect.run_detect", side_effect=fake_detect),
        ):
            main(["detect", "--target", "https://example.com", "--insecure"])
        assert captured.get("verify_tls") is False

    def test_detect_passes_timeout_to_run_detect(self):
        captured: dict = {}

        def fake_detect(**kw):
            captured.update(kw)
            from reaper.detect import DetectResult
            return DetectResult(
                transport="h2-single-packet",
                protocol="h2",
                window=None,
                concurrency_hint="unknown",
                probe_copies=10,
                probe_successes=0,
                recommendation="x",
            )

        with (
            patch("reaper.cli._load_scope"),
            patch("reaper.detect.run_detect", side_effect=fake_detect),
        ):
            main(["detect", "--target", "https://example.com", "--timeout", "25"])
        assert captured.get("timeout") == pytest.approx(25.0)


# ---------------------------------------------------------------------------
# _emit — h1md with a finding, sarif with multiple findings
# ---------------------------------------------------------------------------


class TestEmitAdvanced:
    def _make_result(self, findings=None):
        result = MagicMock()
        result.findings = findings if findings is not None else []
        result.transport = "h2-single-packet"
        result.analysis = None
        return result

    def test_emit_h1md_with_finding_produces_markdown(self, capsys):
        f = _make_finding()
        result = self._make_result(findings=[f])
        _emit(result, "h1md")
        out = capsys.readouterr().out
        assert len(out) > 0
        assert "_No confirmed race findings._" not in out

    def test_emit_sarif_multiple_findings(self, capsys):
        f1 = _make_finding(id="reaper-0001")
        f2 = _make_finding(id="reaper-0002", target="https://example.com/checkout")
        result = self._make_result(findings=[f1, f2])
        _emit(result, "sarif")
        out = capsys.readouterr().out
        d = json.loads(out)
        assert len(d["runs"][0]["results"]) == 2

    def test_emit_json_multiple_findings(self, capsys):
        f1 = _make_finding(id="reaper-0001")
        f2 = _make_finding(id="reaper-0002")
        result = self._make_result(findings=[f1, f2])
        _emit(result, "json")
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert len(parsed) == 2
        ids = {f["id"] for f in parsed}
        assert ids == {"reaper-0001", "reaper-0002"}
