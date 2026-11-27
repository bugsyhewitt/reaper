"""Unit tests for reaper.chain — state-chain TOCTOU analysis.

The chain module (v0.5) has no dedicated test file. These tests cover:
- analyze_chain: timing spread, within_window logic, differential detection
- build_chain_finding: Finding construction from differential chains
- Edge cases: empty results, single endpoint, all same status, wide spread
"""

from __future__ import annotations

import pytest

from reaper.chain import (
    DEFAULT_WINDOW_MS,
    ChainEndpointResult,
    StateChainAnalysis,
    analyze_chain,
    build_chain_finding,
)
from reaper.httpspec import RaceRequest, ResponseSignature


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ep(
    label: str,
    path: str,
    status: int,
    elapsed_ms: float,
) -> ChainEndpointResult:
    req = RaceRequest(method="POST", path=path, authority="app.example.com")
    sig = ResponseSignature(
        status=status,
        body_sha256="aabbcc",
        body_len=10,
        elapsed_ms=elapsed_ms,
    )
    return ChainEndpointResult(label=label, request=req, signature=sig)


# ---------------------------------------------------------------------------
# analyze_chain — empty / trivial cases
# ---------------------------------------------------------------------------


def test_analyze_chain_empty_results():
    result = analyze_chain([])
    assert result.spread_ms == 0.0
    assert result.within_window is True
    assert result.differential_found is False
    assert result.per_endpoint == []
    assert result.reason == "no chain results"


def test_analyze_chain_single_endpoint():
    ep = _make_ep("transfer.http", "/transfer", 200, 15.0)
    result = analyze_chain([ep])
    assert result.spread_ms == 0.0
    assert result.within_window is True
    assert result.differential_found is False


# ---------------------------------------------------------------------------
# analyze_chain — timing spread
# ---------------------------------------------------------------------------


def test_analyze_chain_tight_spread_within_window():
    eps = [
        _make_ep("a.http", "/transfer", 200, 10.0),
        _make_ep("b.http", "/balance", 200, 12.0),
    ]
    result = analyze_chain(eps, window_ms=10.0)
    assert result.spread_ms == pytest.approx(2.0)
    assert result.within_window is True
    assert result.differential_found is False


def test_analyze_chain_wide_spread_outside_window():
    eps = [
        _make_ep("a.http", "/transfer", 200, 10.0),
        _make_ep("b.http", "/balance", 200, 10.0 + DEFAULT_WINDOW_MS + 1),
    ]
    result = analyze_chain(eps)
    assert result.spread_ms > DEFAULT_WINDOW_MS
    assert result.within_window is False


def test_analyze_chain_spread_exactly_at_window_is_within():
    # spread == window_ms should be within (<=, not <)
    eps = [
        _make_ep("a.http", "/a", 200, 0.0),
        _make_ep("b.http", "/b", 200, DEFAULT_WINDOW_MS),
    ]
    result = analyze_chain(eps, window_ms=DEFAULT_WINDOW_MS)
    assert result.within_window is True


def test_analyze_chain_timing_dict_contains_expected_keys():
    eps = [
        _make_ep("a.http", "/a", 200, 10.0),
        _make_ep("b.http", "/b", 200, 20.0),
        _make_ep("c.http", "/c", 200, 15.0),
    ]
    result = analyze_chain(eps)
    assert result.timing["unit"] == "ms"
    assert result.timing["samples"] == 3
    assert result.timing["min"] == pytest.approx(10.0)
    assert result.timing["max"] == pytest.approx(20.0)
    assert "spread" in result.timing
    assert "mean" in result.timing
    assert "stdev" in result.timing


# ---------------------------------------------------------------------------
# analyze_chain — differential detection
# ---------------------------------------------------------------------------


def test_analyze_chain_no_differential_all_200():
    eps = [
        _make_ep("a.http", "/transfer", 200, 10.0),
        _make_ep("b.http", "/balance", 200, 11.0),
    ]
    result = analyze_chain(eps, expected_status=200)
    assert result.differential_found is False
    assert all(not ep["differential"] for ep in result.per_endpoint)


def test_analyze_chain_differential_on_unexpected_status():
    eps = [
        _make_ep("a.http", "/transfer", 200, 10.0),
        _make_ep("b.http", "/balance-check", 403, 11.0),
    ]
    result = analyze_chain(eps, expected_status=200)
    assert result.differential_found is True
    diffs = [ep for ep in result.per_endpoint if ep["differential"]]
    assert len(diffs) == 1
    assert diffs[0]["path"] == "/balance-check"
    assert diffs[0]["status"] == 403


def test_analyze_chain_differential_multiple_endpoints():
    eps = [
        _make_ep("a.http", "/a", 200, 10.0),
        _make_ep("b.http", "/b", 500, 11.0),
        _make_ep("c.http", "/c", 404, 12.0),
    ]
    result = analyze_chain(eps, expected_status=200)
    assert result.differential_found is True
    diffs = [ep for ep in result.per_endpoint if ep["differential"]]
    assert len(diffs) == 2
    paths = {ep["path"] for ep in diffs}
    assert paths == {"/b", "/c"}


def test_analyze_chain_per_endpoint_has_required_keys():
    eps = [_make_ep("a.http", "/a", 200, 10.0)]
    result = analyze_chain(eps)
    ep = result.per_endpoint[0]
    assert "label" in ep
    assert "path" in ep
    assert "status" in ep
    assert "elapsed_ms" in ep
    assert "body_sha256_prefix" in ep
    assert "differential" in ep


def test_analyze_chain_reason_contains_path_on_differential():
    eps = [
        _make_ep("a.http", "/do-transfer", 200, 10.0),
        _make_ep("b.http", "/check-funds", 402, 11.0),
    ]
    result = analyze_chain(eps, expected_status=200)
    assert "/check-funds" in result.reason


def test_analyze_chain_reason_mentions_window_on_wide_spread():
    eps = [
        _make_ep("a.http", "/a", 200, 0.0),
        _make_ep("b.http", "/b", 200, 100.0),
    ]
    result = analyze_chain(eps, window_ms=10.0)
    assert "window" in result.reason or "spread" in result.reason


def test_analyze_chain_custom_expected_status():
    # expected_status=201 — a 200 response is then differential
    eps = [
        _make_ep("a.http", "/create", 201, 10.0),
        _make_ep("b.http", "/create2", 200, 11.0),
    ]
    result = analyze_chain(eps, expected_status=201)
    assert result.differential_found is True
    assert result.per_endpoint[1]["differential"] is True
    assert result.per_endpoint[0]["differential"] is False


def test_analyze_chain_window_ms_respected():
    eps = [
        _make_ep("a.http", "/a", 200, 0.0),
        _make_ep("b.http", "/b", 200, 5.0),
    ]
    # window=4 → spread=5 is outside
    r4 = analyze_chain(eps, window_ms=4.0)
    assert r4.within_window is False
    # window=6 → spread=5 is inside
    r6 = analyze_chain(eps, window_ms=6.0)
    assert r6.within_window is True


# ---------------------------------------------------------------------------
# build_chain_finding
# ---------------------------------------------------------------------------


def _analysis_with_differential(differential: bool = True) -> StateChainAnalysis:
    spread = 3.0
    per_ep = [
        {
            "label": "transfer.http",
            "path": "/transfer",
            "status": 200,
            "elapsed_ms": 10.0,
            "body_sha256_prefix": "aa",
            "differential": False,
        },
        {
            "label": "balance.http",
            "path": "/balance",
            "status": 403 if differential else 200,
            "elapsed_ms": 13.0,
            "body_sha256_prefix": "bb",
            "differential": differential,
        },
    ]
    return StateChainAnalysis(
        spread_ms=spread,
        within_window=True,
        window_ms=DEFAULT_WINDOW_MS,
        per_endpoint=per_ep,
        timing={"unit": "ms", "samples": 2, "spread": spread},
        differential_found=differential,
        reason="diff" if differential else "no diff",
    )


def test_build_chain_finding_returns_none_when_no_differential():
    analysis = _analysis_with_differential(differential=False)
    finding = build_chain_finding(analysis, target="https://app.example.com", vector="state-chain:/transfer,/balance")
    assert finding is None


def test_build_chain_finding_returns_finding_on_differential():
    analysis = _analysis_with_differential(differential=True)
    finding = build_chain_finding(analysis, target="https://app.example.com", vector="state-chain:/transfer,/balance")
    assert finding is not None
    assert finding.tool == "reaper"
    assert finding.variant == "state-chain"
    assert "/balance" in finding.title


def test_build_chain_finding_title_includes_differential_path():
    analysis = _analysis_with_differential(differential=True)
    finding = build_chain_finding(
        analysis,
        target="https://app.example.com",
        vector="state-chain:/transfer,/balance",
    )
    assert finding is not None
    assert "/balance" in finding.title


def test_build_chain_finding_evidence_has_spread():
    analysis = _analysis_with_differential(differential=True)
    finding = build_chain_finding(
        analysis, target="https://t.example", vector="state-chain:/a,/b"
    )
    assert finding is not None
    assert "spread_ms" in finding.evidence
    assert finding.evidence["spread_ms"] == pytest.approx(3.0)


def test_build_chain_finding_custom_severity():
    analysis = _analysis_with_differential(differential=True)
    finding = build_chain_finding(
        analysis,
        target="https://t.example",
        vector="state-chain:/a,/b",
        severity="critical",
    )
    assert finding is not None
    assert finding.severity == "critical"


def test_build_chain_finding_custom_finding_id():
    analysis = _analysis_with_differential(differential=True)
    finding = build_chain_finding(
        analysis,
        target="https://t.example",
        vector="state-chain:/a,/b",
        finding_id="reaper-9999",
    )
    assert finding is not None
    assert finding.id == "reaper-9999"


def test_build_chain_finding_custom_references():
    analysis = _analysis_with_differential(differential=True)
    refs = ["https://portswigger.net/research/smashing-the-state-machine"]
    finding = build_chain_finding(
        analysis,
        target="https://t.example",
        vector="state-chain:/a,/b",
        references=refs,
    )
    assert finding is not None
    assert refs[0] in finding.references
