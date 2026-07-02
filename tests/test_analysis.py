"""Unit tests for the deviation-confirmation analysis (no network).

Covers the benchmark->burst comparison, the final-state false-positive guard,
confidence assignment, and the Finding builder (V0.1-CRITERIA.md #5).
"""

from __future__ import annotations

from reaper.analysis import (
    build_finding,
    confirm_race,
    summarize,
    timing_distribution,
)
from reaper.httpspec import ResponseSignature


def sig(status: int, elapsed: float = 1.0, body: bytes = b"x", so: str | None = None):
    return ResponseSignature.from_bytes(status, body, elapsed, second_order=so)


# baseline: a correct single-use endpoint -> exactly one 200, rest 409.
BASELINE = [sig(200)] + [sig(409)] * 24
# burst: concurrency forced three 200s.
BURST_RACE = [sig(200)] * 3 + [sig(409)] * 22
# burst: server held the line -> a single 200.
BURST_CLEAN = [sig(200)] + [sig(409)] * 24


def test_summarize_counts_statuses_and_successes():
    s = summarize(BURST_RACE)
    assert s["count"] == 25
    assert s["statuses"] == {"200": 3, "409": 22}
    assert s["success_count"] == 3


def test_summarize_distinct_success_body_hashes():
    burst = [sig(200, body=b"a"), sig(200, body=b"b"), sig(409, body=b"c")]
    s = summarize(burst)
    assert len(s["distinct_success_body_hashes"]) == 2  # two distinct 2xx bodies


def test_timing_distribution_shape():
    t = timing_distribution([sig(200, 1.0), sig(200, 3.0)])
    assert t["unit"] == "ms"
    assert t["samples"] == 2
    assert t["min"] == 1.0 and t["max"] == 3.0 and t["spread"] == 2.0


def test_confirm_race_flags_over_limit():
    a = confirm_race(BASELINE, BURST_RACE)
    assert a.is_race
    assert a.expected_max_successes == 1  # derived from the baseline
    assert a.burst_success_count == 3
    assert a.anomalous_response_count == 2  # 3 successes - 1 expected


def test_confirm_race_no_deviation_is_not_a_race():
    a = confirm_race(BASELINE, BURST_CLEAN)
    assert not a.is_race
    assert a.anomalous_response_count == 0
    assert a.confidence == "low"


def test_final_state_guard_suppresses_overwritten_win():
    """Surplus 2xx responses but the persisted final state stayed within the
    limit -> an early win was overwritten; NOT a real finding."""
    a = confirm_race(BASELINE, BURST_RACE, final_state_success_count=1)
    assert a.final_state_verified
    assert not a.final_state_ok
    assert not a.is_race
    assert "overwritten" in a.reason


def test_final_state_verified_yields_high_confidence():
    a = confirm_race(BASELINE, BURST_RACE, final_state_success_count=3)
    assert a.is_race
    assert a.final_state_verified and a.final_state_ok
    assert a.confidence == "high"


def test_unverified_surplus_is_medium_confidence_with_note():
    a = confirm_race(BASELINE, BURST_RACE)
    assert a.is_race
    assert not a.final_state_verified
    assert a.confidence == "medium"
    assert a.notes  # caveat recorded


def test_empty_baseline_defaults_expected_to_one():
    a = confirm_race([], BURST_RACE)
    assert a.expected_max_successes == 1
    assert a.is_race


def test_explicit_expected_max_successes_override():
    # A limit of 3 means 3 successes is NOT over the limit.
    a = confirm_race([], BURST_RACE, expected_max_successes=3)
    assert not a.is_race


def test_build_finding_from_confirmed_race():
    a = confirm_race(BASELINE, BURST_RACE, final_state_success_count=3)
    f = build_finding(
        a,
        target="https://shop.example.com/redeem",
        vector="single-packet:/redeem",
        variant="single-endpoint",
        finding_id="reaper-0007",
        references=["https://portswigger.net/research/smashing-the-state-machine"],
    )
    assert f is not None
    assert f.id == "reaper-0007"
    assert f.tool == "reaper"
    assert f.cwe_id == 362
    assert f.severity == "high"
    assert f.confidence == "high"
    assert f.evidence["anomalous_response_count"] == 2
    assert f.evidence["baseline_vs_burst"]["burst"]["success_count"] == 3
    assert f.evidence["expected_max_successes"] == 1
    assert f.references  # reference propagated through


def test_build_finding_returns_none_when_no_race():
    a = confirm_race(BASELINE, BURST_CLEAN)
    assert build_finding(a, target="https://x/redeem", vector="single-packet:/x") is None


def test_build_finding_returns_none_when_guard_suppresses():
    a = confirm_race(BASELINE, BURST_RACE, final_state_success_count=1)
    assert build_finding(a, target="https://x/redeem", vector="single-packet:/x") is None
