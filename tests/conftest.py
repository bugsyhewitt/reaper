"""Shared pytest fixtures for the reaper test suite."""

from __future__ import annotations

import pytest

from reaper.findings import Finding, race_evidence


@pytest.fixture
def sample_evidence() -> dict:
    """A canonical reaper evidence dict: baseline-vs-burst + counts + timing."""
    return race_evidence(
        baseline={"statuses": {"200": 1, "409": 19}, "success_count": 1},
        burst={"statuses": {"200": 3, "409": 17}, "success_count": 3},
        anomalous_response_count=2,
        timing_distribution={"unit": "ms", "spread": 1.8, "samples": 20},
        reproducible=True,
        notes="2 of 20 returned 200 where baseline gave one 200 + rest 409",
    )


@pytest.fixture
def sample_finding(sample_evidence: dict) -> Finding:
    """A representative confirmed single-packet race finding."""
    return Finding(
        id="reaper-0001",
        tool="reaper",
        title="Coupon redeemed 3x via single-packet race",
        severity="high",
        confidence="high",
        target="https://shop.example.com/redeem",
        vector="single-packet:/redeem",
        variant="single-endpoint",
        evidence=sample_evidence,
        references=["https://portswigger.net/research/smashing-the-state-machine"],
    )
