"""Real, passing tests for the reaper Finding contract + SARIF + h1md adapters.

These exercise the fully-implemented output surface (findings / sarif /
reporting). The engine and client are stubs and are NOT exercised here; the
live race-lab acceptance test lives in ``test_wheel_ship_gate.py`` as a
skip/TODO pending the v0.1 build.
"""

from __future__ import annotations

import pytest

from reaper import __version__
from reaper.findings import (
    CONFIDENCES,
    CWE_RACE_CONDITION,
    SEVERITIES,
    Finding,
    race_evidence,
)
from reaper.reporting import to_h1, to_h1md
from reaper.sarif import SARIF_VERSION, to_sarif


# --- Finding contract ------------------------------------------------------


def test_severity_and_confidence_tuples():
    assert SEVERITIES == ("info", "low", "medium", "high", "critical")
    assert CONFIDENCES == ("low", "medium", "high")


def test_finding_defaults_cwe_362(sample_finding: Finding):
    """cwe_id defaults to 362 (CWE-362 race condition); evidence/refs are set."""
    assert CWE_RACE_CONDITION == 362
    assert sample_finding.cwe_id == 362
    assert sample_finding.tool == "reaper"
    assert sample_finding.oob_proof is None  # unused by reaper, present for contract
    assert isinstance(sample_finding.created_at, str) and sample_finding.created_at


def test_finding_default_factories_are_independent():
    a = Finding(
        id="a", tool="reaper", title="t", severity="low", confidence="low",
        target="https://a.example", vector="single-packet:/x",
    )
    b = Finding(
        id="b", tool="reaper", title="t", severity="low", confidence="low",
        target="https://b.example", vector="single-packet:/y",
    )
    a.evidence["k"] = 1
    a.references.append("r")
    assert b.evidence == {}  # not shared across instances
    assert b.references == []


def test_finding_rejects_bad_severity_and_confidence():
    with pytest.raises(ValueError):
        Finding(
            id="x", tool="reaper", title="t", severity="urgent", confidence="high",
            target="https://e.example", vector="single-packet:/x",
        )
    with pytest.raises(ValueError):
        Finding(
            id="x", tool="reaper", title="t", severity="high", confidence="certain",
            target="https://e.example", vector="single-packet:/x",
        )


def test_evidence_carries_baseline_burst_counts_and_timing():
    ev = race_evidence(
        baseline={"success_count": 1},
        burst={"success_count": 4},
        anomalous_response_count=3,
        timing_distribution={"unit": "ms", "spread": 2.1},
    )
    assert ev["baseline_vs_burst"]["baseline"]["success_count"] == 1
    assert ev["baseline_vs_burst"]["burst"]["success_count"] == 4
    assert ev["anomalous_response_count"] == 3
    assert ev["timing_distribution"]["unit"] == "ms"


def test_to_dict_roundtrips_contract_fields(sample_finding: Finding):
    d = sample_finding.to_dict()
    for key in (
        "id", "tool", "title", "severity", "confidence", "target", "vector",
        "variant", "cwe_id", "evidence", "oob_proof", "references", "created_at",
    ):
        assert key in d
    assert d["cwe_id"] == 362


# --- SARIF 2.1.0 -----------------------------------------------------------


def test_to_sarif_is_dict_and_2_1_0(sample_finding: Finding):
    doc = to_sarif([sample_finding])
    assert isinstance(doc, dict)  # pinned contract: to_sarif -> dict
    assert doc["version"] == "2.1.0" == SARIF_VERSION
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "reaper"
    assert driver["version"] == __version__


def test_to_sarif_result_mapping(sample_finding: Finding):
    doc = to_sarif([sample_finding])
    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == "reaper/single-packet"
    assert result["level"] == "error"  # high -> error
    assert result["rank"] == 80.0
    assert result["message"]["text"] == sample_finding.title
    loc = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert loc == sample_finding.target
    assert result["partialFingerprints"]["reaperFindingId"] == "reaper-0001"
    assert result["properties"]["severity"] == "high"
    assert result["properties"]["cwe"] == "CWE-362"


def test_to_sarif_severity_levels_span_the_enum():
    findings = [
        Finding(id=str(i), tool="reaper", title=f"f{i}", severity=sev,
                confidence="medium", target="https://e.example",
                vector="single-packet:/x")
        for i, sev in enumerate(SEVERITIES)
    ]
    levels = {r["level"] for r in to_sarif(findings)["runs"][0]["results"]}
    assert levels == {"error", "warning", "note"}


def test_to_sarif_rules_deduped_by_vector_class():
    findings = [
        Finding(id="1", tool="reaper", title="a", severity="high",
                confidence="high", target="https://e.example",
                vector="single-packet:/redeem"),
        Finding(id="2", tool="reaper", title="b", severity="medium",
                confidence="medium", target="https://e.example",
                vector="single-packet:/withdraw"),
        Finding(id="3", tool="reaper", title="c", severity="low",
                confidence="low", target="https://e.example",
                vector="last-byte-sync:/confirm"),
    ]
    rules = to_sarif(findings)["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = {r["id"] for r in rules}
    assert rule_ids == {"reaper/single-packet", "reaper/last-byte-sync"}


# --- HackerOne markdown ----------------------------------------------------


def test_to_h1_maps_to_h1_finding(sample_finding: Finding):
    h1 = to_h1(sample_finding)
    assert h1.title == sample_finding.title
    assert h1.severity == "high"
    assert h1.reproduction_steps  # non-empty
    assert h1.business_impact
    assert h1.evidence  # evidence dict rendered into a block


def test_to_h1md_renders_markdown(sample_finding: Finding):
    md = to_h1md([sample_finding])
    assert isinstance(md, str)
    assert "reaper race-condition findings" in md
    assert sample_finding.title in md
