"""SARIF 2.1.0 output for reaper.

SARIF (Static Analysis Results Interchange Format) is the standard machine
output for security scanners: GitHub's Security tab, the VS Code Problems panel,
and most CI SAST dashboards ingest it natively. Emitting SARIF lets reaper's
confirmed race findings appear alongside professional tooling.

This mirrors ferryman's SARIF 2.1.0 structure and the pinned contract's adapter
spec (``scan-primitives/SPEC.md``), with one deliberate difference: reaper's
:func:`to_sarif` returns a **dict** (the SARIF document object) rather than a
JSON string, per the pinned adapter signature ``to_sarif(findings) -> dict``.
Callers serialise with ``json.dumps`` at the edge.

Severity mapping (pinned contract): ``critical``/``high`` -> ``error``,
``medium`` -> ``warning``, ``low``/``info`` -> ``note``; the exact reaper
severity is preserved in ``properties.severity`` plus a numeric ``rank`` (0-100)
so SARIF consumers that surface rank order findings the way reaper does. The
``ruleId`` is ``"<tool>/<vector-class>"`` (e.g. ``reaper/single-packet``) and
``partialFingerprints`` carries the finding ``id``.
"""

from __future__ import annotations

from typing import Any, Iterable

from reaper import __version__
from reaper.findings import Finding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemas/sarif-schema-2.1.0.json"
)

# reaper severity -> SARIF result.level (the coarse SARIF enum).
_LEVEL_BY_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# reaper severity -> SARIF rank (0.0..100.0; higher = more severe).
_RANK_BY_SEVERITY = {
    "critical": 100.0,
    "high": 80.0,
    "medium": 50.0,
    "low": 20.0,
    "info": 5.0,
}


def _level_for(severity: str) -> str:
    return _LEVEL_BY_SEVERITY.get(severity, "warning")


def _rank_for(severity: str) -> float:
    return _RANK_BY_SEVERITY.get(severity, 50.0)


def _vector_class(vector: str) -> str:
    """The rule-grouping class of a vector.

    A reaper vector reads ``<technique>:<endpoint>`` (e.g.
    ``single-packet:/redeem``); the class is the technique before the colon.
    A vector with no colon (e.g. ``last-byte-sync``) is its own class.
    """
    if not vector:
        return "race"
    return vector.split(":", 1)[0]


def _rule_id(f: Finding) -> str:
    """Stable rule id: ``<tool>/<vector-class>`` (e.g. ``reaper/single-packet``)."""
    return f"{f.tool}/{_vector_class(f.vector)}"


def _result_for(f: Finding) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "severity": f.severity,
        "confidence": f.confidence,
        "vector": f.vector,
    }
    if f.variant is not None:
        properties["variant"] = f.variant
    if f.cwe_id is not None:
        properties["cwe"] = f"CWE-{f.cwe_id}"

    result: dict[str, Any] = {
        "ruleId": _rule_id(f),
        "level": _level_for(f.severity),
        "rank": _rank_for(f.severity),
        "message": {"text": f.title or _rule_id(f)},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": f.target}}}
        ],
        "partialFingerprints": {"reaperFindingId": f.id},
        "properties": properties,
    }
    return result


def _rules_for(findings: list[Finding]) -> list[dict[str, Any]]:
    """One SARIF reportingDescriptor per distinct rule id, sorted for stability."""
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(_rule_id(f), f)
    rules: list[dict[str, Any]] = []
    for rule_id in sorted(seen):
        f = seen[rule_id]
        rule: dict[str, Any] = {
            "id": rule_id,
            "name": rule_id.replace("/", "_"),
            "shortDescription": {
                "text": f"{f.tool} race check: {_vector_class(f.vector)}"
            },
            "defaultConfiguration": {"level": _level_for(f.severity)},
            "properties": {"tool": f.tool, "vectorClass": _vector_class(f.vector)},
        }
        if f.cwe_id is not None:
            rule["properties"]["cwe"] = f"CWE-{f.cwe_id}"
        rules.append(rule)
    return rules


def to_sarif(findings: Iterable[Finding]) -> dict[str, Any]:
    """Render reaper findings to a SARIF 2.1.0 document (as a dict).

    Returns the SARIF document object; serialise with ``json.dumps`` at the CLI
    edge. Signature matches the pinned contract: ``to_sarif(findings) -> dict``.
    """
    findings = list(findings)
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "reaper",
                        "version": __version__,
                        "informationUri": "https://github.com/bugsyhewitt/reaper",
                        "rules": _rules_for(findings),
                    }
                },
                "results": [_result_for(f) for f in findings],
            }
        ],
    }
