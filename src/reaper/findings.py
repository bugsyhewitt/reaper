"""Structured finding model for reaper -- the pinned suite Finding contract.

reaper implements the **pinned Finding contract** documented in
``scan-primitives/SPEC.md`` (appendix) exactly, so that when the shared
``web-finding-schema`` lib is later extracted, adopting it is a move rather than
a rewrite. Every field in the contract is present here, in contract order, with
reaper-specific defaults:

- ``tool`` is always ``"reaper"``.
- ``cwe_id`` defaults to **362** -- CWE-362, "Concurrent Execution using Shared
  Resource with Improper Synchronization" (the race-condition anchor).
- ``evidence`` is a free-form dict that, for reaper, carries the
  **baseline-vs-burst diff**, the **count of anomalous responses**, and the
  **timing distribution** of the burst. :func:`race_evidence` documents and
  builds that canonical shape.

Severity casing is **lowercase** to match the real ``h1-reporter`` taxonomy.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

# h1-reporter severity taxonomy, lowest to highest.
SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")
# Confidence levels, lowest to highest.
CONFIDENCES: tuple[str, ...] = ("low", "medium", "high")

# Literal aliases mirroring the pinned contract's inline unions.
Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]

# CWE-362: Concurrent Execution using Shared Resource with Improper
# Synchronization ("Race Condition") -- reaper's anchor CWE.
CWE_RACE_CONDITION = 362


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class Finding:
    """A single confirmed race-condition finding, shaped to the pinned contract.

    Fields are in the exact order of ``scan-primitives/SPEC.md``:

        id           stable identifier for this finding
        tool         producing tool -- always ``"reaper"``
        title        short headline
        severity     one of :data:`SEVERITIES` (h1-reporter taxonomy)
        confidence   one of :data:`CONFIDENCES`
        target       URL / host the race was confirmed against
        vector       technique / injection point, e.g.
                     ``"single-packet:/redeem"`` or ``"last-byte-sync:/withdraw"``
        variant      payload / scenario variant (single-endpoint vs group)
        cwe_id       defaults to :data:`CWE_RACE_CONDITION` (362)
        evidence     baseline-vs-burst diff + anomalous-response count + timing
                     distribution (see :func:`race_evidence`)
        oob_proof    out-of-band callback proof (unused by reaper; kept for the
                     shared contract -- wraith populates it)
        references   external references (advisories, research)
        created_at   ISO-8601 creation timestamp
    """

    id: str
    tool: str
    title: str
    severity: Severity
    confidence: Confidence
    target: str
    vector: str
    variant: str | None = None
    cwe_id: int | None = CWE_RACE_CONDITION
    evidence: dict[str, Any] = field(default_factory=dict)
    oob_proof: str | None = None
    references: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=_now_iso)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(
                f"severity must be one of {SEVERITIES}, got {self.severity!r}"
            )
        if self.confidence not in CONFIDENCES:
            raise ValueError(
                f"confidence must be one of {CONFIDENCES}, got {self.confidence!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict for this finding (contract order)."""
        return dataclasses.asdict(self)


def race_evidence(
    *,
    baseline: dict[str, Any],
    burst: dict[str, Any],
    anomalous_response_count: int,
    timing_distribution: dict[str, Any],
    reproducible: bool | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
    """Build the canonical reaper evidence dict.

    reaper's finding evidence must carry three things (V0.1-CRITERIA.md #5):

    - ``baseline_vs_burst`` -- the sequential baseline signature vs the
      concurrent-burst signature (status codes, body hashes, second-order
      signals) so a triager can see exactly what deviated.
    - ``anomalous_response_count`` -- e.g. "2 of 20 returned 200 where the
      baseline gave one 200 + rest 409".
    - ``timing_distribution`` -- the burst arrival/timing distribution proving
      the requests landed in one window.

    ``reproducible`` and ``notes`` are optional. The dict is free-form (the
    ``Finding.evidence`` field type is ``dict``); this helper only documents and
    assembles the shape the deviation-confirmation stage will emit.
    """
    evidence: dict[str, Any] = {
        "baseline_vs_burst": {"baseline": baseline, "burst": burst},
        "anomalous_response_count": anomalous_response_count,
        "timing_distribution": timing_distribution,
    }
    if reproducible is not None:
        evidence["reproducible"] = reproducible
    if notes is not None:
        evidence["notes"] = notes
    return evidence
