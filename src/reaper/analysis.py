"""Benchmark -> burst deviation confirmation (V0.1-CRITERIA.md #5).

Given the sequential-baseline signatures and the concurrent-burst signatures,
this module decides whether a race was confirmed and, if so, builds the evidence
dict and the :class:`~reaper.findings.Finding`.

The signal for a single-endpoint limit-overrun is simple and robust: a correctly
synchronized single-use resource yields **exactly one success** even under a
concurrent burst, so *more* successes in the burst than the resource's limit
allows is the race. The baseline (when supplied) both establishes that limit and
provides the status/body/timing reference the burst is diffed against.

**Final-state false-positive guard.** An early race win that a later request
overwrites/invalidates is NOT a real finding (V0.1-CRITERIA.md #5). When a
post-burst verification read-back is available (``final_state_success_count``),
a finding is suppressed unless the *persisted* success count also exceeds the
limit. Without a read-back the surplus successes are reported at reduced
confidence and the caveat is recorded in the evidence notes.

R5: response bytes are represented here only by their sha256 hash and status --
never executed or interpreted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from statistics import fmean, pstdev
from typing import Callable, Iterable

from reaper.findings import Finding, race_evidence
from reaper.httpspec import ResponseSignature

__all__ = [
    "RaceAnalysis",
    "build_finding",
    "confirm_race",
    "summarize",
    "timing_distribution",
]

# Default predicate for "the limited operation succeeded": any 2xx status.
def _default_success(sig: ResponseSignature) -> bool:
    return 200 <= sig.status < 300


SuccessPredicate = Callable[[ResponseSignature], bool]


def summarize(
    sigs: Iterable[ResponseSignature],
    *,
    is_success: SuccessPredicate = _default_success,
) -> dict:
    """Summarize a batch of response signatures for the evidence report.

    Returns status distribution, success count, the set of distinct
    success-response body hashes (distinct hashes among successes hint at
    distinct state commits vs. the same response echoed), and total count.
    """
    sigs = list(sigs)
    statuses: dict[str, int] = {}
    for s in sigs:
        statuses[str(s.status)] = statuses.get(str(s.status), 0) + 1
    successes = [s for s in sigs if is_success(s)]
    return {
        "count": len(sigs),
        "statuses": statuses,
        "success_count": len(successes),
        "distinct_success_body_hashes": sorted(
            {s.body_sha256 for s in successes}
        ),
        "second_order": sorted({s.second_order for s in sigs if s.second_order}),
    }


def timing_distribution(sigs: Iterable[ResponseSignature]) -> dict:
    """Timing distribution of a burst (proves the requests landed in one window)."""
    times = [s.elapsed_ms for s in sigs]
    if not times:
        return {"unit": "ms", "samples": 0}
    return {
        "unit": "ms",
        "samples": len(times),
        "min": round(min(times), 3),
        "max": round(max(times), 3),
        "mean": round(fmean(times), 3),
        "spread": round(max(times) - min(times), 3),
        "stdev": round(pstdev(times), 3) if len(times) > 1 else 0.0,
    }


@dataclass(slots=True)
class RaceAnalysis:
    """The outcome of a baseline-vs-burst comparison."""

    is_race: bool
    baseline_summary: dict
    burst_summary: dict
    expected_max_successes: int
    burst_success_count: int
    anomalous_response_count: int
    timing: dict
    final_state_ok: bool
    final_state_verified: bool
    confidence: str
    reason: str
    notes: str = ""
    references: list[str] = field(default_factory=list)


def confirm_race(
    baseline: Iterable[ResponseSignature],
    burst: Iterable[ResponseSignature],
    *,
    is_success: SuccessPredicate = _default_success,
    expected_max_successes: int | None = None,
    final_state_success_count: int | None = None,
) -> RaceAnalysis:
    """Compare the sequential baseline against the concurrent burst.

    Parameters
    ----------
    baseline:
        Sequential baseline signatures (may be empty if the baseline was skipped
        because the resource is single-use -- see the runner).
    burst:
        Concurrent-burst signatures.
    is_success:
        Predicate marking a response as the limited operation succeeding
        (default: any 2xx).
    expected_max_successes:
        The number of successes a correctly synchronized server should allow in
        one window. Defaults to the baseline success count when a baseline ran,
        else ``1`` (the single-use-resource limit).
    final_state_success_count:
        Successes that PERSISTED, from a post-burst verification read-back. When
        provided, the final-state guard requires this to exceed the limit too.
    """
    baseline = list(baseline)
    burst = list(burst)
    baseline_summary = summarize(baseline, is_success=is_success)
    burst_summary = summarize(burst, is_success=is_success)

    if expected_max_successes is None:
        expected_max_successes = (
            baseline_summary["success_count"] if baseline else 1
        )
    burst_success = burst_summary["success_count"]
    surplus = max(0, burst_success - expected_max_successes)

    # --- final-state false-positive guard ---
    final_state_verified = final_state_success_count is not None
    if final_state_verified:
        final_state_ok = final_state_success_count > expected_max_successes
    else:
        final_state_ok = True  # cannot disprove; reduced confidence below

    over_limit = burst_success > expected_max_successes
    is_race = over_limit and final_state_ok

    if not over_limit:
        reason = (
            f"burst produced {burst_success} success(es) <= the "
            f"{expected_max_successes} a synchronized server permits; no race"
        )
    elif not final_state_ok:
        reason = (
            f"burst showed {burst_success} successes but the verified final "
            f"state committed only {final_state_success_count} "
            f"(<= {expected_max_successes}); early win overwritten -- "
            "final-state false positive suppressed"
        )
    else:
        reason = (
            f"burst forced {burst_success} successes where a synchronized "
            f"server permits {expected_max_successes} "
            f"({surplus} over the limit)"
        )

    # Confidence: high when the persisted over-commit was verified; medium when
    # the surplus is only observed in responses (persistence unverified).
    if is_race and final_state_verified:
        confidence = "high"
    elif is_race:
        confidence = "medium"
    else:
        confidence = "low"

    notes = ""
    if is_race and not final_state_verified:
        notes = (
            "surplus successes observed in responses but not verified against "
            "server final state; supply a read-back to confirm persistence"
        )

    return RaceAnalysis(
        is_race=is_race,
        baseline_summary=baseline_summary,
        burst_summary=burst_summary,
        expected_max_successes=expected_max_successes,
        burst_success_count=burst_success,
        anomalous_response_count=surplus,
        timing=timing_distribution(burst),
        final_state_ok=final_state_ok,
        final_state_verified=final_state_verified,
        confidence=confidence,
        reason=reason,
        notes=notes,
    )


def build_finding(
    analysis: RaceAnalysis,
    *,
    target: str,
    vector: str,
    variant: str | None = None,
    finding_id: str = "reaper-0001",
    title: str | None = None,
    severity: str = "high",
    references: Iterable[str] | None = None,
) -> Finding | None:
    """Build a :class:`~reaper.findings.Finding` from a confirmed race, else None.

    Returns ``None`` when ``analysis.is_race`` is False (including when the
    final-state guard suppressed a false positive) -- callers emit nothing.
    """
    if not analysis.is_race:
        return None

    if title is None:
        n = analysis.burst_success_count
        title = (
            f"Limit-overrun race: {n} concurrent successes via "
            f"{vector.split(':', 1)[0]}"
        )

    evidence = race_evidence(
        baseline=analysis.baseline_summary,
        burst=analysis.burst_summary,
        anomalous_response_count=analysis.anomalous_response_count,
        timing_distribution=analysis.timing,
        reproducible=analysis.final_state_verified or None,
        notes=(
            f"{analysis.reason}."
            + (f" {analysis.notes}." if analysis.notes else "")
        ),
    )
    evidence["expected_max_successes"] = analysis.expected_max_successes
    evidence["final_state_verified"] = analysis.final_state_verified

    return Finding(
        id=finding_id,
        tool="reaper",
        title=title,
        severity=severity,
        confidence=analysis.confidence,
        target=target,
        vector=vector,
        variant=variant,
        evidence=evidence,
        references=list(references or []),
    )
