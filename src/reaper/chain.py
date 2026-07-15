"""State-chain multi-endpoint orchestration (``reaper group --state-chain``, v0.5).

A state-chain fires one request per endpoint simultaneously within a single race
window (one HTTP/2 connection, one synchronized ``send()`` call). Classic
use-case: race a "transfer funds" endpoint simultaneously with a "check balance"
endpoint to exploit a TOCTOU -- both arrive at the server within the race window,
not just multiple copies of one request.

The burst engine (``SinglePacketEngine.run_group``) already handles this
mechanically; this module adds per-endpoint labeling, client-side timing-spread
analysis (a proxy for server-side co-arrival), and differential-response
detection on top.

R5: response signatures carry only status + body SHA-256 + timing -- no response
bytes are passed through, evaluated, or executed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from statistics import fmean, pstdev
from typing import Iterable

from reaper.findings import Finding
from reaper.httpspec import RaceRequest, ResponseSignature

__all__ = [
    "ChainEndpointResult",
    "StateChainAnalysis",
    "analyze_chain",
    "build_chain_finding",
    "DEFAULT_WINDOW_MS",
]

DEFAULT_WINDOW_MS = 10.0  # ms -- expected max response-spread for a valid chain


@dataclass(slots=True)
class ChainEndpointResult:
    """Per-endpoint result from a state-chain burst."""

    label: str              # file basename / short identifier for this endpoint
    request: RaceRequest
    signature: ResponseSignature


@dataclass(slots=True)
class StateChainAnalysis:
    """Outcome of a state-chain burst analysis."""

    spread_ms: float            # response-time spread across all endpoints (ms)
    within_window: bool         # spread_ms <= window_ms
    window_ms: float            # the threshold used for within_window
    per_endpoint: list[dict]    # per-endpoint status, timing, differential flag
    timing: dict                # overall timing distribution across endpoints
    differential_found: bool    # any endpoint returned an unexpected status?
    reason: str
    notes: str = ""


def analyze_chain(
    results: list[ChainEndpointResult],
    *,
    window_ms: float = DEFAULT_WINDOW_MS,
    expected_status: int | None = None,
) -> StateChainAnalysis:
    """Analyze state-chain responses for timing spread and differential signals.

    Parameters
    ----------
    results:
        One entry per endpoint, in chain order.
    window_ms:
        Maximum acceptable response-time spread (in ms) to consider the chain
        co-arrived at the server (default 10 ms). Response timing is a
        client-side proxy for server-side request arrival; a tight spread is a
        necessary (not sufficient) condition for a valid race window.
    expected_status:
        When set, any endpoint returning a different HTTP status is flagged as a
        differential hit. Defaults to 200.
    """
    if not results:
        return StateChainAnalysis(
            spread_ms=0.0,
            within_window=True,
            window_ms=window_ms,
            per_endpoint=[],
            timing={"unit": "ms", "samples": 0},
            differential_found=False,
            reason="no chain results",
        )

    exp = expected_status if expected_status is not None else 200
    times = [r.signature.elapsed_ms for r in results]
    mn, mx = min(times), max(times)
    spread = round(mx - mn, 3)
    within_window = spread <= window_ms

    per_endpoint = [
        {
            "label": r.label,
            "path": r.request.path,
            "status": r.signature.status,
            "elapsed_ms": round(r.signature.elapsed_ms, 3),
            "body_sha256_prefix": r.signature.body_sha256[:16],
            "differential": r.signature.status != exp,
        }
        for r in results
    ]
    differentials = [ep for ep in per_endpoint if ep["differential"]]
    differential_found = bool(differentials)

    timing: dict = {
        "unit": "ms",
        "samples": len(times),
        "min": round(mn, 3),
        "max": round(mx, 3),
        "mean": round(fmean(times), 3),
        "spread": spread,
        "stdev": round(pstdev(times), 3) if len(times) > 1 else 0.0,
    }

    if within_window and not differential_found:
        reason = (
            f"chain fired {len(results)} endpoints within {spread:.1f}ms spread "
            f"(<= {window_ms}ms window); all returned expected status {exp}"
        )
    elif not within_window:
        reason = (
            f"response spread {spread:.1f}ms exceeds {window_ms}ms window — "
            "endpoints may not have co-arrived at the server"
        )
    else:
        paths = ", ".join(ep["path"] for ep in differentials)
        reason = (
            f"differential response(s) at {paths} "
            f"(expected HTTP {exp}); spread {spread:.1f}ms"
        )

    return StateChainAnalysis(
        spread_ms=spread,
        within_window=within_window,
        window_ms=window_ms,
        per_endpoint=per_endpoint,
        timing=timing,
        differential_found=differential_found,
        reason=reason,
    )


def build_chain_finding(
    analysis: StateChainAnalysis,
    *,
    target: str,
    vector: str,
    finding_id: str = "reaper-0002",
    severity: str = "high",
    references: Iterable[str] | None = None,
) -> Finding | None:
    """Build a Finding from a differential state-chain result, else None.

    Returns None when no differential responses were detected. A wide spread
    alone (``within_window=False``) is a timing hint, not a confirmed finding;
    the caller should retry or use ``reaper detect`` first.
    """
    if not analysis.differential_found:
        return None

    diffs = [ep for ep in analysis.per_endpoint if ep["differential"]]
    title = (
        "Sub-state chain race: differential response at "
        + ", ".join(ep["path"] for ep in diffs)
    )

    evidence: dict = {
        "spread_ms": analysis.spread_ms,
        "window_ms": analysis.window_ms,
        "within_window": analysis.within_window,
        "per_endpoint": analysis.per_endpoint,
        "timing": analysis.timing,
        "notes": analysis.reason,
    }

    return Finding(
        id=finding_id,
        tool="reaper",
        title=title,
        severity=severity,
        # Server-side co-arrival is unverifiable from the client; medium confidence.
        confidence="medium",
        target=target,
        vector=vector,
        variant="state-chain",
        evidence=evidence,
        references=list(references or []),
    )
