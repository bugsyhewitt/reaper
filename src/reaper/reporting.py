"""HackerOne-markdown output for reaper, built on the shared h1-reporter lib.

reaper's internal :class:`reaper.findings.Finding` is race-shaped (id / vector /
target / baseline-vs-burst evidence). The HackerOne submission body is not
reaper's concern -- that formatting lives in the suite-wide ``h1_reporter``
library so every necromancer tool produces a consistent report. This module is
the thin adapter that maps a reaper finding into an ``h1_reporter.Finding``
(reaper is the 2nd real adopter of h1-reporter, after ferryman).

The mapping is intentionally faithful to the pinned contract's adapter spec
(``scan-primitives/SPEC.md``): ``to_h1(finding) -> h1_reporter.Finding``, then
``to_h1md(findings)`` renders the batch with ``h1_reporter.render_h1md``.
"""

from __future__ import annotations

import json
from typing import Iterable

from h1_reporter import Finding as H1Finding
from h1_reporter import render_h1md

from reaper.findings import Finding

# Race-condition business-impact framing (CWE-362). Confirmed limit-overrun
# races are the high-value class: over-redeemed coupons, over-withdrawn
# balances, MFA/OTP sub-state bypasses.
_IMPACT = (
    "A confirmed race condition lets a limit-once operation execute more than "
    "once within a single check-then-act window -- over-redeeming a coupon, "
    "over-withdrawing a balance, or bypassing an MFA/OTP sub-state gate. The "
    "impact is direct financial or authentication-integrity loss for the "
    "program owner."
)


def _evidence_blocks(f: Finding) -> list[str]:
    """Render the evidence dict as report code blocks.

    reaper evidence carries the baseline-vs-burst diff, the anomalous-response
    count, and the timing distribution; each renders as a fenced JSON block.
    R5: response bytes are data -- they are serialised, never executed.
    """
    if not f.evidence:
        return []
    return [json.dumps(f.evidence, indent=2, default=str, sort_keys=True)]


def to_h1(f: Finding) -> H1Finding:
    """Map one reaper finding into the shared h1_reporter Finding shape."""
    repro: list[str] = [
        f"Send the sequential baseline to `{f.target}` and record the "
        "status/body/timing signature (exactly one success expected).",
        f"Fire the concurrent burst via `{f.vector}` and compare against the "
        "baseline.",
        "Confirm more than one success (an over-limit condition sequential "
        "requests cannot produce) and that the win is not overwritten by a "
        "later request (final-state guard).",
    ]

    description_parts = [
        f"{f.title}.",
        f"Confirmed against `{f.target}` via `{f.vector}`",
    ]
    if f.variant:
        description_parts.append(f"(scenario: {f.variant})")
    if f.cwe_id is not None:
        description_parts.append(f"CWE-{f.cwe_id}.")
    description = " ".join(description_parts)

    return H1Finding(
        title=f.title,
        severity=f.severity,
        description=description,
        reproduction_steps=repro,
        business_impact=_IMPACT,
        evidence=_evidence_blocks(f),
    )


def to_h1md(findings: Iterable[Finding]) -> str:
    """Render reaper findings to HackerOne-flavored markdown."""
    mapped = [to_h1(f) for f in findings]
    return render_h1md(mapped, title="reaper race-condition findings")
