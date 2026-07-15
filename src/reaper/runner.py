"""Scenario orchestration: benchmark -> burst -> confirm -> Finding.

Ties the pieces together for the CLI (:mod:`reaper.cli`) and tests:

1. scope-check + select the burst transport (probe when ``auto``);
2. run the sequential baseline via :class:`reaper.client.BaselineClient`
   (scan-primitives) -- OPT-IN, because on a single-use resource the baseline
   consumes the very unit under test (see the ``baseline_samples`` note);
3. fire the concurrent burst via the raw engine (:mod:`reaper.engine`);
4. confirm the deviation and build findings (:mod:`reaper.analysis`).

[Worker decision: ``baseline_samples`` defaults to 0. reaper's authoritative
over-limit signal is the burst itself -- a correctly synchronized server yields
exactly one success even under a concurrent burst. A sequential baseline is
opt-in (renewable-resource calibration / richer evidence); when supplied it runs
FIRST and its success count becomes the expected limit, faithful to
V0.1-CRITERIA.md #5. The acceptance-gate lab drives the sequential *control* and
the concurrent *attack* on independent resources exactly as the criteria's
deterministic gate specifies.]
"""

from __future__ import annotations

import asyncio
from typing import Any

import dataclasses

from reaper.analysis import RaceAnalysis, build_finding, confirm_race
from reaper.client import BaselineClient
from reaper.engine import (
    TRANSPORT_AUTO,
    TRANSPORT_H1_LAST_BYTE_SYNC,
    TRANSPORT_H2_SINGLE_PACKET,
    LastByteSyncEngine,
    SinglePacketEngine,
    TransportError,
    select_transport,
)
from reaper.findings import Finding
from reaper.httpspec import RaceRequest, ResponseSignature, split_target

__all__ = ["ScenarioResult", "run_group_scenario", "run_single_scenario"]


class ScenarioResult:
    """The result of running a scenario: chosen transport, signatures, findings."""

    def __init__(
        self,
        *,
        transport: str,
        baseline: list[ResponseSignature],
        burst: list[ResponseSignature],
        analysis: RaceAnalysis | None,
        findings: list[Finding],
    ) -> None:
        self.transport = transport
        self.baseline = baseline
        self.burst = burst
        self.analysis = analysis
        self.findings = findings


def _vector(transport: str, path: str) -> str:
    technique = (
        "single-packet"
        if transport == TRANSPORT_H2_SINGLE_PACKET
        else "last-byte-sync"
    )
    return f"{technique}:{path}"


def _run_baseline(
    scope: Any,
    request: RaceRequest,
    samples: int,
    *,
    target: str,
    rate_limit: float | None,
    proxy: str | None,
    timeout: float,
    verify_tls: bool,
) -> list[ResponseSignature]:
    async def _go() -> list[ResponseSignature]:
        async with BaselineClient(
            scope,
            rate_limit=rate_limit,
            proxy=proxy,
            timeout=timeout,
            verify=verify_tls,
        ) as client:
            return await client.baseline(request, samples, target=target)

    return asyncio.run(_go())


def _make_engine(
    transport: str,
    scope: Any,
    target: str,
    *,
    settle: float,
    timeout: float,
    verify_tls: bool,
    proxy: str | None = None,
) -> SinglePacketEngine | LastByteSyncEngine:
    if transport == TRANSPORT_H1_LAST_BYTE_SYNC:
        return LastByteSyncEngine(
            scope, target, settle=settle, timeout=timeout, verify_tls=verify_tls,
            proxy=proxy,
        )
    return SinglePacketEngine(
        scope, target, settle=settle, timeout=timeout, verify_tls=verify_tls,
        proxy=proxy,
    )


def run_single_scenario(
    *,
    target: str,
    scope: Any,
    request: RaceRequest,
    copies: int,
    transport: str = TRANSPORT_AUTO,
    baseline_samples: int = 0,
    expected_max_successes: int | None = None,
    final_state_success_count: int | None = None,
    rate_limit: float | None = None,
    proxy: str | None = None,
    settle: float = 0.1,
    timeout: float = 10.0,
    verify_tls: bool = True,
    finding_id: str = "reaper-0001",
) -> ScenarioResult:
    """Single-endpoint limit-overrun scenario (V0.1-CRITERIA.md #3 + #5).

    Scope is enforced before any socket opens (transport probe, baseline, and
    burst all honour ``scope``).
    """
    if scope is not None:
        scope.assert_in_scope(target)

    chosen = select_transport(
        target, prefer=transport, scope=scope, verify_tls=verify_tls, proxy=proxy
    )

    baseline: list[ResponseSignature] = []
    if baseline_samples > 0:
        baseline = _run_baseline(
            scope,
            request,
            baseline_samples,
            target=target,
            rate_limit=rate_limit,
            proxy=proxy,
            timeout=timeout,
            verify_tls=verify_tls,
        )

    engine = _make_engine(
        chosen, scope, target, settle=settle, timeout=timeout,
        verify_tls=verify_tls, proxy=proxy,
    )
    try:
        burst = engine.run_single_endpoint(request, copies)
    except TransportError:
        if transport == TRANSPORT_AUTO and chosen == TRANSPORT_H2_SINGLE_PACKET:
            # Auto fallback H2 -> H1 (peer refused HTTP/2 mid-flight).
            chosen = TRANSPORT_H1_LAST_BYTE_SYNC
            engine = _make_engine(
                chosen, scope, target, settle=settle, timeout=timeout,
                verify_tls=verify_tls, proxy=proxy,
            )
            burst = engine.run_single_endpoint(request, copies)
        else:
            raise

    analysis = confirm_race(
        baseline,
        burst,
        expected_max_successes=expected_max_successes,
        final_state_success_count=final_state_success_count,
    )
    _scheme, _host, _port, _auth = split_target(target)
    finding = build_finding(
        analysis,
        target=target,
        vector=_vector(chosen, request.path),
        variant="single-endpoint",
        finding_id=finding_id,
        references=[
            "https://portswigger.net/research/smashing-the-state-machine"
        ],
    )
    return ScenarioResult(
        transport=chosen,
        baseline=baseline,
        burst=burst,
        analysis=analysis,
        findings=[finding] if finding else [],
    )


def run_group_scenario(
    *,
    target: str,
    scope: Any,
    group: list[RaceRequest],
    transport: str = TRANSPORT_AUTO,
    expected_max_successes: int | None = None,
    final_state_success_count: int | None = None,
    proxy: str | None = None,
    settle: float = 0.1,
    timeout: float = 10.0,
    verify_tls: bool = True,
    finding_id: str = "reaper-0001",
    auto_delay: bool = False,
    auto_delay_samples: int = 3,
) -> ScenarioResult:
    """Minimal multi-endpoint scenario (V0.1-CRITERIA.md #4).

    A heterogeneous request group sharing one HTTP/2 connection, released on
    per-request delays in one window. Group mode requires HTTP/2 (one
    multiplexed connection); it does not fall back to the per-connection H1
    engine. Scope is enforced before any socket opens.

    When ``auto_delay`` is True, reaper measures the baseline RTT to the
    target with a warm-up GET / (via :func:`~reaper.autodelay.measure_rtt`)
    and distributes the N requests evenly across that window using
    :func:`~reaper.autodelay.auto_delays`. The ``@delay`` values in the
    group file are overridden.
    """
    if scope is not None:
        scope.assert_in_scope(target)

    if auto_delay:
        from reaper.autodelay import auto_delays, measure_rtt

        rtt = measure_rtt(
            target,
            scope,
            proxy=proxy,
            timeout=timeout,
            verify_tls=verify_tls,
            samples=auto_delay_samples,
        )
        computed = auto_delays(rtt, len(group))
        group = [
            dataclasses.replace(req, delay=d)
            for req, d in zip(group, computed)
        ]

    chosen = select_transport(
        target, prefer=transport, scope=scope, verify_tls=verify_tls, proxy=proxy
    )
    if chosen != TRANSPORT_H2_SINGLE_PACKET:
        raise TransportError(
            "group mode needs one multiplexed HTTP/2 connection; target does "
            "not speak HTTP/2 (h2 / h2c)"
        )

    engine = SinglePacketEngine(
        scope, target, settle=settle, timeout=timeout, verify_tls=verify_tls,
        proxy=proxy,
    )
    burst = engine.run_group(group)

    analysis = confirm_race(
        [],
        burst,
        expected_max_successes=expected_max_successes,
        final_state_success_count=final_state_success_count,
    )
    finding = build_finding(
        analysis,
        target=target,
        vector=_vector(chosen, group[0].path if group else "/"),
        variant="multi-endpoint",
        finding_id=finding_id,
        references=[
            "https://portswigger.net/research/smashing-the-state-machine"
        ],
    )
    return ScenarioResult(
        transport=chosen,
        baseline=[],
        burst=burst,
        analysis=analysis,
        findings=[finding] if finding else [],
    )
