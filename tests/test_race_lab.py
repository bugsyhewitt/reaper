"""Live acceptance test: reaper vs the deliberately race-vulnerable Hypercorn lab.

ACCEPTANCE GATE (V0.1-CRITERIA.md, Testability):
- **control** = N sequential single-use-coupon redemptions via reaper's
  scan-primitives baseline client -> exactly 1 success (proves the fixture is
  correct, not broken).
- **attack** = N concurrent redemptions via reaper's HTTP/2 single-packet engine
  -> >1 success (an over-limit condition sequential requests cannot produce).

Skips cleanly if hypercorn / h2 are unavailable.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest

pytest.importorskip("hypercorn")
pytest.importorskip("h2")

from racelab import RaceLabApp, start_lab  # noqa: E402

from reaper.analysis import build_finding, confirm_race  # noqa: E402
from reaper.client import BaselineClient  # noqa: E402
from reaper.engine import SinglePacketEngine, select_transport  # noqa: E402
from reaper.findings import CWE_RACE_CONDITION  # noqa: E402
from reaper.httpspec import RaceRequest  # noqa: E402
from reaper.runner import run_group_scenario, run_single_scenario  # noqa: E402
from scan_primitives import Scope  # noqa: E402

pytestmark = pytest.mark.integration

N = 25  # within the v0.1 20-30 single-packet band


@pytest.fixture(scope="module")
def lab():
    server = start_lab(window=0.1)
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def scope():
    return Scope.from_entries(["127.0.0.1"])


def _redeem_req(code: str) -> RaceRequest:
    return RaceRequest(
        method="POST",
        path=f"/redeem/{code}",
        headers=[("content-type", "application/json")],
        body=b'{"redeem":true}',
    )


def _sequential_baseline(scope, target, request, n):
    async def _go():
        async with BaselineClient(scope) as client:
            return await client.baseline(request, n, target=target)

    return asyncio.run(_go())


def test_transport_probe_selects_h2c(lab, scope):
    """auto-probe recognizes Hypercorn's h2c prior-knowledge as HTTP/2."""
    target = f"{lab.base_url}/redeem/{uuid.uuid4().hex}"
    assert select_transport(target, scope=scope) == "h2-single-packet"


def test_control_sequential_yields_exactly_one_success(lab, scope):
    """CONTROL: N sequential redemptions of one coupon -> exactly 1 success."""
    code = f"control-{uuid.uuid4().hex}"
    target = f"{lab.base_url}/redeem/{code}"
    sigs = _sequential_baseline(scope, target, _redeem_req(code), N)

    successes = sum(1 for s in sigs if 200 <= s.status < 300)
    assert successes == 1, f"expected exactly 1 sequential success, got {successes}"
    assert lab.app.coupons[code]["count"] == 1


def test_attack_concurrent_forces_over_limit(lab, scope):
    """ATTACK: N concurrent single-packet redemptions -> >1 success (over-limit)."""
    code = f"attack-{uuid.uuid4().hex}"
    target = f"{lab.base_url}/redeem/{code}"

    engine = SinglePacketEngine(scope, target, settle=0.1, timeout=10.0)
    sigs = engine.run_single_endpoint(_redeem_req(code), N)

    successes = sum(1 for s in sigs if 200 <= s.status < 300)
    committed = lab.app.coupons[code]["count"]
    assert successes > 1, f"single-packet burst failed to race: {successes} success"
    assert committed == successes, "committed state should match successful responses"


def test_gate_attack_beats_control_and_emits_finding(lab, scope):
    """The full deterministic gate + confirmed CWE-362 finding with the
    final-state guard verified against the server's persisted redeem count."""
    control_code = f"control-{uuid.uuid4().hex}"
    attack_code = f"attack-{uuid.uuid4().hex}"
    control_target = f"{lab.base_url}/redeem/{control_code}"
    attack_target = f"{lab.base_url}/redeem/{attack_code}"

    control = _sequential_baseline(scope, control_target, _redeem_req(control_code), N)
    control_successes = sum(1 for s in control if 200 <= s.status < 300)

    engine = SinglePacketEngine(scope, attack_target, settle=0.1, timeout=10.0)
    attack = engine.run_single_endpoint(_redeem_req(attack_code), N)
    attack_successes = sum(1 for s in attack if 200 <= s.status < 300)

    # The deterministic gate: concurrent forces what sequential cannot.
    assert control_successes == 1
    assert attack_successes > 1

    # Final-state read-back confirms the surplus successes PERSISTED.
    committed = lab.app.coupons[attack_code]["count"]
    analysis = confirm_race(control, attack, final_state_success_count=committed)
    assert analysis.is_race
    assert analysis.expected_max_successes == 1
    assert analysis.burst_success_count == attack_successes
    assert analysis.anomalous_response_count == attack_successes - 1
    assert analysis.final_state_verified and analysis.final_state_ok
    assert analysis.confidence == "high"

    finding = build_finding(
        analysis,
        target=attack_target,
        vector="single-packet:/redeem",
        variant="single-endpoint",
    )
    assert finding is not None
    assert finding.cwe_id == CWE_RACE_CONDITION == 362
    assert finding.evidence["anomalous_response_count"] == attack_successes - 1
    assert finding.evidence["timing_distribution"]["samples"] == N


def test_run_single_scenario_end_to_end_emits_finding(lab, scope):
    """The runner (probe -> burst -> confirm -> Finding) emits a race finding."""
    code = f"attack-{uuid.uuid4().hex}"
    target = f"{lab.base_url}/redeem/{code}"

    result = run_single_scenario(
        target=target,
        scope=scope,
        request=_redeem_req(code),
        copies=N,
        transport="auto",
    )
    assert result.transport == "h2-single-packet"
    assert result.analysis is not None and result.analysis.is_race
    assert len(result.findings) == 1
    assert result.findings[0].cwe_id == 362
    # The burst genuinely over-committed the server's single-use resource.
    assert lab.app.coupons[code]["count"] > 1


def test_group_multi_endpoint_substate_race(lab, scope):
    """Group mode: race /email/change + /email/confirm over one pending slot.

    A heterogeneous request group on one multiplexed HTTP/2 connection. The
    single pending slot should admit one change; concurrency can confirm an
    email that races the change, over-committing the sub-state.
    """
    lab.app.reset()
    target = f"{lab.base_url}/email/change"
    group = [
        RaceRequest(
            method="POST",
            path="/email/change",
            headers=[("content-type", "application/json")],
            body=b'{"email":"attacker@evil.test"}',
        ),
        RaceRequest(
            method="POST",
            path="/email/confirm",
            headers=[("content-type", "application/json")],
            body=b'{"token":"000000"}',
        ),
    ] * (N // 2)

    result = run_group_scenario(target=target, scope=scope, group=group)
    # The group races on one HTTP/2 connection; we assert it executed and that
    # the burst produced responses for every stream (the sub-state mechanics are
    # exercised end-to-end). Any confirmed over-limit is reported as a finding.
    assert result.transport == "h2-single-packet"
    assert len(result.burst) == len(group)
    total_success = sum(1 for s in result.burst if 200 <= s.status < 300)
    assert total_success >= 1


def test_h1_last_byte_sync_fallback_races(lab, scope):
    """HTTP/1.1 last-byte-sync fallback (V0.1-CRITERIA.md #2): one warmed TCP
    connection per request, withhold the final byte, flush them together ->
    forces the same over-limit condition when H2 is unavailable/forced off."""
    code = f"h1-{uuid.uuid4().hex}"
    target = f"{lab.base_url}/redeem/{code}"
    result = run_single_scenario(
        target=target,
        scope=scope,
        request=_redeem_req(code),
        copies=N,
        transport="h1-last-byte-sync",
        settle=0.15,
    )
    assert result.transport == "h1-last-byte-sync"
    assert result.analysis is not None and result.analysis.is_race
    assert len(result.findings) == 1
    assert result.findings[0].vector.startswith("last-byte-sync:")
    assert lab.app.coupons[code]["count"] > 1


@pytest.mark.parametrize("window", [0.0])
def test_soak_tight_window_non_gating(lab, scope, window):
    """Non-gating soak: exercise a tight (delay=0) window without flaking CI.

    With no artificial delay the race may or may not fire; this test only proves
    the engine drives a burst against a near-zero window cleanly (V0.1-CRITERIA.md
    Testability: 'run a delay=0 variant as a non-gating soak test')."""
    code = f"soak-{uuid.uuid4().hex}"
    # window=0 via the lab's query knob -> no artificial sleep in the handler.
    target = f"{lab.base_url}/redeem/{code}?window={window}"
    req = RaceRequest(
        method="POST",
        path=f"/redeem/{code}?window={window}",
        headers=[("content-type", "application/json")],
        body=b'{"redeem":true}',
    )
    engine = SinglePacketEngine(scope, target, settle=0.05, timeout=10.0)
    sigs = engine.run_single_endpoint(req, N)
    assert len(sigs) == N
    successes = sum(1 for s in sigs if 200 <= s.status < 300)
    assert successes >= 1  # at least one redemption always succeeds
