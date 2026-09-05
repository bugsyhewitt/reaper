"""Unit tests for reaper.runner — scenario orchestration without network.

Monkeypatches select_transport, engine.run_*, and BaselineClient so no sockets
open. Tests verify the wiring: correct engine type chosen, correct analysis
called, correct ScenarioResult/StateChainResult shape returned, error paths.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from reaper.engine import (
    TRANSPORT_H1_LAST_BYTE_SYNC,
    TRANSPORT_H2_SINGLE_PACKET,
    TransportError,
)
from reaper.httpspec import ResponseSignature
from reaper.runner import (
    ScenarioResult,
    StateChainResult,
    run_group_scenario,
    run_single_scenario,
    run_state_chain_scenario,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sig(status: int = 200, elapsed: float = 1.0) -> ResponseSignature:
    return ResponseSignature.from_bytes(status, b"body", elapsed)


def _make_request(path="/redeem"):
    req = MagicMock()
    req.path = path
    req.delay = 0.0
    return req


class _Scope:
    """Minimal scope stub — records assert_in_scope calls without MagicMock complications."""
    def __init__(self):
        self.calls = []

    def assert_in_scope(self, url):
        self.calls.append(url)


def _make_scope():
    return _Scope()


# ---------------------------------------------------------------------------
# run_single_scenario
# ---------------------------------------------------------------------------

class TestRunSingleScenario:
    def _patch_engine(self, transport=TRANSPORT_H2_SINGLE_PACKET, burst_sigs=None):
        """Return context managers for a clean single-scenario run."""
        burst = burst_sigs if burst_sigs is not None else [_sig(200)] * 3 + [_sig(409)] * 17

        mock_engine = MagicMock()
        mock_engine.run_single_endpoint.return_value = burst

        patches = [
            patch("reaper.runner.select_transport", return_value=transport),
            patch("reaper.runner.SinglePacketEngine", return_value=mock_engine),
            patch("reaper.runner.LastByteSyncEngine", return_value=mock_engine),
        ]
        return patches, mock_engine

    def test_returns_scenario_result(self):
        patches, engine = self._patch_engine()
        with patches[0], patches[1], patches[2]:
            result = run_single_scenario(
                target="https://example.com/redeem",
                scope=_make_scope(),
                request=_make_request(),
                copies=20,
                transport=TRANSPORT_H2_SINGLE_PACKET,
            )
        assert isinstance(result, ScenarioResult)

    def test_transport_h2_uses_single_packet_engine(self):
        burst = [_sig(200)] * 3 + [_sig(409)] * 17
        mock_engine = MagicMock()
        mock_engine.run_single_endpoint.return_value = burst

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=mock_engine) as mock_cls,
            patch("reaper.runner.LastByteSyncEngine") as mock_h1_cls,
        ):
            run_single_scenario(
                target="https://example.com/redeem",
                scope=_make_scope(),
                request=_make_request(),
                copies=5,
                transport=TRANSPORT_H2_SINGLE_PACKET,
            )
        mock_cls.assert_called_once()
        mock_h1_cls.assert_not_called()

    def test_transport_h1_uses_last_byte_sync_engine(self):
        burst = [_sig(200)] * 2 + [_sig(409)] * 3
        mock_engine = MagicMock()
        mock_engine.run_single_endpoint.return_value = burst

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H1_LAST_BYTE_SYNC),
            patch("reaper.runner.LastByteSyncEngine", return_value=mock_engine) as mock_cls,
            patch("reaper.runner.SinglePacketEngine") as mock_h2_cls,
        ):
            run_single_scenario(
                target="https://example.com/redeem",
                scope=_make_scope(),
                request=_make_request(),
                copies=5,
                transport=TRANSPORT_H1_LAST_BYTE_SYNC,
            )
        mock_cls.assert_called_once()
        mock_h2_cls.assert_not_called()

    def test_scope_checked_before_burst(self):
        scope = _make_scope()
        burst = [_sig(200)]
        mock_engine = MagicMock()
        mock_engine.run_single_endpoint.return_value = burst

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=mock_engine),
            patch("reaper.runner.LastByteSyncEngine", return_value=mock_engine),
        ):
            run_single_scenario(
                target="https://example.com/",
                scope=scope,
                request=_make_request("/"),
                copies=5,
            )
        assert "https://example.com/" in scope.calls

    def test_no_findings_when_burst_clean(self):
        burst = [_sig(200)] + [_sig(409)] * 19
        mock_engine = MagicMock()
        mock_engine.run_single_endpoint.return_value = burst

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=mock_engine),
            patch("reaper.runner.LastByteSyncEngine", return_value=mock_engine),
        ):
            result = run_single_scenario(
                target="https://example.com/redeem",
                scope=_make_scope(),
                request=_make_request(),
                copies=20,
            )
        assert result.findings == []

    def test_finding_when_burst_has_excess_successes(self):
        burst = [_sig(200)] * 5 + [_sig(409)] * 15
        mock_engine = MagicMock()
        mock_engine.run_single_endpoint.return_value = burst

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=mock_engine),
            patch("reaper.runner.LastByteSyncEngine", return_value=mock_engine),
        ):
            result = run_single_scenario(
                target="https://example.com/redeem",
                scope=_make_scope(),
                request=_make_request(),
                copies=20,
                expected_max_successes=1,
            )
        assert len(result.findings) == 1
        assert result.findings[0].cwe_id == 362

    def test_auto_fallback_h2_to_h1_on_transport_error(self):
        burst = [_sig(200)] * 3 + [_sig(409)] * 2
        mock_h2 = MagicMock()
        mock_h2.run_single_endpoint.side_effect = [
            TransportError("peer refused h2"),
        ]
        mock_h1 = MagicMock()
        mock_h1.run_single_endpoint.return_value = burst

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=mock_h2),
            patch("reaper.runner.LastByteSyncEngine", return_value=mock_h1),
        ):
            result = run_single_scenario(
                target="https://example.com/redeem",
                scope=_make_scope(),
                request=_make_request(),
                copies=5,
                transport="auto",
            )
        assert result.transport == TRANSPORT_H1_LAST_BYTE_SYNC

    def test_transport_error_reraises_when_not_auto(self):
        mock_engine = MagicMock()
        mock_engine.run_single_endpoint.side_effect = TransportError("broken")

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=mock_engine),
            patch("reaper.runner.LastByteSyncEngine", return_value=mock_engine),
        ):
            with pytest.raises(TransportError):
                run_single_scenario(
                    target="https://example.com/redeem",
                    scope=_make_scope(),
                    request=_make_request(),
                    copies=5,
                    transport=TRANSPORT_H2_SINGLE_PACKET,
                )

    def test_baseline_samples_zero_skips_baseline_client(self):
        burst = [_sig(200)]
        mock_engine = MagicMock()
        mock_engine.run_single_endpoint.return_value = burst

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=mock_engine),
            patch("reaper.runner.LastByteSyncEngine", return_value=mock_engine),
            patch("reaper.runner._run_baseline") as mock_baseline,
        ):
            run_single_scenario(
                target="https://example.com/",
                scope=_make_scope(),
                request=_make_request("/"),
                copies=5,
                baseline_samples=0,
            )
        mock_baseline.assert_not_called()

    def test_baseline_samples_gt_zero_calls_baseline_client(self):
        burst = [_sig(200)]
        mock_engine = MagicMock()
        mock_engine.run_single_endpoint.return_value = burst

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=mock_engine),
            patch("reaper.runner.LastByteSyncEngine", return_value=mock_engine),
            patch("reaper.runner._run_baseline", return_value=[_sig(200)]) as mock_baseline,
        ):
            run_single_scenario(
                target="https://example.com/",
                scope=_make_scope(),
                request=_make_request("/"),
                copies=5,
                baseline_samples=3,
            )
        mock_baseline.assert_called_once()

    def test_result_carries_chosen_transport(self):
        burst = [_sig(200)]
        mock_engine = MagicMock()
        mock_engine.run_single_endpoint.return_value = burst

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H1_LAST_BYTE_SYNC),
            patch("reaper.runner.SinglePacketEngine", return_value=mock_engine),
            patch("reaper.runner.LastByteSyncEngine", return_value=mock_engine),
        ):
            result = run_single_scenario(
                target="https://example.com/",
                scope=_make_scope(),
                request=_make_request("/"),
                copies=5,
                transport=TRANSPORT_H1_LAST_BYTE_SYNC,
            )
        assert result.transport == TRANSPORT_H1_LAST_BYTE_SYNC


# ---------------------------------------------------------------------------
# run_group_scenario
# ---------------------------------------------------------------------------

class TestRunGroupScenario:
    def _make_group(self, n=3):
        return [_make_request(f"/path{i}") for i in range(n)]

    def test_returns_scenario_result(self):
        burst = [_sig(200)] * 3
        mock_engine = MagicMock()
        mock_engine.run_group.return_value = burst

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=mock_engine),
        ):
            result = run_group_scenario(
                target="https://example.com",
                scope=_make_scope(),
                group=self._make_group(),
                transport=TRANSPORT_H2_SINGLE_PACKET,
            )
        assert isinstance(result, ScenarioResult)

    def test_raises_transport_error_for_h1_target(self):
        mock_engine = MagicMock()

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H1_LAST_BYTE_SYNC),
            patch("reaper.runner.SinglePacketEngine", return_value=mock_engine),
        ):
            with pytest.raises(TransportError, match="group mode"):
                run_group_scenario(
                    target="https://example.com",
                    scope=_make_scope(),
                    group=self._make_group(),
                    transport=TRANSPORT_H1_LAST_BYTE_SYNC,
                )

    def test_scope_enforced(self):
        burst = [_sig(200)] * 2
        mock_engine = MagicMock()
        mock_engine.run_group.return_value = burst
        scope = _make_scope()

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=mock_engine),
        ):
            run_group_scenario(
                target="https://example.com",
                scope=scope,
                group=self._make_group(2),
            )
        assert len(scope.calls) == 1

    def test_auto_delay_overrides_request_delays(self):
        from reaper.httpspec import RaceRequest

        burst = [_sig(200)] * 2
        mock_engine = MagicMock()
        mock_engine.run_group.return_value = burst

        group = [RaceRequest("GET", f"/p{i}") for i in range(2)]
        computed_delays = [0.0, 0.05]
        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=mock_engine),
            patch("reaper.autodelay.measure_rtt", return_value=100.0),
            patch("reaper.autodelay.auto_delays", return_value=computed_delays),
        ):
            result = run_group_scenario(
                target="https://example.com",
                scope=_make_scope(),
                group=group,
                auto_delay=True,
                auto_delay_samples=3,
            )
        assert isinstance(result, ScenarioResult)


# ---------------------------------------------------------------------------
# run_state_chain_scenario
# ---------------------------------------------------------------------------

class TestRunStateChainScenario:
    def _make_chain(self, n=2):
        return [(f"file{i}.http", _make_request(f"/path{i}")) for i in range(n)]

    def test_returns_state_chain_result(self):
        sigs = [_sig(200), _sig(200)]
        mock_engine = MagicMock()
        mock_engine.run_group.return_value = sigs

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=mock_engine),
        ):
            result = run_state_chain_scenario(
                target="https://example.com",
                scope=_make_scope(),
                chain=self._make_chain(),
                transport=TRANSPORT_H2_SINGLE_PACKET,
            )
        assert isinstance(result, StateChainResult)

    def test_raises_for_fewer_than_2_endpoints(self):
        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine"),
        ):
            with pytest.raises(ValueError, match="at least 2"):
                run_state_chain_scenario(
                    target="https://example.com",
                    scope=_make_scope(),
                    chain=self._make_chain(1),
                )

    def test_raises_transport_error_for_h1_target(self):
        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H1_LAST_BYTE_SYNC),
            patch("reaper.runner.SinglePacketEngine"),
        ):
            with pytest.raises(TransportError, match="state-chain"):
                run_state_chain_scenario(
                    target="https://example.com",
                    scope=_make_scope(),
                    chain=self._make_chain(),
                )

    def test_scope_enforced(self):
        sigs = [_sig(200), _sig(200)]
        mock_engine = MagicMock()
        mock_engine.run_group.return_value = sigs
        scope = _make_scope()

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=mock_engine),
        ):
            run_state_chain_scenario(
                target="https://example.com",
                scope=scope,
                chain=self._make_chain(),
            )
        assert len(scope.calls) == 1

    def test_differential_response_produces_finding(self):
        sigs = [_sig(200), _sig(403)]
        mock_engine = MagicMock()
        mock_engine.run_group.return_value = sigs

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=mock_engine),
        ):
            result = run_state_chain_scenario(
                target="https://example.com",
                scope=_make_scope(),
                chain=self._make_chain(),
                expected_status=200,
            )
        assert isinstance(result, StateChainResult)
        assert len(result.chain_results) == 2

    def test_result_labels_match_chain_input(self):
        sigs = [_sig(200), _sig(200)]
        mock_engine = MagicMock()
        mock_engine.run_group.return_value = sigs
        chain = [("transfer.http", _make_request("/transfer")),
                 ("balance.http", _make_request("/balance"))]

        with (
            patch("reaper.runner.select_transport", return_value=TRANSPORT_H2_SINGLE_PACKET),
            patch("reaper.runner.SinglePacketEngine", return_value=mock_engine),
        ):
            result = run_state_chain_scenario(
                target="https://example.com",
                scope=_make_scope(),
                chain=chain,
            )
        labels = [cr.label for cr in result.chain_results]
        assert labels == ["transfer.http", "balance.http"]
