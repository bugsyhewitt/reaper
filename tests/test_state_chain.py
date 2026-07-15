"""Tests for state-chain multi-endpoint orchestration (v0.5 --state-chain).

Unit tests cover analyze_chain() and build_chain_finding() without opening a
socket. Integration tests (marked 'integration') use a Hypercorn H2c server
whose ASGI handler records per-path request-arrival timestamps so the test can
assert server-side co-arrival within the chain window.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import pytest

from reaper.chain import (
    DEFAULT_WINDOW_MS,
    ChainEndpointResult,
    StateChainAnalysis,
    analyze_chain,
    build_chain_finding,
)
from reaper.httpspec import RaceRequest, ResponseSignature, body_hash

# --------------------------------------------------------------------------- #
# Helpers for unit tests                                                        #
# --------------------------------------------------------------------------- #


def _sig(status: int = 200, elapsed_ms: float = 5.0) -> ResponseSignature:
    return ResponseSignature(
        status=status,
        body_sha256=body_hash(b"{}"),
        body_len=2,
        elapsed_ms=elapsed_ms,
    )


def _req(path: str = "/test") -> RaceRequest:
    return RaceRequest(method="POST", path=path, body=b"{}")


def _result(
    label: str, path: str, status: int = 200, elapsed_ms: float = 5.0
) -> ChainEndpointResult:
    return ChainEndpointResult(
        label=label,
        request=_req(path),
        signature=_sig(status=status, elapsed_ms=elapsed_ms),
    )


# --------------------------------------------------------------------------- #
# analyze_chain — unit tests (no network)                                       #
# --------------------------------------------------------------------------- #


def test_analyze_chain_within_window_no_differential():
    results = [
        _result("transfer.txt", "/transfer", 200, elapsed_ms=5.0),
        _result("balance.txt", "/balance", 200, elapsed_ms=6.0),
    ]
    a = analyze_chain(results, window_ms=10.0)
    assert a.within_window
    assert a.spread_ms == pytest.approx(1.0, abs=0.01)
    assert not a.differential_found
    assert len(a.per_endpoint) == 2
    assert a.timing["samples"] == 2
    assert "within" in a.reason or "window" in a.reason


def test_analyze_chain_exceeds_window():
    results = [
        _result("a.txt", "/a", elapsed_ms=1.0),
        _result("b.txt", "/b", elapsed_ms=50.0),
    ]
    a = analyze_chain(results, window_ms=10.0)
    assert not a.within_window
    assert a.spread_ms == pytest.approx(49.0, abs=0.01)
    assert not a.differential_found
    assert "spread" in a.reason or "exceed" in a.reason


def test_analyze_chain_differential_response():
    results = [
        _result("transfer.txt", "/transfer", status=200, elapsed_ms=5.0),
        _result("balance.txt", "/balance", status=403, elapsed_ms=5.5),
    ]
    a = analyze_chain(results, window_ms=10.0, expected_status=200)
    assert a.differential_found
    diffs = [ep for ep in a.per_endpoint if ep["differential"]]
    assert len(diffs) == 1
    assert diffs[0]["path"] == "/balance"
    assert diffs[0]["status"] == 403
    assert "/balance" in a.reason


def test_analyze_chain_multiple_differentials():
    results = [
        _result("a.txt", "/a", status=500, elapsed_ms=5.0),
        _result("b.txt", "/b", status=200, elapsed_ms=5.2),
        _result("c.txt", "/c", status=403, elapsed_ms=5.4),
    ]
    a = analyze_chain(results, expected_status=200)
    diffs = [ep for ep in a.per_endpoint if ep["differential"]]
    assert len(diffs) == 2
    paths = {ep["path"] for ep in diffs}
    assert paths == {"/a", "/c"}


def test_analyze_chain_default_expected_status_is_200():
    results = [
        _result("a.txt", "/a", status=200, elapsed_ms=5.0),
        _result("b.txt", "/b", status=201, elapsed_ms=5.2),
    ]
    a = analyze_chain(results)  # expected_status defaults to 200
    diffs = [ep for ep in a.per_endpoint if ep["differential"]]
    assert len(diffs) == 1
    assert diffs[0]["path"] == "/b"


def test_analyze_chain_empty():
    a = analyze_chain([])
    assert a.spread_ms == 0.0
    assert a.within_window
    assert not a.differential_found
    assert a.timing["samples"] == 0


def test_analyze_chain_single_endpoint():
    results = [_result("only.txt", "/only", status=200, elapsed_ms=10.0)]
    a = analyze_chain(results, window_ms=10.0)
    assert a.spread_ms == 0.0
    assert a.within_window
    assert a.timing["stdev"] == 0.0


def test_analyze_chain_timing_fields():
    results = [
        _result("a.txt", "/a", elapsed_ms=3.0),
        _result("b.txt", "/b", elapsed_ms=7.0),
        _result("c.txt", "/c", elapsed_ms=5.0),
    ]
    a = analyze_chain(results)
    assert a.timing["min"] == pytest.approx(3.0, abs=0.01)
    assert a.timing["max"] == pytest.approx(7.0, abs=0.01)
    assert a.timing["spread"] == pytest.approx(4.0, abs=0.01)
    assert a.timing["samples"] == 3


def test_per_endpoint_body_hash_prefix_truncated():
    results = [_result("a.txt", "/a")]
    a = analyze_chain(results)
    prefix = a.per_endpoint[0]["body_sha256_prefix"]
    assert len(prefix) == 16


# --------------------------------------------------------------------------- #
# build_chain_finding — unit tests (no network)                                 #
# --------------------------------------------------------------------------- #


def test_build_chain_finding_no_differential_returns_none():
    results = [
        _result("a.txt", "/a", 200, 5.0),
        _result("b.txt", "/b", 200, 6.0),
    ]
    a = analyze_chain(results)
    assert not a.differential_found
    finding = build_chain_finding(a, target="http://x.test", vector="single-packet:/a")
    assert finding is None


def test_build_chain_finding_with_differential():
    results = [
        _result("transfer.txt", "/transfer", 200, 5.0),
        _result("check.txt", "/balance-check", 403, 5.5),
    ]
    a = analyze_chain(results, expected_status=200)
    finding = build_chain_finding(
        a, target="http://x.test", vector="single-packet:/transfer"
    )
    assert finding is not None
    assert finding.variant == "state-chain"
    assert "/balance-check" in finding.title
    assert finding.confidence == "medium"
    assert finding.tool == "reaper"
    assert finding.cwe_id == 362


def test_build_chain_finding_evidence_shape():
    results = [
        _result("a.txt", "/a", 200, 5.0),
        _result("b.txt", "/b", 500, 5.5),
    ]
    a = analyze_chain(results, expected_status=200)
    finding = build_chain_finding(a, target="http://x.test", vector="sp:/a")
    assert finding is not None
    ev = finding.evidence
    assert "spread_ms" in ev
    assert "per_endpoint" in ev
    assert "timing" in ev
    assert "within_window" in ev


def test_build_chain_finding_custom_finding_id():
    results = [
        _result("a.txt", "/a", 200, 5.0),
        _result("b.txt", "/b", 503, 5.5),
    ]
    a = analyze_chain(results)
    finding = build_chain_finding(
        a, target="http://x.test", vector="sp:/a", finding_id="reaper-9999"
    )
    assert finding is not None
    assert finding.id == "reaper-9999"


# --------------------------------------------------------------------------- #
# Integration tests — live H2c server with arrival-timestamp tracking          #
# These are skipped when hypercorn or scan_primitives are unavailable.          #
# --------------------------------------------------------------------------- #

try:
    import hypercorn  # noqa: F401
    import h2  # noqa: F401
    from racelab import LabServer, _free_port
    from reaper.engine import SinglePacketEngine  # noqa: F401
    from reaper.runner import run_state_chain_scenario
    from scan_primitives import Scope
    _INTEGRATION_DEPS = True
except ImportError:
    _INTEGRATION_DEPS = False

_skip_no_deps = pytest.mark.skipif(
    not _INTEGRATION_DEPS,
    reason="hypercorn, h2, or scan_primitives not installed",
)


class ChainTrackingApp:
    """ASGI app that records server-side request-arrival timestamps per path.

    Each request handler records ``time.perf_counter()`` at entry (before the
    artificial delay) so the integration tests can assert server-side co-arrival
    within the chain window.
    """

    def __init__(self, window: float = 0.05) -> None:
        self.window = window
        self.arrivals: dict[str, list[float]] = {}

    def reset(self) -> None:
        self.arrivals.clear()

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        assert scope["type"] == "http"
        await self._read_body(receive)
        path = scope["path"]
        # Record arrival BEFORE the delay to measure request receipt time.
        arrival = time.perf_counter()
        self.arrivals.setdefault(path, []).append(arrival)
        await asyncio.sleep(self.window)
        await self._respond(send, 200, {"path": path, "ok": True})

    async def _read_body(self, receive: Any) -> bytes:
        buf = bytearray()
        while True:
            msg = await receive()
            buf.extend(msg.get("body", b""))
            if not msg.get("more_body"):
                break
        return bytes(buf)

    async def _respond(self, send: Any, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def _lifespan(self, receive: Any, send: Any) -> None:
        while True:
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif msg["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return


@pytest.fixture(scope="module")
def chain_lab():
    if not _INTEGRATION_DEPS:
        pytest.skip("integration deps not available")
    app = ChainTrackingApp(window=0.05)
    server = LabServer(app, _free_port())
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def scope():
    if not _INTEGRATION_DEPS:
        pytest.skip("integration deps not available")
    return Scope.from_entries(["127.0.0.1"])


@_skip_no_deps
@pytest.mark.integration
def test_state_chain_server_side_co_arrival(chain_lab, scope):
    """Server-side arrival delta for a 2-endpoint chain is <= 10ms.

    ChainTrackingApp records ``time.perf_counter()`` at request entry for each
    path.  After the burst, we read those timestamps and assert the gap between
    the two endpoints is within DEFAULT_WINDOW_MS (10ms).
    """
    chain_lab.app.reset()
    target = f"http://127.0.0.1:{chain_lab.port}/transfer"

    chain = [
        (
            "transfer.txt",
            RaceRequest(
                method="POST",
                path="/transfer",
                headers=[("content-type", "application/json")],
                body=b'{"amount": 100}',
            ),
        ),
        (
            "balance.txt",
            RaceRequest(
                method="GET",
                path="/balance-check",
                headers=[],
                body=b"",
            ),
        ),
    ]

    result = run_state_chain_scenario(
        target=target,
        scope=scope,
        chain=chain,
        transport="h2-single-packet",
        window_ms=DEFAULT_WINDOW_MS,
        settle=0.1,
        timeout=10.0,
    )

    assert result.transport == "h2-single-packet"
    assert len(result.chain_results) == 2

    for cr in result.chain_results:
        assert cr.signature.status == 200, (
            f"{cr.label} returned HTTP {cr.signature.status}"
        )

    # Server-side co-arrival: both paths must have a recorded arrival.
    transfer_times = chain_lab.app.arrivals.get("/transfer", [])
    balance_times = chain_lab.app.arrivals.get("/balance-check", [])
    assert transfer_times, "no arrivals recorded for /transfer"
    assert balance_times, "no arrivals recorded for /balance-check"

    delta_ms = abs(transfer_times[-1] - balance_times[-1]) * 1000.0
    assert delta_ms <= DEFAULT_WINDOW_MS, (
        f"server-side arrival delta {delta_ms:.2f}ms exceeds "
        f"{DEFAULT_WINDOW_MS}ms chain window"
    )


@_skip_no_deps
@pytest.mark.integration
def test_state_chain_three_endpoints_co_arrive(chain_lab, scope):
    """Three-endpoint chain: all arrive within the window on the server side."""
    chain_lab.app.reset()
    target = f"http://127.0.0.1:{chain_lab.port}/ep1"

    paths = ["/ep1", "/ep2", "/ep3"]
    chain = [
        (f"{p.strip('/')}.txt", RaceRequest(method="GET", path=p, body=b""))
        for p in paths
    ]

    result = run_state_chain_scenario(
        target=target,
        scope=scope,
        chain=chain,
        transport="h2-single-packet",
        settle=0.1,
        timeout=10.0,
    )

    assert result.transport == "h2-single-packet"
    assert len(result.chain_results) == 3
    assert result.analysis.timing["samples"] == 3

    for p in paths:
        assert chain_lab.app.arrivals.get(p), f"no arrivals recorded for {p}"

    all_times = [chain_lab.app.arrivals[p][-1] for p in paths]
    server_spread_ms = (max(all_times) - min(all_times)) * 1000.0
    assert server_spread_ms <= DEFAULT_WINDOW_MS, (
        f"3-endpoint server spread {server_spread_ms:.2f}ms exceeds "
        f"{DEFAULT_WINDOW_MS}ms window"
    )


@_skip_no_deps
@pytest.mark.integration
def test_state_chain_result_structure(chain_lab, scope):
    """run_state_chain_scenario returns a StateChainResult with expected fields."""
    chain_lab.app.reset()
    target = f"http://127.0.0.1:{chain_lab.port}/a"
    chain = [
        ("a.txt", RaceRequest(method="GET", path="/a", body=b"")),
        ("b.txt", RaceRequest(method="GET", path="/b", body=b"")),
    ]
    result = run_state_chain_scenario(
        target=target,
        scope=scope,
        chain=chain,
        window_ms=DEFAULT_WINDOW_MS,
    )
    assert result.analysis.timing["samples"] == 2
    assert result.analysis.window_ms == DEFAULT_WINDOW_MS
    # No differential (all 200) so no finding.
    assert result.findings == []
    assert not result.analysis.differential_found
