"""Transport detection and race-window estimation (``reaper detect``).

``reaper detect`` is the pre-attack reconnaissance command. Given a target
endpoint it:

1. Probes for HTTP/2 (ALPN negotiation / h2c prior knowledge) vs HTTP/1.1.
2. Fires a small non-destructive probe burst (``GET /``) using the detected
   transport to estimate the race window width -- how tightly the server
   processes concurrent requests.
3. Returns a :class:`DetectResult` with the protocol, window timing stats, a
   concurrency hint, and a recommended attack invocation.

R5: probe response bodies are discarded immediately -- only status and
elapsed_ms are retained; bytes are never executed or interpreted.
"""

from __future__ import annotations

import dataclasses
import statistics
from typing import Any

from reaper.engine import (
    TRANSPORT_H1_LAST_BYTE_SYNC,
    TRANSPORT_H2_SINGLE_PACKET,
    LastByteSyncEngine,
    SinglePacketEngine,
    select_transport,
)
from reaper.httpspec import RaceRequest, ResponseSignature, split_target

__all__ = ["DetectResult", "WindowStats", "run_detect"]

# Default probe burst size for window estimation (non-destructive GET /).
_PROBE_COPIES = 10

# Timing spread threshold above which the server is likely serializing requests.
_SERIAL_THRESHOLD_MS = 50.0


@dataclasses.dataclass(frozen=True)
class WindowStats:
    """Timing spread of the probe burst; all values in milliseconds."""

    minimum: float
    median: float
    maximum: float
    spread: float   # maximum - minimum
    stdev: float

    def to_dict(self) -> dict:
        return {
            "min_ms": round(self.minimum, 2),
            "median_ms": round(self.median, 2),
            "max_ms": round(self.maximum, 2),
            "spread_ms": round(self.spread, 2),
            "stdev_ms": round(self.stdev, 2),
        }


@dataclasses.dataclass
class DetectResult:
    """Result of a ``reaper detect`` run."""

    transport: str          # TRANSPORT_H2_SINGLE_PACKET or TRANSPORT_H1_LAST_BYTE_SYNC
    protocol: str           # "h2", "h2c", or "http/1.1"
    window: WindowStats | None  # None if the probe burst produced no responses
    concurrency_hint: str   # "concurrent", "serialized", or "unknown"
    probe_copies: int
    probe_successes: int    # 2xx responses within the probe burst
    recommendation: str     # human-readable attack suggestion

    def to_dict(self) -> dict:
        return {
            "transport": self.transport,
            "protocol": self.protocol,
            "window": self.window.to_dict() if self.window else None,
            "concurrency_hint": self.concurrency_hint,
            "probe_copies": self.probe_copies,
            "probe_successes": self.probe_successes,
            "recommendation": self.recommendation,
        }


def _window_stats(sigs: list[ResponseSignature]) -> WindowStats | None:
    if len(sigs) < 2:
        return None
    times = [s.elapsed_ms for s in sigs]
    mn = min(times)
    mx = max(times)
    return WindowStats(
        minimum=mn,
        median=statistics.median(times),
        maximum=mx,
        spread=mx - mn,
        stdev=statistics.pstdev(times),
    )


def _concurrency_hint(window: WindowStats | None) -> str:
    if window is None:
        return "unknown"
    return "concurrent" if window.spread < _SERIAL_THRESHOLD_MS else "serialized"


def _probe_protocol(transport: str, target: str) -> str:
    scheme, *_ = split_target(target)
    if transport == TRANSPORT_H1_LAST_BYTE_SYNC:
        return "http/1.1"
    return "h2" if scheme == "https" else "h2c"


def _recommendation(
    transport: str,
    protocol: str,
    window: WindowStats | None,
    hint: str,
    target: str,
) -> str:
    if window is not None:
        window_note = f"Race window probe: spread {window.spread:.1f}ms ({hint})."
    else:
        window_note = (
            "Race window probe: no responses received "
            "(target unreachable or rejected GET /)."
        )

    if transport == TRANSPORT_H2_SINGLE_PACKET:
        proto_line = f"HTTP/2 detected ({protocol}) -- single-packet attack available."
        attack = (
            f"reaper single --target {target} --request <reqfile>"
            f" --copies 20 --transport h2-single-packet"
        )
    else:
        proto_line = "HTTP/1.1 only -- last-byte-sync fallback will be used."
        attack = (
            f"reaper single --target {target} --request <reqfile>"
            f" --copies 20 --transport h1-last-byte-sync"
        )

    warning = (
        " NOTE: large spread suggests the server serializes concurrent requests;"
        " race window may be narrow."
        if hint == "serialized"
        else ""
    )

    return f"{proto_line} {window_note}{warning}\nSuggested: {attack}"


def run_detect(
    *,
    target: str,
    scope: Any = None,
    probe_copies: int = _PROBE_COPIES,
    proxy: str | None = None,
    timeout: float = 10.0,
    verify_tls: bool = True,
    settle: float = 0.1,
) -> DetectResult:
    """Detect transport and estimate race window width for *target*.

    Probes the target for HTTP/2 support via ALPN / h2c prior knowledge, then
    fires *probe_copies* benign ``GET /`` requests as a synchronized burst and
    measures the response-timing spread as the race window estimate.

    R5: probe response bodies are discarded -- only status and elapsed_ms are
    retained; bytes are never executed or interpreted.

    SAFETY: scope is asserted before any socket is opened.
    """
    if scope is not None:
        scope.assert_in_scope(target)

    transport = select_transport(
        target,
        prefer="auto",
        scope=scope,
        timeout=timeout,
        verify_tls=verify_tls,
        proxy=proxy,
    )

    _, _, _, authority = split_target(target)
    probe_req = RaceRequest(method="GET", path="/", authority=authority)

    sigs: list[ResponseSignature] = []
    try:
        if transport == TRANSPORT_H2_SINGLE_PACKET:
            engine: SinglePacketEngine | LastByteSyncEngine = SinglePacketEngine(
                scope, target,
                settle=settle, timeout=timeout, verify_tls=verify_tls, proxy=proxy,
            )
        else:
            engine = LastByteSyncEngine(
                scope, target,
                settle=settle, timeout=timeout, verify_tls=verify_tls, proxy=proxy,
            )
        sigs = engine.run_single_endpoint(probe_req, probe_copies)
    except Exception:
        # Probe failure (server down, network error) -- still return the
        # transport detection result with no window stats.
        pass

    protocol = _probe_protocol(transport, target)
    window = _window_stats(sigs)
    hint = _concurrency_hint(window)

    return DetectResult(
        transport=transport,
        protocol=protocol,
        window=window,
        concurrency_hint=hint,
        probe_copies=probe_copies,
        probe_successes=sum(1 for s in sigs if 200 <= s.status < 300),
        recommendation=_recommendation(transport, protocol, window, hint, target),
    )
