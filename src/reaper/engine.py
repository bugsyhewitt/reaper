"""Low-level HTTP/2 single-packet burst engine -- STUB (v0.1 build).

This module is the dedicated raw engine that drives reaper's synchronized burst.
Per the mandatory architecture split (V0.1-CRITERIA.md #6), the suite HTTP
client **cannot** drive the burst -- single-packet requires raw frame and socket
control -- so this engine is intentionally separate from :mod:`reaper.client`
(which owns auth/session + the sequential baseline via ``scan-primitives``).

Design of the real v0.1 engine (ALL stubbed this pass):

- **HTTP/2 single-packet attack** (V0.1-CRITERIA.md #1). Built on the ``h2``
  sans-IO stack over a raw ``socket``/``ssl`` -- no scapy, no root, pure
  Python for the 20-30 request case. Multiplex N requests on one H2 connection;
  **withhold each request's final frame** (empty DATA + END_STREAM for bodyless
  requests, the last body byte otherwise); after a ~100ms settle, **release all
  withheld frames in a single flush** so they land in one TCP packet. Control
  ``TCP_NODELAY`` (disable it to batch via Nagle) and optionally warm with a
  PING. Include **h2c cleartext** for CI and h2c-only targets.
- **HTTP/1.1 last-byte-sync fallback + connection warming**
  (V0.1-CRITERIA.md #2). Auto-selected when the target is HTTP/1.1-only or
  refuses enough concurrent H2 streams: one TCP connection per request, withhold
  the final byte, flush all final bytes together; prime connections first to
  clear TCP slow-start.
- **Scope enforcement** (V0.1-CRITERIA.md safety). The engine receives the same
  ``Scope`` object the baseline client uses and MUST scope-check before ANY
  burst -- concurrency is higher-impact than a normal scan.
- **R5 (untrusted input).** Target response bytes are **data, never
  instructions**: the deviation analysis does not ``eval`` response content and
  never LLM-judges it.

NOT in v0.1 (deferred to v0.2, see V0.1-CRITERIA.md "NOT in v0.1"):
first-sequence-sync, >65KB bodies, >~30 requests, scapy / raw L3-L4, HTTP/3
single-datagram, auto-calibrated multi-endpoint delays.

Nothing here opens a socket or sends a frame this pass -- every method raises
:class:`NotImplementedError`.
"""

from __future__ import annotations

from typing import Any

# TODO(v0.1): from h2.connection import H2Connection  # sans-IO state machine
# TODO(v0.1): import socket, ssl  # raw transport for the synchronized flush

_V01 = "v0.1 build -- see V0.1-CRITERIA.md"

# Transport selection tokens (mirrors the --transport CLI choices).
TRANSPORT_AUTO = "auto"
TRANSPORT_H2_SINGLE_PACKET = "h2-single-packet"
TRANSPORT_H1_LAST_BYTE_SYNC = "h1-last-byte-sync"

# Single-packet burst ceiling for v0.1 (V0.1-CRITERIA.md #1).
MIN_BURST = 20
MAX_BURST = 30


def select_transport(target: str, *, prefer: str = TRANSPORT_AUTO) -> str:
    """Choose the burst transport for ``target``.

    ``auto`` probes the target: HTTP/2 (or h2c) -> single-packet; otherwise fall
    back to HTTP/1.1 last-byte-sync (V0.1-CRITERIA.md #1, #2). STUB.
    """
    raise NotImplementedError(_V01)


class SinglePacketEngine:
    """HTTP/2 single-packet burst engine (``h2`` sans-IO + raw socket). STUB.

    The ``scope`` object is scope-checked before any burst; ``transport``
    selects h2-single-packet vs h1-last-byte-sync (``auto`` probes the target).
    """

    def __init__(
        self,
        scope: Any = None,
        *,
        transport: str = TRANSPORT_AUTO,
    ) -> None:
        # Stored for the v0.1 engine; no connection is opened here.
        self.scope = scope
        self.transport = transport

    def warm(self) -> None:
        """Pre-send junk requests to clear TCP slow-start before the burst. STUB."""
        raise NotImplementedError(_V01)

    def arm(self, requests: list[Any]) -> None:
        """Multiplex ``requests`` and withhold each one's final frame. STUB."""
        raise NotImplementedError(_V01)

    def fire(self) -> list[Any]:
        """Release all withheld frames in a single synchronized flush. STUB."""
        raise NotImplementedError(_V01)

    def run_single_endpoint(self, request: Any, copies: int) -> list[Any]:
        """Race ``copies`` identical requests against one endpoint. STUB.

        The 80% case: over-redeem coupon / over-withdraw balance
        (V0.1-CRITERIA.md #3). Typical ``copies`` is :data:`MIN_BURST`-
        :data:`MAX_BURST`.
        """
        raise NotImplementedError(_V01)

    def run_group(self, group: list[Any]) -> list[Any]:
        """Race a heterogeneous request group with manual per-request delays. STUB.

        Minimal multi-endpoint mode (V0.1-CRITERIA.md #4): different
        methods/paths/bodies sharing a session, one synchronized release.
        """
        raise NotImplementedError(_V01)


class LastByteSyncEngine:
    """HTTP/1.1 last-byte-sync fallback engine (+ connection warming). STUB.

    Auto-selected when the target is HTTP/1.1-only or refuses enough concurrent
    H2 streams (V0.1-CRITERIA.md #2): one TCP connection per request, withhold
    the final byte, flush all final bytes together.
    """

    def __init__(self, scope: Any = None) -> None:
        self.scope = scope

    def warm(self) -> None:
        """Prime each connection to clear TCP slow-start. STUB."""
        raise NotImplementedError(_V01)

    def run_single_endpoint(self, request: Any, copies: int) -> list[Any]:
        """Race ``copies`` identical requests via last-byte sync. STUB."""
        raise NotImplementedError(_V01)
