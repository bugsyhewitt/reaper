"""Low-level HTTP/2 single-packet burst engine (``h2`` sans-IO + raw socket/ssl).

Per the mandatory architecture split (V0.1-CRITERIA.md #6), the suite HTTP client
**cannot** drive the synchronized burst -- single-packet needs raw frame and
socket control -- so this engine is separate from :mod:`reaper.client` (which
owns auth/session + the sequential baseline via ``scan-primitives``). The same
``Scope`` object flows into this engine so the burst is scope-checked too.

The HTTP/2 single-packet attack (James Kettle, DEF CON 31), as built here:

1. Open ONE HTTP/2 connection (TLS+ALPN ``h2`` for ``https``, or h2c
   prior-knowledge cleartext for ``http`` -- needed for the CI lab).
2. Multiplex N requests as N streams; **withhold each request's final frame** --
   an empty ``DATA``+``END_STREAM`` for a bodyless request, the last body byte
   otherwise -- so every request is parked one frame short of complete.
3. Settle ~100ms, then **release all withheld frames in a single flush** (one
   ``send()`` of the combined buffer, with ``TCP_NODELAY`` disabled so Nagle
   also batches) -- so they land in one TCP packet and race in one window.

R5: response bytes are UNTRUSTED DATA -- hashed for comparison, never executed.

NOT in v0.1 (see V0.1-CRITERIA.md): first-sequence-sync, >65KB bodies, >~30
requests, scapy / raw L3-L4, HTTP/3, auto-calibrated multi-endpoint delays.
"""

from __future__ import annotations

import socket
import ssl
import time
from typing import Any

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import (
    ConnectionTerminated,
    DataReceived,
    RemoteSettingsChanged,
    ResponseReceived,
    StreamEnded,
    StreamReset,
)

from reaper.httpspec import (
    RaceRequest,
    ResponseSignature,
    body_hash,
    h1_bytes,
    h2_headers,
    split_target,
)

__all__ = [
    "MAX_BURST",
    "MIN_BURST",
    "TRANSPORT_AUTO",
    "TRANSPORT_H1_LAST_BYTE_SYNC",
    "TRANSPORT_H2_SINGLE_PACKET",
    "LastByteSyncEngine",
    "SinglePacketEngine",
    "TransportError",
    "select_transport",
]

# Transport selection tokens (mirrors the --transport CLI choices).
TRANSPORT_AUTO = "auto"
TRANSPORT_H2_SINGLE_PACKET = "h2-single-packet"
TRANSPORT_H1_LAST_BYTE_SYNC = "h1-last-byte-sync"

# Single-packet burst window for v0.1 (V0.1-CRITERIA.md #1). Advisory, not a hard
# cap: the engine warns outside this band but still fires.
MIN_BURST = 20
MAX_BURST = 30

# The HTTP/2 connection preface (client). Sent verbatim for h2c prior knowledge.
_H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

_DEFAULT_SETTLE = 0.1
_DEFAULT_TIMEOUT = 10.0
_READ_CHUNK = 65535


class TransportError(RuntimeError):
    """Raised when a transport cannot be established or the peer refuses it.

    In ``auto`` mode the orchestrator catches this to fall back H2 -> H1.
    """


def _tcp_connect(host: str, port: int, timeout: float) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def _maybe_tls(
    sock: socket.socket,
    scheme: str,
    host: str,
    *,
    alpn: list[str] | None,
    verify: bool,
) -> socket.socket:
    if scheme != "https":
        return sock
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        ctx.set_alpn_protocols(alpn)
    return ctx.wrap_socket(sock, server_hostname=host)


# --------------------------------------------------------------------------- #
# Transport selection / probing
# --------------------------------------------------------------------------- #


def select_transport(
    target: str,
    *,
    prefer: str = TRANSPORT_AUTO,
    scope: Any = None,
    timeout: float = 3.0,
    verify_tls: bool = True,
) -> str:
    """Choose the burst transport for ``target``.

    An explicit ``prefer`` is returned unchanged. ``auto`` probes the target:
    HTTP/2 (ALPN ``h2`` for TLS, or an h2c prior-knowledge handshake for
    cleartext) selects :data:`TRANSPORT_H2_SINGLE_PACKET`; anything else falls
    back to :data:`TRANSPORT_H1_LAST_BYTE_SYNC` (V0.1-CRITERIA.md #1, #2).

    SAFETY: scope is asserted before the probe opens any socket.
    """
    if prefer != TRANSPORT_AUTO:
        return prefer
    if scope is not None:
        scope.assert_in_scope(target)

    scheme, host, port, _authority = split_target(target)
    try:
        if scheme == "https":
            return (
                TRANSPORT_H2_SINGLE_PACKET
                if _probe_alpn_h2(host, port, timeout, verify_tls)
                else TRANSPORT_H1_LAST_BYTE_SYNC
            )
        return (
            TRANSPORT_H2_SINGLE_PACKET
            if _probe_h2c(host, port, timeout)
            else TRANSPORT_H1_LAST_BYTE_SYNC
        )
    except OSError:
        return TRANSPORT_H1_LAST_BYTE_SYNC


def _probe_alpn_h2(host: str, port: int, timeout: float, verify: bool) -> bool:
    raw = _tcp_connect(host, port, timeout)
    try:
        tls = _maybe_tls(
            raw, "https", host, alpn=["h2", "http/1.1"], verify=verify
        )
        try:
            return tls.selected_alpn_protocol() == "h2"
        finally:
            tls.close()
    except ssl.SSLError:
        raw.close()
        return False


def _probe_h2c(host: str, port: int, timeout: float) -> bool:
    """Return True if the cleartext peer speaks HTTP/2 with prior knowledge."""
    sock = _tcp_connect(host, port, timeout)
    try:
        conn = H2Connection(config=H2Configuration(client_side=True))
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())
        sock.settimeout(timeout)
        data = sock.recv(_READ_CHUNK)
        if not data:
            return False
        # A server that speaks h2c answers our preface with a SETTINGS frame;
        # an HTTP/1.1-only server replies with an ASCII status line instead.
        events = conn.receive_data(data)
        return any(isinstance(ev, RemoteSettingsChanged) for ev in events)
    except (OSError, ValueError):
        return False
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# HTTP/2 single-packet engine
# --------------------------------------------------------------------------- #


class SinglePacketEngine:
    """HTTP/2 single-packet burst engine (``h2`` sans-IO + raw socket).

    Parameters
    ----------
    scope:
        Authorized ``scan_primitives.Scope`` (or any object exposing
        ``assert_in_scope``). Checked before ANY socket is opened.
    target:
        The target URL. Provides scheme/host/port/authority and is the value
        scope is asserted against.
    settle:
        Seconds to wait after priming, before the synchronized release (~0.1).
    timeout:
        Per-socket timeout in seconds.
    tcp_nodelay:
        ``TCP_NODELAY`` state for the release. Default ``False`` (Nagle enabled)
        so the kernel also batches -- the single combined ``send()`` is the
        primary single-packet mechanism (V0.1-CRITERIA.md #1).
    warm_ping:
        Send an HTTP/2 PING before the release to warm the path.
    verify_tls:
        Verify TLS certs for ``https`` targets (default on).
    """

    def __init__(
        self,
        scope: Any = None,
        target: str | None = None,
        *,
        transport: str = TRANSPORT_H2_SINGLE_PACKET,
        settle: float = _DEFAULT_SETTLE,
        timeout: float = _DEFAULT_TIMEOUT,
        tcp_nodelay: bool = False,
        warm_ping: bool = True,
        verify_tls: bool = True,
    ) -> None:
        self.scope = scope
        self.target = target
        self.transport = transport
        self.settle = settle
        self.timeout = timeout
        self.tcp_nodelay = tcp_nodelay
        self.warm_ping = warm_ping
        self.verify_tls = verify_tls

    # -- scope + connection ------------------------------------------------- #

    def _assert_scope(self) -> None:
        if self.scope is not None and self.target is not None:
            self.scope.assert_in_scope(self.target)

    def _connect(self) -> tuple[socket.socket, H2Connection, str, str]:
        """Open a scope-checked HTTP/2 connection; return (sock, conn, scheme, authority)."""
        if self.target is None:
            raise TransportError("no target set on the engine")
        scheme, host, port, authority = split_target(self.target)
        sock = _tcp_connect(host, port, self.timeout)
        try:
            sock = _maybe_tls(
                sock, scheme, host, alpn=["h2"], verify=self.verify_tls
            )
            if scheme == "https" and sock.selected_alpn_protocol() != "h2":
                raise TransportError("peer did not negotiate HTTP/2 via ALPN")
        except ssl.SSLError as exc:  # pragma: no cover - network dependent
            sock.close()
            raise TransportError(f"TLS/ALPN negotiation failed: {exc}") from exc

        conn = H2Connection(config=H2Configuration(client_side=True, header_encoding="utf-8"))
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())
        self._drain_handshake(sock, conn)
        return sock, conn, scheme, authority

    def _drain_handshake(self, sock: socket.socket, conn: H2Connection) -> None:
        """Read the peer's initial SETTINGS and flush our ACK (best effort)."""
        sock.settimeout(self.timeout)
        try:
            data = sock.recv(_READ_CHUNK)
        except socket.timeout:  # pragma: no cover - network dependent
            return
        if not data:
            raise TransportError("connection closed during HTTP/2 handshake")
        conn.receive_data(data)
        out = conn.data_to_send()
        if out:
            sock.sendall(out)

    # -- the single-packet pipeline ---------------------------------------- #

    def _arm(
        self,
        conn: H2Connection,
        requests: list[RaceRequest],
        scheme: str,
        authority: str,
    ) -> tuple[list[int], dict[int, bytes], dict[int, float]]:
        """Open a stream per request, send everything but the final frame.

        Returns ``(stream_order, withheld_final_frame, per_stream_delay)``.
        """
        order: list[int] = []
        withheld: dict[int, bytes] = {}
        delays: dict[int, float] = {}
        for req in requests:
            sid = conn.get_next_available_stream_id()
            conn.send_headers(sid, h2_headers(req, scheme=scheme, authority=authority), end_stream=False)
            body = req.body
            if body:
                if len(body) > 1:
                    conn.send_data(sid, body[:-1], end_stream=False)
                withheld[sid] = body[-1:]
            else:
                # Bodyless: withhold an empty DATA frame carrying END_STREAM.
                withheld[sid] = b""
            order.append(sid)
            delays[sid] = req.delay
        return order, withheld, delays

    def _fire(
        self,
        sock: socket.socket,
        conn: H2Connection,
        order: list[int],
        withheld: dict[int, bytes],
        delays: dict[int, float],
    ) -> float:
        """Release the withheld frames. Returns the fire timestamp (perf_counter).

        With no manual delays this is a single combined flush -- the true
        single packet. With manual per-request delays (group mode) each stream's
        final frame is released on its own schedule within the window, but the
        arming/priming is already done so only the tiny final frame is timed.
        """
        # Toggle Nagle for the release per config (disabled NODELAY == batch).
        sock.setsockopt(
            socket.IPPROTO_TCP, socket.TCP_NODELAY, 1 if self.tcp_nodelay else 0
        )
        if self.warm_ping:
            conn.ping(b"\x00\x00\x00\x00\x00\x00\x00\x00")
            sock.sendall(conn.data_to_send())

        distinct_delays = {d for d in delays.values()}
        fire_ts = time.perf_counter()
        if distinct_delays == {0.0}:
            # Single synchronized release: one send() of all withheld frames.
            for sid in order:
                conn.send_data(sid, withheld[sid], end_stream=True)
            sock.sendall(conn.data_to_send())
        else:
            # Manual-delay group release (V0.1-CRITERIA.md #4). Release in delay
            # order; each frame is a single tiny send.
            start = fire_ts
            for sid in sorted(order, key=lambda s: delays[s]):
                wait = delays[sid] - (time.perf_counter() - start)
                if wait > 0:
                    time.sleep(wait)
                conn.send_data(sid, withheld[sid], end_stream=True)
                sock.sendall(conn.data_to_send())
        return fire_ts

    def _collect(
        self,
        sock: socket.socket,
        conn: H2Connection,
        order: list[int],
        fire_ts: float,
    ) -> list[ResponseSignature]:
        """Read all N responses and return one signature per stream (in order)."""
        pending = set(order)
        status: dict[int, int] = {}
        bodies: dict[int, bytearray] = {sid: bytearray() for sid in order}
        ended_at: dict[int, float] = {}
        sock.settimeout(self.timeout)

        while pending:
            try:
                data = sock.recv(_READ_CHUNK)
            except socket.timeout:
                break
            if not data:
                break
            events = conn.receive_data(data)
            for ev in events:
                if isinstance(ev, ResponseReceived):
                    status[ev.stream_id] = _status_of(ev.headers)
                elif isinstance(ev, DataReceived):
                    bodies[ev.stream_id].extend(ev.data)
                    if ev.flow_controlled_length:
                        conn.acknowledge_received_data(
                            ev.flow_controlled_length, ev.stream_id
                        )
                elif isinstance(ev, StreamEnded):
                    ended_at.setdefault(ev.stream_id, time.perf_counter())
                    pending.discard(ev.stream_id)
                elif isinstance(ev, StreamReset):
                    ended_at.setdefault(ev.stream_id, time.perf_counter())
                    status.setdefault(ev.stream_id, 0)
                    pending.discard(ev.stream_id)
                elif isinstance(ev, ConnectionTerminated):
                    pending.clear()
                    break
            out = conn.data_to_send()
            if out:
                sock.sendall(out)

        return [
            ResponseSignature.from_bytes(
                status=status.get(sid, 0),
                body=bytes(bodies[sid]),
                elapsed_ms=(ended_at.get(sid, time.perf_counter()) - fire_ts) * 1000.0,
            )
            for sid in order
        ]

    def _run(self, requests: list[RaceRequest]) -> list[ResponseSignature]:
        self._assert_scope()
        sock, conn, scheme, authority = self._connect()
        try:
            order, withheld, delays = self._arm(conn, requests, scheme, authority)
            sock.sendall(conn.data_to_send())  # priming flush
            time.sleep(self.settle)
            fire_ts = self._fire(sock, conn, order, withheld, delays)
            return self._collect(sock, conn, order, fire_ts)
        finally:
            try:
                conn.close_connection()
                sock.sendall(conn.data_to_send())
            except Exception:  # pragma: no cover - best-effort teardown
                pass
            sock.close()

    # -- public API --------------------------------------------------------- #

    def run_single_endpoint(
        self, request: RaceRequest, copies: int
    ) -> list[ResponseSignature]:
        """Race ``copies`` identical requests against one endpoint.

        The 80% case: over-redeem coupon / over-withdraw balance
        (V0.1-CRITERIA.md #3). Typical ``copies`` is :data:`MIN_BURST`-
        :data:`MAX_BURST`.
        """
        if copies < 2:
            raise ValueError("a race needs at least 2 concurrent copies")
        return self._run([request] * copies)

    def run_group(self, group: list[RaceRequest]) -> list[ResponseSignature]:
        """Race a heterogeneous request group with manual per-request delays.

        Minimal multi-endpoint mode (V0.1-CRITERIA.md #4): different
        methods/paths/bodies multiplexed on one HTTP/2 connection (one shared
        session), released on manual per-request delays in one window.
        """
        if len(group) < 2:
            raise ValueError("a group race needs at least 2 requests")
        return self._run(list(group))


def _status_of(headers: list[tuple[str, str]]) -> int:
    """Extract the numeric ``:status`` from an HTTP/2 response header block."""
    for name, value in headers:
        if name == ":status":
            try:
                return int(value)
            except ValueError:  # pragma: no cover - malformed peer
                return 0
    return 0


# --------------------------------------------------------------------------- #
# HTTP/1.1 last-byte-sync fallback engine
# --------------------------------------------------------------------------- #


class LastByteSyncEngine:
    """HTTP/1.1 last-byte-sync fallback engine (+ connection warming).

    Auto-selected when the target is HTTP/1.1-only or refuses enough concurrent
    H2 streams (V0.1-CRITERIA.md #2): one TCP connection per request, warm each
    to clear TCP slow-start, withhold the final byte, then flush every final
    byte together in a tight loop so the requests complete in one window.
    """

    def __init__(
        self,
        scope: Any = None,
        target: str | None = None,
        *,
        settle: float = _DEFAULT_SETTLE,
        timeout: float = _DEFAULT_TIMEOUT,
        warm: bool = True,
        verify_tls: bool = True,
    ) -> None:
        self.scope = scope
        self.target = target
        self.settle = settle
        self.timeout = timeout
        self.warm = warm
        self.verify_tls = verify_tls

    def _assert_scope(self) -> None:
        if self.scope is not None and self.target is not None:
            self.scope.assert_in_scope(self.target)

    def _open(self, scheme: str, host: str, port: int) -> socket.socket:
        sock = _tcp_connect(host, port, self.timeout)
        return _maybe_tls(
            sock, scheme, host, alpn=["http/1.1"], verify=self.verify_tls
        )

    def _warm(self, sock: socket.socket, authority: str) -> None:
        """Send a benign, side-effect-free request to clear TCP slow-start."""
        warm = f"GET / HTTP/1.1\r\nHost: {authority}\r\nConnection: keep-alive\r\n\r\n"
        sock.sendall(warm.encode("latin-1"))
        try:
            _read_h1_response(sock, self.timeout)
        except (socket.timeout, OSError):  # pragma: no cover - network dependent
            pass

    def run_single_endpoint(
        self, request: RaceRequest, copies: int
    ) -> list[ResponseSignature]:
        """Race ``copies`` identical requests via last-byte sync."""
        if copies < 2:
            raise ValueError("a race needs at least 2 concurrent copies")
        self._assert_scope()
        if self.target is None:
            raise TransportError("no target set on the engine")
        scheme, host, port, authority = split_target(self.target)
        payload = h1_bytes(request, authority=authority)
        if len(payload) < 2:
            raise ValueError("request too short for last-byte sync")

        socks: list[socket.socket] = []
        try:
            for _ in range(copies):
                sock = self._open(scheme, host, port)
                if self.warm:
                    self._warm(sock, request.authority or authority)
                socks.append(sock)

            # Arm: send everything but the final byte on every connection.
            for sock in socks:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.sendall(payload[:-1])
            time.sleep(self.settle)

            # Fire: release the final byte on every connection in a tight loop.
            final = payload[-1:]
            fire_ts = time.perf_counter()
            for sock in socks:
                sock.sendall(final)

            out: list[ResponseSignature] = []
            for sock in socks:
                status, body = _read_h1_response(sock, self.timeout)
                out.append(
                    ResponseSignature(
                        status=status,
                        body_sha256=body_hash(body),
                        body_len=len(body),
                        elapsed_ms=(time.perf_counter() - fire_ts) * 1000.0,
                    )
                )
            return out
        finally:
            for sock in socks:
                try:
                    sock.close()
                except OSError:  # pragma: no cover
                    pass


def _read_h1_response(sock: socket.socket, timeout: float) -> tuple[int, bytes]:
    """Read one HTTP/1.1 response; return (status, body). Content-Length or EOF.

    R5: the response is untrusted data -- parsed for status/length only, never
    executed. Chunked transfer-encoding is read to EOF as a pragmatic fallback.
    """
    sock.settimeout(timeout)
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(_READ_CHUNK)
        if not chunk:
            break
        buf.extend(chunk)
    header_end = buf.find(b"\r\n\r\n")
    if header_end == -1:
        return 0, bytes(buf)
    head = buf[:header_end].decode("latin-1")
    body = bytes(buf[header_end + 4:])

    status = 0
    lines = head.split("\r\n")
    if lines:
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])

    content_length: int | None = None
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            if name.strip().lower() == "content-length" and value.strip().isdigit():
                content_length = int(value.strip())
                break

    if content_length is not None:
        while len(body) < content_length:
            chunk = sock.recv(_READ_CHUNK)
            if not chunk:
                break
            body += chunk
        body = body[:content_length]
    else:
        # No Content-Length: read until the peer closes (bounded by timeout).
        try:
            while True:
                chunk = sock.recv(_READ_CHUNK)
                if not chunk:
                    break
                body += chunk
        except socket.timeout:  # pragma: no cover - network dependent
            pass
    return status, body
