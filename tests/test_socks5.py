"""Tests for SOCKS5 proxy support in the raw burst engines.

These tests use a minimal in-process SOCKS5 server (no-auth, domain-name
address type) to verify the protocol handshake without a real proxy.  The
engine-level tests only verify the handshake succeeds and the target host/port
are forwarded correctly — the tunnel teardown is expected because there is no
real target server behind the mock proxy.
"""

from __future__ import annotations

import socket
import struct
import threading

import pytest
from pytest_socket import disable_socket, enable_socket

from reaper.engine import (
    TransportError,
    LastByteSyncEngine,
    SinglePacketEngine,
    parse_socks5_proxy,
    _recv_exact,
    _socks5_tunnel,
)
from reaper.httpspec import RaceRequest
from scan_primitives import Scope


# --------------------------------------------------------------------------- #
# Mock SOCKS5 server
# --------------------------------------------------------------------------- #


class _MockSocks5Server:
    """Minimal SOCKS5 no-auth / DOMAINNAME server for unit testing.

    Accepts one connection, performs the RFC 1928 handshake, records the
    requested target, replies with success, then closes the tunnel side.
    The socket returned to the caller looks connected but will EOF immediately
    — enough for testing the handshake path without a real backend.
    """

    def __init__(self) -> None:
        self.last_target: tuple[str, int] | None = None
        self._error: Exception | None = None
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(1)
        self._port = self._srv.getsockname()[1]
        self._done = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return self._port

    @property
    def proxy_url(self) -> str:
        return f"socks5://127.0.0.1:{self._port}"

    def wait(self, timeout: float = 5.0) -> None:
        """Block until the server has handled one connection (or timed out)."""
        self._done.wait(timeout)

    def _serve(self) -> None:
        try:
            self._srv.settimeout(5.0)
            conn, _ = self._srv.accept()
        except socket.timeout:
            return
        finally:
            self._srv.close()

        try:
            # -- RFC 1928 §3: method negotiation --
            greeting = _recv_exact(conn, 3)
            if greeting != b"\x05\x01\x00":
                self._error = ValueError(f"bad greeting {greeting!r}")
                return
            conn.sendall(b"\x05\x00")

            # -- RFC 1928 §4: CONNECT request --
            hdr = _recv_exact(conn, 4)
            atyp = hdr[3]
            if atyp == 3:
                dlen = _recv_exact(conn, 1)[0]
                host = _recv_exact(conn, dlen).decode("ascii")
                port_bytes = _recv_exact(conn, 2)
                port = struct.unpack(">H", port_bytes)[0]
                self.last_target = (host, port)
            elif atyp == 1:
                addr_bytes = _recv_exact(conn, 4)
                host = socket.inet_ntoa(addr_bytes)
                port_bytes = _recv_exact(conn, 2)
                port = struct.unpack(">H", port_bytes)[0]
                self.last_target = (host, port)

            # -- RFC 1928 §6: success reply (bound addr 0.0.0.0:0) --
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        except Exception as exc:
            self._error = exc
        finally:
            conn.close()
            self._done.set()

    def assert_no_error(self) -> None:
        if self._error:
            raise AssertionError(f"mock SOCKS5 server error: {self._error}") from self._error


# --------------------------------------------------------------------------- #
# parse_socks5_proxy
# --------------------------------------------------------------------------- #


def test_parse_socks5_proxy_basic():
    host, port = parse_socks5_proxy("socks5://127.0.0.1:1080")
    assert host == "127.0.0.1"
    assert port == 1080


def test_parse_socks5_proxy_socks5h_scheme():
    host, port = parse_socks5_proxy("socks5h://proxy.corp:9050")
    assert host == "proxy.corp"
    assert port == 9050


def test_parse_socks5_proxy_default_port():
    host, port = parse_socks5_proxy("socks5://myproxy.internal")
    assert host == "myproxy.internal"
    assert port == 1080


def test_parse_socks5_proxy_rejects_http_scheme():
    with pytest.raises(ValueError, match="socks5"):
        parse_socks5_proxy("http://proxy.example:8080")


def test_parse_socks5_proxy_rejects_missing_host():
    with pytest.raises(ValueError):
        parse_socks5_proxy("socks5://")


# --------------------------------------------------------------------------- #
# _socks5_tunnel (handshake verification via mock server)
# --------------------------------------------------------------------------- #


def test_socks5_tunnel_handshake_succeeds():
    srv = _MockSocks5Server()
    sock = _socks5_tunnel("127.0.0.1", srv.port, "target.example.com", 443, 5.0)
    sock.close()
    srv.wait()
    srv.assert_no_error()
    assert srv.last_target == ("target.example.com", 443)


def test_socks5_tunnel_records_correct_port():
    srv = _MockSocks5Server()
    sock = _socks5_tunnel("127.0.0.1", srv.port, "api.example.com", 8080, 5.0)
    sock.close()
    srv.wait()
    srv.assert_no_error()
    assert srv.last_target == ("api.example.com", 8080)


def test_socks5_tunnel_error_reply_raises_transport_error():
    """A non-zero REP byte from the proxy must raise TransportError."""

    def _bad_server(srv_sock: socket.socket) -> None:
        try:
            conn, _ = srv_sock.accept()
            try:
                _recv_exact(conn, 3)
                conn.sendall(b"\x05\x00")  # auth ok
                _recv_exact(conn, 4)       # consume CONNECT header
                dlen = _recv_exact(conn, 1)[0]
                _recv_exact(conn, dlen + 2)
                # REP=0x05: connection refused
                conn.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            finally:
                conn.close()
        finally:
            srv_sock.close()

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    t = threading.Thread(target=_bad_server, args=(srv,), daemon=True)
    t.start()

    with pytest.raises(TransportError, match="connection refused"):
        _socks5_tunnel("127.0.0.1", port, "target.example.com", 443, 5.0)
    t.join(timeout=2.0)


# --------------------------------------------------------------------------- #
# Engine integration: proxy parameter flows to raw socket
# --------------------------------------------------------------------------- #


def test_single_packet_engine_uses_socks5_proxy():
    """SinglePacketEngine with proxy routes the raw H2 connection through SOCKS5."""
    srv = _MockSocks5Server()
    scope = Scope.from_entries(["target.example.com"])
    engine = SinglePacketEngine(
        scope,
        "http://target.example.com/redeem",
        proxy=srv.proxy_url,
        timeout=3.0,
    )
    req = RaceRequest(method="POST", path="/redeem", body=b"x")
    with pytest.raises((TransportError, OSError)):
        # The mock proxy closes the tunnel immediately after handshake; the H2
        # connect attempt fails. We only care that the SOCKS5 handshake ran.
        engine.run_single_endpoint(req, 2)
    srv.wait(timeout=3.0)
    srv.assert_no_error()
    assert srv.last_target == ("target.example.com", 80)


def test_last_byte_engine_uses_socks5_proxy():
    """LastByteSyncEngine with proxy routes each H1 connection through SOCKS5."""
    srv = _MockSocks5Server()
    scope = Scope.from_entries(["target.example.com"])
    engine = LastByteSyncEngine(
        scope,
        "http://target.example.com/redeem",
        proxy=srv.proxy_url,
        timeout=3.0,
    )
    req = RaceRequest(method="POST", path="/redeem", body=b"x")
    with pytest.raises((TransportError, OSError)):
        engine.run_single_endpoint(req, 2)
    srv.wait(timeout=3.0)
    srv.assert_no_error()
    assert srv.last_target == ("target.example.com", 80)


def test_single_packet_engine_invalid_proxy_scheme_raises():
    scope = Scope.from_entries(["x.example"])
    engine = SinglePacketEngine(
        scope,
        "http://x.example/path",
        proxy="http://proxy.example:8080",
        timeout=3.0,
    )
    req = RaceRequest(method="GET", path="/path")
    with pytest.raises(ValueError, match="socks5"):
        engine.run_single_endpoint(req, 2)


# --------------------------------------------------------------------------- #
# Scope guard still fires BEFORE proxy connection when out of scope
# --------------------------------------------------------------------------- #


def test_proxy_does_not_bypass_scope_check():
    """Even with a proxy configured, an out-of-scope target must raise before any socket."""
    disable_socket()
    try:
        scope = Scope.from_entries(["allowed.example.com"])
        engine = SinglePacketEngine(
            scope,
            "http://evil.attacker.test/steal",
            proxy="socks5://127.0.0.1:1080",
        )
        req = RaceRequest(method="GET", path="/steal")
        from scan_primitives import OutOfScopeError
        with pytest.raises(OutOfScopeError):
            engine.run_single_endpoint(req, 2)
    finally:
        enable_socket()


# --------------------------------------------------------------------------- #
# CLI: --proxy option is exposed and parsed
# --------------------------------------------------------------------------- #


def test_cli_single_proxy_option_parsed():
    from reaper.cli import build_parser
    parser = build_parser()
    args = parser.parse_args([
        "single",
        "--target", "http://x.example/redeem",
        "--request", "req.http",
        "--copies", "20",
        "--proxy", "socks5://127.0.0.1:1080",
    ])
    assert args.proxy == "socks5://127.0.0.1:1080"


def test_cli_group_proxy_option_parsed():
    from reaper.cli import build_parser
    parser = build_parser()
    args = parser.parse_args([
        "group",
        "--target", "http://x.example",
        "--group-file", "g.group",
        "--proxy", "socks5://10.0.0.1:9050",
    ])
    assert args.proxy == "socks5://10.0.0.1:9050"


def test_cli_proxy_defaults_to_none():
    from reaper.cli import build_parser
    parser = build_parser()
    args = parser.parse_args([
        "single",
        "--target", "http://x.example/redeem",
        "--request", "req.http",
        "--copies", "20",
    ])
    assert args.proxy is None
