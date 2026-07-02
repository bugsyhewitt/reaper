"""Unit tests for the HTTP data model, parsers, transport selection, and the
scope guard -- all without opening a socket.

The scope-guard tests use pytest-socket to *prove* the scope check fires BEFORE
any egress: with sockets disabled, an out-of-scope target must raise
``OutOfScopeError`` (the guard) rather than a socket-blocked error.
"""

from __future__ import annotations

import pytest
from pytest_socket import disable_socket, enable_socket

from reaper.engine import (
    TRANSPORT_H1_LAST_BYTE_SYNC,
    TRANSPORT_H2_SINGLE_PACKET,
    LastByteSyncEngine,
    SinglePacketEngine,
    select_transport,
)
from reaper.httpspec import (
    RaceRequest,
    h1_bytes,
    h2_headers,
    parse_group_file,
    parse_request_file,
    split_target,
)
from scan_primitives import OutOfScopeError, Scope


# --- split_target ----------------------------------------------------------


def test_split_target_https_default_port():
    scheme, host, port, authority = split_target("https://shop.example.com/redeem")
    assert (scheme, host, port, authority) == ("https", "shop.example.com", 443, "shop.example.com")


def test_split_target_explicit_port_in_authority():
    scheme, host, port, authority = split_target("http://127.0.0.1:8000/x")
    assert (scheme, host, port, authority) == ("http", "127.0.0.1", 8000, "127.0.0.1:8000")


def test_split_target_bare_host_defaults_http():
    scheme, host, port, authority = split_target("example.com")
    assert scheme == "http" and host == "example.com" and port == 80


# --- parse_request_file ----------------------------------------------------


RAW = (
    "POST /redeem HTTP/1.1\r\n"
    "Host: shop.example.com\r\n"
    "Content-Type: application/json\r\n"
    "Connection: keep-alive\r\n"
    "Content-Length: 999\r\n"
    "\r\n"
    '{"code":"SAVE10"}'
)


def test_parse_request_basic_fields():
    req = parse_request_file(RAW)
    assert req.method == "POST"
    assert req.path == "/redeem"
    assert req.authority == "shop.example.com"
    assert req.body == b'{"code":"SAVE10"}'


def test_parse_request_strips_hop_by_hop_and_host_and_content_length():
    req = parse_request_file(RAW)
    names = {n for n, _ in req.headers}
    assert "host" not in names  # -> :authority
    assert "connection" not in names  # hop-by-hop
    assert "content-length" not in names  # recomputed per transport
    assert ("content-type", "application/json") in req.headers


def test_parse_request_lowercases_header_names():
    req = parse_request_file(RAW)
    assert all(n == n.lower() for n, _ in req.headers)


def test_parse_request_rejects_empty():
    with pytest.raises(ValueError):
        parse_request_file("")


# --- parse_group_file ------------------------------------------------------


GROUP = (
    "@delay 0\n"
    "POST /email/change HTTP/1.1\n"
    "Host: app.example.com\n"
    "\n"
    '{"email":"a@evil.test"}\n'
    "%%%\n"
    "@delay 0.05\n"
    "POST /email/confirm HTTP/1.1\n"
    "Host: app.example.com\n"
    "\n"
    '{"token":"000000"}'
)


def test_parse_group_splits_requests_and_reads_delays():
    reqs = parse_group_file(GROUP)
    assert len(reqs) == 2
    assert reqs[0].path == "/email/change" and reqs[0].delay == 0.0
    assert reqs[1].path == "/email/confirm" and reqs[1].delay == 0.05
    assert reqs[0].body == b'{"email":"a@evil.test"}'


def test_parse_group_rejects_empty():
    with pytest.raises(ValueError):
        parse_group_file("%%%\n%%%\n")


# --- header / wire rendering -----------------------------------------------


def test_h2_headers_pseudo_first_and_content_length():
    req = RaceRequest(method="POST", path="/redeem",
                      headers=[("content-type", "application/json")], body=b"{}")
    headers = h2_headers(req, scheme="https", authority="shop.example.com")
    assert headers[0] == (":method", "POST")
    assert (":path", "/redeem") in headers
    assert (":scheme", "https") in headers
    assert (":authority", "shop.example.com") in headers
    assert ("content-length", "2") in headers
    # no Host pseudo/real header leaks in
    assert all(n != "host" for n, _ in headers)


def test_h2_headers_bodyless_has_no_content_length():
    req = RaceRequest(method="GET", path="/", headers=[])
    headers = h2_headers(req, scheme="http", authority="x")
    assert all(n != "content-length" for n, _ in headers)


def test_h1_bytes_has_host_content_length_and_body():
    req = RaceRequest(method="POST", path="/withdraw",
                      headers=[("content-type", "application/json")], body=b'{"amt":100}')
    raw = h1_bytes(req, authority="bank.example.com")
    assert raw.startswith(b"POST /withdraw HTTP/1.1\r\n")
    assert b"Host: bank.example.com\r\n" in raw
    assert b"Content-Length: 11\r\n" in raw
    assert raw.endswith(b'{"amt":100}')


# --- transport selection (no network for explicit prefer) ------------------


def test_select_transport_explicit_prefer_is_returned_unchanged():
    assert (
        select_transport("https://x.example", prefer=TRANSPORT_H2_SINGLE_PACKET)
        == TRANSPORT_H2_SINGLE_PACKET
    )
    assert (
        select_transport("https://x.example", prefer=TRANSPORT_H1_LAST_BYTE_SYNC)
        == TRANSPORT_H1_LAST_BYTE_SYNC
    )


# --- scope guard fires BEFORE any socket -----------------------------------


def test_single_packet_engine_blocks_out_of_scope_before_egress():
    disable_socket()
    try:
        scope = Scope.from_entries(["shop.example.com"])
        engine = SinglePacketEngine(scope, "https://evil.attacker.test/redeem")
        req = RaceRequest(method="POST", path="/redeem", body=b"x")
        with pytest.raises(OutOfScopeError):
            engine.run_single_endpoint(req, 20)
    finally:
        enable_socket()


def test_last_byte_engine_blocks_out_of_scope_before_egress():
    disable_socket()
    try:
        scope = Scope.from_entries(["shop.example.com"])
        engine = LastByteSyncEngine(scope, "https://evil.attacker.test/redeem")
        req = RaceRequest(method="POST", path="/redeem", body=b"x")
        with pytest.raises(OutOfScopeError):
            engine.run_single_endpoint(req, 20)
    finally:
        enable_socket()


def test_select_transport_scope_checks_before_probe():
    disable_socket()
    try:
        scope = Scope.from_entries(["shop.example.com"])
        with pytest.raises(OutOfScopeError):
            select_transport("https://evil.attacker.test/x", scope=scope)
    finally:
        enable_socket()


def test_run_single_endpoint_requires_two_copies():
    engine = SinglePacketEngine(Scope.from_entries(["x.example"]), "https://x.example/")
    with pytest.raises(ValueError):
        engine.run_single_endpoint(RaceRequest(method="GET", path="/"), 1)
