"""Request/response data model + raw-HTTP parsers for reaper.

This module holds the plumbing shared by the baseline client
(:mod:`reaper.client`) and the low-level burst engine (:mod:`reaper.engine`):

- :class:`RaceRequest` -- one request to race (method / path / headers / body,
  plus an optional *manual* per-request ``delay`` used only by the group mode).
- :class:`ResponseSignature` -- the R5-safe fingerprint of a single response
  (status, body **hash**, body length, elapsed ms, optional second-order signal).
  Response bytes are hashed with :mod:`hashlib`; they are **never** evaluated,
  executed, or interpreted -- they are data (R5).
- :func:`parse_request_file` / :func:`parse_group_file` -- parse a raw HTTP
  request (Burp/Repeater style) and the reaper group-file format.
- :func:`h2_headers` / :func:`h1_bytes` -- render a :class:`RaceRequest` onto the
  wire for the HTTP/2 (pseudo-header) and HTTP/1.1 (raw-bytes) transports.
- :func:`split_target` -- scheme/host/port/authority from a target URL.

Nothing here opens a socket.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from urllib.parse import urlsplit

__all__ = [
    "RaceRequest",
    "ResponseSignature",
    "body_hash",
    "h1_bytes",
    "h2_headers",
    "parse_group_file",
    "parse_request_file",
    "split_target",
]

# Default ports per scheme.
_DEFAULT_PORT = {"http": 80, "https": 443}

# Header names that are illegal in HTTP/2 (RFC 9113 s8.2.2, connection-specific)
# or are otherwise regenerated per-transport. Compared case-insensitively.
# ``host`` is dropped because it becomes the ``:authority`` pseudo-header;
# ``content-length`` is recomputed from the actual body.
_H2_STRIP = frozenset(
    {
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
    }
)

# The reaper group-file request separator (a line that is exactly this token).
GROUP_SEPARATOR = "%%%"
# A group-file directive setting the next request's manual delay, e.g. "@delay 0.05".
_DELAY_DIRECTIVE = "@delay"


def body_hash(body: bytes) -> str:
    """Return the sha256 hex digest of ``body``.

    R5: the response body is UNTRUSTED DATA. It is hashed for comparison and
    never executed, deserialized into code, or handed to a shell/LLM tool call.
    """
    return hashlib.sha256(body).hexdigest()


@dataclass(slots=True)
class RaceRequest:
    """One request to be raced.

    Attributes:
        method: HTTP method (upper-case).
        path: request target, e.g. ``/redeem?x=1``.
        headers: ordered ``(name, value)`` pairs. Names are stored lower-cased.
        body: request body bytes (may be empty).
        delay: manual per-request delay in seconds, honoured only by the group
            mode's synchronized release. ``0`` for the single-endpoint scenario.
        authority: optional ``host[:port]`` override (from a ``Host:`` header);
            falls back to the target's authority at send time.
    """

    method: str
    path: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    delay: float = 0.0
    authority: str | None = None


@dataclass(slots=True)
class ResponseSignature:
    """R5-safe fingerprint of one response (never carries executable content)."""

    status: int
    body_sha256: str
    body_len: int
    elapsed_ms: float
    second_order: str | None = None

    @classmethod
    def from_bytes(
        cls,
        status: int,
        body: bytes,
        elapsed_ms: float,
        *,
        second_order: str | None = None,
    ) -> ResponseSignature:
        return cls(
            status=status,
            body_sha256=body_hash(body),
            body_len=len(body),
            elapsed_ms=elapsed_ms,
            second_order=second_order,
        )


def split_target(target: str) -> tuple[str, str, int, str]:
    """Return ``(scheme, host, port, authority)`` for a target URL.

    ``authority`` is ``host`` when the port is the scheme default, else
    ``host:port`` -- the value used for the HTTP/2 ``:authority`` pseudo-header
    and the HTTP/1.1 ``Host`` header.
    """
    if "://" not in target:
        target = "//" + target
    parts = urlsplit(target, scheme="http")
    scheme = (parts.scheme or "http").lower()
    host = parts.hostname
    if not host:
        raise ValueError(f"cannot parse host from target {target!r}")
    port = parts.port or _DEFAULT_PORT.get(scheme, 80)
    authority = host if port == _DEFAULT_PORT.get(scheme) else f"{host}:{port}"
    return scheme, host, port, authority


def _split_head_body(raw: bytes) -> tuple[str, bytes]:
    """Split a raw HTTP message into its (text) head and (bytes) body."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            return raw[:idx].decode("latin-1"), raw[idx + len(sep):]
    return raw.decode("latin-1"), b""


def parse_request_file(
    data: str | bytes,
    *,
    default_authority: str | None = None,
    delay: float = 0.0,
) -> RaceRequest:
    """Parse a raw HTTP request (Burp/Repeater style) into a :class:`RaceRequest`.

    The first line is ``METHOD PATH [HTTP/x]``; header lines follow until a blank
    line; everything after the blank line is the body. A ``Host:`` header (if
    present) sets :attr:`RaceRequest.authority`. Connection-specific headers and
    ``Content-Length`` are dropped here and regenerated per-transport at send
    time. Bodies are read as raw bytes -- untrusted data, never executed (R5).
    """
    raw = data.encode("latin-1") if isinstance(data, str) else data
    head, body = _split_head_body(raw)
    lines = head.split("\n")
    if not lines or not lines[0].strip():
        raise ValueError("empty request: no request line")

    request_line = lines[0].strip()
    tokens = request_line.split()
    if len(tokens) < 2:
        raise ValueError(f"malformed request line: {request_line!r}")
    method, path = tokens[0].upper(), tokens[1]

    headers: list[tuple[str, str]] = []
    authority = default_authority
    for line in lines[1:]:
        line = line.rstrip("\r")
        if not line.strip():
            continue
        if ":" not in line:
            raise ValueError(f"malformed header line: {line!r}")
        name, value = line.split(":", 1)
        name, value = name.strip().lower(), value.strip()
        if name == "host":
            authority = value
            continue
        if name in _H2_STRIP:
            continue
        headers.append((name, value))

    return RaceRequest(
        method=method,
        path=path,
        headers=headers,
        body=body,
        delay=delay,
        authority=authority,
    )


def parse_group_file(
    data: str | bytes,
    *,
    default_authority: str | None = None,
) -> list[RaceRequest]:
    """Parse a reaper group file into an ordered list of :class:`RaceRequest`.

    The group file is a sequence of raw HTTP requests separated by a line that
    is exactly ``%%%``. Each request block may be preceded by a manual-delay
    directive on its own line::

        @delay 0
        POST /email/change HTTP/1.1
        Host: app.example.com

        {"email":"attacker@evil.test"}
        %%%
        @delay 0.05
        POST /email/confirm HTTP/1.1
        Host: app.example.com

        {"token":"000000"}

    ``@delay <seconds>`` sets that request's manual release offset within the
    synchronized burst (MANUAL, never auto-calibrated -- see V0.1-CRITERIA.md).
    Lines beginning with ``#`` before a block's request line are comments.
    """
    text = data.decode("latin-1") if isinstance(data, bytes) else data
    blocks: list[list[str]] = [[]]
    for line in text.splitlines():
        if line.strip() == GROUP_SEPARATOR:
            blocks.append([])
        else:
            blocks[-1].append(line)

    requests: list[RaceRequest] = []
    for block in blocks:
        delay = 0.0
        body_lines: list[str] = []
        # Strip leading directive / comment lines that precede the request line.
        started = False
        for line in block:
            stripped = line.strip()
            if not started:
                if not stripped:
                    continue
                low = stripped.lower()
                if low.startswith(_DELAY_DIRECTIVE):
                    parts = stripped.split(None, 1)
                    if len(parts) == 2:
                        try:
                            delay = float(parts[1])
                        except ValueError as exc:
                            raise ValueError(
                                f"bad @delay directive: {stripped!r}"
                            ) from exc
                    continue
                if stripped.startswith("#"):
                    continue
                started = True
            body_lines.append(line)
        if not started:
            continue  # blank / directive-only block
        requests.append(
            parse_request_file(
                "\n".join(body_lines),
                default_authority=default_authority,
                delay=delay,
            )
        )
    if not requests:
        raise ValueError("group file contains no requests")
    return requests


def h2_headers(
    req: RaceRequest,
    *,
    scheme: str,
    authority: str,
) -> list[tuple[str, str]]:
    """Render ``req`` as an HTTP/2 header block (pseudo-headers first).

    Emits ``:method :path :scheme :authority`` then the request's regular
    headers (already lower-cased and stripped of connection-specific fields).
    ``content-length`` is added when there is a body so the peer frames the
    stream correctly.
    """
    pseudo: list[tuple[str, str]] = [
        (":method", req.method),
        (":path", req.path),
        (":scheme", scheme),
        (":authority", req.authority or authority),
    ]
    regular = [(n, v) for (n, v) in req.headers if not n.startswith(":")]
    if req.body:
        regular.append(("content-length", str(len(req.body))))
    return pseudo + regular


def h1_bytes(req: RaceRequest, *, authority: str) -> bytes:
    """Render ``req`` as raw HTTP/1.1 request bytes (for last-byte-sync).

    Forces ``Host`` (from the request's authority or the target), sets an
    explicit ``Content-Length``, and keeps the connection alive so a warmed
    connection can carry the withheld-final-byte request.
    """
    host = req.authority or authority
    lines = [f"{req.method} {req.path} HTTP/1.1", f"Host: {host}"]
    seen = {"host", "content-length", "connection"}
    for name, value in req.headers:
        if name in seen:
            continue
        lines.append(f"{name}: {value}")
    lines.append(f"Content-Length: {len(req.body)}")
    lines.append("Connection: keep-alive")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    return head + req.body
