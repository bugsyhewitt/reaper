"""Deliberately race-vulnerable ASGI app + Hypercorn harness for the CI lab.

This is the acceptance fixture for reaper's v0.1 (V0.1-CRITERIA.md, Testability).
It is served by **Hypercorn** so it speaks HTTP/2 cleartext (h2c, prior
knowledge, no TLS certs) for reaper's single-packet engine, AND HTTP/1.1 for the
scan-primitives baseline client -- Hypercorn sniffs the connection preface and
serves whichever the client speaks. (uvicorn does NOT support HTTP/2.)

Two make-or-break properties (both satisfied here):

1. **Runs concurrently.** A single Hypercorn asyncio worker serves requests
   concurrently: each handler ``await``s a small artificial delay, which yields
   the event loop so a synchronized burst interleaves and the check-then-act
   window opens. A serialized server would never race (silent false-negative).
2. **Non-atomic check-then-act with a widened window.** Each vulnerable endpoint
   reads shared state, ``await asyncio.sleep(window)``, then writes -- backed by
   a plain dict with no locking.

Fixtures:
- **A (single-use coupon):** ``POST /redeem/{code}`` -> check unused, sleep,
  mark used + credit; ``GET /coupon/{code}`` reads the committed redeem count
  (the final-state read-back used to confirm persistence).
- **C (multi-endpoint sub-state):** ``POST /email/change`` sets a single pending
  slot; ``POST /email/confirm`` commits it -- racing change+confirm over one slot.

``GET /reset`` clears all state. All lab code is trusted test scaffolding.
"""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
from contextlib import closing
from urllib.parse import parse_qs, urlsplit


class RaceLabApp:
    """A tiny non-atomic ASGI app with a deliberately widened race window."""

    def __init__(self, window: float = 0.1) -> None:
        self.window = window
        self.coupons: dict[str, dict] = {}
        self.pending_email: dict | None = None
        self.confirmed_emails: list[str] = []

    def reset(self) -> None:
        self.coupons.clear()
        self.pending_email = None
        self.confirmed_emails.clear()

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        assert scope["type"] == "http"
        body = await self._read_body(receive)
        path = scope["path"]
        query = parse_qs(scope.get("query_string", b"").decode("latin-1"))
        window = float(query.get("window", [self.window])[0])

        if path.startswith("/redeem/"):
            status, payload = await self._redeem(path.rsplit("/", 1)[-1], window)
        elif path.startswith("/coupon/"):
            status, payload = self._read_coupon(path.rsplit("/", 1)[-1])
        elif path == "/email/change":
            status, payload = await self._email_change(body, window)
        elif path == "/email/confirm":
            status, payload = await self._email_confirm(body, window)
        elif path == "/reset":
            self.reset()
            status, payload = 200, {"ok": True}
        else:
            status, payload = 200, {"ok": True, "path": path}

        await self._respond(send, status, payload)

    # -- vulnerable handlers ------------------------------------------------ #

    async def _redeem(self, code: str, window: float) -> tuple[int, dict]:
        coupon = self.coupons.setdefault(code, {"used": False, "count": 0})
        if not coupon["used"]:            # CHECK
            await asyncio.sleep(window)    # widen the window (yields the loop)
            coupon["used"] = True          # ACT
            coupon["count"] += 1
            return 200, {"ok": True, "redemption_id": coupon["count"], "code": code}
        return 409, {"ok": False, "error": "coupon already redeemed", "code": code}

    def _read_coupon(self, code: str) -> tuple[int, dict]:
        coupon = self.coupons.get(code, {"used": False, "count": 0})
        # count == committed successful redemptions == the persisted final state.
        return 200, {"code": code, "redeemed_count": coupon["count"]}

    async def _email_change(self, body: bytes, window: float) -> tuple[int, dict]:
        data = _json(body)
        if self.pending_email is None:     # CHECK (single pending slot free)
            await asyncio.sleep(window)
            self.pending_email = {"email": data.get("email", ""), "token": data.get("token", "")}
            return 200, {"ok": True, "pending": self.pending_email["email"]}
        return 409, {"ok": False, "error": "a change is already pending"}

    async def _email_confirm(self, body: bytes, window: float) -> tuple[int, dict]:
        if self.pending_email is not None:  # CHECK
            await asyncio.sleep(window)
            email = self.pending_email["email"]  # ACT
            self.confirmed_emails.append(email)
            self.pending_email = None
            return 200, {"ok": True, "confirmed": email}
        return 409, {"ok": False, "error": "nothing pending to confirm"}

    # -- ASGI plumbing ------------------------------------------------------ #

    async def _read_body(self, receive) -> bytes:
        buf = bytearray()
        while True:
            msg = await receive()
            buf.extend(msg.get("body", b""))
            if not msg.get("more_body"):
                break
        return bytes(buf)

    async def _respond(self, send, status: int, payload: dict) -> None:
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

    async def _lifespan(self, receive, send) -> None:
        while True:
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif msg["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return


def _json(body: bytes) -> dict:
    try:
        obj = json.loads(body or b"{}")
        return obj if isinstance(obj, dict) else {}
    except (ValueError, TypeError):
        return {}


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class LabServer:
    """Runs :class:`RaceLabApp` under Hypercorn in a background thread."""

    def __init__(self, app: RaceLabApp, port: int) -> None:
        self.app = app
        self.port = port
        self.base_url = f"http://127.0.0.1:{port}"
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self, ready_timeout: float = 10.0) -> None:
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        deadline = time.time() + ready_timeout
        while time.time() < deadline:
            with closing(socket.socket()) as probe:
                probe.settimeout(0.2)
                try:
                    probe.connect(("127.0.0.1", self.port))
                    return
                except OSError:
                    time.sleep(0.05)
        raise RuntimeError("lab server did not start in time")

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)

    def _serve(self) -> None:
        from hypercorn.asyncio import serve
        from hypercorn.config import Config

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        config = Config()
        config.bind = [f"127.0.0.1:{self.port}"]
        config.accesslog = None
        config.errorlog = None

        async def _trigger() -> None:
            while not self._stop.is_set():
                await asyncio.sleep(0.05)

        try:
            loop.run_until_complete(serve(self.app, config, shutdown_trigger=_trigger))
        finally:
            loop.close()


def start_lab(window: float = 0.1) -> LabServer:
    """Start a fresh race-lab server on an ephemeral port and return it."""
    server = LabServer(RaceLabApp(window=window), _free_port())
    server.start()
    return server
