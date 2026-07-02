"""scan-primitives-backed auth/baseline client.

Per the mandatory architecture split (V0.1-CRITERIA.md #6, shared-infra note),
reaper uses the shared ``scan-primitives`` :class:`~scan_primitives.ScanClient`
for the **well-formed** traffic only:

- authentication / session setup, and
- the **sequential baseline** (send solo requests first and record each one's
  status, response-body **hash**, timing, and optional second-order signal).

The shared client **cannot** drive the synchronized burst -- single-packet needs
raw frame/socket control, which lives in :mod:`reaper.engine`. The same ``Scope``
object is handed to the engine so the burst is scope-checked too. ``ScanClient``
already asserts scope before every request, so an out-of-scope baseline target
raises ``OutOfScopeError`` before any socket opens.

R5: response bytes fetched here are UNTRUSTED DATA -- hashed for comparison,
never executed, deserialized into code, or passed to a shell/LLM tool call.
"""

from __future__ import annotations

import time
from typing import Any, Awaitable, Callable

import httpx
from scan_primitives import ScanClient

from reaper.httpspec import RaceRequest, ResponseSignature, split_target

__all__ = ["BaselineClient"]

# A second-order probe maps a fetched response to a short string signal (e.g.
# an account balance read back after the operation). It receives untrusted
# response data and MUST treat it as data (R5); it returns a comparable token.
SecondOrder = Callable[[httpx.Response], Awaitable[str] | str]


def _url_for(target: str, req: RaceRequest) -> str:
    """Build the absolute URL the baseline sends to (scheme+authority+path).

    Uses the request's own authority if it carried a ``Host`` header, else the
    target's -- mirroring what the burst engine puts on the wire.
    """
    scheme, _host, _port, authority = split_target(target)
    return f"{scheme}://{req.authority or authority}{req.path}"


class BaselineClient:
    """Auth/session + sequential-baseline client over ``scan-primitives``.

    Wraps a scope-aware, rate-limited :class:`~scan_primitives.ScanClient`. Used
    for the well-formed baseline only; the burst is driven by
    :mod:`reaper.engine`, which is handed the same ``scope``.
    """

    def __init__(
        self,
        scope: Any = None,
        *,
        rate_limit: float | None = None,
        proxy: str | None = None,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        verify: bool = True,
    ) -> None:
        self.scope = scope
        self.rate_limit = rate_limit
        self.proxy = proxy
        self.timeout = timeout
        self._client = ScanClient(
            scope,
            rate_limit=rate_limit,
            proxy=proxy,
            timeout=timeout,
            transport=transport,
            verify=verify,
        )

    async def __aenter__(self) -> "BaselineClient":
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def authenticate(
        self, login: RaceRequest, *, target: str
    ) -> httpx.Response:
        """Establish an authenticated session for the race scenario.

        Sends ``login`` (e.g. a POST to a login endpoint) through the scope-aware
        client. Cookies set on the response persist in the client's jar and are
        replayed on the subsequent baseline requests (same session). Returns the
        response so the caller can assert the login succeeded. Scope is enforced
        by ``ScanClient`` before the socket opens.
        """
        return await self._client.request(
            login.method,
            _url_for(target, login),
            headers=dict(login.headers),
            content=login.body,
        )

    async def baseline(
        self,
        request: RaceRequest,
        samples: int,
        *,
        target: str,
        second_order: SecondOrder | None = None,
    ) -> list[ResponseSignature]:
        """Send ``samples`` sequential copies of ``request`` and fingerprint each.

        Records status / body-hash / body-length / timing (and an optional
        second-order signal) per request so the deviation-confirmation stage can
        diff the sequential baseline against the concurrent burst
        (V0.1-CRITERIA.md #5). Sequential by construction: a correctly
        synchronized single-use endpoint yields exactly one success here.

        R5: response bytes are data, never instructions.
        """
        url = _url_for(target, request)
        headers = dict(request.headers)
        sigs: list[ResponseSignature] = []
        for _ in range(samples):
            start = time.perf_counter()
            resp = await self._client.request(
                request.method, url, headers=headers, content=request.body
            )
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            signal: str | None = None
            if second_order is not None:
                result = second_order(resp)
                signal = await result if hasattr(result, "__await__") else result  # type: ignore[assignment]
            sigs.append(
                ResponseSignature.from_bytes(
                    status=resp.status_code,
                    body=resp.content,
                    elapsed_ms=elapsed_ms,
                    second_order=signal,
                )
            )
        return sigs

    @property
    def requests(self) -> list[Any]:
        """The scope-checked requests dispatched so far (evidence / assertions)."""
        return self._client.requests
