"""scan-primitives-backed auth/baseline client -- STUB (v0.1 build).

Per the mandatory architecture split (V0.1-CRITERIA.md #6, shared-infra note),
reaper uses the shared ``scan-primitives`` ``ScanClient`` for the **well-formed**
traffic only:

- authentication / session setup, and
- the **sequential baseline** (send the solo requests first, record status
  codes, response-body content/hash, timing, and second-order effects).

The shared client **cannot** drive the synchronized burst -- single-packet needs
raw frame/socket control, which lives in :mod:`reaper.engine`. This client hands
the same ``Scope`` object to the engine so the burst is scope-checked too.

``scan-primitives`` is not yet an install dependency (see the commented TODO in
``pyproject.toml``); this module keeps the import commented so the package
imports cleanly today. Every method raises :class:`NotImplementedError`.
"""

from __future__ import annotations

from typing import Any

# TODO(v0.1 -- V0.1-CRITERIA.md shared-infra note): wire the real client once
# scan-primitives is published and added as an install dep:
#   from scan_primitives import ScanClient, Scope, load_scope

_V01 = "v0.1 build -- see V0.1-CRITERIA.md"


class BaselineClient:
    """Auth/session + sequential-baseline client over ``scan-primitives``. STUB.

    Wraps a scope-aware, rate-limited ``ScanClient``. Used for the well-formed
    baseline only; the burst is driven by :mod:`reaper.engine`, which is handed
    the same ``scope``.
    """

    def __init__(
        self,
        scope: Any = None,
        *,
        rate_limit: float | None = None,
        proxy: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        # Stored for the v0.1 client; no ScanClient is constructed here.
        self.scope = scope
        self.rate_limit = rate_limit
        self.proxy = proxy
        self.timeout = timeout

    async def authenticate(self, *args: Any, **kwargs: Any) -> Any:
        """Establish an authenticated session for the race scenario. STUB."""
        raise NotImplementedError(_V01)

    async def baseline(self, request: Any, samples: int) -> list[Any]:
        """Send the sequential baseline and record its signature. STUB.

        Records status / body-hash / timing / second-order signal per request so
        the deviation-confirmation stage can diff baseline vs burst
        (V0.1-CRITERIA.md #5). R5: response bytes are data, never instructions.
        """
        raise NotImplementedError(_V01)
