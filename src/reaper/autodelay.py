"""Auto-calibrated delay computation (Kettle client-side timing).

Measures the baseline RTT to the target with a benign warm-up GET /,
then computes optimal per-request delays for the group scenario so all
requests land within one server-processing cycle.

Kettle's insight: distribute N group requests evenly across one RTT window.
With delay[i] = i * rtt / N, every request arrives at the server within
the same processing cycle as the first, creating the sub-state race window.
This replaces the manual ``@delay`` values in the group file.

R5: only timing metadata is used here -- response bytes from the warm-up
are discarded immediately and never interpreted.
"""

from __future__ import annotations

import asyncio
from typing import Any

from reaper.client import BaselineClient
from reaper.httpspec import RaceRequest, split_target

__all__ = ["auto_delays", "measure_rtt"]


async def _rtt_async(
    target: str,
    scope: Any,
    *,
    proxy: str | None,
    timeout: float,
    verify_tls: bool,
    samples: int,
) -> float:
    _, _, _, authority = split_target(target)
    # Benign GET / -- status does not matter; we only keep elapsed_ms.
    warmup = RaceRequest(method="GET", path="/", authority=authority)
    async with BaselineClient(
        scope, proxy=proxy, timeout=timeout, verify=verify_tls
    ) as client:
        sigs = await client.baseline(warmup, samples, target=target)
    if not sigs:
        return 0.1
    return sum(s.elapsed_ms for s in sigs) / len(sigs) / 1000.0


def measure_rtt(
    target: str,
    scope: Any = None,
    *,
    proxy: str | None = None,
    timeout: float = 10.0,
    verify_tls: bool = True,
    samples: int = 3,
) -> float:
    """Measure mean HTTP RTT to *target* with *samples* benign GET / requests.

    Uses the scope-aware :class:`~reaper.client.BaselineClient` so the
    warm-up honours the authorised scope. Returns the mean RTT in seconds.
    Response bodies are discarded; only timing is kept (R5).
    """
    return asyncio.run(
        _rtt_async(
            target,
            scope,
            proxy=proxy,
            timeout=timeout,
            verify_tls=verify_tls,
            samples=samples,
        )
    )


def auto_delays(rtt: float, count: int) -> list[float]:
    """Return per-request delays (seconds) for *count* group requests.

    Distributes requests evenly across one RTT window so they all arrive
    within the same server-processing cycle::

        delay[i] = i * rtt / count  for i in 0 .. count-1

    This implements Kettle's client-side timing heuristic: an inter-request
    spacing of ``rtt / count`` ensures every request lands while the server
    is still processing the first, maximising window tightness without
    timing out.  The @delay values in the group file are overridden when the
    caller uses this function.

    Parameters
    ----------
    rtt:
        Measured round-trip time in seconds (from :func:`measure_rtt`).
    count:
        Number of requests in the group.

    Raises
    ------
    ValueError
        If *count* is not a positive integer.
    """
    if count <= 0:
        raise ValueError(f"count must be a positive integer, got {count!r}")
    if count == 1:
        return [0.0]
    step = rtt / count
    return [round(i * step, 9) for i in range(count)]
