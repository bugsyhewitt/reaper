"""reaper -- headless HTTP/2 single-packet race-condition detector.

reaper resurrects the dead ancestor ``race-the-web`` (HTTP/1.1 threaded racing,
pre-single-packet era) with the modern single-packet attack technique (James
Kettle, DEF CON 31): multiplex N requests on one HTTP/2 connection, withhold
each request's final frame, then release all withheld frames in a single
synchronized TCP flush so they land in one packet -- eliminating network jitter
and opening a true atomic race window. It benchmarks a sequential baseline,
fires the concurrent burst, and flags statistical deviations (status / body /
timing / second-order) as findings.

v1.0.0 is complete: the low-level single-packet engine (:mod:`reaper.engine`),
the scan-primitives auth/baseline client (:mod:`reaper.client`), the
benchmark→burst deviation confirmation (:mod:`reaper.analysis`), the scenario
orchestration (:mod:`reaper.runner`), SOCKS5 proxy support, auto-calibrated
group delay (:mod:`reaper.autodelay`), the pre-attack detect command
(:mod:`reaper.detect`), and the multi-endpoint TOCTOU chain
(:mod:`reaper.chain`) are all implemented alongside the
findings/SARIF/HackerOne output surface.
"""

from __future__ import annotations

__version__ = "1.0.0"

from reaper.findings import CONFIDENCES, SEVERITIES, Finding

__all__ = ["Finding", "SEVERITIES", "CONFIDENCES", "__version__"]
