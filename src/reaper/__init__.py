"""reaper -- headless HTTP/2 single-packet race-condition detector.

reaper resurrects the dead ancestor ``race-the-web`` (HTTP/1.1 threaded racing,
pre-single-packet era) with the modern single-packet attack technique (James
Kettle, DEF CON 31): multiplex N requests on one HTTP/2 connection, withhold
each request's final frame, then release all withheld frames in a single
synchronized TCP flush so they land in one packet -- eliminating network jitter
and opening a true atomic race window. It benchmarks a sequential baseline,
fires the concurrent burst, and flags statistical deviations (status / body /
timing / second-order) as findings.

This package is the suite-baseline scaffold. The findings/SARIF/HackerOne output
surface is fully implemented; the low-level single-packet engine and the shared
auth/baseline client are stubs pending the v0.1 build (see ``V0.1-CRITERIA.md``).
"""

from __future__ import annotations

__version__ = "0.1.0"

from reaper.findings import CONFIDENCES, SEVERITIES, Finding

__all__ = ["Finding", "SEVERITIES", "CONFIDENCES", "__version__"]
