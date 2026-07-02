"""reaper command-line interface.

[Worker decision: argparse, not Click, matching the suite convention
(ferryman/enshroud) and the V0.1-CRITERIA.md shared block. Two scenario
subcommands map to the two v0.1 race modes:

- ``single`` -- single-endpoint limit-overrun: replay one request in N identical
  concurrent copies against one synchronized gate (V0.1-CRITERIA.md #3).
- ``group``  -- minimal multi-endpoint: a request-group file of heterogeneous
  requests sharing a session, with MANUAL per-request delays and one
  synchronized release (V0.1-CRITERIA.md #4).

``--transport`` auto-selects the burst transport: ``auto`` probes the target and
picks ``h2-single-packet`` (HTTP/2 / h2c) or falls back to
``h1-last-byte-sync`` (HTTP/1.1-only targets) -- V0.1-CRITERIA.md #1, #2.

This is the suite-baseline scaffold: ``--version`` and ``--help`` are fully
wired; the scenario handlers raise ``NotImplementedError`` until the v0.1 build
lands the engine (:mod:`reaper.engine`) and the baseline client
(:mod:`reaper.client`). Output would then render via :mod:`reaper.sarif` /
:mod:`reaper.reporting`, which are already implemented.]

Exit codes:
    0  informational (``--version``)
    2  usage / no scenario given (argparse default)
"""

from __future__ import annotations

import argparse
from typing import Sequence

from reaper import __version__
from reaper.engine import (
    TRANSPORT_AUTO,
    TRANSPORT_H1_LAST_BYTE_SYNC,
    TRANSPORT_H2_SINGLE_PACKET,
)

_TRANSPORTS = (
    TRANSPORT_AUTO,
    TRANSPORT_H2_SINGLE_PACKET,
    TRANSPORT_H1_LAST_BYTE_SYNC,
)
_FORMATS = ("json", "text", "h1md", "sarif")

_NOT_YET = "v0.1 build -- see V0.1-CRITERIA.md"


def _common_options() -> argparse.ArgumentParser:
    """Options shared by every scenario subcommand."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--target",
        required=True,
        metavar="URL",
        help="target URL / host the race is fired against (must be in scope)",
    )
    common.add_argument(
        "--scope-file",
        metavar="PATH",
        dest="scope_file",
        help="scope file (one host/CIDR per line); enforced before any burst",
    )
    common.add_argument(
        "--transport",
        choices=_TRANSPORTS,
        default=TRANSPORT_AUTO,
        help=(
            "burst transport (default: auto -- probe the target and pick "
            "h2-single-packet, else fall back to h1-last-byte-sync)"
        ),
    )
    common.add_argument(
        "--format",
        choices=_FORMATS,
        default="json",
        dest="output_format",
        help="finding output format (default: json)",
    )
    return common


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reaper",
        description=(
            "Headless HTTP/2 single-packet race-condition detector. Benchmarks a "
            "sequential baseline, fires a synchronized concurrent burst, and "
            "reports confirmed limit-overrun / sub-state races."
        ),
        epilog="Authorized testing only. See the Ethical Use notice in the README.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"reaper {__version__}",
    )

    common = _common_options()
    sub = parser.add_subparsers(dest="scenario", metavar="SCENARIO")

    p_single = sub.add_parser(
        "single",
        parents=[common],
        help="single-endpoint limit-overrun: N identical concurrent copies",
        description=(
            "Replay one request in N identical concurrent copies against a "
            "single synchronized gate (over-redeem coupon, over-withdraw "
            "balance). V0.1-CRITERIA.md #3."
        ),
    )
    p_single.add_argument(
        "--request",
        required=True,
        metavar="REQFILE",
        help="raw HTTP request file to replay",
    )
    p_single.add_argument(
        "--copies",
        required=True,
        type=int,
        metavar="N",
        help="number of identical concurrent copies to race (20-30 typical)",
    )
    p_single.set_defaults(handler=_run_single)

    p_group = sub.add_parser(
        "group",
        parents=[common],
        help="minimal multi-endpoint: a request-group file with manual delays",
        description=(
            "Race a heterogeneous request group (different methods/paths/bodies) "
            "sharing a session, with MANUAL per-request delays and one "
            "synchronized release (MFA/OTP + email-confirm sub-state races). "
            "V0.1-CRITERIA.md #4."
        ),
    )
    p_group.add_argument(
        "--group-file",
        required=True,
        metavar="GROUPFILE",
        dest="group_file",
        help="request-group file: heterogeneous requests + manual per-request delays",
    )
    p_group.set_defaults(handler=_run_group)

    return parser


def _run_single(args: argparse.Namespace) -> int:
    # V0.1-CRITERIA.md #3 + #5: warm, arm N copies, single-flush, then diff the
    # sequential baseline against the burst and emit confirmed findings.
    raise NotImplementedError(_NOT_YET)


def _run_group(args: argparse.Namespace) -> int:
    # V0.1-CRITERIA.md #4 + #5: manual-delay heterogeneous group, one release,
    # then baseline-vs-burst deviation confirmation.
    raise NotImplementedError(_NOT_YET)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    handler = getattr(args, "handler", None)
    if handler is None:
        # No scenario given: print help and signal a usage error.
        parser.print_help()
        return 2
    return handler(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
