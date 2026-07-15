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

Each handler orchestrates (via :mod:`reaper.runner`): scope-check + transport
probe, an opt-in sequential baseline through the ``scan-primitives`` client
(:mod:`reaper.client`), the synchronized burst through the raw engine
(:mod:`reaper.engine`), then deviation confirmation (:mod:`reaper.analysis`)
rendered via :mod:`reaper.sarif` / :mod:`reaper.reporting`.]

Exit codes:
    0  ran cleanly, no confirmed race
    1  ran cleanly, at least one confirmed race emitted
    2  usage / no scenario given (argparse default)
    3  runtime error (out-of-scope / transport / IO)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from reaper import __version__
from reaper.engine import (
    TRANSPORT_AUTO,
    TRANSPORT_H1_LAST_BYTE_SYNC,
    TRANSPORT_H2_SINGLE_PACKET,
    TransportError,
)

_TRANSPORTS = (
    TRANSPORT_AUTO,
    TRANSPORT_H2_SINGLE_PACKET,
    TRANSPORT_H1_LAST_BYTE_SYNC,
)
_FORMATS = ("json", "text", "h1md", "sarif")

# Exit codes beyond argparse's usage-error 2.
_EXIT_OK = 0  # ran cleanly, no confirmed race
_EXIT_FINDING = 1  # ran cleanly, at least one confirmed race emitted
_EXIT_RUNTIME = 3  # out-of-scope / transport / IO failure


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
    common.add_argument(
        "--baseline-samples",
        type=int,
        default=0,
        dest="baseline_samples",
        metavar="N",
        help=(
            "sequential baseline samples to send FIRST via scan-primitives "
            "(default: 0). Opt-in: on a single-use resource the baseline "
            "consumes the unit under test; the burst is the authoritative "
            "over-limit signal"
        ),
    )
    common.add_argument(
        "--proxy",
        default=None,
        metavar="URL",
        help=(
            "SOCKS5 proxy URL (e.g. socks5://127.0.0.1:1080) to route ALL "
            "traffic through — baseline requests AND the raw H2/H1 burst. "
            "Useful for routing bursts through Caido/Burp or internal proxies."
        ),
    )
    common.add_argument(
        "--rate-limit",
        type=float,
        default=None,
        dest="rate_limit",
        metavar="RPS",
        help="baseline requests/second (scan-primitives token bucket)",
    )
    common.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="per-socket / per-request timeout in seconds (default: 10)",
    )
    common.add_argument(
        "--insecure",
        action="store_true",
        help="skip TLS certificate verification (https targets only)",
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


def _load_scope(args: argparse.Namespace):
    """Build the authorized scope: the --scope-file, else just the target host.

    Falling back to a scope of exactly the target host keeps the tool usable
    without a scope file while still forbidding egress to any other host -- the
    conservative default for a synchronized burst.
    """
    from reaper.httpspec import split_target
    from scan_primitives import Scope, load_scope

    if args.scope_file:
        return load_scope(args.scope_file)
    _scheme, host, _port, _authority = split_target(args.target)
    return Scope.from_entries([host])


def _emit(result, output_format: str) -> None:
    """Render a ScenarioResult to stdout in the requested format."""
    from reaper.reporting import to_h1md
    from reaper.sarif import to_sarif

    findings = result.findings
    if output_format == "json":
        print(json.dumps([f.to_dict() for f in findings], indent=2, default=str))
    elif output_format == "sarif":
        print(json.dumps(to_sarif(findings), indent=2, default=str))
    elif output_format == "h1md":
        print(to_h1md(findings) if findings else "_No confirmed race findings._")
    else:  # text
        a = result.analysis
        print(f"transport: {result.transport}")
        if a is not None:
            print(
                f"baseline successes: {a.baseline_summary['success_count']} "
                f"| burst successes: {a.burst_success_count} "
                f"| expected limit: {a.expected_max_successes}"
            )
            print(f"timing: {a.timing}")
            print(f"result: {a.reason}")
        print(f"confirmed findings: {len(findings)}")
        for f in findings:
            print(f"  - [{f.severity}/{f.confidence}] {f.title} ({f.vector})")


def _run_single(args: argparse.Namespace) -> int:
    # V0.1-CRITERIA.md #3 + #5: (opt-in) sequential baseline, arm N copies,
    # single-flush burst, then diff baseline vs burst and emit confirmed findings.
    from reaper.httpspec import parse_request_file, split_target
    from reaper.runner import run_single_scenario
    from scan_primitives import OutOfScopeError

    try:
        scope = _load_scope(args)
        _scheme, _host, _port, authority = split_target(args.target)
        raw = Path(args.request).read_bytes()
        request = parse_request_file(raw, default_authority=authority)
        result = run_single_scenario(
            target=args.target,
            scope=scope,
            request=request,
            copies=args.copies,
            transport=args.transport,
            baseline_samples=args.baseline_samples,
            rate_limit=args.rate_limit,
            proxy=getattr(args, "proxy", None),
            timeout=args.timeout,
            verify_tls=not args.insecure,
        )
    except OutOfScopeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return _EXIT_RUNTIME
    except (TransportError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return _EXIT_RUNTIME

    _emit(result, args.output_format)
    return _EXIT_FINDING if result.findings else _EXIT_OK


def _run_group(args: argparse.Namespace) -> int:
    # V0.1-CRITERIA.md #4 + #5: manual-delay heterogeneous group, one release,
    # then burst deviation confirmation.
    from reaper.httpspec import parse_group_file, split_target
    from reaper.runner import run_group_scenario
    from scan_primitives import OutOfScopeError

    try:
        scope = _load_scope(args)
        _scheme, _host, _port, authority = split_target(args.target)
        raw = Path(args.group_file).read_bytes()
        group = parse_group_file(raw, default_authority=authority)
        result = run_group_scenario(
            target=args.target,
            scope=scope,
            group=group,
            transport=args.transport,
            proxy=getattr(args, "proxy", None),
            timeout=args.timeout,
            verify_tls=not args.insecure,
        )
    except OutOfScopeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return _EXIT_RUNTIME
    except (TransportError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return _EXIT_RUNTIME

    _emit(result, args.output_format)
    return _EXIT_FINDING if result.findings else _EXIT_OK


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
