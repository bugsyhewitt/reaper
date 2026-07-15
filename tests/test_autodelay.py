"""Unit tests for auto-delay calibration (no network required).

Tests the pure-math ``auto_delays`` function and the CLI argument plumbing
for ``--auto-delay`` / ``--auto-delay-samples``.  ``measure_rtt`` wraps
``BaselineClient`` and requires a live server; it is covered by
``test_race_lab.py`` (``-m integration``).
"""

from __future__ import annotations

import pytest

from reaper.autodelay import auto_delays


# ---------------------------------------------------------------------------
# auto_delays — pure math
# ---------------------------------------------------------------------------


def test_auto_delays_first_is_always_zero():
    for count in range(1, 10):
        delays = auto_delays(0.5, count)
        assert delays[0] == 0.0, f"first delay should be 0 for count={count}"


def test_auto_delays_distributes_evenly():
    rtt = 1.0
    count = 4
    delays = auto_delays(rtt, count)
    assert len(delays) == count
    step = rtt / count
    for i, d in enumerate(delays):
        assert abs(d - round(i * step, 9)) < 1e-12, (
            f"delay[{i}] expected {i * step:.9f}, got {d:.9f}"
        )


def test_auto_delays_two_requests_half_rtt():
    delays = auto_delays(0.2, 2)
    assert len(delays) == 2
    assert delays[0] == 0.0
    assert abs(delays[1] - 0.1) < 1e-9


def test_auto_delays_single_request_is_zero():
    delays = auto_delays(0.5, 1)
    assert delays == [0.0]


def test_auto_delays_all_within_one_rtt_window():
    rtt = 0.3
    count = 7
    delays = auto_delays(rtt, count)
    assert len(delays) == count
    # Last delay is (count-1) / count * rtt, which is strictly less than rtt.
    assert delays[-1] < rtt


def test_auto_delays_length_matches_count():
    for count in (2, 5, 10, 20, 30):
        delays = auto_delays(0.1, count)
        assert len(delays) == count


def test_auto_delays_returns_ascending_sequence():
    delays = auto_delays(0.5, 8)
    for a, b in zip(delays, delays[1:]):
        assert b > a, "delays must be strictly increasing"


def test_auto_delays_rejects_zero_count():
    with pytest.raises(ValueError):
        auto_delays(0.1, 0)


def test_auto_delays_rejects_negative_count():
    with pytest.raises(ValueError):
        auto_delays(0.1, -3)


def test_auto_delays_tiny_rtt():
    delays = auto_delays(0.001, 20)
    assert len(delays) == 20
    assert delays[0] == 0.0
    assert delays[-1] < 0.001


def test_auto_delays_large_rtt():
    # 5-second RTT (very slow server), 3-request group.
    delays = auto_delays(5.0, 3)
    assert len(delays) == 3
    assert abs(delays[1] - 5.0 / 3) < 1e-9
    assert abs(delays[2] - 10.0 / 3) < 1e-9


# ---------------------------------------------------------------------------
# CLI argument plumbing
# ---------------------------------------------------------------------------


def test_cli_group_auto_delay_defaults_false():
    from reaper.cli import build_parser

    parser = build_parser()
    args = parser.parse_args([
        "group",
        "--target", "http://x.example",
        "--group-file", "g.group",
    ])
    assert args.auto_delay is False
    assert args.auto_delay_samples == 3


def test_cli_group_auto_delay_flag_sets_true():
    from reaper.cli import build_parser

    parser = build_parser()
    args = parser.parse_args([
        "group",
        "--target", "http://x.example",
        "--group-file", "g.group",
        "--auto-delay",
    ])
    assert args.auto_delay is True
    assert args.auto_delay_samples == 3


def test_cli_group_auto_delay_samples_override():
    from reaper.cli import build_parser

    parser = build_parser()
    args = parser.parse_args([
        "group",
        "--target", "http://x.example",
        "--group-file", "g.group",
        "--auto-delay",
        "--auto-delay-samples", "5",
    ])
    assert args.auto_delay is True
    assert args.auto_delay_samples == 5


def test_cli_single_has_no_auto_delay():
    """The single subcommand must not expose --auto-delay (group-only feature)."""
    from reaper.cli import build_parser

    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([
            "single",
            "--target", "http://x.example/r",
            "--request", "r.http",
            "--copies", "20",
            "--auto-delay",
        ])


# ---------------------------------------------------------------------------
# run_group_scenario: auto_delay wires through (runner-level, no network)
# ---------------------------------------------------------------------------


def test_run_group_scenario_auto_delay_replaces_manual_delays(monkeypatch):
    """When auto_delay=True, computed delays override the @delay values from
    the group file. Verified by monkeypatching measure_rtt to return a
    known RTT and asserting the engine sees the computed delays."""
    from reaper.httpspec import RaceRequest

    captured: list[list[float]] = []

    def fake_measure_rtt(target, scope, **kw):
        return 0.6  # 0.6s RTT → delays for 3 requests: [0, 0.2, 0.4]

    def fake_run_group(self, group):
        captured.append([r.delay for r in group])
        raise RuntimeError("stop here — not testing burst")  # short-circuit

    monkeypatch.setattr("reaper.autodelay.measure_rtt", fake_measure_rtt)
    monkeypatch.setattr(
        "reaper.engine.SinglePacketEngine.run_group", fake_run_group
    )

    from reaper.engine import TransportError

    group = [
        RaceRequest(method="POST", path="/email/change", body=b"x", delay=0.0),
        RaceRequest(method="POST", path="/email/confirm", body=b"y", delay=99.0),
        RaceRequest(method="POST", path="/email/verify", body=b"z", delay=99.0),
    ]

    # Need to stub transport selection too so it picks H2 without a real server.
    monkeypatch.setattr(
        "reaper.runner.select_transport",
        lambda *a, **kw: "h2-single-packet",
    )

    from reaper.runner import run_group_scenario
    from scan_primitives import Scope

    scope = Scope.from_entries(["x.example"])

    with pytest.raises(RuntimeError, match="stop here"):
        run_group_scenario(
            target="http://x.example",
            scope=scope,
            group=group,
            auto_delay=True,
            auto_delay_samples=3,
        )

    assert captured, "engine.run_group was never called"
    computed = captured[0]
    assert len(computed) == 3
    assert computed[0] == 0.0
    assert abs(computed[1] - 0.2) < 1e-6  # 0.6 / 3 = 0.2
    assert abs(computed[2] - 0.4) < 1e-6  # 2 * 0.6 / 3 = 0.4
    # Original @delay values (99.0) must be overridden.
    assert 99.0 not in computed
