"""v0.1 release ship-gate: build the wheel, install into a fresh venv, prove it works.

Skippable via `pytest -m "not ship_gate"`. Runs in the full v0.1 suite. Mirrors
ferryman's ship-gate: build -> fresh-venv install -> `reaper --version` ->
public-API import.

The live acceptance test -- "concurrent redemptions produce >1 success where
the sequential baseline produces exactly 1" against the Hypercorn race-lab --
is a marked skip below (the single-packet engine and the CI race-lab fixture are
NOT built this pass; see V0.1-CRITERIA.md).
"""

from __future__ import annotations

import subprocess
import sys
import venv
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


@pytest.mark.ship_gate
def test_wheel_builds_cleanly(tmp_path):
    """`python -m build --wheel --sdist` produces both artifacts with no error."""
    out = tmp_path / "build-out"
    _run(
        [sys.executable, "-m", "build", "--wheel", "--sdist", "--outdir", str(out)],
        cwd=REPO_ROOT,
    )
    wheels = list(out.glob("reaper-0.1.0-*.whl"))
    sdists = list(out.glob("reaper-0.1.0.tar.gz"))
    assert wheels, f"wheel not built; got: {list(out.iterdir())}"
    assert sdists, f"sdist not built; got: {list(out.iterdir())}"
    test_wheel_builds_cleanly._wheel = wheels[0]


@pytest.mark.ship_gate
def test_wheel_installs_into_fresh_venv(tmp_path):
    """`pip install <wheel>` into a brand-new venv resolves the entry-point."""
    wheel = getattr(test_wheel_builds_cleanly, "_wheel", None)
    if wheel is None:
        pytest.skip("preceding build test did not produce a wheel")

    venv_dir = tmp_path / "fresh-venv"
    venv.create(venv_dir, with_pip=True, clear=True)
    pip = venv_dir / "bin" / "pip"

    # Install wheel; pip resolves declared runtime deps (httpx, h1-reporter, h2).
    _run([str(pip), "install", "--quiet", str(wheel)])

    cli = venv_dir / "bin" / "reaper"
    version_out = _run([str(cli), "--version"]).stdout.strip()
    assert version_out == "reaper 0.1.0", f"unexpected --version output: {version_out!r}"

    test_wheel_installs_into_fresh_venv._venv_dir = venv_dir


@pytest.mark.ship_gate
def test_wheel_version_importable_in_fresh_venv(tmp_path):
    """`import reaper; reaper.__version__` == '0.1.0' inside the fresh venv."""
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding install test did not build a venv")

    py = venv_dir / "bin" / "python"
    _run([str(py), "-c", "import reaper; assert reaper.__version__ == '0.1.0'"])


@pytest.mark.ship_gate
def test_installed_wheel_public_api(tmp_path):
    """The installed wheel exposes the full public API surface (incl. stubs)."""
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding install test did not build a venv")

    py = venv_dir / "bin" / "python"
    check_script = (
        "import reaper.cli, reaper.findings, reaper.sarif, reaper.reporting, "
        "reaper.engine, reaper.client; "
        "from reaper.findings import Finding; "
        "from reaper.sarif import to_sarif; "
        "from reaper.reporting import to_h1, to_h1md"
    )
    _run([str(py), "-c", check_script])


@pytest.mark.ship_gate
@pytest.mark.integration
@pytest.mark.skip(
    reason="v0.1 build: single-packet engine + Hypercorn race-lab not built "
    "this pass -- see V0.1-CRITERIA.md (Testability)."
)
def test_race_lab_concurrent_beats_sequential():
    """ACCEPTANCE (v0.1): against the deliberately race-vulnerable Hypercorn lab,
    N sequential single-use-coupon redemptions yield exactly 1 success (control),
    while N concurrent redemptions via reaper yield >1 success (over-limit).

    TODO(v0.1): build the Hypercorn h2/h2c race-lab fixture (Fixtures A/B/C) and
    the single-packet engine, then implement this deterministic gate.
    """
    raise AssertionError("unreachable: skipped until the v0.1 engine + lab land")
