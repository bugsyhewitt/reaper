# Worker output — reaper maturity lap (p2council-r2)

## Summary

Shipped docs+tests maturity improvement for `reaper` v1.0.0. No feature changes.

## Files changed

### README.md
- Fixed stale `"version": "0.1.0"` in SARIF example → `"1.0.0"`
- Added **Output format examples** section with representative output for `text`, `h1md`, `json`, and `sarif` formats (only `sarif` was shown before)
- Added **Worked walkthroughs** section with real invocation → representative output for all three subcommands (`detect`, `single`, `group`)
- Added **Exit codes** table documenting `0`, `1`, `2`, `3`
- Added **Troubleshooting / FAQ** section covering:
  - "server closes connection before last byte" / `TransportError: peer closed`
  - "H2 not supported" / auto-fallback to h1-last-byte-sync
  - "SOCKS5 timeout" / proxy connection refused
  - "no race window detected" / `concurrency: serialized` from `detect`
  - "out-of-scope" error before any burst
  - "reaper finds no race but Turbo Intruder does"

### tests/test_cli.py (new — 67 functions)
Dedicated test file for `cli.py` (581 lines, zero dedicated tests before).
- `TestBuildParser` (13 tests): arg parsing, defaults, required args, mutually-exclusive group, invalid choices
- `TestMainDispatch` (5 tests): subcommand dispatch wiring to runner/detect, exit-code contract
- `TestErrorHandling` (6 tests): OutOfScopeError, TransportError, OSError, state-chain too-few-files
- `TestEmit` (7 tests): all four output formats (json, text, h1md, sarif), no-findings paths

### tests/test_runner.py (new — 22 functions)
Dedicated test file for `runner.py` (405 lines, only indirect coverage before).
- `TestRunSingleScenario` (11 tests): engine selection, scope enforcement, finding/no-finding, auto-fallback H2→H1, baseline samples, transport error re-raise
- `TestRunGroupScenario` (4 tests): H2 requirement, scope, auto-delay integration, result shape
- `TestRunStateChainScenario` (6 tests): 2-endpoint minimum, H2 requirement, scope, differential detection, label fidelity

### tests/test_single_scenario.py (new — 16 functions)
Focused coverage of the single-endpoint attack path (previously zero dedicated tests).
- `TestSingleCleanServer` (2 tests): clean server yields no finding
- `TestSingleRaceConfirmed` (6 tests): finding shape, severity, target, vector, id, custom id
- `TestSingleFinalStateGuard` (1 test): final_state_success_count suppresses false positives
- `TestSingleResultStructure` (3 tests): burst/baseline/analysis fields on result
- `TestSingleViaCLI` (2 tests): full CLI→runner wiring for single subcommand

## Test results

182 passed, 15 deselected (integration + ship_gate) in 0.29s — see test-output.txt.

`ruff check src/` — clean. `ruff check tests/` — new files clean; pre-existing test files have historical ruff issues not in scope of this lap (CI only lints `src/`).
