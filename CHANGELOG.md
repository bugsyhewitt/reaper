# Changelog

All notable changes to reaper are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions use [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added
- GitHub Actions CI workflow (`pytest -m "not integration"`) on push and pull request.

### Changed
- Quality sweep: removed dead code, duplicate imports, and redundant helper paths.
- README header: added comic-card image.

---

## [1.0.0] — 2026-07-15

### Added
- Stable release marker. All v0.1–v0.5 milestones complete; engine API frozen.

### Changed
- Version bumped to 1.0.0 in `pyproject.toml`.

---

## [0.5.0] — 2026-07-14

### Added
- **`reaper group --state-chain file1,file2,...`** — multi-endpoint TOCTOU chain. Fires one request per endpoint simultaneously on a single HTTP/2 connection (one synchronized `send()` call). Per-endpoint timing spread and differential-response detection flag TOCTOU races across separate endpoints sharing a resource (e.g. `/transfer` + `/balance-check`). Completes the minimal multi-endpoint mode outlined in v0.1 criteria item 4 with full auto-calibration support.

---

## [0.4.0] — 2026-07-14

### Added
- **`reaper detect`** — pre-attack recon command. Probes the target for HTTP/2 vs HTTP/1.1 support, fires a non-destructive probe burst (`GET /`) with the detected transport, and reports the race-window spread, a concurrency hint (`concurrent` / `serialized`), and a recommended attack invocation.

---

## [0.3.0] — 2026-07-14

### Added
- **Auto-calibrated group delay** (`--auto-delay` / `--auto-delay-samples`). Measures baseline RTT with warm-up requests and computes `delay[i] = i * rtt / N` (Kettle client-side timing), removing guesswork from `@delay` tuning for MFA/OTP and email-confirm sub-state races.

---

## [0.2.0] — 2026-07-14

### Added
- **SOCKS5 proxy support** (`--proxy socks5://host:port`). Both the sequential baseline engine and the raw H2 burst engine route through the tunnel.

---

## [0.1.0] — 2026-07-02

### Added
- **HTTP/2 single-packet attack engine** (`hyper-h2` + raw `socket`/`ssl`, no scapy, no root). Multiplexes N requests on one H2 connection, withholds each request's final frame, then releases all withheld frames in a single TCP flush. `TCP_NODELAY` control and optional PING warm-up. Supports h2c cleartext. Targets 20–30 concurrent requests.
- **HTTP/1.1 last-byte-sync fallback** with connection warming. Auto-selected when the target refuses concurrent H2 streams; withholds the final byte per request and flushes them together.
- **Single-endpoint limit-overrun scenario** (N identical requests, one synchronized gate) — the 80% case (coupon, balance, OTP).
- **Minimal multi-endpoint mode** — heterogeneous request group (different methods/paths/bodies) sharing a session/auth context with manual per-request `@delay` ordering.
- **Benchmark + statistical deviation confirmation** — sequential baseline (status codes, body hash, timing) followed by concurrent burst; deviations flagged with an evidence report (baseline-vs-burst diff, anomalous response count, timing distribution, reproducibility indicator).
- **False-positive guard** for early race wins later overwritten.
- **Findings output** in the suite `Finding` schema (`cwe_id=362`), SARIF 2.1.0, and HackerOne markdown via `h1-reporter`.
- **CI race-lab fixtures**: single-use coupon (`POST /redeem`), wallet overdraw, and multi-endpoint sub-state; served over HTTP/2 via Hypercorn and HTTP/1.1 for the last-byte-sync path. Deterministic gate: N sequential redemptions yield exactly 1 success; N concurrent redemptions via reaper yield >1.
- Suite `ship_gate` wheel smoke test.
- MIT LICENSE.

[Unreleased]: https://github.com/bugsyhewitt/reaper/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/bugsyhewitt/reaper/releases/tag/v1.0.0
[0.5.0]: https://github.com/bugsyhewitt/reaper/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/bugsyhewitt/reaper/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/bugsyhewitt/reaper/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/bugsyhewitt/reaper/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/bugsyhewitt/reaper/releases/tag/v0.1.0
