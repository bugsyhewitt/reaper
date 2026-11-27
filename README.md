# reaper

<p align="center">
  <img src="https://raw.githubusercontent.com/bugsyhewitt/bugsyhewitt.github.io/main/public/cards/reaper.jpg" alt="reaper" width="680">
</p>

Headless **HTTP/2 single-packet** race-condition detector for authorized
bug-bounty and penetration testing.

reaper resurrects the dead ancestor [`race-the-web`](https://github.com/aaronhnatiw/race-the-web)
(HTTP/1.1 threaded racing, pre-single-packet era) and brings the modern
**single-packet attack** (James Kettle, DEF CON 31 — *Smashing the State
Machine*) to a headless Python 3 CLI. It multiplexes N requests on one HTTP/2
connection, **withholds each request's final frame**, then releases all withheld
frames in a **single synchronized TCP flush** so they land in one packet —
eliminating network jitter and opening a true atomic race window. It benchmarks
a sequential baseline, fires the concurrent burst, and flags statistical
deviations (status / body-hash / timing / second-order) as findings.

Where PortSwigger's Turbo Intruder is Burp/Jython-locked, reaper is a standalone
CLI. Findings come out in the suite finding schema, **SARIF 2.1.0**, and
HackerOne markdown (via `h1-reporter`).

> **Status:** v1.0.0. The core engine is complete and stable across six
> shipped milestones:
> - v0.1 — HTTP/2 single-packet engine, HTTP/1.1 last-byte-sync fallback,
>   scan-primitives baseline client, statistical deviation confirmation, SARIF
>   2.1.0 + HackerOne output, CI race-lab
> - v0.2 — SOCKS5 proxy support (`--proxy socks5://host:port`)
> - v0.3 — Auto-calibrated group delay (`--auto-delay`, Kettle RTT timing)
> - v0.4 — `reaper detect` pre-attack recon (transport probe + race-window
>   estimation)
> - v0.5 — `reaper group --state-chain` multi-endpoint TOCTOU chain
> - v1.0.0 — stable release; all v0.1 criteria met, no known open gaps

## Architecture

reaper is built as six cooperating modules behind a single CLI entry-point. Each
module has a narrow responsibility; nothing leaks across the boundary.

### Module map

```
reaper/
├── cli.py        — argparse entry-point; routes to _run_single, _run_group, _run_detect
├── runner.py     — scenario orchestration: scope → transport → baseline → burst → analysis
├── engine.py     — raw H2/H1 burst transport (SinglePacketEngine, LastByteSyncEngine)
├── client.py     — scan-primitives BaselineClient wrapper (sequential baseline)
├── detect.py     — pre-attack recon: transport probe + race-window estimation
├── autodelay.py  — Kettle RTT-based per-request delay calibration
├── chain.py      — state-chain TOCTOU analysis (v0.5)
├── analysis.py   — baseline-vs-burst deviation confirmation + Finding builder
├── httpspec.py   — data model (RaceRequest, ResponseSignature) + raw-HTTP parsers
├── findings.py   — Finding schema (CWE-362, severity, evidence)
├── sarif.py      — SARIF 2.1.0 output adapter
└── reporting.py  — HackerOne markdown output adapter
```

### H2 burst engine (`engine.py`)

`SinglePacketEngine` implements the HTTP/2 single-packet attack:

1. **Connect**: open one TCP connection; for `https://` targets, negotiate H2 via
   ALPN (`h2`). For `http://` cleartext targets, send an H2 prior-knowledge
   preface (`PRI * HTTP/2.0`) directly — no HTTP Upgrade roundtrip.
2. **Arm** (`_arm`): open one H2 stream per request via `h2.send_headers()`. For
   each stream, send all body bytes except the last one (or queue an empty DATA
   frame for bodyless requests). Every stream is parked one frame short of
   complete — the server cannot process them until it receives `END_STREAM`.
3. **Settle**: wait ~100ms with `TCP_NODELAY` enabled. This lets TCP buffers
   flush all the priming data to the server so the final frames are the only
   thing left to send.
4. **Fire** (`_fire`): disable `TCP_NODELAY` (Nagle enabled) and send **all**
   withheld final frames in a single `send()` call. Nagle and the single
   `send()` together ensure the kernel emits one TCP packet carrying every
   stream's `END_STREAM` flag. The server dequeues all N requests in one
   read — this is the race window.
5. **Collect** (`_collect`): read all N responses; return one `ResponseSignature`
   per stream (status, body-SHA256, body length, elapsed ms from fire timestamp).

`LastByteSyncEngine` provides the HTTP/1.1 fallback: N TCP connections opened in
parallel, each warmed with a benign `GET /` to clear TCP slow-start, then one
final byte withheld per connection. All final bytes are released in a tight loop.
Synchronization is weaker than H2 single-packet (network jitter between
per-connection sends), but it still creates a race window on a correctly
instrumented target.

### Transport auto-selection

`select_transport` in `engine.py` probes the target before the burst:

- For `https://` targets: open a TLS connection with ALPN `["h2", "http/1.1"]` and
  check `selected_alpn_protocol()`. H2 negotiated → `h2-single-packet`; H1 → `h1-last-byte-sync`.
- For `http://` targets: send the H2 prior-knowledge preface and check whether the
  server responds with an H2 `SETTINGS` frame. Yes → `h2-single-packet`; No or
  error → `h1-last-byte-sync`.
- Any `OSError` during probing falls back to `h1-last-byte-sync` silently.

When `--proxy` is set, the probe routes through the SOCKS5 tunnel first so the
transport decision reflects what is reachable through the proxy.

### Auto-calibrated delay (`autodelay.py`)

The `measure_rtt` function sends `--auto-delay-samples` benign `GET /` requests
through the scan-primitives `BaselineClient` and returns the mean elapsed time
in seconds. Only elapsed_ms is kept; response bodies are discarded (R5).

`auto_delays(rtt, count)` applies Kettle's client-side timing heuristic:

```
delay[i] = i * rtt / count    for i in 0 .. count-1
```

This distributes `count` group requests evenly across one RTT window so they all
arrive at the server within the same processing cycle. `delay[0]` is always
`0.0`; `delay[count-1]` is `(count-1) * rtt / count`, strictly less than one RTT.
The delays override any `@delay` values in the group file.

### Pre-attack recon (`detect.py`)

`run_detect` ties together transport selection and a small non-destructive probe
burst into a `DetectResult`. Key outputs:

- `transport` — which burst engine will be used (`h2-single-packet` or `h1-last-byte-sync`).
- `window` — a `WindowStats` with min / median / max / spread / stdev of the probe
  response times (in ms). This is a client-side estimate of the server's race
  window width; a tight spread (<50ms threshold) suggests the server processes
  concurrent requests in parallel.
- `concurrency_hint` — `"concurrent"` when `spread < 50ms`, `"serialized"` when
  the spread is wide (server likely serializes). A serialized hint means a race
  window may be narrow but doesn't rule out a finding.
- `recommendation` — a copy-paste ready attack invocation.

The probe fires benign `GET /` requests — it does not touch the target endpoint
under test and does not consume any single-use resource.

### State-chain TOCTOU (`chain.py`)

`analyze_chain` takes the per-endpoint results of a `reaper group --state-chain`
burst and reports:

- `spread_ms` — response-time spread across all chain endpoints (a proxy for
  client-side co-arrival). A tight spread suggests all requests landed at the
  server in one processing window.
- `within_window` — `spread_ms <= window_ms` (default 10ms).
- `differential_found` — any endpoint returned an HTTP status different from the
  expected (default 200).

A `differential_found=True` with a tight spread is the signal for a TOCTOU race:
one endpoint's read of shared state saw an inconsistency because another endpoint
was writing at the same time. `build_chain_finding` turns this into a CWE-362
`Finding`.

### Scenario orchestration (`runner.py`)

`run_single_scenario` and `run_group_scenario` wire the pieces in order:

1. Assert the target is in scope (`scan_primitives.Scope.assert_in_scope`).
2. Select the transport (`select_transport`), or use the caller's `--transport`.
3. If `baseline_samples > 0`: run the sequential baseline through
   `BaselineClient` to establish the expected success count.
4. Build and fire the burst through `SinglePacketEngine` or `LastByteSyncEngine`.
5. Pass the baseline and burst signatures to `confirm_race` (analysis module).
6. If `is_race=True`, build a `Finding` via `build_finding` and return a
   `ScenarioResult` with transport, signatures, analysis, and findings.

## Ethical Use

You are responsible for ensuring you have authorization to test any target.
Only race systems you own or have explicit written permission to test. A
synchronized concurrent burst is inherently higher-impact on a target than a
normal scan — respect the program's scope and rate posture. Use of this tool
against unauthorized targets may violate computer-fraud laws. The authors accept
no liability for misuse.

## Install

Requires Python 3.13+.

```bash
git clone https://github.com/bugsyhewitt/reaper
cd reaper
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Scope file format

A plain-text file, one entry per line. Entries can be:

- Hostnames: `api.example.com`
- IP addresses: `10.0.0.1`
- CIDR blocks: `192.168.1.0/24`

Lines starting with `#` are ignored. Scope is enforced (via `scan-primitives`)
**before any burst** — egress to an out-of-scope host raises rather than sends.

```
# Production targets
shop.example.com
10.20.30.0/24
```

## Usage

reaper exposes a recon command (`detect`) and two race scenario subcommands
(`single`, `group`). All take a `--target` and an optional `--scope-file`.

**Pre-attack recon** — detect the target's transport and estimate the race
window width before committing to a full attack:

```bash
reaper detect --target https://shop.example.com/redeem --scope-file scope.txt
```

Prints detected transport (`h2-single-packet` or `h1-last-byte-sync`), the
estimated race window spread, a concurrency hint (`concurrent` / `serialized`),
and a recommended attack invocation. Pass `--format json` to get machine-readable
output. A serialized hint means the server is likely processing concurrent
requests sequentially — the race window may be narrow.

**Single-endpoint limit-overrun** — replay one request in N identical concurrent
copies against a single synchronized gate (the 80% case: over-redeem a coupon,
over-withdraw a balance):

```bash
reaper single --target https://shop.example.com/redeem \
  --request redeem.http --copies 20 --scope-file scope.txt
```

**Minimal multi-endpoint** — race a heterogeneous request group (different
methods / paths / bodies) sharing a session, with per-request delays and one
synchronized release (MFA/OTP and email-confirm sub-state races):

```bash
# Auto-calibrated delays (recommended): reaper measures RTT and computes
# optimal inter-request spacing automatically.
reaper group --target https://app.example.com \
  --group-file scenario.group --scope-file scope.txt --auto-delay

# Manual delays: @delay directives in the group file control release offsets.
reaper group --target https://app.example.com \
  --group-file scenario.group --scope-file scope.txt
```

The group file is a sequence of raw HTTP requests separated by a line that is
exactly `%%%`; each block may be preceded by an `@delay <seconds>` directive
setting that request's **manual** release offset within the synchronized window.
With `--auto-delay`, the `@delay` values are overridden by the auto-computed
delays.

**Methodology.** reaper's authoritative over-limit signal is the concurrent
burst itself: a correctly synchronized server yields exactly **one** success even
under a synchronized burst, so *more* successes than the resource's limit is the
race. A sequential baseline (`--baseline-samples N`) is **opt-in** — on a
single-use resource it consumes the very unit under test — and, when supplied,
runs first to establish the expected limit and the deviation reference. reaper
guards the **final-state false positive**: a surplus success that a later request
overwrites is not reported as confirmed. Exit code is `1` when a race is
confirmed, `0` when none is, `3` on an out-of-scope / transport / IO error.

### SOCKS5 proxy

`--proxy socks5://host:port` routes **all** traffic through a SOCKS5 proxy —
both the scan-primitives sequential baseline requests and the raw H2/H1 burst
sockets. This is useful when:

- The target is only reachable from an internal network (pivoting via a SOCKS5
  tunnel created by your C2 or SSH `-D`).
- You want to capture the synchronized burst through Caido or Burp for
  inspection (Burp → Proxy → SOCKS upstream; point reaper at Burp's SOCKS port).

```bash
reaper single --target http://internal.corp/api/redeem \
  --request redeem.http --copies 20 \
  --proxy socks5://127.0.0.1:1080
```

reaper uses the SOCKS5 no-auth method (RFC 1928) with a DOMAINNAME address type
so the proxy resolves the hostname — correct for targets only reachable via the
proxy network. The scope check runs **before** the proxy connection is opened,
so `OutOfScopeError` still fires without sending a byte to the proxy. Only
`socks5://` and `socks5h://` schemes are accepted; `http://` proxies are not
supported for the raw burst sockets (use `httpx[socks]` for baseline-only
routing if needed).

### Transport auto-selection

`--transport auto` (default) probes the target and picks the burst transport:

- `h2-single-packet` — HTTP/2 (or h2c cleartext) targets: withhold each
  request's final frame, release all in one flush.
- `h1-last-byte-sync` — HTTP/1.1-only targets (or targets that refuse enough
  concurrent H2 streams): one TCP connection per request, withhold the final
  byte, flush all final bytes together, with connection warming first.

Force one with `--transport h2-single-packet` or `--transport h1-last-byte-sync`.

## Commands

```
reaper --version
reaper detect --target URL
              [--scope-file PATH] [--probe-copies N]
              [--proxy socks5://HOST:PORT] [--timeout S] [--insecure]
              [--format {text,json}]
reaper single --target URL --request REQFILE --copies N
              [--transport {auto,h2-single-packet,h1-last-byte-sync}]
              [--scope-file PATH] [--format {json,text,h1md,sarif}]
              [--baseline-samples N] [--rate-limit RPS]
              [--proxy socks5://HOST:PORT] [--timeout S] [--insecure]
reaper group  --target URL --group-file GROUPFILE
              [--transport {auto,h2-single-packet,h1-last-byte-sync}]
              [--scope-file PATH] [--format {json,text,h1md,sarif}]
              [--proxy socks5://HOST:PORT] [--timeout S] [--insecure]
              [--auto-delay] [--auto-delay-samples N]
```

- `--target` — the URL / host the race is fired against (must be in scope).
- `--request` — raw HTTP request file to replay (single-endpoint scenario).
- `--copies` — number of identical concurrent copies to race (20–30 typical).
- `--group-file` — request-group file: heterogeneous requests + per-request delays.
- `--transport` — burst transport (default `auto`).
- `--scope-file` — scope file (one host/CIDR per line); enforced before any burst.
  With no `--scope-file`, scope defaults to exactly the target host.
- `--format` — finding output: `json` (default), `text`, `h1md`, or `sarif`.
- `--baseline-samples` — sequential baseline samples to send first (default `0`,
  opt-in; see Methodology above).
- `--proxy` — SOCKS5 proxy URL (`socks5://host:port`) for all traffic (v0.2).
- `--rate-limit` — baseline requests/second (scan-primitives token bucket).
- `--timeout` — per-socket / per-request timeout in seconds (default `10`).
- `--insecure` — skip TLS certificate verification (`https` targets only).
- `--auto-delay` — *(group only, v0.3)* auto-calibrate per-request delays from
  measured RTT. Sends warm-up GET / requests to the target, computes
  `delay[i] = i * rtt / N`, and overrides any `@delay` values in the group
  file. Recommended for most sub-state race scenarios — removes the guesswork
  from manual delay tuning.
- `--auto-delay-samples N` — *(group only, v0.3)* number of warm-up requests
  to average for RTT measurement when `--auto-delay` is set (default `3`).
- `--probe-copies N` — *(detect only, v0.4)* number of concurrent `GET /`
  probes to fire for the window estimation burst (default `10`, range `2–30`).

## Example output

A confirmed single-packet race renders as a suite finding (CWE-362). In SARIF
2.1.0 (`--format sarif`) the same finding maps to:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemas/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { "name": "reaper", "version": "1.0.0", "rules": [ ... ] } },
      "results": [
        {
          "ruleId": "reaper/single-packet",
          "level": "error",
          "rank": 80.0,
          "message": { "text": "Coupon redeemed 3x via single-packet race" },
          "locations": [ { "physicalLocation": { "artifactLocation": { "uri": "https://shop.example.com/redeem" } } } ],
          "partialFingerprints": { "reaperFindingId": "reaper-0001" },
          "properties": { "severity": "high", "confidence": "high", "vector": "single-packet:/redeem", "cwe": "CWE-362" }
        }
      ]
    }
  ]
}
```

The `evidence` on each finding carries the **baseline-vs-burst diff**, the
**count of anomalous responses** (e.g. "2 of 20 returned 200 where the baseline
gave one 200 + rest 409"), and the burst **timing distribution**. Response bytes
are treated strictly as data (R5) — never evaluated, never LLM-judged.

## Development

```bash
pip install -e ".[dev]"
pytest -m "not ship_gate and not integration"   # fast unit tests
pytest -m integration                            # live Hypercorn race-lab
pytest -m ship_gate                              # build → fresh-venv install
```

The `integration` marker runs the live Hypercorn race-lab acceptance test:
against a deliberately race-vulnerable single-use-coupon app, N sequential
redemptions yield exactly **1** success (control) while N concurrent redemptions
via reaper's single-packet engine yield **>1** (over-limit). It skips cleanly if
`hypercorn` is not installed. The `ship_gate` marker runs the slow build →
fresh-venv install → `--version` → public-API gate.

## Output format examples

All four formats are available via `--format` on `single` and `group`. `detect` supports `text` and `json` only.

### `--format text`

```
transport: h2-single-packet
baseline successes: 1 | burst successes: 3 | expected limit: 1
timing: {'unit': 'ms', 'samples': 20, 'min': 12.4, 'max': 38.1, 'spread': 25.7, ...}
result: over-limit: burst produced 3 successes, expected at most 1
confirmed findings: 1
  - [high/high] Concurrent limit overrun on /redeem (single-packet:/redeem)
```

### `--format h1md`

Renders a HackerOne-ready markdown bug report via `h1-reporter`. Output is a formatted Markdown block with title, severity, vector, impact, and evidence code blocks — paste directly into a HackerOne submission or your note-taking tool.

```markdown
## Concurrent limit overrun on /redeem

**Severity:** High | **CWE:** CWE-362 | **Confidence:** High

**Vector:** `single-packet:/redeem`

...evidence blocks...
```

### `--format json`

```json
[
  {
    "id": "reaper-0001",
    "tool": "reaper",
    "title": "Concurrent limit overrun on /redeem",
    "severity": "high",
    "confidence": "high",
    "target": "https://shop.example.com/redeem",
    "vector": "single-packet:/redeem",
    "variant": "single-endpoint",
    "cwe_id": 362,
    "evidence": {
      "baseline_summary": { "count": 25, "success_count": 1, "statuses": {"200": 1, "409": 24} },
      "burst_summary":    { "count": 20, "success_count": 3, "statuses": {"200": 3, "409": 17} },
      "timing": { "unit": "ms", "samples": 20, "min": 12.4, "max": 38.1, "spread": 25.7 }
    },
    "references": ["https://portswigger.net/research/smashing-the-state-machine"]
  }
]
```

### `--format sarif`

See the SARIF 2.1.0 example in the [Example output](#example-output) section above.

## The HTTP/2 single-packet attack

The HTTP/2 single-packet attack was first described by James Kettle (albinowax)
at DEF CON 31, 2023, in *Smashing the State Machine*. It exploits a fundamental
property of HTTP/2 multiplexing to eliminate network jitter as a source of false
negatives in race-condition testing.

### Why traditional concurrent requests miss races

Classic race testing (HTTP/1.1 threaded — the [`race-the-web`](https://github.com/aaronhnatiw/race-the-web)
approach) fires multiple requests in parallel, each on its own TCP connection.
Even with thread synchronization, network jitter between connections means the
requests arrive at the server in a spread that can be tens or hundreds of
milliseconds wide. A server that processes shared-state mutations within a 1ms
window will not be caught by a 50ms spread — the second request arrives after
the first has already committed.

### How HTTP/2 multiplexing closes the window

HTTP/2 carries multiple request streams over a single TCP connection. Each
stream is independent, but they share the same socket buffer — which means a
server reads all of them in one `recv()` call when they arrive together.

The single-packet attack exploits this:

1. All N requests are sent as N H2 streams, with their final `DATA+END_STREAM`
   frame **withheld**. The server receives each request's headers and all body
   bytes except the last — it cannot process any of them until `END_STREAM`
   arrives.
2. After a ~100ms settle, all withheld final frames are released in a **single
   `send()` call** with Nagle's algorithm enabled. The kernel batches them into
   one TCP segment.
3. The server receives one packet, dequeues N requests simultaneously, and
   schedules N handler goroutines/threads in one event-loop tick. All N requests
   enter the shared-state critical section within the same scheduler quantum.

The result: network jitter is eliminated. The race window is determined by the
server's internal scheduling, not by the client's network path.

### Why this beats Turbo Intruder

PortSwigger's Turbo Intruder implements the same technique (it was in Kettle's
original research), but it is locked to Burp Suite's Java/Jython runtime and is
hard to integrate into headless pipelines. reaper is a standalone CLI that:

- Requires no Burp Suite or JVM.
- Outputs SARIF 2.1.0, JSON, and HackerOne markdown — integrating cleanly with
  CI and bug-bounty workflows.
- Enforces scope via `scan-primitives` before any burst.
- Supports SOCKS5 proxying for internal targets.

### Server requirements for the single-packet attack to work

The H2 single-packet attack requires the target server to:

1. **Speak HTTP/2** — either via TLS+ALPN on `https://` or via h2c prior
   knowledge on `http://`. HTTP/1.1-only servers fall back to last-byte-sync
   automatically (`--transport auto`).
2. **Accept enough concurrent streams** — the default H2 `SETTINGS_MAX_CONCURRENT_STREAMS`
   is 100; most servers support at least 20-30 concurrent streams. If the server
   enforces a low limit, reaper's burst is capped at that limit.
3. **Not buffer-serialize requests** — a server that reads all streams into a
   queue and processes them one at a time will not exhibit the race even when
   they arrive simultaneously. `reaper detect` measures this with
   `concurrency_hint`.
4. **Not require `Content-Length` for body-less requests** — most servers handle
   bodyless `POST` with just `END_STREAM`; a server that waits for a
   `Content-Length`-matching body before processing will not race.

## Race condition model

Race conditions in HTTP APIs typically fall into three patterns. reaper has a
subcommand for each.

### Limit-overrun (the 80% case) — `reaper single`

A single resource is guarded by a check-then-commit sequence:

```
1. Read the current count (e.g. coupon uses = 0)
2. Check the count is below the limit (0 < 1 → allow)
3. Increment and commit (uses = 1)
```

Under a synchronized burst, N requests all read the same initial state at step 1
(uses = 0), all pass the check at step 2, and all attempt to commit at step 3.
Only one commit writes `uses = 1`; the others may also write `1` on a last-write-
wins resource, or may each write independently if the increment is not atomic.
The result: N successes where the resource limit allows one.

This is the classic coupon over-redemption, withdrawal over-draw, free-tier
over-use, and vote-stuffing pattern. Kettle's research found it is by far the
most common exploitable race in web applications.

### Sub-state race — `reaper group`

A session-bound operation transitions through intermediate states, and an
attacker can fire two requests that both read the same intermediate state before
either commits. Example: a password-reset flow that sets a `password_reset_token`
in the session and checks it on the next request. Racing two `POST /reset`
requests may allow both to consume the same token.

The group file captures a heterogeneous set of requests with explicit or
auto-calibrated per-request delays. `--auto-delay` uses Kettle's RTT heuristic
to distribute requests across one RTT window without manual tuning.

### TOCTOU chaining — `reaper group --state-chain`

A time-of-check to time-of-use (TOCTOU) race fires two *different* endpoints
in the same window: one that reads shared state (the check) and one that modifies
it (the use). Classic example:

```
Request 1: POST /transfer  {"amount": 1000, "to": "attacker"}
Request 2: GET  /balance   {}
```

If the balance endpoint is called after the transfer has debited the account but
before the transaction is committed, it may return the pre-debit balance.
A differential response (the balance returned differs from what the post-transfer
balance should be) is the signal.

`--state-chain` fires each request file against its own endpoint in one
synchronized window. `reaper` reports timing spread (did they co-arrive?) and
differential status codes (did any endpoint return an unexpected response?).

## Worked walkthroughs

### `reaper detect` — pre-attack recon

```bash
reaper detect --target https://shop.example.com/redeem --scope-file scope.txt
```

Representative output:

```
transport : h2-single-packet
protocol  : h2
window    : spread=4.2ms  min=11.8ms  median=13.5ms  max=16.0ms  stdev=1.3ms
concurrency: concurrent
probe     : 10/10 2xx

Recommended attack:
  reaper single --target https://shop.example.com/redeem \
    --request redeem.http --copies 20 --scope-file scope.txt
```

A `concurrency: serialized` hint means the server is processing requests sequentially — the race window may be narrow and the attack less likely to succeed. A `--format json` flag returns the same data as a machine-readable dict.

### `reaper single` — single-endpoint limit overrun

```bash
# Redeem a coupon 20 times simultaneously in one synchronized packet burst.
reaper single \
  --target https://shop.example.com/redeem \
  --request redeem.http \
  --copies 20 \
  --scope-file scope.txt \
  --format text
```

`redeem.http` is a raw HTTP request in Burp/Repeater format:

```
POST /redeem HTTP/1.1
Host: shop.example.com
Content-Type: application/json
Authorization: Bearer eyJ...

{"code": "SAVE20"}
```

Representative output (race confirmed):

```
transport: h2-single-packet
baseline successes: 0 | burst successes: 3 | expected limit: 1
result: over-limit: burst produced 3 successes, expected at most 1
confirmed findings: 1
  - [high/high] Concurrent limit overrun on /redeem (single-packet:/redeem)
```

Exit code is `1` (finding confirmed). A clean run exits `0`.

### `reaper group` — multi-endpoint sub-state race

```bash
# Race two endpoints sharing a session — e.g. /verify-otp + /complete-transfer.
reaper group \
  --target https://app.example.com \
  --group-file mfa_race.group \
  --auto-delay \
  --scope-file scope.txt \
  --format json
```

`mfa_race.group` contains two raw HTTP requests separated by `%%%`:

```
POST /verify-otp HTTP/1.1
Host: app.example.com
Content-Type: application/json

{"code": "123456"}
%%%
POST /complete-transfer HTTP/1.1
Host: app.example.com
Content-Type: application/json

{"amount": 1000, "to": "attacker"}
```

`--auto-delay` measures round-trip time and computes optimal inter-request delays automatically; use `--auto-delay-samples 5` to average more RTT samples for a noisy link. With `--format json` the output is the JSON finding array.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Ran cleanly; no confirmed race detected |
| `1` | Ran cleanly; at least one confirmed race finding emitted |
| `2` | Usage error — no scenario given (argparse default) |
| `3` | Runtime error — out-of-scope target, transport failure, or I/O error |

A non-zero exit code on code `3` does **not** mean a race was found — it means reaper could not complete the scan. Check stderr for the error message.

## Troubleshooting / FAQ

**"server closes connection before last byte" or `TransportError: peer closed`**

The target closed the H2 connection mid-flight. Common causes: aggressive idle timeout, H2 stream limit too low, or the server does not support enough concurrent streams. Try `--transport h1-last-byte-sync` to fall back to per-connection H1. If `--transport auto` already selected H1 and the error persists, the target may be load-balanced and closing keep-alive connections faster than the warmup completes — lower `--copies` or add `--timeout 30`.

**"H2 not supported" / transport falls back to h1-last-byte-sync automatically**

The target only speaks HTTP/1.1. reaper automatically falls back under `--transport auto`. The H1 last-byte-sync engine still provides a synchronized burst (one TCP connection per copy, withholds the final byte, flushes all together) but the synchronization window is wider than H2 single-packet. You can force H2 with `--transport h2-single-packet` to confirm the diagnosis; this will error rather than fall back.

**"SOCKS5 timeout" / proxy connection refused**

The proxy is not reachable or the target is not routable via the proxy. Verify with `curl --socks5-hostname 127.0.0.1:1080 https://target` from the same host. For an SSH SOCKS5 tunnel (`ssh -D 1080 jump`), ensure the tunnel is active and the target's hostname resolves through the proxy (reaper uses DOMAINNAME address type, so the proxy resolves the hostname).

**"no race window detected" or `concurrency: serialized` from `reaper detect`**

The server is processing concurrent requests sequentially — either at the application layer (a mutex or a queue), at a load balancer, or behind a rate limiter. The race window may be too narrow to exploit. You can still attempt `reaper single` to confirm, but a serialized server is unlikely to yield a finding. Consider chaining sub-state endpoints with `reaper group --state-chain` where the race depends on ordering rather than true parallelism.

**"out-of-scope" error before any burst**

The `--target` hostname is not in the `--scope-file`. Add the target to the scope file, or omit `--scope-file` to default the scope to exactly the target host. reaper's scope check fires before any socket opens — no bytes are sent to an out-of-scope target.

**reaper finds no race but Turbo Intruder does**

reaper's authoritative signal is the synchronized burst itself — a clean server returns exactly one success even under a concurrent burst. If Turbo Intruder finds a race but reaper does not, the server may be sensitive to the specific request body or session token used. Confirm the request file contains the correct auth token and body. Also consider adding `--baseline-samples 3` to calibrate the expected success count from a sequential run first.

## Roadmap

See [CHANGELOG.md](CHANGELOG.md) for the full per-version release history and [POST_V01.md](POST_V01.md) for the post-v1.0 roadmap.

The single differentiator — the **HTTP/2 single-packet attack** — plus the
HTTP/1.1 last-byte-sync fallback, connection warming, statistical deviation
confirmation, and the CI race-lab are the v0.1 build (see `V0.1-CRITERIA.md`).
Subsequent releases shipped SOCKS5 (v0.2), auto-calibrated delay (v0.3),
pre-attack recon (v0.4), sub-state TOCTOU chaining (v0.5), and the stable
v1.0.0 release. The still-unshipped frontier (first-sequence-sync / >65KB
bodies, HTTP/3 QUIC, endpoint auto-discovery, distributed bursts, GUI) is
documented in [POST_V01.md](POST_V01.md).

## License / Attribution

MIT — see [LICENSE](LICENSE).

- Dead ancestor: [`race-the-web`](https://github.com/aaronhnatiw/race-the-web)
  by Aaron Hnatiw (HTTP/1.1 threaded racing, pre-single-packet era).
- Core technique: James Kettle (albinowax), PortSwigger —
  *[Smashing the State Machine](https://portswigger.net/research/smashing-the-state-machine)*
  (DEF CON 31, 2023), the single-packet attack.
- Large-body extension (v0.2 direction): RyotaK — first-sequence-sync research
  on breaking the ~1500-byte / 65535-byte window.
