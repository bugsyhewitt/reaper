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
