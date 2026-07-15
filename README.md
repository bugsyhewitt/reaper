# reaper

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

> **Status:** v0.4. The v0.1 core (HTTP/2 single-packet engine, HTTP/1.1
> last-byte-sync fallback, scan-primitives baseline, deviation confirmation) is
> complete. v0.2 added **SOCKS5 proxy support**. v0.3 adds **auto-calibrated
> delay** (`--auto-delay`) for the group scenario. v0.4 adds **`reaper detect`**
> — a pre-attack recon command that auto-detects transport (H2 vs H1.1) and
> estimates race window width by firing a non-destructive probe burst.

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
      "tool": { "driver": { "name": "reaper", "version": "0.1.0", "rules": [ ... ] } },
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

## Roadmap

The single differentiator — the **HTTP/2 single-packet attack** — plus the
HTTP/1.1 last-byte-sync fallback, connection warming, statistical deviation
confirmation, and the CI race-lab are the v0.1 build (see `V0.1-CRITERIA.md`).

**Shipped in v0.2:**

- **SOCKS5 proxy support** (`--proxy socks5://host:port`) — baseline and raw
  burst both route through the tunnel.

**Shipped in v0.3:**

- **Auto-calibrated delay** (`--auto-delay` / `--auto-delay-samples`) for the
  group scenario — reaper measures baseline RTT with warm-up GET / requests
  and computes `delay[i] = i * rtt / N` (Kettle client-side timing), removing
  the guesswork from `@delay` tuning for MFA/OTP and email-confirm sub-state
  races.

**Shipped in v0.4:**

- **`reaper detect`** — pre-attack recon command. Probes the target for HTTP/2
  vs HTTP/1.1 support, fires a non-destructive probe burst (`GET /`) with the
  detected transport, and reports the race window spread, a concurrency hint
  (`concurrent` / `serialized`), and a recommended attack invocation. Useful as
  a first step before committing to a full race attempt.

**Deferred (post-v0.4):**

- **First-sequence-sync / >65KB bodies / >~30 requests** (RyotaK: IP
  fragmentation + TCP sequence reordering at L3–L4; needs scapy, raw sockets,
  root).
- **HTTP/3 single-datagram attack** (QUIC) — new protocol surface, low prevalence.
- **Endpoint auto-discovery, distributed / multi-host bursts, any GUI.**

## License / Attribution

MIT — see [LICENSE](LICENSE).

- Dead ancestor: [`race-the-web`](https://github.com/aaronhnatiw/race-the-web)
  by Aaron Hnatiw (HTTP/1.1 threaded racing, pre-single-packet era).
- Core technique: James Kettle (albinowax), PortSwigger —
  *[Smashing the State Machine](https://portswigger.net/research/smashing-the-state-machine)*
  (DEF CON 31, 2023), the single-packet attack.
- Large-body extension (v0.2 direction): RyotaK — first-sequence-sync research
  on breaking the ~1500-byte / 65535-byte window.
