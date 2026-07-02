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

> **Status:** v0.1. The HTTP/2 single-packet engine (TLS + h2c cleartext), the
> HTTP/1.1 last-byte-sync fallback with connection warming, the scan-primitives
> baseline client, benchmark→burst deviation confirmation with a final-state
> false-positive guard, and the Hypercorn CI race-lab are all built and tested.
> The findings / SARIF / HackerOne output surface is unchanged.

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

reaper exposes two race scenarios as subcommands. Both take a `--target`, an
optional `--scope-file`, a `--transport`, and a `--format`.

**Single-endpoint limit-overrun** — replay one request in N identical concurrent
copies against a single synchronized gate (the 80% case: over-redeem a coupon,
over-withdraw a balance):

```bash
reaper single --target https://shop.example.com/redeem \
  --request redeem.http --copies 20 --scope-file scope.txt
```

**Minimal multi-endpoint** — race a heterogeneous request group (different
methods / paths / bodies) sharing a session, with **manual** per-request delays
and one synchronized release (MFA/OTP and email-confirm sub-state races):

```bash
reaper group --target https://app.example.com \
  --group-file scenario.group --scope-file scope.txt
```

The group file is a sequence of raw HTTP requests separated by a line that is
exactly `%%%`; each block may be preceded by an `@delay <seconds>` directive
setting that request's **manual** release offset within the synchronized window
(never auto-calibrated — see [Roadmap](#roadmap)).

**Methodology.** reaper's authoritative over-limit signal is the concurrent
burst itself: a correctly synchronized server yields exactly **one** success even
under a synchronized burst, so *more* successes than the resource's limit is the
race. A sequential baseline (`--baseline-samples N`) is **opt-in** — on a
single-use resource it consumes the very unit under test — and, when supplied,
runs first to establish the expected limit and the deviation reference. reaper
guards the **final-state false positive**: a surplus success that a later request
overwrites is not reported as confirmed. Exit code is `1` when a race is
confirmed, `0` when none is, `3` on an out-of-scope / transport / IO error.

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
reaper single --target URL --request REQFILE --copies N
              [--transport {auto,h2-single-packet,h1-last-byte-sync}]
              [--scope-file PATH] [--format {json,text,h1md,sarif}]
              [--baseline-samples N] [--rate-limit RPS] [--timeout S] [--insecure]
reaper group  --target URL --group-file GROUPFILE
              [--transport {auto,h2-single-packet,h1-last-byte-sync}]
              [--scope-file PATH] [--format {json,text,h1md,sarif}]
              [--timeout S] [--insecure]
```

- `--target` — the URL / host the race is fired against (must be in scope).
- `--request` — raw HTTP request file to replay (single-endpoint scenario).
- `--copies` — number of identical concurrent copies to race (20–30 typical).
- `--group-file` — request-group file: heterogeneous requests + manual delays.
- `--transport` — burst transport (default `auto`).
- `--scope-file` — scope file (one host/CIDR per line); enforced before any burst.
  With no `--scope-file`, scope defaults to exactly the target host.
- `--format` — finding output: `json` (default), `text`, `h1md`, or `sarif`.
- `--baseline-samples` — sequential baseline samples to send first (default `0`,
  opt-in; see Methodology above).
- `--rate-limit` — baseline requests/second (scan-primitives token bucket).
- `--timeout` — per-socket / per-request timeout in seconds (default `10`).
- `--insecure` — skip TLS certificate verification (`https` targets only).

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

**Explicitly NOT in v0.1** (deferred):

- **First-sequence-sync / >65KB bodies / >~30 requests** (RyotaK: IP
  fragmentation + TCP sequence reordering at L3–L4; needs scapy, raw sockets,
  root) → **v0.2**.
- **HTTP/3 single-datagram attack** (QUIC) — new protocol surface, low prevalence.
- **Auto-calibration of multi-endpoint delays** (Kettle client-side timing) —
  ship manual delays first.
- **Endpoint auto-discovery, distributed / multi-host bursts, SOCKS/proxy
  chaining, any GUI.**

## License / Attribution

MIT — see [LICENSE](LICENSE).

- Dead ancestor: [`race-the-web`](https://github.com/aaronhnatiw/race-the-web)
  by Aaron Hnatiw (HTTP/1.1 threaded racing, pre-single-packet era).
- Core technique: James Kettle (albinowax), PortSwigger —
  *[Smashing the State Machine](https://portswigger.net/research/smashing-the-state-machine)*
  (DEF CON 31, 2023), the single-packet attack.
- Large-body extension (v0.2 direction): RyotaK — first-sequence-sync research
  on breaking the ~1500-byte / 65535-byte window.
