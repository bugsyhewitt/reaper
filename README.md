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

> **Status:** suite-baseline scaffold. The findings / SARIF / HackerOne output
> surface is fully implemented and tested. The low-level single-packet engine,
> the HTTP/1.1 last-byte-sync fallback, connection warming, deviation
> confirmation, and the CI race-lab are **v0.1-pending** (see
> [Roadmap](#roadmap) and `V0.1-CRITERIA.md`). Scenario commands currently raise
> `NotImplementedError`.

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

> Both scenarios are **v0.1-pending** — they currently raise
> `NotImplementedError` until the single-packet engine lands. `--version` and
> `--help` are fully wired today.

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
reaper group  --target URL --group-file GROUPFILE
              [--transport {auto,h2-single-packet,h1-last-byte-sync}]
              [--scope-file PATH] [--format {json,text,h1md,sarif}]
```

- `--target` — the URL / host the race is fired against (must be in scope).
- `--request` — raw HTTP request file to replay (single-endpoint scenario).
- `--copies` — number of identical concurrent copies to race (20–30 typical).
- `--group-file` — request-group file: heterogeneous requests + manual delays.
- `--transport` — burst transport (default `auto`).
- `--scope-file` — scope file (one host/CIDR per line); enforced before any burst.
- `--format` — finding output: `json` (default), `text`, `h1md`, or `sarif`.

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
pytest -m "not ship_gate"
```

The `ship_gate` marker runs the slow build → fresh-venv install → `--version`
gate. The `integration` marker covers the live Hypercorn race-lab acceptance
test (v0.1-pending).

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
