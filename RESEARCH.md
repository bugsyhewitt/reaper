# reaper — Research Brief

**Tool:** reaper  
**Class:** race conditions / single-packet attack  
**Status:** registered, not yet built  
**[CHECK: confirm codename before first build. Also confirm exact ancestor repo — race-the-web (aaronhnatiw/TheHackerBlog) or cleanest alternative — before first build if race-the-web is unsuitable.]**

---

## Dead Ancestor

**race-the-web** (aaronhnatiw / TheHackerBlog, ~2017-18) — pre-single-packet-attack era. HTTP/1.1 threaded request racing only. No HTTP/2 frame-withholding, no connection warming, no last-byte sync. Abandoned.

**Confirmation of "dead":** verify last commit date and lack of HTTP/2 single-packet support before first build. If race-the-web is too thin as an ancestor, consider using the race-condition tooling from older HackerOne/Bugcrowd toolkits (document the chosen ancestor in CLAUDE.md once confirmed).

---

## Why the Niche Is Open

The dominant modern technique — the **single-packet attack** — was published by James Kettle at DEF CON 31 ("Smashing the State Machine", 2023). It sends all concurrent requests in a single TCP packet (or HTTP/2 DATA frame burst), eliminating network jitter and enabling true atomic-window races.

Current tools that implement it:
- **Turbo Intruder** (PortSwigger, Jython, Burp-only) — the reference implementation
- **Burp Repeater** "send group in parallel" — GUI only
- **h2spacex** (nxenon) — low-level HTTP/2 library, not a workflow tool
- **Raceocat** (JavanXD) — low-level, not a workflow tool

**Automated scanners** (Nuclei, Nikto, etc.) cannot detect race conditions at all — no signature-based approach is possible for timing-window bugs.

This is a high-value, incumbent-free niche for bug bounty (balance manipulation, coupon-reuse, limit-overrun, MFA sub-state races, OTP bypass). A headless CLI with the single-packet attack is genuinely novel.

Reference research:
- James Kettle, "Smashing the State Machine" (DEF CON 31, 2023) — primary source
- ryotkak, "Breaking the 1500-byte / 65535-byte window" — first-sequence-sync extension
- PortSwigger Web Security Academy: Race Conditions module

---

## Niche to Stake

### Core capability (inform v0.1 criteria)

1. **HTTP/2 single-packet attack** — send N parallel requests in one TCP burst via HTTP/2 frame-withholding:
   - Withhold the DATA frame's END_STREAM flag on all-but-last concurrent requests
   - Release all END_STREAM flags in a single TCP segment (last-byte sync)
   - Achieves true atomic-window racing with sub-millisecond jitter
   - Implementation path: h2spacex-style raw H2 framing (Scapy or h2spacex as dependency) or direct socket with h2 library

2. **Last-byte sync fallback (HTTP/1.1)** — for servers that don't support HTTP/2:
   - Withhold the last byte of each request body
   - Send all last bytes in a single TCP segment
   - Degrades gracefully from H2 single-packet to H1 last-byte sync

3. **Connection warming** — pre-send junk requests on each connection to clear TCP slow-start before the race burst; eliminates first-request jitter that contaminates results

4. **First-sequence-sync extension (ryotkak)** — overcome the ~1500-byte MTU and ~65535-byte congestion-window limits that break single-packet attacks on large request bodies:
   - Fragment the large request across frames in a way that forces a single window send
   - Reference: ryotkak's research on breaking the 1500/65535 boundary

5. **Sub-state / multi-endpoint race orchestration** — coordinate races across multiple endpoints in a single session (e.g., redeem coupon on endpoint A while simultaneously reading balance on endpoint B):
   - Define a "race scenario" as a YAML/JSON config (endpoints, bodies, auth headers, timing)
   - Execute the configured scenario with single-packet synchronization

6. **Deviation detection + benchmarking** — establish a baseline (solo requests) and compare distributions against the concurrent burst:
   - Statistical deviation (response time, status code, body hash) flags race-condition candidates
   - Report confirmed deviations in the canonical SARIF-compatible finding schema

### Suite integration (non-negotiable)
- Use the suite's shared `scan-primitives` HTTP client for the HTTP/1.1 layer; add H2 framing as an internal module.
- Emit findings in the canonical SARIF-compatible finding schema with HackerOne adapter. No bespoke output format.

---

## Prior Art to Study Before Building

| Tool | State | Notes |
|------|-------|-------|
| race-the-web (aaronhnatiw) | Dead ancestor | HTTP/1.1 baseline only, thread model to avoid |
| Turbo Intruder (PortSwigger) | Active (Burp/Jython) | Technique reference — do NOT vendor; uses Jython gate API |
| h2spacex (nxenon) | Active (low-level lib) | H2 raw framing dependency candidate |
| Raceocat (JavanXD) | Active (low-level) | H2 race lib reference |
| ryotkak first-sequence-sync | Research post | Critical for large-body races |
| Kettle DEF CON 31 slides | Reference | Primary technique source |

---

## Not in Scope (do not build, even if useful)

- Non-HTTP race conditions (file system, database-level)
- Full exploit chains beyond detecting the race window (business logic exploitation is the human's job)
- Browser-based race delivery (pure CLI scope)
- Automated result exploitation (reaper detects, human exploits)

---

## Open Questions for Overmind (resolve before v0.1 criteria)

1. Should v0.1 include the H2 single-packet attack, or start with HTTP/1.1 last-byte sync only (simpler, still far ahead of race-the-web)?
2. Should first-sequence-sync (ryotkak) be in v0.1 or post-v0.1?
3. Should multi-endpoint race orchestration (YAML scenario config) be in v0.1 or post-v0.1?
4. Which H2 framing library should be the dependency: h2spacex, the `h2` library (python-hyper), or raw Scapy? This is a build-time architectural decision.
5. Wave 3 budget (500K) — H2 single-packet + last-byte-sync + deviation detection is a strong v0.1; is that the right scope?
