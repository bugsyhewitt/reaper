# reaper

**Status:** registered — awaiting v0.1 criteria from Overmind  
**Slot:** 13 (wave 3, 500K budget)  
**Language:** Python  
**Niche:** race conditions / single-packet attack

Resurrects the dead-ancestor race tooling (race-the-web, pre-single-packet era) with the modern single-packet attack technique (HTTP/2 frame-withholding, James Kettle / DEF CON 31). Covers last-byte sync fallback for HTTP/1.1, connection warming, the first-sequence-sync extension (ryotkak), and sub-state multi-endpoint race orchestration. Headless CLI, no Burp/Turbo Intruder dependency. Emits findings in the canonical SARIF-compatible schema.

See `RESEARCH.md` for the niche brief and prior-art analysis.

> **Do not build until the Overmind defines v0.1 criteria.**
