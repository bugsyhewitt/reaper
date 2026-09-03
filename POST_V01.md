# reaper — Post-v1.0 Roadmap

reaper v1.0.0 ships the HTTP/2 single-packet attack, HTTP/1.1 last-byte-sync fallback, auto-calibrated group delay (v0.3), pre-attack recon (v0.4), and sub-state multi-endpoint TOCTOU chaining (v0.5). What follows is the **still-unshipped frontier** — items that were explicitly deferred from v0.1 and have not shipped in any subsequent release.

---

## 1. First-sequence-sync — large bodies and >~30 requests (the RyotaK path)

**What it is.** The current single-packet engine works at the HTTP/2 application layer: it withholds and then releases frames so they land in one TCP packet. This works reliably when the total payload fits within a single TCP segment (roughly ≤1,500 bytes per request for standard MTU, and ≤65,535 bytes total before the kernel fragments). RyotaK's research documents the next tier: achieving synchronized delivery even for large bodies or burst counts that spill across multiple IP fragments. This requires controlling TCP sequence numbers and IP fragmentation directly — operations that live at OSI L3–L4 and demand raw sockets via **scapy** and **root privileges**.

**Why it matters for reaper vs. Turbo Intruder.** Turbo Intruder is Burp/Jython-locked and does not expose raw-socket primitives. A reaper that handles the large-body / >30-request case would cover OTP brute-scale races (where N approaches 50–100) and API endpoints that require substantial JSON payloads — attack surfaces that today require manual scapy scripting. Closing this gap makes reaper the only headless, scriptable tool covering the full single-packet spectrum.

**Prerequisites.** scapy, raw-socket support (root or `CAP_NET_RAW`), an OS-level bypass for TCP stack reassembly, and a sandboxed CI fixture that can run with elevated privileges (or mock the kernel path for unit testing). This is the most implementation-complex item on the roadmap; it was deliberately deferred from v0.1 to avoid consuming the entire 500K token budget on socket-portability and privilege edge cases.

---

## 2. HTTP/3 single-datagram attack (QUIC)

**What it is.** HTTP/3 runs over QUIC, a UDP-based protocol. The single-packet attack analogy for HTTP/3 is a **single-datagram burst**: multiplex N requests as QUIC streams within one UDP datagram (or a minimal set of datagrams sent in a single `sendmmsg` call), so they arrive at the server's QUIC stack simultaneously. Unlike TCP, QUIC's stream multiplexing is handled at the application layer by the QUIC implementation — making synchronized delivery potentially more tractable than the TCP sequence-reordering path, but requiring a QUIC client library with fine-grained control over datagram assembly.

**Why it matters.** HTTP/3 adoption is accelerating (Cloudflare, Fastly, and major CDNs default to QUIC for supported clients). A target that rate-limits TCP connections or deploys HTTP/2 reset-flood mitigations may still be vulnerable to QUIC-layer race conditions. Turbo Intruder has no QUIC support. Adding HTTP/3 to reaper opens a new protocol surface for race detection that no current headless tooling covers.

**Prerequisites.** A sans-IO or low-level QUIC library with datagram-level send control (e.g. `aioquic` with custom packetizing, or a direct `asyncio` + `socket` QUIC implementation). TLS 1.3 (mandatory for QUIC). Fixture support: a QUIC-capable server for CI (Hypercorn supports QUIC/HTTP3 experimentally). Prevalence is still low on typical bug-bounty targets, so this is lower urgency than the large-body path.

---

## 3. Endpoint auto-discovery

**What it is.** Currently, reaper requires the attacker to supply a scope file listing the exact endpoints to target. Auto-discovery would let reaper crawl an API surface — using OpenAPI/Swagger specs, observed traffic, or a lightweight spider — and identify candidate endpoints that exhibit the structural signatures of race conditions: check-then-act patterns, idempotency keys, shared state references, or non-atomic multi-step flows.

**Why it matters.** The manual scoping step is the main friction point in a reaper engagement. Turbo Intruder delegates discovery entirely to Burp's proxy; a headless reaper user has to reconstruct the API surface independently. Auto-discovery would let reaper operate closer to a zero-configuration mode for well-specified APIs, which is the key gap in its positioning as a Burp-free alternative.

**Prerequisites.** OpenAPI/Swagger parser, optional HAR/traffic-capture import, and a heuristic classifier for race-condition candidate endpoints. Integration with `reaper detect` as a pipeline: discover → detect transport → attack. No elevated privileges required.

---

## 4. Distributed / multi-host bursts

**What it is.** Even with the single-packet engine, all requests originate from one host. Targets with per-IP rate limits or connection-count caps can filter the burst before it reaches the vulnerable endpoint. Distributed bursts coordinate multiple reaper instances (on different IPs or cloud nodes) to fire their withheld frames in a synchronized wall-clock window, simulating an attacker who controls a small botnet or a set of cloud egress IPs.

**Why it matters.** Bug-bounty programs increasingly run behind Cloudflare or similar CDNs that rate-limit aggressively per source IP. Distributed bursting is the next step for bypassing those mitigations. It is also the natural scaling path for OTP brute-scale races where N > 100 requests is needed and a single TCP connection's stream limit becomes a bottleneck.

**Prerequisites.** A coordinator/worker RPC protocol (gRPC or a lightweight WebSocket signaling bus), NTP or PTP clock synchronization between nodes for wall-clock alignment, and a cloud-friendly deployment model (Docker + a small orchestration script). This is the most infrastructure-heavy item and is best tackled after the large-body path is stable.

---

## 5. GUI

**What it is.** A lightweight browser-based or Electron UI that wraps the reaper CLI — scope file builder, request editor, live burst progress, and evidence-report viewer.

**Why it matters.** reaper's headless/scriptable positioning is its primary differentiator from Turbo Intruder, but a GUI lowers the adoption barrier for penetration testers who are comfortable in Burp's visual workflow but want to escape Jython. The GUI would be a thin shell over the existing CLI; it does not change the engine.

**Prerequisites.** Stable CLI API (achieved at v1.0.0). A web framework for the UI (FastAPI + HTMX, or Electron). The GUI is explicitly the lowest-priority item — the core engine and CLI path are the product.
