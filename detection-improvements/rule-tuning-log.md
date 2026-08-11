# Detection Improvements — Rule Tuning Log (Project 3)

Improvements identified through building and validating the threat
intel enrichment pipeline across Phases A–E.

---

## New Capabilities Built

### Custom Rules 100012–100016 (Threat Intel Verdict Tiers)
Five new Wazuh rules that turn Python enrichment verdicts into
first-class dashboard alerts, scaled by severity:
- 100012 (Level 3) — base "enrichment result received"
- 100013 (Level 6) — SUSPICIOUS
- 100014 (Level 8) — REVIEW
- 100015 (Level 10) — LIKELY_MALICIOUS
- 100016 (Level 13) — BLOCK, triggers automated containment

Custom rule count: 11 (end of Project 2) → **16**.

### Hash-Lookup Enrichment (`check_hash()`)
Added to both `OTXClient` and `MISPClient`, plus
`EnrichmentEngine.enrich_hash()` and a dedicated
`calculate_hash_verdict()`. MISP hash checks loop across md5/sha1/
sha256 attribute types since the hash algorithm isn't known in
advance. Validated with 4 automated pytest tests plus real drill
data (Drill 2, Drill 4 Stage 2).

---

## Verdict Logic Improvements

### Multi-Source "Any 2 of 3" Threshold (IP verdicts)
`calculate_verdict()` only returns BLOCK when the AbuseIPDB score
crosses the configured threshold **and** at least one other source
(OTX or MISP) corroborates. A high AbuseIPDB score alone returns
LIKELY_MALICIOUS, not BLOCK — this distinction was validated by two
real false positives caught during testing (Google DNS via MISP-only
match; the empty-file SHA256 hash matched by both OTX and MISP
independently). Prevents single-source noise from triggering
automated firewall actions.

### Private IP Filtering
`process_alert()` skips enrichment entirely for RFC1918 addresses
(`192.168.`, `10.`, `127.0.0.1`). Confirmed correct and necessary
via Drill 1 — without this filter, every internal lab alert (or,
in production, every internal/lateral-movement alert) would produce
meaningless CLEAN verdicts and waste API quota.

---

## Recommended Future Rule Additions

### Rule for Repeated BLOCK Verdicts on the Same IP Within a Window
Currently each BLOCK verdict is handled independently. If the same
IP triggers BLOCK multiple times within a short window (e.g., an
attacker retrying after auto-unblock), that pattern itself is a
stronger signal and should escalate severity or extend the block
duration rather than simply re-applying the same 600-second timeout.

### Separate Severity Tier for Multi-Stage Correlation
Drill 4 demonstrated a full kill chain (100011 → 100008 → 100016)
within an 11-minute window from the same agent pair. A correlation
rule that specifically detects "brute force + payload staging + C2
callback from the same asset within N minutes" would let the
dashboard surface confirmed multi-stage incidents automatically,
rather than requiring an analyst to manually correlate three
separate alerts (as was done for the Drill 4 documentation).

### MISP Feed Coverage Alerting
Drill 3 and Drill 4 both showed MISP returning 0 matches for an IP
that AbuseIPDB/OTX confirmed as 100% malicious. Worth adding
monitoring for MISP feed sync health/freshness so gaps in CIRCL feed
coverage are visible rather than silently reducing correlation
confidence.

---

## Architectural Improvement: Active Response Reliability

**Finding:** Wazuh's native `execd` Active Response dispatch was
found to intermittently fail silently in this deployment — confirmed
via debug-level logging showing `analysisd` reporting successful
dispatch (`Send AR to execd`) with zero corresponding execution log
from `execd` on a meaningful fraction of test runs. This matches
documented upstream Wazuh issue #9370 (AR timeout/dispatch handling
regressed in the 4.2 rework).

**Resolution:** Rather than depend on an unreliable third-party
dispatch mechanism for a security control, engineered a direct-
invocation architecture — the enrichment engine applies the iptables
block itself, in-process, the instant a BLOCK verdict is calculated.
Proven 100% reliable across repeated test runs (vs. intermittent
failures with the native Wazuh AR path). Full narrative in
`docs/lessons-learned.md`.

**Also fixed during this work:** the cron-based auto-unblock script
initially matched *any* historical "BLOCKED" log line for an IP
rather than only the most recent one, causing premature unblocks
(and, separately, was matching the substring "BLOCKED" inside
"UNBLOCKED" itself). Rewritten to track only the latest block
timestamp per IP using a bash associative array. Verified accurate
across multiple drills (618s, 622s against a 600s target).
