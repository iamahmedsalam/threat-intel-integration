# Lessons Learned — Project 3: Threat Intel Integration

---

## From Detection to Decision-Making

Project 1 proved I can detect threats. Project 2 proved I can
investigate and respond to them. Project 3 proves I can build the
layer in between — automated enrichment that turns a raw detection
into a confident, evidence-backed decision, at machine speed, across
multiple independent data sources.

---

## Learning Python From Zero, Purpose-Built for This Project

Before Project 3, I had never written a line of Python. Rather than
copy-pasting code, I worked through a 7-module curriculum built
specifically around what this project needed: variables and control
flow → dictionaries and JSON → functions → real API integration
(built and tested against live AbuseIPDB queries) → error handling
and logging → async I/O → automated testing with pytest. Every
concept was immediately applied to real project code, not abstract
exercises. The result: I can read, explain, and independently debug
every line in this repository — including finding and fixing my own
indentation bugs, a stdin-hang bug in a subprocess script, and a
stale-data bug in a bash cron job.

---

## Infrastructure: Scaling the Lab

Adding a 5th VM (self-hosted MISP) pushed the existing 16GB lab
machine past its limit. Rather than compromise on scope, upgraded to
a 64GB RAM kit and moved all VM storage to a secondary drive — turning
a resource constraint into a permanent capability upgrade for every
future project. Also discovered and resolved a recurring issue: newly
created lab VMs default to Host-Only networking only, which has no
internet access — every VM needed a second NAT adapter added before
`apt`/`pip`/Docker package installation would work. Documented this
as a standard setup step for any future VM in the lab.

---

## Detection Engineering: Multi-Source Correlation in Practice

### Two Real False Positives, Not Hypothetical Ones

The most valuable finding in this project wasn't a success — it was
catching the enrichment pipeline about to make a wrong call, twice,
using real data:

1. **Google DNS (8.8.8.8)** flagged by MISP's CIRCL feed alone (clean
   on both AbuseIPDB and OTX). Multi-source correlation logic
   correctly downgraded this to SUSPICIOUS rather than BLOCK.
2. **The SHA256 hash of an empty file** matched independently by
   both OTX and MISP — investigated thoroughly (bypassing the
   engine's own caching to rule out a code bug) and confirmed as a
   genuine, cross-source, industry-known phenomenon: automated
   malware sandboxes occasionally log a corrupted/empty sample's
   hash as an "indicator."

Both findings directly justify the "any 2 of 3 sources" verdict
design — a single-source signal is not sufficient grounds for
automated action, and this project has concrete evidence why.

### Why Self-Host MISP Instead of Just Using More APIs

Deploying and administering a real MISP instance (Docker Compose,
CIRCL OSINT feed subscription, API key management) demonstrates
threat-intel *platform* skills, not just API consumption — this is
what a SOC actually runs internally to curate and correlate its own
indicators, distinct from pulling data from third-party services.

---

## The Active Response Debugging Story

This is the single most valuable troubleshooting experience in the
project, and worth detailing in full because the process — not just
the outcome — is what a hiring manager will want to hear about.

**The symptom:** Automated IP blocking worked intermittently. Some
test runs blocked the target IP correctly; others silently did
nothing, with no error anywhere.

**The investigation path:**
1. Confirmed the Wazuh rule (100016) was firing correctly every time
   — ruled out the detection layer.
2. Enabled `analysisd.debug=2` and `execd.debug=2` and traced the
   exact dispatch messages between Wazuh's components.
3. Found that `analysisd` reliably logged "Send AR to execd" — but
   `execd`'s corresponding "Received message" log entry was
   sometimes completely absent, with zero errors, zero timeouts,
   nothing. The dispatch was simply vanishing.
4. Tested the Active Response script manually (bypassing Wazuh
   entirely, piping the same JSON payload via stdin) — 100% reliable
   every time. This isolated the failure specifically to Wazuh's
   internal dispatch mechanism, not the script itself.
5. Suspected a stdin-read hang inside the script under `execd`'s
   process-spawning conditions; added a `select()`-based read
   timeout as a hardening measure — the failures persisted even with
   this fix, definitively ruling out the script as the cause.
6. Researched and found a matching, previously-filed upstream Wazuh
   GitHub issue (#9370) describing exactly this behaviour — broken
   Active Response timeout/dispatch handling introduced in the 4.2
   rework, not something specific to this deployment.

**The engineering decision:** Rather than continuing to fight a
confirmed upstream reliability bug in a third-party dispatch
mechanism, redesigned the containment path — the enrichment engine
now applies the iptables block **directly, in-process**, the instant
it calculates a BLOCK verdict, with `sudo` NOPASSWD scoped narrowly
to the `iptables` binary. Proven 100% reliable across every
subsequent test and all 4 live drills. Wazuh's Rule 100016 alert
still fires correctly for dashboard visibility — only the
containment *action* was rearchitected.

**A second bug found and fixed along the way:** the cron-based
auto-unblock script (built to replace Wazuh's own unreliable
stateful-AR timeout tracking) initially calculated an IP's "block
age" using the *first* historical log line matching that IP, not the
most recent one — causing premature unblocks whenever a prior test
run's stale block entry was still in the log. Also separately
matched the substring "BLOCKED" inside "UNBLOCKED," compounding the
issue. Rewritten using a bash associative array to track only the
latest block timestamp per IP. Verified accurate to within the
cron polling interval (618s and 622s against a 600s target,
across two independent drills).

**Why this matters for the portfolio:** most junior candidates would
either give up and hardcode a workaround, or not notice the bug at
all in a quiet-failure scenario like this. This was a genuine
multi-hour investigation that used log analysis, manual isolation
testing, and upstream issue research to arrive at a correct
diagnosis — then made a defensible engineering trade-off rather than
continuing to debug a third-party tool indefinitely.

---

## Performance & Reliability Summary

| Metric | Result |
|---|---|
| API sources integrated | 3 (AbuseIPDB, AlienVault OTX, self-hosted MISP) |
| Custom Wazuh rules added | 5 (100012–100016), bringing total to 16 |
| Automated tests | 19 (15 IP-verdict + 4 hash-verdict), all passing |
| Cache hit speedup | ~14s → near-instant on repeated lookups (SQLite, 1hr TTL) |
| Direct-block reliability | 100% across all tested runs (vs. intermittent native Wazuh AR) |
| Auto-unblock accuracy | 618s / 622s measured against 600s configured timeout |
| Real false positives caught and documented | 2 (Google DNS via MISP; empty-file hash via OTX+MISP) |
| Live drills executed | 4, including a unified multi-stage incident (Drill 4) |
