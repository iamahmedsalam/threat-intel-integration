# Pipeline Architecture

## Lab Infrastructure

```
Wazuh Manager       192.168.56.101   [SIEM + enrichment engine runs here]
Windows 11 Agent    192.168.56.103   [monitored endpoint, Sysmon]
Ubuntu Agent        192.168.56.104   [monitored endpoint, auditd]
Kali Attacker       192.168.56.50    [attack machine]
MISP Server         192.168.56.105   [self-hosted threat intel, Docker]  ← NEW for Project 3
```

Host machine: ASUS TUF Gaming F15, i5-10300H, 64GB RAM (upgraded from 16GB
specifically to run 5 VMs simultaneously — see lessons-learned.md).

## End-to-End Data Flow

```
1. Attack occurs (real or simulated) against a monitored endpoint
       ↓
2. Wazuh Sysmon/auditd decoder generates a base alert
   (e.g. Rule 100011 - SSH brute force, Rule 100008 - file drop)
       ↓
3. Alert written to /var/ossec/logs/alerts/alerts.json
       ↓
4. Python enrichment engine (main.py) tails alerts.json in real time,
   extracts the source IP, filters out private/RFC1918 addresses
       ↓
5. For external IPs: engine queries all 3 threat intel sources
   in sequence (AbuseIPDB, AlienVault OTX, self-hosted MISP)
       ↓
6. Results cached in SQLite (1-hour TTL) to avoid redundant API calls
       ↓
7. Multi-source verdict calculated: BLOCK / LIKELY_MALICIOUS /
   REVIEW / SUSPICIOUS / CLEAN
       ↓
8. Verdict written back to enrichment_alerts.json (a new Wazuh
   <localfile> source) AND to the human-readable enrichment.log
       ↓
9. Wazuh Rules 100012-100016 parse the new JSON source and fire
   dashboard alerts scaled to the verdict severity
       ↓
10. If verdict == BLOCK: enrichment engine directly invokes iptables
    in-process (bypassing Wazuh's Active Response dispatch — see
    lessons-learned.md for why), applying an immediate DROP rule
       ↓
11. Cron job (running every 60s) tracks each IP's most recent block
    timestamp and auto-removes the DROP rule once it exceeds the
    600-second timeout
```

## Why Self-Hosted MISP (Not Just APIs)

AbuseIPDB and OTX are consumed via their public REST APIs. MISP is
different — it's deployed as a full platform (Docker Compose: MISP
core, MariaDB, Redis, mail) on its own VM, subscribed to the CIRCL
OSINT feed. This demonstrates threat intel *platform administration*,
not just API consumption — a MISP instance is what a mid-size SOC
would actually run internally to aggregate and curate its own IOCs
alongside public feeds.

## Why Multi-Source Correlation

No single feed is trusted alone. The verdict logic requires the
AbuseIPDB confidence score to cross a threshold *and* at least one
other source (OTX pulse match or MISP attribute match) to reach
BLOCK. This was validated by two real false positives discovered
during testing:

- **8.8.8.8 (Google DNS)** — MISP alone flagged it (CIRCL feed noise),
  but AbuseIPDB and OTX both showed clean. Verdict: SUSPICIOUS, not
  BLOCK. Multi-source correlation prevented an incorrect block on a
  major public DNS resolver.
- **Empty-file SHA256 hash** (`e3b0c442...`) — both OTX and MISP
  independently reference this hash in sandbox-report pulses (a
  known industry-wide false-positive source: corrupted/empty malware
  samples get their hash logged during automated analysis). Cross-
  referenced against a real WannaCry hash to confirm this wasn't a
  code bug — different pulse names, different MISP event IDs, same
  hash-collision phenomenon.

## Why Direct-Block Instead of Wazuh Active Response

See `docs/lessons-learned.md` for the full troubleshooting narrative.
Summary: Wazuh's native `execd` Active Response dispatch was found to
intermittently fail silently in this deployment (confirmed via debug
logging — `analysisd` would report "Send AR to execd" with zero
corresponding `execd` log entry on a meaningful fraction of runs).
This matches a documented upstream Wazuh issue (#9370) describing
broken AR timeout/dispatch handling since the 4.2 rework. Rather than
depend on an unreliable third-party dispatch mechanism for a security
control, the enrichment engine applies the firewall block directly,
in the same Python process that calculated the verdict — eliminating
the unreliable hop entirely while keeping Wazuh's dashboard alert
(Rule 100016) fully intact for analyst visibility.
