# 🛰️ Threat Intelligence Integration for Wazuh SIEM

**Production-quality Python enrichment engine that correlates live SIEM alerts against 3 threat intelligence sources — MISP (self-hosted), AlienVault OTX, and AbuseIPDB — with automated containment and a fully validated live-fire drill program.**

> Built by [Ahmed Salam](https://iamahmedsalam.com) — AI-Augmented SOC Analyst | CompTIA Security+ | TryHackMe Top 2%

---

## What This Project Proves

A detection rule firing is only useful if an analyst can trust it.
This project builds the layer between "an alert fired" and "here's a
confident, evidence-backed decision" — automated multi-source threat
intelligence correlation, running in real time against a live Wazuh
SIEM, with automated containment for high-confidence threats.

Everything in this repo is real: a self-hosted MISP platform, live
API integrations against AbuseIPDB and AlienVault OTX, a Python
enrichment engine with caching and structured logging, 19 automated
tests, 5 new Wazuh detection rules, and 4 live-fire drills — including
one unified multi-stage incident tying together techniques from all
3 of my SOC portfolio projects.

---

## Architecture

```
Wazuh Alert (Sysmon/auditd) → Python Enrichment Engine
                                    ↓
                 ┌──────────────────┼──────────────────┐
                 ↓                  ↓                  ↓
            AbuseIPDB          AlienVault OTX    Self-hosted MISP
           (IP reputation)     (IP + hash pulses) (IOC correlation)
                 └──────────────────┼──────────────────┘
                                    ↓
                     Multi-source verdict calculation
                        (any 2-of-3 required for BLOCK)
                                    ↓
              ┌─────────────────────┴─────────────────────┐
              ↓                                            ↓
    Wazuh dashboard alert                      Automated containment
    (Rules 100012–100016)                    (direct iptables block +
                                               cron-based auto-unblock)
```

Full write-up: [`architecture/pipeline-architecture.md`](architecture/pipeline-architecture.md)

---

## Key Findings

- **Two real false positives caught and documented** — Google DNS
  flagged by MISP alone (correctly downgraded, not blocked), and a
  cross-source hash-collision false positive on an empty-file SHA256
  matched by both OTX and MISP independently.
- **Discovered and worked around a real Wazuh reliability bug** —
  native Active Response dispatch was intermittently silent-failing
  (matches upstream issue [wazuh/wazuh#9370](https://github.com/wazuh/wazuh/issues/9370)).
  Engineered a direct-invocation containment architecture instead,
  proven 100% reliable across every subsequent test.
- **Auto-unblock timing validated accurate** — 618s and 622s measured
  against a 600-second configured timeout, across two independent
  live drills.
- **4 live drills executed**, culminating in a unified multi-stage
  incident (brute force → payload staging → C2 callback → automated
  containment) documented as a single continuous incident timeline.

---

## Repository Structure

```
threat-intel-integration/
├── README.md
├── architecture/
│   └── pipeline-architecture.md
├── enrichment-engine/
│   ├── src/
│   │   ├── config.py              — YAML config loader
│   │   ├── logger.py              — structured file + console logging
│   │   ├── cache.py                — SQLite caching layer (1hr TTL)
│   │   ├── enrichment.py          — core orchestration + verdict logic
│   │   ├── main.py                 — live alert watcher + direct-block
│   │   └── clients/
│   │       ├── abuseipdb_client.py
│   │       ├── otx_client.py       — IP + hash lookups
│   │       └── misp_client.py      — IP + hash lookups
│   ├── tests/                      — 19 automated pytest tests
│   ├── active-response/
│   │   ├── threat-intel-block.py   — native Wazuh AR script (documented)
│   │   └── threat-intel-cleanup.sh — cron-based reliable auto-unblock
│   ├── config/config.yaml.example
│   └── requirements.txt
├── detection-rules/
│   └── intel-rules.xml             — Rules 100012–100016
├── live-drills/
│   ├── drill-001-ssh-bruteforce-intel.md
│   ├── drill-002-hash-attribution.md
│   ├── drill-003-c2-callback-block.md
│   └── drill-004-multistage-attack-chain.md   ← flagship drill
├── detection-improvements/
│   └── rule-tuning-log.md
├── docs/
│   └── lessons-learned.md          ← full AR debugging story
└── screenshots/
```

---

## Live Drills

| Drill | Tests | Outcome |
|---|---|---|
| [Drill 1](live-drills/drill-001-ssh-bruteforce-intel.md) | SSH brute force + private-IP filtering | Correctly skipped enrichment on internal attacker IP |
| [Drill 2](live-drills/drill-002-hash-attribution.md) | Malware hash attribution (new capability) | CLEAN on real file, BLOCK on WannaCry reference hash |
| [Drill 3](live-drills/drill-003-c2-callback-block.md) | C2 callback + auto-block | Live 100/100 IP blocked in <1s, auto-unblocked at 622s |
| [Drill 4](live-drills/drill-004-multistage-attack-chain.md) | **Multi-stage kill chain** | Full incident: brute force → payload → C2 → automated containment |

---

## Lab Environment

Built on the [Home SOC Lab v2.0](https://github.com/iamahmedsalam/home-soc-lab) infrastructure, extended with a 5th VM:

| VM | IP | Role |
|---|---|---|
| Wazuh Manager | 192.168.56.101 | SIEM + enrichment engine |
| Windows 11 | 192.168.56.103 | Monitored endpoint (Sysmon) |
| Ubuntu Agent | 192.168.56.104 | Monitored endpoint (auditd) |
| Kali Linux | 192.168.56.50 | Attack machine |
| **MISP Server** | **192.168.56.105** | **Self-hosted threat intel (Docker)** |

Host machine upgraded to 64GB RAM specifically to support this 5-VM lab.

---

## Relationship to Prior Projects

| | Project 1 — Home SOC Lab | Project 2 — IR Playbooks | Project 3 — This Repo |
|---|---|---|---|
| **Focus** | Build detection | Respond to detections | Enrich & auto-contain |
| **Proves** | Can you detect? | Can you investigate? | Can you decide, automatically? |
| **Language** | Wazuh rules (XML) | Markdown playbooks | Production Python |

---

## About

**Ahmed Salam** — AI-Augmented SOC Analyst

- 🏆 TryHackMe Top 2% Globally (132 rooms, 30 badges)
- 🎓 CompTIA Security+ Certified
- 🌐 Portfolio: [iamahmedsalam.com](https://iamahmedsalam.com)
- 🐙 GitHub: [iamahmedsalam](https://github.com/iamahmedsalam)

---

## License

MIT License — see [LICENSE](LICENSE) for details.
