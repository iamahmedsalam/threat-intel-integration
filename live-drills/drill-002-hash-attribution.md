# Drill 2 — Malware Hash Attribution

## Alert Summary

| Field | Value |
|---|---|
| **Drill ID** | Drill-002 (Project 3) |
| **Date** | August 11, 2026 |
| **Rule Triggered** | 100008 (Level 10) — file dropped in Temp/AppData |
| **MITRE ATT&CK** | T1105 — Ingress Tool Transfer |
| **Agent** | WIN11-SOC-Endpoint (Agent 001 — 192.168.56.103) |
| **New Capability Tested** | Hash-lookup enrichment (`check_hash()` — OTX + MISP) |
| **Verdict** | True Positive detection; hash attribution correctly distinguishes benign from known-malicious |

---

## What This Drill Tests

Whether the enrichment engine's file-hash lookup capability (built
specifically for this drill — `OTXClient.check_hash()`,
`MISPClient.check_hash()`, `EnrichmentEngine.enrich_hash()`) produces
correct, defensible verdicts on both a genuinely benign file and a
known-malicious reference hash, using the *same* code path.

---

## Attack Execution

Reused the LOLBIN payload-staging technique from Project 2's Drill 005
— `certutil -encode` used to disguise a file as an executable in the
Windows Temp directory:

```powershell
echo "This is a simulated malware payload for Project 3 hash attribution testing - T1105" > C:\Users\Public\payload-source.txt
certutil -encode C:\Users\Public\payload-source.txt C:\Users\Jackal\AppData\Local\Temp\svc-update.exe
```

Rule 100008 fired correctly, confirming the file-drop detection was
unaffected by this project's changes.

**Real file hash extracted:**
```
SHA256: b5f563782e79ee9896710cbae4934d3ba0eeaaf6c0486e836572501eaf23fb66
```

---

## Hash Enrichment Results

### Case 1 — The Actual Dropped File (Real Hash, Benign Content)

```
[CLEAN] Hash: b5f56378...23fb66
  OTX Pulses: 0
  MISP Match: False
  Sources responding: 2/2
```

**Analysis:** Correct. This is a freshly-generated test file with no
prior existence anywhere — it has no threat-intelligence history by
definition. Both sources responded successfully and correctly
reported no matches. This is the desired outcome: the pipeline did
not produce a false positive on benign content.

### Case 2 — Reference Comparison (Known WannaCry SHA256)

To prove the attribution capability actually works when a hash *is*
known-malicious, the same code path was run against a well-documented
public malware hash (WannaCry ransomware):

```
[BLOCK] Hash: ed01ebfb...3841aa (Reference: WannaCry SHA256)
  OTX Pulses: 50
  MISP Match: True
  Sources responding: 2/2
  Sample OTX pulse names:
    - "Broken Seal" DocuSign-themed Delivery with Fileless Process
       Hollowing (Zeppelin/Bloat-A)
    - WannaCry linked Lazarus indicators
    - WanaCrypt0r Ransomworm
  MISP event IDs: [623, 625, 626]
```

**Analysis:** Correct. Real, well-corroborated attribution — 50 OTX
pulses referencing known ransomware campaigns, 3 independent MISP
events. This confirms the hash-lookup pipeline correctly identifies
genuine threats when they exist.

---

## Comparison Table

| | Dropped File Hash | WannaCry Reference Hash |
|---|---|---|
| Verdict | **CLEAN** | **BLOCK** |
| OTX Pulses | 0 | 50 |
| MISP Match | False | True (events 623, 625, 626) |
| Interpretation | Unknown/benign, no threat history | Confirmed ransomware, multi-source corroboration |

---

## An Honest Finding: The Empty-Hash False Positive

During development of the hash-lookup capability (prior to this
drill), an unrelated test against the SHA256 of an *empty file*
(`e3b0c442...`, a universal "null hash") returned unexpected
**matches** from both OTX and MISP. Investigation confirmed this is
not a bug: both sources independently reference this hash in
sandbox-analysis pulses, because automated malware-analysis tools
occasionally submit corrupted or empty samples and log the resulting
(coincidental) hash as an "indicator." Confirmed via completely
different pulse names and MISP event IDs than the WannaCry case —
proving it's a real, cross-source, industry-known false-positive
pattern rather than a caching or code error. Documented here as a
detection-engineering finding worth knowing before deploying
hash-based blocking in production.

---

## Verdict & Classification

| Field | Value |
|---|---|
| Wazuh Detection | True Positive — Rule 100008 fired correctly |
| Hash Attribution (dropped file) | Correct — CLEAN, no false positive |
| Hash Attribution (reference) | Correct — BLOCK with real, corroborated attribution |
| New capability validated | `check_hash()` on both OTX and MISP clients, 4 automated pytest tests passing |

---

## Simulation Context

The file-drop technique and detection are real (Rule 100008 fired on
an actual dropped file with a real hash). The WannaCry reference check
is explicitly labelled as a comparison case using a well-documented
public hash — not claimed to have been found on this endpoint — to
demonstrate what a positive attribution result looks like using the
identical code path.
