# VERITAS-X

### Digital Investigation Intelligence & Evidence Verification Platform
> *Trust the evidence. Verify the conclusion.*

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12+-green.svg)](https://www.python.org/)
[![Architecture](https://img.shields.io/badge/Architecture-Local--First%20%7C%20Air--Gapped-orange.svg)](#core-engineering-principles)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20Docker-lightgrey.svg)](#deployment-options)

---

## 1. Overview

**VERITAS-X** is an open-source, local-first digital forensics and evidence verification platform. Engineered for digital forensics incident response (DFIR) specialists, law enforcement investigators, and corporate security analysts, VERITAS-X addresses the critical flaws of modern forensic tooling: disconnected artifact silos, opaque analytical conclusions, and unverified AI hallucinations.

Unlike conversational chatbot interfaces with forensics bolted on, VERITAS-X is a dedicated investigative system. It ingests forensic disk and network logs, preserves evidence in an immutable vault, indexes normalized events, maps completeness against declarative playbooks, and deterministically validates atomic investigative claims against physical evidence records.

---

## 2. Core Engineering Principles

1. **Evidence Before AI:** The core engine operates deterministically without requiring an LLM or active internet connection.
2. **Local-First & Air-Gapped:** Sensitive forensic evidence never leaves the investigator's control or trusted network perimeter.
3. **Deterministic Verification:** Analytical conclusions are proven through strict predicate matching, SHA-256 hash chains, and source artifact locators.
4. **Transparent Uncertainty:** The absence of evidence in collected sources is never treated as proof of absence; missing artifacts are surfaced as explicit investigation gaps.
5. **Verifiable Reproducibility:** Every generated report, timeline, and claim assessment is bound to its exact input records, hash manifest, and transformation history.

---

## 3. Platform Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        VERITAS-X Forensic Suite                        │
│          Tactical Dark Interface · UTC Clock · Timeline Stream         │
│          Record Inspector · Radial Gap Ring · Claim Matrix             │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTP / REST APIs
┌───────────────────────────────────▼────────────────────────────────────┐
│                       FastAPI Application Layer                        │
│         Case Store · Investigation Router · Evidence Controller        │
└───────┬──────────────┬──────────────┬──────────────┬─────────────┬─────┘
        │              │              │              │             │
┌───────▼──────┐┌──────▼──────┐┌──────▼──────┐┌──────▼─────┐┌──────▼─────┐
│Evidence Vault││Parser Engine││  EGA Engine ││ CAV Engine ││Audit Ledger│
│Bit-Level Lock││EVTX/Auth/USB││ Gap Analysis││Verification││SHA-256 Chain│
│SHA-256 Checks││JSON/CSV/Log ││YAML Playbook││  Predicates││Tamper-Proof│
└──────────────┘└─────────────┘└─────────────┘└────────────┘└────────────┘
```

---

## 4. Key Capabilities

### 🔒 Immutable Local Evidence Vault
- **Pre- and Post-Acquisition Verification:** Calculates SHA-256 hashes immediately upon upload and verifies bit-level integrity before and after normalization.
- **Read-Only Enforced Storage:** Applies filesystem write protections to prevent accidental mutation or contamination of source evidence files.
- **Traceable Custody:** Maintains evidence source paths, file sizes, acquisition timestamps, and custody metadata for every ingested artifact.

### 🔍 Modular Forensic Parsers & Normalization
- **Binary Windows EVTX:** Directly parses native Windows `.evtx` binaries (Sysmon, Security, System logs) without requiring external Windows utilities.
- **Linux Security & Auth Logs:** Parses OpenSSH authentications, `sudo` elevations, and PAM events from `/var/log/auth.log` and `/var/log/secure`.
- **USB & Peripheral History:** Analyzes Windows `setupapi.dev.log` to reconstruct device insertion, vendor IDs, product IDs, and driver installation timestamps.
- **Structured Logs:** Automatically normalizes JSON lines, CSVs, and web server logs into canonical ISO 8601 UTC chronological records.

### 📊 Evidence Gap Analysis (EGA)
- **Declarative Playbooks:** Evaluates artifact collection completeness against standardized YAML investigation templates (e.g., *Ransomware Infection Lifecycle*, *USB Data Exfiltration*).
- **Weighted Requirement Coverage:** Calculates analytical confidence via:
  $$\text{Coverage Score} = \frac{\sum (w_i \cdot s_i)}{\sum w_i} \times 100$$
- **Categorized Completeness:** Explicitly groups requirements into `Observed`, `Partial`, `Not Found`, and `Not Collected` to highlight what evidence the investigator still needs to acquire.

### ⚖️ Claim-Aware Verification (CAV)
- **Atomic Hypothesis Testing:** Decomposes complex investigative theories into testable predicates (e.g., *“Suspect inserted unauthorized USB storage at 14:15 UTC”*).
- **Deterministic Evaluation:** Validates predicates directly against normalized records, citing exact artifact locators (file offset, event ID, line number).
- **Contradiction Detection:** Surfaces conflicting records and flags unverified claims with analytical limitation warnings and mandatory human review alerts.

### 📜 Append-Only Cryptographic Audit Ledger
- **SHA-256 Hash Chaining:** Every case creation, evidence acquisition, claim assessment, and report generation is cryptographically linked to the preceding entry:
  $$\text{Block Hash} = \text{SHA256}(\text{Index} \parallel \text{Timestamp} \parallel \text{Action} \parallel \text{PrevHash})$$
- **Automatic Tamper Detection:** Instantly verifies ledger integrity and exposes any retroactive modification or record deletion.

---

## 5. Deployment Options

### Option A: Standalone Portable Package (Zero Installation)
VERITAS-X is packaged as a completely independent, self-contained desktop package under `dist/VERITAS-X`:
1. Copy or extract the `dist/VERITAS-X` folder to any location (USB drive, forensic workstation, VM, or offline lab).
2. Double-click `VERITAS-X.exe` (or `Run-VERITAS-X.bat`).
3. The platform starts locally and opens `http://127.0.0.1:8000/` in your default browser.
*All case data, vaulted evidence, and database records remain isolated inside the copied folder.*

### Option B: Local Python Environment
1. Clone the repository:
   ```bash
   git clone https://github.com/Kaushiknr/VERITAS-X.git
   cd VERITAS-X
   ```
2. Install Python 3.12+ dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Launch the platform:
   ```bash
   python launcher.py
   # Or on Windows:
   VERITAS-X.bat
   ```
4. Access the workspace at `http://127.0.0.1:8000/`.

### Option C: Docker Compose (Full Stack)
To deploy with persistent OpenSearch and PostgreSQL backends:
```bash
docker compose up -d
```

---

## 6. Pre-Packaged Real-World Datasets

VERITAS-X includes authentic forensic evidence samples located in `data/real_datasets/`:
- `real_attack_sysmon_execution.evtx` — Binary Sysmon log capturing MITRE ATT&CK execution and LOLBin activity.
- `real_attack_sysmon_compiledhtml.evtx` — Binary EVTX log of Compiled HTML Help (`hh.exe`) attack execution.
- `real_openssh_auth.log` — Production OpenSSH authentication log with multi-source brute force attempts.
- `real_linux_system.log` — Enterprise Linux system event log.
- `real_windows_setupapi.log` — Windows device driver setup log detailing hardware and USB device connections.

To load pre-ingested test investigations with 1-click, click the **"Load Demo Investigation"** button in the top navigation bar.

---

## 7. Running Automated Tests

VERITAS-X includes comprehensive automated tests covering vault integrity, parsers, EGA, CAV, audit chains, and real binary EVTX extraction:

```bash
pytest tests -v
```

Expected test suite results:
```
tests/test_api.py::test_health_endpoint PASSED
tests/test_api.py::test_case_lifecycle PASSED
tests/test_audit.py::test_ledger_tamper_detection PASSED
tests/test_cav.py::test_claim_evaluation PASSED
tests/test_ega.py::test_evidence_gap_analysis PASSED
tests/test_parsers.py::test_json_parser PASSED
tests/test_parsers.py::test_sysmon_parser PASSED
tests/test_parsers.py::test_linux_auth_parser PASSED
tests/test_parsers.py::test_usb_parser PASSED
tests/test_real_datasets.py::test_parse_real_openssh_auth_log PASSED
tests/test_real_datasets.py::test_parse_real_linux_system_log PASSED
tests/test_real_datasets.py::test_parse_real_sysmon_binary_evtx PASSED
tests/test_real_datasets.py::test_parse_real_windows_setupapi_log PASSED
tests/test_schemas.py::test_canonical_event_schema PASSED
tests/test_vault.py::test_immutable_vault_storage PASSED
==================== 15 passed in 3.15s ====================
```

---

## 8. Investigation Playbooks

Investigation playbooks are defined as human-readable YAML documents under `playbooks/scenarios/`.

Example excerpt (`ransomware_activity.yaml`):
```yaml
id: playbook_ransomware_001
name: Ransomware Activity & Impact Analysis
description: Analyzes initial access, shadow copy deletion, file encryption, and ransom delivery.
requirements:
  - id: req_shadow_copy_deletion
    title: Shadow Copy Deletion (vssadmin / wmic)
    category: defense_evasion
    weight: 10
    predicates:
      - field: raw_data.CommandLine
        operator: contains
        value: "vssadmin delete shadows"
```

---

## 9. License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for details.
