# VERITAS-X

Digital Investigation Intelligence & Evidence Verification Platform.

VERITAS-X is a local-first, modular digital forensics platform engineered around deterministic claim verification, evidence-gap intelligence, and immutable evidence custody.

## Core Capabilities
- **Local Evidence Vault:** Immutable raw evidence storage with pre- and post-acquisition SHA-256 verification.
- **Forensic Parsers:** Extract and normalize events from JSON, CSV, Sysmon/Windows EVTX, Linux auth logs, and USB history.
- **Evidence Gap Analysis (EGA):** Evaluates multi-source artifact completeness against declarative YAML investigation playbooks.
- **Claim-Aware Verification (CAV):** Evaluates atomic investigative claims using deterministic predicates, exposing supporting records, contradictions, and analytical limitations.
- **Cryptographic Audit Ledger:** SHA-256 hash-chained append-only record ensuring tamper-evident provenance.
- **Reproducible Reports:** Exports evidence-linked investigation reports with manifest hashing.

## Quick Start (Offline / Local Standalone)
1. Install Python 3.12 dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Start the application:
   ```bash
   uvicorn api.main:app --host 127.0.0.1 --port 8000
   ```
3. Open your browser to `http://127.0.0.1:8000/`.

## Running with Docker Compose
To launch with full OpenSearch and PostgreSQL services:
```bash
docker compose up -d
```

## Running Tests
```bash
pytest tests -v
```
