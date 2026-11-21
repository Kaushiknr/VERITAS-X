# VERITAS-X: Project State & Continuous Execution Record

## 1. Project Objective
VERITAS-X is an open-source, local-first digital forensic investigation platform featuring evidence-gap intelligence, deterministic claim verification, and a modern, high-grade forensic analysis interface.

## 2. Architecture & Design Decisions
- **Executable Package:** Standalone Windows native executable (`dist/VERITAS-X/VERITAS-X.exe`) and double-clickable batch launcher (`VERITAS-X.bat`) created for zero-terminal, single-click operation.
- **Desktop Shortcut:** Created on Windows Desktop (`VERITAS-X Forensics.lnk`).
- **Forensic UI Suite:** State-of-the-art dark theme interface inspired by enterprise forensic intelligence tools (Exterro FTK, Magnet AXIOM, Palantir). Includes:
  - Live UTC master clock & real-time telemetry KPI widgets.
  - Interactive activity density stream and timeline node cards.
  - 1-Click "Load Demo Investigation" seeder (`Operation Aegis`).
  - Forensic Record Inspector modal for raw JSON and source locator analysis.
  - Interactive Evidence Gap Analysis (EGA) matrix with radial completion ring.
  - Claim-Aware Verification (CAV) assessment cards with predicate tags, contradiction flags, and human review notices.
  - Cryptographic append-only hash-chained audit ledger inspector.
- **Backend:** FastAPI + Python 3.12 + Pydantic v2 + SQLite / PostgreSQL dual-mode.
- **Evidence Vault:** Bit-level immutable storage with SHA-256 baseline verification.

## 3. Test & Verification
- 15/15 pytest automated tests passing (including real OpenSSH and binary Sysmon EVTX attack logs).
- Standalone executable compiled and verified.
