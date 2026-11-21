"""Authoritative Case and Claim Storage for VERITAS-X with SQLite/Postgres Dual Mode."""
import sqlite3
import json
from pathlib import Path
from typing import List, Optional, Dict, Any
from core.config import settings
from core.models import Case, Claim, ClaimAssessment, CanonicalEvidence, generate_utc_timestamp

class CaseStore:
    """Manages transactional state for cases, evidence registrations, and claims."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or (settings.vault_path.parent / "db" / "veritas_metadata.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                case_type TEXT,
                timezone TEXT,
                status TEXT,
                created_at TEXT,
                updated_at TEXT
            );
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                case_id TEXT,
                data TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(case_id)
            );
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS claims (
                claim_id TEXT PRIMARY KEY,
                case_id TEXT,
                statement TEXT,
                claim_type TEXT,
                subject TEXT,
                object TEXT,
                target_device TEXT,
                created_at TEXT,
                FOREIGN KEY (case_id) REFERENCES cases(case_id)
            );
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS assessments (
                assessment_id TEXT PRIMARY KEY,
                claim_id TEXT,
                data TEXT NOT NULL,
                assessed_at TEXT,
                FOREIGN KEY (claim_id) REFERENCES claims(claim_id)
            );
            """)
            conn.commit()

    # Cases
    def create_case(self, case: Case) -> Case:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO cases VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (case.case_id, case.title, case.description, case.case_type, case.timezone, case.status, case.created_at, case.updated_at)
            )
            conn.commit()
        return case

    def get_case(self, case_id: str) -> Optional[Case]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
            row = cursor.fetchone()
            if row:
                return Case(**dict(row))
        return None

    def list_cases(self) -> List[Case]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cases ORDER BY created_at DESC")
            rows = cursor.fetchall()
            return [Case(**dict(r)) for r in rows]

    def update_case(self, case_id: str, updates: Dict[str, Any]) -> Optional[Case]:
        case = self.get_case(case_id)
        if not case:
            return None
        data = case.model_dump()
        data.update(updates)
        data["updated_at"] = generate_utc_timestamp()
        updated_case = Case(**data)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE cases SET title=?, description=?, case_type=?, timezone=?, status=?, updated_at=? WHERE case_id=?",
                (updated_case.title, updated_case.description, updated_case.case_type, updated_case.timezone, updated_case.status, updated_case.updated_at, case_id)
            )
            conn.commit()
        return updated_case

    # Evidence
    def register_evidence(self, evidence: CanonicalEvidence) -> CanonicalEvidence:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO evidence (evidence_id, case_id, data) VALUES (?, ?, ?)",
                (evidence.evidence_id, evidence.case_id, json.dumps(evidence.model_dump()))
            )
            conn.commit()
        return evidence

    def list_case_evidence(self, case_id: str) -> List[CanonicalEvidence]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM evidence WHERE case_id = ?", (case_id,))
            rows = cursor.fetchall()
            return [CanonicalEvidence(**json.loads(r["data"])) for r in rows]

    def get_evidence(self, evidence_id: str) -> Optional[CanonicalEvidence]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM evidence WHERE evidence_id = ?", (evidence_id,))
            row = cursor.fetchone()
            if row:
                return CanonicalEvidence(**json.loads(row["data"]))
        return None

    # Claims
    def create_claim(self, claim: Claim) -> Claim:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO claims VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (claim.claim_id, claim.case_id, claim.statement, claim.claim_type, claim.subject, claim.object, claim.target_device, claim.created_at)
            )
            conn.commit()
        return claim

    def get_claim(self, claim_id: str) -> Optional[Claim]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM claims WHERE claim_id = ?", (claim_id,))
            row = cursor.fetchone()
            if row:
                return Claim(**dict(row))
        return None

    def list_claims(self, case_id: str) -> List[Claim]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM claims WHERE case_id = ? ORDER BY created_at DESC", (case_id,))
            rows = cursor.fetchall()
            return [Claim(**dict(r)) for r in rows]

    # Assessments
    def save_assessment(self, assessment: ClaimAssessment) -> ClaimAssessment:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO assessments (assessment_id, claim_id, data, assessed_at) VALUES (?, ?, ?, ?)",
                (assessment.assessment_id, assessment.claim_id, json.dumps(assessment.model_dump()), assessment.assessed_at)
            )
            conn.commit()
        return assessment

    def list_assessments(self, claim_id: str) -> List[ClaimAssessment]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM assessments WHERE claim_id = ? ORDER BY assessed_at DESC", (claim_id,))
            rows = cursor.fetchall()
            return [ClaimAssessment(**json.loads(r["data"])) for r in rows]

case_store = CaseStore()
