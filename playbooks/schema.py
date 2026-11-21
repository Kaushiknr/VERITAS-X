"""Playbook Schema and Loader for VERITAS-X."""
from pathlib import Path
from typing import List, Dict, Any, Optional
import yaml
from pydantic import BaseModel, Field
from core.config import settings

class EvidenceRequirement(BaseModel):
    id: str
    label: str
    event_types: List[str]
    required_fields: List[str] = Field(default_factory=list)
    weight: float = 1.0

class VerificationPolicy(BaseModel):
    mode: str = "deterministic"
    missing_data: str = "insufficient"
    conflicting_data: str = "conflicting"
    human_review: bool = True

class PlaybookClaim(BaseModel):
    id: str
    statement: str
    required_predicates: List[str]
    corroboration_predicates: List[str] = Field(default_factory=list)
    refutation_rules: List[Dict[str, Any]] = Field(default_factory=list)
    verification_policy: VerificationPolicy = Field(default_factory=VerificationPolicy)

class Recommendation(BaseModel):
    trigger: str
    action: str

class PlaybookDetail(BaseModel):
    id: str
    version: str = "1.0.0"
    name: str
    category: str
    description: str
    required_sources: List[str]
    evidence_requirements: List[EvidenceRequirement]
    claims: List[PlaybookClaim]
    recommendations: List[Recommendation] = Field(default_factory=list)

class InvestigationPlaybook(BaseModel):
    schema_version: str = "1.0.0"
    playbook: PlaybookDetail

class PlaybookLoader:
    """Discovers, validates and loads YAML investigation playbooks."""

    def __init__(self, directory: Optional[Path] = None):
        self.directory = directory or settings.playbooks_path
        self.directory.mkdir(parents=True, exist_ok=True)

    def load_playbook_file(self, file_path: Path) -> InvestigationPlaybook:
        """Parse and validate a single YAML playbook."""
        with open(file_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        return InvestigationPlaybook(**raw)

    def list_playbooks(self) -> List[InvestigationPlaybook]:
        """Scan directory and return all valid playbooks."""
        playbooks = []
        for file in self.directory.glob("*.yaml"):
            try:
                playbooks.append(self.load_playbook_file(file))
            except Exception as e:
                print(f"Failed to load playbook {file.name}: {e}")
        return playbooks

    def get_playbook(self, playbook_id: str) -> Optional[InvestigationPlaybook]:
        """Retrieve a playbook by identifier."""
        for p in self.list_playbooks():
            if p.playbook.id == playbook_id:
                return p
        return None

playbook_loader = PlaybookLoader()
