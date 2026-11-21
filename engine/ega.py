"""Evidence Gap Analysis (EGA) Engine for VERITAS-X."""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from playbooks.schema import InvestigationPlaybook, EvidenceRequirement
from core.models import NormalizedEvent, CanonicalEvidence

class RequirementEvaluation(BaseModel):
    requirement_id: str
    label: str
    status: str  # observed, partial, not_found, not_collected, collection_unknown, conflicting, unverified
    weight: float
    score_contribution: float
    matching_event_ids: List[str] = Field(default_factory=list)
    missing_fields: List[str] = Field(default_factory=list)
    notes: str = ""

class EGAResult(BaseModel):
    case_id: str
    playbook_id: str
    playbook_name: str
    coverage_score: float  # 0.0 to 100.0
    evaluations: List[RequirementEvaluation]
    missing_sources: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    disclaimer: str = (
        "Evidence coverage measures artifact completeness against investigation requirements. "
        "It is NOT a probability of guilt or incident occurrence."
    )

class EvidenceGapAnalysisEngine:
    """Analyzes evidence presence, partiality, gaps, and recommendations."""

    CONTRIBUTION_WEIGHTS = {
        "observed": 1.0,
        "partial": 0.5,
        "not_found": 0.0,
        "not_collected": 0.0,
        "collection_unknown": 0.0,
        "unverified": 0.0,
        "conflicting": 0.0,
    }

    def evaluate_field_presence(self, event: NormalizedEvent, field_path: str) -> bool:
        """Check if a nested field exists and is non-empty on the event."""
        parts = field_path.split(".")
        current = event.model_dump()
        for part in parts:
            if not isinstance(current, dict) or part not in current:
                return False
            current = current[part]
        return current is not None and current != ""

    def evaluate_coverage(
        self,
        case_id: str,
        playbook: InvestigationPlaybook,
        events: List[NormalizedEvent],
        collected_evidence: List[CanonicalEvidence],
    ) -> EGAResult:
        """Run complete evidence gap analysis against playbook requirements."""
        pb = playbook.playbook
        evaluations: List[RequirementEvaluation] = []

        # Identify collected formats/sources
        collected_formats = set()
        for ev in collected_evidence:
            fmt = ev.identity.file_type.lower()
            collected_formats.add(fmt)
            if ev.processing.parser != "unknown":
                collected_formats.add(ev.processing.parser.lower())

        total_weighted_points = 0.0
        total_max_points = 0.0
        missing_sources = []

        # Check required sources
        for req_src in pb.required_sources:
            # Check if any evidence or parser matches the required source
            matched = any(req_src.lower() in str(fmt) for fmt in collected_formats)
            if not matched and not events:
                missing_sources.append(req_src)

        for req in pb.evidence_requirements:
            w = req.weight
            total_max_points += w

            # Search matching events
            matching_events = [e for e in events if e.event.type in req.event_types or e.event.action in req.event_types]

            if not matching_events:
                # Distinguish Not Collected vs Not Found
                is_source_missing = bool(missing_sources)
                status = "not_collected" if is_source_missing else "not_found"
                contrib = self.CONTRIBUTION_WEIGHTS[status]
                evaluations.append(
                    RequirementEvaluation(
                        requirement_id=req.id,
                        label=req.label,
                        status=status,
                        weight=w,
                        score_contribution=contrib,
                        matching_event_ids=[],
                        missing_fields=req.required_fields,
                        notes=f"No events found matching event types {req.event_types}",
                    )
                )
                total_weighted_points += w * contrib
                continue

            # We have matching events. Check if required fields are satisfied
            fully_valid_events = []
            partial_events = []
            all_missing_fields = set()

            for evt in matching_events:
                missing_in_evt = [f for f in req.required_fields if not self.evaluate_field_presence(evt, f)]
                if not missing_in_evt:
                    fully_valid_events.append(evt.event_id)
                else:
                    partial_events.append(evt.event_id)
                    all_missing_fields.update(missing_in_evt)

            if fully_valid_events:
                status = "observed"
                contrib = self.CONTRIBUTION_WEIGHTS["observed"]
                notes = f"Observed {len(fully_valid_events)} fully validated record(s)"
                matching_ids = fully_valid_events
            else:
                status = "partial"
                contrib = self.CONTRIBUTION_WEIGHTS["partial"]
                notes = f"Found {len(partial_events)} event(s) with missing fields: {list(all_missing_fields)}"
                matching_ids = partial_events

            total_weighted_points += w * contrib
            evaluations.append(
                RequirementEvaluation(
                    requirement_id=req.id,
                    label=req.label,
                    status=status,
                    weight=w,
                    score_contribution=contrib,
                    matching_event_ids=matching_ids,
                    missing_fields=list(all_missing_fields),
                    notes=notes,
                )
            )

        # Calculate coverage percentage: (sum(w_i * s_i) / sum(w_i)) * 100
        coverage_score = 0.0
        if total_max_points > 0:
            coverage_score = round((total_weighted_points / total_max_points) * 100.0, 2)

        # Generate targeted recommendations based on missing or partial requirements
        recommendations = []
        for eval_item in evaluations:
            if eval_item.status in ("not_found", "not_collected", "partial"):
                trigger_name = f"missing_{eval_item.requirement_id}"
                for rec in pb.recommendations:
                    if rec.trigger == trigger_name:
                        recommendations.append(rec.action.strip())

        return EGAResult(
            case_id=case_id,
            playbook_id=pb.id,
            playbook_name=pb.name,
            coverage_score=coverage_score,
            evaluations=evaluations,
            missing_sources=missing_sources,
            recommendations=recommendations,
        )

ega_engine = EvidenceGapAnalysisEngine()
