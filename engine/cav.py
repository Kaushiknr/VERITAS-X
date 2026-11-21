"""Claim-Aware Verification (CAV) Engine for VERITAS-X."""
import hashlib
from typing import List, Dict, Any, Optional
from core.models import Claim, ClaimAssessment, NormalizedEvent, generate_utc_timestamp
from playbooks.schema import InvestigationPlaybook, PlaybookClaim

class ClaimVerificationEngine:
    """Evaluates investigative claims using deterministic predicates and contradiction checks."""

    RULE_VERSION = "1.0.0"

    def verify_claim(
        self,
        claim: Claim,
        playbook: InvestigationPlaybook,
        events: List[NormalizedEvent],
    ) -> ClaimAssessment:
        """Deterministically assess a claim against events and playbook rules."""
        assessment_id = f"assessment_{hashlib.sha256(f'{claim.claim_id}:{claim.statement}'.encode()).hexdigest()[:12]}"
        supporting_events: List[str] = []
        contradicting_events: List[str] = []
        unresolved: List[str] = []
        limitations: List[str] = []

        pb = playbook.playbook
        # Match target playbook claim definition
        matched_pb_claim: Optional[PlaybookClaim] = None
        for pbc in pb.claims:
            if pbc.id == claim.claim_type or pbc.id in claim.statement.lower():
                matched_pb_claim = pbc
                break
        if not matched_pb_claim and pb.claims:
            matched_pb_claim = pb.claims[0]

        required_preds = matched_pb_claim.required_predicates if matched_pb_claim else ["evidence_present"]
        corrob_preds = matched_pb_claim.corroboration_predicates if matched_pb_claim else []

        # Build requirement mapping from playbook
        req_types_map = {r.id: r.event_types for r in pb.evidence_requirements}

        # Check each required predicate
        for pred in required_preds:
            satisfied = False
            target_types = req_types_map.get(pred, [pred])

            for evt in events:
                # Custom predicate checks
                if pred == "usb_connection":
                    if evt.device.type == "usb" or "usb" in evt.event.type or "usb" in evt.event.action:
                        if not claim.target_device or (evt.device.identifier and claim.target_device in evt.device.identifier):
                            supporting_events.append(evt.event_id)
                            satisfied = True
                elif pred == "sensitive_file_access":
                    if "file" in evt.event.category or "file" in evt.event.type:
                        if not claim.object or (evt.file.name and claim.object.lower() in evt.file.name.lower()) or (evt.file.path and claim.object.lower() in evt.file.path.lower()):
                            supporting_events.append(evt.event_id)
                            satisfied = True
                elif pred == "removable_media_write":
                    if evt.event.type in ("removable_media_write", "file_create", "write"):
                        if not claim.object or (evt.file.name and claim.object.lower() in evt.file.name.lower()):
                            supporting_events.append(evt.event_id)
                            satisfied = True
                elif evt.event.type in target_types or evt.event.action in target_types:
                    supporting_events.append(evt.event_id)
                    satisfied = True

            if not satisfied:
                unresolved.append(pred)

        # Check corroboration predicates
        for pred in corrob_preds:
            target_types = req_types_map.get(pred, [pred])
            for evt in events:
                if pred == "destination_hash":
                    if evt.file.sha256:
                        supporting_events.append(evt.event_id)
                elif evt.event.type in target_types or evt.event.action in target_types:
                    supporting_events.append(evt.event_id)

        # Deduplicate evidence IDs
        supporting_events = list(dict.fromkeys(supporting_events))

        # Check for contradictions
        if claim.subject:
            conflicting_user_events = [
                e.event_id for e in events
                if e.actor.username and e.actor.username.lower() != claim.subject.lower()
                and (e.event_id in supporting_events)
            ]
            if conflicting_user_events and not any(e.actor.username and e.actor.username.lower() == claim.subject.lower() for e in events):
                contradicting_events.extend(conflicting_user_events)
                limitations.append(f"Recorded activity is attributed to a different user, not '{claim.subject}'.")

        # Determine CAV status
        has_support = len(supporting_events) > 0
        has_contradiction = len(contradicting_events) > 0
        all_required_met = len(unresolved) == 0

        if has_support and has_contradiction:
            status = "conflicting"
            limitations.append("Material supporting and contradictory evidence are both present.")
        elif has_contradiction and not has_support:
            status = "contradicted"
            limitations.append("Direct contradictory records refute the claim.")
        elif all_required_met and has_support:
            status = "supported"
        elif has_support and not all_required_met:
            status = "partially_supported"
            limitations.append(f"Missing required forensic predicates: {', '.join(unresolved)}.")
        else:
            status = "insufficient_evidence"
            limitations.append("Available forensic records do not substantiate the claim predicates.")

        if "removable_media_write" in unresolved:
            limitations.append("No direct write event to removable storage was observed in captured logs.")

        return ClaimAssessment(
            claim_id=claim.claim_id,
            assessment_id=assessment_id,
            status=status,
            supporting_evidence=supporting_events,
            contradicting_evidence=contradicting_events,
            unresolved_requirements=unresolved,
            limitations=limitations,
            verification_rule_version=self.RULE_VERSION,
            requires_human_review=True,
            assessed_at=generate_utc_timestamp(),
        )

cav_engine = ClaimVerificationEngine()
