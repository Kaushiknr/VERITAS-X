"""Modular AI Provider Interface for VERITAS-X."""
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

class AIProvider(ABC):
    """Abstract interface for optional AI assistance."""

    @abstractmethod
    def decompose_claim(self, question: str) -> Dict[str, Any]:
        """Decompose a natural language investigative query into atomic claim predicates."""
        pass

    @abstractmethod
    def explain_findings(self, claim_statement: str, assessment_status: str, limitations: List[str]) -> str:
        """Provide a plain-language summary of deterministic verification findings."""
        pass

    @abstractmethod
    def summarize_timeline(self, events: List[Dict[str, Any]]) -> str:
        """Generate a concise narrative overview of a sequence of events."""
        pass

class NoAIProvider(AIProvider):
    """Default zero-dependency deterministic provider requiring no LLM or network."""

    def decompose_claim(self, question: str) -> Dict[str, Any]:
        return {
            "statement": question,
            "claim_type": "general_investigation",
            "subject": None,
            "object": None,
            "target_device": None,
            "provider": "deterministic_rule_extractor",
        }

    def explain_findings(self, claim_statement: str, assessment_status: str, limitations: List[str]) -> str:
        explanation = (
            f"Deterministic Assessment for claim: '{claim_statement}'.\n"
            f"Result: {assessment_status.upper().replace('_', ' ')}.\n"
        )
        if limitations:
            explanation += "Key Forensic Observations:\n" + "\n".join(f"- {l}" for l in limitations)
        else:
            explanation += "All required forensic predicates were satisfied by available evidence."
        return explanation

    def summarize_timeline(self, events: List[Dict[str, Any]]) -> str:
        if not events:
            return "No chronological events recorded for this timeline."
        first_ts = events[0].get("time", {}).get("timestamp_utc", "N/A")
        last_ts = events[-1].get("time", {}).get("timestamp_utc", "N/A")
        return (
            f"Investigation timeline encompasses {len(events)} normalized records "
            f"spanning from {first_ts} to {last_ts}."
        )

def get_ai_provider() -> AIProvider:
    """Factory to retrieve configured AI provider (defaults to NoAIProvider)."""
    return NoAIProvider()
