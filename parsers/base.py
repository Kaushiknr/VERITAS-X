"""Base Parser Interface for VERITAS-X."""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any, Optional
from core.models import NormalizedEvent

class BaseParser(ABC):
    """Abstract interface that all forensic artifact parsers must implement."""

    name: str = "base_parser"
    version: str = "1.0.0"
    supported_formats: List[str] = []

    @abstractmethod
    def can_parse(self, file_path: Path, filename: str) -> bool:
        """Evaluate whether this parser can process the given file."""
        pass

    @abstractmethod
    def parse(
        self,
        file_path: Path,
        case_id: str,
        evidence_id: str,
        extraction_run_id: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> List[NormalizedEvent]:
        """Parse source evidence into canonical normalized events."""
        pass
