"""Cross-Source Event Correlation Engine for VERITAS-X."""
from datetime import datetime, timezone
from typing import List, Dict, Any
from pydantic import BaseModel, Field
from core.models import NormalizedEvent

class CorrelatedEventPair(BaseModel):
    correlation_id: str
    relationship_type: str  # temporally_related, host_cooccurrence, user_cooccurrence
    source_event_id: str
    target_event_id: str
    time_delta_seconds: float
    shared_host: str = ""
    shared_user: str = ""
    causation_established: bool = False
    notes: str = ""

class EventCorrelationEngine:
    """Detects temporal and identity relationships within bounded windows."""

    def __init__(self, max_window_seconds: float = 300.0):
        self.max_window_seconds = max_window_seconds

    @staticmethod
    def _parse_ts(ts_str: str) -> float:
        try:
            return datetime.fromisoformat(ts_str).timestamp()
        except Exception:
            return 0.0

    def correlate_events(
        self,
        events: List[NormalizedEvent],
        max_window: float = 300.0,
    ) -> List[CorrelatedEventPair]:
        """Correlate events sharing host or user within a temporal window."""
        results: List[CorrelatedEventPair] = []
        if len(events) < 2:
            return results

        # Sort chronologically
        sorted_events = sorted(events, key=lambda e: self._parse_ts(e.time.timestamp_utc))

        for i in range(len(sorted_events)):
            e1 = sorted_events[i]
            t1 = self._parse_ts(e1.time.timestamp_utc)

            for j in range(i + 1, len(sorted_events)):
                e2 = sorted_events[j]
                t2 = self._parse_ts(e2.time.timestamp_utc)
                delta = t2 - t1

                # If delta exceeds max window, break inner loop because sorted
                if delta > max_window:
                    break

                # Compare attributes
                same_host = (e1.host.hostname and e2.host.hostname and e1.host.hostname == e2.host.hostname)
                same_user = (e1.actor.username and e2.actor.username and e1.actor.username == e2.actor.username)
                different_types = (e1.event.type != e2.event.type)

                if (same_host or same_user) and different_types:
                    corr_id = f"corr_{e1.event_id[:8]}_{e2.event_id[:8]}"
                    notes = f"Event '{e1.event.type}' preceded '{e2.event.type}' by {delta:.1f}s"
                    if same_host:
                        notes += f" on host {e1.host.hostname}"

                    results.append(
                        CorrelatedEventPair(
                            correlation_id=corr_id,
                            relationship_type="temporally_related",
                            source_event_id=e1.event_id,
                            target_event_id=e2.event_id,
                            time_delta_seconds=round(delta, 2),
                            shared_host=e1.host.hostname or "",
                            shared_user=e1.actor.username or "",
                            causation_established=False,  # Proximity is not causation
                            notes=notes,
                        )
                    )

        return results

correlation_engine = EventCorrelationEngine()
