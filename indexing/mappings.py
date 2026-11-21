"""Strict OpenSearch Mappings for VERITAS-X."""
from typing import Dict, Any

EVENTS_INDEX_NAME = "veritas-events-v1"
EVIDENCE_INDEX_NAME = "veritas-evidence-v1"
CORRELATIONS_INDEX_NAME = "veritas-correlations-v1"
CLAIMS_INDEX_NAME = "veritas-claims-v1"
AUDIT_INDEX_NAME = "veritas-audit-v1"

EVENTS_MAPPING: Dict[str, Any] = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
    },
    "mappings": {
        "dynamic": "strict",
        "properties": {
            "event_id": { "type": "keyword" },
            "schema_version": { "type": "keyword" },
            "case_id": { "type": "keyword" },
            "evidence_id": { "type": "keyword" },
            "event": {
                "properties": {
                    "type": { "type": "keyword" },
                    "category": { "type": "keyword" },
                    "action": { "type": "keyword" },
                    "outcome": { "type": "keyword" }
                }
            },
            "time": {
                "properties": {
                    "timestamp_utc": { "type": "date" },
                    "original": { "type": "keyword" },
                    "timezone": { "type": "keyword" },
                    "precision": { "type": "keyword" }
                }
            },
            "actor": {
                "properties": {
                    "user_id": { "type": "keyword" },
                    "username": { "type": "keyword" }
                }
            },
            "host": {
                "properties": {
                    "hostname": { "type": "keyword" },
                    "device_id": { "type": "keyword" }
                }
            },
            "file": {
                "properties": {
                    "name": { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
                    "path": { "type": "keyword", "ignore_above": 2048 },
                    "sha256": { "type": "keyword" }
                }
            },
            "device": {
                "properties": {
                    "type": { "type": "keyword" },
                    "identifier": { "type": "keyword" }
                }
            },
            "process": {
                "properties": {
                    "name": { "type": "keyword" },
                    "pid": { "type": "long" },
                    "parent_pid": { "type": "long" }
                }
            },
            "network": {
                "properties": {
                    "source_ip": { "type": "ip" },
                    "destination_ip": { "type": "ip" },
                    "destination_port": { "type": "integer" }
                }
            },
            "source": {
                "properties": {
                    "format": { "type": "keyword" },
                    "parser": { "type": "keyword" },
                    "parser_version": { "type": "keyword" },
                    "record_locator": { "type": "keyword" }
                }
            },
            "provenance": {
                "properties": {
                    "extraction_run_id": { "type": "keyword" },
                    "normalization_version": { "type": "keyword" }
                }
            }
        }
    }
}

EVIDENCE_MAPPING: Dict[str, Any] = {
    "mappings": {
        "dynamic": "strict",
        "properties": {
            "evidence_id": { "type": "keyword" },
            "case_id": { "type": "keyword" },
            "original_filename": { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
            "file_type": { "type": "keyword" },
            "size_bytes": { "type": "long" },
            "original_sha256": { "type": "keyword" },
            "stored_sha256": { "type": "keyword" },
            "integrity_status": { "type": "keyword" },
            "acquired_by": { "type": "keyword" },
            "acquired_at": { "type": "date" },
            "source_system": { "type": "keyword" },
            "parser": { "type": "keyword" },
            "parser_version": { "type": "keyword" },
            "processing_status": { "type": "keyword" }
        }
    }
}
