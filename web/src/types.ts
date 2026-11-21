export interface Case {
  case_id: string;
  title: string;
  description: string;
  case_type: string;
  timezone: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface CanonicalEvidence {
  evidence_id: string;
  case_id: string;
  identity: {
    original_filename: string;
    file_type: string;
    size_bytes: number;
  };
  acquisition: {
    acquired_at: string;
    acquired_by: string;
    source_system: string;
    acquisition_method: string;
    original_sha256: string;
  };
  storage: {
    object_id: string;
    stored_sha256: string;
    read_only: boolean;
  };
  processing: {
    status: string;
    parser: string;
    parser_version: string;
    processed_at?: string;
  };
  integrity: {
    status: string;
    verification_method: string;
    verified_at: string;
  };
  provenance: {
    source_record_count: number;
    derived_record_count: number;
  };
}

export interface NormalizedEvent {
  event_id: string;
  case_id: string;
  evidence_id: string;
  event: {
    type: string;
    category: string;
    action: string;
    outcome: string;
  };
  time: {
    original: string;
    timezone?: string;
    timestamp_utc: string;
    precision: string;
  };
  actor: {
    user_id?: string;
    username?: string;
  };
  host: {
    hostname?: string;
    device_id?: string;
  };
  file: {
    name?: string;
    path?: string;
    sha256?: string;
  };
  device: {
    type?: string;
    identifier?: string;
  };
  process: {
    name?: string;
    pid?: number;
    parent_pid?: number;
  };
  network: {
    source_ip?: string;
    destination_ip?: string;
    destination_port?: number;
  };
  source: {
    format: string;
    parser: string;
    parser_version: string;
    record_locator: string;
  };
}

export interface RequirementEvaluation {
  requirement_id: string;
  label: string;
  status: 'observed' | 'partial' | 'not_found' | 'not_collected' | 'collection_unknown' | 'conflicting';
  weight: number;
  score_contribution: number;
  matching_event_ids: string[];
  missing_fields: string[];
  notes: string;
}

export interface EGAResult {
  case_id: string;
  playbook_id: string;
  playbook_name: string;
  coverage_score: number;
  evaluations: RequirementEvaluation[];
  missing_sources: string[];
  recommendations: string[];
  disclaimer: string;
}

export interface Claim {
  claim_id: string;
  case_id: string;
  statement: string;
  claim_type: string;
  subject?: string;
  object?: string;
  target_device?: string;
  created_at: string;
}

export interface ClaimAssessment {
  claim_id: string;
  assessment_id: string;
  status: 'supported' | 'partially_supported' | 'insufficient_evidence' | 'contradicted' | 'conflicting' | 'unverified';
  supporting_evidence: string[];
  contradicting_evidence: string[];
  unresolved_requirements: string[];
  limitations: string[];
  verification_rule_version: string;
  requires_human_review: boolean;
  assessed_at: string;
}

export interface CorrelatedPair {
  correlation_id: string;
  relationship_type: string;
  source_event_id: string;
  target_event_id: string;
  time_delta_seconds: number;
  shared_host: string;
  shared_user: string;
  causation_established: boolean;
  notes: string;
}

export interface AuditEvent {
  audit_id: string;
  case_id: string;
  actor_id: string;
  action: string;
  target_id: string;
  timestamp_utc: string;
  result: string;
  previous_record_hash: string;
  record_hash: string;
  details: Record<string, any>;
}

export interface PlaybookMeta {
  id: string;
  version: string;
  name: string;
  category: string;
  description: string;
  required_sources: string[];
}
