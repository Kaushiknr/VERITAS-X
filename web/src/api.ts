import {
  Case,
  CanonicalEvidence,
  NormalizedEvent,
  EGAResult,
  Claim,
  ClaimAssessment,
  CorrelatedPair,
  AuditEvent,
  PlaybookMeta,
} from './types';

const API_BASE = '/api/v1';

async function fetchJSON<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, options);
  const data = await res.json();
  if (!res.ok || data.success === false) {
    const errorMsg = data?.error?.message || `HTTP ${res.status}: ${res.statusText}`;
    throw new Error(errorMsg);
  }
  return data.data as T;
}

export const api = {
  // System Health
  async getHealth() {
    return fetchJSON<any>(`${API_BASE}/health`);
  },

  // Cases
  async listCases(): Promise<Case[]> {
    return fetchJSON<Case[]>(`${API_BASE}/cases`);
  },

  async createCase(data: { title: string; description: string; case_type: string; timezone: string }): Promise<Case> {
    return fetchJSON<Case>(`${API_BASE}/cases`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
  },

  // Evidence
  async listEvidence(caseId: string): Promise<CanonicalEvidence[]> {
    return fetchJSON<CanonicalEvidence[]>(`${API_BASE}/cases/${caseId}/evidence`);
  },

  async uploadEvidence(caseId: string, file: File, acquiredBy: string = 'investigator_001'): Promise<any> {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('acquired_by', acquiredBy);
    return fetchJSON<any>(`${API_BASE}/cases/${caseId}/evidence`, {
      method: 'POST',
      body: formData,
    });
  },

  async verifyEvidence(evidenceId: string): Promise<any> {
    return fetchJSON<any>(`${API_BASE}/evidence/${evidenceId}/verify`, {
      method: 'POST',
    });
  },

  async reprocessEvidence(evidenceId: string): Promise<any> {
    return fetchJSON<any>(`${API_BASE}/evidence/${evidenceId}/reprocess`, {
      method: 'POST',
    });
  },

  // Investigations & Timeline
  async getTimeline(caseId: string): Promise<{ total_events: number; events: NormalizedEvent[] }> {
    return fetchJSON<{ total_events: number; events: NormalizedEvent[] }>(`${API_BASE}/investigations/${caseId}/timeline`);
  },

  async searchEvents(caseId: string, q?: string, eventType?: string): Promise<NormalizedEvent[]> {
    const params = new URLSearchParams();
    if (q) params.set('q', q);
    if (eventType) params.set('event_type', eventType);
    return fetchJSON<NormalizedEvent[]>(`${API_BASE}/investigations/${caseId}/events?${params.toString()}`);
  },

  async getCoverage(caseId: string, playbookId: string): Promise<EGAResult> {
    return fetchJSON<EGAResult>(`${API_BASE}/investigations/${caseId}/coverage?playbook_id=${playbookId}`);
  },

  async getCorrelations(caseId: string): Promise<{ correlation_count: number; correlations: CorrelatedPair[] }> {
    return fetchJSON<{ correlation_count: number; correlations: CorrelatedPair[] }>(`${API_BASE}/investigations/${caseId}/correlations`);
  },

  // Playbooks
  async listPlaybooks(): Promise<PlaybookMeta[]> {
    return fetchJSON<PlaybookMeta[]>(`${API_BASE}/playbooks`);
  },

  // Claims
  async listClaims(caseId: string): Promise<Claim[]> {
    return fetchJSON<Claim[]>(`${API_BASE}/cases/${caseId}/claims`);
  },

  async createClaim(caseId: string, data: { statement: string; claim_type: string; subject?: string; object?: string; target_device?: string }): Promise<Claim> {
    return fetchJSON<Claim>(`${API_BASE}/cases/${caseId}/claims`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
  },

  async verifyClaim(claimId: string, playbookId: string): Promise<ClaimAssessment> {
    return fetchJSON<ClaimAssessment>(`${API_BASE}/claims/${claimId}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ playbook_id: playbookId }),
    });
  },

  async getClaimAssessments(claimId: string): Promise<ClaimAssessment[]> {
    return fetchJSON<ClaimAssessment[]>(`${API_BASE}/claims/${claimId}/assessments`);
  },

  // Reports
  async generateReport(caseId: string, playbookId: string): Promise<any> {
    return fetchJSON<any>(`${API_BASE}/cases/${caseId}/reports`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ playbook_id: playbookId }),
    });
  },

  async verifyReportManifest(reportId: string): Promise<any> {
    return fetchJSON<any>(`${API_BASE}/reports/${reportId}/verify`, {
      method: 'POST',
    });
  },

  // Audit
  async listAudit(caseId?: string): Promise<AuditEvent[]> {
    const url = caseId ? `${API_BASE}/audit?case_id=${caseId}` : `${API_BASE}/audit`;
    return fetchJSON<AuditEvent[]>(url);
  },

  async verifyAuditLedger(): Promise<any> {
    return fetchJSON<any>(`${API_BASE}/audit/verify`, {
      method: 'POST',
    });
  },
};
