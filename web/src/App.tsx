import React, { useState, useEffect } from 'react';
import {
  Shield,
  FolderOpen,
  Database,
  Clock,
  Layers,
  CheckCircle2,
  AlertTriangle,
  GitMerge,
  FileText,
  Lock,
  Search,
  Upload,
  RefreshCw,
  ExternalLink,
  HelpCircle,
  FileCheck,
  Terminal,
} from 'lucide-react';
import { api } from './api';
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

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('cases');
  const [cases, setCases] = useState<Case[]>([]);
  const [activeCase, setActiveCase] = useState<Case | null>(null);
  const [systemHealth, setSystemHealth] = useState<any>(null);
  const [playbooks, setPlaybooks] = useState<PlaybookMeta[]>([]);
  const [selectedPlaybook, setSelectedPlaybook] = useState<string>('usb_data_exfiltration');

  // Tab Data States
  const [evidenceList, setEvidenceList] = useState<CanonicalEvidence[]>([]);
  const [timelineEvents, setTimelineEvents] = useState<NormalizedEvent[]>([]);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [egaResult, setEgaResult] = useState<EGAResult | null>(null);
  const [claims, setClaims] = useState<Claim[]>([]);
  const [claimAssessments, setClaimAssessments] = useState<Record<string, ClaimAssessment>>({});
  const [correlations, setCorrelations] = useState<CorrelatedPair[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [auditVerified, setAuditVerified] = useState<boolean | null>(null);
  const [reportsHistory, setReportsHistory] = useState<any[]>([]);

  // Form states
  const [newCaseTitle, setNewCaseTitle] = useState('');
  const [newCaseDesc, setNewCaseDesc] = useState('');
  const [newCaseType, setNewCaseType] = useState('insider_threat');
  const [newClaimStmt, setNewClaimStmt] = useState('');
  const [newClaimSubj, setNewClaimSubj] = useState('');
  const [newClaimObj, setNewClaimObj] = useState('');
  const [newClaimDev, setNewClaimDev] = useState('');
  const [loading, setLoading] = useState(false);
  const [statusMsg, setStatusMsg] = useState<{ text: string; isError?: boolean } | null>(null);

  // Initial Load
  useEffect(() => {
    loadInitialData();
  }, []);

  // When active case changes, reload case-specific data
  useEffect(() => {
    if (activeCase) {
      loadCaseData(activeCase.case_id);
    }
  }, [activeCase, selectedPlaybook]);

  async function loadInitialData() {
    try {
      const health = await api.getHealth();
      setSystemHealth(health);
      const pbList = await api.listPlaybooks();
      setPlaybooks(pbList);
      const caseList = await api.listCases();
      setCases(caseList);
      if (caseList.length > 0 && !activeCase) {
        setActiveCase(caseList[0]);
      }
      checkAuditChain();
    } catch (e: any) {
      showStatus(e.message, true);
    }
  }

  async function loadCaseData(caseId: string) {
    setLoading(true);
    try {
      const [evList, tl, cov, clmList, corrList, audList] = await Promise.all([
        api.listEvidence(caseId).catch(() => []),
        api.getTimeline(caseId).catch(() => ({ total_events: 0, events: [] })),
        api.getCoverage(caseId, selectedPlaybook).catch(() => null),
        api.listClaims(caseId).catch(() => []),
        api.getCorrelations(caseId).catch(() => ({ correlation_count: 0, correlations: [] })),
        api.listAudit(caseId).catch(() => []),
      ]);

      setEvidenceList(evList);
      setTimelineEvents(tl.events);
      setEgaResult(cov);
      setClaims(clmList);
      setCorrelations(corrList.correlations);
      setAuditEvents(audList);

      // Fetch assessments for claims
      for (const c of clmList) {
        const assList = await api.getClaimAssessments(c.claim_id).catch(() => []);
        if (assList.length > 0) {
          setClaimAssessments((prev) => ({ ...prev, [c.claim_id]: assList[0] }));
        }
      }
    } catch (e: any) {
      showStatus(e.message, true);
    } finally {
      setLoading(false);
    }
  }

  function showStatus(text: string, isError: boolean = false) {
    setStatusMsg({ text, isError });
    setTimeout(() => setStatusMsg(null), 5000);
  }

  async function handleCreateCase(e: React.FormEvent) {
    e.preventDefault();
    if (!newCaseTitle.trim()) return;
    try {
      const created = await api.createCase({
        title: newCaseTitle,
        description: newCaseDesc,
        case_type: newCaseType,
        timezone: 'UTC',
      });
      setCases([created, ...cases]);
      setActiveCase(created);
      setNewCaseTitle('');
      setNewCaseDesc('');
      showStatus(`Case created: ${created.case_id}`);
    } catch (e: any) {
      showStatus(e.message, true);
    }
  }

  async function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    if (!activeCase || !e.target.files || e.target.files.length === 0) return;
    const file = e.target.files[0];
    setLoading(true);
    try {
      const res = await api.uploadEvidence(activeCase.case_id, file);
      showStatus(`Evidence uploaded to vault & parsed: ${res.indexed_events_count} records indexed.`);
      loadCaseData(activeCase.case_id);
    } catch (e: any) {
      showStatus(e.message, true);
    } finally {
      setLoading(false);
    }
  }

  async function handleVerifyEvidence(evId: string) {
    try {
      const res = await api.verifyEvidence(evId);
      showStatus(
        res.integrity_verified
          ? `Integrity Verified: SHA-256 matches baseline hash (${res.baseline_sha256.substring(0, 16)}...)`
          : `INTEGRITY COMPROMISED: Hash mismatch!`,
        !res.integrity_verified
      );
      if (activeCase) loadCaseData(activeCase.case_id);
    } catch (e: any) {
      showStatus(e.message, true);
    }
  }

  async function handleReprocessEvidence(evId: string) {
    try {
      const res = await api.reprocessEvidence(evId);
      showStatus(`Reprocessed ${res.reprocessed_records} events from vault.`);
      if (activeCase) loadCaseData(activeCase.case_id);
    } catch (e: any) {
      showStatus(e.message, true);
    }
  }

  async function handleCreateClaim(e: React.FormEvent) {
    e.preventDefault();
    if (!activeCase || !newClaimStmt.trim()) return;
    try {
      const created = await api.createClaim(activeCase.case_id, {
        statement: newClaimStmt,
        claim_type: selectedPlaybook === 'usb_data_exfiltration' ? 'usb_file_transfer' : 'automated_encryption',
        subject: newClaimSubj || undefined,
        object: newClaimObj || undefined,
        target_device: newClaimDev || undefined,
      });
      setClaims([created, ...claims]);
      setNewClaimStmt('');
      setNewClaimSubj('');
      setNewClaimObj('');
      setNewClaimDev('');
      showStatus(`Claim registered: ${created.claim_id}`);
    } catch (e: any) {
      showStatus(e.message, true);
    }
  }

  async function handleVerifyClaim(claimId: string) {
    try {
      const ass = await api.verifyClaim(claimId, selectedPlaybook);
      setClaimAssessments((prev) => ({ ...prev, [claimId]: ass }));
      showStatus(`Claim verified deterministically: Status = ${ass.status.toUpperCase()}`);
      checkAuditChain();
    } catch (e: any) {
      showStatus(e.message, true);
    }
  }

  async function checkAuditChain() {
    try {
      const res = await api.verifyAuditLedger();
      setAuditVerified(res.chain_valid);
    } catch {
      setAuditVerified(false);
    }
  }

  async function handleGenerateReport() {
    if (!activeCase) return;
    try {
      const pkg = await api.generateReport(activeCase.case_id, selectedPlaybook);
      setReportsHistory([pkg, ...reportsHistory]);
      showStatus(`Report generated: ${pkg.report_id}. Manifest: ${pkg.manifest_sha256.substring(0, 16)}...`);
    } catch (e: any) {
      showStatus(e.message, true);
    }
  }

  // Filtered timeline
  const filteredEvents = timelineEvents.filter((ev) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    const str = JSON.stringify(ev).toLowerCase();
    return str.includes(q);
  });

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Top Banner & Header */}
      <header
        style={{
          backgroundColor: '#0f172a',
          borderBottom: '1px solid #1e293b',
          padding: '0.75rem 1.5rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div
            style={{
              width: '36px',
              height: '36px',
              borderRadius: '8px',
              backgroundColor: '#0284c7',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Shield size={22} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ fontWeight: 800, fontSize: '1.15rem', letterSpacing: '0.05em', color: '#f8fafc' }}>
                VERITAS-X
              </span>
              <span
                style={{
                  fontSize: '0.65rem',
                  fontWeight: 700,
                  backgroundColor: '#0369a1',
                  color: '#e0f2fe',
                  padding: '0.15rem 0.4rem',
                  borderRadius: '4px',
                  textTransform: 'uppercase',
                }}
              >
                Local-First
              </span>
            </div>
            <p style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Trust the evidence. Verify the conclusion.</p>
          </div>
        </div>

        {/* Case Selector and System Indicators */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>Case:</span>
            <select
              value={activeCase?.case_id || ''}
              onChange={(e) => {
                const c = cases.find((x) => x.case_id === e.target.value);
                if (c) setActiveCase(c);
              }}
              style={{
                backgroundColor: '#1e293b',
                color: '#f8fafc',
                border: '1px solid #334155',
                borderRadius: '6px',
                padding: '0.35rem 0.75rem',
                fontSize: '0.85rem',
                outline: 'none',
              }}
            >
              {cases.map((c) => (
                <option key={c.case_id} value={c.case_id}>
                  {c.case_id} - {c.title}
                </option>
              ))}
            </select>
          </div>

          {/* Audit Chain Pill */}
          <div
            onClick={checkAuditChain}
            title="Click to re-verify cryptographic hash chain"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
              backgroundColor: auditVerified ? '#064e3b' : '#7f1d1d',
              color: auditVerified ? '#6ee7b7' : '#fca5a5',
              padding: '0.3rem 0.6rem',
              borderRadius: '999px',
              fontSize: '0.75rem',
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            <Lock size={12} />
            <span>Audit: {auditVerified ? 'Chain Verified' : 'Checking...'}</span>
          </div>

          {/* OpenSearch Status */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
              backgroundColor: systemHealth?.opensearch_connected ? '#0c4a6e' : '#334155',
              color: systemHealth?.opensearch_connected ? '#7dd3fc' : '#94a3b8',
              padding: '0.3rem 0.6rem',
              borderRadius: '999px',
              fontSize: '0.75rem',
              fontWeight: 600,
            }}
          >
            <Database size={12} />
            <span>OpenSearch: {systemHealth?.opensearch_connected ? 'Connected' : 'Offline / Standalone'}</span>
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav
        style={{
          backgroundColor: '#0f172a',
          borderBottom: '1px solid #1e293b',
          display: 'flex',
          padding: '0 1.5rem',
          gap: '0.25rem',
          overflowX: 'auto',
        }}
      >
        {[
          { id: 'cases', label: 'Cases', icon: FolderOpen, count: cases.length },
          { id: 'evidence', label: 'Evidence Vault', icon: Database, count: evidenceList.length },
          { id: 'timeline', label: 'Timeline & Events', icon: Clock, count: timelineEvents.length },
          { id: 'coverage', label: 'Evidence Gap (EGA)', icon: Layers, count: egaResult?.coverage_score ? `${egaResult.coverage_score}%` : null },
          { id: 'claims', label: 'Claim Verification (CAV)', icon: CheckCircle2, count: claims.length },
          { id: 'correlations', label: 'Correlations', icon: GitMerge, count: correlations.length },
          { id: 'reports', label: 'Reports & Manifests', icon: FileText, count: reportsHistory.length },
          { id: 'audit', label: 'Audit Ledger', icon: Lock, count: auditEvents.length },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.75rem 1rem',
                backgroundColor: 'transparent',
                border: 'none',
                borderBottom: isActive ? '2px solid #38bdf8' : '2px solid transparent',
                color: isActive ? '#38bdf8' : '#94a3b8',
                fontWeight: isActive ? 600 : 500,
                fontSize: '0.85rem',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              <Icon size={16} />
              <span>{tab.label}</span>
              {tab.count !== null && (
                <span
                  style={{
                    backgroundColor: isActive ? '#0284c7' : '#1e293b',
                    color: '#ffffff',
                    fontSize: '0.7rem',
                    padding: '0.1rem 0.4rem',
                    borderRadius: '999px',
                    fontWeight: 700,
                  }}
                >
                  {tab.count}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Status Bar */}
      {statusMsg && (
        <div
          style={{
            backgroundColor: statusMsg.isError ? '#7f1d1d' : '#064e3b',
            color: statusMsg.isError ? '#fecaca' : '#a7f3d0',
            padding: '0.5rem 1.5rem',
            fontSize: '0.85rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <span>{statusMsg.text}</span>
          <button
            onClick={() => setStatusMsg(null)}
            style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', fontSize: '1rem' }}
          >
            ×
          </button>
        </div>
      )}

      {/* Main Content Workspace */}
      <main style={{ flex: 1, padding: '1.5rem', overflowY: 'auto' }}>
        {/* CASE MANAGEMENT TAB */}
        {activeTab === 'cases' && (
          <div style={{ display: 'grid', gridTemplateColumns: '350px 1fr', gap: '1.5rem' }}>
            {/* Create Case Form */}
            <div style={{ backgroundColor: '#1e293b', padding: '1.25rem', borderRadius: '8px', border: '1px solid #334155' }}>
              <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '1rem', color: '#f8fafc' }}>
                Open New Investigation
              </h3>
              <form onSubmit={handleCreateCase}>
                <div style={{ marginBottom: '1rem' }}>
                  <label style={{ display: 'block', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '0.35rem' }}>
                    Investigation Title *
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Suspected USB Exfiltration"
                    value={newCaseTitle}
                    onChange={(e) => setNewCaseTitle(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '0.5rem',
                      backgroundColor: '#0f172a',
                      border: '1px solid #334155',
                      borderRadius: '6px',
                      color: '#f8fafc',
                      fontSize: '0.85rem',
                    }}
                  />
                </div>
                <div style={{ marginBottom: '1rem' }}>
                  <label style={{ display: 'block', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '0.35rem' }}>
                    Incident Scenario Category
                  </label>
                  <select
                    value={newCaseType}
                    onChange={(e) => setNewCaseType(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '0.5rem',
                      backgroundColor: '#0f172a',
                      border: '1px solid #334155',
                      borderRadius: '6px',
                      color: '#f8fafc',
                      fontSize: '0.85rem',
                    }}
                  >
                    <option value="insider_threat">Insider Threat / Data Theft</option>
                    <option value="ransomware">Ransomware Incident</option>
                    <option value="credential_theft">Credential Compromise</option>
                    <option value="unauthorized_access">Unauthorized Access</option>
                  </select>
                </div>
                <div style={{ marginBottom: '1rem' }}>
                  <label style={{ display: 'block', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '0.35rem' }}>
                    Description & Case Objectives
                  </label>
                  <textarea
                    rows={3}
                    placeholder="Forensic scope, hostnames, targets..."
                    value={newCaseDesc}
                    onChange={(e) => setNewCaseDesc(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '0.5rem',
                      backgroundColor: '#0f172a',
                      border: '1px solid #334155',
                      borderRadius: '6px',
                      color: '#f8fafc',
                      fontSize: '0.85rem',
                      resize: 'none',
                    }}
                  />
                </div>
                <button
                  type="submit"
                  style={{
                    width: '100%',
                    padding: '0.6rem',
                    backgroundColor: '#0284c7',
                    color: '#ffffff',
                    border: 'none',
                    borderRadius: '6px',
                    fontWeight: 600,
                    fontSize: '0.85rem',
                    cursor: 'pointer',
                  }}
                >
                  Create Case
                </button>
              </form>
            </div>

            {/* Cases List */}
            <div style={{ backgroundColor: '#1e293b', padding: '1.25rem', borderRadius: '8px', border: '1px solid #334155' }}>
              <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '1rem', color: '#f8fafc' }}>
                Active Investigations
              </h3>
              {cases.length === 0 ? (
                <p style={{ color: '#64748b', fontSize: '0.85rem' }}>No cases created yet.</p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  {cases.map((c) => {
                    const isSelected = activeCase?.case_id === c.case_id;
                    return (
                      <div
                        key={c.case_id}
                        onClick={() => setActiveCase(c)}
                        style={{
                          padding: '1rem',
                          backgroundColor: isSelected ? '#0f172a' : '#1e293b',
                          border: isSelected ? '1px solid #38bdf8' : '1px solid #334155',
                          borderRadius: '6px',
                          cursor: 'pointer',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span style={{ fontWeight: 700, fontSize: '0.95rem', color: isSelected ? '#38bdf8' : '#f8fafc' }}>
                            {c.title}
                          </span>
                          <span
                            style={{
                              fontSize: '0.7rem',
                              padding: '0.15rem 0.5rem',
                              borderRadius: '4px',
                              backgroundColor: c.status === 'active' ? '#065f46' : '#334155',
                              color: c.status === 'active' ? '#34d399' : '#94a3b8',
                              fontWeight: 600,
                            }}
                          >
                            {c.status.toUpperCase()}
                          </span>
                        </div>
                        <p style={{ fontSize: '0.8rem', color: '#94a3b8', marginTop: '0.35rem' }}>{c.description || 'No description provided'}</p>
                        <div style={{ display: 'flex', gap: '1rem', fontSize: '0.75rem', color: '#64748b', marginTop: '0.5rem' }}>
                          <span>ID: {c.case_id}</span>
                          <span>Type: {c.case_type}</span>
                          <span>Opened: {new Date(c.created_at).toLocaleDateString()}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        )}

        {/* EVIDENCE VAULT TAB */}
        {activeTab === 'evidence' && (
          <div>
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                backgroundColor: '#1e293b',
                padding: '1rem 1.25rem',
                borderRadius: '8px',
                border: '1px solid #334155',
                marginBottom: '1.5rem',
              }}
            >
              <div>
                <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc' }}>
                  Evidence Vault & Acquisition Pipeline
                </h3>
                <p style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
                  Original evidence is stored immutable in the local vault. SHA-256 baseline is computed and verified on arrival.
                </p>
              </div>
              <label
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  backgroundColor: '#0284c7',
                  color: '#ffffff',
                  padding: '0.5rem 1rem',
                  borderRadius: '6px',
                  fontWeight: 600,
                  fontSize: '0.85rem',
                  cursor: 'pointer',
                }}
              >
                <Upload size={16} />
                <span>Acquire / Import Evidence</span>
                <input type="file" onChange={handleFileUpload} style={{ display: 'none' }} />
              </label>
            </div>

            {/* Evidence Table */}
            <div style={{ backgroundColor: '#1e293b', borderRadius: '8px', border: '1px solid #334155', overflow: 'hidden' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
                <thead>
                  <tr style={{ backgroundColor: '#0f172a', borderBottom: '1px solid #334155', color: '#94a3b8' }}>
                    <th style={{ padding: '0.75rem 1rem' }}>Evidence ID</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Filename</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Size</th>
                    <th style={{ padding: '0.75rem 1rem' }}>SHA-256 Baseline Hash</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Integrity Status</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Parser</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Records</th>
                    <th style={{ padding: '0.75rem 1rem' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {evidenceList.length === 0 ? (
                    <tr>
                      <td colSpan={8} style={{ padding: '2rem', textAlign: 'center', color: '#64748b' }}>
                        No forensic evidence imported for this case. Click "Acquire / Import Evidence" above to upload logs.
                      </td>
                    </tr>
                  ) : (
                    evidenceList.map((ev) => (
                      <tr key={ev.evidence_id} style={{ borderBottom: '1px solid #334155' }}>
                        <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', color: '#38bdf8' }}>
                          {ev.evidence_id}
                        </td>
                        <td style={{ padding: '0.75rem 1rem', fontWeight: 600, color: '#f8fafc' }}>
                          {ev.identity.original_filename}
                        </td>
                        <td style={{ padding: '0.75rem 1rem', color: '#94a3b8' }}>
                          {(ev.identity.size_bytes / 1024).toFixed(1)} KB
                        </td>
                        <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', fontSize: '0.75rem', color: '#94a3b8' }}>
                          {ev.acquisition.original_sha256.substring(0, 20)}...
                        </td>
                        <td style={{ padding: '0.75rem 1rem' }}>
                          <span
                            style={{
                              backgroundColor: ev.integrity.status === 'verified' ? '#065f46' : '#7f1d1d',
                              color: ev.integrity.status === 'verified' ? '#34d399' : '#fca5a5',
                              padding: '0.2rem 0.5rem',
                              borderRadius: '4px',
                              fontSize: '0.75rem',
                              fontWeight: 700,
                            }}
                          >
                            {ev.integrity.status.toUpperCase()}
                          </span>
                        </td>
                        <td style={{ padding: '0.75rem 1rem', color: '#94a3b8' }}>
                          {ev.processing.parser}
                        </td>
                        <td style={{ padding: '0.75rem 1rem', fontWeight: 600, color: '#f8fafc' }}>
                          {ev.provenance.derived_record_count}
                        </td>
                        <td style={{ padding: '0.75rem 1rem' }}>
                          <div style={{ display: 'flex', gap: '0.5rem' }}>
                            <button
                              onClick={() => handleVerifyEvidence(ev.evidence_id)}
                              title="Recalculate SHA-256 against baseline"
                              style={{
                                display: 'flex',
                                alignItems: 'center',
                                gap: '0.25rem',
                                backgroundColor: '#0f172a',
                                border: '1px solid #334155',
                                color: '#38bdf8',
                                padding: '0.3rem 0.5rem',
                                borderRadius: '4px',
                                cursor: 'pointer',
                                fontSize: '0.75rem',
                              }}
                            >
                              <FileCheck size={14} /> Verify
                            </button>
                            <button
                              onClick={() => handleReprocessEvidence(ev.evidence_id)}
                              title="Reprocess normalized events"
                              style={{
                                display: 'flex',
                                alignItems: 'center',
                                gap: '0.25rem',
                                backgroundColor: '#0f172a',
                                border: '1px solid #334155',
                                color: '#94a3b8',
                                padding: '0.3rem 0.5rem',
                                borderRadius: '4px',
                                cursor: 'pointer',
                                fontSize: '0.75rem',
                              }}
                            >
                              <RefreshCw size={14} /> Reprocess
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* TIMELINE & EVENTS TAB */}
        {activeTab === 'timeline' && (
          <div>
            {/* Search & Filter Bar */}
            <div
              style={{
                backgroundColor: '#1e293b',
                padding: '1rem',
                borderRadius: '8px',
                border: '1px solid #334155',
                display: 'flex',
                gap: '1rem',
                marginBottom: '1.5rem',
              }}
            >
              <div style={{ flex: 1, position: 'relative' }}>
                <Search size={16} color="#64748b" style={{ position: 'absolute', left: '10px', top: '10px' }} />
                <input
                  type="text"
                  placeholder="Search across filename, process name, actor, IP, or hash..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '0.5rem 0.5rem 0.5rem 2.2rem',
                    backgroundColor: '#0f172a',
                    border: '1px solid #334155',
                    borderRadius: '6px',
                    color: '#f8fafc',
                    fontSize: '0.85rem',
                  }}
                />
              </div>
              <div style={{ display: 'flex', alignItems: 'center', color: '#94a3b8', fontSize: '0.85rem' }}>
                Showing {filteredEvents.length} of {timelineEvents.length} chronological events
              </div>
            </div>

            {/* Timeline Stream */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {filteredEvents.length === 0 ? (
                <div style={{ backgroundColor: '#1e293b', padding: '2rem', borderRadius: '8px', textAlign: 'center', color: '#64748b' }}>
                  No events found matching current criteria.
                </div>
              ) : (
                filteredEvents.map((ev) => (
                  <div
                    key={ev.event_id}
                    style={{
                      backgroundColor: '#1e293b',
                      borderRadius: '8px',
                      border: '1px solid #334155',
                      padding: '1rem',
                      display: 'grid',
                      gridTemplateColumns: '180px 140px 1fr',
                      gap: '1rem',
                      alignItems: 'center',
                    }}
                  >
                    <div>
                      <div style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: '#38bdf8' }}>
                        {new Date(ev.time.timestamp_utc).toISOString().replace('T', ' ').substring(0, 19)}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: '#64748b', marginTop: '0.2rem' }}>
                        Tz: {ev.time.timezone || 'UTC'}
                      </div>
                    </div>

                    <div>
                      <span
                        style={{
                          display: 'inline-block',
                          fontSize: '0.75rem',
                          fontWeight: 700,
                          padding: '0.2rem 0.5rem',
                          borderRadius: '4px',
                          backgroundColor:
                            ev.event.type === 'usb_connection'
                              ? '#0284c7'
                              : ev.event.type === 'file_access'
                              ? '#059669'
                              : '#475569',
                          color: '#ffffff',
                        }}
                      >
                        {ev.event.type.replace('_', ' ').toUpperCase()}
                      </span>
                      <div style={{ fontSize: '0.7rem', color: '#94a3b8', marginTop: '0.25rem' }}>
                        {ev.event.action}
                      </div>
                    </div>

                    <div style={{ fontSize: '0.85rem' }}>
                      <div style={{ color: '#f8fafc', fontWeight: 500 }}>
                        {ev.file.path || ev.file.name || ev.process.name || ev.device.identifier || 'System Event'}
                      </div>
                      <div style={{ display: 'flex', gap: '1.25rem', color: '#94a3b8', fontSize: '0.75rem', marginTop: '0.35rem' }}>
                        {ev.actor.username && <span>User: <strong>{ev.actor.username}</strong></span>}
                        {ev.host.hostname && <span>Host: <strong>{ev.host.hostname}</strong></span>}
                        {ev.device.identifier && <span>Device: <strong>{ev.device.identifier}</strong></span>}
                        {ev.process.pid && <span>PID: <strong>{ev.process.pid}</strong></span>}
                        {ev.source.record_locator && <span style={{ color: '#64748b' }}>Locator: {ev.source.record_locator}</span>}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {/* EVIDENCE GAP INTELLIGENCE (EGA) TAB */}
        {activeTab === 'coverage' && (
          <div>
            {/* Playbook Selector & Gauge */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr 300px',
                gap: '1.5rem',
                backgroundColor: '#1e293b',
                padding: '1.5rem',
                borderRadius: '8px',
                border: '1px solid #334155',
                marginBottom: '1.5rem',
              }}
            >
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
                  <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#f8fafc' }}>
                    Evidence Gap Analysis Engine (EGA)
                  </h3>
                  <select
                    value={selectedPlaybook}
                    onChange={(e) => setSelectedPlaybook(e.target.value)}
                    style={{
                      backgroundColor: '#0f172a',
                      color: '#38bdf8',
                      border: '1px solid #334155',
                      borderRadius: '6px',
                      padding: '0.3rem 0.6rem',
                      fontSize: '0.85rem',
                      fontWeight: 600,
                    }}
                  >
                    {playbooks.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name}
                      </option>
                    ))}
                  </select>
                </div>
                <p style={{ fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.5 }}>
                  The EGA engine evaluates collected evidence artifacts against formal investigation playbooks. It
                  mathematically computes artifact coverage and differentiates between <strong>Observed</strong>,{' '}
                  <strong>Partial</strong>, <strong>Not Found</strong>, and <strong>Not Collected</strong> sources to eliminate
                  speculative investigation conclusions.
                </p>
                <blockquote
                  style={{
                    marginTop: '0.75rem',
                    padding: '0.5rem 0.75rem',
                    borderLeft: '3px solid #38bdf8',
                    backgroundColor: '#0f172a',
                    fontSize: '0.75rem',
                    color: '#94a3b8',
                  }}
                >
                  {egaResult?.disclaimer}
                </blockquote>
              </div>

              {/* Coverage Gauge Card */}
              <div
                style={{
                  backgroundColor: '#0f172a',
                  borderRadius: '8px',
                  border: '1px solid #334155',
                  padding: '1rem',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                <div style={{ fontSize: '0.8rem', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Evidence Coverage
                </div>
                <div
                  style={{
                    fontSize: '2.75rem',
                    fontWeight: 800,
                    color:
                      (egaResult?.coverage_score || 0) >= 75
                        ? '#34d399'
                        : (egaResult?.coverage_score || 0) >= 40
                        ? '#fbbf24'
                        : '#f87171',
                    marginTop: '0.25rem',
                  }}
                >
                  {egaResult?.coverage_score ?? 0}%
                </div>
                <div
                  style={{
                    width: '100%',
                    height: '8px',
                    backgroundColor: '#334155',
                    borderRadius: '999px',
                    marginTop: '0.75rem',
                    overflow: 'hidden',
                  }}
                >
                  <div
                    style={{
                      height: '100%',
                      width: `${egaResult?.coverage_score ?? 0}%`,
                      backgroundColor:
                        (egaResult?.coverage_score || 0) >= 75
                          ? '#10b981'
                          : (egaResult?.coverage_score || 0) >= 40
                          ? '#f59e0b'
                          : '#ef4444',
                      borderRadius: '999px',
                      transition: 'width 0.4s ease',
                    }}
                  />
                </div>
              </div>
            </div>

            {/* Requirements Breakdown & Recommendations */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', gap: '1.5rem' }}>
              {/* Requirements Status */}
              <div style={{ backgroundColor: '#1e293b', borderRadius: '8px', border: '1px solid #334155', padding: '1.25rem' }}>
                <h4 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#f8fafc', marginBottom: '1rem' }}>
                  Playbook Evidence Requirements Breakdown
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  {egaResult?.evaluations.map((req) => {
                    const statusColor =
                      req.status === 'observed'
                        ? '#10b981'
                        : req.status === 'partial'
                        ? '#f59e0b'
                        : req.status === 'not_collected'
                        ? '#64748b'
                        : '#ef4444';
                    return (
                      <div
                        key={req.requirement_id}
                        style={{
                          backgroundColor: '#0f172a',
                          padding: '1rem',
                          borderRadius: '6px',
                          border: '1px solid #334155',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span style={{ fontWeight: 600, color: '#f8fafc', fontSize: '0.9rem' }}>{req.label}</span>
                          <span
                            style={{
                              backgroundColor: `${statusColor}22`,
                              color: statusColor,
                              border: `1px solid ${statusColor}66`,
                              padding: '0.15rem 0.5rem',
                              borderRadius: '4px',
                              fontSize: '0.75rem',
                              fontWeight: 700,
                            }}
                          >
                            {req.status.replace('_', ' ').toUpperCase()}
                          </span>
                        </div>
                        <p style={{ fontSize: '0.8rem', color: '#94a3b8', marginTop: '0.4rem' }}>{req.notes}</p>
                        {req.missing_fields && req.missing_fields.length > 0 && (
                          <div style={{ fontSize: '0.75rem', color: '#fca5a5', marginTop: '0.35rem' }}>
                            Missing attributes: {req.missing_fields.join(', ')}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Actionable Recommendations */}
              <div style={{ backgroundColor: '#1e293b', borderRadius: '8px', border: '1px solid #334155', padding: '1.25rem' }}>
                <h4 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#f8fafc', marginBottom: '1rem' }}>
                  Recommended Next Actions
                </h4>
                {(!egaResult?.recommendations || egaResult.recommendations.length === 0) ? (
                  <p style={{ fontSize: '0.85rem', color: '#64748b' }}>
                    All essential requirements have been observed. No gap recommendations.
                  </p>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    {egaResult.recommendations.map((rec, i) => (
                      <div
                        key={i}
                        style={{
                          backgroundColor: '#0f172a',
                          border: '1px solid #38bdf844',
                          borderLeft: '4px solid #38bdf8',
                          padding: '0.75rem',
                          borderRadius: '4px',
                          fontSize: '0.8rem',
                          color: '#e2e8f0',
                          lineHeight: 1.4,
                        }}
                      >
                        {rec}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* CLAIM-AWARE VERIFICATION (CAV) TAB */}
        {activeTab === 'claims' && (
          <div style={{ display: 'grid', gridTemplateColumns: '380px 1fr', gap: '1.5rem' }}>
            {/* Create Claim Form */}
            <div style={{ backgroundColor: '#1e293b', borderRadius: '8px', border: '1px solid #334155', padding: '1.25rem' }}>
              <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc', marginBottom: '1rem' }}>
                Register Investigative Claim
              </h3>
              <form onSubmit={handleCreateClaim}>
                <div style={{ marginBottom: '1rem' }}>
                  <label style={{ display: 'block', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '0.35rem' }}>
                    Claim Statement *
                  </label>
                  <textarea
                    rows={3}
                    required
                    placeholder="e.g. The user copied confidential.pdf to an unauthorized USB drive."
                    value={newClaimStmt}
                    onChange={(e) => setNewClaimStmt(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '0.5rem',
                      backgroundColor: '#0f172a',
                      border: '1px solid #334155',
                      borderRadius: '6px',
                      color: '#f8fafc',
                      fontSize: '0.85rem',
                      resize: 'none',
                    }}
                  />
                </div>
                <div style={{ marginBottom: '1rem' }}>
                  <label style={{ display: 'block', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '0.35rem' }}>
                    Subject (Suspected Actor / Username)
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. jsmith or admin"
                    value={newClaimSubj}
                    onChange={(e) => setNewClaimSubj(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '0.5rem',
                      backgroundColor: '#0f172a',
                      border: '1px solid #334155',
                      borderRadius: '6px',
                      color: '#f8fafc',
                      fontSize: '0.85rem',
                    }}
                  />
                </div>
                <div style={{ marginBottom: '1rem' }}>
                  <label style={{ display: 'block', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '0.35rem' }}>
                    Target Object (File / Resource)
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. confidential.pdf"
                    value={newClaimObj}
                    onChange={(e) => setNewClaimObj(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '0.5rem',
                      backgroundColor: '#0f172a',
                      border: '1px solid #334155',
                      borderRadius: '6px',
                      color: '#f8fafc',
                      fontSize: '0.85rem',
                    }}
                  />
                </div>
                <div style={{ marginBottom: '1rem' }}>
                  <label style={{ display: 'block', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '0.35rem' }}>
                    Target Device (Serial / Identifier)
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. USB-123 or SanDisk-4096"
                    value={newClaimDev}
                    onChange={(e) => setNewClaimDev(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '0.5rem',
                      backgroundColor: '#0f172a',
                      border: '1px solid #334155',
                      borderRadius: '6px',
                      color: '#f8fafc',
                      fontSize: '0.85rem',
                    }}
                  />
                </div>
                <button
                  type="submit"
                  style={{
                    width: '100%',
                    padding: '0.6rem',
                    backgroundColor: '#0284c7',
                    color: '#ffffff',
                    border: 'none',
                    borderRadius: '6px',
                    fontWeight: 600,
                    fontSize: '0.85rem',
                    cursor: 'pointer',
                  }}
                >
                  Register Claim
                </button>
              </form>
            </div>

            {/* Claims & Deterministic Assessment List */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {claims.length === 0 ? (
                <div style={{ backgroundColor: '#1e293b', padding: '2rem', borderRadius: '8px', textAlign: 'center', color: '#64748b' }}>
                  No claims registered for this case yet. Enter a claim on the left to verify it against evidence.
                </div>
              ) : (
                claims.map((claim) => {
                  const assessment = claimAssessments[claim.claim_id];
                  const status = assessment?.status;
                  const statusBg =
                    status === 'supported'
                      ? '#065f46'
                      : status === 'partially_supported'
                      ? '#78350f'
                      : status === 'insufficient_evidence'
                      ? '#334155'
                      : '#881337';
                  const statusColor =
                    status === 'supported'
                      ? '#34d399'
                      : status === 'partially_supported'
                      ? '#fcd34d'
                      : status === 'insufficient_evidence'
                      ? '#94a3b8'
                      : '#fda4af';

                  return (
                    <div
                      key={claim.claim_id}
                      style={{
                        backgroundColor: '#1e293b',
                        borderRadius: '8px',
                        border: '1px solid #334155',
                        padding: '1.25rem',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <span style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: '#38bdf8' }}>
                              {claim.claim_id}
                            </span>
                            <span style={{ fontSize: '0.75rem', color: '#64748b' }}>Type: {claim.claim_type}</span>
                          </div>
                          <p style={{ fontSize: '0.95rem', fontWeight: 600, color: '#f8fafc', marginTop: '0.35rem' }}>
                            "{claim.statement}"
                          </p>
                        </div>
                        <button
                          onClick={() => handleVerifyClaim(claim.claim_id)}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.35rem',
                            backgroundColor: '#0284c7',
                            color: '#ffffff',
                            border: 'none',
                            padding: '0.4rem 0.8rem',
                            borderRadius: '6px',
                            fontSize: '0.8rem',
                            fontWeight: 600,
                            cursor: 'pointer',
                          }}
                        >
                          <CheckCircle2 size={14} /> Run CAV
                        </button>
                      </div>

                      {/* Verification Outcome Card */}
                      {assessment && (
                        <div
                          style={{
                            marginTop: '1rem',
                            padding: '1rem',
                            backgroundColor: '#0f172a',
                            borderRadius: '6px',
                            border: '1px solid #334155',
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
                              Deterministic CAV Outcome (v{assessment.verification_rule_version})
                            </span>
                            <span
                              style={{
                                backgroundColor: statusBg,
                                color: statusColor,
                                padding: '0.2rem 0.6rem',
                                borderRadius: '4px',
                                fontSize: '0.75rem',
                                fontWeight: 800,
                              }}
                            >
                              {assessment.status.toUpperCase()}
                            </span>
                          </div>

                          {/* Supporting Evidence IDs */}
                          <div style={{ marginTop: '0.75rem', fontSize: '0.8rem' }}>
                            <span style={{ color: '#94a3b8' }}>Supporting Records: </span>
                            {assessment.supporting_evidence.length === 0 ? (
                              <span style={{ color: '#64748b' }}>None</span>
                            ) : (
                              assessment.supporting_evidence.map((id) => (
                                <span
                                  key={id}
                                  style={{
                                    fontFamily: 'monospace',
                                    fontSize: '0.75rem',
                                    backgroundColor: '#0284c722',
                                    color: '#38bdf8',
                                    padding: '0.1rem 0.4rem',
                                    borderRadius: '4px',
                                    marginRight: '0.35rem',
                                  }}
                                >
                                  {id}
                                </span>
                              ))
                            )}
                          </div>

                          {/* Limitations and Missing Predicates */}
                          {assessment.limitations.length > 0 && (
                            <div style={{ marginTop: '0.5rem' }}>
                              <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>Forensic Limitations:</span>
                              <ul style={{ paddingLeft: '1.25rem', marginTop: '0.25rem', fontSize: '0.75rem', color: '#fca5a5' }}>
                                {assessment.limitations.map((lim, idx) => (
                                  <li key={idx}>{lim}</li>
                                ))}
                              </ul>
                            </div>
                          )}

                          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.75rem', fontSize: '0.75rem', color: '#64748b' }}>
                            <span>Assessment ID: {assessment.assessment_id}</span>
                            <span>Human Review Required: {assessment.requires_human_review ? 'YES' : 'NO'}</span>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>
        )}

        {/* CORRELATIONS TAB */}
        {activeTab === 'correlations' && (
          <div>
            <div
              style={{
                backgroundColor: '#1e293b',
                padding: '1rem 1.25rem',
                borderRadius: '8px',
                border: '1px solid #334155',
                marginBottom: '1.5rem',
              }}
            >
              <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc' }}>
                Cross-Source Event Correlation
              </h3>
              <p style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
                Detects temporal and identity relationships within a bounded 300-second window. Identifies candidate
                relationships without falsely asserting causation.
              </p>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {correlations.length === 0 ? (
                <div style={{ backgroundColor: '#1e293b', padding: '2rem', borderRadius: '8px', textAlign: 'center', color: '#64748b' }}>
                  No correlated event pairs identified within the 300s temporal threshold.
                </div>
              ) : (
                correlations.map((c) => (
                  <div
                    key={c.correlation_id}
                    style={{
                      backgroundColor: '#1e293b',
                      borderRadius: '8px',
                      border: '1px solid #334155',
                      padding: '1rem',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                    }}
                  >
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <span style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: '#38bdf8' }}>
                          {c.correlation_id}
                        </span>
                        <span
                          style={{
                            fontSize: '0.7rem',
                            backgroundColor: '#0f172a',
                            color: '#94a3b8',
                            padding: '0.1rem 0.4rem',
                            borderRadius: '4px',
                          }}
                        >
                          Delta: {c.time_delta_seconds}s
                        </span>
                      </div>
                      <p style={{ fontSize: '0.85rem', color: '#f8fafc', marginTop: '0.25rem' }}>{c.notes}</p>
                      <div style={{ display: 'flex', gap: '1rem', fontSize: '0.75rem', color: '#64748b', marginTop: '0.35rem' }}>
                        <span>Source: <code>{c.source_event_id}</code></span>
                        <span>Target: <code>{c.target_event_id}</code></span>
                        <span>Causation Proven: <strong>{c.causation_established ? 'YES' : 'NO (Candidate)'}</strong></span>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {/* REPORTS TAB */}
        {activeTab === 'reports' && (
          <div>
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                backgroundColor: '#1e293b',
                padding: '1.25rem',
                borderRadius: '8px',
                border: '1px solid #334155',
                marginBottom: '1.5rem',
              }}
            >
              <div>
                <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc' }}>
                  Reproducible Investigation Reports
                </h3>
                <p style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
                  Compiles verified evidence provenance, EGA coverage, CAV claim outcomes, and cryptographic audit proofs into
                  reproducible manifest-hashed reports.
                </p>
              </div>
              <button
                onClick={handleGenerateReport}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  backgroundColor: '#0284c7',
                  color: '#ffffff',
                  border: 'none',
                  padding: '0.6rem 1.25rem',
                  borderRadius: '6px',
                  fontWeight: 600,
                  fontSize: '0.85rem',
                  cursor: 'pointer',
                }}
              >
                <FileText size={16} />
                <span>Generate Verified Report</span>
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {reportsHistory.length === 0 ? (
                <div style={{ backgroundColor: '#1e293b', padding: '2rem', borderRadius: '8px', textAlign: 'center', color: '#64748b' }}>
                  No reports generated yet for this session. Click "Generate Verified Report" above.
                </div>
              ) : (
                reportsHistory.map((rep) => (
                  <div
                    key={rep.report_id}
                    style={{
                      backgroundColor: '#1e293b',
                      borderRadius: '8px',
                      border: '1px solid #334155',
                      padding: '1.25rem',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div>
                        <span style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: '#38bdf8' }}>
                          Report ID: {rep.report_id}
                        </span>
                        <div style={{ fontSize: '0.8rem', fontFamily: 'monospace', color: '#94a3b8', marginTop: '0.2rem' }}>
                          Manifest SHA-256: {rep.manifest_sha256}
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: '0.5rem' }}>
                        <a
                          href={`/api/v1/reports/${rep.report_id}/download?format=html`}
                          target="_blank"
                          rel="noreferrer"
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.25rem',
                            backgroundColor: '#0f172a',
                            border: '1px solid #334155',
                            color: '#38bdf8',
                            padding: '0.4rem 0.8rem',
                            borderRadius: '4px',
                            fontSize: '0.8rem',
                            textDecoration: 'none',
                            fontWeight: 600,
                          }}
                        >
                          <ExternalLink size={14} /> Open HTML
                        </a>
                        <a
                          href={`/api/v1/reports/${rep.report_id}/download?format=json`}
                          download
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '0.25rem',
                            backgroundColor: '#0f172a',
                            border: '1px solid #334155',
                            color: '#94a3b8',
                            padding: '0.4rem 0.8rem',
                            borderRadius: '4px',
                            fontSize: '0.8rem',
                            textDecoration: 'none',
                            fontWeight: 600,
                          }}
                        >
                          Download JSON
                        </a>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {/* AUDIT LEDGER TAB */}
        {activeTab === 'audit' && (
          <div>
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                backgroundColor: '#1e293b',
                padding: '1.25rem',
                borderRadius: '8px',
                border: '1px solid #334155',
                marginBottom: '1.5rem',
              }}
            >
              <div>
                <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc' }}>
                  Cryptographic Append-Only Audit Ledger
                </h3>
                <p style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
                  Every case mutation, evidence acquisition, hash check, and claim assessment is recorded in an immutable
                  SHA-256 hash-chain block sequence.
                </p>
              </div>
              <button
                onClick={checkAuditChain}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  backgroundColor: '#0284c7',
                  color: '#ffffff',
                  border: 'none',
                  padding: '0.5rem 1rem',
                  borderRadius: '6px',
                  fontWeight: 600,
                  fontSize: '0.85rem',
                  cursor: 'pointer',
                }}
              >
                <Lock size={14} />
                <span>Verify Ledger Chain</span>
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {auditEvents.length === 0 ? (
                <div style={{ backgroundColor: '#1e293b', padding: '2rem', borderRadius: '8px', textAlign: 'center', color: '#64748b' }}>
                  No audit entries recorded yet.
                </div>
              ) : (
                auditEvents.map((aud, idx) => (
                  <div
                    key={aud.audit_id}
                    style={{
                      backgroundColor: '#1e293b',
                      borderRadius: '8px',
                      border: '1px solid #334155',
                      padding: '1rem',
                      display: 'grid',
                      gridTemplateColumns: '60px 180px 1fr 200px',
                      gap: '1rem',
                      alignItems: 'center',
                    }}
                  >
                    <span style={{ fontSize: '0.8rem', fontWeight: 700, color: '#64748b' }}>#{idx + 1}</span>
                    <div>
                      <div style={{ fontSize: '0.8rem', fontWeight: 700, color: '#38bdf8' }}>{aud.action}</div>
                      <div style={{ fontSize: '0.7rem', color: '#64748b' }}>Actor: {aud.actor_id}</div>
                    </div>
                    <div style={{ fontSize: '0.75rem', fontFamily: 'monospace' }}>
                      <div style={{ color: '#94a3b8' }}>
                        Hash: <span style={{ color: '#f8fafc' }}>{aud.record_hash.substring(0, 24)}...</span>
                      </div>
                      <div style={{ color: '#64748b' }}>
                        Prev: {aud.previous_record_hash.substring(0, 24)}...
                      </div>
                    </div>
                    <div style={{ fontSize: '0.75rem', color: '#94a3b8', textAlign: 'right' }}>
                      {new Date(aud.timestamp_utc).toISOString().replace('T', ' ').substring(0, 19)} UTC
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
