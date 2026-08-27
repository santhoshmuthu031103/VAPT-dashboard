import { useState, useEffect } from 'react';
import {
  Shield, ShieldAlert, ShieldX, FileText, Search, ChevronDown, ChevronUp,
  AlertCircle, RefreshCw, Info, ExternalLink, Clock, Download, ArrowLeft,
  Globe, Zap, ScanSearch, CheckCircle2, User, Users, Building, Layers, Eye
} from 'lucide-react';
import { DonutChart } from './SvgCharts';
import { triggerFileDownload } from '../utils/downloadHelper';

export default function Reports({ apiBase, activeReportId, onBackToTasks }) {
  const [reportType, setReportType] = useState('web_pentest'); // 'web_pentest' | 'openvas'
  
  // ── OpenVAS State ──
  const [reportId, setReportId]       = useState(activeReportId || '');
  const [report, setReport]           = useState(null);
  const [loading, setLoading]         = useState(false);
  const [error, setError]             = useState(null);
  const [expandedRow, setExpandedRow]       = useState(null);
  const [expandedWebRow, setExpandedWebRow] = useState(null);
  const [search, setSearch]                 = useState('');
  const [severityFilter, setSeverity] = useState('ALL');
  const [downloading, setDownloading] = useState(null); // 'html' | 'xml' | 'pdf' | null

  // ── Web Pen Testing Report State ──
  const [webHistory, setWebHistory]     = useState([]);
  const [targetGroups, setTargetGroups] = useState([]);
  const [reportGroupFilter, setReportGroupFilter] = useState('');
  const [selectedScanId, setSelectedScanId] = useState('');
  const [customTarget, setCustomTarget] = useState('');
  const [selectedTool, setSelectedTool] = useState('zap');
  const [companyName, setCompanyName]   = useState('Wyzmindz Solutions');
  const [auditorName, setAuditorName]   = useState('Santhosh M (Network Admin)');
  const [approverName, setApproverName] = useState('Leo Antony Charles (IT Manager)');
  const [docTitle, setDocTitle]         = useState('Infrastructure Vulnerability Assessment & Penetration Testing');
  
  const [previewData, setPreviewData]   = useState(null);
  const [loadingPreview, setLoadingPreview] = useState(false);
  const [previewError, setPreviewError] = useState(null);
  const [downloadingWeb, setDownloadingWeb] = useState(null);

  // Fetch scan history and target groups for report generation
  useEffect(() => {
    Promise.allSettled([
      fetch(`${apiBase}/api/scanners/history`),
      fetch(`${apiBase}/api/target-groups`)
    ]).then(([histRes, groupRes]) => {
      if (histRes.status === 'fulfilled' && histRes.value.ok) {
        histRes.value.json().then(data => {
          const allScans = Array.isArray(data) ? data.filter(d => !!d.tool) : [];
          setWebHistory(allScans);
          if (allScans.length > 0 && !selectedScanId) {
            setSelectedScanId(allScans[0].id.toString());
            loadWebReportPreview(allScans[0].id);
          }
        });
      }
      if (groupRes.status === 'fulfilled' && groupRes.value.ok) {
        groupRes.value.json().then(gData => {
          setTargetGroups(Array.isArray(gData) ? gData : []);
        });
      }
    }).catch(() => {});
  }, [apiBase]);

  const loadWebReportPreview = async (scanId) => {
    if (!scanId) return;
    setLoadingPreview(true);
    setPreviewError(null);
    try {
      const res = await fetch(`${apiBase}/api/scanners/history/${scanId}/report?fmt=json&company=${encodeURIComponent(companyName)}&auditor=${encodeURIComponent(auditorName)}&doc_title=${encodeURIComponent(docTitle)}`);
      if (!res.ok) throw new Error(`Failed to load report data (${res.status})`);
      const data = await res.json();
      setPreviewData(data.normalized);
    } catch (e) {
      setPreviewError(e.message);
      setPreviewData(null);
    } finally {
      setLoadingPreview(false);
    }
  };

  const downloadWebReport = async (fmt) => {
    if (!selectedScanId) return;
    setDownloadingWeb(fmt);
    try {
      const res = await fetch(`${apiBase}/api/scanners/history/${selectedScanId}/report?fmt=${fmt}&company=${encodeURIComponent(companyName)}&auditor=${encodeURIComponent(auditorName)}&doc_title=${encodeURIComponent(docTitle)}`);
      if (!res.ok) throw new Error(`Download failed (${res.status})`);
      const blob = await res.blob();
      triggerFileDownload(blob, `vapt-audit-report-scan${selectedScanId}.${fmt}`);
    } catch (err) {
      alert(`Export error: ${err.message}`);
    } finally {
      setDownloadingWeb(null);
    }
  };

  const handleDownload = async (fmt) => {
    if (!reportId) return;
    setDownloading(fmt);
    try {
      const res = await fetch(`${apiBase}/api/reports/${reportId}/download?fmt=${fmt}&company=${encodeURIComponent(companyName)}&auditor=${encodeURIComponent(auditorName)}&approved_by=${encodeURIComponent(approverName)}`);
      if (!res.ok) throw new Error('Download failed');
      const blob = await res.blob();
      triggerFileDownload(blob, `openvas-vapt-audit-${reportId.slice(0, 8)}.${fmt}`);
    } catch (err) { alert(`Export error: ${err.message}`); }
    finally { setDownloading(null); }
  };

  useEffect(() => {
    if (activeReportId) {
      setReportId(activeReportId);
      setReportType('openvas');
      fetchReport(activeReportId);
    }
  }, [activeReportId]);

  const fetchReport = async (id) => {
    const idToFetch = id || reportId;
    if (!idToFetch) return;
    setLoading(true); setError(null); setExpandedRow(null);
    try {
      const res = await fetch(`${apiBase}/api/reports/${idToFetch}`);
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || 'Failed to load report. Verify the report ID.');
      }
      setReport(await res.json());
    } catch (err) { setError(err.message); setReport(null); }
    finally { setLoading(false); }
  };

  const severityBadge = (sev) => {
    switch (sev?.toLowerCase()) {
      case 'critical': return 'badge-critical';
      case 'high':     return 'badge-high';
      case 'medium':   return 'badge-medium';
      case 'low':      return 'badge-low';
      default:         return 'badge-info';
    }
  };

  const severityBorder = (sev) => {
    switch (sev?.toLowerCase()) {
      case 'critical': return '#dc2626';
      case 'high':     return 'var(--severity-high)';
      case 'medium':   return 'var(--severity-medium)';
      case 'low':      return 'var(--severity-low)';
      default:         return 'var(--severity-info)';
    }
  };

  const fmtDate = (str) => {
    if (!str) return '—';
    try { return new Date(str).toLocaleString(); } catch { return str; }
  };

  const vulnerabilities = report?.vulnerabilities || [];
  const filtered = vulnerabilities.filter(v => {
    const q = search.toLowerCase();
    const matchSearch =
      (v.name || '').toLowerCase().includes(q) ||
      (v.cve || '').toLowerCase().includes(q) ||
      (v.description || '').toLowerCase().includes(q) ||
      (v.host || '').includes(q) ||
      (v.port || '').toString().includes(q);
    const matchSev = severityFilter === 'ALL' || (v.severity || '').toUpperCase() === severityFilter;
    return matchSearch && matchSev;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

      {/* Top Tab Mode Switcher */}
      <div style={{ display: 'flex', gap: 8, borderBottom: '1px solid var(--border-subtle)', paddingBottom: 12 }}>
        <button
          className={`btn ${reportType === 'web_pentest' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setReportType('web_pentest')}
          style={{ display: 'flex', alignItems: 'center', gap: 6 }}
        >
          <Globe size={15} />
          Security Scanner &amp; Pen Testing Reports (Nmap / ZAP / SQLmap / Nuclei / Nikto / Gobuster / FFuF)
        </button>
        <button
          className={`btn ${reportType === 'openvas' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setReportType('openvas')}
          style={{ display: 'flex', alignItems: 'center', gap: 6 }}
        >
          <ShieldAlert size={15} />
          Infrastructure Audits (OpenVAS)
        </button>
      </div>

      {/* ═══════════════════ SECURITY SCANNER & PEN TESTING REPORTS ═══════════════════ */}
      {reportType === 'web_pentest' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          
          {/* Report Config Bar */}
          <div className="card">
            <div className="card-body" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: 'var(--text-primary)' }}>
                    Security Scanner &amp; Penetration Testing Audit Reports
                  </h3>
                  <p style={{ margin: '4px 0 0', fontSize: 12, color: 'var(--text-muted)' }}>
                    Export formal executive audit reports for security scan runs (Nmap, OWASP ZAP, SQLmap, Nuclei, Nikto, Gobuster, FFuF)
                  </p>
                </div>
                {previewData && (
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button
                      className="btn btn-primary"
                      onClick={() => downloadWebReport('pdf')}
                      disabled={!!downloadingWeb}
                      style={{ height: '36px', display: 'flex', alignItems: 'center', gap: 6 }}
                    >
                      {downloadingWeb === 'pdf' ? <RefreshCw size={14} className="spin" /> : <FileText size={14} />}
                      Download PDF Report
                    </button>
                    <button
                      className="btn btn-secondary"
                      onClick={() => downloadWebReport('html')}
                      disabled={!!downloadingWeb}
                      style={{ height: '36px', display: 'flex', alignItems: 'center', gap: 6 }}
                    >
                      {downloadingWeb === 'html' ? <RefreshCw size={14} className="spin" /> : <Download size={14} />}
                      Download HTML
                    </button>
                  </div>
                )}
              </div>

              {(() => {
                const selectedReportGroup = targetGroups.find(g => g.id.toString() === reportGroupFilter.toString());
                const reportGroupHosts = selectedReportGroup
                  ? (Array.isArray(selectedReportGroup.targets) ? selectedReportGroup.targets : (selectedReportGroup.targets ? selectedReportGroup.targets.split(',') : [])).map(h => h.trim().toLowerCase()).filter(Boolean)
                  : [];

                const filteredWebHistory = webHistory.filter(h => {
                  if (reportGroupFilter && reportGroupHosts.length > 0) {
                    const hTarget = (h.target || '').toLowerCase();
                    return reportGroupHosts.some(gh => hTarget.includes(gh) || gh.includes(hTarget));
                  }
                  return true;
                });

                return (
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
                    {targetGroups.length > 0 && (
                      <div className="form-group">
                        <label className="form-label"><Users size={13} /> Target Group</label>
                        <select
                          className="form-select"
                          value={reportGroupFilter}
                          onChange={(e) => setReportGroupFilter(e.target.value)}
                        >
                          <option value="">All Groups (All Scans)</option>
                          {targetGroups.map(g => (
                            <option key={g.id} value={g.id}>🟣 {g.name}</option>
                          ))}
                        </select>
                      </div>
                    )}

                    <div className="form-group">
                      <label className="form-label"><Layers size={13} /> Select Scan Run</label>
                      <select
                        className="form-select"
                        value={selectedScanId}
                        onChange={(e) => {
                          setSelectedScanId(e.target.value);
                          loadWebReportPreview(e.target.value);
                        }}
                      >
                        {filteredWebHistory.length === 0 ? (
                          <option value="">No scans matching filter</option>
                        ) : (
                          filteredWebHistory.map(h => (
                            <option key={h.id} value={h.id}>
                              #{h.id} [{h.tool.toUpperCase()}] {h.target} ({h.timestamp ? h.timestamp.split(' ')[0] : 'recent'})
                            </option>
                          ))
                        )}
                      </select>
                    </div>

                    <div className="form-group">
                      <label className="form-label"><Building size={13} /> Organization / Client</label>
                      <input
                        className="form-input"
                        placeholder="e.g. Target Organization"
                        value={companyName}
                        onChange={(e) => setCompanyName(e.target.value)}
                      />
                    </div>

                    <div className="form-group">
                      <label className="form-label"><User size={13} /> Lead Auditor</label>
                      <input
                        className="form-input"
                        placeholder="e.g. VAPT Security Team"
                        value={auditorName}
                        onChange={(e) => setAuditorName(e.target.value)}
                      />
                    </div>

                    <div className="form-group" style={{ display: 'flex', alignItems: 'flex-end' }}>
                      <button
                        className="btn btn-secondary btn-full"
                        onClick={() => loadWebReportPreview(selectedScanId)}
                        disabled={loadingPreview || !selectedScanId}
                        style={{ height: '36px' }}
                      >
                        {loadingPreview ? <RefreshCw size={14} className="spin" /> : <Eye size={14} />}
                        Refresh Preview
                      </button>
                    </div>
                  </div>
                );
              })()}
            </div>
          </div>

          {/* Web Report Preview */}
          {loadingPreview ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '4rem', gap: '1rem' }}>
              <RefreshCw className="spin" size={36} style={{ color: 'var(--violet-400)' }} />
              <span className="text-secondary">Rendering VAPT audit report preview...</span>
            </div>
          ) : previewError ? (
            <div className="alert alert-error">
              <AlertCircle size={16} />
              <div>
                <h4 style={{ fontWeight: 600 }}>Error Loading Report</h4>
                <p style={{ fontSize: '0.85rem' }}>{previewError}</p>
              </div>
            </div>
          ) : !previewData ? (
            <div className="card">
              <div className="card-body empty-state" style={{ padding: '40px' }}>
                <FileText size={48} className="text-muted" style={{ marginBottom: '1rem' }} />
                <h3>No Web Pentest Scan Selected</h3>
                <p style={{ fontSize: '0.85rem', marginTop: '0.5rem' }}>
                  Run a scan in <strong>OWASP ZAP</strong>, <strong>Nuclei</strong>, <strong>Nikto</strong>, or <strong>Gobuster</strong> tabs, then select it here to generate full VAPT audit reports.
                </p>
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              
              {/* Executive Summary Card */}
              <div className="card">
                <div className="card-body" style={{ padding: '24px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexWrap: 'wrap', gap: 10 }}>
                    <div>
                      <span style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', letterSpacing: '0.5px' }}>
                        Executive Security Posture
                      </span>
                      <h3 style={{ margin: '4px 0 0', color: 'var(--text-primary)' }}>{previewData.target_url}</h3>
                    </div>
                    <span style={{
                      background: previewData.posture?.color || 'var(--emerald-500)',
                      color: '#ffffff',
                      padding: '6px 14px',
                      borderRadius: '6px',
                      fontWeight: 800,
                      fontSize: '14px',
                      letterSpacing: '0.5px'
                    }}>
                      POSTURE: {previewData.posture?.level || 'GOOD'}
                    </span>
                  </div>
                  <p style={{ color: 'var(--text-secondary)', fontSize: 13, lineHeight: 1.6, margin: 0 }}>
                    {previewData.posture?.desc}
                  </p>
                </div>
              </div>

              {/* Severity KPIs */}
              <div className="grid-4" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))' }}>
                {[
                  { label: 'Critical', count: previewData.counts?.Critical || 0, color: '#dc2626' },
                  { label: 'High', count: previewData.counts?.High || 0, color: '#ea580c' },
                  { label: 'Medium', count: previewData.counts?.Medium || 0, color: '#d97706' },
                  { label: 'Low', count: previewData.counts?.Low || 0, color: '#2563eb' },
                  { label: 'Info', count: previewData.counts?.Informational || 0, color: '#64748b' },
                ].map(({ label, count, color }) => (
                  <div key={label} className="card" style={{ borderLeft: `4px solid ${color}` }}>
                    <div className="card-body" style={{ padding: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div>
                        <span style={{ fontSize: '0.75rem', textTransform: 'uppercase', fontWeight: 600, color: 'var(--text-muted)' }}>{label}</span>
                        <h3 style={{ fontSize: '1.8rem', marginTop: '0.2rem', color, fontWeight: 800 }}>{count}</h3>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Findings List */}
              <div className="card">
                <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <h4 style={{ margin: 0, fontWeight: 600 }}>Identified Observations &amp; Vulnerabilities ({previewData.total_findings})</h4>
                  <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Tool: {previewData.tool}</span>
                </div>
                <div className="card-body" style={{ padding: 0 }}>
                  {previewData.observations?.length === 0 ? (
                    <div style={{ textAlign: 'center', padding: '30px', color: 'var(--emerald-400)' }}>
                      &check; No vulnerabilities found for this scan run.
                    </div>
                  ) : (
                    <div className="table-wrap" style={{ border: 'none', borderRadius: 0 }}>
                      <table style={{ borderCollapse: 'separate', borderSpacing: '0 2px' }}>
                        <thead>
                          <tr>
                            <th style={{ width: '30px' }}></th>
                            <th style={{ width: '40px' }}>#</th>
                            <th>Vulnerability Title</th>
                            <th>Severity</th>
                            <th>CVSS</th>
                            <th>CWE</th>
                            <th>Endpoint</th>
                            <th>Status</th>
                          </tr>
                        </thead>
                        <tbody>
                          {previewData.observations.map((obs, idx) => {
                            const isExp = expandedWebRow === idx;
                            const border = severityBorder(obs.severity);

                            return (
                              <>
                                <tr
                                  key={idx}
                                  onClick={() => setExpandedWebRow(isExp ? null : idx)}
                                  style={{ cursor: 'pointer', borderLeft: `3px solid ${border}`, transition: 'background 0.15s' }}
                                >
                                  <td style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
                                    {isExp ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                                  </td>
                                  <td style={{ textAlign: 'center', fontWeight: 'bold' }}>{obs.id}</td>
                                  <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{obs.title}</td>
                                  <td><span className={`badge ${severityBadge(obs.severity)}`}>{obs.severity}</span></td>
                                  <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 'bold', color: border }}>{obs.cvss_score?.toFixed(1)}</td>
                                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--violet-500)' }}>{obs.cwe || '—'}</td>
                                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{obs.endpoint || '—'}</td>
                                  <td><span className={`badge ${obs.status === 'Resolved' ? 'badge-success' : 'badge-high'}`}>{obs.status || 'Open'}</span></td>
                                </tr>

                                {isExp && (
                                  <tr key={`${idx}-web-exp`}>
                                    <td colSpan={8} style={{ padding: '8px 16px 18px 16px', background: 'var(--bg-base, #f8fafc)' }}>
                                      <div style={{
                                        padding: '16px 20px',
                                        borderLeft: `4px solid ${border}`,
                                        borderRadius: '8px',
                                        background: 'var(--bg-surface, #ffffff)',
                                        border: '1px solid var(--border-default, #e2e8f0)',
                                        boxShadow: '0 4px 12px rgba(0, 0, 0, 0.05)',
                                        display: 'flex',
                                        flexDirection: 'column',
                                        gap: '14px'
                                      }}>
                                        {/* Description */}
                                        <div>
                                          <h5 style={{
                                            margin: '0 0 6px 0',
                                            color: 'var(--text-primary, #0f172a)',
                                            fontWeight: 700,
                                            fontSize: '13px',
                                            display: 'flex',
                                            alignItems: 'center',
                                            gap: '6px'
                                          }}>
                                            <FileText size={14} style={{ color: 'var(--violet-500, #7c3aed)' }} />
                                            <span>Observation Details</span>
                                          </h5>
                                          <div style={{
                                            fontSize: '13px',
                                            lineHeight: 1.6,
                                            whiteSpace: 'pre-wrap',
                                            color: 'var(--text-primary, #1e293b)',
                                            background: 'var(--bg-base, #f8fafc)',
                                            padding: '12px 14px',
                                            borderRadius: '6px',
                                            border: '1px solid var(--border-default, #e2e8f0)',
                                            fontFamily: 'inherit'
                                          }}>
                                            {obs.description || 'Detailed vulnerability finding identified during audit.'}
                                          </div>
                                        </div>

                                        {/* Impact / Remediation */}
                                        {(obs.solution || obs.impact) && (
                                          <div>
                                            <h5 style={{
                                              margin: '0 0 6px 0',
                                              color: 'var(--emerald-600, #059669)',
                                              fontWeight: 700,
                                              fontSize: '13px',
                                              display: 'flex',
                                              alignItems: 'center',
                                              gap: '6px'
                                            }}>
                                              <CheckCircle2 size={14} style={{ color: 'var(--emerald-500, #10b981)' }} />
                                              <span>Remediation &amp; Mitigation Guidance</span>
                                            </h5>
                                            <div style={{
                                              fontSize: '13px',
                                              lineHeight: 1.6,
                                              whiteSpace: 'pre-wrap',
                                              color: 'var(--text-primary, #0f172a)',
                                              background: 'var(--emerald-dim, rgba(16, 185, 129, 0.08))',
                                              padding: '12px 14px',
                                              borderRadius: '6px',
                                              border: '1px solid rgba(16, 185, 129, 0.25)',
                                              fontFamily: 'inherit'
                                            }}>
                                              {obs.solution || obs.impact}
                                            </div>
                                          </div>
                                        )}

                                        {/* Endpoint / Evidence Footer */}
                                        <div style={{
                                          borderTop: '1px solid var(--border-default, #e2e8f0)',
                                          paddingTop: '10px',
                                          display: 'flex',
                                          flexWrap: 'wrap',
                                          alignItems: 'center',
                                          gap: '16px',
                                          fontSize: '12px',
                                          color: 'var(--text-secondary, #64748b)'
                                        }}>
                                          {obs.endpoint && (
                                            <span>
                                              <strong>Vulnerable Target:</strong> <code style={{ background: 'var(--bg-base, #f1f5f9)', padding: '2px 6px', borderRadius: '4px', color: 'var(--text-primary)' }}>{obs.endpoint}</code>
                                            </span>
                                          )}
                                          {obs.cwe && (
                                            <span>
                                              <strong>Weakness:</strong> <span className="badge badge-secondary" style={{ fontSize: '11px' }}>{obs.cwe}</span>
                                            </span>
                                          )}
                                        </div>
                                      </div>
                                    </td>
                                  </tr>
                                )}
                              </>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </div>

            </div>
          )}

        </div>
      )}

      {/* ═══════════════════ OPENVAS / INFRASTRUCTURE AUDITS ═══════════════════ */}
      {reportType === 'openvas' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Report selector */}
          <div className="card">
            <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 14, padding: '20px' }}>
              <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                <div style={{ display: 'flex', flex: 1, gap: 8, minWidth: '280px' }} className="form-group">
                  <input
                    type="text"
                    className="form-input"
                    style={{ flex: 1 }}
                    placeholder="Enter GVM Report ID…"
                    value={reportId}
                    onChange={e => setReportId(e.target.value)}
                  />
                  <button className="btn btn-primary btn-sm" onClick={() => fetchReport()} disabled={loading || !reportId} style={{ height: '36px' }}>
                    {loading ? <RefreshCw className="spin" size={14} /> : 'Load Report'}
                  </button>
                </div>
                {onBackToTasks && (
                  <button className="btn btn-secondary btn-sm" onClick={onBackToTasks} style={{ height: '36px' }}>
                    <ArrowLeft size={14} /> Back to Audits
                  </button>
                )}
                {report && (
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button
                      className="btn btn-primary btn-sm"
                      onClick={() => handleDownload('pdf')}
                      disabled={!!downloading}
                      title="Download PDF report"
                      style={{ height: '36px', display: 'flex', alignItems: 'center', gap: 6 }}
                    >
                      {downloading === 'pdf' ? <RefreshCw size={14} className="spin" /> : <FileText size={14} />}
                      Download PDF Report
                    </button>
                    <button
                      className="btn btn-secondary btn-sm"
                      onClick={() => handleDownload('html')}
                      disabled={!!downloading}
                      title="Download styled HTML report"
                      style={{ height: '36px', display: 'flex', alignItems: 'center', gap: 6 }}
                    >
                      {downloading === 'html' ? <RefreshCw size={14} className="spin" /> : <Download size={14} />}
                      Download HTML
                    </button>
                    <button
                      className="btn btn-ghost btn-sm"
                      onClick={() => handleDownload('xml')}
                      disabled={!!downloading}
                      title="Download raw GVM XML"
                      style={{ height: '36px', fontSize: 11 }}
                    >
                      XML
                    </button>
                  </div>
                )}
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12, borderTop: '1px solid var(--border-subtle)', paddingTop: 12 }}>
                <div className="form-group">
                  <label className="form-label"><Building size={13} /> Organization / Client</label>
                  <input
                    className="form-input"
                    placeholder="e.g. Wyzmindz Solutions"
                    value={companyName}
                    onChange={(e) => setCompanyName(e.target.value)}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label"><User size={13} /> Assessment Conducted By (Auditor)</label>
                  <input
                    className="form-input"
                    placeholder="e.g. Santhosh M (Network Admin)"
                    value={auditorName}
                    onChange={(e) => setAuditorName(e.target.value)}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label"><CheckCircle2 size={13} /> Reviewed &amp; Approved By</label>
                  <input
                    className="form-input"
                    placeholder="e.g. Leo Antony Charles (IT Manager)"
                    value={approverName}
                    onChange={(e) => setApproverName(e.target.value)}
                  />
                </div>
              </div>
            </div>
          </div>

          {loading ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '4rem', gap: '1.5rem' }}>
              <RefreshCw className="spin" size={40} style={{ color: 'var(--violet-400)' }} />
              <span className="text-secondary">Fetching full report from OpenVAS…</span>
            </div>
          ) : error ? (
            <div className="alert alert-error">
              <AlertCircle size={16} />
              <div>
                <h4 style={{ fontWeight: 600 }}>Failed to Load Report</h4>
                <p style={{ fontSize: '0.85rem' }}>{error}</p>
              </div>
            </div>
          ) : !report ? (
            <div className="card">
              <div className="card-body empty-state" style={{ border: 'none', padding: '40px' }}>
                <FileText size={48} className="text-muted" style={{ marginBottom: '1rem' }} />
                <h3>No Report Loaded</h3>
                <p style={{ fontSize: '0.85rem', marginTop: '0.5rem' }}>
                  Run an audit from the <strong>Audits</strong> tab and click the <FileText size={13} style={{ verticalAlign: 'middle' }} /> icon on a completed task.
                </p>
              </div>
            </div>
          ) : (
            <>
              {/* Scan Metadata */}
              <div className="card">
                <div className="card-body" style={{ display: 'flex', gap: '2rem', flexWrap: 'wrap', alignItems: 'center', padding: '20px' }}>
                  <div>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Task</span>
                    <p style={{ fontWeight: 700, marginTop: '0.2rem', color: 'var(--text-primary)' }}>{report.task_name || '—'}</p>
                  </div>
                  <div>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: '4px', fontWeight: 600 }}><Clock size={12} /> Scan Started</span>
                    <p style={{ fontFamily: 'var(--font-mono)', marginTop: '0.2rem', fontSize: '0.85rem', color: 'var(--text-primary)' }}>{fmtDate(report.scan_start)}</p>
                  </div>
                  <div>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: '4px', fontWeight: 600 }}><Clock size={12} /> Scan Ended</span>
                    <p style={{ fontFamily: 'var(--font-mono)', marginTop: '0.2rem', fontSize: '0.85rem', color: 'var(--text-primary)' }}>{fmtDate(report.scan_end)}</p>
                  </div>
                </div>
              </div>
              {/* KPI cards */}
              <div className="grid-4">
                {[
                  { label: 'High', count: report.summary.high, color: 'var(--severity-high)', Icon: ShieldX },
                  { label: 'Medium', count: report.summary.medium, color: 'var(--severity-medium)', Icon: ShieldAlert },
                  { label: 'Low', count: report.summary.low, color: 'var(--severity-low)', Icon: Shield },
                  { label: 'Log', count: report.summary.log, color: 'var(--severity-info)', Icon: Info },
                ].map(({ label, count, color, Icon }) => (
                  <div key={label} className="card" style={{ borderLeft: `3px solid ${color}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div className="card-body" style={{ padding: '16px', display: 'flex', flex: 1, justifyContent: 'space-between', alignItems: 'center' }}>
                      <div>
                        <span style={{ fontSize: '0.75rem', textTransform: 'uppercase', fontWeight: 600, color: 'var(--text-secondary)' }}>{label} Threats</span>
                        <h3 style={{ fontSize: '2rem', marginTop: '0.25rem', color, fontWeight: 800 }}>{count}</h3>
                      </div>
                      <Icon size={24} style={{ color }} />
                    </div>
                  </div>
                ))}
              </div>

              {/* Filters & Table */}
              <div className="card">
                <div className="card-header" style={{ flexWrap: 'wrap', gap: 12 }}>
                  <div style={{ position: 'relative', width: 260 }}>
                    <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none' }} />
                    <input
                      type="text"
                      className="form-input"
                      style={{ paddingLeft: 30, height: 32, fontSize: 12 }}
                      placeholder="Filter by name, CVE, host, port…"
                      value={search}
                      onChange={e => setSearch(e.target.value)}
                    />
                  </div>
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                    {['ALL', 'HIGH', 'MEDIUM', 'LOW', 'LOG'].map(sev => (
                      <button
                        key={sev}
                        className={`btn btn-sm ${severityFilter === sev ? 'btn-primary' : 'btn-secondary'}`}
                        onClick={() => { setSeverity(sev); setExpandedRow(null); }}
                        style={{ fontSize: 11, padding: '4px 10px' }}
                      >{sev}</button>
                    ))}
                  </div>
                  <span style={{ fontSize: 12, color: 'var(--text-muted)', marginLeft: 'auto' }}>
                    {filtered.length} / {vulnerabilities.length} findings
                  </span>
                </div>

                <div className="card-body" style={{ padding: 0 }}>
                  {filtered.length === 0 ? (
                    <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>
                      <p>No findings match the current filter.</p>
                    </div>
                  ) : (
                    <div className="table-wrap" style={{ border: 'none', borderRadius: 0 }}>
                      <table style={{ borderCollapse: 'separate', borderSpacing: '0 2px' }}>
                        <thead>
                          <tr>
                            <th style={{ width: '30px' }}></th>
                            <th>Vulnerability</th>
                            <th>Severity</th>
                            <th style={{ width: '70px' }}>CVSS</th>
                            <th>Host</th>
                            <th>Port/Proto</th>
                            <th>CVE</th>
                            <th>Family</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filtered.map((v, idx) => {
                            const isExp = expandedRow === idx;
                            const border = severityBorder(v.severity);
                            return (
                              <>
                                <tr
                                  key={idx}
                                  onClick={() => setExpandedRow(isExp ? null : idx)}
                                  style={{ cursor: 'pointer', borderLeft: `3px solid ${border}`, transition: 'background 0.15s' }}
                                >
                                  <td style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
                                    {isExp ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                                  </td>
                                  <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{v.name}</td>
                                  <td><span className={`badge ${severityBadge(v.severity)}`}>{v.severity}</span></td>
                                  <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 'bold', color: border }}>{v.cvss?.toFixed(1)}</td>
                                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--violet-300)' }}>{v.host || '—'}</td>
                                  <td><code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--violet-300)' }}>{v.port}{v.protocol ? `/${v.protocol}` : ''}</code></td>
                                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: v.cve !== 'N/A' ? 'var(--severity-high)' : 'var(--text-muted)' }}>{v.cve}</td>
                                  <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{v.family}</td>
                                </tr>

                                {isExp && (
                                  <tr key={`${idx}-exp`}>
                                    <td colSpan={8} style={{ padding: '8px 16px 18px 16px', background: 'var(--bg-base, #f8fafc)' }}>
                                      <div style={{
                                        padding: '16px 20px',
                                        borderLeft: `4px solid ${border}`,
                                        borderRadius: '8px',
                                        background: 'var(--bg-surface, #ffffff)',
                                        border: '1px solid var(--border-default, #e2e8f0)',
                                        boxShadow: '0 4px 12px rgba(0, 0, 0, 0.05)',
                                        display: 'flex',
                                        flexDirection: 'column',
                                        gap: '14px'
                                      }}>
                                        {/* Description Section */}
                                        <div>
                                          <h5 style={{
                                            margin: '0 0 6px 0',
                                            color: 'var(--text-primary, #0f172a)',
                                            fontWeight: 700,
                                            fontSize: '13px',
                                            display: 'flex',
                                            alignItems: 'center',
                                            gap: '6px'
                                          }}>
                                            <FileText size={14} style={{ color: 'var(--violet-500, #7c3aed)' }} />
                                            <span>Vulnerability Description</span>
                                          </h5>
                                          <div style={{
                                            fontSize: '13px',
                                            lineHeight: 1.6,
                                            whiteSpace: 'pre-wrap',
                                            color: 'var(--text-primary, #1e293b)',
                                            background: 'var(--bg-base, #f8fafc)',
                                            padding: '12px 14px',
                                            borderRadius: '6px',
                                            border: '1px solid var(--border-default, #e2e8f0)',
                                            fontFamily: 'inherit'
                                          }}>
                                            {v.description || 'No description available.'}
                                          </div>
                                        </div>

                                        {/* Remediation Section */}
                                        {v.solution && (
                                          <div>
                                            <h5 style={{
                                              margin: '0 0 6px 0',
                                              color: 'var(--emerald-600, #059669)',
                                              fontWeight: 700,
                                              fontSize: '13px',
                                              display: 'flex',
                                              alignItems: 'center',
                                              gap: '6px'
                                            }}>
                                              <CheckCircle2 size={14} style={{ color: 'var(--emerald-500, #10b981)' }} />
                                              <span>Recommended Remediation</span>
                                            </h5>
                                            <div style={{
                                              fontSize: '13px',
                                              lineHeight: 1.6,
                                              whiteSpace: 'pre-wrap',
                                              color: 'var(--text-primary, #0f172a)',
                                              background: 'var(--emerald-dim, rgba(16, 185, 129, 0.08))',
                                              padding: '12px 14px',
                                              borderRadius: '6px',
                                              border: '1px solid rgba(16, 185, 129, 0.25)',
                                              fontFamily: 'inherit'
                                            }}>
                                              {v.solution}
                                            </div>
                                          </div>
                                        )}

                                        {/* Technical References & OID Footer */}
                                        <div style={{
                                          borderTop: '1px solid var(--border-default, #e2e8f0)',
                                          paddingTop: '10px',
                                          display: 'flex',
                                          flexWrap: 'wrap',
                                          alignItems: 'center',
                                          gap: '16px',
                                          fontSize: '12px',
                                          color: 'var(--text-secondary, #64748b)'
                                        }}>
                                          {v.nvt_oid && (
                                            <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                                              <strong>NVT OID:</strong>
                                              <code style={{
                                                background: 'var(--bg-base, #f1f5f9)',
                                                padding: '2px 6px',
                                                borderRadius: '4px',
                                                color: 'var(--text-primary, #0f172a)',
                                                fontSize: '11px',
                                                fontFamily: 'var(--font-mono)'
                                              }}>
                                                {v.nvt_oid}
                                              </code>
                                            </span>
                                          )}
                                          {v.qod && (
                                            <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                                              <strong>Detection Quality (QoD):</strong>
                                              <span className="badge badge-info" style={{ fontSize: '11px' }}>{v.qod}%</span>
                                            </span>
                                          )}
                                          {v.cve !== 'N/A' && v.cve && (
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                                              <strong>Advisories:</strong>
                                              {v.cve.split(',').map(c => c.trim()).filter(Boolean).map(cid => (
                                                <a
                                                  key={cid}
                                                  href={`https://nvd.nist.gov/vuln/detail/${cid}`}
                                                  target="_blank"
                                                  rel="noopener noreferrer"
                                                  style={{
                                                    color: 'var(--violet-600, #7c3aed)',
                                                    background: 'var(--violet-dim, rgba(124, 58, 237, 0.1))',
                                                    border: '1px solid rgba(124, 58, 237, 0.2)',
                                                    padding: '2px 8px',
                                                    borderRadius: '4px',
                                                    display: 'inline-flex',
                                                    alignItems: 'center',
                                                    gap: '4px',
                                                    textDecoration: 'none',
                                                    fontSize: '11px',
                                                    fontWeight: 600
                                                  }}
                                                >
                                                  <ExternalLink size={10} /> {cid}
                                                </a>
                                              ))}
                                            </div>
                                          )}
                                        </div>
                                      </div>
                                    </td>
                                  </tr>
                                )}
                              </>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </div>
            </>
          )}
        </div>
      )}

    </div>
  );
}
