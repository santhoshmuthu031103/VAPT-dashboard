import { useState, useEffect } from 'react';
import { Shield, ShieldAlert, ShieldX, FileText, Search, ChevronDown, ChevronUp, AlertCircle, RefreshCw, Info, ExternalLink, Clock, Download } from 'lucide-react';

export default function Reports({ apiBase, activeReportId, onBackToTasks }) {
  const [reportId, setReportId]       = useState(activeReportId || '');
  const [report, setReport]           = useState(null);
  const [loading, setLoading]         = useState(false);
  const [error, setError]             = useState(null);
  const [expandedRow, setExpandedRow] = useState(null);
  const [search, setSearch]           = useState('');
  const [severityFilter, setSeverity] = useState('ALL');
  const [downloading, setDownloading] = useState(null); // 'html' | 'xml' | null

  const handleDownload = async (fmt) => {
    if (!reportId) return;
    setDownloading(fmt);
    try {
      const res = await fetch(`${apiBase}/api/reports/${reportId}/download?fmt=${fmt}`);
      if (!res.ok) throw new Error('Download failed');
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href     = url;
      a.download = `openvas-report-${reportId.slice(0, 8)}.${fmt}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) { alert(`Export error: ${err.message}`); }
    finally { setDownloading(null); }
  };

  useEffect(() => {
    if (activeReportId) {
      setReportId(activeReportId);
      fetchReport(activeReportId);
    }
  }, [activeReportId]);  // eslint-disable-line react-hooks/exhaustive-deps

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
      case 'high':   return 'badge-high';
      case 'medium': return 'badge-medium';
      case 'low':    return 'badge-low';
      default:       return 'badge-log';
    }
  };

  const severityBorder = (sev) => {
    switch (sev?.toLowerCase()) {
      case 'high':   return 'var(--severity-high)';
      case 'medium': return 'var(--severity-medium)';
      case 'low':    return 'var(--severity-low)';
      default:       return 'var(--severity-log)';
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
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      <div>
        <h2 style={{ fontSize: '1.8rem', marginBottom: '0.5rem' }}>Vulnerability Audit Reports</h2>
        <p>Full OpenVAS findings — click any row to expand description, solution, and CVE links.</p>
      </div>

      {/* Report selector */}
      <div className="panel" style={{ display: 'flex', gap: '1rem', alignItems: 'center', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', flex: 1, gap: '0.75rem', minWidth: '280px' }}>
          <input
            type="text"
            placeholder="Enter GVM Report ID…"
            value={reportId}
            onChange={e => setReportId(e.target.value)}
          />
          <button className="btn btn-primary" onClick={() => fetchReport()} disabled={loading || !reportId}>
            {loading ? <RefreshCw className="animate-spin-slow" size={16} /> : 'Load Report'}
          </button>
        </div>
        {onBackToTasks && (
          <button className="btn btn-secondary" onClick={onBackToTasks}>← Back to Audits</button>
        )}
        {report && (
          <>
            <button
              className="btn btn-primary"
              style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}
              onClick={() => handleDownload('pdf')}
              disabled={!!downloading}
              title="Download PDF report"
            >
              {downloading === 'pdf' ? <RefreshCw size={14} className="animate-spin-slow" /> : <Download size={14} />}
              PDF
            </button>
            <button
              className="btn btn-secondary"
              style={{ color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
              onClick={() => handleDownload('xml')}
              disabled={!!downloading}
              title="Download raw GVM XML"
            >
              {downloading === 'xml' ? <RefreshCw size={14} className="animate-spin-slow" /> : <Download size={14} />}
              XML
            </button>
          </>
        )}
      </div>

      {loading ? (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '4rem', gap: '1.5rem' }}>
          <RefreshCw className="animate-spin-slow" size={40} style={{ color: 'var(--accent-cyan)' }} />
          <span className="text-secondary">Fetching full report from OpenVAS…</span>
        </div>
      ) : error ? (
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '2rem', border: '1px solid var(--severity-high)', borderRadius: '8px', backgroundColor: 'var(--severity-high-dim)' }}>
          <AlertCircle size={24} style={{ color: 'var(--severity-high)', flexShrink: 0 }} />
          <div>
            <h4 style={{ color: 'var(--severity-high)' }}>Failed to Load Report</h4>
            <p style={{ fontSize: '0.9rem' }}>{error}</p>
          </div>
        </div>
      ) : !report ? (
        <div style={{ textAlign: 'center', padding: '4rem', color: 'var(--text-secondary)' }} className="panel">
          <FileText size={48} className="text-muted" style={{ marginBottom: '1rem' }} />
          <h3>No Report Loaded</h3>
          <p style={{ fontSize: '0.9rem', marginTop: '0.5rem' }}>
            Run an audit from the <strong>Audits</strong> tab and click the <FileText size={13} style={{ verticalAlign: 'middle' }} /> icon on a completed task.
          </p>
        </div>
      ) : (
        <>
          {/* Scan Metadata */}
          <div className="panel" style={{ display: 'flex', gap: '2rem', flexWrap: 'wrap', alignItems: 'center' }}>
            <div>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Task</span>
              <p style={{ fontWeight: 700, marginTop: '0.2rem' }}>{report.task_name || '—'}</p>
            </div>
            <div>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: '4px' }}><Clock size={12} /> Scan Started</span>
              <p style={{ fontFamily: 'monospace', marginTop: '0.2rem', fontSize: '0.9rem' }}>{fmtDate(report.scan_start)}</p>
            </div>
            <div>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: '4px' }}><Clock size={12} /> Scan Ended</span>
              <p style={{ fontFamily: 'monospace', marginTop: '0.2rem', fontSize: '0.9rem' }}>{fmtDate(report.scan_end)}</p>
            </div>
          </div>

          {/* KPI cards */}
          <div className="grid-dashboard">
            {[
              { label: 'High', count: report.summary.high, color: 'var(--severity-high)', Icon: ShieldX },
              { label: 'Medium', count: report.summary.medium, color: 'var(--severity-medium)', Icon: ShieldAlert },
              { label: 'Low', count: report.summary.low, color: 'var(--severity-low)', Icon: Shield },
              { label: 'Log', count: report.summary.log, color: 'var(--severity-log)', Icon: Info },
            ].map(({ label, count, color, Icon }) => (
              <div key={label} className="panel" style={{ borderLeft: `4px solid ${color}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <span style={{ fontSize: '0.85rem', textTransform: 'uppercase', fontWeight: 600, color: 'var(--text-secondary)' }}>{label} Threats</span>
                  <h3 style={{ fontSize: '2.5rem', marginTop: '0.25rem', color }}>{count}</h3>
                </div>
                <Icon size={36} style={{ color }} />
              </div>
            ))}
          </div>

          {/* Filters */}
          <div className="panel" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', flexWrap: 'wrap' }}>
              <div style={{ position: 'relative', flex: 1, minWidth: '250px' }}>
                <Search size={16} className="text-muted" style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)' }} />
                <input type="text" placeholder="Filter by name, CVE, host, port…" value={search} onChange={e => setSearch(e.target.value)} style={{ paddingLeft: '2.5rem' }} />
              </div>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                {['ALL', 'HIGH', 'MEDIUM', 'LOW', 'LOG'].map(sev => (
                  <button
                    key={sev}
                    className={`btn ${severityFilter === sev ? 'btn-primary' : 'btn-secondary'}`}
                    onClick={() => { setSeverity(sev); setExpandedRow(null); }}
                    style={{ padding: '0.5rem 1rem', fontSize: '0.85rem' }}
                  >{sev}</button>
                ))}
              </div>
              <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>{filtered.length} / {vulnerabilities.length} findings</span>
            </div>

            {filtered.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-secondary)' }}>
                <p>No findings match the current filter.</p>
              </div>
            ) : (
              <div className="table-container">
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
                              {isExp ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                            </td>
                            <td style={{ fontWeight: 600 }}>{v.name}</td>
                            <td><span className={`badge ${severityBadge(v.severity)}`}>{v.severity}</span></td>
                            <td style={{ fontFamily: 'monospace', fontWeight: 'bold', color: border }}>{v.cvss?.toFixed(1)}</td>
                            <td style={{ fontFamily: 'monospace', fontSize: '0.85rem', color: 'var(--accent-cyan)' }}>{v.host || '—'}</td>
                            <td><code style={{ fontFamily: 'monospace', fontSize: '0.85rem', color: 'var(--accent-cyan)' }}>{v.port}{v.protocol ? `/${v.protocol}` : ''}</code></td>
                            <td style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: v.cve !== 'N/A' ? 'var(--severity-high)' : 'var(--text-muted)' }}>{v.cve}</td>
                            <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{v.family}</td>
                          </tr>

                          {isExp && (
                            <tr key={`${idx}-exp`}>
                              <td colSpan={8} style={{ padding: '0 1rem 1rem', background: 'rgba(0,0,0,0.3)' }}>
                                <div style={{ padding: '1.25rem', borderLeft: `4px solid ${border}`, borderRadius: '0 8px 8px 0', background: 'rgba(255,255,255,0.02)', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                                  {/* Description */}
                                  <div>
                                    <h5 style={{ marginBottom: '0.4rem', color: 'var(--text-primary)' }}>Description</h5>
                                    <p style={{ fontSize: '0.9rem', lineHeight: 1.6, whiteSpace: 'pre-wrap', color: 'var(--text-secondary)' }}>{v.description || 'No description available.'}</p>
                                  </div>

                                  {/* Solution */}
                                  {v.solution && (
                                    <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '0.75rem' }}>
                                      <h5 style={{ marginBottom: '0.4rem', color: 'var(--severity-log)' }}>Remediation</h5>
                                      <p style={{ fontSize: '0.9rem', lineHeight: 1.6, whiteSpace: 'pre-wrap', color: 'var(--text-secondary)' }}>{v.solution}</p>
                                    </div>
                                  )}

                                  {/* Metadata row */}
                                  <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '0.75rem', display: 'flex', flexWrap: 'wrap', gap: '1.5rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                                    {v.nvt_oid && <span><strong>NVT OID:</strong> <code style={{ color: 'var(--text-secondary)' }}>{v.nvt_oid}</code></span>}
                                    {v.qod && <span><strong>QoD:</strong> {v.qod}%</span>}
                                    {v.cve !== 'N/A' && v.cve && v.cve.split(',').map(c => c.trim()).filter(Boolean).map(cid => (
                                      <a key={cid} href={`https://nvd.nist.gov/vuln/detail/${cid}`} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '3px' }}>
                                        <ExternalLink size={12} /> {cid}
                                      </a>
                                    ))}
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
        </>
      )}
    </div>
  );
}
