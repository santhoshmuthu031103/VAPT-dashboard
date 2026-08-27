import { useState } from 'react';
import {
  Shield, Settings2, Filter, Tag, Zap, Download,
  Loader2, Globe, Clock, Layers, AlertTriangle, CheckCircle2, Info, FileText
} from 'lucide-react';
import TargetSelector from './TargetSelector';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];

function getBadgeClass(sev) {
  switch ((sev || '').toLowerCase()) {
    case 'critical': return 'badge-critical';
    case 'high':     return 'badge-high';
    case 'medium':   return 'badge-medium';
    case 'low':      return 'badge-low';
    default:         return 'badge-info';
  }
}

function SeveritySummary({ results }) {
  const counts = {};
  SEVERITY_ORDER.forEach(s => counts[s] = 0);
  results.forEach(r => {
    const s = (r.info?.severity || 'info').toLowerCase();
    counts[s] = (counts[s] || 0) + 1;
  });
  const entries = SEVERITY_ORDER.filter(s => counts[s] > 0);
  if (!entries.length) return null;
  return (
    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
      {entries.map(s => (
        <span key={s} className={`badge badge-${s}`}>
          {counts[s]} {s}
        </span>
      ))}
    </div>
  );
}

import { triggerFileDownload } from '../utils/downloadHelper';

function exportCSV(results) {
  const headers = ['severity', 'template-id', 'name', 'matched-at', 'host'];
  const rows = results.map(r => [
    r.info?.severity || 'info',
    r['template-id'] || '',
    r.info?.name || '',
    r['matched-at'] || r.host || '',
    r.host || '',
  ]);
  const csv = [headers, ...rows].map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  triggerFileDownload(blob, 'nuclei_results.csv');
}

export default function NucleiDashboard({ apiBase }) {
  const [targetUrl, setTargetUrl]           = useState('');
  const [category, setCategory]             = useState('all');
  const [severity, setSeverity]             = useState('info');
  const [rateLimit, setRateLimit]           = useState(150);
  const [concurrency, setConcurrency]       = useState(25);
  const [timeout, setTimeout_]              = useState(5);
  const [customTags, setCustomTags]         = useState('');
  const [loading, setLoading]               = useState(false);
  const [results, setResults]               = useState(null);
  const [error, setError]                   = useState('');
  const [expandedRow, setExpandedRow]       = useState(null);
  const [downloadingReport, setDownloadingReport] = useState(null);

  const downloadReport = async (fmt) => {
    if (!results || !targetUrl) return;
    setDownloadingReport(fmt);
    try {
      const res = await fetch(`${apiBase}/api/scanners/report/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tool: 'nuclei',
          target_url: targetUrl,
          results: results,
          format: fmt,
          metadata: {
            app_name: targetUrl.replace(/^https?:\/\//, '').split('/')[0],
            doc_title: `Web Application VAPT Report - Nuclei Vulnerability Scan`,
            prepared_by: 'VAPT Security Team'
          }
        })
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`Report generation failed (${res.status}): ${errText}`);
      }
      const blob = await res.blob();
      triggerFileDownload(blob, `vapt-nuclei-report-${Date.now()}.${fmt}`);
    } catch (e) {
      alert(`Report download error: ${e.message}`);
    } finally {
      setDownloadingReport(null);
    }
  };


  const runScan = async () => {
    if (!targetUrl.trim()) { setError('Target URL is required.'); return; }
    setLoading(true); setError(''); setResults(null); setExpandedRow(null);
    try {
      const params = new URLSearchParams({
        host: targetUrl,
        category,
        severity,
        rate_limit: rateLimit,
        concurrency,
        timeout,
        ...(customTags ? { custom_tags: customTags } : {})
      });
      const res = await fetch(`${apiBase}/api/scanners/nuclei/results?${params}`);
      if (!res.ok) throw new Error(`Server error: ${res.status}`);
      const data = await res.json();
      setResults(data);
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  const filtered = results
    ? results.filter(r => {
        const s = (r.info?.severity || 'info').toLowerCase();
        if (severity === 'info') return true;
        const order = SEVERITY_ORDER;
        return order.indexOf(s) <= order.indexOf(severity);
      })
    : null;

  return (
    <div className="scanner-layout">
      {/* ── Config Panel ── */}
      <div className="scanner-config-panel">
        <div className="scanner-config-header">
          <Shield size={15} style={{ color: 'var(--violet-300)' }} />
          <h3>Scan Configuration</h3>
        </div>
        <div className="scanner-config-body">

          <div className="form-group">
            <label className="form-label"><Globe size={13}/> Target URL / Host / Group</label>
            <TargetSelector
              value={targetUrl}
              onChange={(val) => setTargetUrl(val)}
              placeholder="https://example.com or choose Target Group..."
              apiBase={apiBase}
              disabled={loading}
            />
          </div>

          <div className="divider" />

          <div className="form-group">
            <label className="form-label"><Layers size={13}/> Template Category</label>
            <select className="form-select" value={category} onChange={e => setCategory(e.target.value)}>
              <option value="all">All Templates</option>
              <option value="cve">CVEs (Known Vulnerabilities)</option>
              <option value="vulnerability">General Vulnerabilities</option>
              <option value="misconfiguration">Misconfigurations</option>
              <option value="exposure">Exposures &amp; Data Leaks</option>
              <option value="default-login">Default Credentials</option>
              <option value="fuzzing">Fuzzing</option>
              <option value="network">Network Detection</option>
            </select>
          </div>

          <div className="form-group">
            <label className="form-label"><Filter size={13}/> Minimum Severity</label>
            <select className="form-select" value={severity} onChange={e => setSeverity(e.target.value)}>
              <option value="info">All (Info &amp; above)</option>
              <option value="low">Low &amp; above</option>
              <option value="medium">Medium &amp; above</option>
              <option value="high">High &amp; Critical only</option>
              <option value="critical">Critical only</option>
            </select>
          </div>

          <div className="form-group">
            <label className="form-label"><Tag size={13}/> Custom Tags</label>
            <input
              className="form-input"
              placeholder="e.g. xss,rce,ssrf"
              value={customTags}
              onChange={e => setCustomTags(e.target.value)}
            />
            <span className="form-hint">Comma-separated Nuclei template tags</span>
          </div>

          <div className="divider" />

          <div className="form-row form-row-2">
            <div className="form-group">
              <label className="form-label"><Zap size={13}/> Rate Limit</label>
              <input
                className="form-input"
                type="number" min={1} max={1000}
                value={rateLimit}
                onChange={e => setRateLimit(Number(e.target.value))}
              />
              <span className="form-hint">Req/sec</span>
            </div>
            <div className="form-group">
              <label className="form-label"><Layers size={13}/> Concurrency</label>
              <input
                className="form-input"
                type="number" min={1} max={100}
                value={concurrency}
                onChange={e => setConcurrency(Number(e.target.value))}
              />
              <span className="form-hint">Templates</span>
            </div>
          </div>

          <div className="form-group">
            <label className="form-label"><Clock size={13}/> Timeout (sec/template)</label>
            <input
              className="form-input"
              type="number" min={1} max={60}
              value={timeout}
              onChange={e => setTimeout_(Number(e.target.value))}
            />
          </div>

          <button
            className="btn btn-primary btn-full"
            onClick={runScan}
            disabled={loading || !targetUrl.trim()}
            style={{ marginTop: 4 }}
          >
            {loading
              ? <><Loader2 size={14} className="spin" /> Running Scan...</>
              : <><Shield size={14} /> Launch Nuclei Scan</>
            }
          </button>

          {results && results.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <button className="btn btn-primary btn-full btn-sm" onClick={() => downloadReport('pdf')} disabled={!!downloadingReport}>
                {downloadingReport === 'pdf' ? <Loader2 size={13} className="spin" /> : <FileText size={13} />}
                Download VAPT Report (PDF)
              </button>
              <button className="btn btn-secondary btn-full btn-sm" onClick={() => downloadReport('html')} disabled={!!downloadingReport}>
                {downloadingReport === 'html' ? <Loader2 size={13} className="spin" /> : <Download size={13} />}
                Download Report (HTML)
              </button>
              <button className="btn btn-ghost btn-full btn-sm" onClick={() => exportCSV(results)} style={{ fontSize: 11 }}>
                <Download size={12} /> Export CSV
              </button>
            </div>
          )}
        </div>
      </div>

      {/* ── Results Panel ── */}
      <div className="scanner-results-panel">
        {error && (
          <div className="alert alert-error">
            <AlertTriangle size={15} style={{ flexShrink: 0, marginTop: 1 }} />
            {error}
          </div>
        )}

        {!results && !loading && (
          <div className="empty-state">
            <Shield size={40} />
            <h4>No scan results yet</h4>
            <p>Configure your scan options and click <strong>Launch Nuclei Scan</strong> to begin template-based vulnerability detection.</p>
          </div>
        )}

        {loading && (
          <div className="empty-state">
            <Loader2 size={36} className="spin" style={{ opacity: 0.5 }} />
            <h4>Nuclei scan in progress</h4>
            <p>Running templates against <strong>{targetUrl}</strong>. This may take several minutes.</p>
          </div>
        )}

        {filtered && !loading && (
          <>
            <div className="scanner-results-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
              <div>
                <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
                  {filtered.length} finding{filtered.length !== 1 ? 's' : ''} detected
                </div>
                <SeveritySummary results={filtered} />
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn btn-primary btn-sm" onClick={() => downloadReport('pdf')} disabled={!!downloadingReport}>
                  {downloadingReport === 'pdf' ? <Loader2 size={13} className="spin" /> : <FileText size={13} />}
                  PDF Report
                </button>
                <button className="btn btn-secondary btn-sm" onClick={() => downloadReport('html')} disabled={!!downloadingReport}>
                  {downloadingReport === 'html' ? <Loader2 size={13} className="spin" /> : <Download size={13} />}
                  HTML Report
                </button>
              </div>
            </div>

            {filtered.length === 0 ? (
              <div className="alert alert-success">
                <CheckCircle2 size={15} style={{ flexShrink: 0, marginTop: 1 }} />
                No vulnerabilities found matching the selected filters.
              </div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      {filtered.some(i => i.host && i.host !== targetUrl) && <th>Host</th>}
                      <th>Severity</th>
                      <th>Template ID</th>
                      <th>Vulnerability</th>
                      <th>Matched URL</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map((item, idx) => {
                      const hasMultiHost = filtered.some(i => i.host && i.host !== targetUrl);
                      return (
                        <React.Fragment key={idx}>
                          <tr
                            style={{ cursor: 'pointer' }}
                            onClick={() => setExpandedRow(expandedRow === idx ? null : idx)}
                          >
                            {hasMultiHost && (
                              <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--violet-600)', fontWeight: 600 }}>
                                {item.host || '—'}
                              </td>
                            )}
                            <td>
                              <span className={`badge ${getBadgeClass(item.info?.severity)}`}>
                                {item.info?.severity || 'info'}
                              </span>
                            </td>
                            <td className="td-mono">{item['template-id']}</td>
                            <td style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{item.info?.name}</td>
                            <td className="td-mono">{item['matched-at'] || item.host}</td>
                          </tr>
                          {expandedRow === idx && (
                            <tr key={`${idx}-exp`}>
                              <td colSpan={hasMultiHost ? 5 : 4} style={{ background: 'var(--bg-elevated)', padding: '12px 16px' }}>
                                <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.7 }}>
                                  {item.info?.description && <p><strong>Description:</strong> {item.info.description}</p>}
                                  {item.info?.tags && <p><strong>Tags:</strong> {Array.isArray(item.info.tags) ? item.info.tags.join(', ') : item.info.tags}</p>}
                                  {item.info?.reference && <p><strong>References:</strong> {Array.isArray(item.info.reference) ? item.info.reference.join(', ') : item.info.reference}</p>}
                                  {item.host && <p><strong>Target Host:</strong> {item.host}</p>}
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
