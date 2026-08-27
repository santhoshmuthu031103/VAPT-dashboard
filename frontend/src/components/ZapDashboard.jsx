import { useState } from 'react';
import {
  Zap, ShieldCheck, Settings2, Globe, Download,
  Loader2, AlertTriangle, CheckCircle2, ExternalLink,
  Clock, Layers, Filter, FileText
} from 'lucide-react';
import { DonutChart } from './SvgCharts';
import TargetSelector from './TargetSelector';

function getRiskBadge(risk) {
  switch ((risk || '').toLowerCase()) {
    case 'high':   return 'badge-high';
    case 'medium': return 'badge-medium';
    case 'low':    return 'badge-low';
    default:       return 'badge-info';
  }
}

import { triggerFileDownload } from '../utils/downloadHelper';

function exportCSV(results) {
  const headers = ['risk', 'alert', 'confidence', 'url', 'description'];
  const rows = results.map(r => [r.risk, r.alert, r.confidence, r.url, r.description || '']);
  const csv = [headers, ...rows].map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  triggerFileDownload(blob, 'zap_results.csv');
}


export default function ZapDashboard({ apiBase }) {
  const [targetUrl, setTargetUrl]       = useState('');
  const [policy, setPolicy]             = useState('default');
  const [strength, setStrength]         = useState('Medium');
  const [spiderDepth, setSpiderDepth]   = useState(5);
  const [maxCrawlDuration, setMaxCrawlDuration] = useState(2);
  const [ajaxSpider, setAjaxSpider]     = useState(false);
  const [includeRegex, setIncludeRegex] = useState('');
  const [excludeRegex, setExcludeRegex] = useState('');
  const [loading, setLoading]           = useState(false);
  const [results, setResults]           = useState(null);
  const [error, setError]               = useState('');
  const [expandedRow, setExpandedRow]   = useState(null);
  const [downloadingReport, setDownloadingReport] = useState(null); // 'pdf' | 'html' | null

  const downloadReport = async (fmt) => {
    if (!results || !targetUrl) return;
    setDownloadingReport(fmt);
    try {
      const res = await fetch(`${apiBase}/api/scanners/report/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tool: 'zap',
          target_url: targetUrl,
          results: results,
          format: fmt,
          metadata: {
            app_name: targetUrl.replace(/^https?:\/\//, '').split('/')[0],
            doc_title: `Web Application VAPT Report - OWASP ZAP`,
            prepared_by: 'VAPT Security Team'
          }
        })
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`Report generation failed (${res.status}): ${errText}`);
      }
      const blob = await res.blob();
      triggerFileDownload(blob, `vapt-zap-report-${Date.now()}.${fmt}`);
    } catch (e) {
      alert(`Report download error: ${e.message}`);
    } finally {
      setDownloadingReport(null);
    }
  };


  const runScan = async () => {
    if (!targetUrl.trim()) { setError('Target URL is required.'); return; }
    setLoading(true); setError(''); setResults(null);
    try {
      const res = await fetch(`${apiBase}/api/scanners/zap/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_url: targetUrl,
          policy,
          strength,
          spider_depth: spiderDepth,
          max_crawl_duration: maxCrawlDuration,
          ajax_spider: ajaxSpider,
          include_regex: includeRegex || null,
          exclude_regex: excludeRegex || null,
        }),
      });
      if (!res.ok) throw new Error(`Server error: ${res.status}`);
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setResults(data);
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  const riskCounts = { High: 0, Medium: 0, Low: 0, Informational: 0 };
  (results || []).forEach(r => {
    const k = r.risk in riskCounts ? r.risk : 'Informational';
    riskCounts[k]++;
  });

  return (
    <div className="scanner-layout">
      {/* ── Config Panel ── */}
      <div className="scanner-config-panel">
        <div className="scanner-config-header">
          <Zap size={15} style={{ color: 'var(--violet-300)' }} />
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
            <label className="form-label"><ShieldCheck size={13}/> Scan Policy</label>
            <select className="form-select" value={policy} onChange={e => setPolicy(e.target.value)}>
              <option value="default">Default Policy — Balanced</option>
              <option value="api">API Scan — REST/GraphQL focus</option>
              <option value="stealth">Stealth — Passive only (no active attacks)</option>
            </select>
          </div>

          <div className="form-group">
            <label className="form-label"><Zap size={13}/> Attack Strength</label>
            <select className="form-select" value={strength} onChange={e => setStrength(e.target.value)}>
              <option value="Low">Low — Minimal payloads, safe</option>
              <option value="Medium">Medium — Standard coverage</option>
              <option value="High">High — Thorough, more requests</option>
              <option value="Insane">Insane — Maximum coverage</option>
            </select>
          </div>

          <div className="divider" />

          <div className="form-row form-row-2">
            <div className="form-group">
              <label className="form-label"><Layers size={13}/> Spider Depth</label>
              <input
                className="form-input"
                type="number" min={1} max={20}
                value={spiderDepth}
                onChange={e => setSpiderDepth(Number(e.target.value))}
              />
            </div>
            <div className="form-group">
              <label className="form-label"><Clock size={13}/> Crawl (min)</label>
              <input
                className="form-input"
                type="number" min={1} max={60}
                value={maxCrawlDuration}
                onChange={e => setMaxCrawlDuration(Number(e.target.value))}
              />
            </div>
          </div>

          <label className="toggle-wrapper">
            <div className="toggle">
              <input type="checkbox" checked={ajaxSpider} onChange={e => setAjaxSpider(e.target.checked)} />
              <span className="toggle-track" />
            </div>
            <span className="toggle-label">Ajax Spider (JS-heavy apps)</span>
          </label>

          <div className="divider" />

          <div className="form-group">
            <label className="form-label"><Filter size={13}/> Include URL Regex</label>
            <input
              className="form-input"
              placeholder="e.g. .*\.example\.com.*"
              value={includeRegex}
              onChange={e => setIncludeRegex(e.target.value)}
            />
          </div>

          <div className="form-group">
            <label className="form-label"><Filter size={13}/> Exclude URL Regex</label>
            <input
              className="form-input"
              placeholder="e.g. .*logout.*"
              value={excludeRegex}
              onChange={e => setExcludeRegex(e.target.value)}
            />
          </div>

          <button
            className="btn btn-primary btn-full"
            onClick={runScan}
            disabled={loading || !targetUrl.trim()}
            style={{ marginTop: 4 }}
          >
            {loading
              ? <><Loader2 size={14} className="spin" /> Scanning...</>
              : <><Zap size={14} /> Launch ZAP Scan</>
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
            <Zap size={40} />
            <h4>DAST scanner ready</h4>
            <p>Configure your scan policy and attack strength, then launch ZAP to perform dynamic application security testing.</p>
          </div>
        )}

        {loading && (
          <div className="empty-state">
            <Loader2 size={36} className="spin" style={{ opacity: 0.5 }} />
            <h4>ZAP scan in progress</h4>
            <p>Spidering and actively scanning <strong>{targetUrl}</strong>. This may take several minutes.</p>
          </div>
        )}

        {results && !loading && (
          <>
            <div className="scanner-results-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
              <div>
                <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
                  {results.length} alert{results.length !== 1 ? 's' : ''} discovered
                </div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  {['High','Medium','Low','Informational'].map(r => {
                    const c = (riskGroups?.[r] || []).length;
                    if (!c) return null;
                    return (
                      <span key={r} className={`badge badge-${r.toLowerCase() === 'informational' ? 'info' : r.toLowerCase()}`}>
                        {c} {r}
                      </span>
                    );
                  })}
                </div>
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

            {results.length === 0 ? (
              <div className="alert alert-success">
                <CheckCircle2 size={15} style={{ flexShrink: 0, marginTop: 1 }} />
                No alerts discovered by OWASP ZAP.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                <div className="card" style={{ padding: '1rem 1.5rem', display: 'flex', justifyContent: 'center' }}>
                  <DonutChart
                    title="Alerts"
                    data={[
                      { name: 'High', value: (riskGroups?.['High'] || []).length, color: '#b91c1c' },
                      { name: 'Medium', value: (riskGroups?.['Medium'] || []).length, color: '#ea580c' },
                      { name: 'Low', value: (riskGroups?.['Low'] || []).length, color: '#0284c7' },
                      { name: 'Info', value: (riskGroups?.['Informational'] || []).length, color: '#64748b' }
                    ]}
                  />
                </div>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        {results.some(a => a.host && a.host !== targetUrl) && <th>Host</th>}
                        <th>Risk</th>
                        <th>Alert</th>
                        <th>Confidence</th>
                        <th>URL</th>
                      </tr>
                    </thead>
                    <tbody>
                      {results.map((alert, idx) => {
                        const hasMultiHost = results.some(a => a.host && a.host !== targetUrl);
                        return (
                          <React.Fragment key={idx}>
                            <tr
                              style={{ cursor: 'pointer' }}
                              onClick={() => setExpandedRow(expandedRow === idx ? null : idx)}
                            >
                              {hasMultiHost && (
                                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--violet-600)', fontWeight: 600 }}>
                                  {alert.host || '—'}
                                </td>
                              )}
                              <td><span className={`badge ${getRiskBadge(alert.risk)}`}>{alert.risk}</span></td>
                              <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{alert.alert}</td>
                              <td>{alert.confidence}</td>
                              <td>
                                <a
                                  className="td-mono"
                                  href={alert.url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  style={{ color: 'var(--violet-300)', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 4 }}
                                  onClick={e => e.stopPropagation()}
                                >
                                  {(alert.url || '').substring(0, 50)}{(alert.url || '').length > 50 ? '...' : ''}
                                  <ExternalLink size={11} />
                                </a>
                              </td>
                            </tr>
                            {expandedRow === idx && (
                              <tr key={`${idx}-exp`}>
                                <td colSpan={hasMultiHost ? 5 : 4} style={{ background: 'var(--bg-elevated)', padding: '14px 16px' }}>
                                  <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.8 }}>
                                    {alert.host && <p><strong>Target Host:</strong> {alert.host}</p>}
                                    {alert.description && <p><strong>Description:</strong> {alert.description}</p>}
                                    {alert.solution && <p><strong>Solution:</strong> {alert.solution}</p>}
                                    {alert.reference && <p><strong>Reference:</strong> {alert.reference}</p>}
                                    {alert.cweid && <p><strong>CWE ID:</strong> CWE-{alert.cweid}</p>}
                                    {alert.wascid && <p><strong>WASC ID:</strong> WASC-{alert.wascid}</p>}
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
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
