import { useState } from 'react';
import {
  ScanSearch, Settings2, Clock, Zap, ShieldAlert,
  Download, Loader2, Globe, AlertTriangle, CheckCircle2,
  UserCircle, Lock, FileText
} from 'lucide-react';
import TargetSelector from './TargetSelector';

const TUNING_OPTS = [
  { value: 'all',      label: 'Full Scan — All Plugins' },
  { value: 'xss',     label: 'XSS — Cross-Site Scripting' },
  { value: 'sqli',    label: 'SQLi — SQL Injection' },
  { value: 'misconfig', label: 'Misconfigurations Only' },
];

const EVASION_OPTS = [
  { value: '0', label: 'None' },
  { value: '1', label: 'Random URI encoding' },
  { value: '2', label: 'Directory self-reference (/./)' },
  { value: '3', label: 'Premature URL ending' },
  { value: '4', label: 'Prepend long random string' },
];

import { triggerFileDownload } from '../utils/downloadHelper';

function exportCSV(results) {
  const headers = ['id', 'message'];
  const vulns = results.vulnerabilities || [];
  const rows = vulns.map(v => [v.id, v.msg]);
  const csv = [headers, ...rows].map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  triggerFileDownload(blob, 'nikto_results.csv');
}

export default function NiktoDashboard({ apiBase }) {
  const [effectiveHost, setEffectiveHost] = useState('127.0.0.1');
  const [port, setPort]                 = useState('80');
  const [ssl, setSsl]                   = useState(false);
  const [maxTime, setMaxTime]           = useState('15m');
  const [tuning, setTuning]             = useState('all');
  const [evasion, setEvasion]           = useState('0');
  const [userAgent, setUserAgent]       = useState('');
  const [authUser, setAuthUser]         = useState('');
  const [authPass, setAuthPass]         = useState('');
  const [loading, setLoading]           = useState(false);
  const [results, setResults]           = useState(null);
  const [error, setError]               = useState('');
  const [downloadingReport, setDownloadingReport] = useState(null);

  const downloadReport = async (fmt) => {
    if (!results || !effectiveHost) return;
    setDownloadingReport(fmt);
    try {
      const res = await fetch(`${apiBase}/api/scanners/report/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tool: 'nikto',
          target_url: `http${ssl ? 's' : ''}://${effectiveHost}:${port}`,
          results: results,
          format: fmt,
          metadata: {
            app_name: effectiveHost,
            doc_title: `Web Application VAPT Report - Nikto Audit`,
            prepared_by: 'VAPT Security Team'
          }
        })
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`Report generation failed (${res.status}): ${errText}`);
      }
      const blob = await res.blob();
      triggerFileDownload(blob, `vapt-nikto-report-${Date.now()}.${fmt}`);
    } catch (err) {
      console.error(err);
      alert('Report generation failed: ' + err.message);
    } finally {
      setDownloadingReport(null);
    }
  };

  const runScan = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    if (!effectiveHost.trim()) {
      setError('Please select or specify a target host');
      return;
    }
    setLoading(true);
    setError('');
    setResults(null);

    const payload = {
      host: effectiveHost.trim(),
      port: parseInt(port, 10) || 80,
      ssl,
      max_time: maxTime,
      tuning,
      evasion,
      user_agent: userAgent.trim() || undefined,
      auth_user: authUser.trim() || undefined,
      auth_pass: authPass.trim() || undefined,
    };

    try {
      const res = await fetch(`${apiBase}/api/scanners/nikto`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.detail || `Scan failed (HTTP ${res.status})`);
      }

      const data = await res.json();
      setResults(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="scanner-layout">
      {/* ── Config Panel ── */}
      <div className="scanner-config-panel">
        <div className="scanner-config-header">
          <ScanSearch size={15} style={{ color: 'var(--violet-300)' }} />
          <h3>Scan Configuration</h3>
        </div>
        <div className="scanner-config-body">

          <div className="form-group">
            <label className="form-label"><Globe size={13}/> Target Host / Group</label>
            <TargetSelector
              value={effectiveHost}
              onChange={(val) => setEffectiveHost(val)}
              placeholder="192.168.1.1 or choose Target Group..."
              apiBase={apiBase}
              disabled={loading}
              required
            />
          </div>

          <div className="form-row form-row-2">
            <div className="form-group">
              <label className="form-label">Port</label>
              <input className="form-input" value={port} onChange={e => setPort(e.target.value)} />
            </div>
            <div className="form-group" style={{ justifyContent: 'flex-end' }}>
              <label className="form-label">SSL/TLS</label>
              <label className="toggle-wrapper">
                <div className="toggle">
                  <input type="checkbox" checked={ssl} onChange={e => setSsl(e.target.checked)} />
                  <span className="toggle-track" />
                </div>
                <span className="toggle-label">{ssl ? 'Enabled' : 'Disabled'}</span>
              </label>
            </div>
          </div>

          <div className="divider" />

          <div className="form-group">
            <label className="form-label"><Zap size={13}/> Tuning Profile</label>
            <select className="form-select" value={tuning} onChange={e => setTuning(e.target.value)}>
              {TUNING_OPTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>

          <div className="form-group">
            <label className="form-label"><Clock size={13}/> Max Scan Time</label>
            <input
              className="form-input"
              placeholder="e.g. 15m, 1h"
              value={maxTime}
              onChange={e => setMaxTime(e.target.value)}
            />
            <span className="form-hint">Format: 30s, 15m, 1h</span>
          </div>

          <div className="form-group">
            <label className="form-label"><ShieldAlert size={13}/> Evasion Technique</label>
            <select className="form-select" value={evasion} onChange={e => setEvasion(e.target.value)}>
              {EVASION_OPTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>

          <div className="form-group">
            <label className="form-label"><Settings2 size={13}/> User-Agent Override</label>
            <input
              className="form-input"
              placeholder="Mozilla/5.0 ..."
              value={userAgent}
              onChange={e => setUserAgent(e.target.value)}
            />
          </div>

          <div className="divider" />

          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 4 }}>
            Basic Auth (optional)
          </div>
          <div className="form-row form-row-2">
            <div className="form-group">
              <label className="form-label"><UserCircle size={13}/> Username</label>
              <input className="form-input" placeholder="admin" value={authUser} onChange={e => setAuthUser(e.target.value)} />
            </div>
            <div className="form-group">
              <label className="form-label"><Lock size={13}/> Password</label>
              <input className="form-input" type="password" placeholder="••••••" value={authPass} onChange={e => setAuthPass(e.target.value)} />
            </div>
          </div>

          <button
            className="btn btn-primary btn-full"
            onClick={runScan}
            disabled={loading || !effectiveHost.trim()}
            style={{ marginTop: 4 }}
          >
            {loading
              ? <><Loader2 size={14} className="spin" /> Scanning...</>
              : <><ScanSearch size={14} /> Launch Nikto Scan</>
            }
          </button>

          {results?.vulnerabilities?.length > 0 && (
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
            <ScanSearch size={40} />
            <h4>Ready to audit</h4>
            <p>Select your target and configure the scan profile, then launch Nikto to audit the web server configuration.</p>
          </div>
        )}

        {loading && (
          <div className="empty-state">
            <Loader2 size={36} className="spin" style={{ opacity: 0.5 }} />
            <h4>Nikto scan in progress</h4>
            <p>Auditing <strong>{effectiveHost}</strong>:{port}. This may take several minutes.</p>
          </div>
        )}

        {results && !loading && (
          <>
            <div className="scanner-results-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
              <div>
                <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
                  Scan of{' '}
                  <span className="td-mono" style={{ color: 'var(--violet-300)' }}>{results.ip || results.host}</span>
                  {' '}:{results.port}
                </div>
                {results.banner && (
                  <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginTop: 2 }}>
                    {results.banner}
                  </div>
                )}
                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>
                  {results.vulnerabilities?.length || 0} findings detected
                </div>
              </div>
              {results.vulnerabilities?.length > 0 && (
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
              )}
            </div>

            {!results.vulnerabilities?.length ? (
              <div className="alert alert-success">
                <CheckCircle2 size={15} style={{ flexShrink: 0, marginTop: 1 }} />
                No vulnerabilities identified. The target may be unreachable or fully hardened.
              </div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Method</th>
                      <th>URI</th>
                      <th>Finding</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.vulnerabilities.map((v, idx) => (
                      <tr key={idx}>
                        <td className="td-mono" style={{ color: 'var(--text-muted)', fontSize: 11 }}>{v.id}</td>
                        <td><span className="badge badge-violet">{v.method || 'GET'}</span></td>
                        <td className="td-mono" style={{ color: 'var(--violet-300)', fontSize: 11 }}>{v.uri}</td>
                        <td style={{ color: 'var(--text-primary)' }}>{v.msg}</td>
                      </tr>
                    ))}
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
