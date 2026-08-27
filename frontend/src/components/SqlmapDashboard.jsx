import { useState } from 'react';
import {
  Database, ShieldAlert, Loader2, AlertTriangle, CheckCircle2, FileText, Download
} from 'lucide-react';
import TargetSelector from './TargetSelector';
import { triggerFileDownload } from '../utils/downloadHelper';

export default function SqlmapDashboard({ apiBase }) {
  const [targetUrl, setTargetUrl] = useState('');
  const [risk, setRisk]           = useState(1);
  const [level, setLevel]         = useState(1);
  const [forms, setForms]         = useState(false);
  const [loading, setLoading]     = useState(false);
  const [results, setResults]     = useState(null);
  const [error, setError]         = useState('');
  const [downloadingReport, setDownloadingReport] = useState(null);

  const downloadReport = async (fmt = 'pdf') => {
    if (!results) return;
    setDownloadingReport(fmt);
    try {
      const res = await fetch(`${apiBase}/api/scanners/report/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tool: 'sqlmap',
          target_url: targetUrl,
          results: results,
          format: fmt,
          metadata: {
            app_name: targetUrl,
            doc_title: 'Database Security & SQL Injection Assessment Report',
            organization: 'Security Operations'
          }
        })
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`Report generation failed (${res.status}): ${errText}`);
      }
      const blob = await res.blob();
      triggerFileDownload(blob, `vapt-sqlmap-audit-${targetUrl.replace(/[^a-zA-Z0-9.-]/g, '_')}.${fmt}`);
    } catch (err) {
      alert(`Report download error: ${err.message}`);
    } finally {
      setDownloadingReport(null);
    }
  };

  const runScan = async () => {
    if (!targetUrl.trim()) { setError('Target URL is required.'); return; }
    setLoading(true); setError(''); setResults(null);
    try {
      const params = new URLSearchParams({
        host: targetUrl,
        risk,
        level,
        forms
      });
      const res = await fetch(`${apiBase}/api/scanners/sqlmap/results?${params}`);
      if (!res.ok) throw new Error(`Server error: ${res.status}`);
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      setResults(data);
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  return (
    <div className="scanner-layout">
      {/* ── Config Panel ── */}
      <div className="scanner-config-panel">
        <div className="scanner-config-header">
          <Database size={15} style={{ color: 'var(--amber-400)' }} />
          <h3>SQLmap Configuration</h3>
        </div>
        <div className="scanner-config-body">

          <div className="form-group">
            <label className="form-label">Target URL / Host / Group</label>
            <TargetSelector
              value={targetUrl}
              onChange={(val) => setTargetUrl(val)}
              placeholder="http://example.com/vuln.php?id=1 or choose Target Group..."
              apiBase={apiBase}
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label className="form-label">Risk Level (1-3)</label>
            <input
              type="range" min={1} max={3}
              value={risk}
              onChange={e => setRisk(Number(e.target.value))}
            />
            <div style={{ textAlign: 'right', fontSize: 12, color: 'var(--text-muted)' }}>{risk}</div>
          </div>

          <div className="form-group">
            <label className="form-label">Scan Level (1-5)</label>
            <input
              type="range" min={1} max={5}
              value={level}
              onChange={e => setLevel(Number(e.target.value))}
            />
            <div style={{ textAlign: 'right', fontSize: 12, color: 'var(--text-muted)' }}>{level}</div>
          </div>

          <label className="toggle-wrapper">
            <div className="toggle">
              <input type="checkbox" checked={forms} onChange={e => setForms(e.target.checked)} />
              <span className="toggle-track" />
            </div>
            <span className="toggle-label">Test Forms (--forms)</span>
          </label>

          <button
            className="btn btn-primary btn-full"
            onClick={runScan}
            disabled={loading || !targetUrl.trim()}
            style={{ marginTop: 12 }}
          >
            {loading
              ? <><Loader2 size={14} className="spin" /> Scanning...</>
              : <><Database size={14} /> Launch SQLmap</>
            }
          </button>
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
            <Database size={40} />
            <h4>Ready for Injection Testing</h4>
            <p>Configure parameters and launch SQLmap to test for SQL injection vulnerabilities.</p>
          </div>
        )}

        {loading && (
          <div className="empty-state">
            <Loader2 size={36} className="spin" style={{ opacity: 0.5 }} />
            <h4>SQLmap scan running</h4>
            <p>Analyzing <strong>{targetUrl}</strong> for SQL injections...</p>
          </div>
        )}

        {results && !loading && (
          <>
            <div className="scanner-results-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
              <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                {results.injections?.length || 0} Injection(s) Found
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button
                  className="btn btn-primary btn-sm"
                  onClick={() => downloadReport('pdf')}
                  disabled={!!downloadingReport}
                >
                  {downloadingReport === 'pdf' ? <Loader2 size={13} className="spin" /> : <FileText size={13} />}
                  PDF Report
                </button>
                <button
                  className="btn btn-secondary btn-sm"
                  onClick={() => downloadReport('html')}
                  disabled={!!downloadingReport}
                >
                  {downloadingReport === 'html' ? <Loader2 size={13} className="spin" /> : <Download size={13} />}
                  HTML Report
                </button>
              </div>
            </div>

            {results.injections?.length === 0 ? (
              <div className="alert alert-success">
                <CheckCircle2 size={15} style={{ flexShrink: 0, marginTop: 1 }} />
                No SQL injections were found based on current risk and level settings.
              </div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Parameter</th>
                      <th>Type</th>
                      <th>Title</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.injections.map((item, idx) => (
                      <tr key={idx}>
                        <td style={{ fontWeight: 600, color: 'var(--red-400)' }}>{item.parameter}</td>
                        <td>{item.type}</td>
                        <td>{item.title}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            <div style={{ marginTop: '20px' }}>
              <h4>Raw Output</h4>
              <pre style={{
                background: 'var(--sidebar-bg)',
                padding: 12,
                borderRadius: 6,
                fontSize: 12,
                color: 'var(--text-muted)',
                maxHeight: '400px',
                overflowY: 'auto'
              }}>
                {results.raw_output}
              </pre>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
