import { useState } from 'react';
import {
  Search, Settings2, BookOpen, Cpu, AlertTriangle, CheckCircle2, Loader2, Copy, Check, FileText, Download
} from 'lucide-react';
import TargetSelector from './TargetSelector';

const WORDLISTS = {
  common:    '/usr/share/wordlists/dirb/common.txt',
  big:       '/usr/share/wordlists/dirb/big.txt',
  custom:    '__custom__',
};

function getStatusBadge(status) {
  if (status >= 200 && status < 300) return 'badge-success';
  if (status >= 300 && status < 400) return 'badge-info';
  if (status >= 400 && status < 500) return 'badge-medium';
  return 'badge-high';
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  const doCopy = (e) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  return (
    <button className="btn btn-ghost btn-icon btn-sm" onClick={doCopy} title="Copy path">
      {copied ? <Check size={12} style={{ color: 'var(--emerald-400)' }} /> : <Copy size={12} />}
    </button>
  );
}

import { triggerFileDownload } from '../utils/downloadHelper';

export default function FfufDashboard({ apiBase }) {
  const [targetUrl, setTargetUrl]         = useState('');
  const [wordlistKey, setWordlistKey]     = useState('common');
  const [customWordlist, setCustomWordlist] = useState('');
  const [threads, setThreads]             = useState(40);
  const [loading, setLoading]             = useState(false);
  const [results, setResults]             = useState(null);
  const [error, setError]                 = useState('');
  const [downloadingReport, setDownloadingReport] = useState(null);

  const downloadReport = async (fmt = 'pdf') => {
    if (!results) return;
    setDownloadingReport(fmt);
    try {
      const res = await fetch(`${apiBase}/api/scanners/report/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tool: 'ffuf',
          target_url: targetUrl,
          results: results,
          format: fmt,
          metadata: {
            app_name: targetUrl,
            doc_title: 'Web Application Fuzzing & Endpoint Discovery Report',
            organization: 'Security Operations'
          }
        })
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`Report generation failed (${res.status}): ${errText}`);
      }
      const blob = await res.blob();
      triggerFileDownload(blob, `vapt-ffuf-audit-${targetUrl.replace(/[^a-zA-Z0-9.-]/g, '_')}.${fmt}`);
    } catch (err) {
      alert(`Report download error: ${err.message}`);
    } finally {
      setDownloadingReport(null);
    }
  };

  const runScan = async () => {
    if (!targetUrl.trim()) { setError('Target URL is required.'); return; }
    setLoading(true); setError(''); setResults(null);
    const wordlist = wordlistKey === 'custom' ? customWordlist : WORDLISTS[wordlistKey];
    try {
      const params = new URLSearchParams({
        host: targetUrl,
        wordlist,
        threads
      });
      const res = await fetch(`${apiBase}/api/scanners/ffuf/results?${params}`);
      if (!res.ok) throw new Error(`Server error: ${res.status}`);
      const data = await res.json();
      if (data.length > 0 && data[0].error) throw new Error(data[0].error);
      setResults(data);
    } catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };

  return (
    <div className="scanner-layout">
      {/* ── Config Panel ── */}
      <div className="scanner-config-panel">
        <div className="scanner-config-header">
          <Search size={15} style={{ color: 'var(--blue-400)' }} />
          <h3>FFuF Configuration</h3>
        </div>
        <div className="scanner-config-body">

          <div className="form-group">
            <label className="form-label">Target URL / Host / Group</label>
            <TargetSelector
              value={targetUrl}
              onChange={(val) => {
                if (val && !val.includes('FUZZ') && val.startsWith('http')) {
                  setTargetUrl(val.endsWith('/') ? `${val}FUZZ` : `${val}/FUZZ`);
                } else {
                  setTargetUrl(val);
                }
              }}
              placeholder="http://example.com/FUZZ or choose Target Group..."
              apiBase={apiBase}
              disabled={loading}
            />
            <span className="form-hint">Use 'FUZZ' keyword where you want to fuzz endpoints.</span>
          </div>

          <div className="divider" />

          <div className="form-group">
            <label className="form-label"><BookOpen size={13}/> Wordlist</label>
            <select className="form-select" value={wordlistKey} onChange={e => setWordlistKey(e.target.value)}>
              <option value="common">common.txt — Fast (4,600 words)</option>
              <option value="big">big.txt — Thorough (20,000 words)</option>
              <option value="custom">Custom Path...</option>
            </select>
          </div>

          {wordlistKey === 'custom' && (
            <div className="form-group">
              <label className="form-label">Custom Wordlist Path</label>
              <input
                className="form-input"
                placeholder="/path/to/wordlist.txt"
                value={customWordlist}
                onChange={e => setCustomWordlist(e.target.value)}
              />
            </div>
          )}

          <div className="form-group">
            <label className="form-label"><Cpu size={13}/> Threads — {threads}</label>
            <input
              type="range" min={1} max={100}
              value={threads}
              onChange={e => setThreads(Number(e.target.value))}
            />
          </div>

          <button
            className="btn btn-primary btn-full"
            onClick={runScan}
            disabled={loading || !targetUrl.trim()}
            style={{ marginTop: 12 }}
          >
            {loading
              ? <><Loader2 size={14} className="spin" /> Fuzzing...</>
              : <><Search size={14} /> Launch FFuF</>
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
            <Search size={40} />
            <h4>Ready to Fuzz</h4>
            <p>Configure your wordlist and launch FFuF to discover paths or parameters.</p>
          </div>
        )}

        {loading && (
          <div className="empty-state">
            <Loader2 size={36} className="spin" style={{ opacity: 0.5 }} />
            <h4>FFuF scan running</h4>
            <p>Fuzzing <strong>{targetUrl}</strong>...</p>
          </div>
        )}

        {results && !loading && (
          <>
            <div className="scanner-results-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
              <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                {results.length} Match{results.length !== 1 ? 'es' : ''} Discovered
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

            {results.length === 0 ? (
              <div className="alert alert-success">
                <CheckCircle2 size={15} style={{ flexShrink: 0, marginTop: 1 }} />
                No results found.
              </div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Status</th>
                      <th>Match (FUZZ)</th>
                      <th>Length</th>
                      <th>Words</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.map((item, idx) => (
                      <tr key={idx}>
                        <td><span className={`badge ${getStatusBadge(item.status)}`}>{item.status}</span></td>
                        <td style={{ fontWeight: 600, color: 'var(--text-primary)' }} className="td-mono">{item.input?.FUZZ || JSON.stringify(item.input)}</td>
                        <td style={{ color: 'var(--text-muted)' }}>{item.length}</td>
                        <td style={{ color: 'var(--text-muted)' }}>{item.words}</td>
                        <td><CopyButton text={item.url} /></td>
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
