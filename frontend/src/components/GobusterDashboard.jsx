import { useState } from 'react';
import {
  Globe, Settings2, Filter, BookOpen, Cpu, Download,
  Loader2, FolderOpen, AlertTriangle, CheckCircle2, Copy, Check, FileText
} from 'lucide-react';
import TargetSelector from './TargetSelector';

const WORDLISTS = {
  common:    '/usr/share/wordlists/dirb/common.txt',
  big:       '/usr/share/wordlists/dirb/big.txt',
  raft:      '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
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

function exportCSV(results) {
  const headers = ['status', 'path', 'size', 'redirect'];
  const rows = results.map(r => [r.status, r.path, r.size, r.redirect || '']);
  const csv = [headers, ...rows].map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  triggerFileDownload(blob, 'gobuster_results.csv');
}

export default function GobusterDashboard({ apiBase }) {
  const [targetUrl, setTargetUrl]         = useState('');
  const [mode, setMode]                   = useState('dir');
  const [wordlistKey, setWordlistKey]     = useState('common');
  const [customWordlist, setCustomWordlist] = useState('');
  const [extensions, setExtensions]       = useState('');
  const [ignoredCodes, setIgnoredCodes]   = useState('404');
  const [threads, setThreads]             = useState(20);
  const [followRedirects, setFollowRedirects] = useState(false);
  const [addHeaders, setAddHeaders]       = useState('');
  const [loading, setLoading]             = useState(false);
  const [results, setResults]             = useState(null);
  const [error, setError]                 = useState('');
  const [downloadingReport, setDownloadingReport] = useState(null);

  const downloadReport = async (fmt) => {
    if (!results || !targetUrl) return;
    setDownloadingReport(fmt);
    try {
      const res = await fetch(`${apiBase}/api/scanners/report/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tool: 'gobuster',
          target_url: targetUrl,
          results: results,
          format: fmt,
          metadata: {
            app_name: targetUrl.replace(/^https?:\/\//, '').split('/')[0],
            doc_title: `Web Application VAPT Report - Gobuster Enumeration`,
            prepared_by: 'VAPT Security Team'
          }
        })
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`Report generation failed (${res.status}): ${errText}`);
      }
      const blob = await res.blob();
      triggerFileDownload(blob, `vapt-gobuster-report-${Date.now()}.${fmt}`);
    } catch (e) {
      alert(`Report download error: ${e.message}`);
    } finally {
      setDownloadingReport(null);
    }
  };


  const runScan = async () => {
    if (!targetUrl.trim()) { setError('Target URL is required.'); return; }
    setLoading(true); setError(''); setResults(null);

    const wl = wordlistKey === 'custom' ? customWordlist : WORDLISTS[wordlistKey];
    const params = new URLSearchParams({
      host: targetUrl,
      mode,
      wordlist: wl || '',
      threads: String(threads),
      ignored_codes: ignoredCodes,
    });
    if (extensions.trim())     params.set('extensions', extensions.trim());
    if (followRedirects)       params.set('follow_redirect', 'true');
    if (addHeaders.trim())     params.set('headers', addHeaders.trim());

    try {
      const res = await fetch(`${apiBase}/api/scanners/gobuster/results?${params}`);
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
          <Globe size={15} style={{ color: 'var(--violet-300)' }} />
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

          <div className="form-group">
            <label className="form-label"><Settings2 size={13}/> Scan Mode</label>
            <select className="form-select" value={mode} onChange={e => setMode(e.target.value)}>
              <option value="dir">DIR — Directory Brute-Force</option>
              <option value="dns">DNS — Subdomain Enumeration</option>
              <option value="vhost">VHOST — Virtual Host Discovery</option>
              <option value="fuzz">FUZZ — URL Fuzzing</option>
            </select>
          </div>

          <div className="divider" />

          <div className="form-group">
            <label className="form-label"><BookOpen size={13}/> Wordlist</label>
            <select className="form-select" value={wordlistKey} onChange={e => setWordlistKey(e.target.value)}>
              <option value="common">common.txt — Fast (4,600 words)</option>
              <option value="big">big.txt — Thorough (20,000 words)</option>
              <option value="raft">directory-list-2.3 — Deep (220,000 words)</option>
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

          <div className="form-row form-row-2">
            <div className="form-group">
              <label className="form-label"><FolderOpen size={13}/> File Extensions</label>
              <input
                className="form-input"
                placeholder="php,html,txt"
                value={extensions}
                onChange={e => setExtensions(e.target.value)}
              />
            </div>
            <div className="form-group">
              <label className="form-label"><Filter size={13}/> Ignore Codes</label>
              <input
                className="form-input"
                placeholder="404,403"
                value={ignoredCodes}
                onChange={e => setIgnoredCodes(e.target.value)}
              />
            </div>
          </div>

          <div className="form-group">
            <label className="form-label"><Cpu size={13}/> Threads — {threads}</label>
            <input
              type="range" min={1} max={100}
              value={threads}
              onChange={e => setThreads(Number(e.target.value))}
            />
          </div>

          <div className="form-group">
            <label className="form-label">Custom Headers</label>
            <input
              className="form-input"
              placeholder="Authorization: Bearer token"
              value={addHeaders}
              onChange={e => setAddHeaders(e.target.value)}
            />
            <span className="form-hint">One header per field (key: value)</span>
          </div>

          <label className="toggle-wrapper">
            <div className="toggle">
              <input type="checkbox" checked={followRedirects} onChange={e => setFollowRedirects(e.target.checked)} />
              <span className="toggle-track" />
            </div>
            <span className="toggle-label">Follow Redirects</span>
          </label>

          <button
            className="btn btn-primary btn-full"
            onClick={runScan}
            disabled={loading || !targetUrl.trim()}
            style={{ marginTop: 4 }}
          >
            {loading
              ? <><Loader2 size={14} className="spin" /> Enumerating...</>
              : <><Globe size={14} /> Launch Gobuster</>
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
            <Globe size={40} />
            <h4>Ready to enumerate</h4>
            <p>Configure your wordlist and scan options, then launch Gobuster to discover hidden directories, files, and endpoints.</p>
          </div>
        )}

        {loading && (
          <div className="empty-state">
            <Loader2 size={36} className="spin" style={{ opacity: 0.5 }} />
            <h4>Gobuster scan running</h4>
            <p>Brute-forcing directories on <strong>{targetUrl}</strong>...</p>
          </div>
        )}

        {results && !loading && (
          <>
            <div className="scanner-results-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
              <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                {results.length} path{results.length !== 1 ? 's' : ''} discovered
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
                No paths found with the current wordlist and filters.
              </div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Status</th>
                      <th>Path</th>
                      <th>Size</th>
                      <th>Redirect</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.map((item, idx) => (
                      <tr key={idx}>
                        <td><span className={`badge ${getStatusBadge(item.status)}`}>{item.status}</span></td>
                        <td style={{ fontWeight: 600, color: 'var(--text-primary)' }} className="td-mono">{item.path}</td>
                        <td style={{ color: 'var(--text-muted)' }}>{item.size ? `${item.size}B` : '—'}</td>
                        <td className="td-mono">{item.redirect || '—'}</td>
                        <td><CopyButton text={item.path} /></td>
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
