import { useState, useEffect, useRef } from 'react';
import { Play, Square, Trash2, Plus, RefreshCw, FileText, CheckCircle2, AlertTriangle, Search, Download } from 'lucide-react';

export default function Tasks({ apiBase, onSelectReport }) {
  const [tasks, setTasks]           = useState([]);
  const [targets, setTargets]       = useState([]);
  const [configs, setConfigs]       = useState([]);
  const [scanners, setScanners]     = useState([]);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState(null);

  const [searchTerm, setSearchTerm] = useState('');
  const [page, setPage]             = useState(1);
  const [limit]                     = useState(10);
  const [totalTasks, setTotalTasks] = useState(0);

  // Form state
  const [showAddForm, setShowAddForm] = useState(false);
  const [name, setName]               = useState('');
  const [targetId, setTargetId]       = useState('');
  const [configId, setConfigId]       = useState('');
  const [scannerId, setScannerId]     = useState('');
  const [submitting, setSubmitting]   = useState(false);
  const [formError, setFormError]     = useState(null);
  const [downloadingId, setDownloading] = useState(null); // track which report is downloading

  const pollRef = useRef(null);

  const fetchInitialData = async (silent = false) => {
    if (!silent) setLoading(true);
    setError(null);
    try {
      const [tasksRes, targetsRes, configsRes, scannersRes] = await Promise.all([
        fetch(`${apiBase}/api/tasks?page=${page}&limit=${limit}`),
        fetch(`${apiBase}/api/targets`),
        fetch(`${apiBase}/api/scan-configs`),
        fetch(`${apiBase}/api/scanners`),
      ]);
      if (!tasksRes.ok)    throw new Error('Failed to retrieve tasks');
      if (!targetsRes.ok)  throw new Error('Failed to retrieve targets');
      if (!configsRes.ok)  throw new Error('Failed to retrieve scan configs');

      const tasksData    = await tasksRes.json();
      const targetsData  = await targetsRes.json();
      const configsData  = await configsRes.json();
      const scannersData = scannersRes.ok ? await scannersRes.json() : [];

      setTasks(tasksData.tasks || []);
      setTotalTasks(tasksData.total || 0);
      setTargets(targetsData);
      setConfigs(configsData);
      setScanners(scannersData);

      if (configsData.length) {
        setConfigId(prev => prev || configsData[0].id);
      }
      if (scannersData.length) {
        setScannerId(prev => {
          if (prev) return prev;
          const defaultScanner = scannersData.find(s => s.name === 'OpenVAS Default') || scannersData[0];
          return defaultScanner.id;
        });
      }
    } catch (err) {
      setError(err.message);
    } finally {
      if (!silent) setLoading(false);
    }
  };

  useEffect(() => {
    fetchInitialData();
    pollRef.current = setInterval(() => fetchInitialData(true), 5000);
    return () => clearInterval(pollRef.current);
  }, [page]);  // eslint-disable-line react-hooks/exhaustive-deps

  const handleCreate = async (e) => {
    e.preventDefault(); setSubmitting(true); setFormError(null);
    try {
      const res = await fetch(`${apiBase}/api/tasks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer admin-token' },
        body: JSON.stringify({ name, target_id: targetId, config_id: configId, scanner_id: scannerId }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Failed to create task');
      setName(''); setTargetId(''); setShowAddForm(false);
      fetchInitialData();
    } catch (err) { setFormError(err.message); }
    finally { setSubmitting(false); }
  };

  const handleStart = async (taskId) => {
    try {
      const res = await fetch(`${apiBase}/api/tasks/${taskId}/start`, {
        method: 'POST', headers: { 'Authorization': 'Bearer admin-token' }
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Failed to start scan');
      fetchInitialData(true);
    } catch (err) { alert(`Error: ${err.message}`); }
  };

  const handleStop = async (taskId) => {
    try {
      const res = await fetch(`${apiBase}/api/tasks/${taskId}/stop`, {
        method: 'POST', headers: { 'Authorization': 'Bearer admin-token' }
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Failed to stop scan');
      fetchInitialData(true);
    } catch (err) { alert(`Error: ${err.message}`); }
  };

  const handleDelete = async (taskId) => {
    if (!confirm('Delete this scan task?')) return;
    try {
      const res = await fetch(`${apiBase}/api/tasks/${taskId}`, {
      method: 'DELETE', headers: { 'Authorization': 'Bearer admin-token' }
    });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Failed to delete');
      fetchInitialData();
    } catch (err) { alert(`Error: ${err.message}`); }
  };

  const handleDownload = async (reportId, taskName, fmt = 'html') => {
    setDownloading(reportId);
    try {
      const res = await fetch(`${apiBase}/api/reports/${reportId}/download?fmt=${fmt}`);
      if (!res.ok) throw new Error('Download failed');
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      const safeName = (taskName || 'report').replace(/[^a-z0-9]/gi, '_').toLowerCase();
      a.href     = url;
      a.download = `openvas-${safeName}-${reportId.slice(0, 8)}.${fmt}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) { alert(`Download error: ${err.message}`); }
    finally { setDownloading(null); }
  };

  const getStatusBadge = (status, progress) => {
    switch (status?.toLowerCase()) {
      case 'done':
        return <span className="badge badge-log"><CheckCircle2 size={12} /> Done</span>;
      case 'running':
        return (
          <span className="badge badge-cyan" style={{ border: '1px solid var(--accent-cyan)', color: 'var(--accent-cyan)', background: 'var(--accent-cyan-dim)' }}>
            <RefreshCw size={12} className="animate-spin-slow" /> Running {progress > 0 ? `(${progress}%)` : ''}
          </span>
        );
      case 'new':
        return <span className="badge badge-low">Ready</span>;
      case 'stopped':
        return <span className="badge badge-medium"><AlertTriangle size={12} /> Stopped</span>;
      default:
        return <span className="badge badge-log">{status || '—'}</span>;
    }
  };

  const filteredTasks = tasks.filter(t =>
    (t.name || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
    (t.target_name || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
    (t.target_hosts || '').toLowerCase().includes(searchTerm.toLowerCase())
  );

  const totalPages = Math.ceil(totalTasks / limit);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.8rem', marginBottom: '0.5rem' }}>OpenVAS Vulnerability Audits</h2>
          <p>Configure and run live scan tasks. Click <FileText size={13} style={{ verticalAlign: 'middle' }} /> on a completed task to view its report.</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowAddForm(!showAddForm)}>
          <Plus size={16} /> Create Audit Task
        </button>
      </div>

      {showAddForm && (
        <div className="panel" style={{ borderLeft: '4px solid var(--accent-cyan)' }}>
          <h3 style={{ marginBottom: '1.25rem' }}>New Audit Task</h3>
          <form onSubmit={handleCreate} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '1.25rem' }}>
              <div>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Task Name</label>
                <input type="text" placeholder="e.g. Monthly Web Server Audit" value={name} onChange={e => setName(e.target.value)} required />
              </div>
              <div>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Target Scope</label>
                <select value={targetId} onChange={e => setTargetId(e.target.value)} required>
                  <option value="">— Select Target —</option>
                  {targets.map(t => <option key={t.id} value={t.id}>{t.name} ({t.hosts})</option>)}
                </select>
              </div>
              <div>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Scan Configuration</label>
                <select value={configId} onChange={e => setConfigId(e.target.value)}>
                  {configs.length === 0
                    ? <option value="">Loading…</option>
                    : configs.map(c => <option key={c.id} value={c.id}>{c.name}</option>)
                  }
                </select>
              </div>
              <div>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Scanner</label>
                <select value={scannerId} onChange={e => setScannerId(e.target.value)}>
                  {scanners.length === 0
                    ? <option value="08b69003-5fc2-4037-a479-93b440211c73">OpenVAS Default</option>
                    : scanners.map(s => <option key={s.id} value={s.id}>{s.name}</option>)
                  }
                </select>
              </div>
            </div>
            {formError && <div className="badge badge-high" style={{ padding: '0.75rem', width: '100%', textTransform: 'none', fontSize: '0.9rem' }}>{formError}</div>}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '1rem' }}>
              <button type="button" className="btn btn-secondary" onClick={() => setShowAddForm(false)}>Cancel</button>
              <button type="submit" className="btn btn-primary" disabled={submitting}>
                {submitting ? <RefreshCw className="animate-spin-slow" size={16} /> : null} Register Task
              </button>
            </div>
          </form>
        </div>
      )}

      <div className="panel" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
          <div style={{ position: 'relative', flex: 1 }}>
            <Search size={18} className="text-muted" style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)' }} />
            <input type="text" placeholder="Search tasks by name, target, or IP…" value={searchTerm} onChange={e => setSearchTerm(e.target.value)} style={{ paddingLeft: '2.5rem' }} />
          </div>
          <button className="btn btn-secondary" onClick={() => fetchInitialData()} disabled={loading}>
            <RefreshCw size={16} className={loading ? 'animate-spin-slow' : ''} />
          </button>
        </div>

        {loading ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '3rem', gap: '1rem' }}>
            <RefreshCw className="animate-spin-slow" size={32} style={{ color: 'var(--accent-cyan)' }} />
            <span className="text-secondary">Loading from OpenVAS…</span>
          </div>
        ) : error ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '2rem', border: '1px solid var(--severity-high)', borderRadius: '8px', backgroundColor: 'var(--severity-high-dim)' }}>
            <AlertTriangle size={24} style={{ color: 'var(--severity-high)', flexShrink: 0 }} />
            <div><h4 style={{ color: 'var(--severity-high)' }}>Error Loading Tasks</h4><p style={{ fontSize: '0.9rem' }}>{error}</p></div>
          </div>
        ) : (
          <>
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Task Name</th>
                    <th>Target</th>
                    <th>Config</th>
                    <th>Scanner</th>
                    <th>Status</th>
                    <th style={{ width: '120px', textAlign: 'center' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredTasks.length === 0 ? (
                    <tr><td colSpan={6} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>No tasks found. Create one above.</td></tr>
                  ) : filteredTasks.map(t => (
                    <tr key={t.id} style={{ cursor: t.report_id ? 'pointer' : 'default' }}
                        title={t.report_id ? 'Click anywhere to view report' : ''}>
                      <td onClick={t.report_id ? () => onSelectReport(t.report_id) : undefined} style={{ fontWeight: 600 }}>
                        {t.name}
                      </td>
                      <td onClick={t.report_id ? () => onSelectReport(t.report_id) : undefined}>
                        {t.target_name} <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>({t.target_hosts})</span>
                      </td>
                      <td onClick={t.report_id ? () => onSelectReport(t.report_id) : undefined} style={{ fontSize: '0.85rem' }}>{t.config_name || '—'}</td>
                      <td onClick={t.report_id ? () => onSelectReport(t.report_id) : undefined} style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>{t.scanner_name}</td>
                      <td onClick={t.report_id ? () => onSelectReport(t.report_id) : undefined}>{getStatusBadge(t.status, t.progress)}</td>
                      <td>
                        <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'center', alignItems: 'center' }}>
                          {t.status?.toLowerCase() === 'new' && (
                            <button className="btn btn-secondary" style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }} onClick={() => handleStart(t.id)} title="Start Scan">
                              <Play size={13} />
                            </button>
                          )}
                          {t.status?.toLowerCase() === 'running' && (
                            <button className="btn btn-secondary" style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }} onClick={() => handleStop(t.id)} title="Stop Scan">
                              <Square size={13} />
                            </button>
                          )}
                          {t.report_id && (
                            <button className="btn btn-secondary" style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem', color: 'var(--accent-cyan)' }} onClick={() => onSelectReport(t.report_id)} title="View Report">
                              <FileText size={13} />
                            </button>
                          )}
                          {t.report_id && (
                            <button
                              className="btn btn-secondary"
                              style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem', color: '#f87171', position: 'relative' }}
                              onClick={() => handleDownload(t.report_id, t.name, 'pdf')}
                              title="Download Report (PDF)"
                              disabled={downloadingId === t.report_id}
                            >
                              {downloadingId === t.report_id
                                ? <RefreshCw size={13} className="animate-spin-slow" />
                                : <Download size={13} />}
                              PDF
                            </button>
                          )}
                          <button className="btn btn-secondary" style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem', color: 'var(--severity-high)' }} onClick={() => handleDelete(t.id)} title="Delete Task">
                            <Trash2 size={13} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {totalPages > 1 && (
              <div style={{ display: 'flex', justifyContent: 'center', gap: '1rem', alignItems: 'center', paddingTop: '0.5rem' }}>
                <button className="btn btn-secondary" disabled={page <= 1} onClick={() => setPage(p => Math.max(p - 1, 1))}>← Prev</button>
                <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Page {page} of {totalPages} ({totalTasks} tasks)</span>
                <button className="btn btn-secondary" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>Next →</button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
