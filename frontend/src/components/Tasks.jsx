import { useState, useEffect, useRef } from 'react';
import { Play, Square, Trash2, Plus, RefreshCw, FileText, CheckCircle2, AlertTriangle, Search, Download, Target, ShieldAlert, X } from 'lucide-react';
import { triggerFileDownload } from '../utils/downloadHelper';
import TargetSelector from './TargetSelector';

const STATUS_COLOR = {
  'done':      { color: '#10b981', bg: 'rgba(16,185,129,0.1)' },
  'running':   { color: '#7c3aed', bg: 'rgba(124,58,237,0.1)' },
  'requested': { color: '#d97706', bg: 'rgba(217,119,6,0.1)'  },
  'stopped':   { color: '#dc2626', bg: 'rgba(220,38,38,0.1)'  },
  'new':       { color: '#2563eb', bg: 'rgba(37,99,235,0.1)'  },
};

function TaskStatusBadge({ status, progress }) {
  const normalized = (status || '').toLowerCase();
  const s = STATUS_COLOR[normalized] || { color: 'var(--text-muted)', bg: 'rgba(255,255,255,0.05)' };
  
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      padding: '2px 8px', borderRadius: 20,
      background: s.bg, color: s.color,
      fontSize: 11, fontWeight: 700,
      textTransform: 'uppercase',
    }}>
      {normalized === 'running' && (
        <span style={{ width: 5, height: 5, borderRadius: '50%', background: s.color, animation: 'ring-pulse 1.5s ease-in-out infinite', display: 'inline-block' }} />
      )}
      {status === 'Running' && progress > 0 ? `Running (${progress}%)` : status}
    </span>
  );
}

export default function Tasks({ apiBase, onSelectReport }) {
  const [tasks, setTasks]           = useState([]);
  const [targets, setTargets]       = useState([]);
  const [targetGroups, setTargetGroups] = useState([]);
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
  const [targetScopeVal, setTargetScopeVal] = useState('');
  const [configId, setConfigId]       = useState('');
  const [scannerId, setScannerId]     = useState('');
  const [submitting, setSubmitting]   = useState(false);
  const [formError, setFormError]     = useState(null);
  const [downloadingId, setDownloading] = useState(null);

  const pollRef = useRef(null);

  const fetchInitialData = async (silent = false) => {
    if (!silent) setLoading(true);
    setError(null);
    try {
      const [tasksRes, targetsRes, groupsRes, configsRes, scannersRes] = await Promise.allSettled([
        fetch(`${apiBase}/api/tasks?page=${page}&limit=${limit}`),
        fetch(`${apiBase}/api/targets`),
        fetch(`${apiBase}/api/target-groups`),
        fetch(`${apiBase}/api/scan-configs`),
        fetch(`${apiBase}/api/scanners`),
      ]);

      if (tasksRes.status === 'fulfilled' && tasksRes.value.ok) {
        const tasksData = await tasksRes.value.json();
        setTasks(tasksData.tasks || []);
        setTotalTasks(tasksData.total || 0);
      }
      if (targetsRes.status === 'fulfilled' && targetsRes.value.ok) {
        setTargets(await targetsRes.value.json());
      }
      if (groupsRes.status === 'fulfilled' && groupsRes.value.ok) {
        const gData = await groupsRes.value.json();
        setTargetGroups(Array.isArray(gData) ? gData : []);
      }
      if (configsRes.status === 'fulfilled' && configsRes.value.ok) {
        const configsData = await configsRes.value.json();
        setConfigs(configsData);
        if (configsData.length) {
          setConfigId(prev => prev || configsData[0].id);
        }
      }
      if (scannersRes.status === 'fulfilled' && scannersRes.value.ok) {
        const scannersData = await scannersRes.value.json();
        setScanners(scannersData);
        if (scannersData.length) {
          setScannerId(prev => {
            if (prev) return prev;
            const defaultScanner = scannersData.find(s => s.name === 'OpenVAS Default') || scannersData[0];
            return defaultScanner.id;
          });
        }
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
  }, [page]);

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
      setName(''); setTargetId(''); setTargetScopeVal(''); setShowAddForm(false);
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

  const handleDownload = async (reportId, taskName, fmt = 'pdf') => {
    setDownloading(reportId);
    try {
      const res = await fetch(`${apiBase}/api/reports/${reportId}/download?fmt=${fmt}`);
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`Download failed (${res.status}): ${errText}`);
      }
      const blob = await res.blob();
      const safeName = (taskName || 'report').replace(/[^a-z0-9]/gi, '_').toLowerCase();
      triggerFileDownload(blob, `openvas-${safeName}-${reportId.slice(0, 8)}.${fmt}`);
    } catch (err) { alert(`Download error: ${err.message}`); }
    finally { setDownloading(null); }
  };

  const filteredTasks = tasks.filter(t =>
    (t.name || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
    (t.target_name || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
    (t.target_hosts || '').toLowerCase().includes(searchTerm.toLowerCase())
  );

  const totalPages = Math.ceil(totalTasks / limit);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Action Header */}
      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <button className="btn btn-primary" onClick={() => setShowAddForm(!showAddForm)}>
          <Plus size={14} /> Create Audit Task
        </button>
      </div>

      {/* Task Creation Form */}
      {showAddForm && (
        <div className="card fade-in" style={{ borderLeft: '3px solid var(--violet-500)', position: 'relative', zIndex: 100, overflow: 'visible' }}>
          <div className="card-header">
            <span className="card-title"><ShieldAlert size={14} style={{ color: 'var(--violet-300)' }} /> New Audit Task</span>
            <button className="btn btn-ghost btn-icon btn-sm" onClick={() => setShowAddForm(false)}><X size={14} /></button>
          </div>
          <form onSubmit={handleCreate}>
            <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div className="form-row form-row-2">
                <div className="form-group">
                  <label className="form-label">Task Name</label>
                  <input className="form-input" placeholder="e.g. Monthly Web Server Audit" value={name} onChange={e => setName(e.target.value)} required />
                </div>
                <div className="form-group" style={{ minWidth: '240px' }}>
                  <label className="form-label">Target Scope (Group or Single Target)</label>
                  <TargetSelector
                    value={targetScopeVal}
                    onChange={(val, meta) => {
                      setTargetScopeVal(val);
                      if (meta?.isGroup && meta?.groupObj) {
                        setTargetId(`group:${meta.groupObj.id}`);
                      } else if (meta?.targetObj) {
                        setTargetId(meta.targetObj.id);
                      } else {
                        setTargetId(val);
                      }
                    }}
                    placeholder="Choose Target Group or Saved Target..."
                    apiBase={apiBase}
                    allowGroups={true}
                    disabled={submitting}
                    required
                  />
                </div>
              </div>

              <div className="form-row form-row-2">
                <div className="form-group">
                  <label className="form-label">Scan Configuration</label>
                  <select className="form-select" value={configId} onChange={e => setConfigId(e.target.value)}>
                    {configs.length === 0
                      ? <option value="">Loading configs...</option>
                      : configs.map(c => <option key={c.id} value={c.id}>{c.name}</option>)
                    }
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">Scanner</label>
                  <select className="form-select" value={scannerId} onChange={e => setScannerId(e.target.value)}>
                    {scanners.length === 0
                      ? <option value="08b69003-5fc2-4037-a479-93b440211c73">OpenVAS Default</option>
                      : scanners.map(s => <option key={s.id} value={s.id}>{s.name}</option>)
                    }
                  </select>
                </div>
              </div>

              {formError && <div className="alert alert-error"><AlertTriangle size={14} />{formError}</div>}

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
                <button type="button" className="btn btn-secondary btn-sm" onClick={() => setShowAddForm(false)}>Cancel</button>
                <button type="submit" className="btn btn-primary btn-sm" disabled={submitting}>
                  {submitting ? <><RefreshCw size={13} className="spin" /> Registering...</> : <><Plus size={13} /> Register Task</>}
                </button>
              </div>
            </div>
          </form>
        </div>
      )}

      {/* Tasks Table Card */}
      <div className="card">
        <div className="card-header">
          <span className="card-title"><ShieldAlert size={14} style={{ color: 'var(--violet-300)' }} /> Audit Scans
            <span style={{ marginLeft: 8, fontWeight: 400, color: 'var(--text-muted)', fontSize: 12 }}>
              {totalTasks} total
            </span>
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{ position: 'relative' }}>
              <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none' }} />
              <input
                className="form-input"
                style={{ paddingLeft: 30, width: 220, height: 32, fontSize: 12 }}
                placeholder="Search scans by target or name..."
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
              />
            </div>
            <button className="btn btn-ghost btn-icon btn-sm" onClick={() => fetchInitialData()} disabled={loading} title="Refresh">
              <RefreshCw size={13} style={{ animation: loading ? 'spin 0.8s linear infinite' : 'none' }} />
            </button>
          </div>
        </div>

        {loading ? (
          <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 10 }}>
            {[...Array(4)].map((_, i) => <div key={i} className="skeleton" style={{ height: 20 }} />)}
          </div>
        ) : error ? (
          <div className="card-body">
            <div className="alert alert-error"><AlertTriangle size={14} />{error}</div>
          </div>
        ) : (
          <div className="table-wrap" style={{ border: 'none', borderRadius: 0, borderTop: '1px solid var(--border-default)' }}>
            <table>
              <thead>
                <tr>
                  <th>Task Name</th>
                  <th>Target</th>
                  <th>Config</th>
                  <th>Status</th>
                  <th>Progress</th>
                  <th style={{ width: 180, textAlign: 'center' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredTasks.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--text-muted)' }}>
                      No tasks found. Create one above to start.
                    </td>
                  </tr>
                ) : filteredTasks.map(t => (
                  <tr
                    key={t.id}
                    style={{ cursor: t.report_id ? 'pointer' : 'default' }}
                    onClick={t.report_id ? () => onSelectReport(t.report_id) : undefined}
                  >
                    <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{t.name}</td>
                    <td>
                      <div style={{ fontWeight: 500 }}>{t.target_name}</div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>{t.target_hosts}</div>
                    </td>
                    <td style={{ fontSize: 12 }}>{t.config_name || '—'}</td>
                    <td><TaskStatusBadge status={t.status} progress={t.progress} /></td>
                    <td style={{ verticalAlign: 'middle' }}>
                      {t.status === 'Running' ? (
                        <div className="progress-bar-wrap" style={{ width: 70 }}>
                          <div className="progress-bar" />
                        </div>
                      ) : (
                        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                          {t.status === 'Done' ? '100%' : '—'}
                        </span>
                      )}
                    </td>
                    <td onClick={e => e.stopPropagation()}>
                      <div style={{ display: 'flex', gap: 6, justifyContent: 'center' }}>
                        {t.status?.toLowerCase() === 'new' && (
                          <button className="btn btn-secondary btn-sm" style={{ padding: '4px 8px' }} onClick={() => handleStart(t.id)} title="Start Scan">
                            <Play size={12} />
                          </button>
                        )}
                        {t.status?.toLowerCase() === 'running' && (
                          <button className="btn btn-secondary btn-sm" style={{ padding: '4px 8px' }} onClick={() => handleStop(t.id)} title="Stop Scan">
                            <Square size={12} style={{ color: 'var(--critical)' }} />
                          </button>
                        )}
                        {t.report_id && (
                          <button className="btn btn-secondary btn-sm" style={{ padding: '4px 8px', color: 'var(--violet-300)' }} onClick={() => onSelectReport(t.report_id)} title="View Report">
                            <FileText size={12} />
                          </button>
                        )}
                        {t.report_id && (
                          <button
                            className="btn btn-secondary btn-sm"
                            style={{ padding: '4px 8px', color: 'var(--emerald-400)' }}
                            onClick={() => handleDownload(t.report_id, t.name, 'pdf')}
                            title="Download PDF"
                            disabled={downloadingId === t.report_id}
                          >
                            {downloadingId === t.report_id ? (
                              <RefreshCw size={12} className="spin" />
                            ) : (
                              <Download size={12} />
                            )}
                          </button>
                        )}
                        <button
                          className="btn btn-ghost btn-icon btn-sm"
                          style={{ color: 'var(--critical)' }}
                          onClick={() => handleDelete(t.id)}
                          title="Delete Task"
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        
        {totalPages > 1 && !loading && (
          <div style={{ display: 'flex', justifyContent: 'center', gap: 10, alignItems: 'center', padding: '16px', borderTop: '1px solid var(--border-default)' }}>
            <button className="btn btn-secondary btn-sm" disabled={page <= 1} onClick={() => setPage(p => Math.max(p - 1, 1))}>← Prev</button>
            <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Page {page} of {totalPages}</span>
            <button className="btn btn-secondary btn-sm" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>Next →</button>
          </div>
        )}
      </div>
    </div>
  );
}
