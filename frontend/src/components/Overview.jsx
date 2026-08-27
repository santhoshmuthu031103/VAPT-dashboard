import { useState, useEffect, useCallback, useRef } from 'react';
import {
  Activity, Target, CheckCircle2, XCircle, ArrowRight,
  Shield, Globe, ScanSearch, Zap, Terminal, RefreshCw,
  TrendingUp, AlertTriangle, Clock
} from 'lucide-react';

const QUICK_SCANNERS = [
  { id: 'nmap',     label: 'Nmap',     icon: Terminal,   color: '#7c3aed', desc: 'Port scanner' },
  { id: 'nuclei',   label: 'Nuclei',   icon: Shield,     color: '#10b981', desc: 'Vuln templates' },
  { id: 'nikto',    label: 'Nikto',    icon: ScanSearch, color: '#d97706', desc: 'Web server audit' },
  { id: 'gobuster', label: 'Gobuster', icon: Globe,      color: '#2563eb', desc: 'Dir brute-force' },
  { id: 'zap',      label: 'OWASP ZAP',icon: Zap,        color: '#dc2626', desc: 'DAST scanner' },
];

const STATUS_COLOR = {
  'Done':      { color: '#10b981', bg: 'rgba(16,185,129,0.1)' },
  'Running':   { color: '#7c3aed', bg: 'rgba(124,58,237,0.1)' },
  'Requested': { color: '#d97706', bg: 'rgba(217,119,6,0.1)'  },
  'Stopped':   { color: '#dc2626', bg: 'rgba(220,38,38,0.1)'  },
};

function useInterval(fn, delay) {
  const savedFn = useRef(fn);
  useEffect(() => { savedFn.current = fn; }, [fn]);
  useEffect(() => {
    if (delay === null) return;
    const id = setInterval(() => savedFn.current(), delay);
    return () => clearInterval(id);
  }, [delay]);
}

function StatCard({ label, value, sub, color, icon: Icon, loading }) {
  return (
    <div className="stat-card">
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <span className="stat-label">{label}</span>
        <div style={{ width: 34, height: 34, borderRadius: 8, background: `${color}18`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
          <Icon size={16} style={{ color }} />
        </div>
      </div>
      {loading
        ? <div className="skeleton" style={{ height: 36, width: '60%', marginTop: 4 }} />
        : <div className="stat-value" style={{ color }} key={value}>{value ?? '—'}</div>
      }
      <div className="stat-sub">{sub}</div>
    </div>
  );
}

function TaskStatusBadge({ status }) {
  const s = STATUS_COLOR[status] || { color: 'var(--text-muted)', bg: 'rgba(255,255,255,0.05)' };
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      padding: '2px 8px', borderRadius: 20,
      background: s.bg, color: s.color,
      fontSize: 11, fontWeight: 700,
    }}>
      {status === 'Running' && (
        <span style={{ width: 5, height: 5, borderRadius: '50%', background: s.color, animation: 'ring-pulse 1.5s ease-in-out infinite', display: 'inline-block' }} />
      )}
      {status}
    </span>
  );
}

export default function Overview({ apiBase, onTabChange }) {
  const [tasks, setTasks]     = useState([]);
  const [targets, setTargets] = useState([]);
  const [status, setStatus]   = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [refreshing, setRefreshing]   = useState(false);

  const fetchAll = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    else setRefreshing(true);
    try {
      const [tRes, tgRes, sRes] = await Promise.all([
        fetch(`${apiBase}/api/tasks?page=1&limit=100`),
        fetch(`${apiBase}/api/targets`),
        fetch(`${apiBase}/api/status`),
      ]);
      if (tRes.ok)  { const d = await tRes.json();  setTasks(d.tasks || d || []); }
      if (tgRes.ok) { setTargets(await tgRes.json()); }
      if (sRes.ok)  { setStatus(await sRes.json()); }
      setLastUpdated(new Date());
    } catch (_) {}
    finally { setLoading(false); setRefreshing(false); }
  }, [apiBase]);

  useEffect(() => { fetchAll(); }, [fetchAll]);
  // Live-poll every 10 seconds
  useInterval(() => fetchAll(true), 10000);

  const taskList     = Array.isArray(tasks) ? tasks : (tasks.tasks || []);
  const running      = taskList.filter(t => t.status === 'Running').length;
  const done         = taskList.filter(t => t.status === 'Done').length;
  const recentTasks  = [...taskList].sort((a, b) => (b.last_change || '') > (a.last_change || '') ? 1 : -1).slice(0, 8);

  const SYSTEM_TOOLS = [
    { label: 'OpenVAS GVM', key: 'gvm_connected',      mode: status?.gvm_mode },
    { label: 'OWASP ZAP',  key: 'zap_mode',            isMode: true },
    { label: 'Nuclei',     key: 'nuclei_mode',          isMode: true },
    { label: 'Gobuster',   key: 'gobuster_mode',        isMode: true },
    { label: 'Nikto',      key: 'nikto_mode',           isMode: true },
    { label: 'Nmap',       key: 'nmap_mode',            isMode: true },
  ].map(t => ({
    ...t,
    online: t.isMode
      ? (status?.[t.key] && status[t.key] === 'Live')
      : !!status?.[t.key],
  }));

  const timeAgo = lastUpdated
    ? Math.round((Date.now() - lastUpdated.getTime()) / 1000)
    : null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>

      {/* ── Live Header Strip ── */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        flexWrap: 'wrap', gap: 10,
        padding: '10px 16px',
        background: 'rgba(16,185,129,0.04)',
        border: '1px solid rgba(16,185,129,0.12)',
        borderRadius: 8,
      }}>
        <div className="live-indicator">
          <span className="live-dot" />
          Live Dashboard
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          {timeAgo !== null && (
            <span style={{ fontSize: 11, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4 }}>
              <Clock size={11} />
              Updated {timeAgo}s ago
            </span>
          )}
          <button
            className="btn btn-ghost btn-sm btn-icon"
            onClick={() => fetchAll(true)}
            disabled={refreshing}
            title="Refresh now"
          >
            <RefreshCw size={13} style={{ animation: refreshing ? 'spin 0.8s linear infinite' : 'none' }} />
          </button>
        </div>
      </div>

      {/* ── Stat Cards ── */}
      <div className="grid-4">
        <StatCard label="Total Targets"    value={targets.length}  sub="Registered hosts"         color="var(--violet-400)"   icon={Target}      loading={loading} />
        <StatCard label="Total Scans"      value={taskList.length} sub={`${running} running now`} color="var(--medium)"       icon={Activity}    loading={loading} />
        <StatCard label="Completed"        value={done}            sub="Ready for review"          color="var(--emerald-500)"  icon={CheckCircle2} loading={loading} />
        <StatCard label="Active Threats"   value={running > 0 ? running : 'None'} sub="Currently running scans" color={running > 0 ? 'var(--violet-300)' : 'var(--text-muted)'} icon={AlertTriangle} loading={loading} />
      </div>

      {/* ── Main Grid ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: 20 }}>

        {/* Recent Scans */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <Activity size={14} style={{ color: 'var(--violet-300)' }} />
              Audit Scan Activity
              {running > 0 && (
                <span style={{ marginLeft: 6 }} className="live-indicator">
                  <span className="live-dot" style={{ width: 5, height: 5 }} />
                  {running} running
                </span>
              )}
            </span>
            <button className="btn btn-ghost btn-sm" onClick={() => onTabChange?.('tasks')} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12 }}>
              View all <ArrowRight size={12} />
            </button>
          </div>
          {loading ? (
            <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 10 }}>
              {[...Array(4)].map((_, i) => (
                <div key={i} className="skeleton" style={{ height: 20, width: `${70 + Math.random() * 20}%` }} />
              ))}
            </div>
          ) : recentTasks.length === 0 ? (
            <div style={{ padding: '40px 20px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
              No scans yet.{' '}
              <button className="btn btn-ghost btn-sm" onClick={() => onTabChange?.('tasks')} style={{ color: 'var(--violet-300)', padding: '0 4px' }}>
                Create one →
              </button>
            </div>
          ) : (
            <div className="fade-in">
              <table>
                <thead>
                  <tr>
                    <th>Scan Name</th>
                    <th>Status</th>
                    <th>Progress</th>
                    <th>Last Changed</th>
                  </tr>
                </thead>
                <tbody>
                  {recentTasks.map((t, i) => (
                    <tr key={t.id || i}>
                      <td style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{t.name}</td>
                      <td><TaskStatusBadge status={t.status} /></td>
                      <td>
                        {t.status === 'Running' ? (
                          <div className="progress-bar-wrap" style={{ width: 80 }}>
                            <div className="progress-bar" />
                          </div>
                        ) : (
                          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                            {t.status === 'Done' ? '100%' : '—'}
                          </span>
                        )}
                      </td>
                      <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{t.last_change || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right Column */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

          {/* System Health */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">
                <TrendingUp size={14} style={{ color: 'var(--violet-300)' }} />
                System Health
              </span>
              {status && (
                <span className="live-indicator" style={{ fontSize: 10 }}>
                  <span className="live-dot" style={{ width: 5, height: 5 }} />
                  Live
                </span>
              )}
            </div>
            <div className="card-body" style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
              {loading
                ? [...Array(6)].map((_, i) => <div key={i} className="skeleton" style={{ height: 16, width: '80%' }} />)
                : SYSTEM_TOOLS.map(tool => (
                  <div key={tool.label} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                    <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{tool.label}</span>
                    <span className={`tool-badge ${tool.online ? 'live' : 'offline'}`}>
                      {tool.online
                        ? <><span style={{ width: 5, height: 5, borderRadius: '50%', background: 'var(--emerald-500)', display: 'inline-block', animation: 'ring-pulse 2s ease-in-out infinite' }} /> Live</>
                        : <><XCircle size={10} /> Offline</>
                      }
                    </span>
                  </div>
                ))
              }
            </div>
          </div>

          {/* Quick Launch */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">
                <Zap size={14} style={{ color: 'var(--violet-300)' }} />
                Quick Launch
              </span>
            </div>
            <div className="card-body" style={{ padding: 12, display: 'flex', flexDirection: 'column', gap: 6 }}>
              {QUICK_SCANNERS.map(s => {
                const Icon = s.icon;
                return (
                  <button
                    key={s.id}
                    className="btn btn-secondary btn-sm"
                    onClick={() => onTabChange?.(s.id)}
                    style={{ justifyContent: 'flex-start', gap: 8, border: '1px solid transparent', transition: 'all 0.15s' }}
                    onMouseEnter={e => e.currentTarget.style.borderColor = s.color + '60'}
                    onMouseLeave={e => e.currentTarget.style.borderColor = 'transparent'}
                  >
                    <div style={{ width: 22, height: 22, borderRadius: 5, background: s.color + '20', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                      <Icon size={12} style={{ color: s.color }} />
                    </div>
                    <span style={{ fontWeight: 500 }}>{s.label}</span>
                    <span style={{ marginLeft: 'auto', color: 'var(--text-muted)', fontSize: 10 }}>{s.desc}</span>
                  </button>
                );
              })}
            </div>
          </div>

        </div>
      </div>


      {/* ── Targets Grid ── */}
      {targets.length > 0 && (
        <div className="card fade-in">
          <div className="card-header">
            <span className="card-title">
              <Target size={14} style={{ color: 'var(--violet-300)' }} />
              Registered Targets
            </span>
            <button className="btn btn-ghost btn-sm" onClick={() => onTabChange?.('targets')} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12 }}>
              Manage <ArrowRight size={12} />
            </button>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 10, padding: 14 }}>
            {targets.map(t => (
              <div key={t.id} style={{
                padding: '10px 14px',
                borderRadius: 7,
                border: '1px solid var(--border-subtle)',
                background: 'var(--bg-elevated)',
                display: 'flex', flexDirection: 'column', gap: 3,
                transition: 'border-color 0.15s',
                cursor: 'default',
              }}
                onMouseEnter={e => e.currentTarget.style.borderColor = 'var(--violet-500)'}
                onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--border-subtle)'}
              >
                <div style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-primary)' }}>{t.name}</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--violet-300)' }}>{t.hosts}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
