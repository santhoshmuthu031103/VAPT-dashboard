import React, { useState, useEffect } from 'react';
import {
  Calendar, Clock, Target, Trash2, Play, AlertCircle, CheckCircle2,
  Terminal, Shield, ScanSearch, Globe, Database, Zap, Plus, RefreshCw,
  Layers, ArrowUpRight, Timer, CheckCircle, XCircle, Pause, PlayCircle,
  Repeat, Users, Edit3, X, Save, Check
} from 'lucide-react';
import TargetSelector from './TargetSelector';

const TOOLS = [
  { id: 'nmap',     name: 'Nmap',      icon: Terminal,   desc: 'Port & Service Discovery', defaultType: 'quick' },
  { id: 'nuclei',   name: 'Nuclei',    icon: Shield,     desc: 'CVE & Template Engine',    defaultType: 'critical,high' },
  { id: 'nikto',    name: 'Nikto',     icon: ScanSearch, desc: 'Web Server Misconfig',     defaultType: 'standard' },
  { id: 'gobuster', name: 'Gobuster',  icon: Globe,      desc: 'Directory Brute-force',    defaultType: 'dir' },
  { id: 'ffuf',     name: 'FFuF',      icon: ScanSearch, desc: 'Fast Web Fuzzing',         defaultType: 'fuzz' },
  { id: 'sqlmap',   name: 'SQLmap',    icon: Database,   desc: 'SQL Injection Audit',      defaultType: 'quick' },
  { id: 'zap',      name: 'OWASP ZAP', icon: Zap,        desc: 'DAST Vulnerability Scan',  defaultType: 'baseline' }
];

const FREQUENCIES = [
  { id: 'once',    label: 'Run Once',           desc: 'Executes once at specified date/time' },
  { id: 'hourly',  label: 'Hourly (Recurring)', desc: 'Repeats every hour at specified minute' },
  { id: 'daily',   label: 'Daily (Recurring)',  desc: 'Repeats every day at specified time' },
  { id: 'weekly',  label: 'Weekly (Recurring)', desc: 'Repeats every week on chosen day & time' },
  { id: 'monthly', label: 'Monthly (Recurring)',desc: 'Repeats every month on chosen date & time' },
];

const DAYS_OF_WEEK = [
  { id: 1, label: 'Mon', full: 'Monday' },
  { id: 2, label: 'Tue', full: 'Tuesday' },
  { id: 3, label: 'Wed', full: 'Wednesday' },
  { id: 4, label: 'Thu', full: 'Thursday' },
  { id: 5, label: 'Fri', full: 'Friday' },
  { id: 6, label: 'Sat', full: 'Saturday' },
  { id: 0, label: 'Sun', full: 'Sunday' }
];

const MONTH_DAYS = [1, 2, 5, 10, 15, 20, 25, 28];

const TIME_PRESETS = [
  { time: '08:00', label: '8:00 AM' },
  { time: '10:00', label: '10:00 AM' },
  { time: '14:00', label: '2:00 PM' },
  { time: '18:00', label: '6:00 PM' },
  { time: '23:00', label: '11:00 PM (Night)' }
];

const formatTimeLabel = (timeStr) => {
  if (!timeStr) return '';
  const [hStr, mStr] = timeStr.split(':');
  const h = Number(hStr) || 0;
  const m = Number(mStr) || 0;
  const period = h >= 12 ? 'PM' : 'AM';
  const displayH = h % 12 || 12;
  const displayM = m < 10 ? `0${m}` : m;
  return `${displayH}:${displayM} ${period}`;
};

const getOrdinal = (n) => {
  const s = ['th', 'st', 'nd', 'rd'];
  const v = n % 100;
  return n + (s[(v - 20) % 10] || s[v] || s[0]);
};

// Calculates target datetime-local ISO string from frequency settings
const calculateTargetRunAt = (freq, timeStr, weekDay, monthDay, hourMin) => {
  const now = new Date();
  const target = new Date();

  if (freq === 'hourly') {
    target.setMinutes(Number(hourMin) || 0, 0, 0);
    if (target <= now) {
      target.setHours(target.getHours() + 1);
    }
  } else if (freq === 'daily') {
    const [h, m] = (timeStr || '10:00').split(':').map(Number);
    target.setHours(h, m, 0, 0);
    if (target <= now) {
      target.setDate(target.getDate() + 1);
    }
  } else if (freq === 'weekly') {
    const [h, m] = (timeStr || '10:00').split(':').map(Number);
    target.setHours(h, m, 0, 0);
    const currentDay = now.getDay();
    const desiredDay = Number(weekDay);
    let daysAhead = desiredDay - currentDay;
    if (daysAhead < 0 || (daysAhead === 0 && target <= now)) {
      daysAhead += 7;
    }
    target.setDate(target.getDate() + daysAhead);
  } else if (freq === 'monthly') {
    const [h, m] = (timeStr || '10:00').split(':').map(Number);
    target.setHours(h, m, 0, 0);
    const day = Math.min(Math.max(Number(monthDay) || 1, 1), 28);
    target.setDate(day);
    if (target <= now) {
      target.setMonth(target.getMonth() + 1);
    }
  }

  const d = new Date(target.getTime() - target.getTimezoneOffset() * 60000);
  return d.toISOString().slice(0, 16);
};

export default function SchedulerDashboard({ apiBase }) {
  const [scheduledScans, setScheduledScans] = useState([]);
  const [stats, setStats] = useState({ total: 0, pending: 0, running: 0, completed: 0, failed: 0 });
  const [loading, setLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [runningId, setRunningId] = useState(null);
  const [togglingId, setTogglingId] = useState(null);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  // ── Form State (Schedule Creator) ──
  const [selectedTool, setSelectedTool] = useState('nmap');
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('quick');
  const [frequency, setFrequency] = useState('once');
  const [runAt, setRunAt] = useState('');
  const [groupName, setGroupName] = useState('');
  
  // Timing parameters for recurring creator
  const [timeOfDay, setTimeOfDay] = useState('10:00');
  const [weeklyDay, setWeeklyDay] = useState(1); // 1 = Mon
  const [monthlyDay, setMonthlyDay] = useState(1);
  const [hourlyMinute, setHourlyMinute] = useState(0);

  // ── Edit Modal State ──
  const [editingScan, setEditingScan] = useState(null);
  const [editTool, setEditTool] = useState('nmap');
  const [editTarget, setEditTarget] = useState('');
  const [editScanType, setEditScanType] = useState('quick');
  const [editFrequency, setEditFrequency] = useState('once');
  const [editRunAt, setEditRunAt] = useState('');
  const [editGroupName, setEditGroupName] = useState('');
  const [editTimeOfDay, setEditTimeOfDay] = useState('10:00');
  const [editWeeklyDay, setEditWeeklyDay] = useState(1);
  const [editMonthlyDay, setEditMonthlyDay] = useState(1);
  const [editHourlyMinute, setEditHourlyMinute] = useState(0);
  const [savingEdit, setSavingEdit] = useState(false);
  const [editError, setEditError] = useState('');

  // Default datetime for 'once' mode
  const getDefaultDatetime = (minutesToAdd = 30) => {
    const d = new Date(Date.now() + minutesToAdd * 60 * 1000);
    d.setMinutes(d.getMinutes() - d.getTimezoneOffset());
    return d.toISOString().slice(0, 16);
  };

  useEffect(() => {
    setRunAt(getDefaultDatetime(30));
  }, []);

  // Synchronize creator runAt when recurring options change
  useEffect(() => {
    if (frequency !== 'once') {
      const calculated = calculateTargetRunAt(frequency, timeOfDay, weeklyDay, monthlyDay, hourlyMinute);
      setRunAt(calculated);
    }
  }, [frequency, timeOfDay, weeklyDay, monthlyDay, hourlyMinute]);

  // Synchronize editor editRunAt when recurring options change
  useEffect(() => {
    if (editingScan && editFrequency !== 'once') {
      const calculated = calculateTargetRunAt(editFrequency, editTimeOfDay, editWeeklyDay, editMonthlyDay, editHourlyMinute);
      setEditRunAt(calculated);
    }
  }, [editFrequency, editTimeOfDay, editWeeklyDay, editMonthlyDay, editHourlyMinute]);

  const fetchScheduledScans = async () => {
    try {
      setLoading(true);
      const res = await fetch(`${apiBase}/api/scheduler`);
      if (!res.ok) throw new Error(`HTTP Error ${res.status}`);
      const data = await res.json();
      setScheduledScans(data.scans || []);
      if (data.stats) setStats(data.stats);
      setError('');
    } catch (err) {
      console.error(err);
      setError('Unable to connect to scheduler backend. Retrying...');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScheduledScans();
    const interval = setInterval(fetchScheduledScans, 10000);
    return () => clearInterval(interval);
  }, [apiBase]);

  const handleToolChange = (toolId) => {
    setSelectedTool(toolId);
    const toolObj = TOOLS.find(t => t.id === toolId);
    if (toolObj) setScanType(toolObj.defaultType);
  };

  const handleTargetSelect = (val, meta) => {
    setTarget(val);
    if (meta?.isGroup) {
      setGroupName(meta.groupName || '');
    } else {
      setGroupName('');
    }
  };

  const setPresetTime = (minutes) => {
    setRunAt(getDefaultDatetime(minutes));
  };

  const handleSchedule = async (e) => {
    e.preventDefault();
    setError('');
    setSuccessMsg('');

    if (!target.trim()) {
      setError('Please provide a valid target host, IP, or Target Group.');
      return;
    }
    if (!runAt) {
      setError('Please select a scheduled execution time.');
      return;
    }

    try {
      setSubmitting(true);
      const dateObj = new Date(runAt);
      const isoString = dateObj.toISOString();

      const res = await fetch(`${apiBase}/api/scheduler`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tool: selectedTool,
          target: target.trim(),
          scan_type: scanType.trim() || 'default',
          run_at: isoString,
          frequency: frequency,
          group_name: groupName || null
        })
      });

      if (!res.ok) {
        const d = await res.json();
        throw new Error(d.detail || 'Failed to schedule scan.');
      }

      const freqLabel = FREQUENCIES.find(f => f.id === frequency)?.label || frequency;
      setSuccessMsg(`Automated ${selectedTool.toUpperCase()} scan [${freqLabel}] scheduled for ${new Date(runAt).toLocaleString()}!`);
      setTarget('');
      setGroupName('');
      setRunAt(getDefaultDatetime(30));
      fetchScheduledScans();
      setTimeout(() => setSuccessMsg(''), 6000);
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id) => {
    try {
      const res = await fetch(`${apiBase}/api/scheduler/${id}`, { method: 'DELETE' });
      if (!res.ok) throw new Error('Failed to cancel scheduled scan');
      fetchScheduledScans();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleToggleActive = async (id) => {
    try {
      setTogglingId(id);
      const res = await fetch(`${apiBase}/api/scheduler/${id}/toggle-active`, { method: 'POST' });
      if (!res.ok) throw new Error('Failed to toggle job state');
      fetchScheduledScans();
    } catch (err) {
      setError(err.message);
    } finally {
      setTogglingId(null);
    }
  };

  const handleRunNow = async (id) => {
    try {
      setRunningId(id);
      const res = await fetch(`${apiBase}/api/scheduler/${id}/run-now`, { method: 'POST' });
      if (!res.ok) throw new Error('Failed to start immediate execution');
      setSuccessMsg(`Scan #${id} triggered immediately in background!`);
      fetchScheduledScans();
      setTimeout(() => setSuccessMsg(''), 5000);
    } catch (err) {
      setError(err.message);
    } finally {
      setRunningId(null);
    }
  };

  const handleOpenEdit = (scan) => {
    setEditingScan(scan);
    setEditTool(scan.tool || 'nmap');
    setEditTarget(scan.target || '');
    setEditScanType(scan.scan_type || 'quick');
    const freq = (scan.frequency || 'once').toLowerCase();
    setEditFrequency(freq);
    setEditGroupName(scan.group_name || '');
    setEditError('');

    let tOfDay = '10:00';
    let wDay = 1;
    let mDay = 1;
    let hMin = 0;
    let initialRunAt = getDefaultDatetime(15);

    try {
      if (scan.run_at) {
        const d = new Date(scan.run_at);
        if (!isNaN(d.getTime())) {
          const hours = String(d.getHours()).padStart(2, '0');
          const minutes = String(d.getMinutes()).padStart(2, '0');
          tOfDay = `${hours}:${minutes}`;
          wDay = d.getDay();
          mDay = Math.min(d.getDate(), 28);
          hMin = d.getMinutes();
          
          d.setMinutes(d.getMinutes() - d.getTimezoneOffset());
          initialRunAt = d.toISOString().slice(0, 16);
        }
      }
    } catch (_) {}

    setEditTimeOfDay(tOfDay);
    setEditWeeklyDay(wDay);
    setEditMonthlyDay(mDay);
    setEditHourlyMinute(hMin);

    if (freq === 'once') {
      setEditRunAt(initialRunAt);
    } else {
      setEditRunAt(calculateTargetRunAt(freq, tOfDay, wDay, mDay, hMin));
    }
  };

  const handleSaveEdit = async (e) => {
    e.preventDefault();
    if (!editingScan) return;
    setEditError('');

    if (!editTarget.trim()) {
      setEditError('Please provide a valid target scope.');
      return;
    }
    if (!editRunAt) {
      setEditError('Please select a scheduled execution time.');
      return;
    }

    try {
      setSavingEdit(true);
      const dateObj = new Date(editRunAt);
      const isoString = dateObj.toISOString();

      const res = await fetch(`${apiBase}/api/scheduler/${editingScan.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tool: editTool,
          target: editTarget.trim(),
          scan_type: editScanType.trim() || 'default',
          run_at: isoString,
          frequency: editFrequency,
          group_name: editGroupName || null
        })
      });

      if (!res.ok) {
        const d = await res.json();
        throw new Error(d.detail || 'Failed to update scheduled scan.');
      }

      const freqLabel = FREQUENCIES.find(f => f.id === editFrequency)?.label || editFrequency;
      setSuccessMsg(`Job #${editingScan.id} [${editTool.toUpperCase()}] updated & rescheduled for ${new Date(editRunAt).toLocaleString()} (${freqLabel})!`);
      setEditingScan(null);
      fetchScheduledScans();
      setTimeout(() => setSuccessMsg(''), 6000);
    } catch (err) {
      setEditError(err.message);
    } finally {
      setSavingEdit(false);
    }
  };

  const getToolIcon = (toolName) => {
    const t = TOOLS.find(item => item.id === (toolName || '').toLowerCase());
    if (!t) return <Terminal size={14} />;
    const IconComp = t.icon;
    return <IconComp size={14} />;
  };

  const getFrequencyBadge = (freq, runAt) => {
    const f = (freq || 'once').toLowerCase();
    switch (f) {
      case 'hourly':
        return <span className="badge badge-secondary" style={{ fontSize: '11px' }}><Repeat size={10} /> Hourly</span>;
      case 'daily':
        return <span className="badge badge-info" style={{ fontSize: '11px' }}><Repeat size={10} /> Daily</span>;
      case 'weekly':
        return <span className="badge badge-violet" style={{ fontSize: '11px' }}><Repeat size={10} /> Weekly</span>;
      case 'monthly':
        return <span className="badge badge-warning" style={{ fontSize: '11px' }}><Repeat size={10} /> Monthly</span>;
      default:
        return <span className="badge badge-neutral" style={{ fontSize: '11px' }}>Once</span>;
    }
  };

  const getStatusBadge = (status, isActive = 1) => {
    if (isActive === 0) {
      return <span className="badge badge-neutral"><Pause size={11} /> Paused</span>;
    }
    switch ((status || '').toLowerCase()) {
      case 'completed':
        return <span className="badge badge-success"><CheckCircle size={11} /> Completed</span>;
      case 'running':
        return <span className="badge badge-violet"><RefreshCw size={11} className="spinner" /> Running</span>;
      case 'failed':
        return <span className="badge badge-critical"><XCircle size={11} /> Failed</span>;
      default:
        return <span className="badge badge-info"><Clock size={11} /> Active</span>;
    }
  };

  // Human description for frequency summary
  const getFrequencySummary = (freq, tOfDay, wDay, mDay, hMin, nextRunStr) => {
    let nextFormatted = '';
    try {
      if (nextRunStr) {
        nextFormatted = new Date(nextRunStr).toLocaleString();
      }
    } catch (_) {}

    switch (freq) {
      case 'daily':
        return `Triggers every day at ${formatTimeLabel(tOfDay)} (Next run: ${nextFormatted})`;
      case 'weekly': {
        const dayObj = DAYS_OF_WEEK.find(d => d.id === Number(wDay));
        return `Triggers every ${dayObj ? dayObj.full : 'week'} at ${formatTimeLabel(tOfDay)} (Next run: ${nextFormatted})`;
      }
      case 'monthly':
        return `Triggers on the ${getOrdinal(mDay)} of every month at ${formatTimeLabel(tOfDay)} (Next run: ${nextFormatted})`;
      case 'hourly':
        return `Triggers every hour at :${String(hMin).padStart(2, '0')} (Next run: ${nextFormatted})`;
      default:
        return `Triggers once on ${nextFormatted}`;
    }
  };

  return (
    <div className="scheduler-view" style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      
      {/* Top Stat Metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '16px' }}>
        <div className="stat-card">
          <span className="stat-label">Total Scheduled</span>
          <div className="stat-value">{stats.total}</div>
          <span className="stat-sub">Across all security tools</span>
        </div>
        <div className="stat-card">
          <span className="stat-label" style={{ color: 'var(--info)' }}>Pending / Active</span>
          <div className="stat-value" style={{ color: 'var(--info)' }}>{stats.pending}</div>
          <span className="stat-sub">Recurring & upcoming runs</span>
        </div>
        <div className="stat-card">
          <span className="stat-label" style={{ color: 'var(--emerald-500)' }}>Completed</span>
          <div className="stat-value" style={{ color: 'var(--emerald-500)' }}>{stats.completed}</div>
          <span className="stat-sub">Saved to Scan History</span>
        </div>
        <div className="stat-card">
          <span className="stat-label" style={{ color: 'var(--critical)' }}>Failed</span>
          <div className="stat-value" style={{ color: 'var(--critical)' }}>{stats.failed}</div>
          <span className="stat-sub">Errors during execution</span>
        </div>
      </div>

      {/* Main Grid: Config on Left, Schedule Table on Right */}
      <div className="scanner-layout">
        
        {/* ════════════════════ LEFT SIDE: SCHEDULE CREATOR ════════════════════ */}
        <div className="scanner-config-panel">
          <div className="scanner-config-header">
            <Calendar size={15} style={{ color: 'var(--violet-400)' }} />
            <h3>Configure Schedule</h3>
          </div>
          
          <form onSubmit={handleSchedule} className="scanner-config-body">
            {error && (
              <div className="error-message">
                <AlertCircle size={16} />
                <span>{error}</span>
              </div>
            )}
            {successMsg && (
              <div className="no-findings" style={{ background: 'var(--emerald-dim)', color: 'var(--emerald-500)' }}>
                <CheckCircle2 size={16} />
                <span>{successMsg}</span>
              </div>
            )}

            {/* Target Selector (Supports single host or Target Groups) */}
            <div className="form-group">
              <label className="form-label">
                <Target size={13} /> Target Host / Group
              </label>
              <TargetSelector
                value={target}
                onChange={handleTargetSelect}
                placeholder="Choose Target Group or enter IP/hostname..."
                apiBase={apiBase}
                required
              />
              <span className="form-hint">Choose a pre-defined Target Group or enter an IP/hostname</span>
            </div>

            {/* Security Tool Selector */}
            <div className="form-group">
              <label className="form-label">
                <Layers size={13} /> Assessment Engine
              </label>
              <select
                className="form-select"
                value={selectedTool}
                onChange={(e) => handleToolChange(e.target.value)}
              >
                {TOOLS.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name} — {t.desc}
                  </option>
                ))}
              </select>
            </div>

            {/* Scan Type / Profile */}
            <div className="form-group">
              <label className="form-label">
                <Terminal size={13} /> Scan Profile / Arguments
              </label>
              <input
                type="text"
                className="form-input"
                placeholder="quick, full, service, etc."
                value={scanType}
                onChange={(e) => setScanType(e.target.value)}
              />
            </div>

            {/* Frequency Selector */}
            <div className="form-group">
              <label className="form-label">
                <Repeat size={13} /> Scan Frequency
              </label>
              <select
                className="form-select"
                value={frequency}
                onChange={(e) => setFrequency(e.target.value)}
              >
                {FREQUENCIES.map((f) => (
                  <option key={f.id} value={f.id}>
                    {f.label} — {f.desc}
                  </option>
                ))}
              </select>
            </div>

            {/* ── FREQUENCY SPECIFIC TIMING CONTROLS ── */}
            {frequency === 'once' && (
              <>
                <div className="form-group">
                  <label className="form-label">
                    <Clock size={13} /> Execution Date &amp; Time
                  </label>
                  <input
                    type="datetime-local"
                    className="form-input"
                    value={runAt}
                    onChange={(e) => setRunAt(e.target.value)}
                    required
                  />
                </div>

                <div className="form-group">
                  <label className="form-label" style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    <Timer size={12} /> Quick Presets
                  </label>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px' }}>
                    <button type="button" className="btn btn-secondary btn-sm" onClick={() => setPresetTime(15)}>
                      +15 Minutes
                    </button>
                    <button type="button" className="btn btn-secondary btn-sm" onClick={() => setPresetTime(60)}>
                      +1 Hour
                    </button>
                    <button type="button" className="btn btn-secondary btn-sm" onClick={() => setPresetTime(360)}>
                      +6 Hours
                    </button>
                    <button type="button" className="btn btn-secondary btn-sm" onClick={() => setPresetTime(1440)}>
                      Tomorrow
                    </button>
                  </div>
                </div>
              </>
            )}

            {frequency === 'daily' && (
              <div style={{ background: 'rgba(2, 132, 199, 0.06)', border: '1px solid rgba(2, 132, 199, 0.2)', borderRadius: '8px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <div className="form-group" style={{ margin: 0 }}>
                  <label className="form-label" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                    <Clock size={13} style={{ color: '#0284c7' }} /> Daily Execution Time
                  </label>
                  <input
                    type="time"
                    className="form-input"
                    value={timeOfDay}
                    onChange={(e) => setTimeOfDay(e.target.value)}
                    required
                  />
                </div>

                <div>
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '6px' }}>Common Time Presets:</span>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                    {TIME_PRESETS.map((p) => (
                      <button
                        type="button"
                        key={p.time}
                        onClick={() => setTimeOfDay(p.time)}
                        className={`btn btn-sm ${timeOfDay === p.time ? 'btn-primary' : 'btn-ghost'}`}
                        style={{ padding: '3px 8px', fontSize: '11px' }}
                      >
                        {p.label}
                      </button>
                    ))}
                  </div>
                </div>

                <div style={{ fontSize: '11px', color: '#0284c7', background: 'rgba(2, 132, 199, 0.1)', padding: '6px 10px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Repeat size={12} />
                  <span>{getFrequencySummary('daily', timeOfDay, weeklyDay, monthlyDay, hourlyMinute, runAt)}</span>
                </div>
              </div>
            )}

            {frequency === 'weekly' && (
              <div style={{ background: 'rgba(167, 139, 250, 0.06)', border: '1px solid rgba(167, 139, 250, 0.2)', borderRadius: '8px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <div className="form-group" style={{ margin: 0 }}>
                  <label className="form-label" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                    <Calendar size={13} style={{ color: 'var(--violet-400)' }} /> Day of the Week
                  </label>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: '4px' }}>
                    {DAYS_OF_WEEK.map((d) => (
                      <button
                        type="button"
                        key={d.id}
                        onClick={() => setWeeklyDay(d.id)}
                        className={`btn btn-sm ${weeklyDay === d.id ? 'btn-primary' : 'btn-secondary'}`}
                        style={{ padding: '6px 2px', fontSize: '11px', textAlign: 'center' }}
                      >
                        {d.label}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="form-group" style={{ margin: 0 }}>
                  <label className="form-label" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                    <Clock size={13} style={{ color: 'var(--violet-400)' }} /> Weekly Execution Time
                  </label>
                  <input
                    type="time"
                    className="form-input"
                    value={timeOfDay}
                    onChange={(e) => setTimeOfDay(e.target.value)}
                    required
                  />
                </div>

                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                  {TIME_PRESETS.map((p) => (
                    <button
                      type="button"
                      key={p.time}
                      onClick={() => setTimeOfDay(p.time)}
                      className={`btn btn-sm ${timeOfDay === p.time ? 'btn-primary' : 'btn-ghost'}`}
                      style={{ padding: '3px 8px', fontSize: '11px' }}
                    >
                      {p.label}
                    </button>
                  ))}
                </div>

                <div style={{ fontSize: '11px', color: 'var(--violet-400)', background: 'rgba(167, 139, 250, 0.1)', padding: '6px 10px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Repeat size={12} />
                  <span>{getFrequencySummary('weekly', timeOfDay, weeklyDay, monthlyDay, hourlyMinute, runAt)}</span>
                </div>
              </div>
            )}

            {frequency === 'monthly' && (
              <div style={{ background: 'rgba(234, 179, 8, 0.06)', border: '1px solid rgba(234, 179, 8, 0.2)', borderRadius: '8px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <div className="form-group" style={{ margin: 0 }}>
                  <label className="form-label" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                    <Calendar size={13} style={{ color: '#eab308' }} /> Day of the Month
                  </label>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '4px' }}>
                    {MONTH_DAYS.map((d) => (
                      <button
                        type="button"
                        key={d}
                        onClick={() => setMonthlyDay(d)}
                        className={`btn btn-sm ${monthlyDay === d ? 'btn-primary' : 'btn-secondary'}`}
                        style={{ padding: '4px 6px', fontSize: '11px' }}
                      >
                        {getOrdinal(d)}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="form-group" style={{ margin: 0 }}>
                  <label className="form-label" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                    <Clock size={13} style={{ color: '#eab308' }} /> Monthly Execution Time
                  </label>
                  <input
                    type="time"
                    className="form-input"
                    value={timeOfDay}
                    onChange={(e) => setTimeOfDay(e.target.value)}
                    required
                  />
                </div>

                <div style={{ fontSize: '11px', color: '#eab308', background: 'rgba(234, 179, 8, 0.1)', padding: '6px 10px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Repeat size={12} />
                  <span>{getFrequencySummary('monthly', timeOfDay, weeklyDay, monthlyDay, hourlyMinute, runAt)}</span>
                </div>
              </div>
            )}

            {frequency === 'hourly' && (
              <div style={{ background: 'rgba(100, 116, 139, 0.06)', border: '1px solid rgba(100, 116, 139, 0.2)', borderRadius: '8px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                <div className="form-group" style={{ margin: 0 }}>
                  <label className="form-label" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                    <Clock size={13} /> Minute Offset (Past Each Hour)
                  </label>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '4px' }}>
                    {[0, 15, 30, 45].map((m) => (
                      <button
                        type="button"
                        key={m}
                        onClick={() => setHourlyMinute(m)}
                        className={`btn btn-sm ${hourlyMinute === m ? 'btn-primary' : 'btn-secondary'}`}
                        style={{ padding: '4px 6px', fontSize: '11px' }}
                      >
                        :{String(m).padStart(2, '0')}
                      </button>
                    ))}
                  </div>
                </div>

                <div style={{ fontSize: '11px', color: 'var(--text-secondary)', background: 'rgba(100, 116, 139, 0.1)', padding: '6px 10px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Repeat size={12} />
                  <span>{getFrequencySummary('hourly', timeOfDay, weeklyDay, monthlyDay, hourlyMinute, runAt)}</span>
                </div>
              </div>
            )}

            {/* Submit Button */}
            <button
              type="submit"
              className="btn btn-primary btn-full"
              disabled={submitting}
              style={{ marginTop: '8px' }}
            >
              {submitting ? (
                <>
                  <RefreshCw size={14} className="spinner" />
                  <span>Scheduling Scan...</span>
                </>
              ) : (
                <>
                  <Plus size={14} />
                  <span>Schedule Automated Scan</span>
                </>
              )}
            </button>
          </form>
        </div>

        {/* ════════════════════ RIGHT SIDE: SCHEDULED JOBS TABLE ════════════════════ */}
        <div className="scanner-main-panel">
          <div className="card">
            <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Clock size={16} style={{ color: 'var(--violet-400)' }} />
                <h3 style={{ margin: 0, fontSize: '15px' }}>Scheduled Jobs Queue</h3>
              </div>
              <button
                className="btn btn-secondary btn-sm"
                onClick={fetchScheduledScans}
                disabled={loading}
              >
                <RefreshCw size={12} className={loading ? 'spinner' : ''} />
                <span>Refresh</span>
              </button>
            </div>

            <div className="card-body" style={{ padding: 0 }}>
              {scheduledScans.length === 0 ? (
                <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  <Calendar size={32} style={{ margin: '0 auto 12px', opacity: 0.5 }} />
                  <p style={{ margin: 0, fontSize: '13px' }}>No scheduled scans in queue.</p>
                  <span style={{ fontSize: '12px' }}>Use the form on the left to set up one-time or recurring scan jobs.</span>
                </div>
              ) : (
                <div className="table-responsive">
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Job ID</th>
                        <th>Tool</th>
                        <th>Target Scope</th>
                        <th>Frequency</th>
                        <th>Next / Scheduled Run</th>
                        <th>Status</th>
                        <th style={{ textAlign: 'right' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scheduledScans.map((scan) => {
                        let dateDisplay = scan.next_run || scan.run_at;
                        try {
                          const d = new Date(dateDisplay);
                          dateDisplay = d.toLocaleString();
                        } catch (_) {}

                        const isRecurring = scan.frequency && scan.frequency.toLowerCase() !== 'once';
                        const isActive = scan.is_active !== undefined ? scan.is_active : 1;

                        return (
                          <tr key={scan.id} style={{ opacity: isActive === 0 ? 0.6 : 1 }}>
                            <td style={{ color: 'var(--text-muted)', fontSize: '12px', fontWeight: 600 }}>
                              #{scan.id}
                            </td>
                            <td>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                <span style={{ color: 'var(--violet-400)' }}>
                                  {getToolIcon(scan.tool)}
                                </span>
                                <strong style={{ textTransform: 'uppercase', fontSize: '12px', color: 'var(--text-primary)' }}>
                                  {scan.tool}
                                </strong>
                              </div>
                            </td>
                            <td>
                              <div>
                                <div className="td-mono" style={{ color: 'var(--text-primary)', fontWeight: 500, fontSize: '12px' }}>
                                  {scan.target.length > 35 ? scan.target.slice(0, 35) + '...' : scan.target}
                                </div>
                                {scan.group_name && (
                                  <span style={{ fontSize: '10px', color: 'var(--violet-400)', display: 'inline-flex', alignItems: 'center', gap: '3px' }}>
                                    <Users size={10} /> {scan.group_name}
                                  </span>
                                )}
                              </div>
                            </td>
                            <td>
                              {getFrequencyBadge(scan.frequency, scan.run_at)}
                            </td>
                            <td style={{ fontSize: '12px' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                <Clock size={12} style={{ color: 'var(--text-muted)' }} />
                                <span>{dateDisplay}</span>
                              </div>
                              {scan.last_run && (
                                <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
                                  Last: {new Date(scan.last_run).toLocaleTimeString()}
                                </div>
                              )}
                            </td>
                            <td>
                              {getStatusBadge(scan.status, isActive)}
                            </td>
                            <td style={{ textAlign: 'right' }}>
                              <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                                {isRecurring && (
                                  <button
                                    className={`btn ${isActive === 1 ? 'btn-secondary' : 'btn-primary'} btn-sm`}
                                    onClick={() => handleToggleActive(scan.id)}
                                    disabled={togglingId === scan.id}
                                    title={isActive === 1 ? "Pause recurring job" : "Resume recurring job"}
                                    style={{ padding: '4px 8px', fontSize: '11px' }}
                                  >
                                    {isActive === 1 ? <Pause size={11} /> : <PlayCircle size={11} />}
                                    <span>{isActive === 1 ? 'Pause' : 'Resume'}</span>
                                  </button>
                                )}
                                <button
                                  className="btn btn-secondary btn-sm"
                                  onClick={() => handleOpenEdit(scan)}
                                  title="Edit timing & repeat frequency"
                                  style={{ padding: '4px 8px', fontSize: '11px', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                                >
                                  <Edit3 size={11} />
                                  <span>Edit</span>
                                </button>
                                <button
                                  className="btn btn-secondary btn-sm"
                                  onClick={() => handleRunNow(scan.id)}
                                  disabled={runningId === scan.id}
                                  title="Trigger scan immediately"
                                  style={{ padding: '4px 8px', fontSize: '11px' }}
                                >
                                  <Play size={11} style={{ fill: 'currentColor' }} />
                                  <span>Run Now</span>
                                </button>
                                <button
                                  className="btn btn-ghost btn-sm"
                                  onClick={() => handleDelete(scan.id)}
                                  title="Delete scheduled job"
                                  style={{ padding: '6px', color: 'var(--critical)' }}
                                >
                                  <Trash2 size={13} />
                                </button>
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>

        </div>

      </div>

      {/* ════════════════════ EDIT SCHEDULED SCAN MODAL ════════════════════ */}
      {editingScan && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 9999,
          padding: '20px'
        }}>
          <div className="card" style={{
            width: '100%',
            maxWidth: '560px',
            borderRadius: '12px',
            boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.6)',
            overflow: 'hidden',
            maxHeight: '90vh',
            display: 'flex',
            flexDirection: 'column'
          }}>
            <div style={{
              padding: '16px 20px',
              borderBottom: '1px solid var(--border-subtle)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Edit3 size={18} style={{ color: 'var(--violet-400)' }} />
                <h3 style={{ margin: 0, fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Edit Scheduled Scan #{editingScan.id}
                </h3>
              </div>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => setEditingScan(null)}
                style={{ padding: '4px', color: 'var(--text-muted)' }}
              >
                <X size={18} />
              </button>
            </div>

            <form onSubmit={handleSaveEdit} style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px', overflowY: 'auto' }}>
              {editError && (
                <div className="alert alert-error" style={{ padding: '8px 12px', fontSize: '12px' }}>
                  <AlertCircle size={14} />
                  <span>{editError}</span>
                </div>
              )}

              {/* Target & Group */}
              <div className="form-group">
                <label className="form-label" style={{ fontSize: '12px' }}>Target Scope / Host</label>
                <input
                  type="text"
                  className="form-input"
                  value={editTarget}
                  onChange={(e) => setEditTarget(e.target.value)}
                  placeholder="e.g. 192.168.1.1, https://example.com"
                  required
                />
              </div>

              {/* Tool Selection */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div className="form-group">
                  <label className="form-label" style={{ fontSize: '12px' }}>Security Tool</label>
                  <select
                    className="form-select"
                    value={editTool}
                    onChange={(e) => {
                      setEditTool(e.target.value);
                      const t = TOOLS.find(item => item.id === e.target.value);
                      if (t) setEditScanType(t.defaultType);
                    }}
                  >
                    {TOOLS.map(t => (
                      <option key={t.id} value={t.id}>{t.name} ({t.desc})</option>
                    ))}
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label" style={{ fontSize: '12px' }}>Scan Profile</label>
                  <input
                    type="text"
                    className="form-input"
                    value={editScanType}
                    onChange={(e) => setEditScanType(e.target.value)}
                    placeholder="e.g. quick, full, dir"
                  />
                </div>
              </div>

              {/* Frequency Selector */}
              <div className="form-group">
                <label className="form-label" style={{ fontSize: '12px' }}>Repeat Frequency</label>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(90px, 1fr))', gap: '6px' }}>
                  {FREQUENCIES.map(f => (
                    <button
                      type="button"
                      key={f.id}
                      onClick={() => setEditFrequency(f.id)}
                      className={`btn btn-sm ${editFrequency === f.id ? 'btn-primary' : 'btn-secondary'}`}
                      style={{ padding: '6px 8px', fontSize: '11px', textAlign: 'center' }}
                    >
                      {f.id === 'once' ? 'Once' : f.label.split(' ')[0]}
                    </button>
                  ))}
                </div>
              </div>

              {/* ── FREQUENCY SPECIFIC TIMING CONTROLS FOR MODAL ── */}
              {editFrequency === 'once' && (
                <div className="form-group">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <label className="form-label" style={{ margin: 0, fontSize: '12px' }}>Execution Date &amp; Time</label>
                    <div style={{ display: 'flex', gap: '4px' }}>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        onClick={() => setEditRunAt(getDefaultDatetime(15))}
                        style={{ padding: '2px 6px', fontSize: '10px' }}
                      >
                        +15m
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        onClick={() => setEditRunAt(getDefaultDatetime(60))}
                        style={{ padding: '2px 6px', fontSize: '10px' }}
                      >
                        +1h
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        onClick={() => setEditRunAt(getDefaultDatetime(1440))}
                        style={{ padding: '2px 6px', fontSize: '10px' }}
                      >
                        Tomorrow
                      </button>
                    </div>
                  </div>
                  <input
                    type="datetime-local"
                    className="form-input"
                    value={editRunAt}
                    onChange={(e) => setEditRunAt(e.target.value)}
                    required
                  />
                </div>
              )}

              {editFrequency === 'daily' && (
                <div style={{ background: 'rgba(2, 132, 199, 0.06)', border: '1px solid rgba(2, 132, 199, 0.2)', borderRadius: '8px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  <div className="form-group" style={{ margin: 0 }}>
                    <label className="form-label" style={{ fontSize: '12px', fontWeight: 600 }}>
                      <Clock size={13} style={{ color: '#0284c7' }} /> Daily Execution Time (e.g. 10:00 AM)
                    </label>
                    <input
                      type="time"
                      className="form-input"
                      value={editTimeOfDay}
                      onChange={(e) => setEditTimeOfDay(e.target.value)}
                      required
                    />
                  </div>

                  <div>
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '6px' }}>Quick Presets:</span>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                      {TIME_PRESETS.map((p) => (
                        <button
                          type="button"
                          key={p.time}
                          onClick={() => setEditTimeOfDay(p.time)}
                          className={`btn btn-sm ${editTimeOfDay === p.time ? 'btn-primary' : 'btn-ghost'}`}
                          style={{ padding: '3px 8px', fontSize: '11px' }}
                        >
                          {p.label}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div style={{ fontSize: '11px', color: '#0284c7', background: 'rgba(2, 132, 199, 0.1)', padding: '6px 10px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Repeat size={12} />
                    <span>{getFrequencySummary('daily', editTimeOfDay, editWeeklyDay, editMonthlyDay, editHourlyMinute, editRunAt)}</span>
                  </div>
                </div>
              )}

              {editFrequency === 'weekly' && (
                <div style={{ background: 'rgba(167, 139, 250, 0.06)', border: '1px solid rgba(167, 139, 250, 0.2)', borderRadius: '8px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  <div className="form-group" style={{ margin: 0 }}>
                    <label className="form-label" style={{ fontSize: '12px', fontWeight: 600 }}>
                      <Calendar size={13} style={{ color: 'var(--violet-400)' }} /> Day of the Week
                    </label>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: '4px' }}>
                      {DAYS_OF_WEEK.map((d) => (
                        <button
                          type="button"
                          key={d.id}
                          onClick={() => setEditWeeklyDay(d.id)}
                          className={`btn btn-sm ${editWeeklyDay === d.id ? 'btn-primary' : 'btn-secondary'}`}
                          style={{ padding: '6px 2px', fontSize: '11px', textAlign: 'center' }}
                        >
                          {d.label}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="form-group" style={{ margin: 0 }}>
                    <label className="form-label" style={{ fontSize: '12px', fontWeight: 600 }}>
                      <Clock size={13} style={{ color: 'var(--violet-400)' }} /> Weekly Execution Time
                    </label>
                    <input
                      type="time"
                      className="form-input"
                      value={editTimeOfDay}
                      onChange={(e) => setEditTimeOfDay(e.target.value)}
                      required
                    />
                  </div>

                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                    {TIME_PRESETS.map((p) => (
                      <button
                        type="button"
                        key={p.time}
                        onClick={() => setEditTimeOfDay(p.time)}
                        className={`btn btn-sm ${editTimeOfDay === p.time ? 'btn-primary' : 'btn-ghost'}`}
                        style={{ padding: '3px 8px', fontSize: '11px' }}
                      >
                        {p.label}
                      </button>
                    ))}
                  </div>

                  <div style={{ fontSize: '11px', color: 'var(--violet-400)', background: 'rgba(167, 139, 250, 0.1)', padding: '6px 10px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Repeat size={12} />
                    <span>{getFrequencySummary('weekly', editTimeOfDay, editWeeklyDay, editMonthlyDay, editHourlyMinute, editRunAt)}</span>
                  </div>
                </div>
              )}

              {editFrequency === 'monthly' && (
                <div style={{ background: 'rgba(234, 179, 8, 0.06)', border: '1px solid rgba(234, 179, 8, 0.2)', borderRadius: '8px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  <div className="form-group" style={{ margin: 0 }}>
                    <label className="form-label" style={{ fontSize: '12px', fontWeight: 600 }}>
                      <Calendar size={13} style={{ color: '#eab308' }} /> Day of the Month
                    </label>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '4px' }}>
                      {MONTH_DAYS.map((d) => (
                        <button
                          type="button"
                          key={d}
                          onClick={() => setEditMonthlyDay(d)}
                          className={`btn btn-sm ${editMonthlyDay === d ? 'btn-primary' : 'btn-secondary'}`}
                          style={{ padding: '4px 6px', fontSize: '11px' }}
                        >
                          {getOrdinal(d)}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="form-group" style={{ margin: 0 }}>
                    <label className="form-label" style={{ fontSize: '12px', fontWeight: 600 }}>
                      <Clock size={13} style={{ color: '#eab308' }} /> Monthly Execution Time
                    </label>
                    <input
                      type="time"
                      className="form-input"
                      value={editTimeOfDay}
                      onChange={(e) => setEditTimeOfDay(e.target.value)}
                      required
                    />
                  </div>

                  <div style={{ fontSize: '11px', color: '#eab308', background: 'rgba(234, 179, 8, 0.1)', padding: '6px 10px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Repeat size={12} />
                    <span>{getFrequencySummary('monthly', editTimeOfDay, editWeeklyDay, editMonthlyDay, editHourlyMinute, editRunAt)}</span>
                  </div>
                </div>
              )}

              {editFrequency === 'hourly' && (
                <div style={{ background: 'rgba(100, 116, 139, 0.06)', border: '1px solid rgba(100, 116, 139, 0.2)', borderRadius: '8px', padding: '12px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  <div className="form-group" style={{ margin: 0 }}>
                    <label className="form-label" style={{ fontSize: '12px', fontWeight: 600 }}>
                      <Clock size={13} /> Minute Offset (Past Each Hour)
                    </label>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '4px' }}>
                      {[0, 15, 30, 45].map((m) => (
                        <button
                          type="button"
                          key={m}
                          onClick={() => setEditHourlyMinute(m)}
                          className={`btn btn-sm ${editHourlyMinute === m ? 'btn-primary' : 'btn-secondary'}`}
                          style={{ padding: '4px 6px', fontSize: '11px' }}
                        >
                          :{String(m).padStart(2, '0')}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)', background: 'rgba(100, 116, 139, 0.1)', padding: '6px 10px', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Repeat size={12} />
                    <span>{getFrequencySummary('hourly', editTimeOfDay, editWeeklyDay, editMonthlyDay, editHourlyMinute, editRunAt)}</span>
                  </div>
                </div>
              )}

              {/* Action Buttons */}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px', marginTop: '8px', borderTop: '1px solid var(--border-subtle)', paddingTop: '16px' }}>
                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={() => setEditingScan(null)}
                  disabled={savingEdit}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary btn-sm"
                  disabled={savingEdit}
                  style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
                >
                  {savingEdit ? <RefreshCw size={13} className="spin" /> : <Save size={13} />}
                  <span>Save &amp; Reschedule</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

    </div>
  );
}
