import React, { useState, useEffect } from 'react';
import { Server, ShieldAlert, ShieldCheck, Cpu, RefreshCw, Key, Shield, Database } from 'lucide-react';

export default function Settings({ apiBase, onStatusChange }) {
  const [status, setStatus] = useState(null);
  const [feeds, setFeeds] = useState(null);
  const [loading, setLoading] = useState(true);
  const [feedsLoading, setFeedsLoading] = useState(true);
  const [error, setError] = useState(null);

  // Connection form state
  const [connType, setConnType] = useState('socket');
  const [socketPath, setSocketPath] = useState('/run/gvmd/gvmd.sock');
  const [host, setHost] = useState('localhost');
  const [port, setPort] = useState(9390);
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submitMsg, setSubmitMsg] = useState(null);

  const fetchStatus = async () => {
    setLoading(true);
    setFeedsLoading(true);
    setError(null);
    try {
      const [res, feedsRes] = await Promise.all([
        fetch(`${apiBase}/api/status`),
        fetch(`${apiBase}/api/feed-status`),
      ]);
      if (!res.ok) throw new Error('Failed to fetch backend connection status.');
      const data = await res.json();
      setStatus(data);
      if (onStatusChange) onStatusChange(data);
      
      if (feedsRes.ok) {
        setFeeds(await feedsRes.json());
      }
      
      // Pre-fill form fields with active settings
      if (data.settings) {
        setConnType(data.settings.connection_type || 'socket');
        setSocketPath(data.settings.socket_path || '/run/gvmd/gvmd.sock');
        setHost(data.settings.host || 'localhost');
        setPort(data.settings.port || 9390);
        setUsername(data.settings.username || 'admin');
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
      setFeedsLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setSubmitMsg(null);
    try {
      const res = await fetch(`${apiBase}/api/settings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          connection_type: connType,
          socket_path: socketPath,
          host,
          port: parseInt(port),
          username,
          password
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Failed to save settings.');
      
      setSubmitMsg({ type: 'success', text: data.message || 'Settings applied successfully!' });
      fetchStatus(); // Refresh status
    } catch (err) {
      setSubmitMsg({ type: 'error', text: err.message });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }} className="fade-in">
      {/* Connection Integrity Status */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <Server size={14} style={{ color: 'var(--violet-300)' }} /> Connection Integrity Status
          </span>
          <button 
            className="btn btn-secondary btn-sm" 
            onClick={fetchStatus} 
            disabled={loading}
          >
            <RefreshCw size={13} className={loading ? 'spin' : ''} />
            Probe Status
          </button>
        </div>

        <div className="card-body">
          {loading ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-secondary)' }}>
              <RefreshCw className="spin" size={16} />
              <span>Probing connector APIs...</span>
            </div>
          ) : error ? (
            <div className="alert alert-error">
              <ShieldAlert size={14} /> Backend Offline: {error}
            </div>
          ) : (
            <>
              <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '1.25rem' }}>
                <span className={`badge ${status?.gvm_connected ? 'badge-success' : 'badge-critical'}`}>
                  {status?.gvm_connected ? <ShieldCheck size={12} /> : <ShieldAlert size={12} />}
                  OpenVAS/GVM: {status?.gvm_mode}
                </span>
                <span className={`badge ${status?.nmap_connected ? 'badge-success' : 'badge-critical'}`}>
                  {status?.nmap_connected ? <ShieldCheck size={12} /> : <ShieldAlert size={12} />}
                  Nmap Scanner: {status?.nmap_mode}
                </span>
                {status?.nuclei_mode && (
                  <span className={`badge ${status?.nuclei_mode === 'Live' ? 'badge-success' : 'badge-critical'}`}>
                    {status?.nuclei_mode === 'Live' ? <ShieldCheck size={12} /> : <ShieldAlert size={12} />}
                    Nuclei: {status?.nuclei_mode}
                  </span>
                )}
                {status?.nikto_mode && (
                  <span className={`badge ${status?.nikto_mode === 'Live' ? 'badge-success' : 'badge-critical'}`}>
                    {status?.nikto_mode === 'Live' ? <ShieldCheck size={12} /> : <ShieldAlert size={12} />}
                    Nikto: {status?.nikto_mode}
                  </span>
                )}
                {status?.zap_mode && (
                  <span className={`badge ${status?.zap_mode === 'Live' ? 'badge-success' : 'badge-critical'}`}>
                    {status?.zap_mode === 'Live' ? <ShieldCheck size={12} /> : <ShieldAlert size={12} />}
                    OWASP ZAP: {status?.zap_mode}
                  </span>
                )}
                {status?.gobuster_mode && (
                  <span className={`badge ${status?.gobuster_mode === 'Live' ? 'badge-success' : 'badge-critical'}`}>
                    {status?.gobuster_mode === 'Live' ? <ShieldCheck size={12} /> : <ShieldAlert size={12} />}
                    Gobuster: {status?.gobuster_mode}
                  </span>
                )}
              </div>

              {/* Feed status section */}
              <div style={{ borderTop: '1px solid var(--border-default)', paddingTop: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Database size={13} style={{ color: 'var(--violet-400)' }} />
                  Scanner Signature &amp; Template Feeds
                </div>
                
                {feedsLoading ? (
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <RefreshCw className="spin" size={12} /> Loading signature databases...
                  </div>
                ) : feeds ? (
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px' }}>
                    {/* OpenVAS Feeds */}
                    {(feeds.gvm_feeds || []).map(f => (
                      <div key={f.type} style={{ background: 'var(--bg-elevated)', borderRadius: 6, padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 4, border: '1px solid var(--border-default)' }}>
                        <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--violet-300)', textTransform: 'uppercase' }}>{f.type} Signature Feed</span>
                        <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)' }}>{f.name}</span>
                        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Version: <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{f.version || '—'}</span></span>
                      </div>
                    ))}
                    {/* Nuclei Feed */}
                    {feeds.nuclei_templates && (
                      <div style={{ background: 'var(--bg-elevated)', borderRadius: 6, padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 4, border: '1px solid var(--border-default)' }}>
                        <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--emerald-400)', textTransform: 'uppercase' }}>YAML Vulnerability templates</span>
                        <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)' }}>Nuclei Community Templates</span>
                        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Active Signatures: <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{feeds.nuclei_templates.count.toLocaleString()} templates</span></span>
                      </div>
                    )}
                  </div>
                ) : (
                  <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Signature feed data unavailable (connectors offline).</div>
                )}
              </div>
            </>
          )}
        </div>
      </div>

      {/* Configuration Panel */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <Key size={14} style={{ color: 'var(--violet-300)' }} /> GVM / OpenVAS Daemon Settings
          </span>
        </div>

        <div className="card-body">
          <form onSubmit={handleSubmit} className="form-section">
            <div className="form-row-2">
              <div className="form-group">
                <label className="form-label">Connection Type</label>
                <select 
                  className="form-select"
                  value={connType} 
                  onChange={(e) => setConnType(e.target.value)}
                >
                  <option value="socket">Unix Socket (Local Daemon)</option>
                  <option value="tls">TLS Connection (Remote Host)</option>
                </select>
              </div>

              {connType === 'socket' ? (
                <div className="form-group">
                  <label className="form-label">Socket Path</label>
                  <input 
                    type="text" 
                    className="form-input"
                    value={socketPath} 
                    onChange={(e) => setSocketPath(e.target.value)} 
                    required 
                  />
                </div>
              ) : (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 120px', gap: '12px' }}>
                  <div className="form-group">
                    <label className="form-label">Host / IP Address</label>
                    <input 
                      type="text" 
                      className="form-input"
                      value={host} 
                      onChange={(e) => setHost(e.target.value)} 
                      required 
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Port</label>
                    <input 
                      type="number" 
                      className="form-input"
                      value={port} 
                      onChange={(e) => setPort(e.target.value)} 
                      required 
                    />
                  </div>
                </div>
              )}
            </div>

            <div className="form-row-2">
              <div className="form-group">
                <label className="form-label">GMP Username</label>
                <input 
                  type="text" 
                  className="form-input"
                  value={username} 
                  onChange={(e) => setUsername(e.target.value)} 
                  required 
                />
              </div>
              <div className="form-group">
                <label className="form-label">GMP Password</label>
                <input 
                  type="password" 
                  className="form-input"
                  value={password} 
                  onChange={(e) => setPassword(e.target.value)} 
                  placeholder="Enter password to authenticate" 
                  required 
                />
              </div>
            </div>

            {submitMsg && (
              <div className={`alert ${submitMsg.type === 'success' ? 'alert-success' : 'alert-error'}`}>
                {submitMsg.text}
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
              <button type="submit" className="btn btn-primary" disabled={submitting}>
                {submitting ? <RefreshCw className="spin" size={14} /> : <Shield size={14} />}
                Apply Settings & Authenticate
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
