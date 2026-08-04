import React, { useState, useEffect } from 'react';
import { Server, ShieldAlert, ShieldCheck, Cpu, RefreshCw, Key, Shield } from 'lucide-react';

export default function Settings({ apiBase, onStatusChange }) {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
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
    setError(null);
    try {
      const res = await fetch(`${apiBase}/api/status`);
      if (!res.ok) throw new Error('Failed to fetch backend connection status.');
      const data = await res.json();
      setStatus(data);
      if (onStatusChange) onStatusChange(data);
      
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
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      <div>
        <h2 style={{ fontSize: '1.8rem', marginBottom: '0.5rem' }}>Shield Connect Settings</h2>
        <p>Orchestrate active scanning instances and GVM/OpenVAS connector configuration.</p>
      </div>

      {/* Backend Status Summary */}
      <div className="panel" style={{ display: 'flex', flexWrap: 'wrap', gap: '2rem', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Server size={20} className="text-secondary" /> Connection Integrity Status
          </h3>
          {loading ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <RefreshCw className="animate-spin-slow text-muted" size={18} />
              <span className="text-secondary">Probing APIs...</span>
            </div>
          ) : error ? (
            <div className="badge badge-high" style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <ShieldAlert size={14} /> Backend Off-line: {error}
            </div>
          ) : (
            <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
              <div className={`badge ${status?.gvm_connected ? 'badge-log' : 'badge-medium'}`}>
                {status?.gvm_connected ? <ShieldCheck size={14} /> : <ShieldAlert size={14} />}
                OpenVAS/GVM: {status?.gvm_mode}
              </div>
              <div className={`badge ${status?.nmap_connected ? 'badge-log' : 'badge-medium'}`}>
                {status?.nmap_connected ? <ShieldCheck size={14} /> : <ShieldAlert size={14} />}
                Nmap Scanner: {status?.nmap_mode}
              </div>
              {status?.nuclei_mode && (
                <div className={`badge ${status?.nuclei_mode === 'Live' ? 'badge-log' : 'badge-medium'}`}>
                  {status?.nuclei_mode === 'Live' ? <ShieldCheck size={14} /> : <ShieldAlert size={14} />}
                  Nuclei: {status?.nuclei_mode}
                </div>
              )}
              {status?.nikto_mode && (
                <div className={`badge ${status?.nikto_mode === 'Live' ? 'badge-log' : 'badge-medium'}`}>
                  {status?.nikto_mode === 'Live' ? <ShieldCheck size={14} /> : <ShieldAlert size={14} />}
                  Nikto: {status?.nikto_mode}
                </div>
              )}
              {status?.zap_mode && (
                <div className={`badge ${status?.zap_mode === 'Live' ? 'badge-log' : 'badge-medium'}`}>
                  {status?.zap_mode === 'Live' ? <ShieldCheck size={14} /> : <ShieldAlert size={14} />}
                  OWASP ZAP: {status?.zap_mode}
                </div>
              )}
              {status?.gobuster_mode && (
                <div className={`badge ${status?.gobuster_mode === 'Live' ? 'badge-log' : 'badge-medium'}`}>
                  {status?.gobuster_mode === 'Live' ? <ShieldCheck size={14} /> : <ShieldAlert size={14} />}
                  Gobuster: {status?.gobuster_mode}
                </div>
              )}
            </div>
          )}
        </div>

        <button className="btn btn-secondary" onClick={fetchStatus} disabled={loading}>
          <RefreshCw size={16} className={loading ? 'animate-spin-slow' : ''} /> Probe Status
        </button>
      </div>

      {/* Configuration Panel */}
      <div className="panel">
        <h3 style={{ marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Key size={20} className="text-secondary" /> GVM / OpenVAS Daemon Settings
        </h3>

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1.25rem' }}>
            <div>
              <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Connection Type</label>
              <select value={connType} onChange={(e) => setConnType(e.target.value)}>
                <option value="socket">Unix Socket (Local Daemon)</option>
                <option value="tls">TLS Connection (Remote Host)</option>
              </select>
            </div>

            {connType === 'socket' ? (
              <div>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Socket Path</label>
                <input 
                  type="text" 
                  value={socketPath} 
                  onChange={(e) => setSocketPath(e.target.value)} 
                  required 
                />
              </div>
            ) : (
              <>
                <div>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Host / IP Address</label>
                  <input 
                    type="text" 
                    value={host} 
                    onChange={(e) => setHost(e.target.value)} 
                    required 
                  />
                </div>
                <div>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Port</label>
                  <input 
                    type="number" 
                    value={port} 
                    onChange={(e) => setPort(e.target.value)} 
                    required 
                  />
                </div>
              </>
            )}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1.25rem' }}>
            <div>
              <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>GMP Username</label>
              <input 
                type="text" 
                value={username} 
                onChange={(e) => setUsername(e.target.value)} 
                required 
              />
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>GMP Password</label>
              <input 
                type="password" 
                value={password} 
                onChange={(e) => setPassword(e.target.value)} 
                placeholder="Enter password to authenticate" 
                required 
              />
            </div>
          </div>

          {submitMsg && (
            <div className={`badge ${submitMsg.type === 'success' ? 'badge-log' : 'badge-high'}`} style={{ padding: '0.75rem', width: '100%', textTransform: 'none', fontSize: '0.9rem' }}>
              {submitMsg.text}
            </div>
          )}

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              {submitting ? <RefreshCw className="animate-spin-slow" size={16} /> : <Shield size={16} />}
              Apply Settings & Authenticate
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
