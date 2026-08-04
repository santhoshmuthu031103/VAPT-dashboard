import { useState, useEffect } from 'react';
import { Shield, Plus, Trash2, Search, AlertCircle, RefreshCw, Key, ChevronDown, ChevronUp, Terminal, Monitor, Wifi } from 'lucide-react';

export default function Targets({ apiBase }) {
  const [targets, setTargets]       = useState([]);
  const [credentials, setCreds]     = useState([]);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState(null);
  const [searchTerm, setSearchTerm] = useState('');

  // ── Add Target form ──────────────────────────────────────────────────
  const [showAddForm, setShowAddForm]   = useState(false);
  const [name, setName]                 = useState('');
  const [hosts, setHosts]               = useState('');
  const [comment, setComment]           = useState('');
  const [sshCredId, setSshCredId]       = useState('');
  const [smbCredId, setSmbCredId]       = useState('');
  const [submitting, setSubmitting]     = useState(false);
  const [formError, setFormError]       = useState(null);

  // ── Add Credential form ───────────────────────────────────────────────
  const [showCredForm, setShowCredForm]   = useState(false);
  const [credName, setCredName]           = useState('');
  const [credType, setCredType]           = useState('ssh_password'); // ssh_password | ssh_key | smb | rdp
  const [credUser, setCredUser]           = useState('');
  const [credPass, setCredPass]           = useState('');
  const [credKey, setCredKey]             = useState('');
  const [credSubmitting, setCredSubm]     = useState(false);
  const [credFormErr, setCredFormErr]     = useState(null);

  const fetchAll = async () => {
    setLoading(true); setError(null);
    try {
      const [tRes, cRes] = await Promise.all([
        fetch(`${apiBase}/api/targets`),
        fetch(`${apiBase}/api/credentials`),
      ]);
      if (!tRes.ok) throw new Error('Failed to load targets.');
      if (!cRes.ok) throw new Error('Failed to load credentials.');
      setTargets(await tRes.json());
      setCreds(await cRes.json());
    } catch (err) { setError(err.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { fetchAll(); }, []);

  const handleCreateTarget = async (e) => {
    e.preventDefault(); setSubmitting(true); setFormError(null);
    try {
      const res = await fetch(`${apiBase}/api/targets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer admin-token' },
        body: JSON.stringify({
          name, hosts, comment,
          ssh_credential_id: sshCredId || null,
          smb_credential_id: smbCredId || null,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Failed to create target.');
      setName(''); setHosts(''); setComment(''); setSshCredId(''); setSmbCredId('');
      setShowAddForm(false); fetchAll();
    } catch (err) { setFormError(err.message); }
    finally { setSubmitting(false); }
  };

  const handleCreateCred = async (e) => {
    e.preventDefault(); setCredSubm(true); setCredFormErr(null);
    try {
      const payload = { name: credName, credential_type: credType, username: credUser };
      if (credType === 'ssh_key') payload.private_key = credKey;
      else payload.password = credPass;

      const res = await fetch(`${apiBase}/api/credentials`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer admin-token' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Failed to create credential.');
      setCredName(''); setCredUser(''); setCredPass(''); setCredKey('');
      setShowCredForm(false); fetchAll();
    } catch (err) { setCredFormErr(err.message); }
    finally { setCredSubm(false); }
  };

  const handleDeleteTarget = async (id) => {
    if (!confirm('Delete this target from OpenVAS?')) return;
    const res = await fetch(`${apiBase}/api/targets/${id}`, {
      method: 'DELETE', headers: { 'Authorization': 'Bearer admin-token' }
    });
    if (res.ok) fetchAll(); else alert('Failed to delete target.');
  };

  const handleDeleteCred = async (id) => {
    if (!confirm('Delete this credential?')) return;
    const res = await fetch(`${apiBase}/api/credentials/${id}`, {
      method: 'DELETE', headers: { 'Authorization': 'Bearer admin-token' }
    });
    if (res.ok) fetchAll(); else alert('Failed to delete credential.');
  };

  const filtered = targets.filter(t =>
    (t.name || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
    (t.hosts || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
    (t.comment || '').toLowerCase().includes(searchTerm.toLowerCase())
  );

  const credTypeLabel = (t) => {
    switch (t) {
      case 'ssh_password': return '🐧 SSH (user+pass)';
      case 'ssh_key':      return '🔑 SSH (user+key)';
      case 'smb':          return '🪟 SMB (Windows)';
      case 'rdp':          return '🖥️ RDP (Windows)';
      case 'username+password': return '🔐 User+Password';
      default: return t;
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.8rem', marginBottom: '0.5rem' }}>Scan Targets & Credentials</h2>
          <p>Define authorized hosts and attach SSH/SMB credentials for authenticated scanning.</p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button className="btn btn-secondary" onClick={() => setShowCredForm(!showCredForm)}>
            <Key size={15} /> Add Credential
          </button>
          <button className="btn btn-primary" onClick={() => setShowAddForm(!showAddForm)}>
            <Plus size={15} /> Define New Target
          </button>
        </div>
      </div>

      {/* ── Add Credential Form ────────────────────────────────────────────── */}
      {showCredForm && (
        <div className="panel" style={{ borderLeft: '4px solid var(--accent-cyan)' }}>
          <h3 style={{ marginBottom: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Key size={18} /> New Credential Set
          </h3>
          <form onSubmit={handleCreateCred} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1.25rem' }}>
              <div>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Credential Name</label>
                <input type="text" placeholder="e.g. Linux SSH Key" value={credName} onChange={e => setCredName(e.target.value)} required />
              </div>
              <div>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Credential Type</label>
                <select value={credType} onChange={e => setCredType(e.target.value)}>
                  <option value="ssh_password">🐧 Linux – SSH (Username + Password)</option>
                  <option value="ssh_key">🔑 Linux – SSH (Username + Private Key)</option>
                  <option value="smb">🪟 Windows – SMB (Username + Password)</option>
                  <option value="rdp">🖥️ Windows – RDP (Username + Password)</option>
                </select>
              </div>
              <div>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Username</label>
                <input type="text" placeholder={credType.startsWith('ssh') ? 'e.g. root' : 'e.g. Administrator'} value={credUser} onChange={e => setCredUser(e.target.value)} required />
              </div>
              {credType === 'ssh_key' ? (
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>SSH Private Key (PEM)</label>
                  <textarea rows="6" placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;..." value={credKey} onChange={e => setCredKey(e.target.value)} required style={{ fontFamily: 'monospace', fontSize: '0.8rem' }} />
                </div>
              ) : (
                <div>
                  <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Password</label>
                  <input type="password" placeholder="••••••••" value={credPass} onChange={e => setCredPass(e.target.value)} required />
                </div>
              )}
            </div>
            {credFormErr && <div className="badge badge-high" style={{ padding: '0.75rem', width: '100%', textTransform: 'none', fontSize: '0.9rem' }}>{credFormErr}</div>}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '1rem' }}>
              <button type="button" className="btn btn-secondary" onClick={() => setShowCredForm(false)}>Cancel</button>
              <button type="submit" className="btn btn-primary" disabled={credSubmitting}>
                {credSubmitting ? <RefreshCw className="animate-spin-slow" size={15} /> : <Key size={15} />} Save Credential
              </button>
            </div>
          </form>
        </div>
      )}

      {/* ── Add Target Form ────────────────────────────────────────────── */}
      {showAddForm && (
        <div className="panel" style={{ borderLeft: '4px solid var(--accent-cyan)' }}>
          <h3 style={{ marginBottom: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Shield size={18} /> New Audit Target
          </h3>
          <form onSubmit={handleCreateTarget} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1.25rem' }}>
              <div>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Target Name</label>
                <input type="text" placeholder="e.g. Production Web Cluster" value={name} onChange={e => setName(e.target.value)} required />
              </div>
              <div>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Hosts / IPs / CIDR</label>
                <input type="text" placeholder="e.g. 192.168.1.0/24, 10.0.0.5" value={hosts} onChange={e => setHosts(e.target.value)} required />
              </div>
              <div>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
                  <Terminal size={13} style={{ marginRight: '4px', verticalAlign: 'middle' }} /> SSH Credential (Linux)
                </label>
                <select value={sshCredId} onChange={e => setSshCredId(e.target.value)}>
                  <option value="">— None —</option>
                  {credentials.filter(c => c.type === 'ssh_password' || c.type === 'ssh_key' || c.type === 'username+password').map(c => (
                    <option key={c.id} value={c.id}>{c.name} [{c.type}]</option>
                  ))}
                </select>
              </div>
              <div>
                <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
                  <Monitor size={13} style={{ marginRight: '4px', verticalAlign: 'middle' }} /> SMB/RDP Credential (Windows)
                </label>
                <select value={smbCredId} onChange={e => setSmbCredId(e.target.value)}>
                  <option value="">— None —</option>
                  {credentials.filter(c => c.type === 'smb' || c.type === 'rdp' || c.type === 'username+password').map(c => (
                    <option key={c.id} value={c.id}>{c.name} [{c.type}]</option>
                  ))}
                </select>
              </div>
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Notes / Scope</label>
              <textarea rows="2" placeholder="Authorized scope, owner, notes..." value={comment} onChange={e => setComment(e.target.value)} />
            </div>
            {formError && <div className="badge badge-high" style={{ padding: '0.75rem', width: '100%', textTransform: 'none', fontSize: '0.9rem' }}>{formError}</div>}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '1rem' }}>
              <button type="button" className="btn btn-secondary" onClick={() => setShowAddForm(false)}>Cancel</button>
              <button type="submit" className="btn btn-primary" disabled={submitting}>
                {submitting ? <RefreshCw className="animate-spin-slow" size={15} /> : <Shield size={15} />} Register Target
              </button>
            </div>
          </form>
        </div>
      )}

      {/* ── Targets Table ───────────────────────────────────────────────── */}
      <div className="panel" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
          <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}><Wifi size={16} /> Registered Targets</h3>
          <div style={{ display: 'flex', gap: '0.75rem', flex: 1, maxWidth: '420px' }}>
            <div style={{ position: 'relative', flex: 1 }}>
              <Search size={16} className="text-muted" style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)' }} />
              <input type="text" placeholder="Search targets…" value={searchTerm} onChange={e => setSearchTerm(e.target.value)} style={{ paddingLeft: '2.5rem' }} />
            </div>
            <button className="btn btn-secondary" onClick={fetchAll} disabled={loading}><RefreshCw size={15} className={loading ? 'animate-spin-slow' : ''} /></button>
          </div>
        </div>

        {loading ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '3rem', gap: '1rem' }}>
            <RefreshCw className="animate-spin-slow" size={32} style={{ color: 'var(--accent-cyan)' }} />
            <span className="text-secondary">Loading from OpenVAS…</span>
          </div>
        ) : error ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '2rem', border: '1px solid var(--severity-high)', borderRadius: '8px', backgroundColor: 'var(--severity-high-dim)' }}>
            <AlertCircle size={24} style={{ color: 'var(--severity-high)', flexShrink: 0 }} />
            <div><h4 style={{ color: 'var(--severity-high)' }}>Error Loading Targets</h4><p style={{ fontSize: '0.9rem' }}>{error}</p></div>
          </div>
        ) : filtered.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-secondary)' }}>
            <Shield size={40} className="text-muted" style={{ marginBottom: '1rem' }} />
            <h3>No Targets Found</h3>
            <p style={{ fontSize: '0.9rem', marginTop: '0.5rem' }}>Create a target above to start scanning.</p>
          </div>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Hosts / Scope</th>
                  <th>SSH Credential</th>
                  <th>SMB Credential</th>
                  <th>Notes</th>
                  <th style={{ width: '60px', textAlign: 'center' }}>Del</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(t => (
                  <tr key={t.id}>
                    <td style={{ fontWeight: 600 }}>{t.name}</td>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.85rem', color: 'var(--accent-cyan)' }}>{t.hosts}</td>
                    <td>
                      {t.ssh_credential_name
                        ? <span className="badge badge-log">🔑 {t.ssh_credential_name}</span>
                        : <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>—</span>}
                    </td>
                    <td>
                      {t.smb_credential_name
                        ? <span className="badge badge-low">🪟 {t.smb_credential_name}</span>
                        : <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>—</span>}
                    </td>
                    <td style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>{t.comment}</td>
                    <td style={{ textAlign: 'center' }}>
                      <Trash2 size={14} className="btn-icon" onClick={() => handleDeleteTarget(t.id)} style={{ color: 'var(--severity-high)' }} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ── Saved Credentials Table ──────────────────────────────────────── */}
      <div className="panel" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}><Key size={16} /> Saved Credentials</h3>
        {credentials.length === 0 ? (
          <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>No credentials saved. Use "Add Credential" to create one.</p>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Type</th>
                  <th>Username</th>
                  <th style={{ width: '60px', textAlign: 'center' }}>Del</th>
                </tr>
              </thead>
              <tbody>
                {credentials.map(c => (
                  <tr key={c.id}>
                    <td style={{ fontWeight: 600 }}>{c.name}</td>
                    <td><span className="badge badge-log">{credTypeLabel(c.type)}</span></td>
                    <td style={{ fontFamily: 'monospace' }}>{c.username}</td>
                    <td style={{ textAlign: 'center' }}>
                      <Trash2 size={14} className="btn-icon" onClick={() => handleDeleteCred(c.id)} style={{ color: 'var(--severity-high)' }} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
