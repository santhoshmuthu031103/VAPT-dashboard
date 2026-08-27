import React, { useState, useEffect } from 'react';
import {
  Shield, Plus, Trash2, Search, AlertCircle, RefreshCw,
  Key, Terminal, Monitor, Wifi, Lock, User, Server, Globe,
  CheckCircle2, X, FolderOpen, Edit2, Users, Tag, Check, Copy
} from 'lucide-react';

const CRED_TYPES = [
  { value: 'ssh_password', label: 'Linux — SSH (Username + Password)' },
  { value: 'ssh_key',      label: 'Linux — SSH (Username + Key)' },
  { value: 'smb',          label: 'Windows — SMB' },
  { value: 'rdp',          label: 'Windows — RDP' },
];

const GROUP_COLORS = [
  { label: 'Purple',  value: '#8b5cf6' },
  { label: 'Blue',    value: '#3b82f6' },
  { label: 'Emerald', value: '#10b981' },
  { label: 'Amber',   value: '#f59e0b' },
  { label: 'Rose',    value: '#f43f5e' },
  { label: 'Cyan',    value: '#06b6d4' },
];

function CredTypeBadge({ type }) {
  const map = { ssh_password: 'SSH', ssh_key: 'SSH Key', smb: 'SMB', rdp: 'RDP', 'username+password': 'Auth' };
  return <span className="badge badge-violet">{map[type] || type}</span>;
}

export default function Targets({ apiBase }) {
  // Navigation sub-tab: 'groups' | 'inventory'
  const [activeTab, setActiveTab] = useState('groups');

  const [targets, setTargets]         = useState([]);
  const [targetGroups, setTargetGroups] = useState([]);
  const [credentials, setCreds]       = useState([]);
  const [portLists, setPortLists]     = useState([]);
  const [loading, setLoading]         = useState(true);
  const [error, setError]             = useState(null);
  const [searchTerm, setSearch]       = useState('');
  const [copiedHost, setCopiedHost]   = useState(null);
  
  // Forms: 'target' | 'cred' | 'group' | null
  const [activeForm, setForm]         = useState(null);
  const [editingTargetId, setEditingTargetId] = useState(null);
  const [editingCredId, setEditingCredId]     = useState(null);
  const [editingGroupId, setEditingGroupId]   = useState(null);

  // Target form fields
  const [name, setName]               = useState('');
  const [hosts, setHosts]             = useState('');
  const [comment, setComment]         = useState('');
  const [sshCredId, setSshCred]       = useState('');
  const [smbCredId, setSmbCred]       = useState('');
  const [portListId, setPortListId]   = useState('');
  const [submitting, setSub]          = useState(false);
  const [formErr, setFormErr]         = useState(null);

  // Credential form fields
  const [credName, setCredName]       = useState('');
  const [credType, setCredType]       = useState('ssh_password');
  const [credUser, setCredUser]       = useState('');
  const [credPass, setCredPass]       = useState('');
  const [credKey, setCredKey]         = useState('');
  const [credSub, setCredSub]         = useState(false);
  const [credErr, setCredErr]         = useState(null);

  // Selection & Bulk Action state in Inventory
  const [selectedTargetIds, setSelectedTargetIds] = useState([]);
  const [bulkGroupId, setBulkGroupId]             = useState('');

  // Target Group form fields
  const [groupName, setGroupName]     = useState('');
  const [groupDesc, setGroupDesc]     = useState('');
  const [groupHosts, setGroupHosts]   = useState('');
  const [groupColor, setGroupColor]   = useState('#8b5cf6');
  const [groupSub, setGroupSub]       = useState(false);
  const [groupErr, setGroupErr]       = useState(null);

  // ── Quick-pick registered targets in Group Form ──
  const handleToggleTargetInGroup = (t) => {
    const currentHosts = groupHosts
      .split(/[\n,]+/)
      .map(h => h.trim())
      .filter(Boolean);

    const tHosts = (t.hosts || t.name || '')
      .split(/[\n,]+/)
      .map(h => h.trim())
      .filter(Boolean);

    const isAllIncluded = tHosts.length > 0 && tHosts.every(th => currentHosts.includes(th));

    let updated;
    if (isAllIncluded) {
      updated = currentHosts.filter(ch => !tHosts.includes(ch));
    } else {
      const toAdd = tHosts.filter(th => !currentHosts.includes(th));
      updated = [...currentHosts, ...toAdd];
    }
    setGroupHosts(updated.join('\n'));
  };

  const handleSelectAllTargetsInGroup = () => {
    const allHosts = new Set();
    targets.forEach(t => {
      (t.hosts || '')
        .split(/[\n,]+/)
        .map(h => h.trim())
        .filter(Boolean)
        .forEach(h => allHosts.add(h));
    });
    setGroupHosts(Array.from(allHosts).join('\n'));
  };

  const handleClearTargetsInGroup = () => {
    setGroupHosts('');
  };

  // ── Inventory Multi-Selection & Bulk Actions ──
  const handleToggleSelectTarget = (id) => {
    setSelectedTargetIds(prev =>
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
    );
  };

  const handleSelectAllInventory = (filtered) => {
    if (selectedTargetIds.length === filtered.length && filtered.length > 0) {
      setSelectedTargetIds([]);
    } else {
      setSelectedTargetIds(filtered.map(t => t.id));
    }
  };

  const handleCreateGroupFromSelected = () => {
    const selected = targets.filter(t => selectedTargetIds.includes(t.id));
    if (!selected.length) return;

    const allHosts = new Set();
    selected.forEach(t => {
      (t.hosts || '')
        .split(/[\n,]+/)
        .map(h => h.trim())
        .filter(Boolean)
        .forEach(h => allHosts.add(h));
    });

    setEditingGroupId(null);
    setGroupName(selected.length === 1 ? `${selected[0].name} Group` : `Group (${selected.length} Targets)`);
    setGroupDesc(`Group containing ${selected.map(t => t.name).join(', ')}`);
    setGroupHosts(Array.from(allHosts).join('\n'));
    setGroupColor('#8b5cf6');
    setGroupErr(null);
    setActiveTab('groups');
    setForm('group');
  };

  const handleAddSelectedToExistingGroup = async (groupId) => {
    if (!groupId) return;
    try {
      const group = targetGroups.find(g => g.id.toString() === groupId.toString());
      if (!group) return;

      const existingHosts = (Array.isArray(group.targets) ? group.targets : (group.targets ? group.targets.split(',') : [])).map(h => h.trim()).filter(Boolean);
      const hostsSet = new Set(existingHosts);

      const selected = targets.filter(t => selectedTargetIds.includes(t.id));
      selected.forEach(t => {
        (t.hosts || '')
          .split(/[\n,]+/)
          .map(h => h.trim())
          .filter(Boolean)
          .forEach(h => hostsSet.add(h));
      });

      const res = await fetch(`${apiBase}/api/target-groups/${groupId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targets: Array.from(hostsSet)
        })
      });
      if (res.ok) {
        setSelectedTargetIds([]);
        setBulkGroupId('');
        fetchAll();
      } else {
        alert('Failed to update group targets.');
      }
    } catch (e) {
      alert(`Failed to add targets to group: ${e.message}`);
    }
  };

  const fetchAll = async () => {
    setLoading(true); setError(null);
    try {
      const [tRes, cRes, pRes, gRes] = await Promise.allSettled([
        fetch(`${apiBase}/api/targets`),
        fetch(`${apiBase}/api/credentials`),
        fetch(`${apiBase}/api/port-lists`),
        fetch(`${apiBase}/api/target-groups`)
      ]);
      
      if (tRes.status === 'fulfilled' && tRes.value && tRes.value.ok) {
        setTargets(await tRes.value.json());
      }
      if (cRes.status === 'fulfilled' && cRes.value && cRes.value.ok) {
        setCreds(await cRes.value.json());
      }
      if (pRes.status === 'fulfilled' && pRes.value && pRes.value.ok) {
        const pData = await pRes.value.json();
        setPortLists(Array.isArray(pData) ? pData : []);
        if (pData.length) {
          const defaultPl = pData.find(p => p.name && (p.name.includes("IANA assigned TCP") || p.name.includes("All IANA"))) || pData[0];
          setPortListId(prev => prev || defaultPl.id);
        }
      }
      if (gRes.status === 'fulfilled' && gRes.value && gRes.value.ok) {
        setTargetGroups(await gRes.value.json());
      }
    } catch (e) { 
      setError(e.message); 
    } finally { 
      setLoading(false); 
    }
  };

  useEffect(() => { fetchAll(); }, []);

  // ── Open Target Form ──
  const openTargetCreate = () => {
    setEditingTargetId(null);
    setName(''); setHosts(''); setComment(''); setSshCred(''); setSmbCred('');
    setFormErr(null);
    setForm(activeForm === 'target' ? null : 'target');
  };

  const openTargetEdit = (target) => {
    setEditingTargetId(target.id);
    setName(target.name || '');
    setHosts(target.hosts || '');
    setComment(target.comment || '');
    setSshCred(target.ssh_credential_id || '');
    setSmbCred(target.smb_credential_id || '');
    setPortListId(target.port_list_id || (portLists[0]?.id || ''));
    setFormErr(null);
    setForm('target');
  };

  // ── Open Credential Form ──
  const openCredCreate = () => {
    setEditingCredId(null);
    setCredName(''); setCredType('ssh_password'); setCredUser(''); setCredPass(''); setCredKey('');
    setCredErr(null);
    setForm(activeForm === 'cred' ? null : 'cred');
  };

  const openCredEdit = (cred) => {
    setEditingCredId(cred.id);
    setCredName(cred.name || '');
    setCredType(cred.type || 'ssh_password');
    setCredUser(cred.username || '');
    setCredPass('');
    setCredKey('');
    setCredErr(null);
    setForm('cred');
  };

  // ── Open Target Group Form ──
  const openGroupCreate = () => {
    setEditingGroupId(null);
    setGroupName('');
    setGroupDesc('');
    setGroupHosts('');
    setGroupColor('#8b5cf6');
    setGroupErr(null);
    setForm(activeForm === 'group' ? null : 'group');
  };

  const openGroupEdit = (group) => {
    setEditingGroupId(group.id);
    setGroupName(group.name || '');
    setGroupDesc(group.description || '');
    const hostsList = Array.isArray(group.targets) ? group.targets.join('\n') : (group.targets || '');
    setGroupHosts(hostsList);
    setGroupColor(group.color || '#8b5cf6');
    setGroupErr(null);
    setForm('group');
  };

  // ── Save or Update Target Group ──
  const handleSaveGroup = async (e) => {
    e.preventDefault();
    setGroupSub(true); setGroupErr(null);
    try {
      const isEditing = Boolean(editingGroupId);
      const url = isEditing ? `${apiBase}/api/target-groups/${editingGroupId}` : `${apiBase}/api/target-groups`;
      const method = isEditing ? 'PUT' : 'POST';

      const targetsArray = groupHosts
        .split(/[\n,]+/)
        .map(h => h.trim())
        .filter(h => h.length > 0);

      if (targetsArray.length === 0) {
        throw new Error('Please specify at least one target host or IP address.');
      }

      const payload = {
        name: groupName.trim(),
        description: groupDesc.trim(),
        targets: targetsArray,
        color: groupColor
      };

      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || `Failed to ${isEditing ? 'update' : 'create'} target group.`);

      setForm(null);
      setEditingGroupId(null);
      fetchAll();
    } catch (e) {
      setGroupErr(e.message);
    } finally {
      setGroupSub(false);
    }
  };

  const handleDeleteGroup = async (id) => {
    if (!confirm('Are you sure you want to delete this target group?')) return;
    try {
      const res = await fetch(`${apiBase}/api/target-groups/${id}`, { method: 'DELETE' });
      if (res.ok) fetchAll(); else alert('Failed to delete target group.');
    } catch (err) {
      alert(err.message);
    }
  };

  // ── Save or Update Target ──
  const handleSaveTarget = async (e) => {
    e.preventDefault(); setSub(true); setFormErr(null);
    try {
      const isEditing = Boolean(editingTargetId);
      const url = isEditing ? `${apiBase}/api/targets/${editingTargetId}` : `${apiBase}/api/targets`;
      const method = isEditing ? 'PUT' : 'POST';

      const payload = {
        name,
        hosts,
        comment,
        ssh_credential_id: sshCredId || null,
        smb_credential_id: smbCredId || null,
        port_list_id: portListId || null
      };

      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer admin-token' },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || `Failed to ${isEditing ? 'update' : 'create'} target.`);

      setName(''); setHosts(''); setComment(''); setSshCred(''); setSmbCred('');
      setEditingTargetId(null);
      setForm(null);
      fetchAll();
    } catch (e) { setFormErr(e.message); }
    finally { setSub(false); }
  };

  // ── Save or Update Credential ──
  const handleSaveCred = async (e) => {
    e.preventDefault(); setCredSub(true); setCredErr(null);
    try {
      const isEditing = Boolean(editingCredId);
      const url = isEditing ? `${apiBase}/api/credentials/${editingCredId}` : `${apiBase}/api/credentials`;
      const method = isEditing ? 'PUT' : 'POST';

      const payload = {
        name: credName,
        credential_type: credType,
        username: credUser
      };

      if (credType === 'ssh_key') {
        if (credKey) payload.private_key = credKey;
      } else {
        if (credPass) payload.password = credPass;
      }

      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer admin-token' },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || `Failed to ${isEditing ? 'update' : 'create'} credential.`);

      setCredName(''); setCredUser(''); setCredPass(''); setCredKey('');
      setEditingCredId(null);
      setForm(null);
      fetchAll();
    } catch (e) { setCredErr(e.message); }
    finally { setCredSub(false); }
  };

  const handleDeleteTarget = async (id) => {
    if (!confirm('Delete this target from OpenVAS?')) return;
    const res = await fetch(`${apiBase}/api/targets/${id}`, { method: 'DELETE', headers: { 'Authorization': 'Bearer admin-token' } });
    if (res.ok) fetchAll(); else alert('Failed to delete target.');
  };

  const handleDeleteCred = async (id) => {
    if (!confirm('Delete this credential?')) return;
    const res = await fetch(`${apiBase}/api/credentials/${id}`, { method: 'DELETE', headers: { 'Authorization': 'Bearer admin-token' } });
    if (res.ok) fetchAll(); else alert('Failed to delete credential.');
  };

  const copyToClipboard = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedHost(id);
    setTimeout(() => setCopiedHost(null), 2000);
  };

  const filteredGroups = targetGroups.filter(g =>
    (g.name || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
    (g.description || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
    (Array.isArray(g.targets) ? g.targets.join(' ') : (g.targets || '')).toLowerCase().includes(searchTerm.toLowerCase())
  );

  const filteredTargets = targets.filter(t =>
    (t.name || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
    (t.hosts || '').toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Total grouped hosts count
  const totalGroupedHosts = targetGroups.reduce((acc, g) => {
    const count = Array.isArray(g.targets) ? g.targets.length : (g.targets ? g.targets.split(',').length : 0);
    return acc + count;
  }, 0);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

      {/* ── Sub Navigation & Action Bar ── */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        
        {/* Tab switchers */}
        <div style={{ display: 'flex', background: 'var(--bg-card)', padding: '4px', borderRadius: '8px', border: '1px solid var(--border-default)', gap: '4px' }}>
          <button
            className={`btn ${activeTab === 'groups' ? 'btn-primary' : 'btn-ghost'}`}
            style={{ fontSize: '13px', padding: '6px 14px', borderRadius: '6px' }}
            onClick={() => { setActiveTab('groups'); setForm(null); }}
          >
            <Users size={14} />
            <span>Target Groups ({targetGroups.length})</span>
          </button>
          <button
            className={`btn ${activeTab === 'inventory' ? 'btn-primary' : 'btn-ghost'}`}
            style={{ fontSize: '13px', padding: '6px 14px', borderRadius: '6px' }}
            onClick={() => { setActiveTab('inventory'); setForm(null); }}
          >
            <Server size={14} />
            <span>OpenVAS Inventory ({targets.length})</span>
          </button>
        </div>

        {/* Action buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          {activeTab === 'groups' ? (
            <button
              className="btn btn-primary"
              onClick={openGroupCreate}
            >
              <Plus size={14} />
              {activeForm === 'group' && !editingGroupId ? 'Close' : 'New Target Group'}
            </button>
          ) : (
            <>
              <button
                className={`btn ${activeForm === 'cred' && !editingCredId ? 'btn-primary' : 'btn-secondary'}`}
                onClick={openCredCreate}
              >
                <Key size={14} />
                {activeForm === 'cred' && !editingCredId ? 'Close' : 'Add Credential'}
              </button>
              <button
                className="btn btn-primary"
                onClick={openTargetCreate}
              >
                <Plus size={14} />
                {activeForm === 'target' && !editingTargetId ? 'Close' : 'New Target'}
              </button>
            </>
          )}
        </div>
      </div>

      {/* ── Target Group Form (Create & Edit) ── */}
      {activeForm === 'group' && (
        <div className="card fade-in" style={{ borderLeft: `3px solid ${groupColor}` }}>
          <div className="card-header">
            <span className="card-title">
              <Users size={14} style={{ color: groupColor }} />
              {editingGroupId ? 'Edit Target Group' : 'Create New Target Group'}
            </span>
            <button className="btn btn-ghost btn-icon btn-sm" onClick={() => { setForm(null); setEditingGroupId(null); }}>
              <X size={14} />
            </button>
          </div>
          <form onSubmit={handleSaveGroup}>
            <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div className="form-row form-row-2">
                <div className="form-group">
                  <label className="form-label"><Users size={12} /> Group Name</label>
                  <input
                    className="form-input"
                    placeholder="e.g. Production Web Cluster, DMZ Gateway Servers"
                    value={groupName}
                    onChange={e => setGroupName(e.target.value)}
                    required
                  />
                </div>
                <div className="form-group">
                  <label className="form-label"><Tag size={12} /> Group Badge Color</label>
                  <div style={{ display: 'flex', gap: '8px', alignItems: 'center', height: '38px' }}>
                    {GROUP_COLORS.map(c => (
                      <button
                        key={c.value}
                        type="button"
                        onClick={() => setGroupColor(c.value)}
                        style={{
                          width: '24px',
                          height: '24px',
                          borderRadius: '50%',
                          background: c.value,
                          border: groupColor === c.value ? '2px solid #fff' : '2px solid transparent',
                          boxShadow: groupColor === c.value ? `0 0 0 2px ${c.value}` : 'none',
                          cursor: 'pointer'
                        }}
                        title={c.label}
                      />
                    ))}
                  </div>
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Description / Scope Details</label>
                <input
                  className="form-input"
                  placeholder="e.g. Core microservices running on port 8080/443 in AWS us-east-1"
                  value={groupDesc}
                  onChange={e => setGroupDesc(e.target.value)}
                />
              </div>

              {/* Quick-Select from Defined Targets */}
              {targets.length > 0 && (
                <div style={{
                  background: 'var(--bg-base, #f8fafc)',
                  border: '1px solid var(--border-default, #e2e8f0)',
                  borderRadius: '8px',
                  padding: '12px 14px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '10px'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-primary, #0f172a)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Globe size={13} style={{ color: 'var(--violet-600, #7c3aed)' }} />
                      <span>Quick-Add from Registered Targets ({targets.length})</span>
                    </span>
                    <div style={{ display: 'flex', gap: '6px' }}>
                      <button
                        type="button"
                        onClick={handleSelectAllTargetsInGroup}
                        className="btn btn-secondary btn-sm"
                        style={{ fontSize: '11px', padding: '2px 8px', height: '24px' }}
                      >
                        Select All
                      </button>
                      <button
                        type="button"
                        onClick={handleClearTargetsInGroup}
                        className="btn btn-ghost btn-sm"
                        style={{ fontSize: '11px', padding: '2px 8px', height: '24px', color: 'var(--text-muted)' }}
                      >
                        Clear
                      </button>
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', maxHeight: '140px', overflowY: 'auto', paddingRight: '4px' }}>
                    {targets.map(t => {
                      const tHosts = (t.hosts || t.name || '').split(/[\n,]+/).map(h => h.trim()).filter(Boolean);
                      const currentHosts = groupHosts.split(/[\n,]+/).map(h => h.trim()).filter(Boolean);
                      const isSelected = tHosts.length > 0 && tHosts.every(th => currentHosts.includes(th));

                      return (
                        <button
                          key={`pick-target-${t.id}`}
                          type="button"
                          onClick={() => handleToggleTargetInGroup(t)}
                          style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '6px',
                            padding: '5px 10px',
                            borderRadius: '6px',
                            fontSize: '12px',
                            cursor: 'pointer',
                            transition: 'all 0.15s ease',
                            border: isSelected ? '1.5px solid var(--violet-600, #7c3aed)' : '1px solid var(--border-default, #cbd5e1)',
                            background: isSelected ? 'var(--violet-dim, #f5f3ff)' : 'var(--bg-surface, #ffffff)',
                            color: isSelected ? 'var(--violet-700, #6d28d9)' : 'var(--text-primary, #0f172a)',
                            boxShadow: isSelected ? '0 1px 3px rgba(124, 58, 237, 0.15)' : '0 1px 2px rgba(0, 0, 0, 0.04)',
                            fontWeight: isSelected ? 600 : 500
                          }}
                        >
                          {isSelected ? (
                            <Check size={13} style={{ color: 'var(--emerald-600, #059669)', flexShrink: 0 }} />
                          ) : (
                            <Plus size={13} style={{ color: 'var(--violet-500, #7c3aed)', flexShrink: 0 }} />
                          )}
                          <span>{t.name}</span>
                          <span style={{ fontSize: '11px', color: isSelected ? 'var(--violet-600, #7c3aed)' : 'var(--text-secondary, #64748b)', fontFamily: 'var(--font-mono)' }}>
                            ({t.hosts})
                          </span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}

              <div className="form-group">
                <label className="form-label"><Server size={12} /> Target Hosts / IPs / CIDRs (one per line or comma-separated)</label>
                <textarea
                  className="form-input"
                  rows={4}
                  placeholder={`192.168.1.10\n192.168.1.11\n10.0.0.0/24\napi.production.internal`}
                  value={groupHosts}
                  onChange={e => setGroupHosts(e.target.value)}
                  required
                  style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', resize: 'vertical' }}
                />
                <span className="form-hint">Scanners will evaluate all hosts in this group in sequence or batch.</span>
              </div>

              {groupErr && <div className="error-message"><AlertCircle size={14} /><span>{groupErr}</span></div>}

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
                <button type="button" className="btn btn-secondary btn-sm" onClick={() => { setForm(null); setEditingGroupId(null); }}>Cancel</button>
                <button type="submit" className="btn btn-primary btn-sm" disabled={groupSub}>
                  {groupSub ? <><RefreshCw size={13} className="spinner" /> Saving...</> : <><CheckCircle2 size={13} /> {editingGroupId ? 'Update Group' : 'Create Group'}</>}
                </button>
              </div>
            </div>
          </form>
        </div>
      )}

      {/* ── Credential Form (Create & Edit) ── */}
      {activeForm === 'cred' && (
        <div className="card fade-in" style={{ borderLeft: '3px solid var(--violet-500)' }}>
          <div className="card-header">
            <span className="card-title">
              <Key size={14} style={{ color: 'var(--violet-300)' }} />
              {editingCredId ? 'Edit Credential' : 'New Credential Set'}
            </span>
            <button className="btn btn-ghost btn-icon btn-sm" onClick={() => { setForm(null); setEditingCredId(null); }}><X size={14} /></button>
          </div>
          <form onSubmit={handleSaveCred}>
            <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div className="form-row form-row-2">
                <div className="form-group">
                  <label className="form-label"><User size={12}/> Credential Name</label>
                  <input className="form-input" placeholder="e.g. Production SSH Key" value={credName} onChange={e => setCredName(e.target.value)} required />
                </div>
                <div className="form-group">
                  <label className="form-label"><Lock size={12}/> Credential Type</label>
                  <select className="form-select" value={credType} onChange={e => setCredType(e.target.value)}>
                    {CRED_TYPES.map(c => <option key={c.value} value={c.value}>{c.label}</option>)}
                  </select>
                </div>
              </div>

              <div className="form-row form-row-2">
                <div className="form-group">
                  <label className="form-label"><User size={12}/> Username</label>
                  <input className="form-input" placeholder={credType.startsWith('ssh') ? 'root' : 'Administrator'} value={credUser} onChange={e => setCredUser(e.target.value)} required />
                </div>
                {credType !== 'ssh_key' && (
                  <div className="form-group">
                    <label className="form-label">
                      <Lock size={12}/> {editingCredId ? 'Change Password (leave empty to keep current)' : 'Password'}
                    </label>
                    <input
                      className="form-input"
                      type="password"
                      placeholder={editingCredId ? 'Enter new password...' : '••••••••'}
                      value={credPass}
                      onChange={e => setCredPass(e.target.value)}
                      required={!editingCredId}
                    />
                  </div>
                )}
              </div>

              {credType === 'ssh_key' && (
                <div className="form-group">
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                    <label className="form-label" style={{ margin: 0 }}>
                      {editingCredId ? 'Update SSH Private Key (PEM) (optional)' : 'SSH Private Key (PEM)'}
                    </label>
                    <label
                      htmlFor="pem-file-input"
                      title="Load key from file"
                      style={{
                        display: 'inline-flex', alignItems: 'center', gap: 5,
                        padding: '3px 10px', borderRadius: 6, cursor: 'pointer',
                        fontSize: 12, fontWeight: 500,
                        background: 'var(--primary-50, #ede9fe)',
                        color: 'var(--primary-600, #7c3aed)',
                        border: '1px solid var(--primary-200, #c4b5fd)',
                        transition: 'background 0.15s'
                      }}
                    >
                      <FolderOpen size={12} /> Browse file
                    </label>
                    <input
                      id="pem-file-input"
                      type="file"
                      accept=".pem,.key,.txt,text/plain"
                      style={{ display: 'none' }}
                      onChange={e => {
                        const file = e.target.files?.[0];
                        if (!file) return;
                        const reader = new FileReader();
                        reader.onload = ev => setCredKey(ev.target.result);
                        reader.readAsText(file);
                        e.target.value = '';
                      }}
                    />
                  </div>
                  <textarea
                    className="form-input"
                    rows={6}
                    placeholder={editingCredId ? 'Paste new private key to replace, or leave blank to keep current...' : '-----BEGIN RSA PRIVATE KEY-----\n...'}
                    value={credKey}
                    onChange={e => setCredKey(e.target.value)}
                    required={!editingCredId}
                    style={{ fontFamily: 'var(--font-mono)', fontSize: 12, resize: 'vertical' }}
                  />
                </div>
              )}

              {credErr && <div className="error-message"><AlertCircle size={14} /><span>{credErr}</span></div>}

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
                <button type="button" className="btn btn-secondary btn-sm" onClick={() => { setForm(null); setEditingCredId(null); }}>Cancel</button>
                <button type="submit" className="btn btn-primary btn-sm" disabled={credSub}>
                  {credSub ? <><RefreshCw size={13} className="spinner" /> Saving...</> : <><CheckCircle2 size={13} /> {editingCredId ? 'Update Credential' : 'Save Credential'}</>}
                </button>
              </div>
            </div>
          </form>
        </div>
      )}

      {/* ── Target Form (Create & Edit) ── */}
      {activeForm === 'target' && (
        <div className="card fade-in" style={{ borderLeft: '3px solid var(--emerald-500)' }}>
          <div className="card-header">
            <span className="card-title">
              <Shield size={14} style={{ color: 'var(--emerald-400)' }} />
              {editingTargetId ? 'Edit Assessment Target' : 'New Audit Target'}
            </span>
            <button className="btn btn-ghost btn-icon btn-sm" onClick={() => { setForm(null); setEditingTargetId(null); }}><X size={14} /></button>
          </div>
          <form onSubmit={handleSaveTarget}>
            <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div className="form-row form-row-2">
                <div className="form-group">
                  <label className="form-label"><Server size={12}/> Target Name</label>
                  <input className="form-input" placeholder="e.g. Production Web Cluster" value={name} onChange={e => setName(e.target.value)} required />
                </div>
                <div className="form-group">
                  <label className="form-label"><Wifi size={12}/> Hosts / IPs / CIDR</label>
                  <input className="form-input" placeholder="192.168.1.0/24, 10.0.0.5" value={hosts} onChange={e => setHosts(e.target.value)} required />
                </div>
              </div>

              <div className="form-row form-row-3">
                <div className="form-group">
                  <label className="form-label"><Terminal size={12}/> Attached SSH Credential (Linux)</label>
                  <select className="form-select" value={sshCredId} onChange={e => setSshCred(e.target.value)}>
                    <option value="">— None —</option>
                    {credentials.filter(c => c.type === 'ssh_password' || c.type === 'ssh_key' || c.type === 'username+password').map(c => (
                      <option key={c.id} value={c.id}>{c.name}</option>
                    ))}
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label"><Monitor size={12}/> Attached SMB/RDP Credential (Windows)</label>
                  <select className="form-select" value={smbCredId} onChange={e => setSmbCred(e.target.value)}>
                    <option value="">— None —</option>
                    {credentials.filter(c => c.type === 'smb' || c.type === 'rdp' || c.type === 'username+password').map(c => (
                      <option key={c.id} value={c.id}>{c.name}</option>
                    ))}
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label"><Globe size={12}/> Port Scan List</label>
                  <select className="form-select" value={portListId} onChange={e => setPortListId(e.target.value)}>
                    {portLists.map(p => (
                      <option key={p.id} value={p.id}>{p.name}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="form-group">
                <label className="form-label">Notes / Authorized Scope</label>
                <textarea className="form-input" rows={2} placeholder="e.g. Authorized by SOC team for Q3 assessment..." value={comment} onChange={e => setComment(e.target.value)} style={{ resize: 'vertical' }} />
              </div>

              {formErr && <div className="error-message"><AlertCircle size={14} /><span>{formErr}</span></div>}

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
                <button type="button" className="btn btn-secondary btn-sm" onClick={() => { setForm(null); setEditingTargetId(null); }}>Cancel</button>
                <button type="submit" className="btn btn-primary btn-sm" disabled={submitting}>
                  {submitting ? <><RefreshCw size={13} className="spinner" /> Saving...</> : <><Shield size={13} /> {editingTargetId ? 'Update Target' : 'Register Target'}</>}
                </button>
              </div>
            </div>
          </form>
        </div>
      )}

      {/* ── Search and Filter Header ── */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
        <div style={{ position: 'relative', width: 280 }}>
          <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none' }} />
          <input
            className="form-input"
            style={{ paddingLeft: 30, height: 34, fontSize: 13 }}
            placeholder={activeTab === 'groups' ? 'Search target groups...' : 'Search targets...'}
            value={searchTerm}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <button className="btn btn-ghost btn-icon btn-sm" onClick={fetchAll} disabled={loading} title="Refresh Data">
          <RefreshCw size={13} style={{ animation: loading ? 'spin 0.8s linear infinite' : 'none' }} />
        </button>
      </div>

      {/* ── TAB 1: Target Groups View ── */}
      {activeTab === 'groups' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          
          {/* Group Stat Bar */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '14px' }}>
            <div className="stat-card">
              <span className="stat-label">Target Groups</span>
              <div className="stat-value">{targetGroups.length}</div>
              <span className="stat-sub">Configured clusters</span>
            </div>
            <div className="stat-card">
              <span className="stat-label" style={{ color: 'var(--violet-400)' }}>Grouped Hosts</span>
              <div className="stat-value" style={{ color: 'var(--violet-400)' }}>{totalGroupedHosts}</div>
              <span className="stat-sub">Across all groups</span>
            </div>
            <div className="stat-card">
              <span className="stat-label" style={{ color: 'var(--emerald-500)' }}>Universal Selector</span>
              <div className="stat-value" style={{ color: 'var(--emerald-500)', fontSize: '18px' }}>Active</div>
              <span className="stat-sub">Available across all scanners</span>
            </div>
          </div>

          {/* Target Groups Grid */}
          {loading ? (
            <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 10 }}>
              {[...Array(3)].map((_, i) => <div key={i} className="skeleton" style={{ height: 40 }} />)}
            </div>
          ) : filteredGroups.length === 0 ? (
            <div className="card">
              <div className="empty-state" style={{ border: 'none', padding: '40px 20px' }}>
                <Users size={40} style={{ color: 'var(--text-muted)' }} />
                <h4>No target groups defined</h4>
                <p>Organize multiple server IPs and hostnames into Target Groups for streamlined multi-target auditing.</p>
                <button className="btn btn-primary btn-sm" onClick={openGroupCreate} style={{ marginTop: '12px' }}>
                  <Plus size={13} /> Create First Target Group
                </button>
              </div>
            </div>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: '16px' }}>
              {filteredGroups.map((g) => {
                const targetList = Array.isArray(g.targets) ? g.targets : (g.targets ? g.targets.split(',') : []);
                const color = g.color || '#8b5cf6';

                return (
                  <div
                    key={g.id}
                    className="card fade-in"
                    style={{
                      borderTop: `3px solid ${color}`,
                      display: 'flex',
                      flexDirection: 'column',
                      justifyContent: 'space-between',
                      position: 'relative'
                    }}
                  >
                    <div className="card-body" style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '8px' }}>
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <h4 style={{ margin: 0, fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
                              {g.name}
                            </h4>
                            <span
                              style={{
                                fontSize: '11px',
                                padding: '2px 8px',
                                borderRadius: '12px',
                                background: `${color}20`,
                                color: color,
                                fontWeight: 600
                              }}
                            >
                              {targetList.length} host{targetList.length !== 1 ? 's' : ''}
                            </span>
                          </div>
                          {g.description && (
                            <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: 'var(--text-muted)' }}>
                              {g.description}
                            </p>
                          )}
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <button
                            className="btn btn-ghost btn-icon btn-sm"
                            onClick={() => openGroupEdit(g)}
                            title="Edit Target Group"
                          >
                            <Edit2 size={13} />
                          </button>
                          <button
                            className="btn btn-ghost btn-icon btn-sm"
                            onClick={() => handleDeleteGroup(g.id)}
                            style={{ color: 'var(--critical)' }}
                            title="Delete Target Group"
                          >
                            <Trash2 size={13} />
                          </button>
                        </div>
                      </div>

                      {/* Member Targets Preview */}
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                        <span style={{ fontSize: '11px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.4px', color: 'var(--text-muted)' }}>
                          Group Targets
                        </span>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', maxHeight: '100px', overflowY: 'auto' }}>
                          {targetList.map((t, idx) => (
                            <span
                              key={idx}
                              onClick={() => copyToClipboard(t, `${g.id}-${idx}`)}
                              style={{
                                fontSize: '11px',
                                fontFamily: 'var(--font-mono)',
                                background: 'var(--bg-elevated)',
                                padding: '3px 8px',
                                borderRadius: '4px',
                                border: '1px solid var(--border-default)',
                                color: 'var(--text-primary)',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '4px',
                                cursor: 'pointer'
                              }}
                              title="Click to copy host"
                            >
                              {t}
                              {copiedHost === `${g.id}-${idx}` ? (
                                <Check size={10} style={{ color: 'var(--emerald-500)' }} />
                              ) : (
                                <Copy size={10} style={{ color: 'var(--text-muted)' }} />
                              )}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

        </div>
      )}

      {/* ── TAB 2: OpenVAS Inventory & Credentials ── */}
      {activeTab === 'inventory' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Targets Table */}
          <div className="card">
            <div className="card-header">
              <span className="card-title"><Wifi size={14} style={{ color: 'var(--violet-300)' }} /> Registered Targets
                <span style={{ marginLeft: 8, fontWeight: 400, color: 'var(--text-muted)', fontSize: 12 }}>
                  {filteredTargets.length} host{filteredTargets.length !== 1 ? 's' : ''}
                </span>
              </span>
            </div>
            {/* Bulk Action Toolbar */}
            {selectedTargetIds.length > 0 && (
              <div
                style={{
                  background: 'var(--violet-dim, rgba(139, 92, 246, 0.12))',
                  borderTop: '1px solid var(--violet-500, #8b5cf6)',
                  borderBottom: '1px solid var(--violet-500, #8b5cf6)',
                  padding: '10px 16px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: '12px'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span
                    style={{
                      background: 'var(--violet-500, #8b5cf6)',
                      color: '#fff',
                      borderRadius: '12px',
                      padding: '2px 8px',
                      fontSize: '11px',
                      fontWeight: 700
                    }}
                  >
                    {selectedTargetIds.length} Selected
                  </span>
                  <span style={{ fontSize: '13px', color: 'var(--text-primary)', fontWeight: 500 }}>
                    Select bulk action for chosen targets:
                  </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    className="btn btn-primary btn-sm"
                    onClick={handleCreateGroupFromSelected}
                    style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px' }}
                  >
                    <Plus size={13} />
                    <span>Create Group from Selected</span>
                  </button>

                  {targetGroups.length > 0 && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <select
                        className="form-select"
                        value={bulkGroupId}
                        onChange={e => setBulkGroupId(e.target.value)}
                        style={{ height: '30px', fontSize: '12px', padding: '2px 8px' }}
                      >
                        <option value="">— Add to Existing Group —</option>
                        {targetGroups.map(g => (
                          <option key={g.id} value={g.id}>{g.name}</option>
                        ))}
                      </select>
                      <button
                        type="button"
                        className="btn btn-secondary btn-sm"
                        disabled={!bulkGroupId}
                        onClick={() => handleAddSelectedToExistingGroup(bulkGroupId)}
                        style={{ fontSize: '12px', height: '30px' }}
                      >
                        Apply
                      </button>
                    </div>
                  )}

                  <button
                    type="button"
                    className="btn btn-ghost btn-sm"
                    onClick={() => setSelectedTargetIds([])}
                    style={{ fontSize: '12px', color: 'var(--text-muted)' }}
                  >
                    Clear
                  </button>
                </div>
              </div>
            )}

            {loading ? (
              <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 10 }}>
                {[...Array(3)].map((_, i) => <div key={i} className="skeleton" style={{ height: 20 }} />)}
              </div>
            ) : error ? (
              <div className="card-body">
                <div className="error-message"><AlertCircle size={14} /><span>{error}</span></div>
              </div>
            ) : filteredTargets.length === 0 ? (
              <div className="empty-state" style={{ border: 'none' }}>
                <Shield size={36} />
                <h4>No targets registered</h4>
                <p>Click <strong>New Target</strong> above to add your first assessment target.</p>
              </div>
            ) : (
              <div className="table-wrap" style={{ borderRadius: 0, border: 'none', borderTop: '1px solid var(--border-default)' }}>
                <table>
                  <thead>
                    <tr>
                      <th style={{ width: 36, textAlign: 'center' }}>
                        <input
                          type="checkbox"
                          checked={selectedTargetIds.length === filteredTargets.length && filteredTargets.length > 0}
                          onChange={() => handleSelectAllInventory(filteredTargets)}
                          style={{ cursor: 'pointer' }}
                          title="Select all targets"
                        />
                      </th>
                      <th>Name</th>
                      <th>Hosts / Scope</th>
                      <th>Target Groups</th>
                      <th>Port Scan List</th>
                      <th>SSH Credential</th>
                      <th>SMB Credential</th>
                      <th>Notes</th>
                      <th style={{ width: 80, textAlign: 'center' }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredTargets.map(t => {
                      const isSelected = selectedTargetIds.includes(t.id);
                      
                      // Check which target groups include this target
                      const memberGroups = targetGroups.filter(g => {
                        const gList = (Array.isArray(g.targets) ? g.targets : (g.targets ? g.targets.split(',') : [])).map(h => h.trim().toLowerCase());
                        const tHosts = (t.hosts || t.name || '').split(/[\n,]+/).map(h => h.trim().toLowerCase());
                        return tHosts.some(th => gList.includes(th));
                      });

                      return (
                        <tr key={t.id} style={{ background: isSelected ? 'var(--violet-dim, rgba(139, 92, 246, 0.06))' : 'transparent' }}>
                          <td style={{ textAlign: 'center' }}>
                            <input
                              type="checkbox"
                              checked={isSelected}
                              onChange={() => handleToggleSelectTarget(t.id)}
                              style={{ cursor: 'pointer' }}
                            />
                          </td>
                          <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{t.name}</td>
                          <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--violet-300)' }}>{t.hosts}</td>
                          <td>
                            {memberGroups.length > 0 ? (
                              <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                                {memberGroups.map(g => (
                                  <span
                                    key={g.id}
                                    style={{
                                      fontSize: '10px',
                                      padding: '2px 6px',
                                      borderRadius: '4px',
                                      background: `${g.color || '#8b5cf6'}20`,
                                      color: g.color || '#8b5cf6',
                                      border: `1px solid ${g.color || '#8b5cf6'}40`,
                                      fontWeight: 600
                                    }}
                                  >
                                    {g.name}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>
                            )}
                          </td>
                          <td>
                            {t.port_list_name ? (
                              <span className="badge badge-secondary" style={{ fontSize: 11 }}>
                                {t.port_list_name}
                              </span>
                            ) : (
                              <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
                            )}
                          </td>
                          <td>
                            {t.ssh_credential_name
                              ? <span className="badge badge-success">{t.ssh_credential_name}</span>
                              : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>}
                          </td>
                          <td>
                            {t.smb_credential_name
                              ? <span className="badge badge-info">{t.smb_credential_name}</span>
                              : <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>}
                          </td>
                          <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>{t.comment || '—'}</td>
                          <td style={{ textAlign: 'center' }}>
                            <div style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                              <button
                                className="btn btn-ghost btn-icon btn-sm"
                                onClick={() => openTargetEdit(t)}
                                style={{ color: 'var(--text-secondary)' }}
                                title="Edit target & attached credentials"
                              >
                                <Edit2 size={13} />
                              </button>
                              <button
                                className="btn btn-ghost btn-icon btn-sm"
                                onClick={() => handleDeleteTarget(t.id)}
                                style={{ color: 'var(--critical)' }}
                                title="Delete target"
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

          {/* Credentials Table */}
          <div className="card">
            <div className="card-header">
              <span className="card-title"><Key size={14} style={{ color: 'var(--violet-300)' }} /> Saved Credentials
                <span style={{ marginLeft: 8, fontWeight: 400, color: 'var(--text-muted)', fontSize: 12 }}>
                  {credentials.length} stored
                </span>
              </span>
            </div>

            {credentials.length === 0 ? (
              <div className="empty-state" style={{ border: 'none' }}>
                <Key size={36} />
                <h4>No credentials saved</h4>
                <p>Click <strong>Add Credential</strong> to create SSH, SMB, or RDP authentication sets.</p>
              </div>
            ) : (
              <div className="table-wrap" style={{ borderRadius: 0, border: 'none', borderTop: '1px solid var(--border-default)' }}>
                <table>
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Type</th>
                      <th>Username</th>
                      <th style={{ width: 80, textAlign: 'center' }}>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {credentials.map(c => (
                      <tr key={c.id}>
                        <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{c.name}</td>
                        <td><CredTypeBadge type={c.type} /></td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{c.username}</td>
                        <td style={{ textAlign: 'center' }}>
                          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                            <button
                              className="btn btn-ghost btn-icon btn-sm"
                              onClick={() => openCredEdit(c)}
                              style={{ color: 'var(--text-secondary)' }}
                              title="Edit credential & password"
                            >
                              <Edit2 size={13} />
                            </button>
                            <button
                              className="btn btn-ghost btn-icon btn-sm"
                              onClick={() => handleDeleteCred(c.id)}
                              style={{ color: 'var(--critical)' }}
                              title="Delete credential"
                            >
                              <Trash2 size={13} />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

    </div>
  );
}
