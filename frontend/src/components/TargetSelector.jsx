import React, { useState, useEffect, useRef } from 'react';
import { Target, Users, Server, ChevronDown, Check, X, Globe, Layers } from 'lucide-react';

export default function TargetSelector({
  value = '',
  onChange,
  placeholder = 'Select target or enter IP/host...',
  apiBase = '',
  allowGroups = true,
  disabled = false,
  required = false,
  className = '',
  style = {}
}) {
  const [isOpen, setIsOpen] = useState(false);
  const [targetGroups, setTargetGroups] = useState([]);
  const [registeredTargets, setRegisteredTargets] = useState([]);
  const [loading, setLoading] = useState(false);
  const dropdownRef = useRef(null);

  useEffect(() => {
    let isMounted = true;
    const fetchTargetsAndGroups = async () => {
      try {
        setLoading(true);
        const [gRes, tRes] = await Promise.allSettled([
          allowGroups ? fetch(`${apiBase}/api/target-groups`) : Promise.resolve(null),
          fetch(`${apiBase}/api/targets`)
        ]);

        if (!isMounted) return;

        if (gRes.status === 'fulfilled' && gRes.value && gRes.value.ok) {
          const gData = await gRes.value.json();
          setTargetGroups(Array.isArray(gData) ? gData : []);
        }
        if (tRes.status === 'fulfilled' && tRes.value && tRes.value.ok) {
          const tData = await tRes.value.json();
          setRegisteredTargets(Array.isArray(tData) ? tData : []);
        }
      } catch (err) {
        console.error('TargetSelector fetch error:', err);
      } finally {
        if (isMounted) setLoading(false);
      }
    };

    fetchTargetsAndGroups();
    return () => { isMounted = false; };
  }, [apiBase, allowGroups]);

  // Handle click outside
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setIsOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleSelectGroup = (group) => {
    const targetsStr = Array.isArray(group.targets) ? group.targets.join(', ') : group.targets;
    if (onChange) {
      onChange(targetsStr, { isGroup: true, groupName: group.name, groupObj: group });
    }
    setIsOpen(false);
  };

  const handleSelectRegistered = (tgt) => {
    const hostStr = tgt.hosts || tgt.name;
    if (onChange) {
      onChange(hostStr, { isGroup: false, targetName: tgt.name, targetObj: tgt });
    }
    setIsOpen(false);
  };

  const handleInputChange = (e) => {
    if (onChange) {
      onChange(e.target.value, { isGroup: false });
    }
  };

  const handleClear = () => {
    if (onChange) {
      onChange('', { isGroup: false });
    }
  };

  // Check if current value matches any group
  const matchedGroup = targetGroups.find(g => {
    const targetsStr = Array.isArray(g.targets) ? g.targets.join(', ') : g.targets;
    return targetsStr === value || g.name === value;
  });

  return (
    <div ref={dropdownRef} style={{ position: 'relative', width: '100%', zIndex: isOpen ? 999999 : 1, ...style }}>
      <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
        <input
          type="text"
          className={`form-input ${className}`}
          placeholder={placeholder}
          value={value}
          onChange={handleInputChange}
          onClick={() => setIsOpen(true)}
          disabled={disabled}
          required={required}
          style={{
            paddingRight: '64px',
            width: '100%',
            fontFamily: value && !matchedGroup ? 'var(--font-mono)' : 'inherit',
            fontSize: '13px'
          }}
        />

        {/* Action icons & badge inside input */}
        <div style={{ position: 'absolute', right: '8px', display: 'flex', alignItems: 'center', gap: '4px' }}>
          {matchedGroup && (
            <span
              style={{
                fontSize: '10px',
                padding: '2px 6px',
                borderRadius: '4px',
                background: 'var(--violet-dim)',
                color: 'var(--violet-500)',
                border: '1px solid rgba(109, 40, 217, 0.2)',
                fontWeight: 600,
                textTransform: 'uppercase',
                pointerEvents: 'none'
              }}
            >
              Group
            </span>
          )}

          {value && (
            <button
              type="button"
              onClick={handleClear}
              className="btn-ghost"
              style={{
                padding: '3px',
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                border: 'none',
                background: 'transparent'
              }}
              title="Clear selection"
            >
              <X size={13} />
            </button>
          )}

          <button
            type="button"
            onClick={() => setIsOpen(prev => !prev)}
            className="btn-ghost"
            style={{
              padding: '4px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
              border: 'none',
              background: 'transparent',
              transform: isOpen ? 'rotate(180deg)' : 'none',
              transition: 'transform 0.2s'
            }}
            title="Choose target or group"
          >
            <ChevronDown size={14} />
          </button>
        </div>
      </div>

      {/* Clean, Normal Dropdown Menu matching Application Theme */}
      {isOpen && (
        <div
          style={{
            position: 'absolute',
            top: 'calc(100% + 4px)',
            left: 0,
            right: 0,
            zIndex: 999999,
            background: 'var(--bg-surface, #ffffff)',
            border: '1px solid var(--border-default, #e2e8f0)',
            borderRadius: '8px',
            boxShadow: '0 12px 28px -4px rgba(0, 0, 0, 0.18), 0 6px 14px -2px rgba(0, 0, 0, 0.08)',
            maxHeight: '260px',
            overflowY: 'auto',
            padding: '6px'
          }}
        >
          {loading && (
            <div style={{ padding: '12px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>
              Loading targets & groups...
            </div>
          )}

          {/* Section: Target Groups */}
          {allowGroups && targetGroups.length > 0 && (
            <div style={{ marginBottom: '6px' }}>
              <div
                style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px',
                  color: 'var(--violet-600, #7c3aed)',
                  padding: '6px 10px 4px 10px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px'
                }}
              >
                <Users size={12} />
                <span>Target Groups ({targetGroups.length})</span>
              </div>

              {targetGroups.map((g) => {
                const targetList = Array.isArray(g.targets) ? g.targets : (g.targets ? g.targets.split(',') : []);
                const targetsStr = targetList.join(', ');
                const isSelected = value === targetsStr || value === g.name;

                return (
                  <div
                    key={`group-${g.id}`}
                    onClick={() => handleSelectGroup(g)}
                    style={{
                      padding: '8px 10px',
                      borderRadius: '6px',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      background: isSelected ? 'var(--violet-dim, #f5f3ff)' : 'transparent',
                      transition: 'background 0.15s ease',
                      marginBottom: '2px',
                      color: 'var(--text-primary, #0f172a)'
                    }}
                    onMouseEnter={(e) => { e.currentTarget.style.background = isSelected ? 'var(--violet-dim, #f5f3ff)' : 'var(--bg-base, #f8fafc)'; }}
                    onMouseLeave={(e) => { e.currentTarget.style.background = isSelected ? 'var(--violet-dim, #f5f3ff)' : 'transparent'; }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
                      <span
                        style={{
                          width: '10px',
                          height: '10px',
                          borderRadius: '50%',
                          background: g.color || '#8b5cf6',
                          flexShrink: 0
                        }}
                      />
                      <div style={{ minWidth: 0 }}>
                        <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary, #0f172a)' }}>
                          {g.name}
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--text-secondary, #64748b)', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                          {targetList.length} server{targetList.length !== 1 ? 's' : ''}: {targetsStr.slice(0, 45)}{targetsStr.length > 45 ? '...' : ''}
                        </div>
                      </div>
                    </div>
                    {isSelected && <Check size={14} style={{ color: 'var(--emerald-500, #10b981)', flexShrink: 0 }} />}
                  </div>
                );
              })}
            </div>
          )}

          {/* Section: Saved Targets */}
          {registeredTargets.length > 0 && (
            <div>
              <div
                style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px',
                  color: 'var(--emerald-600, #059669)',
                  padding: '6px 10px 4px 10px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  borderTop: allowGroups && targetGroups.length > 0 ? '1px solid var(--border-default, #e2e8f0)' : 'none',
                  paddingTop: allowGroups && targetGroups.length > 0 ? '8px' : '4px'
                }}
              >
                <Server size={12} />
                <span>Saved Targets ({registeredTargets.length})</span>
              </div>

              {registeredTargets.map((t) => {
                const hostStr = t.hosts || t.name;
                const isSelected = value === hostStr;

                return (
                  <div
                    key={`target-${t.id}`}
                    onClick={() => handleSelectRegistered(t)}
                    style={{
                      padding: '8px 10px',
                      borderRadius: '6px',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      background: isSelected ? 'var(--emerald-dim, #ecfdf5)' : 'transparent',
                      transition: 'background 0.15s ease',
                      marginBottom: '2px',
                      color: 'var(--text-primary, #0f172a)'
                    }}
                    onMouseEnter={(e) => { e.currentTarget.style.background = isSelected ? 'var(--emerald-dim, #ecfdf5)' : 'var(--bg-base, #f8fafc)'; }}
                    onMouseLeave={(e) => { e.currentTarget.style.background = isSelected ? 'var(--emerald-dim, #ecfdf5)' : 'transparent'; }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
                      <Globe size={13} style={{ color: 'var(--text-secondary, #64748b)', flexShrink: 0 }} />
                      <div style={{ minWidth: 0 }}>
                        <div style={{ fontSize: '13px', fontWeight: 500, color: 'var(--text-primary, #0f172a)' }}>
                          {t.name}
                        </div>
                        <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary, #64748b)' }}>
                          {hostStr}
                        </div>
                      </div>
                    </div>
                    {isSelected && <Check size={14} style={{ color: 'var(--emerald-500, #10b981)', flexShrink: 0 }} />}
                  </div>
                );
              })}
            </div>
          )}

          {targetGroups.length === 0 && registeredTargets.length === 0 && !loading && (
            <div style={{ padding: '12px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>
              No saved targets or groups found. Type an IP/host directly.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
