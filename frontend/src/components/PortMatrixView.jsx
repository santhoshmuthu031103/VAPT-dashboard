import React, { useState } from 'react';
import {
  Shield, AlertTriangle, CheckCircle, Database, Globe,
  Terminal, Server, Lock, Unlock, Filter, Layers, Info, LayoutGrid, Table
} from 'lucide-react';

/**
 * Categorizes and evaluates security risk of an open port.
 */
export function evaluatePortRisk(portNum, service = '', state = 'open') {
  const p = parseInt(portNum, 10);
  const s = (service || '').toLowerCase();

  // Database ports (High/Critical risk if exposed publicly)
  if ([3306, 5432, 27017, 1433, 1521, 6379, 9200, 9300].includes(p) || s.includes('mysql') || s.includes('postgres') || s.includes('mongo') || s.includes('redis')) {
    return {
      category: 'Database',
      risk: 'Critical',
      badgeClass: 'badge-critical',
      icon: Database,
      color: 'var(--critical)',
      summary: 'Direct Database Exposure',
      recommendation: 'Ensure database is bound to localhost (127.0.0.1) or protected behind a VPN/Firewall. Do not expose directly to public networks.'
    };
  }

  // Windows / SMB / NetBIOS (High Risk)
  if ([445, 139, 135, 137, 138].includes(p) || s.includes('smb') || s.includes('netbios') || s.includes('microsoft-ds')) {
    return {
      category: 'File Sharing',
      risk: 'Critical',
      badgeClass: 'badge-critical',
      icon: Server,
      color: 'var(--critical)',
      summary: 'SMB / NetBIOS Protocol Exposed',
      recommendation: 'Block ports 139/445 at firewall boundary to prevent lateral movement, WannaCry/EternalBlue-style exploits, and anonymous enumeration.'
    };
  }

  // Cleartext / Insecure Protocols
  if ([21, 23, 80, 110, 143, 8080].includes(p) || s.includes('telnet') || s.includes('ftp') || s.includes('http')) {
    if (p === 80 || p === 8080) {
      return {
        category: 'Web (Unencrypted)',
        risk: 'Medium',
        badgeClass: 'badge-medium',
        icon: Unlock,
        color: 'var(--medium)',
        summary: 'Plaintext HTTP Traffic',
        recommendation: 'Configure automatic 301 redirection from HTTP (port 80) to HTTPS (port 443) with HSTS headers.'
      };
    }
    return {
      category: 'Legacy Protocol',
      risk: 'High',
      badgeClass: 'badge-high',
      icon: Unlock,
      color: 'var(--high)',
      summary: `Insecure Cleartext Protocol (${s.toUpperCase() || 'FTP/Telnet'})`,
      recommendation: 'Decommission unencrypted legacy protocols. Replace FTP with SFTP (Port 22) and Telnet with SSH.'
    };
  }

  // Remote Administration (SSH, RDP, VNC)
  if ([22, 3389, 5900, 5901, 2222].includes(p) || s.includes('ssh') || s.includes('rdp') || s.includes('vnc')) {
    return {
      category: 'Remote Access',
      risk: p === 22 ? 'Low' : 'Medium',
      badgeClass: p === 22 ? 'badge-info' : 'badge-medium',
      icon: Terminal,
      color: p === 22 ? 'var(--info)' : 'var(--medium)',
      summary: `${s.toUpperCase() || 'SSH/RDP'} Administrative Port`,
      recommendation: 'Enforce MFA / Public Key authentication, disable password auth for root, and consider IP allowlisting or rate-limiting (Fail2Ban).'
    };
  }

  // Encrypted Web Services (HTTPS)
  if ([443, 8443, 9443].includes(p) || s.includes('https') || s.includes('ssl')) {
    return {
      category: 'Web (Encrypted)',
      risk: 'Secure',
      badgeClass: 'badge-success',
      icon: Lock,
      color: 'var(--emerald-500)',
      summary: 'Encrypted HTTPS Service',
      recommendation: 'Ensure modern TLS 1.2/1.3 ciphers are active and obsolete TLS 1.0/1.1 protocols are disabled.'
    };
  }

  // DNS / NTP / Mail / Other standard
  if ([53, 123, 25, 587, 465].includes(p) || s.includes('domain') || s.includes('smtp') || s.includes('dns')) {
    return {
      category: 'Infrastructure',
      risk: 'Low',
      badgeClass: 'badge-info',
      icon: Globe,
      color: 'var(--info)',
      summary: `${s.toUpperCase()} Infrastructure Service`,
      recommendation: 'Keep service daemon patched to latest upstream release and ensure open relay / recursive queries are disabled.'
    };
  }

  // Default / Other
  return {
    category: 'Application Service',
    risk: 'Informational',
    badgeClass: 'badge-info',
    icon: Server,
    color: 'var(--text-secondary)',
    summary: `Active Port ${p} (${s || 'TCP'})`,
    recommendation: 'Verify business requirement for this exposed port. If not required, close or restrict in firewall.'
  };
}

export default function PortMatrixView({ results = [], host = '' }) {
  const [activeFilter, setActiveFilter] = useState('all');
  const [viewMode, setViewMode] = useState('matrix'); // 'matrix' or 'table'
  const [selectedHostFilter, setSelectedHostFilter] = useState('all');

  if (!results || results.length === 0) {
    return null;
  }

  // Parse all port findings with risk data
  const evaluatedPorts = results.map(item => {
    const portNum = item.port || item.port_number || 0;
    const serviceName = item.service || item.service_name || 'unknown';
    const state = item.state || 'open';
    const version = item.version || item.product || '';
    const hostName = item.host || host;
    const riskData = evaluatePortRisk(portNum, serviceName, state);

    return {
      host: hostName,
      port: portNum,
      protocol: item.protocol || 'tcp',
      state,
      service: serviceName,
      version: version || 'Version not identified',
      ...riskData
    };
  });

  // Check unique hosts
  const uniqueHosts = Array.from(new Set(evaluatedPorts.map(p => p.host).filter(Boolean)));
  const hasMultipleHosts = uniqueHosts.length > 1;

  // Calculate Metrics
  const totalCount = evaluatedPorts.length;
  const criticalCount = evaluatedPorts.filter(p => p.risk === 'Critical').length;
  const highCount = evaluatedPorts.filter(p => p.risk === 'High').length;
  const mediumCount = evaluatedPorts.filter(p => p.risk === 'Medium').length;
  const secureCount = evaluatedPorts.filter(p => p.risk === 'Secure' || p.risk === 'Low').length;

  // Filtered List
  const filteredPorts = evaluatedPorts.filter(p => {
    if (selectedHostFilter !== 'all' && p.host !== selectedHostFilter) return false;
    if (activeFilter === 'all') return true;
    if (activeFilter === 'critical') return p.risk === 'Critical' || p.risk === 'High';
    if (activeFilter === 'database') return p.category === 'Database';
    if (activeFilter === 'web') return p.category.includes('Web');
    if (activeFilter === 'remote') return p.category === 'Remote Access';
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', width: '100%' }}>
      
      {/* KPI Exposure Summary Banner */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '12px' }}>
        <div style={{ background: 'var(--card-bg)', border: '1px solid var(--card-border)', borderRadius: '8px', padding: '12px 16px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Exposed Ports</span>
          <div style={{ fontSize: '24px', fontWeight: 800, color: 'var(--text-primary)', marginTop: '2px' }}>{totalCount}</div>
        </div>
        <div style={{ background: 'var(--card-bg)', border: '1px solid var(--card-border)', borderRadius: '8px', padding: '12px 16px' }}>
          <span style={{ fontSize: '11px', color: 'var(--critical)', fontWeight: 600, textTransform: 'uppercase' }}>High / Critical Risk</span>
          <div style={{ fontSize: '24px', fontWeight: 800, color: 'var(--critical)', marginTop: '2px' }}>{criticalCount + highCount}</div>
        </div>
        <div style={{ background: 'var(--card-bg)', border: '1px solid var(--card-border)', borderRadius: '8px', padding: '12px 16px' }}>
          <span style={{ fontSize: '11px', color: 'var(--medium)', fontWeight: 600, textTransform: 'uppercase' }}>Medium Risk</span>
          <div style={{ fontSize: '24px', fontWeight: 800, color: 'var(--medium)', marginTop: '2px' }}>{mediumCount}</div>
        </div>
        <div style={{ background: 'var(--card-bg)', border: '1px solid var(--card-border)', borderRadius: '8px', padding: '12px 16px' }}>
          <span style={{ fontSize: '11px', color: 'var(--emerald-500)', fontWeight: 600, textTransform: 'uppercase' }}>Encrypted / Secure</span>
          <div style={{ fontSize: '24px', fontWeight: 800, color: 'var(--emerald-500)', marginTop: '2px' }}>{secureCount}</div>
        </div>
      </div>

      {/* Header with Filters & View Mode Toggle */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        
        {/* Category Filters */}
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', alignItems: 'center' }}>
          {hasMultipleHosts && (
            <select
              className="form-select"
              value={selectedHostFilter}
              onChange={(e) => setSelectedHostFilter(e.target.value)}
              style={{ padding: '4px 8px', fontSize: '12px', height: '30px', marginRight: '6px' }}
            >
              <option value="all">All Group Hosts ({uniqueHosts.length})</option>
              {uniqueHosts.map(h => (
                <option key={h} value={h}>{h}</option>
              ))}
            </select>
          )}

          <button
            className={`btn btn-sm ${activeFilter === 'all' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveFilter('all')}
          >
            All Ports ({totalCount})
          </button>
          {(criticalCount + highCount) > 0 && (
            <button
              className={`btn btn-sm ${activeFilter === 'critical' ? 'btn-danger' : 'btn-secondary'}`}
              onClick={() => setActiveFilter('critical')}
              style={{ color: activeFilter === 'critical' ? '#fff' : 'var(--critical)' }}
            >
              <AlertTriangle size={12} /> High Risks ({criticalCount + highCount})
            </button>
          )}
          <button
            className={`btn btn-sm ${activeFilter === 'web' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveFilter('web')}
          >
            Web Services
          </button>
          <button
            className={`btn btn-sm ${activeFilter === 'database' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveFilter('database')}
          >
            Databases
          </button>
          <button
            className={`btn btn-sm ${activeFilter === 'remote' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveFilter('remote')}
          >
            Remote Access
          </button>
        </div>

        {/* View Toggle */}
        <div style={{ display: 'flex', gap: '4px', background: 'var(--bg-elevated)', padding: '2px', borderRadius: '6px' }}>
          <button
            className={`btn btn-sm ${viewMode === 'matrix' ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setViewMode('matrix')}
            title="Visual Matrix View"
            style={{ padding: '4px 8px' }}
          >
            <LayoutGrid size={13} />
            <span>Matrix</span>
          </button>
          <button
            className={`btn btn-sm ${viewMode === 'table' ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setViewMode('table')}
            title="Raw Table View"
            style={{ padding: '4px 8px' }}
          >
            <Table size={13} />
            <span>Table</span>
          </button>
        </div>
      </div>

      {/* Visual Port Matrix Grid */}
      {viewMode === 'matrix' ? (
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
          gap: '14px'
        }}>
          {filteredPorts.map((p, idx) => {
            const IconComp = p.icon;
            return (
              <div
                key={idx}
                className="card"
                style={{
                  padding: '16px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '10px',
                  borderLeft: `4px solid ${p.color}`,
                  background: 'var(--card-bg)'
                }}
              >
                {/* Top Row: Port Number, Host Badge & Risk Badge */}
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <div style={{
                      width: '32px',
                      height: '32px',
                      borderRadius: '6px',
                      background: 'var(--bg-elevated)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      color: p.color
                    }}>
                      <IconComp size={16} />
                    </div>
                    <div>
                      <div style={{ fontSize: '16px', fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                        {p.port} <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 500 }}>/{p.protocol}</span>
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
                        {p.service}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '4px' }}>
                    <span className={`badge ${p.badgeClass}`} style={{ fontSize: '10px' }}>
                      {p.risk}
                    </span>
                    {hasMultipleHosts && (
                      <span style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--violet-600)', background: 'var(--violet-dim)', padding: '1px 6px', borderRadius: '4px' }}>
                        {p.host}
                      </span>
                    )}
                  </div>
                </div>

                {/* Service Version */}
                <div style={{
                  fontSize: '12px',
                  color: 'var(--text-secondary)',
                  background: 'var(--bg-base)',
                  padding: '6px 10px',
                  borderRadius: '4px',
                  fontFamily: 'var(--font-mono)'
                }}>
                  {p.version}
                </div>

                {/* Security Impact & Recommendation */}
                <div style={{
                  fontSize: '11px',
                  color: 'var(--text-secondary)',
                  lineHeight: '1.4',
                  borderTop: '1px solid var(--border-subtle)',
                  paddingTop: '8px'
                }}>
                  <strong style={{ color: 'var(--text-primary)', display: 'block', marginBottom: '2px' }}>
                    {p.summary}
                  </strong>
                  <span>{p.recommendation}</span>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        /* Raw Data Table */
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                {hasMultipleHosts && <th>Target Host</th>}
                <th>Port / Proto</th>
                <th>Service Name</th>
                <th>State</th>
                <th>Category</th>
                <th>Risk Level</th>
                <th>Version Details</th>
              </tr>
            </thead>
            <tbody>
              {filteredPorts.map((p, idx) => (
                <tr key={idx}>
                  {hasMultipleHosts && (
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--violet-600)', fontWeight: 600 }}>
                      {p.host}
                    </td>
                  )}
                  <td style={{ fontWeight: 800, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                    {p.port}/{p.protocol}
                  </td>
                  <td style={{ color: 'var(--violet-400)', fontWeight: 600 }}>{p.service}</td>
                  <td>
                    <span className="badge badge-success">{p.state}</span>
                  </td>
                  <td>{p.category}</td>
                  <td>
                    <span className={`badge ${p.badgeClass}`}>{p.risk}</span>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>{p.version}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

    </div>
  );
}
