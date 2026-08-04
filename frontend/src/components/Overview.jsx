import React, { useState, useEffect, useRef } from 'react';
import { Shield, ShieldAlert, ShieldX, CheckCircle2, Activity, Users, AlertCircle, RefreshCw, Terminal, ArrowUpRight } from 'lucide-react';

export default function Overview({ apiBase, onTabChange, onSelectReport }) {
  const [tasks, setTasks] = useState([]);
  const [targets, setTargets] = useState([]);
  // Keep status in a ref so switching tabs does NOT reset it to null (fixes flicker)
  const [status, setStatus] = useState(() => {
    try { return JSON.parse(sessionStorage.getItem('vapt_status') || 'null'); } catch { return null; }
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Aggregated vulnerabilities from completed reports
  const [vulnerabilityAggregate, setVulnerabilityAggregate] = useState({
    high: 0,
    medium: 0,
    low: 0,
    log: 0,
    total: 0
  });
  const [recentFindings, setRecentFindings] = useState([]);
  const [loadingVulnerabilities, setLoadingVulnerabilities] = useState(false);

  const fetchDashboardData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [tasksRes, targetsRes, statusRes] = await Promise.all([
        fetch(`${apiBase}/api/tasks`),
        fetch(`${apiBase}/api/targets`),
        fetch(`${apiBase}/api/status`)
      ]);

      if (!tasksRes.ok || !targetsRes.ok || !statusRes.ok) {
        throw new Error('Failed to synchronize dashboard telemetry.');
      }

      const tasksData = await tasksRes.json();
      const targetsData = await targetsRes.json();
      const statusData = await statusRes.json();

      setTasks(tasksData.tasks || []);
      setTargets(targetsData);
      setStatus(statusData);
      // Persist status so tab-switch doesn't flash 'Offline'
      try { sessionStorage.setItem('vapt_status', JSON.stringify(statusData)); } catch {}

      // Now aggregate report metrics from completed tasks
      const completedTasks = (tasksData.tasks || []).filter(t => t.status?.toLowerCase() === 'done' && t.report_id);
      if (completedTasks.length > 0) {
        aggregateVulnerabilities(completedTasks);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const aggregateVulnerabilities = async (completedTasks) => {
    setLoadingVulnerabilities(true);
    let high = 0, medium = 0, low = 0, log = 0, total = 0;
    const allFindings = [];

    try {
      // Limit to fetching reports for the 5 most recent completed tasks to avoid overload
      const tasksToFetch = completedTasks.slice(0, 5);
      const reportPromises = tasksToFetch.map(t => 
        fetch(`${apiBase}/api/reports/${t.report_id}`).then(res => res.ok ? res.json() : null)
      );

      const reports = await Promise.all(reportPromises);
      reports.forEach((rep, index) => {
        if (!rep) return;
        const taskName = tasksToFetch[index].name;
        const reportId = tasksToFetch[index].report_id;
        
        // Sum counts
        high += rep.summary.high || 0;
        medium += rep.summary.medium || 0;
        low += rep.summary.low || 0;
        log += rep.summary.log || 0;
        total += rep.summary.total || 0;

        // Compile findings for recent findings table
        if (rep.vulnerabilities) {
          rep.vulnerabilities.forEach(v => {
            allFindings.push({
              ...v,
              taskName,
              reportId
            });
          });
        }
      });

      setVulnerabilityAggregate({ high, medium, low, log, total });
      
      // Sort findings by severity and CVSS (highest first)
      const sortedFindings = allFindings.sort((a, b) => b.cvss - a.cvss);
      setRecentFindings(sortedFindings.slice(0, 5)); // Keep top 5 threats
    } catch (err) {
      console.error("Error aggregating vulnerabilities: ", err);
    } finally {
      setLoadingVulnerabilities(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const activeScansCount = tasks.filter(t => t.status?.toLowerCase() === 'running').length;
  const readyTasksCount = tasks.filter(t => t.status?.toLowerCase() === 'new').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.8rem', marginBottom: '0.5rem' }}>Shield Security Command</h2>
          <p>Real-time security auditing dashboard. Monitor open vulnerabilities, targets, and scan operations.</p>
        </div>
        <button className="btn btn-secondary" onClick={fetchDashboardData} disabled={loading}>
          <RefreshCw size={16} className={loading ? 'animate-spin-slow' : ''} /> Sync Telemetry
        </button>
      </div>

      {error && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '2.5rem', border: '1px solid var(--severity-high)', borderRadius: '8px', backgroundColor: 'var(--severity-high-dim)' }}>
          <AlertCircle size={28} style={{ color: 'var(--severity-high)' }} />
          <div>
            <h4 style={{ color: 'var(--severity-high)', fontSize: '1.1rem' }}>Telemetry Sync Failed</h4>
            <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>{error}</p>
          </div>
        </div>
      )}

      {/* Main KPI Counters */}
      <div className="grid-dashboard">
        <div className="panel" style={{ display: 'flex', gap: '1.25rem', alignItems: 'center' }}>
          <div style={{ padding: '0.75rem', borderRadius: '8px', backgroundColor: 'var(--accent-cyan-dim)' }}>
            <Activity size={28} style={{ color: 'var(--accent-cyan)' }} />
          </div>
          <div>
            <span className="text-secondary" style={{ fontSize: '0.85rem', textTransform: 'uppercase', fontWeight: 600 }}>Active Scans</span>
            <h3 style={{ fontSize: '2rem', marginTop: '0.2rem' }}>{activeScansCount}</h3>
          </div>
        </div>

        <div className="panel" style={{ display: 'flex', gap: '1.25rem', alignItems: 'center' }}>
          <div style={{ padding: '0.75rem', borderRadius: '8px', backgroundColor: 'rgba(255, 255, 255, 0.05)' }}>
            <Shield size={28} className="text-secondary" />
          </div>
          <div>
            <span className="text-secondary" style={{ fontSize: '0.85rem', textTransform: 'uppercase', fontWeight: 600 }}>Deployed Audits</span>
            <h3 style={{ fontSize: '2rem', marginTop: '0.2rem' }}>{tasks.length}</h3>
          </div>
        </div>

        <div className="panel" style={{ display: 'flex', gap: '1.25rem', alignItems: 'center' }}>
          <div style={{ padding: '0.75rem', borderRadius: '8px', backgroundColor: 'rgba(255, 255, 255, 0.05)' }}>
            <Users size={28} className="text-secondary" />
          </div>
          <div>
            <span className="text-secondary" style={{ fontSize: '0.85rem', textTransform: 'uppercase', fontWeight: 600 }}>Scope Targets</span>
            <h3 style={{ fontSize: '2rem', marginTop: '0.2rem' }}>{targets.length}</h3>
          </div>
        </div>

        <div className="panel" style={{ display: 'flex', gap: '1.25rem', alignItems: 'center' }}>
          <div style={{ padding: '0.75rem', borderRadius: '8px', backgroundColor: status?.gvm_connected ? 'var(--severity-log-dim)' : 'var(--severity-high-dim)' }}>
            <CheckCircle2 size={28} style={{ color: status?.gvm_connected ? 'var(--severity-log)' : 'var(--severity-high)' }} />
          </div>
          <div>
            <span className="text-secondary" style={{ fontSize: '0.85rem', textTransform: 'uppercase', fontWeight: 600 }}>Scanner Connect</span>
            <h3 style={{ fontSize: '1.25rem', marginTop: '0.4rem', color: status?.gvm_connected ? 'var(--severity-log)' : 'var(--severity-high)' }}>
              {status?.gvm_connected ? 'Online' : 'Offline / Mock'}
            </h3>
          </div>
        </div>
      </div>

      {/* Aggregate Threat Metrics Card */}
      <div className="panel">
        <h3 style={{ marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <ShieldAlert size={20} className="text-secondary" /> Unified Network Vulnerability Posture
        </h3>
        {loadingVulnerabilities ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '2rem', gap: '0.5rem' }}>
            <RefreshCw size={24} className="animate-spin-slow text-muted" />
            <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Calculating risk profiles...</span>
          </div>
        ) : vulnerabilityAggregate.total === 0 ? (
          <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)', fontSize: '0.9rem' }}>
            No vulnerability data compiled. Run an audit task in the <span style={{ textDecoration: 'underline', cursor: 'pointer', color: 'var(--accent-cyan)' }} onClick={() => onTabChange('tasks')}>Audits Tab</span> to view risks.
          </div>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1.5rem' }}>
            <div style={{ padding: '1rem', borderRadius: '8px', background: 'var(--severity-high-dim)', border: '1px solid rgba(248, 113, 113, 0.15)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--severity-high)' }}>
                <span style={{ fontSize: '0.85rem', fontWeight: 'bold' }}>HIGH SEVERITY</span>
                <ShieldX size={16} />
              </div>
              <h2 style={{ fontSize: '2.5rem', marginTop: '0.5rem', color: 'var(--severity-high)' }}>{vulnerabilityAggregate.high}</h2>
            </div>
            
            <div style={{ padding: '1rem', borderRadius: '8px', background: 'var(--severity-medium-dim)', border: '1px solid rgba(251, 191, 36, 0.15)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--severity-medium)' }}>
                <span style={{ fontSize: '0.85rem', fontWeight: 'bold' }}>MEDIUM SEVERITY</span>
                <ShieldAlert size={16} />
              </div>
              <h2 style={{ fontSize: '2.5rem', marginTop: '0.5rem', color: 'var(--severity-medium)' }}>{vulnerabilityAggregate.medium}</h2>
            </div>

            <div style={{ padding: '1rem', borderRadius: '8px', background: 'var(--severity-low-dim)', border: '1px solid rgba(96, 165, 250, 0.15)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--severity-low)' }}>
                <span style={{ fontSize: '0.85rem', fontWeight: 'bold' }}>LOW SEVERITY</span>
                <Shield size={16} />
              </div>
              <h2 style={{ fontSize: '2.5rem', marginTop: '0.5rem', color: 'var(--severity-low)' }}>{vulnerabilityAggregate.low}</h2>
            </div>

            <div style={{ padding: '1rem', borderRadius: '8px', background: 'var(--severity-log-dim)', border: '1px solid rgba(52, 211, 153, 0.15)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--severity-log)' }}>
                <span style={{ fontSize: '0.85rem', fontWeight: 'bold' }}>LOG FINDINGS</span>
                <CheckCircle2 size={16} />
              </div>
              <h2 style={{ fontSize: '2.5rem', marginTop: '0.5rem', color: 'var(--severity-log)' }}>{vulnerabilityAggregate.log}</h2>
            </div>
          </div>
        )}
      </div>

      {/* Two Column Layout: Recent Scans + High Risk Alerts */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '1.5rem' }}>
        
        {/* Recent Scan Tasks */}
        <div className="panel" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3>Recent Audit Scans</h3>
            <button className="btn btn-secondary" style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }} onClick={() => onTabChange('tasks')}>
              Manage <ArrowUpRight size={12} />
            </button>
          </div>

          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Audit Scan</th>
                  <th>Target</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {tasks.slice(0, 4).map((task) => (
                  <tr key={task.id}>
                    <td>
                      <div style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{task.name}</div>
                    </td>
                    <td><code style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)' }}>{task.target_hosts}</code></td>
                    <td>
                      <span className={`badge ${task.status?.toLowerCase() === 'done' ? 'badge-log' : task.status?.toLowerCase() === 'running' ? 'badge-cyan animate-pulse-slow' : 'badge-low'}`} style={{ fontSize: '0.65rem', padding: '0.15rem 0.4rem' }}>
                        {task.status}
                      </span>
                    </td>
                  </tr>
                ))}
                {tasks.length === 0 && (
                  <tr>
                    <td colSpan="3" style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem', padding: '2rem' }}>
                      No scan configurations deployed.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* High Risk Critical Threats */}
        <div className="panel" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3>High Risk Threats Identified</h3>
            <button className="btn btn-secondary" style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }} onClick={() => onTabChange('reports')}>
              Reports <ArrowUpRight size={12} />
            </button>
          </div>

          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Threat / Vulnerability</th>
                  <th>Severity</th>
                  <th>CVSS</th>
                  <th>Host Info</th>
                </tr>
              </thead>
              <tbody>
                {recentFindings.map((finding, idx) => (
                  <tr key={idx} style={{ cursor: 'pointer' }} onClick={() => onSelectReport(finding.reportId)}>
                    <td>
                      <div style={{ fontWeight: 500, color: 'var(--text-primary)', whiteSpace: 'nowrap', textOverflow: 'ellipsis', overflow: 'hidden', maxWidth: '240px' }} title={finding.name}>
                        {finding.name}
                      </div>
                    </td>
                    <td>
                      <span className={`badge ${finding.severity.toLowerCase() === 'high' ? 'badge-high' : 'badge-medium'}`} style={{ fontSize: '0.65rem', padding: '0.15rem 0.4rem' }}>
                        {finding.severity}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', fontWeight: 'bold' }}>{finding.cvss}</td>
                    <td><code style={{ fontSize: '0.8rem' }}>Port {finding.port}</code></td>
                  </tr>
                ))}
                {recentFindings.length === 0 && (
                  <tr>
                    <td colSpan="4" style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem', padding: '2rem' }}>
                      No critical threat vectors recorded.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </div>
  );
}
