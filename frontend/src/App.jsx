import React, { useState, useEffect } from 'react';
import { Activity, Target, ShieldAlert, FileText, Terminal, Settings as SettingsIcon, Shield, ShieldCheck, ShieldAlert as AlertIcon, Info, Bot } from 'lucide-react';
import Overview from './components/Overview';
import Targets from './components/Targets';
import Tasks from './components/Tasks';
import Reports from './components/Reports';
import Nmap from './components/Nmap';
import CVEs from './components/CVEs';
import Settings from './components/Settings';
import ToolScanners from './components/ToolScanners';

// Global relative API base url
const API_BASE = "";

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [gvmStatus, setGvmStatus] = useState(null);
  const [selectedReportId, setSelectedReportId] = useState('');

  const fetchStatus = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/status`);
      if (res.ok) {
        const data = await res.json();
        setGvmStatus(data);
      }
    } catch (err) {
      console.error("Failed to query connection status:", err);
    }
  };

  useEffect(() => {
    fetchStatus();
    // Poll connection status every 10s
    const statusInterval = setInterval(fetchStatus, 10000);
    return () => clearInterval(statusInterval);
  }, []);

  const handleSelectReport = (reportId) => {
    setSelectedReportId(reportId);
    setActiveTab('reports');
  };

  const handleBackToTasks = () => {
    setSelectedReportId('');
    setActiveTab('tasks');
  };

  const handleStatusChange = (statusData) => {
    setGvmStatus(statusData);
  };

  const renderContent = () => {
    switch (activeTab) {
      case 'dashboard':
        return <Overview apiBase={API_BASE} onTabChange={setActiveTab} onSelectReport={handleSelectReport} />;
      case 'targets':
        return <Targets apiBase={API_BASE} />;
      case 'tasks':
        return <Tasks apiBase={API_BASE} onSelectReport={handleSelectReport} />;
      case 'reports':
        return <Reports apiBase={API_BASE} activeReportId={selectedReportId} onBackToTasks={handleBackToTasks} />;
      case 'nmap':
        return <Nmap apiBase={API_BASE} />;
      case 'toolscanners':
        return <ToolScanners apiBase={API_BASE} />;
      case 'cves':
        return <CVEs apiBase={API_BASE} />;
      case 'settings':
        return <Settings apiBase={API_BASE} onStatusChange={handleStatusChange} />;
      default:
        return <Overview apiBase={API_BASE} onTabChange={setActiveTab} onSelectReport={handleSelectReport} />;
    }
  };

  return (
    <div className="dashboard-layout">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        {/* Brand Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '2.5rem' }}>
          <div style={{ 
            background: 'var(--accent-cyan-dim)', 
            padding: '0.5rem', 
            borderRadius: '8px', 
            border: '1px solid var(--accent-cyan)',
            boxShadow: 'var(--glow-cyan)'
          }}>
            <Shield size={22} style={{ color: 'var(--accent-cyan)' }} />
          </div>
          <div>
            <h1 style={{ fontSize: '1.25rem', fontWeight: 700, letterSpacing: '0.05em' }}>VAPT SHIELD</h1>
            <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>Audit Dashboard</span>
          </div>
        </div>

        {/* Nav Links */}
        <nav style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', flex: 1 }}>
          <button 
            className={`btn ${activeTab === 'dashboard' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ justifyContent: 'flex-start', border: activeTab === 'dashboard' ? '' : '1px solid transparent' }}
            onClick={() => setActiveTab('dashboard')}
          >
            <Activity size={18} /> Command Room
          </button>
          
          <button 
            className={`btn ${activeTab === 'targets' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ justifyContent: 'flex-start', border: activeTab === 'targets' ? '' : '1px solid transparent' }}
            onClick={() => setActiveTab('targets')}
          >
            <Target size={18} /> Scan Targets
          </button>

          <button 
            className={`btn ${activeTab === 'tasks' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ justifyContent: 'flex-start', border: activeTab === 'tasks' ? '' : '1px solid transparent' }}
            onClick={() => setActiveTab('tasks')}
          >
            <ShieldAlert size={18} /> Audit Scans
          </button>

          <button 
            className={`btn ${activeTab === 'reports' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ justifyContent: 'flex-start', border: activeTab === 'reports' ? '' : '1px solid transparent' }}
            onClick={() => setActiveTab('reports')}
          >
            <FileText size={18} /> Threat Reports
          </button>

          <button 
            className={`btn ${activeTab === 'nmap' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ justifyContent: 'flex-start', border: activeTab === 'nmap' ? '' : '1px solid transparent' }}
            onClick={() => setActiveTab('nmap')}
          >
            <Terminal size={18} /> Nmap Console
          </button>

          <button 
            className={`btn ${activeTab === 'toolscanners' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ justifyContent: 'flex-start', border: activeTab === 'toolscanners' ? '' : '1px solid transparent' }}
            onClick={() => setActiveTab('toolscanners')}
          >
            <Bot size={18} /> Tool Scanners
          </button>

          <button 
            className={`btn ${activeTab === 'cves' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ justifyContent: 'flex-start', border: activeTab === 'cves' ? '' : '1px solid transparent' }}
            onClick={() => setActiveTab('cves')}
          >
            <Info size={18} /> CVE Library
          </button>

          <button 
            className={`btn ${activeTab === 'settings' ? 'btn-primary' : 'btn-secondary'}`}
            style={{ justifyContent: 'flex-start', border: activeTab === 'settings' ? '' : '1px solid transparent' }}
            onClick={() => setActiveTab('settings')}
          >
            <SettingsIcon size={18} /> Configuration
          </button>
        </nav>

        {/* Footer GVM Connection Indicator */}
        <div style={{ 
          marginTop: 'auto', 
          padding: '0.75rem', 
          borderRadius: '8px', 
          backgroundColor: 'rgba(255,255,255,0.02)',
          border: '1px solid var(--border-subtle)',
          fontSize: '0.75rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.4rem'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span className="text-secondary">OpenVAS Connector</span>
            <span style={{ 
              width: '8px', 
              height: '8px', 
              borderRadius: '50%', 
              backgroundColor: gvmStatus?.gvm_connected ? 'var(--severity-log)' : 'var(--severity-high)',
              boxShadow: gvmStatus?.gvm_connected ? 'var(--glow-log)' : 'var(--glow-high)',
              display: 'inline-block'
            }}></span>
          </div>
          <div style={{ color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            Mode: {gvmStatus?.gvm_mode || 'Checking...'}
          </div>
        </div>
      </aside>

      {/* Main Panel Content Area */}
      <main className="main-content">
        {renderContent()}
      </main>
    </div>
  );
}
