import React, { useState, useEffect, Component } from 'react';
import {
  LayoutDashboard, Target, ShieldAlert, FileText,
  Terminal, Shield, ScanSearch, Globe, BookOpen,
  Settings, Zap, Activity, ChevronRight, Sun, Moon, Database,
  AlertCircle, RefreshCw
} from 'lucide-react';
import './index.css';
import Overview from './components/Overview';
import Targets from './components/Targets';
import Tasks from './components/Tasks';
import Reports from './components/Reports';
import Nmap from './components/Nmap';
import CVEs from './components/CVEs';
import SettingsPage from './components/Settings';
import NucleiDashboard from './components/NucleiDashboard';
import NiktoDashboard from './components/NiktoDashboard';
import ZapDashboard from './components/ZapDashboard';
import GobusterDashboard from './components/GobusterDashboard';
import SqlmapDashboard from './components/SqlmapDashboard';
import FfufDashboard from './components/FfufDashboard';
import History from './components/History';
import SchedulerDashboard from './components/SchedulerDashboard';
import { Calendar } from 'lucide-react';

class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("Dashboard Error caught:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="card" style={{ padding: '24px', borderLeft: '4px solid var(--critical)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: 'var(--critical)', marginBottom: '12px' }}>
            <AlertCircle size={20} />
            <h4 style={{ margin: 0 }}>Component Render Issue</h4>
          </div>
          <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
            {this.state.error?.message || 'An unexpected rendering error occurred in this module.'}
          </p>
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => this.setState({ hasError: false, error: null })}
          >
            <RefreshCw size={13} /> Retry Component
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

const API_BASE = '';

const NAV_GROUPS = [
  {
    label: 'Core',
    items: [
      { id: 'dashboard', label: 'Overview',     icon: LayoutDashboard },
      { id: 'targets',   label: 'Targets',      icon: Target },
      { id: 'tasks',     label: 'Audit Scans',  icon: ShieldAlert },
      { id: 'scheduler', label: 'Scheduler',    icon: Calendar },
      { id: 'reports',   label: 'Reports',      icon: FileText },
    ]
  },
  {
    label: 'Scanners',
    items: [
      { id: 'nmap',    label: 'Nmap',        icon: Terminal },
      { id: 'nuclei',  label: 'Nuclei',      icon: Shield },
      { id: 'nikto',   label: 'Nikto',       icon: ScanSearch },
      { id: 'gobuster',label: 'Gobuster',    icon: Globe },
      { id: 'ffuf',    label: 'FFuF',        icon: ScanSearch },
      { id: 'sqlmap',  label: 'SQLmap',      icon: Database },
      { id: 'zap',     label: 'OWASP ZAP',   icon: Zap },
      { id: 'history', label: 'Scan History', icon: Activity },
    ]
  },
  {
    label: 'Intelligence',
    items: [
      { id: 'cves', label: 'CVE Library', icon: BookOpen },
    ]
  },
  {
    label: 'System',
    items: [
      { id: 'settings', label: 'Settings', icon: Settings },
    ]
  },
];

const PAGE_TITLES = {
  dashboard: { title: 'Security Overview',     desc: 'Real-time threat intelligence & scan activity' },
  targets:   { title: 'Target Management',     desc: 'Define and manage your assessment targets' },
  tasks:     { title: 'Audit Scans',            desc: 'Run and monitor OpenVAS vulnerability scans' },
  scheduler: { title: 'Scan Scheduler',         desc: 'Schedule automated security scans' },
  reports:   { title: 'Threat Reports',         desc: 'Review detailed penetration test findings' },
  history:   { title: 'Scan History & Trends',  desc: 'Historical scan run logs and visual threat trends' },
  nmap:      { title: 'Nmap Port Scanner',      desc: 'Network discovery and port enumeration' },
  nuclei:    { title: 'Nuclei Scanner',         desc: 'Template-based vulnerability detection engine' },
  nikto:     { title: 'Nikto Web Scanner',      desc: 'Web server configuration and vulnerability audit' },
  gobuster:  { title: 'Gobuster',               desc: 'Directory & DNS brute-force enumeration' },
  ffuf:      { title: 'FFuF',                   desc: 'Fast web fuzzer' },
  sqlmap:    { title: 'SQLmap',                 desc: 'Automatic SQL injection testing' },
  zap:       { title: 'OWASP ZAP',             desc: 'Dynamic application security testing (DAST)' },
  cves:      { title: 'CVE Library',            desc: 'Browse and search known vulnerabilities' },
  settings:  { title: 'Configuration',          desc: 'System settings and service configuration' },
};

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [gvmStatus, setGvmStatus] = useState(null);
  const [selectedReportId, setSelectedReportId] = useState('');

  useEffect(() => {
    const fetch_status = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/status`);
        if (res.ok) setGvmStatus(await res.json());
      } catch (_) {}
    };
    fetch_status();
    const t = setInterval(fetch_status, 12000);
    return () => clearInterval(t);
  }, []);

  const handleSelectReport = (id) => { setSelectedReportId(id); setActiveTab('reports'); };
  const handleBackToTasks  = ()   => { setSelectedReportId(''); setActiveTab('tasks'); };

  const page = PAGE_TITLES[activeTab] || PAGE_TITLES.dashboard;

  return (
    <div className="app-layout">
      {/* ── Sidebar ── */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="sidebar-brand-icon">
            <Shield size={18} color="#fff" />
          </div>
          <div className="sidebar-brand-text">
            <h1>VAPT SHIELD</h1>
            <span>Security Platform</span>
          </div>
        </div>

        <nav className="sidebar-nav">
          {NAV_GROUPS.map(group => (
            <div key={group.label}>
              <div className="nav-group-label">{group.label}</div>
              {group.items.map(item => {
                const Icon = item.icon;
                return (
                  <button
                    key={item.id}
                    className={`nav-item ${activeTab === item.id ? 'active' : ''}`}
                    onClick={() => setActiveTab(item.id)}
                  >
                    <Icon size={15} />
                    {item.label}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className="status-pill">
            <span className={`status-dot ${gvmStatus?.gvm_connected ? 'online' : 'offline'}`} />
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)' }}>OpenVAS GVM</div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                {gvmStatus ? (gvmStatus.gvm_connected ? 'Connected' : 'Disconnected') : 'Checking...'}
              </div>
            </div>
            <Activity size={12} style={{ color: 'var(--text-muted)' }} />
          </div>
        </div>
      </aside>

      {/* ── Main ── */}
      <main className="main-panel">
        {/* Top Header */}
        <div style={{
          padding: '14px 28px',
          borderBottom: '1px solid var(--sidebar-border)',
          background: 'var(--sidebar-bg)',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          flexShrink: 0
        }}>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>VAPT Shield</span>
          <ChevronRight size={12} style={{ color: 'var(--text-muted)' }} />
          <span style={{ fontSize: 12, color: 'var(--text-secondary)', fontWeight: 500 }}>{page.title}</span>
        </div>

        {/* Page Content */}
        <div className="page-container">
          <div className="page-header">
            <h2>{page.title}</h2>
            <p>{page.desc}</p>
          </div>

          {/* Render all pages with ErrorBoundary isolation */}
          <div style={{ display: activeTab === 'dashboard' ? 'block' : 'none' }}>
            <ErrorBoundary>
              <Overview apiBase={API_BASE} onTabChange={setActiveTab} onSelectReport={handleSelectReport} />
            </ErrorBoundary>
          </div>
          <div style={{ display: activeTab === 'targets' ? 'block' : 'none' }}>
            <ErrorBoundary>
              <Targets apiBase={API_BASE} />
            </ErrorBoundary>
          </div>
          <div style={{ display: activeTab === 'tasks' ? 'block' : 'none' }}>
            <ErrorBoundary>
              <Tasks apiBase={API_BASE} onSelectReport={handleSelectReport} />
            </ErrorBoundary>
          </div>
          <div style={{ display: activeTab === 'scheduler' ? 'block' : 'none' }}>
            <ErrorBoundary>
              <SchedulerDashboard apiBase={API_BASE} />
            </ErrorBoundary>
          </div>
          <div style={{ display: activeTab === 'reports' ? 'block' : 'none' }}>
            <ErrorBoundary>
              <Reports apiBase={API_BASE} activeReportId={selectedReportId} onBackToTasks={handleBackToTasks} />
            </ErrorBoundary>
          </div>
          <div style={{ display: activeTab === 'history' ? 'block' : 'none' }}>
            <ErrorBoundary>
              <History apiBase={API_BASE} />
            </ErrorBoundary>
          </div>
          <div style={{ display: activeTab === 'nmap' ? 'block' : 'none' }}>
            <ErrorBoundary>
              <Nmap apiBase={API_BASE} />
            </ErrorBoundary>
          </div>
          <div style={{ display: activeTab === 'nuclei' ? 'block' : 'none' }}>
            <ErrorBoundary>
              <NucleiDashboard apiBase={API_BASE} />
            </ErrorBoundary>
          </div>
          <div style={{ display: activeTab === 'nikto' ? 'block' : 'none' }}>
            <ErrorBoundary>
              <NiktoDashboard apiBase={API_BASE} />
            </ErrorBoundary>
          </div>
          <div style={{ display: activeTab === 'gobuster' ? 'block' : 'none' }}>
            <ErrorBoundary>
              <GobusterDashboard apiBase={API_BASE} />
            </ErrorBoundary>
          </div>
          <div style={{ display: activeTab === 'ffuf' ? 'block' : 'none' }}>
            <ErrorBoundary>
              <FfufDashboard apiBase={API_BASE} />
            </ErrorBoundary>
          </div>
          <div style={{ display: activeTab === 'sqlmap' ? 'block' : 'none' }}>
            <ErrorBoundary>
              <SqlmapDashboard apiBase={API_BASE} />
            </ErrorBoundary>
          </div>
          <div style={{ display: activeTab === 'zap' ? 'block' : 'none' }}>
            <ErrorBoundary>
              <ZapDashboard apiBase={API_BASE} />
            </ErrorBoundary>
          </div>
          <div style={{ display: activeTab === 'cves' ? 'block' : 'none' }}>
            <ErrorBoundary>
              <CVEs apiBase={API_BASE} />
            </ErrorBoundary>
          </div>
          <div style={{ display: activeTab === 'settings' ? 'block' : 'none' }}>
            <ErrorBoundary>
              <SettingsPage apiBase={API_BASE} onStatusChange={setGvmStatus} />
            </ErrorBoundary>
          </div>
        </div>
      </main>
    </div>
  );
}
