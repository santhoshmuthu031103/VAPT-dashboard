import React, { useState, useEffect } from 'react';
import { Calendar, Shield, Trash2, ArrowRight, ExternalLink, RefreshCw, Eye, X, FileText, Download, Loader2, Search, Users } from 'lucide-react';
import { DonutChart, BarChart, LineChart, MultiLineChart } from './SvgCharts';
import PortMatrixView from './PortMatrixView';
import { triggerFileDownload } from '../utils/downloadHelper';

const TOOL_COLORS = {
  nmap: '#7c3aed',     // violet
  nuclei: '#10b981',   // emerald
  nikto: '#d97706',    // amber
  gobuster: '#2563eb', // blue
  zap: '#dc2626',      // red
  sqlmap: '#a855f7',   // purple
  ffuf: '#06b6d4'      // cyan
};

const TOOL_LABELS = {
  nmap: 'Nmap Ports',
  nuclei: 'Nuclei Vulns',
  nikto: 'Nikto Items',
  gobuster: 'Gobuster Paths',
  zap: 'ZAP Vulns',
  sqlmap: 'SQLmap Injections',
  ffuf: 'FFuF Endpoints'
};

export default function History({ apiBase }) {
  const [history, setHistory] = useState([]);
  const [trends, setTrends] = useState([]);
  const [targetGroups, setTargetGroups] = useState([]);
  const [selectedGroupId, setSelectedGroupId] = useState('');
  const [stats, setStats] = useState({ total_scans: 0, total_findings: 0, high_severity: 0 });
  const [loading, setLoading] = useState(false);
  const [selectedTool, setSelectedTool] = useState('all');
  const [targetFilter, setTargetFilter] = useState('');
  const [search, setSearch] = useState('');
  
  // Detailed scan inspection modal
  const [selectedScan, setSelectedScan] = useState(null);
  const [scanDetail, setScanDetail] = useState(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [downloadingReportId, setDownloadingReportId] = useState(null);

  const handleDownloadReport = async (e, scanId, tool, fmt = 'pdf') => {
    e.stopPropagation();
    setDownloadingReportId(`${scanId}-${fmt}`);
    try {
      const res = await fetch(`${apiBase}/api/scanners/history/${scanId}/report?fmt=${fmt}`);
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`Report generation failed (${res.status}): ${errText}`);
      }
      const blob = await res.blob();
      triggerFileDownload(blob, `vapt-${tool.toLowerCase()}-audit-${scanId}.${fmt}`);
    } catch (err) {
      alert(`Report download error: ${err.message}`);
    } finally {
      setDownloadingReportId(null);
    }
  };


  useEffect(() => {
    fetchHistoryAndTrends();
  }, [selectedTool]);

  const fetchHistoryAndTrends = async () => {
    setLoading(true);
    try {
      // 1. Fetch History List
      let url = `${apiBase}/api/scanners/history`;
      const queryParams = [];
      if (selectedTool !== 'all') {
        queryParams.push(`tool=${selectedTool}`);
      }
      if (queryParams.length > 0) {
        url += `?${queryParams.join('&')}`;
      }
      
      const [resHist, resTrends, resGroups] = await Promise.allSettled([
        fetch(url),
        fetch(`${apiBase}/api/scanners/history/trends`),
        fetch(`${apiBase}/api/target-groups`)
      ]);

      if (resHist.status === 'fulfilled' && resHist.value.ok) {
        const dataHist = await resHist.value.json();
        setHistory(Array.isArray(dataHist) ? dataHist : []);
      }

      if (resTrends.status === 'fulfilled' && resTrends.value.ok) {
        const dataTrends = await resTrends.value.json();
        setTrends(Array.isArray(dataTrends.trends) ? dataTrends.trends : []);
      }

      if (resGroups.status === 'fulfilled' && resGroups.value.ok) {
        const dataGroups = await resGroups.value.json();
        setTargetGroups(Array.isArray(dataGroups) ? dataGroups : []);
      }
    } catch (e) {
      console.error("Failed to load history:", e);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (e, scanId) => {
    e.stopPropagation();
    if (!window.confirm("Are you sure you want to delete this scan run from history?")) return;
    try {
      const res = await fetch(`${apiBase}/api/scanners/history/${scanId}`, { method: 'DELETE' });
      if (res.ok) {
        setHistory(prev => prev.filter(item => item.id !== scanId));
        // Refresh trends
        const resTrends = await fetch(`${apiBase}/api/scanners/history/trends`);
        if (resTrends.ok) {
          const dataTrends = await resTrends.json();
          setTrends(Array.isArray(dataTrends.trends) ? dataTrends.trends : []);
        }
      }
    } catch (e) {
      console.error("Failed to delete scan:", e);
    }
  };

  const handleViewDetail = async (scan) => {
    setSelectedScan(scan);
    setLoadingDetail(true);
    setScanDetail(null);
    try {
      const res = await fetch(`${apiBase}/api/scanners/history/${scan.id}`);
      if (res.ok) {
        const data = await res.json();
        setScanDetail(data);
      }
    } catch (e) {
      console.error("Failed to fetch scan detail:", e);
    } finally {
      setLoadingDetail(false);
    }
  };

  // Compile line chart trend points
  const getTrendDataPoints = () => {
    const trendList = Array.isArray(trends) ? trends : [];
    const filteredTrends = trendList.filter(t => selectedTool === 'all' || t.tool === selectedTool);
    
    // Aggregate findings count per date
    const dateMap = {};
    filteredTrends.forEach(t => {
      const dateKey = t.date;
      dateMap[dateKey] = (dateMap[dateKey] || 0) + (t.findings || 0);
    });

    // Convert map to sorted array
    const sortedPoints = Object.entries(dateMap)
      .map(([date, value]) => ({ date, value }))
      .sort((a, b) => new Date(a.date) - new Date(b.date));

    return sortedPoints;
  };

  const formatToolName = (tool) => {
    const names = {
      nmap: "Nmap Port Scanner",
      nuclei: "Nuclei Vuln Scanner",
      nikto: "Nikto Web Auditor",
      gobuster: "Gobuster Dir Buster",
      zap: "OWASP ZAP Dynamic Scan",
      sqlmap: "SQLmap Injection Tool",
      ffuf: "FFuF Web Fuzzer"
    };
    return names[tool] || tool.toUpperCase();
  };

  // Compile trend points for MultiLineChart (when selectedTool is 'all')
  const getMultiTrendDataPoints = () => {
    const trendList = Array.isArray(trends) ? trends : [];
    const dateMap = {};
    trendList.forEach(t => {
      const dateKey = t.date;
      if (!dateMap[dateKey]) {
        dateMap[dateKey] = { date: dateKey, nmap: 0, nuclei: 0, nikto: 0, gobuster: 0, zap: 0, sqlmap: 0, ffuf: 0 };
      }
      if (dateMap[dateKey][t.tool] !== undefined) {
        dateMap[dateKey][t.tool] += (t.findings || 0);
      }
    });
    return Object.values(dateMap).sort((a, b) => new Date(a.date) - new Date(b.date));
  };

  const getScanDistributionData = () => {
    const histList = Array.isArray(history) ? history : [];
    const counts = { nmap: 0, nuclei: 0, nikto: 0, gobuster: 0, zap: 0, sqlmap: 0, ffuf: 0 };
    histList.forEach(item => {
      if (counts[item.tool] !== undefined) {
        counts[item.tool]++;
      }
    });
    return Object.entries(counts).map(([tool, value]) => ({
      name: TOOL_LABELS[tool]?.split(' ')[0] || tool.toUpperCase(),
      value,
      color: TOOL_COLORS[tool]
    })).filter(d => d.value > 0);
  };

  const getNmapServiceData = () => {
    const services = {};
    history.filter(item => item.tool === 'nmap').forEach(item => {
      const svcs = item.summary?.services || {};
      Object.entries(svcs).forEach(([svc, count]) => {
        services[svc] = (services[svc] || 0) + count;
      });
    });
    const colors = ['#a78bfa', '#34d399', '#f97316', '#2563eb', '#dc2626', '#64748b', '#ec4899', '#eab308', '#06b6d4'];
    return Object.entries(services).map(([name, value], i) => ({
      name,
      value,
      color: colors[i % colors.length]
    })).filter(d => d.value > 0);
  };

  const getSeverityDistributionData = (tool) => {
    const totals = { High: 0, Medium: 0, Low: 0, Info: 0 };
    history.filter(item => item.tool === tool).forEach(item => {
      const sum = item.summary || {};
      totals.High += sum.high || 0;
      totals.Medium += sum.medium || 0;
      totals.Low += sum.low || 0;
      totals.Info += sum.info || 0;
    });
    return [
      { name: 'High', value: totals.High, color: '#dc2626' },
      { name: 'Medium', value: totals.Medium, color: '#ea580c' },
      { name: 'Low', value: totals.Low, color: '#2563eb' },
      { name: 'Info', value: totals.Info, color: '#64748b' }
    ].filter(d => d.value > 0);
  };

  const getNiktoSeverityData = () => {
    const totals = { High: 0, Medium: 0, Low: 0, Info: 0 };
    history.filter(item => item.tool === 'nikto').forEach(item => {
      const sev = item.summary?.severity || {};
      totals.High += sev.high || 0;
      totals.Medium += sev.medium || 0;
      totals.Low += sev.low || 0;
      totals.Info += sev.info || 0;
    });
    return [
      { name: 'High', value: totals.High, color: '#dc2626' },
      { name: 'Medium', value: totals.Medium, color: '#ea580c' },
      { name: 'Low', value: totals.Low, color: '#2563eb' },
      { name: 'Info', value: totals.Info, color: '#64748b' }
    ].filter(d => d.value > 0);
  };

  const getGobusterCodesData = () => {
    const codes = {};
    history.filter(item => item.tool === 'gobuster').forEach(item => {
      const status_codes = item.summary?.status_codes || {};
      Object.entries(status_codes).forEach(([code, count]) => {
        codes[code] = (codes[code] || 0) + count;
      });
    });
    const getColorForStatus = (status) => {
      if (status.startsWith('2')) return '#10b981';
      if (status.startsWith('3')) return '#0ea5e9';
      if (status.startsWith('4')) return '#ea580c';
      if (status.startsWith('5')) return '#dc2626';
      return '#64748b';
    };
    return Object.entries(codes).map(([name, value]) => ({
      name: `HTTP ${name}`,
      value,
      color: getColorForStatus(name)
    })).filter(d => d.value > 0);
  };

  const renderLeftWidget = () => {
    if (selectedTool === 'all') {
      return (
        <div className="card" style={{ flex: '1 1 60%', minWidth: '320px', padding: '1.25rem' }}>
          <h4 style={{ marginBottom: '0.4rem', fontWeight: 600, color: 'var(--text-primary)' }}>Historical Findings Trend</h4>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '1.25rem' }}>
            Comparative findings count over time for all scanning suites.
          </p>
          <MultiLineChart
            data={getMultiTrendDataPoints()}
            seriesKeys={['nmap', 'nuclei', 'nikto', 'gobuster', 'zap', 'sqlmap', 'ffuf']}
            colors={TOOL_COLORS}
            labels={TOOL_LABELS}
            height={190}
          />
        </div>
      );
    }
    return (
      <div className="card" style={{ flex: '1 1 60%', minWidth: '320px', padding: '1.25rem' }}>
        <h4 style={{ marginBottom: '0.4rem', fontWeight: 600, color: 'var(--text-primary)' }}>{formatToolName(selectedTool)} Trend</h4>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '1.25rem' }}>
          Findings count over time for {formatToolName(selectedTool)}.
        </p>
        <LineChart
          data={getTrendDataPoints()}
          height={190}
          color={TOOL_COLORS[selectedTool] || '#0284c7'}
        />
      </div>
    );
  };

  const renderRightWidget = () => {
    if (selectedTool === 'all') {
      const data = getScanDistributionData();
      return (
        <div className="card" style={{ flex: '1 1 35%', minWidth: '280px', padding: '1.25rem', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <h4 style={{ marginBottom: '0.4rem', fontWeight: 600, color: 'var(--text-primary)' }}>Scan Distribution</h4>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '1.25rem' }}>
              Comparison of scanning runs executed per tool utility.
            </p>
          </div>
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <DonutChart data={data} title="Total Scans" />
          </div>
        </div>
      );
    }

    let chartData = [];
    let widgetTitle = '';
    let widgetDesc = '';
    let donutTitle = 'Findings';

    if (selectedTool === 'nmap') {
      chartData = getNmapServiceData();
      widgetTitle = 'Service Distribution';
      widgetDesc = 'Cumulative open ports grouped by discovered protocol service.';
      donutTitle = 'Ports';
    } else if (selectedTool === 'nuclei' || selectedTool === 'zap') {
      chartData = getSeverityDistributionData(selectedTool);
      widgetTitle = 'Severity Breakdown';
      widgetDesc = `Historical threats identified by ${formatToolName(selectedTool)} classified by severity.`;
      donutTitle = 'Vulns';
    } else if (selectedTool === 'nikto') {
      chartData = getNiktoSeverityData();
      widgetTitle = 'Vulnerability Severity';
      widgetDesc = 'Nikto reported items dynamically classified by risk keywords.';
      donutTitle = 'Items';
    } else if (selectedTool === 'gobuster') {
      chartData = getGobusterCodesData();
      widgetTitle = 'HTTP Status Codes';
      widgetDesc = 'Response codes returned during path brute-forcing.';
      donutTitle = 'Paths';
    }

    return (
      <div className="card" style={{ flex: '1 1 35%', minWidth: '280px', padding: '1.25rem', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
        <div>
          <h4 style={{ marginBottom: '0.4rem', fontWeight: 600, color: 'var(--text-primary)' }}>{widgetTitle}</h4>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '1.25rem' }}>
            {widgetDesc}
          </p>
        </div>
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <DonutChart data={chartData} title={donutTitle} />
        </div>
      </div>
    );
  };

  // Format summaries
  const renderSummaryBadge = (item) => {
    const summary = item.summary || {};
    if (item.status === 'failed') {
      return <span style={{ color: 'var(--red-400)', fontSize: '0.8rem' }}>Failed Scan</span>;
    }

    if (item.tool === 'nmap') {
      return <span className="badge badge-info">{summary.open_ports || 0} Ports Open</span>;
    }
    if (item.tool === 'gobuster') {
      const codes = summary.status_codes || {};
      const count = Object.values(codes).reduce((a, b) => a + b, 0);
      return <span className="badge badge-info">{count} Paths Found</span>;
    }
    if (item.tool === 'nikto') {
      return <span className="badge badge-medium">{summary.vulns_count || 0} Items Reported</span>;
    }
    if (item.tool === 'nuclei' || item.tool === 'zap') {
      const h = summary.high || 0;
      const m = summary.medium || 0;
      const l = summary.low || 0;
      return (
        <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
          {h > 0 && <span className="badge badge-high">{h} High</span>}
          {m > 0 && <span className="badge badge-medium">{m} Med</span>}
          {l > 0 && <span className="badge badge-low">{l} Low</span>}
          {h === 0 && m === 0 && l === 0 && <span className="badge badge-info">0 Vulns</span>}
        </div>
      );
    }
    return <span style={{ color: 'var(--text-muted)' }}>—</span>;
  };

  // Compile detailed chart for scan detail view modal
  const getDetailChartData = (detail) => {
    if (!detail || !detail.results) return [];
    const results = detail.results;
    
    if (detail.tool === 'nuclei') {
      const high = sumVal(results, v => v.info?.severity?.toLowerCase() in {high: 1, critical: 1});
      const med = sumVal(results, v => v.info?.severity?.toLowerCase() === 'medium');
      const low = sumVal(results, v => v.info?.severity?.toLowerCase() === 'low');
      const info = sumVal(results, v => v.info?.severity?.toLowerCase() === 'info');
      return [
        { name: 'High', value: high, color: '#dc2626' },
        { name: 'Medium', value: med, color: '#ea580c' },
        { name: 'Low', value: low, color: '#2563eb' },
        { name: 'Info', value: info, color: '#64748b' }
      ];
    }
    if (detail.tool === 'zap') {
      const high = sumVal(results, a => a.risk?.toLowerCase() === 'high');
      const med = sumVal(results, a => a.risk?.toLowerCase() === 'medium');
      const low = sumVal(results, a => a.risk?.toLowerCase() === 'low');
      const info = sumVal(results, a => a.risk?.toLowerCase() === 'informational');
      return [
        { name: 'High', value: high, color: '#dc2626' },
        { name: 'Medium', value: med, color: '#ea580c' },
        { name: 'Low', value: low, color: '#2563eb' },
        { name: 'Info', value: info, color: '#64748b' }
      ];
    }
    if (detail.tool === 'nmap') {
      const services = {};
      results.forEach(p => {
        const s = p.service || 'unknown';
        services[s] = (services[s] || 0) + 1;
      });
      const colors = ['#a78bfa', '#34d399', '#f97316', '#2563eb', '#dc2626', '#64748b', '#ec4899', '#eab308', '#06b6d4'];
      return Object.entries(services).map(([k, v], i) => ({
        name: k,
        value: v,
        color: colors[i % colors.length]
      }));
    }
    if (detail.tool === 'gobuster') {
      const codes = {};
      results.forEach(r => {
        const s = String(r.status || 'unknown');
        codes[s] = (codes[s] || 0) + 1;
      });
      const getColorForStatus = (status) => {
        if (status.startsWith('2')) return '#10b981';
        if (status.startsWith('3')) return '#0ea5e9';
        if (status.startsWith('4')) return '#ea580c';
        if (status.startsWith('5')) return '#dc2626';
        return '#64748b';
      };
      return Object.entries(codes).map(([k, v]) => ({
        name: `HTTP ${k}`,
        value: v,
        color: getColorForStatus(k)
      }));
    }
    if (detail.tool === 'nikto') {
      const vulns = results.vulnerabilities || [];
      let high = 0, med = 0, low = 0, info = 0;
      vulns.forEach(v => {
        const msg = (v.msg || '').toLowerCase();
        if (/(exploit|sqli|injection|rce|cve-|bypass|vulnerable|remote code|execute)/.test(msg)) {
          high++;
        } else if (/(xss|cross-site|csrf|ssrf|clickjacking|cors)/.test(msg)) {
          med++;
        } else if (/(header|cookie|protection|ssl|tls|deprecated|option|banner)/.test(msg)) {
          low++;
        } else {
          info++;
        }
      });
      return [
        { name: 'High', value: high, color: '#dc2626' },
        { name: 'Medium', value: med, color: '#ea580c' },
        { name: 'Low', value: low, color: '#2563eb' },
        { name: 'Info', value: info, color: '#64748b' }
      ];
    }
    return [];
  };

  const sumVal = (arr, filterFn) => {
    return arr.filter(filterFn).length;
  };

  const selectedGroup = targetGroups.find(g => g.id.toString() === selectedGroupId.toString());
  const groupTargetsList = selectedGroup ? (Array.isArray(selectedGroup.targets) ? selectedGroup.targets : (selectedGroup.targets ? selectedGroup.targets.split(',') : [])).map(h => h.trim().toLowerCase()).filter(Boolean) : [];

  const filteredHistory = history.filter(item => {
    if (selectedGroupId && groupTargetsList.length > 0) {
      const itemTarget = (item.target || '').toLowerCase();
      const match = groupTargetsList.some(gh => itemTarget.includes(gh) || gh.includes(itemTarget));
      if (!match) return false;
    }
    if (targetFilter) {
      return (item.target || '').toLowerCase().includes(targetFilter.toLowerCase());
    }
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* Search and Filters */}
      {/* Search and Filters */}
      <div className="card" style={{ padding: '12px 16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', flexWrap: 'wrap' }}>
          {/* Tool Selector Pills */}
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', alignItems: 'center' }}>
            {['all', 'nmap', 'nuclei', 'nikto', 'gobuster', 'zap', 'sqlmap', 'ffuf'].map(tool => (
              <button
                key={tool}
                onClick={() => setSelectedTool(tool)}
                className={`btn btn-sm ${selectedTool === tool ? 'btn-primary' : 'btn-secondary'}`}
                style={{ textTransform: 'uppercase', fontSize: '11px', padding: '4px 10px', height: '32px' }}
              >
                {tool}
              </button>
            ))}
          </div>

          {/* Target Group & Host Search Controls */}
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
            {targetGroups.length > 0 && (
              <div style={{ position: 'relative', minWidth: '170px' }}>
                <select
                  className="form-select"
                  value={selectedGroupId}
                  onChange={(e) => setSelectedGroupId(e.target.value)}
                  style={{
                    height: '32px',
                    fontSize: '12px',
                    paddingRight: '28px',
                    background: 'var(--bg-surface, #ffffff)',
                    border: '1px solid var(--border-default, #cbd5e1)',
                    color: 'var(--text-primary, #0f172a)'
                  }}
                >
                  <option value="">All Target Groups</option>
                  {targetGroups.map(g => (
                    <option key={g.id} value={g.id}>🟣 {g.name}</option>
                  ))}
                </select>
              </div>
            )}

            <div style={{ position: 'relative', width: '200px' }}>
              <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)', pointerEvents: 'none' }} />
              <input
                type="text"
                className="form-input"
                placeholder="Filter by target host..."
                value={targetFilter}
                onChange={(e) => setTargetFilter(e.target.value)}
                style={{
                  height: '32px',
                  fontSize: '12px',
                  paddingLeft: '30px',
                  background: 'var(--bg-surface, #ffffff)',
                  border: '1px solid var(--border-default, #cbd5e1)',
                  color: 'var(--text-primary, #0f172a)'
                }}
              />
            </div>

            <button
              className="btn btn-secondary btn-sm"
              onClick={fetchHistoryAndTrends}
              style={{ height: '32px', padding: '0 10px', display: 'flex', alignItems: 'center', gap: '4px' }}
              title="Refresh History"
            >
              <RefreshCw size={13} className={loading ? 'spin' : ''} />
            </button>
          </div>
        </div>
      </div>

      {/* Historical Trends Split Dashboard */}
      <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap' }}>
        {renderLeftWidget()}
        {renderRightWidget()}
      </div>

      {/* Scan History Table */}
      <div className="card">
        <h4 style={{ padding: '1.25rem 1.25rem 0.5rem', fontWeight: 600, color: 'var(--text-primary)' }}>Scan Run Logs</h4>
        {loading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: '3rem' }}>
            <div className="spinner">Loading scan logs...</div>
          </div>
        ) : filteredHistory.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
            No scan logs captured yet. Execute a scan tab to register history database runs.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '0.85rem 1.25rem', textAlign: 'left' }}>Tool</th>
                  <th style={{ padding: '0.85rem 1.25rem', textAlign: 'left' }}>Target</th>
                  <th style={{ padding: '0.85rem 1.25rem', textAlign: 'left' }}>Scan Type / Policy</th>
                  <th style={{ padding: '0.85rem 1.25rem', textAlign: 'left' }}>Run Date (UTC)</th>
                  <th style={{ padding: '0.85rem 1.25rem', textAlign: 'left' }}>Findings Summary</th>
                  <th style={{ padding: '0.85rem 1.25rem', textAlign: 'center' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredHistory.map((item) => (
                  <tr
                    key={item.id}
                    onClick={() => handleViewDetail(item)}
                    style={{ borderBottom: '1px solid var(--border-subtle)', cursor: 'pointer', transition: 'background 0.15s' }}
                    className="hover-row"
                  >
                    <td style={{ padding: '0.85rem 1.25rem', fontWeight: 600, color: 'var(--violet-300)', textTransform: 'uppercase' }}>
                      {item.tool}
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem', fontFamily: 'monospace', color: 'var(--text-primary)' }}>
                      {item.target}
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem', color: 'var(--text-secondary)' }}>
                      {item.scan_type || '—'}
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem', color: 'var(--text-muted)' }}>
                      {item.timestamp ? item.timestamp.replace('T', ' ').substring(0, 19) : '—'}
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem' }}>
                      {renderSummaryBadge(item)}
                    </td>
                    <td style={{ padding: '0.85rem 1.25rem', textAlign: 'center' }}>
                      <div style={{ display: 'inline-flex', gap: '0.4rem', justifyContent: 'center', alignItems: 'center' }}>
                        <button
                          className="btn btn-secondary btn-sm"
                          style={{ padding: '4px 8px', borderRadius: '5px' }}
                          title="View details"
                          onClick={() => handleViewDetail(item)}
                        >
                          <Eye size={13} />
                        </button>
                        <button
                          className="btn btn-primary btn-sm"
                          style={{ padding: '4px 8px', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '3px', borderRadius: '5px', fontWeight: 600 }}
                          title="Download VAPT Audit Report (PDF)"
                          onClick={(e) => handleDownloadReport(e, item.id, item.tool, 'pdf')}
                          disabled={downloadingReportId === `${item.id}-pdf`}
                        >
                          {downloadingReportId === `${item.id}-pdf` ? <Loader2 size={11} className="spin" /> : <FileText size={11} />}
                          PDF
                        </button>
                        <button
                          className="btn btn-secondary btn-sm"
                          style={{ padding: '4px 8px', fontSize: '11px', display: 'flex', alignItems: 'center', gap: '3px', borderRadius: '5px' }}
                          title="Download Audit Report (HTML)"
                          onClick={(e) => handleDownloadReport(e, item.id, item.tool, 'html')}
                          disabled={downloadingReportId === `${item.id}-html`}
                        >
                          {downloadingReportId === `${item.id}-html` ? <Loader2 size={11} className="spin" /> : <Download size={11} />}
                          HTML
                        </button>
                        <button
                          className="btn btn-ghost btn-sm"
                          style={{ padding: '4px 8px', color: 'var(--red-400)', borderRadius: '5px' }}
                          onClick={(e) => handleDelete(e, item.id)}
                          title="Delete log"
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

      {/* Detail Modal Overlay */}
      {selectedScan && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(4px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          zIndex: 1000,
          padding: '1rem'
        }}>
          <div style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '12px',
            width: '100%',
            maxWidth: '750px',
            maxHeight: '90vh',
            display: 'flex', flexDirection: 'column',
            overflow: 'hidden',
            boxShadow: '0 20px 25px -5px rgba(0,0,0,0.1)'
          }}>
            {/* Modal Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '1rem 1.25rem', borderBottom: '1px solid var(--border-subtle)' }}>
              <div>
                <h3 style={{ margin: 0, color: 'var(--text-primary)', fontWeight: 600 }}>Scan Log Details</h3>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  ID: {selectedScan.id} • {formatToolName(selectedScan.tool)} • {selectedScan.target}
                </span>
              </div>
              <button
                onClick={() => setSelectedScan(null)}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X size={20} />
              </button>
            </div>

            {/* Modal Content */}
            <div style={{ overflowY: 'auto', padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              {loadingDetail ? (
                <div style={{ display: 'flex', justifyContent: 'center', padding: '3rem' }}>
                  <div className="spinner">Fetching detailed scan report...</div>
                </div>
              ) : !scanDetail ? (
                <div style={{ textAlign: 'center', color: 'var(--red-400)' }}>Failed to load scan report.</div>
              ) : (
                <>
                  {/* Summary and Chart Row */}
                  <div style={{ display: 'flex', flexDirection: 'row', gap: '1.5rem', flexWrap: 'wrap' }}>
                    <div style={{ flex: 1, minWidth: '240px', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                      <h4 style={{ margin: 0, fontSize: '1rem', color: 'var(--text-primary)', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.25rem' }}>Metadata</h4>
                      <table style={{ width: '100%', fontSize: '0.85rem' }}>
                        <tbody>
                          <tr><td style={{ color: 'var(--text-muted)', padding: '4px 0' }}>Target:</td><td style={{ color: 'var(--text-primary)', fontWeight: 600, fontFamily: 'monospace' }}>{scanDetail.target}</td></tr>
                          <tr><td style={{ color: 'var(--text-muted)', padding: '4px 0' }}>Scan Type:</td><td style={{ color: 'var(--text-primary)' }}>{scanDetail.scan_type || 'default'}</td></tr>
                          <tr><td style={{ color: 'var(--text-muted)', padding: '4px 0' }}>Date Run:</td><td style={{ color: 'var(--text-primary)' }}>{scanDetail.timestamp}</td></tr>
                          <tr><td style={{ color: 'var(--text-muted)', padding: '4px 0' }}>Status:</td><td><span className={`badge ${scanDetail.status === 'completed' ? 'badge-info' : 'badge-high'}`}>{scanDetail.status}</span></td></tr>
                        </tbody>
                      </table>
                    </div>

                    {/* Chart Container */}
                    {getDetailChartData(scanDetail).length > 0 && (
                      <div className="card" style={{ flex: 1, minWidth: '280px', padding: '0.85rem', background: 'var(--bg-base)', border: '1px solid var(--border-subtle)', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                        <h4 style={{ margin: '0 0 0.5rem', fontSize: '0.9rem', color: 'var(--text-primary)' }}>Scan Metrics</h4>
                        <DonutChart data={getDetailChartData(scanDetail)} title="Findings" />
                      </div>
                    )}
                  </div>

                  {/* Detailed Table */}
                  <div>
                    <h4 style={{ margin: '0 0 0.5rem', fontSize: '1rem', color: 'var(--text-primary)', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.25rem' }}>Findings Output</h4>
                    
                    {/* Render specific details for tool */}
                    {scanDetail.tool === 'nmap' && (
                      <div style={{ marginTop: '12px' }}>
                        <PortMatrixView results={scanDetail.results} host={scanDetail.target} />
                      </div>
                    )}

                    {scanDetail.tool === 'gobuster' && (
                      <div style={{ overflowX: 'auto' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem' }}>
                          <thead>
                            <tr style={{ color: 'var(--text-muted)', borderBottom: '1px solid var(--border-subtle)' }}>
                              <th style={{ padding: '6px', textAlign: 'left' }}>Path</th>
                              <th style={{ padding: '6px', textAlign: 'left' }}>Status</th>
                              <th style={{ padding: '6px', textAlign: 'left' }}>Size</th>
                              <th style={{ padding: '6px', textAlign: 'left' }}>Redirect</th>
                            </tr>
                          </thead>
                          <tbody>
                            {scanDetail.results.map((r, idx) => (
                              <tr key={idx} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                                <td style={{ padding: '6px', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'monospace' }}>{r.path}</td>
                                <td style={{ padding: '6px' }}><span className={`badge ${r.status >= 200 && r.status < 300 ? 'badge-info' : 'badge-medium'}`}>{r.status}</span></td>
                                <td style={{ padding: '6px', color: 'var(--text-muted)' }}>{r.size} B</td>
                                <td style={{ padding: '6px', color: 'var(--violet-600)', fontFamily: 'monospace' }}>{r.redirect || '—'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}

                    {(scanDetail.tool === 'nuclei' || scanDetail.tool === 'zap') && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                        {scanDetail.results.map((vuln, idx) => {
                          const name = scanDetail.tool === 'nuclei' ? vuln.info?.name : vuln.alert;
                          const severity = scanDetail.tool === 'nuclei' ? vuln.info?.severity : vuln.risk;
                          const url = scanDetail.tool === 'nuclei' ? vuln['matched-at'] : vuln.url;
                          const description = vuln.description || vuln.info?.description;
                          const solution = vuln.solution || vuln.info?.remediation;

                          return (
                            <div key={idx} style={{ border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '0.75rem', background: 'var(--bg-base)' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                                <strong style={{ color: 'var(--text-primary)', fontSize: '0.85rem' }}>{name}</strong>
                                <span className={`badge ${severity?.toLowerCase() in {high: 1, critical: 1} ? 'badge-high' : severity?.toLowerCase() === 'medium' ? 'badge-medium' : 'badge-low'}`}>
                                  {severity}
                                </span>
                              </div>
                              {url && <div style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: 'var(--violet-600)', marginBottom: '0.4rem' }}>{url}</div>}
                              {description && <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', margin: '0 0 0.4rem' }}>{description}</p>}
                              {solution && <p style={{ fontSize: '0.75rem', color: 'var(--emerald-500)', margin: 0 }}><strong>Fix:</strong> {solution}</p>}
                            </div>
                          );
                        })}
                      </div>
                    )}

                    {scanDetail.tool === 'nikto' && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                        {((scanDetail.results || {}).vulnerabilities || []).map((v, idx) => (
                          <div key={idx} style={{ padding: '0.5rem', background: 'var(--bg-base)', border: '1px solid var(--border-subtle)', borderRadius: '4px', fontSize: '0.8rem', color: 'var(--text-primary)' }}>
                            {v.msg}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </>
              )}
            </div>

            {/* Modal Footer */}
            <div style={{ padding: '0.85rem 1.25rem', borderTop: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--bg-base)' }}>
              <div>
                {selectedScan && (
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    <button
                      className="btn btn-primary btn-sm"
                      onClick={(e) => handleDownloadReport(e, selectedScan.id, selectedScan.tool, 'pdf')}
                      disabled={downloadingReportId === `${selectedScan.id}-pdf`}
                    >
                      {downloadingReportId === `${selectedScan.id}-pdf` ? <Loader2 size={13} className="spin" /> : <FileText size={13} />}
                      Download VAPT Report (PDF)
                    </button>
                    <button
                      className="btn btn-secondary btn-sm"
                      onClick={(e) => handleDownloadReport(e, selectedScan.id, selectedScan.tool, 'html')}
                      disabled={downloadingReportId === `${selectedScan.id}-html`}
                    >
                      {downloadingReportId === `${selectedScan.id}-html` ? <Loader2 size={13} className="spin" /> : <Download size={13} />}
                      Download HTML
                    </button>
                  </div>
                )}
              </div>
              <button className="btn btn-secondary" onClick={() => setSelectedScan(null)}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
