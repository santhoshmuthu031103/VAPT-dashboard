import React, { useState, useEffect, useRef } from 'react';
import { Terminal, Shield, RefreshCw, AlertTriangle, CheckCircle, Search, Cpu, FileText, Download, Loader2 } from 'lucide-react';
import { BarChart } from './SvgCharts';
import TargetSelector from './TargetSelector';

import PortMatrixView from './PortMatrixView';

import { triggerFileDownload } from '../utils/downloadHelper';

export default function Nmap({ apiBase, defaultHost = '127.0.0.1' }) {
  const [host, setHost] = useState(defaultHost);
  const [scanType, setScanType] = useState('quick');
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState(null);

  // Raw streaming logs
  const [logs, setLogs] = useState([]);
  // Parsed open ports
  const [results, setResults] = useState([]);
  const [loadingResults, setLoadingResults] = useState(false);
  const [downloadingReport, setDownloadingReport] = useState(null);

  const downloadReport = async (fmt = 'pdf') => {
    if (!results || results.length === 0) return;
    setDownloadingReport(fmt);
    try {
      const res = await fetch(`${apiBase}/api/scanners/report/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tool: 'nmap',
          target_url: host,
          results: results,
          format: fmt,
          metadata: {
            app_name: host,
            doc_title: 'Network Infrastructure & Port Security Audit Report',
            organization: 'Security Operations'
          }
        })
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`Report generation failed (${res.status}): ${errText}`);
      }
      const blob = await res.blob();
      triggerFileDownload(blob, `vapt-nmap-audit-${host.replace(/[^a-zA-Z0-9.-]/g, '_')}.${fmt}`);
    } catch (err) {
      alert(`Report download error: ${err.message}`);
    } finally {
      setDownloadingReport(null);
    }
  };

  const eventSourceRef = useRef(null);
  const terminalEndRef = useRef(null);

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  // Clean up SSE connection on unmount
  useEffect(() => {
    return () => {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
      }
    };
  }, []);

  const handleStartScan = (e) => {
    e.preventDefault();
    if (!host) return;

    setScanning(true);
    setError(null);
    setLogs([]);
    setResults([]);

    // 1. Establish SSE EventSource to stream raw nmap output
    const sseUrl = `${apiBase}/api/nmap/scan?host=${encodeURIComponent(host)}&scan_type=${encodeURIComponent(scanType)}`;
    
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    const eventSource = new EventSource(sseUrl);
    eventSourceRef.current = eventSource;

    eventSource.onmessage = (event) => {
      // Append raw line
      setLogs((prev) => [...prev, event.data]);
      
      // Check if multi-target scan or single scan completed
      if (event.data.includes("[VAPT-NMAP-COMPLETE]") || (event.data.includes("Nmap done:") && !host.includes(",") && !host.includes(" "))) {
        eventSource.close();
        setScanning(false);
        fetchParsedResults();
      }
    };

    eventSource.onerror = (err) => {
      // If server finished stream or connection closed
      if (eventSource.readyState === EventSource.CLOSED || eventSource.readyState === 2) {
        eventSource.close();
        setScanning(false);
        fetchParsedResults();
        return;
      }
      console.error("SSE Connection Error:", err);
      eventSource.close();
      setScanning(false);
      fetchParsedResults();
    };
  };

  const fetchParsedResults = async () => {
    setLoadingResults(true);
    try {
      const res = await fetch(`${apiBase}/api/nmap/results?host=${encodeURIComponent(host)}&scan_type=${encodeURIComponent(scanType)}`);
      if (!res.ok) throw new Error('Failed to retrieve parsed Nmap services.');
      const data = await res.json();
      setResults(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoadingResults(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Target form */}
      <div className="card" style={{ position: 'relative', zIndex: 10 }}>
        <form onSubmit={handleStartScan} className="card-body" style={{ display: 'flex', flexWrap: 'wrap', gap: '1.5rem', alignItems: 'flex-end', padding: '20px' }}>
          <div style={{ flex: 2, minWidth: '220px' }} className="form-group">
            <label className="form-label">Target Host / Network IP / Group</label>
            <TargetSelector
              value={host}
              onChange={(val) => setHost(val)}
              placeholder="e.g. 192.168.1.1 or choose Target Group..."
              apiBase={apiBase}
              disabled={scanning}
              required
            />
          </div>

          <div style={{ flex: 1, minWidth: '180px' }} className="form-group">
            <label className="form-label">Scan Mode Profile</label>
            <select className="form-select" value={scanType} onChange={(e) => setScanType(e.target.value)} disabled={scanning}>
              <option value="quick">Quick Scan (Fast Common Ports)</option>
              <option value="service">Service Mapping (-sV on common ports)</option>
              <option value="os">OS Fingerprinting (-O detection)</option>
              <option value="full">Full Audit Scan (Deep Port Range + OS + SV)</option>
              <option value="stealth">Stealth SYN Scan (-sS -T2)</option>
              <option value="udp">UDP Scan (-sU -F)</option>
              <option value="all_ports">All Ports Scan (-p- -sV)</option>
              <option value="vuln">Vulnerability Scripts (--script vuln)</option>
              <option value="aggressive">Aggressive Scan (-A)</option>
            </select>
          </div>

          <button type="submit" className="btn btn-primary" style={{ height: '36px', minWidth: '160px' }} disabled={scanning || !host}>
            {scanning ? <RefreshCw className="spinner" size={14} /> : <Terminal size={14} />}
            {scanning ? 'Audit Scanning...' : 'Launch Nmap Scan'}
          </button>
        </form>
      </div>

      {/* Double Column Display: Live Terminal Stream + Parsed Services Results */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))', gap: '1.5rem', alignItems: 'start' }}>
        
        {/* Live Terminal Stream Panel */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              <Terminal size={14} style={{ color: 'var(--violet-300)' }} /> Real-time Stdout Terminal
            </span>
          </div>
          <div className="card-body" style={{ padding: '20px' }}>
            <div className="terminal-console" style={{ minHeight: '350px', maxHeight: '550px', overflowY: 'auto' }}>
              {logs.length === 0 ? (
                <div className="text-muted" style={{ display: 'flex', height: '100%', alignItems: 'center', justifyContent: 'center', minHeight: '200px' }}>
                  Waiting to capture stdout stream...
                </div>
              ) : (
                logs.map((line, idx) => {
                  const isError = line.startsWith("[VAPT-NMAP-ERROR]");
                  const isHeader = line.startsWith("[VAPT-NMAP]");
                  let className = "terminal-line";
                  if (isError) className += " error";
                  else if (isHeader) className += " info";
                  
                  return (
                    <div key={idx} className={className}>
                      {line}
                    </div>
                  );
                })
              )}
              <div ref={terminalEndRef} />
            </div>
          </div>
        </div>

        {/* Parsed Open Ports Results Panel */}
        <div className="card">
          <div className="card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
            <span className="card-title">
              <Cpu size={14} style={{ color: 'var(--violet-300)' }} /> Interactive Port & Service Matrix
            </span>
            {results && results.length > 0 && !loadingResults && (
              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  className="btn btn-primary btn-sm"
                  onClick={() => downloadReport('pdf')}
                  disabled={!!downloadingReport}
                  style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11px', padding: '4px 10px', borderRadius: '5px' }}
                >
                  {downloadingReport === 'pdf' ? <Loader2 size={12} className="spin" /> : <FileText size={12} />}
                  PDF Report
                </button>
                <button
                  className="btn btn-secondary btn-sm"
                  onClick={() => downloadReport('html')}
                  disabled={!!downloadingReport}
                  style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11px', padding: '4px 10px', borderRadius: '5px' }}
                >
                  {downloadingReport === 'html' ? <Loader2 size={12} className="spin" /> : <Download size={12} />}
                  HTML Report
                </button>
              </div>
            )}
          </div>
          <div className="card-body" style={{ padding: '20px' }}>
            {loadingResults ? (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', height: '350px', justifyContent: 'center', gap: '1rem' }}>
                <RefreshCw className="spinner" size={32} style={{ color: 'var(--violet-400)' }} />
                <span className="text-secondary">Synthesizing network service details...</span>
              </div>
            ) : error ? (
              <div className="error-message">
                <AlertTriangle size={14} />
                <span>{error}</span>
              </div>
            ) : results.length === 0 ? (
              <div className="empty-state" style={{ display: 'flex', height: '350px', alignItems: 'center', justifyContent: 'center', borderStyle: 'dashed' }}>
                <Search size={36} style={{ marginBottom: '0.75rem', strokeWidth: 1.5 }} />
                <h4>No Services Discovered Yet</h4>
                <p style={{ fontSize: '0.85rem' }}>Run an Nmap scan above to generate the visual port & risk matrix.</p>
              </div>
            ) : (
              <PortMatrixView results={results} host={host} />
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

