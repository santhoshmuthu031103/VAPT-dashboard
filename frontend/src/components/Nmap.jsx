import React, { useState, useEffect, useRef } from 'react';
import { Terminal, Shield, RefreshCw, AlertTriangle, CheckCircle, Search, Cpu } from 'lucide-react';

export default function Nmap({ apiBase }) {
  const [host, setHost] = useState('127.0.0.1');
  const [scanType, setScanType] = useState('quick');
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState(null);

  // Raw streaming logs
  const [logs, setLogs] = useState([]);
  // Parsed open ports
  const [results, setResults] = useState([]);
  const [loadingResults, setLoadingResults] = useState(false);

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
      
      // Check if scan completed in mock or standard logs
      if (event.data.includes("Nmap done:") || event.data.includes("[VAPT-NMAP-ERROR]")) {
        eventSource.close();
        setScanning(false);
        fetchParsedResults(); // grab the parsed results once complete!
      }
    };

    eventSource.onerror = (err) => {
      console.error("SSE Connection Error:", err);
      setLogs((prev) => [...prev, "[VAPT-NMAP-ERROR] Event stream connection lost."]);
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
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      <div>
        <h2 style={{ fontSize: '1.8rem', marginBottom: '0.5rem' }}>Nmap Port Scanner</h2>
        <p>Perform live port scanning, service mapping, and operating system detection on targeted nodes.</p>
      </div>

      {/* Target form */}
      <div className="panel">
        <form onSubmit={handleStartScan} style={{ display: 'flex', flexWrap: 'wrap', gap: '1.5rem', alignItems: 'flex-end' }}>
          <div style={{ flex: 2, minWidth: '220px' }}>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Target Host / Network IP / Domain</label>
            <input 
              type="text" 
              placeholder="e.g. 192.168.1.1, scanme.nmap.org" 
              value={host} 
              onChange={(e) => setHost(e.target.value)} 
              required
              disabled={scanning}
            />
          </div>

          <div style={{ flex: 1, minWidth: '180px' }}>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Scan Mode Profile</label>
            <select value={scanType} onChange={(e) => setScanType(e.target.value)} disabled={scanning}>
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

          <button type="submit" className="btn btn-primary" style={{ height: '44px', minWidth: '160px' }} disabled={scanning || !host}>
            {scanning ? <RefreshCw className="animate-spin-slow" size={16} /> : <Terminal size={16} />}
            {scanning ? 'Audit Scanning...' : 'Launch Nmap Scan'}
          </button>
        </form>
      </div>

      {/* Double Column Display: Live Terminal Stream + Parsed Services Results */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '1.5rem' }}>
        
        {/* Live Terminal Stream Panel */}
        <div className="panel" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Terminal size={18} className="text-secondary" /> Real-time Stdout Terminal
          </h3>
          
          <div className="terminal-console">
            {logs.length === 0 ? (
              <div className="text-muted" style={{ display: 'flex', height: '100%', alignItems: 'center', justifyContent: 'center' }}>
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

        {/* Parsed Open Ports Results Panel */}
        <div className="panel" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Cpu size={18} className="text-secondary" /> Discovered Services Table
          </h3>

          {loadingResults ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', height: '350px', justifyContent: 'center', gap: '1rem' }}>
              <RefreshCw className="animate-spin-slow" size={32} style={{ color: 'var(--accent-cyan)' }} />
              <span className="text-secondary">Synthesizing network service details...</span>
            </div>
          ) : error ? (
            <div style={{ padding: '1rem', border: '1px solid var(--severity-high)', borderRadius: '8px', backgroundColor: 'var(--severity-high-dim)', color: 'var(--severity-high)' }}>
              <AlertTriangle size={18} style={{ marginRight: '0.5rem', verticalAlign: 'middle' }} />
              {error}
            </div>
          ) : results.length === 0 ? (
            <div className="table-container" style={{ display: 'flex', height: '350px', alignItems: 'center', justifyContent: 'center', borderStyle: 'dashed' }}>
              <div style={{ textAlign: 'center', color: 'var(--text-muted)' }}>
                <Search size={36} style={{ marginBottom: '0.75rem', strokeWidth: 1.5 }} />
                <h4>No Services Discovered</h4>
                <p style={{ fontSize: '0.85rem' }}>Run a scan or select a different host range.</p>
              </div>
            </div>
          ) : (
            <div className="table-container" style={{ height: '350px', overflowY: 'auto' }}>
              <table>
                <thead>
                  <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>State</th>
                    <th>Service Name</th>
                    <th>Software Version</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((service, idx) => (
                    <tr key={idx}>
                      <td style={{ fontWeight: 'bold', color: 'var(--text-primary)' }}>{service.port}</td>
                      <td><code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>{service.protocol}</code></td>
                      <td>
                        <span className={`badge ${service.state === 'open' ? 'badge-log' : 'badge-medium'}`} style={{ padding: '0.15rem 0.4rem', fontSize: '0.7rem' }}>
                          {service.state}
                        </span>
                      </td>
                      <td style={{ color: 'var(--accent-cyan)' }}>{service.service}</td>
                      <td style={{ fontSize: '0.85rem' }}>{service.version || 'Unknown'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
