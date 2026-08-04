import React, { useState } from 'react';
import './ToolScanners.css'; // Optional: if we want specific styling

function ToolScanners() {
  const [host, setHost] = useState('');
  const [selectedTool, setSelectedTool] = useState('nuclei');
  const [scanOutput, setScanOutput] = useState([]);
  const [zapResults, setZapResults] = useState([]);
  const [isScanning, setIsScanning] = useState(false);

  const startScan = async () => {
    if (!host) {
      alert("Please enter a target host or URL.");
      return;
    }
    
    setIsScanning(true);
    setScanOutput([]);
    setZapResults([]);
    
    if (selectedTool === 'zap') {
      try {
        const response = await fetch(`http://localhost:8000/api/scanners/zap/results?host=${encodeURIComponent(host)}`);
        const data = await response.json();
        setZapResults(data);
      } catch (err) {
        setScanOutput([`Error fetching ZAP results: ${err}`]);
      } finally {
        setIsScanning(false);
      }
    } else {
      // SSE Stream for Nuclei, Nikto, Gobuster
      const eventSource = new EventSource(`http://localhost:8000/api/scanners/${selectedTool}/stream?host=${encodeURIComponent(host)}`);
      
      eventSource.onmessage = (event) => {
        setScanOutput(prev => [...prev, event.data]);
      };
      
      eventSource.onerror = (error) => {
        console.log("EventSource failed:", error);
        eventSource.close();
        setIsScanning(false);
      };
    }
  };

  const clearOutput = () => {
    setScanOutput([]);
    setZapResults([]);
  };

  return (
    <div className="tool-scanners-container">
      <div className="header-section">
        <h1 className="page-title">Specialized Web Scanners</h1>
        <p className="page-subtitle">Run targeted open-source tools against specific hosts</p>
      </div>

      <div className="scan-controls glass-panel">
        <div className="control-group">
          <label>Target Host/URL</label>
          <input 
            type="text" 
            placeholder="e.g., example.com or http://192.168.1.100" 
            value={host}
            onChange={(e) => setHost(e.target.value)}
            disabled={isScanning}
          />
        </div>
        
        <div className="control-group">
          <label>Select Tool</label>
          <select 
            value={selectedTool} 
            onChange={(e) => setSelectedTool(e.target.value)}
            disabled={isScanning}
          >
            <option value="nuclei">Nuclei (Vulnerability Scanner)</option>
            <option value="nikto">Nikto (Web Server Scanner)</option>
            <option value="gobuster">Gobuster (Directory Bruteforcing)</option>
            <option value="zap">OWASP ZAP (Web App Proxy/Scanner)</option>
          </select>
        </div>
        
        <div className="button-group">
          <button 
            className="primary-btn" 
            onClick={startScan} 
            disabled={isScanning || !host}
          >
            {isScanning ? 'Scanning...' : 'Start Scan'}
          </button>
          <button 
            className="secondary-btn" 
            onClick={clearOutput}
            disabled={isScanning}
          >
            Clear Output
          </button>
        </div>
      </div>

      <div className="results-container">
        {selectedTool === 'zap' && zapResults.length > 0 ? (
          <div className="zap-alerts glass-panel">
            <h2>ZAP Alerts Found ({zapResults.length})</h2>
            <div className="alerts-grid">
              {zapResults.map((alert, idx) => (
                <div key={idx} className="alert-card">
                  <div className={`risk-badge risk-${alert.risk.toLowerCase()}`}>{alert.risk}</div>
                  <h3>{alert.alert}</h3>
                  <p><strong>URL:</strong> {alert.url}</p>
                  <p><strong>Description:</strong> {alert.description}</p>
                  <p><strong>Solution:</strong> {alert.solution}</p>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="terminal-window">
            <div className="terminal-header">
              <span className="dot red"></span>
              <span className="dot yellow"></span>
              <span className="dot green"></span>
              <span className="terminal-title">{selectedTool.toUpperCase()} Output</span>
            </div>
            <div className="terminal-body">
              {scanOutput.length === 0 ? (
                <div className="terminal-placeholder">Ready to scan. Output will appear here...</div>
              ) : (
                scanOutput.map((line, idx) => (
                  <div key={idx} className="terminal-line">{line}</div>
                ))
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default ToolScanners;
