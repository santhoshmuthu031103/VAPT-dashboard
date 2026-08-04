import React, { useState } from 'react';
import { Terminal, Shield, List, Search } from 'lucide-react';
import './ToolScanners.css';

function ToolScanners({ apiBase }) {
  const [host, setHost] = useState('');
  const [activeTab, setActiveTab] = useState('nuclei');
  
  // State for each tool's output to keep them independent
  const [outputs, setOutputs] = useState({
    nuclei: [],
    nikto: [],
    gobuster: []
  });
  const [zapResults, setZapResults] = useState([]);
  
  const [isScanning, setIsScanning] = useState({
    nuclei: false,
    nikto: false,
    gobuster: false,
    zap: false
  });

  const startScan = async () => {
    if (!host) {
      alert("Please enter a target host or URL.");
      return;
    }
    
    // Set scanning state for current tab
    setIsScanning(prev => ({ ...prev, [activeTab]: true }));
    
    if (activeTab === 'zap') {
      setZapResults([]);
      try {
        const response = await fetch(`${apiBase}/api/scanners/zap/results?host=${encodeURIComponent(host)}`);
        const data = await response.json();
        setZapResults(data);
      } catch (err) {
        console.error("ZAP Error:", err);
      } finally {
        setIsScanning(prev => ({ ...prev, [activeTab]: false }));
      }
    } else {
      // Clear current tab output
      setOutputs(prev => ({ ...prev, [activeTab]: [] }));
      
      const eventSource = new EventSource(`${apiBase}/api/scanners/${activeTab}/stream?host=${encodeURIComponent(host)}`);
      
      eventSource.onmessage = (event) => {
        setOutputs(prev => ({ 
          ...prev, 
          [activeTab]: [...prev[activeTab], event.data] 
        }));
      };
      
      eventSource.onerror = (error) => {
        console.log(`EventSource failed for ${activeTab}:`, error);
        eventSource.close();
        setIsScanning(prev => ({ ...prev, [activeTab]: false }));
      };
    }
  };

  const clearOutput = () => {
    if (activeTab === 'zap') {
      setZapResults([]);
    } else {
      setOutputs(prev => ({ ...prev, [activeTab]: [] }));
    }
  };

  return (
    <div className="tool-scanners-container">
      <div className="header-section" style={{ marginBottom: '1rem' }}>
        <h1 style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>Specialized Web Scanners</h1>
        <p>Run targeted open-source tools against specific hosts with real-time feedback.</p>
      </div>

      <div className="panel" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        {/* Input & Controls */}
        <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: '300px' }}>
            <label style={{ display: 'block', marginBottom: '0.5rem', color: 'var(--text-secondary)' }}>
              Target Host/URL
            </label>
            <input 
              type="text" 
              placeholder="e.g., example.com or http://192.168.1.100" 
              value={host}
              onChange={(e) => setHost(e.target.value)}
              disabled={isScanning[activeTab]}
            />
          </div>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button 
              className="btn btn-primary" 
              onClick={startScan} 
              disabled={isScanning[activeTab] || !host}
            >
              {isScanning[activeTab] ? 'Scanning...' : 'Start Scan'}
            </button>
            <button 
              className="btn btn-secondary" 
              onClick={clearOutput}
              disabled={isScanning[activeTab]}
            >
              Clear Output
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="scanner-tabs">
          <button 
            className={`scanner-tab ${activeTab === 'nuclei' ? 'active' : ''}`}
            onClick={() => setActiveTab('nuclei')}
          >
            <Terminal size={16} /> Nuclei
          </button>
          <button 
            className={`scanner-tab ${activeTab === 'nikto' ? 'active' : ''}`}
            onClick={() => setActiveTab('nikto')}
          >
            <List size={16} /> Nikto
          </button>
          <button 
            className={`scanner-tab ${activeTab === 'gobuster' ? 'active' : ''}`}
            onClick={() => setActiveTab('gobuster')}
          >
            <Search size={16} /> Gobuster
          </button>
          <button 
            className={`scanner-tab ${activeTab === 'zap' ? 'active' : ''}`}
            onClick={() => setActiveTab('zap')}
          >
            <Shield size={16} /> OWASP ZAP
          </button>
        </div>

        {/* Tab Content */}
        <div className="scanner-content">
          {activeTab === 'zap' ? (
            <div className="zap-container">
              {zapResults.length === 0 ? (
                <div className="empty-state">No ZAP alerts yet. Run a scan to see results.</div>
              ) : (
                <div className="alerts-grid">
                  {zapResults.map((alert, idx) => (
                    <div key={idx} className="alert-card">
                      <div className={`badge badge-${alert.risk.toLowerCase() === 'high' ? 'high' : alert.risk.toLowerCase() === 'medium' ? 'medium' : 'low'}`}>
                        {alert.risk} Risk
                      </div>
                      <h3 style={{ marginTop: '0.5rem' }}>{alert.alert}</h3>
                      <p style={{ margin: '0.5rem 0' }}><strong>URL:</strong> {alert.url}</p>
                      <p style={{ color: 'var(--text-primary)', fontSize: '0.9rem' }}>{alert.description}</p>
                      <div style={{ marginTop: 'auto', paddingTop: '1rem', borderTop: '1px solid var(--border-subtle)' }}>
                        <span style={{ fontSize: '0.85rem', color: 'var(--accent-cyan)' }}>Solution: </span>
                        <span style={{ fontSize: '0.85rem' }}>{alert.solution}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="terminal-console">
              {outputs[activeTab].length === 0 ? (
                <div style={{ color: 'var(--text-muted)', fontStyle: 'italic', padding: '1rem' }}>
                  Ready to scan with {activeTab.toUpperCase()}. Output will stream here...
                </div>
              ) : (
                outputs[activeTab].map((line, idx) => (
                  <div key={idx} className="terminal-line">{line}</div>
                ))
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default ToolScanners;
