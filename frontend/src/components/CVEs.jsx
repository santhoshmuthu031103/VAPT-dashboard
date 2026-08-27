import { useState, useEffect } from 'react';
import { Search, RefreshCw, AlertTriangle, ChevronLeft, ChevronRight } from 'lucide-react';

export default function CVEs({ apiBase }) {
  const [cves, setCves] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  const [searchTerm, setSearchTerm] = useState('');
  const [page, setPage] = useState(1);
  const [limit] = useState(20);
  const [total, setTotal] = useState(0);

  const fetchCves = async () => {
    setLoading(true);
    setError(null);
    try {
      const url = new URL(`${apiBase}/api/cves`, window.location.origin);
      if (searchTerm) url.searchParams.append('search', searchTerm);
      url.searchParams.append('page', page);
      url.searchParams.append('limit', limit);
      
      const res = await fetch(url);
      if (!res.ok) throw new Error('Failed to retrieve CVEs');
      
      const data = await res.json();
      // Filter out empty items that might have crept in from XML parsing
      setCves((data.cves || []).filter(c => c.name));
      setTotal(data.total || 0);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCves();
  }, [page]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleSearch = (e) => {
    e.preventDefault();
    setPage(1);
    fetchCves();
  };

  const totalPages = Math.ceil(total / limit);

  const getSeverityBadge = (severityStr) => {
    if (!severityStr) return '—';
    const val = parseFloat(severityStr);
    if (isNaN(val)) return <span className="badge badge-info">{severityStr}</span>;
    if (val >= 9.0) return <span className="badge badge-critical">{val} CRITICAL</span>;
    if (val >= 7.0) return <span className="badge badge-high">{val} HIGH</span>;
    if (val >= 4.0) return <span className="badge badge-medium">{val} MEDIUM</span>;
    return <span className="badge badge-low">{val} LOW</span>;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }} className="fade-in">
      <div className="card">
        {/* Search Bar Block */}
        <div className="card-header" style={{ borderBottom: 'none', paddingBottom: 0 }}>
          <form onSubmit={handleSearch} style={{ display: 'flex', gap: '12px', alignItems: 'center', width: '100%' }}>
            <div style={{ position: 'relative', flex: 1 }}>
              <Search size={15} className="text-muted" style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)' }} />
              <input 
                type="text" 
                className="form-input"
                placeholder="Search CVEs (e.g. Log4j, CVE-2021-44228)..." 
                value={searchTerm} 
                onChange={e => setSearchTerm(e.target.value)} 
                style={{ paddingLeft: '32px' }} 
              />
            </div>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? <RefreshCw size={13} className="spin" /> : null}
              Search Library
            </button>
          </form>
        </div>

        {/* Content Area */}
        <div className="card-body">
          {loading ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '40px 0', gap: '12px' }}>
              <RefreshCw className="spin" size={24} style={{ color: 'var(--violet-400)' }} />
              <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>Querying OpenVAS vulnerability library...</span>
            </div>
          ) : error ? (
            <div className="alert alert-error">
              <AlertTriangle size={14} style={{ flexShrink: 0 }} />
              <div>
                <h4 style={{ fontWeight: 600, fontSize: 13 }}>Vulnerability Database Error</h4>
                <p style={{ fontSize: 12, marginTop: 2 }}>{error}</p>
              </div>
            </div>
          ) : (
            <>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th style={{ width: '160px' }}>CVE Identifier</th>
                      <th style={{ width: '110px', textAlign: 'center' }}>CVSS Severity</th>
                      <th>Description</th>
                      <th style={{ width: '130px' }}>Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {cves.length === 0 ? (
                      <tr>
                        <td colSpan={4} style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--text-muted)' }}>
                          No vulnerabilities found matching your search.
                        </td>
                      </tr>
                    ) : (
                      cves.map((c, i) => (
                        <tr key={c.id || c.name || i}>
                          <td className="td-mono" style={{ fontWeight: 600, color: 'var(--violet-300)', fontSize: 12 }}>
                            {c.name}
                          </td>
                          <td style={{ textAlign: 'center' }}>
                            {getSeverityBadge(c.severity)}
                          </td>
                          <td style={{ fontSize: '13px', color: 'var(--text-primary)' }}>
                            {c.description || 'No description summary available.'}
                          </td>
                          <td style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                            {c.creation_time ? new Date(c.creation_time).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : '—'}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
              
              {totalPages > 1 && (
                <div style={{ display: 'flex', justifyContent: 'center', gap: '16px', alignItems: 'center', marginTop: '20px' }}>
                  <button 
                    className="btn btn-secondary btn-sm" 
                    disabled={page <= 1} 
                    onClick={() => setPage(p => Math.max(p - 1, 1))}
                  >
                    <ChevronLeft size={13} /> Prev
                  </button>
                  <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                    Page {page} of {totalPages} <span style={{ color: 'var(--text-muted)', marginLeft: 4 }}>({total} CVE records)</span>
                  </span>
                  <button 
                    className="btn btn-secondary btn-sm" 
                    disabled={page >= totalPages} 
                    onClick={() => setPage(p => p + 1)}
                  >
                    Next <ChevronRight size={13} />
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
