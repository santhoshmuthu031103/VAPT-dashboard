import { useState, useEffect } from 'react';
import { Search, RefreshCw, AlertTriangle } from 'lucide-react';

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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.8rem', marginBottom: '0.5rem' }}>CVE Library</h2>
          <p>Search and browse Common Vulnerabilities and Exposures (CVEs) straight from the OpenVAS database.</p>
        </div>
      </div>

      <div className="panel" style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        <form onSubmit={handleSearch} style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
          <div style={{ position: 'relative', flex: 1 }}>
            <Search size={18} className="text-muted" style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)' }} />
            <input 
              type="text" 
              placeholder="Search CVEs (e.g. Log4j, CVE-2021-44228)..." 
              value={searchTerm} 
              onChange={e => setSearchTerm(e.target.value)} 
              style={{ paddingLeft: '2.5rem' }} 
            />
          </div>
          <button type="submit" className="btn btn-primary" disabled={loading}>
            Search
          </button>
        </form>

        {loading ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '3rem', gap: '1rem' }}>
            <RefreshCw className="animate-spin-slow" size={32} style={{ color: 'var(--accent-cyan)' }} />
            <span className="text-secondary">Querying CVE database...</span>
          </div>
        ) : error ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '2rem', border: '1px solid var(--severity-high)', borderRadius: '8px', backgroundColor: 'var(--severity-high-dim)' }}>
            <AlertTriangle size={24} style={{ color: 'var(--severity-high)', flexShrink: 0 }} />
            <div><h4 style={{ color: 'var(--severity-high)' }}>Error Loading CVEs</h4><p style={{ fontSize: '0.9rem' }}>{error}</p></div>
          </div>
        ) : (
          <>
            <div className="table-container">
              <table>
                <thead>
                  <tr>
                    <th style={{ width: '150px' }}>CVE ID</th>
                    <th style={{ width: '80px', textAlign: 'center' }}>Severity</th>
                    <th>Description</th>
                    <th style={{ width: '150px' }}>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {cves.length === 0 ? (
                    <tr><td colSpan={4} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>No CVEs found matching your search.</td></tr>
                  ) : cves.map((c, i) => (
                    <tr key={c.id || c.name || i}>
                      <td style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>{c.name}</td>
                      <td style={{ textAlign: 'center' }}>
                        {c.severity ? (
                          <span className={parseFloat(c.severity) >= 7.0 ? 'badge badge-high' : parseFloat(c.severity) >= 4.0 ? 'badge badge-medium' : 'badge badge-low'}>
                            {c.severity}
                          </span>
                        ) : '—'}
                      </td>
                      <td style={{ fontSize: '0.9rem' }}>{c.description || 'No description available.'}</td>
                      <td style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                        {c.creation_time ? new Date(c.creation_time).toLocaleDateString() : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            
            {totalPages > 1 && (
              <div style={{ display: 'flex', justifyContent: 'center', gap: '1rem', alignItems: 'center', paddingTop: '0.5rem' }}>
                <button className="btn btn-secondary" disabled={page <= 1} onClick={() => setPage(p => Math.max(p - 1, 1))}>← Prev</button>
                <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>Page {page} of {totalPages} ({total} CVEs)</span>
                <button className="btn btn-secondary" disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}>Next →</button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
