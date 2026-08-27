import sqlite3
import json
import os
from datetime import datetime, timedelta

DB_DIR = "/root/vapt-dashboard/backend/data"
DB_PATH = os.path.join(DB_DIR, "vapt.db")

def seed_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Empty existing history first to start clean
    cursor.execute("DELETE FROM scan_history")
    
    # 1. Nmap Scans
    nmap_results_1 = [
        {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 8.9p1"},
        {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "nginx 1.18.0"}
    ]
    nmap_results_2 = nmap_results_1 + [
        {"port": 443, "protocol": "tcp", "state": "open", "service": "ssl/http", "version": "nginx 1.18.0"},
        {"port": 3306, "protocol": "tcp", "state": "open", "service": "mysql", "version": "MySQL 8.0.28"}
    ]
    
    # 2. Nuclei Scans
    nuclei_results_1 = [
        {"template-id": "tech-detect", "info": {"name": "Wappalyzer Technology Detection", "severity": "info"}, "type": "http", "host": "192.168.1.100", "matched-at": "http://192.168.1.100"},
        {"template-id": "exposed-panels", "info": {"name": "Exposed Login Panel", "severity": "low"}, "type": "http", "host": "192.168.1.100", "matched-at": "http://192.168.1.100/admin/"}
    ]
    nuclei_results_2 = nuclei_results_1 + [
        {"template-id": "CVE-2021-41773", "info": {"name": "Apache 2.4.49 - Path Traversal", "severity": "high"}, "type": "http", "host": "192.168.1.100", "matched-at": "http://192.168.1.100/cgi-bin/.%2e/.%2e/etc/passwd"},
        {"template-id": "subdomain-takeover", "info": {"name": "Subdomain Takeover", "severity": "medium"}, "type": "dns", "host": "192.168.1.100", "matched-at": "192.168.1.100"}
    ]

    # 3. Gobuster Scans
    gobuster_results_1 = [
        {"path": "/images", "status": 301, "size": 315, "redirect": "/images/"},
        {"path": "/robots.txt", "status": 200, "size": 26, "redirect": ""}
    ]
    gobuster_results_2 = gobuster_results_1 + [
        {"path": "/admin", "status": 401, "size": 456, "redirect": ""},
        {"path": "/server-status", "status": 403, "size": 277, "redirect": ""}
    ]

    # 4. Nikto Scans
    nikto_results_1 = {
        "host": "192.168.1.100", "ip": "192.168.1.100", "port": "80",
        "vulnerabilities": [
            {"id": 1, "msg": "The anti-clickjacking X-Frame-Options header is not present."},
            {"id": 2, "msg": "The X-XSS-Protection header is not defined."}
        ]
    }
    
    # 5. ZAP Scans
    zap_results_1 = [
        {"alert": "SQL Injection", "risk": "High", "confidence": "High", "url": "http://192.168.1.100/products.php?id=1", "description": "SQL Injection detected", "solution": "Parameterize input"},
        {"alert": "Cross-Site Scripting", "risk": "Medium", "confidence": "Medium", "url": "http://192.168.1.100/search.php?q=1", "description": "Reflected XSS detected", "solution": "Escape inputs"}
    ]
    zap_results_2 = zap_results_1 + [
        {"alert": "Cookie without SameSite Attribute", "risk": "Low", "confidence": "High", "url": "http://192.168.1.100/", "description": "SameSite not set", "solution": "Configure SameSite"}
    ]

    # Generate dates
    today = datetime.utcnow()
    
    scans = [
        ("nmap", "192.168.1.100", "quick", today - timedelta(days=5), "completed", nmap_results_1),
        ("nmap", "192.168.1.100", "full", today - timedelta(days=3), "completed", nmap_results_2),
        ("nmap", "192.168.1.105", "quick", today - timedelta(days=1), "completed", nmap_results_1),
        
        ("nuclei", "192.168.1.100", "vulnerability", today - timedelta(days=4), "completed", nuclei_results_1),
        ("nuclei", "192.168.1.100", "all", today - timedelta(days=2), "completed", nuclei_results_2),
        
        ("gobuster", "192.168.1.100", "dir", today - timedelta(days=4), "completed", gobuster_results_1),
        ("gobuster", "192.168.1.100", "dir", today - timedelta(days=2), "completed", gobuster_results_2),
        
        ("nikto", "192.168.1.100", "port 80", today - timedelta(days=3), "completed", nikto_results_1),
        
        ("zap", "192.168.1.100", "default", today - timedelta(days=4), "completed", zap_results_1),
        ("zap", "192.168.1.100", "default", today - timedelta(days=1), "completed", zap_results_2),
    ]

    for tool, target, scan_type, dt, status, results in scans:
        date_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            INSERT INTO scan_history (tool, target, scan_type, timestamp, status, results)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (tool, target, scan_type, date_str, status, json.dumps(results)))
        
    conn.commit()
    conn.close()
    print("Database seeded successfully with historical scans!")

if __name__ == "__main__":
    seed_db()
