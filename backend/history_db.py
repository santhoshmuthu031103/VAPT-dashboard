import sqlite3
import json
import os
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

logger = logging.getLogger("history_db")

DB_DIR = "/root/vapt-dashboard/backend/data"
DB_PATH = os.path.join(DB_DIR, "vapt.db")

def init_db():
    """Initializes the database directory and tables."""
    try:
        os.makedirs(DB_DIR, exist_ok=True)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Create scan_history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool TEXT NOT NULL,
                target TEXT NOT NULL,
                scan_type TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL,
                results TEXT NOT NULL
            )
        """)
        
        # Create scheduled_scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scheduled_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool TEXT NOT NULL,
                target TEXT NOT NULL,
                scan_type TEXT,
                run_at DATETIME NOT NULL,
                status TEXT DEFAULT 'pending',
                frequency TEXT DEFAULT 'once',
                cron_expr TEXT,
                last_run DATETIME,
                next_run DATETIME,
                group_name TEXT,
                is_active INTEGER DEFAULT 1
            )
        """)

        # Migration helper for scheduled_scans table if columns don't exist
        cursor.execute("PRAGMA table_info(scheduled_scans)")
        cols = [col[1] for col in cursor.fetchall()]
        if "frequency" not in cols:
            cursor.execute("ALTER TABLE scheduled_scans ADD COLUMN frequency TEXT DEFAULT 'once'")
        if "cron_expr" not in cols:
            cursor.execute("ALTER TABLE scheduled_scans ADD COLUMN cron_expr TEXT")
        if "last_run" not in cols:
            cursor.execute("ALTER TABLE scheduled_scans ADD COLUMN last_run DATETIME")
        if "next_run" not in cols:
            cursor.execute("ALTER TABLE scheduled_scans ADD COLUMN next_run DATETIME")
        if "group_name" not in cols:
            cursor.execute("ALTER TABLE scheduled_scans ADD COLUMN group_name TEXT")
        if "is_active" not in cols:
            cursor.execute("ALTER TABLE scheduled_scans ADD COLUMN is_active INTEGER DEFAULT 1")

        # Create target_groups table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS target_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT DEFAULT '',
                targets TEXT NOT NULL,
                color TEXT DEFAULT '#3b82f6',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()
        logger.info(f"Database initialized at {DB_PATH}")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")

def save_scan(tool: str, target: str, scan_type: str, status: str, results: Any) -> Optional[int]:
    """Saves a completed scan run to history database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        results_str = json.dumps(results)
        cursor.execute("""
            INSERT INTO scan_history (tool, target, scan_type, status, results, timestamp)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
        """, (tool.lower(), target, scan_type, status, results_str))
        
        conn.commit()
        last_id = cursor.lastrowid
        conn.close()
        logger.info(f"Saved {tool} scan history for {target} (ID: {last_id})")
        return last_id
    except Exception as e:
        logger.error(f"Failed to save scan history: {e}")
        return None

def get_scan_history(tool: str = None, target: str = None) -> List[Dict[str, Any]]:
    """
    Returns list of all scan histories without massive raw results to keep list retrieval fast.
    Computes summary statistics dynamically.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = "SELECT id, tool, target, scan_type, timestamp, status, results FROM scan_history"
        params = []
        
        conditions = []
        if tool:
            conditions.append("tool = ?")
            params.append(tool.lower())
        if target:
            conditions.append("target LIKE ?")
            params.append(f"%{target}%")
            
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
            
        query += " ORDER BY timestamp DESC"
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        history_list = []
        for row in rows:
            scan_id = row["id"]
            tool_name = row["tool"]
            raw_results = row["results"]
            
            # Parse results to compute brief summary statistics
            summary_info = {}
            try:
                data = json.loads(raw_results)
                if tool_name == "nmap":
                    # Count open ports and service distribution
                    ports_count = len(data) if isinstance(data, list) else 0
                    services = {}
                    if isinstance(data, list):
                        for p in data:
                            s = p.get("service") or "unknown"
                            services[s] = services.get(s, 0) + 1
                    summary_info = {"open_ports": ports_count, "services": services}
                elif tool_name == "nuclei":
                    # Count severities
                    high = sum(1 for v in data if isinstance(v, dict) and v.get("info", {}).get("severity", "").lower() in ("high", "critical"))
                    medium = sum(1 for v in data if isinstance(v, dict) and v.get("info", {}).get("severity", "").lower() == "medium")
                    low = sum(1 for v in data if isinstance(v, dict) and v.get("info", {}).get("severity", "").lower() == "low")
                    info = sum(1 for v in data if isinstance(v, dict) and v.get("info", {}).get("severity", "").lower() == "info")
                    summary_info = {"high": high, "medium": medium, "low": low, "info": info}
                elif tool_name == "nikto":
                    # Count vulnerabilities and compute keyword-based severity classification
                    vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
                    high, med, low, info = 0, 0, 0, 0
                    for v in vulns:
                        msg = v.get("msg", "").lower()
                        if any(k in msg for k in ["exploit", "sqli", "injection", "rce", "cve-", "bypass", "vulnerable", "remote code", "execute"]):
                            high += 1
                        elif any(k in msg for k in ["xss", "cross-site", "csrf", "ssrf", "clickjacking", "cors"]):
                            med += 1
                        elif any(k in msg for k in ["header", "cookie", "protection", "ssl", "tls", "deprecated", "option", "banner"]):
                            low += 1
                        else:
                            info += 1
                    summary_info = {
                        "vulns_count": len(vulns),
                        "severity": {"high": high, "medium": med, "low": low, "info": info}
                    }
                elif tool_name == "gobuster":
                    # Count response codes
                    codes = {}
                    if isinstance(data, list):
                        for item in data:
                            status_code = str(item.get("status", "unknown"))
                            codes[status_code] = codes.get(status_code, 0) + 1
                    summary_info = {"status_codes": codes}
                elif tool_name == "zap":
                    # Count alert risk levels
                    high = sum(1 for a in data if isinstance(a, dict) and a.get("risk", "").lower() == "high")
                    medium = sum(1 for a in data if isinstance(a, dict) and a.get("risk", "").lower() == "medium")
                    low = sum(1 for a in data if isinstance(a, dict) and a.get("risk", "").lower() == "low")
                    info = sum(1 for a in data if isinstance(a, dict) and a.get("risk", "").lower() == "informational")
                    summary_info = {"high": high, "medium": medium, "low": low, "info": info}
                elif tool_name == "sqlmap":
                    injections = data.get("injections", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
                    summary_info = {"injections_count": len(injections), "injections": injections}
                elif tool_name == "ffuf":
                    results_list = data.get("results", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
                    summary_info = {"endpoints_count": len(results_list)}
            except Exception:
                summary_info = {"error": "Failed to compute summary"}
                
            history_list.append({
                "id": scan_id,
                "tool": tool_name,
                "target": row["target"],
                "scan_type": row["scan_type"],
                "timestamp": row["timestamp"],
                "status": row["status"],
                "summary": summary_info
            })
            
        conn.close()
        return history_list
    except Exception as e:
        logger.error(f"Failed to fetch scan history: {e}")
        return []

def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    """Returns the full scan record including raw parsed results."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, tool, target, scan_type, timestamp, status, results FROM scan_history WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        
        scan_record = None
        if row:
            scan_record = {
                "id": row["id"],
                "tool": row["tool"],
                "target": row["target"],
                "scan_type": row["scan_type"],
                "timestamp": row["timestamp"],
                "status": row["status"],
                "results": json.loads(row["results"])
            }
            
        conn.close()
        return scan_record
    except Exception as e:
        logger.error(f"Failed to fetch scan detail: {e}")
        return None

def delete_scan(scan_id: int) -> bool:
    """Deletes a scan record from the history database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,))
        conn.commit()
        conn.close()
        logger.info(f"Deleted scan record ID: {scan_id}")
        return True
    except Exception as e:
        logger.error(f"Failed to delete scan record: {e}")
        return False

def get_trends_data() -> Dict[str, Any]:
    """
    Returns scan count and findings aggregates grouped by tool and date for line charts.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Select all completed scans ordered by timestamp
        cursor.execute("""
            SELECT id, tool, timestamp, results 
            FROM scan_history 
            WHERE status = 'completed'
            ORDER BY timestamp ASC
        """)
        rows = cursor.fetchall()
        
        trends = []
        for row in rows:
            tool_name = row["tool"]
            raw_results = row["results"]
            timestamp_str = row["timestamp"]
            
            # Format timestamp to YYYY-MM-DD
            try:
                dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                date_str = dt.strftime("%Y-%m-%d")
            except Exception:
                date_str = timestamp_str.split(" ")[0]
                
            findings_count = 0
            severity_counts = {"high": 0, "medium": 0, "low": 0}
            
            try:
                data = json.loads(raw_results)
                if tool_name == "nmap":
                    findings_count = len(data) if isinstance(data, list) else 0
                elif tool_name == "nuclei":
                    for v in data:
                        if isinstance(v, dict):
                            sev = v.get("info", {}).get("severity", "").lower()
                            if sev in ("high", "critical"):
                                severity_counts["high"] += 1
                            elif sev == "medium":
                                severity_counts["medium"] += 1
                            elif sev == "low":
                                severity_counts["low"] += 1
                    findings_count = len(data)
                elif tool_name == "nikto":
                    vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
                    findings_count = len(vulns)
                    for v in vulns:
                        msg = v.get("msg", "").lower()
                        if any(k in msg for k in ["exploit", "sqli", "injection", "rce", "cve-", "bypass", "vulnerable", "remote code", "execute"]):
                            severity_counts["high"] += 1
                        elif any(k in msg for k in ["xss", "cross-site", "csrf", "ssrf", "clickjacking", "cors"]):
                            severity_counts["medium"] += 1
                        elif any(k in msg for k in ["header", "cookie", "protection", "ssl", "tls", "deprecated", "option", "banner"]):
                            severity_counts["low"] += 1
                elif tool_name == "gobuster":
                    findings_count = len(data) if isinstance(data, list) else 0
                elif tool_name == "zap":
                    for a in data:
                        if isinstance(a, dict):
                            risk = a.get("risk", "").lower()
                            if risk == "high":
                                severity_counts["high"] += 1
                            elif risk == "medium":
                                severity_counts["medium"] += 1
                            elif risk == "low":
                                severity_counts["low"] += 1
                    findings_count = len(data)
                elif tool_name == "sqlmap":
                    injections = data.get("injections", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
                    findings_count = len(injections)
                    if findings_count > 0:
                        severity_counts["high"] += findings_count
                elif tool_name == "ffuf":
                    results_list = data.get("results", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
                    findings_count = len(results_list)
            except Exception:
                pass
                
            trends.append({
                "id": row["id"],
                "tool": tool_name,
                "date": date_str,
                "findings": findings_count,
                "severity": severity_counts
            })
            
        conn.close()
        return {"trends": trends}
    except Exception as e:
        logger.error(f"Failed to fetch trends data: {e}")
        return {"trends": []}

def add_scheduled_scan(
    tool: str, 
    target: str, 
    scan_type: str, 
    run_at: str, 
    frequency: str = "once", 
    cron_expr: str = None, 
    group_name: str = None,
    next_run: str = None
) -> Optional[int]:
    """Adds a scheduled scan with optional recurring frequency to the database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO scheduled_scans (tool, target, scan_type, run_at, frequency, cron_expr, group_name, next_run, status, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', 1)
        """, (tool.lower(), target, scan_type, run_at, frequency.lower(), cron_expr, group_name, next_run or run_at))
        
        conn.commit()
        last_id = cursor.lastrowid
        conn.close()
        logger.info(f"Scheduled {tool} scan for {target} at {run_at} [Freq: {frequency}] (ID: {last_id})")
        return last_id
    except Exception as e:
        logger.error(f"Failed to save scheduled scan: {e}")
        return None

def get_scheduled_scans(status: Optional[str] = None) -> List[Dict[str, Any]]:
    """Gets scheduled scans with optional status filter, ordered by most recent or nearest run_at."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if status:
            cursor.execute("SELECT * FROM scheduled_scans WHERE status = ? ORDER BY run_at ASC", (status,))
        else:
            cursor.execute("SELECT * FROM scheduled_scans ORDER BY id DESC")
        rows = cursor.fetchall()
        
        scans = []
        for row in rows:
            scans.append(dict(row))
            
        conn.close()
        return scans
    except Exception as e:
        logger.error(f"Failed to fetch scheduled scans: {e}")
        return []

def delete_scheduled_scan(scan_id: int) -> bool:
    """Deletes a scheduled scan record."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM scheduled_scans WHERE id = ?", (scan_id,))
        conn.commit()
        conn.close()
        logger.info(f"Deleted scheduled scan ID: {scan_id}")
        return True
    except Exception as e:
        logger.error(f"Failed to delete scheduled scan: {e}")
        return False

def update_scheduled_scan(
    scan_id: int,
    tool: Optional[str] = None,
    target: Optional[str] = None,
    scan_type: Optional[str] = None,
    run_at: Optional[str] = None,
    frequency: Optional[str] = None,
    cron_expr: Optional[str] = None,
    group_name: Optional[str] = None
) -> bool:
    """Updates scheduled scan parameters and resets status to pending."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Fetch current record first
        cursor.execute("SELECT * FROM scheduled_scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return False

        # Build update fields
        updates = []
        params = []
        if tool is not None:
            updates.append("tool = ?")
            params.append(tool.lower())
        if target is not None:
            updates.append("target = ?")
            params.append(target)
        if scan_type is not None:
            updates.append("scan_type = ?")
            params.append(scan_type)
        if run_at is not None:
            updates.append("run_at = ?")
            params.append(run_at)
            updates.append("next_run = ?")
            params.append(run_at)
        if frequency is not None:
            updates.append("frequency = ?")
            params.append(frequency.lower())
        if cron_expr is not None:
            updates.append("cron_expr = ?")
            params.append(cron_expr)
        if group_name is not None:
            updates.append("group_name = ?")
            params.append(group_name)

        # Always reset status to pending and is_active to 1 when rescheduled
        updates.append("status = 'pending'")
        updates.append("is_active = 1")

        if updates:
            query = f"UPDATE scheduled_scans SET {', '.join(updates)} WHERE id = ?"
            params.append(scan_id)
            cursor.execute(query, tuple(params))
            conn.commit()

        conn.close()
        logger.info(f"Updated scheduled scan ID: {scan_id}")
        return True
    except Exception as e:
        logger.error(f"Failed to update scheduled scan: {e}")
        return False

def update_scheduled_scan_status(
    scan_id: int, 
    status: str, 
    last_run: Optional[str] = None, 
    next_run: Optional[str] = None
) -> bool:
    """Updates status, last_run, and next_run for a scheduled scan."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        if last_run and next_run:
            cursor.execute("""
                UPDATE scheduled_scans 
                SET status = ?, last_run = ?, next_run = ?
                WHERE id = ?
            """, (status, last_run, next_run, scan_id))
        elif last_run:
            cursor.execute("""
                UPDATE scheduled_scans 
                SET status = ?, last_run = ?
                WHERE id = ?
            """, (status, last_run, scan_id))
        else:
            cursor.execute("UPDATE scheduled_scans SET status = ? WHERE id = ?", (status, scan_id))
            
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Failed to update scheduled scan status: {e}")
        return False

def toggle_scheduled_scan_active(scan_id: int, is_active: Optional[int] = None) -> bool:
    """Toggles or sets the active state for recurring scheduled scans."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        if is_active is None:
            cursor.execute("""
                UPDATE scheduled_scans 
                SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END,
                    status = CASE WHEN is_active = 1 THEN 'paused' ELSE 'pending' END
                WHERE id = ?
            """, (scan_id,))
        else:
            status = 'pending' if is_active == 1 else 'paused'
            cursor.execute("""
                UPDATE scheduled_scans 
                SET is_active = ?, status = ?
                WHERE id = ?
            """, (is_active, status, scan_id))
            
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Failed to toggle scheduled scan active state: {e}")
        return False

# ==========================================
# Target Groups Management
# ==========================================

def create_target_group(name: str, targets: List[str], description: str = "", color: str = "#3b82f6") -> Optional[int]:
    """Creates a new target group."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        targets_json = json.dumps(targets)
        
        cursor.execute("""
            INSERT INTO target_groups (name, description, targets, color, created_at, updated_at)
            VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))
        """, (name.strip(), description.strip(), targets_json, color or "#3b82f6"))
        
        conn.commit()
        last_id = cursor.lastrowid
        conn.close()
        logger.info(f"Created Target Group '{name}' with {len(targets)} targets (ID: {last_id})")
        return last_id
    except Exception as e:
        logger.error(f"Failed to create target group: {e}")
        return None

def get_target_groups() -> List[Dict[str, Any]]:
    """Lists all target groups."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM target_groups ORDER BY name ASC")
        rows = cursor.fetchall()
        
        groups = []
        for row in rows:
            g = dict(row)
            try:
                g["targets"] = json.loads(g["targets"])
            except Exception:
                g["targets"] = [g["targets"]] if g["targets"] else []
            groups.append(g)
            
        conn.close()
        return groups
    except Exception as e:
        logger.error(f"Failed to fetch target groups: {e}")
        return []

def get_target_group_by_id(group_id: int) -> Optional[Dict[str, Any]]:
    """Gets a target group by ID."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM target_groups WHERE id = ?", (group_id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        g = dict(row)
        try:
            g["targets"] = json.loads(g["targets"])
        except Exception:
            g["targets"] = [g["targets"]] if g["targets"] else []
        return g
    except Exception as e:
        logger.error(f"Failed to fetch target group {group_id}: {e}")
        return None

def update_target_group(
    group_id: int, 
    name: Optional[str] = None, 
    targets: Optional[List[str]] = None, 
    description: Optional[str] = None, 
    color: Optional[str] = None
) -> bool:
    """Updates a target group."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        fields = []
        params = []
        if name is not None:
            fields.append("name = ?")
            params.append(name.strip())
        if targets is not None:
            fields.append("targets = ?")
            params.append(json.dumps(targets))
        if description is not None:
            fields.append("description = ?")
            params.append(description.strip())
        if color is not None:
            fields.append("color = ?")
            params.append(color)
            
        if not fields:
            conn.close()
            return True
            
        fields.append("updated_at = datetime('now')")
        params.append(group_id)
        
        query = f"UPDATE target_groups SET {', '.join(fields)} WHERE id = ?"
        cursor.execute(query, tuple(params))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Failed to update target group {group_id}: {e}")
        return False

def delete_target_group(group_id: int) -> bool:
    """Deletes a target group."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM target_groups WHERE id = ?", (group_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Failed to delete target group {group_id}: {e}")
        return False
