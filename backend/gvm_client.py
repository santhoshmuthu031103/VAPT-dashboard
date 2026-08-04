import time
import uuid
import logging
import threading
import xmltodict
from typing import Dict, List, Any, Optional

logger = logging.getLogger("gvm_client")
logging.basicConfig(level=logging.INFO)

# Default Greenbone UUIDs
DEFAULT_SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"  # OpenVAS Default
DEFAULT_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"   # Full and Fast

# How long a GMP context stays open before we proactively close & reopen it
_CONN_MAX_AGE = 55   # seconds (GVM idles out at ~60 s)
_CACHE_TTL    = 30   # seconds for list caches (targets, tasks, configs, credentials, scanners)
_STATUS_TTL   = 20   # seconds between real connection-check calls for /api/status


class GmpConnectionWrapper:
    def __init__(self, client):
        self.client = client
        self.gmp = None
        self.conn = None
        self._inner_gmp = None

    def __enter__(self):
        self.conn = self.client._create_connection()
        from gvm.protocols.gmp import Gmp
        self.gmp = Gmp(connection=self.conn)
        self._inner_gmp = self.gmp.__enter__()
        self._inner_gmp.authenticate(self.client.username, self.client.password)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.gmp:
            self.gmp.__exit__(exc_type, exc_val, exc_tb)
        self._inner_gmp = None

    def __getattr__(self, name):
        if self._inner_gmp:
            return getattr(self._inner_gmp, name)
        raise AttributeError(f"'GmpConnectionWrapper' object has no attribute '{name}'")


class GVMClient:
    def __init__(self, connection_type: str = "tls",
                 socket_path: str = "/run/gvmd/gvmd.sock",
                 host: str = "127.0.0.1",
                 port: int = 9390,
                 username: str = "admin",
                 password: str = "admin123"):
        self.connection_type = connection_type
        self.socket_path = socket_path
        self.host = host
        self.port = port
        self.username = username
        self.password = password

        self.mock_mode = False
        # ── Persistent session ─────────────────────────────────────────────
        self._session_lock    = threading.Lock()
        self._session         = None   # active inner protocol instance kept open
        self._session_wrapper = None   # the Gmp instance to call __exit__ on
        self._session_born    = 0.0    # epoch when current session was opened
        # ── In-memory TTL cache ────────────────────────────────────────────
        self._cache: Dict   = {}
        # ── Status throttle ───────────────────────────────────────────────
        self._last_status_check = 0.0

        self._open_session()

    # ──────────────────────────────────────────────────────────────────────
    # CONNECTION HELPERS
    # ──────────────────────────────────────────────────────────────────────

    def _create_connection(self):
        from gvm.connections import UnixSocketConnection, TLSConnection
        if self.connection_type == "socket":
            return UnixSocketConnection(path=self.socket_path)
        return TLSConnection(hostname=self.host, port=self.port)

    def _open_session(self):
        """Open (or re-open) a persistent authenticated GMP session."""
        try:
            from gvm.protocols.gmp import Gmp
            conn = self._create_connection()
            gmp  = Gmp(connection=conn)
            inner = gmp.__enter__()
            inner.authenticate(self.username, self.password)
            self._session         = inner
            self._session_wrapper = gmp
            self._session_born    = time.time()
            self.mock_mode        = False
            logger.info("GVM persistent session opened.")
        except Exception as e:
            self._session         = None
            self._session_wrapper = None
            self.mock_mode        = True
            logger.warning(f"Could not open persistent GVM session: {e}")

    def _close_session(self):
        try:
            if self._session_wrapper:
                self._session_wrapper.__exit__(None, None, None)
        except Exception:
            pass
        self._session         = None
        self._session_wrapper = None

    def _get_session(self):
        """Return the active GMP session, reopening if stale or dead."""
        with self._session_lock:
            age = time.time() - self._session_born
            if self._session is None or age > _CONN_MAX_AGE:
                self._close_session()
                self._open_session()
            return self._session

    # Backwards-compat context-manager shim used by write methods
    # (keeps each mutating call in its own fresh session for safety)
    def _get_gmp(self):
        """Return a fresh one-shot GmpConnectionWrapper for mutating calls."""
        return GmpConnectionWrapper(self)

    # Public alias used by main.py status endpoint
    def try_connect(self):
        """Rate-limited connection check (at most once per _STATUS_TTL seconds)."""
        now = time.time()
        if now - self._last_status_check < _STATUS_TTL:
            return   # skip – cached result still fresh
        self._last_status_check = now
        if self._session is None or (now - self._session_born) > _CONN_MAX_AGE:
            self._close_session()
            self._open_session()

    # ──────────────────────────────────────────────────────────────────────────
    # CACHE HELPER  (used by all read methods below)
    # ──────────────────────────────────────────────────────────────────────────

    def _cached_read(self, key: str, fetch_fn):
        """Return cached value if fresh, else call fetch_fn with the persistent session."""
        entry = self._cache.get(key)
        if entry and (time.time() - entry["ts"] < _CACHE_TTL):
            return entry["data"]
        gmp = self._get_session()
        if gmp is None:
            raise RuntimeError("Not connected to OpenVAS")
        try:
            result = fetch_fn(gmp)
        except Exception:
            # Session might have died – reopen once and retry
            self._close_session()
            self._open_session()
            gmp = self._session
            if gmp is None:
                raise
            result = fetch_fn(gmp)
        self._cache[key] = {"ts": time.time(), "data": result}
        return result

    def _invalidate(self, *keys):
        for k in keys:
            self._cache.pop(k, None)

    # ──────────────────────────────────────────────────────────────────────────
    # TARGET MANAGEMENT
    # ──────────────────────────────────────────────────────────────────────────

    def get_targets(self) -> List[Dict[str, Any]]:
        def fetch(gmp):
            response = gmp.get_targets()
            data = xmltodict.parse(response)
            targets_xml = data.get("get_targets_response", {}).get("target", [])
            if not isinstance(targets_xml, list):
                targets_xml = [targets_xml]
            targets = []
            for t in targets_xml:
                if not t:
                    continue
                ssh_cred = t.get("ssh_lsc_credential") or t.get("ssh_credential") or {}
                smb_cred = t.get("smb_lsc_credential") or t.get("smb_credential") or {}
                targets.append({
                    "id": t.get("@id"),
                    "name": t.get("name"),
                    "hosts": t.get("hosts"),
                    "comment": t.get("comment", ""),
                    "ssh_credential_id": ssh_cred.get("@id") if isinstance(ssh_cred, dict) else None,
                    "ssh_credential_name": ssh_cred.get("name") if isinstance(ssh_cred, dict) else None,
                    "smb_credential_id": smb_cred.get("@id") if isinstance(smb_cred, dict) else None,
                    "smb_credential_name": smb_cred.get("name") if isinstance(smb_cred, dict) else None,
                })
            return targets
        return self._cached_read("targets", fetch)

    def create_target(self, name: str, hosts: str, comment: str = "",
                      ssh_credential_id: Optional[str] = None,
                      smb_credential_id: Optional[str] = None) -> str:
        with self._get_gmp() as gmp:
            kwargs: Dict[str, Any] = dict(name=name, hosts=[hosts], comment=comment)
            if ssh_credential_id:
                kwargs["ssh_credential_id"] = ssh_credential_id
            if smb_credential_id:
                kwargs["smb_credential_id"] = smb_credential_id
            response = gmp.create_target(**kwargs)
            data = xmltodict.parse(response)
            self._invalidate("targets")
            return data.get("create_target_response", {}).get("@id")

    def delete_target(self, target_id: str) -> bool:
        try:
            with self._get_gmp() as gmp:
                gmp.delete_target(target_id=target_id)
                self._invalidate("targets")
                return True
        except Exception as e:
            logger.error(f"Error deleting target {target_id}: {e}")
            return False

    # ──────────────────────────────────────────────────────────────────────────
    # CREDENTIAL MANAGEMENT
    # ──────────────────────────────────────────────────────────────────────────

    def list_credential_sets(self) -> List[Dict[str, Any]]:
        def fetch(gmp):
            response = gmp.get_credentials()
            data = xmltodict.parse(response)
            creds_xml = data.get("get_credentials_response", {}).get("credential", [])
            if not isinstance(creds_xml, list):
                creds_xml = [creds_xml]
            result = []
            for c in creds_xml:
                if not c:
                    continue
                ctype_raw = c.get("type", "")
                type_map = {"up": "username+password", "usk": "ssh_key", "smb": "smb", "snmp": "snmp", "krb5": "kerberos"}
                ctype = type_map.get(ctype_raw.lower(), ctype_raw)
                result.append({
                    "id": c.get("@id"),
                    "name": c.get("name"),
                    "type": ctype,
                    "username": c.get("login", ""),
                    "comment": c.get("comment", ""),
                })
            return result
        return self._cached_read("credentials", fetch)

    def create_credential(self, name: str, credential_type: str,
                           username: str, password: Optional[str] = None,
                           private_key: Optional[str] = None,
                           comment: str = "") -> str:
        from gvm.protocols.gmp.requests import CredentialType
        type_map = {
            "ssh_password": CredentialType.USERNAME_PASSWORD,
            "ssh_key":      CredentialType.USERNAME_SSH_KEY,
            "smb":          CredentialType.USERNAME_PASSWORD,
            "rdp":          CredentialType.USERNAME_PASSWORD,
        }
        gvm_type = type_map.get(credential_type, CredentialType.USERNAME_PASSWORD)
        with self._get_gmp() as gmp:
            kwargs: Dict[str, Any] = dict(
                name=name, credential_type=gvm_type, login=username, comment=comment,
            )
            if private_key:
                kwargs["key"] = {"private": private_key}
            elif password:
                kwargs["password"] = password
            response = gmp.create_credential(**kwargs)
            data = xmltodict.parse(response)
            self._invalidate("credentials")
            return data.get("create_credential_response", {}).get("@id")

    def delete_credential(self, cred_id: str) -> bool:
        try:
            with self._get_gmp() as gmp:
                gmp.delete_credential(credential_id=cred_id)
                self._invalidate("credentials")
                return True
        except Exception as e:
            logger.error(f"Error deleting credential {cred_id}: {e}")
            return False

    # ──────────────────────────────────────────────────────────────────────────
    # SCAN CONFIGS
    # ──────────────────────────────────────────────────────────────────────────

    def list_scan_configs(self) -> List[Dict[str, Any]]:
        def fetch(gmp):
            response = gmp.get_scan_configs()
            data = xmltodict.parse(response)
            configs_xml = data.get("get_configs_response", {}).get("config", [])
            if not isinstance(configs_xml, list):
                configs_xml = [configs_xml]
            return [{"id": c.get("@id"), "name": c.get("name")} for c in configs_xml if c]
        return self._cached_read("scan_configs", fetch)

    def list_scanners(self) -> List[Dict[str, Any]]:
        def fetch(gmp):
            response = gmp.get_scanners()
            data = xmltodict.parse(response)
            scanners_xml = data.get("get_scanners_response", {}).get("scanner", [])
            if not isinstance(scanners_xml, list):
                scanners_xml = [scanners_xml]
            return [{"id": s.get("@id"), "name": s.get("name"), "type": s.get("type", "")}
                    for s in scanners_xml if s]
        return self._cached_read("scanners", fetch)

    # ──────────────────────────────────────────────────────────────────────────
    # CVE MANAGEMENT
    # ──────────────────────────────────────────────────────────────────────────

    def get_cves(self, search_term: str = "", page: int = 1, limit: int = 50) -> Dict[str, Any]:
        def fetch(gmp):
            filter_str = f"rows={limit} first={(page - 1) * limit + 1} sort-reverse=creation_time"
            if search_term and search_term.strip().upper() != "CVE":
                filter_str += f" {search_term}"
            
            response = gmp.get_cves(filter_string=filter_str)
            data = xmltodict.parse(response)
            info_resp = data.get("get_info_response", {})
            
            info_list = info_resp.get("info", [])
            if not isinstance(info_list, list):
                info_list = [info_list] if info_list else []
                
            cves = []
            for item in info_list:
                cve_data = item.get("cve", {})
                cves.append({
                    "id": cve_data.get("@id", ""),
                    "name": item.get("name", ""),
                    "creation_time": item.get("creation_time", ""),
                    "modification_time": item.get("modification_time", ""),
                    "description": cve_data.get("description", ""),
                    "severity": cve_data.get("severity", ""),
                    "cvss": cve_data.get("cvss", "")
                })
            
            report_count = info_resp.get("info_count", {})
            total = int(report_count.get("filtered", 0) if isinstance(report_count, dict) else 0)
            
            return {
                "cves": cves,
                "total": total,
                "page": page,
                "limit": limit
            }
        
        # Don't cache search results
        gmp = self._get_session()
        if gmp is None:
            raise RuntimeError("Not connected to OpenVAS")
        return fetch(gmp)

    # ──────────────────────────────────────────────────────────────────────────
    # TASK MANAGEMENT
    # ──────────────────────────────────────────────────────────────────────────

    def get_tasks(self) -> List[Dict[str, Any]]:
        def fetch(gmp):
            response = gmp.get_tasks()
            data = xmltodict.parse(response)
            tasks_xml = data.get("get_tasks_response", {}).get("task", [])
            if not isinstance(tasks_xml, list):
                tasks_xml = [tasks_xml]
            tasks = []
            for t in tasks_xml:
                if not t:
                    continue
                target_node = t.get("target") or {}
                last_report_node = t.get("last_report") or {}
                current_report_node = t.get("current_report") or {}
                report_inner = (last_report_node.get("report") or
                                current_report_node.get("report") or {})
                report_id = report_inner.get("@id") if isinstance(report_inner, dict) else None
                try:
                    progress = max(0, int(t.get("progress") or 0))
                except (ValueError, TypeError):
                    progress = 0
                tasks.append({
                    "id": t.get("@id"),
                    "name": t.get("name"),
                    "status": t.get("status"),
                    "progress": progress,
                    "target_id": target_node.get("@id") if isinstance(target_node, dict) else None,
                    "target_name": target_node.get("name") if isinstance(target_node, dict) else "",
                    "target_hosts": target_node.get("hosts", "") if isinstance(target_node, dict) else "",
                    "config_id": (t.get("config") or {}).get("@id"),
                    "config_name": (t.get("config") or {}).get("name", ""),
                    "scanner_id": (t.get("scanner") or {}).get("@id"),
                    "scanner_name": (t.get("scanner") or {}).get("name", ""),
                    "report_id": report_id,
                    "report_count": int((t.get("report_count") or {}).get("#text", 0) or 0),
                })
            return tasks
        # Tasks change during scans — use a short 8-second TTL
        entry = self._cache.get("tasks")
        if entry and (time.time() - entry["ts"] < 8):
            return entry["data"]
        gmp = self._get_session()
        if gmp is None:
            raise RuntimeError("Not connected to OpenVAS")
        try:
            result = fetch(gmp)
        except Exception:
            self._close_session(); self._open_session()
            gmp = self._session
            if gmp is None: raise
            result = fetch(gmp)
        self._cache["tasks"] = {"ts": time.time(), "data": result}
        return result

    def create_task(self, name: str, target_id: str,
                    config_id: str = DEFAULT_CONFIG_ID,
                    scanner_id: str = DEFAULT_SCANNER_ID,
                    credential_id: Optional[str] = None) -> str:
        with self._get_gmp() as gmp:
            response = gmp.create_task(
                name=name, config_id=config_id, target_id=target_id, scanner_id=scanner_id,
            )
            data = xmltodict.parse(response)
            self._invalidate("tasks")
            return data.get("create_task_response", {}).get("@id")

    def start_task(self, task_id: str) -> Optional[str]:
        with self._get_gmp() as gmp:
            response = gmp.start_task(task_id=task_id)
            data = xmltodict.parse(response)
            self._invalidate("tasks")
            return data.get("start_task_response", {}).get("report_id")

    def stop_task(self, task_id: str) -> bool:
        try:
            with self._get_gmp() as gmp:
                gmp.stop_task(task_id=task_id)
                self._invalidate("tasks")
                return True
        except Exception as e:
            logger.error(f"Error stopping task {task_id}: {e}")
            return False

    def delete_task(self, task_id: str) -> bool:
        try:
            with self._get_gmp() as gmp:
                gmp.delete_task(task_id=task_id)
                self._invalidate("tasks")
                return True
        except Exception as e:
            logger.error(f"Error deleting task {task_id}: {e}")
            return False

    # ──────────────────────────────────────────────────────────────────────────
    # REPORT VIEWING
    # ──────────────────────────────────────────────────────────────────────────

    def get_report(self, report_id: str) -> Dict[str, Any]:
        with self._get_gmp() as gmp:
            # ignore_pagination=True and details=True give us the full result set
            try:
                response = gmp.get_report(
                    report_id=report_id,
                    ignore_pagination=True,
                    details=True,
                )
            except TypeError:
                # older python-gvm versions
                response = gmp.get_report(report_id=report_id)

            data = xmltodict.parse(response)
            report_xml = data.get("get_reports_response", {}).get("report", {})
            # The results live at report > report > results > result
            inner = report_xml.get("report") or report_xml
            results_node = inner.get("results") or {}
            results = results_node.get("result", [])
            if not isinstance(results, list):
                results = [results]

            # Task / target metadata
            task_node = inner.get("task") or {}
            hosts_node = inner.get("host") or []
            if not isinstance(hosts_node, list):
                hosts_node = [hosts_node]

            # Severity counts
            severity_counts = inner.get("severity") or {}

            vulnerabilities = []
            summary = {"high": 0, "medium": 0, "low": 0, "log": 0, "total": 0}

            for r in results:
                if not r:
                    continue
                threat = (r.get("threat") or "Log").strip()
                sev_lower = threat.lower()

                # CVSS score
                try:
                    cvss = float(r.get("severity") or r.get("cvss_base") or 0)
                except (ValueError, TypeError):
                    cvss = 0.0

                # map threat → severity bucket
                if sev_lower in ("high", "critical"):
                    summary["high"] += 1
                    sev_bucket = "High"
                elif sev_lower == "medium":
                    summary["medium"] += 1
                    sev_bucket = "Medium"
                elif sev_lower == "low":
                    summary["low"] += 1
                    sev_bucket = "Low"
                else:
                    summary["log"] += 1
                    sev_bucket = "Log"

                summary["total"] += 1

                # NVT details
                nvt = r.get("nvt") or {}
                nvt_refs = nvt.get("refs") or {}
                refs_list = nvt_refs.get("ref") or []
                if not isinstance(refs_list, list):
                    refs_list = [refs_list]
                cves = [ref.get("@id", "") for ref in refs_list
                        if isinstance(ref, dict) and ref.get("@type", "").upper() == "CVE"]

                solution_node = nvt.get("solution") or {}
                solution_text = (solution_node.get("#text") if isinstance(solution_node, dict)
                                 else str(solution_node))

                host_node = r.get("host") or {}
                hostname = ""
                if isinstance(host_node, dict):
                    hostname = host_node.get("hostname") or host_node.get("#text") or ""
                elif isinstance(host_node, str):
                    hostname = host_node

                # Parse tags
                tags_str = nvt.get("tags") or ""
                tags = {}
                for tag_pair in tags_str.split("|"):
                    if "=" in tag_pair:
                        k, v = tag_pair.split("=", 1)
                        tags[k.strip()] = v.strip()

                vulnerabilities.append({
                    "name": r.get("name") or nvt.get("name") or "Unknown",
                    "severity": sev_bucket,
                    "cvss": cvss,
                    "port": r.get("port") or "",
                    "protocol": r.get("protocol") or "",
                    "host": hostname,
                    "description": r.get("description") or nvt.get("summary") or "",
                    "solution": solution_text or "",
                    "cve": ", ".join(cves) if cves else "",
                    "nvt_oid": nvt.get("@oid") or "",
                    "family": nvt.get("family") or "",
                    "qod": (r.get("qod") or {}).get("value") or "",
                    "insight": tags.get("insight") or "",
                    "impact": tags.get("impact") or "",
                    "solution_type": tags.get("solution_type") or "",
                    "vuldetect": tags.get("vuldetect") or "",
                    "affected": tags.get("affected") or ""
                })

            # Sort by CVSS descending
            vulnerabilities.sort(key=lambda v: v["cvss"], reverse=True)

            return {
                "report_id": report_id,
                "task_name": task_node.get("name") if isinstance(task_node, dict) else "",
                "scan_start": inner.get("scan_start") or "",
                "scan_end": inner.get("scan_end") or "",
                "summary": summary,
                "vulnerabilities": vulnerabilities,
            }

    # ──────────────────────────────────────────────────────────────────────────
    # REPORT EXPORT HELPERS
    # ──────────────────────────────────────────────────────────────────────────

    def get_report_raw_xml(self, report_id: str) -> bytes:
        """Return the raw XML bytes exactly as GVM sends them (same as OpenVAS XML export)."""
        with self._get_gmp() as gmp:
            try:
                response = gmp.get_report(
                    report_id=report_id,
                    ignore_pagination=True,
                    details=True,
                )
            except TypeError:
                response = gmp.get_report(report_id=report_id)
            # python-gvm returns a string
            if isinstance(response, str):
                return response.encode("utf-8")
            return response

    def render_html_report(self, report: Dict[str, Any]) -> str:
        """Generate a classic OpenVAS LaTeX-style HTML report for PDF export."""
        summary = report.get("summary", {})
        vulns   = report.get("vulnerabilities", [])
        task    = report.get("task_name", "Unknown Task")
        start   = report.get("scan_start", "—")
        end     = report.get("scan_end", "—")
        
        # OpenVAS LaTeX Severity Colors
        sev_color = {
            "High": "#b91c1c",    # Red
            "Medium": "#ea580c",  # Orange
            "Low": "#0284c7",     # Blue
            "Log": "#475569"      # Gray
        }
        
        # Group vulnerabilities by host
        hosts = {}
        for v in vulns:
            h = v.get("host", "Unknown Host")
            if h not in hosts:
                hosts[h] = []
            hosts[h].append(v)
            
        # Build Table of Contents and Body
        toc_html = "<h2>Contents</h2><ul class='toc'>"
        toc_html += "<li><a href='#sec-1'>1 Result Overview</a></li>"
        toc_html += "<li><a href='#sec-2'>2 Results per Host</a></li>"
        
        body_html = f"<h2 id='sec-1'>1 Result Overview</h2>"
        body_html += f"""
        <table class='overview-table'>
            <thead>
                <tr>
                    <th>Host</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Log</th><th>False P.</th>
                </tr>
            </thead>
            <tbody>
        """
        for h, host_vulns in hosts.items():
            h_high = sum(1 for v in host_vulns if v.get("severity") == "High")
            h_med  = sum(1 for v in host_vulns if v.get("severity") == "Medium")
            h_low  = sum(1 for v in host_vulns if v.get("severity") == "Low")
            h_log  = sum(1 for v in host_vulns if v.get("severity") == "Log")
            body_html += f"<tr><td><a href='#host-{h}'>{h}</a></td><td>0</td><td>{h_high}</td><td>{h_med}</td><td>{h_low}</td><td>{h_log}</td><td>0</td></tr>"
            
        body_html += f"""
            <tr class='total-row'>
                <td>Total: {len(hosts)}</td><td>0</td><td>{summary.get('high', 0)}</td><td>{summary.get('medium', 0)}</td><td>{summary.get('low', 0)}</td><td>{summary.get('log', 0)}</td><td>0</td>
            </tr>
            </tbody>
        </table>
        <p style="font-size: 13px; margin-top: 15px;">This report contains all {len(vulns)} results. Overrides are off. Notes are included.</p>
        """
        
        body_html += "<h2 id='sec-2' style='page-break-before: always;'>2 Results per Host</h2>"
        
        host_idx = 1
        for h, host_vulns in hosts.items():
            toc_html += f"<li><a href='#host-{h}'>2.{host_idx} {h}</a></li>"
            body_html += f"<h3 id='host-{h}'>2.{host_idx} {h}</h3>"
            body_html += f"<p style='font-size: 13px; margin-bottom: 20px;'>Host scan start: {start}<br>Host scan end: {end}</p>"
            
            vuln_idx = 1
            for v in host_vulns:
                sev = v.get("severity", "Log")
                color = sev_color.get(sev, "#475569")
                port = v.get("port", "general/tcp")
                title = f"2.{host_idx}.{vuln_idx} {sev} {port}"
                cve = v.get("cve", "")
                
                # TOC Entry for Vulnerability
                toc_html += f"<li class='toc-sub'><a href='#vuln-{host_idx}-{vuln_idx}'>{title}</a></li>"
                
                body_html += f"<h4 id='vuln-{host_idx}-{vuln_idx}'>{title}</h4>"
                
                # Build rows dynamically based on presence
                rows = ""
                
                if v.get("description"):
                    rows += f"<tr><td><strong>Summary</strong><br/>{v.get('description', '')}</td></tr>"
                
                if v.get("qod"):
                    rows += f"<tr><td><strong>Quality of Detection (QoD):</strong> {v.get('qod', '')}%</td></tr>"
                    
                if v.get("vuldetect"):
                    rows += f"<tr><td><strong>Vulnerability Detection Method</strong><br/>{v.get('vuldetect', '')}</td></tr>"
                    
                if v.get("impact"):
                    rows += f"<tr><td><strong>Impact</strong><br/>{v.get('impact', '')}</td></tr>"
                
                if v.get("solution"):
                    sol_type = f"<strong>Solution type:</strong> {v.get('solution_type', 'Mitigation')}<br/>" if v.get('solution_type') else ""
                    rows += f"<tr><td><strong>Solution:</strong><br/>{sol_type}{v.get('solution', '')}</td></tr>"
                
                if v.get("affected"):
                    rows += f"<tr><td><strong>Affected Software/OS</strong><br/>{v.get('affected', '')}</td></tr>"
                    
                if v.get("insight"):
                    rows += f"<tr><td><strong>Vulnerability Insight</strong><br/>{v.get('insight', '')}</td></tr>"
                    
                if cve:
                    rows += f"<tr><td><strong>References</strong><br/>cve: {cve}</td></tr>"
                
                body_html += f"""
                <table class='vuln-table'>
                    <thead>
                        <tr>
                            <th style='background-color: {color}; color: white;'>{sev} (CVSS: {v.get('cvss', 0.0):.1f})<br/>NVT: {v.get('name', '')}</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
                """
                vuln_idx += 1
            host_idx += 1
            
        toc_html += "</ul>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Scan Report</title>
  <style>
    body {{
        font-family: "Times New Roman", Times, serif;
        font-size: 14px;
        line-height: 1.4;
        color: #000;
        max-width: 800px;
        margin: 0 auto;
        padding: 40px 20px;
    }}
    h1 {{ text-align: center; font-size: 28px; font-weight: normal; margin-top: 100px; margin-bottom: 40px; }}
    .title-date {{ text-align: center; font-size: 18px; margin-bottom: 60px; }}
    .title-summary {{ text-align: center; font-weight: bold; margin-bottom: 10px; }}
    .title-desc {{ text-align: justify; margin-bottom: 100px; font-size: 14px; line-height: 1.6; padding: 0 40px; }}
    
    h2 {{ font-size: 22px; border-bottom: 1px solid #ccc; padding-bottom: 5px; margin-top: 40px; }}
    h3 {{ font-size: 18px; margin-top: 30px; }}
    h4 {{ font-size: 16px; margin-top: 25px; margin-bottom: 10px; }}
    
    a {{ color: #0284c7; text-decoration: none; }}
    
    .toc {{ list-style-type: none; padding-left: 0; }}
    .toc li {{ margin-bottom: 5px; font-size: 14px; font-weight: bold; color: #0284c7; }}
    .toc .toc-sub {{ padding-left: 20px; font-weight: normal; font-size: 13px; }}
    
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; page-break-inside: avoid; }}
    th, td {{ border: 1px solid #000; padding: 8px 12px; text-align: left; vertical-align: top; }}
    
    .overview-table th {{ background-color: #8ba3c7; color: #000; font-weight: bold; text-align: center; }}
    .overview-table td {{ text-align: center; }}
    .overview-table td:first-child {{ text-align: left; }}
    .total-row {{ font-weight: bold; border-top: 2px solid #000; }}
    
    .vuln-table th {{ text-align: left; font-weight: normal; font-size: 14px; padding: 10px; }}
    .vuln-table td {{ font-size: 13px; line-height: 1.5; }}
    .vuln-table strong {{ display: block; margin-bottom: 4px; font-size: 14px; }}
  </style>
</head>
<body>
  <h1>Scan Report</h1>
  <div class="title-date">August 2026</div>
  <div class="title-summary">Summary</div>
  <div class="title-desc">
    This document reports on the results of an automatic security scan. All dates are displayed using the timezone "Coordinated Universal Time", which is abbreviated "UTC". The task was "{task}". The scan started at {start} and ended at {end}. The report first summarises the results found. Then, for each host, the report describes every issue found. Please consider the advice given in each description, in order to rectify the issue.
  </div>
  
  <div style="page-break-after: always;"></div>
  
  {toc_html}
  
  <div style="page-break-after: always;"></div>
  
  {body_html}
</body>
</html>"""



    def _cache_get(self, key: str):
        entry = self._cache.get(key)
        if entry and (time.time() - entry["ts"] < self._cache_ttl):
            return entry["data"]
        return None

    def _cache_set(self, key: str, data: Any):
        self._cache[key] = {"ts": time.time(), "data": data}
