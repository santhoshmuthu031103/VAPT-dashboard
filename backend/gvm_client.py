import time
import uuid
import logging
import threading
import xmltodict
from datetime import datetime
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
        self._gmp_lock        = threading.Lock()
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
            
        with self._gmp_lock:
            # Recheck cache inside lock
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
                port_list = t.get("port_list") or {}
                targets.append({
                    "id": t.get("@id"),
                    "name": t.get("name"),
                    "hosts": t.get("hosts"),
                    "comment": t.get("comment", ""),
                    "ssh_credential_id": ssh_cred.get("@id") if isinstance(ssh_cred, dict) else None,
                    "ssh_credential_name": ssh_cred.get("name") if isinstance(ssh_cred, dict) else None,
                    "smb_credential_id": smb_cred.get("@id") if isinstance(smb_cred, dict) else None,
                    "smb_credential_name": smb_cred.get("name") if isinstance(smb_cred, dict) else None,
                    "port_list_id": port_list.get("@id") if isinstance(port_list, dict) else None,
                    "port_list_name": port_list.get("name") if isinstance(port_list, dict) else None,
                })
            return targets
        return self._cached_read("targets", fetch)

    def create_target(self, name: str, hosts: str, comment: str = "",
                      ssh_credential_id: Optional[str] = None,
                      smb_credential_id: Optional[str] = None,
                      port_list_id: str = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5") -> str:
        with self._get_gmp() as gmp:
            kwargs: Dict[str, Any] = dict(
                name=name,
                hosts=[hosts],
                comment=comment,
                port_list_id=port_list_id
            )
            if ssh_credential_id:
                kwargs["ssh_credential_id"] = ssh_credential_id
            if smb_credential_id:
                kwargs["smb_credential_id"] = smb_credential_id
            response = gmp.create_target(**kwargs)
            data = xmltodict.parse(response)
            self._invalidate("targets")
            return data.get("create_target_response", {}).get("@id")

    def modify_target(self, target_id: str, name: Optional[str] = None,
                      hosts: Optional[str] = None, comment: Optional[str] = None,
                      ssh_credential_id: Optional[str] = None,
                      smb_credential_id: Optional[str] = None,
                      port_list_id: Optional[str] = None) -> bool:
        with self._get_gmp() as gmp:
            kwargs: Dict[str, Any] = dict(target_id=target_id)
            if name:
                kwargs["name"] = name
            if hosts:
                kwargs["hosts"] = [hosts]
            if comment is not None:
                kwargs["comment"] = comment
            if port_list_id:
                kwargs["port_list_id"] = port_list_id
            if ssh_credential_id:
                kwargs["ssh_credential_id"] = ssh_credential_id
            if smb_credential_id:
                kwargs["smb_credential_id"] = smb_credential_id
            
            gmp.modify_target(**kwargs)
            self._invalidate("targets")
            return True

    def delete_target(self, target_id: str) -> bool:
        try:
            with self._get_gmp() as gmp:
                gmp.delete_target(target_id=target_id)
                self._invalidate("targets")
                return True
        except Exception as e:
            logger.error(f"Error deleting target {target_id}: {e}")
            return False

    def list_port_lists(self) -> List[Dict[str, Any]]:
        def fetch(gmp):
            response = gmp.get_port_lists()
            data = xmltodict.parse(response)
            pl_xml = data.get("get_port_lists_response", {}).get("port_list", [])
            if not isinstance(pl_xml, list):
                pl_xml = [pl_xml]
            res = []
            for p in pl_xml:
                if not p:
                    continue
                res.append({
                    "id": p.get("@id"),
                    "name": p.get("name"),
                    "comment": p.get("comment", "")
                })
            return res
        return self._cached_read("port_lists", fetch)

    def get_feed_status(self) -> List[Dict[str, Any]]:
        def fetch(gmp):
            response = gmp.get_feeds()
            data = xmltodict.parse(response)
            feeds = data.get("get_feeds_response", {}).get("feed", [])
            if not isinstance(feeds, list):
                feeds = [feeds]
            res = []
            for f in feeds:
                if not f:
                    continue
                res.append({
                    "type": f.get("type"),
                    "name": f.get("name"),
                    "version": f.get("version"),
                    "description": f.get("description", "")
                })
            return res
        return self._cached_read("feed_status", fetch)

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
        try:
            from gvm.protocols.gmp.requests.v227 import CredentialType
        except ImportError:
            try:
                from gvm.protocols.gmp.requests.v226 import CredentialType
            except ImportError:
                try:
                    from gvm.protocols.gmp.requests.v225 import CredentialType
                except ImportError:
                    try:
                        from gvm.protocols.gmp.requests.v224 import CredentialType
                    except ImportError:
                        from gvm.protocols.gmp.requests.next import CredentialType
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
                kwargs["private_key"] = private_key
            elif password:
                kwargs["password"] = password
            response = gmp.create_credential(**kwargs)
            data = xmltodict.parse(response)
            resp_node = data.get("create_credential_response", {})
            status = resp_node.get("@status")
            if status not in ("200", "201"):
                status_text = resp_node.get("@status_text", "Unknown GVM error")
                raise Exception(status_text)
            self._invalidate("credentials")
            return resp_node.get("@id")

    def modify_credential(self, cred_id: str, name: Optional[str] = None,
                          credential_type: Optional[str] = None,
                          username: Optional[str] = None, password: Optional[str] = None,
                          private_key: Optional[str] = None, comment: Optional[str] = None) -> bool:
        # Check if type changed
        current_creds = self.list_credential_sets()
        curr = next((c for c in current_creds if c["id"] == cred_id), None)
        
        type_map_normalized = {
            "ssh_password": "username+password",
            "ssh_key": "ssh_key",
            "smb": "smb",
            "rdp": "rdp"
        }
        
        type_changed = False
        if curr and credential_type:
            target_mapped = type_map_normalized.get(credential_type, credential_type)
            curr_type = curr.get("type", "")
            curr_type_norm = type_map_normalized.get(curr_type, curr_type)
            if curr_type_norm != target_mapped:
                type_changed = True

        if type_changed and curr:
            new_name = name or curr.get("name", "Credential")
            new_user = username or curr.get("username", "root")
            new_id = self.create_credential(
                name=new_name,
                credential_type=credential_type,
                username=new_user,
                password=password,
                private_key=private_key,
                comment=comment or curr.get("comment", "")
            )
            # Re-link any targets that used the old cred_id
            try:
                targets = self.get_targets()
                for t in targets:
                    tid = t.get("id")
                    updated = False
                    ssh_id = t.get("ssh_credential_id")
                    smb_id = t.get("smb_credential_id")
                    if ssh_id == cred_id:
                        ssh_id = new_id
                        updated = True
                    if smb_id == cred_id:
                        smb_id = new_id
                        updated = True
                    if updated:
                        self.modify_target(tid, ssh_credential_id=ssh_id, smb_credential_id=smb_id)
            except Exception as e:
                logger.error(f"Error re-linking targets to updated credential: {e}")
                
            self.delete_credential(cred_id)
            self._invalidate("credentials")
            self._invalidate("targets")
            return True
        else:
            with self._get_gmp() as gmp:
                kwargs: Dict[str, Any] = dict(credential_id=cred_id)
                if name:
                    kwargs["name"] = name
                if username:
                    kwargs["login"] = username
                if password:
                    kwargs["password"] = password
                if private_key:
                    kwargs["private_key"] = private_key
                if comment is not None:
                    kwargs["comment"] = comment
                
                gmp.modify_credential(**kwargs)
                self._invalidate("credentials")
                return True

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
        if self.mock_mode:
            mock_data = [
                {
                    "id": "CVE-2021-44228",
                    "name": "CVE-2021-44228",
                    "creation_time": "2021-12-10T00:00:00Z",
                    "modification_time": "2021-12-15T00:00:00Z",
                    "description": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints (Log4Shell).",
                    "severity": "10.0",
                    "cvss": "10.0"
                },
                {
                    "id": "CVE-2017-0144",
                    "name": "CVE-2017-0144",
                    "creation_time": "2017-03-14T00:00:00Z",
                    "modification_time": "2017-03-20T00:00:00Z",
                    "description": "The SMBv1 server in Microsoft Windows Vista SP2, Windows 7 SP1, Windows 8.1, Windows RT 8.1, Windows Server 2008 SP2, Windows Server 2012, and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets (EternalBlue).",
                    "severity": "8.1",
                    "cvss": "8.1"
                },
                {
                    "id": "CVE-2014-0160",
                    "name": "CVE-2014-0160",
                    "creation_time": "2014-04-07T00:00:00Z",
                    "modification_time": "2014-04-10T00:00:00Z",
                    "description": "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory (Heartbleed).",
                    "severity": "5.0",
                    "cvss": "5.0"
                },
                {
                    "id": "CVE-2020-0601",
                    "name": "CVE-2020-0601",
                    "creation_time": "2020-01-14T00:00:00Z",
                    "modification_time": "2020-01-18T00:00:00Z",
                    "description": "A spoofing vulnerability exists in the way Windows CryptoAPI (Crypt32.dll) validates Elliptic Curve Cryptography (ECC) certificates.",
                    "severity": "8.1",
                    "cvss": "8.1"
                },
                {
                    "id": "CVE-2019-0708",
                    "name": "CVE-2019-0708",
                    "creation_time": "2019-05-14T00:00:00Z",
                    "modification_time": "2019-05-20T00:00:00Z",
                    "description": "A remote code execution vulnerability exists in Remote Desktop Services formerly known as Terminal Services when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests (BlueKeep).",
                    "severity": "9.8",
                    "cvss": "9.8"
                }
            ]
            term = (search_term or "").strip().lower()
            filtered_mock = mock_data
            if term:
                filtered_mock = [
                    c for c in mock_data
                    if term in c["name"].lower() or term in c["description"].lower()
                ]
            start = (page - 1) * limit
            end = start + limit
            return {
                "cves": filtered_mock[start:end],
                "total": len(filtered_mock),
                "page": page,
                "limit": limit
            }

        key = f"cves:{search_term.strip().lower()}:{page}:{limit}"
        entry = self._cache.get(key)
        if entry and (time.time() - entry["ts"] < 3600):
            return entry["data"]

        def fetch(gmp):
            filter_str = f"rows={limit} first={(page - 1) * limit + 1} sort-reverse=creation_time"
            term = (search_term or "").strip()
            if term and term.upper() != "CVE":
                import re
                cve_match_exact = re.match(r'^cve-\d{4}-\d+$', term, re.IGNORECASE)
                cve_match_partial = re.match(r'^cve-\d{4}-?$', term, re.IGNORECASE)
                cve_start = re.match(r'^cve-?$', term, re.IGNORECASE)
                has_operator = any(op in term for op in ('=', '~', '>', '<', ':'))
                
                if has_operator:
                    filter_str += f" {term}"
                elif cve_match_exact:
                    filter_str += f' name="{term.upper()}"'
                elif cve_match_partial or cve_start:
                    filter_str += f' name~"{term.upper()}"'
                else:
                    filter_str += f' description~"{term}"'
            
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
        
        with self._gmp_lock:
            # Recheck cache inside lock
            entry = self._cache.get(key)
            if entry and (time.time() - entry["ts"] < 3600):
                return entry["data"]
            gmp = self._get_session()
            if gmp is None:
                raise RuntimeError("Not connected to OpenVAS")
            try:
                result = fetch(gmp)
            except Exception:
                self._close_session()
                self._open_session()
                gmp = self._session
                if gmp is None:
                    raise
                result = fetch(gmp)
            self._cache[key] = {"ts": time.time(), "data": result}
            return result

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

    def render_html_report(self, report: Dict[str, Any], metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Generate an enterprise-grade Infrastructure VAPT Audit Report for OpenVAS/GVM scans.
        Includes cover page, auditor details, approver details, full Scanned Contents Table of Contents,
        methodology, executive posture, and detailed findings.
        """
        import html
        metadata = metadata or {}
        summary = report.get("summary", {})
        vulns   = report.get("vulnerabilities", [])
        task    = report.get("task_name", "Infrastructure Security Assessment")
        start   = report.get("scan_start", "—")
        end     = report.get("scan_end", "—")

        # Metadata defaults & overrides
        report_date = metadata.get("report_date") or datetime.now().strftime("%d %b, %Y")
        doc_title   = metadata.get("doc_title") or f"Infrastructure Vulnerability Assessment & Penetration Testing Report"
        org_name    = metadata.get("organization") or metadata.get("company_name") or "Wyzmindz Solutions"
        prepared_by = metadata.get("prepared_by") or metadata.get("auditor") or "Santhosh M (Network Admin)"
        reviewed_by = metadata.get("reviewed_by") or metadata.get("approved_by") or "Leo Antony Charles (IT Manager)"
        doc_id      = metadata.get("doc_id") or "VAPT-GVM-" + datetime.now().strftime("%Y%m%d-%H%M")
        
        # Severity Colors
        sev_color = {
            "Critical": "#dc2626",
            "High": "#ea580c",
            "Medium": "#d97706",
            "Low": "#2563eb",
            "Log": "#64748b",
            "Info": "#64748b",
            "Informational": "#64748b"
        }

        # Calculate counts
        high_cnt = summary.get("high", 0)
        med_cnt  = summary.get("medium", 0)
        low_cnt  = summary.get("low", 0)
        log_cnt  = summary.get("log", 0)
        total_vulns = len(vulns)

        if high_cnt > 0:
            posture_level = "WEAK"
            posture_color = "#dc2626"
            posture_desc = "The infrastructure security posture is currently weak due to active high-severity vulnerabilities that present immediate operational and data compromise risks. Urgent patching is required."
        elif med_cnt > 0:
            posture_level = "MODERATE"
            posture_color = "#d97706"
            posture_desc = "The infrastructure displays a moderate security posture. While no immediate critical exploits were verified, medium-severity flaws require prioritized remediation to prevent exploitation chains."
        elif low_cnt > 0:
            posture_level = "GOOD"
            posture_color = "#2563eb"
            posture_desc = "A solid defensive baseline is maintained with only low-severity configuration hygiene items identified across the audited assets."
        else:
            posture_level = "EXCELLENT"
            posture_color = "#16a34a"
            posture_desc = "All assessed infrastructure assets passed without exploitable vulnerabilities, reflecting adherence to hardened security baselines."

        # Group vulnerabilities by host
        hosts = {}
        for v in vulns:
            h = v.get("host", "Unknown Host")
            if h not in hosts:
                hosts[h] = []
            hosts[h].append(v)

        host_list_str = ", ".join(list(hosts.keys())) if hosts else "Assigned Network Scope"

        # ── Table of Contents & Scanned Items List ──
        toc_hosts_html = ""
        host_num = 1
        for h, host_vulns in hosts.items():
            toc_hosts_html += f"""
            <div style="margin-top: 14px; margin-bottom: 8px;">
                <div style="font-weight: 700; color: #0284c7; font-size: 13px; margin-bottom: 6px;">
                    <a href="#host-{h}" style="color: #0284c7; text-decoration: none;">4.{host_num} Host: {html.escape(h)} <span style="font-size: 11px; color: #64748b; font-weight: normal;">({len(host_vulns)} Scanned Results)</span></a>
                </div>
                <table class="styled-table" style="font-size: 11px; margin-top: 4px; margin-bottom: 12px;">
                    <thead>
                        <tr style="background: #1e293b;">
                            <th style="width: 9%; text-align: center;">Item</th>
                            <th style="width: 14%; text-align: center;">Severity</th>
                            <th style="width: 16%;">Port / Proto</th>
                            <th>Scanned Vulnerability / NVT Test Name</th>
                            <th style="width: 10%; text-align: center;">CVSS</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            item_num = 1
            for v in host_vulns:
                raw_sev = (v.get("severity") or "Log").capitalize()
                sev = "Informational" if raw_sev in ["Log", "Info"] else raw_sev
                badge_bg = sev_color.get(sev, "#64748b")
                port = v.get("port", "general/tcp")
                name = v.get("name", "Vulnerability Finding")
                cvss_score = float(v.get("cvss", 0.0))
                
                toc_hosts_html += f"""
                        <tr>
                            <td style="text-align: center; font-weight: 600; color: #475569;">4.{host_num}.{item_num}</td>
                            <td style="text-align: center;"><span style="background: {badge_bg}; color: white; padding: 2px 7px; border-radius: 4px; font-weight: 700; font-size: 10px; text-transform: uppercase;">{sev}</span></td>
                            <td style="font-family: monospace; color: #0284c7; font-weight: 600;">{html.escape(port)}</td>
                            <td><a href="#vuln-{host_num}-{item_num}" style="color: #0f172a; text-decoration: none; font-weight: 600;">{html.escape(name)}</a></td>
                            <td style="text-align: center; font-weight: 700; color: {'#dc2626' if cvss_score>=7.0 else '#ea580c' if cvss_score>=4.0 else '#0f172a'};">{cvss_score:.1f}</td>
                        </tr>
                """
                item_num += 1

            toc_hosts_html += """
                    </tbody>
                </table>
            </div>
            """
            host_num += 1

        # ── Overview Table Rows ──
        overview_rows_html = ""
        for h, host_vulns in hosts.items():
            h_high = sum(1 for v in host_vulns if (v.get("severity") or "").capitalize() == "High")
            h_med  = sum(1 for v in host_vulns if (v.get("severity") or "").capitalize() == "Medium")
            h_low  = sum(1 for v in host_vulns if (v.get("severity") or "").capitalize() == "Low")
            h_log  = sum(1 for v in host_vulns if (v.get("severity") or "").capitalize() in ["Log", "Info"])
            overview_rows_html += f"""
            <tr>
                <td style="font-weight: 600; font-family: monospace; color: #0284c7;"><a href="#host-{h}" style="color: #0284c7; text-decoration: none;">{html.escape(h)}</a></td>
                <td style="text-align: center; font-weight: {'bold' if h_high>0 else 'normal'}; color: {'#dc2626' if h_high>0 else '#64748b'};">{h_high}</td>
                <td style="text-align: center; font-weight: {'bold' if h_med>0 else 'normal'}; color: {'#ea580c' if h_med>0 else '#64748b'};">{h_med}</td>
                <td style="text-align: center; color: {'#2563eb' if h_low>0 else '#64748b'};">{h_low}</td>
                <td style="text-align: center; color: #64748b;">{h_log}</td>
                <td style="text-align: center; font-weight: 700;">{len(host_vulns)}</td>
            </tr>
            """

        # ── Detailed Findings Cards ──
        findings_html = ""
        finding_id = 1
        h_idx = 1
        for h, host_vulns in hosts.items():
            findings_html += f"""
            <div id="host-{h}" style="margin-top: 30px; margin-bottom: 15px; padding-bottom: 6px; border-bottom: 2px solid #0f172a; display: flex; justify-content: space-between; align-items: flex-end;">
                <h3 style="margin: 0; color: #0f172a; font-size: 16px;">Target Host: <code style="color: #0284c7;">{html.escape(h)}</code></h3>
                <span style="font-size: 11px; color: #64748b;">{len(host_vulns)} Scanned Results</span>
            </div>
            """
            v_idx = 1
            for v in host_vulns:
                raw_sev = (v.get("severity") or "Log").capitalize()
                sev = "Informational" if raw_sev in ["Log", "Info"] else raw_sev
                color = sev_color.get(sev, "#64748b")
                port = v.get("port", "general/tcp")
                name = v.get("name", "Vulnerability Finding")
                cvss_score = float(v.get("cvss", 0.0))
                cve = v.get("cve", "")
                qod = v.get("qod", "")

                details_blocks = ""
                if v.get("description"):
                    details_blocks += f"""
                    <div style="margin-top: 10px;">
                        <h5 style="margin: 0 0 4px 0; font-size: 12px; text-transform: uppercase; color: #0f172a; letter-spacing: 0.5px;">Summary &amp; Description</h5>
                        <p style="margin: 0 0 10px 0; color: #334155; font-size: 12px; line-height: 1.6; text-align: justify;">{html.escape(v.get('description',''))}</p>
                    </div>
                    """

                if v.get("vuldetect"):
                    details_blocks += f"""
                    <div style="margin-top: 8px;">
                        <h5 style="margin: 0 0 4px 0; font-size: 11px; text-transform: uppercase; color: #475569;">Vulnerability Detection Method</h5>
                        <pre style="background: #0f172a; color: #38bdf8; padding: 10px 12px; border-radius: 6px; font-family: monospace; font-size: 11px; line-height: 1.4; white-space: pre-wrap; margin: 0 0 10px 0;">{html.escape(v.get('vuldetect',''))}</pre>
                    </div>
                    """

                if v.get("impact"):
                    details_blocks += f"""
                    <div style="margin-top: 8px;">
                        <h5 style="margin: 0 0 4px 0; font-size: 11px; text-transform: uppercase; color: #dc2626;">Technical Impact</h5>
                        <p style="margin: 0 0 10px 0; color: #334155; font-size: 12px; line-height: 1.5;">{html.escape(v.get('impact',''))}</p>
                    </div>
                    """

                if v.get("solution"):
                    sol_type_badge = f"<span style='background: #e2e8f0; color: #334155; padding: 2px 6px; border-radius: 3px; font-size: 10px; margin-left: 6px;'>{html.escape(v.get('solution_type','Mitigation'))}</span>" if v.get("solution_type") else ""
                    details_blocks += f"""
                    <div style="margin-top: 10px; background: #f0fdf4; border-left: 4px solid #16a34a; padding: 12px 16px; border-radius: 0 6px 6px 0;">
                        <h5 style="margin: 0 0 4px 0; font-size: 12px; text-transform: uppercase; color: #15803d; font-weight: 700;">Remediation &amp; Mitigation {sol_type_badge}</h5>
                        <p style="margin: 0; color: #166534; font-size: 12px; line-height: 1.5;">{html.escape(v.get('solution',''))}</p>
                    </div>
                    """

                if cve and cve != "N/A":
                    details_blocks += f"""
                    <div style="margin-top: 8px; font-size: 11px; color: #64748b;">
                        <strong>CVE References:</strong> <code style="color: #ea580c;">{html.escape(cve)}</code>
                    </div>
                    """

                findings_html += f"""
                <div id="vuln-{h_idx}-{v_idx}" class="finding-card" style="page-break-inside: avoid; border: 1px solid #e2e8f0; border-radius: 8px; margin-bottom: 20px; background: #ffffff; box-shadow: 0 1px 3px rgba(0,0,0,0.05); overflow: hidden;">
                    <div style="background: #f8fafc; border-bottom: 2px solid {color}; padding: 10px 16px; display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <span style="background: {color}; color: white; padding: 3px 8px; border-radius: 4px; font-weight: 800; font-size: 11px; margin-right: 8px;">#{finding_id} (4.{h_idx}.{v_idx})</span>
                            <strong style="font-size: 14px; color: #0f172a;">{html.escape(name)}</strong>
                        </div>
                        <span style="background: {color}; color: white; padding: 4px 10px; border-radius: 4px; font-weight: 700; font-size: 11px; text-transform: uppercase;">{sev}</span>
                    </div>
                    <div style="padding: 14px 18px;">
                        <table style="width: 100%; border-collapse: collapse; margin-bottom: 10px; font-size: 12px;">
                            <tr style="border-bottom: 1px solid #f1f5f9;">
                                <td style="width: 25%; padding: 5px 0; color: #64748b; font-weight: 600;">TARGET PORT</td>
                                <td style="padding: 5px 0; font-family: monospace; color: #0284c7; font-weight: 600;">{html.escape(port)}</td>
                            </tr>
                            <tr style="border-bottom: 1px solid #f1f5f9;">
                                <td style="padding: 5px 0; color: #64748b; font-weight: 600;">CVSS v3.1 BASE SCORE</td>
                                <td style="padding: 5px 0; color: #0f172a;"><strong>{cvss_score:.1f}</strong> / 10.0</td>
                            </tr>
                            {f'<tr style="border-bottom: 1px solid #f1f5f9;"><td style="padding: 5px 0; color: #64748b; font-weight: 600;">DETECTION QUALITY (QoD)</td><td style="padding: 5px 0; color: #334155;">{qod}%</td></tr>' if qod else ''}
                        </table>
                        {details_blocks}
                    </div>
                </div>
                """
                finding_id += 1
                v_idx += 1
            h_idx += 1

        # ── Full HTML Document ──
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Infrastructure VAPT Report - {html.escape(task)}</title>
    <style>
        @page {{
            size: A4;
            margin: 18mm 15mm 18mm 15mm;
            @bottom-right {{
                content: counter(page);
            }}
        }}
        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif;
            color: #1e293b;
            background: #ffffff;
            line-height: 1.5;
            margin: 0;
            padding: 0;
            font-size: 12px;
        }}
        .page-break {{ page-break-before: always; }}
        .no-break {{ page-break-inside: avoid; }}
        .report-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #e2e8f0;
            padding-bottom: 8px;
            margin-bottom: 24px;
            font-size: 11px;
            color: #64748b;
        }}
        .brand-logo {{
            font-size: 18px;
            font-weight: 800;
            color: #0f172a;
            letter-spacing: -0.5px;
        }}
        .brand-logo span {{ color: #0284c7; }}
        .cover-container {{
            min-height: 85vh;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            padding: 40px 10px;
        }}
        .cover-title {{
            font-size: 30px;
            font-weight: 800;
            color: #0f172a;
            line-height: 1.2;
            margin: 0 0 10px 0;
        }}
        .cover-subtitle {{
            font-size: 16px;
            color: #0284c7;
            font-weight: 600;
            margin: 0 0 40px 0;
        }}
        .meta-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 25px;
            font-size: 13px;
        }}
        .meta-table td {{
            padding: 9px 14px;
            border-bottom: 1px solid #e2e8f0;
        }}
        .meta-table td:first-child {{
            font-weight: 700;
            color: #475569;
            width: 35%;
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.5px;
            background: #f8fafc;
        }}
        table.styled-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 16px 0;
            font-size: 12px;
        }}
        table.styled-table th {{
            background: #0f172a;
            color: #ffffff;
            font-weight: 600;
            text-align: left;
            padding: 9px 12px;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        table.styled-table td {{
            padding: 9px 12px;
            border-bottom: 1px solid #e2e8f0;
            color: #334155;
        }}
        table.styled-table tr:nth-child(even) {{ background: #f8fafc; }}
        h1, h2, h3, h4, h5 {{ color: #0f172a; font-weight: 700; }}
        h2.section-heading {{
            font-size: 18px;
            border-bottom: 2px solid #0f172a;
            padding-bottom: 6px;
            margin-top: 35px;
            margin-bottom: 16px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .kpi-card {{
            border-radius: 8px;
            padding: 14px;
            text-align: center;
            flex: 1;
            color: white;
        }}
        .kpi-number {{ font-size: 26px; font-weight: 800; line-height: 1; margin-bottom: 4px; }}
        .kpi-label {{ font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }}
    </style>
</head>
<body>

    <!-- ════════════════════════ COVER PAGE ════════════════════════ -->
    <div class="cover-container">
        <div class="report-header">
            <div class="brand-logo">VAPT<span>SHIELD</span> // INFRASTRUCTURE AUDIT</div>
            <div>{html.escape(report_date)}</div>
        </div>

        <div style="margin-top: 50px;">
            <div style="display: inline-block; background: #e0f2fe; color: #0369a1; padding: 6px 14px; border-radius: 20px; font-weight: 700; font-size: 12px; text-transform: uppercase; margin-bottom: 16px; letter-spacing: 1px;">
                INTERNAL SECURITY ASSESSMENT REPORT
            </div>
            <h1 class="cover-title">{html.escape(doc_title)}</h1>
            <div class="cover-subtitle">Task: {html.escape(task)}</div>
        </div>

        <div>
            <table class="meta-table">
                <tr>
                    <td>Report Release Date</td>
                    <td><strong>{html.escape(report_date)}</strong></td>
                </tr>
                <tr>
                    <td>Client / Organization</td>
                    <td><strong>{html.escape(org_name)}</strong></td>
                </tr>
                <tr>
                    <td>Assessment Conducted By</td>
                    <td><strong>{html.escape(prepared_by)}</strong></td>
                </tr>
                <tr>
                    <td>Reviewed &amp; Approved By</td>
                    <td><strong>{html.escape(reviewed_by)}</strong></td>
                </tr>
                <tr>
                    <td>Type of Audit</td>
                    <td>Internal Infrastructure Vulnerability Assessment &amp; Penetration Testing (OpenVAS / GVM)</td>
                </tr>
                <tr>
                    <td>Target Scope / Hosts</td>
                    <td><code style="color: #0284c7;">{html.escape(host_list_str)}</code></td>
                </tr>
                <tr>
                    <td>Assessment Execution Period</td>
                    <td>{html.escape(start)} &mdash; {html.escape(end)}</td>
                </tr>
                <tr>
                    <td>Security Tools Employed</td>
                    <td>OpenVAS / Greenbone Community Feed (80,000+ NVTs), Nmap Port Scanner, CVSS v3.1 Engine</td>
                </tr>
                <tr>
                    <td>Overall Security Posture</td>
                    <td>
                        <span style="background: {posture_color}; color: white; padding: 4px 10px; border-radius: 4px; font-weight: 800; font-size: 11px;">
                            {posture_level}
                        </span>
                    </td>
                </tr>
            </table>
        </div>

        <div style="margin-top: 35px; border-top: 1px solid #e2e8f0; padding-top: 12px; font-size: 11px; color: #94a3b8; display: flex; justify-content: space-between;">
            <div>Confidential &mdash; For Internal Security Review Only</div>
            <div>Generated for {html.escape(org_name)}</div>
        </div>
    </div>

    <!-- ════════════════════════ TABLE OF CONTENTS & SCANNED ITEMS ════════════════════════ -->
    <div class="page-break"></div>
    <div class="report-header">
        <div>Infrastructure VAPT // {html.escape(org_name)}</div>
        <div>{html.escape(report_date)}</div>
    </div>

    <h2 class="section-heading">Table of Contents &amp; Scanned Contents Index</h2>
    <div style="font-size: 12px; line-height: 1.8; color: #334155; margin-bottom: 25px;">
        <div style="margin-bottom: 12px; padding: 12px 16px; background: #f8fafc; border-radius: 6px; border-left: 4px solid #0284c7;">
            <div style="font-weight: 700; color: #0f172a; margin-bottom: 4px;"><a href="#sec-exec" style="color: #0f172a; text-decoration: none;">1. Executive Summary &amp; Security Posture</a></div>
            <div style="font-weight: 700; color: #0f172a; margin-bottom: 4px;"><a href="#sec-methodology" style="color: #0f172a; text-decoration: none;">2. Scanning Methodology &amp; Tools Employed</a></div>
            <div style="font-weight: 700; color: #0f172a; margin-bottom: 4px;"><a href="#sec-scope" style="color: #0f172a; text-decoration: none;">3. Assessment Scope &amp; Result Overview per Host</a></div>
            <div style="font-weight: 700; color: #0f172a;"><a href="#sec-findings" style="color: #0f172a; text-decoration: none;">4. Detailed Vulnerability Observations &amp; Scanned Results</a></div>
        </div>

        {toc_hosts_html}

        <div style="margin-top: 14px; padding: 12px 16px; background: #f8fafc; border-radius: 6px; border-left: 4px solid #0284c7;">
            <div style="font-weight: 700; color: #0f172a; margin-bottom: 4px;"><a href="#sec-remediation" style="color: #0f172a; text-decoration: none;">5. Remediation Roadmap &amp; Best Practices</a></div>
            <div style="font-weight: 700; color: #0f172a;"><a href="#sec-appendix" style="color: #0f172a; text-decoration: none;">6. Appendix &amp; Security Glossary</a></div>
        </div>
    </div>

    <!-- ════════════════════════ EXECUTIVE SUMMARY ════════════════════════ -->
    <div class="page-break"></div>
    <div class="report-header">
        <div>Infrastructure VAPT // {html.escape(org_name)}</div>
        <div>{html.escape(report_date)}</div>
    </div>

    <h2 id="sec-exec" class="section-heading">1. Executive Summary &amp; Security Posture</h2>
    <div style="font-size: 12px; line-height: 1.7; color: #334155; margin-bottom: 24px; text-align: justify;">
        <p>
            An internal infrastructure vulnerability assessment was performed against the designated scope (<strong>{html.escape(host_list_str)}</strong>) under task <strong>{html.escape(task)}</strong> for <strong>{html.escape(org_name)}</strong>. The objective was to discover reachable services, evaluate system hardening standards, identify unpatched Common Vulnerabilities and Exposures (CVEs), and assess overall infrastructure risk.
        </p>
        <div style="background: #f8fafc; border-left: 4px solid {posture_color}; padding: 14px 18px; border-radius: 0 8px 8px 0; margin: 16px 0;">
            <strong style="color: #0f172a; font-size: 13px;">POSTURE ASSESSMENT: <span style="color: {posture_color};">{posture_level}</span></strong>
            <p style="margin: 6px 0 0; color: #475569; font-size: 12px;">{posture_desc}</p>
        </div>
    </div>

    <!-- KPI Cards -->
    <div style="display: flex; gap: 12px; margin-bottom: 30px;">
        <div class="kpi-card" style="background: #dc2626;">
            <div class="kpi-number">{high_cnt}</div>
            <div class="kpi-label">High Severity</div>
        </div>
        <div class="kpi-card" style="background: #ea580c;">
            <div class="kpi-number">{med_cnt}</div>
            <div class="kpi-label">Medium Severity</div>
        </div>
        <div class="kpi-card" style="background: #2563eb;">
            <div class="kpi-number">{low_cnt}</div>
            <div class="kpi-label">Low Severity</div>
        </div>
        <div class="kpi-card" style="background: #64748b;">
            <div class="kpi-number">{log_cnt}</div>
            <div class="kpi-label">Informational</div>
        </div>
        <div class="kpi-card" style="background: #0f172a;">
            <div class="kpi-number">{total_vulns}</div>
            <div class="kpi-label">Total Findings</div>
        </div>
    </div>

    <!-- ════════════════════════ METHODOLOGY & TOOLS ════════════════════════ -->
    <h2 id="sec-methodology" class="section-heading">2. Scanning Methodology &amp; Tools Employed</h2>
    <div style="font-size: 12px; line-height: 1.7; color: #334155; text-align: justify;">
        <p>
            The audit utilized an industry-standard, multi-phase vulnerability assessment methodology adhering to <strong>NIST SP 800-115</strong> (Technical Guide to Information Security Testing and Assessment) and <strong>CVSS v3.1</strong> scoring metrics:
        </p>
        <table class="styled-table">
            <thead>
                <tr>
                    <th style="width: 28%;">Tool / Module</th>
                    <th style="width: 22%;">Version / Feed</th>
                    <th>Functional Scope &amp; Audit Rationale</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><strong>OpenVAS / GVM</strong></td>
                    <td>Greenbone Community Feed (80k+ NVTs)</td>
                    <td>Comprehensive network vulnerability scanner executing authenticated and unauthenticated Network Vulnerability Tests (NVTs) to discover CVEs, missing patches, and insecure service configurations.</td>
                </tr>
                <tr>
                    <td><strong>Nmap Network Mapper</strong></td>
                    <td>v7.94 Engine</td>
                    <td>Performs active TCP/UDP host discovery, service fingerprinting, and port state analysis prior to deep vulnerability scanning.</td>
                </tr>
                <tr>
                    <td><strong>CVSS v3.1 Engine</strong></td>
                    <td>FIRST Standard Framework</td>
                    <td>Provides standardized vulnerability severity scoring evaluating exploitability metrics (Attack Vector, Attack Complexity, Privileges Required) and impact (Confidentiality, Integrity, Availability).</td>
                </tr>
            </tbody>
        </table>
    </div>

    <!-- ════════════════════════ RESULT OVERVIEW PER HOST ════════════════════════ -->
    <div class="page-break"></div>
    <div class="report-header">
        <div>Infrastructure VAPT // {html.escape(org_name)}</div>
        <div>{html.escape(report_date)}</div>
    </div>

    <h2 id="sec-scope" class="section-heading">3. Assessment Scope &amp; Result Overview per Host</h2>
    <table class="styled-table">
        <thead>
            <tr>
                <th>Target Host</th>
                <th style="text-align: center;">High</th>
                <th style="text-align: center;">Medium</th>
                <th style="text-align: center;">Low</th>
                <th style="text-align: center;">Info / Log</th>
                <th style="text-align: center;">Total Findings</th>
            </tr>
        </thead>
        <tbody>
            {overview_rows_html}
            <tr style="background: #f1f5f9; font-weight: 800; border-top: 2px solid #0f172a;">
                <td>Total ({len(hosts)} Hosts)</td>
                <td style="text-align: center; color: #dc2626;">{high_cnt}</td>
                <td style="text-align: center; color: #ea580c;">{med_cnt}</td>
                <td style="text-align: center; color: #2563eb;">{low_cnt}</td>
                <td style="text-align: center; color: #64748b;">{log_cnt}</td>
                <td style="text-align: center;">{total_vulns}</td>
            </tr>
        </tbody>
    </table>

    <!-- ════════════════════════ DETAILED FINDINGS ════════════════════════ -->
    <div class="page-break"></div>
    <div class="report-header">
        <div>Infrastructure VAPT // {html.escape(org_name)}</div>
        <div>{html.escape(report_date)}</div>
    </div>

    <h2 id="sec-findings" class="section-heading">4. Detailed Vulnerability Observations &amp; Scanned Results</h2>
    {findings_html if findings_html else "<div style='padding: 30px; text-align: center; color: #16a34a; font-weight: 600;'>No vulnerabilities were identified across the audited assets.</div>"}

    <!-- ════════════════════════ REMEDIATION & CONCLUSION ════════════════════════ -->
    <div class="page-break"></div>
    <div class="report-header">
        <div>Infrastructure VAPT // {html.escape(org_name)}</div>
        <div>{html.escape(report_date)}</div>
    </div>

    <h2 id="sec-remediation" class="section-heading">5. Remediation Roadmap &amp; Best Practices</h2>
    <div style="font-size: 12px; line-height: 1.7; color: #334155; text-align: justify;">
        <p>
            Remediating the security observations identified during this audit requires a structured patch management and system hardening roadmap:
        </p>
        <table class="styled-table">
            <thead>
                <tr>
                    <th style="width: 25%;">Severity Level</th>
                    <th style="width: 25%;">Recommended SLA</th>
                    <th>Action Plan</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><span style="background: #dc2626; color: white; padding: 2px 8px; border-radius: 3px; font-weight: 700;">HIGH / CRITICAL</span></td>
                    <td><strong>Within 48 &mdash; 96 Hours</strong></td>
                    <td>Immediately apply vendor patches, disable vulnerable services, or implement temporary firewall/network isolation.</td>
                </tr>
                <tr>
                    <td><span style="background: #ea580c; color: white; padding: 2px 8px; border-radius: 3px; font-weight: 700;">MEDIUM</span></td>
                    <td><strong>Within 10 Days</strong></td>
                    <td>Review service configuration, upgrade dependent software packages, and enforce strong cryptographic cipher suites.</td>
                </tr>
                <tr>
                    <td><span style="background: #2563eb; color: white; padding: 2px 8px; border-radius: 3px; font-weight: 700;">LOW</span></td>
                    <td><strong>Within 15 &mdash; 30 Days</strong></td>
                    <td>Address security hygiene recommendations, disable obsolete banners, and schedule regular maintenance windows.</td>
                </tr>
            </tbody>
        </table>
    </div>

    <h2 id="sec-appendix" class="section-heading" style="margin-top: 30px;">6. Appendix &amp; Security Glossary</h2>
    <table class="styled-table" style="font-size: 11px;">
        <tr><td style="width: 25%; font-weight: bold; background: #f8fafc;">VAPT</td><td>Vulnerability Assessment and Penetration Testing &mdash; A structured audit methodology identifying and assessing vulnerabilities in IT assets.</td></tr>
        <tr><td style="font-weight: bold; background: #f8fafc;">NVT</td><td>Network Vulnerability Test &mdash; A specialized scanning script in OpenVAS/GVM designed to detect a specific CVE, configuration flaw, or exploit signature.</td></tr>
        <tr><td style="font-weight: bold; background: #f8fafc;">CVSS v3.1</td><td>Common Vulnerability Scoring System &mdash; Standardized numerical framework assessing vulnerability severity from 0.0 to 10.0.</td></tr>
        <tr><td style="font-weight: bold; background: #f8fafc;">CVE</td><td>Common Vulnerabilities and Exposures &mdash; Public dictionary of standardized identifiers for known software vulnerabilities.</td></tr>
        <tr><td style="font-weight: bold; background: #f8fafc;">QoD</td><td>Quality of Detection &mdash; Greenbone metric (0-100%) expressing confidence in the vulnerability detection accuracy.</td></tr>
    </table>

</body>
</html>
"""

    def _cache_get(self, key: str):
        entry = self._cache.get(key)
        if entry and (time.time() - entry["ts"] < self._cache_ttl):
            return entry["data"]
        return None

    def _cache_set(self, key: str, data: Any):
        self._cache[key] = {"ts": time.time(), "data": data}
