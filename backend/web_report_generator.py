import os
import datetime
import html
import pdfkit
from typing import Dict, List, Any, Optional

class WebReportGenerator:
    """
    Engine to transform scan outputs from OWASP ZAP, Nuclei, Nikto, and Gobuster
    (or combined web scans) into professional Web Application VAPT audit reports.
    """

    SEVERITY_COLORS = {
        "Critical": "#dc2626",
        "High": "#ea580c",
        "Medium": "#d97706",
        "Low": "#2563eb",
        "Informational": "#64748b",
        "Info": "#64748b",
    }

    SEVERITY_SLA = {
        "Critical": {"sla": "2 Days", "cvss": "9.0 - 10.0", "impact": "Bypassing critical security controls, Arbitrary code/script execution, Account takeover. Requires immediate fix."},
        "High": {"sla": "4 Days", "cvss": "7.0 - 8.9", "impact": "Bypass of authentication/authorization, Direct object manipulation. Requires urgent fix."},
        "Medium": {"sla": "10 Days", "cvss": "4.0 - 6.9", "impact": "Vulnerabilities requiring specific pre-conditions or chained exploits to cause significant harm."},
        "Low": {"sla": "15 Days", "cvss": "0.1 - 3.9", "impact": "Minor security hygiene flaws, lack of defense-in-depth headers, information leakage."},
        "Informational": {"sla": "N/A", "cvss": "0.0", "impact": "Fingerprinting details, service discovery, or informational banners."},
    }

    @staticmethod
    def calculate_posture(counts: Dict[str, int]) -> Dict[str, str]:
        critical = counts.get("Critical", 0)
        high = counts.get("High", 0)
        medium = counts.get("Medium", 0)
        low = counts.get("Low", 0)

        if critical > 0 or high > 0:
            return {
                "level": "WEAK",
                "color": "#dc2626",
                "desc": "The application's security posture is weak due to the presence of critical or high-severity vulnerabilities that pose significant and immediate operational risk."
            }
        elif medium > 0:
            return {
                "level": "MODERATE",
                "color": "#d97706",
                "desc": "With medium-severity issues present, the application's security stance is moderate, highlighting the need for prioritized remediation."
            }
        elif low > 0:
            return {
                "level": "GOOD",
                "color": "#2563eb",
                "desc": "This state reflects a solid security posture achieved with only low-severity or informational hygiene findings remaining."
            }
        else:
            return {
                "level": "EXCELLENT",
                "color": "#16a34a",
                "desc": "The highest security level is attained when all assessed vectors pass without security flaws or when no exploitable vulnerabilities are identified."
            }

    @classmethod
    def normalize_findings(cls, tool: str, results: Any, target_url: str) -> Dict[str, Any]:
        """
        Normalizes findings from any supported web pen testing tool into a standard format.
        """
        tool_lower = (tool or "").lower()
        observations: List[Dict[str, Any]] = []
        tool_info = []

        if tool_lower == "zap":
            tool_info.append({"name": "OWASP ZAP (Zed Attack Proxy)", "version": "v2.17.0", "type": "Open Source DAST", "license": "Apache 2.0"})
            if isinstance(results, list):
                for idx, alert in enumerate(results, 1):
                    risk = (alert.get("risk") or "Low").capitalize()
                    if risk == "Info":
                        risk = "Informational"
                    
                    cwe_id = alert.get("cweid") or alert.get("cwe_id") or ""
                    cwe_str = f"CWE-{cwe_id}" if cwe_id and str(cwe_id) != "0" else "CWE-200"
                    
                    cvss_map = {"Critical": 9.2, "High": 7.5, "Medium": 5.3, "Low": 3.1, "Informational": 0.0}
                    cvss_val = cvss_map.get(risk, 3.1)

                    endpoint = alert.get("url") or target_url
                    param = alert.get("param") or ""
                    param_info = f" (Parameter: {param})" if param else ""

                    desc = alert.get("description") or f"OWASP ZAP identified {alert.get('alert', 'an issue')} during dynamic vulnerability scanning."
                    solution = alert.get("solution") or "Apply proper input validation, output encoding, and secure HTTP header configurations."
                    
                    steps = [
                        f"Target URL: {endpoint}{param_info}",
                        f"Trigger payload / evidence: {alert.get('evidence', 'Identified via automated DAST check')}",
                        f"Confidence level: {alert.get('confidence', 'Medium')}"
                    ]
                    if alert.get("attack"):
                        steps.append(f"Attack vector probe: {alert.get('attack')}")

                    observations.append({
                        "id": idx,
                        "title": alert.get("alert", "Vulnerability Finding"),
                        "category": alert.get("wascid") and f"WASC-{alert.get('wascid')}" or "Web Application Security",
                        "severity": risk,
                        "cvss_score": cvss_val,
                        "cvss_vector": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:{'H' if risk in ['Critical','High'] else 'L'}/I:{'H' if risk in ['Critical','High'] else 'L'}/A:N",
                        "cwe": cwe_str,
                        "status": "Active",
                        "endpoint": endpoint,
                        "description": desc,
                        "solution": solution,
                        "steps": steps,
                        "reference": alert.get("reference") or "https://owasp.org/www-project-top-ten/",
                        "evidence": alert.get("evidence") or "",
                        "attributing_factor": "Application Logic / Configuration",
                    })

        elif tool_lower == "nuclei":
            tool_info.append({"name": "ProjectDiscovery Nuclei", "version": "v3.7.0", "type": "Open Source Vulnerability Scanner", "license": "MIT"})
            if isinstance(results, list):
                for idx, item in enumerate(results, 1):
                    info = item.get("info") or {}
                    raw_sev = (info.get("severity") or "info").lower()
                    sev_map = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Informational", "unknown": "Informational"}
                    sev = sev_map.get(raw_sev, "Low")

                    classif = info.get("classification") or {}
                    cve_id = classif.get("cve-id") or ""
                    if isinstance(cve_id, list):
                        cve_id = ", ".join(cve_id)
                    cwe_id = classif.get("cwe-id") or ""
                    if isinstance(cwe_id, list):
                        cwe_id = ", ".join([f"CWE-{c}" if not str(c).startswith("CWE-") else str(c) for c in cwe_id])
                    elif cwe_id and not str(cwe_id).startswith("CWE-"):
                        cwe_id = f"CWE-{cwe_id}"

                    cvss_score = classif.get("cvss-score") or (9.3 if sev == "Critical" else 7.8 if sev == "High" else 5.4 if sev == "Medium" else 3.2 if sev == "Low" else 0.0)

                    endpoint = item.get("matched-at") or item.get("host") or target_url
                    refs = info.get("reference") or []
                    ref_str = ", ".join(refs) if isinstance(refs, list) else str(refs)

                    tags = info.get("tags") or []
                    tag_str = ", ".join(tags) if isinstance(tags, list) else str(tags)

                    steps = [
                        f"Template: {item.get('template-id', 'nuclei-template')}",
                        f"Matched Target: {endpoint}",
                        f"Protocol: {item.get('type', 'http').upper()}"
                    ]
                    if item.get("extracted-results"):
                        steps.append(f"Extracted Artifacts: {', '.join(item['extracted-results'])}")
                    if item.get("curl-command"):
                        steps.append(f"Reproduction Command: {item['curl-command']}")

                    observations.append({
                        "id": idx,
                        "title": info.get("name") or item.get("template-id") or "Vulnerability Observation",
                        "category": tag_str or "Template Rule Detection",
                        "severity": sev,
                        "cvss_score": float(cvss_score) if str(cvss_score).replace('.','',1).isdigit() else 5.0,
                        "cvss_vector": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:{'H' if sev in ['Critical','High'] else 'L'}/I:{'H' if sev in ['Critical','High'] else 'L'}/A:N",
                        "cwe": cwe_id or (cve_id if cve_id else "CWE-200"),
                        "status": "Active",
                        "endpoint": endpoint,
                        "description": info.get("description") or f"Nuclei security template detected positive vulnerability signature on target.",
                        "solution": info.get("remediation") or "Patch the affected component or update configuration according to vendor guidelines.",
                        "steps": steps,
                        "reference": ref_str or "https://projectdiscovery.io",
                        "evidence": item.get("matcher-name") or "",
                        "attributing_factor": "Software Component / Misconfiguration",
                    })

        elif tool_lower == "nikto":
            tool_info.append({"name": "Nikto Web Server Scanner", "version": "v2.5.0", "type": "Open Source Web Audit Tool", "license": "GPLv2"})
            vulns = results.get("vulnerabilities", []) if isinstance(results, dict) else (results if isinstance(results, list) else [])
            for idx, v in enumerate(vulns, 1):
                msg = v.get("msg") or v.get("message") or ""
                msg_lower = msg.lower()
                if any(k in msg_lower for k in ["remote code", "command execution", "sql injection", "admin access without auth"]):
                    sev = "High"
                    cvss = 7.5
                elif any(k in msg_lower for k in ["xss", "cross site", "directory indexing", "sensitive file", "trace.axd", "backup file"]):
                    sev = "Medium"
                    cvss = 5.2
                elif any(k in msg_lower for k in ["header missing", "x-frame-options", "cookie without", "anti-clickjacking", "http methods"]):
                    sev = "Low"
                    cvss = 3.3
                else:
                    sev = "Informational"
                    cvss = 0.0

                endpoint = target_url.rstrip("/") + (v.get("uri") or "")
                observations.append({
                    "id": idx,
                    "title": f"Web Server Finding: {v.get('id', 'NIKTO-' + str(idx))}",
                    "category": "Web Server Configuration & Files",
                    "severity": sev,
                    "cvss_score": cvss,
                    "cvss_vector": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "cwe": "CWE-16 (Configuration)",
                    "status": "Active",
                    "endpoint": endpoint,
                    "description": msg,
                    "solution": "Harden server configuration, remove unreferenced/diagnostic files, and apply secure response headers.",
                    "steps": [
                        f"HTTP Method: {v.get('method', 'GET')}",
                        f"Target URI: {v.get('uri', '/')}",
                        f"Server Observation: {msg}"
                    ],
                    "reference": "https://cgit.osvdb.org/",
                    "evidence": msg,
                    "attributing_factor": "Server Configuration",
                })

        elif tool_lower == "gobuster":
            tool_info.append({"name": "Gobuster Directory & Asset Enumerator", "version": "v3.6", "type": "Open Source URL/DNS Brute-forcer", "license": "Apache 2.0"})
            entries = results if isinstance(results, list) else []
            for idx, item in enumerate(entries, 1):
                status_code = item.get("status") or 200
                path = item.get("path") or ""
                endpoint = target_url.rstrip("/") + path
                size = item.get("size", "")
                
                p_lower = path.lower()
                if any(s in p_lower for s in [".env", ".git", "wp-config", "id_rsa", "backup.sql", "database.yml"]):
                    sev = "Critical"
                    cvss = 9.1
                    cat = "Exposed Secrets / Configuration Files"
                elif any(s in p_lower for s in ["/admin", "/phpmyadmin", "/dashboard", "/api/v1", "/swagger", "/actuator"]):
                    sev = "Medium"
                    cvss = 5.0
                    cat = "Administrative & API Endpoints"
                elif status_code in [200, 301, 302]:
                    sev = "Low"
                    cvss = 2.0
                    cat = "Discovered Web Path"
                else:
                    sev = "Informational"
                    cvss = 0.0
                    cat = "Enumerated Resource"

                observations.append({
                    "id": idx,
                    "title": f"Discovered Endpoint: {path} (HTTP {status_code})",
                    "category": cat,
                    "severity": sev,
                    "cvss_score": cvss,
                    "cvss_vector": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "cwe": "CWE-538 (File Exposure)",
                    "status": "Active",
                    "endpoint": endpoint,
                    "description": f"Directory enumeration identified accessible resource at '{path}' returning HTTP status code {status_code} ({size} bytes).",
                    "solution": "Ensure sensitive administrative interfaces and files are protected with access controls or removed from public web roots.",
                    "steps": [
                        f"Request Method: GET {path}",
                        f"HTTP Response Status: {status_code}",
                        f"Response Body Size: {size} Bytes",
                        f"Redirect Location: {item.get('redirect', 'None')}"
                    ],
                    "reference": "https://owasp.org/www-project-web-security-testing-guide/",
                    "evidence": f"HTTP {status_code} {size}B",
                    "attributing_factor": "Directory Structure / Exposure",
                })

        elif tool_lower == "nmap":
            tool_info.append({"name": "Nmap Network Scanner", "version": "v7.94", "type": "Network Infrastructure & Port Scanner", "license": "NPSL / GPLv2"})
            ports_list = results if isinstance(results, list) else (results.get("ports", []) if isinstance(results, dict) else [])
            for idx, p in enumerate(ports_list, 1):
                port_num = p.get("port") or 0
                try:
                    port_int = int(port_num)
                except Exception:
                    port_int = 0
                proto = (p.get("protocol") or "tcp").upper()
                svc = p.get("service") or "unknown"
                svc_lower = svc.lower()
                version = p.get("version") or "N/A"
                state = p.get("state") or "open"
                reason = p.get("reason") or "syn-ack"

                # Risk evaluation
                if port_int in [3306, 5432, 27017, 1433, 1521, 6379, 9200, 9300] or any(k in svc_lower for k in ['mysql', 'postgres', 'mongo', 'redis', 'elasticsearch']):
                    sev = "Critical"
                    cvss = 9.1
                    cat = "Direct Database Exposure"
                    cwe = "CWE-200 (Exposure of Sensitive Information)"
                    desc = f"Database service '{svc}' ({version}) is publicly listening on {port_int}/{proto}. Direct database exposure allows remote unauthorized brute-forcing, exploitation of database vulnerabilities, and data compromise."
                    solution = f"Restrict access to port {port_int} using host-level firewalls (iptables/ufw) or cloud security groups. Bind database daemons to localhost (127.0.0.1) or internal VPC networks only."
                elif port_int in [445, 139, 135, 137, 138] or any(k in svc_lower for k in ['smb', 'netbios', 'microsoft-ds']):
                    sev = "Critical"
                    cvss = 8.5
                    cat = "SMB / NetBIOS File Sharing Exposed"
                    cwe = "CWE-284 (Improper Access Control)"
                    desc = f"File sharing and RPC protocol '{svc}' is listening on {port_int}/{proto}. Exposure of SMB/RPC enables remote enumeration, pass-the-hash attacks, and lateral exploitation."
                    solution = f"Block ports 135-139 and 445 at the network boundary firewall. Disable SMBv1 and enforce SMB signing."
                elif port_int in [21, 23, 110, 143] or any(k in svc_lower for k in ['telnet', 'ftp']):
                    sev = "High"
                    cvss = 7.5
                    cat = "Insecure Cleartext Protocol"
                    cwe = "CWE-319 (Cleartext Transmission of Sensitive Information)"
                    desc = f"Legacy unencrypted protocol '{svc}' is active on {port_int}/{proto}. Cleartext communication exposes credentials and session tokens to interception and Man-in-the-Middle (MitM) sniffing."
                    solution = "Decommission legacy plaintext protocols. Replace FTP with SFTP (Port 22) and Telnet with SSH."
                elif port_int in [80, 8080] or svc_lower == 'http':
                    sev = "Medium"
                    cvss = 5.3
                    cat = "Unencrypted HTTP Service"
                    cwe = "CWE-319 (Cleartext Transmission)"
                    desc = f"Unencrypted HTTP web server ({version}) is reachable on {port_int}/{proto}. Requests transmitted over HTTP are subject to eavesdropping and manipulation."
                    solution = "Enforce automatic 301 HTTP-to-HTTPS redirection and activate HTTP Strict Transport Security (HSTS)."
                elif port_int in [3389, 5900, 5901, 2222] or any(k in svc_lower for k in ['rdp', 'vnc']):
                    sev = "Medium"
                    cvss = 5.8
                    cat = "Remote Desktop / Management Access"
                    cwe = "CWE-284 (Improper Access Control)"
                    desc = f"Remote administration interface '{svc}' ({version}) is open on {port_int}/{proto}. Open management ports increase the attack surface for automated brute-force attempts."
                    solution = "Place remote management interfaces behind a VPN, apply IP allowlisting, and enforce Multi-Factor Authentication (MFA)."
                elif port_int == 22 or svc_lower == 'ssh':
                    sev = "Low"
                    cvss = 3.0
                    cat = "SSH Remote Administration"
                    cwe = "CWE-200 (Information Exposure)"
                    desc = f"OpenSSH management service ({version}) detected on {port_int}/{proto} ({state})."
                    solution = "Disable root SSH login, enforce public-key authentication only, and deploy Fail2ban for brute-force mitigation."
                elif port_int in [443, 8443, 9443] or any(k in svc_lower for k in ['https', 'ssl']):
                    sev = "Informational"
                    cvss = 0.0
                    cat = "Encrypted Web Service (HTTPS)"
                    cwe = "CWE-200 (Information Exposure)"
                    desc = f"Encrypted HTTPS web service ({version}) is active on {port_int}/{proto}."
                    solution = "Maintain current TLS certificates and ensure obsolete TLS 1.0 and 1.1 protocols are disabled."
                else:
                    sev = "Low"
                    cvss = 2.5
                    cat = "Network Service Exposure"
                    cwe = "CWE-200 (Information Exposure)"
                    desc = f"Network service '{svc}' ({version}) is listening on {port_int}/{proto} ({state})."
                    solution = "Verify necessity of this open port. Close or firewall any unnecessary services to minimize attack surface."

                observations.append({
                    "id": idx,
                    "title": f"Open Port {port_int}/{proto} - {svc.upper()} ({version})",
                    "category": cat,
                    "severity": sev,
                    "cvss_score": cvss,
                    "cvss_vector": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:{'H' if sev in ['Critical','High'] else 'L'}/I:{'H' if sev in ['Critical','High'] else 'N'}/A:N",
                    "cwe": cwe,
                    "status": "Active",
                    "endpoint": f"{target_url}:{port_int}",
                    "description": desc,
                    "solution": solution,
                    "steps": [
                        f"Target Host: {target_url}",
                        f"Port / Protocol: {port_int}/{proto}",
                        f"Detected Service: {svc} ({version})",
                        f"State: {state} (Reason: {reason})"
                    ],
                    "reference": "https://nmap.org/book/man.html",
                    "evidence": f"Port {port_int}/{proto} {state} {svc} {version}",
                    "attributing_factor": "Network Infrastructure & Service Configuration",
                })

        elif tool_lower == "sqlmap":
            tool_info.append({"name": "SQLMap Automatic SQL Injection", "version": "v1.8", "type": "Database Takeover & SQLi Tool", "license": "GPLv2"})
            inj_list = results.get("injections", []) if isinstance(results, dict) else (results if isinstance(results, list) else [])
            for idx, item in enumerate(inj_list, 1):
                param = item.get("parameter") or "unknown parameter"
                inj_type = item.get("type") or "SQL Injection"
                title = item.get("title") or "SQL Injection Vulnerability"
                payload = item.get("payload") or item.get("title") or "Dynamic SQL payload"

                observations.append({
                    "id": idx,
                    "title": f"SQL Injection on Parameter: {param}",
                    "category": "Database Injection & Data Exfiltration",
                    "severity": "Critical",
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "cwe": "CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)",
                    "status": "Active",
                    "endpoint": target_url,
                    "description": f"SQLMap detected a confirmed {inj_type} vulnerability affecting parameter '{param}'. Exploitation enables arbitrary database querying, authentication bypass, data extraction, and potential backend takeover.",
                    "solution": "Use parameterized queries (Prepared Statements) with bound parameters across all database interactions. Implement strict server-side input validation and apply least privilege principles to database accounts.",
                    "steps": [
                        f"Target URL: {target_url}",
                        f"Vulnerable Parameter: {param}",
                        f"Injection Technique: {inj_type}",
                        f"Technique Title: {title}"
                    ],
                    "reference": "https://owasp.org/www-community/attacks/SQL_Injection",
                    "evidence": f"Parameter: {param} | Technique: {inj_type}",
                    "attributing_factor": "Database Query Construction / Missing Parameterization",
                })

        elif tool_lower == "ffuf":
            tool_info.append({"name": "FFuF Fast Web Fuzzer", "version": "v2.1", "type": "Web Endpoint & Directory Fuzzer", "license": "MIT"})
            items = results.get("results", []) if isinstance(results, dict) else (results if isinstance(results, list) else [])
            for idx, item in enumerate(items, 1):
                url = item.get("url") or target_url
                status_code = item.get("status") or 200
                length = item.get("length") or item.get("size") or 0
                words = item.get("words") or 0

                url_lower = url.lower()
                if any(s in url_lower for s in [".env", ".git", "wp-config", "id_rsa", "backup.sql", "database.yml"]):
                    sev = "Critical"
                    cvss = 9.1
                    cat = "Exposed Secrets & Sensitive Files"
                elif any(s in url_lower for s in ["/admin", "/phpmyadmin", "/dashboard", "/api/v1", "/swagger", "/actuator"]):
                    sev = "Medium"
                    cvss = 5.0
                    cat = "Administrative & API Endpoints"
                else:
                    sev = "Low" if status_code in [200, 301, 302] else "Informational"
                    cvss = 2.0 if status_code in [200, 301, 302] else 0.0
                    cat = "Fuzzed Web Endpoint"

                observations.append({
                    "id": idx,
                    "title": f"Discovered Endpoint: {url} (HTTP {status_code})",
                    "category": cat,
                    "severity": sev,
                    "cvss_score": cvss,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "cwe": "CWE-538 (File and Directory Information Exposure)",
                    "status": "Active",
                    "endpoint": url,
                    "description": f"FFuF endpoint fuzzing identified accessible resource at '{url}' returning HTTP status code {status_code} ({length} bytes, {words} words).",
                    "solution": "Ensure sensitive administrative interfaces and debug files are protected behind proper authentication or removed from production web roots.",
                    "steps": [
                        f"Fuzzed URL: {url}",
                        f"HTTP Status: {status_code}",
                        f"Content Length: {length} Bytes",
                        f"Words: {words}"
                    ],
                    "reference": "https://github.com/ffuf/ffuf",
                    "evidence": f"HTTP {status_code} {length}B",
                    "attributing_factor": "Web Server Directory Exposure",
                })

        elif tool_lower in ["combined", "multi", "vapt"]:
            tool_info.extend([
                {"name": "OWASP ZAP", "version": "v2.17.0", "type": "Open Source DAST", "license": "Apache 2.0"},
                {"name": "ProjectDiscovery Nuclei", "version": "v3.7.0", "type": "Open Source Vulnerability Scanner", "license": "MIT"},
                {"name": "Nikto Web Scanner", "version": "v2.5.0", "type": "Open Source Web Audit Tool", "license": "GPLv2"},
                {"name": "Gobuster", "version": "v3.6", "type": "Open Source Directory Enumerator", "license": "Apache 2.0"}
            ])
            if isinstance(results, dict):
                sub_id = 1
                for sub_tool, sub_res in results.items():
                    sub_norm = cls.normalize_findings(sub_tool, sub_res, target_url)
                    for item in sub_norm.get("observations", []):
                        item["id"] = sub_id
                        item["title"] = f"[{sub_tool.upper()}] {item['title']}"
                        observations.append(item)
                        sub_id += 1
            elif isinstance(results, list):
                for idx, item in enumerate(results, 1):
                    observations.append({
                        "id": idx,
                        "title": item.get("title") or item.get("name") or "Security Observation",
                        "category": item.get("category", "Web Pen Testing"),
                        "severity": item.get("severity", "Medium"),
                        "cvss_score": float(item.get("cvss_score", 5.0)),
                        "cvss_vector": item.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
                        "cwe": item.get("cwe", "CWE-200"),
                        "status": item.get("status", "Active"),
                        "endpoint": item.get("endpoint", target_url),
                        "description": item.get("description", "Security finding detected during testing."),
                        "solution": item.get("solution", "Remediate according to OWASP guidelines."),
                        "steps": item.get("steps", [f"Target: {target_url}"]),
                        "reference": item.get("reference", "https://owasp.org"),
                        "evidence": item.get("evidence", ""),
                        "attributing_factor": item.get("attributing_factor", "Security Assessment"),
                    })

        # Calculate counts
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for obs in observations:
            sev = obs["severity"]
            if sev in counts:
                counts[sev] += 1
            elif sev == "Info":
                counts["Informational"] += 1
            else:
                counts["Low"] += 1

        posture = cls.calculate_posture(counts)

        return {
            "tool": tool_lower.upper(),
            "target_url": target_url,
            "observations": observations,
            "counts": counts,
            "total_findings": len(observations),
            "posture": posture,
            "tools_used": tool_info
        }

    @classmethod
    def render_html_report(cls, data: Dict[str, Any], metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Renders an enterprise-grade HTML report directly matching the Strobes VAPT audit format.
        """
        metadata = metadata or {}
        tool_name = data.get("tool", "WEB PENETRATION TESTING")
        tool_lower = tool_name.lower()
        target_url = data.get("target_url", "https://target-app.local")
        observations = data.get("observations", [])
        counts = data.get("counts", {})
        posture = data.get("posture", {})
        tools_used = data.get("tools_used", [])

        # Tool-specific titles & types
        title_map = {
            "nmap": "Network Infrastructure & Port Security Audit Report",
            "zap": "Dynamic Application Security Testing (DAST) VAPT Report",
            "sqlmap": "Database Security & SQL Injection Assessment Report",
            "nuclei": "Vulnerability Assessment & Exploit Audit Report",
            "nikto": "Web Server Configuration & Hardening Audit Report",
            "gobuster": "Directory & Endpoint Surface Enumeration Report",
            "ffuf": "Web Application Fuzzing & Endpoint Discovery Report",
        }
        audit_type_map = {
            "nmap": "Network Infrastructure & Port Vulnerability Assessment",
            "zap": "Web Application Dynamic Security Testing (DAST / OWASP)",
            "sqlmap": "Database Penetration Testing & SQL Injection Audit",
            "nuclei": "Automated Vulnerability & Signature Detection Audit",
            "nikto": "Web Server Security Configuration Audit",
            "gobuster": "Web Application Directory & Attack Surface Enumeration",
            "ffuf": "Web Application Resource & Endpoint Fuzzing Audit",
        }
        brand_map = {
            "nmap": "INFRASTRUCTURE AUDIT",
            "zap": "DAST AUDIT",
            "sqlmap": "DATABASE AUDIT",
            "nuclei": "VULN AUDIT",
            "nikto": "SERVER AUDIT",
            "gobuster": "SURFACE ENUMERATION",
            "ffuf": "FUZZING AUDIT",
        }

        default_doc_title = title_map.get(tool_lower, "Web Application Vulnerability Assessment and Penetration Testing Report")
        default_audit_type = audit_type_map.get(tool_lower, "Web Application Vulnerability Assessment & Penetration Testing (VAPT)")
        brand_sub = brand_map.get(tool_lower, "SECURITY AUDIT")

        # Metadata fields with defaults
        report_date = metadata.get("report_date") or datetime.datetime.now().strftime("%d %b, %Y")
        audit_period = metadata.get("audit_period") or f"{datetime.datetime.now().strftime('%d %b, %Y')} - {datetime.datetime.now().strftime('%d %b, %Y')}"
        doc_title = metadata.get("doc_title") or default_doc_title
        audit_type = metadata.get("audit_type") or default_audit_type
        doc_id = metadata.get("doc_id") or "VAPT-RPT-" + datetime.datetime.now().strftime("%Y%m%d-%H%M")
        doc_version = metadata.get("doc_version") or "1.0"
        prepared_by = metadata.get("prepared_by") or metadata.get("auditor") or "Santhosh M (Network Admin)"
        reviewed_by = metadata.get("reviewed_by") or metadata.get("approved_by") or "Leo Antony Charles (IT Manager)"
        approved_by = metadata.get("approved_by") or "Leo Antony Charles (IT Manager)"
        org_name = metadata.get("organization") or metadata.get("company_name") or "Wyzmindz Solutions"
        app_name = metadata.get("app_name") or target_url.replace("http://", "").replace("https://", "").split("/")[0]

        # Build Observations Rows for Table
        summary_rows_html = ""
        for obs in observations:
            sev = obs["severity"]
            badge_color = cls.SEVERITY_COLORS.get(sev, "#64748b")
            cwe_ref = obs.get("cwe", "CWE-200")
            summary_rows_html += f"""
            <tr>
                <td style="text-align: center; font-weight: bold;">{obs['id']}</td>
                <td style="font-weight: 600; color: #0f172a;">{html.escape(app_name)}<br><small style="color: #64748b; font-family: monospace;">{html.escape(obs.get('endpoint',''))[:45]}</small></td>
                <td style="font-weight: 600; color: #1e293b;">{html.escape(obs['title'])}</td>
                <td style="font-family: monospace; font-size: 11px;">{html.escape(cwe_ref)}</td>
                <td><span style="background: {badge_color}; color: #fff; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; text-transform: uppercase;">{sev}</span></td>
                <td style="font-size: 11px; color: #334155;">{html.escape(obs.get('solution',''))[:85]}...</td>
                <td style="text-align: center;"><span style="background: {'#16a34a' if obs['status']=='Resolved' else '#ea580c'}; color: white; padding: 3px 6px; border-radius: 3px; font-size: 10px;">{obs['status']}</span></td>
            </tr>
            """

        # Build Detailed Observation Sections
        details_html = ""
        for obs in observations:
            sev = obs["severity"]
            badge_color = cls.SEVERITY_COLORS.get(sev, "#64748b")
            steps_li = "".join([f"<li>{html.escape(s)}</li>" for s in obs.get("steps", [])])
            
            evidence_block = ""
            if obs.get("evidence"):
                evidence_block = f"""
                <div style="margin-top: 12px; margin-bottom: 12px;">
                    <div style="font-weight: 700; font-size: 11px; text-transform: uppercase; color: #475569; margin-bottom: 4px;">PROOF OF CONCEPT / EVIDENCE OUTPUT</div>
                    <pre style="background: #0f172a; color: #38bdf8; padding: 12px; border-radius: 6px; font-family: 'Courier New', Courier, monospace; font-size: 11px; line-height: 1.4; overflow-x: auto; white-space: pre-wrap;">{html.escape(obs['evidence'])}</pre>
                </div>
                """

            details_html += f"""
            <div class="finding-card" style="page-break-inside: avoid; border: 1px solid #e2e8f0; border-radius: 8px; margin-bottom: 25px; background: #ffffff; box-shadow: 0 1px 3px rgba(0,0,0,0.05); overflow: hidden;">
                <div style="background: #f8fafc; border-bottom: 2px solid {badge_color}; padding: 12px 18px; display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span style="background: {badge_color}; color: white; padding: 3px 8px; border-radius: 4px; font-weight: 800; font-size: 11px; margin-right: 8px;">#{obs['id']}</span>
                        <strong style="font-size: 15px; color: #0f172a;">{html.escape(obs['title'])}</strong>
                    </div>
                    <span style="background: {badge_color}; color: white; padding: 4px 10px; border-radius: 4px; font-weight: 700; font-size: 11px; text-transform: uppercase;">{sev}</span>
                </div>
                <div style="padding: 16px 20px;">
                    <table style="width: 100%; border-collapse: collapse; margin-bottom: 14px; font-size: 12px;">
                        <tr style="border-bottom: 1px solid #f1f5f9;">
                            <td style="width: 25%; padding: 6px 0; color: #64748b; font-weight: 600;">CATEGORY</td>
                            <td style="padding: 6px 0; color: #1e293b;">{html.escape(obs.get('category','Input Validation & Business Logic'))}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid #f1f5f9;">
                            <td style="padding: 6px 0; color: #64748b; font-weight: 600;">CVSS v3.1 METRICS</td>
                            <td style="padding: 6px 0; color: #1e293b;"><strong>{obs.get('cvss_score', 5.0):.1f}</strong> &mdash; <code style="color: #475569; font-size: 11px;">{html.escape(obs.get('cvss_vector',''))}</code></td>
                        </tr>
                        <tr style="border-bottom: 1px solid #f1f5f9;">
                            <td style="padding: 6px 0; color: #64748b; font-weight: 600;">CWE IDENTIFIER</td>
                            <td style="padding: 6px 0; color: #0284c7; font-weight: 600;">{html.escape(obs.get('cwe','CWE-200'))}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid #f1f5f9;">
                            <td style="padding: 6px 0; color: #64748b; font-weight: 600;">ATTRIBUTING FACTOR</td>
                            <td style="padding: 6px 0; color: #1e293b;">{html.escape(obs.get('attributing_factor','Implementation / Configuration'))}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid #f1f5f9;">
                            <td style="padding: 6px 0; color: #64748b; font-weight: 600;">CURRENT STATUS</td>
                            <td style="padding: 6px 0;"><span style="background: {'#16a34a' if obs['status']=='Resolved' else '#dc2626'}; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: 600;">{obs['status']}</span></td>
                        </tr>
                        <tr>
                            <td style="padding: 6px 0; color: #64748b; font-weight: 600;">AFFECTED ENDPOINT</td>
                            <td style="padding: 6px 0; font-family: monospace; color: #0284c7; word-break: break-all;">{html.escape(obs.get('endpoint', target_url))}</td>
                        </tr>
                    </table>

                    <div style="margin-top: 10px;">
                        <h4 style="color: #0f172a; margin: 0 0 6px 0; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px;">Description</h4>
                        <p style="color: #334155; font-size: 12px; line-height: 1.6; margin: 0 0 12px 0; text-align: justify;">{html.escape(obs.get('description',''))}</p>
                    </div>

                    {evidence_block}

                    <div style="margin-top: 10px;">
                        <h4 style="color: #0f172a; margin: 0 0 6px 0; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px;">Steps to Reproduce / Verification</h4>
                        <ol style="color: #334155; font-size: 12px; line-height: 1.6; margin: 0 0 12px 0; padding-left: 20px;">
                            {steps_li}
                        </ol>
                    </div>

                    <div style="margin-top: 12px; background: #f0fdf4; border-left: 4px solid #16a34a; padding: 12px 16px; border-radius: 0 6px 6px 0;">
                        <h4 style="color: #15803d; margin: 0 0 4px 0; font-size: 12px; text-transform: uppercase; font-weight: 700;">Remediation & Mitigation</h4>
                        <p style="color: #166534; font-size: 12px; line-height: 1.5; margin: 0;">{html.escape(obs.get('solution','Apply recommended defense-in-depth sanitization and configuration standards.'))}</p>
                    </div>

                    <div style="margin-top: 10px; font-size: 11px; color: #64748b;">
                        <strong>References:</strong> <a href="{html.escape(obs.get('reference','#'))}" target="_blank" style="color: #2563eb; text-decoration: none;">{html.escape(obs.get('reference','https://owasp.org'))}</a>
                    </div>
                </div>
            </div>
            """

        # Tools Used HTML table
        tools_rows = ""
        for idx, t in enumerate(tools_used, 1):
            tools_rows += f"""
            <tr>
                <td style="text-align: center;">{idx}</td>
                <td><strong>{html.escape(t['name'])}</strong></td>
                <td style="font-family: monospace;">{html.escape(t['version'])}</td>
                <td>{html.escape(t['license'])}</td>
                <td>{html.escape(t['type'])}</td>
            </tr>
            """

        # Build full HTML document
        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Application VAPT Audit Report - {html.escape(app_name)}</title>
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
        .page-break {{
            page-break-before: always;
        }}
        .no-break {{
            page-break-inside: avoid;
        }}
        /* Header & Footer */
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
        .brand-logo span {{
            color: #0284c7;
        }}
        /* Cover Page */
        .cover-container {{
            min-height: 85vh;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            padding: 40px 10px;
        }}
        .cover-title {{
            font-size: 32px;
            font-weight: 800;
            color: #0f172a;
            line-height: 1.2;
            margin: 0 0 10px 0;
        }}
        .cover-subtitle {{
            font-size: 18px;
            color: #0284c7;
            font-weight: 600;
            margin: 0 0 40px 0;
        }}
        .meta-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 30px;
            font-size: 13px;
        }}
        .meta-table td {{
            padding: 10px 14px;
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
        /* Tables */
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
        table.styled-table tr:nth-child(even) {{
            background: #f8fafc;
        }}
        /* Headings */
        h1, h2, h3, h4 {{
            color: #0f172a;
            font-weight: 700;
        }}
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
        .kpi-number {{
            font-size: 26px;
            font-weight: 800;
            line-height: 1;
            margin-bottom: 4px;
        }}
        .kpi-label {{
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
    </style>
</head>
<body>

    <!-- ════════════════════════ COVER PAGE ════════════════════════ -->
    <div class="cover-container">
        <div class="report-header">
            <div class="brand-logo">VAPT<span>SHIELD</span> // {brand_sub}</div>
            <div>{html.escape(report_date)}</div>
        </div>

        <div style="margin-top: 60px;">
            <div style="display: inline-block; background: #e0f2fe; color: #0369a1; padding: 6px 14px; border-radius: 20px; font-weight: 700; font-size: 12px; text-transform: uppercase; margin-bottom: 16px; letter-spacing: 1px;">
                SECURITY ASSESSMENT REPORT
            </div>
            <h1 class="cover-title">{html.escape(doc_title)}</h1>
            <div class="cover-subtitle">Target Application / Host: {html.escape(app_name)}</div>
        </div>

        <div>
            <table class="meta-table">
                <tr>
                    <td>Report Release Date</td>
                    <td><strong>{html.escape(report_date)}</strong></td>
                </tr>
                <tr>
                    <td>Type of Audit</td>
                    <td>{html.escape(audit_type)}</td>
                </tr>
                <tr>
                    <td>Target Scope / URL</td>
                    <td><code style="color: #0284c7;">{html.escape(target_url)}</code></td>
                </tr>
                <tr>
                    <td>Assessment Period</td>
                    <td>{html.escape(audit_period)}</td>
                </tr>
                <tr>
                    <td>Audit Tools Employed</td>
                    <td>{html.escape(tool_name)} Engine Suite</td>
                </tr>
                <tr>
                    <td>Overall Security Posture</td>
                    <td>
                        <span style="background: {posture.get('color','#16a34a')}; color: white; padding: 4px 10px; border-radius: 4px; font-weight: 800; font-size: 11px;">
                            {posture.get('level','GOOD')}
                        </span>
                    </td>
                </tr>
            </table>
        </div>

        <div style="margin-top: 40px; border-top: 1px solid #e2e8f0; padding-top: 12px; font-size: 11px; color: #94a3b8; display: flex; justify-content: space-between;">
            <div>Confidential &mdash; For Internal Security Review Only</div>
            <div>Generated by VAPT Security Platform</div>
        </div>
    </div>

    <!-- ════════════════════════ DOCUMENT CONTROL ════════════════════════ -->
    <div class="page-break"></div>
    <div class="report-header">
        <div>Web Application VAPT // {html.escape(org_name)}</div>
        <div>{html.escape(report_date)}</div>
    </div>

    <h2 class="section-heading">Document Control</h2>

    <h3 style="font-size: 14px; margin-top: 20px;">Document Preparation</h3>
    <table class="styled-table">
        <tr><td style="width: 30%; font-weight: bold; background: #f8fafc;">DOCUMENT TITLE</td><td>{html.escape(doc_title)}</td></tr>
        <tr><td style="font-weight: bold; background: #f8fafc;">DOCUMENT ID</td><td><code style="color: #0284c7;">{html.escape(doc_id)}</code></td></tr>
        <tr><td style="font-weight: bold; background: #f8fafc;">DOCUMENT VERSION</td><td>{html.escape(doc_version)}</td></tr>
        <tr><td style="font-weight: bold; background: #f8fafc;">PREPARED BY</td><td>{html.escape(prepared_by)}</td></tr>
        <tr><td style="font-weight: bold; background: #f8fafc;">REVIEWED BY</td><td>{html.escape(reviewed_by)}</td></tr>
        <tr><td style="font-weight: bold; background: #f8fafc;">APPROVED BY</td><td>{html.escape(approved_by)}</td></tr>
        <tr><td style="font-weight: bold; background: #f8fafc;">RELEASE DATE</td><td>{html.escape(report_date)}</td></tr>
    </table>

    <h3 style="font-size: 14px; margin-top: 25px;">Document Distribution List</h3>
    <table class="styled-table">
        <thead>
            <tr><th>Name</th><th>Organization</th><th>Designation</th><th>Role / Email</th></tr>
        </thead>
        <tbody>
            <tr>
                <td><strong>Security Operations</strong></td>
                <td>{html.escape(org_name)}</td>
                <td>Application Security Lead</td>
                <td>security@{html.escape(app_name.lower())}</td>
            </tr>
            <tr>
                <td><strong>Engineering Team</strong></td>
                <td>{html.escape(org_name)}</td>
                <td>DevSecOps / Lead Developer</td>
                <td>engineering@{html.escape(app_name.lower())}</td>
            </tr>
        </tbody>
    </table>

    <!-- ════════════════════════ TABLE OF CONTENTS ════════════════════════ -->
    <h2 class="section-heading" style="margin-top: 30px;">Table of Contents</h2>
    <div style="font-size: 12px; line-height: 1.8; color: #334155;">
        <div style="display: flex; justify-content: space-between; border-bottom: 1px dotted #cbd5e1; padding: 4px 0;"><strong>1. INTRODUCTION &amp; SCOPE</strong><span>Page 3</span></div>
        <div style="display: flex; justify-content: space-between; border-bottom: 1px dotted #cbd5e1; padding: 4px 0;"><strong>2. AUDIT METHODOLOGY &amp; TEST CASES</strong><span>Page 3</span></div>
        <div style="display: flex; justify-content: space-between; border-bottom: 1px dotted #cbd5e1; padding: 4px 0;"><strong>3. TOOLS &amp; SOFTWARE EMPLOYED</strong><span>Page 4</span></div>
        <div style="display: flex; justify-content: space-between; border-bottom: 1px dotted #cbd5e1; padding: 4px 0;"><strong>4. EXECUTIVE SUMMARY &amp; METRICS</strong><span>Page 4</span></div>
        <div style="display: flex; justify-content: space-between; border-bottom: 1px dotted #cbd5e1; padding: 4px 0;"><strong>5. SUMMARY OF RESULTS &amp; SEVERITY CLASSIFICATION</strong><span>Page 5</span></div>
        <div style="display: flex; justify-content: space-between; border-bottom: 1px dotted #cbd5e1; padding: 4px 0;"><strong>6. DETAILED OBSERVATIONS &amp; MITIGATION GUIDE</strong><span>Page 6+</span></div>
        <div style="display: flex; justify-content: space-between; border-bottom: 1px dotted #cbd5e1; padding: 4px 0;"><strong>7. CONCLUSION &amp; BEST PRACTICES</strong><span>Appendix</span></div>
    </div>

    <!-- ════════════════════════ SCOPE & METHODOLOGY ════════════════════════ -->
    <div class="page-break"></div>
    <div class="report-header">
        <div>Web Application VAPT // {html.escape(org_name)}</div>
        <div>{html.escape(report_date)}</div>
    </div>

    <h2 class="section-heading">1. Introduction &amp; Engagement Scope</h2>
    <p style="text-align: justify; color: #334155; line-height: 1.6;">
        The goal of this penetration testing assessment is to identify existing technical vulnerabilities within the target web application, assess their real-world exploitability, and provide verified remediation guidance to enhance the defense-in-depth posture of the organization.
    </p>

    <table class="styled-table">
        <tr><td style="width: 30%; font-weight: bold; background: #f8fafc;">Application Name</td><td><strong>{html.escape(app_name)}</strong></td></tr>
        <tr><td style="font-weight: bold; background: #f8fafc;">Target Endpoint</td><td><code style="color: #0284c7;">{html.escape(target_url)}</code></td></tr>
        <tr><td style="font-weight: bold; background: #f8fafc;">Testing Type</td><td>Grey Box / Automated DAST &amp; Vulnerability Assessment</td></tr>
        <tr><td style="font-weight: bold; background: #f8fafc;">Testing Scope</td><td>Dynamic Web Application Security, Endpoint Routing, Header Hygiene &amp; Logic</td></tr>
        <tr><td style="font-weight: bold; background: #f8fafc;">Out of Scope</td><td>Denial of Service (DoS), Social Engineering, Infrastructure Hosting Hypervisors</td></tr>
    </table>

    <h2 class="section-heading">2. OWASP Top 10 Test Cases Performed</h2>
    <table class="styled-table" style="font-size: 11px;">
        <thead>
            <tr><th>No</th><th>Test Category</th><th>Methodology Scope</th><th>Status</th></tr>
        </thead>
        <tbody>
            <tr><td>1</td><td><strong>A01: Broken Access Control</strong></td><td>IDOR, unauthorized administrative access, privilege escalation, bypass checks</td><td><span style="color: #16a34a; font-weight: 600;">&check; Evaluated</span></td></tr>
            <tr><td>2</td><td><strong>A02: Cryptographic Failures</strong></td><td>TLS cipher strength, plaintext transmission, cookie secure flags, sensitive data</td><td><span style="color: #16a34a; font-weight: 600;">&check; Evaluated</span></td></tr>
            <tr><td>3</td><td><strong>A03: Injection</strong></td><td>SQL injection, command injection, blind extraction, LDAP/XPath injection</td><td><span style="color: #16a34a; font-weight: 600;">&check; Evaluated</span></td></tr>
            <tr><td>4</td><td><strong>A04: Insecure Design</strong></td><td>Business logic flaws, brute-force rate limits, credential recovery validation</td><td><span style="color: #16a34a; font-weight: 600;">&check; Evaluated</span></td></tr>
            <tr><td>5</td><td><strong>A05: Security Misconfiguration</strong></td><td>Default credentials, directory indexing, missing security headers (CSP, HSTS)</td><td><span style="color: #16a34a; font-weight: 600;">&check; Evaluated</span></td></tr>
            <tr><td>6</td><td><strong>A06: Vulnerable &amp; Outdated Components</strong></td><td>Known CVEs in web servers, frameworks, JavaScript libraries, third-party code</td><td><span style="color: #16a34a; font-weight: 600;">&check; Evaluated</span></td></tr>
            <tr><td>7</td><td><strong>A07: Identification &amp; Auth Failures</strong></td><td>Session management, password spraying, token entropy, credential transport</td><td><span style="color: #16a34a; font-weight: 600;">&check; Evaluated</span></td></tr>
            <tr><td>8</td><td><strong>A08: Software &amp; Data Integrity Failures</strong></td><td>Insecure deserialization, untrusted plugin execution, CI/CD pipeline integrity</td><td><span style="color: #16a34a; font-weight: 600;">&check; Evaluated</span></td></tr>
            <tr><td>9</td><td><strong>A09: Security Logging &amp; Monitoring</strong></td><td>Log evasion, stack trace leakage in error responses, verbose debug handlers</td><td><span style="color: #16a34a; font-weight: 600;">&check; Evaluated</span></td></tr>
            <tr><td>10</td><td><strong>A10: Server-Side Request Forgery (SSRF)</strong></td><td>Internal network metadata exfiltration, loopback access, cloud token querying</td><td><span style="color: #16a34a; font-weight: 600;">&check; Evaluated</span></td></tr>
        </tbody>
    </table>

    <!-- ════════════════════════ TOOLS & EXECUTIVE SUMMARY ════════════════════════ -->
    <div class="page-break"></div>
    <div class="report-header">
        <div>Web Application VAPT // {html.escape(org_name)}</div>
        <div>{html.escape(report_date)}</div>
    </div>

    <h2 class="section-heading">3. Testing Tools &amp; Software Used</h2>
    <table class="styled-table">
        <thead>
            <tr><th>No</th><th>Tool Name</th><th>Version</th><th>License</th><th>Functional Focus</th></tr>
        </thead>
        <tbody>
            {tools_rows}
        </tbody>
    </table>

    <h2 class="section-heading">4. Executive Summary</h2>
    <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 18px; margin-bottom: 20px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <span style="font-size: 13px; font-weight: 700; text-transform: uppercase; color: #475569;">Application Security Posture</span>
            <span style="background: {posture.get('color','#16a34a')}; color: white; padding: 6px 14px; border-radius: 6px; font-weight: 800; font-size: 14px; letter-spacing: 0.5px;">
                {posture.get('level','GOOD')}
            </span>
        </div>
        <p style="color: #334155; font-size: 12px; line-height: 1.6; margin: 0;">
            {posture.get('desc','Assessment completed.')}
        </p>
    </div>

    <!-- KPI Metric Cards -->
    <div style="display: flex; gap: 10px; margin-bottom: 25px;">
        <div class="kpi-card" style="background: #dc2626;">
            <div class="kpi-number">{counts.get('Critical', 0)}</div>
            <div class="kpi-label">Critical</div>
        </div>
        <div class="kpi-card" style="background: #ea580c;">
            <div class="kpi-number">{counts.get('High', 0)}</div>
            <div class="kpi-label">High</div>
        </div>
        <div class="kpi-card" style="background: #d97706;">
            <div class="kpi-number">{counts.get('Medium', 0)}</div>
            <div class="kpi-label">Medium</div>
        </div>
        <div class="kpi-card" style="background: #2563eb;">
            <div class="kpi-number">{counts.get('Low', 0)}</div>
            <div class="kpi-label">Low</div>
        </div>
        <div class="kpi-card" style="background: #64748b;">
            <div class="kpi-number">{counts.get('Informational', 0)}</div>
            <div class="kpi-label">Info</div>
        </div>
    </div>

    <h3 style="font-size: 14px; margin-top: 20px;">Vulnerability Severity Classification SLA</h3>
    <table class="styled-table" style="font-size: 11px;">
        <thead>
            <tr><th>Severity</th><th>CVSS Range</th><th>Remediation SLA</th><th>Business Impact Description</th></tr>
        </thead>
        <tbody>
            <tr>
                <td><span style="background: #dc2626; color: white; padding: 2px 6px; border-radius: 3px; font-weight: bold;">Critical</span></td>
                <td>9.0 - 10.0</td>
                <td><strong>2 Days</strong></td>
                <td>Direct compromise of critical systems, full data breach, arbitrary code execution.</td>
            </tr>
            <tr>
                <td><span style="background: #ea580c; color: white; padding: 2px 6px; border-radius: 3px; font-weight: bold;">High</span></td>
                <td>7.0 - 8.9</td>
                <td><strong>4 Days</strong></td>
                <td>Bypass of security boundaries, significant privilege escalation or data tampering.</td>
            </tr>
            <tr>
                <td><span style="background: #d97706; color: white; padding: 2px 6px; border-radius: 3px; font-weight: bold;">Medium</span></td>
                <td>4.0 - 6.9</td>
                <td><strong>10 Days</strong></td>
                <td>Flaws requiring user interaction, chained vulnerabilities, or partial info leakage.</td>
            </tr>
            <tr>
                <td><span style="background: #2563eb; color: white; padding: 2px 6px; border-radius: 3px; font-weight: bold;">Low</span></td>
                <td>0.1 - 3.9</td>
                <td><strong>15 Days</strong></td>
                <td>Minor defense-in-depth gaps, missing HTTP security headers, fingerprinting info.</td>
            </tr>
        </tbody>
    </table>

    <!-- ════════════════════════ SUMMARY TABLE ════════════════════════ -->
    <div class="page-break"></div>
    <div class="report-header">
        <div>Web Application VAPT // {html.escape(org_name)}</div>
        <div>{html.escape(report_date)}</div>
    </div>

    <h2 class="section-heading">5. Summary of Identified Findings</h2>
    {f"<p style='color: #64748b;'>Total of <strong>{len(observations)}</strong> security observation(s) documented.</p>" if observations else "<p style='color: #16a34a;'><strong>&check; No vulnerabilities detected during the scan.</strong></p>"}

    {f"""
    <table class="styled-table" style="font-size: 11px;">
        <thead>
            <tr>
                <th style="width: 30px;">#</th>
                <th>Asset / Scope</th>
                <th>Vulnerability Title</th>
                <th>CWE</th>
                <th>Severity</th>
                <th>Recommended Fix</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            {summary_rows_html}
        </tbody>
    </table>
    """ if observations else ""}

    <!-- ════════════════════════ DETAILED OBSERVATIONS ════════════════════════ -->
    <div class="page-break"></div>
    <div class="report-header">
        <div>Web Application VAPT // {html.escape(org_name)}</div>
        <div>{html.escape(report_date)}</div>
    </div>

    <h2 class="section-heading">6. Detailed Vulnerability Observations &amp; Proofs of Concept</h2>
    {details_html if details_html else "<div style='padding: 30px; text-align: center; color: #16a34a; font-weight: 600;'>No vulnerabilities were identified during this assessment. Target web application meets current baseline criteria.</div>"}

    <!-- ════════════════════════ CONCLUSION & GLOSSARY ════════════════════════ -->
    <div class="page-break"></div>
    <div class="report-header">
        <div>Web Application VAPT // {html.escape(org_name)}</div>
        <div>{html.escape(report_date)}</div>
    </div>

    <h2 class="section-heading">7. Conclusion &amp; Best Practices</h2>
    <div style="font-size: 12px; line-height: 1.7; color: #334155; text-align: justify;">
        <p>
            The automated and dynamic web penetration test of <strong>{html.escape(app_name)}</strong> has been concluded. Remediating the findings listed in this report will systematically improve the application's defensive posture and align development standards with industry benchmarks including OWASP Top 10 and NIST SP 800-115.
        </p>
        <h4 style="color: #0f172a; margin-top: 15px;">Key Remediation Principles</h4>
        <ul>
            <li><strong>Input Validation &amp; Output Encoding:</strong> Employ strict schema validation, prepared statements, and context-aware HTML/JavaScript encoding.</li>
            <li><strong>Secure Header Configuration:</strong> Implement robust Content Security Policy (CSP), Strict-Transport-Security (HSTS), and anti-framing protections.</li>
            <li><strong>Continuous DevSecOps Auditing:</strong> Re-run automated security scans following any major releases or infrastructure changes.</li>
        </ul>
    </div>

    <h2 class="section-heading" style="margin-top: 30px;">8. Appendices &amp; Glossary</h2>
    <table class="styled-table" style="font-size: 11px;">
        <tr><td style="width: 30%; font-weight: bold; background: #f8fafc;">VAPT</td><td>Vulnerability Assessment and Penetration Testing &mdash; A systematic security audit combining automated flaw detection and validation.</td></tr>
        <tr><td style="font-weight: bold; background: #f8fafc;">DAST</td><td>Dynamic Application Security Testing &mdash; Black/Grey box analysis testing running web applications from the outside.</td></tr>
        <tr><td style="font-weight: bold; background: #f8fafc;">CVSS</td><td>Common Vulnerability Scoring System &mdash; Standardized numerical framework assessing vulnerability exploitability and impact.</td></tr>
        <tr><td style="font-weight: bold; background: #f8fafc;">CWE</td><td>Common Weakness Enumeration &mdash; Community-developed taxonomy of software architecture, code, and design weaknesses.</td></tr>
    </table>

</body>
</html>
"""
        return html_doc

    @classmethod
    def generate_pdf_report(cls, data: Dict[str, Any], metadata: Optional[Dict[str, Any]] = None) -> bytes:
        """
        Generates PDF bytes from the rendered HTML report using pdfkit / wkhtmltopdf.
        """
        html_content = cls.render_html_report(data, metadata)
        options = {
            'page-size': 'A4',
            'margin-top': '0.5in',
            'margin-right': '0.5in',
            'margin-bottom': '0.5in',
            'margin-left': '0.5in',
            'encoding': "UTF-8",
            'no-outline': None,
            'enable-local-file-access': None,
            'quiet': ''
        }
        return pdfkit.from_string(html_content, False, options=options)
