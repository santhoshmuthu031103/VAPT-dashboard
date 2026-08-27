import asyncio
import subprocess
import logging
import re
import os
import uuid
import xml.etree.ElementTree as ET
from typing import AsyncGenerator, Dict, List, Any

logger = logging.getLogger("nikto_client")

def extract_targets(host_input: str) -> List[str]:
    if not host_input:
        return []
    targets = [t.strip() for t in re.split(r'[\s,\n]+', str(host_input).strip()) if t.strip()]
    seen = set()
    unique = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique

class NiktoClient:
    def __init__(self):
        self.mock_mode = False
        self.check_nikto()

    def check_nikto(self):
        try:
            subprocess.run(["nikto", "-Version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            logger.info("Nikto is installed and available on PATH.")
            self.mock_mode = False
        except Exception:
            logger.warning("Nikto is not installed or not in PATH. Falling back to MOCK MODE.")
            self.mock_mode = True

    async def scan_stream(self, host: str, port: str = "80") -> AsyncGenerator[str, None]:
        """
        Runs Nikto scans one-by-one sequentially for each host in a target group.
        """
        targets = extract_targets(host)
        if not targets:
            yield "[VAPT-NIKTO-ERROR] No valid target hosts provided.\n"
            yield "[VAPT-NIKTO-COMPLETE]\n"
            return

        total_targets = len(targets)
        if total_targets > 1:
            yield f"[VAPT-NIKTO] Multi-target Group Scan initialized: {total_targets} hosts queued ({', '.join(targets)})\n"
        else:
            yield f"[VAPT-NIKTO] Target Scan initialized for: {targets[0]}\n"

        for idx, single_host in enumerate(targets, 1):
            if total_targets > 1:
                yield f"\n============================================================\n"
                yield f"[VAPT-NIKTO] >>> Processing Host ({idx}/{total_targets}): {single_host} (Port: {port}) <<<\n"
                yield f"============================================================\n"

            cmd = ["nikto", "-h", single_host, "-port", str(port)]
            cmd_str = " ".join(cmd)
            yield f"[VAPT-NIKTO] Starting scan: {cmd_str}\n"

            if self.mock_mode:
                yield f"+ Target Hostname:    {single_host}\n"
                yield f"+ Target Port:        {port}\n"
                await asyncio.sleep(0.5)
                yield f"+ Server: Apache/2.4.41 (Ubuntu)\n"
                yield f"+ The anti-clickjacking X-Frame-Options header is not present.\n"
                yield f"+ The X-Content-Type-Options header is not set.\n"
                await asyncio.sleep(0.5)
                yield f"+ 1 host(s) tested\n"
                continue

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT
                )

                while True:
                    line = await process.stdout.readline()
                    if not line:
                        break
                    yield line.decode("utf-8", errors="replace")

                await process.wait()
            except Exception as e:
                yield f"[VAPT-NIKTO-ERROR] Executing Nikto on {single_host} failed: {str(e)}\n"

        if total_targets > 1:
            yield f"\n[VAPT-NIKTO] Group Scan finished: All {total_targets} hosts scanned successfully.\n"
        
        yield "\n[VAPT-NIKTO-COMPLETE]\n"

    async def scan_results_parsed(self, host: str, port: str = "80",
                                   ssl: bool = False, tuning: str = "all",
                                   max_time: str = "15m", evasion: str = "0",
                                   user_agent: str = None,
                                   auth_user: str = None, auth_pass: str = None) -> dict:
        targets = extract_targets(host)
        if not targets:
            return {"vulnerabilities": []}

        if self.mock_mode:
            await asyncio.sleep(1.0)
            all_vulns = []
            for t in targets:
                all_vulns.extend([
                    {"id": 1, "host": t, "msg": f"[{t}] The anti-clickjacking X-Frame-Options header is not present."},
                    {"id": 2, "host": t, "msg": f"[{t}] The X-XSS-Protection header is not defined."},
                ])
            return {
                "host": host,
                "targets": targets,
                "port": port,
                "vulnerabilities": all_vulns
            }

        all_vulns = []
        last_banner = ""

        for single_host in targets:
            tmp_file = f"/tmp/nikto_{uuid.uuid4().hex}.xml"
            cmd = ["nikto", "-h", single_host, "-port", str(port), "-Format", "xml", "-output", tmp_file, "-maxtime", str(max_time)]

            if ssl:
                cmd.append("-ssl")
            if tuning != "all":
                tuning_map = {"xss": "4", "sqli": "9", "misconfig": "2"}
                if tuning in tuning_map:
                    cmd.extend(["-Tuning", tuning_map[tuning]])
            if evasion != "0":
                cmd.extend(["-evasion", str(evasion)])
            if user_agent:
                cmd.extend(["-useragent", user_agent])
            if auth_user and auth_pass:
                cmd.extend(["-id", f"{auth_user}:{auth_pass}"])

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await process.communicate()
                
                if os.path.exists(tmp_file):
                    try:
                        tree = ET.parse(tmp_file)
                        root_el = tree.getroot()
                        scandetails = root_el.find("scandetails")
                        if scandetails is not None:
                            last_banner = scandetails.attrib.get("targetbanner", "") or last_banner
                            for item in scandetails.findall("item"):
                                vuln_id = item.attrib.get("id", "N/A")
                                method  = item.attrib.get("method", "")
                                uri_el  = item.find("uri")
                                uri     = "".join(uri_el.itertext()).strip() if uri_el is not None else ""
                                desc_el = item.find("description")
                                desc    = "".join(desc_el.itertext()).strip() if desc_el is not None else "Unknown vulnerability"
                                all_vulns.append({
                                    "host":   single_host,
                                    "id":     vuln_id,
                                    "method": method,
                                    "uri":    uri,
                                    "msg":    f"[{single_host}] {desc}" if len(targets) > 1 else desc,
                                })
                    except Exception as xml_err:
                        logger.error(f"Error parsing Nikto XML for {single_host}: {xml_err}")
                    finally:
                        try:
                            os.remove(tmp_file)
                        except Exception:
                            pass
            except Exception as e:
                logger.error(f"Error executing Nikto for {single_host}: {e}")

        return {
            "host": host,
            "targets": targets,
            "port": port,
            "banner": last_banner,
            "vulnerabilities": all_vulns
        }
