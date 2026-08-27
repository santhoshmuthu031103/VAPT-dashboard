import asyncio
import subprocess
import logging
import re
import os
import tempfile
import xml.etree.ElementTree as ET
from typing import AsyncGenerator, Dict, List, Any

logger = logging.getLogger("nmap_client")

def extract_targets(host_input: str) -> List[str]:
    """Splits comma, newline, or whitespace separated host strings into unique cleaned host items."""
    if not host_input:
        return []
    targets = [t.strip() for t in re.split(r'[\s,\n]+', str(host_input).strip()) if t.strip()]
    # Preserve order while deduplicating
    seen = set()
    unique_targets = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique_targets.append(t)
    return unique_targets

class NmapClient:
    def __init__(self):
        self.mock_mode = False
        self.check_nmap()

    def check_nmap(self):
        try:
            # Check if nmap is available on PATH
            subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            logger.info("Nmap is installed and available on PATH.")
            self.mock_mode = False
        except Exception:
            logger.warning("Nmap is not installed or not in PATH. Falling back to MOCK MODE.")
            self.mock_mode = True

    def _get_scan_args(self, host: str, scan_type: str) -> List[str]:
        if scan_type == "quick":
            return ["-F", host]
        elif scan_type == "service":
            return ["-sV", "-F", host]
        elif scan_type == "os":
            return ["-O", "-F", host]
        elif scan_type == "full":
            return ["-sV", "-O", "-p", "1-1000", host]
        elif scan_type == "stealth":
            return ["-sS", "-T2", host]
        elif scan_type == "udp":
            return ["-sU", "-F", host]
        elif scan_type == "all_ports":
            return ["-p-", "-sV", host]
        elif scan_type == "vuln":
            return ["-sV", "--script=vuln", host]
        elif scan_type == "aggressive":
            return ["-A", host]
        else:
            return [scan_type, host]

    async def scan_stream(self, host: str, scan_type: str = "quick") -> AsyncGenerator[str, None]:
        """
        Runs an Nmap scan one-by-one for each target in a target group / comma-separated list.
        Streams the raw text output line-by-line.
        """
        import history_db

        targets = extract_targets(host)
        if not targets:
            yield "[VAPT-NMAP-ERROR] No valid target hosts provided.\n"
            yield "[VAPT-NMAP-COMPLETE]\n"
            return

        total_targets = len(targets)
        if total_targets > 1:
            yield f"[VAPT-NMAP] Multi-target Group Scan initialized: {total_targets} hosts queued ({', '.join(targets)})\n"
        else:
            yield f"[VAPT-NMAP] Target Scan initialized for: {targets[0]}\n"

        all_collected_ports = []

        for idx, single_host in enumerate(targets, 1):
            if total_targets > 1:
                yield f"\n============================================================\n"
                yield f"[VAPT-NMAP] >>> Processing Host ({idx}/{total_targets}): {single_host} <<<\n"
                yield f"============================================================\n"

            if self.mock_mode:
                yield f"Starting Nmap 7.94 ( https://nmap.org ) at UTC\n"
                await asyncio.sleep(0.5)
                yield f"Nmap scan report for {single_host}\n"
                await asyncio.sleep(0.5)
                yield "Host is up (0.045s latency).\n"
                yield "PORT     STATE SERVICE     VERSION\n"
                await asyncio.sleep(0.3)
                yield f"22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu (host: {single_host})\n"
                await asyncio.sleep(0.3)
                yield f"80/tcp   open  http        nginx 1.18.0 (host: {single_host})\n"
                await asyncio.sleep(0.4)
                yield f"\nNmap done: 1 IP address (1 host up) scanned.\n"

                mock_ports = [
                    {"host": single_host, "port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 8.9p1 Ubuntu", "reason": "syn-ack"},
                    {"host": single_host, "port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "nginx 1.18.0", "reason": "syn-ack"},
                ]
                all_collected_ports.extend(mock_ports)
                continue

            # Real execution for single_host
            xml_file = tempfile.mktemp(suffix=f"_nmap_{idx}.xml")
            args = self._get_scan_args(single_host, scan_type)
            cmd = ["nmap"] + args + ["-oX", xml_file]
            cmd_str = " ".join(["nmap"] + args)

            yield f"[VAPT-NMAP] Executing: {cmd_str}\n"

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

                # Parse XML for this host
                if os.path.exists(xml_file):
                    try:
                        root = ET.parse(xml_file).getroot()
                        for port_node in root.findall(".//port"):
                            port_id = port_node.get("portid")
                            protocol = port_node.get("protocol")
                            
                            state_node = port_node.find("state")
                            state = state_node.get("state") if state_node is not None else "unknown"
                            reason = state_node.get("reason") if state_node is not None else ""
                            
                            service_node = port_node.find("service")
                            service = "unknown"
                            version = ""
                            if service_node is not None:
                                service = service_node.get("name", "unknown")
                                product = service_node.get("product", "")
                                version_str = service_node.get("version", "")
                                extrainfo = service_node.get("extrainfo", "")
                                
                                version_parts = [p for p in [product, version_str, extrainfo] if p]
                                version = " ".join(version_parts) if version_parts else "N/A"
                            
                            all_collected_ports.append({
                                "host": single_host,
                                "port": int(port_id) if (port_id and port_id.isdigit()) else port_id,
                                "protocol": protocol,
                                "state": state,
                                "service": service,
                                "version": version or "N/A",
                                "reason": reason
                            })
                    except Exception as e:
                        logger.error(f"Error parsing Nmap XML for {single_host}: {e}")
                    finally:
                        try:
                            os.remove(xml_file)
                        except Exception:
                            pass
            except Exception as e:
                yield f"[VAPT-NMAP-ERROR] Executing Nmap for {single_host} failed: {str(e)}\n"
                if os.path.exists(xml_file):
                    try:
                        os.remove(xml_file)
                    except Exception:
                        pass

        # Save aggregated scan history
        try:
            history_db.save_scan("nmap", host, scan_type, "completed", all_collected_ports)
        except Exception as e:
            logger.error(f"Error saving nmap history: {e}")

        if total_targets > 1:
            yield f"\n[VAPT-NMAP] Scan complete: All {total_targets} group hosts finished. Total open ports found: {len(all_collected_ports)}\n"
        
        yield "\n[VAPT-NMAP-COMPLETE]\n"

    async def scan_results_parsed(self, host: str, scan_type: str = "quick") -> List[Dict[str, Any]]:
        """
        Runs an Nmap scan (or multi-target group scan), parses the XML, and returns structured data.
        """
        targets = extract_targets(host)
        if not targets:
            return []

        all_ports = []

        if self.mock_mode:
            for t in targets:
                all_ports.extend([
                    {"host": t, "port": "22", "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 8.9p1 Ubuntu", "reason": "syn-ack"},
                    {"host": t, "port": "80", "protocol": "tcp", "state": "open", "service": "http", "version": "nginx 1.18.0", "reason": "syn-ack"},
                    {"host": t, "port": "443", "protocol": "tcp", "state": "open", "service": "https", "version": "nginx 1.18.0 (SSL)", "reason": "syn-ack"},
                ])
            return all_ports

        for single_host in targets:
            args = self._get_scan_args(single_host, scan_type)
            cmd = ["nmap"] + [a for a in args if a != single_host] + ["-oX", "-", single_host]

            try:
                process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                xml_data = process.stdout.decode("utf-8", errors="replace")
                
                root = ET.fromstring(xml_data)
                
                for port_node in root.findall(".//port"):
                    port_id = port_node.get("portid")
                    protocol = port_node.get("protocol")
                    
                    state_node = port_node.find("state")
                    state = state_node.get("state") if state_node is not None else "unknown"
                    reason = state_node.get("reason") if state_node is not None else ""
                    
                    service_node = port_node.find("service")
                    service = "unknown"
                    version = ""
                    if service_node is not None:
                        service = service_node.get("name", "unknown")
                        product = service_node.get("product", "")
                        version_str = service_node.get("version", "")
                        extrainfo = service_node.get("extrainfo", "")
                        
                        version_parts = [p for p in [product, version_str, extrainfo] if p]
                        version = " ".join(version_parts) if version_parts else "N/A"
                    
                    all_ports.append({
                        "host": single_host,
                        "port": port_id,
                        "protocol": protocol,
                        "state": state,
                        "service": service,
                        "version": version or "N/A",
                        "reason": reason
                    })
            except Exception as e:
                logger.error(f"Error parsing Nmap XML for {single_host}: {e}")

        return all_ports
