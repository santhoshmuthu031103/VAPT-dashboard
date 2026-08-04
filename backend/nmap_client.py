import asyncio
import subprocess
import logging
import xml.etree.ElementTree as ET
from typing import AsyncGenerator, Dict, List, Any

logger = logging.getLogger("nmap_client")

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

    async def scan_stream(self, host: str, scan_type: str = "quick") -> AsyncGenerator[str, None]:
        """
        Runs an Nmap scan and streams the raw text output line-by-line.
        If in Mock Mode, simulates the output line-by-line with standard timings.
        """
        # Determine options based on scan type
        if scan_type == "quick":
            args = ["-F", host]
        elif scan_type == "service":
            args = ["-sV", "-F", host]
        elif scan_type == "os":
            args = ["-O", "-F", host]
        elif scan_type == "full":
            args = ["-sV", "-O", "-p", "1-1000", host]
        elif scan_type == "stealth":
            args = ["-sS", "-T2", host]
        elif scan_type == "udp":
            args = ["-sU", "-F", host]
        elif scan_type == "all_ports":
            args = ["-p-", "-sV", host]
        elif scan_type == "vuln":
            args = ["-sV", "--script=vuln", host]
        elif scan_type == "aggressive":
            args = ["-A", host]
        else:
            args = [scan_type, host]  # Assume direct args

        cmd = ["nmap"] + args
        cmd_str = " ".join(cmd)

        yield f"[VAPT-NMAP] Starting scan: {cmd_str}\n"

        if self.mock_mode:
            # Simulate real-time streaming output
            yield "Starting Nmap 7.94 ( https://nmap.org ) at 2026-07-28 15:40 UTC\n"
            await asyncio.sleep(0.8)
            yield f"Nmap scan report for {host}\n"
            await asyncio.sleep(1.0)
            yield "Host is up (0.045s latency).\n"
            yield "Not shown: 994 closed tcp ports (reset)\n"
            yield "PORT     STATE SERVICE     VERSION\n"
            await asyncio.sleep(0.5)
            yield "22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)\n"
            await asyncio.sleep(0.6)
            yield "80/tcp   open  http        nginx 1.18.0\n"
            await asyncio.sleep(0.4)
            yield "443/tcp  open  ssl/http    nginx 1.18.0\n"
            await asyncio.sleep(0.8)
            yield "3306/tcp open  mysql       MySQL 8.0.28-0ubuntu0.20.04.3\n"
            await asyncio.sleep(0.5)
            yield "8080/tcp open  http-proxy  Apache Tomcat 9.0.58\n"
            await asyncio.sleep(1.0)
            
            if "os" in scan_type or "full" in scan_type:
                yield "Device type: general purpose\n"
                yield "Running: Linux 5.X\n"
                yield "OS CPE: cpe:/o:linux:linux_kernel:5\n"
                yield "OS details: Linux 5.4 - 5.15\n"
                yield "Network Distance: 1 hop\n"
                await asyncio.sleep(0.4)
            
            yield "\nNmap done: 1 IP address (1 host up) scanned in 4.60 seconds\n"
            return

        # Real live execution
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
            yield f"[VAPT-NMAP-ERROR] Executing Nmap failed: {str(e)}\n"

    async def scan_results_parsed(self, host: str, scan_type: str = "quick") -> List[Dict[str, Any]]:
        """
        Runs an Nmap scan with XML output enabled, parses the XML, and returns structured data.
        """
        # Determine scan configurations
        if scan_type == "quick":
            args = ["-F", "-oX", "-"]
        elif scan_type == "service":
            args = ["-sV", "-F", "-oX", "-"]
        elif scan_type == "os":
            args = ["-O", "-F", "-oX", "-"]
        elif scan_type == "full":
            args = ["-sV", "-O", "-p", "1-1000", "-oX", "-"]
        elif scan_type == "stealth":
            args = ["-sS", "-T2", "-oX", "-"]
        elif scan_type == "udp":
            args = ["-sU", "-F", "-oX", "-"]
        elif scan_type == "all_ports":
            args = ["-p-", "-sV", "-oX", "-"]
        elif scan_type == "vuln":
            args = ["-sV", "--script=vuln", "-oX", "-"]
        elif scan_type == "aggressive":
            args = ["-A", "-oX", "-"]
        else:
            args = [scan_type, "-oX", "-"]

        cmd = ["nmap"] + args + [host]

        if self.mock_mode:
            # Simulated parsed result
            ports = [
                {"port": "22", "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 8.9p1 Ubuntu", "reason": "syn-ack"},
                {"port": "80", "protocol": "tcp", "state": "open", "service": "http", "version": "nginx 1.18.0", "reason": "syn-ack"},
                {"port": "443", "protocol": "tcp", "state": "open", "service": "https", "version": "nginx 1.18.0 (SSL)", "reason": "syn-ack"},
                {"port": "3306", "protocol": "tcp", "state": "open", "service": "mysql", "version": "MySQL 8.0.28", "reason": "syn-ack"},
                {"port": "8080", "protocol": "tcp", "state": "open", "service": "http", "version": "Apache Tomcat 9.0.58", "reason": "syn-ack"}
            ]
            return ports

        try:
            # Runs process synchronously to grab XML buffer
            process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            xml_data = process.stdout.decode("utf-8", errors="replace")
            
            root = ET.fromstring(xml_data)
            ports = []
            
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
                
                ports.append({
                    "port": port_id,
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                    "version": version or "N/A",
                    "reason": reason
                })
                
            return ports
        except Exception as e:
            logger.error(f"Error parsing Nmap XML: {e}")
            return []
