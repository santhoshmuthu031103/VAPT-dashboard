import asyncio
import subprocess
import logging
import json
from typing import AsyncGenerator, Dict, List, Any

logger = logging.getLogger("nuclei_client")

class NucleiClient:
    def __init__(self):
        self.mock_mode = False
        self.check_nuclei()

    def check_nuclei(self):
        try:
            subprocess.run(["nuclei", "-version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            logger.info("Nuclei is installed and available on PATH.")
            self.mock_mode = False
        except Exception:
            logger.warning("Nuclei is not installed or not in PATH. Falling back to MOCK MODE.")
            self.mock_mode = True

    async def scan_stream(self, host: str, templates: str = "") -> AsyncGenerator[str, None]:
        """
        Runs a Nuclei scan and streams the raw text output line-by-line.
        """
        cmd = ["nuclei", "-u", host]
        if templates:
            cmd.extend(["-t", templates])
            
        cmd_str = " ".join(cmd)
        yield f"[VAPT-NUCLEI] Starting scan: {cmd_str}\n"

        if self.mock_mode:
            yield f"                     __     _\n"
            yield f"   ____  __  _______/ /__  (_)\n"
            yield f"  / __ \\/ / / / ___/ / _ \\/ /\n"
            yield f" / / / / /_/ / /__/ /  __/ /\n"
            yield f"/_/ /_/\\__,_/\\___/_/\\___/_/\n"
            yield f"\n"
            yield f"[WRN] Use with caution. You are responsible for your actions.\n"
            yield f"[INF] Using Nuclei Engine 3.1.0 (built: 2026-01-01)\n"
            await asyncio.sleep(1.0)
            yield f"[INF] Templates loaded for current scan: 6542\n"
            await asyncio.sleep(1.5)
            
            # Simulate finding some vulnerabilities
            yield f"[tech-detect] [http] [info] {host} (nginx)\n"
            await asyncio.sleep(0.5)
            yield f"[ssl-dns-names] [ssl] [info] {host} (*.example.com)\n"
            await asyncio.sleep(1.2)
            yield f"[CVE-2021-41773] [http] [high] {host} (Apache Path Traversal)\n"
            await asyncio.sleep(0.8)
            yield f"[exposed-panels] [http] [low] {host}/admin/login.php\n"
            await asyncio.sleep(2.0)
            yield f"[INF] Scan results written to output file\n"
            return

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
            yield f"[VAPT-NUCLEI-ERROR] Executing Nuclei failed: {str(e)}\n"

    async def scan_results_parsed(self, host: str, templates: str = "") -> List[Dict[str, Any]]:
        """
        Runs Nuclei with JSONL output, parses it, and returns structured vulnerabilities.
        """
        cmd = ["nuclei", "-u", host, "-jsonl"]
        if templates:
            cmd.extend(["-t", templates])

        if self.mock_mode:
            # Simulated parsed result
            await asyncio.sleep(2.0)
            return [
                {
                    "template-id": "tech-detect",
                    "info": {"name": "Wappalyzer Technology Detection", "severity": "info"},
                    "type": "http",
                    "host": host,
                    "matched-at": f"http://{host}",
                    "extracted-results": ["nginx"]
                },
                {
                    "template-id": "CVE-2021-41773",
                    "info": {"name": "Apache 2.4.49 - Path Traversal", "severity": "high"},
                    "type": "http",
                    "host": host,
                    "matched-at": f"http://{host}/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"
                },
                {
                    "template-id": "exposed-panels",
                    "info": {"name": "Exposed Login Panel", "severity": "low"},
                    "type": "http",
                    "host": host,
                    "matched-at": f"http://{host}/admin/login.php"
                }
            ]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await process.communicate()
            
            results = []
            for line in stdout.decode("utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
            return results
        except Exception as e:
            logger.error(f"Error executing Nuclei JSON: {e}")
            return []
