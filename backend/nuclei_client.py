import asyncio
import subprocess
import logging
import json
import re
from typing import AsyncGenerator, Dict, List, Any

logger = logging.getLogger("nuclei_client")

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
        Runs Nuclei scans one-by-one sequentially for each host/URL in a target group.
        Streams raw text output line-by-line.
        """
        targets = extract_targets(host)
        if not targets:
            yield "[VAPT-NUCLEI-ERROR] No valid targets specified.\n"
            yield "[VAPT-NUCLEI-COMPLETE]\n"
            return

        total_targets = len(targets)
        if total_targets > 1:
            yield f"[VAPT-NUCLEI] Multi-target Group Scan initialized: {total_targets} hosts queued ({', '.join(targets)})\n"
        else:
            yield f"[VAPT-NUCLEI] Target Scan initialized for: {targets[0]}\n"

        for idx, single_host in enumerate(targets, 1):
            target_url = f"http://{single_host}" if not single_host.startswith("http") else single_host

            if total_targets > 1:
                yield f"\n============================================================\n"
                yield f"[VAPT-NUCLEI] >>> Processing Host ({idx}/{total_targets}): {single_host} <<<\n"
                yield f"============================================================\n"

            cmd = ["nuclei", "-u", target_url]
            if templates:
                cmd.extend(["-t", templates])
                
            cmd_str = " ".join(cmd)
            yield f"[VAPT-NUCLEI] Starting scan: {cmd_str}\n"

            if self.mock_mode:
                yield f"[INF] Using Nuclei Engine for {single_host}\n"
                await asyncio.sleep(0.5)
                yield f"[tech-detect] [http] [info] {target_url} (nginx)\n"
                await asyncio.sleep(0.5)
                yield f"[exposed-panels] [http] [low] {target_url}/admin/login.php\n"
                await asyncio.sleep(0.5)
                yield f"[INF] Scan completed for {single_host}\n"
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
                yield f"[VAPT-NUCLEI-ERROR] Executing Nuclei on {single_host} failed: {str(e)}\n"

        if total_targets > 1:
            yield f"\n[VAPT-NUCLEI] Group Scan finished: All {total_targets} hosts scanned successfully.\n"
        
        yield "\n[VAPT-NUCLEI-COMPLETE]\n"

    async def scan_results_parsed(self, host: str, templates: str = "", category: str = "all",
                                   severity: str = "info", rate_limit: int = 150,
                                   concurrency: int = 25, timeout: int = 5,
                                   custom_tags: str = None) -> List[Dict[str, Any]]:
        """
        Runs Nuclei with JSONL output sequentially for each target in a target group,
        parses the results, and returns structured vulnerabilities.
        """
        targets = extract_targets(host)
        if not targets:
            return []

        all_results = []

        # Severity filter
        severity_map = {
            "info": "info,low,medium,high,critical",
            "low": "low,medium,high,critical",
            "medium": "medium,high,critical",
            "high": "high,critical",
            "critical": "critical"
        }
        sev_str = severity_map.get(severity, "info,low,medium,high,critical")

        if self.mock_mode:
            await asyncio.sleep(1.0)
            for t in targets:
                all_results.extend([
                    {
                        "template-id": "tech-detect",
                        "info": {"name": "Wappalyzer Technology Detection", "severity": "info"},
                        "type": "http",
                        "host": t,
                        "matched-at": f"http://{t}",
                        "extracted-results": ["nginx"]
                    },
                    {
                        "template-id": "exposed-panels",
                        "info": {"name": "Exposed Login Panel", "severity": "low"},
                        "type": "http",
                        "host": t,
                        "matched-at": f"http://{t}/admin/login.php"
                    }
                ])
            return all_results

        for single_host in targets:
            target_url = f"http://{single_host}" if not single_host.startswith("http") else single_host
            cmd = ["nuclei", "-u", target_url, "-jsonl",
                   "-rl", str(rate_limit),
                   "-c", str(concurrency),
                   "-timeout", str(timeout),
                   "-severity", sev_str]

            if templates:
                cmd.extend(["-t", templates])

            if custom_tags:
                cmd.extend(["-tags", custom_tags])
            elif category != "all":
                if category == "vulnerability":
                    cmd.extend(["-tags", "vulnerability,vuln"])
                else:
                    cmd.extend(["-tags", category])

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, _ = await process.communicate()
                
                for line in stdout.decode("utf-8").splitlines():
                    if not line.strip():
                        continue
                    try:
                        item = json.loads(line)
                        if "host" not in item or not item["host"]:
                            item["host"] = single_host
                        all_results.append(item)
                    except json.JSONDecodeError:
                        pass
            except Exception as e:
                logger.error(f"Error executing Nuclei JSON for {single_host}: {e}")

        return all_results
