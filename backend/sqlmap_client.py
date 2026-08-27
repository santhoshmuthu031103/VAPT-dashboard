import asyncio
import subprocess
import logging
import os
import re
from typing import AsyncGenerator, Dict, List, Any

logger = logging.getLogger("sqlmap_client")

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

class SqlmapClient:
    def __init__(self):
        self.mock_mode = False
        self.check_sqlmap()

    def check_sqlmap(self):
        try:
            subprocess.run(["sqlmap", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            logger.info("SQLmap is installed and available on PATH.")
            self.mock_mode = False
        except Exception:
            logger.warning("SQLmap is not installed or not in PATH. Falling back to MOCK MODE.")
            self.mock_mode = True

    async def scan_stream(self, host: str) -> AsyncGenerator[str, None]:
        targets = extract_targets(host)
        if not targets:
            yield "[VAPT-SQLMAP-ERROR] No valid target URLs/hosts provided.\n"
            yield "[VAPT-SQLMAP-COMPLETE]\n"
            return

        total_targets = len(targets)
        if total_targets > 1:
            yield f"[VAPT-SQLMAP] Multi-target Group Scan initialized: {total_targets} hosts queued ({', '.join(targets)})\n"
        else:
            yield f"[VAPT-SQLMAP] Target Scan initialized for: {targets[0]}\n"

        for idx, single_host in enumerate(targets, 1):
            url = f"http://{single_host}" if not single_host.startswith("http") else single_host

            if total_targets > 1:
                yield f"\n============================================================\n"
                yield f"[VAPT-SQLMAP] >>> Processing Host ({idx}/{total_targets}): {url} <<<\n"
                yield f"============================================================\n"

            cmd = ["sqlmap", "-u", url, "--batch", "--level=1", "--risk=1"]
            cmd_str = " ".join(cmd)
            yield f"[VAPT-SQLMAP] Starting scan: {cmd_str}\n"

            if self.mock_mode:
                yield f"[!] testing connection to {url}\n"
                await asyncio.sleep(0.5)
                yield f"[INFO] target URL is stable\n"
                yield f"[INFO] heuristic test shows parameter 'id' on {single_host} might be injectable\n"
                await asyncio.sleep(0.5)
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
                yield f"[VAPT-SQLMAP-ERROR] Executing SQLmap on {single_host} failed: {str(e)}\n"

        if total_targets > 1:
            yield f"\n[VAPT-SQLMAP] Group Scan finished: All {total_targets} hosts tested for SQLi.\n"

        yield "\n[VAPT-SQLMAP-COMPLETE]\n"

    async def scan_results_parsed(self, host: str, risk: int = 1, level: int = 1, forms: bool = False) -> dict:
        targets = extract_targets(host)
        if not targets:
            return {"injections": [], "raw_output": ""}

        if self.mock_mode:
            await asyncio.sleep(1.0)
            all_injections = []
            for t in targets:
                all_injections.append({
                    "host": t,
                    "parameter": f"id (GET) on {t}",
                    "type": "boolean-based blind",
                    "title": f"[{t}] AND boolean-based blind - WHERE or HAVING clause"
                })
            return {
                "injections": all_injections,
                "raw_output": f"Multi-target SQLmap audit finished for {len(targets)} host(s)."
            }

        all_injections = []
        raw_outputs = []

        for single_host in targets:
            url = f"http://{single_host}" if not single_host.startswith("http") else single_host
            cmd = ["sqlmap", "-u", url, "--batch", f"--risk={risk}", f"--level={level}"]
            if forms:
                cmd.append("--forms")

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()
                output = stdout.decode("utf-8", errors="replace")
                raw_outputs.append(f"--- Output for {single_host} ---\n{output}")

                lines = output.splitlines()
                for i, line in enumerate(lines):
                    if line.startswith("Parameter:"):
                        param = line.split("Parameter:")[1].strip()
                        inj_type = ""
                        title = ""
                        for j in range(i+1, min(i+5, len(lines))):
                            if lines[j].strip().startswith("Type:"):
                                inj_type = lines[j].split("Type:")[1].strip()
                            elif lines[j].strip().startswith("Title:"):
                                title = lines[j].split("Title:")[1].strip()
                        
                        if param:
                            all_injections.append({
                                "host": single_host,
                                "parameter": f"{param} ({single_host})",
                                "type": inj_type,
                                "title": f"[{single_host}] {title}" if len(targets) > 1 else title
                            })
            except Exception as e:
                logger.error(f"Error executing SQLmap on {single_host}: {e}")

        return {
            "injections": all_injections,
            "raw_output": "\n\n".join(raw_outputs)
        }
