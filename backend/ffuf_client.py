import asyncio
import subprocess
import logging
import os
import json
import re
import tempfile
from typing import AsyncGenerator, List, Dict, Any

logger = logging.getLogger("ffuf_client")

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

class FfufClient:
    def __init__(self):
        self.mock_mode = False
        self.check_ffuf()

    def check_ffuf(self):
        try:
            subprocess.run(["ffuf", "-V"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            logger.info("FFuF is installed and available on PATH.")
            self.mock_mode = False
        except Exception:
            logger.warning("FFuF is not installed or not in PATH. Falling back to MOCK MODE.")
            self.mock_mode = True

    async def scan_stream(self, host: str, wordlist: str = "/usr/share/dirb/wordlists/common.txt") -> AsyncGenerator[str, None]:
        targets = extract_targets(host)
        if not targets:
            yield "[VAPT-FFUF-ERROR] No valid targets specified.\n"
            yield "[VAPT-FFUF-COMPLETE]\n"
            return

        total_targets = len(targets)
        if total_targets > 1:
            yield f"[VAPT-FFUF] Multi-target Group Scan initialized: {total_targets} hosts queued ({', '.join(targets)})\n"
        else:
            yield f"[VAPT-FFUF] Target Scan initialized for: {targets[0]}\n"

        for idx, single_host in enumerate(targets, 1):
            url = f"http://{single_host}" if not single_host.startswith("http") else single_host
            if "FUZZ" not in url:
                url = url.rstrip("/") + "/FUZZ"

            if total_targets > 1:
                yield f"\n============================================================\n"
                yield f"[VAPT-FFUF] >>> Processing Host ({idx}/{total_targets}): {url} <<<\n"
                yield f"============================================================\n"

            cmd = ["ffuf", "-u", url, "-w", wordlist, "-mc", "200,204,301,302,307,401,403"]
            cmd_str = " ".join(cmd)
            yield f"[VAPT-FFUF] Starting scan: {cmd_str}\n"

            if self.mock_mode:
                yield f":: URL              : {url}\n"
                await asyncio.sleep(0.5)
                yield f"admin                   [Status: 401, Size: 456, host: {single_host}]\n"
                yield f"images                  [Status: 301, Size: 315, host: {single_host}]\n"
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
                yield f"[VAPT-FFUF-ERROR] Executing FFuF on {single_host} failed: {str(e)}\n"

        if total_targets > 1:
            yield f"\n[VAPT-FFUF] Group Scan finished: All {total_targets} hosts fuzzed successfully.\n"

        yield "\n[VAPT-FFUF-COMPLETE]\n"

    async def scan_results_parsed(self, host: str, wordlist: str = "/usr/share/dirb/wordlists/common.txt", threads: int = 40) -> list:
        targets = extract_targets(host)
        if not targets:
            return []

        if self.mock_mode:
            await asyncio.sleep(1.0)
            all_mock = []
            for t in targets:
                all_mock.extend([
                    {"host": t, "input": {"FUZZ": "admin"}, "status": 401, "length": 456, "words": 42, "url": f"http://{t}/admin"},
                    {"host": t, "input": {"FUZZ": "images"}, "status": 301, "length": 315, "words": 20, "url": f"http://{t}/images"}
                ])
            return all_mock

        all_results = []

        for single_host in targets:
            url = f"http://{single_host}" if not single_host.startswith("http") else single_host
            if "FUZZ" not in url:
                url = url.rstrip("/") + "/FUZZ"
                
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp_file:
                tmp_path = tmp_file.name

            cmd = [
                "ffuf", "-u", url, "-w", wordlist, 
                "-t", str(threads),
                "-mc", "200,204,301,302,307,401,403",
                "-o", tmp_path, "-of", "json",
                "-noninteractive"
            ]

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await process.communicate()
                
                if os.path.exists(tmp_path):
                    with open(tmp_path, "r") as f:
                        data = json.load(f)
                        for item in data.get("results", []):
                            all_results.append({
                                "host": single_host,
                                "input": item.get("input", {}),
                                "status": item.get("status"),
                                "length": item.get("length"),
                                "words": item.get("words"),
                                "url": item.get("url")
                            })
            except Exception as e:
                logger.error(f"Error executing FFuF for {single_host}: {e}")
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

        return all_results
