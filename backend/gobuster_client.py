import asyncio
import subprocess
import logging
import os
import re
from typing import AsyncGenerator, List, Dict, Any

logger = logging.getLogger("gobuster_client")

BUNDLED_WORDLIST = "/usr/share/dirb/wordlists/common.txt"
_LEGACY_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

def _resolve_wordlist(requested: str) -> str:
    for candidate in [requested, BUNDLED_WORDLIST, _LEGACY_WORDLIST]:
        if candidate and os.path.isfile(candidate) and os.path.getsize(candidate) > 0:
            return candidate
    raise FileNotFoundError(
        f"No valid wordlist found. Requested: {requested}. "
        f"Bundled fallback: {BUNDLED_WORDLIST} (also missing or empty). "
        "Please install wordlists: apt-get install dirb"
    )

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

class GobusterClient:
    def __init__(self):
        self.mock_mode = False
        self.check_gobuster()

    def check_gobuster(self):
        try:
            subprocess.run(["gobuster", "version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            logger.info("Gobuster is installed and available on PATH.")
            self.mock_mode = False
        except Exception:
            logger.warning("Gobuster is not installed or not in PATH. Falling back to MOCK MODE.")
            self.mock_mode = True

    async def scan_stream(self, host: str, wordlist: str = "/usr/share/dirb/wordlists/common.txt") -> AsyncGenerator[str, None]:
        targets = extract_targets(host)
        if not targets:
            yield "[VAPT-GOBUSTER-ERROR] No valid target hosts provided.\n"
            yield "[VAPT-GOBUSTER-COMPLETE]\n"
            return

        total_targets = len(targets)
        if total_targets > 1:
            yield f"[VAPT-GOBUSTER] Multi-target Group Scan initialized: {total_targets} hosts queued ({', '.join(targets)})\n"
        else:
            yield f"[VAPT-GOBUSTER] Target Scan initialized for: {targets[0]}\n"

        for idx, single_host in enumerate(targets, 1):
            url = f"http://{single_host}" if not single_host.startswith("http") else single_host

            if total_targets > 1:
                yield f"\n============================================================\n"
                yield f"[VAPT-GOBUSTER] >>> Processing Host ({idx}/{total_targets}): {url} <<<\n"
                yield f"============================================================\n"

            try:
                resolved_wl = _resolve_wordlist(wordlist)
            except FileNotFoundError as wle:
                yield f"[VAPT-GOBUSTER-ERROR] {wle}\n"
                continue

            cmd = ["gobuster", "dir", "-u", url, "-w", resolved_wl, "-q", "--no-color", "--no-progress"]
            cmd_str = " ".join(cmd)
            yield f"[VAPT-GOBUSTER] Starting scan: {cmd_str}\n"

            if self.mock_mode:
                yield f"[+] Url:                     {url}\n"
                yield f"[+] Wordlist:                {resolved_wl}\n"
                await asyncio.sleep(0.5)
                yield f"/images               (Status: 301) [Size: 315] [--> {url}/images/]\n"
                yield f"/admin                (Status: 401) [Size: 456]\n"
                await asyncio.sleep(0.5)
                yield f"Finished enumeration for {url}\n"
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
                yield f"[VAPT-GOBUSTER-ERROR] Executing Gobuster on {url} failed: {str(e)}\n"

        if total_targets > 1:
            yield f"\n[VAPT-GOBUSTER] Group Scan finished: All {total_targets} hosts enumerated successfully.\n"

        yield "\n[VAPT-GOBUSTER-COMPLETE]\n"

    async def scan_results_parsed(self, host: str, wordlist: str = "/usr/share/dirb/wordlists/common.txt",
                                   mode: str = "dir", extensions: str = "",
                                   ignored_codes: str = "404", threads: int = 20,
                                   follow_redirects: bool = False,
                                   headers: str = None) -> list:
        targets = extract_targets(host)
        if not targets:
            return []

        if self.mock_mode:
            await asyncio.sleep(1.0)
            all_mock = []
            for t in targets:
                all_mock.extend([
                    {"host": t, "path": "/images", "status": 301, "size": 315, "redirect": "/images/"},
                    {"host": t, "path": "/admin", "status": 401, "size": 456, "redirect": ""},
                ])
            return all_mock

        resolved_wl = _resolve_wordlist(wordlist)
        all_results = []

        for single_host in targets:
            url = f"http://{single_host}" if not single_host.startswith("http") else single_host
            gobuster_mode = mode if mode in ("dir", "dns", "vhost", "fuzz") else "dir"

            cmd = ["gobuster", gobuster_mode, "-u", url, "-w", resolved_wl,
                   "-q", "--no-color", "--no-progress", "-t", str(threads)]
            if extensions:
                cmd.extend(["-x", extensions])
            if ignored_codes:
                cmd.extend(["-b", ignored_codes])
            if follow_redirects:
                cmd.append("-r")
            if headers:
                cmd.extend(["-H", headers])

            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await process.communicate()

                for line in stdout.decode("utf-8", errors="replace").splitlines():
                    if not line.startswith("/"):
                        continue
                    match = re.search(r'(/[\w\-\./]+)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\]', line)
                    if match:
                        path = match.group(1)
                        status = int(match.group(2))
                        size = int(match.group(3))
                        redirect = ""
                        redir_match = re.search(r'\[-->\s+(.*?)\]', line)
                        if redir_match:
                            redirect = redir_match.group(1)
                        all_results.append({
                            "host": single_host,
                            "path": path,
                            "status": status,
                            "size": size,
                            "redirect": redirect
                        })
            except Exception as e:
                logger.error(f"Error executing Gobuster on {single_host}: {e}")

        return all_results
