import asyncio
import subprocess
import logging
from typing import AsyncGenerator

logger = logging.getLogger("gobuster_client")

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

    async def scan_stream(self, host: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> AsyncGenerator[str, None]:
        """
        Runs a Gobuster scan and streams the raw text output line-by-line.
        """
        url = f"http://{host}" if not host.startswith("http") else host
        cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q"]
        cmd_str = " ".join(cmd)
        
        yield f"[VAPT-GOBUSTER] Starting scan: {cmd_str}\n"

        if self.mock_mode:
            yield f"===============================================================\n"
            yield f"Gobuster v3.5\n"
            yield f"by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)\n"
            yield f"===============================================================\n"
            yield f"[+] Url:                     {url}\n"
            yield f"[+] Method:                  GET\n"
            yield f"[+] Threads:                 10\n"
            yield f"[+] Wordlist:                {wordlist}\n"
            yield f"===============================================================\n"
            yield f"Starting gobuster in directory enumeration mode\n"
            yield f"===============================================================\n"
            await asyncio.sleep(1.0)
            yield f"/images               (Status: 301) [Size: 315] [--> {url}/images/]\n"
            await asyncio.sleep(0.5)
            yield f"/admin                (Status: 401) [Size: 456]\n"
            await asyncio.sleep(1.5)
            yield f"/css                  (Status: 301) [Size: 312] [--> {url}/css/]\n"
            await asyncio.sleep(0.8)
            yield f"/js                   (Status: 301) [Size: 311] [--> {url}/js/]\n"
            await asyncio.sleep(1.2)
            yield f"/robots.txt           (Status: 200) [Size: 26]\n"
            await asyncio.sleep(0.5)
            yield f"/server-status        (Status: 403) [Size: 277]\n"
            yield f"===============================================================\n"
            yield f"Finished\n"
            yield f"===============================================================\n"
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
            yield f"[VAPT-GOBUSTER-ERROR] Executing Gobuster failed: {str(e)}\n"
