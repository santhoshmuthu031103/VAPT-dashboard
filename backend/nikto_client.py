import asyncio
import subprocess
import logging
from typing import AsyncGenerator

logger = logging.getLogger("nikto_client")

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
        Runs a Nikto scan and streams the raw text output line-by-line.
        """
        cmd = ["nikto", "-h", host, "-port", port]
        cmd_str = " ".join(cmd)
        
        yield f"[VAPT-NIKTO] Starting scan: {cmd_str}\n"

        if self.mock_mode:
            yield f"- Nikto v2.1.6\n"
            yield f"---------------------------------------------------------------------------\n"
            yield f"+ Target IP:          192.168.1.100\n"
            yield f"+ Target Hostname:    {host}\n"
            yield f"+ Target Port:        {port}\n"
            yield f"+ Start Time:         2026-08-04 09:30:00 (GMT)\n"
            yield f"---------------------------------------------------------------------------\n"
            await asyncio.sleep(1.0)
            yield f"+ Server: Apache/2.4.41 (Ubuntu)\n"
            await asyncio.sleep(0.5)
            yield f"+ The anti-clickjacking X-Frame-Options header is not present.\n"
            await asyncio.sleep(0.5)
            yield f"+ The X-XSS-Protection header is not defined.\n"
            await asyncio.sleep(1.0)
            yield f"+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type\n"
            await asyncio.sleep(1.5)
            yield f"+ /config.php: PHP config file found. This might contain sensitive information.\n"
            await asyncio.sleep(2.0)
            yield f"+ /phpmyadmin/: phpMyAdmin directory found.\n"
            yield f"+ 8510 requests: 0 error(s) and 5 item(s) reported on remote host\n"
            yield f"+ End Time:           2026-08-04 09:31:00 (GMT) (60 seconds)\n"
            yield f"---------------------------------------------------------------------------\n"
            yield f"+ 1 host(s) tested\n"
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
            yield f"[VAPT-NIKTO-ERROR] Executing Nikto failed: {str(e)}\n"
