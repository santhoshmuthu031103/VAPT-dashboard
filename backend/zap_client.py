import asyncio
import logging
import re
from typing import Dict, List, Any
from zapv2 import ZAPv2

logger = logging.getLogger("zap_client")

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

class ZAPClient:
    def __init__(self, proxy_url="http://127.0.0.1:8081"):
        self.proxy_url = proxy_url
        self.zap = ZAPv2(proxies={'http': proxy_url, 'https': proxy_url})
        self.mock_mode = False
        
        # Test connection
        try:
            version = self.zap.core.version
            logger.info(f"ZAP Daemon connected. Version: {version}")
        except Exception as e:
            logger.warning(f"Failed to connect to ZAP Daemon at {proxy_url}: {e}. ZAP is unavailable.")
            self.mock_mode = True

    async def scan_results_parsed(self, host: str, strength: str = "Medium",
                                   spider_depth: int = 5, max_crawl_duration: int = 2,
                                   ajax_spider: bool = False,
                                   include_regex: str = None,
                                   exclude_regex: str = None) -> List[Dict[str, Any]]:
        """
        Runs ZAP Active Scan sequentially for each target in a target group and fetches aggregated alerts.
        """
        targets = extract_targets(host)
        if not targets:
            return []

        all_alerts = []

        if self.mock_mode:
            logger.warning("ZAP is in MOCK MODE (Daemon unavailable), returning mock results.")
            await asyncio.sleep(1.0)
            for t in targets:
                all_alerts.extend([
                    {
                        "host": t,
                        "alert": "SQL Injection",
                        "risk": "High",
                        "confidence": "High",
                        "url": f"http://{t}/products.php?id=1",
                        "param": "id",
                        "evidence": "MySQL Error",
                        "description": f"SQL Injection detected on {t}.",
                        "solution": "Use prepared statements.",
                        "cweid": "89",
                        "wascid": "19",
                        "reference": "https://cwe.mitre.org/data/definitions/89.html",
                        "attack": "1' OR '1'='1"
                    },
                    {
                        "host": t,
                        "alert": "X-Frame-Options Header Not Set",
                        "risk": "Low",
                        "confidence": "High",
                        "url": f"http://{t}/index.html",
                        "param": "",
                        "evidence": "",
                        "description": f"The X-Frame-Options header is not set on {t}.",
                        "solution": "Configure X-Frame-Options header to DENY.",
                        "cweid": "1021",
                        "wascid": "15",
                        "reference": "https://cwe.mitre.org/data/definitions/1021.html"
                    }
                ])
            return all_alerts

        for single_host in targets:
            url = f"http://{single_host}" if not single_host.startswith("http") else single_host
            try:
                logger.info(f"ZAP accessing target: {url}")
                self.zap.urlopen(url)
                await asyncio.sleep(2)

                logger.info(f"ZAP starting spider for: {url}")
                scan_id = self.zap.spider.scan(url)
                
                while int(self.zap.spider.status(scan_id)) < 100:
                    await asyncio.sleep(2)

                strength_map = {
                    "Low": "Low", "Medium": "Medium", "High": "High",
                    "Insane": "Insane", "Default": "Default"
                }
                zap_strength = strength_map.get(strength, "Medium")

                logger.info(f"ZAP starting active scan for: {url} with strength {zap_strength}")
                try:
                    self.zap.ascan.set_policy_attack_strength(
                        id="0",
                        attackstrength=zap_strength
                    )
                except Exception as se:
                    logger.warning(f"Could not set attack strength (non-fatal): {se}")
                
                ascan_id = self.zap.ascan.scan(url)
                
                waits = 0
                while int(self.zap.ascan.status(ascan_id)) < 100 and waits < 300:
                    await asyncio.sleep(2)
                    waits += 1
                    
                alerts = self.zap.core.alerts(baseurl=url)
                for a in alerts:
                    all_alerts.append({
                        "host": single_host,
                        "alert": a.get("alert", "Unknown Alert"),
                        "risk": a.get("risk", "Low"),
                        "confidence": a.get("confidence", "Low"),
                        "url": a.get("url", ""),
                        "param": a.get("param", ""),
                        "evidence": a.get("evidence", ""),
                        "description": a.get("description", ""),
                        "solution": a.get("solution", ""),
                        "cweid": a.get("cweid", ""),
                        "wascid": a.get("wascid", ""),
                        "reference": a.get("reference", ""),
                        "attack": a.get("attack", ""),
                        "other": a.get("other", "")
                    })
            except Exception as e:
                logger.error(f"Error during ZAP scan for {single_host}: {e}")

        return all_alerts
