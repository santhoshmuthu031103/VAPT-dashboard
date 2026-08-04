import sys
import os

# Add backend directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

from main import gvm_client

try:
    print("Testing get_cves WITH specific search:")
    res2 = gvm_client.get_cves(search_term="CVE-2021-44228", page=1, limit=5)
    print(f"Got {len(res2['cves'])} CVEs, total: {res2['total']}")
except Exception as e:
    import traceback
    traceback.print_exc()
