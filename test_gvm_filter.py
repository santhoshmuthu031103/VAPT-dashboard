import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))
from main import gvm_client

try:
    print("Testing get_cves WITH specific name filter:")
    res = gvm_client.get_cves(search_term='name="CVE-2021-44228"', page=1, limit=5)
    print(f"Got {len(res['cves'])} CVEs, total: {res['total']}")

    print("\nTesting get_cves WITH specific name substring filter:")
    res2 = gvm_client.get_cves(search_term='name~"CVE-2021"', page=1, limit=5)
    print(f"Got {len(res2['cves'])} CVEs, total: {res2['total']}")
except Exception as e:
    import traceback
    traceback.print_exc()
