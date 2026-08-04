import asyncio
from gvm_client import GVMClient

client = GVMClient()
# Use a target ID from the API response
target_id = "f56fd2bb-9d00-44db-aa27-385217c78dda" 
config_id = "daba56c8-73ec-11df-a475-002264764cea" # Full and fast
scanner_id = "6acd0832-df90-11e4-b9d5-28d24461215b" # CVE

try:
    task_id = client.create_task("Test Task", target_id, config_id, scanner_id)
    print("Created:", task_id)
except Exception as e:
    print("Error:", e)
