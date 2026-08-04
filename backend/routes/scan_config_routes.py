from fastapi import APIRouter, HTTPException
from main import gvm_client

router = APIRouter()

@router.get("/scan-configs")
def list_scan_configs():
    try:
        return gvm_client.list_scan_configs()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
