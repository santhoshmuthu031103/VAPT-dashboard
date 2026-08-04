from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
from middleware.auth import admin_required
from main import gvm_client

router = APIRouter()

class TargetCreate(BaseModel):
    name: str
    hosts: str
    comment: Optional[str] = ""
    ssh_credential_id: Optional[str] = None   # attach existing SSH credential
    smb_credential_id: Optional[str] = None   # attach existing SMB credential

@router.get("/targets")
def list_targets():
    try:
        return gvm_client.get_targets()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/targets")
def create_target(payload: TargetCreate, admin: dict = Depends(admin_required)):
    try:
        target_id = gvm_client.create_target(
            name=payload.name,
            hosts=payload.hosts,
            comment=payload.comment or "",
            ssh_credential_id=payload.ssh_credential_id,
            smb_credential_id=payload.smb_credential_id
        )
        return {"id": target_id, "name": payload.name, "hosts": payload.hosts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/targets/{target_id}")
def delete_target(target_id: str, admin: dict = Depends(admin_required)):
    success = gvm_client.delete_target(target_id)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to delete target.")
    return {"status": "success"}
