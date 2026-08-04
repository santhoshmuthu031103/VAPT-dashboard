from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
from main import gvm_client
from middleware.auth import admin_required

router = APIRouter()

class CredentialCreate(BaseModel):
    name: str
    credential_type: str  # "ssh_password", "ssh_key", "smb", "rdp"
    username: str
    password: Optional[str] = None
    private_key: Optional[str] = None
    comment: Optional[str] = ""

@router.get("/credentials")
def list_credentials():
    try:
        return gvm_client.list_credential_sets()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/credentials")
def create_credential(payload: CredentialCreate, admin: dict = Depends(admin_required)):
    try:
        cred_id = gvm_client.create_credential(
            name=payload.name,
            credential_type=payload.credential_type,
            username=payload.username,
            password=payload.password,
            private_key=payload.private_key,
            comment=payload.comment or ""
        )
        return {"id": cred_id, "name": payload.name, "type": payload.credential_type}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/credentials/{cred_id}")
def delete_credential(cred_id: str, admin: dict = Depends(admin_required)):
    try:
        success = gvm_client.delete_credential(cred_id)
        if not success:
            raise HTTPException(status_code=400, detail="Failed to delete credential.")
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
