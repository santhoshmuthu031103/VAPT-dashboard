from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List, Union
from middleware.auth import admin_required
from main import gvm_client
import history_db

router = APIRouter()

class TargetCreate(BaseModel):
    name: str
    hosts: str
    comment: Optional[str] = ""
    ssh_credential_id: Optional[str] = None   # attach existing SSH credential
    smb_credential_id: Optional[str] = None   # attach existing SMB credential
    port_list_id: Optional[str] = None        # attach custom port list

class TargetUpdate(BaseModel):
    name: Optional[str] = None
    hosts: Optional[str] = None
    comment: Optional[str] = None
    ssh_credential_id: Optional[str] = None
    smb_credential_id: Optional[str] = None
    port_list_id: Optional[str] = None

class TargetGroupCreate(BaseModel):
    name: str
    targets: Union[List[str], str]
    description: Optional[str] = ""
    color: Optional[str] = "#3b82f6"

class TargetGroupUpdate(BaseModel):
    name: Optional[str] = None
    targets: Optional[Union[List[str], str]] = None
    description: Optional[str] = None
    color: Optional[str] = None

@router.get("/targets")
def list_targets():
    try:
        return gvm_client.get_targets()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/port-lists")
def list_port_lists():
    try:
        return gvm_client.list_port_lists()
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
            smb_credential_id=payload.smb_credential_id,
            port_list_id=payload.port_list_id or "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
        )
        return {"id": target_id, "name": payload.name, "hosts": payload.hosts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/targets/{target_id}")
def update_target(target_id: str, payload: TargetUpdate, admin: dict = Depends(admin_required)):
    try:
        success = gvm_client.modify_target(
            target_id=target_id,
            name=payload.name,
            hosts=payload.hosts,
            comment=payload.comment,
            ssh_credential_id=payload.ssh_credential_id,
            smb_credential_id=payload.smb_credential_id,
            port_list_id=payload.port_list_id
        )
        if not success:
            raise HTTPException(status_code=400, detail="Failed to update target.")
        return {"status": "success", "id": target_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/targets/{target_id}")
def delete_target(target_id: str, admin: dict = Depends(admin_required)):
    success = gvm_client.delete_target(target_id)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to delete target.")
    return {"status": "success"}

# ==========================================
# Target Groups API Endpoints
# ==========================================

@router.get("/target-groups")
def list_target_groups():
    try:
        return history_db.get_target_groups()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/target-groups")
def create_target_group(payload: TargetGroupCreate):
    try:
        # Normalize targets to list
        if isinstance(payload.targets, str):
            targets_list = [t.strip() for t in payload.targets.replace("\n", ",").split(",") if t.strip()]
        else:
            targets_list = [str(t).strip() for t in payload.targets if str(t).strip()]
            
        group_id = history_db.create_target_group(
            name=payload.name,
            targets=targets_list,
            description=payload.description or "",
            color=payload.color or "#3b82f6"
        )
        if not group_id:
            raise HTTPException(status_code=400, detail="Group with this name may already exist or invalid input.")
            
        return {"id": group_id, "name": payload.name, "targets": targets_list, "description": payload.description, "color": payload.color}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/target-groups/{group_id}")
def get_target_group(group_id: int):
    try:
        group = history_db.get_target_group_by_id(group_id)
        if not group:
            raise HTTPException(status_code=404, detail="Target group not found")
        return group
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/target-groups/{group_id}")
def update_target_group(group_id: int, payload: TargetGroupUpdate):
    try:
        targets_list = None
        if payload.targets is not None:
            if isinstance(payload.targets, str):
                targets_list = [t.strip() for t in payload.targets.replace("\n", ",").split(",") if t.strip()]
            else:
                targets_list = [str(t).strip() for t in payload.targets if str(t).strip()]

        success = history_db.update_target_group(
            group_id=group_id,
            name=payload.name,
            targets=targets_list,
            description=payload.description,
            color=payload.color
        )
        if not success:
            raise HTTPException(status_code=400, detail="Failed to update target group")
        return {"status": "success", "id": group_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/target-groups/{group_id}")
def delete_target_group(group_id: int):
    try:
        success = history_db.delete_target_group(group_id)
        if not success:
            raise HTTPException(status_code=400, detail="Failed to delete target group")
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

