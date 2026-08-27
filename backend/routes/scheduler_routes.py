from fastapi import APIRouter, HTTPException, BackgroundTasks, Query
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import history_db
import scheduler

router = APIRouter(tags=["scheduler"])

class ScheduledScanCreate(BaseModel):
    tool: str
    target: str
    scan_type: Optional[str] = "quick"
    run_at: str # ISO formatted string
    frequency: Optional[str] = "once"
    group_name: Optional[str] = None
    cron_expr: Optional[str] = None

class ScheduledScanUpdate(BaseModel):
    tool: Optional[str] = None
    target: Optional[str] = None
    scan_type: Optional[str] = None
    run_at: Optional[str] = None # ISO formatted string
    frequency: Optional[str] = None
    group_name: Optional[str] = None
    cron_expr: Optional[str] = None

@router.get("/scheduler")
def list_scheduled_scans(status: Optional[str] = Query(None)):
    try:
        scans = history_db.get_scheduled_scans(status=status)
        all_scans = history_db.get_scheduled_scans()
        stats = {
            "total": len(all_scans),
            "pending": sum(1 for s in all_scans if s.get("status") == "pending"),
            "running": sum(1 for s in all_scans if s.get("status") == "running"),
            "completed": sum(1 for s in all_scans if s.get("status") == "completed"),
            "failed": sum(1 for s in all_scans if s.get("status") == "failed"),
        }
        return {
            "scans": scans,
            "stats": stats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scheduler")
def create_scheduled_scan(scan: ScheduledScanCreate):
    try:
        # Validate date
        try:
            dt = datetime.fromisoformat(scan.run_at.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid run_at format. Use ISO 8601 string.")
        
        freq = (scan.frequency or "once").lower()
        
        scan_id = history_db.add_scheduled_scan(
            tool=scan.tool,
            target=scan.target,
            scan_type=scan.scan_type or "default",
            run_at=scan.run_at,
            frequency=freq,
            cron_expr=scan.cron_expr,
            group_name=scan.group_name,
            next_run=scan.run_at
        )
        if not scan_id:
            raise HTTPException(status_code=500, detail="Failed to save scheduled scan to database")
            
        # Add to APScheduler
        scheduler.add_job_to_scheduler(
            scan_id=scan_id,
            tool=scan.tool,
            target=scan.target,
            scan_type=scan.scan_type or "",
            run_at_str=scan.run_at,
            frequency=freq
        )
        
        return {"status": "success", "id": scan_id, "frequency": freq}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/scheduler/{scan_id}")
def update_scheduled_scan_endpoint(scan_id: int, scan: ScheduledScanUpdate):
    try:
        scans = history_db.get_scheduled_scans()
        existing = next((s for s in scans if s["id"] == scan_id), None)
        if not existing:
            raise HTTPException(status_code=404, detail="Scheduled scan not found")

        # Validate date if provided
        run_at = scan.run_at or existing.get("run_at")
        if scan.run_at:
            try:
                datetime.fromisoformat(scan.run_at.replace("Z", "+00:00"))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid run_at format. Use ISO 8601 string.")

        freq = (scan.frequency or existing.get("frequency") or "once").lower()
        tool = scan.tool or existing.get("tool")
        target = scan.target or existing.get("target")
        scan_type = scan.scan_type or existing.get("scan_type", "quick")
        group_name = scan.group_name if scan.group_name is not None else existing.get("group_name")
        cron_expr = scan.cron_expr if scan.cron_expr is not None else existing.get("cron_expr")

        success = history_db.update_scheduled_scan(
            scan_id=scan_id,
            tool=tool,
            target=target,
            scan_type=scan_type,
            run_at=run_at,
            frequency=freq,
            cron_expr=cron_expr,
            group_name=group_name
        )

        if not success:
            raise HTTPException(status_code=500, detail="Failed to update scheduled scan in database")

        # Update in APScheduler
        scheduler.add_job_to_scheduler(
            scan_id=scan_id,
            tool=tool,
            target=target,
            scan_type=scan_type or "",
            run_at_str=run_at,
            frequency=freq
        )

        return {"status": "success", "id": scan_id, "run_at": run_at, "frequency": freq}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scheduler/{scan_id}/toggle-active")
def toggle_scheduled_scan_active(scan_id: int):
    try:
        scans = history_db.get_scheduled_scans()
        target_scan = next((s for s in scans if s["id"] == scan_id), None)
        if not target_scan:
            raise HTTPException(status_code=404, detail="Scheduled scan not found")

        current_active = target_scan.get("is_active", 1)
        new_active = 0 if current_active == 1 else 1

        history_db.toggle_scheduled_scan_active(scan_id, new_active)

        if new_active == 1:
            # Re-register to APScheduler
            scheduler.add_job_to_scheduler(
                scan_id=scan_id,
                tool=target_scan["tool"],
                target=target_scan["target"],
                scan_type=target_scan.get("scan_type", ""),
                run_at_str=target_scan["run_at"],
                frequency=target_scan.get("frequency", "once")
            )
        else:
            # Remove from APScheduler
            scheduler.remove_job_from_scheduler(scan_id)

        return {"status": "success", "id": scan_id, "is_active": new_active}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scheduler/{scan_id}/run-now")
async def run_scheduled_scan_now(scan_id: int, background_tasks: BackgroundTasks):
    try:
        scans = history_db.get_scheduled_scans()
        target_scan = next((s for s in scans if s["id"] == scan_id), None)
        if not target_scan:
            raise HTTPException(status_code=404, detail="Scheduled scan not found")
            
        background_tasks.add_task(
            scheduler.execute_scheduled_scan,
            scan_id,
            target_scan["tool"],
            target_scan["target"],
            target_scan.get("scan_type", ""),
            target_scan.get("frequency", "once")
        )
        return {"status": "triggered", "message": f"Scan #{scan_id} execution started in background"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/scheduler/{scan_id}")
def delete_scheduled_scan(scan_id: int):
    try:
        # Remove from db
        history_db.delete_scheduled_scan(scan_id)
        # Remove from scheduler if active
        scheduler.remove_job_from_scheduler(scan_id)
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

