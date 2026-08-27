import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from history_db import update_scheduled_scan_status, save_scan, get_scheduled_scans
import nmap_client
import nuclei_client
import nikto_client
import gobuster_client
import zap_client
import sqlmap_client
import ffuf_client
import asyncio
from datetime import datetime, timezone

logger = logging.getLogger("vapt_scheduler")

# Standard in-memory scheduler
scheduler = AsyncIOScheduler()

# Tool clients for background execution
clients = {
    "nmap": nmap_client.NmapClient(),
    "nuclei": nuclei_client.NucleiClient(),
    "nikto": nikto_client.NiktoClient(),
    "gobuster": gobuster_client.GobusterClient(),
    "zap": zap_client.ZAPClient(),
    "sqlmap": sqlmap_client.SqlmapClient(),
    "ffuf": ffuf_client.FfufClient()
}

async def run_single_tool_scan(tool: str, target: str, scan_type: str):
    """Executes a single tool scan against a target host."""
    client = clients.get(tool.lower())
    if not client:
        raise ValueError(f"Unknown tool: {tool}")
        
    t = tool.lower()
    if t == "nmap":
        return await client.scan_results_parsed(target, scan_type or "quick")
    elif t == "nuclei":
        return await client.scan_results_parsed(target, scan_type or "info")
    elif t == "nikto":
        return await client.scan_results_parsed(target)
    elif t == "gobuster":
        return await client.scan_results_parsed(target, scan_type or "dir")
    elif t == "zap":
        return await client.scan_results_parsed(target)
    elif t == "sqlmap":
        return await client.scan_results_parsed(target, scan_type or "quick")
    elif t == "ffuf":
        return await client.scan_results_parsed(target, scan_type or "dir")
    return None

async def execute_scheduled_scan(scan_id: int, tool: str, target: str, scan_type: str, frequency: str = "once"):
    logger.info(f"Executing scheduled scan #{scan_id} - Tool: {tool}, Target: {target}, Frequency: {frequency}")
    update_scheduled_scan_status(scan_id, "running")
    
    # Split multiple targets (if comma or newline separated)
    raw_targets = [tgt.strip() for tgt in target.replace("\n", ",").split(",") if tgt.strip()]
    if not raw_targets:
        raw_targets = [target.strip()]

    now_iso = datetime.now(timezone.utc).isoformat()

    try:
        combined_results = []
        has_success = False

        for tgt in raw_targets:
            try:
                res = await run_single_tool_scan(tool, tgt, scan_type)
                if res:
                    has_success = True
                    if isinstance(res, list):
                        combined_results.extend(res)
                    else:
                        combined_results.append(res)
                    # Also save individual target history entry
                    save_scan(tool, tgt, scan_type, "completed", res)
            except Exception as item_err:
                logger.error(f"Error scanning target {tgt} in scan #{scan_id}: {item_err}")
                save_scan(tool, tgt, scan_type, "failed", {"error": str(item_err)})

        if has_success:
            if frequency.lower() == "once":
                update_scheduled_scan_status(scan_id, "completed", last_run=now_iso, next_run=None)
            else:
                # Find next run time from scheduler job
                job = scheduler.get_job(f"scan_{scan_id}")
                next_run_iso = job.next_run_time.isoformat() if job and job.next_run_time else None
                update_scheduled_scan_status(scan_id, "pending", last_run=now_iso, next_run=next_run_iso)
            logger.info(f"Scheduled scan #{scan_id} execution finished successfully.")
        else:
            if frequency.lower() == "once":
                update_scheduled_scan_status(scan_id, "failed", last_run=now_iso)
            else:
                job = scheduler.get_job(f"scan_{scan_id}")
                next_run_iso = job.next_run_time.isoformat() if job and job.next_run_time else None
                update_scheduled_scan_status(scan_id, "pending", last_run=now_iso, next_run=next_run_iso)
            logger.warning(f"Scheduled scan #{scan_id} yielded no successful results.")
            
    except Exception as e:
        logger.error(f"Failed to execute scheduled scan #{scan_id}: {e}")
        save_scan(tool, target, scan_type, "failed", {"error": str(e)})
        update_scheduled_scan_status(scan_id, "failed", last_run=now_iso)

def add_job_to_scheduler(scan_id: int, tool: str, target: str, scan_type: str, run_at_str: str, frequency: str = "once") -> bool:
    """Adds or updates a job in APScheduler based on frequency."""
    job_id = f"scan_{scan_id}"
    freq = (frequency or "once").lower()

    try:
        dt = datetime.fromisoformat(run_at_str.replace("Z", "+00:00"))
    except Exception:
        dt = datetime.now(timezone.utc)

    try:
        if freq == "hourly":
            scheduler.add_job(
                execute_scheduled_scan,
                IntervalTrigger(hours=1, start_date=dt, timezone=dt.tzinfo),
                args=[scan_id, tool, target, scan_type, freq],
                id=job_id,
                replace_existing=True
            )
        elif freq == "daily":
            scheduler.add_job(
                execute_scheduled_scan,
                CronTrigger(hour=dt.hour, minute=dt.minute, timezone=dt.tzinfo),
                args=[scan_id, tool, target, scan_type, freq],
                id=job_id,
                replace_existing=True
            )
        elif freq == "weekly":
            scheduler.add_job(
                execute_scheduled_scan,
                CronTrigger(day_of_week=dt.weekday(), hour=dt.hour, minute=dt.minute, timezone=dt.tzinfo),
                args=[scan_id, tool, target, scan_type, freq],
                id=job_id,
                replace_existing=True
            )
        elif freq == "monthly":
            scheduler.add_job(
                execute_scheduled_scan,
                CronTrigger(day=min(dt.day, 28), hour=dt.hour, minute=dt.minute, timezone=dt.tzinfo),
                args=[scan_id, tool, target, scan_type, freq],
                id=job_id,
                replace_existing=True
            )
        else:
            # Once
            scheduler.add_job(
                execute_scheduled_scan,
                DateTrigger(run_date=dt),
                args=[scan_id, tool, target, scan_type, "once"],
                id=job_id,
                replace_existing=True
            )
        return True
    except Exception as ex:
        logger.warning(f"Could not register scheduler job {job_id}: {ex}")
        return False

def remove_job_from_scheduler(scan_id: int):
    """Removes a job from APScheduler."""
    job_id = f"scan_{scan_id}"
    try:
        scheduler.remove_job(job_id)
    except Exception:
        pass

def restore_pending_jobs():
    """Restores all active / pending jobs from SQLite DB on server startup."""
    try:
        scans = get_scheduled_scans()
        now_tz = datetime.now(timezone.utc)
        for s in scans:
            if s.get("is_active", 1) == 0:
                continue
                
            freq = (s.get("frequency") or "once").lower()
            status = s.get("status", "pending")
            
            # For 'once', only restore if status is pending and run_at is future or recent
            if freq == "once" and status != "pending":
                continue

            run_at_str = s.get("run_at", "")
            try:
                dt = datetime.fromisoformat(run_at_str.replace("Z", "+00:00"))
                if freq == "once" and dt < now_tz:
                    # In past, leave as-is or mark completed
                    continue
                add_job_to_scheduler(
                    scan_id=s["id"],
                    tool=s["tool"],
                    target=s["target"],
                    scan_type=s.get("scan_type", ""),
                    run_at_str=run_at_str,
                    frequency=freq
                )
            except Exception as ex:
                logger.warning(f"Could not restore job {s.get('id')}: {ex}")
    except Exception as e:
        logger.error(f"Error restoring pending jobs: {e}")

