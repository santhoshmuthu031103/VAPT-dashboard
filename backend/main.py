import os
import asyncio
import pdfkit
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, Response, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from gvm_client import GVMClient
from nmap_client import NmapClient
from nuclei_client import NucleiClient
from nikto_client import NiktoClient
from zap_client import ZAPClient
from gobuster_client import GobusterClient
from sqlmap_client import SqlmapClient
from ffuf_client import FfufClient

# New imports for auth and additional routes
from middleware.auth import admin_required
import history_db
import scheduler

# Initialize scan history database
history_db.init_db()


app = FastAPI(title="VAPT Dashboard Server", description="Backend APIs for orchestrating OpenVAS & Nmap scans")

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Global client instances
gvm_client = GVMClient()
nmap_client = NmapClient()
nuclei_client = NucleiClient()
nikto_client = NiktoClient()
zap_client = ZAPClient()
gobuster_client = GobusterClient()
sqlmap_client = SqlmapClient()
ffuf_client = FfufClient()

# Request Models
class TargetCreate(BaseModel):
    name: str
    hosts: str
    comment: Optional[str] = ""

class TaskCreate(BaseModel):
    name: str
    target_id: str
    config_id: Optional[str] = "daba56c8-73ec-11df-a475-002264764cea"  # Default to Full and Fast
    scanner_id: Optional[str] = "08b69003-5fc2-4037-a479-93b440211c73"  # OpenVAS Default
    credential_id: Optional[str] = None

class ConnectionSettings(BaseModel):
    connection_type: str
    socket_path: Optional[str] = "/run/gvmd/gvmd.sock"
    host: Optional[str] = "localhost"
    port: Optional[int] = 9390
    username: str
    password: str

# API ROUTES

@app.get("/api/status")
def get_status():
    # Re-check live connection each request so the UI is always accurate
    try:
        gvm_client.try_connect()
    except Exception:
        pass
    return {
        "gvm_connected": not gvm_client.mock_mode,
        "nmap_connected": not nmap_client.mock_mode,
        "gvm_mode": "Live" if not gvm_client.mock_mode else "Mock Mode",
        "nmap_mode": "Live" if not nmap_client.mock_mode else "Mock Mode",
        "nuclei_mode": "Live" if not nuclei_client.mock_mode else "Mock Mode",
        "nikto_mode": "Live" if not nikto_client.mock_mode else "Mock Mode",
        "zap_mode": "Live" if not zap_client.mock_mode else "Mock Mode",
        "gobuster_mode": "Live" if not gobuster_client.mock_mode else "Mock Mode",
        "sqlmap_mode": "Live" if not sqlmap_client.mock_mode else "Mock Mode",
        "ffuf_mode": "Live" if not ffuf_client.mock_mode else "Mock Mode",
        "settings": {
            "connection_type": gvm_client.connection_type,
            "socket_path": gvm_client.socket_path,
            "host": gvm_client.host,
            "port": gvm_client.port,
            "username": gvm_client.username
        }
    }

@app.post("/api/settings")
def update_settings(settings: ConnectionSettings):
    global gvm_client
    try:
        gvm_client = GVMClient(
            connection_type=settings.connection_type,
            socket_path=settings.socket_path or "/run/gvmd/gvmd.sock",
            host=settings.host or "localhost",
            port=settings.port or 9390,
            username=settings.username,
            password=settings.password
        )
        return {
            "status": "success",
            "message": "Settings updated and connection re-initialized.",
            "gvm_connected": not gvm_client.mock_mode
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to apply settings: {str(e)}")

# Register routers (targets, scan configs, credentials, scanners)
from routes import target_routes, scan_config_routes, credential_routes, scanners_routes, scheduler_routes
app.include_router(target_routes.router, prefix="/api")
app.include_router(scan_config_routes.router, prefix="/api")
app.include_router(credential_routes.router, prefix="/api")
app.include_router(scanners_routes.router, prefix="/api")
app.include_router(scheduler_routes.router, prefix="/api")

@app.on_event("startup")
async def startup_event():
    scheduler.scheduler.start()
    scheduler.restore_pending_jobs()

@app.on_event("shutdown")
async def shutdown_event():
    scheduler.scheduler.shutdown()


@app.get("/api/scanners")
def list_scanners():
    try:
        return gvm_client.list_scanners()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def get_nuclei_template_count() -> int:
    import os
    count = 0
    base_dir = "/root/nuclei-templates"
    if os.path.exists(base_dir):
        for root, dirs, files in os.walk(base_dir):
            for file in files:
                if file.endswith(".yaml"):
                    count += 1
    return count

@app.get("/api/feed-status")
def get_feed_status():
    try:
        gvm_feeds = gvm_client.get_feed_status()
    except Exception:
        gvm_feeds = []
        
    try:
        nuclei_count = get_nuclei_template_count()
    except Exception:
        nuclei_count = 0
        
    return {
        "gvm_feeds": gvm_feeds,
        "nuclei_templates": {
            "count": nuclei_count,
            "path": "/root/nuclei-templates"
        }
    }

@app.get("/api/cves")
def list_cves(search: str = Query("", max_length=100), page: int = Query(1, ge=1), limit: int = Query(50, ge=1, le=100)):
    try:
        return gvm_client.get_cves(search_term=search, page=page, limit=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Tasks API with pagination
@app.get("/api/tasks")
def list_tasks(page: int = Query(1, ge=1), limit: int = Query(20, ge=1, le=100)):
    try:
        all_tasks = gvm_client.get_tasks()
        start = (page - 1) * limit
        end = start + limit
        return {
            "page": page,
            "limit": limit,
            "total": len(all_tasks),
            "tasks": all_tasks[start:end]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/tasks")
def create_task(task: TaskCreate, request: Request, admin: Any = Depends(admin_required)):
    try:
        resolved_target_id = task.target_id
        if resolved_target_id and resolved_target_id.startswith("group:"):
            try:
                group_id = int(resolved_target_id.split(":", 1)[1])
                group = history_db.get_target_group_by_id(group_id)
                if group and group.get("targets"):
                    group_targets = group["targets"]
                    hosts_list = group_targets if isinstance(group_targets, list) else [str(group_targets)]
                    hosts_str = ", ".join([h.strip() for h in hosts_list if h.strip()])
                    
                    if hosts_str:
                        group_tgt_name = f"[Group] {group['name']}"
                        existing_targets = gvm_client.list_targets()
                        found = next((t for t in existing_targets if t.get("name") == group_tgt_name), None)
                        if found:
                            resolved_target_id = found["id"]
                        else:
                            resolved_target_id = gvm_client.create_target(
                                name=group_tgt_name,
                                hosts=hosts_str,
                                comment=f"Auto-generated GVM target for group {group['name']}"
                            )
            except Exception as ge:
                logger.warning(f"Failed to auto-resolve target group {task.target_id}: {ge}")

        task_id = gvm_client.create_task(
            name=task.name,
            target_id=resolved_target_id,
            config_id=task.config_id,
            scanner_id=task.scanner_id or "08b69003-5fc2-4037-a479-93b440211c73",
        )
        return {"id": task_id, "name": task.name, "target_id": resolved_target_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/tasks/{task_id}/start")
def start_task(task_id: str, admin: Any = Depends(admin_required)):
    try:
        report_id = gvm_client.start_task(task_id)
        if not report_id:
            raise HTTPException(status_code=400, detail="Could not start task. Check if task exists and GVM status.")
        return {"status": "started", "report_id": report_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/tasks/{task_id}/stop")
def stop_task(task_id: str, admin: Any = Depends(admin_required)):
    try:
        success = gvm_client.stop_task(task_id)
        if not success:
            raise HTTPException(status_code=400, detail="Failed to stop task.")
        return {"status": "stopped"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/tasks/{task_id}")
def delete_task(task_id: str, admin: Any = Depends(admin_required)):
    try:
        success = gvm_client.delete_task(task_id)
        if not success:
            raise HTTPException(status_code=400, detail="Failed to delete task.")
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Reports API
@app.get("/api/reports/{report_id}")
def get_report(report_id: str):
    try:
        return gvm_client.get_report(report_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/reports/{report_id}/download")
def download_report(
    report_id: str,
    fmt: str = Query("html", description="Export format: xml, html, pdf"),
    company: Optional[str] = Query(None),
    auditor: Optional[str] = Query(None),
    approved_by: Optional[str] = Query(None),
    doc_title: Optional[str] = Query(None),
):
    """
    Download a full OpenVAS / GVM Infrastructure Audit report.
    - fmt=xml  → raw GVM XML
    - fmt=html → executive styled HTML report
    - fmt=pdf  → enterprise PDF report with cover page and methodology
    """
    metadata = {
        "organization": company or "Wyzmindz Solutions",
        "prepared_by": auditor or "Santhosh M (Network Admin)",
        "reviewed_by": approved_by or "Leo Antony Charles (IT Manager)",
        "doc_title": doc_title or "Infrastructure Vulnerability Assessment & Penetration Testing Report"
    }
    try:
        if fmt == "xml":
            raw_xml = gvm_client.get_report_raw_xml(report_id)
            filename = f"openvas-report-{report_id[:8]}.xml"
            return StreamingResponse(
                iter([raw_xml]),
                media_type="application/xml",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'}
            )
        elif fmt == "pdf":
            report = gvm_client.get_report(report_id)
            html_content = gvm_client.render_html_report(report, metadata)
            pdf_bytes = pdfkit.from_string(html_content, False, options={
                'page-size': 'A4',
                'margin-top': '0.5in',
                'margin-right': '0.5in',
                'margin-bottom': '0.5in',
                'margin-left': '0.5in',
                'encoding': "UTF-8",
                'no-outline': None,
                'enable-local-file-access': None,
                'quiet': ''
            })
            filename = f"openvas-vapt-audit-{report_id[:8]}.pdf"
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "Access-Control-Expose-Headers": "Content-Disposition"
                }
            )
        else:
            # Generate HTML report from parsed data
            report = gvm_client.get_report(report_id)
            html_content = gvm_client.render_html_report(report, metadata)
            filename = f"openvas-vapt-audit-{report_id[:8]}.html"
            return Response(
                content=html_content.encode("utf-8"),
                media_type="text/html",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "Access-Control-Expose-Headers": "Content-Disposition"
                }
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class WebReportPayload(BaseModel):
    tool: str
    target_url: str
    results: Any
    metadata: Optional[Dict[str, Any]] = None
    format: Optional[str] = "html"

@app.post("/api/reports/web-pentest/generate")
def generate_web_pentest_report(payload: WebReportPayload):
    from web_report_generator import WebReportGenerator
    try:
        norm = WebReportGenerator.normalize_findings(payload.tool, payload.results, payload.target_url)
        fmt = (payload.format or "html").lower()
        if fmt == "json":
            return {
                "status": "success",
                "normalized": norm,
                "html": WebReportGenerator.render_html_report(norm, payload.metadata)
            }
        elif fmt == "pdf":
            pdf_bytes = WebReportGenerator.generate_pdf_report(norm, payload.metadata)
            filename = f"vapt-{payload.tool.lower()}-report.pdf"
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "Access-Control-Expose-Headers": "Content-Disposition"
                }
            )
        else:
            html_str = WebReportGenerator.render_html_report(norm, payload.metadata)
            filename = f"vapt-{payload.tool.lower()}-report.html"
            return Response(
                content=html_str.encode("utf-8"),
                media_type="text/html",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "Access-Control-Expose-Headers": "Content-Disposition"
                }
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Nmap API
@app.get("/api/nmap/scan")
async def stream_nmap_scan(host: str = Query(..., description="Target Host IP or Domain"),
                            scan_type: str = Query("quick", description="quick, service, os, full")):
    """
    Streams raw Nmap CLI stdout logs line-by-line via SSE (Server-Sent Events).
    """
    async def event_generator():
        async for line in nmap_client.scan_stream(host, scan_type):
            yield f"data: {line}\n\n"
            await asyncio.sleep(0.01)
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/api/nmap/results")
async def get_nmap_results(host: str = Query(..., description="Target Host IP or Domain"),
                           scan_type: str = Query("quick", description="quick, service, os, full")):
    """
    Executes Nmap scan, parses and returns structured services list.
    Checks for a very recent scan (within 60 seconds) in database first to avoid running it twice.
    """
    try:
        # Check if there is a very recent scan result in the database
        import sqlite3, json
        from datetime import datetime, timedelta
        
        DB_PATH = "/root/vapt-dashboard/backend/data/vapt.db"
        if os.path.exists(DB_PATH):
            try:
                conn = sqlite3.connect(DB_PATH)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT results, timestamp FROM scan_history 
                    WHERE tool = 'nmap' AND target = ? AND scan_type = ? AND status = 'completed'
                    ORDER BY timestamp DESC LIMIT 1
                """, (host, scan_type))
                row = cursor.fetchone()
                conn.close()
                
                if row:
                    timestamp_str = row["timestamp"]
                    scan_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                    if datetime.utcnow() - scan_time < timedelta(seconds=60):
                        return json.loads(row["results"])
            except Exception:
                pass

        results = await nmap_client.scan_results_parsed(host, scan_type)
        history_db.save_scan("nmap", host, scan_type, "completed", results)
        return results
    except Exception as e:
        history_db.save_scan("nmap", host, scan_type, "failed", {"error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))

# Host compiled react static assets
frontend_dist_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../frontend/dist"))
if os.path.exists(frontend_dist_path):
    app.mount("/", StaticFiles(directory=frontend_dist_path, html=True), name="static")
else:
    @app.get("/")
    def read_root():
        return {
            "status": "online",
            "message": "VAPT Dashboard API Server is running. Compile frontend using 'npm run build' inside frontend/ to serve the UI here."
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
