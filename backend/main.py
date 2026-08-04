import os
import asyncio
import pdfkit
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from gvm_client import GVMClient
from nmap_client import NmapClient
# New imports for auth and additional routes
from middleware.auth import admin_required


app = FastAPI(title="VAPT Dashboard Server", description="Backend APIs for orchestrating OpenVAS & Nmap scans")

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global client instances
gvm_client = GVMClient()
nmap_client = NmapClient()

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

# Register routers (targets, scan configs, credentials)
from routes import target_routes, scan_config_routes, credential_routes
app.include_router(target_routes.router, prefix="/api")
app.include_router(scan_config_routes.router, prefix="/api")
app.include_router(credential_routes.router, prefix="/api")

@app.get("/api/scanners")
def list_scanners():
    try:
        return gvm_client.list_scanners()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

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
        task_id = gvm_client.create_task(
            name=task.name,
            target_id=task.target_id,
            config_id=task.config_id,
            scanner_id=task.scanner_id or "08b69003-5fc2-4037-a479-93b440211c73",
        )
        return {"id": task_id, "name": task.name, "target_id": task.target_id}
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
def download_report(report_id: str, fmt: str = Query("html", description="Export format: xml, html, pdf")):
    """
    Download a full OpenVAS report.
    - fmt=xml  → raw GVM XML (same as OpenVAS XML export)
    - fmt=html → self-contained styled HTML report
    - fmt=pdf  → PDF rendered from the styled HTML
    """
    try:
        if fmt == "xml":
            # Fetch raw XML directly from GVM
            raw_xml = gvm_client.get_report_raw_xml(report_id)
            filename = f"openvas-report-{report_id[:8]}.xml"
            return StreamingResponse(
                iter([raw_xml]),
                media_type="application/xml",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'}
            )
        elif fmt == "pdf":
            # Generate PDF from HTML
            report = gvm_client.get_report(report_id)
            html_content = gvm_client.render_html_report(report)
            pdf_bytes = pdfkit.from_string(html_content, False, options={
                'page-size': 'A4',
                'margin-top': '0.75in',
                'margin-right': '0.75in',
                'margin-bottom': '0.75in',
                'margin-left': '0.75in',
                'encoding': "UTF-8",
                'no-outline': None
            })
            filename = f"openvas-report-{report_id[:8]}.pdf"
            return StreamingResponse(
                iter([pdf_bytes]),
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'}
            )
        else:
            # Generate HTML report from parsed data
            report = gvm_client.get_report(report_id)
            html_content = gvm_client.render_html_report(report)
            filename = f"openvas-report-{report_id[:8]}.html"
            return StreamingResponse(
                iter([html_content.encode("utf-8")]),
                media_type="text/html",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'}
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
    """
    try:
        results = await nmap_client.scan_results_parsed(host, scan_type)
        return results
    except Exception as e:
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
