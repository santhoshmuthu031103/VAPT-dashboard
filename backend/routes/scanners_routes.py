import asyncio
import json
import datetime
from fastapi import APIRouter, Query, HTTPException, Body
from fastapi.responses import StreamingResponse, HTMLResponse, Response
from typing import Optional, Dict, Any, List
from pydantic import BaseModel
import main
import history_db
from web_report_generator import WebReportGenerator

router = APIRouter(prefix="/scanners", tags=["scanners"])

class WebReportRequest(BaseModel):
    tool: str
    target_url: str
    results: Any
    metadata: Optional[Dict[str, Any]] = None
    format: Optional[str] = "html"

class ZapScanRequest(BaseModel):
    target_url: Optional[str] = None
    host: Optional[str] = None
    policy: Optional[str] = "default"
    strength: Optional[str] = "Medium"
    spider_depth: Optional[int] = 5
    max_crawl_duration: Optional[int] = 2
    ajax_spider: Optional[bool] = False
    include_regex: Optional[str] = None
    exclude_regex: Optional[str] = None

class NiktoScanRequest(BaseModel):
    host: str
    port: Optional[Any] = "80"
    ssl: Optional[bool] = False
    tuning: Optional[str] = "all"
    max_time: Optional[str] = "15m"
    evasion: Optional[str] = "0"
    user_agent: Optional[str] = None
    auth_user: Optional[str] = None
    auth_pass: Optional[str] = None

class NucleiScanRequest(BaseModel):
    host: str
    category: Optional[str] = "all"
    severity: Optional[str] = "info"
    rate_limit: Optional[int] = 150
    concurrency: Optional[int] = 25
    timeout: Optional[int] = 5
    custom_tags: Optional[str] = None

class GobusterScanRequest(BaseModel):
    host: str
    mode: Optional[str] = "dir"
    wordlist: Optional[str] = "/usr/share/dirb/wordlists/common.txt"
    extensions: Optional[str] = ""
    ignored_codes: Optional[str] = "404"
    threads: Optional[int] = 20
    follow_redirects: Optional[bool] = False
    headers: Optional[str] = None

class FfufScanRequest(BaseModel):
    host: str
    wordlist: Optional[str] = "/usr/share/dirb/wordlists/common.txt"
    threads: Optional[int] = 40

class SqlmapScanRequest(BaseModel):
    host: str
    risk: Optional[int] = 1
    level: Optional[int] = 1
    forms: Optional[bool] = False


# ── Nuclei ──────────────────────────────────────────────────────────────

@router.get("/nuclei/stream")
async def stream_nuclei(host: str = Query(...)):
    async def event_generator():
        async for line in main.nuclei_client.scan_stream(host):
            yield f"data: {line}\n\n"
            await asyncio.sleep(0.01)
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@router.get("/nuclei/results")
async def get_nuclei_results(
    host:        str = Query(...),
    category:    str = Query("all"),
    severity:    str = Query("info"),
    rate_limit:  int = Query(150),
    concurrency: int = Query(25),
    timeout:     int = Query(5),
    custom_tags: Optional[str] = Query(None),
):
    try:
        results = await main.nuclei_client.scan_results_parsed(
            host,
            category=category,
            severity=severity,
            rate_limit=rate_limit,
            concurrency=concurrency,
            timeout=timeout,
            custom_tags=custom_tags,
        )
        history_db.save_scan("nuclei", host, category, "completed", results)
        return results
    except Exception as e:
        history_db.save_scan("nuclei", host, category, "failed", {"error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/nuclei")
@router.post("/nuclei/scan")
async def run_nuclei_scan(req: NucleiScanRequest):
    try:
        results = await main.nuclei_client.scan_results_parsed(
            req.host,
            category=req.category or "all",
            severity=req.severity or "info",
            rate_limit=req.rate_limit or 150,
            concurrency=req.concurrency or 25,
            timeout=req.timeout or 5,
            custom_tags=req.custom_tags,
        )
        history_db.save_scan("nuclei", req.host, req.category or "all", "completed", results)
        return results
    except Exception as e:
        history_db.save_scan("nuclei", req.host, req.category or "all", "failed", {"error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))


# ── Nikto ───────────────────────────────────────────────────────────────

@router.get("/nikto/stream")
async def stream_nikto(host: str = Query(...)):
    async def event_generator():
        async for line in main.nikto_client.scan_stream(host):
            yield f"data: {line}\n\n"
            await asyncio.sleep(0.01)
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@router.get("/nikto/results")
async def get_nikto_results(
    host:       str  = Query(...),
    port:       str  = Query("80"),
    ssl:        bool = Query(False),
    tuning:     str  = Query("all"),
    max_time:   str  = Query("15m"),
    evasion:    str  = Query("0"),
    user_agent: Optional[str] = Query(None),
    auth_user:  Optional[str] = Query(None),
    auth_pass:  Optional[str] = Query(None),
):
    try:
        results = await main.nikto_client.scan_results_parsed(
            host, port,
            ssl=ssl,
            tuning=tuning,
            max_time=max_time,
            evasion=evasion,
            user_agent=user_agent,
            auth_user=auth_user,
            auth_pass=auth_pass,
        )
        history_db.save_scan("nikto", host, f"port {port}", "completed", results)
        return results
    except Exception as e:
        history_db.save_scan("nikto", host, f"port {port}", "failed", {"error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/nikto")
@router.post("/nikto/scan")
async def run_nikto_scan(req: NiktoScanRequest):
    try:
        results = await main.nikto_client.scan_results_parsed(
            req.host,
            str(req.port or "80"),
            ssl=req.ssl or False,
            tuning=req.tuning or "all",
            max_time=req.max_time or "15m",
            evasion=req.evasion or "0",
            user_agent=req.user_agent,
            auth_user=req.auth_user,
            auth_pass=req.auth_pass,
        )
        history_db.save_scan("nikto", req.host, f"port {req.port}", "completed", results)
        return results
    except Exception as e:
        history_db.save_scan("nikto", req.host, f"port {req.port}", "failed", {"error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))


# ── Gobuster ─────────────────────────────────────────────────────────────

@router.get("/gobuster/stream")
async def stream_gobuster(host: str = Query(...)):
    async def event_generator():
        async for line in main.gobuster_client.scan_stream(host):
            yield f"data: {line}\n\n"
            await asyncio.sleep(0.01)
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@router.get("/gobuster/results")
async def get_gobuster_results(
    host:             str  = Query(...),
    mode:             str  = Query("dir"),
    wordlist:         str  = Query("/usr/share/dirb/wordlists/common.txt"),
    extensions:       str  = Query(""),
    ignored_codes:    str  = Query("404"),
    threads:          int  = Query(20),
    follow_redirects: bool = Query(False),
    headers:          Optional[str] = Query(None),
):
    try:
        results = await main.gobuster_client.scan_results_parsed(
            host,
            mode=mode,
            wordlist=wordlist,
            extensions=extensions,
            ignored_codes=ignored_codes,
            threads=threads,
            follow_redirects=follow_redirects,
            headers=headers,
        )
        history_db.save_scan("gobuster", host, mode, "completed", results)
        return results
    except Exception as e:
        history_db.save_scan("gobuster", host, mode, "failed", {"error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/gobuster")
@router.post("/gobuster/scan")
async def run_gobuster_scan(req: GobusterScanRequest):
    try:
        results = await main.gobuster_client.scan_results_parsed(
            req.host,
            mode=req.mode or "dir",
            wordlist=req.wordlist or "/usr/share/dirb/wordlists/common.txt",
            extensions=req.extensions or "",
            ignored_codes=req.ignored_codes or "404",
            threads=req.threads or 20,
            follow_redirects=req.follow_redirects or False,
            headers=req.headers,
        )
        history_db.save_scan("gobuster", req.host, req.mode or "dir", "completed", results)
        return results
    except Exception as e:
        history_db.save_scan("gobuster", req.host, req.mode or "dir", "failed", {"error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))


# ── OWASP ZAP ────────────────────────────────────────────────────────────

@router.get("/zap/results")
async def get_zap_results(
    host:               str  = Query(...),
    policy:             str  = Query("default"),
    strength:           str  = Query("Medium"),
    spider_depth:       int  = Query(5),
    max_crawl_duration: int  = Query(2),
    ajax_spider:        bool = Query(False),
    include_regex:      Optional[str] = Query(None),
    exclude_regex:      Optional[str] = Query(None),
):
    try:
        results = await main.zap_client.scan_results_parsed(
            host,
            strength=strength,
            spider_depth=spider_depth,
            max_crawl_duration=max_crawl_duration,
            ajax_spider=ajax_spider,
            include_regex=include_regex,
            exclude_regex=exclude_regex,
        )
        history_db.save_scan("zap", host, policy, "completed", results)
        return results
    except Exception as e:
        history_db.save_scan("zap", host, policy, "failed", {"error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/zap/scan")
@router.post("/zap")
async def run_zap_scan(req: ZapScanRequest):
    target = req.target_url or req.host
    if not target:
        raise HTTPException(status_code=400, detail="Missing target URL or host")
    try:
        results = await main.zap_client.scan_results_parsed(
            target,
            strength=req.strength or "Medium",
            spider_depth=req.spider_depth or 5,
            max_crawl_duration=req.max_crawl_duration or 2,
            ajax_spider=req.ajax_spider or False,
            include_regex=req.include_regex,
            exclude_regex=req.exclude_regex,
        )
        history_db.save_scan("zap", target, req.policy or "default", "completed", results)
        return results
    except Exception as e:
        history_db.save_scan("zap", target, req.policy or "default", "failed", {"error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))


# ── SQLmap ───────────────────────────────────────────────────────────────

@router.get("/sqlmap/stream")
async def stream_sqlmap(host: str = Query(...)):
    async def event_generator():
        async for line in main.sqlmap_client.scan_stream(host):
            yield f"data: {line}\n\n"
            await asyncio.sleep(0.01)
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@router.get("/sqlmap/results")
async def get_sqlmap_results(
    host:  str  = Query(...),
    risk:  int  = Query(1),
    level: int  = Query(1),
    forms: bool = Query(False),
):
    try:
        results = await main.sqlmap_client.scan_results_parsed(
            host,
            risk=risk,
            level=level,
            forms=forms
        )
        history_db.save_scan("sqlmap", host, f"Risk: {risk}, Level: {level}", "completed", results)
        return results
    except Exception as e:
        history_db.save_scan("sqlmap", host, f"Risk: {risk}, Level: {level}", "failed", {"error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/sqlmap")
@router.post("/sqlmap/scan")
async def run_sqlmap_scan(req: SqlmapScanRequest):
    try:
        results = await main.sqlmap_client.scan_results_parsed(
            req.host,
            risk=req.risk or 1,
            level=req.level or 1,
            forms=req.forms or False
        )
        history_db.save_scan("sqlmap", req.host, f"Risk: {req.risk}, Level: {req.level}", "completed", results)
        return results
    except Exception as e:
        history_db.save_scan("sqlmap", req.host, f"Risk: {req.risk}, Level: {req.level}", "failed", {"error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))


# ── FFuF ─────────────────────────────────────────────────────────────────

@router.get("/ffuf/stream")
async def stream_ffuf(
    host:     str = Query(...),
    wordlist: str = Query("/usr/share/dirb/wordlists/common.txt")
):
    async def event_generator():
        async for line in main.ffuf_client.scan_stream(host, wordlist):
            yield f"data: {line}\n\n"
            await asyncio.sleep(0.01)
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@router.get("/ffuf/results")
async def get_ffuf_results(
    host:     str = Query(...),
    wordlist: str = Query("/usr/share/dirb/wordlists/common.txt"),
    threads:  int = Query(40),
):
    try:
        results = await main.ffuf_client.scan_results_parsed(
            host,
            wordlist=wordlist,
            threads=threads
        )
        history_db.save_scan("ffuf", host, f"wordlist={wordlist.split('/')[-1]}", "completed", results)
        return results
    except Exception as e:
        history_db.save_scan("ffuf", host, f"wordlist={wordlist.split('/')[-1]}", "failed", {"error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/ffuf")
@router.post("/ffuf/scan")
async def run_ffuf_scan(req: FfufScanRequest):
    try:
        results = await main.ffuf_client.scan_results_parsed(
            req.host,
            wordlist=req.wordlist or "/usr/share/dirb/wordlists/common.txt",
            threads=req.threads or 40
        )
        history_db.save_scan("ffuf", req.host, "custom", "completed", results)
        return results
    except Exception as e:
        history_db.save_scan("ffuf", req.host, "custom", "failed", {"error": str(e)})
        raise HTTPException(status_code=500, detail=str(e))


# ── Scan History & Trends ──────────────────────────────────────────────────

@router.get("/history")
def get_history(tool: Optional[str] = Query(None), target: Optional[str] = Query(None)):
    """Fetch all logged scan runs (light summary format)."""
    return history_db.get_scan_history(tool=tool, target=target)

@router.get("/history/trends")
def get_trends():
    """Fetch scan count and finding aggregates grouped by tool and date."""
    return history_db.get_trends_data()

@router.get("/history/{scan_id}")
def get_history_detail(scan_id: int):
    """Fetch the full detail and raw results of a past scan."""
    record = history_db.get_scan_by_id(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found")
    return record

@router.delete("/history/{scan_id}")
def delete_history_record(scan_id: int):
    """Delete a scan run from history database."""
    success = history_db.delete_scan(scan_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to delete scan record")
    return {"status": "success", "message": f"Scan ID {scan_id} deleted"}


# ── Web Pen Testing Reports (ZAP, Nuclei, Nikto, Gobuster) ──────────────────

@router.post("/report/generate")
def generate_web_report(req: WebReportRequest):
    """
    Generates a Web Application VAPT Audit Report for ZAP, Nuclei, Nikto, or Gobuster.
    Supports formats: 'html', 'pdf', 'json'.
    """
    try:
        norm_data = WebReportGenerator.normalize_findings(
            tool=req.tool,
            results=req.results,
            target_url=req.target_url
        )
        
        fmt = (req.format or "html").lower()
        
        if fmt == "json":
            return {
                "status": "success",
                "normalized": norm_data,
                "html": WebReportGenerator.render_html_report(norm_data, req.metadata)
            }
        elif fmt == "pdf":
            pdf_bytes = WebReportGenerator.generate_pdf_report(norm_data, req.metadata)
            filename = f"vapt-report-{req.tool.lower()}-{datetime_str()}.pdf"
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "Access-Control-Expose-Headers": "Content-Disposition"
                }
            )
        else:
            # HTML
            html_content = WebReportGenerator.render_html_report(norm_data, req.metadata)
            filename = f"vapt-report-{req.tool.lower()}-{datetime_str()}.html"
            return Response(
                content=html_content.encode("utf-8"),
                media_type="text/html",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "Access-Control-Expose-Headers": "Content-Disposition"
                }
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")

@router.get("/history/{scan_id}/report")
def download_history_report(
    scan_id: int,
    fmt: str = Query("html", description="html, pdf, or json"),
    doc_title: Optional[str] = Query(None),
    company: Optional[str] = Query(None),
    auditor: Optional[str] = Query(None),
):
    record = history_db.get_scan_by_id(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found")
    
    tool = record.get("tool", "")
    target = record.get("target", "")
    raw_results = record.get("results")
    
    tool_title = "Network Infrastructure Audit" if tool.lower() == "nmap" else "Web Application VAPT"
    metadata = {
        "report_date": record.get("timestamp", "").split(" ")[0] if record.get("timestamp") else None,
        "doc_title": doc_title or f"{tool_title} Report - {tool.upper()}",
        "organization": company or "Wyzmindz Solutions",
        "prepared_by": auditor or "Santhosh M (Network Admin)",
        "reviewed_by": "Leo Antony Charles (IT Manager)",
        "approved_by": "Leo Antony Charles (IT Manager)"
    }
    
    try:
        norm_data = WebReportGenerator.normalize_findings(
            tool=tool,
            results=raw_results,
            target_url=target
        )
        
        fmt_clean = fmt.lower()
        if fmt_clean == "pdf":
            pdf_bytes = WebReportGenerator.generate_pdf_report(norm_data, metadata)
            filename = f"vapt-{tool.lower()}-scan-{scan_id}.pdf"
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "Access-Control-Expose-Headers": "Content-Disposition"
                }
            )
        elif fmt_clean == "json":
            return {
                "status": "success",
                "scan_id": scan_id,
                "normalized": norm_data,
                "html": WebReportGenerator.render_html_report(norm_data, metadata)
            }
        else:
            html_content = WebReportGenerator.render_html_report(norm_data, metadata)
            filename = f"vapt-{tool.lower()}-scan-{scan_id}.html"
            return Response(
                content=html_content.encode("utf-8"),
                media_type="text/html",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "Access-Control-Expose-Headers": "Content-Disposition"
                }
            )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to render history report: {str(e)}")

def datetime_str():
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
