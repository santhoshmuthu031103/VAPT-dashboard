import asyncio
from fastapi import APIRouter, Query, HTTPException, Request
from fastapi.responses import StreamingResponse

# The clients will be initialized in main.py and attached to the app state, 
# or we can import them directly if they are globally available.
# We will import the global instances from main.py
import main

router = APIRouter(prefix="/scanners", tags=["scanners"])

@router.get("/nuclei/stream")
async def stream_nuclei(host: str = Query(..., description="Target Host")):
    async def event_generator():
        async for line in main.nuclei_client.scan_stream(host):
            yield f"data: {line}\n\n"
            await asyncio.sleep(0.01)
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@router.get("/nuclei/results")
async def get_nuclei_results(host: str = Query(...)):
    try:
        return await main.nuclei_client.scan_results_parsed(host)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/nikto/stream")
async def stream_nikto(host: str = Query(...)):
    async def event_generator():
        async for line in main.nikto_client.scan_stream(host):
            yield f"data: {line}\n\n"
            await asyncio.sleep(0.01)
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@router.get("/gobuster/stream")
async def stream_gobuster(host: str = Query(...)):
    async def event_generator():
        async for line in main.gobuster_client.scan_stream(host):
            yield f"data: {line}\n\n"
            await asyncio.sleep(0.01)
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@router.get("/zap/results")
async def get_zap_results(host: str = Query(...)):
    try:
        return await main.zap_client.scan_results_parsed(host)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
