from fastapi import FastAPI, HTTPException, status
from fastapi.responses import HTMLResponse, PlainTextResponse
from celery.result import AsyncResult

from app.schemas import ScanRequest, ScanResponse, ScanStatusResponse
from app.celery_worker import celery_app, run_nmap_scan
from app.reporter import generate_html_report, generate_markdown_report, generate_diff_html_report
from app.diff_engine import compute_scan_diff
from app.database import engine, Base
from app import models

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Nmap Scanning & Threat Intelligence Service API",
    version="2.1.0",
    description="Asenkron Nmap keşif, optimize agresif analiz, hibrit CVE korelasyonu ve fark motoru."
    
)

@app.post("/scan", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
def start_scan(request: ScanRequest):
    task = run_nmap_scan.delay(target=str(request.target), profile=request.profile)
    return ScanResponse(task_id=task.id, status="ACCEPTED")

@app.get("/scan/{task_id}", response_model=ScanStatusResponse)
def get_scan_status(task_id: str):
    res = AsyncResult(task_id, app=celery_app)
    if res.state == "PROGRESS":
        return ScanStatusResponse(task_id=task_id, status="PROGRESS", result=res.info)
    elif res.state == "SUCCESS":
        return ScanStatusResponse(task_id=task_id, status="SUCCESS", result=res.result)
    elif res.state == "FAILURE":
        return ScanStatusResponse(task_id=task_id, status="FAILURE", result={"error": str(res.result)})
    return ScanStatusResponse(task_id=task_id, status=res.state, result=None)

@app.delete("/scan/{task_id}")
def cancel_scan(task_id: str):
    celery_app.control.revoke(task_id, terminate=True, signal="SIGTERM")
    return {"task_id": task_id, "status": "CANCELLED", "message": "Tarama görevi sonlandırıldı."}

@app.get("/scan/{task_id}/report/html", response_class=HTMLResponse)
def get_html_report(task_id: str):
    res = AsyncResult(task_id, app=celery_app)
    if res.state != "SUCCESS":
        raise HTTPException(status_code=400, detail="Rapor oluşturmak için tarama tamamlanmış olmalıdır.")
    return generate_html_report(res.result)

@app.get("/scan/{task_id}/report/md", response_class=PlainTextResponse)
def get_md_report(task_id: str):
    res = AsyncResult(task_id, app=celery_app)
    if res.state != "SUCCESS":
        raise HTTPException(status_code=400, detail="Rapor oluşturmak için tarama tamamlanmış olmalıdır.")
    return generate_markdown_report(res.result)

@app.get("/scan/{current_id}/diff/{previous_id}")
def get_scan_diff(current_id: str, previous_id: str):
    res_curr = AsyncResult(current_id, app=celery_app)
    res_prev = AsyncResult(previous_id, app=celery_app)

    if res_curr.state != "SUCCESS" or res_prev.state != "SUCCESS":
        raise HTTPException(status_code=400, detail="Fark analizi için her iki taramanın da tamamlanması gerekir.")

    curr_data = res_curr.result
    prev_data = res_prev.result

    if not isinstance(curr_data, dict) or not isinstance(prev_data, dict):
        raise HTTPException(status_code=400, detail="Tarama verileri geçerli değil.")

    curr_data["task_id"] = current_id
    prev_data["task_id"] = previous_id

    return compute_scan_diff(prev_data, curr_data)

@app.get("/scan/{current_id}/diff/{previous_id}/html", response_class=HTMLResponse)
def get_scan_diff_html(current_id: str, previous_id: str):
    diff_data = get_scan_diff(current_id=current_id, previous_id=previous_id)
    return generate_diff_html_report(diff_data)