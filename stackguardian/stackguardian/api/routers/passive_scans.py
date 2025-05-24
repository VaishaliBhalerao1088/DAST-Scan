from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from celery.result import AsyncResult

from stackguardian.stackguardian.core.database import get_db
from stackguardian.stackguardian.schemas.scan import ScanTarget
from stackguardian.stackguardian.models.user import User
from stackguardian.stackguardian.api.deps import get_current_user
from stackguardian.stackguardian.tasks.scan_tasks import run_ssl_tls_scan_task, run_http_headers_scan_task
from stackguardian.stackguardian.tasks.celery_worker import celery_app
# TaskStatus will be created in the next step, importing it here for now
from stackguardian.stackguardian.schemas.task import TaskStatus

router = APIRouter()

@router.post("/scan/ssl_tls", response_model=TaskStatus, status_code=status.HTTP_202_ACCEPTED)
async def start_ssl_tls_scan(target: ScanTarget, current_user: User = Depends(get_current_user)):
    # Ensure URL is passed as a string to the Celery task
    task = run_ssl_tls_scan_task.delay(str(target.url))
    return {"task_id": task.id, "status": task.status}

@router.post("/scan/http_headers", response_model=TaskStatus, status_code=status.HTTP_202_ACCEPTED)
async def start_http_headers_scan(target: ScanTarget, current_user: User = Depends(get_current_user)):
    # Ensure URL is passed as a string to the Celery task
    task = run_http_headers_scan_task.delay(str(target.url))
    return {"task_id": task.id, "status": task.status}

@router.get("/scan/result/{task_id}", response_model=TaskStatus)
async def get_scan_result(task_id: str, current_user: User = Depends(get_current_user)):
    task_result = AsyncResult(task_id, app=celery_app)
    result = None
    status_val = task_result.status

    if task_result.ready():
        if task_result.successful():
            result = task_result.get()
            status_val = "SUCCESS"
        else:
            # Handle failure, task_result.info might be an exception
            error_info = task_result.info
            if isinstance(error_info, Exception):
                result = {"error": str(error_info)}
            else:
                result = {"error": "Task failed", "info": error_info}
            status_val = "FAILURE"
    
    return {"task_id": task_id, "status": status_val, "result": result}
