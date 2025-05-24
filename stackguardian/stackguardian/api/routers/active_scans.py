from fastapi import APIRouter, Depends, HTTPException, status
from celery.result import AsyncResult

from stackguardian.stackguardian.models.user import User
from stackguardian.stackguardian.api.deps import get_current_user
from stackguardian.stackguardian.tasks.scan_tasks import run_zap_scan_task, run_nuclei_scan_task
from stackguardian.stackguardian.tasks.celery_worker import celery_app
from stackguardian.stackguardian.schemas.task import TaskStatus
from stackguardian.stackguardian.schemas.active_scan import ZapScanConfig, NucleiScanConfig

router = APIRouter()

@router.post("/scan/zap", response_model=TaskStatus, status_code=status.HTTP_202_ACCEPTED)
async def start_zap_scan(config: ZapScanConfig, current_user: User = Depends(get_current_user)):
    task = run_zap_scan_task.delay(config.model_dump())
    return {"task_id": task.id, "status": task.status}

@router.post("/scan/nuclei", response_model=TaskStatus, status_code=status.HTTP_202_ACCEPTED)
async def start_nuclei_scan(config: NucleiScanConfig, current_user: User = Depends(get_current_user)):
    task = run_nuclei_scan_task.delay(config.model_dump())
    return {"task_id": task.id, "status": task.status}

@router.get("/scan/result/{task_id}", response_model=TaskStatus)
async def get_active_scan_result(task_id: str, current_user: User = Depends(get_current_user)):
    task_result = AsyncResult(task_id, app=celery_app)
    if task_result.ready():
        if task_result.successful():
            result_data = task_result.get()
            # Ensure result_data is serializable, it should be a dict from model_dump()
            return {"task_id": task_id, "status": "SUCCESS", "result": result_data}
        else:
            # Handle task failure - result.info might be an exception object or a dict
            error_info = task_result.info
            if isinstance(error_info, Exception):
                # Attempt to get traceback if available, otherwise None
                tb = getattr(error_info, "__traceback__", None)
                error_info = {"error": str(error_info), "traceback": str(tb)} # Basic serialization
            elif not isinstance(error_info, dict) : # if it's not a dict from our tasks' error return
                error_info = {"error": "Task failed with non-dictionary info", "details": str(error_info)}
            return {"task_id": task_id, "status": "FAILURE", "result": error_info}
    else:
        return {"task_id": task_id, "status": task_result.status, "result": None}
