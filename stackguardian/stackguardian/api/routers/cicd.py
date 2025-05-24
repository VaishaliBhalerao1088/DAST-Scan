from fastapi import APIRouter, Depends, HTTPException, status, Body
from celery.result import AsyncResult

from stackguardian.stackguardian.models.user import User
from stackguardian.stackguardian.api.deps import get_current_user
from stackguardian.stackguardian.tasks.scan_tasks import (
    run_ssl_tls_scan_task, 
    run_http_headers_scan_task, 
    run_zap_scan_task, 
    run_nuclei_scan_task
)
from stackguardian.stackguardian.tasks.celery_worker import celery_app
from stackguardian.stackguardian.schemas.task import TaskStatus # Base TaskStatus
from stackguardian.stackguardian.schemas.scan import ScanTarget
from stackguardian.stackguardian.schemas.active_scan import ZapScanConfig, NucleiScanConfig, ActiveScanReport
from stackguardian.stackguardian.models.scan_results import ScanType, SeverityLevel
from stackguardian.stackguardian.schemas.cicd import CICDScanTriggerRequest, CICDTaskStatus, CICDScanResultRequest

router = APIRouter()

@router.post("/trigger_scan", response_model=CICDTaskStatus, status_code=status.HTTP_202_ACCEPTED)
async def trigger_scan_cicd(
    payload: CICDScanTriggerRequest, # Use the new request body
    current_user: User = Depends(get_current_user) # Standard auth
):
    task = None
    # Validate that the correct config is provided for the scan_type
    if payload.scan_type == ScanType.SSL_TLS:
        task = run_ssl_tls_scan_task.delay(str(payload.target_url))
    elif payload.scan_type == ScanType.HTTP_HEADERS:
        task = run_http_headers_scan_task.delay(str(payload.target_url))
    elif payload.scan_type == ScanType.ZAP:
        if not payload.zap_config:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="zap_config is required for ZAP scans")
        # Ensure target_url in zap_config matches common target_url or handle as needed
        if payload.zap_config.target_url != payload.target_url:
            # For now, let's assume zap_config.target_url is authoritative if provided
            # Or one might choose to enforce they are the same or use the one from zap_config
            # For this implementation, we will use the target_url from zap_config
            pass 
        task = run_zap_scan_task.delay(payload.zap_config.model_dump())
    elif payload.scan_type == ScanType.NUCLEI:
        if not payload.nuclei_config:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="nuclei_config is required for Nuclei scans")
        if payload.nuclei_config.target_url != payload.target_url:
             # Similar handling as ZAP, use the target_url from nuclei_config
            pass
        task = run_nuclei_scan_task.delay(payload.nuclei_config.model_dump())
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Unsupported scan_type: {payload.scan_type}")

    if not task: # Should not happen if previous logic is correct
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to initiate scan task.")

    return CICDTaskStatus(task_id=task.id, status=task.status, result=None)

@router.post("/fetch_results", response_model=CICDTaskStatus) # Changed to POST to accept a request body
async def fetch_scan_results_cicd(
    payload: CICDScanResultRequest, # Use the new request body
    current_user: User = Depends(get_current_user)
):
    task_id = payload.task_id
    task_result = AsyncResult(task_id, app=celery_app)

    if not task_result.ready():
        return CICDTaskStatus(task_id=task_id, status=task_result.status, result=None)

    if task_result.failed():
        error_info = task_result.info
        # Ensure error_info is a serializable dict
        if isinstance(error_info, Exception):
            tb_str = "".join(traceback.format_tb(error_info.__traceback__)) if hasattr(error_info, "__traceback__") else "No traceback available."
            error_info = {"error": str(error_info), "traceback": tb_str}
        elif not isinstance(error_info, dict): # If it's not an exception and not our dict format
            error_info = {"error": "Task failed with non-dictionary info", "details": str(error_info)}
        
        # For CI/CD, a failed scan task itself might be a pipeline failure condition
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
                            detail={"message": "Scan task failed", "task_id": task_id, "error_details": error_info})

    # Task successful
    scan_data = task_result.get() # This is a dict (from model_dump() in tasks or passive scan dict)

    # Apply fail_on_severity logic
    if payload.fail_on_severity and isinstance(scan_data, dict) and "vulnerabilities" in scan_data:
        severity_order = [SeverityLevel.INFORMATIONAL, SeverityLevel.UNKNOWN, SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        try:
            fail_severity_index = severity_order.index(payload.fail_on_severity)
        except ValueError: # Should not happen if SeverityLevel enum is used correctly
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid fail_on_severity value.")

        for vuln in scan_data.get("vulnerabilities", []):
            vuln_severity_str = vuln.get("severity", SeverityLevel.UNKNOWN.value)
            try:
                vuln_severity = SeverityLevel(vuln_severity_str.upper()) # Ensure case-insensitivity if coming from various tools
                if vuln_severity in severity_order and severity_order.index(vuln_severity) >= fail_severity_index:
                    raise HTTPException(
                        status_code=status.HTTP_412_PRECONDITION_FAILED,
                        detail={
                            "message": f"Scan failed severity policy: Found '{vuln.get('name')}' severity '{vuln_severity.value}' (threshold: {payload.fail_on_severity.value}).",
                            "task_id": task_id,
                            "scan_result_summary": scan_data.get("summary")
                        }
                    )
            except ValueError: # If vuln.get("severity") is not a valid SeverityLevel member
                # Log this anomaly, but don't necessarily fail the check for it unless desired
                print(f"Warning: Unknown severity '{vuln_severity_str}' found in vulnerability '{vuln.get('name')}' for task {task_id}.")
                pass 

    # Minimum alert level filtering - This should filter the 'vulnerabilities' list in scan_data
    if payload.minimum_alert_level and isinstance(scan_data, dict) and "vulnerabilities" in scan_data:
        severity_order = [SeverityLevel.INFORMATIONAL, SeverityLevel.UNKNOWN, SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        try:
            min_alert_level_index = severity_order.index(payload.minimum_alert_level)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid minimum_alert_level value.")

        filtered_vulnerabilities = []
        for vuln in scan_data.get("vulnerabilities", []):
            vuln_severity_str = vuln.get("severity", SeverityLevel.UNKNOWN.value)
            try:
                vuln_severity = SeverityLevel(vuln_severity_str.upper())
                if vuln_severity in severity_order and severity_order.index(vuln_severity) >= min_alert_level_index:
                    filtered_vulnerabilities.append(vuln)
            except ValueError:
                # If severity is unknown, decide whether to include it or not.
                # For now, we only include known severities that meet the threshold.
                pass 
        scan_data["vulnerabilities"] = filtered_vulnerabilities
        # Recalculate summary if filtering is applied? For now, summary remains original.

    return CICDTaskStatus(task_id=task_id, status="SUCCESS", result=scan_data)
