from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any

from stackguardian.stackguardian.core.database import get_db
from stackguardian.stackguardian.models.user import User, UserRole # UserRole needed for future filtering logic
from stackguardian.stackguardian.models.scan_results import SeverityLevel, ScanType # Enums for query params
from stackguardian.stackguardian.services.reporting_service import (
    get_recent_scan_runs,
    get_vulnerability_summary_by_target,
    get_overall_vulnerability_summary,
    list_vulnerabilities,
)
from stackguardian.stackguardian.api.deps import get_current_user
from stackguardian.stackguardian.schemas.report import (
    ReportScanRun,
    ReportVulnerabilityFinding,
    VulnerabilitySummary,
)

router = APIRouter()

@router.get("/scans/recent", response_model=List[ReportScanRun])
async def get_recent_scans_api(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user), # Use current_user for auth, can filter by user_id if not admin etc.
    limit: int = Query(10, ge=1, le=100)
):
    # Add logic here if only admins can see all scans, or users see their own
    # user_id_filter = current_user.id if current_user.role != UserRole.ADMIN else None 
    # For now, assuming get_current_user just ensures authentication
    return get_recent_scan_runs(db=db, user_id=None, limit=limit) # Pass current_user.id if needed

@router.get("/summary/overall", response_model=VulnerabilitySummary)
async def get_overall_summary_api(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # user_id_filter = current_user.id if current_user.role != UserRole.ADMIN else None
    summary_data = get_overall_vulnerability_summary(db=db, user_id=None)
    # The service function already returns a dict with keys matching VulnerabilitySummary fields
    # if they are named {'HIGH': count, ...}.
    # Let's adjust the VulnerabilitySummary schema or the service output for direct compatibility.
    # Assuming get_overall_vulnerability_summary returns Dict[SeverityLevel.value, int]
    # And VulnerabilitySummary expects Dict[SeverityLevel, int]
    # Pydantic should handle enum key conversion if types match.
    
    # If get_overall_vulnerability_summary returns Dict[str, int] where str is SeverityLevel.value
    # and VulnerabilitySummary expects Dict[SeverityLevel, int], Pydantic handles it.
    return VulnerabilitySummary(severity_counts=summary_data)


@router.get("/summary/target/{target_name:path}", response_model=VulnerabilitySummary) # Use path parameter for target
async def get_target_summary_api(
    target_name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # user_id_filter = current_user.id if current_user.role != UserRole.ADMIN else None
    summary_data = get_vulnerability_summary_by_target(db=db, target=target_name, user_id=None)
    if not summary_data["last_scanned"] and not any(summary_data["severity_counts"].values()):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No scan data found for this target")
    return VulnerabilitySummary(**summary_data) # summary_data from service matches VulnerabilitySummary fields

@router.get("/vulnerabilities", response_model=List[ReportVulnerabilityFinding])
async def list_vulnerabilities_api(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    target: Optional[str] = Query(None),
    min_severity: Optional[SeverityLevel] = Query(None), # FastAPI handles enum conversion from query param
    scan_type: Optional[ScanType] = Query(None),       # FastAPI handles enum conversion
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0)
):
    # user_id_filter = current_user.id if current_user.role != UserRole.ADMIN else None
    return list_vulnerabilities(
        db=db, user_id=None, target=target, min_severity=min_severity,
        scan_type=scan_type, limit=limit, offset=offset
    )
