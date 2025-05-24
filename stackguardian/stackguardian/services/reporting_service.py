from sqlalchemy.orm import Session
from sqlalchemy import func, case
from typing import Optional, List, Dict, Any
from datetime import datetime

from stackguardian.stackguardian.models.scan_results import (
    ScanRun, 
    VulnerabilityFinding, 
    SeverityLevel, 
    ScanType, 
    ScanStatus
)
from stackguardian.stackguardian.models.user import User # For type hinting if needed, not strictly for query building here


def get_recent_scan_runs(db: Session, user_id: Optional[int] = None, limit: int = 10) -> List[ScanRun]:
    query = db.query(ScanRun).order_by(ScanRun.created_at.desc())
    if user_id:
        query = query.filter(ScanRun.user_id == user_id)
    return query.limit(limit).all()

def get_vulnerability_summary_by_target(db: Session, target: str, user_id: Optional[int] = None) -> Dict[str, Any]:
    # Counts vulnerabilities by severity for a specific target across all its successful scans
    query = (
        db.query(
            VulnerabilityFinding.severity,
            func.count(VulnerabilityFinding.id).label("count"),
        )
        .join(ScanRun, VulnerabilityFinding.scan_run_id == ScanRun.id)
        .filter(ScanRun.target == target)
        .filter(ScanRun.status == ScanStatus.SUCCESS) # Only count from successful scans
    )
    if user_id: # If scans are user-specific and user is not admin
        query = query.filter(ScanRun.user_id == user_id)
    
    query = query.group_by(VulnerabilityFinding.severity).all()

    summary = {level.value: 0 for level in SeverityLevel} # Initialize all severities to 0
    for severity_enum, count in query: # severity_enum is the actual enum object
        if severity_enum: # Ensure severity is not None
            summary[severity_enum.value] = count 
    
    # Get latest scan run for this target to show last scanned date
    latest_scan_query = (
        db.query(ScanRun.updated_at)
        .filter(ScanRun.target == target)
        .filter(ScanRun.status == ScanStatus.SUCCESS)
    )
    if user_id:
        latest_scan_query = latest_scan_query.filter(ScanRun.user_id == user_id)
    
    latest_scan_date_result = latest_scan_query.order_by(ScanRun.updated_at.desc()).first()

    return {
        "target": target,
        "severity_counts": summary,
        "last_scanned": latest_scan_date_result[0] if latest_scan_date_result else None,
    }

def get_overall_vulnerability_summary(db: Session, user_id: Optional[int] = None) -> Dict[str, int]:
    # Counts all vulnerabilities by severity across all targets and successful scans
    query = db.query(
        VulnerabilityFinding.severity,
        func.count(VulnerabilityFinding.id).label("count"),
    ).join(ScanRun, VulnerabilityFinding.scan_run_id == ScanRun.id).filter(ScanRun.status == ScanStatus.SUCCESS)

    if user_id: # Optional: if results should be filtered by user
         query = query.filter(ScanRun.user_id == user_id)
    
    results = query.group_by(VulnerabilityFinding.severity).all()
    
    summary = {level.value: 0 for level in SeverityLevel}
    for severity_enum, count in results: # severity_enum is the actual enum object
        if severity_enum:
            summary[severity_enum.value] = count
    return summary

def list_vulnerabilities(
    db: Session,
    user_id: Optional[int] = None,
    target: Optional[str] = None,
    min_severity: Optional[SeverityLevel] = None,
    scan_type: Optional[ScanType] = None,
    is_resolved: Optional[bool] = None, # Placeholder for future status field
    limit: int = 100,
    offset: int = 0,
) -> List[VulnerabilityFinding]:
    query = db.query(VulnerabilityFinding).join(ScanRun, VulnerabilityFinding.scan_run_id == ScanRun.id)

    if user_id:
        query = query.filter(ScanRun.user_id == user_id)
    if target:
        query = query.filter(ScanRun.target.ilike(f"%{target}%")) # Case-insensitive search
    if scan_type:
        query = query.filter(ScanRun.scan_type == scan_type)
    
    # Severity filtering: if min_severity is HIGH, include HIGH and CRITICAL
    if min_severity:
        severity_order = [SeverityLevel.INFORMATIONAL, SeverityLevel.UNKNOWN, SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        if min_severity in severity_order:
            min_severity_index = severity_order.index(min_severity)
            inclusive_severities = [s for s in severity_order if severity_order.index(s) >= min_severity_index]
            query = query.filter(VulnerabilityFinding.severity.in_(inclusive_severities))

    # Placeholder for resolved status, requires a status field on VulnerabilityFinding
    # if is_resolved is not None:
    #     query = query.filter(VulnerabilityFinding.status == ("resolved" if is_resolved else "active"))

    query = query.order_by(
        # Order by severity (Critical first), then by last_seen_at
        case(
            [
                (VulnerabilityFinding.severity == SeverityLevel.CRITICAL, 0),
                (VulnerabilityFinding.severity == SeverityLevel.HIGH, 1),
                (VulnerabilityFinding.severity == SeverityLevel.MEDIUM, 2),
                (VulnerabilityFinding.severity == SeverityLevel.LOW, 3),
                (VulnerabilityFinding.severity == SeverityLevel.INFORMATIONAL, 4),
                (VulnerabilityFinding.severity == SeverityLevel.UNKNOWN, 5),
            ],
            else_=6 # Default for any other unexpected values
        ),
        VulnerabilityFinding.last_seen_at.desc()
    )
    
    return query.limit(limit).offset(offset).all()
