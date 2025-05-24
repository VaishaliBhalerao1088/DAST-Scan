from pydantic import BaseModel, HttpUrl
from typing import List, Optional, Dict, Any
from datetime import datetime
from stackguardian.stackguardian.models.scan_results import SeverityLevel, ScanType, ScanStatus # Import enums

# Schemas for ScanRun and VulnerabilityFinding for response consistency

class ReportScanRun(BaseModel): # Similar to models.ScanRun but for API output
    id: int
    task_id: str
    # user_id: Optional[int] # Decide if to expose user_id directly
    scan_type: ScanType
    target: str
    status: ScanStatus
    created_at: datetime
    updated_at: datetime
    summary: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True # Pydantic v2 (orm_mode for v1)

class ReportVulnerabilityFinding(BaseModel): # Similar to models.VulnerabilityFinding
    id: int
    scan_run_id: int
    name: str
    severity: SeverityLevel
    description: Optional[str] = None
    cwe: Optional[str] = None
    url_found: Optional[str] = None # Changed from HttpUrl to str for flexibility
    parameter: Optional[str] = None
    evidence: Optional[str] = None
    solution: Optional[str] = None
    raw_details: Optional[Dict[str, Any]] = None # Or just Any
    first_seen_at: datetime
    last_seen_at: datetime
    
    # We might want to include basic ScanRun info here too, or a nested ScanRun_light model
    # scan_run: Optional[ReportScanRun] # Example of nesting

    class Config:
        from_attributes = True

class VulnerabilitySummary(BaseModel):
    target: Optional[str] = None # Optional because overall summary won't have a single target
    severity_counts: Dict[SeverityLevel, int]
    last_scanned: Optional[datetime] = None
