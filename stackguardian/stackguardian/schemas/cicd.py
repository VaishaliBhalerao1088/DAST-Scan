from pydantic import BaseModel, HttpUrl, Field
from typing import Optional, Dict, Any, Union
from stackguardian.stackguardian.models.scan_results import ScanType, SeverityLevel # For ScanType and SeverityLevel enums
from stackguardian.stackguardian.schemas.scan import ScanTarget # For passive
from stackguardian.stackguardian.schemas.active_scan import ZapScanConfig, NucleiScanConfig # For active
from stackguardian.stackguardian.schemas.task import TaskStatus # Base TaskStatus

class CICDScanTriggerRequest(BaseModel):
    scan_type: ScanType
    target_url: HttpUrl # Common for most scans
    # Specific configs - only one should be provided based on scan_type
    zap_config: Optional[ZapScanConfig] = None 
    nuclei_config: Optional[NucleiScanConfig] = None
    # Passive scans usually just need target_url, which is already there.
    # Add other common options if needed, e.g., fail_on_severity: Optional[SeverityLevel] = None

class CICDTaskStatus(TaskStatus): # Inherits from existing TaskStatus
    # Could add more CI/CD specific fields if needed in the future
    pass

# Schema for fetching results with potential blocking/filtering logic
class CICDScanResultRequest(BaseModel):
    task_id: str
    fail_on_severity: Optional[SeverityLevel] = None # e.g., "HIGH" - pipeline fails if >= HIGH found
    minimum_alert_level: Optional[SeverityLevel] = None # Only return alerts of this level or higher
