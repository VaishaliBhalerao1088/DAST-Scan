from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any

class ZapScanConfig(BaseModel):
    target_url: HttpUrl
    scan_type: str  # e.g., "baseline", "full", "api"
    context_id: Optional[str] = None
    api_definition_url: Optional[HttpUrl] = None
    other_options: Optional[Dict[str, Any]] = None

class NucleiScanConfig(BaseModel):
    target_url: HttpUrl # Or target: str if it can be more than just URLs
    templates: Optional[List[str]] = None
    severity: Optional[List[str]] = None # e.g., ["critical", "high"]
    other_options: Optional[Dict[str, Any]] = None

class ActiveScanResultItem(BaseModel):
    name: str
    severity: str  # e.g., "High", "Medium", "Low", "Informational"
    description: str
    cwe: Optional[int] = None
    url_found: Optional[str] = None
    parameter: Optional[str] = None
    evidence: Optional[str] = None
    solution: Optional[str] = None # Or remediation
    raw_details: Optional[Dict[str, Any]] = None # For tool-specific raw output

class ActiveScanReport(BaseModel):
    scan_tool: str  # e.g., "OWASP ZAP", "Nuclei"
    target: str
    summary: Dict[str, Any] # e.g., counts of vulnerabilities by severity
    vulnerabilities: List[ActiveScanResultItem]
