import enum
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, Enum as SQLAlchemyEnum, ForeignKey
from stackguardian.stackguardian.core.database import Base
# Import User if you decide to link ScanRun to users directly by ORM relationship,
# for ForeignKey("users.id") as a string, direct import is not strictly necessary here.
# from stackguardian.stackguardian.models.user import User 

class ScanType(str, enum.Enum):
    SSL_TLS = "ssl_tls"
    HTTP_HEADERS = "http_headers"
    ZAP = "zap"
    NUCLEI = "nuclei"
    # Add other scan types as needed

class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    STARTED = "STARTED"
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"

class ScanRun(Base):
    __tablename__ = "scan_runs"
    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(String, unique=True, index=True, nullable=False) # Celery task ID
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True) # Optional: link to user who initiated
    scan_type = Column(SQLAlchemyEnum(ScanType), nullable=False)
    target = Column(String, nullable=False) # e.g., URL, IP
    status = Column(SQLAlchemyEnum(ScanStatus), nullable=False, default=ScanStatus.PENDING)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    # Raw configuration used for this scan run
    scan_config = Column(JSON, nullable=True) 
    # Summary of findings, could be counts by severity
    summary = Column(JSON, nullable=True) 

class SeverityLevel(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    UNKNOWN = "UNKNOWN"

class VulnerabilityFinding(Base):
    __tablename__ = "vulnerability_findings"
    id = Column(Integer, primary_key=True, index=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    
    name = Column(String, nullable=False)
    severity = Column(SQLAlchemyEnum(SeverityLevel), nullable=False)
    description = Column(Text, nullable=True)
    cwe = Column(String, nullable=True) # CWE IDs can be like CWE-79
    url_found = Column(Text, nullable=True) # URL where finding was discovered
    parameter = Column(Text, nullable=True) # Parameter involved, if any
    evidence = Column(Text, nullable=True)
    solution = Column(Text, nullable=True) # Or remediation
    
    # Tool-specific raw details, helps in not losing any info
    raw_details = Column(JSON, nullable=True) 
    
    first_seen_at = Column(DateTime, default=datetime.utcnow)
    last_seen_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    # status (e.g., new, confirmed, false_positive, resolved) - can be added later
