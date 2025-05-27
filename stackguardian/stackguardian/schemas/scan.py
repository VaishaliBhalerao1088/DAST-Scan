from pydantic import BaseModel, HttpUrl
from typing import Optional

class ScanTarget(BaseModel):
    url: HttpUrl
    ip_address: Optional[str] = None
