from pydantic import BaseModel
from typing import Optional, Any

class TaskStatus(BaseModel):
    task_id: str
    status: str  # e.g., PENDING, STARTED, SUCCESS, FAILURE
    result: Optional[Any] = None
