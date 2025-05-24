from celery import Celery
from stackguardian.stackguardian.core.config import settings

# Initialize Celery
celery_app = Celery(
    "worker",  # Changed from "tasks" to "worker" as per instruction
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=['stackguardian.stackguardian.tasks.scan_tasks'] # Added for task discovery
)

# Configure Celery
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # Optional: Add other configurations as needed
)

# Auto-discover tasks
# The 'include' parameter in Celery constructor is now the preferred way.
# If you still want to use autodiscover_tasks, it would look like:
# celery_app.autodiscover_tasks(["stackguardian.stackguardian.tasks"])

if __name__ == "__main__":
    celery_app.start()
