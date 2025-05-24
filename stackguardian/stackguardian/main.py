from fastapi import FastAPI
from .core.config import settings
from .api.routers import (
    users as user_router, 
    passive_scans as passive_scan_router, 
    active_scans as active_scan_router,
    reports as reports_router,
    cicd as cicd_router # Import the new CI/CD router
)
from .core.database import Base, engine
# Ensure all models are imported so Base.metadata.create_all creates them
from .models import User, ScanRun, VulnerabilityFinding 

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title=settings.PROJECT_NAME)

@app.get("/")
async def root():
    return {"message": "Hello World"}

app.include_router(user_router.router, prefix=f"{settings.API_V1_STR}/users", tags=["users"])
app.include_router(passive_scan_router.router, prefix=f"{settings.API_V1_STR}/passive", tags=["passive_scans"])
app.include_router(active_scan_router.router, prefix=f"{settings.API_V1_STR}/active", tags=["active_scans"])
app.include_router(reports_router.router, prefix=f"{settings.API_V1_STR}/reports", tags=["reports"])
app.include_router(cicd_router.router, prefix=f"{settings.API_V1_STR}/cicd", tags=["cicd"]) # Include the CI/CD router
