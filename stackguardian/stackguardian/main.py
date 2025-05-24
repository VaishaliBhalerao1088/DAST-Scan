from fastapi import FastAPI
from .core.config import settings
from .api.routers import users as user_router, passive_scans as passive_scan_router
from .core.database import Base, engine
from .models import User # Ensure User model is imported for create_all

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title=settings.PROJECT_NAME)

@app.get("/")
async def root():
    return {"message": "Hello World"}

app.include_router(user_router.router, prefix=f"{settings.API_V1_STR}/users", tags=["users"])
app.include_router(passive_scan_router.router, prefix=f"{settings.API_V1_STR}/passive", tags=["passive_scans"])
