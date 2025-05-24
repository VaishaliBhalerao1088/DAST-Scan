from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "StackGuardian"
    SECRET_KEY: str = "d778c3434c0573659c43e754c624cf85dfa86ab8e412b424b3bc658892a818ca"  # Replace with your generated key
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    DATABASE_URL: str = "sqlite:///./stackguardian.db"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/0"
    ZAP_API_KEY: Optional[str] = None # Set your ZAP API key if required by your ZAP instance
    ZAP_BASE_URL: str = "http://localhost:8080" # Default ZAP API URL

    class Config:
        case_sensitive = True

settings = Settings()
