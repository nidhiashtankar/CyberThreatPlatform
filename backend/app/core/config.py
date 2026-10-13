import os
from typing import List, Set
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "AI Cyber Threat Intelligence & Automated Response Platform"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "sqlite:///./cyber_threat_platform.db"
    )

    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]

    # Secret key
    SECRET_KEY: str = os.getenv("SECRET_KEY", "academic-prototype-cyber-threat-secret-2026")

    # Detection Thresholds
    LOGIN_FAILED_THRESHOLD: int = int(os.getenv("LOGIN_FAILED_THRESHOLD", "5"))
    LOGIN_WINDOW_SECONDS: int = int(os.getenv("LOGIN_WINDOW_SECONDS", "120"))
    
    PORT_SCAN_PORT_THRESHOLD: int = int(os.getenv("PORT_SCAN_PORT_THRESHOLD", "10"))
    PORT_SCAN_WINDOW_SECONDS: int = int(os.getenv("PORT_SCAN_WINDOW_SECONDS", "60"))
    
    CORRELATION_WINDOW_SECONDS: int = int(os.getenv("CORRELATION_WINDOW_SECONDS", "1800"))
    RISK_DECAY_HALF_LIFE_HOURS: float = float(os.getenv("RISK_DECAY_HALF_LIFE_HOURS", "24.0"))

    # Configured Honeytokens / Decoys
    HONEYTOKEN_IDENTIFIERS: Set[str] = {
        "HONEYTOKEN_AWS_DEV_KEY_9921",
        "decoy_admin_token_alpha",
        "svc_backup_decoy",
        "PROD_DB_SECRET_DECOY_X9",
        "fake_api_gateway_key_demo"
    }

    class Config:
        case_sensitive = True
        env_file = ".env"
        extra = "allow"


settings = Settings()
