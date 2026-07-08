from pydantic_settings import BaseSettings
from typing import Optional
import sys
from pathlib import Path


class Settings(BaseSettings):
    # App
    APP_NAME: str = "Kraken"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    SECRET_KEY: str = "changeme_super_secret_key_please_change"
    INTERNAL_API_KEY: str = "changeme_internal_api_key_please_change"

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://kraken:kraken_pass@localhost:5432/krakendb"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_PASSWORD: Optional[str] = None

    # JWT
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_EXPIRE_MINUTES: int = 60 * 24 * 7
    JWT_ISSUER: str = "kraken"

    # Docker sandbox
    SANDBOX_IMAGE: str = "kraken_sandbox"
    SANDBOX_MAX_LIFETIME: int = 300
    SANDBOX_NETWORK: str = "kraken_sandbox_net"
    SANDBOX_MAX_CONCURRENT: int = 20

    # Paths — configurabili
    DATA_DIR: str = "/app/data"
    MALWARE_DIR: str = "/app/data/malware"
    LOGS_DIR: str = "/app/data/logs"
    SIEM_LOG_FILE: str = "/app/data/logs/siem.jsonl"
    GEOIP_DB_PATH: str = "/app/data/GeoLite2-City.mmdb"

    # Telegram
    TELEGRAM_BOT_TOKEN: Optional[str] = None
    TELEGRAM_CHAT_ID: Optional[str] = None

    # Sensors
    SSH_SENSOR_PORT: int = 2222
    HTTP_SENSOR_PORT: int = 8080
    FTP_SENSOR_PORT: int = 2121
    TELNET_SENSOR_PORT: int = 2323

    # Rate limiting
    RATE_LIMIT_LOGIN: str = "10/minute"
    RATE_LIMIT_INGEST: str = "200/minute"
    RATE_LIMIT_DEFAULT: str = "60/minute"
    RATE_LIMIT_EXPORT: str = "30/minute"

    # CORS — comma-separated origins, e.g. "https://mydomain.com,https://other.com"
    CORS_ORIGINS: str = "http://localhost:8000"

    # Body limit
    MAX_BODY_SIZE: int = 65_536

    # Sandbox API (sensors -> app via HTTP instead of Docker socket)
    SANDBOX_API_URL: str = "http://kraken_app:8000/api/v1/containers"

    # Security
    BCRYPT_ROUNDS: int = 12

    class Config:
        env_file = ".env"
        case_sensitive = True

    def validate_secrets(self):
        """Refuse to start in production with default secrets."""
        defaults = {
            "changeme_super_secret_key_please_change",
            "changeme_internal_api_key_please_change",
        }
        if not self.DEBUG:
            if self.SECRET_KEY in defaults or len(self.SECRET_KEY) < 32:
                print("❌ SECRET_KEY is insecure. Set a random value of 32+ chars in .env")
                sys.exit(1)
            if self.INTERNAL_API_KEY in defaults or len(self.INTERNAL_API_KEY) < 32:
                print("❌ INTERNAL_API_KEY is insecure. Set a random value of 32+ chars in .env")
                sys.exit(1)

    def get_cors_origins(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    def ensure_dirs(self):
        Path(self.DATA_DIR).mkdir(parents=True, exist_ok=True)
        Path(self.MALWARE_DIR).mkdir(parents=True, exist_ok=True)
        Path(self.LOGS_DIR).mkdir(parents=True, exist_ok=True)


settings = Settings()
