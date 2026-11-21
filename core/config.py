"""Configuration settings for VERITAS-X Digital Forensics Platform."""
from pathlib import Path
from pydantic import BaseModel
import os

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
VAULT_DIR = DATA_DIR / "vault"
DATABASE_DIR = DATA_DIR / "db"
REPORTS_DIR = DATA_DIR / "reports"
PLAYBOOKS_DIR = BASE_DIR / "playbooks" / "scenarios"

# Ensure runtime directories exist
for directory in [DATA_DIR, VAULT_DIR, DATABASE_DIR, REPORTS_DIR, PLAYBOOKS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

class Settings(BaseModel):
    app_name: str = "VERITAS-X"
    app_version: str = "1.0.0"
    environment: str = os.getenv("VERITAS_ENV", "local")
    host: str = os.getenv("VERITAS_HOST", "127.0.0.1")
    port: int = int(os.getenv("VERITAS_PORT", "8000"))
    opensearch_url: str = os.getenv("OPENSEARCH_URL", "http://127.0.0.1:9200")
    opensearch_user: str = os.getenv("OPENSEARCH_USER", "admin")
    opensearch_password: str = os.getenv("OPENSEARCH_PASSWORD", "VeritasX_2026_Secure!")
    database_url: str = os.getenv("DATABASE_URL", f"sqlite:///{DATABASE_DIR}/veritas.db")
    vault_path: Path = VAULT_DIR
    reports_path: Path = REPORTS_DIR
    playbooks_path: Path = PLAYBOOKS_DIR
    enable_ai: bool = os.getenv("VERITAS_ENABLE_AI", "false").lower() in ("true", "1")
    ai_provider: str = os.getenv("VERITAS_AI_PROVIDER", "none")

settings = Settings()
