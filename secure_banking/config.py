"""Configuration helpers for the banking server and web gateway."""

from __future__ import annotations

import os
from pathlib import Path
from typing import List

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DOTENV_PATH = PROJECT_ROOT / ".env"
load_dotenv(DOTENV_PATH)


def get_project_root() -> Path:
    return PROJECT_ROOT


def get_bank_server_host() -> str:
    return os.getenv("BANK_SERVER_HOST", "localhost")


def get_bank_server_port() -> int:
    return int(os.getenv("BANK_SERVER_PORT", "1234"))


def get_firebase_web_api_key() -> str:
    return os.getenv("FIREBASE_WEB_API_KEY", "").strip()


def get_firebase_service_account_path() -> str:
    return os.getenv("FIREBASE_SERVICE_ACCOUNT_PATH", "").strip()


def get_gateway_session_secret() -> str:
    return os.getenv("GATEWAY_SESSION_SECRET", "local-dev-session-secret")


def get_frontend_origins() -> List[str]:
    raw = os.getenv("FRONTEND_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def get_gateway_host() -> str:
    return os.getenv("GATEWAY_HOST", "127.0.0.1")


def get_gateway_port() -> int:
    return int(os.getenv("GATEWAY_PORT", "8000"))


def get_frontend_dev_host() -> str:
    return os.getenv("FRONTEND_DEV_HOST", "127.0.0.1")


def get_frontend_dev_port() -> int:
    return int(os.getenv("FRONTEND_DEV_PORT", "5173"))


def get_frontend_dist_path() -> Path:
    return PROJECT_ROOT / "frontend" / "dist"


def get_admin_panel_password() -> str:
    return os.getenv("ADMIN_PANEL_PASSWORD", "").strip()


def get_audit_log_path() -> Path:
    raw = os.getenv("AUDIT_LOG_PATH", "").strip()
    if raw:
        return Path(raw).expanduser()
    return PROJECT_ROOT / "audit.log"
