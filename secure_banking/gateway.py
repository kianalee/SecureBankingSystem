"""FastAPI gateway that bridges browser sessions to the socket ATM protocol."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import socket
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .config import (
    get_admin_panel_password,
    get_bank_server_host,
    get_bank_server_port,
    get_frontend_dist_path,
    get_frontend_origins,
    get_gateway_session_secret,
)
from .firebase_support import fetch_audit_logs
from .protocol import ATMProtocolClient
from .session_store import GatewaySession, SessionStore, utcnow_iso


COOKIE_NAME = "securebank_sid"
ADMIN_COOKIE_NAME = "securebank_admin"
store = SessionStore()
SESSION_SIGNING_KEY = get_gateway_session_secret()
FRONTEND_DIST_PATH = get_frontend_dist_path()
ADMIN_COOKIE_VALUE = "admin"


def api_response(status: str, message: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {"status": status, "message": message, "data": data or {}}


def sign_value(value: str) -> str:
    signature = hmac.new(
        SESSION_SIGNING_KEY.encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return "{}.{}".format(value, signature)


def sign_session_id(session_id: str) -> str:
    return sign_value(session_id)


def parse_signed_value(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None

    value, _, signature = raw.partition(".")
    if not value or not signature:
        return None

    expected_signature = sign_value(value).partition(".")[2]
    if not hmac.compare_digest(signature, expected_signature):
        return None

    return value


def get_explicit_session_id(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization") or request.headers.get("Authorization")
    if auth and auth.lower().startswith("bearer "):
        return parse_signed_value(auth[7:].strip())

    raw = request.headers.get("x-session") or request.headers.get("x-securebank-sid")
    return parse_signed_value(raw)


def get_session_id(request: Request) -> Optional[str]:
    # ATM sessions intentionally prefer explicit per-tab headers.
    explicit_session_id = get_explicit_session_id(request)
    if explicit_session_id:
        return explicit_session_id

    # Cookie fallback is kept only for backwards compatibility with old builds.
    return parse_signed_value(request.cookies.get(COOKIE_NAME))


def get_optional_session(request: Request) -> Optional[GatewaySession]:
    session_id = get_session_id(request)
    if not session_id:
        return None

    session = store.get(session_id)
    if session is None:
        return None

    session.touch()
    return session


def require_session(request: Request) -> GatewaySession:
    session = get_optional_session(request)
    if session is None:
        raise HTTPException(status_code=401, detail="No active ATM session. Connect first.")
    return session


def is_admin_authenticated(request: Request) -> bool:
    return parse_signed_value(request.cookies.get(ADMIN_COOKIE_NAME)) == ADMIN_COOKIE_VALUE


def require_admin(request: Request) -> None:
    if not is_admin_authenticated(request):
        raise HTTPException(status_code=401, detail="Admin login required.")


def guest_session_payload() -> Dict[str, Any]:
    return {
        "clientId": None,
        "connected": False,
        "authenticated": False,
        "authenticatedEmail": None,
        "authenticatedUid": None,
        "phase": "disconnected",
        "lastAction": None,
        "connectedAt": None,
        "lastActivityAt": None,
        "protocolEvents": [],
        "protocolSummary": {
            "secureChannel": False,
            "phase1Complete": False,
            "phase2Complete": False,
        },
    }


def close_session(session_id: str) -> None:
    session = store.delete(session_id)
    if session is not None:
        session.client.close(send_exit=True)


def check_bank_server_health() -> Dict[str, Any]:
    host = get_bank_server_host()
    port = get_bank_server_port()
    try:
        with socket.create_connection((host, port), timeout=1.5):
            return {"reachable": True, "host": host, "port": port, "message": "Bank server reachable"}
    except OSError as exc:
        return {"reachable": False, "host": host, "port": port, "message": str(exc)}


class ConnectRequest(BaseModel):
    clientId: str = Field(..., min_length=1, max_length=100)


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=120)
    email: str = Field(..., min_length=3, max_length=240)
    password: str = Field(..., min_length=6, max_length=240)


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=240)
    password: str = Field(..., min_length=6, max_length=240)


class AmountRequest(BaseModel):
    amount: float


class AdminLoginRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=240)


app = FastAPI(
    title="SecureBankingSystem Gateway",
    description="Browser-facing gateway for the socket-based ATM banking protocol.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_frontend_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(HTTPException)
async def http_exception_handler(_: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=api_response("error", str(exc.detail), {}),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(_: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content=api_response("error", str(exc), {}),
    )


@app.get("/health")
async def healthcheck() -> Dict[str, Any]:
    return api_response("ok", "Gateway healthy", {"time": utcnow_iso()})


@app.post("/api/session/connect")
async def connect_session(payload: ConnectRequest, request: Request, response: Response) -> Dict[str, Any]:
    existing_session_id = get_explicit_session_id(request)
    if existing_session_id:
        close_session(existing_session_id)

    session_id = secrets.token_urlsafe(24)
    client = ATMProtocolClient()
    status = client.connect(payload.clientId)
    session = GatewaySession(
        session_id=session_id,
        client=client,
        created_at=utcnow_iso(),
        last_seen_at=utcnow_iso(),
    )
    store.upsert(session)

    signed = sign_session_id(session_id)
    # ATM sessions use the explicit session token returned in the JSON response.
    # Clear any legacy cookie so multiple localhost ports or tabs cannot clobber each other.
    response.delete_cookie(COOKIE_NAME)

    return api_response(
        "ok",
        "Secure ATM session established.",
        {
            "session": session.public_state(),
            "sessionToken": signed,
            "phase": status["phase"],
            "protocolSummary": status["protocolSummary"],
            "protocolEvents": status["protocolEvents"],
        },
    )


@app.get("/api/session/status")
async def session_status(request: Request) -> Dict[str, Any]:
    session = require_session(request)
    return api_response("ok", "Session status retrieved.", session.client.status_payload())


@app.get("/api/session/peek")
async def session_peek(request: Request) -> Dict[str, Any]:
    session = get_optional_session(request)
    payload = session.client.status_payload() if session is not None else guest_session_payload()
    return api_response("ok", "Session snapshot retrieved.", payload)


@app.post("/api/auth/register")
async def register(payload: RegisterRequest, request: Request) -> Dict[str, Any]:
    session = require_session(request)
    result = session.client.register(payload.username, payload.email, payload.password)
    return api_response(result.get("status", "ok"), result.get("msg", "Registration processed."), result)


@app.post("/api/auth/login")
async def login(payload: LoginRequest, request: Request) -> Dict[str, Any]:
    session = require_session(request)
    result = session.client.login(payload.email, payload.password)
    return api_response(result.get("status", "ok"), result.get("msg", "Login processed."), result)


@app.post("/api/auth/logout")
async def logout(request: Request) -> Dict[str, Any]:
    session = require_session(request)
    result = session.client.logout()
    return api_response(result.get("status", "ok"), result.get("msg", "Logout processed."), result)


@app.get("/api/account/balance")
async def balance(request: Request, silent: bool = False) -> Dict[str, Any]:
    session = require_session(request)
    result = session.client.balance(record_activity=not silent)
    return api_response(result.get("status", "ok"), result.get("msg", "Balance retrieved."), result)


@app.post("/api/account/deposit")
async def deposit(payload: AmountRequest, request: Request) -> Dict[str, Any]:
    if payload.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be greater than 0.")

    session = require_session(request)
    result = session.client.deposit(payload.amount)
    return api_response(result.get("status", "ok"), result.get("msg", "Deposit processed."), result)


@app.post("/api/account/withdraw")
async def withdraw(payload: AmountRequest, request: Request) -> Dict[str, Any]:
    if payload.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be greater than 0.")

    session = require_session(request)
    result = session.client.withdraw(payload.amount)
    return api_response(result.get("status", "ok"), result.get("msg", "Withdrawal processed."), result)


@app.get("/api/admin/active-sessions")
async def active_sessions(request: Request) -> Dict[str, Any]:
    require_admin(request)
    sessions = [session.public_state() for session in store.list()]
    return api_response(
        "ok",
        "Active session snapshot retrieved.",
        {"count": len(sessions), "sessions": sessions},
    )


@app.get("/api/admin/audit-logs")
async def audit_logs(request: Request, limit: int = 20) -> Dict[str, Any]:
    require_admin(request)
    result = fetch_audit_logs(limit=max(1, min(limit, 50)))
    message = "Audit logs retrieved." if result["available"] else result["message"]
    return api_response(
        "ok" if result["available"] else "error",
        message,
        {"available": result["available"], "logs": result["logs"]},
    )


@app.get("/api/admin/overview")
async def admin_overview(request: Request) -> Dict[str, Any]:
    require_admin(request)
    health = check_bank_server_health()
    sessions = [session.public_state() for session in store.list()]
    logs = fetch_audit_logs(limit=10)
    return api_response(
        "ok",
        "Admin overview retrieved.",
        {
            "server": health,
            "sessions": {"count": len(sessions), "items": sessions},
            "audit": {
                "available": logs["available"],
                "message": logs["message"],
                "items": logs["logs"],
                "path": logs.get("path"),
            },
        },
    )


@app.get("/api/admin/auth/status")
async def admin_auth_status(request: Request) -> Dict[str, Any]:
    return api_response(
        "ok",
        "Admin auth status retrieved.",
        {
            "authenticated": is_admin_authenticated(request),
            "configured": bool(get_admin_panel_password()),
        },
    )


@app.post("/api/admin/auth/login")
async def admin_auth_login(payload: AdminLoginRequest, response: Response) -> Dict[str, Any]:
    expected_password = get_admin_panel_password()
    if not expected_password:
        raise HTTPException(status_code=503, detail="ADMIN_PANEL_PASSWORD is not configured.")

    if not hmac.compare_digest(payload.password, expected_password):
        raise HTTPException(status_code=401, detail="Incorrect admin password.")

    response.set_cookie(
        key=ADMIN_COOKIE_NAME,
        value=sign_value(ADMIN_COOKIE_VALUE),
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=60 * 60 * 8,
    )
    return api_response("ok", "Admin access granted.", {"authenticated": True})


@app.post("/api/admin/auth/logout")
async def admin_auth_logout(response: Response) -> Dict[str, Any]:
    response.delete_cookie(ADMIN_COOKIE_NAME)
    return api_response("ok", "Admin signed out.", {"authenticated": False})


@app.delete("/api/session")
async def disconnect_session(request: Request, response: Response) -> Dict[str, Any]:
    session_id = get_session_id(request)
    if session_id:
        close_session(session_id)
    response.delete_cookie(COOKIE_NAME)
    return api_response("ok", "ATM session closed.", {})


if FRONTEND_DIST_PATH.exists():
    assets_dir = FRONTEND_DIST_PATH / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/", include_in_schema=False)
    @app.get("/app", include_in_schema=False)
    @app.get("/admin", include_in_schema=False)
    async def serve_frontend_shell() -> FileResponse:
        return FileResponse(FRONTEND_DIST_PATH / "index.html")
else:

    @app.get("/", include_in_schema=False)
    async def frontend_not_built() -> Dict[str, Any]:
        return api_response(
            "ok",
            "Gateway running. Build the frontend or run the Vite dev server to view the GUI.",
            {
                "frontendDistPath": str(FRONTEND_DIST_PATH),
                "suggestedCommand": "cd frontend && npm run build",
            },
        )
