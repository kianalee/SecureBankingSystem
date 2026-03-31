"""Lazy Firebase initialization shared by the bank server and gateway."""

from __future__ import annotations

from dataclasses import dataclass
import threading
from typing import Any, Dict, List

from .config import get_firebase_service_account_path, get_firebase_web_api_key

try:
    import firebase_admin
    from firebase_admin import auth, credentials, firestore
except ImportError:  # pragma: no cover - environment dependent
    firebase_admin = None
    auth = None
    credentials = None
    firestore = None


@dataclass
class FirebaseContext:
    auth: Any
    db: Any
    firestore: Any
    web_api_key: str


_firebase_lock = threading.Lock()
_firebase_context: FirebaseContext | None = None


def get_firebase_context() -> FirebaseContext:
    global _firebase_context

    if _firebase_context is not None:
        return _firebase_context

    if firebase_admin is None or auth is None or credentials is None or firestore is None:
        raise RuntimeError(
            "firebase_admin is not installed. Install the Python dependencies before starting the server."
        )

    web_api_key = get_firebase_web_api_key()
    service_account_path = get_firebase_service_account_path()

    if not web_api_key:
        raise RuntimeError("FIREBASE_WEB_API_KEY is required.")
    if not service_account_path:
        raise RuntimeError("FIREBASE_SERVICE_ACCOUNT_PATH is required.")

    with _firebase_lock:
        if _firebase_context is not None:
            return _firebase_context

        if not firebase_admin._apps:
            cred = credentials.Certificate(service_account_path)
            firebase_admin.initialize_app(cred)

        _firebase_context = FirebaseContext(
            auth=auth,
            db=firestore.client(),
            firestore=firestore,
            web_api_key=web_api_key,
        )
        return _firebase_context


def is_firebase_available() -> bool:
    try:
        get_firebase_context()
        return True
    except Exception:
        return False


def fetch_audit_logs(limit: int = 20) -> Dict[str, Any]:
    try:
        context = get_firebase_context()
        documents = (
            context.db.collection("auditLogs")
            .order_by("time", direction=context.firestore.Query.DESCENDING)
            .limit(limit)
            .stream()
        )

        logs: List[Dict[str, Any]] = []
        for document in documents:
            item = document.to_dict()
            timestamp = item.get("time")
            logs.append(
                {
                    "id": document.id,
                    "userID": item.get("userID"),
                    "email": item.get("email"),
                    "action": item.get("action"),
                    "time": timestamp.isoformat() if timestamp else None,
                }
            )

        return {"available": True, "message": "ok", "logs": logs}
    except Exception as exc:
        return {"available": False, "message": str(exc), "logs": []}
