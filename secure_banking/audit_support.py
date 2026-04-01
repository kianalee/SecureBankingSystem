"""Local audit log helpers."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from .config import get_audit_log_path


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def append_audit_log_entry(uid: str, email: str, action: str) -> None:
    path = get_audit_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "time": utcnow_iso(),
        "userID": uid,
        "email": email,
        "action": action,
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


def read_audit_log_entries(limit: int = 20) -> Dict[str, Any]:
    path = get_audit_log_path()
    if not path.exists():
        return {
            "available": True,
            "message": "ok",
            "path": str(path),
            "logs": [],
        }

    with path.open("r", encoding="utf-8") as handle:
        lines = [line.strip() for line in handle.readlines() if line.strip()]

    logs: List[Dict[str, Any]] = []
    for line in reversed(lines[-limit:]):
        try:
            logs.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return {
        "available": True,
        "message": "ok",
        "path": str(path),
        "logs": logs,
    }
