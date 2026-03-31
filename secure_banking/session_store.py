"""In-memory session registry for the web gateway."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import threading
from typing import Dict, List, Optional

from .protocol import ATMProtocolClient


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class GatewaySession:
    session_id: str
    client: ATMProtocolClient
    created_at: str
    last_seen_at: str

    def touch(self) -> None:
        self.last_seen_at = utcnow_iso()

    def public_state(self) -> Dict[str, object]:
        status = self.client.status_payload()
        return {
            "sessionId": self.session_id,
            "clientId": status.get("clientId"),
            "connected": status.get("connected"),
            "authenticated": status.get("authenticated"),
            "authenticatedEmail": status.get("authenticatedEmail"),
            "phase": status.get("phase"),
            "lastAction": status.get("lastAction"),
            "createdAt": self.created_at,
            "lastSeenAt": self.last_seen_at,
            "connectedAt": status.get("connectedAt"),
            "lastActivityAt": status.get("lastActivityAt"),
        }


class SessionStore:
    def __init__(self) -> None:
        self._sessions: Dict[str, GatewaySession] = {}
        self._lock = threading.Lock()

    def upsert(self, session: GatewaySession) -> GatewaySession:
        with self._lock:
            self._sessions[session.session_id] = session
            return session

    def get(self, session_id: str) -> Optional[GatewaySession]:
        with self._lock:
            return self._sessions.get(session_id)

    def delete(self, session_id: str) -> Optional[GatewaySession]:
        with self._lock:
            return self._sessions.pop(session_id, None)

    def list(self) -> List[GatewaySession]:
        with self._lock:
            return list(self._sessions.values())
