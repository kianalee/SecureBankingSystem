from secure_banking.protocol import ATMProtocolClient
from secure_banking.session_store import GatewaySession, SessionStore


def test_session_store_upsert_get_delete_cycle():
    store = SessionStore()
    session = GatewaySession(
        session_id="session-1",
        client=ATMProtocolClient(),
        created_at="2026-03-25T12:00:00+00:00",
        last_seen_at="2026-03-25T12:00:00+00:00",
    )

    store.upsert(session)
    loaded = store.get("session-1")
    assert loaded is session
    assert len(store.list()) == 1

    removed = store.delete("session-1")
    assert removed is session
    assert store.get("session-1") is None
