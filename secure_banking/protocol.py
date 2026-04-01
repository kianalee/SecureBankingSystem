"""Reusable client implementation for the socket-based banking protocol."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import random
import socket
import struct
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import get_bank_server_host, get_bank_server_port


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def send_msg(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_msg(sock: socket.socket) -> bytes:
    length = struct.unpack(">I", _recv_exact(sock, 4))[0]
    return _recv_exact(sock, length)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    buffer = b""
    while len(buffer) < size:
        chunk = sock.recv(size - len(buffer))
        if not chunk:
            raise ConnectionError("Socket closed unexpectedly")
        buffer += chunk
    return buffer


def send_utf(sock: socket.socket, value: str) -> None:
    send_msg(sock, value.encode("utf-8"))


def recv_utf(sock: socket.socket) -> str:
    return recv_msg(sock).decode("utf-8")


def rsa_encrypt_raw(pub_key: RSA.RsaKey, plaintext: bytes) -> bytes:
    key_size = (pub_key.n.bit_length() + 7) // 8
    padded = plaintext.rjust(key_size, b"\x00")
    encrypted = pow(int.from_bytes(padded, "big"), pub_key.e, pub_key.n)
    return encrypted.to_bytes(key_size, "big")


def rsa_decrypt_raw(priv_key: RSA.RsaKey, ciphertext: bytes) -> bytes:
    key_size = (priv_key.n.bit_length() + 7) // 8
    decrypted = pow(int.from_bytes(ciphertext, "big"), priv_key.d, priv_key.n)
    return decrypted.to_bytes(key_size, "big").lstrip(b"\x00")


def derive_aes_key(master_key: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"atm-master-aes-key",
    ).derive(master_key.encode("utf-8"))


def derive_phase2_keys(master_key: str) -> tuple[bytes, bytes]:
    master_bytes = master_key.encode("utf-8")

    enc_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"atm-encryption-key",
    ).derive(master_bytes)

    mac_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"atm-mac-key",
    ).derive(master_bytes)

    return enc_key, mac_key


def aes_encrypt(key: bytes, plaintext: str) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    return cipher.iv + ciphertext


def aes_decrypt(key: bytes, ciphertext: bytes) -> str:
    iv = ciphertext[:16]
    payload = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(payload), AES.block_size).decode("utf-8")


def send_secure_utf(sock: socket.socket, enc_key: bytes, mac_key: bytes, obj: Dict[str, Any]) -> None:
    plaintext = json.dumps(obj)
    ciphertext = aes_encrypt(enc_key, plaintext)
    tag = hmac_sha256(mac_key, ciphertext)
    packet = {
        "ct": base64.b64encode(ciphertext).decode("utf-8"),
        "tag": base64.b64encode(tag).decode("utf-8"),
    }
    send_utf(sock, json.dumps(packet))


def recv_secure_utf(sock: socket.socket, enc_key: bytes, mac_key: bytes) -> Dict[str, Any]:
    packet = json.loads(recv_utf(sock))
    ciphertext = base64.b64decode(packet["ct"])
    tag = base64.b64decode(packet["tag"])
    expected_tag = hmac_sha256(mac_key, ciphertext)
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("MAC verification failed")
    plaintext = aes_decrypt(enc_key, ciphertext)
    return json.loads(plaintext)


@dataclass
class ProtocolEvent:
    timestamp: str
    phase: str
    title: str
    detail: str


class ATMProtocolClient:
    def __init__(self, host: Optional[str] = None, port: Optional[int] = None, timeout: int = 10):
        self.host = host or get_bank_server_host()
        self.port = port or get_bank_server_port()
        self.timeout = timeout
        self.client_id: Optional[str] = None
        self.sock: Optional[socket.socket] = None
        self.enc_key: Optional[bytes] = None
        self.mac_key: Optional[bytes] = None
        self.master_key: Optional[str] = None
        self.connected_at: Optional[str] = None
        self.last_activity_at: Optional[str] = None
        self.last_action: Optional[str] = None
        self.current_phase = "disconnected"
        self.authenticated = False
        self.authenticated_email: Optional[str] = None
        self.authenticated_uid: Optional[str] = None
        self._events: List[ProtocolEvent] = []
        self._lock = threading.RLock()

    def _record(self, phase: str, title: str, detail: str) -> None:
        self.current_phase = phase
        self.last_activity_at = utcnow_iso()
        self._events.append(
            ProtocolEvent(
                timestamp=self.last_activity_at,
                phase=phase,
                title=title,
                detail=detail,
            )
        )
        self._events = self._events[-12:]

    def _assert_connected(self) -> socket.socket:
        if self.sock is None or self.enc_key is None or self.mac_key is None:
            raise RuntimeError("ATM session is not connected.")
        return self.sock

    def _send_command_locked(self, payload: Dict[str, Any], *, record_last_action: bool = True) -> Dict[str, Any]:
        sock = self._assert_connected()
        send_secure_utf(sock, self.enc_key, self.mac_key, payload)
        response = recv_secure_utf(sock, self.enc_key, self.mac_key)
        if record_last_action:
            self.last_action = payload.get("cmd", "").upper()
            self.last_activity_at = utcnow_iso()
        return response

    def connect(self, client_id: str) -> Dict[str, Any]:
        with self._lock:
            if self.sock is not None:
                self.close(send_exit=True)

            client_id = client_id.strip()
            if not client_id:
                raise ValueError("clientId is required.")

            self.client_id = client_id
            self.authenticated = False
            self.authenticated_email = None
            self.authenticated_uid = None
            self._events = []
            self._record("phase1", "Connecting", f"Opening secure channel to {self.host}:{self.port}.")

            key_pair = RSA.generate(2048)
            public_key = key_pair.publickey()

            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            sock.settimeout(self.timeout)
            self.sock = sock
            self.connected_at = utcnow_iso()

            send_msg(sock, public_key.export_key(format="DER"))
            self._record("phase1", "Public key sent", "ATM public key delivered to the bank server.")

            bank_pub_bytes = recv_msg(sock)
            bank_pub_key = RSA.import_key(bank_pub_bytes)
            self._record("phase1", "Bank key received", "Received the bank server RSA public key.")

            send_utf(sock, client_id)

            message1_b64 = recv_utf(sock)
            message1 = rsa_decrypt_raw(key_pair, base64.b64decode(message1_b64))
            nonce_bundle = message1.decode("utf-8", errors="replace").replace("\x00", "").strip()
            parts = nonce_bundle.split("||")
            nonce_k = parts[0]

            initials = "".join(word[0] for word in client_id.split() if word)
            my_nonce = "N{}{}".format(initials or "ATM", random.randint(0, 999))
            message2 = rsa_encrypt_raw(bank_pub_key, "{}||{}".format(my_nonce, nonce_k).encode("utf-8"))
            send_utf(sock, base64.b64encode(message2).decode("utf-8"))
            self._record("phase1", "Mutual authentication", "Nonce challenge returned to the bank server.")

            message3_b64 = recv_utf(sock)
            message3 = rsa_decrypt_raw(key_pair, base64.b64decode(message3_b64))
            nonce_check = message3.decode("utf-8", errors="replace").replace("\x00", "").strip()
            if nonce_k not in nonce_check:
                raise RuntimeError("Nonce verification failed during phase 1.")

            message4_b64 = recv_utf(sock)
            master_key_bytes = rsa_decrypt_raw(key_pair, base64.b64decode(message4_b64))
            self.master_key = master_key_bytes.decode("utf-8", errors="replace").replace("\x00", "").strip()
            self._record("phase1", "Master key issued", "Phase 1 completed and master key delivered.")

            send_utf(sock, client_id)
            enc_payload_b64 = recv_utf(sock)
            aes_key = derive_aes_key(self.master_key)
            decrypted = aes_decrypt(aes_key, base64.b64decode(enc_payload_b64))
            enc_key_hex, mac_key_hex = decrypted.split("||", 1)
            self.enc_key = bytes.fromhex(enc_key_hex)
            self.mac_key = bytes.fromhex(mac_key_hex)

            expected_enc_key, expected_mac_key = derive_phase2_keys(self.master_key)
            if self.enc_key != expected_enc_key or self.mac_key != expected_mac_key:
                raise RuntimeError("Derived phase 2 keys do not match the bank server payload.")

            self._record("phase2", "Secure session ready", "Encryption and MAC keys established for ATM commands.")
            return self.status_payload()

    def register(self, username: str, email: str, password: str) -> Dict[str, Any]:
        with self._lock:
            response = self._send_command_locked(
                {
                    "cmd": "REGISTER",
                    "username": username.strip(),
                    "email": email.strip(),
                    "password": password,
                }
            )
            self._record("phase3", "Registration attempted", response.get("msg", ""))
            return response

    def login(self, email: str, password: str) -> Dict[str, Any]:
        with self._lock:
            response = self._send_command_locked(
                {
                    "cmd": "LOGIN",
                    "email": email.strip(),
                    "password": password,
                }
            )
            if response.get("status") == "ok":
                self.authenticated = True
                self.authenticated_email = email.strip()
                self.authenticated_uid = response.get("uid")
            self._record("phase3", "Login attempted", response.get("msg", ""))
            return response

    def logout(self) -> Dict[str, Any]:
        with self._lock:
            response = self._send_command_locked({"cmd": "LOGOUT"})
            if response.get("status") == "ok":
                self.authenticated = False
                self.authenticated_email = None
                self.authenticated_uid = None
            self._record("phase3", "Logout", response.get("msg", ""))
            return response

    def balance(self, record_activity: bool = True) -> Dict[str, Any]:
        with self._lock:
            response = self._send_command_locked({"cmd": "BALANCE"}, record_last_action=record_activity)
            if record_activity:
                self._record("phase3", "Balance inquiry", "Latest balance retrieved from the bank server.")
            return response

    def deposit(self, amount: float) -> Dict[str, Any]:
        with self._lock:
            response = self._send_command_locked({"cmd": "DEPOSIT", "amount": amount})
            message = response.get("msg") or "Deposit processed."
            self._record("phase3", "Deposit", message)
            return response

    def withdraw(self, amount: float) -> Dict[str, Any]:
        with self._lock:
            response = self._send_command_locked({"cmd": "WITHDRAW", "amount": amount})
            message = response.get("msg") or "Withdrawal processed."
            self._record("phase3", "Withdrawal", message)
            return response

    def close(self, send_exit: bool = True) -> None:
        with self._lock:
            sock = self.sock
            if sock is not None and send_exit and self.enc_key is not None and self.mac_key is not None:
                try:
                    self._send_command_locked({"cmd": "EXIT"})
                except Exception:
                    pass

            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

            self.sock = None
            self.enc_key = None
            self.mac_key = None
            self.master_key = None
            self.authenticated = False
            self.authenticated_email = None
            self.authenticated_uid = None
            self.current_phase = "disconnected"
            self.last_action = "EXIT" if send_exit else self.last_action
            self._record("disconnected", "Session closed", "ATM session disconnected from the bank server.")

    def status_payload(self) -> Dict[str, Any]:
        return {
            "clientId": self.client_id,
            "connected": self.sock is not None,
            "authenticated": self.authenticated,
            "authenticatedEmail": self.authenticated_email,
            "authenticatedUid": self.authenticated_uid,
            "phase": self.current_phase,
            "lastAction": self.last_action,
            "connectedAt": self.connected_at,
            "lastActivityAt": self.last_activity_at,
            "protocolEvents": [asdict(item) for item in self._events],
            "protocolSummary": {
                "secureChannel": self.sock is not None and self.enc_key is not None and self.mac_key is not None,
                "phase1Complete": self.master_key is not None,
                "phase2Complete": self.enc_key is not None and self.mac_key is not None,
            },
        }
