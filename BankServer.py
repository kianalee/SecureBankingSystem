"""
BankServer.py — Bank Server (BS) (RSA + Simulated Symmetric Encryption)
=========================================================================

Security Protocol
-----------------
Phase 1 — Mutual Authentication & Master Key Distribution (per client)
  1.  ATM  → Server : ATM RSA public key
  2.  Server → ATM  : Server RSA public key
  3.  ATM  → Server : client ID
  4.  Server → ATM  : Message 1  E(PU_ATM,  [NK1 || ID_BS])
  5.  ATM  → Server : Message 2  E(PU_BS,  [N_ATM || N_BS1])
  6.  Server → ATM  : Message 3  E(PU_ATM,  N_BS1)
  7.  Server → ATM  : Message 4  E(PU_ATM,  E(PR_BS, MasterKey))

Phase 2 — Session Key Distribution
  - The first ATM to send IDA + IDB triggers KAB generation.
  - Server sends E(KA, [KAB || IDB]) to the requesting ATM.
  - Server sends E(KB, [KAB || IDA]) to the other ATM via its stored socket.

Usage:
    python BankServer.py
"""

import socket
import threading
import random
import base64
import struct

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import json
import hashlib
import hmac

# ── Configuration ──────────────────────────────────────────────────────────────
HOST = "localhost"
PORT = 1234
ID_K = "KDCServer"

# ── Shared state (protected by state_lock) ─────────────────────────────────────
state_lock  = threading.Condition()
master_keys: dict[str, str]           = {}   # clientID → master key string
client_outs: dict[str, socket.socket] = {}   # clientID → socket
users_db: dict[str, dict] = {}   # username -> {"password_hash": str, "balance": float}
users_lock = threading.Lock()

# Send and receive utf helpers using encryption and mac keys -------------------
def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def send_secure_utf(sock: socket.socket, enc_key: bytes, mac_key: bytes, obj: dict) -> None:
    plaintext = json.dumps(obj)
    ciphertext = aes_encrypt(enc_key, plaintext)   # returns bytes
    tag = hmac_sha256(mac_key, ciphertext)

    packet = {
        "ct": base64.b64encode(ciphertext).decode("utf-8"),
        "tag": base64.b64encode(tag).decode("utf-8")
    }
    send_utf(sock, json.dumps(packet))

def recv_secure_utf(sock: socket.socket, enc_key: bytes, mac_key: bytes) -> dict:
    packet = json.loads(recv_utf(sock))

    ciphertext = base64.b64decode(packet["ct"])
    tag = base64.b64decode(packet["tag"])

    expected_tag = hmac_sha256(mac_key, ciphertext)
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("MAC verification failed")

    plaintext = aes_decrypt(enc_key, ciphertext)   # returns str
    return json.loads(plaintext)

# ── Socket framing ─────────────────────────────────────────────────────────────

def send_msg(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack(">I", len(data)) + data)

def recv_msg(sock: socket.socket) -> bytes:
    length = struct.unpack(">I", _recv_exact(sock, 4))[0]
    return _recv_exact(sock, length)

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed unexpectedly")
        buf += chunk
    return buf

def send_utf(sock: socket.socket, s: str) -> None:
    send_msg(sock, s.encode("utf-8"))

def recv_utf(sock: socket.socket) -> str:
    return recv_msg(sock).decode("utf-8")


# ── RSA raw (NoPadding) — mirrors Java RSA/ECB/NoPadding ──────────────────────

def rsa_encrypt_raw(pub_key: RSA.RsaKey, plaintext: bytes) -> bytes:
    k      = (pub_key.n.bit_length() + 7) // 8
    padded = plaintext.rjust(k, b'\x00')
    c      = pow(int.from_bytes(padded, 'big'), pub_key.e, pub_key.n)
    return c.to_bytes(k, 'big')

def rsa_decrypt_raw(priv_key: RSA.RsaKey, ciphertext: bytes) -> bytes:
    k = (priv_key.n.bit_length() + 7) // 8
    m = pow(int.from_bytes(ciphertext, 'big'), priv_key.d, priv_key.n)
    return m.to_bytes(k, 'big').lstrip(b'\x00')


# ── AES symmetric encryption ────────────────────────────────────────────

def aes_encrypt(key: bytes, plaintext: str) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC)
    ct = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return cipher.iv + ct

def aes_decrypt(key: bytes, ciphertext: bytes) -> str:
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()

# ── Deriving AES key from master key ────────────────────────────────────────────
def derive_aes_key(master_key: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"atm-master-aes-key",
    ).derive(master_key.encode("utf-8"))

# ── HKDF to derive Encryption and MAC keys ────────────────────────────────────────────

def derive_keys(master_key: str) -> tuple[bytes, bytes]:
    """
    Derive an AES encryption key and a MAC key from the master key
    using HKDF-SHA256.
    Returns (enc_key, mac_key) — both 32 bytes (256-bit).
    """
    master_bytes = master_key.encode("utf-8")

    # Derive encryption key
    enc_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,                    
        info=b"atm-encryption-key",   # context label — keeps keys domain-separated
    ).derive(master_bytes)

    # Derive MAC key
    mac_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"atm-mac-key",          # different label = completely different key
    ).derive(master_bytes)

    return enc_key, mac_key

# Key Distribution Protocol (Phase 1 and 2)
def key_distribution(conn: socket.socket, kdc_pub: RSA.RsaKey, kdc_priv: RSA.RsaKey):
    # ── Step 1 : receive client RSA public key ────────────────────────────
        client_pub_bytes = recv_msg(conn)
        client_pub_key   = RSA.import_key(client_pub_bytes)

        # ── Step 2 : send KDC RSA public key ──────────────────────────────────
        send_msg(conn, kdc_pub.export_key(format="DER"))

        # ── Step 3 : receive client ID ────────────────────────────────────────
        client_id = recv_utf(conn)
        print(f"Client Hosted, ID: {client_id}\n")

        # ── Step 4 : Message 1 — E(PU_ATM, [NK1 || ID_KDC]) ──────────────────
        nonce_k    = f"NK{random.randint(0, 999)}"
        msg1_plain = f"{nonce_k}||{ID_K}".encode()
        msg1_enc   = rsa_encrypt_raw(client_pub_key, msg1_plain)
        send_utf(conn, base64.b64encode(msg1_enc).decode())

        # ── Step 5 : receive Message 2 — E(PU_KDC, [N_ATM || NK1]) ───────────
        msg2_b64  = recv_utf(conn)
        print(f"Received Message 2 (Encrypted) from {client_id}: {msg2_b64}\n")
        msg2_dec  = rsa_decrypt_raw(kdc_priv, base64.b64decode(msg2_b64))
        decrypted2 = msg2_dec.decode("utf-8", errors="replace").replace("\x00", "").strip()

        parts         = decrypted2.split("||")
        nonce_k_recvd = parts[1] if len(parts) > 1 else ""

        if nonce_k in decrypted2:
            print(f"Decrypted message 2 from {client_id} contains Nonce K.\n")
            print(f"Authentication Successful: {client_id} is verified!")
        else:
            print("Authentication Failed!")
            conn.close()
            return

        # ── Step 6 : Message 3 — E(PU_ATM, NK1) ──────────────────────────────
        msg3_enc = rsa_encrypt_raw(client_pub_key, nonce_k_recvd.encode())
        send_utf(conn, base64.b64encode(msg3_enc).decode())

        # ── Step 7 : Message 4 — E(PU_ATM, MasterKey)) ────────────
        master_key = f"MK{random.randint(0, 999)}"
        msg4_enc   = rsa_encrypt_raw(client_pub_key,  master_key.encode())
        send_utf(conn, base64.b64encode(msg4_enc).decode())

        # Store master key and output socket, notify waiting threads
        with state_lock:
            master_keys[client_id] = master_key
            client_outs[client_id] = conn
            state_lock.notify_all()

        print(f"[Phase 1] complete for {client_id}. Master Key = {master_key}\n")

        # ── Phase 2 ───────────────────────────────────────────────────────────
        print(f"=== Phase 2 Starting for {client_id} ===\n")

        # Receive ID from client
        rcv_idclient = recv_utf(conn)
        print(f"[Phase 2] KDC received client ID={rcv_idclient} from {client_id}\n")

        # Generate session key KAB
        enc_key, mac_key = derive_keys(master_key)

        # Send E(K_ATM, [EK || MAC]) to the requesting client
        aes_key = derive_aes_key(master_key)
        payload = f"{enc_key.hex()}||{mac_key.hex()}"
        enc_for_client = aes_encrypt(aes_key, payload)
        send_utf(conn, base64.b64encode(enc_for_client).decode())

        return enc_key, mac_key, client_id

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def process_phase3(conn: socket.socket, client_id: str, enc_key: bytes, mac_key: bytes) -> None:
    print(f"=== Phase 3 Starting for {client_id} ===\n")
    authenticated_user = None

    while True:
        try:
            req = recv_secure_utf(conn, enc_key, mac_key)
            cmd = req.get("cmd", "").upper()

            if cmd == "EXIT":
                send_secure_utf(conn, enc_key, mac_key, {
                    "status": "ok",
                    "msg": "Goodbye"
                })
                print(f"[Phase 3] {client_id} exited.")
                break

            elif cmd == "REGISTER":
                username = req.get("username", "").strip()
                password = req.get("password", "").strip()

                if not username or not password:
                    resp = {"status": "error", "msg": "Username/password cannot be empty"}
                else:
                    with users_lock:
                        if username in users_db:
                            resp = {"status": "error", "msg": "User already exists"}
                        else:
                            users_db[username] = {
                                "password_hash": hash_password(password),
                                "balance": 0.0
                            }
                            resp = {"status": "ok", "msg": "Registration successful"}

                send_secure_utf(conn, enc_key, mac_key, resp)

            elif cmd == "LOGIN":
                username = req.get("username", "").strip()
                password = req.get("password", "").strip()

                with users_lock:
                    if username not in users_db:
                        resp = {"status": "error", "msg": "Unknown user"}
                    elif not hmac.compare_digest(
                        users_db[username]["password_hash"],
                        hash_password(password)
                    ):
                        resp = {"status": "error", "msg": "Invalid credentials"}
                    else:
                        authenticated_user = username
                        resp = {"status": "ok", "msg": "Login successful"}

                send_secure_utf(conn, enc_key, mac_key, resp)
            elif cmd == "LOGOUT":
                authenticated_user = None
                send_secure_utf(conn, enc_key, mac_key, {
                    "status": "ok",
                    "msg": "Logged out successfully"
                })
            else:
                if authenticated_user is None:
                    send_secure_utf(conn, enc_key, mac_key, {
                        "status": "error",
                        "msg": "Please log in first"
                    })
                    continue

                with users_lock:
                    balance = users_db[authenticated_user]["balance"]

                    if cmd == "BALANCE":
                        resp = {"status": "ok", "balance": balance}

                    elif cmd == "DEPOSIT":
                        amount = float(req.get("amount", 0))
                        if amount <= 0:
                            resp = {"status": "error", "msg": "Amount must be positive"}
                        else:
                            users_db[authenticated_user]["balance"] += amount
                            resp = {
                                "status": "ok",
                                "balance": users_db[authenticated_user]["balance"]
                            }
                            print(f"[TX] {authenticated_user} deposited ${amount:.2f}")

                    elif cmd == "WITHDRAW":
                        amount = float(req.get("amount", 0))
                        if amount <= 0:
                            resp = {"status": "error", "msg": "Amount must be positive"}
                        elif amount > balance:
                            resp = {"status": "error", "msg": "Insufficient funds"}
                        else:
                            users_db[authenticated_user]["balance"] -= amount
                            resp = {
                                "status": "ok",
                                "balance": users_db[authenticated_user]["balance"]
                            }
                            print(f"[TX] {authenticated_user} withdrew ${amount:.2f}")

                    else:
                        resp = {"status": "error", "msg": "Unknown command"}

                send_secure_utf(conn, enc_key, mac_key, resp)

        except Exception as e:
            print(f"[Phase 3] Error for {client_id}: {e}")
            break

# ── Client handler thread ──────────────────────────────────────────────────────

class ClientHandler(threading.Thread):
    def __init__(self, conn: socket.socket, addr, client_number: int, kp: RSA.RsaKey):
        super().__init__(daemon=True)
        self.conn          = conn
        self.addr          = addr
        self.client_number = client_number
        self.kp            = kp

    def run(self):
        try:
            self._handle()
        except Exception as e:
            print(f"[KDC] Error in handler for client #{self.client_number}: {e}")
        finally:
            self.conn.close()

    def _handle(self):
        conn     = self.conn
        kdc_pub  = self.kp.publickey()
        kdc_priv = self.kp

        enc_key, mac_key, client_id = key_distribution(conn, kdc_pub, kdc_priv)
        process_phase3(conn, client_id, enc_key, mac_key)

        


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    kp = RSA.generate(2048)
    print("KDC RSA-2048 key pair generated.")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(10)
    print(f"KDC Bank Server is up and running on {HOST}:{PORT}\n")

    client_number = 1
    try:
        while True:
            conn, addr = server_sock.accept()
            print(f"Client connected: {addr}")
            ClientHandler(conn, addr, client_number, kp).start()
            client_number += 1
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down.")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()