"""
server.py — Multi-threaded Bank Server (RSA + AES Hybrid Encryption)
=====================================================================

Security Protocol
-----------------
  1. Server → ATM  : RSA-2048 public key (PEM)
  2. ATM   → Server: RSA-OAEP { uname | pw_hash | N_c }
                     Only server can decrypt → authenticates CUSTOMER
  3. Server verifies credentials, generates N_s, derives:
                     Master Secret = SHA-256(N_c || N_s)
  4. Server → ATM  : plaintext N_s  ||  HMAC(N_c, "server:" || N_s)
                     ATM already knows N_c, so it can verify the HMAC.
                     This proves the server decrypted step 2 (knows N_c)
                     → authenticates SERVER to ATM
  5. ATM verifies HMAC, derives same MS = SHA-256(N_c || N_s).
  6. All transactions: AES-256-CBC encrypted with Master Secret.
"""

import socket
import threading
import hashlib
import hmac as hmac_mod
import os
import json
import struct

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad

# ── Configuration ──────────────────────────────────────────────────────────────
HOST         = "127.0.0.1"
PORT         = 9999
RSA_KEY_FILE = "server_rsa.pem"
RSA_KEY_BITS = 2048

# ── In-memory user store  { username: { password_hash, balance } } ─────────────
users_lock = threading.Lock()
users: dict[str, dict] = {}


# ── RSA key management ─────────────────────────────────────────────────────────

def load_or_generate_rsa_key() -> RSA.RsaKey:
    if os.path.exists(RSA_KEY_FILE):
        with open(RSA_KEY_FILE, "rb") as f:
            key = RSA.import_key(f.read())
        print(f"[RSA] Loaded existing key from '{RSA_KEY_FILE}'")
    else:
        print(f"[RSA] Generating {RSA_KEY_BITS}-bit RSA key pair …")
        key = RSA.generate(RSA_KEY_BITS)
        with open(RSA_KEY_FILE, "wb") as f:
            f.write(key.export_key())
        print(f"[RSA] Key pair saved to '{RSA_KEY_FILE}'")
    return key


# ── Crypto helpers ─────────────────────────────────────────────────────────────

def rsa_decrypt(private_key: RSA.RsaKey, ciphertext: bytes) -> bytes:
    return PKCS1_OAEP.new(private_key).decrypt(ciphertext)


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac_mod.new(key, data, hashlib.sha256).digest()


def derive_master_secret(nc: bytes, ns: bytes) -> bytes:
    """MS = SHA-256(N_c || N_s)"""
    return hashlib.sha256(nc + ns).digest()


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    return iv + AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, AES.block_size))


def aes_decrypt(key: bytes, data: bytes) -> bytes:
    iv, ct = data[:16], data[16:]
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), AES.block_size)


# ── Length-prefixed socket framing ─────────────────────────────────────────────

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


# ── Mutual Authentication + Key Distribution Handshake ────────────────────────

def authenticate_client(
    conn: socket.socket,
    server_key: RSA.RsaKey
) -> tuple[str | None, bytes | None]:
    """
    Returns (username, master_secret) on success, (None, None) on failure.
    """
    # ── Step 1 : send RSA public key ─────────────────────────────────────────
    pub_pem = server_key.publickey().export_key()
    send_msg(conn, pub_pem)
    print("[AUTH] Sent RSA public key to ATM.")

    # ── Step 2 : receive RSA-OAEP { uname_len(2) | username | pw_hash(64) | N_c(32) }
    try:
        plaintext = rsa_decrypt(server_key, recv_msg(conn))
        uname_len = struct.unpack(">H", plaintext[:2])[0]
        off       = 2
        username  = plaintext[off: off + uname_len].decode()
        off      += uname_len
        pw_hash   = plaintext[off: off + 64].decode()
        off      += 64
        nc        = plaintext[off: off + 32]
    except Exception as e:
        print(f"[AUTH] Failed to parse client blob: {e}")
        send_msg(conn, b"AUTH_FAIL:parse_error")
        return None, None

    # ── Step 3 : verify credentials ──────────────────────────────────────────
    with users_lock:
        if username not in users:
            send_msg(conn, b"AUTH_FAIL:unknown_user")
            print(f"[AUTH] Unknown user '{username}'")
            return None, None
        stored_hash = users[username]["password_hash"]

    if not hmac_mod.compare_digest(stored_hash, pw_hash):
        send_msg(conn, b"AUTH_FAIL:bad_credentials")
        print(f"[AUTH] Bad credentials for '{username}'")
        return None, None

    # ── Step 4 : generate N_s, derive MS, prove server identity ──────────────
    #
    # Server proof = HMAC(N_c, "server:" || N_s)
    # The ATM can verify this because it knows N_c (it generated it).
    # A man-in-the-middle cannot forge this without knowing N_c, which
    # was RSA-encrypted and only the real server could have decrypted.
    #
    ns            = os.urandom(32)
    master_secret = derive_master_secret(nc, ns)
    server_proof  = hmac_sha256(nc, b"server:" + ns)   # 32 bytes

    # Send: N_s (32) || server_proof (32) — plaintext is fine because
    # proof is unforgeable without knowing N_c.
    send_msg(conn, ns + server_proof)

    print(f"[AUTH] ✓ Mutual auth OK for '{username}' | MS={master_secret[:8].hex()}…")
    return username, master_secret


# ── Encrypted Transaction Loop ─────────────────────────────────────────────────

def process_transactions(conn: socket.socket, username: str, ms: bytes) -> None:
    print(f"[TX] Session open for '{username}'")
    try:
        while True:
            request = json.loads(aes_decrypt(ms, recv_msg(conn)).decode())
            cmd     = request.get("cmd", "").upper()

            with users_lock:
                balance = users[username]["balance"]

                if cmd == "BALANCE":
                    resp = {"status": "ok", "balance": balance}

                elif cmd == "DEPOSIT":
                    amount = float(request.get("amount", 0))
                    if amount <= 0:
                        resp = {"status": "error", "msg": "Amount must be positive"}
                    else:
                        users[username]["balance"] += amount
                        resp = {"status": "ok", "balance": users[username]["balance"]}
                        print(f"[TX] {username} deposited ${amount:.2f}")

                elif cmd == "WITHDRAW":
                    amount = float(request.get("amount", 0))
                    if amount <= 0:
                        resp = {"status": "error", "msg": "Amount must be positive"}
                    elif amount > balance:
                        resp = {"status": "error", "msg": "Insufficient funds"}
                    else:
                        users[username]["balance"] -= amount
                        resp = {"status": "ok", "balance": users[username]["balance"]}
                        print(f"[TX] {username} withdrew ${amount:.2f}")

                elif cmd == "QUIT":
                    resp = {"status": "ok", "msg": "Goodbye"}
                    send_msg(conn, aes_encrypt(ms, json.dumps(resp).encode()))
                    break

                else:
                    resp = {"status": "error", "msg": "Unknown command"}

            send_msg(conn, aes_encrypt(ms, json.dumps(resp).encode()))

    except (ConnectionError, ValueError) as e:
        print(f"[TX] Session ended for '{username}': {e}")
    finally:
        print(f"[TX] Session closed for '{username}'")


# ── Per-client thread ──────────────────────────────────────────────────────────

def handle_client(conn: socket.socket, addr: tuple, server_key: RSA.RsaKey) -> None:
    print(f"\n[SERVER] New connection from {addr}")
    try:
        first = recv_msg(conn)

        if first == b"REGISTER":
            handle_register(conn)
            return

        if first != b"LOGIN":
            send_msg(conn, b"ERROR:expected LOGIN or REGISTER")
            return

        username, ms = authenticate_client(conn, server_key)
        if username:
            process_transactions(conn, username, ms)

    except Exception as e:
        print(f"[SERVER] Error with {addr}: {e}")
    finally:
        conn.close()
        print(f"[SERVER] Connection from {addr} closed.")


def handle_register(conn: socket.socket) -> None:
    try:
        data     = json.loads(recv_msg(conn).decode())
        username = data["username"].strip()
        password = data["password"]

        if not username or not password:
            send_msg(conn, b"REG_FAIL:empty_fields")
            return

        pw_hash = hashlib.sha256(password.encode()).hexdigest()

        with users_lock:
            if username in users:
                send_msg(conn, b"REG_FAIL:username_taken")
                return
            users[username] = {"password_hash": pw_hash, "balance": 0.0}

        send_msg(conn, b"REG_OK")
        print(f"[REGISTER] New account: '{username}'")
    except Exception as e:
        send_msg(conn, f"REG_FAIL:{e}".encode())


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    server_key  = load_or_generate_rsa_key()
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(5)
    print(f"[SERVER] Bank server listening on {HOST}:{PORT}")
    print("[SERVER] Waiting for ATM connections …\n")

    try:
        while True:
            conn, addr = server_sock.accept()
            threading.Thread(
                target=handle_client,
                args=(conn, addr, server_key),
                daemon=True
            ).start()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down.")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()