"""
atm_client.py — ATM Client (RSA + AES Hybrid Encryption)
=========================================================

Security Protocol (mirrors server.py)
--------------------------------------
  1. Receive server RSA public key (PEM).
  2. RSA-OAEP encrypt { uname | pw_hash | N_c } → send to server.
     Only server can decrypt → authenticates CUSTOMER.
  3. Receive plaintext { N_s | HMAC(N_c, "server:" || N_s) }.
  4. Verify HMAC using our own N_c → proves server decrypted step 2
     → authenticates SERVER to ATM.
  5. Derive Master Secret = SHA-256(N_c || N_s).
  6. All subsequent transactions: AES-256-CBC with Master Secret.
"""

import socket
import hashlib
import hmac as hmac_mod
import os
import json
import struct
import getpass

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad

# ── Configuration (must match server) ─────────────────────────────────────────
HOST = "127.0.0.1"
PORT = 9999


# ── Crypto helpers ─────────────────────────────────────────────────────────────

def rsa_encrypt(public_key: RSA.RsaKey, plaintext: bytes) -> bytes:
    return PKCS1_OAEP.new(public_key).encrypt(plaintext)


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac_mod.new(key, data, hashlib.sha256).digest()


def derive_master_secret(nc: bytes, ns: bytes) -> bytes:
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


# ── Registration ───────────────────────────────────────────────────────────────

def register(sock: socket.socket) -> bool:
    print("\n── Register New Account ──────────────────")
    username = input("  Choose a username : ").strip()
    password = getpass.getpass("  Choose a password : ")
    confirm  = getpass.getpass("  Confirm password  : ")

    if password != confirm:
        print("  [!] Passwords do not match.")
        return False

    send_msg(sock, b"REGISTER")
    send_msg(sock, json.dumps({"username": username, "password": password}).encode())

    resp = recv_msg(sock)
    if resp == b"REG_OK":
        print(f"  [✓] Account '{username}' created!")
        return True
    else:
        print(f"  [✗] Registration failed: {resp.decode()}")
        return False


# ── RSA-based Login + Key Distribution ────────────────────────────────────────

def login(sock: socket.socket) -> tuple[str | None, bytes | None]:
    print("\n── ATM Login ─────────────────────────────")
    username = input("  Username : ").strip()
    password = getpass.getpass("  Password : ")
    pw_hash  = hashlib.sha256(password.encode()).hexdigest()   # 64-char hex

    send_msg(sock, b"LOGIN")

    # Step 1 — receive server RSA public key
    pub_pem    = recv_msg(sock)
    server_pub = RSA.import_key(pub_pem)
    print("  [AUTH] Received server RSA-2048 public key.")

    # Step 2 — RSA-OAEP encrypt { uname_len(2) | username | pw_hash(64) | N_c(32) }
    nc      = os.urandom(32)
    uname_b = username.encode()
    blob    = struct.pack(">H", len(uname_b)) + uname_b + pw_hash.encode() + nc
    send_msg(sock, rsa_encrypt(server_pub, blob))
    print("  [AUTH] Sent RSA-encrypted credentials and nonce N_c.")

    # Step 3 — receive { N_s(32) | server_proof(32) }
    reply = recv_msg(sock)

    if reply.startswith(b"AUTH_FAIL"):
        print(f"  [✗] Authentication failed: {reply.decode()}")
        return None, None

    if len(reply) < 64:
        print("  [✗] Malformed server response.")
        return None, None

    ns           = reply[:32]
    server_proof = reply[32:64]

    # Step 4 — verify server identity using our own N_c as the HMAC key
    expected_proof = hmac_sha256(nc, b"server:" + ns)
    if not hmac_mod.compare_digest(expected_proof, server_proof):
        print("  [✗] Server authentication FAILED — possible man-in-the-middle!")
        return None, None

    # Step 5 — derive Master Secret
    master_secret = derive_master_secret(nc, ns)

    print("  [✓] Server identity verified.")
    print(f"  [✓] Master Secret established (first 8 bytes: {master_secret[:8].hex()}…)")
    return username, master_secret


# ── Encrypted transaction helper ───────────────────────────────────────────────

def send_command(sock: socket.socket, ms: bytes, **kwargs) -> dict:
    send_msg(sock, aes_encrypt(ms, json.dumps(kwargs).encode()))
    return json.loads(aes_decrypt(ms, recv_msg(sock)).decode())


# ── ATM Menu ───────────────────────────────────────────────────────────────────

def atm_menu(sock: socket.socket, username: str, ms: bytes) -> None:
    print(f"\n  Welcome, {username}!")
    while True:
        print("\n── ATM Menu ──────────────────────────────")
        print("  1. Check Balance")
        print("  2. Deposit")
        print("  3. Withdraw")
        print("  4. Quit")
        choice = input("  Select option: ").strip()

        if choice == "1":
            resp = send_command(sock, ms, cmd="BALANCE")
            if resp["status"] == "ok":
                print(f"  [✓] Current balance: ${resp['balance']:.2f}")
            else:
                print(f"  [✗] {resp.get('msg')}")

        elif choice == "2":
            try:
                amount = float(input("  Enter deposit amount: $"))
            except ValueError:
                print("  [!] Invalid amount.")
                continue
            resp = send_command(sock, ms, cmd="DEPOSIT", amount=amount)
            if resp["status"] == "ok":
                print(f"  [✓] Deposited ${amount:.2f}. New balance: ${resp['balance']:.2f}")
            else:
                print(f"  [✗] {resp.get('msg')}")

        elif choice == "3":
            try:
                amount = float(input("  Enter withdrawal amount: $"))
            except ValueError:
                print("  [!] Invalid amount.")
                continue
            resp = send_command(sock, ms, cmd="WITHDRAW", amount=amount)
            if resp["status"] == "ok":
                print(f"  [✓] Withdrew ${amount:.2f}. New balance: ${resp['balance']:.2f}")
            else:
                print(f"  [✗] {resp.get('msg')}")

        elif choice == "4":
            send_command(sock, ms, cmd="QUIT")
            print("  [✓] Session ended. Goodbye!")
            break

        else:
            print("  [!] Invalid option, please try again.")


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    print("╔══════════════════════════════════════════╗")
    print("║          Secure ATM Client               ║")
    print("║    RSA-2048 + AES-256-CBC Encryption     ║")
    print("╚══════════════════════════════════════════╝")

    while True:
        print("\n  1. Register new account")
        print("  2. Login")
        print("  3. Exit")
        choice = input("  Select option: ").strip()

        if choice == "3":
            print("  Goodbye!")
            break

        if choice not in ("1", "2"):
            print("  [!] Invalid option.")
            continue

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((HOST, PORT))
            print(f"\n  [✓] Connected to bank server at {HOST}:{PORT}")
        except ConnectionRefusedError:
            print("  [✗] Could not connect. Is the bank server running?")
            continue

        try:
            if choice == "1":
                register(sock)
            elif choice == "2":
                username, ms = login(sock)
                if username and ms:
                    atm_menu(sock, username, ms)
        except (ConnectionError, OSError) as e:
            print(f"  [✗] Connection error: {e}")
        finally:
            sock.close()


if __name__ == "__main__":
    main()