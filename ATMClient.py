"""
ATMClient.py — ATM Client (RSA + Simulated Symmetric Encryption)
=================================================================

Merges Client_A.java and Client_B.java into a single script.
The client ID is passed as a command-line argument, so any number
of ATM clients can run simultaneously.

Security Protocol (mirrors BankServer.py)
------------------------------------------
Phase 1 — Mutual Authentication & Master Key Distribution
  1.  ATM  → Server : ATM RSA public key
  2.  Server → ATM  : Server RSA public key
  3.  ATM  → Server : client ID
  4.  Server → ATM  : Message 1  E(PU_ATM,  [NK1 || ID_KDC])
  5.  ATM  → Server : Message 2  E(PU_KDC,  [N_ATM || NK1])
  6.  Server → ATM  : Message 3  E(PU_ATM,  NK1)
  7.  Server → ATM  : Message 4  E(PU_ATM,  E(PR_KDC, MasterKey))

Phase 2 — Session Key Distribution
  - User enters the ID of the ATM they want to establish a session with.
  - Client sends IDA + IDB to the server.
  - Receives E(KA, [KAB || IDB]) or E(KB, [KAB || IDA]) depending on
    which client triggered the exchange.

Usage:
    python ATMClient.py "Client A"
    python ATMClient.py "Client B"
    python ATMClient.py "Client C"   ← any ID works
"""

import sys
import socket
import random
import base64
import struct
import json
import hmac
import hashlib

from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# ── Configuration ──────────────────────────────────────────────────────────────
KDC_HOST = "localhost"
KDC_PORT = 1234

# performs a hash of the data using the mac_key to ensure data integrity later
def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

# send secure utf performs the encryption using the encryption key, tags the hashed message with the mac key, and sends the utf
def send_secure_utf(sock: socket.socket, enc_key: bytes, mac_key: bytes, obj: dict) -> None:
    # converts a python dictionary into a json object, encrypts that using the encryption key.
    plaintext = json.dumps(obj)
    ciphertext = aes_encrypt(enc_key, plaintext)  
    # generates a hash of the encrypted message using the mac key.
    tag = hmac_sha256(mac_key, ciphertext)

    packet = {
        "ct": base64.b64encode(ciphertext).decode("utf-8"),
        "tag": base64.b64encode(tag).decode("utf-8")
    }
    # sends the packet as a json object to the other side of the connection.
    send_utf(sock, json.dumps(packet))

# receive secure utf performs the decryption using the encryption key to get the message, verifies the data integrity using the tag hashed by the mac key.
def recv_secure_utf(sock: socket.socket, enc_key: bytes, mac_key: bytes) -> dict:
    packet = json.loads(recv_utf(sock))

    ciphertext = base64.b64decode(packet["ct"])
    tag = base64.b64decode(packet["tag"])

    # Message Verification by verifying the tag with the message with the hash of the original message received (Data Integrity)
    expected_tag = hmac_sha256(mac_key, ciphertext)
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("MAC verification failed")

    # Decrypts the message using the encryption key and returns the string.
    plaintext = aes_decrypt(enc_key, ciphertext)  
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

# send and receive utf functions to more accurately transmit messages as bytes and display received messages.
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

# ── Deriving AES key from master key ────────────────────────────────────────────
def derive_aes_key(master_key: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"atm-master-aes-key",
    ).derive(master_key.encode("utf-8"))


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

# ── Function for handling valid deposit and withdrawal amounts (in float only) ────────────────────────────────────────────
def get_valid_amount(prompt: str) -> float:
    while True:
        value = input(prompt).strip()
        try:
            amount = float(value)

            if amount <= 0:
                print("Amount must be greater than 0. Try again.")
                continue

            return amount

        except ValueError:
            print("Invalid input. Please enter a valid number (e.g., 100.50).")

# Add to Server GUI, this is the main part that should be converted to a GUI.
def phase3_menu(sock: socket.socket, my_id: str, enc_key: bytes, mac_key: bytes) -> None:
    logged_in = False

    while True:
        if not logged_in:
            print("\n1. Register")
            print("2. Login")
            print("3. Exit")
            choice = input("Choose an option: ").strip()

            # REGISTRATION (new user)
            if choice == "1":
                username = input("Enter username: ").strip()
                email = input("Enter email: ").strip()
                password = input("Enter password: ").strip()

                send_secure_utf(sock, enc_key, mac_key, {
                    "cmd": "REGISTER",
                    "username": username,
                    "email": email,
                    "password": password
                })
                resp = recv_secure_utf(sock, enc_key, mac_key)
                print(f"[{my_id}] Server response: {resp}")
            #LOG IN (existing user)
            elif choice == "2":
                email = input("Enter email: ").strip()
                password = input("Enter password: ").strip()

                send_secure_utf(sock, enc_key, mac_key, {
                    "cmd": "LOGIN",
                    "email": email,
                    "password": password
                })
                resp = recv_secure_utf(sock, enc_key, mac_key)
                print(f"[{my_id}] Server response: {resp}")

                if resp.get("status") == "ok":
                    logged_in = True
            #EXIT the program
            elif choice == "3":
                send_secure_utf(sock, enc_key, mac_key, {"cmd": "EXIT"})
                resp = recv_secure_utf(sock, enc_key, mac_key)
                print(f"[{my_id}] Server response: {resp}")
                break

            else:
                print("Invalid option.")
        # Once user logs in, they enter the Transaction menu
        else:
            print("\n1. Balance")
            print("2. Deposit")
            print("3. Withdraw")
            print("4. Logout")
            choice = input("Choose an option: ").strip()
            # BALANCE QUERY (reads balance)
            if choice == "1":
                send_secure_utf(sock, enc_key, mac_key, {"cmd": "BALANCE"})
                resp = recv_secure_utf(sock, enc_key, mac_key)
                print(f"[{my_id}] Server response: {resp}")
            # DEPOSIT (adds to balance)
            elif choice == "2":
                amount = get_valid_amount("Enter deposit amount: ")
                send_secure_utf(sock, enc_key, mac_key, {
                    "cmd": "DEPOSIT",
                    "amount": amount
                })
                resp = recv_secure_utf(sock, enc_key, mac_key)
                print(f"[{my_id}] Server response: {resp}")
            # WITHDRAW (removes from balance)
            elif choice == "3":
                amount = get_valid_amount("Enter withdrawal amount: ")
                send_secure_utf(sock, enc_key, mac_key, {
                    "cmd": "WITHDRAW",
                    "amount": amount
                })
                resp = recv_secure_utf(sock, enc_key, mac_key)
                print(f"[{my_id}] Server response: {resp}")
            # LOG OUT (no longer perform transactions)
            elif choice == "4":
                send_secure_utf(sock, enc_key, mac_key, {"cmd": "LOGOUT"})
                resp = recv_secure_utf(sock, enc_key, mac_key)
                print(f"[{my_id}] Server response: {resp}")
                logged_in = False

            else:
                print("Invalid option.")

# Key Distribution (Phases 1 and 2)
def key_distribution(my_id: str):
    # Generate RSA-2048 key pair for this client
    kp          = RSA.generate(2048)
    my_pub_key  = kp.publickey()
    my_priv_key = kp

    # Connect to the Bank / KDC server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((KDC_HOST, KDC_PORT))
    print(f"[{my_id}] Connected to Bank Server at {KDC_HOST}:{KDC_PORT}\n")
    # ── Step 1 : send our RSA public key ──────────────────────────────────────
    send_msg(sock, my_pub_key.export_key(format="DER"))

    # ── Step 2 : receive KDC's RSA public key ─────────────────────────────────
    kdc_pub_bytes = recv_msg(sock)
    kdc_pub_key   = RSA.import_key(kdc_pub_bytes)
    print(f"[{my_id}] Received Bank Server public key.")

    # ── Step 3 : send our ID ──────────────────────────────────────────────────
    send_utf(sock, my_id)

    # ── Step 4 : receive Message 1 — E(PU_ATM, [NK1 || IDK]) ─────────────────
    msg1_b64 = recv_utf(sock)
    print(f"[{my_id}] Received Message 1 (Encrypted): {msg1_b64}")

    msg1_dec  = rsa_decrypt_raw(my_priv_key, base64.b64decode(msg1_b64))
    decrypted1 = msg1_dec.decode("utf-8", errors="replace").replace("\x00", "").strip()
    print(f"[{my_id}] Decrypted Message 1: {decrypted1}")

    parts   = decrypted1.split("||")
    nonce_k = parts[0]
    id_k    = parts[1] if len(parts) > 1 else ""

    # ── Step 5 : send Message 2 — E(PU_KDC, [N_ATM || NK1]) ─────────────────
    # Nonce prefix uses the client's ID initials to stay distinct (mirrors NA / NB in Java)
    initials   = "".join(w[0] for w in my_id.split())
    my_nonce   = f"N{initials}{random.randint(0, 999)}"
    msg2_plain = f"{my_nonce}||{nonce_k}".encode()
    msg2_enc   = rsa_encrypt_raw(kdc_pub_key, msg2_plain)
    send_utf(sock, base64.b64encode(msg2_enc).decode())
    print(f"[{my_id}] Sent Message 2 (nonce + KDC nonce echo)\n")

    # ── Step 6 : receive Message 3 — E(PU_ATM, NK1) ──────────────────────────
    msg3_b64  = recv_utf(sock)
    print(f"[{my_id}] Received Message 3 (Encrypted): {msg3_b64}")

    msg3_dec   = rsa_decrypt_raw(my_priv_key, base64.b64decode(msg3_b64))
    nonce_check = msg3_dec.decode("utf-8", errors="replace").replace("\x00", "").strip()
    print(f"[{my_id}] Decrypted Message 3: {nonce_check}")

    if nonce_k in nonce_check:
        print(f"[{my_id}] Nonce K verified from KDC Server.")
    else:
        print(f"[{my_id}] Nonce was possibly corrupted. Closing connection.")
        sock.close()
        return

    # ── Step 7 : receive Message 4 — E(PU_ATM, MasterKey)) ─────────
    msg4_b64    = recv_utf(sock)
    outer_dec   = rsa_decrypt_raw(my_priv_key, base64.b64decode(msg4_b64))
    master_key  = outer_dec.decode("utf-8", errors="replace").replace("\x00", "").strip()
    print(f"[{my_id}] Decrypted Message 4 (Master Key): {master_key}\n")

    # ── Phase 2 ───────────────────────────────────────────────────────────────
    print("=== Phase 2 Starting ===\n")


    # Send ATM Client ID to server
    send_utf(sock, my_id)
    print(f"[{my_id}] Sent IDA={my_id} to Bank Server.\n")

    # Receive the encryption and MAC key and decrypt it using the AES Master Key(either as the requester or the responder)
    enc_msg = recv_utf(sock)
    aes_key = derive_aes_key(master_key)
    decrypted = aes_decrypt(aes_key, base64.b64decode(enc_msg))
    print(f"[{my_id}] Decrypted: {decrypted}")

    phase2_parts = decrypted.split("||")
    enc_key_hex  = phase2_parts[0]
    mac_key_hex  = phase2_parts[1] if len(phase2_parts) > 1 else ""

    print(f"[{my_id}] Encryption Key = {enc_key_hex}")
    print(f"[{my_id}] MAC Key = {mac_key_hex}")

    enc_key = bytes.fromhex(enc_key_hex)
    mac_key = bytes.fromhex(mac_key_hex)


    print(f"=== Phase 2 Complete. [{my_id}] holds Encryption Key = {enc_key} and MAC Key {mac_key} ===")
    return enc_key, mac_key, sock

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print('Usage: python ATMClient.py "Client A"')
        sys.exit(1)

    my_id = sys.argv[1]
    print(f"---- ATM Client [{my_id}] ----\n")

    # Key Distribution protocol to ensure secure connection between ATM and Bank Server, and encryption key (session key) and mac key for user transactions are distributed.
    enc_key, mac_key, sock = key_distribution(my_id)

    # Phase 3 and 4: Prompt User to enter Username and Password or register, once logged in they enter the transaction menu
    phase3_menu(sock, my_id, enc_key, mac_key)

    sock.close()


if __name__ == "__main__":
    main()