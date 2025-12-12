#!/usr/bin/env python3
import os
import socket
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

HOST = "0.0.0.0"
PORT = 9000

# Mot de passe partagé (TP) : même valeur côté client
PSK = b"bts-ciel-secret"  # change-le si tu veux

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,           # AES-256
        salt=salt,
        iterations=200_000,
    )
    return kdf.derive(password)

def recvall(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connexion interrompue")
        data += chunk
    return data

def recv_frame(sock: socket.socket) -> bytes:
    (length,) = struct.unpack("!I", recvall(sock, 4))
    return recvall(sock, length)

def send_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack("!I", len(payload)) + payload)

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[SERVER] Listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            with conn:
                print(f"[SERVER] Client: {addr}")

                # 1) handshake simple: envoi du salt au client
                salt = os.urandom(16)
                send_frame(conn, salt)

                key = derive_key(PSK, salt)
                aesgcm = AESGCM(key)

                # 2) réception: nonce(12) + ciphertext
                nonce = recv_frame(conn)
                ct = recv_frame(conn)

                # 3) déchiffrement
                try:
                    plaintext = aesgcm.decrypt(nonce, ct, None)
                except Exception as e:
                    print("[SERVER] Decrypt failed:", e)
                    send_frame(conn, b"ERR")
                    continue

                print("[SERVER] Received (decrypted):", plaintext.decode(errors="ignore").strip())

                # 4) réponse chiffrée
                reply = b"Bien recu !"
                nonce2 = os.urandom(12)
                ct2 = aesgcm.encrypt(nonce2, reply, None)
                send_frame(conn, nonce2)
                send_frame(conn, ct2)

if __name__ == "__main__":
    main()
