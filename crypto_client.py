#!/usr/bin/env python3
import os
import socket
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

SERVER_IP = "IP_SERVEUR"
PORT = 9000

PSK = b"bts-ciel-secret"  # doit être identique au serveur

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
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
    msg = input("Message a envoyer: ").encode()

    with socket.create_connection((SERVER_IP, PORT)) as sock:
        # 1) réception du salt envoyé par le serveur
        salt = recv_frame(sock)

        key = derive_key(PSK, salt)
        aesgcm = AESGCM(key)

        # 2) envoi chiffré
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, msg, None)
        send_frame(sock, nonce)
        send_frame(sock, ct)

        # 3) réception réponse chiffrée
        nonce2 = recv_frame(sock)
        ct2 = recv_frame(sock)
        reply = aesgcm.decrypt(nonce2, ct2, None)
        print("Reponse (dechiffree):", reply.decode(errors="ignore"))

if __name__ == "__main__":
    main()
