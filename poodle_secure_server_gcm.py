#!/usr/bin/env python3
"""
Secure server against POODLE/padding-oracle style attacks.

Uses AES-GCM (AEAD):
- No PKCS#7 padding oracle exists.
- Any ciphertext modification fails tag verification.

Run this instead of server.py. If attacker.py tries its CBC padding-oracle
logic against this server, it will fail.
"""

import logging
import os
import socket
import threading

import requests as http_req
from Crypto.Cipher import AES
from flask import Flask, jsonify, request

KEY = os.urandom(16)  # AES-128-GCM key
NONCE_SIZE = 12
TAG_SIZE = 16

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5000
ATTACKER_PORT = 5001

app = Flask(__name__)
logging.getLogger("werkzeug").setLevel(logging.ERROR)


def fmt(data):
    return " ".join(str(b) for b in data)


def get_local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def encrypt_gcm(message):
    nonce = os.urandom(NONCE_SIZE)
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return nonce, ciphertext, tag


@app.route("/oracle", methods=["POST"])
def oracle():
    """
    Compatibility endpoint for attacker.py.
    Unlike CBC padding-oracle, this leaks nothing useful.
    """
    try:
        blob = bytes.fromhex(request.get_json(force=True).get("ciphertext", ""))
        if len(blob) < NONCE_SIZE + TAG_SIZE:
            return jsonify({"valid": False})

        nonce = blob[:NONCE_SIZE]
        tag = blob[-TAG_SIZE:]
        ciphertext = blob[NONCE_SIZE:-TAG_SIZE]

        cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
        cipher.decrypt_and_verify(ciphertext, tag)
        return jsonify({"valid": True})
    except Exception:
        # Any tampering/noise/wrong format lands here.
        return jsonify({"valid": False})


def main():
    local_ip = get_local_ip()
    attacker_ip = input("Enter attacker PC IP (blank for localhost): ").strip() or "127.0.0.1"
    attacker_url = f"http://{attacker_ip}:{ATTACKER_PORT}/capture"

    threading.Thread(
        target=lambda: app.run(host=SERVER_HOST, port=SERVER_PORT, threaded=True),
        daemon=True,
    ).start()

    print("=" * 58)
    print("SECURE SERVER (AES-GCM) — POODLE/PADDING ORACLE RESISTANT")
    print(f"This PC IP : {local_ip}")
    print(f"Oracle     : http://{local_ip}:{SERVER_PORT}/oracle")
    print(f"Attacker   : {attacker_url}")
    print(f"Key        : {fmt(KEY)}")
    print("=" * 58)

    while True:
        try:
            msg = input("\nEnter plaintext (or 'quit'): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nInput closed.")
            return

        if not msg:
            continue
        if msg.lower() == "quit":
            break

        nonce, ciphertext, tag = encrypt_gcm(msg)
        packet = nonce + ciphertext + tag

        print(f"Plaintext        : {msg}")
        print(f"Nonce            : {fmt(nonce)}")
        print(f"Ciphertext       : {fmt(ciphertext)}")
        print(f"Tag              : {fmt(tag)}")
        print(f"Nonce+CT+Tag     : {fmt(packet)}")

        try:
            http_req.post(attacker_url, json={"ciphertext": packet.hex()}, timeout=3)
            print("Status           : Sent to attacker")
        except Exception:
            print("Status           : Attacker not running")


if __name__ == "__main__":
    main()
