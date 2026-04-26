#!/usr/bin/env python3
"""
Encryption Server + Padding Oracle
Run in Terminal 1. Type plaintext, it encrypts with AES-CBC + PKCS#7
and sends ciphertext to the attacker on port 5001.
Exposes /oracle on port 5000 — only answers "is padding valid?" (yes/no).
"""

import os
import socket
import threading
import logging
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests as http_req

# --- Config ---
BLOCK_SIZE = 16
KEY = os.urandom(16)
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


def valid_padding(block):
    p = block[-1]
    return 1 <= p <= BLOCK_SIZE and block[-p:] == bytes([p]) * p


@app.route("/oracle", methods=["POST"])
def oracle():
    try:
        ct = bytes.fromhex(request.get_json(force=True).get("ciphertext", ""))
        if len(ct) != 2 * BLOCK_SIZE:
            return jsonify({"valid": False})
        iv, block = ct[:BLOCK_SIZE], ct[BLOCK_SIZE:]
        pt = AES.new(KEY, AES.MODE_CBC, iv=iv).decrypt(block)
        return jsonify({"valid": valid_padding(pt)})
    except Exception:
        return jsonify({"valid": False})


def main():
    local_ip = get_local_ip()
    attacker_ip = input("Enter attacker PC IP (blank for localhost): ").strip() or "127.0.0.1"
    attacker_url = f"http://{attacker_ip}:{ATTACKER_PORT}/capture"

    threading.Thread(
        target=lambda: app.run(host=SERVER_HOST, port=SERVER_PORT, threaded=True),
        daemon=True,
    ).start()

    print("=" * 50)
    print("ENCRYPTION SERVER + PADDING ORACLE")
    print(f"Key       : {fmt(KEY)}")
    print(f"Oracle    : http://{local_ip}:{SERVER_PORT}/oracle")
    print(f"Attacker  : {attacker_url}")
    print("=" * 50)

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

        raw = msg.encode()
        padded = pad(raw, BLOCK_SIZE)
        iv = os.urandom(BLOCK_SIZE)
        ct = AES.new(KEY, AES.MODE_CBC, iv=iv).encrypt(padded)
        pad_count = len(padded) - len(raw)

        print(f"Plaintext  : {msg}")
        print(f"Padding    : {pad_count} byte(s)")
        print(f"IV+CT      : {fmt(iv + ct)}")

        try:
            http_req.post(attacker_url, json={"ciphertext": (iv + ct).hex()}, timeout=3)
            print("Status     : Sent to attacker")
        except Exception:
            print("Status     : Attacker not running")


if __name__ == "__main__":
    main()
