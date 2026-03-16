#!/usr/bin/env python3
"""
Encryption Server + Padding Oracle
Run in Terminal 1. Type plaintext, it encrypts with AES-CBC + PKCS#7
and sends ciphertext to the attacker on port 5001.
Exposes /oracle on port 5000 — only answers "is padding valid?" (yes/no).
"""

import os
import threading
import logging
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests as http_req

# --- Hardcoded values ---
BLOCK_SIZE = 16                        # AES block size: 16 bytes (128 bits)
KEY = os.urandom(16)                   # AES-128 key: 16 bytes, random each run
SERVER_PORT = 5000
ATTACKER_URL = "http://127.0.0.1:5001/capture"

app = Flask(__name__)
logging.getLogger("werkzeug").setLevel(logging.ERROR)  # hide flask logs


@app.route("/oracle", methods=["POST"])
def oracle():
    """The vulnerability: only tells if PKCS#7 padding is valid or not."""
    data = request.get_json(force=True)
    ct_hex = data.get("ciphertext", "")

    try:
        ct_bytes = bytes.fromhex(ct_hex)
    except ValueError:
        return jsonify({"valid": False})

    if len(ct_bytes) != 2 * BLOCK_SIZE:
        return jsonify({"valid": False})

    iv_part = ct_bytes[:BLOCK_SIZE]
    ct_part = ct_bytes[BLOCK_SIZE:]

    try:
        cipher = AES.new(KEY, AES.MODE_CBC, iv=iv_part)
        pt = cipher.decrypt(ct_part)
        pad_byte = pt[-1]
        if pad_byte < 1 or pad_byte > BLOCK_SIZE:
            return jsonify({"valid": False})
        valid = pt[-pad_byte:] == bytes([pad_byte] * pad_byte)
    except Exception:
        valid = False

    return jsonify({"valid": valid})


def main():
    # start flask in background thread
    t = threading.Thread(target=lambda: app.run(host="127.0.0.1", port=SERVER_PORT, threaded=True), daemon=True)
    t.start()

    print("=" * 50)
    print("  ENCRYPTION SERVER + PADDING ORACLE")
    print("=" * 50)
    print(f"  Algorithm  : AES-128-CBC")
    print(f"  Block size : {BLOCK_SIZE} bytes")
    print(f"  Padding    : PKCS#7")
    print(f"  Key (hex)  : {KEY.hex()}")
    print(f"  Oracle     : http://127.0.0.1:{SERVER_PORT}/oracle")
    print("=" * 50)
    print()

    while True:
        try:
            msg = input("Enter plaintext (or 'quit'): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nInput closed. Oracle stays alive for attacker.")
            try:
                t.join()
            except KeyboardInterrupt:
                pass
            return

        if not msg:
            continue
        if msg.lower() == "quit":
            break

        # encrypt
        iv = os.urandom(BLOCK_SIZE)
        cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)
        padded = pad(msg.encode(), BLOCK_SIZE)
        ct = cipher.encrypt(padded)
        pad_count = len(padded) - len(msg.encode())

        print(f"\nPlaintext       : {msg}")
        print(f"Plaintext bytes : {len(msg.encode())}")
        print(f"PKCS#7 padding  : added {pad_count} bytes of value 0x{pad_count:02x}")
        print(f"After padding   : {len(padded)} bytes ({len(padded)//BLOCK_SIZE} block(s))")
        print(f"IV  (hex)       : {iv.hex()}")
        print(f"CT  (hex)       : {ct.hex()}")
        print(f"IV+CT (hex)     : {(iv+ct).hex()}")

        # send to attacker
        try:
            http_req.post(ATTACKER_URL, json={"ciphertext": (iv+ct).hex()}, timeout=3)
            print(f"Status          : Sent to attacker")
        except Exception:
            print(f"Status          : Attacker not running")
        print()


if __name__ == "__main__":
    main()
