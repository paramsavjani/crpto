#!/usr/bin/env python3
"""
Encryption Server + Padding Oracle  (Terminal 1)

Run this in one terminal. Type plaintext messages, they get encrypted
with AES-128-CBC + PKCS#7 padding and sent to the attacker.

Flask runs silently in the background on port 5000 to serve /oracle requests.
"""

import os
import sys
import threading
import logging
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests as http_req

# ──────────────────────────────────────────────
# HARDCODED / CONFIGURABLE VALUES
# ──────────────────────────────────────────────
BLOCK_SIZE   = 16          # AES block size (128 bits) — fixed by AES spec
KEY_SIZE     = 16          # AES-128 = 16 bytes, AES-192 = 24, AES-256 = 32
KEY          = os.urandom(KEY_SIZE)   # random key, generated fresh each run
PADDING      = "PKCS#7"   # padding standard used
SERVER_PORT  = 5000        # port this server listens on
ATTACKER_URL = "http://127.0.0.1:5001/capture"  # where to send ciphertext
# ──────────────────────────────────────────────

oracle_queries = 0

app = Flask(__name__)
log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)


@app.route("/oracle", methods=["POST"])
def oracle():
    """Only answers: is the PKCS#7 padding valid? True or False."""
    global oracle_queries
    oracle_queries += 1

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


def start_flask():
    app.run(host="127.0.0.1", port=SERVER_PORT, threaded=True)


def print_config():
    print("=" * 55)
    print("  ENCRYPTION SERVER  (Padding Oracle)")
    print("=" * 55)
    print()
    print("  Hardcoded values:")
    print(f"    Algorithm    : AES-{KEY_SIZE * 8}-CBC")
    print(f"    Block size   : {BLOCK_SIZE} bytes ({BLOCK_SIZE * 8} bits)")
    print(f"    Key size     : {KEY_SIZE} bytes ({KEY_SIZE * 8} bits)")
    print(f"    Padding      : {PADDING}")
    print(f"    Key (hex)    : {KEY.hex()}")
    print(f"    Server port  : {SERVER_PORT}")
    print(f"    Attacker URL : {ATTACKER_URL}")
    print()
    print("  The /oracle endpoint only reveals if padding is valid.")
    print("  The attacker never sees the key.")
    print("-" * 55)
    print()


def main():
    print_config()

    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()
    print(f"  [OK] Oracle listening on port {SERVER_PORT}\n")

    while True:
        try:
            plaintext = input("  Enter message (or 'quit'): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  [*] Input ended. Oracle stays alive (Ctrl+C to stop).")
            # Keep the oracle running so the attacker can still query it
            try:
                flask_thread.join()
            except KeyboardInterrupt:
                pass
            print("  Bye.")
            return

        if not plaintext:
            continue
        if plaintext.lower() == "quit":
            print("  Bye.")
            break

        pt_bytes = plaintext.encode()
        iv = os.urandom(BLOCK_SIZE)
        cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)
        ct = cipher.encrypt(pad(pt_bytes, BLOCK_SIZE))

        padded_len = len(pad(pt_bytes, BLOCK_SIZE))
        pad_bytes_added = padded_len - len(pt_bytes)

        print()
        print(f"  Plaintext      : {plaintext}")
        print(f"  Plaintext bytes: {len(pt_bytes)}")
        print(f"  PKCS#7 padding : {pad_bytes_added} bytes of value 0x{pad_bytes_added:02x}")
        print(f"  Padded length  : {padded_len} bytes ({padded_len // BLOCK_SIZE} blocks)")
        print(f"  IV       (hex) : {iv.hex()}")
        print(f"  CT       (hex) : {ct.hex()}")
        print(f"  Full IV+CT     : {(iv + ct).hex()}")

        delivered = False
        try:
            http_req.post(
                ATTACKER_URL,
                json={"ciphertext": (iv + ct).hex()},
                timeout=3,
            )
            delivered = True
        except Exception:
            pass

        status = "SENT to attacker" if delivered else "FAILED (attacker not running?)"
        print(f"  Status         : {status}")
        print()


if __name__ == "__main__":
    main()
