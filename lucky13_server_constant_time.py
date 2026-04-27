#!/usr/bin/env python3

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
FIXED_RECORD_LEN = 128
FIXED_ORACLE_DELAY = 0.00006

ENC_KEY = os.urandom(16)
MAC_KEY = os.urandom(32)

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 6000
ATTACKER_PORT = 6001

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


def pkcs7_valid(data):
    if not data:
        return False, 0
    p = data[-1]
    ok = 1 <= p <= BLOCK_SIZE and data[-p:] == bytes([p]) * p
    return ok, p if ok else 0


def fixed_len_slice(data, start, size):
    out = data[start:start + size]
    if len(out) < size:
        out += b"\x00" * (size - len(out))
    return out


@app.route("/lucky13_oracle", methods=["POST"])
def lucky13_oracle():
    start = time.perf_counter()

    try:
        blob = bytes.fromhex(request.get_json(force=True).get("ciphertext", ""))
    except Exception:
        blob = b""

    if len(blob) >= 2 * BLOCK_SIZE and len(blob) % BLOCK_SIZE == 0:
        iv, body = blob[:BLOCK_SIZE], blob[BLOCK_SIZE:]
    else:
        iv, body = b"\x00" * BLOCK_SIZE, b"\x00" * BLOCK_SIZE

    try:
        pt = AES.new(ENC_KEY, AES.MODE_CBC, iv=iv).decrypt(body)
    except Exception:
        pt = b"\x00" * BLOCK_SIZE

    valid_pad, pad_len = pkcs7_valid(pt)
    unpadded_len = len(pt) - pad_len if valid_pad else len(pt)

    msg_fixed = fixed_len_slice(pt, 0, FIXED_RECORD_LEN)
    recv_mac_fixed = fixed_len_slice(pt, max(0, unpadded_len - MAC_SIZE), MAC_SIZE)

    calc = b"\x00" * MAC_SIZE
    for _ in range(3):
        calc = hmac.new(MAC_KEY, msg_fixed, sha256).digest()
    _ = hmac.compare_digest(calc, recv_mac_fixed)

    elapsed = time.perf_counter() - start
    remaining = FIXED_ORACLE_DELAY - elapsed
    if remaining > 0:
        time.sleep(remaining)

    return jsonify({"status": "ok"})


def main():
    local_ip = get_local_ip()
    attacker_ip = input("Enter attacker PC IP (blank for localhost): ").strip() or "127.0.0.1"
    attacker_url = f"http://{attacker_ip}:{ATTACKER_PORT}/capture"

    threading.Thread(
        target=lambda: app.run(host=SERVER_HOST, port=SERVER_PORT, threaded=True),
        daemon=True,
    ).start()

    print("=" * 66)
    print("LUCKY-13 RESISTANT SERVER (CONSTANT-TIME STYLE ORACLE)")
    print(f"This PC IP : {local_ip}")
    print(f"Oracle     : http://{local_ip}:{SERVER_PORT}/lucky13_oracle")
    print(f"Attacker   : {attacker_url}")
    print("=" * 66)

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
        packet = iv + ct
        print(f"Plaintext      : {msg}")
        print(f"Padded bytes   : {len(padded)}")
        print(f"IV + ciphertext: {fmt(packet)}")

        try:
            http_req.post(attacker_url, json={"ciphertext": packet.hex()}, timeout=3)
            print("Status         : Sent to attacker")
        except Exception:
            print("Status         : Attacker not running")


if __name__ == "__main__":
    main()
