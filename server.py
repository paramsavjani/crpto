#!/usr/bin/env python3
"""
Sender / Encryption Server  (port 5000)

- Web UI to type a plaintext message
- Encrypts with AES-CBC and sends ciphertext to the attacker/receiver
- Exposes /oracle endpoint (the vulnerability) that only says valid/invalid padding
"""

import os
from flask import Flask, request, jsonify, render_template_string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests as http_req

app = Flask(__name__)

KEY = os.urandom(16)
BLOCK_SIZE = 16
ATTACKER_URL = "http://127.0.0.1:5001/capture"

PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Secure Messenger</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0f172a; color: #e2e8f0;
    min-height: 100vh; display: flex; justify-content: center; padding: 40px 20px;
  }
  .card {
    background: #1e293b; border-radius: 16px; padding: 40px;
    max-width: 660px; width: 100%; box-shadow: 0 8px 32px rgba(0,0,0,.4);
  }
  h1 { font-size: 1.6rem; margin-bottom: 6px; color: #38bdf8; }
  .sub { color: #94a3b8; margin-bottom: 28px; font-size: .9rem; }
  textarea {
    width: 100%; height: 120px; padding: 14px; border-radius: 10px;
    border: 1px solid #334155; background: #0f172a; color: #f1f5f9;
    font-size: 1rem; resize: vertical; outline: none;
  }
  textarea:focus { border-color: #38bdf8; }
  button {
    margin-top: 16px; padding: 12px 32px; border: none; border-radius: 10px;
    background: #2563eb; color: #fff; font-size: 1rem; cursor: pointer;
    transition: background .2s;
  }
  button:hover { background: #1d4ed8; }
  button:disabled { background: #334155; cursor: not-allowed; }
  .log { margin-top: 28px; }
  .entry {
    background: #0f172a; border-radius: 10px; padding: 16px; margin-bottom: 12px;
    border-left: 4px solid #22c55e; word-break: break-all; font-size: .85rem;
  }
  .entry .label { color: #94a3b8; font-size: .75rem; margin-bottom: 4px; }
  .entry .hex { font-family: 'Courier New', monospace; color: #34d399; }
  .entry .plain { color: #fbbf24; }
</style>
</head>
<body>
<div class="card">
  <h1>Secure Messenger - Sender</h1>
  <p class="sub">AES-128-CBC encryption. Type a message and send it to the receiver.</p>
  <textarea id="msg" placeholder="Type your secret message here..."></textarea>
  <button id="btn" onclick="send()">Encrypt &amp; Send</button>
  <div class="log" id="log"></div>
</div>
<script>
async function send() {
  const btn = document.getElementById('btn');
  const msg = document.getElementById('msg').value.trim();
  if (!msg) return;
  btn.disabled = true; btn.textContent = 'Sending...';
  try {
    const r = await fetch('/send', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({message: msg})
    });
    const d = await r.json();
    const log = document.getElementById('log');
    log.innerHTML = `
      <div class="entry">
        <div class="label">PLAINTEXT</div>
        <div class="plain">${msg}</div>
      </div>
      <div class="entry">
        <div class="label">IV (hex)</div>
        <div class="hex">${d.iv}</div>
      </div>
      <div class="entry">
        <div class="label">CIPHERTEXT (hex)</div>
        <div class="hex">${d.ciphertext}</div>
      </div>
      <div class="entry" style="border-color:#2563eb">
        <div class="label">STATUS</div>
        <div>${d.delivered ? 'Delivered to receiver' : 'Receiver not reachable (ciphertext still created)'}</div>
      </div>
    ` + log.innerHTML;
    document.getElementById('msg').value = '';
  } catch(e) { alert('Error: ' + e); }
  btn.disabled = false; btn.textContent = 'Encrypt & Send';
}
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(PAGE)


@app.route("/send", methods=["POST"])
def send_message():
    data = request.get_json(force=True)
    plaintext = data.get("message", "")
    if not plaintext:
        return jsonify({"error": "empty message"}), 400

    iv = os.urandom(BLOCK_SIZE)
    cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(plaintext.encode(), BLOCK_SIZE))

    full_hex = (iv + ct).hex()

    delivered = False
    try:
        http_req.post(ATTACKER_URL, json={"ciphertext": full_hex}, timeout=3)
        delivered = True
    except Exception:
        pass

    return jsonify({
        "iv": iv.hex(),
        "ciphertext": ct.hex(),
        "full_hex": full_hex,
        "delivered": delivered,
    })


@app.route("/oracle", methods=["POST"])
def oracle():
    """The vulnerability: tells if PKCS#7 padding is valid after decryption."""
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
        dec = AES.new(KEY, AES.MODE_CBC, iv=iv_part)
        pt = dec.decrypt(ct_part)
        pad_byte = pt[-1]
        if pad_byte < 1 or pad_byte > BLOCK_SIZE:
            return jsonify({"valid": False})
        valid = pt[-pad_byte:] == bytes([pad_byte] * pad_byte)
    except Exception:
        valid = False

    return jsonify({"valid": valid})


if __name__ == "__main__":
    print("\n  Sender Server running on http://127.0.0.1:5000")
    print("  Oracle endpoint: POST http://127.0.0.1:5000/oracle\n")
    app.run(host="127.0.0.1", port=5000, threaded=True)
