# CBC Padding Oracle Attack - Real-Time Demo

A real-time demonstration of the CBC Padding Oracle Attack using two Flask servers.

## Architecture

```
  Sender (port 5000)                Attacker (port 5001)
  ┌──────────────────┐              ┌──────────────────────┐
  │  Web UI: type     │   cipher    │  Dashboard: shows     │
  │  plaintext, hit   │──────────>  │  captured ciphertext  │
  │  send             │   text      │  + real-time decrypt  │
  │                   │             │                       │
  │  /oracle endpoint │ <────────── │  padding oracle       │
  │  (the vuln)       │   queries   │  attack engine        │
  └──────────────────┘              └──────────────────────┘
```

1. **Sender** encrypts your message with AES-CBC and sends ciphertext to the attacker
2. **Attacker** captures it, then queries the sender's `/oracle` endpoint thousands of times
3. Each query only reveals "is the padding valid?" — but that's enough to recover every byte

## Setup

```bash
pip install -r requirements.txt
```

## Usage

**Terminal 1** — Start the sender server:
```bash
python server.py
```

**Terminal 2** — Start the attacker dashboard:
```bash
python attacker.py
```

Then:
1. Open http://127.0.0.1:5000 — type a message and click Send
2. Open http://127.0.0.1:5001 — see the captured ciphertext, click "Start Padding Oracle Attack"
3. Watch the bytes get recovered in real-time

## Files

| File | Description |
|---|---|
| `server.py` | Sender web UI + AES-CBC encryption + padding oracle endpoint (port 5000) |
| `attacker.py` | MITM attacker dashboard with real-time decryption via SSE (port 5001) |
