# CBC Padding Oracle Attack — Terminal Demo

Demonstrates the CBC Padding Oracle Attack entirely in the terminal. No browser needed.

## Hardcoded Values

| Value | Setting | Why |
|---|---|---|
| `BLOCK_SIZE` | 16 bytes (128 bits) | Fixed by AES spec |
| `KEY_SIZE` | 16 bytes | AES-128 (random key generated each run) |
| `IV` | 16 bytes | Random per message |
| `PADDING` | PKCS#7 | Pads plaintext to block boundary, pad byte = number of bytes added |
| `SERVER_PORT` | 5000 | Sender + oracle |
| `LISTEN_PORT` | 5001 | Attacker |

## How It Works

```
Terminal 1 (server.py)              Terminal 2 (attacker.py)
┌───────────────────────┐           ┌───────────────────────┐
│ You type plaintext     │  cipher  │ Captures ciphertext    │
│ → AES-CBC encrypt      │────────> │ → Starts attack        │
│ → sends to attacker    │          │                        │
│                        │  "valid?"│ For each byte:         │
│ /oracle endpoint       │ <────────│  try 256 guesses       │
│ answers yes/no only    │────────> │  ask oracle valid?     │
│                        │  yes/no  │  if yes → byte found   │
│                        │          │                        │
│ NEVER reveals the key  │          │ → Decrypted plaintext! │
└───────────────────────┘           └───────────────────────┘
```

## PKCS#7 Padding

Pads the plaintext so its length is a multiple of 16 bytes:
- 1 byte short → add `01`
- 2 bytes short → add `02 02`
- 3 bytes short → add `03 03 03`
- Full block → add `10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10`

## Setup

```bash
pip install -r requirements.txt
```

## Usage

**Terminal 1** — start the sender/oracle:
```
$ python3 server.py
```

**Terminal 2** — start the attacker:
```
$ python3 attacker.py
```

Type a message in Terminal 1, watch Terminal 2 decrypt it byte-by-byte.

## Files

| File | Description |
|---|---|
| `server.py` | Sender: input plaintext, AES-CBC encrypt, expose /oracle (port 5000) |
| `attacker.py` | Attacker: capture ciphertext, padding oracle attack, show progress (port 5001) |
