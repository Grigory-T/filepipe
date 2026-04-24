# filepipe

`filepipe` is a minimal client for encrypted store-and-forward file transfer over HTTPS.

This repository contains only the client-side code. It does not include relay deployment code.

## Requirements

- Python 3.12 or compatible Python 3
- `cryptography`

## Quick Start

Linux:

```bash
git clone https://github.com/your-org/filepipe.git
cd filepipe
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Windows PowerShell:

```powershell
git clone https://github.com/your-org/filepipe.git
cd filepipe
python -m venv .venv
.\.venv\\Scripts\\pip.exe install -r requirements.txt
```

## First-Time Setup

Do the following on both machines.

Initialize the client once on each machine.

Linux:

```bash
.venv/bin/python scripts/init_client.py --relay https://your-relay.example/filepipe
```

Windows PowerShell:

```powershell
.\.venv\\Scripts\\python.exe scripts/init_client.py --relay https://your-relay.example/filepipe
```

This creates:

- `keys/enc_private.pem`
- `keys/enc_public.pem`
- `keys/sign_private.pem`
- `keys/sign_public.pem`
- `client.json`
- `peers.txt`

The init command also prints one copy/paste text block with both public keys.

Send that text block to the peer over chat, messenger, or email.

## Add Peers

After receiving the peer text block, open `peers.txt` and paste it in this form:

```text
bob:
-----BEGIN FILEPIPE PUBLIC KEYS-----
encryption_public_key:
...
signing_public_key:
...
-----END FILEPIPE PUBLIC KEYS-----
```

The first line is only the peer name followed by `:`.

## Send A File

Run this on the client that is sending the file.

Linux:

```bash
.venv/bin/python scripts/send_file.py --peer bob --input file.bin
```

Windows PowerShell:

```powershell
.\.venv\\Scripts\\python.exe scripts/send_file.py --peer bob --input .\\file.bin
```

The command prints JSON containing `object_id`. Send that `object_id` to the peer over the secure side channel.

## Receive A File

Run this on the client that is receiving the file.

Linux:

```bash
.venv/bin/python scripts/receive_file.py --peer bob --object-id=<object-id>
```

Windows PowerShell:

```powershell
.\.venv\\Scripts\\python.exe scripts/receive_file.py --peer bob --object-id=<object-id>
```

By default, the file is saved under the original source filename in the current directory.
Use `--output` only when you want a different path.
Use `--object-id=<value>` exactly in that form.

Flow:

1. Run `scripts/init_client.py --relay ...`.
2. Send the printed public-keys block to the peer.
3. Paste the peer block into `peers.txt` under a name.
4. Send with `scripts/send_file.py --peer <name> --input ...`.
5. Pass `object_id` to the peer.
6. Receive with `scripts/receive_file.py --peer <name> --object-id=<id>`.

## Config

See `config/client.json.example`.

`insecure_skip_verify` disables TLS certificate verification. Use it only for debugging.

Fields:

- `relay_url`
- `cafile`
- `insecure_skip_verify`
- `key_dir`
- `peer_file`
- `chunk_size`
- `expires_in_hours`

`chunk_size` is an operational compatibility setting. If one specific machine stalls on larger uploads, try a smaller value such as `65536`.
