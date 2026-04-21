from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from filepipe.keys import generate_keyset
from scripts.peer_card import render_peer_template, render_public_keys_card


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key-dir", default="./keys")
    parser.add_argument("--relay", required=True)
    parser.add_argument("--config", default="./client.json")
    parser.add_argument("--peer-text-file", default="./peers.txt")
    args = parser.parse_args()

    key_dir = Path(args.key_dir)
    config_path = Path(args.config)
    peer_text_file = Path(args.peer_text_file)

    metadata = generate_keyset(key_dir, "client")
    config_path.parent.mkdir(parents=True, exist_ok=True)
    peer_text_file.parent.mkdir(parents=True, exist_ok=True)

    config = {
        "relay_url": args.relay,
        "cafile": None,
        "key_dir": str(key_dir),
        "peer_file": str(peer_text_file),
        "chunk_size": 8 * 1024 * 1024,
        "expires_in_hours": 24,
    }
    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

    enc_public_pem = (key_dir / "enc_public.pem").read_text(encoding="utf-8").strip()
    sign_public_pem = (key_dir / "sign_public.pem").read_text(encoding="utf-8").strip()
    public_keys_text = render_public_keys_card(enc_public_pem, sign_public_pem)
    if not peer_text_file.exists():
        peer_text_file.write_text(render_peer_template(), encoding="utf-8")

    print(f"created: {config_path}")
    print(f"created: {key_dir}")
    print(f"created: {peer_text_file}")
    print()
    print("copy and send this text block to the peer:")
    print()
    print(public_keys_text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
