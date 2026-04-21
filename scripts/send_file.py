from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.client_config import load_config, load_peer
from filepipe.transfer import send_file


def _write_temp_pem(text: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
    except Exception:
        os.unlink(path)
        raise
    return path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="./client.json")
    parser.add_argument("--peer", required=True)
    parser.add_argument("--input", required=True)
    args = parser.parse_args()

    config = load_config(args.config)
    peer = load_peer(config, args.peer)
    temp_path = _write_temp_pem(peer["enc_public_pem"])
    try:
        result = send_file(
            relay_url=config["relay_url"],
            cafile=config.get("cafile"),
            insecure_skip_verify=bool(config.get("insecure_skip_verify", False)),
            sender_key_dir=config["key_dir"],
            recipient_public_key_path=temp_path,
            input_path=args.input,
            chunk_size=int(config.get("chunk_size", 8 * 1024 * 1024)),
            expires_in_hours=int(config.get("expires_in_hours", 24)),
        )
    finally:
        os.unlink(temp_path)
    result["peer"] = args.peer
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
