from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import crypto


def generate_keyset(output_dir: str | Path, name: str) -> dict[str, Any]:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)

    sign_private = crypto.generate_signing_private_key()
    sign_public = sign_private.public_key()
    enc_private = crypto.generate_encryption_private_key()
    enc_public = enc_private.public_key()

    (directory / "sign_private.pem").write_bytes(crypto.ed25519_private_to_pem(sign_private))
    (directory / "sign_public.pem").write_bytes(crypto.ed25519_public_to_pem(sign_public))
    (directory / "enc_private.pem").write_bytes(crypto.x25519_private_to_pem(enc_private))
    (directory / "enc_public.pem").write_bytes(crypto.x25519_public_to_pem(enc_public))

    metadata = {
        "name": name,
        "signing_key_id": crypto.public_key_id(crypto.ed25519_public_bytes_raw(sign_public)),
        "encryption_key_id": crypto.public_key_id(crypto.x25519_public_bytes_raw(enc_public)),
    }
    (directory / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return metadata


def load_local_keyset(directory: str | Path) -> dict[str, Any]:
    path = Path(directory)
    sign_private = crypto.load_ed25519_private_key((path / "sign_private.pem").read_bytes())
    sign_public = crypto.load_ed25519_public_key((path / "sign_public.pem").read_bytes())
    enc_private = crypto.load_x25519_private_key((path / "enc_private.pem").read_bytes())
    enc_public = crypto.load_x25519_public_key((path / "enc_public.pem").read_bytes())
    metadata_path = path / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8")) if metadata_path.exists() else {}
    metadata.setdefault("signing_key_id", crypto.public_key_id(crypto.ed25519_public_bytes_raw(sign_public)))
    metadata.setdefault("encryption_key_id", crypto.public_key_id(crypto.x25519_public_bytes_raw(enc_public)))
    return {
        "directory": str(path),
        "metadata": metadata,
        "sign_private": sign_private,
        "sign_public": sign_public,
        "enc_private": enc_private,
        "enc_public": enc_public,
    }
