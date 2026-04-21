from __future__ import annotations

import hashlib
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from . import crypto, keys
from .http_client import RelayHttpClient
from .manifest import sha256_hex

DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024


def utc_timestamp(hours_from_now: int) -> tuple[str, str]:
    created_at = datetime.now(timezone.utc).replace(microsecond=0)
    expires_at = created_at + timedelta(hours=hours_from_now)
    return (
        created_at.isoformat().replace("+00:00", "Z"),
        expires_at.isoformat().replace("+00:00", "Z"),
    )


def _chunk_iter(handle: Any, chunk_size: int):
    while True:
        chunk = handle.read(chunk_size)
        if chunk == b"":
            break
        yield chunk


def _build_manifest(
    object_id: str,
    original_name: str,
    created_at: str,
    expires_at: str,
    sender_keyset: dict[str, Any],
    recipient_public_key,
    wrap_info: dict[str, str],
    nonce_prefix: bytes,
    plaintext_size: int,
    chunk_size: int,
    chunks: list[dict[str, Any]],
    total_ciphertext_sha256: str,
) -> dict[str, Any]:
    return {
        "protocol": "filepipe-poc/v1",
        "object_id": object_id,
        "created_at": created_at,
        "expires_at": expires_at,
        "original_name": original_name,
        "plaintext_size": plaintext_size,
        "chunk_size": chunk_size,
        "chunk_count": len(chunks),
        "ciphertext_sha256": total_ciphertext_sha256,
        "sender_signing_key_id": sender_keyset["metadata"]["signing_key_id"],
        "recipient_encryption_key_id": crypto.public_key_id(crypto.x25519_public_bytes_raw(recipient_public_key)),
        "algorithms": {
            "manifest_signature": "Ed25519",
            "content_encryption": "AES-256-GCM-chunked",
            "content_key_wrap": wrap_info["algorithm"],
        },
        "content_key_wrap": wrap_info,
        "nonce_prefix": crypto.b64e(nonce_prefix),
        "chunks": chunks,
    }


def send_file(
    relay_url: str,
    cafile: str | None,
    insecure_skip_verify: bool,
    sender_key_dir: str,
    recipient_public_key_path: str,
    input_path: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    expires_in_hours: int = 24,
) -> dict[str, Any]:
    client = RelayHttpClient(relay_url, cafile=cafile, insecure_skip_verify=insecure_skip_verify)
    sender_keys = keys.load_local_keyset(sender_key_dir)
    recipient_public_key = crypto.load_x25519_public_key(Path(recipient_public_key_path).read_bytes())

    object_id = crypto.random_token()
    created_at, expires_at = utc_timestamp(expires_in_hours)
    content_key = os.urandom(32)
    nonce_prefix = os.urandom(8)
    wrap_info = crypto.build_wrapped_content_key(object_id, content_key, recipient_public_key)

    plaintext_size = 0
    chunks_meta: list[dict[str, Any]] = []
    total_ciphertext_hasher = hashlib.sha256()
    input_file = Path(input_path)

    with tempfile.TemporaryDirectory(prefix="filepipe-send-") as tmp_dir:
        tmp_root = Path(tmp_dir)
        with input_file.open("rb") as source:
            chunk_index = 0
            saw_any = False
            for plaintext in _chunk_iter(source, chunk_size):
                saw_any = True
                plaintext_size += len(plaintext)
                ciphertext = crypto.encrypt_chunk(content_key, nonce_prefix, object_id, chunk_index, plaintext)
                (tmp_root / f"{chunk_index:08d}.chunk").write_bytes(ciphertext)
                total_ciphertext_hasher.update(ciphertext)
                chunks_meta.append(
                    {
                        "index": chunk_index,
                        "plaintext_size": len(plaintext),
                        "ciphertext_size": len(ciphertext),
                        "sha256": sha256_hex(ciphertext),
                    }
                )
                chunk_index += 1

            if not saw_any:
                ciphertext = crypto.encrypt_chunk(content_key, nonce_prefix, object_id, 0, b"")
                (tmp_root / "00000000.chunk").write_bytes(ciphertext)
                total_ciphertext_hasher.update(ciphertext)
                chunks_meta.append(
                    {
                        "index": 0,
                        "plaintext_size": 0,
                        "ciphertext_size": len(ciphertext),
                        "sha256": sha256_hex(ciphertext),
                    }
                )

        manifest = _build_manifest(
            object_id=object_id,
            original_name=input_file.name,
            created_at=created_at,
            expires_at=expires_at,
            sender_keyset=sender_keys,
            recipient_public_key=recipient_public_key,
            wrap_info=wrap_info,
            nonce_prefix=nonce_prefix,
            plaintext_size=plaintext_size,
            chunk_size=chunk_size,
            chunks=chunks_meta,
            total_ciphertext_sha256=total_ciphertext_hasher.hexdigest(),
        )
        signature = crypto.sign_manifest(manifest, sender_keys["sign_private"])

        client.post_json(
            "/v1/uploads",
            {
                "object_id": object_id,
                "created_at": created_at,
                "expires_at": expires_at,
                "chunk_count": len(chunks_meta),
                "original_name": input_file.name,
            },
        )

        for chunk_meta in chunks_meta:
            ciphertext = (tmp_root / f"{chunk_meta['index']:08d}.chunk").read_bytes()
            client.put_bytes(f"/v1/uploads/{object_id}/chunks/{chunk_meta['index']}", ciphertext)

        client.post_json(f"/v1/uploads/{object_id}/finalize", {"manifest": manifest, "signature": signature})

    return {
        "object_id": object_id,
        "expires_at": expires_at,
        "chunk_count": len(chunks_meta),
        "sender_signing_key_id": sender_keys["metadata"]["signing_key_id"],
        "recipient_encryption_key_id": manifest["recipient_encryption_key_id"],
    }


def receive_file(
    relay_url: str,
    cafile: str | None,
    insecure_skip_verify: bool,
    recipient_key_dir: str,
    sender_public_key_path: str,
    object_id: str,
    output_path: str | None = None,
) -> dict[str, Any]:
    client = RelayHttpClient(relay_url, cafile=cafile, insecure_skip_verify=insecure_skip_verify)
    envelope = client.get_json(f"/v1/objects/{object_id}/manifest")
    manifest = envelope["manifest"]
    signature = envelope["signature"]

    sender_public_key = crypto.load_ed25519_public_key(Path(sender_public_key_path).read_bytes())
    crypto.verify_manifest_signature(manifest, signature, sender_public_key)

    recipient_keys = keys.load_local_keyset(recipient_key_dir)
    recipient_key_id = recipient_keys["metadata"]["encryption_key_id"]
    if manifest["recipient_encryption_key_id"] != recipient_key_id:
        raise ValueError("manifest recipient key does not match local key")

    content_key = crypto.unwrap_content_key(
        manifest["object_id"],
        manifest["content_key_wrap"],
        recipient_keys["enc_private"],
    )
    nonce_prefix = crypto.b64d(manifest["nonce_prefix"])
    total_ciphertext_hasher = hashlib.sha256()
    plaintext_size = 0

    output = Path(output_path or manifest["original_name"])
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as sink:
        for chunk_meta in manifest["chunks"]:
            ciphertext = client.get_bytes(f"/v1/objects/{object_id}/chunks/{chunk_meta['index']}")
            if sha256_hex(ciphertext) != chunk_meta["sha256"]:
                raise ValueError(f"chunk hash mismatch for chunk {chunk_meta['index']}")
            if len(ciphertext) != chunk_meta["ciphertext_size"]:
                raise ValueError(f"chunk size mismatch for chunk {chunk_meta['index']}")
            total_ciphertext_hasher.update(ciphertext)
            plaintext = crypto.decrypt_chunk(content_key, nonce_prefix, object_id, chunk_meta["index"], ciphertext)
            if len(plaintext) != chunk_meta["plaintext_size"]:
                raise ValueError(f"plaintext size mismatch for chunk {chunk_meta['index']}")
            sink.write(plaintext)
            plaintext_size += len(plaintext)

    if total_ciphertext_hasher.hexdigest() != manifest["ciphertext_sha256"]:
        raise ValueError("total ciphertext hash mismatch")
    if plaintext_size != manifest["plaintext_size"]:
        raise ValueError("plaintext size mismatch")

    return {
        "object_id": object_id,
        "output_path": str(output),
        "plaintext_size": plaintext_size,
        "original_name": manifest["original_name"],
    }
