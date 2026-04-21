from __future__ import annotations

import base64
import os
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .manifest import canonical_json_bytes, key_id_from_public_bytes

WRAP_INFO = b"filepipe-wrap-v1"
CHUNK_AAD_PREFIX = b"filepipe-chunk-v1:"


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text.encode("ascii"))


def random_token(num_bytes: int = 24) -> str:
    return b64e(os.urandom(num_bytes)).rstrip("=")


def generate_signing_private_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


def generate_encryption_private_key() -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.generate()


def public_key_id(public_key_bytes: bytes) -> str:
    return key_id_from_public_bytes(public_key_bytes)


def ed25519_private_to_pem(key: ed25519.Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def ed25519_public_to_pem(key: ed25519.Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def x25519_private_to_pem(key: x25519.X25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def x25519_public_to_pem(key: x25519.X25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_ed25519_private_key(data: bytes) -> ed25519.Ed25519PrivateKey:
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise TypeError("Expected Ed25519 private key")
    return key


def load_ed25519_public_key(data: bytes) -> ed25519.Ed25519PublicKey:
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise TypeError("Expected Ed25519 public key")
    return key


def load_x25519_private_key(data: bytes) -> x25519.X25519PrivateKey:
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, x25519.X25519PrivateKey):
        raise TypeError("Expected X25519 private key")
    return key


def load_x25519_public_key(data: bytes) -> x25519.X25519PublicKey:
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, x25519.X25519PublicKey):
        raise TypeError("Expected X25519 public key")
    return key


def ed25519_public_bytes_raw(key: ed25519.Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def x25519_public_bytes_raw(key: x25519.X25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def sign_manifest(manifest: dict[str, Any], private_key: ed25519.Ed25519PrivateKey) -> str:
    return b64e(private_key.sign(canonical_json_bytes(manifest)))


def verify_manifest_signature(manifest: dict[str, Any], signature_b64: str, public_key: ed25519.Ed25519PublicKey) -> None:
    public_key.verify(b64d(signature_b64), canonical_json_bytes(manifest))


def build_wrapped_content_key(
    object_id: str,
    content_key: bytes,
    recipient_public_key: x25519.X25519PublicKey,
) -> dict[str, str]:
    ephemeral_private = x25519.X25519PrivateKey.generate()
    shared_secret = ephemeral_private.exchange(recipient_public_key)
    salt = os.urandom(16)
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=WRAP_INFO,
    ).derive(shared_secret)
    nonce = os.urandom(12)
    wrapped_key = AESGCM(wrapping_key).encrypt(nonce, content_key, object_id.encode("utf-8"))
    return {
        "algorithm": "X25519+HKDF-SHA256+AES-256-GCM",
        "ephemeral_public_key": b64e(x25519_public_bytes_raw(ephemeral_private.public_key())),
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "ciphertext": b64e(wrapped_key),
    }


def unwrap_content_key(
    object_id: str,
    wrapped_info: dict[str, str],
    recipient_private_key: x25519.X25519PrivateKey,
) -> bytes:
    ephemeral_public = x25519.X25519PublicKey.from_public_bytes(b64d(wrapped_info["ephemeral_public_key"]))
    shared_secret = recipient_private_key.exchange(ephemeral_public)
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b64d(wrapped_info["salt"]),
        info=WRAP_INFO,
    ).derive(shared_secret)
    return AESGCM(wrapping_key).decrypt(
        b64d(wrapped_info["nonce"]),
        b64d(wrapped_info["ciphertext"]),
        object_id.encode("utf-8"),
    )


def encrypt_chunk(content_key: bytes, nonce_prefix: bytes, object_id: str, index: int, plaintext: bytes) -> bytes:
    if len(nonce_prefix) != 8:
        raise ValueError("nonce_prefix must be 8 bytes")
    nonce = nonce_prefix + index.to_bytes(4, "big")
    aad = CHUNK_AAD_PREFIX + object_id.encode("utf-8") + b":" + index.to_bytes(4, "big")
    return AESGCM(content_key).encrypt(nonce, plaintext, aad)


def decrypt_chunk(content_key: bytes, nonce_prefix: bytes, object_id: str, index: int, ciphertext: bytes) -> bytes:
    nonce = nonce_prefix + index.to_bytes(4, "big")
    aad = CHUNK_AAD_PREFIX + object_id.encode("utf-8") + b":" + index.to_bytes(4, "big")
    return AESGCM(content_key).decrypt(nonce, ciphertext, aad)
