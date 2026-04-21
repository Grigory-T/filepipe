from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def key_id_from_public_bytes(public_key_bytes: bytes) -> str:
    return hashlib.sha256(public_key_bytes).hexdigest()[:16]
