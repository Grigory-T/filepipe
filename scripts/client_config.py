from __future__ import annotations

import json
import re
from pathlib import Path

from scripts.peer_card import parse_peer_cards


def load_config(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validate_peer_name(peer_name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", peer_name):
        raise ValueError("peer name must use only letters, numbers, dot, dash, or underscore")
    return peer_name


def load_peer(config: dict, peer_name: str) -> dict[str, str]:
    peer_name = validate_peer_name(peer_name)
    peer_file = Path(config.get("peer_file", "./peers.txt"))
    peers = parse_peer_cards(peer_file.read_text(encoding="utf-8"))
    if peer_name not in peers:
        raise ValueError(f"unknown peer: {peer_name}")
    return peers[peer_name]
