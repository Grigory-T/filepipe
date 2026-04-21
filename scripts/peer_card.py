from __future__ import annotations

BEGIN_MARKER = "-----BEGIN FILEPIPE PUBLIC KEYS-----"
END_MARKER = "-----END FILEPIPE PUBLIC KEYS-----"


def render_public_keys_card(enc_public_pem: str, sign_public_pem: str) -> str:
    return (
        f"{BEGIN_MARKER}\n"
        "encryption_public_key:\n"
        f"{enc_public_pem.strip()}\n\n"
        "signing_public_key:\n"
        f"{sign_public_pem.strip()}\n"
        f"{END_MARKER}\n"
    )


def render_peer_template() -> str:
    return (
        "# Add peers here.\n"
        "# Format:\n"
        "# alice:\n"
        "# -----BEGIN FILEPIPE PUBLIC KEYS-----\n"
        "# encryption_public_key:\n"
        "# -----BEGIN PUBLIC KEY-----\n"
        "# ...\n"
        "# -----END PUBLIC KEY-----\n"
        "#\n"
        "# signing_public_key:\n"
        "# -----BEGIN PUBLIC KEY-----\n"
        "# ...\n"
        "# -----END PUBLIC KEY-----\n"
        "# -----END FILEPIPE PUBLIC KEYS-----\n"
        "\n"
    )


def parse_peer_cards(text: str) -> dict[str, dict[str, str]]:
    entries: dict[str, dict[str, str]] = {}
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index].strip()
        if not line or line.startswith("#"):
            index += 1
            continue
        if not line.endswith(":"):
            raise ValueError(f"invalid peer line: {lines[index]}")

        peer_name = line[:-1].strip()
        if not peer_name:
            raise ValueError("empty peer name")

        index += 1
        while index < len(lines) and (not lines[index].strip() or lines[index].lstrip().startswith("#")):
            index += 1
        if index >= len(lines) or lines[index].strip() != BEGIN_MARKER:
            raise ValueError(f"missing public keys block for peer: {peer_name}")

        block_lines = [lines[index]]
        index += 1
        while index < len(lines):
            block_lines.append(lines[index])
            if lines[index].strip() == END_MARKER:
                break
            index += 1
        else:
            raise ValueError(f"unterminated public keys block for peer: {peer_name}")

        block = "\n".join(block_lines)
        enc_public_pem = _extract_labeled_public_key(block, "encryption_public_key:")
        sign_public_pem = _extract_labeled_public_key(block, "signing_public_key:")
        entries[peer_name] = {
            "enc_public_pem": enc_public_pem,
            "sign_public_pem": sign_public_pem,
        }
        index += 1

    return entries


def _extract_labeled_public_key(block: str, label: str) -> str:
    label_index = block.find(label)
    if label_index < 0:
        raise ValueError(f"missing {label.rstrip(':')}")

    begin = block.find("-----BEGIN PUBLIC KEY-----", label_index)
    end = block.find("-----END PUBLIC KEY-----", begin)
    if begin < 0 or end < 0 or end <= begin:
        raise ValueError(f"invalid {label.rstrip(':')}")

    return block[begin : end + len("-----END PUBLIC KEY-----")].strip() + "\n"
