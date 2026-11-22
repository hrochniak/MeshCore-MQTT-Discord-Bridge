"""Packet deduplication cache and fingerprinting.

Tracks seen packets across multiple MQTT brokers to suppress duplicates
and enable Discord message patching with multi-observer path info.
"""

import hashlib
import threading
import time

from .config import cfg


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEDUP_WINDOW_SECS = cfg["dedup_window"]

# ---------------------------------------------------------------------------
# Dedup cache state
# ---------------------------------------------------------------------------
_dedup_cache: dict = {}
dedup_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------

def packet_fingerprint(raw_hex: str) -> str | None:
    """Compute SHA256(payload_type_byte + payload_bytes) from raw hex.

    Matches MeshCore firmware's calculatePacketHash() — strips routing
    header, transport codes, and path so the same message from different
    routes produces the same fingerprint.
    """
    try:
        data = bytes.fromhex(raw_hex)
    except ValueError:
        return None
    if len(data) < 2:
        return None

    header = data[0]
    route_type = header & 0x03
    offset = 1

    # Skip transport codes (4 bytes) if present
    if route_type in (0, 3):
        if len(data) < offset + 4:
            return None
        offset += 4

    # Skip path_len byte + path bytes
    if len(data) < offset + 1:
        return None
    path_len_byte = data[offset]
    offset += 1
    hash_size  = (path_len_byte >> 6) + 1
    hop_count  = path_len_byte & 63
    path_bytes = hop_count * hash_size
    # Legacy fallback (same as parser)
    remaining = len(data) - offset
    if hash_size == 4 or path_bytes > remaining:
        path_bytes = min(path_len_byte, remaining, 64)
    offset += path_bytes

    payload = data[offset:]
    if not payload:
        return None

    payload_type = (header >> 2) & 0x0F
    digest = hashlib.sha256(bytes([payload_type]) + payload).hexdigest()
    return digest


# ---------------------------------------------------------------------------
# Dedup entry management
# ---------------------------------------------------------------------------

def get_dedup_entry(fingerprint: str) -> dict | None:
    """Retrieve or create a deduplication entry for the fingerprint.

    Evicts expired entries first.  Each entry tracks:
    - time: monotonic timestamp of first seen
    - brokers: set of broker names that sent this packet
    - discord_message_id/webhook_url/username/content: for patching
    - has_sent_initial: bool — whether first Discord send is done
    - message_posted_event: Event — signals when Discord POST completes
    - delay_finished_event: Event — triggers early send
    - paths: list of formatted path strings for the compact layout
    - region: parsed region name to be prefixed once
    """
    now = time.monotonic()
    with dedup_lock:
        # Evict expired entries
        expired = [k for k, entry in _dedup_cache.items()
                    if now - entry["time"] > DEDUP_WINDOW_SECS]
        for k in expired:
            del _dedup_cache[k]

        if fingerprint in _dedup_cache:
            return _dedup_cache[fingerprint]

        # Create new entry
        entry = {
            "time": now,
            "brokers": set(),
            "discord_message_id": None,
            "discord_webhook_url": None,
            "discord_username": None,
            "discord_content": None,
            "has_sent_initial": False,
            "message_posted_event": threading.Event(),
            "delay_finished_event": threading.Event(),
            "paths": [],
            "region": None,
        }
        _dedup_cache[fingerprint] = entry
        return entry
