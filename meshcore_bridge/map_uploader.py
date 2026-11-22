"""MeshCore map uploader — uploads Advert nodes to map.meshcore.io.

Verifies Ed25519 Advert signatures, deduplicates by public key,
signs upload requests with a local private key, and POSTs to the
official MeshCore map API.
"""

import hashlib
import json
import threading
import time

import requests
from Crypto.Signature import eddsa

from .config import cfg
from .logger import log, log_error


# ---------------------------------------------------------------------------
# Upload deduplication state
# ---------------------------------------------------------------------------
_map_seen_adverts: dict = {}
_map_seen_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------

def _verify_advert_signature_bytes(payload_bytes: bytes) -> bool:
    """Verify the Ed25519 signature of an Advert packet.

    An Advert's signature is payload_bytes[36:100] over the message:
    payload_bytes[0:32] (publicKey) + payload_bytes[32:36] (timestamp)
    + payload_bytes[100:] (appData / flags + rest)
    using public key payload_bytes[0:32].
    """
    if len(payload_bytes) < 101:
        return False
    pubkey_bytes = payload_bytes[0:32]
    sig_bytes = payload_bytes[36:100]
    msg_to_verify = pubkey_bytes + payload_bytes[32:36] + payload_bytes[100:]
    try:
        pub_key = eddsa.import_public_key(pubkey_bytes)
        verifier = eddsa.new(pub_key, "rfc8032")
        verifier.verify(msg_to_verify, sig_bytes)
        return True
    except Exception as e:
        log(f"[WARN] Map Advert signature verification failed: {e}")
        return False


def _extract_advert_payload_bytes(raw_hex: str) -> bytes | None:
    """Extract only the payload bytes, skipping routing and path headers."""
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

    # Skip path length byte + path bytes
    if len(data) < offset + 1:
        return None
    path_len_byte = data[offset]
    offset += 1
    hash_size  = (path_len_byte >> 6) + 1
    hop_count  = path_len_byte & 63
    path_bytes = hop_count * hash_size
    remaining = len(data) - offset
    if hash_size == 4 or path_bytes > remaining:
        path_bytes = min(path_len_byte, remaining, 64)
    offset += path_bytes

    return data[offset:]


# ---------------------------------------------------------------------------
# Upload processing
# ---------------------------------------------------------------------------

def process_map_upload(raw_hex: str, parsed: dict):
    """Process Advert packet and upload to map.meshcore.io if enabled."""
    map_cfg = cfg["map_uploader"]
    if not map_cfg["enabled"]:
        return

    # Check if Advert has valid coordinates (must be present and not 0.0/0.0)
    has_loc = parsed.get("has_location", False)
    lat = parsed.get("latitude")
    lon = parsed.get("longitude")

    if not has_loc or lat is None or lon is None or (lat == 0.0 and lon == 0.0):
        return

    # Verify signature
    payload_bytes = _extract_advert_payload_bytes(raw_hex)
    if not payload_bytes:
        log("[WARN] Map uploader: could not extract payload bytes")
        return

    if not _verify_advert_signature_bytes(payload_bytes):
        log(f"[WARN] Map uploader: Advert signature verification failed "
            f"for node {parsed.get('sender') or 'unknown'}")
        return

    # Deduplicate node uploads (node pubkey / sender_id)
    pub_key = parsed.get("sender_id")
    if not pub_key:
        return
    ts = parsed.get("timestamp", 0)

    now = time.monotonic()
    with _map_seen_lock:
        # Replay attack and throttling check
        if pub_key in _map_seen_adverts:
            seen_ts, seen_mono = _map_seen_adverts[pub_key]
            if ts <= seen_ts:
                log(f"[INFO] Map uploader: ignoring possible replay attack "
                    f"for node {parsed.get('sender') or pub_key[:8]}")
                return
            if ts < seen_ts + 3600:
                log(f"[INFO] Map uploader: ignoring timestamp too new to "
                    f"reupload for node {parsed.get('sender') or pub_key[:8]}")
                return
        _map_seen_adverts[pub_key] = (ts, now)

    # Validate private key
    priv_key_hex = map_cfg.get("private_key")
    if not priv_key_hex or len(priv_key_hex) not in (64, 128):
        log_error(
            f"[ERROR] Map uploader enabled but valid private_key "
            f"(64 or 128 hex characters) is missing "
            f"(got length {len(priv_key_hex) if priv_key_hex else 0})")
        return

    # If 64-byte key (128 hex chars) → combined pub+priv; seed is first 32 bytes
    if len(priv_key_hex) == 128:
        priv_key_hex = priv_key_hex[:64]

    try:
        priv_key_bytes = bytes.fromhex(priv_key_hex)
        priv_key = eddsa.import_private_key(priv_key_bytes)
        uploader_pubkey = priv_key.public_key().export_key(format='raw')
    except Exception as e:
        log_error(f"[ERROR] Map uploader: Failed to parse/import "
                  f"private key: {e}")
        return

    # Build and sign upload payload
    data = {
        "params": {
            "freq": map_cfg["freq"],
            "cr": map_cfg["cr"],
            "sf": map_cfg["sf"],
            "bw": map_cfg["bw"],
        },
        "links": [f"meshcore://{raw_hex.lower()}"]
    }

    try:
        json_str = json.dumps(data, separators=(',', ':'))
        data_hash = hashlib.sha256(json_str.encode('utf-8')).digest()
        signer = eddsa.new(priv_key, 'rfc8032')
        sig_bytes = signer.sign(data_hash)

        request_data = {
            "data": json_str,
            "signature": sig_bytes.hex(),
            "publicKey": uploader_pubkey.hex()
        }

        api_url = "https://map.meshcore.io/api/v1/uploader/node"
        log(f"[INFO] Map uploader: Uploading advert for node "
            f"{parsed.get('sender') or pub_key[:8]} to official map...")

        res = requests.post(api_url, json=request_data, timeout=10)
        res.raise_for_status()
        log(f"[INFO] Map uploader response: {res.json()}")
    except Exception as e:
        log_error(
            f"[ERROR] Map uploader upload failed for node "
            f"{parsed.get('sender') or pub_key[:8]}: {e}")
