"""MeshCore binary packet parser.

Parses raw hex-encoded MeshCore mesh packets into structured dictionaries.
Supports GroupText (decryption), Advert (location/identity), and generic types.
"""

import hashlib
import hmac
import struct

from .crypto import decrypt_group_text

ROUTE_TYPES = {
    0: "TransportFlood",
    1: "Flood",
    2: "Direct",
    3: "TransportDirect"
}

PAYLOAD_TYPES = {
    0: "Request",
    1: "Response",
    2: "TextMessage",
    3: "Ack",
    4: "Advert",
    5: "GroupText",
    6: "GroupData",
    7: "AnonRequest",
    8: "Path",
    9: "Trace",
    10: "Multipart",
    11: "Control",
    15: "RawCustom"
}

DEVICE_ROLES = {
    1: "companion",
    2: "repeater",
    3: "room",
    4: "sensor"
}

def parse_packet(hex_data: str, channel_lookup: dict, known_regions: list = None) -> dict | None:
    """
    Parses a MeshCore packet from raw hex string.
    Returns a normalized dictionary of the parsed contents, or None if invalid.
    """
    try:
        bytes_data = bytes.fromhex(hex_data)
    except ValueError:
        return None

    if len(bytes_data) < 2:
        return None

    offset = 0

    # 1. Parse header
    header = bytes_data[offset]
    route_type_val = header & 0x03
    payload_type_val = (header >> 2) & 0x0F
    payload_version = (header >> 6) & 0x03
    offset += 1

    route_type = ROUTE_TYPES.get(route_type_val, f"Unknown ({route_type_val})")
    payload_type = PAYLOAD_TYPES.get(payload_type_val, f"Unknown ({payload_type_val})")

    # 2. Parse transport codes
    transport_codes = None
    if route_type_val in (0, 3):  # TransportFlood or TransportDirect
        if len(bytes_data) < offset + 4:
            return None
        code_0 = struct.unpack('<H', bytes_data[offset:offset+2])[0]
        code_1 = struct.unpack('<H', bytes_data[offset+2:offset+4])[0]
        transport_codes = [code_0, code_1]
        offset += 4

    # 3. Parse path length byte
    if len(bytes_data) < offset + 1:
        return None
    path_len_byte = bytes_data[offset]
    offset += 1

    hash_size = (path_len_byte >> 6) + 1
    hop_count = path_len_byte & 63
    path_byte_length = hop_count * hash_size
    
    payload_start = offset
    remaining_after_path = len(bytes_data) - payload_start
    
    use_legacy = False
    if hash_size == 4:
        use_legacy = True
    elif path_byte_length > remaining_after_path:
        use_legacy = True
        
    if use_legacy:
        path_byte_length = min(path_len_byte, remaining_after_path, 64)
        hop_count = path_byte_length
        hash_size = 1

    if len(bytes_data) < offset + path_byte_length:
        return None

    # 4. Parse path data
    path = []
    if hop_count > 0:
        path_bytes = bytes_data[offset:offset+path_byte_length]
        for i in range(hop_count):
            hop = path_bytes[i * hash_size : (i + 1) * hash_size]
            path.append(hop.hex().upper())
        offset += path_byte_length

    # 5. Extract payload bytes
    payload_bytes = bytes_data[offset:]
    
    # 6. Parse based on Payload Type
    parsed_payload = None

    region_name = "unknown"
    if route_type_val in (0, 3) and len(bytes_data) >= 5:
        tc0 = struct.unpack('<H', bytes_data[1:3])[0]
        region_name = f"0x{tc0:04X}"
        if known_regions:
            for r in known_regions:
                r_name = r if (r.startswith('#') or r.startswith('$')) else '#' + r
                r_key = hashlib.sha256(r_name.encode('utf-8')).digest()[:16]
                hmac_data = bytes([payload_type_val]) + payload_bytes
                hmac_mac = hmac.new(r_key, hmac_data, digestmod=hashlib.sha256).digest()
                code = struct.unpack('<H', hmac_mac[:2])[0]
                if code == 0: code += 1
                elif code == 0xFFFF: code -= 1
                if code == tc0:
                    region_name = r
                    break

    if payload_type_val == 5:  # GroupText
        if len(payload_bytes) < 3:
            return None
        channel_hash = payload_bytes[0]
        cipher_mac = payload_bytes[1:3]
        ciphertext = payload_bytes[3:]

        # Lookup candidates list in channel_lookup
        candidates = channel_lookup.get(channel_hash)
        if not candidates:
            # We don't monitor/have key for this channel
            return {
                "packet_type": "GroupText",
                "route_type": route_type.lower(),
                "channel_hash": f"0x{channel_hash:02X}",
                "region": region_name,
                "decrypted": False,
                "path": path,
                "hop_count": hop_count,
            }

        # Try decrypting with each candidate key until one succeeds
        decrypted_data = None
        matched_channel_name = None
        for ch_name, ch_key, webhook in candidates:
            decrypted_data = decrypt_group_text(ciphertext, cipher_mac, ch_key)
            if decrypted_data:
                matched_channel_name = ch_name
                break
        
        if decrypted_data:
            return {
                "packet_type": "GroupText",
                "route_type": route_type.lower(),
                "channel": matched_channel_name,
                "channel_hash": f"0x{channel_hash:02X}",
                "channel_hash_int": channel_hash,
                "region": region_name,
                "sender": decrypted_data.get("sender"),
                "message": decrypted_data["message"],
                "path": path,
                "hop_count": hop_count,
                "decrypted": True,
                "sender_id": None,
            }
        else:
            # Just report with the first candidate name
            fallback_name = candidates[0][0]
            return {
                "packet_type": "GroupText",
                "route_type": route_type.lower(),
                "channel": fallback_name,
                "channel_hash": f"0x{channel_hash:02X}",
                "region": region_name,
                "decrypted": False,
                "error": "MAC verification or decryption failed for all candidates",
                "path": path,
                "hop_count": hop_count,
            }

    elif payload_type_val == 4:  # Advert
        if len(payload_bytes) < 101:
            return None
        
        pubkey = payload_bytes[0:32].hex().upper()
        timestamp = struct.unpack('<I', payload_bytes[32:36])[0]
        signature = payload_bytes[36:100].hex().upper()
        flags = payload_bytes[100]
        
        role_val = flags & 0x0F
        role = DEVICE_ROLES.get(role_val, "companion")
        
        has_location = bool(flags & 0x10)
        has_feature1 = bool(flags & 0x20)
        has_feature2 = bool(flags & 0x40)
        has_name = bool(flags & 0x80)
        
        payload_offset = 101
        
        latitude = None
        longitude = None
        if has_location and len(payload_bytes) >= payload_offset + 8:
            lat_raw = struct.unpack('<i', payload_bytes[payload_offset:payload_offset+4])[0]
            lon_raw = struct.unpack('<i', payload_bytes[payload_offset+4:payload_offset+8])[0]
            latitude = round(lat_raw / 1000000.0, 6)
            longitude = round(lon_raw / 1000000.0, 6)
            payload_offset += 8
            
        if has_feature1:
            payload_offset += 2
        if has_feature2:
            payload_offset += 2
            
        name = None
        if has_name and len(payload_bytes) > payload_offset:
            name_bytes = payload_bytes[payload_offset:]
            # Strip nulls and sanitize control chars
            null_idx = name_bytes.find(b'\x00')
            if null_idx >= 0:
                name_bytes = name_bytes[:null_idx]
            try:
                name = name_bytes.decode('utf-8').strip()
                # Clean control characters
                name = "".join(ch for ch in name if ord(ch) >= 32)
            except Exception:
                pass
                
        return {
            "packet_type": "Advert",
            "route_type": route_type.lower(),
            "sender_id": pubkey,
            "sender": name,
            "timestamp": timestamp,
            "signature": signature,
            "role": role,
            "role_id": role_val,
            "has_location": has_location,
            "latitude": latitude,
            "longitude": longitude,
            "path": path,
            "hop_count": hop_count,
            "region": region_name,
        }

    return {
        "packet_type": payload_type,
        "route_type": route_type.lower(),
        "path": path,
        "hop_count": hop_count,
        "region": region_name,
    }
