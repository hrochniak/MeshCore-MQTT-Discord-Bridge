"""MeshCore cryptographic primitives.

Handles channel key derivation, channel hash calculation, and
AES-128-ECB decryption with HMAC-SHA256 verification for GroupText messages.
"""

import hashlib
import re
import struct
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256


# The built-in "Public" channel uses a fixed, well-known key
# that is NOT derived from the channel name via SHA-256.
# See: https://meshcore.io / MeshCore Companion Protocol docs
PUBLIC_CHANNEL_KEY = bytes.fromhex('8b3387e9c5cdea6ac9e5edbaa115cd72')

def derive_channel_key(channel_name: str) -> bytes:
    """
    Computes first 16 bytes of SHA256(normalized channel_name).
    Prepends '#' if missing for hashtag channels.
    
    Special case: The built-in "Public" channel (without '#') uses
    a fixed, well-known key that is hardcoded in MeshCore firmware.
    """
    if channel_name == "Public":
        return PUBLIC_CHANNEL_KEY
    name = channel_name if channel_name.startswith('#') else '#' + channel_name
    sha = hashlib.sha256(name.encode('utf-8')).digest()
    return sha[:16]

def calculate_channel_hash(channel_key: bytes) -> bytes:
    """
    Calculates channel hash as the first byte of SHA256(channel_key)
    """
    sha = hashlib.sha256(channel_key).digest()
    return sha[:1]

def decrypt_group_text(ciphertext: bytes, cipher_mac: bytes, channel_key: bytes) -> dict | None:
    """
    Verifies message integrity using HMAC-SHA256 and decrypts with AES-128-ECB.
    """
    # 1. Verify HMAC-SHA256 using 32-byte padded channel secret
    channel_secret = channel_key + b'\x00' * 16
    
    hmac_obj = HMAC.new(channel_secret, ciphertext, digestmod=SHA256)
    calculated_mac = hmac_obj.digest()[:2]
    
    if calculated_mac != cipher_mac:
        return None
    
    # 2. Decrypt using AES-128 ECB with first 16 bytes of channel secret
    try:
        cipher = AES.new(channel_key, AES.MODE_ECB)
        decrypted = cipher.decrypt(ciphertext)
    except Exception:
        return None
        
    if len(decrypted) < 5:
        return None
        
    # 3. Parse MeshCore format: timestamp(4) + flags(1) + message_text
    timestamp = struct.unpack('<I', decrypted[0:4])[0]
    flags_and_attempt = decrypted[4]
    
    # Extract message text with UTF-8 decoding
    message_bytes = decrypted[5:]
    # Remove null padding / termination
    null_idx = message_bytes.find(b'\x00')
    if null_idx >= 0:
        message_bytes = message_bytes[:null_idx]
        
    try:
        message_text = message_bytes.decode('utf-8')
    except UnicodeDecodeError:
        try:
            message_text = message_bytes.decode('utf-8', errors='replace')
        except Exception:
            return None

    # Parse sender and message (format: "sender: message")
    colon_index = message_text.find(': ')
    sender = None
    content = message_text
    
    if 0 < colon_index < 50:
        potential_sender = message_text[:colon_index]
        if not re.search(r'[:\[\]]', potential_sender):
            sender = potential_sender
            content = message_text[colon_index + 2:]
            
    return {
        "timestamp": timestamp,
        "flags": flags_and_attempt,
        "sender": sender,
        "message": content
    }
