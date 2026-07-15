"""Discord message formatting for GroupText and Advert packets.

Provides content builders, path/hop formatting helpers, and the
haversine distance calculator.  All formatting logic is centralised
here so it is defined once and reused for both initial sends and
subsequent patches.
"""

import math
import urllib.parse

from .config import cfg


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ROLE_ICONS = {
    "companion": "👤",
    "repeater":  "📡",
    "room":      "🏠",
    "sensor":    "🌡️",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_compact_hop_info(parsed: dict, observer: str) -> str:
    """Format hop info compactly.

    Examples:
        Direct via Dungeon
        5 hops 14 BA 3E via Gabik
    """
    if parsed.get("hop_count", 0) == 0:
        return f"Direct via {observer}"
    p_str = " ".join(parsed["path"]) if parsed.get("path") else ""
    return f"{parsed['hop_count']} hops {p_str} via {observer}"


def assemble_paths_footer(dedup_entry: dict) -> str:
    """Assemble the footer line from collected paths and region.

    Must be called while holding dedup_lock.

    Example output:
        Region: sk-ke • Direct via Dungeon • 3 hops AB CD via Gabik
    """
    combined_paths = " • ".join(dedup_entry["paths"])
    reg = dedup_entry["region"]
    if reg and reg != "unknown" and not reg.startswith("0x"):
        return f"Region: {reg} • {combined_paths}"
    return combined_paths


def calculate_distance(lat1: float, lon1: float,
                       lat2: float, lon2: float) -> float | None:
    """Calculate haversine distance between two points in kilometres."""
    try:
        dlat = math.radians(lat1 - lat2)
        dlon = math.radians(lon1 - lon2)
        a = (math.sin(dlat / 2) ** 2
             + math.cos(math.radians(lat2))
             * math.cos(math.radians(lat1))
             * math.sin(dlon / 2) ** 2)
        return 6371.0 * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Content builders
# ---------------------------------------------------------------------------

def build_group_text_content(message: str, dedup_entry: dict) -> str:
    """Build Discord message content for a GroupText packet.

    Must be called while holding dedup_lock.
    """
    footer = assemble_paths_footer(dedup_entry)
    return f"{message}\n-# {footer}"


def build_advert_content(parsed: dict, dedup_entry: dict) -> str:
    """Build Discord message content for an Advert packet.

    Must be called while holding dedup_lock.
    """
    sender    = parsed.get("sender") or "unknown"
    sender_id = parsed.get("sender_id", "")
    role      = parsed["role"]
    role_id   = parsed.get("role_id", 1)

    role_icon  = ROLE_ICONS.get(role, "⚙️")
    first_line = f"{role_icon} **{sender}**"

    # Build meshcore:// deep link → QR / contact info page
    enc_name      = urllib.parse.quote_plus(sender)
    meshcore_link = (f"meshcore://contact/add?name={enc_name}"
                     f"&public_key={sender_id}&type={role_id}")
    encoded_uri      = urllib.parse.quote_plus(meshcore_link)
    contact_info_url = (f"https://tools.meshcore.ninja/qr"
                        f"?mode=test&uri={encoded_uri}")

    second_line_parts = [f"🏷️ [Get Contact](<{contact_info_url}>)"]

    if parsed.get("has_location"):
        lat = parsed["latitude"]
        lon = parsed["longitude"]
        maps_url = f"https://www.google.com/maps?q={lat},{lon}"
        dist_str = ""
        home_lat = cfg["adverts"]["home_lat"]
        home_lon = cfg["adverts"]["home_lon"]
        if home_lat is not None and home_lon is not None:
            dist_km = calculate_distance(
                lat, lon, float(home_lat), float(home_lon))
            if dist_km is not None:
                dist_str = f" ({dist_km:.2f} km)"
        second_line_parts.append(
            f"📍 [Google Maps](<{maps_url}>){dist_str}")

    footer = assemble_paths_footer(dedup_entry)
    return (first_line + "\n"
            + " ".join(second_line_parts)
            + f"\n-# {footer}")
