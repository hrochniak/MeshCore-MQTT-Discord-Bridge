"""Configuration loading, validation, and defaults.

Loads config.yaml, validates required sections, builds derived data
structures (channel lookup, broker list).

Missing optional sections gracefully default instead of crashing.
"""

import os
import sys

import yaml

from .crypto import derive_channel_key, calculate_channel_hash


# ---------------------------------------------------------------------------
# YAML loading and validation
# ---------------------------------------------------------------------------

def _load_yaml(config_path: str) -> dict:
    """Load and validate the YAML configuration file."""
    if os.path.isdir(config_path):
        print(
            f"FATAL: '{config_path}' is a directory, not a file. "
            f"This usually happens in Docker when the config file does not exist "
            f"on the host before the container starts — Docker auto-creates a directory "
            f"in its place. Create config.yaml on the host first, then restart the container.",
            file=sys.stderr
        )
        sys.exit(1)

    if not os.path.isfile(config_path):
        print(
            f"FATAL: Configuration file '{config_path}' not found. "
            f"Please create it from config.example.yaml.",
            file=sys.stderr
        )
        sys.exit(1)

    try:
        with open(config_path, "r") as f:
            raw = yaml.safe_load(f)
    except Exception as e:
        print(f"FATAL: Failed to parse '{config_path}': {e}", file=sys.stderr)
        sys.exit(1)

    if not raw or not isinstance(raw, dict):
        print("FATAL: config.yaml is empty or invalid.", file=sys.stderr)
        sys.exit(1)

    # Required sections — these must exist for the app to function
    if "mqtt" not in raw or not raw["mqtt"] or not isinstance(raw["mqtt"], dict):
        print("FATAL: 'mqtt' section missing, empty, or invalid in config.yaml.", file=sys.stderr)
        sys.exit(1)
    if "channels" not in raw or not raw["channels"] or not isinstance(raw["channels"], (list, dict)):
        print("FATAL: 'channels' section missing, empty, or invalid in config.yaml.", file=sys.stderr)
        sys.exit(1)

    return raw


# ---------------------------------------------------------------------------
# Derived data structures
# ---------------------------------------------------------------------------

def _build_channel_lookup(raw: dict) -> dict:
    """Build channel hash → [(name, key, webhook)] lookup table."""
    channel_lookup = {}
    channels_config = raw.get("channels") or {}
    if isinstance(channels_config, list):
        channels_dict = {ch: "" for ch in channels_config}
    else:
        channels_dict = channels_config

    for ch, webhook in channels_dict.items():
        key = derive_channel_key(ch)
        ch_hash = calculate_channel_hash(key)
        hash_int = ch_hash[0]
        if hash_int not in channel_lookup:
            channel_lookup[hash_int] = []
        channel_lookup[hash_int].append((ch, key, webhook))

    return channel_lookup


def _build_broker_list(raw: dict) -> list:
    """Normalize broker configuration to a list of broker dicts.

    Supports both single-broker (mqtt.host/port) and multi-broker
    (mqtt.brokers[]) configuration formats.  Missing per-broker
    keys fall back to the parent mqtt block.

    Port defaults: 1883 without TLS, 8883 with TLS enabled.
    """
    mqtt_conf = raw["mqtt"]
    brokers = []

    if "brokers" in mqtt_conf and isinstance(mqtt_conf["brokers"], list):
        for b in mqtt_conf["brokers"]:
            tls_explicit = (b.get("tls") if b.get("tls") is not None
                            else mqtt_conf.get("tls", False))
            port = b.get("port") or mqtt_conf.get("port")
            if port is None:
                port = 8883 if tls_explicit else 1883

            brokers.append({
                "name": b.get("name") or b.get("host") or "unknown",
                "host": b.get("host"),
                "port": port,
                "username": b.get("username") or mqtt_conf.get("username"),
                "password": b.get("password") or mqtt_conf.get("password"),
                "topic": (b.get("topic") or mqtt_conf.get("topic")
                          or "meshcore/packets"),
                "tls": tls_explicit,
                "tls_verify": (b.get("tls_verify")
                               if b.get("tls_verify") is not None
                               else mqtt_conf.get("tls_verify", True)),
            })
    else:
        # Fallback to single-broker configuration
        tls_explicit = mqtt_conf.get("tls", False)
        port = mqtt_conf.get("port")
        if port is None:
            port = 8883 if tls_explicit else 1883

        brokers.append({
            "name": mqtt_conf.get("name") or mqtt_conf.get("host") or "unknown",
            "host": mqtt_conf.get("host"),
            "port": port,
            "username": mqtt_conf.get("username"),
            "password": mqtt_conf.get("password"),
            "topic": mqtt_conf.get("topic") or "meshcore/packets",
            "tls": tls_explicit,
            "tls_verify": (mqtt_conf.get("tls_verify")
                           if mqtt_conf.get("tls_verify") is not None
                           else True),
        })

    return brokers


def _build_map_uploader_config(raw: dict) -> dict:
    """Build map uploader config from config.yaml."""
    raw_cfg = raw.get("map_uploader") or {}

    return {
        "enabled": raw_cfg.get("enabled", False),
        "private_key": raw_cfg.get("private_key"),
        "freq": raw_cfg.get("freq", 433.0),
        "sf": int(raw_cfg.get("sf", 12)),
        "bw": raw_cfg.get("bw", 125.0),
        "cr": int(raw_cfg.get("cr", 5)),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_config() -> dict:
    """Load, validate, and return the processed application configuration.

    Returns a flat dict with all config sections resolved, defaults
    applied, and derived data structures built.
    """
    config_path = os.environ.get("MESHCORE_CONFIG", "config.yaml")
    raw = _load_yaml(config_path)

    channel_lookup = _build_channel_lookup(raw)
    brokers = _build_broker_list(raw)

    settings = raw.get("settings") or {}
    adverts_raw = raw.get("adverts") or {}

    adv_enabled = adverts_raw.get("enabled")

    return {
        "channel_lookup": channel_lookup,
        "brokers": brokers,
        "broker_count": len([b for b in brokers if b.get("host")]),
        "adverts": {
            "enabled": adv_enabled if adv_enabled is not None else False,
            "webhook_url": adverts_raw.get("webhook_url") or "",
            "home_lat": adverts_raw.get("home_lat"),
            "home_lon": adverts_raw.get("home_lon"),
            "filter_roles": adverts_raw.get("filter_roles") or [
                "companion", "repeater", "room", "sensor"
            ],
        },
        "regions": raw.get("regions") or [],
        "errors_webhook_url": (raw.get("errors_webhook_url") or "").strip(),
        "debug_webhook_url": (raw.get("debug_webhook_url") or "").strip(),
        "dedup_window": int(settings.get("dedup_window") or 30),
        "watchdog_timeout": int(settings.get("watchdog_timeout") or 300),
        "map_uploader": _build_map_uploader_config(raw),
    }


# ---------------------------------------------------------------------------
# Module-level singleton — loaded once when the package is first imported
# ---------------------------------------------------------------------------
cfg = load_config()
