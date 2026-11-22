#!/usr/bin/env python3
"""MeshCore MQTT→Discord Bridge — entry point.

Usage:
    python subscriber.py
    python -m meshcore_bridge
"""

from meshcore_bridge.mqtt_client import main

if __name__ == "__main__":
    main()
