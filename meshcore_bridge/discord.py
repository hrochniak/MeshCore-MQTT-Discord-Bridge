"""Discord webhook operations.

Handles sending, patching, and debug-redirecting Discord webhook messages.
"""

import urllib.parse

import requests

from .config import cfg
from .logger import get_hostname, log_error


# ---------------------------------------------------------------------------
# Discord webhook delivery
# ---------------------------------------------------------------------------

def send_to_discord(webhook_url: str, username: str, content: str,
                    wait: bool = False) -> dict | None:
    """Send a message to a Discord webhook.

    If debug_webhook_url is configured, redirects ALL messages there instead.
    Returns the Discord API response dict when *wait* is True and successful.
    """
    target = (cfg["debug_webhook_url"]
              if cfg["debug_webhook_url"]
              else webhook_url)
    if not target:
        return None

    # Hostname is allowed ONLY in debug and error channels.
    # If the target is the debug channel, we can append the hostname.
    # Otherwise, it goes to public channels, so we keep the username clean.
    if cfg["debug_webhook_url"] and target == cfg["debug_webhook_url"]:
        sender_name = f"{username} ({get_hostname()})"
    else:
        sender_name = username

    # Suppress embeds by adding flags parameter
    payload = {"username": sender_name, "content": content, "flags": 4096}
    params = {}
    if wait:
        params["wait"] = "true"

    try:
        response = requests.post(target, json=payload, params=params, timeout=5)
        response.raise_for_status()
        if wait:
            return response.json()
    except Exception as e:
        log_error(f"[ERROR] Webhook delivery failed for {username} to {target}: {e}")
    return None


def patch_discord_message(webhook_url: str, message_id: str,
                          username: str, content: str):
    """Patch/Edit an existing Discord message sent via webhook."""
    target = (cfg["debug_webhook_url"]
              if cfg["debug_webhook_url"]
              else webhook_url)
    if not target:
        return

    # Build PATCH URL: /webhooks/{id}/{token}/messages/{message_id}
    parsed_url = urllib.parse.urlparse(target)
    path = parsed_url.path.rstrip('/')
    patch_path = f"{path}/messages/{message_id}"

    patch_url = urllib.parse.urlunparse((
        parsed_url.scheme,
        parsed_url.netloc,
        patch_path,
        parsed_url.params,
        parsed_url.query,
        parsed_url.fragment
    ))

    if cfg["debug_webhook_url"] and target == cfg["debug_webhook_url"]:
        sender_name = f"{username} ({get_hostname()})"
    else:
        sender_name = username

    payload = {"username": sender_name, "content": content, "flags": 4096}
    try:
        response = requests.patch(patch_url, json=payload, timeout=5)
        response.raise_for_status()
    except Exception as e:
        log_error(f"[ERROR] Failed to patch Discord message {message_id}: {e}")
