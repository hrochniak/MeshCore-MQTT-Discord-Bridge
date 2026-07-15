"""Logging, error reporting, and Discord error notifications.

Provides session logging (stdout + file), persistent error logging,
and rate-limited Discord error delivery with per-broker deduplication.
"""

import datetime
import os
import sys
import time

import requests

from .config import cfg


# ---------------------------------------------------------------------------
# Session and error log paths
# ---------------------------------------------------------------------------
os.makedirs("logs", exist_ok=True)

_session_ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
SESSION_LOG_PATH = os.path.join("logs", f"session_{_session_ts}.log")
ERROR_LOG_PATH   = os.path.join("logs", "error.log")

_log_file = None


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def get_git_commit() -> str:
    """Get the current abbreviated git commit SHA using pure Python."""
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        # Go one level up to the project root where .git lives
        project_root = os.path.dirname(script_dir)
        git_dir = os.path.join(project_root, ".git")
        if not os.path.isdir(git_dir):
            return "unknown"

        head_path = os.path.join(git_dir, "HEAD")
        if not os.path.isfile(head_path):
            return "unknown"

        with open(head_path, "r", encoding="utf-8") as f:
            head_content = f.read().strip()

        if head_content.startswith("ref:"):
            ref_subpath = head_content.split(" ", 1)[1]
            ref_path = os.path.join(git_dir, ref_subpath)
            if os.path.isfile(ref_path):
                with open(ref_path, "r", encoding="utf-8") as f:
                    return f.read().strip()[:7]
            else:
                packed_path = os.path.join(git_dir, "packed-refs")
                if os.path.isfile(packed_path):
                    with open(packed_path, "r", encoding="utf-8") as f:
                        for line in f:
                            if line.strip() and not line.startswith("#"):
                                parts = line.strip().split()
                                if len(parts) == 2 and parts[1] == ref_subpath:
                                    return parts[0][:7]
        else:
            return head_content[:7]
    except Exception:
        pass
    return "unknown"


def get_hostname() -> str:
    """Get the host/server name.

    Resolves SERVER_HOSTNAME env var if present (for Docker),
    falling back to socket.gethostname().
    """
    import socket
    return os.environ.get("SERVER_HOSTNAME") or socket.gethostname()


# ---------------------------------------------------------------------------
# Session log management
# ---------------------------------------------------------------------------

def open_session_log():
    """Open the session log file for writing."""
    global _log_file
    try:
        _log_file = open(SESSION_LOG_PATH, "a", encoding="utf-8", buffering=1)
    except OSError as e:
        print(f"Warning: Cannot open session log {SESSION_LOG_PATH}: {e}",
              file=sys.stderr)


def close_session_log():
    """Close the session log file."""
    global _log_file
    if _log_file:
        _log_file.close()
        _log_file = None


def log(line: str):
    """Write a line to stdout AND to the session log file."""
    print(line, flush=True)
    if _log_file:
        try:
            _log_file.write(line + "\n")
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Error reporting state — shared across modules
# ---------------------------------------------------------------------------

# Re-entrancy guard: prevents log_error → send_error_to_discord → log_error loops
_in_error_delivery = False

# Set by watchdog to suppress general error Discord spam during reconnects
in_watchdog_reconnect = False

# Per-broker error deduplication (set of broker hostnames / alert keys)
reported_broker_errors: set = set()

# Rate limiting for "all brokers down" critical alert
_last_all_brokers_failed_time = 0.0


# ---------------------------------------------------------------------------
# Discord error delivery
# ---------------------------------------------------------------------------

def send_error_to_discord(content: str):
    """Send an error/status notification to the errors Discord channel.

    If debug_webhook_url is configured, routes there exclusively instead.
    """
    target = (cfg["debug_webhook_url"]
              if cfg["debug_webhook_url"]
              else cfg["errors_webhook_url"])
    if not target:
        return

    sender_name = get_hostname()
    payload = {"username": sender_name, "content": content}
    try:
        response = requests.post(target, json=payload, timeout=5)
        response.raise_for_status()
    except Exception as e:
        # Use basic log to avoid recursion — don't call log_error here
        log(f"[ERROR] Failed to send error to Discord: {e}")


# ---------------------------------------------------------------------------
# Error logging with Discord notification
# ---------------------------------------------------------------------------

def log_error(msg: str, broker_host: str = None, all_brokers_failed: bool = False):
    """Write error to stderr AND to the persistent error log file,
    and send it to Discord with deduplication.

    Args:
        msg: Error message text.
        broker_host: If set, deduplicates per-broker (reports only once per session).
        all_brokers_failed: If True, throttles "all down" alert to once per hour.
    """
    print(msg, file=sys.stderr, flush=True)
    try:
        with open(ERROR_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
    except OSError as e:
        print(f"Warning: Could not write to {ERROR_LOG_PATH}: {e}",
              file=sys.stderr)

    global _in_error_delivery, _last_all_brokers_failed_time
    if _in_error_delivery:
        return

    # Rate-limited "all brokers down" critical alert (once per hour)
    if all_brokers_failed:
        now_mono = time.monotonic()
        if now_mono - _last_all_brokers_failed_time >= 3600.0:
            _last_all_brokers_failed_time = now_mono
            _in_error_delivery = True
            try:
                send_error_to_discord(
                    "**🚨 CRITICAL: All MQTT brokers are down!**")
            finally:
                _in_error_delivery = False
        return

    # Per-broker error deduplication (report once per session per host)
    if broker_host:
        if broker_host not in reported_broker_errors:
            reported_broker_errors.add(broker_host)
            _in_error_delivery = True
            try:
                if "\n" in msg:
                    parts = msg.split("\n", 1)
                    header = parts[0]
                    body = parts[1]
                    formatted_msg = f"**⚠️ {header}**\n```\n{body}\n```"
                else:
                    formatted_msg = f"**⚠️ {msg}**"
                send_error_to_discord(formatted_msg)
            finally:
                _in_error_delivery = False
        return

    # Default general error logging (suppressed during watchdog reconnect)
    if not in_watchdog_reconnect:
        _in_error_delivery = True
        try:
            send_error_to_discord(
                f"**⚠️ System Error/Warning:**\n```\n{msg[-1900:]}\n```")
        finally:
            _in_error_delivery = False
