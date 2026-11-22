"""MQTT client management, packet processing, and application entry point.

Handles broker connections (single/multi, TLS/hybrid), the packet
processing pipeline (parse → dedup → format → Discord), the worker
thread, the watchdog, and the main() entry point.
"""

import datetime
import json
import queue
import ssl
import threading
import time
import traceback

import paho.mqtt.client as mqtt
import requests

from .config import cfg
from . import logger
from .logger import log, log_error, send_error_to_discord, get_hostname, get_git_commit
from .discord import send_to_discord, patch_discord_message
from .dedup import packet_fingerprint, get_dedup_entry, dedup_lock
from .formatter import (
    get_compact_hop_info, assemble_paths_footer,
    build_group_text_content, build_advert_content,
)
from .packet_parser import parse_packet
from .map_uploader import process_map_upload


# ---------------------------------------------------------------------------
# Module state
# ---------------------------------------------------------------------------

# Packet queue — on_message enqueues, worker thread processes.
# This keeps the MQTT loop unblocked so no packets are dropped.
_packet_queue: queue.Queue = queue.Queue()

# Watchdog state
_last_packet_time = time.monotonic()
_mqtt_clients: list = []  # List of all active MQTT client instances

# Broker connection state tracking
_broker_connection_states: dict = {}
_broker_states_lock = threading.Lock()
_connections_initialized = False

# Hybrid TLS fallback tracking
_broker_fallback_active: dict = {}

# Graceful shutdown flag — suppresses Discord notifications during Ctrl+C
_shutting_down = False


# ---------------------------------------------------------------------------
# Broker health monitoring
# ---------------------------------------------------------------------------

def _check_all_brokers_down():
    """Check if all configured MQTT brokers are currently disconnected.

    Raises a rate-limited critical error if so.
    """
    if _shutting_down or not _connections_initialized:
        return
    with _broker_states_lock:
        if not _broker_connection_states:
            return
        all_down = all(not state
                       for state in _broker_connection_states.values())
    if all_down:
        log_error("All brokers are disconnected.", all_brokers_failed=True)


# ---------------------------------------------------------------------------
# MQTT callbacks
# ---------------------------------------------------------------------------

def on_connect(client, userdata, flags, rc, properties=None):
    """MQTT connect callback — subscribes to topic, tracks broker state,
    and handles hybrid SSL recovery notifications."""
    global _last_packet_time
    client_config = userdata or {}
    topic = client_config.get("topic") or "meshcore/packets"
    host = client_config.get("host", "unknown")

    if rc == 0:
        log(f"[INFO] Connected to MQTT broker ({host}). "
            f"Subscribing to: {topic}")
        client.subscribe(topic)
        _last_packet_time = time.monotonic()
        logger.in_watchdog_reconnect = False

        # Update broker connection state
        current_fallback = client_config.get("_current_fallback", False)
        with _broker_states_lock:
            _broker_connection_states[host] = True

        tls_mode = client_config.get("_tls_verify_mode", True)

        # 1) If we recovered back to secure SSL after a fallback warning
        if (not current_fallback
                and _broker_fallback_active.get(host) is True):
            _broker_fallback_active[host] = False
            fallback_alert_key = f"fallback_{host}"
            logger.reported_broker_errors.discard(fallback_alert_key)
            send_error_to_discord(
                f"**🟢 MQTT Connection Recovered with SSL Verification "
                f"({host})**\n"
                "The broker connection has been successfully established "
                "and verified using the SSL certificate."
            )

        # 2) If connected securely but config is still set to 'hybrid'
        elif not current_fallback and tls_mode == "hybrid":
            hybrid_warning_key = f"hybrid_prompt_{host}"
            if hybrid_warning_key not in logger.reported_broker_errors:
                logger.reported_broker_errors.add(hybrid_warning_key)
                send_error_to_discord(
                    f"**ℹ️ MQTT Broker Verification Reminder ({host}):**\n"
                    "Connection is securely verified using SSL. The config "
                    "is still set to 'hybrid' — you can revert it back to "
                    "'true' in config.yaml."
                )
    else:
        with _broker_states_lock:
            _broker_connection_states[host] = False
        log_error(
            f"[ERROR] MQTT connection failed for {host} with code {rc}",
            broker_host=host)
        _check_all_brokers_down()


def on_disconnect(client, userdata, flags, rc, properties=None):
    """MQTT disconnect callback — updates broker state and checks health."""
    if _shutting_down:
        return
    client_config = userdata or {}
    host = client_config.get("host", "unknown")
    with _broker_states_lock:
        _broker_connection_states[host] = False
    log_error(f"[WARN] MQTT Disconnected from {host} with reason code {rc}",
              broker_host=host)
    _check_all_brokers_down()


def on_message(client, userdata, msg):
    """MQTT message callback — enqueue the raw event immediately and return.

    All processing happens in the worker thread to keep this non-blocking.
    """
    global _last_packet_time
    _last_packet_time = time.monotonic()
    client_config = userdata or {}
    _packet_queue.put((msg, client_config))


# ---------------------------------------------------------------------------
# Dedup-aware Discord dispatch
# ---------------------------------------------------------------------------

def _dispatch_deduplicated(dedup_entry, broker_name, hop_info, parsed,
                           build_content_fn, webhook_url, username):
    """Common dedup-aware send/patch pattern for Discord messages.

    On first arrival: starts a delayed-send thread (waits up to 5s to
    collect paths from multiple brokers, or triggers early when all
    brokers have reported).

    On subsequent arrivals: updates paths, patches the existing Discord
    message with the new footer.
    """
    if not dedup_entry:
        return

    with dedup_lock:
        if hop_info not in dedup_entry["paths"]:
            dedup_entry["paths"].append(hop_info)
        if not dedup_entry["region"]:
            dedup_entry["region"] = parsed.get("region")
        is_initial = not dedup_entry["has_sent_initial"]
        if is_initial:
            dedup_entry["has_sent_initial"] = True
            dedup_entry["brokers"].add(broker_name)

    if is_initial:
        def send_delayed():
            # Wait up to 5s (non-blocking, can be signaled early)
            dedup_entry["delay_finished_event"].wait(timeout=5.0)

            with dedup_lock:
                content = build_content_fn(dedup_entry)
                dedup_entry["discord_content"] = content

            res = send_to_discord(webhook_url, username, content, wait=True)
            if res and "id" in res:
                with dedup_lock:
                    dedup_entry["discord_message_id"] = res["id"]
                    dedup_entry["discord_webhook_url"] = webhook_url
                    dedup_entry["discord_username"] = username

            dedup_entry["message_posted_event"].set()

        threading.Thread(target=send_delayed, daemon=True).start()
    else:
        with dedup_lock:
            dedup_entry["brokers"].add(broker_name)
            total_brokers_seen = len(dedup_entry["brokers"])

        # Early send trigger: all configured brokers have reported
        if total_brokers_seen >= cfg["broker_count"]:
            dedup_entry["delay_finished_event"].set()

        # Wait for the initial POST to finish
        posted_ok = dedup_entry["message_posted_event"].wait(timeout=8.0)

        with dedup_lock:
            msg_id      = dedup_entry["discord_message_id"]
            new_content = build_content_fn(dedup_entry)
            url         = dedup_entry["discord_webhook_url"]
            user        = dedup_entry["discord_username"]
            old_content = dedup_entry["discord_content"]
            dedup_entry["discord_content"] = new_content

        # Only patch if the message content actually changed
        if posted_ok and msg_id and url and new_content != old_content:
            patch_discord_message(url, msg_id, user, new_content)


# ---------------------------------------------------------------------------
# Packet processing
# ---------------------------------------------------------------------------

def _process_message(msg, client_config=None):
    """Process a single MQTT message: parse, dedup, format, and send."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    raw_hex = None
    client_config = client_config or {}
    broker_name = (client_config.get("name")
                   or client_config.get("host")
                   or "unknown")

    try:
        payload_str = msg.payload.decode("utf-8")
        event = json.loads(payload_str)
    except Exception:
        return

    raw_hex = event.get("raw")
    if not raw_hex:
        return

    # 1. Log every raw packet (before dedup check)
    log(f"[{now}] RAW  [{broker_name}] {raw_hex}")

    try:
        parsed = parse_packet(raw_hex, cfg["channel_lookup"],
                              known_regions=cfg["regions"])
        if not parsed:
            return

        # 2. Deduplication
        fingerprint = packet_fingerprint(raw_hex)
        dedup_entry = (get_dedup_entry(fingerprint)
                       if fingerprint else None)

        is_dup_packet = False
        if dedup_entry:
            with dedup_lock:
                if broker_name in dedup_entry["brokers"]:
                    log(f"[{now}] DUP  [{broker_name}] "
                        "(suppressed duplicate from same broker)")
                    is_dup_packet = True
                else:
                    dedup_entry["brokers"].add(broker_name)

        if is_dup_packet:
            return

        # Prepare signal metrics (available in event payload)
        rssi = event.get("RSSI")
        if rssi is not None:
            rssi = float(rssi)
        snr = event.get("SNR")
        if snr is not None:
            snr = float(snr)

        hop_info = get_compact_hop_info(parsed, broker_name)

        # --- 3. GroupText ---
        if parsed["packet_type"] == "GroupText":
            if not parsed.get("decrypted"):
                return  # unknown channel, skip silently

            channel = parsed["channel"]
            sender  = parsed.get("sender") or "unknown"
            message = parsed["message"]

            # Structured log line
            log(f"[{now}] MSG  [{broker_name}] {channel}  "
                f"<{sender}>  {message}")

            # Resolve webhook URL for this channel
            candidates = channel_lookup_for(parsed)
            webhook_url = ""
            for ch_name, ch_key, ch_webhook in candidates:
                if ch_name == channel:
                    webhook_url = ch_webhook
                    break

            # Build content callback (closure over message)
            def _build_gt(entry, _msg=message):
                return build_group_text_content(_msg, entry)

            _dispatch_deduplicated(
                dedup_entry, broker_name, hop_info, parsed,
                _build_gt, webhook_url, sender)

        # --- 4. Advert ---
        elif parsed["packet_type"] == "Advert":
            adv = cfg["adverts"]
            if adv["enabled"]:
                role = parsed["role"]
                if role in adv["filter_roles"]:
                    sender    = parsed.get("sender") or "unknown"
                    sender_id = parsed.get("sender_id", "")

                    # Build lat/lon string for log
                    if parsed["has_location"]:
                        lat = parsed["latitude"]
                        lon = parsed["longitude"]
                        loc_str = f"{lat}/{lon}"
                    else:
                        loc_str = "no-location"

                    short_hash = (sender_id[:8]
                                  if sender_id else "????????")
                    log(f"[{now}] ADV  [{broker_name}] {sender}  "
                        f"{short_hash}  {loc_str}")

                    # Build content callback (closure over parsed)
                    def _build_adv(entry, _p=parsed):
                        return build_advert_content(_p, entry)

                    adv_webhook_url = adv["webhook_url"]
                    _dispatch_deduplicated(
                        dedup_entry, broker_name, hop_info, parsed,
                        _build_adv, adv_webhook_url, "Advert")

            # Map Uploader integration — runs independently of Discord
            try:
                process_map_upload(raw_hex, parsed)
            except Exception as e:
                log_error(
                    f"[ERROR] Map uploader failed in processing loop: {e}")

    except Exception:
        err_msg   = traceback.format_exc()
        now_str   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = (
            f"[{now_str}] Error processing message:\n{err_msg}"
            f"Raw Packet: {raw_hex}\n{'-' * 60}"
        )
        log_error(log_entry)

        err_webhook = cfg["errors_webhook_url"]
        if err_webhook:
            content = (
                f"**⚠️ Script Error**\n```python\n{err_msg[-1500:]}\n```\n"
                f"**Raw Packet:**\n`{raw_hex}`"
            )
            payload = {"username": "MeshCore Error Logger",
                       "content": content}
            try:
                requests.post(err_webhook, json=payload, timeout=5)
            except Exception:
                pass


def channel_lookup_for(parsed: dict) -> list:
    """Look up channel webhook candidates from parsed packet info."""
    return cfg["channel_lookup"].get(
        parsed.get("channel_hash_int", -1)) or []


# ---------------------------------------------------------------------------
# Worker thread
# ---------------------------------------------------------------------------

def _worker_thread():
    """Drain the packet queue and process each message sequentially."""
    while True:
        queue_item = _packet_queue.get()
        try:
            if isinstance(queue_item, tuple) and len(queue_item) == 2:
                msg, client_config = queue_item
            else:
                msg = queue_item
                client_config = {}
            _process_message(msg, client_config)
        except Exception:
            log_error(
                f"[ERROR] Worker unhandled exception:\n"
                f"{traceback.format_exc()}")
        finally:
            _packet_queue.task_done()


# ---------------------------------------------------------------------------
# Watchdog thread
# ---------------------------------------------------------------------------

def _watchdog_thread():
    """Background thread — reconnects ALL clients if no packet received
    within watchdog_timeout seconds."""
    global _last_packet_time
    while True:
        time.sleep(30)
        elapsed = time.monotonic() - _last_packet_time
        if elapsed > cfg["watchdog_timeout"] and _mqtt_clients:
            logger.in_watchdog_reconnect = True
            log(
                f"[WARN] Watchdog: no packet for {int(elapsed)}s "
                f"(limit {cfg['watchdog_timeout']}s), forcing reconnect "
                f"on all clients."
            )
            for client in _mqtt_clients:
                host = "unknown"
                b = None
                if (hasattr(client, "_userdata")
                        and isinstance(client._userdata, dict)):
                    b = client._userdata
                    host = b.get("host", "unknown")
                try:
                    # If using hybrid mode, watchdog reconnect always
                    # tries secure SSL first so that if the cert has been
                    # fixed, we recover back to verified mode.
                    if b and b.get("tls_verify") == "hybrid":
                        new_client = _create_client(b, fallback=False)
                        for idx, old_client in enumerate(_mqtt_clients):
                            if old_client is client:
                                try:
                                    old_client.disconnect()
                                    old_client.loop_stop()
                                except Exception:
                                    pass
                                _mqtt_clients[idx] = new_client
                                client = new_client
                                break

                    client.connect(b["host"], b["port"], keepalive=30)
                    client.loop_start()
                except Exception as e:
                    is_ssl_error = (
                        "CERTIFICATE_VERIFY_FAILED" in str(e)
                        or "expired" in str(e)
                        or "verify failed" in str(e))
                    if (b and b.get("tls_verify") == "hybrid"
                            and is_ssl_error):
                        # Fallback reconnect in hybrid mode
                        try:
                            log_error(
                                f"MQTT primary connection failed for "
                                f"{host}:\n{e}",
                                broker_host=host)
                            new_client = _create_client(b, fallback=True)
                            for idx, old_client in enumerate(_mqtt_clients):
                                if old_client is client:
                                    try:
                                        old_client.disconnect()
                                        old_client.loop_stop()
                                    except Exception:
                                        pass
                                    _mqtt_clients[idx] = new_client
                                    client = new_client
                                    break
                            _broker_fallback_active[host] = True
                            client.connect(
                                b["host"], b["port"], keepalive=30)
                            client.loop_start()
                        except Exception as fallback_err:
                            log_error(
                                f"[WARN] Watchdog reconnect failed "
                                f"(both secure and fallback) for "
                                f"{host}: {fallback_err}",
                                broker_host=host)
                            _check_all_brokers_down()
                    else:
                        log_error(
                            f"[WARN] Watchdog reconnect failed for "
                            f"{host}: {e}",
                            broker_host=host)
                        _check_all_brokers_down()


# ---------------------------------------------------------------------------
# MQTT client factory and connection
# ---------------------------------------------------------------------------

def _create_client(b: dict, fallback: bool = False) -> mqtt.Client:
    """Instantiate and configure a new mqtt.Client with correct TLS parameters."""
    host = b["host"]
    port = b["port"]
    tls_verify = b.get("tls_verify", True)

    try:
        client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            userdata=b)
    except AttributeError:
        client = mqtt.Client(userdata=b)

    if b.get("username"):
        client.username_pw_set(b["username"], b.get("password"))

    # Set callbacks
    client.on_connect    = on_connect
    client.on_message    = on_message
    client.on_disconnect = on_disconnect

    # Determine cert validation level
    if b.get("tls") or port == 8883:
        if tls_verify == "hybrid":
            reqs = ssl.CERT_NONE if fallback else ssl.CERT_REQUIRED
        else:
            reqs = ssl.CERT_REQUIRED if tls_verify else ssl.CERT_NONE

        # Fresh context configuration
        client.tls_set(cert_reqs=reqs, tls_version=ssl.PROTOCOL_TLS_CLIENT)
        if reqs == ssl.CERT_NONE:
            client._ssl_context.check_hostname = False

    # Store flags in userdata to pass down to callbacks
    b["_current_fallback"] = fallback
    b["_tls_verify_mode"] = tls_verify
    return client


def _connect_client(client, b: dict, fallback: bool = False):
    """Connect a client, supporting hybrid fallback by rebuilding if necessary."""
    host = b["host"]
    port = b["port"]
    tls_verify = b.get("tls_verify", True)

    # If fallback is requested, rebuild the client instance to avoid
    # SSLContext contamination
    if fallback or (hasattr(client, "_ssl_context")
                    and client._ssl_context is not None):
        client = _create_client(b, fallback=fallback)
        # Update master list so watchdog targets the correct instance
        for idx, old_client in enumerate(_mqtt_clients):
            if (hasattr(old_client, "_userdata")
                    and isinstance(old_client._userdata, dict)
                    and old_client._userdata.get("host") == host):
                try:
                    old_client.disconnect()
                    old_client.loop_stop()
                except Exception:
                    pass
                _mqtt_clients[idx] = client
                break

    log(f"[INFO] Connecting to broker {host}:{port} "
        f"(verify: {tls_verify}, fallback: {fallback}) ...")
    client.connect(host, port, keepalive=30)

    # Save fallback active state globally
    _broker_fallback_active[host] = fallback

    # Trigger Discord notification once per session when fallback occurs
    if fallback:
        fallback_alert_key = f"fallback_{host}"
        if fallback_alert_key not in logger.reported_broker_errors:
            logger.reported_broker_errors.add(fallback_alert_key)
            send_error_to_discord(
                f"**⚠️ MQTT Broker Fallback ({host}):**\n"
                "Connection was established in fallback mode "
                "(without verification)."
            )

    client.loop_start()
    return client


# ---------------------------------------------------------------------------
# Application entry point
# ---------------------------------------------------------------------------

def main():
    """Application entry point: log config, connect brokers, run forever."""
    global _connections_initialized, _shutting_down

    logger.open_session_log()
    log(f"[INFO] Session log: {logger.SESSION_LOG_PATH}")
    log("[INFO] Configured Channels:")
    for hash_int, ch_list in cfg["channel_lookup"].items():
        for ch, key, webhook in ch_list:
            log(f"  - {ch} -> hash_int: {hash_int} (0x{hash_int:02x}) "
                f"| key: {key.hex()}")

    commit_sha = get_git_commit()
    send_error_to_discord(
        f"**🟢 Script started/restarted** (commit: `{commit_sha}`)")

    log(f"[INFO] Watchdog timeout: {cfg['watchdog_timeout']}s "
        f"| Dedup window: {cfg['dedup_window']}s")

    # Start background threads
    threading.Thread(target=_watchdog_thread, daemon=True).start()
    threading.Thread(target=_worker_thread, daemon=True).start()

    # Initialize broker connection states
    for b in cfg["brokers"]:
        if b["host"]:
            _broker_connection_states[b["host"]] = False

    # Connect to all configured brokers
    for b in cfg["brokers"]:
        if not b["host"]:
            continue
        try:
            client = _create_client(b, fallback=False)
            try:
                client = _connect_client(client, b, fallback=False)
            except Exception as e:
                # If hybrid mode and SSL verification failure → try fallback
                is_ssl_error = (
                    "CERTIFICATE_VERIFY_FAILED" in str(e)
                    or "expired" in str(e)
                    or "verify failed" in str(e))
                if b.get("tls_verify") == "hybrid" and is_ssl_error:
                    log_error(
                        f"MQTT primary connection failed for "
                        f"{b['host']}:\n{e}",
                        broker_host=b["host"])
                    try:
                        client = _connect_client(
                            client, b, fallback=True)
                    except Exception as fallback_err:
                        log_error(
                            f"[ERROR] MQTT fallback connection also "
                            f"failed for {b['host']}: {fallback_err}",
                            broker_host=b["host"])
                        _check_all_brokers_down()
                else:
                    log_error(
                        f"[ERROR] Failed to connect/initialize broker "
                        f"{b['host']}: {e}",
                        broker_host=b["host"])
                    _check_all_brokers_down()

            _mqtt_clients.append(client)
        except Exception as e:
            log_error(
                f"[ERROR] Failed to connect/initialize broker "
                f"{b['host']}: {e}",
                broker_host=b["host"])
            _check_all_brokers_down()

    _connections_initialized = True

    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        _shutting_down = True
        log("\n[INFO] Shutting down.")
        for client in _mqtt_clients:
            client.disconnect()
            client.loop_stop()
    except Exception as e:
        log_error(f"[FATAL] System Error: {e}")
    finally:
        logger.close_session_log()
