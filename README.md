# MeshCore MQTT→Discord Bridge

A lightweight Python service that connects to MQTT brokers receiving [MeshCore](https://meshcore.io) mesh radio packets, decrypts group channel messages, and forwards them to Discord webhooks.

## Quick Start

```bash
git clone https://github.com/hrochniak/MeshCore-MQTT-Discord-Bridge.git
cd MeshCore-MQTT-Discord-Bridge

pip install -r requirements.txt

cp config.example.yaml config.yaml
# Edit config.yaml — fill in your MQTT broker and Discord webhook URLs

python subscriber.py
```

<details>
<summary>Docker</summary>

```bash
git clone https://github.com/hrochniak/MeshCore-MQTT-Discord-Bridge.git
cd MeshCore-MQTT-Discord-Bridge

cp config.example.yaml config.yaml
# Edit config.yaml

docker compose up -d --build
docker compose logs -f     # view logs
docker compose down        # stop
```

</details>

## Configuration

All configuration lives in a single `config.yaml` file. Only two sections are required — everything else is optional and commented out in `config.example.yaml`.

### MQTT Broker (required)

```yaml
mqtt:
  host: mqtt.example.com
  port: 8883
  username: your_username
  password: your_password
  topic: meshcore/+/packets
```

Port defaults to 8883 with TLS or 1883 without.

#### Multi-broker Support

When multiple MQTT observers see the same mesh traffic, duplicate packets are automatically suppressed and combined into a single Discord message showing path info from all observers:

```yaml
mqtt:
  brokers:
    - host: mqtt.example.com
      name: "Observer-1"
      port: 8883
      username: your_username
      password: your_password
      topic: meshcore/+/packets
    - host: mqtt2.example.com
      name: "Observer-2"
      port: 8883
      username: your_username
      password: your_password
      topic: meshcore/+/packets
```

#### TLS Verification Modes

| Mode | Behaviour |
|------|-----------|
| `true` (default) | Full SSL certificate verification |
| `false` | Skip verification |
| `"hybrid"` | Try verified first, fall back to unverified if cert fails. Sends Discord alerts on fallback and recovery. The watchdog periodically retries secure connections and notifies when the certificate is valid again. |

### Channels (required)

Map MeshCore channel names to Discord webhook URLs. Each channel's messages are decrypted and forwarded to its webhook:

```yaml
channels:
  Public: "https://discord.com/api/webhooks/..."
  "#slovakia": "https://discord.com/api/webhooks/..."
  "#emergency": "https://discord.com/api/webhooks/..."
```

- `Public` (no `#`) — the built-in MeshCore public channel with its fixed firmware key
- `#channelname` — hashtag channels with keys derived from the name via SHA-256
- Channels listed without a webhook URL are still decrypted and logged locally

### Adverts (optional)

Forward MeshCore Advert beacons (node announcements) to a Discord channel. Each Advert includes the device role, a MeshCore contact deep-link (QR code), and Google Maps position:

```yaml
adverts:
  enabled: true
  webhook_url: "https://discord.com/api/webhooks/..."
  # Reference point for distance calculation (optional).
  # When set, each Advert shows distance from this point.
  # If omitted, distance is not displayed.
  home_lat: 48.7305
  home_lon: 19.4571
  filter_roles:             # which device roles to forward
    - companion
    - repeater
    - room
    - sensor
```

Discord output:
```
📡 NodeName
🏷️ Get Contact 📍 Google Maps (12.34 km)
 Region: sk • Direct via Observer-1
```

Role icons: 👤 companion · 📡 repeater · 🏠 room · 🌡️ sensor

### Regions (optional)

MeshCore packets carry transport codes that identify the region. By default these are shown as raw hex (e.g. `0x1A2B`). If you list known region names, the bridge resolves them to human-readable labels in Discord message footers:

```yaml
regions:
  - "sk"
  - "sk-ke"
```

### Error & Debug Webhooks (optional)

```yaml
# Connection errors, script crashes, broker status changes
errors_webhook_url: "https://discord.com/api/webhooks/..."

# When set, ALL messages (channels + adverts + errors) are redirected
# here instead of their normal targets. Useful for development/testing.
debug_webhook_url: "https://discord.com/api/webhooks/..."
```

When `debug_webhook_url` is set, no messages go to the real channel/advert webhooks — everything is routed to the debug channel instead. Clear the value to disable.

### Settings (optional)

```yaml
settings:
  dedup_window: 30        # duplicate suppression window in seconds (default: 30)
  watchdog_timeout: 300   # reconnect if no packet received for this many seconds (default: 300)
```

### Map Uploader (optional)

Automatically upload Advert node positions to the official [MeshCore map](https://map.meshcore.io). Requires an Ed25519 private key for signing upload requests. Each Advert signature is verified before uploading, and duplicate/replay uploads are suppressed:

```yaml
map_uploader:
  enabled: true
  private_key: "your_ed25519_hex_private_key"   # 64 or 128 hex chars
  freq: 433.0      # radio frequency in MHz
  sf: 12           # spread factor
  bw: 125.0        # bandwidth in kHz
  cr: 5            # coding rate
```

## Logging

All output goes to stdout and to a timestamped session log file in `logs/`:

```
logs/
├── session_20250715_143022.log    # full session log
├── session_20250716_091500.log
└── error.log                      # persistent error-only log
```

When running in Docker, mount `./logs` as a volume for log persistence (this is the default in `docker-compose.yml`).

## How It Works

1. **MQTT ingress** — paho-mqtt clients connect to configured brokers, receive raw hex-encoded packets, and enqueue them to a non-blocking queue
2. **Packet parsing** — binary MeshCore packets are decoded: header, routing type, transport codes, path hops, and payload
3. **Decryption** — GroupText payloads are decrypted with AES-128-ECB after HMAC-SHA256 verification using derived channel keys
4. **Deduplication** — SHA256 fingerprint (matching firmware's `calculatePacketHash()`) prevents duplicate processing across multiple brokers
5. **Discord delivery** — messages are sent via webhooks with a 5-second collection window to gather path info from all brokers, then patched with the combined footer
6. **Watchdog** — background thread forces reconnection if no packet is received within the timeout; hybrid TLS mode retries secure connections first

## Discord Message Format

**GroupText:**
```
Hello from the mesh!
 Region: sk-ke • Direct via Observer-1 • 3 hops AB CD EF via Observer-2
```
The sender's MeshCore name is used as the Discord webhook username.

**Advert:**
```
📡 NodeName
🏷️ Get Contact 📍 Google Maps (12.34 km)
 Region: sk • Direct via Observer-1
```

## Project Structure

```
meshcore_bridge/
├── __init__.py        — package marker, version
├── __main__.py        — python -m meshcore_bridge entry point
├── config.py          — config loading, validation, defaults
├── crypto.py          — AES decryption, HMAC, channel key derivation
├── packet_parser.py   — binary MeshCore packet parser
├── logger.py          — logging, error reporting, Discord alerts
├── discord.py         — webhook send / patch
├── dedup.py           — SHA256 fingerprinting, dedup cache
├── formatter.py       — message formatting, haversine distance
├── map_uploader.py    — map.meshcore.io upload with Ed25519 signing
└── mqtt_client.py     — MQTT clients, processing pipeline, watchdog
```

## License

[MIT](LICENSE)
