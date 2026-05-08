# swarmnoise

Automated collector for GreyNoise Project Swarm sensor data, scoped to Fortinet-targeted attack traffic observed by a sensor in Frankfurt, Germany.

Produces a plain-text IP feed compatible with **FortiGate External Threat Feed** (and any other firewall that consumes a newline-separated IP blocklist over HTTPS).

## Threat feeds

### Full feed

```
https://raw.githubusercontent.com/fabs-net/swarmnoise/main/feeds/fortinet_ips.txt
```

All source IPs observed attacking the sensor in the last 30 days. Best coverage, slightly higher false-positive risk.

### Filtered feed

```
https://raw.githubusercontent.com/fabs-net/swarmnoise/main/feeds/fortinet_ips_filtered.txt
```

Subset of the full feed where the session is classified **malicious** by GreyNoise. Sourced from the [GreyNoise v3 Sessions API](https://docs.greynoise.io/reference/getsessions) with Lucene query filtering — no rate-limited enrichment APIs involved. Each IP includes enriched metadata (tags, CVEs, source geo, Suricata signatures) in `feeds/filtered_metadata.json`.

Both feeds:
- One IP per line, no comments, no headers
- Rolling 30-day window — IPs not seen in 30 days are pruned automatically
- Updated 1–10 times per day at randomised times

### FortiGate setup

**Security Fabric → External Connectors → Threat Feeds → IP Address**

| Field | Value |
|---|---|
| Name | `swarmnoise-fortinet` |
| URI | `https://raw.githubusercontent.com/fabs-net/swarmnoise/main/feeds/fortinet_ips.txt` |
| HTTP basic auth | off |
| Refresh rate | 60 min |

For the lower false-positive filtered feed, use `fortinet_ips_filtered.txt` as the URI instead.

Then reference the connector in a firewall policy with action **Deny** or in an IPS sensor.

## How it works

A GitHub Actions workflow fires **every hour**. Each day at midnight UTC it:

1. Picks a random number between **1 and 10** — the number of fetches for that day
2. Distributes those fetches randomly across the remaining hours of the day
3. Persists the schedule in `state/today.json`

Each subsequent hourly check compares the current hour against the schedule and fires a fetch when due. On `workflow_dispatch` (manual trigger) the schedule gate is bypassed and a fetch always runs.

The commit pattern is **organic and unpredictable** — anywhere from 1 to 10 commits per day at random times.

### Two-API architecture

The collector uses two separate GreyNoise API endpoints:

| | Full feed | Filtered feed |
|---|---|---|
| **API** | v1 Swarm (`/v1/workspaces/{id}/sensors/activity`) | v3 Sessions (`/v3/sessions`) |
| **Filter** | None — all sessions | `classification:malicious` (Lucene query) |
| **Page size** | 1,000 | 100 |
| **Pagination** | 30-min time chunks (scroll token unusable) | Standard page-based |
| **Metadata** | Basic (IP, port, protocol) | Rich (tags, CVEs, geo, Suricata) |

### First run (bootstrap)

On the first run `feeds/ip_metadata.json` does not exist, so the script automatically bootstraps the feed by fetching the last 30 days of data. This takes ~37 minutes (1,437 API calls at 0.5 s/call).

### Pagination

The GreyNoise API caps responses at 1,000 sessions per request. The scroll/cursor token it returns is ~8 KB of base64 — too large to pass back as a query parameter (HTTP 414) or request header (HTTP 400). Scrolling is therefore not used.

Instead, each fetch window is split into **30-minute chunks**. At the observed sensor rate (~2,000 sessions/30 min) some chunks still hit the 1,000-session cap and a subset of sessions in those windows may be missed. The IP feed is still comprehensive — unique attacker IPs converge quickly across repeated fetches.

## Repository structure

```
swarmnoise/
├── .github/workflows/
│   └── scheduler.yml              # Hourly trigger, randomised schedule logic + fetch
├── scripts/
│   └── fetch_sessions.py          # v1 full feed + v3 filtered feed, run log
├── feeds/
│   ├── fortinet_ips.txt           # Full IP blocklist (one IP per line)
│   ├── fortinet_ips_filtered.txt  # Filtered feed (malicious IPs only)
│   ├── ip_metadata.json           # Per-IP first_seen/last_seen (full feed)
│   └── filtered_metadata.json    # Per-IP enriched metadata (filtered feed)
├── runs/                          # Run log JSON files (always written)
├── state/
│   └── today.json                 # Daily schedule state
├── requirements.txt
└── README.md
```

## GitHub Secrets required

Set these under **Settings → Secrets and variables → Actions**:

| Secret | Description |
|---|---|
| `GREYNOISE_API_KEY` | GreyNoise API key (viz.greynoise.io → Settings → API Key) |
| `WORKSPACE_ID` | GreyNoise workspace UUID |
| `SENSOR_ID` | Swarm sensor UUID (viz.greynoise.io → Observe → Sensors) |

`GITHUB_TOKEN` is used automatically by Actions for commits — no PAT required.

## File schemas

**`feeds/ip_metadata.json`** — rolling 30-day IP index
```json
{
  "192.0.2.1": { "first_seen": "2026-04-05T09:00:00Z", "last_seen": "2026-05-05T10:26:00Z" }
}
```

**`runs/YYYY-MM-DD_HHMM_run_log.json`** — always written, even if no sessions found
```json
{
  "timestamp": "2026-05-05T12:00:00Z",
  "time_window_start": "2026-05-05T06:00:00Z",
  "time_window_end": "2026-05-05T12:00:00Z",
  "sessions_found": 412,
  "feed_ip_count": 1349,
  "filtered_ip_count": 87,
  "duration_seconds": 8.3,
  "error": null
}
```

**`feeds/filtered_metadata.json`** — per-IP enriched metadata (filtered feed only)
```json
{
  "192.0.2.1": {
    "first_seen": "2026-04-05T09:00:00Z",
    "last_seen": "2026-05-05T10:26:00Z",
    "classification": "malicious",
    "tags": ["Mirai TCP Scanner", "Mirai"],
    "tag_categories": ["worm"],
    "tag_intentions": ["malicious"],
    "cves": [],
    "country": "United States",
    "country_code": "US",
    "asn": "AS32181",
    "org": "GigeNET",
    "is_vpn": false,
    "is_tor": false,
    "is_bot": false,
    "rdns": "host.example.com",
    "destination_ports": [23, 80],
    "protocols": ["tcp"],
    "suricata_signatures": ["Mirai TCP Scanner"]
  }
}
```

## Querying data locally

```bash
# Show current feed IP count
wc -l feeds/fortinet_ips.txt

# Show enriched metadata for all malicious IPs
jq '.' feeds/filtered_metadata.json
```
