# swarmnoise

Automated collector for GreyNoise Project Swarm sensor data, scoped to Fortinet-targeted attack traffic observed by a sensor in Frankfurt, Germany.

Produces a plain-text IP feed compatible with **FortiGate External Threat Feed** (and any other firewall that consumes a newline-separated IP blocklist over HTTPS).

## Threat feed

```
https://raw.githubusercontent.com/fabs-xyz/swarmnoise/main/feeds/fortinet_ips.txt
```

- One IP per line, no comments, no headers
- Rolling 30-day window — IPs not seen in 30 days are pruned automatically
- Updated 1–10 times per day at randomised times
- Currently ~1,300+ unique attacker IPs

### FortiGate setup

**Security Fabric → External Connectors → Threat Feeds → IP Address**

| Field | Value |
|---|---|
| Name | `swarmnoise-fortinet` |
| URI | `https://raw.githubusercontent.com/fabs-xyz/swarmnoise/main/feeds/fortinet_ips.txt` |
| HTTP basic auth | off |
| Refresh rate | 60 min |

Then reference `swarmnoise-fortinet` in a firewall policy with action **Deny** or in an IPS sensor.

## How it works

A GitHub Actions workflow fires **every hour**. Each day at midnight UTC it:

1. Picks a random number between **1 and 10** — the number of fetches for that day
2. Distributes those fetches randomly across the remaining hours of the day
3. Persists the schedule in `state/today.json`

Each subsequent hourly check compares the current hour against the schedule and fires a fetch when due. On `workflow_dispatch` (manual trigger) the schedule gate is bypassed and a fetch always runs.

The commit pattern is **organic and unpredictable** — anywhere from 1 to 10 commits per day at random times.

### First run (bootstrap)

On the first run `feeds/ip_metadata.json` does not exist, so the script automatically bootstraps the feed by fetching the last 30 days of data. This takes ~37 minutes (1,437 API calls at 0.5 s/call).

### Pagination

The GreyNoise API caps responses at 1,000 sessions per request. The scroll/cursor token it returns is ~8 KB of base64 — too large to pass back as a query parameter (HTTP 414) or request header (HTTP 400). Scrolling is therefore not used.

Instead, each fetch window is split into **30-minute chunks**. At the observed sensor rate (~2,000 sessions/30 min) some chunks still hit the 1,000-session cap and a subset of sessions in those windows may be missed. The IP feed is still comprehensive — unique attacker IPs converge quickly across repeated fetches.

## Repository structure

```
swarmnoise/
├── .github/workflows/
│   └── scheduler.yml          # Hourly trigger, randomised schedule logic + fetch
├── scripts/
│   └── fetch_sessions.py      # GreyNoise API fetch, feed update, run log
├── feeds/
│   ├── fortinet_ips.txt       # Public IP blocklist (one IP per line)
│   └── ip_metadata.json       # Per-IP first_seen/last_seen metadata
├── data/                      # Session JSON files (one per non-bootstrap run)
├── runs/                      # Run log JSON files (always written)
├── state/
│   └── today.json             # Daily schedule state
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

**`data/YYYY-MM-DD_HHMM.json`** — raw session data (non-bootstrap runs only)
```json
{
  "fetch_timestamp": "2026-05-05T12:00:00Z",
  "sensor_id": "...",
  "workspace_id": "...",
  "time_window_start": "2026-05-05T06:00:00Z",
  "time_window_end": "2026-05-05T12:00:00Z",
  "session_count": 412,
  "sessions": [
    {
      "session_id": "...",
      "source_ip": "192.0.2.1",
      "source_port": 54321,
      "destination_ip": "...",
      "destination_port": 443,
      "start_time": "2026-05-05T06:01:00Z",
      "stop_time": "2026-05-05T06:01:02Z",
      "protocols": ["tcp"],
      "packets": 4,
      "bytes": 240,
      "http_uri": null
    }
  ]
}
```

**`runs/YYYY-MM-DD_HHMM_run_log.json`** — always written, even if no sessions found
```json
{
  "timestamp": "2026-05-05T12:00:00Z",
  "sensor_id": "...",
  "workspace_id": "...",
  "time_window_start": "2026-05-05T06:00:00Z",
  "time_window_end": "2026-05-05T12:00:00Z",
  "sessions_found": 412,
  "feed_ip_count": 1349,
  "duration_seconds": 8.3,
  "error": null
}
```

## Querying data locally

```bash
# Count total sessions across all data files
jq '[.[].session_count] | add' data/*.json

# List all unique attacker IPs from raw session data
jq -r '[.[].sessions[].source_ip] | unique[]' data/*.json

# Show current feed IP count
wc -l feeds/fortinet_ips.txt
```
