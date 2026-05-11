# SwarmNoise

<p align="center">
  <img src="state/swarmnoise-banner_3.png" alt="Swarmnoise banner" />
</p>

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](#)
[![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-Automated-2088FF?logo=githubactions&logoColor=white)](#)
[![Threat Feed](https://img.shields.io/badge/Threat%20Feed-Firewall%20Ready-B22222)](#)
[![GreyNoise](https://img.shields.io/badge/Source-GreyNoise%20Swarm-1F2937)](#)

Automated collector for [GreyNoise Project Swarm](https://www.greynoise.io/project-swarm) sensor activity. Deploys one or more Swarm sensors and produces newline-separated IP threat feeds compatible with any firewall or security platform that supports external IP block lists — including FortiGate, pfSense/OPNsense, Palo Alto Networks (EDL), and others. Monthly snapshots are archived for long-term evidence retention.

---

## Data & Licensing

- **You must provide your own GreyNoise account.** This project uses the GreyNoise API. All use of GreyNoise data is subject to the [GreyNoise EULA](https://www.greynoise.io/terms).
- **No live or real threat data is included in this repository.** Files under `feeds/`, `runs/`, and `state/` contain synthetic example data only. Deploy your own instance and configure your secrets to collect real data.
- GreyNoise is a trademark of GreyNoise Intelligence, Inc. Fortinet, FortiGate, Palo Alto Networks, pfSense, and OPNsense are trademarks of their respective owners. All trademarks are used for identification purposes only.

---

## At a glance

- Scope: attacker source IPs seen by your Swarm sensor(s)
- Output: full feed + filtered feed + high-confidence feed + enriched metadata + run logs + monthly archive
- Multi-sensor: map multiple sensors with human-readable labels; IPs corroborated by 2+ sensors flagged in metadata
- Runtime: GitHub Actions only (no self-hosted infrastructure)
- Update model: randomized 1 to 10 fetches/day via hourly scheduler checks
- Integration: direct HTTPS feed consumption by any firewall supporting external IP block lists
- Access model: private fork with PAT-based HTTP Basic Auth on the firewall (recommended)

---

## Threat feeds

### Full feed

```text
https://raw.githubusercontent.com/<your-org>/<your-repo>/main/feeds/threat_feed.txt
```

All source IPs observed attacking the sensor in the last 30 days. Highest coverage, higher false-positive risk.

### Filtered feed

```text
https://raw.githubusercontent.com/<your-org>/<your-repo>/main/feeds/threat_feed_filtered.txt
```

Malicious and suspicious IPs only, with enriched metadata in `feeds/filtered_metadata.json` (tags, CVEs, geo, ASN/org, Suricata signatures, protocols, destination ports, sensor attribution).

### High-confidence feed

```text
https://raw.githubusercontent.com/<your-org>/<your-repo>/main/feeds/threat_feed_high_confidence.txt
```

Multi-sensor corroborated IPs (seen by 2+ sensors) OR classified as malicious. Lowest false-positive risk — **recommended for production deny policies**.

All feeds are one IP per line, rolling 30-day window, updated at randomized times each day.

---

## Setup

### 1. Fork this repository as a private repo

Fork `swarmnoise` into your own GitHub account or organization. **Set the fork visibility to Private** during the fork dialog (GitHub defaults to public). Keeping it private prevents your sensor's attacker activity from being publicly visible.

### 2. Set GitHub Actions secrets

Go to `Settings → Secrets and variables → Actions` in your fork and add:

| Secret | Description |
|---|---|
| `GREYNOISE_API_KEY` | GreyNoise API key (from `viz.greynoise.io` → Settings → API) |
| `WORKSPACE_ID` | GreyNoise workspace UUID |
| `SENSOR_IDS` | Comma-separated sensor definitions in `uuid:label` format, e.g. `a1b2c3d4-...:berlin,e5f6g7h8-...:tokyo`. For a single sensor, use `uuid:default`. Backward-compatible: if `SENSOR_IDS` is not set, falls back to `SENSOR_ID`. |
| `GH_PAT` | GitHub Personal Access Token (classic) with `repo` scope — used by workflows to commit feed updates back to the repository |

### 3. Activate the scheduled workflows

The workflow files ship with their `schedule` triggers **commented out** so this blueprint repository does not produce spurious failed runs. In your fork, uncomment the `schedule` block in both files:

**`.github/workflows/scheduler.yml`**
```yaml
on:
  schedule:
    - cron: '0 * * * *'   # Every hour on the hour
  workflow_dispatch:
```

**`.github/workflows/monthly_archive.yml`**
```yaml
on:
  schedule:
    - cron: '0 23 * * *'   # Runs daily at 23:00 UTC
  workflow_dispatch:
```

Commit the changes, then verify both workflows appear under **Actions → Workflows**.

### 4. Trigger a first run

Use `workflow_dispatch` on the `Scheduler — Randomized Daily Fetch` workflow to force an immediate bootstrap fetch. The first run will collect the last 30 days of sensor data automatically.

### 5. Create a read-only PAT for your firewall and point it at the feed URLs

Create a **separate fine-grained PAT** with `Contents: Read-only` access scoped to your fork — see [Firewall Integration](docs/firewall-integration.md) for step-by-step instructions.

Replace `<your-org>/<your-repo>` in the feed URLs with your fork's path and configure HTTP Basic Auth on your firewall platform using `x-token` as the username and your fine-grained PAT as the password.

---

## Repository structure

```text
swarmnoise/
  .github/workflows/
    scheduler.yml
    monthly_archive.yml
  scripts/
    fetch_sessions.py
    archive_month.py
  feeds/
    threat_feed.txt
    threat_feed_filtered.txt
    threat_feed_high_confidence.txt
    ip_metadata.json
    filtered_metadata.json
  runs/
  state/
    today.json
  archive/
    YYYY-MM/
      filtered_metadata.json
      ip_metadata.json
      summary.json
  docs/
    multi-sensor.md
    firewall-integration.md
    architecture.md
    operations.md
  requirements.txt
  README.md
```

---

## Documentation

| Topic | Document |
|---|---|
| Multi-sensor setup, `SENSOR_IDS`, `seen_by`, `multi_sensor`, high-confidence feed | [docs/multi-sensor.md](docs/multi-sensor.md) |
| Firewall integration (FortiGate, Palo Alto, pfSense), private repo access | [docs/firewall-integration.md](docs/firewall-integration.md) |
| Architecture, scheduler, file schemas, pagination | [docs/architecture.md](docs/architecture.md) |
| Operator playbook, querying data, troubleshooting, security | [docs/operations.md](docs/operations.md) |
