# swarmnoise

<p align="center">
  <img src="state/swarmnoise-banner_3.png" alt="Swarmnoise banner" />
</p>

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](#)
[![GitHub Actions](https://img.shields.io/badge/GitHub%20Actions-Automated-2088FF?logo=githubactions&logoColor=white)](#)
[![Threat Feed](https://img.shields.io/badge/Threat%20Feed-Firewall%20Ready-B22222)](#)
[![GreyNoise](https://img.shields.io/badge/Source-GreyNoise%20Swarm-1F2937)](#)

Automated collector for GreyNoise Project Swarm sensor activity. Deploys one or more Swarm sensors and produces newline-separated IP threat feeds compatible with any firewall or security platform that supports external IP block lists — including FortiGate, pfSense/OPNsense, Palo Alto Networks (EDL), and others. Monthly snapshots are archived for long-term evidence retention.

---

## Data & Licensing

- **You must provide your own GreyNoise account.** This project uses the GreyNoise API. All use of GreyNoise data is subject to the [GreyNoise EULA](https://www.greynoise.io/terms).
- **No live or real threat data is included in this repository.** Files under `feeds/`, `runs/`, and `state/` contain synthetic example data only. Deploy your own instance and configure your secrets to collect real data.
- GreyNoise is a trademark of GreyNoise Intelligence, Inc. Fortinet, FortiGate, Palo Alto Networks, pfSense, and OPNsense are trademarks of their respective owners. All trademarks are used for identification purposes only.

---

## At a glance

- Scope: attacker source IPs seen by your Swarm sensor(s)
- Output: full feed + filtered feed + enriched metadata + run logs + monthly archive
- Runtime: GitHub Actions only (no self-hosted infrastructure)
- Update model: randomized 1 to 10 fetches/day via hourly scheduler checks
- Integration: direct HTTPS feed consumption by any firewall supporting external IP block lists
- Access model: private fork with PAT-based HTTP Basic Auth on the firewall (recommended)

## Table of contents

- [Threat feeds](#threat-feeds)
- [Firewall integration](#firewall-integration)
  - [Private repo access (recommended)](#private-repo-access-recommended)
  - [Platform examples](#platform-examples)
- [Collection architecture](#collection-architecture)
- [Scheduler behavior](#scheduler-behavior)
- [Monthly archive snapshots](#monthly-archive-snapshots)
- [Repository structure](#repository-structure)
- [Setup](#setup)
- [File schemas](#file-schemas)
- [Querying data locally](#querying-data-locally)
- [Operator playbook](#operator-playbook)
- [Troubleshooting](#troubleshooting)
- [Security notes](#security-notes)

---

## Threat feeds

### Full feed

```text
https://raw.githubusercontent.com/<your-org>/<your-repo>/main/feeds/threat_feed.txt
```

All source IPs observed attacking the sensor in the last 30 days.

- Highest coverage
- Higher false-positive risk than the filtered feed

### Filtered feed

```text
https://raw.githubusercontent.com/<your-org>/<your-repo>/main/feeds/threat_feed_filtered.txt
```

Subset of the full feed where session classification matches:

- `classification:malicious`
- `classification:suspicious`

The filtered stream is built from the [GreyNoise v3 Sessions API](https://docs.greynoise.io/reference/getsessions) and includes enriched metadata in `feeds/filtered_metadata.json` (tags, CVEs, geo, ASN/org, Suricata signatures, protocols, destination ports).

Both feeds are:

- One IP per line (no comments, no headers)
- Rolling 30-day window (auto-pruned)
- Updated at randomized times each day

---

## Firewall integration

Both feed files are plain newline-separated IP lists with no headers or comments, making them compatible with any platform that supports external IP block lists or threat feed connectors.

### Generic configuration

| Field | Value |
|---|---|
| Feed URL (full) | `https://raw.githubusercontent.com/<your-org>/<your-repo>/main/feeds/threat_feed.txt` |
| Feed URL (filtered) | `https://raw.githubusercontent.com/<your-org>/<your-repo>/main/feeds/threat_feed_filtered.txt` |
| Format | One IP per line, no headers |
| Authentication | HTTP Basic Auth with a GitHub PAT (private repo, recommended) or none (public repo) |
| Recommended refresh | 60 min |

### Private repo access (recommended)

Keep your fork **private**. This prevents your sensor's attacker activity from being publicly visible while still allowing your firewall to pull the feeds directly over HTTPS.

GitHub's `raw.githubusercontent.com` endpoint accepts a Personal Access Token (PAT) as an HTTP Basic Auth password. Most firewall platforms expose username/password fields in their external connector or threat feed configuration — this maps cleanly to that model.

**Create a dedicated read-only PAT for your firewall:**

1. Go to `GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens`
2. Click **Generate new token**
3. Set **Resource owner** to your account (or org)
4. Under **Repository access**, select **Only select repositories** → choose your swarmnoise fork
5. Under **Permissions → Repository permissions**, set **Contents** to `Read-only`
6. Leave all other permissions at `No access`
7. Generate and copy the token (`github_pat_...`)

> This token is separate from the `GH_PAT` Actions secret (which needs write access to commit feed updates). The firewall PAT is strictly read-only and scoped to a single repository.

**Configure your firewall:**

| Field | Value |
|---|---|
| URI | `https://raw.githubusercontent.com/<your-org>/<your-repo>/main/feeds/threat_feed.txt` |
| Username | `x-token` (any string is accepted by GitHub) |
| Password | `github_pat_xxxxxxxxxxxx` (your fine-grained PAT) |

GitHub validates the token and serves the raw file. No proxy or self-hosted infrastructure is required.

**Public repo alternative:** If you are comfortable with your sensor activity being publicly visible, make the fork public. No authentication is required — the feed URLs work directly with no credentials.

### Platform examples

**FortiGate** — `Security Fabric → External Connectors → Threat Feeds → IP Address`

Private repo (recommended):

| Field | Value |
|---|---|
| Name | `swarmnoise` |
| URI | `https://raw.githubusercontent.com/<your-org>/<your-repo>/main/feeds/threat_feed.txt` |
| HTTP basic auth | on |
| Username | `x-token` |
| Password | `github_pat_xxxxxxxxxxxx` |
| Refresh rate | 60 min |

Public repo:

| Field | Value |
|---|---|
| Name | `swarmnoise` |
| URI | `https://raw.githubusercontent.com/<your-org>/<your-repo>/main/feeds/threat_feed.txt` |
| HTTP basic auth | off |
| Refresh rate | 60 min |

**Palo Alto Networks (EDL)** — `Objects → External Dynamic Lists`

| Field | Value |
|---|---|
| Type | IP List |
| Source | `https://x-token:github_pat_xxxxxxxxxxxx@raw.githubusercontent.com/<your-org>/<your-repo>/main/feeds/threat_feed.txt` |
| Repeat | Every hour |

> Palo Alto EDL sources do not have separate credential fields — embed credentials directly in the URL as shown. For public repos, use the plain URL without credentials.

**pfSense / OPNsense** — `Firewall → Aliases → URLs`

| Field | Value |
|---|---|
| Type | URL Table (IPs) |
| URL | `https://x-token:github_pat_xxxxxxxxxxxx@raw.githubusercontent.com/<your-org>/<your-repo>/main/feeds/threat_feed.txt` |
| Refresh | 1 day (or use cron for hourly) |

> pfSense and OPNsense URL alias fields do not have separate credential fields — embed credentials in the URL as shown. For public repos, use the plain URL without credentials.

For lower false-positive tolerance, substitute `threat_feed_filtered.txt` for `threat_feed.txt` in any URL above.

---

## Collection architecture

The collector uses two GreyNoise API paths in parallel:

| | Full feed | Filtered feed |
|---|---|---|
| API | v1 Swarm (`/v1/workspaces/{id}/sensors/activity`) | v3 Sessions (`/v3/sessions`) |
| Filter | none | `classification:malicious OR classification:suspicious` |
| Page size | 1000 | 100 |
| Pagination | 30-minute chunk windows | page-based |
| Metadata depth | basic | enriched (tags, CVEs, geo, signatures) |

### First run bootstrap

If `feeds/ip_metadata.json` does not exist, bootstrap mode fetches the last 30 days automatically.

### Pagination constraints

The v1 scroll token is too large to reuse safely in request paths/headers, so v1 collection runs in 30-minute time chunks. This keeps feed convergence high and operationally stable under API limits.

---

## Scheduler behavior

Workflow: `.github/workflows/scheduler.yml`

- Hourly cron trigger (`0 * * * *`)
- Daily random plan generated in Berlin time (`Europe/Berlin`)
- Randomized target: 1 to 10 runs/day
- Scheduled hours persisted in `state/today.json`
- Missed-hour catch-up logic included (overdue hour handling)
- On failure, automatic retry at next cron tick
- `workflow_dispatch` bypasses schedule gating and forces a fetch

Result: organic, hard-to-predict update timing rather than rigid fixed intervals.

---

## Monthly archive snapshots

Workflow: `.github/workflows/monthly_archive.yml`

- Triggered daily at `23:00 UTC`
- Executes only on the last day of month (manual dispatch can bypass guard)
- Runs `scripts/archive_month.py`
- Writes `archive/YYYY-MM/` with:
  - `filtered_metadata.json`
  - `ip_metadata.json`
  - `summary.json`

This provides durable month-end snapshots independent of the rolling 30-day live window.

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
  requirements.txt
  README.md
```

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
| `SENSOR_ID` | Swarm sensor UUID |
| `GH_PAT` | GitHub Personal Access Token (classic) with `repo` scope — used by workflows to commit feed updates back to the repository |

### 3. Enable GitHub Actions

Actions are enabled by default on forks. Verify both workflows are active under `Actions → Workflows`.

### 4. Trigger a first run

Use `workflow_dispatch` on the `Scheduler — Randomized Daily Fetch` workflow to force an immediate bootstrap fetch. The first run will collect the last 30 days of sensor data automatically.

### 5. Create a read-only PAT for your firewall and point it at the feed URLs

Create a **separate fine-grained PAT** with `Contents: Read-only` access scoped to your fork — see [Private repo access (recommended)](#private-repo-access-recommended) for step-by-step instructions.

Replace `<your-org>/<your-repo>` in the feed URLs with your fork's path and configure HTTP Basic Auth on your firewall platform using `x-token` as the username and your fine-grained PAT as the password.

---

## File schemas

`feeds/ip_metadata.json` (rolling 30-day index)

```json
{
  "192.0.2.1": {
    "first_seen": "2026-04-05T09:00:00Z",
    "last_seen": "2026-05-05T10:26:00Z"
  }
}
```

`runs/YYYY-MM-DD_HHMM_run_log.json` (always written)

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

`feeds/filtered_metadata.json` (enriched filtered-feed metadata)

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
    "asn": "AS64496",
    "org": "Example ISP",
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

---

## Querying data locally

```bash
# Count full-feed IPs
wc -l feeds/threat_feed.txt

# Count filtered-feed IPs
wc -l feeds/threat_feed_filtered.txt

# Inspect enriched metadata
jq '.' feeds/filtered_metadata.json

# Inspect latest monthly snapshot summary
jq '.' archive/$(date -u +%Y-%m)/summary.json
```

---

## Operator playbook

1. Start with `threat_feed_filtered.txt` in production deny policies
2. Track feed growth and churn using `runs/*_run_log.json`
3. Review `filtered_metadata.json` tags/CVEs before adding custom block automation
4. Use monthly `archive/YYYY-MM/summary.json` for trend baselining
5. Use `threat_feed.txt` for broader detection-focused controls where acceptable

---

## Troubleshooting

### No feed updates visible

- Check latest run in Actions (`Scheduler - Randomized Daily Fetch`)
- Verify `state/today.json` has scheduled hours and completed runs
- Confirm required secrets are set (`GREYNOISE_API_KEY`, `WORKSPACE_ID`, `SENSOR_ID`, `GH_PAT`)

### Workflow runs but no sessions found

- This can be legitimate for low-activity windows
- Check run log `error` field and time window coverage
- Manual dispatch can force an immediate run for validation

### Archive did not appear

- Archive workflow only writes on last day of month unless manually triggered
- Check `.github/workflows/monthly_archive.yml` logs for guard decision output

---

## Security notes

- Never commit API keys or PAT tokens — keep all credentials in GitHub Actions secrets
- **Keep the repository private (recommended).** Forking as a private repo prevents your sensor's attacker activity from being publicly visible. Use a fine-grained GitHub PAT with `Contents: Read-only` scope on your firewall for feed access — see [Private repo access (recommended)](#private-repo-access-recommended)
- The `GH_PAT` Actions secret (write access, used by workflows to commit feed updates) and the firewall PAT (read-only, used to pull feeds) should be **separate tokens** with separate scopes
- If you choose to make the repository public, feed files are publicly accessible — this is intentional for firewall consumption, but be aware your sensor's observed attacker activity will be visible to anyone
