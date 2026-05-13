#!/usr/bin/env python3
"""
archive_month.py

Creates a monthly snapshot of the current threat feed data.

Reads:
  - feeds/filtered_metadata.json  — enriched per-IP metadata (malicious/suspicious)
  - feeds/ip_metadata.json        — full feed per-IP first/last seen
  - runs/*.json                   — per-run logs for the current month

Writes to archive/YYYY-MM/:
  - filtered_metadata.json        — copy of the filtered feed at month-end
  - ip_metadata.json              — copy of the full feed at month-end
  - summary.json                  — pre-aggregated stats for the month

Intended to be run on the last day of each month via monthly_archive.yml.
No external dependencies beyond the standard library.
"""

import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def load_json(path: Path) -> dict | list:
    try:
        return json.loads(path.read_text())
    except Exception as exc:
        print(f"[error] Failed to read {path}: {exc}", file=sys.stderr)
        sys.exit(1)


def build_summary(
    filtered_metadata: dict,
    ip_metadata: dict,
    run_logs: list,
    month_str: str,
    generated_at: str,
) -> dict:
    """
    Aggregate stats from the current feed state and run logs for the given month.

    Run logs are filtered to the current month (YYYY-MM) using their timestamp field.
    Feed metadata reflects the rolling 30-day window at the time of archiving —
    this is the full picture of activity seen during the month.
    """
    # --- Run log aggregates (current month only) ---
    month_runs = [
        r for r in run_logs
        if isinstance(r, dict) and r.get("timestamp", "").startswith(month_str)
    ]
    total_sessions = sum(r.get("sessions_found", 0) for r in month_runs)
    total_runs     = len(month_runs)

    # --- Per-IP aggregates from filtered feed ---
    by_country      = Counter()
    by_tag          = Counter()
    by_tag_category = Counter()
    by_org          = Counter()
    by_port         = Counter()
    by_classification = Counter()
    by_sensor       = Counter()
    multi_sensor_count = 0
    flags = {"is_vpn": 0, "is_tor": 0, "is_bot": 0}

    for ip, meta in filtered_metadata.items():
        if not isinstance(meta, dict):
            continue

        country_code = meta.get("country_code") or "unknown"
        by_country[country_code] += 1

        for tag in (meta.get("tags") or []):
            by_tag[tag] += 1

        for cat in (meta.get("tag_categories") or []):
            by_tag_category[cat] += 1

        org = meta.get("org") or "unknown"
        by_org[org] += 1

        for port in (meta.get("destination_ports") or []):
            by_port[str(port)] += 1

        classification = meta.get("classification") or "unknown"
        by_classification[classification] += 1

        if meta.get("multi_sensor"):
            multi_sensor_count += 1

        for sensor in (meta.get("seen_by") or []):
            by_sensor[sensor] += 1

        for flag in ("is_vpn", "is_tor", "is_bot"):
            if meta.get(flag):
                flags[flag] += 1

    return {
        "month":        month_str,
        "generated_at": generated_at,
        "totals": {
            "sessions":           total_sessions,
            "full_feed_ips":      len(ip_metadata),
            "filtered_ips":       len(filtered_metadata),
            "multi_sensor_ips":   multi_sensor_count,
            "runs":               total_runs,
        },
        "by_country":          dict(by_country.most_common()),
        "by_tag":              dict(by_tag.most_common()),
        "by_tag_category":     dict(by_tag_category.most_common()),
        "by_org":              dict(by_org.most_common()),
        "by_destination_port": dict(by_port.most_common()),
        "by_classification":   dict(by_classification.most_common()),
        "by_sensor":           dict(by_sensor.most_common()),
        "flags":               flags,
    }


def load_run_logs(runs_dir: Path) -> list:
    """Load all run log JSON files from the runs/ directory."""
    logs = []
    for log_path in sorted(runs_dir.glob("*_run_log.json")):
        try:
            data = json.loads(log_path.read_text())
            if isinstance(data, dict):
                logs.append(data)
        except Exception as exc:
            print(f"[warning] Skipping unreadable run log {log_path.name}: {exc}",
                  file=sys.stderr)
    return logs


def main() -> None:
    repo_root = Path(__file__).parent.parent

    feeds_dir   = repo_root / "feeds"
    runs_dir    = repo_root / "runs"
    archive_dir = repo_root / "archive"

    # Determine the month being archived
    now       = datetime.now(timezone.utc)
    month_str = now.strftime("%Y-%m")

    print(f"[*] Archiving month: {month_str}")

    # --- Load source files ---
    filtered_metadata_path = feeds_dir / "filtered_metadata.json"
    ip_metadata_path       = feeds_dir / "ip_metadata.json"

    if not filtered_metadata_path.exists():
        print("[error] feeds/filtered_metadata.json not found — nothing to archive.",
              file=sys.stderr)
        sys.exit(1)

    if not ip_metadata_path.exists():
        print("[error] feeds/ip_metadata.json not found — nothing to archive.",
              file=sys.stderr)
        sys.exit(1)

    filtered_metadata = load_json(filtered_metadata_path)
    ip_metadata       = load_json(ip_metadata_path)
    run_logs          = load_run_logs(runs_dir)

    print(f"  [+] Loaded {len(filtered_metadata)} filtered IPs, "
          f"{len(ip_metadata)} full feed IPs, "
          f"{len(run_logs)} run logs")

    # --- Build summary ---
    generated_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    summary = build_summary(
        filtered_metadata, ip_metadata, run_logs, month_str, generated_at,
    )

    month_runs = summary["totals"]["runs"]
    print(f"  [+] Summary: {summary['totals']['sessions']} sessions across "
          f"{month_runs} runs this month")

    # --- Write archive ---
    out_dir = archive_dir / month_str
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "filtered_metadata.json").write_text(
        json.dumps(filtered_metadata, indent=2, sort_keys=True)
    )
    (out_dir / "ip_metadata.json").write_text(
        json.dumps(ip_metadata, indent=2, sort_keys=True)
    )
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2)
    )

    print(f"[+] Archive written to archive/{month_str}/")
    print(f"    - filtered_metadata.json  ({len(filtered_metadata)} IPs)")
    print(f"    - ip_metadata.json        ({len(ip_metadata)} IPs)")
    print("    - summary.json")
    print("[*] Done.")


if __name__ == "__main__":
    main()
