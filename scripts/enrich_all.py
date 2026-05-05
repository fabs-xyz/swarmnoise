#!/usr/bin/env python3
"""
One-shot enrichment script.

Loads all IPs from feeds/ip_metadata.json, looks up each one in the
GreyNoise Community API, and writes:
  - feeds/classification_cache.json  (enrichment results)
  - feeds/fortinet_ips_filtered.txt  (malicious/suspicious IPs only)

Run manually via the enrich GitHub Actions workflow, or locally:
  GREYNOISE_API_KEY=<key> python scripts/enrich_all.py
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

COMMUNITY_API = "https://api.greynoise.io/v3/community"
FILTERED_FEED_CLASSIFICATIONS = {"malicious", "suspicious"}
MAX_PER_MIN = 12  # conservative — Community API hard limit is 25/min but enforced strictly


def get_env(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        print(f"[error] Required environment variable '{name}' is not set.", file=sys.stderr)
        sys.exit(1)
    return val


def enrich_all(api_key: str, ips: list, existing_cache: dict) -> dict:
    """Enrich every IP in `ips` that is not already in `existing_cache`."""
    to_enrich = [ip for ip in ips if ip not in existing_cache]
    cache = dict(existing_cache)

    if not to_enrich:
        print("[*] All IPs already in cache — nothing to do.")
        return cache

    # Brief pause before starting — gives any lingering rate-limit window time to clear.
    print("[*] Cold-start pause: 60s before first request...")
    time.sleep(60)

    total            = len(to_enrich)
    interval         = 60.0 / MAX_PER_MIN
    done             = 0
    errors           = 0
    consecutive_429s = 0

    print(f"[*] Enriching {total} IPs at {MAX_PER_MIN} req/min "
          f"(est. {total / MAX_PER_MIN / 60:.1f}h)")

    req_headers = {"key": api_key, "Accept": "application/json"}

    for ip in to_enrich:
        t_start = time.monotonic()
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        try:
            resp = requests.get(
                f"{COMMUNITY_API}/{ip}",
                headers=req_headers,
                timeout=15,
            )

            if resp.status_code == 404:
                cache[ip] = {"classification": "unknown", "name": None, "checked_at": now_str}
                consecutive_429s = 0

            elif resp.status_code == 429:
                consecutive_429s += 1
                sleep_time = 120 if consecutive_429s >= 3 else 70
                print(f"  [!] Rate limited (#{consecutive_429s}) — sleeping {sleep_time}s",
                      file=sys.stderr)
                time.sleep(sleep_time)
                # Do NOT retry immediately — skip this IP and let the paced loop continue.
                # The script is resumable; uncached IPs will be picked up on re-run.
                errors += 1
                done += 1
                continue

            elif resp.ok:
                data = resp.json()
                cache[ip] = {
                    "classification": data.get("classification", "unknown"),
                    "name":           data.get("name"),
                    "checked_at":     now_str,
                }
                consecutive_429s = 0

            else:
                errors += 1
                consecutive_429s = 0
                print(f"  [!] HTTP {resp.status_code} for {ip}", file=sys.stderr)

        except requests.RequestException as exc:
            errors += 1
            print(f"  [!] Request error for {ip}: {exc}", file=sys.stderr)

        done += 1
        if done % 100 == 0 or done == total:
            pct = done / total * 100
            eta_min = (total - done) / MAX_PER_MIN
            print(f"  [{done}/{total}] {pct:.1f}% complete — ~{eta_min:.0f} min remaining")

        elapsed   = time.monotonic() - t_start
        remaining = interval - elapsed
        if remaining > 0:
            time.sleep(remaining)

    print(f"\n[*] Enrichment complete — {done} processed, {errors} errors")

    dist: dict = {}
    for entry in cache.values():
        c = entry.get("classification", "unknown")
        dist[c] = dist.get(c, 0) + 1
    print(f"[*] Classification distribution: {dist}")

    return cache


def write_filtered_feed(cache: dict, metadata: dict, feeds_dir: Path) -> int:
    filtered = sorted(
        ip for ip in metadata
        if cache.get(ip, {}).get("classification") in FILTERED_FEED_CLASSIFICATIONS
    )
    feed_path = feeds_dir / "fortinet_ips_filtered.txt"
    feed_path.write_text("\n".join(filtered) + "\n" if filtered else "")
    print(f"[*] Filtered feed written: {feed_path} ({len(filtered)} IPs)")
    return len(filtered)


def main() -> None:
    api_key   = get_env("GREYNOISE_API_KEY")
    repo_root = Path(__file__).parent.parent
    feeds_dir = repo_root / "feeds"

    # Load ip_metadata.json
    metadata_path = feeds_dir / "ip_metadata.json"
    if not metadata_path.exists():
        print(f"[error] {metadata_path} not found — run fetch_sessions.py first.",
              file=sys.stderr)
        sys.exit(1)

    metadata: dict = json.loads(metadata_path.read_text())
    all_ips = list(metadata.keys())
    print(f"[*] Loaded {len(all_ips)} IPs from ip_metadata.json")

    # Load existing cache (partial runs are resumable)
    cache_path = feeds_dir / "classification_cache.json"
    cache: dict = {}
    if cache_path.exists():
        try:
            cache = json.loads(cache_path.read_text())
            print(f"[*] Loaded existing cache with {len(cache)} entries "
                  f"({len(all_ips) - len(cache)} remaining)")
        except Exception:
            cache = {}

    # Enrich
    cache = enrich_all(api_key, all_ips, cache)

    # Save cache
    cache_path.write_text(json.dumps(cache, indent=2, sort_keys=True))
    print(f"[*] Cache saved to {cache_path} ({len(cache)} entries)")

    # Write filtered feed
    write_filtered_feed(cache, metadata, feeds_dir)


if __name__ == "__main__":
    main()
