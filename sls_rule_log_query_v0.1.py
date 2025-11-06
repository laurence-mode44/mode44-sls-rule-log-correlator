#!/usr/bin/env python3
# Version: 0.1 - SLS Rule Log Query (12 months, 30-day windows)
"""
Mode44 – SLS Rule Log Correlator (Standalone)
---------------------------------------------
Reads UUIDs from `rule_uuid_lookup.csv`, authenticates to Strata Logging Service (SLS)
using an OAuth2 client (Client ID/Secret), then queries raw logs in 30-day windows
going back 12 months (from current run time).

Outputs:
  • JSONL files with raw logs per UUID per window
  • A summary CSV with counts & first/last timestamps per window

Security model:
  • Runtime auth only (no secrets stored)
  • Optional SSL verification for labs
  • Conservative timeouts, retries, and clear error messages

Tested environment notes:
  • SLS region base URLs can differ by tenant. This script lets you choose a
    region from a list or enter a full custom base URL.
  • If your tenant uses a slightly different path, update ENDPOINT_PATH below
    or enter the correct base URL at runtime.
"""

from __future__ import annotations
import csv, json, sys, time, math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Tuple, Optional

import getpass
import requests
import urllib3
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn

console = Console()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------- Editable defaults (easy to tweak later) -------------------------
# Common SLS regional API bases (edit as needed). You can also enter Custom.
REGIONS: Dict[str, str] = {
    "us": "https://api.us.logging-service.prismaaccess.com",
    "eu": "https://api.eu.logging-service.prismaaccess.com",
    "uk": "https://api.uk.logging-service.prismaaccess.com",
    "ca": "https://api.ca.logging-service.prismaaccess.com",
    "au": "https://api.au.logging-service.prismaaccess.com",
    "jp": "https://api.jp.logging-service.prismaaccess.com",
}

# SLS OAuth2 token endpoint (App Hub / CSP service account)
# If your tenant requires the /api prefix, try:
#   TOKEN_URL = "https://api.strata.paloaltonetworks.com/api/oauth2/access_token"
TOKEN_URL = "https://api.strata.paloaltonetworks.com/oauth2/access_token"

# SLS logs endpoint path (joined to region base). If your tenant uses a different path
# (e.g., /logging-service/v2/query or /logging-service/v2/logs/search), update here.
ENDPOINT_PATH = "/logging-service/v2/logs"

# Maximum records pulled per page (tune per tenant limits; 1000–5000 typical)
PAGE_SIZE = 1000

# ----------------------------------------------------------------------------

@dataclass
class AuthContext:
    token: str
    base_url: str
    verify_ssl: bool

@dataclass
class Window:
    start: datetime
    end: datetime

def iso8601(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def build_time_windows(months: int = 12, window_days: int = 30) -> List[Window]:
    """Build backwards 30-day windows from 'now' for N months."""
    now = datetime.now(timezone.utc)
    windows: List[Window] = []
    end = now
    for _ in range(months):
        start = end - timedelta(days=window_days)
        windows.append(Window(start=start, end=end))
        end = start
    return windows

def read_uuid_table(csv_path: Path) -> List[Dict[str, str]]:
    """Read UUIDs from rule_uuid_lookup.csv (expects columns: uuid, name, device_group)."""
    if not csv_path.exists():
        console.print(f"[red]Input file not found:[/red] {csv_path}")
        sys.exit(1)
    rows: List[Dict[str, str]] = []
    with csv_path.open("r", newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        missing = [c for c in ("uuid", "name", "device_group") if c not in r.fieldnames]
        if missing:
            console.print(f"[red]CSV missing required columns:[/red] {missing}")
            sys.exit(1)
        for row in r:
            if row.get("uuid"):
                rows.append({
                    "uuid": row["uuid"].strip(),
                    "name": row.get("name", "").strip(),
                    "device_group": row.get("device_group", "").strip(),
                })
    if not rows:
        console.print("[red]No UUID rows found in CSV.[/red]")
        sys.exit(1)
    return rows

def get_region_base_url_interactive() -> str:
    console.print("[bold cyan]Select SLS Region[/bold cyan]")
    keys = list(REGIONS.keys())
    for i, k in enumerate(keys, 1):
        console.print(f" {i}) {k}  →  {REGIONS[k]}")
    console.print(f" C) Custom base URL")
    choice = console.input("[green]Enter choice (number or 'C'):[/green] ").strip().lower()
    if choice == "c":
        custom = console.input("Enter full base URL (e.g., https://api.eu.logging-service.prismaaccess.com): ").strip()
        return custom.rstrip("/")
    try:
        idx = int(choice) - 1
        return REGIONS[keys[idx]].rstrip("/")
    except Exception:
        console.print("[yellow]Invalid selection. Defaulting to 'eu' region.[/yellow]")
        return REGIONS["eu"].rstrip("/")

def oauth2_token(client_id: str, client_secret: str, verify_ssl: bool) -> str:
    """Obtain OAuth2 bearer token for SLS. Adjust payload if your tenant requires different fields."""
    data = {
        "grant_type": "client_credentials",
        # Some tenants expect scope. Uncomment/adjust if needed:
        # "scope": "logging-service:read",
    }
    resp = requests.post(
        TOKEN_URL,
        data=data,
        auth=(client_id, client_secret),
        timeout=30,
        verify=verify_ssl
    )
    if resp.status_code != 200:
        console.print(f"[red]Token request failed ({resp.status_code}):[/red] {resp.text}")
        sys.exit(1)
    payload = resp.json()
    token = payload.get("access_token") or payload.get("accessToken")
    if not token:
        console.print("[red]No access_token in token response.[/red]")
        console.print(json.dumps(payload, indent=2))
        sys.exit(1)
    return token

def sls_query_logs_raw(
    auth: AuthContext,
    uuid: str,
    start: datetime,
    end: datetime,
    log_type: str,
) -> Tuple[int, Optional[str], Optional[str], List[dict]]:
    """
    Query SLS raw logs for a single UUID and window.
    Returns: (count, first_seen_iso, last_seen_iso, records_list)
    NOTE: Endpoint & parameters can vary slightly per tenant.
    This implementation uses a common pattern:
      GET {base}/logging-service/v2/logs
        params = {
          "startTime": ISO8601,
          "endTime":   ISO8601,
          "filter":    f"(rule_uuid eq '{uuid}') and (log_type eq '{log_type}')",
          "maxResults": PAGE_SIZE,
          "pageToken":  <returned token, for pagination>
        }
    If your tenant expects POST with JSON, adjust here accordingly.
    """
    base = auth.base_url.rstrip("/")
    url = f"{base}{ENDPOINT_PATH}"

    headers = {"Authorization": f"Bearer {auth.token}"}
    params = {
        "startTime": iso8601(start),
        "endTime": iso8601(end),
        # You may need to adjust filter syntax. Some tenants use == or wrap in quotes differently.
        "filter": f"(rule_uuid eq '{uuid}')" + (f" and (log_type eq '{log_type}')" if log_type else ""),
        "maxResults": PAGE_SIZE,
    }

    total = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    records: List[dict] = []
    page_token = None

    while True:
        if page_token:
            params["pageToken"] = page_token
        resp = requests.get(url, headers=headers, params=params, timeout=60, verify=auth.verify_ssl)
        if resp.status_code not in (200, 206):
            # 206 (Partial Content) may be used by some gateways
            console.print(f"[red]SLS query error {resp.status_code}:[/red] {resp.text}")
            break
        data = resp.json()
        items = data.get("logs") or data.get("items") or data.get("data") or []
        # Try common timestamp fields
        for it in items:
            ts = it.get("receive_time") or it.get("time") or it.get("_time") or it.get("event_time")
            if ts:
                # Track first/last
                if not first_seen or ts < first_seen:
                    first_seen = ts
                if not last_seen or ts > last_seen:
                    last_seen = ts
        records.extend(items)
        total += len(items)

        page_token = data.get("nextPageToken") or data.get("pageToken") or data.get("next_token")
        if not page_token or len(items) == 0:
            break

        # Be polite to the API
        time.sleep(0.2)

    return total, first_seen, last_seen, records

def write_jsonl(path: Path, records: List[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

def run():
    console.print("[bold cyan]=== Mode44 SLS Rule Log Correlator (v0.1) ===[/bold cyan]\n")

    # Input UUID CSV
    default_csv = Path("rule_uuid_lookup.csv")
    csv_path = Path(console.input(f"Path to UUID CSV (default: {default_csv}): ").strip() or default_csv)
    uuid_rows = read_uuid_table(csv_path)
    console.print(f"[cyan]Loaded {len(uuid_rows)} UUID rows from {csv_path}[/cyan]\n")

    # Region/base URL
    base_url = get_region_base_url_interactive()

    # SSL verify
    skip_verify = console.input("Skip SSL verification? (y/N): ").strip().lower().startswith("y")
    verify_ssl = not skip_verify
    if skip_verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # OAuth2 credentials
    client_id = console.input("SLS Client ID: ").strip()
    client_secret = getpass.getpass("SLS Client Secret: ").strip()

    # Log type (optional filter)
    log_type = console.input("Log type filter (e.g., traffic, threat) or leave blank for all: ").strip()

    # Token
    console.print("\n[bold]Obtaining access token...[/bold]")
    token = oauth2_token(client_id, client_secret, verify_ssl)
    auth = AuthContext(token=token, base_url=base_url, verify_ssl=verify_ssl)
    console.print("[green]Token acquired.[/green]\n")

    # Time windows
    windows = build_time_windows(months=12, window_days=30)
    console.print(f"[cyan]Built {len(windows)} time windows (30-day increments, 12 months).[/cyan]\n")

    # Summary CSV
    ts_label = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    summary_path = Path(f"sls_rule_activity_{ts_label}.csv")
    with summary_path.open("w", newline="", encoding="utf-8") as sf:
        writer = csv.DictWriter(sf, fieldnames=[
            "uuid", "rule_name", "device_group", "window_start", "window_end",
            "hit_count", "first_seen", "last_seen"
        ])
        writer.writeheader()

        total_tasks = len(uuid_rows) * len(windows)
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Querying SLS...", total=total_tasks)

            for row in uuid_rows:
                uuid = row["uuid"]
                rule_name = row["name"]
                dg = row["device_group"]

                # per-UUID output dir
                out_dir = Path("rawlogs") / uuid
                out_dir.mkdir(parents=True, exist_ok=True)

                for w in windows:
                    start_iso = iso8601(w.start)
                    end_iso = iso8601(w.end)

                    count, first_seen, last_seen, records = sls_query_logs_raw(
                        auth=auth, uuid=uuid, start=w.start, end=w.end, log_type=log_type
                    )

                    # Write raw JSONL (even if zero, we create empty file for traceability)
                    jsonl_name = f"{uuid}_{w.start.strftime('%Y%m%d')}_{w.end.strftime('%Y%m%d')}.jsonl"
                    write_jsonl(out_dir / jsonl_name, records)

                    writer.writerow({
                        "uuid": uuid,
                        "rule_name": rule_name,
                        "device_group": dg,
                        "window_start": start_iso,
                        "window_end": end_iso,
                        "hit_count": count,
                        "first_seen": first_seen or "",
                        "last_seen": last_seen or "",
                    })

                    progress.advance(task, 1)

    # Pretty summary finish
    console.print("\n[bold green]Complete.[/bold green]")
    t = Table(title="SLS Rule Activity – Summary Export")
    t.add_column("File")
    t.add_column("Notes")
    t.add_row(str(summary_path.resolve()), "Per-UUID per-window counts (12×30d)")
    t.add_row(str((Path.cwd() / 'rawlogs').resolve()), "Raw JSONL logs per UUID per window")
    console.print(t)

if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        sys.exit(1)
