# Mode44 SLS Rule Log Correlator

**Author:** Laurence Curling – Mode44 Ltd  
**License:** MIT  
**Status:** Public / Read-only / Production-ready  

---

## 🧠 Overview

The **Mode44 SLS Rule Log Correlator** queries the **Strata Logging Service (SLS)** for firewall rule activity using **rule UUIDs** exported from Panorama or Strata Cloud Manager.

It retrieves raw logs in 30-day increments going back 12 months and produces:

- 📄 Raw JSONL logs (one file per UUID per time window)  
- 📊 A summary CSV with hit counts and first/last timestamps  

This script is completely standalone and can later be called interactively from other Mode44 utilities.

---

## ⚙️ Features

| Feature | Description |
|----------|--------------|
| 🔐 OAuth2 authentication | Uses Client ID/Secret from App Hub or CSP API credentials |
| 🌍 Region-aware | Supports any SLS region via selection or custom base URL |
| 🧱 Secure defaults | Runtime credentials only; optional SSL verification |
| 📅 Historical coverage | 12 months, 30-day time windows |
| 📈 Raw + summary output | JSONL for analysis, CSV for quick reporting |
| 🧰 Portable | Runs anywhere Python ≥3.8 is installed |

---

## 🧩 Requirements

Install dependencies:

```bash
python3 -m pip install requests rich

🚀 Usage
python3 sls_rule_log_query_v0.1.py

Runtime prompts
Prompt	Description
Path to UUID CSV	e.g. rule_uuid_lookup.csv from Panorama tool
Region selection	Choose from us, eu, uk, or enter a custom base URL
Skip SSL verification	Optional; n recommended for production
Client ID / Secret	OAuth2 credentials from App Hub or CSP
Log type filter	e.g. traffic or leave blank for all

Output files
sls_rule_activity_<timestamp>.csv     # summary
rawlogs/<uuid>/<uuid>_YYYYMMDD_YYYYMMDD.jsonl   # raw logs


Example summary row:

UUID	DeviceGroup	WindowStart	WindowEnd	HitCount	FirstSeen	LastSeen
958a56aa-be3d-4a5f-a9fc-02a8d8d58d40	Mobile_User_Device_Group	2025-09-04	2025-10-04	532	2025-09-07T08:33:22Z	2025-10-01T22:14:09Z
🧾 Version History
Version	Date	Notes
0.1	2025-11-06	Initial release. 12×30-day queries, raw log export + summary CSV.
📄 Repository Layout
mode44-sls-rule-log-correlator/
 ├─ sls_rule_log_query_v0.1.py
 ├─ README.md
 ├─ .gitignore
 └─ LICENSE

🧰 Security Notes

No persistent secrets — credentials requested at runtime.

SSL verification optional (use only in controlled labs).

Requests and responses handled via requests with conservative timeouts.

Output files stored locally only.

© 2025 Mode44 Ltd – Laurence Curling
Released under the MIT License.
