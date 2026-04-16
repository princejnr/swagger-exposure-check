> [!CAUTION]
> **AUTHORISED USE ONLY.**
> Run this tool exclusively against systems you **own** or have **explicit written permission** to test.
> Unauthorised scanning may violate the Computer Misuse Act or equivalent laws in your jurisdiction.
> The author accepts **no liability** for misuse.

# swagger-exposure-check

> A defensive security tool that discovers exposed Swagger / OpenAPI documentation endpoints across your infrastructure — including optional wildcard subdomain enumeration.

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)]()

---

## Table of Contents

- [What it does](#what-it-does)
- [Why it matters](#why-it-matters)
- [Quick start](#quick-start)
- [Wildcard & subdomain support](#wildcard--subdomain-support)
- [CLI reference](#cli-reference)
- [Output format](#output-format)
- [Severity ratings](#severity-ratings)
- [Requirements](#requirements)
- [Disclaimer](#disclaimer)

---

## What it does

`swagger_exposure_check.py` probes a list of hostnames for publicly reachable API documentation endpoints such as:

| Path | Description |
|---|---|
| `/swagger-ui.html` | Swagger UI (Spring Boot default) |
| `/v2/api-docs` | Swagger 2.0 raw JSON |
| `/v3/api-docs` | OpenAPI 3.0 raw JSON |
| `/openapi.json` | OpenAPI 3.0 canonical path |
| `/openapi.yaml` | OpenAPI 3.0 YAML |
| `/swagger.json` | Swagger 2.0/3.0 JSON |
| `/docs` | FastAPI / Starlette |
| `/redoc` | ReDoc UI |

For each endpoint it:
1. **Discovers Historical Paths:** (Optional) Queries the Wayback Machine (CDX) to find deeply nested or legacy documentation paths.
2. **Scrapes JavaScript Bundles:** (Optional) Fetches the application root, identifies `.js` bundles, and scrapes them for hidden API routes.
3. **Fetches** the URL (with retry & configurable timeout).
4. **Reads up to 4 KB** of the response body to detect real Swagger/OpenAPI content.
5. **Audits Security Headers:** Checks for missing `X-Frame-Options`, `CSP`, `X-Content-Type-Options`, and `HSTS`.
6. **Detects WAFs:** Identifies common Web Application Firewalls (Cloudflare, Akamai, etc.).
7. **Classifies** the result by severity (`critical` / `high` / `medium` / `info` / `ok` / `error`).
8. **Prints** a live, colour-coded progress table to the terminal.
9. **Writes** a timestamped `.csv` and `.json` report.

### Live output example

```
  swagger-exposure-check v3.2
  Hosts: 12  |  Paths: 15  |  Total checks: 180  |  Workers: 3

  [ 1/180] 🟢 404        OK  https://api.example.com/swagger
  [ 2/180] 💥 200  CRITICAL  https://dev.example.com/v2/swagger.json
  [ 3/180] 🔴 200      HIGH  https://staging.example.com/docs
  [ 4/180] 🟡 302    MEDIUM  https://example.com/api-docs
  ...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    CRITICAL  █  1
        HIGH  █  1
      MEDIUM  █  1
          OK  ████████████████  177
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ⚠  CRITICAL / HIGH severity endpoints:
       https://dev.example.com/v2/swagger.json [WAF: cloudflare] [Missing: X-Frame-Options, CSP]
       Note: unprotected API docs confirmed in body (missing 2 security headers)
```

---

## Why it matters

Exposed API documentation is a **common security misconfiguration** that can:

- Reveal full API surface area (endpoints, parameters, data models) to attackers
- Expose authentication schemes and internal micro-service topology
- Enable automated attack planning without any prior reconnaissance

**PCI-DSS, ISO 27001, and OWASP API Top 10 (API9:2023 — Improper Inventory Management)** all flag unintentionally exposed API documentation as a risk finding.

---

## Quick start

```bash
# Clone / download
git clone https://github.com/youruser/swagger-exposure-check.git
cd swagger-exposure-check

# No external dependencies — uses Python stdlib only
python3 swagger_exposure_check.py hosts.txt --output-dir ./reports
```

### `hosts.txt` format

```
# Plain hostnames
api.example.com
internal-gateway.corp:8443

# Wildcard — all common subdomains of example.com are enumerated via DNS
*.example.com

# Comments and blank lines are ignored
```

---

## Wildcard & subdomain support

When an entry starts with `*.` (e.g. `*.example.com`), the tool performs a two-stage discovery before any probing begins:

1. **OSINT Discovery:** Queries the public `crt.sh` Certificate Transparency logs API to find real, historically valid subdomains for that domain.
2. **Wordlist Expansion:** Combines the OSINT results with a built-in wordlist of **60 common names** (`api`, `dev`, `staging`, `admin`, `gateway`, etc.).
3. **DNS Validation:** Resolves every candidate via DNS concurrently (default 20 threads) to filter out dead subdomains.

### Historical Discovery (Wayback Machine)

Use `--use-wayback` to query the **Wayback Machine (CDX API)** for historical URLs associated with your targets. The tool filters thousands of archived URLs for keywords like `swagger`, `openapi`, and `.json` to discover deeply nested or legacy documentation paths that no longer appear on the main site but may still be active.

### JavaScript Scraping

Use `--use-js` to enable the automated JavaScript scraping engine. The tool will:
1. Fetch the root page of each target host.
2. Identify all `<script src="...">` bundles (Webpack, Vite, etc.).
3. Fetch and scan those JS files for hardcoded API endpoints using high-precision regex.
4. Add any discovered paths to the probe queue for that host.

```bash
# Combine all discovery methods for maximum coverage
python3 swagger_exposure_check.py hosts.txt \
  --enumerate-subdomains \
  --use-wayback \
  --use-js
```

---

## 🗺️ Roadmap & Future Features

While this tool currently checks the most standard Swagger paths, developers sometimes hide API docs in deeply nested random directories. 

Future versions of this tool aim to implement:
- **Deep Fuzzing Support:** Expanded built-in wordlists containing hundreds of known nested Swagger directory structures pulled from SecLists.

---

## Authenticated / Proxied Scanning

If your target is behind a WAF (like Cloudflare Teams), an identity proxy, or basic auth, you can pass custom HTTP headers to the scanner:

```bash
python3 swagger_exposure_check.py hosts.txt \
  -H "Authorization: Bearer eyJhb..." \
  -H "CF-Access-Client-Id: 12345"
```

---

## CLI reference

```
usage: swagger_exposure_check.py [-h] [--timeout TIMEOUT] [--http]
                                  [--insecure] [--paths-file PATHS_FILE]
                                  [-H HEADER]
                                  [--subdomains-file SUBDOMAINS_FILE]
                                  [--enumerate-subdomains]
                                  [--no-dns-check] [--workers WORKERS]
                                  [--dns-workers DNS_WORKERS]
                                  [--retries RETRIES] [--output-dir OUTPUT_DIR]
                                  [--output-urls OUTPUT_URLS]
                                  [--use-wayback] [--use-js] [--version] [--yes]
                                  [hosts_file]
```

| Flag | Default | Description |
|---|---|---|
| `hosts_file` | `hosts.txt` | Path to hostnames file |
| `--timeout` | `10` | HTTP request timeout (seconds) |
| `--http` | `false` | Use `http://` instead of `https://` |
| `--insecure` | `false` | Skip TLS certificate verification |
| `--paths-file` | _(built-in paths)_ | Custom paths to probe |
| `-H`, `--header` | | Custom HTTP header (`Key: Value`). Can be used multiple times |
| `--enumerate-subdomains` | **`false` (off)** | Enable `crt.sh` + wordlist enumeration on `*.` entries |
| `--subdomains-file` | _(built-in list)_ | Custom subdomain wordlist for `*.` expansion |
| `--no-dns-check` | `false` | Probe all subdomain candidates without DNS filtering |
| `--workers` | **`3`** | HTTP concurrency — raise deliberately for bulk audits |
| `--dns-workers` | `20` | DNS resolution concurrency |
| `--retries` | `2` | Retries on transient network errors |
| `--output-dir` | `.` | Directory for CSV/JSON reports |
| `--output-urls` | | Optional file to write raw exposed URLs (HIGH/MEDIUM severity) |
| `--use-wayback` | **`false`** | Query Wayback Machine (CDX) for historical URL discovery |
| `--use-js` | **`false`** | Scrape .js bundles for hidden API paths |
| `--version` | | Show program's version number and exit |
| `--yes` | `false` | Skip interactive consent prompt (for CI/scripted use) |

### Common recipes

```bash
# Internal network (HTTP, self-signed certs, custom paths):
python3 swagger_exposure_check.py hosts.txt \
  --http --insecure \
  --paths-file internal-paths.txt \
  --workers 50 --output-dir ./reports

# Deep discovery scan (subdomains + historical + JS scraping):
python3 swagger_exposure_check.py hosts.txt \
  --enumerate-subdomains --use-wayback --use-js
```

---

## Output format

Two timestamped files are written after every run.

### CSV (`swagger_exposure_report_YYYYMMDDTHHMMSSZ.csv`)

| Column | Description |
|---|---|
| `tool_version` | Version of the tool used |
| `host` | Target hostname (as probed) |
| `path` | URL path checked |
| `url` | Full URL |
| `status` | HTTP status code |
| `content_type` | `Content-Type` header value |
| `final_url` | URL after redirects |
| `body_confirmed` | `True` if response body contained API-doc tokens |
| `severity` | `critical` / `high` / `medium` / `info` / `ok` / `error` |
| `note` | Human-readable reason |
| `error` | Network/connection error message if any |
| `missing_headers` | List of missing security headers |
| `waf_detected` | Detected WAF signature if any |

### JSON (`swagger_exposure_report_YYYYMMDDTHHMMSSZ.json`)

```json
{
  "generated_at_utc": "2026-04-14T21:32:00+00:00",
  "tool_version": "3.2.0",
  "total_hosts_probed": 12,
  "total_findings": 180,
  "counts_by_severity": {
    "critical": 1,
    "high": 1,
    "medium": 1,
    "info": 3,
    "ok": 173,
    "error": 1
  },
  "findings": [ ... ]
}
```

---

## Severity ratings

| Severity | Condition |
|---|---|
| 💥 **critical** | HTTP 200 + API-doc tokens confirmed in response body |
| 🔴 **high** | HTTP 200 + API JSON/YAML content type (unconfirmed body) |
| 🟡 **medium** | HTTP 2xx/3xx with redirect toward a documentation path |
| 🔵 **info** | Endpoint exists but is protected (401/403) or an unexpected redirect |
| 🟢 **ok** | HTTP 404 — endpoint not present, **or** reachable but no documentation content detected |
| ⚫ **error** | Network error, DNS failure, timeout |

---

## Requirements

- **Python 3.9+**
- **No third-party libraries** — uses only the Python standard library

---

## Disclaimer

> This tool is intended **exclusively** for use against systems you own or have explicit written permission to assess.  
> Unauthorised scanning may violate computer crime laws in your jurisdiction.  
> The authors accept no liability for misuse.
