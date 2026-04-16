#!/usr/bin/env python3
"""
swagger-exposure-check — DEFENSIVE USE ONLY

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  IMPORTANT — AUTHORISED USE ONLY
  Run this tool ONLY against infrastructure you own or have
  explicit written permission to assess. Unauthorised scanning
  may violate computer crime laws in your jurisdiction.
  The authors accept NO liability for misuse.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib import error, request

__version__ = "3.2.0"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_PATHS: list[str] = [
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v3/swagger.json",
    "/docs",
    "/redoc",
]

# Common subdomains probed when a wildcard entry (*.example.com) is given.
DEFAULT_SUBDOMAINS: list[str] = [
    "www", "api", "api2", "api-v1", "api-v2", "dev", "staging", "stage",
    "uat", "qa", "test", "sandbox", "demo", "preview",
    "admin", "portal", "dashboard", "console", "management", "manager",
    "internal", "intranet", "private",
    "gateway", "gw", "proxy", "lb",
    "docs", "documentation", "swagger", "openapi", "redoc",
    "service", "services", "svc",
    "app", "apps", "mobile", "m",
    "auth", "login", "sso", "oauth", "identity",
    "data", "analytics", "reporting", "report",
    "backend", "backend-api", "server",
    "v1", "v2", "v3",
    "prod", "production",
    "legacy", "old",
    "partner", "partners", "b2b", "external",
    "payments", "pay", "checkout", "billing",
    "notifications", "notify", "webhooks",
    "cdn", "static", "assets",
]

BODY_CONFIRMATION_TOKENS: tuple[str, ...] = (
    '"openapi"', '"swagger"', "openapi:",
    "swagger:", "swagger-ui", "SwaggerUIBundle", "redoc", "ReDoc",
)

# New security check constants
SECURITY_HEADERS: dict[str, str] = {
    "X-Frame-Options": "Prevents Clickjacking (e.g. DENY, SAMEORIGIN)",
    "Content-Security-Policy": "Mitigates XSS and data injection (e.g. default-src 'self')",
    "X-Content-Type-Options": "Prevents MIME-sniffing (e.g. nosniff)",
    "Strict-Transport-Security": "Forces HTTPS (HSTS)",
}

WAF_INDICATORS: tuple[str, ...] = (
    "cloudflare", "cf-ray", "incapsula", "sucuri", "akami", "imperva",
    "f5", "barracuda", "wordfence", "mod_security", "fortinet",
)

WAYBACK_TOKENS: tuple[str, ...] = (
    "swagger", "openapi", "api-docs", "redoc", "docs", ".json", ".yaml", ".yml",
)

JS_SRC_REGEX = re.compile(r'src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
API_PATH_REGEX = re.compile(r'["\'](/[a-zA-Z0-9._\-/{}]+(?:swagger|openapi|api-docs|redoc)[a-zA-Z0-9._\-/{}]*)["\']', re.IGNORECASE)

MAX_BODY_READ = 4096
DEFAULT_WORKERS = 3        # Conservative default — raise with --workers for authorised bulk audits
DEFAULT_DNS_WORKERS = 20
DEFAULT_RETRIES = 2
RETRY_BACKOFF = 0.5

# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------

_USE_COLOUR = sys.stdout.isatty()
_COLOURS = {
    "critical": "\033[1;31m",
    "high":     "\033[91m",
    "medium":   "\033[93m",
    "info":     "\033[96m",
    "ok":       "\033[92m",
    "error":    "\033[90m",
    "reset":    "\033[0m",
    "bold":     "\033[1m",
    "dim":      "\033[2m",
}


def colour(text: str, key: str) -> str:
    if not _USE_COLOUR:
        return text
    return f"{_COLOURS.get(key, '')}{text}{_COLOURS['reset']}"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    host: str
    path: str
    url: str
    status: int | None
    content_type: str
    final_url: str
    body_confirmed: bool
    severity: str
    note: str
    error: str
    missing_headers: list[str] = field(default_factory=list)
    waf_detected: str = ""


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Check approved hosts for exposed Swagger/OpenAPI endpoints.\n"
            "Supports wildcard entries (*.example.com) that are expanded via DNS."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "hosts_file",
        nargs="?",
        default="hosts.txt",
        help="Text file with one hostname (or host:port or *.domain) per line. Default: hosts.txt.",
    )
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="HTTP request timeout in seconds. Default: 10.")
    parser.add_argument("--http", action="store_true",
                        help="Probe http:// instead of https://.")
    parser.add_argument("--insecure", action="store_true",
                        help="Disable TLS certificate verification.")
    parser.add_argument("--paths-file",
                        help="File of paths to probe, one per line.")
    parser.add_argument("-H", "--header", action="append", default=[],
                        help="Custom header in 'Key: Value' format. Can be used multiple times.")
    parser.add_argument("--subdomains-file",
                        help="Custom subdomain wordlist for wildcard expansion, one per line.")
    parser.add_argument("--enumerate-subdomains", action="store_true",
                        help="Activate subdomain enumeration (crt.sh + wordlist) for *.domain entries.")
    parser.add_argument("--no-dns-check", action="store_true",
                        help="Skip DNS validation when expanding wildcards (probe all candidates).")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                        help=f"HTTP probe worker threads. Default: {DEFAULT_WORKERS} (conservative).")
    parser.add_argument("--dns-workers", type=int, default=DEFAULT_DNS_WORKERS,
                        help=f"DNS resolution worker threads. Default: {DEFAULT_DNS_WORKERS}.")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES,
                        help=f"Retries on transient errors. Default: {DEFAULT_RETRIES}.")
    parser.add_argument("--output-dir", default=".",
                        help="Directory to write reports into. Default: current directory.")
    parser.add_argument("--output-urls",
                        help="Optional: extract just the URLs of HIGH/MEDIUM findings to a text file.")
    parser.add_argument("--use-wayback", action="store_true",
                        help="Query Wayback Machine (CDX) for historical URLs (discovery).")
    parser.add_argument("--use-js", action="store_true",
                        help="Scrape .js bundles for hidden API paths (discovery).")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--yes", action="store_true",
                        help="Skip the interactive authorisation confirmation prompt (for CI/scripts).")
    return parser.parse_args()


# ---------------------------------------------------------------------------
# File loading helpers
# ---------------------------------------------------------------------------

def load_lines(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(f"file not found: {path}")
    lines: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


# ---------------------------------------------------------------------------
# Wildcard / subdomain expansion
# ---------------------------------------------------------------------------

def is_wildcard(entry: str) -> bool:
    return entry.startswith("*.") or entry.startswith("*.")


def expand_wildcard(
    pattern: str,
    subdomains: list[str],
    dns_check: bool,
    dns_workers: int,
    timeout: float,
) -> list[str]:
    """
    Expand *.example.com -> [api.example.com, dev.example.com, ...]
    Uses both a local wordlist and OSINT (crt.sh Certificate Transparency logs).
    If dns_check is True, only return entries that resolve in DNS.
    """
    domain = re.sub(r"^\*\.", "", pattern)
    
    print(colour(f"\n  ⟳  Enumerating subdomains for {pattern} ...", "dim"))
    
    candidates_set = {f"{sub}.{domain}" for sub in subdomains}
    
    # OSINT: crt.sh Certificate Transparency lookup
    try:
        print(colour("     Querying Certificate Transparency logs (crt.sh) ...", "dim"))
        req = request.Request(f"https://crt.sh/?q=%.{domain}&output=json", method="GET")
        req.add_header("User-Agent", f"swagger-exposure-check/{__version__}")
        with request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode('utf-8'))
                for entry in data:
                    name = entry.get("name_value", "")
                    # crt.sh returns multi-line strings for certs with multiple SANs
                    for n in name.splitlines():
                        n = n.strip().lower()
                        if n.endswith(domain) and not n.startswith("*"):
                            candidates_set.add(n)
        print(colour(f"     Combined OSINT + Wordlist: {len(candidates_set)} unique candidates", "dim"))
    except Exception as exc:
        print(colour(f"     ⚠ OSINT fetch failed ({exc}), falling back to wordlist only.", "medium"))
    
    candidates = list(candidates_set)

    if not dns_check:
        return candidates

    print(colour(f"     Validating DNS resolution ({len(candidates)} candidates) ...", "dim"))

    resolved: list[str] = []

    def _resolve(host: str) -> str | None:
        try:
            socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            return host
        except (socket.gaierror, OSError):
            return None

    with ThreadPoolExecutor(max_workers=dns_workers) as pool:
        for result in pool.map(_resolve, candidates):
            if result:
                resolved.append(result)

    print(colour(f"     {len(resolved)} subdomain(s) resolved for {pattern}\n", "dim"))
    return resolved


def expand_hosts(
    raw_hosts: list[str],
    subdomains: list[str],
    dns_check: bool,
    dns_workers: int,
    timeout: float,
) -> list[str]:
    """Expand wildcard entries; pass through concrete hosts unchanged."""
    final: list[str] = []
    for entry in raw_hosts:
        if is_wildcard(entry):
            expanded = expand_wildcard(entry, subdomains, dns_check, dns_workers, timeout)
            final.extend(expanded)
        else:
            final.append(entry)
    # Deduplicate, preserve order
    seen: set[str] = set()
    unique: list[str] = []
    for h in final:
        if h not in seen:
            seen.add(h)
            unique.append(h)
    return unique


def fetch_wayback_urls(host: str, timeout: float) -> set[str]:
    """
    Query Wayback Machine CDX for historical URLs of a given host.
    Filters results for potential Swagger/OpenAPI endpoints.
    """
    print(colour(f"     ⟳  Querying Wayback Machine for {host} ...", "dim"))
    found_paths: set[str] = set()
    cdx_url = f"https://web.archive.org/cdx/search/cdx?url={host}/*&output=json&fl=original&collapse=urlkey"
    
    try:
        req = request.Request(cdx_url, method="GET")
        req.add_header("User-Agent", f"swagger-exposure-check/{__version__}")
        with request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode('utf-8'))
                if not data or len(data) < 2:
                    return found_paths
                
                # First row is header: ["original"]
                for row in data[1:]:
                    original_url = row[0]
                    try:
                        # Extract path from URL
                        # Split by host and take the last part
                        if host in original_url:
                            path = original_url.split(host, 1)[-1]
                            if not path.startswith("/"):
                                path = f"/{path}"
                            
                            # Filter for interesting tokens
                            if any(t in path.lower() for t in WAYBACK_TOKENS):
                                # Remove query params for cleaner path probing
                                clean_path = path.split("?")[0].split("#")[0]
                                
                                # Noise reduction: skip paths with likely garbage/encoding artifacts
                                garbage_indicators = ("%", "\\", "\"", "'", "<", ">", "http", ":", " ", " h ", " -", ",")
                                if any(g in clean_path.lower() for g in garbage_indicators):
                                    continue
                                    
                                if clean_path and clean_path != "/":
                                    found_paths.add(clean_path)
                    except Exception:
                        continue
        if found_paths:
            print(colour(f"        ✓ Discovered {len(found_paths)} unique historical paths", "dim"))
    except Exception as exc:
        print(colour(f"        ⚠ Wayback fetch failed for {host} ({exc})", "error"))
        
    return found_paths


def scrape_js_urls(
    opener: request.OpenerDirector,
    host: str,
    base_url: str,
    html_content: str,
    timeout: float,
) -> set[str]:
    """
    Find <script src="..."> tags in HTML, fetch the JS, and scrape for API paths.
    """
    discovered_paths: set[str] = set()
    script_srcs = JS_SRC_REGEX.findall(html_content)
    if not script_srcs:
        return discovered_paths

    print(colour(f"     ⟳  Scraping {len(script_srcs)} JS bundles for {host} ...", "dim"))
    
    for src in script_srcs:
        # Resolve relative URLs
        if src.startswith("//"):
            js_url = f"https:{src}"
        elif src.startswith("/"):
            js_url = f"{base_url.rstrip('/')}{src}"
        elif src.startswith("http"):
            js_url = src
        else:
            js_url = f"{base_url.rstrip('/')}/{src}"

        # Only scrape JS from the same host to be polite/safe
        if host not in js_url:
            continue

        try:
            req = request.Request(js_url, method="GET")
            req.add_header("User-Agent", f"swagger-exposure-check/{__version__}")
            with opener.open(req, timeout=timeout) as resp:
                if resp.status == 200:
                    js_content = resp.read(MAX_BODY_READ * 10).decode("utf-8", errors="replace")
                    # Find potential API paths
                    matches = API_PATH_REGEX.findall(js_content)
                    for m in matches:
                        clean_m = m.split("?")[0].split("#")[0]
                        if clean_m and clean_m != "/":
                            discovered_paths.add(clean_m)
        except Exception:
            continue
            
    if discovered_paths:
        print(colour(f"        ✓ Discovered {len(discovered_paths)} paths from JS scraping", "dim"))
    return discovered_paths


# ---------------------------------------------------------------------------
# HTTP plumbing
# ---------------------------------------------------------------------------

def build_opener(insecure: bool, custom_headers: list[str] = None) -> request.OpenerDirector:
    handlers: list[request.BaseHandler] = []
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(request.HTTPSHandler(context=ctx))
    opener = request.build_opener(*handlers)
    headers = [
        ("User-Agent", f"swagger-exposure-check/{__version__}"),
        ("Accept", "application/json,text/html,application/yaml,text/plain,*/*"),
    ]
    if custom_headers:
        for ch in custom_headers:
            if ":" in ch:
                k, v = ch.split(":", 1)
                headers.append((k.strip(), v.strip()))
    opener.addheaders = headers
    return opener


def _body_confirmed(body_bytes: bytes) -> bool:
    try:
        snippet = body_bytes.decode("utf-8", errors="replace")
    except Exception:
        return False
    return any(t in snippet for t in BODY_CONFIRMATION_TOKENS)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def classify(
    status: int | None,
    content_type: str,
    final_url: str,
    path: str,
    err: str,
    body_confirmed: bool = False,
    missing_headers: list[str] = None,
    waf_detected: str = "",
) -> tuple[str, str]:
    lowered_type = content_type.lower()
    lowered_url = final_url.lower()
    missing_count = len(missing_headers) if missing_headers else 0

    if err:
        if waf_detected:
            return "info", f"blocked by {waf_detected}"
        return "error", err

    if status == 200:
        note_suffix = f" (missing {missing_count} security headers)" if missing_count > 0 else ""
        if body_confirmed:
            return "critical", f"unprotected API docs confirmed in body{note_suffix}"
        
        # If not confirmed in body, be more skeptical of common web types (often custom 404s)
        if any(t in lowered_type for t in ("json", "yaml")):
            return "high", f"endpoint reachable (likely API data){note_suffix}"
        
        if any(t in lowered_type for t in ("html", "text/plain")):
            # If it's just HTML/Text and NOT confirmed, it's likely a generic landing or 404 page
            return "ok", "reachable but no API documentation detected"
            
        return "medium", f"reachable with uncommon content type{note_suffix}"

    if status in (301, 302, 307, 308):
        doc_tokens = ("swagger", "api-docs", "openapi", "redoc", "docs")
        if any(t in lowered_url for t in doc_tokens):
            return "medium", "redirects toward documentation endpoint"
        return "info", "redirected"

    if status in (401, 403):
        if waf_detected:
            return "info", f"protected/blocked by {waf_detected}"
        return "ok", "endpoint present but protected"

    if status == 404:
        return "ok", "not found"

    if status:
        if waf_detected:
            return "info", f"http {status} (via {waf_detected})"
        return "info", f"http {status}"

    return "error", f"no response for {path}"


# ---------------------------------------------------------------------------
# Fetch with retry
# ---------------------------------------------------------------------------

def fetch(
    opener: request.OpenerDirector,
    timeout: float,
    url: str,
    host: str,
    path: str,
    retries: int,
) -> Finding:
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            req = request.Request(url, method="GET")
            with opener.open(req, timeout=timeout) as resp:
                status: int | None = getattr(resp, "status", None)
                headers = resp.headers
                ct: str = headers.get("Content-Type", "")
                final_url: str = resp.geturl()
                
                # Check for WAF
                waf = ""
                header_text = str(headers).lower()
                for indicator in WAF_INDICATORS:
                    if indicator in header_text:
                        waf = indicator
                        break
                
                # Check for security headers
                missing = []
                for sh in SECURITY_HEADERS:
                    if sh not in headers:
                        missing.append(sh)
                
                body = resp.read(MAX_BODY_READ)
                confirmed = _body_confirmed(body)
                sev, note = classify(status, ct, final_url, path, "", confirmed, missing, waf)
                return Finding(host, path, url, status, ct, final_url, confirmed, sev, note, "", missing, waf)
        
        except error.HTTPError as exc:
            headers = exc.headers
            ct = headers.get("Content-Type", "")
            fu = exc.geturl() or url
            
            # WAF detection on error
            waf = ""
            header_text = str(headers).lower()
            for indicator in WAF_INDICATORS:
                if indicator in header_text:
                    waf = indicator
                    break
            
            sev, note = classify(exc.code, ct, fu, path, "", False, [], waf)
            return Finding(host, path, url, exc.code, ct, fu, False, sev, note, "", [], waf)
            
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt < retries:
                time.sleep(RETRY_BACKOFF * (attempt + 1))

    msg = str(last_exc).strip() if last_exc else "unknown error"
    msg = msg or (last_exc.__class__.__name__ if last_exc else "unknown error")
    sev, note = classify(None, "", url, path, msg)
    return Finding(host, path, url, None, "", url, False, sev, note, msg, [], "")


# ---------------------------------------------------------------------------
# Concurrent scanning
# ---------------------------------------------------------------------------

def iter_findings(
    hosts: list[str],
    paths: list[str],
    scheme: str,
    opener: request.OpenerDirector,
    timeout: float,
    retries: int,
    workers: int,
    custom_host_paths: dict[str, set[str]] = None,
) -> list[Finding]:
    tasks = []
    custom_host_paths = custom_host_paths or {}
    for host in hosts:
        # Combine default paths with host-specific discovered paths
        host_paths = set(paths) | custom_host_paths.get(host, set())
        for path in host_paths:
            normalized = path if path.startswith("/") else f"/{path}"
            url = f"{scheme}://{host}{normalized}"
            tasks.append((url, host, normalized))

    findings: list[Finding] = []
    total = len(tasks)
    done = 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(fetch, opener, timeout, url, host, path, retries): (url, host, path)
            for url, host, path in tasks
        }
        for future in as_completed(futures):
            finding = future.result()
            findings.append(finding)
            done += 1
            _print_progress(finding, done, total)

    findings.sort(key=lambda f: (f.host, f.path))
    return findings


# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------

_SEV_ICON = {
    "critical": "💥",
    "high": "🔴",
    "medium": "🟡",
    "info": "🔵",
    "ok": "🟢",
    "error": "⚫",
}


def _print_progress(finding: Finding, done: int, total: int) -> None:
    sev = finding.severity
    icon = _SEV_ICON.get(sev, "  ")
    status_str = str(finding.status) if finding.status else "ERR"
    width = len(str(total))
    sev_lbl = colour(sev.upper().rjust(8), sev)
    print(f"  [{done:>{width}}/{total}] {icon} {status_str:>3}  {sev_lbl}  {finding.url}")


def print_summary(findings: list[Finding]) -> None:
    lvls = ("critical", "high", "medium", "info", "ok", "error")
    counts = {lv: sum(1 for f in findings if f.severity == lv) for lv in lvls}

    print()
    print(colour("━" * 64, "bold"))
    print(colour("  SUMMARY", "bold"))
    print(colour("━" * 64, "bold"))

    for level in lvls:
        count = counts[level]
        if count == 0:
            continue
        bar = "█" * min(count, 40)
        lbl = colour(level.upper().rjust(8), level)
        print(f"  {lbl}  {bar}  {count}")

    # Show Critical/High findings in detail
    warn_findings = [f for f in findings if f.severity in ("critical", "high")]
    if warn_findings:
        print()
        print(colour("  ⚠  CRITICAL / HIGH severity endpoints:", "critical"))
        for f in warn_findings:
            waf_tag = f" [WAF: {f.waf_detected}]" if f.waf_detected else ""
            headers_tag = f" [Missing: {', '.join(f.missing_headers)}]" if f.missing_headers else ""
            print(f"       {f.url}{waf_tag}{headers_tag}")
            print(f"       Note: {f.note}")

    print(colour("━" * 64, "bold"))
    print()


# ---------------------------------------------------------------------------
# Report writing
# ---------------------------------------------------------------------------

def write_reports(findings: list[Finding], output_dir: Path, output_urls_file: str | None = None) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    csv_path = output_dir / f"swagger_exposure_report_{stamp}.csv"
    json_path = output_dir / f"swagger_exposure_report_{stamp}.json"

    fieldnames = [
        "tool_version", "host", "path", "url", "status", "content_type",
        "final_url", "body_confirmed", "severity", "note", "error",
        "missing_headers", "waf_detected"
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for f in findings:
            row = asdict(f)
            row["tool_version"] = __version__
            row["missing_headers"] = ", ".join(row["missing_headers"])
            writer.writerow(row)

    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "tool_version": __version__,
        "total_hosts_probed": len({f.host for f in findings}),
        "total_findings": len(findings),
        "counts_by_severity": {
            lv: sum(1 for f in findings if f.severity == lv)
            for lv in ("critical", "high", "medium", "info", "ok", "error")
        },
        "findings": [asdict(f) for f in findings],
    }
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    if output_urls_file:
        urls_path = Path(output_urls_file)
        urls_path.parent.mkdir(parents=True, exist_ok=True)
        exposed_urls = [f.url for f in findings if f.severity in ("critical", "high", "medium")]
        urls_path.write_text("\n".join(exposed_urls) + "\n", encoding="utf-8")

    return csv_path, json_path


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _confirm_scope(hosts: list[str], yes: bool) -> bool:
    """
    Print a clear scope summary and require explicit confirmation
    unless --yes was passed (for CI / scripted use).
    """
    print(colour("\n  ╔══════════════════════════════════════════════════════════╗", "bold"))
    print(colour("  ║          AUTHORISED USE CONFIRMATION                     ║", "bold"))
    print(colour("  ╚══════════════════════════════════════════════════════════╝", "bold"))
    print()
    print("  You are about to probe the following targets:")
    for h in hosts:
        print(f"    • {h}")
    print()
    print(colour("  ⚠  Only proceed if you own these systems or have written", "medium"))
    print(colour("     authorisation to perform security testing on them.", "medium"))
    print()
    if yes:
        print(colour("  --yes flag set: skipping interactive prompt.", "dim"))
        return True
    try:
        answer = input("  Confirm you are authorised to scan all targets above [yes/no]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer == "yes"


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)

    try:
        raw_hosts = load_lines(Path(args.hosts_file))
        paths = load_lines(Path(args.paths_file)) if args.paths_file else DEFAULT_PATHS
        subdomains = (
            load_lines(Path(args.subdomains_file))
            if args.subdomains_file
            else DEFAULT_SUBDOMAINS
        )
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    # Warn and exit if wildcard entries are present but --enumerate-subdomains not set
    wildcards = [h for h in raw_hosts if is_wildcard(h)]
    if wildcards and not args.enumerate_subdomains:
        print(colour("\n  ⚠  Wildcard entries detected in hosts file:", "medium"), file=sys.stderr)
        for w in wildcards:
            print(f"     {w}", file=sys.stderr)
        print(colour(
            "\n  Subdomain enumeration is OFF by default.\n"
            "  Add --enumerate-subdomains to activate it.\n"
            "  Wildcard entries will be skipped this run.\n", "medium"
        ), file=sys.stderr)
        raw_hosts = [h for h in raw_hosts if not is_wildcard(h)]
        if not raw_hosts:
            print("  No concrete hosts remaining. Exiting.", file=sys.stderr)
            return 1

    # Expand wildcards -> concrete host list (only if flag is set)
    dns_check = not args.no_dns_check
    if args.enumerate_subdomains:
        hosts = expand_hosts(raw_hosts, subdomains, dns_check, args.dns_workers, args.timeout)
    else:
        hosts = raw_hosts

    # Interactive consent gate — must confirm scope before any probing
    if not _confirm_scope(hosts, args.yes):
        print(colour("\n  Scan aborted — authorisation not confirmed.\n", "error"))
        return 1

    scheme = "http" if args.http else "https"
    opener = build_opener(args.insecure, args.header)

    custom_host_paths = {}
    total_discovered = 0
    if args.use_wayback:
        print(colour("\n  ⟳  Phase 1: Historical Discovery (Wayback Machine)", "bold"))
        osint_timeout = max(30.0, args.timeout)
        for host in hosts:
            discovered = fetch_wayback_urls(host, osint_timeout)
            if discovered:
                custom_host_paths.setdefault(host, set()).update(discovered)
                total_discovered += len(discovered)
        print(colour(f"     Discovery complete: {total_discovered} historical paths found.\n", "dim"))

    if args.use_js:
        print(colour("  ⟳  Phase 2: Automated JS Scraping", "bold"))
        for host in hosts:
            base_url = f"{scheme}://{host}"
            try:
                req = request.Request(base_url, method="GET")
                req.add_header("User-Agent", f"swagger-exposure-check/{__version__}")
                with opener.open(req, timeout=args.timeout) as resp:
                    if "text/html" in resp.headers.get("Content-Type", "").lower():
                        html = resp.read(MAX_BODY_READ * 2).decode("utf-8", errors="replace")
                        js_paths = scrape_js_urls(opener, host, base_url, html, args.timeout)
                        if js_paths:
                            custom_host_paths.setdefault(host, set()).update(js_paths)
                            total_discovered += len(js_paths)
            except Exception as exc:
                print(colour(f"        ⚠ Root fetch failed for {host} ({exc})", "error"))
        print(colour(f"     JS scraping complete.\n", "dim"))

    total_checks = (len(hosts) * len(paths)) + total_discovered
    print(colour(f"\n  swagger-exposure-check v{__version__}", "bold"))
    print(
        f"  Hosts: {len(hosts)}  |  Paths: {len(paths)}  |  "
        f"Total checks: {total_checks}  |  Workers: {args.workers}"
    )
    if total_discovered > 0:
        print(colour(f"  + {total_discovered} unique discovered paths will be probed.", "dim"))
    
    if wildcards and args.enumerate_subdomains:
        dns_label = "with DNS filter" if dns_check else "no DNS filter"
        print(colour(f"  Wildcards: {', '.join(wildcards)}  ({dns_label})", "dim"))
    print()

    findings = iter_findings(
        hosts, paths, scheme, opener, args.timeout, args.retries, args.workers, custom_host_paths
    )
    print_summary(findings)

    csv_path, json_path = write_reports(findings, output_dir, args.output_urls)
    print(f"  CSV  → {csv_path}")
    print(f"  JSON → {json_path}")
    if args.output_urls:
        print(f"  TXT  → {args.output_urls}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
