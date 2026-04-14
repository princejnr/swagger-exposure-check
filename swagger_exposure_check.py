#!/usr/bin/env python3
"""
swagger-exposure-check v3.1 — DEFENSIVE USE ONLY

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  IMPORTANT — AUTHORISED USE ONLY
  Run this tool ONLY against infrastructure you own or have
  explicit written permission to assess. Unauthorised scanning
  may violate computer crime laws in your jurisdiction.
  The authors accept NO liability for misuse.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Checks Swagger/OpenAPI documentation endpoints on approved hosts.

Features:
  - Conservative defaults (3 workers) — designed for authorised audits, not spray scanning
  - Wildcard entries (*.example.com) require --enumerate-subdomains to activate
  - Subdomain OSINT via Certificate Transparency logs (crt.sh) + wordlist expansion
  - DNS validation filters candidates to only live hosts before probing
  - Custom HTTP headers (useful for WAF bypasses or authenticated scanning)
  - Partial body read (4 KB) for accurate content detection
  - Coloured live console table + CSV, JSON, and raw URL text outputs
  - Automatic retries on transient network errors
  - Interactive consent gate — you must confirm scope before scanning begins
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
    "high":   "\033[91m",
    "medium": "\033[93m",
    "info":   "\033[96m",
    "ok":     "\033[92m",
    "error":  "\033[90m",
    "reset":  "\033[0m",
    "bold":   "\033[1m",
    "dim":    "\033[2m",
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
        req.add_header("User-Agent", "swagger-exposure-check/3.1")
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
        ("User-Agent", "swagger-exposure-check/3.1"),
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
) -> tuple[str, str]:
    lowered_type = content_type.lower()
    lowered_url = final_url.lower()
    if err:
        return "error", err
    if status == 200:
        if body_confirmed:
            return "high", "API documentation confirmed in body"
        if any(t in lowered_type for t in ("json", "yaml", "html", "text/plain")):
            return "high", "endpoint reachable"
        return "medium", "reachable with uncommon content type"
    if status in (301, 302, 307, 308):
        doc_tokens = ("swagger", "api-docs", "openapi", "redoc", "docs")
        if any(t in lowered_url for t in doc_tokens):
            return "medium", "redirects toward documentation endpoint"
        return "info", "redirected"
    if status in (401, 403):
        return "info", "endpoint present but protected"
    if status == 404:
        return "ok", "not found"
    if status:
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
                ct: str = resp.headers.get("Content-Type", "")
                final_url: str = resp.geturl()
                body = resp.read(MAX_BODY_READ)
                confirmed = _body_confirmed(body)
                sev, note = classify(status, ct, final_url, path, "", confirmed)
                return Finding(host, path, url, status, ct, final_url, confirmed, sev, note, "")
        except error.HTTPError as exc:
            ct = exc.headers.get("Content-Type", "")
            fu = exc.geturl() or url
            sev, note = classify(exc.code, ct, fu, path, "")
            return Finding(host, path, url, exc.code, ct, fu, False, sev, note, "")
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt < retries:
                time.sleep(RETRY_BACKOFF * (attempt + 1))

    msg = str(last_exc).strip() if last_exc else "unknown error"
    msg = msg or (last_exc.__class__.__name__ if last_exc else "unknown error")
    sev, note = classify(None, "", url, path, msg)
    return Finding(host, path, url, None, "", url, False, sev, note, msg)


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
) -> list[Finding]:
    tasks = []
    for host in hosts:
        for path in paths:
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

_SEV_ICON = {"high": "🔴", "medium": "🟡", "info": "🔵", "ok": "🟢", "error": "⚫"}


def _print_progress(finding: Finding, done: int, total: int) -> None:
    sev = finding.severity
    icon = _SEV_ICON.get(sev, "  ")
    status_str = str(finding.status) if finding.status else "ERR"
    width = len(str(total))
    sev_lbl = colour(sev.upper().rjust(6), sev)
    print(f"  [{done:>{width}}/{total}] {icon} {status_str:>3}  {sev_lbl}  {finding.url}")


def print_summary(findings: list[Finding]) -> None:
    counts = {lv: sum(1 for f in findings if f.severity == lv)
              for lv in ("high", "medium", "info", "ok", "error")}

    print()
    print(colour("━" * 64, "bold"))
    print(colour("  SUMMARY", "bold"))
    print(colour("━" * 64, "bold"))

    for level, count in counts.items():
        if count == 0:
            continue
        bar = "█" * min(count, 40)
        lbl = colour(level.upper().rjust(8), level)
        print(f"  {lbl}  {bar}  {count}")

    high_findings = [f for f in findings if f.severity == "high"]
    if high_findings:
        print()
        print(colour("  ⚠  HIGH severity endpoints:", "high"))
        for f in high_findings:
            confirmed_tag = " (body-confirmed)" if f.body_confirmed else ""
            print(f"       {f.url}  [{f.note}{confirmed_tag}]")

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
        "host", "path", "url", "status", "content_type",
        "final_url", "body_confirmed", "severity", "note", "error",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for f in findings:
            writer.writerow(asdict(f))

    summary = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "total_hosts_probed": len({f.host for f in findings}),
        "total_findings": len(findings),
        "counts_by_severity": {
            lv: sum(1 for f in findings if f.severity == lv)
            for lv in ("high", "medium", "info", "ok", "error")
        },
        "findings": [asdict(f) for f in findings],
    }
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    
    if output_urls_file:
        urls_path = Path(output_urls_file)
        urls_path.parent.mkdir(parents=True, exist_ok=True)
        exposed_urls = [f.url for f in findings if f.severity in ("high", "medium")]
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

    total_checks = len(hosts) * len(paths)
    print(colour("\n  swagger-exposure-check v3.1", "bold"))
    print(
        f"  Hosts: {len(hosts)}  |  Paths: {len(paths)}  |  "
        f"Total checks: {total_checks}  |  Workers: {args.workers}"
    )
    if wildcards and args.enumerate_subdomains:
        dns_label = "with DNS filter" if dns_check else "no DNS filter"
        print(colour(f"  Wildcards: {', '.join(wildcards)}  ({dns_label})", "dim"))
    print()

    findings = iter_findings(hosts, paths, scheme, opener, args.timeout, args.retries, args.workers)
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
