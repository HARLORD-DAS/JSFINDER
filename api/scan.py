"""
JSLeakHunter — Vercel Serverless Function Entry Point (/api/scan)
Hardened with SSRF Protection, Safe Stream Reading, CORS Headers,
and Genuine Per-Resource Attribution.
"""
import re
import os
import sys
import json
import socket
import ipaddress
from collections import defaultdict
from urllib.parse import urljoin, urlparse, parse_qs
from http.server import BaseHTTPRequestHandler
import requests
import urllib3
from bs4 import BeautifulSoup

# Suppress insecure request warnings for robust scanning of targets with self-signed SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/javascript,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 10
TIMEOUT = (CONNECT_TIMEOUT, READ_TIMEOUT)
MAX_PAGE_SIZE = 2 * 1024 * 1024   # 2 MB for HTML
MAX_JS_SIZE = 10 * 1024 * 1024    # 10 MB per JS file
MAX_JS_FILES = 60                 # Max scripts scanned per site
MAX_REDIRECTS = 5

PATTERNS = {
    "Email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    "AWS Key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Internal IP": re.compile(r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.(?:\d{1,3})\.(?:\d{1,3})|172\.(?:1[6-9]|2\d|3[0-1])\.(?:\d{1,3})\.(?:\d{1,3}))\b"),
    "API Endpoint": re.compile(r'''["']((?:/api(?:/|["'])|/internal(?:/|["']))[^"' \t\r\n]*)'''),
}

BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
]

def is_safe_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        if hasattr(ip, "ipv4_mapped") and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return False
        for net in BLOCKED_NETWORKS:
            if ip in net:
                return False
        return True
    except ValueError:
        return False

def validate_url_target(url: str, allow_local: bool = False) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Prohibited URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are allowed.")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid target URL: missing hostname.")

    clean_host = hostname.strip().lower()
    if allow_local:
        return

    if clean_host in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "metadata.google.internal"):
        raise ValueError(f"SSRF Protection: Access to '{clean_host}' is strictly prohibited.")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        addr_info = socket.getaddrinfo(clean_host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"DNS resolution failed for '{clean_host}': {exc}")

    if not addr_info:
        raise ValueError(f"No IP addresses resolved for '{clean_host}'")

    for info in addr_info:
        ip_str = info[4][0]
        if not is_safe_ip(ip_str):
            raise ValueError(
                f"SSRF Protection: Target '{clean_host}' resolved to restricted address ({ip_str}). "
                "Private, loopback, and cloud metadata network destinations are blocked."
            )

def safe_fetch(url: str, max_size: int = MAX_PAGE_SIZE, allow_local: bool = False):
    current_url = url
    for _ in range(MAX_REDIRECTS):
        validate_url_target(current_url, allow_local=allow_local)
        try:
            resp = requests.get(
                current_url,
                headers=HEADERS,
                timeout=TIMEOUT,
                stream=True,
                allow_redirects=False,
                verify=False
            )
        except requests.RequestException as exc:
            raise requests.RequestException(f"Failed to connect to {current_url}: {exc}")

        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location")
            if not loc:
                raise ValueError(f"Redirect from {current_url} missing Location header.")
            current_url = urljoin(current_url, loc)
            continue

        resp.raise_for_status()

        chunks = []
        total = 0
        for chunk in resp.iter_content(chunk_size=16384):
            total += len(chunk)
            if total > max_size:
                chunks.append(chunk[:max_size - (total - len(chunk))])
                break
            chunks.append(chunk)

        encoding = resp.encoding or "utf-8"
        raw_bytes = b"".join(chunks)
        try:
            text = raw_bytes.decode(encoding, errors="replace")
        except Exception:
            text = raw_bytes.decode("utf-8", errors="replace")
        return current_url, text

    raise ValueError(f"Exceeded maximum redirect limit ({MAX_REDIRECTS}) for {url}")

def get_js_files(url: str, allow_local: bool = False) -> set:
    final_url, text = safe_fetch(url, max_size=MAX_PAGE_SIZE, allow_local=allow_local)
    soup = BeautifulSoup(text, "html.parser")
    found = set()
    for script in soup.find_all("script", src=True):
        src = script["src"].strip()
        if not src or src.startswith("data:") or src.startswith("javascript:"):
            continue
        full_url = urljoin(final_url, src)
        p = urlparse(full_url)
        if p.scheme in ("http", "https"):
            found.add(full_url)
        if len(found) >= MAX_JS_FILES:
            break
    return found

def scan_js(js_url: str, allow_local: bool = False) -> defaultdict:
    findings = defaultdict(set)
    try:
        _, text = safe_fetch(js_url, max_size=MAX_JS_SIZE, allow_local=allow_local)
    except Exception as exc:
        print(f"[!] Unable to fetch JavaScript file {js_url}: {exc}")
        return findings

    for category, pattern in PATTERNS.items():
        for match in pattern.findall(text):
            val = match if isinstance(match, str) else match[0]
            val = val.strip()
            if val:
                findings[category].add(val)
    return findings

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        return ""
    if "://" in url:
        return url
    return "https://" + url

class handler(BaseHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        target = query.get("url", [""])[0]

        if not target:
            self.send_json({"status": "error", "message": "Target URL is required"}, 400)
            return

        target = normalize_url(target)
        allow_local = os.environ.get("JSLEAKHUNTER_ALLOW_LOCAL", "").lower() in ("1", "true", "yes")

        try:
            validate_url_target(target, allow_local=allow_local)
        except ValueError as val_err:
            self.send_json({"status": "error", "message": str(val_err)}, 400)
            return

        try:
            js_files = get_js_files(target, allow_local=allow_local)
            all_findings = defaultdict(set)
            resources = []

            for js_url in sorted(js_files):
                findings = scan_js(js_url, allow_local=allow_local)
                file_findings = {}
                file_total = 0
                for cat in PATTERNS:
                    matches = sorted(list(findings.get(cat, set())))
                    file_findings[cat] = matches
                    file_total += len(matches)
                    all_findings[cat].update(matches)

                resources.append({
                    "url": js_url,
                    "findings": file_findings,
                    "total": file_total
                })

            serializable_findings = {}
            total_findings = 0
            for category in PATTERNS:
                vals = sorted(list(all_findings.get(category, set())))
                serializable_findings[category] = vals
                total_findings += len(vals)

            self.send_json({
                "status": "success",
                "target": target,
                "js_files": sorted(list(js_files)),
                "findings": serializable_findings,
                "total_findings": total_findings,
                "resources": resources
            })
        except Exception as exc:
            self.send_json({
                "status": "error",
                "message": f"Unable to reach or scan the target website: {exc}"
            }, 502)

    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))
