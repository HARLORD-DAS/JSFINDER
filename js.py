#!/usr/bin/env python3
"""
JSLeakHunter — World-Class Passive JavaScript Exposure Scanner
Hardened Backend Engine with SSRF Protection, Safe Stream Reading,
Genuine Per-Resource Attribution, and Production Static Serving.
"""
import re
import os
import sys
import json
import socket
import ipaddress
import mimetypes
import webbrowser
from collections import defaultdict
from urllib.parse import urljoin, urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import requests
from bs4 import BeautifulSoup

HEADERS = {"User-Agent": "JSLeakHunter/2.0 (Security-Audit-Scanner)"}
CONNECT_TIMEOUT = 5
READ_TIMEOUT = 10
TIMEOUT = (CONNECT_TIMEOUT, READ_TIMEOUT)
MAX_PAGE_SIZE = 2 * 1024 * 1024   # 2 MB for HTML
MAX_JS_SIZE = 10 * 1024 * 1024    # 10 MB per JS file
MAX_JS_FILES = 60                 # Max scripts scanned per site to avoid DoS
MAX_REDIRECTS = 5

PATTERNS = {
    "Email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    "AWS Key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Internal IP": re.compile(r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.(?:\d{1,3})\.(?:\d{1,3})|172\.(?:1[6-9]|2\d|3[0-1])\.(?:\d{1,3})\.(?:\d{1,3}))\b"),
    "API Endpoint": re.compile(r'''["']((?:/api(?:/|["'])|/internal(?:/|["']))[^"' \t\r\n]*)'''),
}

# Blocked IP networks for SSRF protection
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network
    ipaddress.ip_network("10.0.0.0/8"),         # Private-use (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),      # Carrier-grade NAT (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local / Cloud metadata (AWS/GCP/Azure)
    ipaddress.ip_network("172.16.0.0/12"),      # Private-use (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),     # Private-use (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmark testing
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved / Future use
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6 blocked
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-local
    ipaddress.ip_network("ff00::/8"),           # Multicast
]

def is_safe_ip(ip_str: str) -> bool:
    """Validate whether an IP address is a safe, publicly routable address."""
    try:
        ip = ipaddress.ip_address(ip_str)
        # Handle IPv4-mapped IPv6 (::ffff:192.168.1.1)
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
    """
    Validate target URL against SSRF, non-HTTP schemes, and unresolvable hosts.
    Raises ValueError on security violations or unresolvable targets.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Prohibited URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are allowed.")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid target URL: missing hostname.")

    clean_host = hostname.strip().lower()

    if allow_local:
        return

    # Direct name checks
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
    """
    Safely fetch a URL with SSRF protection, manual redirect validation,
    strict timeouts, and bounded chunked streaming.
    Returns (final_url, response_text).
    """
    current_url = url
    for _ in range(MAX_REDIRECTS):
        validate_url_target(current_url, allow_local=allow_local)
        try:
            resp = requests.get(
                current_url,
                headers=HEADERS,
                timeout=TIMEOUT,
                stream=True,
                allow_redirects=False
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

        # Read stream up to max_size
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

def get_js_files(url: str, allow_local: bool = None) -> set:
    """Discover JavaScript files from a target web page."""
    if allow_local is None:
        allow_local = os.environ.get("JSLEAKHUNTER_ALLOW_LOCAL", "").lower() in ("1", "true", "yes")

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

def scan_js(js_url: str, allow_local: bool = None) -> defaultdict:
    """Fetch and scan an individual JavaScript file against sensitive regex patterns."""
    if allow_local is None:
        allow_local = os.environ.get("JSLEAKHUNTER_ALLOW_LOCAL", "").lower() in ("1", "true", "yes")

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

class JSLeakHunterHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        sys.stdout.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), format % args))

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/scan":
            self.handle_scan(parsed)
            return

        # Static serving: prioritize built React app in dist/, fallback to UI/index.html
        base_dir = os.path.dirname(os.path.abspath(__file__))
        dist_dir = os.path.join(base_dir, "dist")
        ui_dir = os.path.join(base_dir, "UI")

        if os.path.isdir(dist_dir):
            rel_path = path.lstrip("/") or "index.html"
            target_path = os.path.join(dist_dir, rel_path)
            # Prevent path traversal
            if os.path.commonpath([dist_dir, os.path.abspath(target_path)]) != dist_dir or not os.path.exists(target_path):
                # Fallback to index.html for SPA client-side routing
                target_path = os.path.join(dist_dir, "index.html")

            self.serve_file(target_path)
            return

        if path in ("/", "/index.html"):
            ui_path = os.path.join(ui_dir, "index.html")
            if os.path.exists(ui_path):
                self.serve_file(ui_path)
                return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not Found")

    def serve_file(self, file_path):
        try:
            ctype, _ = mimetypes.guess_type(file_path)
            if not ctype:
                ctype = "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
                ctype += "; charset=utf-8"

            with open(file_path, "rb") as f:
                content = f.read()

            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except Exception as exc:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Error serving file: {exc}".encode("utf-8"))

    def handle_scan(self, parsed):
        query = parse_qs(parsed.query)
        target = query.get("url", [""])[0]
        if not target:
            self.send_json({"status": "error", "message": "Target URL is required"}, 400)
            return

        target = normalize_url(target)
        allow_local = os.environ.get("JSLEAKHUNTER_ALLOW_LOCAL", "").lower() in ("1", "true", "yes")

        # SSRF validation before launching scan
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
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True

def start_web_ui(port=5000):
    server = ReusableThreadingHTTPServer(("127.0.0.1", port), JSLeakHunterHandler)
    url = f"http://127.0.0.1:{port}"
    print(f"\n[+] Starting JSLeakHunter Engine at {url}")
    print("[+] Press Ctrl+C to stop the server.")

    if os.environ.get("JSLEAKHUNTER_NO_BROWSER", "") != "1":
        def open_browser():
            try:
                webbrowser.open(url)
            except Exception:
                pass

        import threading
        threading.Thread(target=open_browser, daemon=True).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[-] Web server stopped.")
    finally:
        server.server_close()

def run_cli_mode(target):
    print("=" * 60)
    print("                    JSLEAKHUNTER")
    print("       JavaScript Exposure Scanner (Hardened v2.0)")
    print("=" * 60)
    print(f"\n[+] Target: {target}")

    allow_local = os.environ.get("JSLEAKHUNTER_ALLOW_LOCAL", "").lower() in ("1", "true", "yes")
    try:
        validate_url_target(target, allow_local=allow_local)
        js_files = get_js_files(target, allow_local=allow_local)
    except Exception as exc:
        print(f"[!] Validation/Fetch error: {exc}")
        return

    print(f"[+] JavaScript files discovered: {len(js_files)}")
    if not js_files:
        print("\nNo JavaScript files found.")
        return

    total_findings = 0
    for js_url in sorted(js_files):
        print("\n" + "-" * 60)
        print(f"Scanning: {js_url}")
        print("-" * 60)
        findings = scan_js(js_url, allow_local=allow_local)
        file_count = 0
        for category in PATTERNS:
            values = sorted(findings.get(category, set()))
            if values:
                print(f"\n[{category}]")
                for value in values:
                    print(f"  - {value}")
                total_findings += len(values)
                file_count += len(values)
        if file_count == 0:
            print("\nNo sensitive findings detected.")

    print("\n" + "=" * 60)
    print("                    SCAN SUMMARY")
    print("=" * 60)
    print(f"Total JavaScript Files : {len(js_files)}")
    print(f"Total Findings         : {total_findings}")
    print("=" * 60)
    print("                    SCAN COMPLETE")
    print("=" * 60)

def main():
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg == "--web":
            port = 5000
            if len(sys.argv) > 2 and sys.argv[2].isdigit():
                port = int(sys.argv[2])
            start_web_ui(port)
        else:
            run_cli_mode(normalize_url(arg))
        return

    print("=" * 60)
    print("                    JSLEAKHUNTER")
    print("       JavaScript Exposure Scanner (Hardened v2.0)")
    print("=" * 60)
    print("\nAuthorized Use Only:")
    print("Scan only websites and resources that you own or have explicit permission.")
    print("=" * 60)

    target = input("\nEnter Target URL (or leave blank to start Web UI): ").strip()
    if not target or target.lower() == "web":
        start_web_ui()
    else:
        run_cli_mode(normalize_url(target))

if __name__ == "__main__":
    main()
