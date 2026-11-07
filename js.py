#!/usr/bin/env python3
import re
import os
import sys
import json
import webbrowser
from collections import defaultdict
from urllib.parse import urljoin, urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import requests
from bs4 import BeautifulSoup

HEADERS = {"User-Agent": "JSLeakHunter/1.0"}
TIMEOUT = 10
PATTERNS = {
    "Email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    "AWS Key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Internal IP": re.compile(r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.(?:\d{1,3})\.(?:\d{1,3})|172\.(?:1[6-9]|2\d|3[0-1])\.(?:\d{1,3})\.(?:\d{1,3}))\b"),
    "API Endpoint": re.compile(r'''["']((?:/api(?:/|["'])|/internal(?:/|["']))[^"' \t\r\n]*)'''),
}

def get_js_files(url):
    response = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")
    return {urljoin(response.url, script["src"]) for script in soup.find_all("script", src=True)}

def scan_js(js_url):
    findings = defaultdict(set)
    try:
        response = requests.get(js_url, headers=HEADERS, timeout=TIMEOUT)
        response.raise_for_status()
    except requests.RequestException as exc:
        print(f"[!] Unable to fetch JavaScript file {js_url}: {exc}")
        return findings
    for category, pattern in PATTERNS.items():
        for match in pattern.findall(response.text):
            findings[category].add(match if isinstance(match, str) else match[0])
    return findings

def normalize_url(url):
    url = url.strip()
    if not url:
        return ""
    return url if url.startswith(("http://", "https://")) else "https://" + url

class JSLeakHunterHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Log to stdout for tracking/debugging
        sys.stdout.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), format % args))

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path in ("/", "/index.html"):
            try:
                base_dir = os.path.dirname(os.path.abspath(__file__))
                ui_path = os.path.join(base_dir, "UI", "index.html")
                with open(ui_path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(content.encode("utf-8"))
            except Exception as exc:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Error loading UI: {exc}".encode("utf-8"))
        elif path == "/api/scan":
            query = parse_qs(parsed.query)
            target = query.get("url", [""])[0]
            if not target:
                self.send_json({"status": "error", "message": "Target URL is required"}, 400)
                return
            target = normalize_url(target)
            try:
                js_files = get_js_files(target)
                all_findings = defaultdict(set)
                for js_url in js_files:
                    findings = scan_js(js_url)
                    for cat, matches in findings.items():
                        all_findings[cat].update(matches)
                
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
                    "total_findings": total_findings
                })
            except Exception as exc:
                self.send_json({
                    "status": "error",
                    "message": f"Unable to reach the target website: {exc}"
                }, 200)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

def start_web_ui(port=5000):
    server = ThreadingHTTPServer(("127.0.0.1", port), JSLeakHunterHandler)
    url = f"http://127.0.0.1:{port}"
    print(f"\n[+] Starting Glassmorphism Web UI at {url}")
    print("[+] Press Ctrl+C to stop the server.")
    
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
    print("       JavaScript Exposure Scanner")
    print("=" * 60)
    print(f"\n[+] Target: {target}")
    
    try:
        js_files = get_js_files(target)
    except Exception as exc:
        print(f"[!] Unable to fetch target page: {exc}")
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
        findings = scan_js(js_url)
        for category in PATTERNS:
            values = sorted(findings.get(category, set()))
            if values:
                print(f"\n[{category}]")
                for value in values:
                    print(f"  - {value}")
                total_findings += len(values)
        if not any(findings.values()):
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
            start_web_ui()
        else:
            run_cli_mode(normalize_url(arg))
        return

    print("=" * 60)
    print("                    JSLEAKHUNTER")
    print("       JavaScript Exposure Scanner")
    print("=" * 60)
    print("\nAuthorized Use Only:")
    print("Scan only websites and resources that you own or have explicit permission.")
    print("=" * 60)
    
    target = input("\nEnter Target URL (or leave blank to start Glassmorphism UI): ").strip()
    if not target or target.lower() == "web":
        start_web_ui()
    else:
        run_cli_mode(normalize_url(target))

if __name__ == "__main__":
    main()

