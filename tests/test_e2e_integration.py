import os
import sys
import time
import json
import threading
import unittest
import requests
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

# Import backend module
import js

class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

class TestEndToEndIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Allow local target for the controlled test site only
        os.environ["JSLEAKHUNTER_ALLOW_LOCAL"] = "1"
        cls.old_cwd = os.getcwd()
        cls.test_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "test_site"))

        class CustomSiteHandler(SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=cls.test_dir, **kwargs)
            def log_message(self, *args):
                pass

        cls.target_server = ThreadingHTTPServer(("127.0.0.1", 0), CustomSiteHandler)
        cls.target_port = cls.target_server.server_port
        cls.target_url = f"http://127.0.0.1:{cls.target_port}"

        cls.target_thread = threading.Thread(target=cls.target_server.serve_forever, daemon=True)
        cls.target_thread.start()

        # Start JSLeakHunter Web Server
        cls.backend_server = ThreadingHTTPServer(("127.0.0.1", 0), js.JSLeakHunterHandler)
        cls.backend_port = cls.backend_server.server_port
        cls.backend_url = f"http://127.0.0.1:{cls.backend_port}"

        cls.backend_thread = threading.Thread(target=cls.backend_server.serve_forever, daemon=True)
        cls.backend_thread.start()

    @classmethod
    def tearDownClass(cls):
        os.environ.pop("JSLEAKHUNTER_ALLOW_LOCAL", None)
        cls.target_server.shutdown()
        cls.target_server.server_close()
        cls.backend_server.shutdown()
        cls.backend_server.server_close()

    def test_01_serves_built_frontend_html(self):
        resp = requests.get(f"{self.backend_url}/", timeout=5)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.headers.get("Content-Type", ""))
        self.assertIn("JSLeakHunter", resp.text)
        self.assertIn("<div id=\"root\"></div>", resp.text)

    def test_02_serves_frontend_assets(self):
        # Discover asset name from dist/assets
        dist_assets = os.path.join(self.old_cwd, "dist", "assets")
        files = os.listdir(dist_assets)
        js_files = [f for f in files if f.endswith(".js")]
        self.assertTrue(len(js_files) > 0)
        asset_name = js_files[0]

        resp = requests.get(f"{self.backend_url}/assets/{asset_name}", timeout=5)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("application/javascript", resp.headers.get("Content-Type", ""))
        self.assertGreater(len(resp.content), 1000)

    def test_03_missing_url_returns_400(self):
        resp = requests.get(f"{self.backend_url}/api/scan", timeout=5)
        self.assertEqual(resp.status_code, 400)
        data = resp.json()
        self.assertEqual(data["status"], "error")
        self.assertIn("Target URL is required", data["message"])

    def test_04_ssrf_blocked_when_local_disallowed(self):
        # Temporarily disable allow_local to verify live SSRF blocking in API handler
        os.environ["JSLEAKHUNTER_ALLOW_LOCAL"] = "0"
        try:
            resp = requests.get(f"{self.backend_url}/api/scan?url=http://127.0.0.1:8080", timeout=5)
            self.assertEqual(resp.status_code, 400)
            data = resp.json()
            self.assertEqual(data["status"], "error")
            self.assertIn("SSRF Protection", data["message"])
        finally:
            os.environ["JSLEAKHUNTER_ALLOW_LOCAL"] = "1"

    def test_05_ssrf_blocks_cloud_metadata(self):
        os.environ["JSLEAKHUNTER_ALLOW_LOCAL"] = "0"
        try:
            resp = requests.get(f"{self.backend_url}/api/scan?url=http://169.254.169.254/latest/meta-data/", timeout=5)
            self.assertEqual(resp.status_code, 400)
            data = resp.json()
            self.assertEqual(data["status"], "error")
            self.assertIn("SSRF Protection", data["message"])
        finally:
            os.environ["JSLEAKHUNTER_ALLOW_LOCAL"] = "1"

    def test_06_prohibited_scheme_returns_400(self):
        resp = requests.get(f"{self.backend_url}/api/scan?url=file:///etc/passwd", timeout=5)
        self.assertEqual(resp.status_code, 400)
        data = resp.json()
        self.assertEqual(data["status"], "error")
        self.assertIn("Prohibited URL scheme", data["message"])

    def test_07_real_scan_execution_and_findings(self):
        scan_target = f"{self.target_url}/index.html"
        resp = requests.get(f"{self.backend_url}/api/scan?url={scan_target}", timeout=10)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["target"], scan_target)

        # Verify discovery of app.js
        self.assertEqual(len(data["js_files"]), 1)
        self.assertEqual(data["js_files"][0], f"{self.target_url}/app.js")

        # Verify all 5 categories are present
        findings = data["findings"]
        for cat in ["Email", "JWT", "AWS Key", "Internal IP", "API Endpoint"]:
            self.assertIn(cat, findings)

        # Verify actual findings in test_site/app.js
        self.assertIn("test@example.com", findings["Email"])
        self.assertIn("AKIA1234567890ABCDEF", findings["AWS Key"])
        self.assertIn("192.168.1.10", findings["Internal IP"])
        self.assertIn("/api/v1/users", findings["API Endpoint"])
        self.assertGreater(data["total_findings"], 0)

        # Verify genuine per-resource attribution
        self.assertIn("resources", data)
        self.assertEqual(len(data["resources"]), 1)
        res_entry = data["resources"][0]
        self.assertEqual(res_entry["url"], f"{self.target_url}/app.js")
        self.assertIn("test@example.com", res_entry["findings"]["Email"])
        self.assertEqual(res_entry["total"], data["total_findings"])

    def test_08_clean_page_scan_returns_zero_findings(self):
        clean_target = f"{self.target_url}/clean.html"
        resp = requests.get(f"{self.backend_url}/api/scan?url={clean_target}", timeout=10)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["total_findings"], 0)
        self.assertEqual(len(data["js_files"]), 1)
        self.assertEqual(data["resources"][0]["total"], 0)

    def test_09_no_scripts_page_returns_empty_js_files(self):
        nojs_target = f"{self.target_url}/nojs.html"
        resp = requests.get(f"{self.backend_url}/api/scan?url={nojs_target}", timeout=10)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["total_findings"], 0)
        self.assertEqual(len(data["js_files"]), 0)
        self.assertEqual(len(data["resources"]), 0)

if __name__ == "__main__":
    unittest.main()
