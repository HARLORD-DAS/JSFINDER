import os
import tempfile
import threading
import unittest
import requests
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import js

class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

class TestJSLeakHunter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["JSLEAKHUNTER_ALLOW_LOCAL"] = "1"
        cls.old = os.getcwd()
        cls.tmp = tempfile.TemporaryDirectory()
        root = cls.tmp.name
        site_dir = os.path.join(root, 'site')
        os.makedirs(site_dir)
        
        # Setup files for integration testing
        with open(os.path.join(site_dir, 'index.html'), 'w') as f:
            f.write('<!DOCTYPE html><html><body><h1>Test Site</h1><script src="/app.js"></script><script src="/app.js"></script></body></html>')
            
        with open(os.path.join(site_dir, 'app.js'), 'w') as f:
            f.write('''
            // Dummy test values
            const email1 = "test@example.com";
            const email2 = "test@example.com"; // duplicate
            const jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJkZW1vIn0.signature";
            const aws = "AKIA1234567890ABCDEF";
            const internalIp = "192.168.1.10";
            const api = "/api/v1/users";
            ''')
            
        with open(os.path.join(site_dir, 'clean.html'), 'w') as f:
            f.write('<!DOCTYPE html><html><body><script src="/clean.js"></script></body></html>')
            
        with open(os.path.join(site_dir, 'clean.js'), 'w') as f:
            f.write('const x = 5; console.log(x);')

        with open(os.path.join(site_dir, 'nojs.html'), 'w') as f:
            f.write('<!DOCTYPE html><html><body><h1>No Scripts</h1></body></html>')
            
        os.chdir(site_dir)
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), QuietHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        cls.url = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        os.environ.pop("JSLEAKHUNTER_ALLOW_LOCAL", None)
        cls.server.shutdown()
        cls.server.server_close()
        os.chdir(cls.old)
        cls.tmp.cleanup()

    # 1. EMAIL Regex Tests
    def test_email_positive(self):
        pattern = js.PATTERNS["Email"]
        self.assertTrue(pattern.search("test@example.com"))
        self.assertTrue(pattern.search("user.name+tag@domain.co.uk"))
        self.assertTrue(pattern.search("my_email_123@sub.domain.org"))

    def test_email_negative(self):
        pattern = js.PATTERNS["Email"]
        self.assertFalse(pattern.search("not-an-email"))
        self.assertFalse(pattern.search("abc@"))
        self.assertFalse(pattern.search("@domain.com"))
        self.assertFalse(pattern.search("abc@domain"))

    # 2. JWT Regex Tests
    def test_jwt_positive(self):
        pattern = js.PATTERNS["JWT"]
        self.assertTrue(pattern.search("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJkZW1vIn0.signature"))
        self.assertTrue(pattern.search("eyJabc.def.ghi"))

    def test_jwt_negative(self):
        pattern = js.PATTERNS["JWT"]
        self.assertFalse(pattern.search("not.a.jwt"))
        self.assertFalse(pattern.search("eyJno_dots_here"))
        self.assertFalse(pattern.search("abc.def.ghi"))

    # 3. AWS Key Regex Tests
    def test_aws_key_positive(self):
        pattern = js.PATTERNS["AWS Key"]
        self.assertTrue(pattern.search("AKIA1234567890ABCDEF"))
        self.assertTrue(pattern.search("AKIAZABABABABA123456"))

    def test_aws_key_negative(self):
        pattern = js.PATTERNS["AWS Key"]
        self.assertFalse(pattern.search("akia1234567890abcdef")) # uppercase only
        self.assertFalse(pattern.search("AKIA1234567890ABCDE")) # too short
        self.assertFalse(pattern.search("BKIA1234567890ABCDEF")) # incorrect prefix

    # 4. Internal IP Regex Tests
    def test_internal_ip_positive(self):
        pattern = js.PATTERNS["Internal IP"]
        self.assertTrue(pattern.search("192.168.1.10"))
        self.assertTrue(pattern.search("10.0.0.1"))
        self.assertTrue(pattern.search("172.16.5.5"))
        self.assertTrue(pattern.search("172.31.254.254"))

    def test_internal_ip_negative(self):
        pattern = js.PATTERNS["Internal IP"]
        self.assertFalse(pattern.search("8.8.8.8"))
        self.assertFalse(pattern.search("192.169.1.1"))
        self.assertFalse(pattern.search("172.32.1.1"))
        self.assertFalse(pattern.search("256.256.256.256"))

    # 5. API Endpoint Regex Tests
    def test_api_endpoint_positive(self):
        pattern = js.PATTERNS["API Endpoint"]
        self.assertTrue(pattern.search('"/api/v1/users"'))
        self.assertTrue(pattern.search("'/internal/configs'"))
        self.assertTrue(pattern.search('"/api/v2"'))

    def test_api_endpoint_negative(self):
        pattern = js.PATTERNS["API Endpoint"]
        self.assertFalse(pattern.search('"/not-api/v1"'))
        self.assertFalse(pattern.search('"/external/api"'))

    # 6. Integration: JavaScript Discovery
    def test_integration_discovery(self):
        js_files = js.get_js_files(self.url)
        self.assertEqual(len(js_files), 1)
        self.assertIn(f"{self.url}/app.js", js_files)

    # 7. Integration: Deduplication
    def test_integration_deduplication(self):
        findings = js.scan_js(f"{self.url}/app.js")
        self.assertEqual(len(findings["Email"]), 1)
        self.assertIn("test@example.com", findings["Email"])

    # 8. Integration: No JavaScript
    def test_integration_no_js(self):
        js_files = js.get_js_files(f"{self.url}/nojs.html")
        self.assertEqual(len(js_files), 0)

    # 9. Integration: Clean JavaScript
    def test_integration_clean_js(self):
        findings = js.scan_js(f"{self.url}/clean.js")
        for category in js.PATTERNS:
            self.assertEqual(len(findings[category]), 0)

    # 10. Integration: Invalid URL
    def test_integration_invalid_url(self):
        with self.assertRaises(requests.RequestException):
            js.get_js_files("http://127.0.0.1:9999/nonexistent")

    # 11. Security & SSRF Protection Tests
    def test_ssrf_loopback_blocked(self):
        with self.assertRaises(ValueError) as ctx:
            js.validate_url_target("http://127.0.0.1:8080", allow_local=False)
        self.assertIn("SSRF Protection", str(ctx.exception))

    def test_ssrf_localhost_blocked(self):
        with self.assertRaises(ValueError) as ctx:
            js.validate_url_target("http://localhost:3000", allow_local=False)
        self.assertIn("SSRF Protection", str(ctx.exception))

    def test_ssrf_private_ip_10_blocked(self):
        with self.assertRaises(ValueError) as ctx:
            js.validate_url_target("http://10.0.1.5:8080", allow_local=False)
        self.assertIn("SSRF Protection", str(ctx.exception))

    def test_ssrf_private_ip_192_blocked(self):
        with self.assertRaises(ValueError) as ctx:
            js.validate_url_target("http://192.168.1.1", allow_local=False)
        self.assertIn("SSRF Protection", str(ctx.exception))

    def test_ssrf_cloud_metadata_blocked(self):
        with self.assertRaises(ValueError) as ctx:
            js.validate_url_target("http://169.254.169.254/latest/meta-data/", allow_local=False)
        self.assertIn("SSRF Protection", str(ctx.exception))

    def test_ssrf_prohibited_schemes(self):
        for bad_url in ["file:///etc/passwd", "gopher://127.0.0.1:11211", "ftp://example.com"]:
            with self.assertRaises(ValueError) as ctx:
                js.validate_url_target(bad_url, allow_local=False)
            self.assertIn("Prohibited URL scheme", str(ctx.exception))

    def test_per_resource_findings_structure(self):
        findings = js.scan_js(f"{self.url}/app.js")
        file_findings = {cat: sorted(list(findings.get(cat, set()))) for cat in js.PATTERNS}
        self.assertIn("Email", file_findings)
        self.assertIn("JWT", file_findings)
        self.assertIn("AWS Key", file_findings)
        self.assertIn("Internal IP", file_findings)
        self.assertIn("API Endpoint", file_findings)
        self.assertEqual(len(file_findings["Email"]), 1)
        self.assertEqual(len(file_findings["JWT"]), 1)
        self.assertEqual(len(file_findings["AWS Key"]), 1)

    def test_api_scan_handler_integration(self):
        # Spin up JSLeakHunterHandler on dynamic port
        api_server = ThreadingHTTPServer(('127.0.0.1', 0), js.JSLeakHunterHandler)
        api_thread = threading.Thread(target=api_server.serve_forever, daemon=True)
        api_thread.start()
        api_url = f'http://127.0.0.1:{api_server.server_port}'
        try:
            # Query the /api/scan endpoint targeting our local test site
            resp = requests.get(f"{api_url}/api/scan?url={self.url}", timeout=10)
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["status"], "success")
            self.assertEqual(data["target"], self.url)
            self.assertIn("js_files", data)
            self.assertIn("findings", data)
            self.assertIn("total_findings", data)
            self.assertIn("resources", data)
            self.assertEqual(len(data["resources"]), 1)
            self.assertEqual(data["resources"][0]["url"], f"{self.url}/app.js")
            self.assertIn("Email", data["resources"][0]["findings"])
            self.assertIn("test@example.com", data["resources"][0]["findings"]["Email"])
            self.assertGreater(data["total_findings"], 0)
        finally:
            api_server.shutdown()
            api_server.server_close()

if __name__ == '__main__':
    unittest.main()
