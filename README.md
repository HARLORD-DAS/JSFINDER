# JSLeakHunter (v2.0 Hardened)

> **Passive JavaScript Exposure & Security Audit Platform**  
> A full-stack security reconnaissance platform featuring a hardened Python scanning engine and a modern, interactive React + Framer Motion + GSAP interface.

---

## Architecture Overview

```
JSLeakHunter/
├── js.py                     # Hardened Python scanning engine & standalone static server
├── requirements.txt          # Python dependencies (requests, beautifulsoup4)
├── package.json              # Frontend dependencies (React 18, Vite 5, Framer Motion, GSAP)
├── vite.config.js            # Vite configuration with /api proxy to http://127.0.0.1:5000
├── src/                      # Modern React cybersecurity interface
│   ├── components/           # Intro, Navbar, Hero, Workflow, Dashboard, Findings, Resources, Reports
│   ├── utils/                # Security helpers, safe URL verification, CSV formula hardening
│   ├── App.jsx               # Main orchestration layer & backend API integration
│   └── styles.css            # Dark cybersecurity design system with .bars > div selector
├── dist/                     # Optimized production bundle
├── tests/                    # 32 automated unit and end-to-end integration tests
└── test_site/                # Local test fixture for controlled testing
```

---

## Key Features & Security Enhancements

1. **SSRF & DNS Rebinding Guard**:
   - Blocks destination access to loopback (`127.0.0.0/8`, `::1`), RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), cloud metadata endpoints (`169.254.0.0/16`), and carrier-grade NAT (`100.64.0.0/10`).
   - Re-validates target destinations before every redirect (`allow_redirects=False` with manual inspection).
   - Strict protocol enforcement: accepts only `http` and `https`.

2. **Genuine Per-Resource Attribution**:
   - The scanner attributes each detected leak directly to its originating script file (`resources` field).
   - The UI supports "Group by Script" filtering and resource drawers without fabricating data.

3. **Secure DOM & Export Rendering**:
   - Zero `dangerouslySetInnerHTML`. All external strings and code snippets render safely as React text nodes.
   - CSV exports sanitize cells against spreadsheet formula injection (`=`, `+`, `-`, `@`, `\t`, `\r` escaped with a leading `'`).

4. **Cinematic Opening & Storytelling**:
   - High-tech split-panel entrance transition inspired by modern interactive UI patterns.
   - Pinned GSAP ScrollTrigger 5-stage lifecycle illustration with proper memory cleanup (`ctx.revert()`).
   - Full compliance with `prefers-reduced-motion`.

---

## Local Execution on Windows 11

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm

> **PowerShell Execution Policy Note**: On Windows 11, PowerShell may restrict running `.ps1` script wrappers (e.g. `activate.ps1` or `npm.ps1`). The instructions below use direct executables (`.\.venv\Scripts\python.exe` and `npm.cmd`), which run cleanly without modifying system policies.

---

### Option A: Development Mode (Two Terminals)

**Terminal 1 — Backend Engine:**
```powershell
# Create and populate Python virtual environment (if not already done)
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# Start backend server on port 5000
.\.venv\Scripts\python.exe js.py --web 5000
```
Backend runs at: `http://127.0.0.1:5000`

**Terminal 2 — Frontend Dev Server:**
```powershell
# Install frontend packages (if not already done)
npm.cmd install

# Start Vite hot-reloading dev server on port 5173
npm.cmd run dev
```
Open your browser at: **`http://127.0.0.1:5173`** (proxies `/api` to `:5000`)

---

### Option B: Standalone Production Mode (Single Terminal)

The Python backend directly serves the compiled React single-page application and its static assets:

```powershell
# 1. Build the production React application
npm.cmd run build

# 2. Start the Python server
.\.venv\Scripts\python.exe js.py --web 5000
```
Open your browser at: **`http://127.0.0.1:5000`**

---

### Option C: CLI Mode (Command Line)

```powershell
.\.venv\Scripts\python.exe js.py https://example.com
```

---

## Running the Automated Test Suite

Run all 32 unit and integration tests:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests
```

Output:
```
................................
----------------------------------------------------------------------
Ran 32 tests in 4.373s

OK
```

---

## API Specification

### `GET /api/scan?url=<target_url>`

**Response Format (200 OK):**
```json
{
  "status": "success",
  "target": "https://example.com",
  "js_files": [
    "https://example.com/assets/app.js"
  ],
  "findings": {
    "Email": ["dev@example.com"],
    "JWT": [],
    "AWS Key": [],
    "Internal IP": ["10.0.4.12"],
    "API Endpoint": ["/api/v1/auth"]
  },
  "total_findings": 3,
  "resources": [
    {
      "url": "https://example.com/assets/app.js",
      "findings": {
        "Email": ["dev@example.com"],
        "JWT": [],
        "AWS Key": [],
        "Internal IP": ["10.0.4.12"],
        "API Endpoint": ["/api/v1/auth"]
      },
      "total": 3
    }
  ]
}
```

**Error Format (400 / 502):**
```json
{
  "status": "error",
  "message": "SSRF Protection: Target resolved to restricted address (127.0.0.1)."
}
```

---

## Legal & Ethical Disclaimer

JSLeakHunter is designed strictly for **passive reconnaissance and defensive auditing**. Only analyze assets and web applications that you own or have explicit, prior written permission to test.
