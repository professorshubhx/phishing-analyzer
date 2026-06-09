# PhishAnalyzer v2.0 — Advanced Phishing Email Analysis Tool

> **SOC L1 Triage Tool** | Built by Shubham Chaurasiya | [@Professorshubhx](https://www.linkedin.com/in/shubham-chaurasiya-60932a359/)

A professional-grade phishing email analyzer that automates the complete SOC L1 triage workflow — from raw `.eml` parsing to MITRE ATT&CK-mapped PDF reports.

---

## Features

| Module | What It Does |
|---|---|
| **Email Parser** | Full RFC-2822 parsing — headers, body (text + HTML), attachments |
| **Header Analyzer** | SPF / DKIM / DMARC checks, reply-to mismatch, display name spoofing, received chain analysis |
| **IOC Extractor** | Auto-extracts URLs, IPs, emails, MD5/SHA256 hashes, Bitcoin addresses |
| **URL Analyzer** | Shortener detection, homograph/punycode attacks, IP-based URLs, VirusTotal v3 API |
| **Attachment Analyzer** | Dangerous extensions, MIME mismatch, Office macro detection, VT hash lookup |
| **Threat Scorer** | Weighted scoring (0–100) → CLEAN / SUSPICIOUS / LIKELY_PHISHING / PHISHING verdict |
| **MITRE ATT&CK** | Auto-maps findings to T-codes (T1566.001, T1566.002, T1204.002, etc.) |
| **Report Generator** | JSON + TXT reports saved automatically |
| **Web Dashboard** | Flask web UI — drag-drop upload, real-time report viewer |

---

## Project Structure

```
phishing-analyzer/
├── analyzer/
│   ├── __init__.py
│   ├── email_parser.py          # RFC-2822 email parsing
│   ├── header_analyzer.py       # SPF/DKIM/DMARC + spoofing checks
│   ├── ioc_extractor.py         # IOC extraction (URLs, IPs, hashes)
│   ├── url_analyzer.py          # URL reputation + VT API
│   ├── attachment_analyzer.py   # File analysis + VT hash lookup
│   ├── threat_scorer.py         # Weighted scoring + MITRE mapping
│   └── report_generator.py      # JSON + TXT report output
├── web/
│   ├── app.py                   # Flask web interface
│   └── templates/
│       ├── index.html           # Upload dashboard
│       └── report.html          # Report viewer
├── tests/
│   └── test_parser.py           # Unit tests (pytest)
├── samples/
│   └── sample_phishing.eml      # Test phishing email
├── reports/                     # Auto-generated reports land here
├── uploads/                     # Temp uploaded files
├── config.py                    # All settings + API keys
├── run.py                       # CLI + web launcher
└── requirements.txt
```

---

## Setup

```bash
# 1. Clone / download the project
git clone https://github.com/Professorshubhx/phish-analyzer.git
cd phish-analyzer

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set API keys in config.py (optional — tool works without them)
#    VIRUSTOTAL_API_KEY = "your_free_key_from_virustotal.com"
```

---

## Usage

### CLI Mode (Recommended for SOC work)
```bash
# Basic analysis
python run.py samples/sample_phishing.eml

# With VirusTotal lookups
python run.py samples/sample_phishing.eml

# Output raw JSON
python run.py samples/sample_phishing.eml --json

# Skip VT (faster, offline)
python run.py samples/sample_phishing.eml --no-vt
```

### Web Interface
```bash
python run.py --web
# Open: http://localhost:5000
```

### JSON API
```bash
# POST a raw .eml file
curl -X POST http://localhost:5000/api/analyze \
     -F "email_file=@samples/sample_phishing.eml"
```

### Run Tests
```bash
python tests/test_parser.py
# or
python -m pytest tests/ -v
```

---

## Scoring System

| Score Range | Verdict |
|---|---|
| 0 – 20 | ✅ CLEAN |
| 21 – 50 | ⚠️ SUSPICIOUS |
| 51 – 74 | 🔴 LIKELY_PHISHING |
| 75 – 100 | 🚨 PHISHING |

**Key score contributors:**
- SPF FAIL: +15 pts
- DKIM FAIL/NONE: +15 pts
- DMARC FAIL: +10 pts
- Reply-To mismatch: +10 pts
- Display name spoofing: +12 pts
- VirusTotal URL hit: +20 pts
- VirusTotal file hit: +25 pts
- Suspicious attachment: +15 pts
- Credential keywords: +10 pts
- Urgency keywords: +8 pts

---

## MITRE ATT&CK Coverage

| Technique | ID | Trigger |
|---|---|---|
| Phishing: Spearphishing Attachment | T1566.001 | Auth failures |
| Phishing: Spearphishing Link | T1566.002 | Malicious URLs |
| Masquerading | T1036.005 | Display name spoofing |
| User Execution: Malicious File | T1204.002 | Dangerous attachments |
| Phishing for Information | T1598 | Credential keywords |

---

## Get a Free VirusTotal API Key

1. Register at [virustotal.com](https://virustotal.com)
2. Go to your profile → API Key
3. Free tier: 500 requests/day (enough for SOC L1 use)
4. Add to `config.py` or set env var: `export VT_API_KEY=your_key`

---

## Skills Demonstrated

- Python (OOP, modules, regex, email parsing)
- SOC L1 triage workflow automation
- Email authentication (SPF/DKIM/DMARC)
- IOC extraction and enrichment
- API integration (VirusTotal v3)
- MITRE ATT&CK framework
- Flask web development
- Unit testing (pytest)

---

**Built for:** SOC L1 role portfolio | Defronix Cybersecurity Academy  
**LinkedIn:** https://www.linkedin.com/in/shubham-chaurasiya-60932a359/  
**TryHackMe:** https://tryhackme.com/p/professorshubhx
