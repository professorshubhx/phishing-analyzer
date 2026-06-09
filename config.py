import os

# ─────────────────────────────────────────────
#  PHISHING EMAIL ANALYZER — config.py
#  All settings in one place. Edit before running.
# ─────────────────────────────────────────────

# ── API Keys ──────────────────────────────────
VIRUSTOTAL_API_KEY = os.getenv("VT_API_KEY", "YOUR_VT_API_KEY_HERE")
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_KEY", "YOUR_ABUSEIPDB_KEY_HERE")

# ── Flask Config ──────────────────────────────
FLASK_HOST   = "0.0.0.0"
FLASK_PORT   = 5000
FLASK_DEBUG  = True
SECRET_KEY   = os.getenv("SECRET_KEY", "phish-analyzer-secret-change-in-prod")

# ── Upload Config ─────────────────────────────
UPLOAD_FOLDER   = "uploads"
REPORT_FOLDER   = "reports"
MAX_FILE_SIZE   = 10 * 1024 * 1024   # 10 MB
ALLOWED_EXTENSIONS = {".eml", ".msg", ".txt"}

# ── Threat Scoring Weights ────────────────────
# Each check contributes this many points to the threat score (0-100)
SCORE_WEIGHTS = {
    "spf_fail":             15,
    "dkim_fail":            15,
    "dmarc_fail":           10,
    "reply_to_mismatch":    10,
    "suspicious_sender":    10,
    "url_count_high":        5,
    "url_vt_malicious":     20,
    "url_shortener":         8,
    "ip_in_url":            10,
    "homograph_domain":     12,
    "attachment_suspicious": 15,
    "attachment_vt_hit":    25,
    "urgent_keywords":       8,
    "credential_keywords":  10,
    "spoofed_display_name": 12,
    "mismatched_links":     10,
}

# ── Risk Thresholds ───────────────────────────
RISK_LEVELS = {
    "CLEAN":      (0,  20),
    "SUSPICIOUS": (21, 50),
    "LIKELY_PHISHING": (51, 74),
    "PHISHING":   (75, 100),
}

# ── Known Phishing Keywords ───────────────────
URGENT_KEYWORDS = [
    "urgent", "immediately", "account suspended", "verify your account",
    "click here", "confirm now", "limited time", "act now", "you have won",
    "your account will be closed", "validate", "update your information",
    "security alert", "unusual activity", "login attempt",
]

CREDENTIAL_KEYWORDS = [
    "password", "username", "ssn", "credit card", "bank account",
    "social security", "pin number", "cvv", "otp", "one time password",
]

# ── Known URL Shorteners ──────────────────────
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "short.io",
]

# ── Suspicious Attachment Extensions ─────────
SUSPICIOUS_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".scr", ".pif", ".com", ".msi", ".hta", ".wsf", ".lnk",
    ".docm", ".xlsm", ".pptm",  # macro-enabled Office
]

# ── Legitimate Email Providers (for spoofing detection) ──
LEGIT_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "microsoft.com", "apple.com", "amazon.com", "paypal.com",
    "facebook.com", "google.com", "twitter.com", "linkedin.com",
]
