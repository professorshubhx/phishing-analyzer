"""
run.py
──────
Main entry point. Can be used in two modes:

  CLI mode:  python run.py sample.eml
  Web mode:  python run.py --web
"""

import sys
import json
import argparse
from pathlib import Path
from analyzer import (
    EmailParser, HeaderAnalyzer, IOCExtractor,
    URLAnalyzer, AttachmentAnalyzer, ThreatScorer, ReportGenerator
)

# ── Color output helper ────────────────────────────────────────────────
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    C_RED    = Fore.RED
    C_YEL    = Fore.YELLOW
    C_GRN    = Fore.GREEN
    C_CYN    = Fore.CYAN
    C_MAG    = Fore.MAGENTA
    C_RST    = Style.RESET_ALL
    C_BOLD   = Style.BRIGHT
except ImportError:
    C_RED = C_YEL = C_GRN = C_CYN = C_MAG = C_RST = C_BOLD = ""


VERDICT_COLORS = {
    "CLEAN":             C_GRN,
    "SUSPICIOUS":        C_YEL,
    "LIKELY_PHISHING":   C_RED,
    "PHISHING":          C_RED + C_BOLD,
}


def analyze_email(filepath: str, use_vt=True, verbose=False) -> dict:
    """Core pipeline. Returns full report dict."""
    print(f"\n{C_CYN}[*] Parsing email: {filepath}{C_RST}")

    parser      = EmailParser()
    parsed      = parser.parse_file(filepath)

    print(f"{C_CYN}[*] Analyzing headers...{C_RST}")
    header_az   = HeaderAnalyzer()
    headers     = header_az.analyze(parsed)

    print(f"{C_CYN}[*] Extracting IOCs...{C_RST}")
    ioc_ex      = IOCExtractor()
    iocs        = ioc_ex.extract(parsed)

    print(f"{C_CYN}[*] Analyzing {len(iocs['urls'])} URLs...{C_RST}")
    url_az      = URLAnalyzer()
    urls        = url_az.analyze_urls(iocs["urls"], use_virustotal=use_vt)

    print(f"{C_CYN}[*] Analyzing {len(parsed.attachments)} attachments...{C_RST}")
    att_az      = AttachmentAnalyzer()
    attachments = att_az.analyze(parsed.attachments, use_virustotal=use_vt)

    print(f"{C_CYN}[*] Scoring threat...{C_RST}")
    scorer      = ThreatScorer()
    score       = scorer.score(parsed, headers, iocs, urls, attachments)

    print(f"{C_CYN}[*] Generating report...{C_RST}")
    reporter    = ReportGenerator()
    report      = reporter.generate(parsed, headers, iocs, urls, attachments, score)

    return report


def print_summary(report: dict):
    """Print colored terminal summary."""
    ta       = report["threat_assessment"]
    verdict  = ta["verdict"]
    score    = ta["score"]
    color    = VERDICT_COLORS.get(verdict, "")
    summ     = ta["summary"]
    meta     = report["email_metadata"]

    print(f"\n{'═'*65}")
    print(f"  {C_BOLD}PHISHING EMAIL ANALYSIS RESULT{C_RST}")
    print(f"{'═'*65}")
    print(f"  Subject    : {meta['subject']}")
    print(f"  From       : {meta['sender_name']} <{meta['sender_email']}>")
    print(f"\n  {'─'*60}")
    print(f"  {C_BOLD}VERDICT : {color}{verdict}{C_RST}")
    print(f"  SCORE   : {color}{score}/100{C_RST}")
    print(f"  {'─'*60}")
    print(f"  Findings : {summ['total_findings']}  "
          f"({C_RED}CRIT:{summ['critical_count']}{C_RST}  "
          f"{C_RED}HIGH:{summ['high_count']}{C_RST}  "
          f"{C_YEL}MED:{summ['medium_count']}{C_RST}  "
          f"LOW:{summ['low_count']})")
    print(f"  URLs     : {summ['url_count']}   |  "
          f"Attachments : {summ['attachment_count']}   |  "
          f"IOCs : {summ['ioc_count']}")
    print(f"\n  {C_BOLD}TOP FINDINGS:{C_RST}")

    for f in report["findings"][:8]:
        sev   = f["severity"]
        scolor = C_RED if sev in ("CRITICAL", "HIGH") else (C_YEL if sev == "MEDIUM" else "")
        print(f"  {scolor}[{sev:8s}]{C_RST} {f['finding'][:70]}")

    print(f"\n  {C_BOLD}MITRE ATT&CK:{C_RST}")
    for m in report.get("mitre_attack", []):
        print(f"  {C_MAG}{m['technique_id']}{C_RST} — {m['technique_name']}")

    files = report.get("_files", {})
    print(f"\n  {C_GRN}Reports saved:{C_RST}")
    print(f"  JSON: {files.get('json', 'N/A')}")
    print(f"  TXT : {files.get('txt',  'N/A')}")
    print(f"{'═'*65}\n")


def main():
    ap = argparse.ArgumentParser(
        description="Phishing Email Analyzer — Advanced SOC Triage Tool"
    )
    ap.add_argument("email", nargs="?", help="Path to .eml file")
    ap.add_argument("--web",    action="store_true", help="Launch web interface")
    ap.add_argument("--no-vt",  action="store_true", help="Skip VirusTotal lookups")
    ap.add_argument("--json",   action="store_true", help="Output raw JSON report to stdout")
    ap.add_argument("--verbose",action="store_true", help="Verbose output")
    args = ap.parse_args()

    if args.web:
        from web.app import create_app
        app = create_app()
        app.run(host="0.0.0.0", port=5000, debug=True)
        return

    if not args.email:
        ap.print_help()
        sys.exit(1)

    if not Path(args.email).exists():
        print(f"{C_RED}[!] File not found: {args.email}{C_RST}")
        sys.exit(1)

    report = analyze_email(
        args.email,
        use_vt=not args.no_vt,
        verbose=args.verbose
    )

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print_summary(report)


if __name__ == "__main__":
    main()
