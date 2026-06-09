"""
tests/test_parser.py
────────────────────
Unit tests for email parser and header analyzer.
Run: python -m pytest tests/ -v
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from analyzer.email_parser    import EmailParser
from analyzer.header_analyzer import HeaderAnalyzer
from analyzer.ioc_extractor   import IOCExtractor
from analyzer.threat_scorer   import ThreatScorer


SAMPLE_EML = """From: PayPal <security@paypa1-support.tk>
To: victim@gmail.com
Subject: Urgent: Verify Your Account
Reply-To: harvest@evil.xyz
Authentication-Results: spf=fail; dkim=none; dmarc=fail
X-Originating-IP: 1.2.3.4

Click here: http://bit.ly/fakelink and also http://185.220.0.1/login
Password and credit card required. Act now immediately!
"""


def test_parse_basic_fields():
    parser = EmailParser()
    parsed = parser.parse_string(SAMPLE_EML)
    assert parsed.subject == "Urgent: Verify Your Account"
    assert parsed.sender_email == "security@paypa1-support.tk"
    assert parsed.reply_to == "harvest@evil.xyz"
    assert parsed.x_originating_ip == "1.2.3.4"
    print("✓ test_parse_basic_fields passed")


def test_spf_fail_detection():
    parser = EmailParser()
    parsed = parser.parse_string(SAMPLE_EML)
    ha     = HeaderAnalyzer()
    headers = ha.analyze(parsed)
    assert headers["spf"]["status"] == "fail"
    assert headers["spf"]["flag"] == True
    print("✓ test_spf_fail_detection passed")


def test_dkim_none_detection():
    parser  = EmailParser()
    parsed  = parser.parse_string(SAMPLE_EML)
    ha      = HeaderAnalyzer()
    headers = ha.analyze(parsed)
    assert headers["dkim"]["flag"] == True
    print("✓ test_dkim_none_detection passed")


def test_reply_to_mismatch():
    parser  = EmailParser()
    parsed  = parser.parse_string(SAMPLE_EML)
    ha      = HeaderAnalyzer()
    headers = ha.analyze(parsed)
    assert headers["reply_to_mismatch"]["mismatch"] == True
    print("✓ test_reply_to_mismatch passed")


def test_ioc_url_extraction():
    parser = EmailParser()
    parsed = parser.parse_string(SAMPLE_EML)
    ioc    = IOCExtractor()
    iocs   = ioc.extract(parsed)
    assert len(iocs["urls"]) >= 2
    assert any("bit.ly" in u for u in iocs["urls"])
    print(f"✓ test_ioc_url_extraction passed — found {len(iocs['urls'])} URLs")


def test_ioc_ip_extraction():
    parser = EmailParser()
    parsed = parser.parse_string(SAMPLE_EML)
    ioc    = IOCExtractor()
    iocs   = ioc.extract(parsed)
    assert "185.220.0.1" in iocs["ips"]
    print("✓ test_ioc_ip_extraction passed")


def test_threat_score_phishing():
    parser  = EmailParser()
    parsed  = parser.parse_string(SAMPLE_EML)
    ha      = HeaderAnalyzer()
    ioc     = IOCExtractor()
    headers = ha.analyze(parsed)
    iocs    = ioc.extract(parsed)
    scorer  = ThreatScorer()
    result  = scorer.score(parsed, headers, iocs, [], [])
    assert result["score"] > 50, f"Expected >50, got {result['score']}"
    assert result["verdict"] in ("LIKELY_PHISHING", "PHISHING", "SUSPICIOUS")
    print(f"✓ test_threat_score_phishing passed — score={result['score']}, verdict={result['verdict']}")


if __name__ == "__main__":
    test_parse_basic_fields()
    test_spf_fail_detection()
    test_dkim_none_detection()
    test_reply_to_mismatch()
    test_ioc_url_extraction()
    test_ioc_ip_extraction()
    test_threat_score_phishing()
    print("\n✅ All tests passed!")
