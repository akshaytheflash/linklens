import pytest

from app.analysis.url_heuristics import url_heuristics


def test_normal_url_has_no_red_flags():
    result = url_heuristics("https://example.com/blog/post")
    assert result["ipInUrl"] is False
    assert result["atSymbolInUrl"] is False
    assert result["manySubdomains"] is False
    assert result["phishingKeywords"] == []
    assert result["typosquatting"]["likely"] is False


def test_ip_in_url_detected():
    assert url_heuristics("http://192.168.1.1/admin")["ipInUrl"] is True


def test_at_symbol_detected():
    assert url_heuristics("https://paypal.com@evil.example/login")["atSymbolInUrl"] is True


def test_phishing_keywords_found():
    result = url_heuristics("https://secure-login.example.com/verify-account")
    assert "login" in result["phishingKeywords"]
    assert "verify" in result["phishingKeywords"]


def test_many_subdomains():
    assert url_heuristics("https://a.b.c.d.example.com/x")["manySubdomains"] is True


def test_url_shortener_detected():
    assert url_heuristics("https://bit.ly/3xYzAbc")["urlShortener"] is True


def test_typosquatting_detected():
    result = url_heuristics("https://paypa1.com/login")
    assert result["typosquatting"]["likely"] is True
    assert result["typosquatting"]["target"] == "paypal.com"


def test_suspicious_tld():
    assert url_heuristics("https://free-money.tk/")["suspiciousTld"] is True


def test_punycode_detected():
    assert url_heuristics("https://xn--80ak6aa92e.com/")["punycode"] is True
