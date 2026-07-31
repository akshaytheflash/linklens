from app.main import _domain_policy, _validate_and_guard


def test_validate_rejects_non_http():
    guard = _validate_and_guard("ftp://example.com")
    assert guard is not None


def test_validate_rejects_empty():
    assert _validate_and_guard("") is not None
    assert _validate_and_guard(None) is not None


def test_validate_accepts_http_and_https():
    assert _validate_and_guard("https://example.com") is None
    assert _validate_and_guard("http://example.com") is None


def test_domain_policy_deny_list():
    from app.main import config

    config.deny_domains = ["blocked.example"]
    assert _domain_policy("blocked.example") is not None
    assert _domain_policy("sub.blocked.example") is not None
    assert _domain_policy("fine.example") is None
    config.deny_domains = []


def test_domain_policy_allow_list():
    from app.main import config

    config.allow_domains = ["example.com"]
    assert _domain_policy("example.com") is None
    assert _domain_policy("www.example.com") is None
    assert _domain_policy("notallowed.com") is not None
    config.allow_domains = []
