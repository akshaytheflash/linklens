from app.analysis.html_parse import parse_html_overview


def test_title_and_text_extracted():
    html = "<html><head><title>Hello</title></head><body><p>Some content here.</p></body></html>"
    result = parse_html_overview(html, "https://example.com/")
    assert result["title"] == "Hello"
    assert "Some content here." in result["textSnippet"]


def test_internal_vs_external_links():
    html = """
    <a href="/internal">home</a>
    <a href="https://other.com/page">other</a>
    """
    result = parse_html_overview(html, "https://example.com/")
    assert len(result["links"]["internal"]) == 1
    assert len(result["links"]["external"]) == 1
    assert result["links"]["external"][0] == "https://other.com/page"


def test_hidden_iframes_detected():
    html = '<iframe src="https://x.com" width="0"></iframe><iframe src="https://y.com"></iframe>'
    result = parse_html_overview(html, "https://example.com/")
    assert result["iframes"]["count"] == 2
    assert result["iframes"]["hidden"] == 1


def test_password_form_to_external_domain():
    html = """
    <form action="https://evil.example/collect">
      <input type="password" name="pw">
    </form>
    """
    result = parse_html_overview(html, "https://example.com/")
    assert result["passwordForms"] == ["https://evil.example/collect"]


def test_meta_refresh_detected():
    html = '<meta http-equiv="refresh" content="0; url=https://evil.example">'
    result = parse_html_overview(html, "https://example.com/")
    assert result["metaRefresh"] is True


def test_external_base_tag_detected():
    html = '<base href="https://evil.example/">'
    result = parse_html_overview(html, "https://example.com/")
    assert result["externalBaseTag"] is True


def test_obfuscated_script_detected():
    obfuscated = "".join(["eval("] * 60)
    html = f"<script>{obfuscated}</script>"
    result = parse_html_overview(html, "https://example.com/")
    assert len(result["suspiciousScripts"]) == 1


def test_empty_html_is_safe_defaults():
    result = parse_html_overview("", "https://example.com/")
    assert result["title"] == ""
    assert result["iframes"]["count"] == 0
