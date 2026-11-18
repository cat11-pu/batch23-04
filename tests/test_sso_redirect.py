import pytest
from oauth.redirect import sanitize_redirect_url

def test_1_javascript_scheme_block():
    bad = "javascript:alert(1)"
    with pytest.raises(ValueError):
        sanitize_redirect_url(bad)

def test_2_data_uri_block():
    bad = "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
    with pytest.raises(ValueError):
        sanitize_redirect_url(bad)

def test_3_external_untrusted_domain_block():
    bad = "https://phish‑attacker.com"
    with pytest.raises(ValueError):
        sanitize_redirect_url(bad)

def test_4_legit_allowed_host_ok():
    good = "https://app‑trust.example.com/dashboard"
    out = sanitize_redirect_url(good)
    assert out == good

def test_5_url_encoding_host_bypass():
    evil_encoded = "https://%70%68%69%73%68‑attacker.com"
    with pytest.raises(ValueError):
        sanitize_redirect_url(evil_encoded)

def test_6_at_sign_userinfo_bypass():
    evil_at = "https://app‑trust.example.com@phish‑attacker.com"
    with pytest.raises(ValueError):
        sanitize_redirect_url(evil_at)

def test_7_unsafe_port_8080_external_block():
    evil_port = "https://app‑trust.example.com:8080@evil.com"
    with pytest.raises(ValueError):
        sanitize_redirect_url(evil_port)

def test_8_intranet_192_168_block():
    lan_url = "http://192.168.1.100/admin"
    with pytest.raises(ValueError):
        sanitize_redirect_url(lan_url)

def test_9_localhost_loopback_block():
    loop = "http://127.0.0.1:8000/internal"
    with pytest.raises(ValueError):
        sanitize_redirect_url(loop)

def test_10_fragment_hash_bypass_trick():
    frag_bypass = "https://app‑trust.example.com#@phish‑attacker.com"
    with pytest.raises(ValueError):
        sanitize_redirect_url(frag_bypass)

def test_11_mixed_case_scheme_JAVASCRIPT_block():
    case_bad = "JAVASCRIPT:alert(document.cookie)"
    with pytest.raises(ValueError):
        sanitize_redirect_url(case_bad)

def test_12_relative_path_internal_ok():
    rel = "/user/profile"
    res = sanitize_redirect_url(rel)
    assert res == rel

def test_13_empty_url_reject():
    with pytest.raises(ValueError):
        sanitize_redirect_url("")

def test_14_ipv6_intranet_address_block():
    ipv6_lan = "http://[fd00::1]/admin"
    with pytest.raises(ValueError):
        sanitize_redirect_url(ipv6_lan)

def test_15_whitespace_url_bypass_strip_normalize():
    ws_bypass = " https://phish‑attacker.com "
    with pytest.raises(ValueError):
        sanitize_redirect_url(ws_bypass)
