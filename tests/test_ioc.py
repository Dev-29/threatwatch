import pytest

from threatwatch.core.ioc import InvalidIOC, detect_type, extract_iocs, normalize, refang


@pytest.mark.parametrize("raw,expected", [
    ("hxxps://evil[.]example[.]com/login", "https://evil.example.com/login"),
    ("1.2.3[.]4", "1.2.3.4"),
    ("user[at]example(.)com", "user@example.com"),
])
def test_refang(raw, expected):
    assert refang(raw) == expected


@pytest.mark.parametrize("value,t", [
    ("8.8.8.8", "ipv4"), ("2606:4700::1111", "ipv6"), ("1.2.3.0/24", "cidr"), ("evil.example.com", "domain"),
    ("http://x.example.com/a", "url"), ("d41d8cd98f00b204e9800998ecf8427e", "md5"),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"), ("a" * 64, "sha256"), ("CVE-2024-3400", "cve"),
    ("bob@example.com", "email"), ("not an ioc", None),
])
def test_detect_type(value, t):
    assert detect_type(value) == t


def test_normalize_canonicalises():
    assert normalize("HTTPS://Evil.Example.COM:443/Path?q=1").value == "https://evil.example.com/Path?q=1"
    assert normalize("http://evil.example.com:8080").value == "http://evil.example.com:8080/"
    assert normalize("EVIL.Example.com.").value == "evil.example.com"
    assert normalize("D41D8CD98F00B204E9800998ECF8427E").value == "d41d8cd98f00b204e9800998ecf8427e"
    assert normalize("185.220.101.1:443", "ipv4").value == "185.220.101.1"
    assert normalize("cve-2021-44228").value == "CVE-2021-44228"
    assert normalize("bücher.example.com").value == "xn--bcher-kva.example.com"


@pytest.mark.parametrize("bad", ["10.0.0.1", "192.168.1.1", "127.0.0.1", "google.com", "ftp:/broken", "zzz"])
def test_normalize_rejects(bad):
    with pytest.raises((InvalidIOC, ValueError)):
        normalize(bad)


def test_allowlisted_registrable_only_blocks_exact_domain():
    assert normalize("evil.blogspot.com").value == "evil.blogspot.com"


def test_extract_iocs_from_text():
    text = "C2 at 45.9.148.3 and hxxp://bad[.]example[.]net/x.exe; hash 44d88612fea8a8f36de82e1278abb02f"
    got = {(i.type, i.value) for i in extract_iocs(text)}
    assert ("ipv4", "45.9.148.3") in got
    assert ("url", "http://bad.example.net/x.exe") in got
    assert ("md5", "44d88612fea8a8f36de82e1278abb02f") in got
