from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from threatwatch.modules.asm import checks
from threatwatch.modules.asm.probes import fingerprint, hosting_from_org, parse_cert
from threatwatch.modules.asm.service import grade_for, risk_from_findings


def ids(findings):
    return {f["check_id"] for f in findings}


def test_email_checks():
    assert {"spf-missing", "dmarc-missing"} <= ids(checks.check_email("a.example", ["mx.a.example"], [], []))
    assert "spf-permissive" in ids(checks.check_email("a.example", ["mx"], ["v=spf1 +all"], ["v=DMARC1; p=reject"]))
    assert "dmarc-none" in ids(checks.check_email("a.example", ["mx"], ["v=spf1 -all"], ["v=DMARC1; p=none"]))
    assert ids(checks.check_email("a.example", ["mx"], ["v=spf1 -all"], ["v=DMARC1; p=reject"])) == set()


def test_port_rules():
    found = checks.check_ports("h.example", [{"port": 3389, "service": "rdp", "banner": ""},
                                             {"port": 443, "service": "https", "banner": ""},
                                             {"port": 6379, "service": "redis", "banner": ""}])
    sev = {f["check_id"]: f["severity"] for f in found}
    assert sev == {"port-3389": "high", "port-6379": "critical"}


def test_tls_rules():
    base = {"days_left": 200, "self_signed": False, "trusted": True, "hostname_match": True, "legacy_protocols": [],
            "key_type": "RSA", "key_bits": 2048, "signature_hash": "sha256", "not_after": "2027-01-01"}
    assert checks.check_tls("h", base) == []
    assert "tls-expired" in ids(checks.check_tls("h", {**base, "days_left": -3}))
    assert "tls-legacy-protocol" in ids(checks.check_tls("h", {**base, "legacy_protocols": ["TLSv1.0"]}))
    # a hostname mismatch must not also be reported as an untrusted chain
    mm = ids(checks.check_tls("h", {**base, "trusted": False, "hostname_match": False,
                                    "verify_error": "Hostname mismatch, certificate is not valid for 'h'."}))
    assert mm == {"tls-hostname-mismatch"}


def test_takeover_and_nonprod():
    t = checks.check_takeover("blog.a.example", "acme.github.io", True, "<h1>There isn't a GitHub Pages site here.</h1>")
    assert t[0]["check_id"] == "takeover-fingerprint" and t[0]["severity"] == "high"
    d = checks.check_takeover("old.a.example", "gone.azurewebsites.net", False)
    assert d[0]["check_id"] == "dangling-cname" and d[0]["severity"] == "high"
    web = {"https": {"status": 200}}
    assert checks.check_nonprod("staging.a.example", "a.example", True, web)
    assert not checks.check_nonprod("www.a.example", "a.example", True, web)
    assert not checks.check_nonprod("a.example", "a.example", True, web)


def test_kev_cross_reference():
    http = {"https": {"url": "https://vpn.a.example/", "status": 200, "technologies": ["Fortinet FortiGate"],
                      "security_headers": {"strict-transport-security": True}}}
    kev = [{"cve": "CVE-2024-21762", "vendor": "Fortinet", "product": "FortiOS"}]
    f = [x for x in checks.check_http("vpn.a.example", http, kev) if x["category"] == "intel"]
    assert f and "CVE-2024-21762" in f[0]["evidence"]


def test_risk_is_bounded_by_worst_severity():
    mk = lambda *s: [{"severity": x} for x in s]  # noqa: E731
    assert grade_for(risk_from_findings([])) == "A"
    assert grade_for(risk_from_findings(mk(*["low"] * 50))) == "B"
    assert grade_for(risk_from_findings(mk(*["medium"] * 50))) == "C"
    assert grade_for(risk_from_findings(mk("high"))) == "C"
    assert grade_for(risk_from_findings(mk("critical"))) == "F"


def test_parse_cert_self_signed():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "app.a.example")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1234).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=10))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("*.a.example")]), critical=False)
            .sign(key, hashes.SHA256()))
    info = parse_cert(cert.public_bytes(serialization.Encoding.DER), "app.a.example")
    assert info["self_signed"] and info["key_bits"] == 2048 and info["days_left"] in (9, 10)
    assert info["hostname_match"] is True
    assert parse_cert(cert.public_bytes(serialization.Encoding.DER), "x.y.a.example")["hostname_match"] is False


def test_fingerprint_and_hosting():
    assert "WordPress" in fingerprint({}, '<link href="/wp-content/themes/x.css">', "")
    assert "nginx" in fingerprint({"server": "nginx/1.25"}, "", "")
    assert hosting_from_org("AKAMAI-LINODE-AP Akamai Connected Cloud, SG") == "Linode/Akamai"
    assert hosting_from_org("CLOUDFLARENET, US") == "Cloudflare"
