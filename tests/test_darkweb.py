import asyncio
import json
from datetime import timedelta

import httpx
from sqlalchemy import select

from threatwatch.models import utcnow
from threatwatch.config import get_settings
from threatwatch.models import Asset, Exposure
from threatwatch.modules.darkweb import connectors as cx
from threatwatch.modules.darkweb.importer import _parse_line, import_text
from threatwatch.modules.darkweb.scoring import score_exposure


def _score(**kw):
    base = dict(source_type="breach", data_classes=["Email addresses"], has_password=False, password_plaintext=False,
                leaked_at=None, credibility=0.9, asset_type="email", asset_criticality="medium")
    base.update(kw)
    return score_exposure(**base)


def test_stealer_on_executive_outranks_old_breach():
    now = utcnow()
    stealer, sev1, _ = _score(source_type="stealer_log", data_classes=["Passwords", "Browser cookies"], has_password=True,
                              password_plaintext=True, leaked_at=now - timedelta(days=5), asset_type="executive",
                              asset_criticality="critical")
    old, sev2, _ = _score(leaked_at=now - timedelta(days=3000), asset_criticality="low")
    assert stealer > 85 and sev1 == "critical"
    assert old < 15 and sev2 == "info"


def test_score_monotonic_in_sensitivity_and_soft_capped():
    hashed, *_ = _score(data_classes=["Passwords"], has_password=True)
    plain, *_ = _score(data_classes=["Passwords"], has_password=True, password_plaintext=True)
    assert plain > hashed
    worst, _, factors = _score(source_type="ransomware_leak", data_classes=["Passwords", "Credit cards", "SSN", "Corporate data"],
                               has_password=True, password_plaintext=True, leaked_at=utcnow(),
                               asset_type="executive", asset_criticality="critical", credibility=1.0)
    assert 90 < worst < 100 and any("soft cap" in f["factor"] for f in factors)


def test_mask_secret():
    assert cx.mask_secret("hunter2") == "h*****2"
    assert cx.mask_secret("ab") == "**"


def test_parse_line_formats():
    assert _parse_line("Bob@Acme.example:Secret1") == [("bob@acme.example", "Secret1", None)]
    assert _parse_line("https://sso.acme.example/login:jdoe:P@ss") == [("jdoe", "P@ss", "sso.acme.example")]
    assert _parse_line("https://vpn.acme.example:8443/x|jane@acme.example|pw") == [("jane@acme.example", "pw", "vpn.acme.example")]


def test_import_matches_watchlist_without_storing_plaintext(db):
    db.add_all([Asset(type="domain", value="acme.example", criticality="high"),
                Asset(type="executive", value="Jane Doe", criticality="critical", meta={"emails": ["ceo@ceo-mail.example"]})])
    db.commit()
    content = "\n".join([
        "alice@acme.example:SuperSecret123",          # domain match
        "ceo@ceo-mail.example;Winter2026!",           # executive personal address
        "https://sso.acme.example/login:svc_backup:Backup#1",  # credential for our login portal
        "random@other.example:nope",                  # no match
    ])
    r = import_text(content, "dump.txt")
    assert r["matches"] == 3 and r["new_exposures"] == 3
    rows = db.scalars(select(Exposure)).all()
    blob = json.dumps([[e.raw, e.description, e.title] for e in rows])
    for secret in ("SuperSecret123", "Winter2026!", "Backup#1"):
        assert secret not in blob
    assert "S************3" in blob
    assert import_text(content, "dump.txt")["new_exposures"] == 0  # idempotent


def _search(connector_cls, kind, term, payload, status=200):
    transport = httpx.MockTransport(lambda req: httpx.Response(status, json=payload))
    con = connector_cls(get_settings())
    con.delay = 0

    async def go():
        async with httpx.AsyncClient(transport=transport) as c:
            return await con.search(c, kind, term)

    return asyncio.run(go())


def test_xposedornot_parser():
    payload = {"ExposedBreaches": {"breaches_details": [{
        "breach": "ExampleShop", "details": "d", "domain": "shop.example", "password_risk": "plaintext",
        "verified": "Yes", "xposed_data": "Email addresses;Passwords;Names", "xposed_date": "2024", "xposed_records": 1000}]},
        "ExposedPastes": None}
    f = _search(cx.XposedOrNot, "email", "a@b.example", payload)[0]
    assert f.has_password and f.password_plaintext and f.verified and f.leaked_at.year == 2024
    assert _search(cx.XposedOrNot, "domain", "b.example", payload) == []  # unsupported kind


def test_hudsonrock_domain_parser():
    payload = {"employees": 12, "users": 0, "last_employee_compromised": "2026-10-18T00:00:00.000Z",
               "stealerFamilies": {"Lumma": 5}, "data": {"employees_urls": [{"url": "https://sso.b.example"}]}}
    out = _search(cx.HudsonRock, "domain", "b.example", payload)
    assert len(out) == 1 and out[0].source_type == "stealer_log" and out[0].record_count == 12


def test_ransomware_live_requires_domain_match():
    payload = [{"victim": "Acme Widgets", "domain": "acmewidgets.example", "group": "akira", "attackdate": "2026-10-01"},
               {"victim": "Unrelated", "domain": "other.example", "group": "play"}]
    out = _search(cx.RansomwareLive, "domain", "acmewidgets.example", payload)
    assert [f.raw["group"] for f in out] == ["akira"] and out[0].credibility == 0.9
