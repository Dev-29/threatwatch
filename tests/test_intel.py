import asyncio
from datetime import datetime, timedelta

import httpx
import pytest
from sqlalchemy import select

from threatwatch.models import utcnow
from threatwatch.config import get_settings
from threatwatch.models import Indicator, IndicatorSource
from threatwatch.modules.intel import attack, export, feeds
from threatwatch.modules.intel.feeds import Feed
from threatwatch.modules.intel.scoring import score_indicator
from threatwatch.modules.intel.service import _Agg, merge_into_db


# ------------------------------------------------------------------ scoring
def test_corroboration_raises_confidence():
    now = utcnow()
    _, conf1, _ = score_indicator("ipv4", {"a": 60}, ["scanner"], [], now, now)
    _, conf3, _ = score_indicator("ipv4", {"a": 60, "b": 60, "c": 60}, ["scanner"], [], now, now)
    assert conf3 == conf1 + 16


def test_recency_decay_and_floor():
    now = utcnow()
    fresh, *_ = score_indicator("ipv4", {"a": 90}, ["botnet_c2"], [], now, now)
    month, *_ = score_indicator("ipv4", {"a": 90}, ["botnet_c2"], [], now - timedelta(days=30), now)
    ancient, *_ = score_indicator("ipv4", {"a": 90}, ["botnet_c2"], [], now - timedelta(days=3000), now)
    assert fresh == 90 and month == 45 and ancient == round(90 * 0.35)


def test_cves_do_not_decay():
    now = utcnow()
    s, *_ = score_indicator("cve", {"kev": 100}, ["exploited_vulnerability"], ["ransomware"], now - timedelta(days=900), now)
    assert s == 100


def test_score_explanation_lists_factors():
    now = utcnow()
    *_, factors = score_indicator("url", {"a": 80, "b": 70}, ["phishing"], [], now, now, explain=True)
    names = " ".join(f["factor"] for f in factors)
    assert "corroborated by 2 sources" in names and "threat-type weight" in names


# ------------------------------------------------------------------ ATT&CK
def test_attack_mapping_rules():
    t = attack.map_indicator("ipv4", ["botnet_c2"], ["Lumma Stealer"], [], {"port": 8443})
    assert {"T1071", "T1573", "T1555.003", "T1539", "T1571"} <= set(t)
    assert "T1486" in attack.map_indicator("sha256", ["malware"], ["LockBit 3.0"], [])
    assert "T1566" in attack.map_indicator("url", ["phishing"], [], [])
    assert "T1219" in attack.map_indicator("x509-sha1", ["c2"], ["ResolverRAT"], [])
    assert "T1068" in attack.map_indicator("cve", ["exploited_vulnerability"], [], [],
                                            {"vulnerability_name": "Windows Kernel Privilege Escalation"})
    assert "T1105" in attack.map_indicator("ipv4", [], [], [], {"attack_ids": ["T1105", "bogus"]})


def test_attack_catalogue_and_matrix():
    t = attack.technique("T1566.002")
    assert t["name"] == "Phishing: Spearphishing Link" and t["tactics"] == ["initial-access"]
    assert t["url"].endswith("/T1566/002/")
    cols = attack.matrix({"T1566": 3, "T1071": 1})
    assert [c["tactic"] for c in cols] == attack.active_tactics()
    assert "impact" in attack.active_tactics()
    assert next(c for c in cols if c["tactic"] == "initial-access")["techniques"][0]["count"] == 3


# ------------------------------------------------------------------ ingestion / de-duplication
def _agg(t, v, conf, tt, fam=None):
    return _Agg(t, v, conf, {tt}, {fam} if fam else set(), set(), "https://ref.example/", None, None, {})


def test_merge_deduplicates_across_feeds(db):
    fa = Feed("fa", "A", "", "", None, 90)
    fb = Feed("fb", "B", "", "", None, 60)
    new_a, _ = merge_into_db(db, fa, {("ipv4", "45.9.148.3"): _agg("ipv4", "45.9.148.3", 90, "botnet_c2", "Emotet")})
    new_b, _ = merge_into_db(db, fb, {("ipv4", "45.9.148.3"): _agg("ipv4", "45.9.148.3", 60, "scanner")})
    new_again, _ = merge_into_db(db, fa, {("ipv4", "45.9.148.3"): _agg("ipv4", "45.9.148.3", 90, "botnet_c2")})
    assert (new_a, new_b, new_again) == (1, 0, 0)
    inds = db.scalars(select(Indicator)).all()
    assert len(inds) == 1
    ind = inds[0]
    assert ind.sources == ["fa", "fb"] and ind.source_count == 2
    assert set(ind.threat_types) == {"botnet_c2", "scanner"} and ind.malware_families == ["Emotet"]
    assert ind.confidence == 98
    assert len(db.scalars(select(IndicatorSource)).all()) == 2


# ------------------------------------------------------------------ feed parsers (mocked HTTP)
def _run_fetch(fetch, payload: str):
    transport = httpx.MockTransport(lambda req: httpx.Response(200, text=payload))

    async def go():
        async with httpx.AsyncClient(transport=transport) as c:
            return [r async for r in fetch(c, get_settings())]

    return asyncio.run(go())


def test_parse_sslbl():
    rows = _run_fetch(feeds.fetch_sslbl, "# comment\n# Listingdate,SHA1,Listingreason\n"
                                         "2026-11-02 16:09:46,66c657533cb5d25c1cef98a173f26b69536b67d6,ResolverRAT C&C\n")
    assert rows[0].value == "66c657533cb5d25c1cef98a173f26b69536b67d6"
    assert rows[0].malware == "ResolverRAT" and rows[0].type_hint == "x509-sha1"


def test_parse_spamhaus_ndjson():
    rows = _run_fetch(feeds.fetch_spamhaus_drop, '{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}\n'
                                                 '{"type":"metadata","timestamp":1}\n')
    assert len(rows) == 1 and rows[0].value == "1.10.16.0/20"


def test_parse_feodo():
    rows = _run_fetch(feeds.fetch_feodo, '[{"ip_address":"50.16.16.211","port":443,"status":"online",'
                                         '"first_seen":"2025-01-01 00:00:00","last_online":"2026-11-01","malware":"QakBot"}]')
    assert rows[0].malware == "QakBot" and rows[0].context["port"] == 443
    assert rows[0].last_activity == datetime(2026, 11, 1)


# ------------------------------------------------------------------ STIX export
def test_stix_pattern_escaping():
    assert export.stix_pattern("url", "http://x.example/it's") == "[url:value = 'http://x.example/it\\'s']"
    assert export.stix_pattern("sha256", "a" * 64) == f"[file:hashes.'SHA-256' = '{'a' * 64}']"


def test_stix_bundle_is_valid(db):
    feed = Feed("fa", "A", "", "", None, 90)
    merge_into_db(db, feed, {
        ("ipv4", "45.9.148.3"): _agg("ipv4", "45.9.148.3", 90, "botnet_c2", "Emotet"),
        ("url", "http://bad.example.net/a'b"): _agg("url", "http://bad.example.net/a'b", 80, "phishing"),
        ("cve", "CVE-2024-3400"): _agg("cve", "CVE-2024-3400", 100, "exploited_vulnerability"),
    })
    db.flush()
    inds = db.scalars(select(Indicator)).all()
    bundle = export.stix_bundle(inds)
    types = {o["type"] for o in bundle["objects"]}
    assert {"indicator", "vulnerability", "malware", "attack-pattern", "relationship", "identity"} <= types
    # deterministic ids
    assert export.stix_bundle(inds)["objects"] == bundle["objects"]
    stix2 = pytest.importorskip("stix2")
    from stix2.pattern_visitor import create_pattern_object

    stix2.parse(bundle, allow_custom=True)
    for o in bundle["objects"]:
        if o["type"] == "indicator":
            create_pattern_object(o["pattern"], version="2.1")
