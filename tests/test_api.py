from threatwatch.config import get_settings
from threatwatch.demo import seed


def test_health_and_ui(client):
    assert client.get("/api/health").json()["status"] == "ok"
    assert "ThreatWatch" in client.get("/").text
    assert client.get("/static/js/app.js").status_code == 200


def test_watchlist_validation(client):
    r = client.post("/api/v1/assets", json={"type": "domain", "value": "https://Acme.example.com/path"})
    assert r.status_code == 201 and r.json()["value"] == "acme.example.com"
    assert client.post("/api/v1/assets", json={"type": "domain", "value": "acme.example.com"}).status_code == 409
    assert client.post("/api/v1/assets", json={"type": "domain", "value": "not a domain"}).status_code == 422
    assert client.post("/api/v1/assets", json={"type": "email", "value": "nope"}).status_code == 422
    r = client.post("/api/v1/assets", json={"type": "executive", "value": "Jane Doe", "meta": {"emails": ["JD@Acme.example.com"]}})
    assert r.json()["criticality"] == "high" and r.json()["meta"]["emails"] == ["jd@acme.example.com"]
    aid = r.json()["id"]
    assert client.patch(f"/api/v1/assets/{aid}", json={"enabled": False}).json()["enabled"] is False
    assert client.delete(f"/api/v1/assets/{aid}").status_code == 204


def test_demo_data_endpoints(client):
    seed(reset=True)
    d = client.get("/api/v1/dashboard").json()
    assert d["darkweb"]["total"] > 0 and d["intel"]["active"] > 0 and d["asm"]["latest"]
    ex = client.get("/api/v1/darkweb/exposures", params={"severity": "critical,high"}).json()
    assert ex["total"] > 0 and all(e["severity"] in ("critical", "high") for e in ex["items"])
    detail = client.get(f"/api/v1/darkweb/exposures/{ex['items'][0]['id']}").json()
    assert detail["score_factors"]
    assert client.patch(f"/api/v1/darkweb/exposures/{detail['id']}", json={"status": "investigating"}).json()["status"] == "investigating"

    inds = client.get("/api/v1/intel/indicators", params={"technique": "T1071", "limit": 5}).json()
    assert inds["total"] > 0 and all("T1071" in i["attack_techniques"] for i in inds["items"])
    c2 = client.get("/api/v1/intel/indicators", params={"threat_type": "c2"}).json()["items"]
    assert c2 and all(any(t.endswith("c2") for t in i["threat_types"]) for i in c2)
    one = client.get(f"/api/v1/intel/indicators/{inds['items'][0]['id']}").json()
    assert one["stix"][0]["type"] == "indicator" and one["attack"]

    lk = client.post("/api/v1/intel/lookup", json={"text": "seen 192.0.2.1 and 8.8.8.8"}).json()
    assert lk["extracted"] >= 1

    assert client.get("/api/v1/intel/attack/matrix").json()["total_techniques"] > 5
    assert client.get("/api/v1/phishing/lookalikes").json()["total"] == 10
    scan = client.get("/api/v1/asm/scans").json()[0]
    assert scan["grade"] in "ABCDF" and client.get(f"/api/v1/asm/scans/{scan['id']}/findings").json()
    rep = client.get(f"/api/v1/asm/scans/{scan['id']}/report", params={"format": "html"})
    assert rep.status_code == 200 and "External Risk Report" in rep.text
    assert client.get("/api/v1/alerts", params={"status": "open"}).json()["total"] > 0


def test_exports_and_taxii(client):
    seed(reset=True)
    stix = client.get("/api/v1/intel/export/stix", params={"min_score": 50}).json()
    assert stix["type"] == "bundle" and any(o["type"] == "indicator" for o in stix["objects"])
    js = client.get("/api/v1/intel/export/json", params={"type": "ipv4"}).json()
    assert js["schema"] == "threatwatch.ioc.v1" and all(i["type"] == "ipv4" for i in js["indicators"])
    csv = client.get("/api/v1/intel/export/csv").text.splitlines()
    assert csv[0].startswith("type,value,score")
    assert client.get("/api/v1/intel/export/xml").status_code == 404

    disc = client.get("/taxii2/")
    assert disc.headers["content-type"].startswith("application/taxii+json")
    cols = client.get("/taxii2/api/collections/").json()["collections"]
    objs = client.get(f"/taxii2/api/collections/{cols[0]['id']}/objects/", params={"limit": 5}).json()
    assert objs["more"] is True and objs["objects"]
    assert client.get("/taxii2/api/collections/nope/objects/").status_code == 404


def test_active_asm_requires_authorisation(client):
    r = client.post("/api/v1/asm/scans", json={"root_domain": "example.com", "active": True})
    assert r.status_code == 400


def test_api_key_enforced(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "api_key", "s3cret")
    assert client.get("/api/v1/assets").status_code == 401
    assert client.get("/api/v1/assets", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/api/v1/assets", headers={"X-API-Key": "s3cret"}).status_code == 200
    assert client.get("/api/v1/assets", headers={"Authorization": "Bearer s3cret"}).status_code == 200
    assert client.get("/api/v1/assets", params={"api_key": "s3cret"}).status_code == 200
    assert client.get("/taxii2/").status_code == 401
    assert client.get("/api/health").status_code == 200  # health stays open for load balancers
