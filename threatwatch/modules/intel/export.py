"""Export indicators as STIX 2.1 bundles, ThreatWatch JSON (schema ``threatwatch.ioc.v1``), CSV or plain text.

STIX object IDs are deterministic (UUIDv5 over a namespace + natural key), so re-exporting the
same indicator always yields the same ``indicator--<uuid>``. Consumers can therefore upsert.
See docs/DATA_FORMAT.md for the full mapping.
"""

from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime, timedelta

from ...models import Indicator
from . import attack
from .scoring import score_indicator
from ...models import utcnow

NAMESPACE = uuid.UUID("6f1c3b8e-6b2a-4f5e-9d61-3c1a3d7b2f10")
SCHEMA = "threatwatch.ioc.v1"

# Standard STIX 2.1 TLP 1.0 marking-definition objects (STIX 2.1 spec section 7.2.1.4)
TLP_MARKINGS = {
    "clear": ("marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9", "white"),
    "white": ("marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9", "white"),
    "green": ("marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da", "green"),
    "amber": ("marking-definition--f88d31f6-486f-44da-b317-01333bde0b82", "amber"),
    "red": ("marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed", "red"),
}

IDENTITY_ID = f"identity--{uuid.uuid5(NAMESPACE, 'threatwatch-producer')}"

INDICATOR_TYPES = {
    "botnet_c2": "malicious-activity", "c2": "malicious-activity", "phishing": "malicious-activity",
    "malware_download": "malicious-activity", "payload_delivery": "malicious-activity",
    "malware": "malicious-activity", "compromised": "compromised", "malicious_activity": "malicious-activity",
    "brute_force": "malicious-activity", "scanner": "anomalous-activity", "hijacked_netblock": "malicious-activity",
}


def sid(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(NAMESPACE, f'{kind}:{key}')}"


def ts(dt: datetime | None) -> str:
    dt = dt or utcnow()
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace("'", "\\'")


def stix_pattern(ioc_type: str, value: str) -> str | None:
    v = _esc(value)
    return {
        "ipv4": f"[ipv4-addr:value = '{v}']",
        "ipv6": f"[ipv6-addr:value = '{v}']",
        "cidr": f"[{'ipv6' if ':' in value else 'ipv4'}-addr:value = '{v}']",
        "domain": f"[domain-name:value = '{v}']",
        "url": f"[url:value = '{v}']",
        "email": f"[email-addr:value = '{v}']",
        "md5": f"[file:hashes.MD5 = '{v}']",
        "sha1": f"[file:hashes.'SHA-1' = '{v}']",
        "sha256": f"[file:hashes.'SHA-256' = '{v}']",
        "x509-sha1": f"[x509-certificate:hashes.'SHA-1' = '{v}']",
    }.get(ioc_type)


def _identity() -> dict:
    return {
        "type": "identity", "spec_version": "2.1", "id": IDENTITY_ID,
        "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
        "name": "ThreatWatch", "identity_class": "system",
        "description": "ThreatWatch external threat intelligence platform (aggregated open-source feeds)",
    }


def _marking(tlp: str) -> dict:
    mid, color = TLP_MARKINGS.get(tlp, TLP_MARKINGS["clear"])
    return {
        "type": "marking-definition", "spec_version": "2.1", "id": mid, "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp", "name": f"TLP:{color.upper()}", "definition": {"tlp": color},
    }


def _attack_pattern(tid: str) -> dict:
    t = attack.technique(tid)
    return {
        "type": "attack-pattern", "spec_version": "2.1", "id": sid("attack-pattern", tid),
        "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
        "created_by_ref": IDENTITY_ID, "name": t["name"],
        "external_references": [{"source_name": "mitre-attack", "external_id": tid, "url": t["url"]}],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": p} for p in t["tactics"]],
    }


def _malware(name: str) -> dict:
    return {
        "type": "malware", "spec_version": "2.1", "id": sid("malware", name.lower()),
        "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
        "created_by_ref": IDENTITY_ID, "name": name, "is_family": True,
    }


def _relationship(src: str, rel: str, dst: str, created: str) -> dict:
    return {
        "type": "relationship", "spec_version": "2.1", "id": sid("relationship", f"{src}|{rel}|{dst}"),
        "created": created, "modified": created, "created_by_ref": IDENTITY_ID,
        "relationship_type": rel, "source_ref": src, "target_ref": dst,
    }


def _external_refs(ind: Indicator) -> list[dict]:
    refs = []
    for s in ind.sightings:
        r = {"source_name": s.feed}
        if s.reference:
            r["url"] = s.reference
        refs.append(r)
    return refs


def indicator_to_stix(ind: Indicator) -> list[dict]:
    """STIX objects for one indicator (indicator/vulnerability + relationships). Shared SDOs excluded."""
    objs: list[dict] = []
    created, modified = ts(ind.created_at), ts(ind.updated_at)
    marking = TLP_MARKINGS.get(ind.tlp, TLP_MARKINGS["clear"])[0]
    custom = {
        "x_threatwatch_score": ind.score, "x_threatwatch_severity": ind.severity,
        "x_threatwatch_sources": ind.sources, "x_threatwatch_threat_types": ind.threat_types,
    }
    if ind.type == "cve":
        vid = sid("vulnerability", ind.value)
        objs.append({
            "type": "vulnerability", "spec_version": "2.1", "id": vid, "created": created, "modified": modified,
            "created_by_ref": IDENTITY_ID, "name": ind.value, "description": ind.description or "",
            "external_references": [{"source_name": "cve", "external_id": ind.value}] + _external_refs(ind),
            "labels": ind.tags, "object_marking_refs": [marking], **custom,
        })
        for tid in ind.attack_techniques:
            objs.append(_relationship(sid("attack-pattern", tid), "targets", vid, created))
        return objs

    pattern = stix_pattern(ind.type, ind.value)
    if not pattern:
        return objs
    iid = sid("indicator", f"{ind.type}:{ind.value}")
    phases = sorted({p for tid in ind.attack_techniques for p in attack.technique(tid)["tactics"]})
    obj = {
        "type": "indicator", "spec_version": "2.1", "id": iid, "created": created, "modified": modified,
        "created_by_ref": IDENTITY_ID,
        "name": f"{ind.type}: {ind.value}"[:250],
        "description": ind.description or f"Flagged by {', '.join(ind.sources)} as "
                                          f"{', '.join(ind.threat_types) or 'malicious'}",
        "indicator_types": sorted({INDICATOR_TYPES.get(t, "malicious-activity") for t in ind.threat_types})
        or ["malicious-activity"],
        "pattern": pattern, "pattern_type": "stix", "pattern_version": "2.1",
        "valid_from": ts(ind.first_seen),
        "confidence": ind.confidence,
        "labels": sorted(set(ind.tags)),
        "external_references": _external_refs(ind),
        "object_marking_refs": [marking],
        **custom,
    }
    if not ind.active:
        obj["valid_until"] = ts(max(ind.last_seen, ind.first_seen) + timedelta(seconds=1))
    if phases:
        obj["kill_chain_phases"] = [{"kill_chain_name": "mitre-attack", "phase_name": p} for p in phases]
    objs.append(obj)
    for fam in ind.malware_families:
        objs.append(_relationship(iid, "indicates", sid("malware", fam.lower()), created))
    for tid in ind.attack_techniques:
        objs.append(_relationship(iid, "indicates", sid("attack-pattern", tid), created))
    return objs


def stix_objects(indicators: list[Indicator]) -> list[dict]:
    objects: dict[str, dict] = {IDENTITY_ID: _identity()}
    families: set[str] = set()
    techniques: set[str] = set()
    tlps: set[str] = set()
    for ind in indicators:
        for o in indicator_to_stix(ind):
            objects[o["id"]] = o
        families.update(ind.malware_families)
        techniques.update(ind.attack_techniques)
        tlps.add(ind.tlp)
    for tlp in tlps:
        m = _marking(tlp)
        objects[m["id"]] = m
    for fam in families:
        m = _malware(fam)
        objects[m["id"]] = m
    for tid in techniques:
        ap = _attack_pattern(tid)
        objects[ap["id"]] = ap
    return list(objects.values())


def stix_bundle(indicators: list[Indicator]) -> dict:
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": stix_objects(indicators)}


def indicator_to_json(ind: Indicator, explain: bool = False) -> dict:
    d = {
        "id": ind.id,
        "type": ind.type,
        "value": ind.value,
        "score": ind.score,
        "severity": ind.severity,
        "confidence": ind.confidence,
        "threat_types": ind.threat_types,
        "malware_families": ind.malware_families,
        "tags": ind.tags,
        "attack": [attack.technique(t) for t in ind.attack_techniques],
        "sources": [
            {"feed": s.feed, "confidence": s.confidence, "reference": s.reference,
             "first_seen": ts(s.first_seen), "last_seen": ts(s.last_seen)}
            for s in ind.sightings
        ],
        "source_count": ind.source_count,
        "tlp": ind.tlp,
        "description": ind.description,
        "context": ind.context,
        "first_seen": ts(ind.first_seen),
        "last_seen": ts(ind.last_seen),
        "last_activity": (ind.context or {}).get("last_activity"),
        "active": ind.active,
        "stix_id": sid("vulnerability", ind.value) if ind.type == "cve" else sid("indicator", f"{ind.type}:{ind.value}"),
    }
    if explain:
        from .service import activity_date

        _, _, _, factors = score_indicator(ind.type, ind.source_confidence or {}, ind.threat_types or [],
                                           ind.tags or [], activity_date(ind), explain=True)
        d["score_factors"] = factors
    return d


def json_document(indicators: list[Indicator]) -> dict:
    return {
        "schema": SCHEMA,
        "generated_at": ts(utcnow()),
        "count": len(indicators),
        "indicators": [indicator_to_json(i) for i in indicators],
    }


CSV_FIELDS = ["type", "value", "score", "severity", "confidence", "threat_types", "malware_families",
              "attack_techniques", "sources", "tags", "first_seen", "last_seen", "tlp"]


def csv_document(indicators: list[Indicator]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_FIELDS)
    for i in indicators:
        w.writerow([i.type, i.value, i.score, i.severity, i.confidence, "|".join(i.threat_types),
                    "|".join(i.malware_families), "|".join(i.attack_techniques), "|".join(i.sources),
                    "|".join(i.tags), ts(i.first_seen), ts(i.last_seen), i.tlp])
    return buf.getvalue()


def text_document(indicators: list[Indicator]) -> str:
    return "\n".join(i.value for i in indicators) + "\n"
