"""MITRE ATT&CK catalogue and rule-based mapping of indicators to techniques.

The catalogue ships as an embedded subset (data/attack_techniques.json). ``threatwatch attack-sync``
downloads the full Enterprise matrix into ``TW_DATA_DIR`` which then takes precedence.

Mapping is deterministic and explainable. Three rule families are applied and unioned:

1. **threat type** - what the feed says the indicator *does* (C2, phishing, payload delivery ...)
2. **malware family** - known behaviour of named families (stealers, loaders, ransomware, RATs ...)
3. **tags / indicator type** - e.g. x509 certificates used for C2 imply encrypted channels.

Feeds that already ship ATT&CK IDs (AlienVault OTX pulses) are passed through untouched.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

EMBEDDED_FILE = Path(__file__).resolve().parents[2] / "data" / "attack_techniques.json"


def _synced_file() -> Path:
    from ...config import get_settings

    return Path(get_settings().data_dir) / "attack_techniques.json"

# Canonical kill-chain order. Recent ATT&CK releases split "defense-evasion" into "stealth" and
# "defense-impairment"; both generations are listed and the matrix shows whichever the loaded catalogue uses.
TACTICS = [
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "stealth", "defense-impairment", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control", "exfiltration", "impact",
]


def tactic_name(t: str) -> str:
    return t.replace("-", " ").title().replace(" And ", " and ")


def active_tactics() -> list[str]:
    """Tactics present in the loaded catalogue, in kill-chain order (unknown future tactics appended)."""
    present = {t for v in catalog().values() for t in v.get("tactics", [])}
    return [t for t in TACTICS if t in present] + sorted(present - set(TACTICS))

# ------------------------------------------------------------------ rules
THREAT_TYPE_RULES: dict[str, list[str]] = {
    "c2": ["T1071", "T1071.001", "T1573"],
    "botnet_c2": ["T1071", "T1071.001", "T1573", "T1584.005"],
    "phishing": ["T1566", "T1566.002", "T1598.003", "T1204.001"],
    "malware_download": ["T1105", "T1204.002", "T1189"],
    "payload_delivery": ["T1105", "T1204.002"],
    "malware": ["T1204.002", "T1587.001"],
    "brute_force": ["T1110", "T1110.001", "T1110.003"],
    "scanner": ["T1595", "T1595.001", "T1595.002"],
    "compromised": ["T1584", "T1090"],
    "malicious_activity": ["T1595"],
    "hijacked_netblock": ["T1583", "T1584"],
    "exploited_vulnerability": ["T1190"],
    "spam": ["T1566"],
    "ransomware": ["T1486", "T1490", "T1567"],
    "credential_theft": ["T1555", "T1539", "T1041"],
    "cryptomining": ["T1496"],
    "ddos": ["T1498"],
}

FAMILY_GROUPS: list[tuple[re.Pattern, list[str]]] = [
    # info-stealers
    (re.compile(r"redline|lumma|vidar|raccoon|stealc|meta ?stealer|risepro|rhadamanthys|aurora|"
                r"mystic|atomic|amos|poseidon|acr ?stealer|phemedrone|stealer", re.I),
     ["T1555.003", "T1539", "T1552.001", "T1041"]),
    # keyloggers / info-stealing RATs
    (re.compile(r"agent ?tesla|formbook|xloader|snake ?keylogger|404 ?keylogger|keylog", re.I),
     ["T1056.001", "T1555.003", "T1041"]),
    # loaders / droppers
    (re.compile(r"emotet|qakbot|qbot|icedid|bumblebee|smoke ?loader|guloader|pikabot|latrodectus|"
                r"gootloader|socgholish|darkgate|hijackloader|amadey|privateloader|loader", re.I),
     ["T1105", "T1566.001", "T1204.002", "T1059"]),
    # RATs
    (re.compile(r"asyncrat|remcos|njrat|quasar|dcrat|xworm|nanocore|netwire|warzone|ave ?maria|"
                r"venom ?rat|orcus|rat\b", re.I),
     ["T1219", "T1056.001", "T1113", "T1071.001"]),
    # post-exploitation frameworks
    (re.compile(r"cobalt ?strike|sliver|brute ?ratel|metasploit|meterpreter|havoc|mythic|"
                r"posh ?c2|covenant|empire", re.I),
     ["T1071.001", "T1573.002", "T1055", "T1059.001"]),
    # ransomware
    (re.compile(r"lockbit|blackcat|alphv|akira|black ?basta|\bplay\b|royal|clop|cl0p|conti|"
                r"ransom|medusa|rhysida|8base|bianlian|hunters|qilin|ransomhub|inc ?ransom", re.I),
     ["T1486", "T1490", "T1567.002"]),
    # IoT botnets
    (re.compile(r"mirai|gafgyt|bashlite|mozi|hajime|moobot", re.I),
     ["T1498", "T1110", "T1190", "T1584.005"]),
    # miners
    (re.compile(r"xmrig|coinminer|miner", re.I), ["T1496"]),
]

TAG_RULES: dict[str, list[str]] = {
    "phishing": ["T1566"],
    "ransomware": ["T1486"],
    "stealer": ["T1555.003", "T1539"],
    "rat": ["T1219"],
    "loader": ["T1105"],
    "exe": ["T1204.002"],
    "dll": ["T1218"],
    "doc": ["T1566.001", "T1204.002"],
    "xls": ["T1566.001", "T1204.002"],
    "zip": ["T1027"],
    "elf": ["T1190"],
    "botnet": ["T1584.005"],
    "brute-force": ["T1110"],
    "ssh": ["T1110", "T1133"],
    "rdp": ["T1133", "T1021.001"],
}

TYPE_RULES: dict[str, list[str]] = {
    "x509-sha1": ["T1573.002"],
    "cidr": ["T1583"],
}


@lru_cache
def catalog() -> dict[str, dict]:
    path = _synced_file() if _synced_file().exists() else EMBEDDED_FILE
    with open(path, encoding="utf-8") as fh:
        techniques = json.load(fh)["techniques"]
    if path != EMBEDDED_FILE:  # never lose techniques the mapping rules rely on
        with open(EMBEDDED_FILE, encoding="utf-8") as fh:
            for k, v in json.load(fh)["techniques"].items():
                techniques.setdefault(k, v)
    return techniques


def reload_catalog() -> None:
    catalog.cache_clear()


def technique(tid: str) -> dict:
    t = catalog().get(tid, {})
    parent = tid.split(".")[0]
    name = t.get("name", tid)
    if "." in tid and parent in catalog():
        name = f"{catalog()[parent]['name']}: {name}"
    return {
        "id": tid,
        "name": name,
        "tactics": t.get("tactics", []),
        "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/",
    }


def map_indicator(
    ioc_type: str,
    threat_types: list[str],
    malware_families: list[str],
    tags: list[str],
    context: dict | None = None,
) -> list[str]:
    """Return sorted technique IDs for an indicator."""
    out: set[str] = set()
    for tt in threat_types:
        out.update(THREAT_TYPE_RULES.get(tt, []))
    for fam in malware_families:
        for pattern, techs in FAMILY_GROUPS:
            if pattern.search(fam):
                out.update(techs)
    for tag in tags:
        out.update(TAG_RULES.get(tag.lower(), []))
    out.update(TYPE_RULES.get(ioc_type, []))
    ctx = context or {}
    # C2 on an uncommon port
    port = ctx.get("port")
    if port and any(t in ("c2", "botnet_c2") for t in threat_types) and int(port) not in (80, 443, 53):
        out.add("T1571")
    # KEV vulns: privilege-escalation vs. remote/client exploitation
    vname = (ctx.get("vulnerability_name") or "").lower()
    if "privilege escalation" in vname:
        out.add("T1068")
    if any(k in vname for k in ("browser", "chrome", "office", "word", "excel", "acrobat", "reader")):
        out.add("T1203")
    for tid in ctx.get("attack_ids", []) or []:
        if re.match(r"^T\d{4}(\.\d{3})?$", tid):
            out.add(tid)
    return sorted(out)


def matrix(technique_counts: dict[str, int]) -> list[dict]:
    """Tactic columns with technique counts, for the ATT&CK heat-map view."""
    cols = []
    for tactic in active_tactics():
        techs = []
        for tid, cnt in technique_counts.items():
            t = technique(tid)
            if tactic in t["tactics"]:
                techs.append({**t, "count": cnt})
        techs.sort(key=lambda x: -x["count"])
        cols.append({"tactic": tactic, "name": tactic_name(tactic), "techniques": techs})
    return cols


async def sync_from_mitre() -> int:
    """Download the full Enterprise ATT&CK catalogue and replace the embedded subset."""
    from ...core.http import client

    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    async with client(timeout=120) as c:
        r = await c.get(url)
        r.raise_for_status()
        bundle = r.json()
    techniques: dict[str, dict] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = next((e for e in obj.get("external_references", []) if e.get("source_name") == "mitre-attack"), None)
        if not ext:
            continue
        tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"]
        techniques[ext["external_id"]] = {"name": obj["name"], "tactics": tactics}
    target = _synced_file()
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "w", encoding="utf-8") as fh:
        json.dump({"_comment": "Full MITRE ATT&CK Enterprise catalogue (synced).", "version": "synced",
                   "techniques": dict(sorted(techniques.items()))}, fh, indent=1)
    reload_catalog()
    return len(techniques)
