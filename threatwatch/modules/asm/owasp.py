"""OWASP Top 10 (2021) catalogue and normalisation of agent-reported findings.

The autonomous pentest driver (:mod:`.pentest`) asks a Claude Code agent to report what it
found as loosely-structured JSON. This module is the trusted boundary that turns that
untrusted output into the strict :class:`~threatwatch.models.AsmFinding` dict shape used by
the rest of ASM, and tracks per-category coverage so a report can state which of the ten
OWASP categories were actually exercised.

A finding dict is: ``{hostname, category, check_id, severity, title, description, evidence,
remediation, attack_techniques}`` - identical to the rules in :mod:`.checks`, so the existing
risk scorer, alerting and report renderer all work on pentest findings unchanged.
"""

from __future__ import annotations

import re

# Ordered OWASP Top 10 (2021). ``techniques`` are MITRE ATT&CK IDs so pentest findings render
# with the same ATT&CK links as the rest of ASM; ``cwes`` seed the evidence/reference text.
CATEGORIES: list[dict] = [
    {"id": "A01", "slug": "broken-access-control", "title": "Broken Access Control",
     "cwes": ["CWE-200", "CWE-201", "CWE-284", "CWE-639"], "techniques": ["T1190"],
     "hint": "IDOR / object-level authorisation, path traversal, forced browsing, missing function-level "
             "access control, privilege escalation, CORS misconfiguration, JWT/role tampering."},
    {"id": "A02", "slug": "cryptographic-failures", "title": "Cryptographic Failures",
     "cwes": ["CWE-259", "CWE-327", "CWE-331"], "techniques": ["T1040", "T1557"],
     "hint": "Cleartext transport, weak/legacy TLS, missing HSTS, sensitive data in URLs/cookies, weak "
             "hashing, predictable tokens."},
    {"id": "A03", "slug": "injection", "title": "Injection",
     "cwes": ["CWE-79", "CWE-89", "CWE-78", "CWE-94"], "techniques": ["T1190", "T1059"],
     "hint": "SQL/NoSQL injection, OS command injection, XSS (reflected/stored/DOM), SSTI, LDAP/header "
             "injection. Use safe, non-destructive proof payloads only."},
    {"id": "A04", "slug": "insecure-design", "title": "Insecure Design",
     "cwes": ["CWE-209", "CWE-256", "CWE-501", "CWE-522"], "techniques": ["T1190"],
     "hint": "Missing rate limiting, abusable business logic, weak recovery flows, trust-boundary gaps "
             "visible from the outside."},
    {"id": "A05", "slug": "security-misconfiguration", "title": "Security Misconfiguration",
     "cwes": ["CWE-16", "CWE-611"], "techniques": ["T1190", "T1133"],
     "hint": "Default creds, verbose errors/stack traces, directory listing, exposed admin panels, missing "
             "security headers, open cloud metadata, XXE, unneeded features enabled."},
    {"id": "A06", "slug": "vulnerable-components", "title": "Vulnerable and Outdated Components",
     "cwes": ["CWE-1104", "CWE-937"], "techniques": ["T1190", "T1203"],
     "hint": "Outdated server/framework/library versions with known CVEs, exposed version banners, abandoned "
             "dependencies. Confirm versions passively where possible."},
    {"id": "A07", "slug": "auth-failures", "title": "Identification and Authentication Failures",
     "cwes": ["CWE-287", "CWE-307", "CWE-384", "CWE-620"], "techniques": ["T1110", "T1078", "T1212"],
     "hint": "Credential stuffing / weak lockout, weak password policy, session fixation, predictable session "
             "IDs, missing MFA, flawed password reset. Never brute-force real accounts; demonstrate the weakness."},
    {"id": "A08", "slug": "integrity-failures", "title": "Software and Data Integrity Failures",
     "cwes": ["CWE-345", "CWE-494", "CWE-502"], "techniques": ["T1195", "T1554"],
     "hint": "Insecure deserialization, unsigned/auto-updates, untrusted CI/CD or plugin sources, missing "
             "subresource integrity."},
    {"id": "A09", "slug": "logging-monitoring-failures", "title": "Security Logging and Monitoring Failures",
     "cwes": ["CWE-117", "CWE-532", "CWE-778"], "techniques": [],
     "hint": "Externally observable gaps only: no lockout/alert on attack traffic, sensitive data in client-visible "
             "logs/responses. Do not attempt to assess internal logging."},
    {"id": "A10", "slug": "ssrf", "title": "Server-Side Request Forgery (SSRF)",
     "cwes": ["CWE-918"], "techniques": ["T1190"],
     "hint": "URL/webhook/import/preview features that fetch attacker-supplied URLs; test only against your own "
             "collaborator endpoint, never internal third-party ranges."},
]

BY_ID = {c["id"]: c for c in CATEGORIES}
_BY_SLUG = {c["slug"]: c for c in CATEGORIES}

_SEV_ALIASES = {
    "informational": "info", "information": "info", "none": "info", "note": "info",
    "warning": "low", "minor": "low", "moderate": "medium", "medium": "medium", "med": "medium",
    "important": "high", "severe": "high", "crit": "critical",
}
VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def normalize_severity(value: str | None, cvss: float | None = None) -> str:
    """Map an agent-supplied severity (or CVSS base score) onto ThreatWatch's five levels."""
    if value:
        v = str(value).strip().lower()
        if v in VALID_SEVERITIES:
            return v
        if v in _SEV_ALIASES:
            return _SEV_ALIASES[v]
    if cvss is not None:
        try:
            score = float(cvss)
        except (TypeError, ValueError):
            score = -1.0
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0.0:
            return "low"
    return "info"


_ID_RE = re.compile(r"a(\d{1,2})", re.I)


def map_category(value: str | None) -> dict:
    """Resolve an agent-claimed OWASP category (id, slug, or free text) to a catalogue entry.

    Falls back to A05 (Security Misconfiguration) - the broadest bucket - when nothing matches,
    so a finding is never silently dropped for a malformed category label.
    """
    if value:
        v = str(value).strip().lower()
        m = _ID_RE.search(v.replace(":", "").replace(" ", ""))
        if m:
            cid = f"A{int(m.group(1)):02d}"
            if cid in BY_ID:
                return BY_ID[cid]
        if v in _BY_SLUG:
            return _BY_SLUG[v]
        for cat in CATEGORIES:
            if cat["slug"].replace("-", " ") in v or cat["title"].lower() in v:
                return cat
        keywords = {
            "idor": "A01", "access control": "A01", "authorization": "A01", "authorisation": "A01",
            "traversal": "A01", "ssrf": "A10", "xss": "A03", "sql": "A03", "injection": "A03",
            "ssti": "A03", "command inj": "A03", "crypto": "A02", "tls": "A02", "ssl": "A02",
            "cve": "A06", "outdated": "A06", "component": "A06", "deserial": "A08", "auth": "A07",
            "session": "A07", "password": "A07", "misconfig": "A05", "header": "A05", "xxe": "A05",
        }
        for kw, cid in keywords.items():
            if kw in v:
                return BY_ID[cid]
    return BY_ID["A05"]


def _slugify(text: str, fallback: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", str(text or "").lower()).strip("-")
    return (s or fallback)[:40]


def to_finding(raw: dict, default_host: str) -> dict:
    """Normalise one untrusted agent finding into the AsmFinding dict shape.

    Never trusts the agent for the hostname: callers pass the authorised in-scope host and any
    host the agent names outside that set is ignored in favour of ``default_host``.
    """
    cat = map_category(raw.get("owasp") or raw.get("category") or raw.get("type"))
    severity = normalize_severity(raw.get("severity"), raw.get("cvss"))
    title = str(raw.get("title") or raw.get("name") or cat["title"]).strip()[:500] or cat["title"]
    slug = _slugify(raw.get("check_id") or raw.get("id") or title, cat["slug"])
    check_id = f"{cat['id'].lower()}-{slug}"[:60]

    cwe = raw.get("cwe")
    refs = []
    if cwe:
        refs.append(str(cwe) if str(cwe).upper().startswith("CWE") else f"CWE-{cwe}")
    cves = raw.get("cves") or raw.get("cve")
    if isinstance(cves, str):
        cves = [cves]
    if isinstance(cves, list):
        refs.extend(str(c).strip() for c in cves if c)

    description = str(raw.get("description") or raw.get("detail") or "").strip()[:4000]
    if refs:
        description = (description + f"\n\nReferences: {', '.join(refs)}").strip()

    return {
        "hostname": default_host,
        "category": f"owasp-{cat['id'].lower()}",
        "check_id": check_id,
        "severity": severity,
        "title": f"{cat['id']}: {title}"[:500],
        "description": description or cat["hint"],
        "evidence": str(raw.get("evidence") or raw.get("poc") or raw.get("proof") or "").strip()[:4000] or None,
        "remediation": str(raw.get("remediation") or raw.get("fix") or "").strip()[:4000] or None,
        "attack_techniques": list(cat["techniques"]),
    }


def coverage_skeleton() -> dict:
    """A per-category coverage map, every category starting as ``not-tested``."""
    return {c["id"]: {"title": c["title"], "slug": c["slug"], "status": "not-tested", "notes": ""}
            for c in CATEGORIES}


_COVERAGE_STATES = {"tested", "not-tested", "not-applicable", "finding", "error"}


def merge_coverage(skeleton: dict, agent_coverage, finding_cats: set[str]) -> dict:
    """Fold the agent's self-reported coverage and the categories that produced findings into the map."""
    items = []
    if isinstance(agent_coverage, dict):
        items = agent_coverage.items()
    elif isinstance(agent_coverage, list):
        items = [(e.get("owasp") or e.get("category"), e) for e in agent_coverage if isinstance(e, dict)]
    for key, val in items:
        cat = map_category(key)
        entry = skeleton.get(cat["id"])
        if not entry:
            continue
        if isinstance(val, dict):
            status = str(val.get("status", "tested")).lower()
            entry["notes"] = str(val.get("notes") or val.get("note") or "")[:500]
        else:
            status = str(val).lower()
        entry["status"] = status if status in _COVERAGE_STATES else "tested"
    for cid in finding_cats:
        if cid in skeleton:
            skeleton[cid]["status"] = "finding"
    return skeleton
