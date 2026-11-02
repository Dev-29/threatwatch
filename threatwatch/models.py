"""ORM models. See docs/ARCHITECTURE.md for the entity diagram."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# --------------------------------------------------------------------------- watchlist
class Asset(Base):
    """Something the organisation wants monitored: a domain, an employee/executive, a brand keyword."""

    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("type", "value", name="uq_asset_type_value"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    # domain | email | executive | keyword | brand
    type: Mapped[str] = mapped_column(String(20), index=True)
    value: Mapped[str] = mapped_column(String(255))
    label: Mapped[str | None] = mapped_column(String(255))
    # low | medium | high | critical
    criticality: Mapped[str] = mapped_column(String(10), default="medium")
    # executive: {"emails": [...], "usernames": [...]}; domain: {"monitor_lookalikes": true}
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_scanned_at: Mapped[datetime | None] = mapped_column(DateTime)

    exposures: Mapped[list["Exposure"]] = relationship(back_populates="asset", cascade="all, delete-orphan")


# --------------------------------------------------------------------------- dark web
class Exposure(Base):
    """A leaked credential / data leak / mention of a watched asset in a leak source."""

    __tablename__ = "exposures"

    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    source: Mapped[str] = mapped_column(String(80), index=True)
    # breach | paste | stealer_log | ransomware_leak | forum | code_repo | combolist
    source_type: Mapped[str] = mapped_column(String(30), index=True)
    title: Mapped[str] = mapped_column(String(500))
    identifier: Mapped[str | None] = mapped_column(String(255))  # matched email / username / domain
    description: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(String(1000))
    data_classes: Mapped[list] = mapped_column(JSON, default=list)
    has_password: Mapped[bool] = mapped_column(Boolean, default=False)
    password_plaintext: Mapped[bool] = mapped_column(Boolean, default=False)
    record_count: Mapped[int | None] = mapped_column(Integer)
    leaked_at: Mapped[datetime | None] = mapped_column(DateTime)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    severity: Mapped[str] = mapped_column(String(10), default="info", index=True)
    score_factors: Mapped[list] = mapped_column(JSON, default=list)
    # new | investigating | remediated | false_positive
    status: Mapped[str] = mapped_column(String(20), default="new", index=True)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)

    asset: Mapped[Asset] = relationship(back_populates="exposures")


# --------------------------------------------------------------------------- threat intel
class Indicator(Base):
    """A normalised, de-duplicated indicator of compromise aggregated across feeds."""

    __tablename__ = "indicators"
    __table_args__ = (
        UniqueConstraint("type", "value", name="uq_indicator_type_value"),
        Index("ix_indicator_score", "score"),
        Index("ix_indicator_last_seen", "last_seen"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    # ipv4 | ipv6 | cidr | domain | url | md5 | sha1 | sha256 | email | cve | x509-sha1
    type: Mapped[str] = mapped_column(String(16), index=True)
    value: Mapped[str] = mapped_column(String(2048))
    score: Mapped[int] = mapped_column(Integer, default=0)
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    severity: Mapped[str] = mapped_column(String(10), default="info", index=True)
    threat_types: Mapped[list] = mapped_column(JSON, default=list)
    malware_families: Mapped[list] = mapped_column(JSON, default=list)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    attack_techniques: Mapped[list] = mapped_column(JSON, default=list)
    sources: Mapped[list] = mapped_column(JSON, default=list)
    source_confidence: Mapped[dict] = mapped_column(JSON, default=dict)  # {feed: confidence}
    source_count: Mapped[int] = mapped_column(Integer, default=1)
    tlp: Mapped[str] = mapped_column(String(12), default="clear")
    description: Mapped[str | None] = mapped_column(Text)
    context: Mapped[dict] = mapped_column(JSON, default=dict)  # ports, asn, country, product...
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)

    sightings: Mapped[list["IndicatorSource"]] = relationship(
        back_populates="indicator", cascade="all, delete-orphan"
    )


class IndicatorSource(Base):
    """Per-feed sighting of an indicator: lets us explain *why* something is in the feed."""

    __tablename__ = "indicator_sources"
    __table_args__ = (UniqueConstraint("indicator_id", "feed", name="uq_indicator_feed"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    indicator_id: Mapped[int] = mapped_column(ForeignKey("indicators.id", ondelete="CASCADE"), index=True)
    feed: Mapped[str] = mapped_column(String(60), index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    threat_type: Mapped[str | None] = mapped_column(String(60))
    malware: Mapped[str | None] = mapped_column(String(120))
    reference: Mapped[str | None] = mapped_column(String(1000))
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    indicator: Mapped[Indicator] = relationship(back_populates="sightings")


class FeedState(Base):
    """Runtime state of a configured feed (definitions live in modules/intel/feeds.py)."""

    __tablename__ = "feed_state"

    name: Mapped[str] = mapped_column(String(60), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run: Mapped[datetime | None] = mapped_column(DateTime)
    last_status: Mapped[str | None] = mapped_column(String(20))
    last_message: Mapped[str | None] = mapped_column(Text)
    last_count: Mapped[int] = mapped_column(Integer, default=0)
    last_new: Mapped[int] = mapped_column(Integer, default=0)
    total_runs: Mapped[int] = mapped_column(Integer, default=0)


# --------------------------------------------------------------------------- anti-phishing
class LookalikeDomain(Base):
    __tablename__ = "lookalike_domains"
    __table_args__ = (UniqueConstraint("brand_domain", "domain", name="uq_lookalike"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    brand_domain: Mapped[str] = mapped_column(String(255), index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    domain_unicode: Mapped[str | None] = mapped_column(String(255))
    technique: Mapped[str] = mapped_column(String(40))
    registered: Mapped[bool] = mapped_column(Boolean, default=False)
    dns_a: Mapped[list] = mapped_column(JSON, default=list)
    dns_mx: Mapped[list] = mapped_column(JSON, default=list)
    dns_ns: Mapped[list] = mapped_column(JSON, default=list)
    created_date: Mapped[datetime | None] = mapped_column(DateTime)
    registrar: Mapped[str | None] = mapped_column(String(255))
    http_status: Mapped[int | None] = mapped_column(Integer)
    final_url: Mapped[str | None] = mapped_column(String(1000))
    title: Mapped[str | None] = mapped_column(String(500))
    similarity: Mapped[float] = mapped_column(Float, default=0.0)
    has_login_form: Mapped[bool] = mapped_column(Boolean, default=False)
    parked: Mapped[bool] = mapped_column(Boolean, default=False)
    in_threat_feed: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    severity: Mapped[str] = mapped_column(String(10), default="info")
    score_factors: Mapped[list] = mapped_column(JSON, default=list)
    # new | monitoring | takedown_requested | taken_down | benign
    status: Mapped[str] = mapped_column(String(24), default="new")
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_checked: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# --------------------------------------------------------------------------- ASM
class AsmScan(Base):
    __tablename__ = "asm_scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    root_domain: Mapped[str] = mapped_column(String(255), index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued|running|done|failed
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    grade: Mapped[str | None] = mapped_column(String(2))
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    message: Mapped[str | None] = mapped_column(Text)

    assets: Mapped[list["AsmAsset"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    findings: Mapped[list["AsmFinding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class AsmAsset(Base):
    __tablename__ = "asm_assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("asm_scans.id", ondelete="CASCADE"), index=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    sources: Mapped[list] = mapped_column(JSON, default=list)
    resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    ips: Mapped[list] = mapped_column(JSON, default=list)
    cname: Mapped[str | None] = mapped_column(String(255))
    asn: Mapped[dict] = mapped_column(JSON, default=dict)  # {ip: {asn, org, cc, prefix}}
    hosting: Mapped[str | None] = mapped_column(String(60))  # cloudflare / aws / ...
    ports: Mapped[list] = mapped_column(JSON, default=list)  # [{port, service, banner}]
    http: Mapped[dict] = mapped_column(JSON, default=dict)
    tls: Mapped[dict] = mapped_column(JSON, default=dict)
    technologies: Mapped[list] = mapped_column(JSON, default=list)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)

    scan: Mapped[AsmScan] = relationship(back_populates="assets")


class AsmFinding(Base):
    __tablename__ = "asm_findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("asm_scans.id", ondelete="CASCADE"), index=True)
    hostname: Mapped[str] = mapped_column(String(255))
    category: Mapped[str] = mapped_column(String(40))  # exposure|tls|web|email|dns|intel|takeover
    check_id: Mapped[str] = mapped_column(String(60))
    severity: Mapped[str] = mapped_column(String(10), index=True)
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    attack_techniques: Mapped[list] = mapped_column(JSON, default=list)

    scan: Mapped[AsmScan] = relationship(back_populates="findings")


# --------------------------------------------------------------------------- alerts / jobs
class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    module: Mapped[str] = mapped_column(String(20), index=True)  # darkweb|intel|phishing|asm
    severity: Mapped[str] = mapped_column(String(10), index=True)
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str | None] = mapped_column(Text)
    ref_type: Mapped[str | None] = mapped_column(String(30))
    ref_id: Mapped[int | None] = mapped_column(Integer)
    dedup_key: Mapped[str | None] = mapped_column(String(128), unique=True)
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)  # open|acknowledged|closed
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    notified: Mapped[bool] = mapped_column(Boolean, default=False)


class JobRun(Base):
    __tablename__ = "job_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(30), index=True)
    target: Mapped[str | None] = mapped_column(String(255))
    trigger: Mapped[str] = mapped_column(String(20), default="manual")  # manual|schedule|cli
    status: Mapped[str] = mapped_column(String(20), default="running")  # running|success|failed
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    message: Mapped[str | None] = mapped_column(Text)
    stats: Mapped[dict] = mapped_column(JSON, default=dict)
