"""Command-line interface: ``threatwatch <command>`` (or ``python -m threatwatch``).

Every collection task available in the UI can be run headless, e.g. from cron or CI.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

from .config import get_settings
from .core.jobs import run_job
from .db import create_all, session_scope


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def cmd_serve(a):
    import uvicorn

    s = get_settings()
    uvicorn.run("threatwatch.main:app", host=a.host or s.host, port=a.port or s.port, reload=a.reload,
                log_level=s.log_level.lower())


def cmd_init_db(a):
    create_all()
    print("database initialised:", get_settings().database_url)


def cmd_feeds(a):
    from .modules.intel import service
    from .modules.intel.feeds import FEEDS, available

    create_all()
    if a.list:
        s = get_settings()
        for n, f in FEEDS.items():
            print(f"{n:16} {'ok ' if available(f, s) else 'KEY'} {f.category:12} {f.title}")
        return
    _print(asyncio.run(run_job("feeds", lambda j: service.run_all_feeds(j, only=a.feed or None),
                               target=",".join(a.feed or []) or "all", trigger="cli")))


def cmd_darkweb(a):
    from .modules.darkweb import service

    create_all()
    _print(asyncio.run(run_job("darkweb_scan", lambda j: service.scan(j, only=a.source or None), target="all",
                               trigger="cli")))


def cmd_phishing(a):
    from .modules.phishing import service

    create_all()
    _print(asyncio.run(run_job("phishing_scan", lambda j: service.scan(j, domains=a.domain or None),
                               target=",".join(a.domain or []) or "all", trigger="cli")))


def cmd_analyze(a):
    from .modules.phishing import analyzer

    create_all()

    async def go():
        with session_scope() as db:
            return await analyzer.analyze(a.url, db, fetch=not a.no_fetch)

    _print(asyncio.run(go()))


def cmd_asm(a):
    from .modules.asm import report, service
    from .models import AsmScan

    create_all()
    if a.active and not a.i_am_authorized:
        sys.exit("refusing active scan: pass --i-am-authorized to confirm you own / may test this target")
    sid = service.create_scan(a.domain, a.active)
    res = asyncio.run(run_job("asm_scan", lambda j: service.run_scan(sid, j), target=str(sid), trigger="cli"))
    _print(res)
    if a.report:
        with session_scope() as db:
            scan = db.get(AsmScan, sid)
            content = report.render_markdown(scan) if a.report.endswith(".md") else (
                json.dumps(report.scan_to_dict(scan), indent=2) if a.report.endswith(".json") else report.render_html(scan))
        with open(a.report, "w", encoding="utf-8") as fh:
            fh.write(content)
        print("report written to", a.report)


def cmd_export(a):
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from .models import Indicator
    from .modules.intel import export

    with session_scope() as db:
        q = select(Indicator).where(Indicator.active.is_(True), Indicator.score >= a.min_score)
        if a.type:
            q = q.where(Indicator.type.in_(a.type.split(",")))
        rows = db.scalars(q.options(selectinload(Indicator.sightings)).order_by(Indicator.score.desc()).limit(a.limit)).all()
        if a.format == "stix":
            out = json.dumps(export.stix_bundle(rows), indent=1)
        elif a.format == "json":
            out = json.dumps(export.json_document(rows), indent=1)
        elif a.format == "csv":
            out = export.csv_document(rows)
        else:
            out = export.text_document(rows)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"{len(rows)} indicators written to {a.output}")
    else:
        sys.stdout.write(out)


def cmd_attack_sync(a):
    from .modules.intel import attack

    print("ATT&CK techniques loaded:", asyncio.run(attack.sync_from_mitre()))


def cmd_seed_demo(a):
    from .demo import seed

    create_all()
    _print(seed(reset=a.reset))


def cmd_add_asset(a):
    from .models import Asset

    create_all()
    meta = {"emails": a.email} if a.type == "executive" and a.email else {}
    with session_scope() as db:
        asset = Asset(type=a.type, value=a.value.lower() if a.type in ("domain", "email") else a.value,
                      label=a.label, criticality=a.criticality, meta=meta)
        db.add(asset)
        db.flush()
        print(f"added {a.type} #{asset.id}: {asset.value}")


def _read_password(a, prompt: str = "Password") -> str:
    if getattr(a, "password_stdin", False):
        return sys.stdin.readline().rstrip("\n")
    import getpass

    pw = getpass.getpass(f"{prompt}: ")
    if pw != getpass.getpass(f"{prompt} (again): "):
        sys.exit("passwords do not match")
    return pw


def cmd_user(a):
    from sqlalchemy import select

    from .core import auth
    from .models import User

    create_all()
    try:
        with session_scope() as db:
            if a.action == "list":
                rows = db.scalars(select(User).order_by(User.username)).all()
                if not rows:
                    print("no users yet - create one with: threatwatch user add <username> --role admin")
                for u in rows:
                    state = "disabled" if u.disabled else "active"
                    print(f"{u.username:24} {u.role:8} {state:8} last login: {u.last_login_at or 'never'}")
                return
            if a.action == "add":
                role = a.role or ("admin" if auth.user_count(db) == 0 else "analyst")
                auth.create_user(db, a.username, _read_password(a), role)
                print(f"created {role} '{auth.normalize_username(a.username)}'")
                return
            user = db.scalar(select(User).where(User.username == a.username.strip().lower()))
            if user is None:
                sys.exit(f"no such user: {a.username}")
            if a.action == "passwd":
                auth.set_password(db, user, _read_password(a, "New password"))
                print(f"password changed for '{user.username}'; their sessions were signed out")
            elif a.action in ("disable", "enable", "delete", "role"):
                last_admin = user.role == "admin" and not user.disabled and auth.active_admin_count(db) <= 1
                if last_admin and (a.action in ("disable", "delete") or (a.action == "role" and a.role != "admin")):
                    sys.exit("refusing: this is the last active admin")
                if a.action == "delete":
                    db.delete(user)
                elif a.action == "role":
                    if a.role not in auth.ROLES:
                        sys.exit(f"--role must be one of {', '.join(auth.ROLES)}")
                    user.role = a.role
                else:
                    user.disabled = a.action == "disable"
                    if user.disabled:
                        auth.revoke_user_sessions(db, user.id)
                print(f"{a.action}: '{user.username}' done")
    except auth.AuthError as e:
        sys.exit(str(e))


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="threatwatch", description="ThreatWatch external threat intelligence platform")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the web UI + API")
    s.add_argument("--host")
    s.add_argument("--port", type=int)
    s.add_argument("--reload", action="store_true")
    s.set_defaults(fn=cmd_serve)

    sub.add_parser("init-db", help="create database tables").set_defaults(fn=cmd_init_db)

    s = sub.add_parser("feeds", help="collect threat-intel feeds")
    s.add_argument("--feed", action="append", help="only this feed (repeatable)")
    s.add_argument("--list", action="store_true", help="list feeds and key requirements")
    s.set_defaults(fn=cmd_feeds)

    s = sub.add_parser("darkweb", help="scan the watchlist against leak sources")
    s.add_argument("--source", action="append", help="only this connector (repeatable)")
    s.set_defaults(fn=cmd_darkweb)

    s = sub.add_parser("phishing", help="look-alike domain scan")
    s.add_argument("--domain", action="append", help="brand domain (repeatable; default: watchlist domains)")
    s.set_defaults(fn=cmd_phishing)

    s = sub.add_parser("analyze-url", help="phishing analysis of a single URL")
    s.add_argument("url")
    s.add_argument("--no-fetch", action="store_true", help="static analysis only")
    s.set_defaults(fn=cmd_analyze)

    s = sub.add_parser("asm", help="attack surface scan of a root domain")
    s.add_argument("domain")
    s.add_argument("--active", action="store_true", help="port scan, sensitive paths, AXFR")
    s.add_argument("--i-am-authorized", action="store_true", help="confirm authorisation for active scanning")
    s.add_argument("--report", help="write report to file (.html, .md or .json)")
    s.set_defaults(fn=cmd_asm)

    s = sub.add_parser("export", help="export indicators")
    s.add_argument("--format", choices=["stix", "json", "csv", "txt"], default="stix")
    s.add_argument("--type", help="comma-separated indicator types")
    s.add_argument("--min-score", type=int, default=0)
    s.add_argument("--limit", type=int, default=100000)
    s.add_argument("-o", "--output")
    s.set_defaults(fn=cmd_export)

    s = sub.add_parser("add-asset", help="add a watchlist asset")
    s.add_argument("type", choices=["domain", "email", "executive", "keyword", "brand"])
    s.add_argument("value")
    s.add_argument("--label")
    s.add_argument("--criticality", choices=["low", "medium", "high", "critical"], default="medium")
    s.add_argument("--email", action="append", help="executive email (repeatable)")
    s.set_defaults(fn=cmd_add_asset)

    s = sub.add_parser("user", help="manage web UI user accounts")
    s.add_argument("action", choices=["add", "list", "passwd", "role", "disable", "enable", "delete"])
    s.add_argument("username", nargs="?", default="")
    s.add_argument("--role", choices=["admin", "analyst", "viewer"],
                   help="for add (default: admin for the first user, else analyst) and role")
    s.add_argument("--password-stdin", action="store_true", help="read the password from stdin (for scripts)")
    s.set_defaults(fn=cmd_user)

    sub.add_parser("attack-sync", help="download the full MITRE ATT&CK catalogue").set_defaults(fn=cmd_attack_sync)

    s = sub.add_parser("seed-demo", help="load a fictional demo organisation with sample data")
    s.add_argument("--reset", action="store_true", help="wipe existing data first")
    s.set_defaults(fn=cmd_seed_demo)

    args = p.parse_args(argv)
    if args.cmd == "user" and args.action != "list" and not args.username:
        p.error(f"user {args.action} needs a username")
    if args.cmd == "user" and args.action == "role" and not args.role:
        p.error("user role needs --role")
    logging.basicConfig(level=get_settings().log_level.upper(), format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    args.fn(args)


if __name__ == "__main__":
    main()
