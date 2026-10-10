#!/usr/bin/env python3
from __future__ import annotations
import json, hashlib
from pathlib import Path
from typing import List, Tuple
from xml.etree import ElementTree as ET
import click

A = "{http://schemas.android.com/apk/res/android}"
ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
RISKY_PERMS = {
    "MANAGE_EXTERNAL_STORAGE": "MEDIUM", "REQUEST_INSTALL_PACKAGES": "MEDIUM",
    "SYSTEM_ALERT_WINDOW": "MEDIUM", "BIND_ACCESSIBILITY_SERVICE": "HIGH",
    "READ_SMS": "MEDIUM", "RECEIVE_SMS": "MEDIUM", "READ_CALL_LOG": "MEDIUM",
    "RECORD_AUDIO": "LOW", "READ_CONTACTS": "LOW", "ACCESS_FINE_LOCATION": "LOW",
    "QUERY_ALL_PACKAGES": "LOW", "WRITE_EXTERNAL_STORAGE": "LOW",
    "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": "INFO", "PACKAGE_USAGE_STATS": "HIGH",
    "INSTALL_PACKAGES": "HIGH", "DELETE_PACKAGES": "HIGH",
    "PROCESS_OUTGOING_CALLS": "MEDIUM",
}
SYSTEM_ACTIONS = {
    "android.intent.action.SCREEN_ON", "android.intent.action.SCREEN_OFF",
    "android.intent.action.BOOT_COMPLETED", "android.intent.action.MY_PACKAGE_REPLACED",
    "android.intent.action.TIME_SET", "android.intent.action.TIMEZONE_CHANGED",
}
def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
def parse_manifest(path: Path) -> ET.Element:
    try:
        return ET.parse(str(path)).getroot()
    except Exception as e:
        raise click.ClickException(f"XML parse error: {e}")
def triage(root: ET.Element) -> List[Tuple[str, str, str]]:
    sdk = root.find("uses-sdk")
    target = int(sdk.get(f"{A}targetSdkVersion", "0")) if sdk is not None else 0
    app = root.find("application")
    out = []
    def add(sev, where, msg):
        out.append((sev, where, msg))
    if target and target < 30:
        add("INFO", "uses-sdk", f"targetSdk={target}: legacy platform behavior")
    if app is not None:
        if app.get(f"{A}debuggable") == "true":
            add("HIGH", "application", "debuggable=true")
        if app.get(f"{A}allowBackup", "true") == "true":
            add("MEDIUM", "application", "allowBackup=true")
        ct = app.get(f"{A}usesCleartextTraffic")
        if ct == "true" or (ct is None and 0 < target < 28):
            add("MEDIUM", "application", "cleartext HTTP permitted")
    for p in root.findall("uses-permission"):
        short = p.get(f"{A}name", "").rsplit(".", 1)[-1]
        if short in RISKY_PERMS:
            add(RISKY_PERMS[short], "uses-permission", short)
    if app is not None:
        for el in app.iter():
            if el.tag not in ("activity", "activity-alias", "service", "receiver", "provider"):
                continue
            name = el.get(f"{A}name", "?")
            filters = el.findall("intent-filter")
            attr = el.get(f"{A}exported")
            if target >= 31 and attr is None and filters:
                add("HIGH", f"{el.tag} {name}", "android:exported missing on targetSdk 31+")
            exported = (attr == "true") if attr is not None else bool(filters)
            if not exported:
                continue
            actions = sorted({a.get(f"{A}name", "") for f in filters for a in f.findall("action")})
            perm = el.get(f"{A}permission")
            if el.tag == "provider":
                perm = perm or el.get(f"{A}readPermission") or el.get(f"{A}writePermission")
            if perm:
                continue
            is_launcher = "android.intent.action.MAIN" in actions
            sys_only = bool(actions) and all(a in SYSTEM_ACTIONS for a in actions)
            grant = el.get(f"{A}grantUriPermissions") == "true"
            if is_launcher:
                sev, msg = "INFO", "launcher entry"
            elif el.tag == "provider":
                sev, msg = "HIGH", f"exported provider, no permission{' + grantUriPermissions' if grant else ''}"
            elif el.tag == "service":
                sev, msg = "HIGH", "exported service, no permission"
            elif el.tag == "receiver" and sys_only:
                sev, msg = "LOW", "exported receiver for system-only actions"
            elif el.tag == "receiver":
                sev, msg = "MEDIUM", "exported receiver, no permission"
            else:
                sev, msg = "INFO", f"exported {el.tag} {name}"
            out.append((sev, f"{el.tag} {name}", msg))
    return sorted(out, key=lambda x: ORDER[x[0]])
@click.command()
@click.argument("manifest", type=click.Path(exists=True, path_type=Path))
@click.option("--json", "as_json", is_flag=True, help="Emit JSON")
@click.option("--html", "as_html", is_flag=True, help="Emit HTML report")
@click.option("--batch", "do_batch", is_flag=True, help="Scan directory")
@click.option("--recursive", "-r", "recurse", is_flag=True, help="Recursive scan")
@click.option("--out", type=click.Path(path_type=Path), default=None)
def cli(manifest: Path, as_json: bool, as_html: bool, out: Path | None):
    root = parse_manifest(manifest)
    issues = triage(root)
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for sev, _, _ in issues:
        counts[sev] += 1
    lines = [f"[{sev}] {loc}: {msg}" for sev, loc, msg in issues]
    lines.append("")
    lines.append(f"Severity counts: HIGH={counts['HIGH']} MEDIUM={counts['MEDIUM']} LOW={counts['LOW']} INFO={counts['INFO']}")
    text = "\n".join(lines)
    if out:
        out.write_text(text)
        click.echo(f"Report written to {out}")
    else:
        click.echo(text)
if __name__ == "__main__":
    cli()

def render_html(root, issues, sha):
    package = root.get("package", "?")
    rows = "\n".join(
        f"<tr><td class='{sev}'><b>{sev}</b></td><td>{loc}</td><td>{msg}</td></tr>"
        for sev, loc, msg in issues)
    return f'''<!doctype html><html><head><meta charset="utf-8">
<style>body{{font-family:sans-serif;margin:2rem}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ccc;padding:.4rem}}

def batch_scan(directory: Path, recursive: bool = False) -> dict:
    """Scan all XML files in directory."""
    pattern = "**/*.xml" if recursive else "*.xml"
    results = []
    total_issues = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    
    for xml_file in sorted(directory.glob(pattern)):
        try:
            root = parse_manifest(xml_file)
            issues = triage(root)
            for sev, _, _ in issues:
                total_issues[sev] += 1
            results.append({
                "file": str(xml_file),
                "package": root.get("package", "?"),
                "issues": len(issues),
                "high": sum(1 for s, _, _ in issues if s == "HIGH"),
                "medium": sum(1 for s, _, _ in issues if s == "MEDIUM")
            })
        except Exception as e:
            results.append({"file": str(xml_file), "error": str(e)})
    
    return {"results": results, "totals": total_issues}
.HIGH{{background:#ffe1e1}}.MEDIUM{{background:#fff0cc}}
.LOW{{background:#eef4ff}}.INFO{{background:#f5f5f5}}</style></head><body>
<h1>Audit Report</h1><p><b>Package:</b> {package}</p><p><b>SHA-256:</b> <code>{sha}</code></p>
<table><tr><th>Severity</th><th>Location</th><th>Message</th></tr>{rows}</table></body></html>'''
