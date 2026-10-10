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

def render_html(root, issues, sha):
    package = root.get("package", "?")
    rows = "\n".join(
        f"<tr><td class='{sev}'><b>{sev}</b></td><td>{loc}</td><td>{msg}</td></tr>"
        for sev, loc, msg in issues)
    high_count = sum(1 for s,_,_ in issues if s=="HIGH")
    med_count = sum(1 for s,_,_ in issues if s=="MEDIUM")
    low_count = sum(1 for s,_,_ in issues if s=="LOW")
    info_count = sum(1 for s,_,_ in issues if s=="INFO")
    return f'''<!doctype html>
<html>
<head><meta charset="utf-8">
<title>Audit Report: {package}</title>
<style>
body {{ font-family: sans-serif; margin: 2rem; }}
h1 {{ color: #333; border-bottom: 2px solid #6d4aff; padding-bottom: 0.5rem; }}
table {{ border-collapse: collapse; width: 100%; }}
td, th {{ border: 1px solid #ccc; padding: 0.5rem; }}
th {{ background: #f0f0f0; }}
.HIGH {{ background: #ffe1e1; color: #c00; }}
.MEDIUM {{ background: #fff0cc; color: #a60; }}
.LOW {{ background: #eef4ff; color: #36c; }}
.INFO {{ background: #f5f5f5; color: #666; }}
.meta {{ background: #f9f9f9; padding: 1rem; margin-bottom: 1rem; }}
.code {{ font-family: monospace; word-break: break-all; background: #eee; padding: 0.2rem; }}
.summary {{ display: flex; gap: 1rem; margin: 1rem 0; }}
.count {{ padding: 1rem; border-radius: 4px; text-align: center; min-width: 80px; }}
.count.high {{ background: #ffe1e1; }}
.count.med {{ background: #fff0cc; }}
.count.low {{ background: #eef4ff; }}
.count.info {{ background: #f5f5f5; }}
</style>
</head>
<body>
<h1>Android Manifest Audit Report</h1>
<div class="meta">
<b>Package:</b> {package}<br>
<b>SHA-256:</b> <code class="code">{sha}</code>
</div>
<div class="summary">
<div class="count high"><b>HIGH</b><br>{high_count}</div>
<div class="count med"><b>MEDIUM</b><br>{med_count}</div>
<div class="count low"><b>LOW</b><br>{low_count}</div>
<div class="count info"><b>INFO</b><br>{info_count}</div>
</div>
<table>
<tr><th>Severity</th><th>Location</th><th>Issue</th></tr>
{rows if rows else "<tr><td colspan='3'><i>No issues found</i></td></tr>"}
</table>
</body></html>'''

@click.command()
@click.argument("manifest", type=click.Path(exists=True, path_type=Path))
@click.option("--json", "as_json", is_flag=True, help="Emit JSON")
@click.option("--html", "as_html", is_flag=True, help="Emit HTML report")
@click.option("--out", type=click.Path(path_type=Path), default=None)
def cli(manifest: Path, as_json: bool, as_html: bool, out: Path | None):
    root = parse_manifest(manifest)
    issues = triage(root)
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for sev, _, _ in issues:
        counts[sev] += 1
    sha = sha256_file(manifest)
    if as_html:
        text = render_html(root, issues, sha)
    elif as_json:
        payload = {"package": root.get("package", "?"), "sha256": sha,
                   "issues": [{"severity": s, "location": l, "message": m} for s, l, m in issues],
                   "counts": counts}
        text = json.dumps(payload, indent=2)
    else:
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
