#!/usr/bin/env python3
from __future__ import annotations
import json
import hashlib
import click
from pathlib import Path
from typing import List, Tuple
from lxml import etree

A = "{http://schemas.android.com/apk/res/android}"
ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

RISKY_PERMS = {
    "MANAGE_EXTERNAL_STORAGE": "MEDIUM",
    "REQUEST_INSTALL_PACKAGES": "MEDIUM",
    "SYSTEM_ALERT_WINDOW": "MEDIUM",
    "BIND_ACCESSIBILITY_SERVICE": "HIGH",
    "READ_SMS": "MEDIUM",
    "RECEIVE_SMS": "MEDIUM",
    "READ_CALL_LOG": "MEDIUM",
    "RECORD_AUDIO": "LOW",
    "READ_CONTACTS": "LOW",
    "ACCESS_FINE_LOCATION": "LOW",
    "QUERY_ALL_PACKAGES": "LOW",
    "WRITE_EXTERNAL_STORAGE": "LOW",
    "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": "INFO",
    "PACKAGE_USAGE_STATS": "HIGH",
    "INSTALL_PACKAGES": "HIGH",
    "DELETE_PACKAGES": "HIGH",
    "PROCESS_OUTGOING_CALLS": "MEDIUM",
}

SYSTEM_ACTIONS = {
    "android.intent.action.SCREEN_ON",
    "android.intent.action.SCREEN_OFF",
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.MY_PACKAGE_REPLACED",
    "android.intent.action.TIME_SET",
    "android.intent.action.TIMEZONE_CHANGED",
}

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def parse_manifest(path: Path) -> etree.Element:
    try:
        return etree.parse(str(path)).getroot()
    except Exception as e:
        raise click.ClickException(f"XML parse error: {e}")

def triage(root: etree.Element) -> List[Tuple[str, str, str]]:
    sdk = root.find("uses-sdk")
    target = int(sdk.get(f"{A}targetSdkVersion", "0")) if sdk is not None else 0
    app = root.find("application")
    out: list[tuple[str, str, str]] = []

    def add(sev: str, where: str, msg: str):
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

            if not (is_launcher or sys_only) and not perm:
                add("HIGH", f"{el.tag} {name}", "exported component without permission")
            
            if grant and not perm:
                add("MEDIUM", f"{el.tag} {name}", "grantUriPermissions=true without permission")

    return sorted(out, key=lambda x: ORDER.get(x[0], 99))

@click.command()
@click.argument('manifest_path', type=click.Path(exists=True))
def main(manifest_path):
    path = Path(manifest_path)
    root = parse_manifest(path)
    issues = triage(root)
    
    result = {
        "file": str(path),
        "sha256": sha256_file(path),
        "issues": [{"severity": s, "location": l, "message": m} for s, l, m in issues]
    }
    click.echo(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
