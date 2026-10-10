#!/usr/bin/env python3
"""Triage Android manifest XML files and APKs."""

from __future__ import annotations

import argparse
import concurrent.futures
import glob
import hashlib
import html
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from lxml import etree

ANDROID = "{http://schemas.android.com/apk/res/android}"
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


def parse_manifest_bytes(data: bytes) -> etree._Element:
    """Parse XML with external entity resolution and network access disabled."""
    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        huge_tree=False,
    )
    return etree.fromstring(data, parser=parser)


def parse_manifest(path: Path | str) -> etree._Element:
    """Compatibility helper used by the project tests."""
    return parse_manifest_bytes(Path(path).read_bytes())


def triage(root: etree._Element) -> list[tuple[str, str, str]]:
    sdk = root.find("uses-sdk")
    target = 0
    if sdk is not None:
        try:
            target = int(sdk.get(f"{ANDROID}targetSdkVersion", "0"))
        except ValueError:
            target = 0

    app = root.find("application")
    issues: list[tuple[str, str, str]] = []

    def add(severity: str, location: str, message: str) -> None:
        issues.append((severity, location, message))

    if target and target < 30:
        add("INFO", "uses-sdk", f"targetSdk={target}: legacy platform behavior")

    if app is not None:
        if app.get(f"{ANDROID}debuggable") == "true":
            add("HIGH", "application", "debuggable=true")
        if app.get(f"{ANDROID}allowBackup", "true") == "true":
            add("MEDIUM", "application", "allowBackup=true")
        cleartext = app.get(f"{ANDROID}usesCleartextTraffic")
        if cleartext == "true" or (cleartext is None and 0 < target < 28):
            add("MEDIUM", "application", "cleartext HTTP permitted")

    for permission in root.findall("uses-permission"):
        name = permission.get(f"{ANDROID}name", "").rsplit(".", 1)[-1]
        if name in RISKY_PERMS:
            add(RISKY_PERMS[name], "uses-permission", name)

    if app is not None:
        component_tags = {"activity", "activity-alias", "service", "receiver", "provider"}
        for element in app.iter():
            if element.tag not in component_tags:
                continue

            name = element.get(f"{ANDROID}name", "?")
            location = f"{element.tag} {name}"
            filters = element.findall("intent-filter")
            exported_attr = element.get(f"{ANDROID}exported")

            if target >= 31 and exported_attr is None and filters:
                add("HIGH", location, "android:exported missing on targetSdk 31+")

            exported = exported_attr == "true" if exported_attr is not None else bool(filters)
            if not exported:
                continue

            actions = {
                action.get(f"{ANDROID}name", "")
                for intent_filter in filters
                for action in intent_filter.findall("action")
            }

            permission = element.get(f"{ANDROID}permission")
            if element.tag == "provider":
                permission = (
                    permission
                    or element.get(f"{ANDROID}readPermission")
                    or element.get(f"{ANDROID}writePermission")
                )
            if permission:
                continue

            if "android.intent.action.MAIN" in actions:
                severity, message = "INFO", "launcher entry"
            elif element.tag == "provider":
                grant = element.get(f"{ANDROID}grantUriPermissions") == "true"
                suffix = " + grantUriPermissions" if grant else ""
                severity, message = "HIGH", f"exported provider, no permission{suffix}"
            elif element.tag == "service":
                severity, message = "HIGH", "exported service, no permission"
            elif element.tag == "receiver" and actions and actions <= SYSTEM_ACTIONS:
                severity, message = "LOW", "exported receiver for system-only actions"
            elif element.tag == "receiver":
                severity, message = "MEDIUM", "exported receiver, no permission"
            else:
                severity, message = "INFO", f"exported {element.tag} {name}"

            add(severity, location, message)

    return sorted(issues, key=lambda issue: ORDER[issue[0]])


def decode_input(path: str) -> tuple[bytes, str]:
    if path == "-":
        data = sys.stdin.buffer.read()
        return data, "stdin"

    file_path = Path(path)
    if file_path.suffix.lower() == ".apk":
        result = subprocess.run(
            ["apkanalyzer", "manifest", "print", str(file_path)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"apkanalyzer failed for {file_path}: {detail}")
        return result.stdout, str(file_path)

    return file_path.read_bytes(), str(file_path)


def analyze(path: str) -> dict[str, Any]:
    data, label = decode_input(path)
    root = parse_manifest_bytes(data)
    issues = triage(root)
    counts = {severity: 0 for severity in ORDER}
    for severity, _, _ in issues:
        counts[severity] += 1

    sdk = root.find("uses-sdk")
    try:
        target_sdk = int(sdk.get(f"{ANDROID}targetSdkVersion", "0")) if sdk is not None else 0
    except ValueError:
        target_sdk = 0

    return {
        "file": label,
        "package": root.get("package", "?"),
        "targetSdk": target_sdk,
        "sha256": hashlib.sha256(data).hexdigest(),
        "issues": [
            {"severity": severity, "location": location, "message": message}
            for severity, location, message in issues
        ],
        "counts": counts,
    }


def expand_inputs(patterns: list[str]) -> list[str]:
    """Expand shell-style globs; recursively search when ** is used."""
    found: list[str] = []
    for pattern in patterns:
        matches = glob.glob(pattern, recursive=True)
        found.extend(matches if matches else [pattern])

    # Preserve order while removing duplicates.
    return list(dict.fromkeys(found))


def filter_issues(report: dict[str, Any], threshold: str) -> dict[str, Any]:
    result = dict(report)
    result["issues"] = [
        issue for issue in report["issues"]
        if ORDER[issue["severity"]] <= ORDER[threshold]
    ]
    return result


def render_html(reports: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    for report in reports:
        for issue in report["issues"]:
            cells = (
                issue["severity"],
                report["file"],
                issue["location"],
                issue["message"],
            )
            rows.append(
                "<tr>"
                + "".join(f"<td>{html.escape(str(cell))}</td>" for cell in cells)
                + "</tr>"
            )

    return """<!doctype html>
<html><head><meta charset="utf-8"><title>Manifest audit</title>
<style>
body{font-family:sans-serif;margin:2rem}
table{border-collapse:collapse;width:100%}
td,th{border:1px solid #ccc;padding:.4rem;text-align:left}
.HIGH{background:#ffe1e1}.MEDIUM{background:#fff0cc}
.LOW{background:#eef4ff}.INFO{background:#f5f5f5}
</style></head><body><h1>Manifest audit</h1>
<table><tr><th>Severity</th><th>File</th><th>Location</th><th>Message</th></tr>
""" + "\n".join(rows) + "\n</table></body></html>\n"


def write_output(path: str, text: str) -> None:
    """Create missing parent directories and atomically replace the report."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, destination)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "manifests",
        nargs="+",
        help="XML manifest, APK, glob pattern, or '-' for XML on stdin",
    )
    parser.add_argument("--format", choices=("text", "json", "html"), default="text")
    parser.add_argument("--out", help="Write report here; parent directories are created")
    parser.add_argument(
        "--severity",
        choices=("HIGH", "MEDIUM", "LOW", "INFO"),
        help="Show issues at this severity or higher",
    )
    parser.add_argument("--ci-mode", action="store_true", help="JSON output; fail on HIGH issues")
    parser.add_argument("--jobs", type=int, default=min(4, os.cpu_count() or 1))
    args = parser.parse_args()

    if args.jobs < 1:
        parser.error("--jobs must be at least 1")

    inputs = expand_inputs(args.manifests)
    if "-" in inputs and len(inputs) != 1:
        print("error: stdin ('-') must be the only input", file=sys.stderr)
        return 3

    threshold = args.severity or ("HIGH" if args.ci_mode else "INFO")
    output_format = "json" if args.ci_mode else args.format

    try:
        if len(inputs) == 1 or "-" in inputs:
            reports = [analyze(inputs[0])]
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
                reports = list(pool.map(analyze, inputs))

        visible = [filter_issues(report, threshold) for report in reports]
    except (OSError, RuntimeError, etree.XMLSyntaxError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    result: dict[str, Any] = {"reports": visible}
    if args.ci_mode:
        result["generated_at"] = datetime.now(timezone.utc).isoformat()
        result["blocked"] = any(
            issue["severity"] == "HIGH"
            for report in reports
            for issue in report["issues"]
        )

    if output_format == "json":
        text = json.dumps(result, indent=2)
    elif output_format == "html":
        text = render_html(visible)
    else:
        lines: list[str] = []
        for report in visible:
            lines.append(f"{report['file']} ({report['package']})")
            for issue in report["issues"]:
                lines.append(
                    f"[{issue['severity']}] {issue['location']}: {issue['message']}"
                )
            lines.append("")
        text = "\n".join(lines)

    if args.out:
        try:
            write_output(args.out, text)
        except OSError as exc:
            print(f"error writing report: {exc}", file=sys.stderr)
            return 3
    else:
        print(text)

    # Gate on the filtered issues. CI mode defaults to HIGH, so MEDIUM findings
    # are reported but do not block unless --severity is changed.
    selected = [issue for report in visible for issue in report["issues"]]
    if any(issue["severity"] == "HIGH" for issue in selected):
        return 1
    if sum(issue["severity"] == "MEDIUM" for issue in selected) > 3:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
