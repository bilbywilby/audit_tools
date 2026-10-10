# Audit Tools Operations

Run from the repository root.

## Environment Setup

One-time system prerequisite:
```bash
sudo apt install python3.13-venv
```

Per-environment setup (use when environment is broken or after cleanup):
```bash
cd ~/audit_tools
deactivate 2>/dev/null || true
rm -rf .venv
/usr/bin/python3 -m venv .venv
source .venv/bin/activate
pip install lxml pytest
```

## Verify Environment

```bash
which python3          # Should show .venv in path
python3 -c "import lxml; print(lxml.__version__)"  # Should print version
```

## Scan and Report

Default output:
```bash
bin/audit_manifest path/to/AndroidManifest.xml
```

With explicit format and output file:
```bash
bin/audit_manifest app.xml --format text --out artifacts/report.txt
bin/audit_manifest app.xml --format html --out artifacts/report.html
bin/audit_manifest app.xml --format json --out artifacts/report.json
```

**Verified**: Uses `--format {text,json,html}` (NO `--html`/`--json` shorthands);
`--out` creates parent directories automatically.

## View Reports

```bash
w3m -T text/html -dump artifacts/report.html
cat artifacts/report.txt
```

## Scan an APK

Use Android SDK `apkanalyzer` to decode the binary manifest:
```bash
apkanalyzer manifest print your_app.apk | bin/audit_manifest - --format text --out artifacts/audit_report.txt
```

## Run Tests

```bash
python3 -m pytest tests/ -v
```

Last verified: 2 passed (Python 3.13.5, lxml 6.1.3, pytest 9.1.1)

## CLI Options Reference

| Option | Description |
|--------|-------------|
| `--format {text,json,html}` | Output format (required for file output) |
| `--out FILE` | Write report to FILE; creates parent dirs |
| `--severity {HIGH,MEDIUM,LOW,INFO}` | Filter by minimum severity |
| `--ci-mode` | Force JSON output, exit on HIGH issues |
| `--jobs N` | Parallel worker count |
| `-` | Read XML from stdin |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No selected issue triggers a gate |
| 1 | At least one HIGH issue |
| 2 | More than 3 MEDIUM issues, no HIGH |
| 3 | Input/parsing/report-writing error |
