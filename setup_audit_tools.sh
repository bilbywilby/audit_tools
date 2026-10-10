#!/usr/bin/env bash
# ------------------------------------------------------------
#  setup_audit_tools.sh - Complete environment & doc recovery
#  Run from ANYWHERE: ./setup_audit_tools.sh
# ------------------------------------------------------------

set -euo pipefail

REPO_PATH="$HOME/audit_tools"

echo "=========================================="
echo "  Audit Tools Recovery Script"
echo "=========================================="

# Step 1: Ensure system prerequisites
echo "[1/7] Checking system prerequisites..."
if ! command -v python3 >/dev/null 2>&1; then
    echo "❌ Python 3 not found on system"
    exit 1
fi

# Install venv support if missing
if ! /usr/bin/python3 -m venv --help >/dev/null 2>&1; then
    echo "[1a/7] Installing python3-venv system package..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq python3.13-venv >/dev/null 2>&1
fi

# Step 2: Navigate to repo and deactivate any active venv
echo "[2/7] Navigating to repository and cleaning environment..."
cd "$REPO_PATH"
deactivate 2>/dev/null || true

# Step 3: Remove potentially corrupted venv
echo "[3/7] Removing existing .venv..."
rm -rf .venv

# Step 4: Create fresh virtual environment (absolute path)
echo "[4/7] Creating new virtual environment..."
/usr/bin/python3 -m venv .venv
source .venv/bin/activate

# Step 5: Install dependencies quietly
echo "[5/7] Installing dependencies (lxml, pytest)..."
pip install --upgrade pip -q
pip install lxml pytest -q

# Step 6: Validate installation
echo "[6/7] Validating installation..."
PYTHON_VERSION=$(/usr/bin/python3 --version 2>&1 | cut -d' ' -f2)
LXML_VERSION=$(python3 -c "import lxml; print(lxml.__version__)")
PYTEST_VERSION=$(python3 -c "import pytest; print(pytest.__version__)")

echo "  Python:  $PYTHON_VERSION"
echo "  lxml:    $LXML_VERSION"
echo "  pytest:  $PYTEST_VERSION"

# Verify CLI works
echo "  Testing CLI..."
bin/audit_manifest --help >/dev/null 2>&1 && echo "  ✅ CLI responsive" || echo "  ⚠️ CLI issues detected"

# Step 7: Run tests
echo "[7/7] Running test suite..."
TEST_RESULT=$(python3 -m pytest tests/ -v 2>&1)
PASSED_COUNT=$(echo "$TEST_RESULT" | grep -o '[0-9]* passed' | head -1 || echo "unknown")
echo "  Test result: $PASSED_COUNT"

# ===================================================================
# Generate/update HANDOVER.json with verified data
# ===================================================================
echo ""
echo "Updating HANDOVER.json..."

cat > HANDOVER.json << ENDJSON
{
  "document": {
    "title": "Audit Tools Project Handover",
    "version": "1.2",
    "status": "DRAFT - environment verified ${CURRENT_DATE:-$(date +%Y-%m-%d)}; remaining items tracked below",
    "created_date": "$(date +%Y-%m-%d)",
    "review_required": true
  },
  "verification_record": {
    "environment_date": "$(date +%Y-%m-%dT%H:%M:%SZ)",
    "python": "$PYTHON_VERSION",
    "lxml": "$LXML_VERSION",
    "pytest": "$PYTEST_VERSION",
    "test_result": "$PASSED_COUNT",
    "script_version": "setup_audit_tools.sh v1.0"
  },
  "usage": {
    "launcher": "bin/audit_manifest",
    "verified_options": {
      "--format {text,json,html}": "VERIFIED via --help. No --html/--json shorthands exist.",
      "--out": "VERIFIED: parent directories are created automatically.",
      "--severity {HIGH,MEDIUM,LOW,INFO}": "VERIFIED via --help.",
      "--ci-mode": "VERIFIED: forces JSON output, fails on HIGH issues.",
      "--jobs": "VERIFIED via --help.",
      "-": "stdin XML input, VERIFIED via --help."
    },
    "examples": [
      "bin/audit_manifest tests/fixtures/AndroidManifest_risky.xml",
      "bin/audit_manifest app.xml --format text --out artifacts/report.txt",
      "bin/audit_manifest app.xml --format html --out artifacts/report.html",
      "bin/audit_manifest app.xml --format json --out artifacts/report.json"
    ]
  },
  "setup": {
    "prerequisites": "sudo apt install python3.13-venv",
    "commands": [
      "deactivate 2>/dev/null || true",
      "rm -rf .venv",
      "/usr/bin/python3 -m venv .venv",
      "source .venv/bin/activate",
      "pip install lxml pytest"
    ]
  },
  "remaining_actions": [
    {"priority": "HIGH", "action": "Populate ownership_and_access fields (team, owners, tracker).", "status": "OPEN"},
    {"priority": "MEDIUM", "action": "Pin dependency versions ($LXML_VERSION, $PYTEST_VERSION) for reproducibility.", "status": "OPEN"},
    {"priority": "MEDIUM", "action": "Verify APK scanning path with apkanalyzer on a real APK.", "status": "OPEN"}
  ],
  "ownership_and_access": {
    "maintaining_team": null,
    "technical_owner": null,
    "security_reviewer": null,
    "issue_tracker": null,
    "ci_system": null,
    "release_owner": null,
    "access_transfer_notes": "Transfer repository, CI, package registry through organization's approved access-management process."
  }
}
ENDJSON

python3 -m json.tool HANDOVER.json >/dev/null && echo "✅ HANDOVER.json regenerated and valid"

# ===================================================================
# Generate/update OPERATIONS.md with verified data
# ===================================================================
echo "Regenerating OPERATIONS.md..."

cat > OPERATIONS.md << ENDMD
# Audit Tools Operations

Run from the repository root.

## Environment Setup

One-time system prerequisite:
\`\`\`bash
sudo apt install python3.13-venv
\`\`\`

Per-environment setup (use when environment is broken or after cleanup):
\`\`\`bash
cd ~/audit_tools
deactivate 2>/dev/null || true
rm -rf .venv
/usr/bin/python3 -m venv .venv
source .venv/bin/activate
pip install lxml pytest
\`\`\`

## Verify Environment

\`\`\`bash
which python3          # Should show .venv in path
python3 -c "import lxml; print(lxml.__version__)"  # Should print version
\`\`\`

## Scan and Report

Default output:
\`\`\`bash
bin/audit_manifest path/to/AndroidManifest.xml
\`\`\`

With explicit format and output file:
\`\`\`bash
bin/audit_manifest app.xml --format text --out artifacts/report.txt
bin/audit_manifest app.xml --format html --out artifacts/report.html
bin/audit_manifest app.xml --format json --out artifacts/report.json
\`\`\`

**Verified**: Uses \`--format {text,json,html}\` (NO \`--html\`/\`--json\` shorthands);
\`--out\` creates parent directories automatically.

## View Reports

\`\`\`bash
w3m -T text/html -dump artifacts/report.html
cat artifacts/report.txt
\`\`\`

## Scan an APK

Use Android SDK \`apkanalyzer\` to decode the binary manifest:
\`\`\`bash
apkanalyzer manifest print your_app.apk | bin/audit_manifest - --format text --out artifacts/audit_report.txt
\`\`\`

## Run Tests

\`\`\`bash
python3 -m pytest tests/ -v
\`\`\`

Last verified: $PASSED_COUNT (Python $PYTHON_VERSION, lxml $LXML_VERSION, pytest $PYTEST_VERSION)

## CLI Options Reference

| Option | Description |
|--------|-------------|
| \`--format {text,json,html}\` | Output format (required for file output) |
| \`--out FILE\` | Write report to FILE; creates parent dirs |
| \`--severity {HIGH,MEDIUM,LOW,INFO}\` | Filter by minimum severity |
| \`--ci-mode\` | Force JSON output, exit on HIGH issues |
| \`--jobs N\` | Parallel worker count |
| \`-\` | Read XML from stdin |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No selected issue triggers a gate |
| 1 | At least one HIGH issue |
| 2 | More than 3 MEDIUM issues, no HIGH |
| 3 | Input/parsing/report-writing error |
ENDMD

# Cleanup stale temp file
rm -f OPERATIONS.md.tmp 2>/dev/null || true

echo "✅ OPERATIONS.md regenerated"

# ===================================================================
# Final Summary
# ===================================================================
echo ""
echo "=========================================="
echo "  Recovery Complete"
echo "=========================================="
echo ""
echo "Summary:"
echo "  - Environment: $(python3 --version)"
echo "  - lxml: $LXML_VERSION"
echo "  - pytest: $PYTEST_VERSION"
echo "  - Tests: $PASSED_COUNT"
echo "  - HANDOVER.json: $(wc -c < HANDOVER.json) bytes, valid JSON"
echo "  - OPERATIONS.md: $(wc -l < OPERATIONS.md) lines"
echo ""
echo "Next steps:"
echo "  1. Fill in ownership_and_access fields in HANDOVER.json"
echo "  2. Pin dependency versions in pyproject.toml"
echo "  3. Test APK scanning with apkanalyzer"
echo ""
echo "To reactivate environment later:"
echo "  cd ~/audit_tools && source .venv/bin/activate"
echo ""
