from pathlib import Path
import sys
sys.path.insert(0, 'src')
from audit_manifest import parse_manifest, triage

FIXTURES = Path(__file__).parent / "fixtures"

def test_safe_has_no_highs():
    root = parse_manifest(FIXTURES / "AndroidManifest_safe.xml")
    issues = triage(root)
    assert not any(sev == "HIGH" for sev, _, _ in issues)

def test_risky_flags_issues():
    root = parse_manifest(FIXTURES / "AndroidManifest_risky.xml")
    issues = triage(root)
    severities = [sev for sev, _, _ in issues]
    assert "HIGH" in severities
    assert "MEDIUM" in severities
