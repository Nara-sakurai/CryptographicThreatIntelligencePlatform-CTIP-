"""
Basic tests for the shared scanner core and report formatting.

These tests do NOT require real malware. They use the bundled clean sample
and the EICAR test file that already ship with the project.

Tests that need yara-python are guarded with importorskip, so the reporter-
formatting tests still run in environments where yara isn't installed.
"""
import json
import os
import sys
from pathlib import Path

import pytest

# Make src/ importable when running `pytest` from the project root.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from scanner import Scanner  # noqa: E402

CLEAN_SAMPLE = ROOT / "samples" / "clean" / "hello.py"
EICAR_SAMPLE = ROOT / "samples" / "eicar.com"
DEFAULT_RULES = ROOT / "expanded_database_rules.yar"


# ----------------------------------------------------------------------------
# Report formatting (no yara needed)
# ----------------------------------------------------------------------------
class TestBuildReport:
    def test_build_report_basic_shape(self):
        """build_report produces the documented top-level keys."""
        fake_result = {
            "filepath": "/tmp/sample.bin",
            "rules_path": "rules.yar",
            "timestamp": "2024-01-01T00:00:00",
            "vt_data": {"sha256": "abc", "md5": "def"},
            "yara_data": {"found": False, "matches": [], "loaded_rules": 0},
            "entropy_data": {"entropy": 2.0, "behavior": "TEXT_DATA"},
            "classification": {"threat_level": "CLEAN", "score": 0.0, "confidence": "LOW"},
        }
        report = Scanner.build_report(fake_result)
        assert report["scanned_file"] == "sample.bin"
        assert report["rule_file_path"] == "rules.yar"
        assert report["scan_time"] == "2024-01-01T00:00:00"
        assert report["classification"] == "CLEAN"
        assert report["matches"] == []
        assert report["errors"] == []

    def test_build_report_collects_errors(self):
        """Errors from yara/entropy stages are surfaced in the report."""
        result = {
            "filepath": "x",
            "rules_path": None,
            "yara_data": {"error": "no rules loaded"},
            "entropy_data": {"error": "read failed"},
            "classification": {},
        }
        report = Scanner.build_report(result)
        assert any("Signature scan" in e for e in report["errors"])
        assert any("Entropy analysis" in e for e in report["errors"])

    def test_build_report_empty_input(self):
        report = Scanner.build_report(None)
        assert "error" in report

    def test_write_json_report_roundtrip(self, tmp_path):
        report = {
            "scanned_file": "demo.bin",
            "rule_file_path": "rules.yar",
            "scan_time": "t",
            "matches": [],
            "errors": [],
        }
        out = Scanner.write_json_report(report, tmp_path / "out" / "report.json")
        assert os.path.exists(out)
        with open(out) as f:
            loaded = json.load(f)
        assert loaded["scanned_file"] == "demo.bin"
        assert loaded["matches"] == []


# ----------------------------------------------------------------------------
# Scanner behaviour (needs yara-python)
# ----------------------------------------------------------------------------
class TestScanner:
    yara = pytest.importorskip("yara")  # skip this whole class if yara missing

    def test_scan_missing_file_returns_none(self):
        """A non-existent sample path yields None, not an exception."""
        scn = Scanner(rules_path=None, include_virustotal=False)
        assert scn.scan_file(str(ROOT / "does_not_exist_xyz")) is None

    def test_scan_missing_rules_path_is_graceful(self):
        """A missing rules path must not crash; the scanner still runs."""
        scn = Scanner(rules_path=str(ROOT / "no_such_rules_dir"), include_virustotal=False)
        # SignatureScanner should report an error instead of raising.
        assert scn.signature_scanner.rules is None
        assert scn.scan_file(str(CLEAN_SAMPLE)) is not None  # scan still completes

    def test_scan_clean_file_is_structured(self):
        """Scanning a clean sample returns the expected result shape."""
        scn = Scanner(rules_path=None, include_virustotal=False)
        result = scn.scan_file(str(CLEAN_SAMPLE))
        assert result is not None
        for key in ("filepath", "rules_path", "vt_data", "yara_data",
                    "entropy_data", "classification", "timestamp"):
            assert key in result
        cls = result["classification"]
        assert cls["threat_level"] in {"CLEAN", "SUSPICIOUS", "MALICIOUS"}
        assert 0.0 <= cls["score"] <= 1.0
        # Local-only mode: no VirusTotal lookup attempted
        assert result["vt_data"]["vt_check"]["enabled"] is False

    def test_scan_with_virustotal_enabled_is_safe_without_key(self, monkeypatch):
        """Even with VT enabled, a missing API key must not crash the scan.

        The scan should complete and report vt_check with enabled=True and a
        clear error message, rather than raising or doing a network call.
        """
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        scn = Scanner(rules_path=None, include_virustotal=True)
        result = scn.scan_file(str(CLEAN_SAMPLE))
        assert result is not None
        vtc = result["vt_data"]["vt_check"]
        assert vtc.get("enabled") is True          # requested & normalized
        assert vtc.get("found") is False           # no key -> nothing found
        assert "error" in vtc or "message" in vtc  # safe degradation message
