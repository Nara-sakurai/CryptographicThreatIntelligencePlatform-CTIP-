"""
Scanner Core - Shared, print-free orchestration of the detection pipeline.

This module is the single source of truth for "how a file is scanned".
Both the CLI (main.py) and the local web UI (app.py) use this same logic,
so detection behaviour is identical everywhere.

Design notes:
- Pure logic only: no print() calls. Callers (CLI) supply an `on_progress`
  callback to reproduce their terminal output; the web UI passes None.
- Returns plain dicts with the same shape the project already used, so
  the CLI summary/report code keeps working unchanged.
- `include_virustotal` controls whether hash checking may use the network:
    * True  -> CLI behaviour (VirusTotal lookup, only if an API key is set)
    * False -> web behaviour (local SHA256/MD5 only, never any network)

This scanner is defensive only: it reads files to compute hashes, match
YARA signatures, and measure entropy. It never executes uploaded files
and never transmits them anywhere.
"""
import json
from datetime import datetime
from pathlib import Path

from hash_checker import HashChecker
from signature_scanner import SignatureScanner
from entropy_detector import EntropyDetector
from classifier import ThreatClassifier

# Candidate default rules sources, in priority order. The first one that
# exists (and is usable) wins. Users can always override via rules_path.
DEFAULT_RULES_CANDIDATES = [
    "expanded_database_rules.yar",   # bundled 5.5MB rule file (real rules)
    "all-yara-rules-database",       # directory of rule files (may be empty)
]


def detect_default_rules_path():
    """Return the first existing default rules source, or None."""
    for candidate in DEFAULT_RULES_CANDIDATES:
        path = Path(candidate)
        if path.exists():
            return str(path)
    return None


class Scanner:
    """Coordinates hash / signature / entropy detection for a single scan.

    Args:
        rules_path: Path to a .yar file or a rules directory. None = auto-detect.
        include_virustotal: If True, hash checking may call VirusTotal (CLI).
            If False, only local hashes are computed (web UI).
        on_progress: Optional callback(stage, filepath) called before each
            detection stage. Used by the CLI to print progress; ignored by web.
    """

    def __init__(self, rules_path=None, include_virustotal=True, on_progress=None):
        self.include_virustotal = include_virustotal
        self.on_progress = on_progress

        # Resolve the rules path (explicit > auto-detect > none)
        if rules_path:
            self.rules_path = rules_path
        else:
            self.rules_path = detect_default_rules_path()

        # Detectors (SignatureScanner prints its own load status; that's fine)
        self.hash_checker = HashChecker()
        self.signature_scanner = SignatureScanner(self.rules_path or "all-yara-rules-database")
        self.entropy_detector = EntropyDetector()
        self.classifier = ThreatClassifier()

    def _progress(self, stage):
        if self.on_progress:
            self.on_progress(stage)

    def scan_file(self, filepath):
        """Scan a single file. Returns a result dict, or None if missing."""
        if not Path(filepath).exists():
            return None

        # 1) Hashes (local always; VirusTotal only when enabled & key present)
        self._progress("hash")
        if self.include_virustotal:
            vt_data = self.hash_checker.get_file_hashes(filepath)
            # Normalize the vt_check shape so callers always see a consistent
            # structure (with an `enabled` flag), regardless of the code path.
            vt_check = vt_data.get("vt_check", {}) if isinstance(vt_data, dict) else {}
            if isinstance(vt_check, dict):
                vt_check.setdefault("enabled", True)
                vt_data["vt_check"] = vt_check
        else:
            hashes = self.hash_checker.calculate_hashes(filepath)
            vt_data = {
                **hashes,
                "vt_check": {"enabled": False,
                             "message": "VirusTotal lookup is off (local scan only)"},
                "filename": Path(filepath).name,
            }

        # 2) YARA signature scan
        self._progress("signature")
        yara_data = self.signature_scanner.scan(filepath)

        # 3) Entropy / behaviour analysis
        self._progress("entropy")
        entropy_data = self.entropy_detector.analyze(filepath)

        # 4) Combine everything into a final threat assessment
        classification = self.classifier.classify(filepath, vt_data, yara_data, entropy_data)

        return {
            "filepath": filepath,
            "rules_path": self.rules_path,
            "vt_data": vt_data,
            "yara_data": yara_data,
            "entropy_data": entropy_data,
            "classification": classification,
            "timestamp": datetime.now().isoformat(),
        }

    def scan_directory(self, directory_path, recursive=False, file_extensions=None):
        """Scan all files in a directory. Returns a list of result dicts."""
        dir_path = Path(directory_path)

        if not dir_path.exists() or not dir_path.is_dir():
            return []

        files_to_scan = self._collect_files(dir_path, recursive, file_extensions)
        if not files_to_scan:
            return []

        results = []
        for file_path in files_to_scan:
            try:
                result = self.scan_file(str(file_path))
                if result:
                    results.append(result)
            except Exception:
                # Keep scanning the rest of the directory even if one file fails
                continue
        return results

    def _collect_files(self, dir_path, recursive, file_extensions):
        """Collect files from a directory based on criteria"""
        files_to_scan = []
        if recursive:
            if file_extensions:
                for ext in file_extensions:
                    pattern = f"**/*.{ext}" if not ext.startswith('.') else f"**/*{ext}"
                    files_to_scan.extend([f for f in dir_path.glob(pattern) if f.is_file()])
            else:
                files_to_scan = [f for f in dir_path.glob("**/*") if f.is_file()]
        else:
            for file_path in dir_path.iterdir():
                if file_path.is_file():
                    if not file_extensions or file_path.suffix.lower().lstrip('.') in file_extensions:
                        files_to_scan.append(file_path)
        return files_to_scan

    # ------------------------------------------------------------------
    # Lightweight JSON report formatter (used by the web UI & tests)
    # ------------------------------------------------------------------
    @staticmethod
    def build_report(result):
        """Turn a scan result dict into a small, JSON-serializable report."""
        if not result:
            return {"error": "No scan result to report"}

        classification = result.get("classification", {}) or {}
        yara_data = result.get("yara_data", {}) or {}
        entropy_data = result.get("entropy_data", {}) or {}
        matches = yara_data.get("matches", []) if isinstance(yara_data, dict) else []

        errors = []
        if isinstance(yara_data, dict) and yara_data.get("error"):
            errors.append(f"Signature scan: {yara_data['error']}")
        if isinstance(entropy_data, dict) and entropy_data.get("error"):
            errors.append(f"Entropy analysis: {entropy_data['error']}")

        return {
            "scanned_file": Path(result.get("filepath", "")).name,
            "rule_file_path": result.get("rules_path"),
            "scan_time": result.get("timestamp", datetime.now().isoformat()),
            "classification": classification.get("threat_level", "UNKNOWN"),
            "threat_score": classification.get("score", 0),
            "matches": [
                {
                    "rule": m.get("rule", "Unknown"),
                    "description": m.get("description", ""),
                    "severity": m.get("severity", "Unknown"),
                    "tags": m.get("tags", []),
                    "source": m.get("source", "unknown"),
                    "meta": m.get("meta", {}),
                }
                for m in matches
            ],
            "errors": errors,
        }

    @staticmethod
    def write_json_report(report, out_path):
        """Write a report dict to a JSON file. Returns the output path."""
        out = Path(out_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        return str(out)
