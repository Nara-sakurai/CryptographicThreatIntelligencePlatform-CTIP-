#!/usr/bin/env python3
"""
TriFusion - Local Web Dashboard for YARA-based file scanning.

A small, beginner-friendly Flask UI for the defensive scanning logic that
also powers the CLI (src/scanner.py). It runs ONLY on localhost.

Safety contract (enforced by design):
  * Binds to 127.0.0.1 only - never exposed to the network/internet.
  * Uploaded files are read for scanning (hashes, YARA, entropy) and are
    NEVER executed, NEVER parsed as code, and NEVER sent anywhere.
  * VirusTotal, when explicitly enabled by the user, queries only the file's
    SHA256 hash (a 64-character string), never the file contents. It is
    OFF by default to avoid accidentally sharing hashes of sensitive files.
  * No telemetry of any kind.

Run:
    python app.py
Then open:
    http://127.0.0.1:5000
"""
import os
import sys
from pathlib import Path
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename

# Make the shared detection modules importable (same trick as main.py)
sys.path.insert(0, str(Path(__file__).parent / "src"))
from scanner import Scanner, detect_default_rules_path  # noqa: E402

app = Flask(__name__)


@app.template_filter("basename")
def _basename_filter(path):
    """Return the file name portion of a path (used in results.html)."""
    return os.path.basename(str(path)) if path else ""


# Secret key for flash messages only. Local, single-user, no sensitive data.
app.config["SECRET_KEY"] = "local-only-not-for-production-use"
# Cap uploads at 16 MB to keep the local scanner snappy and avoid accidental
# huge-file uploads.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"
UPLOAD_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

# Cache of scanners keyed by (rules_path, include_virustotal). Building a
# scanner compiles the YARA rules once, so we reuse instances where possible.
_scanners = {}


def get_scanner(rules_path, include_virustotal):
    """Return a (cached) Scanner bound to the chosen rules path and VT mode."""
    key = (rules_path, include_virustotal)
    if key not in _scanners:
        _scanners[key] = Scanner(
            rules_path=rules_path, include_virustotal=include_virustotal
        )
    return _scanners[key]


def vt_available():
    """True only if a VirusTotal API key is configured (in .env)."""
    return bool(os.getenv("VIRUSTOTAL_API_KEY"))


@app.route("/")
def index():
    """Home page: choose rules + upload a sample."""
    return render_template(
        "index.html",
        default_rules=detect_default_rules_path(),
        vt_available=vt_available(),
    )


@app.route("/scan", methods=["POST"])
def scan():
    """Run a local scan and render results (or a safe error)."""
    rules_path = (request.form.get("rules_path") or "").strip() or detect_default_rules_path()
    use_vt = request.form.get("use_virustotal") == "on"

    # --- Validate the rules path -------------------------------------------------
    rules_error = None
    if not rules_path:
        rules_error = (
            "No YARA rules path was found. Add a .yar file or rules directory, "
            "then enter its path above. See the README for details."
        )
    elif not Path(rules_path).exists():
        rules_error = f"YARA rules path not found: {rules_path}"
    if rules_error:
        return _render_scan_error(rules_error, rules_path, use_vt)

    # VirusTotal needs an API key; downgrade gracefully (don't error).
    if use_vt and not vt_available():
        use_vt = False
        flash(
            "VirusTotal lookup requested but no VIRUSTOTAL_API_KEY is set. "
            "The scan ran with local hashing only."
        )

    # --- Resolve the uploaded file to scan --------------------------------------
    sample_path = None
    uploaded_name = None

    upload = request.files.get("sample_file")
    if upload and upload.filename:
        filename = secure_filename(upload.filename)
        if not filename:
            return _render_scan_error(
                "The uploaded file name is not valid. Rename it and try again.",
                rules_path,
                use_vt,
            )
        save_to = UPLOAD_DIR / filename
        upload.save(save_to)
        sample_path = str(save_to)
        uploaded_name = filename

    if not sample_path:
        return _render_scan_error(
            "No file provided. Please choose a file to scan.",
            rules_path,
            use_vt,
        )

    # --- Run the scan -----------------------------------------------------------
    try:
        scn = get_scanner(rules_path, include_virustotal=use_vt)
        result = scn.scan_file(sample_path)
    except Exception as exc:  # never leak a raw stack trace to the user
        return _render_scan_error(
            f"Scan failed unexpectedly: {str(exc)[:160]}", rules_path, use_vt
        )

    if not result:
        return _render_scan_error(
            f"Could not read the sample file: {uploaded_name}", rules_path, use_vt
        )

    # Show whether the rules actually loaded (e.g. invalid ruleset)
    sig = scn.signature_scanner
    if sig.rules is None and getattr(sig, "load_error", None):
        # Surface the rules-load failure but still show what we could compute.
        flash(f"YARA rules did not load: {sig.load_error}")

    # Optionally save a small JSON report alongside the result view.
    report = None
    try:
        report = Scanner.build_report(result)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = secure_filename(uploaded_name or "sample") or "sample"
        out_path = REPORT_DIR / f"scan_{safe_name}_{stamp}.json"
        Scanner.write_json_report(report, out_path)
    except Exception:
        # Reporting is best-effort; the scan itself still succeeded.
        report = None

    return render_template(
        "results.html",
        result=result,
        uploaded_name=uploaded_name,
        rules_path=rules_path,
        use_virustotal=use_vt,
        report_path=report.get("scanned_file") if report else None,
    )


def _render_scan_error(message, rules_path, use_vt):
    """Render the results page in an error state."""
    flash(message)
    return render_template(
        "results.html",
        result=None,
        error=True,
        rules_path=rules_path,
        use_virustotal=use_vt,
    )


if __name__ == "__main__":
    # CRITICAL: 127.0.0.1 only - do not change to 0.0.0.0. See SECURITY.md.
    print("=" * 60)
    print("  TriFusion local dashboard")
    print("  Binding to 127.0.0.1:5000 (LOCALHOST ONLY)")
    print("  Do NOT expose this app to the internet. See SECURITY.md.")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=False)
