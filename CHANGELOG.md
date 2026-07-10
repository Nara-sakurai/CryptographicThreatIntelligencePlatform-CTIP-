# Changelog

All notable changes to this project are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Local Flask web dashboard (`app.py`) for YARA-based scanning, bound to
  `127.0.0.1:5000` only.
- Shared, print-free scan core in `src/scanner.py`, used by both the CLI
  and the web UI so detection logic is identical.
- Web UI templates (`templates/base.html`, `index.html`, `results.html`)
  and plain CSS styling (`static/style.css`).
- Safe upload handling: `uploads/` directory, `secure_filename`, 16 MB
  upload cap; uploads are gitignored and never executed or transmitted.
- Lightweight JSON report formatter (`Scanner.build_report` /
  `write_json_report`) writing to `reports/`.
- **Opt-in VirusTotal lookup** in the web UI: sends only the file's SHA256
  hash (never the file), off by default, requires `VIRUSTOTAL_API_KEY`.
- New `--rules` CLI flag to choose a `.yar` file or rules directory.
- Basic tests under `tests/` (no real malware required).
- `SECURITY.md`, `ROADMAP.md`, and this `CHANGELOG.md`.

### Changed
- Web UI now uses a clean upload-only flow (the bundled-sample picker was
  removed) and normalizes the `vt_check` result shape with an `enabled` flag.
- VirusTotal, when enabled in the web UI, queries the hash only. The CLI keeps
  its existing (optional) VirusTotal behavior when an API key is present.

### Changed
- `SignatureScanner` now accepts a single `.yar` file in addition to a
  rules directory, captures YARA tags, and handles missing/invalid rules
  paths gracefully instead of crashing.
- `main.py` delegates detection to the shared `Scanner` core while keeping
  its existing CLI output and report behaviour.
- `.gitignore` now ignores `uploads/` and `reports/` and keeps web UI
  templates tracked.
- `requirements.txt` adds `Flask>=3.0`.
