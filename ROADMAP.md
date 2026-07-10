# Roadmap

This is a living list of realistic, future improvements for TriFusion.
It is intentionally honest: items here are ideas, not promises, and none
are scheduled. Contributions are welcome.

## CLI

- More `--rules` options (multiple rule paths, glob patterns).
- `--json` / `--no-color` output flags for scripting.
- Exit codes that reflect whether a match was found (useful in pipelines).
- Progress reporting for large directory scans.

## Scanning & rules

- Improved YARA rule validation and clearer load-error reporting.
- Better handling of `include` directives instead of stripping them.
- Support for compiled `.yarc` rule sets.
- Per-rule confidence weighting and de-duplication of overlapping rules.

## Reporting

- JSON export from the web UI (download a report for a scan).
- CSV/HTML report presets from the dashboard.
- Sample report examples committed under `reports/examples/` (safe, EICAR-based).

## Web UI

- Optional scan history for the current session (local memory only).
- Drag-and-drop upload with client-side size checks.
- Accessibility and keyboard navigation improvements.

## Safety & quality

- Safer sample handling guidance and a "clear uploads" button.
- More unit tests and a small integration test against EICAR.
- GitHub Actions CI: install deps, run `pytest`, lint.
- Keep the app strictly local; never add network upload/telemetry features.

## Documentation

- A "writing your first YARA rule" beginner guide.
- Architecture overview of the shared scanner core (`src/scanner.py`).
- Examples of reading the JSON report format programmatically.
