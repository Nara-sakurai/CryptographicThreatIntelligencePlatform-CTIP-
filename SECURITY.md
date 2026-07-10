# Security Policy & Safe Use

TriFusion is a **defensive, educational** tool for local YARA-based file
scanning. It is intended for malware analysts, students, and blue-team
learners working on their own systems with their own test files.

## Defensive use only

This project must be used only for legitimate defensive and educational
purposes such as:

- Learning how YARA signature scanning works.
- Testing detection rules against safe, controlled samples (e.g. EICAR).
- Building defensive detection pipelines on systems you own or are
  explicitly authorized to test.

It must **not** be used to attack, scan, or probe systems, data, or people
you do not own or are not explicitly authorized to assess.

## The local web UI stays local

- The Flask dashboard (`app.py`) binds to **`127.0.0.1` only**. Do not
  change the `host` argument to `0.0.0.0` or otherwise expose it.
- Do not put the dashboard behind a reverse proxy, tunnel, or port forward
  that makes it reachable from the internet or a LAN.
- The app has **no authentication** because it is designed to be a
  single-user, localhost tool. Exposing it removes that assumption.

## VirusTotal lookup is opt-in (hash only)

- The web UI offers an **optional** VirusTotal lookup that is **off by
  default**. It must be explicitly enabled per scan.
- It sends **only the file's SHA256 hash** (a 64-character string) to
  VirusTotal — never the file contents.
- A hash can itself be sensitive: it can reveal that a particular file exists
  in your environment and, for private/proprietary files, effectively discloses
  a fingerprint. **Only enable it for files whose hash you are willing to
  share with a third party.**
- It requires `VIRUSTOTAL_API_KEY` in a local `.env` file. Without a key the
  checkbox is disabled and no network request is made.

## Do not upload real malware to GitHub

- Uploaded samples are saved to the local `uploads/` directory, which is
  **gitignored**. Never commit real malware, live samples, or sensitive
  files.
- Only test files such as the bundled EICAR sample should ever appear in
  this repository.
- If you accidentally stage a sample, remove it from history before pushing.

## Handle suspicious files in an isolated lab

- Work with real (non-EICAR) suspicious files only inside an **isolated VM
  or lab** with no access to production networks or sensitive data.
- TriFusion **reads files to scan them** (hashes, YARA, entropy). It
  **never executes** uploaded files and **never transmits** them anywhere.
  Even so, treat any suspicious file with standard malware-handling
  hygiene.

## Reporting issues safely

When opening an issue, **do not** include:

- Real malware payloads or live samples.
- Secrets, API keys, tokens, or credentials.
- Private client data or internal/sensitive identifiers.
- Live target data, real hostnames, or anything from systems you are not
  authorized to share.

If a security issue is sensitive, prefer describing the reproduction steps
with a minimal, safe example rather than attaching real artifacts.

## Dependencies

Keep dependencies pinned and review third-party packages. See
`requirements.txt`. The scanner relies on `yara-python` for signature
matching; keep it up to date.
