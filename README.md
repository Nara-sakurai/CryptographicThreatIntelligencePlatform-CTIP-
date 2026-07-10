

#  TriFusion – Local YARA Malware Detection (CLI + Web Dashboard)

## Project Overview

**TriFusion** is a defensive, educational malware detection helper that combines **YARA signature scanning**, **entropy analysis**, and (in the CLI) optional **hash verification** to assess files for malicious characteristics. It runs entirely on your own machine.

It offers two ways to use the same scanning logic:

- **CLI** (`main.py`) — the original command-line workflow, unchanged.
- **Local web dashboard** (`app.py`) — a small Flask UI on `http://127.0.0.1:5000` for beginners.

> This is a **defensive** tool. It never executes files, never transmits them
> anywhere, and the web UI is bound to `127.0.0.1` only. See [SECURITY.md](SECURITY.md).

---

## 🎯 Features

* **Multi-Method Detection** – YARA signature scanning, entropy analysis, and (CLI) optional VirusTotal hash lookup.
* **Two interfaces, one engine** – CLI (`main.py`) and a local web dashboard (`app.py`) share the same scan core (`src/scanner.py`).
* **Local web dashboard** – Upload or pick a sample, choose a YARA rules path, and view results in a clean table (rule, tags, metadata, status). Runs on `127.0.0.1` only.
* **Extensive YARA Rules** – Bundled rule database for accurate detection.
* **Entropy Analysis** – Detects encrypted, compressed, or highly random files.
* **Beautiful Terminal Interface** – Color-coded, emoji-enhanced output.
* **Flexible Reporting** – Export results in JSON, CSV, or interactive HTML (CLI); the web UI also writes small JSON reports to `reports/`.
* **Batch & Recursive Scanning** – Scan files, directories, or entire systems.
* **Threat Scoring** – Intelligent scoring system (0.0–1.0) to classify threats as CLEAN, SUSPICIOUS, or MALICIOUS.

---

## 📋 Prerequisites

* Python 3.8 or higher
* Internet connection (for VirusTotal API, optional but recommended)
* 50MB free disk space (for YARA rules)

---

## 🔧 Installation & Setup

### Step 1: Clone the Repository

```bash
git clone https://github.com/Nara-sakurai/TriThreatFusion.git
cd TriThreatFusion
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

Dependencies include:

* `yara-python>=4.3.1` – YARA signature scanning
* `Flask>=3.0` – Local web dashboard (127.0.0.1 only)
* `rich>=13.7.0` – Beautiful terminal output
* `python-dotenv>=1.0.0` – Environment variable management
* `requests>=2.31.0` – VirusTotal API communication (CLI, optional)

### Step 3: Setup VirusTotal API (Optional, CLI only)

1. Get a free API key from [VirusTotal](https://www.virustotal.com).
2. Create a `.env` file in the project root:

```
VIRUSTOTAL_API_KEY=your_api_key_here
```

> Without an API key, hash checking will be disabled, but signature and entropy analysis will still work. **The web UI never uses VirusTotal regardless.**

### Step 4: Verify Installation

```bash
python main.py --scan samples/eicar.com
```

### Step 5: Run the Web Dashboard (Optional)

```bash
python app.py
```

Then open **http://127.0.0.1:5000**.

---

## 📖 Usage Guide

### Scan a Single File

```bash
python main.py --scan <filepath>
```

Example:

```bash
python main.py --scan samples/eicar.com
```

### Scan a Directory

```bash
python main.py --dir <directory>
```

Example:

```bash
python main.py --dir samples/
```

### Recursive Directory Scan

```bash
python main.py --dir <directory> --recursive
```

### Scan Specific File Types

```bash
python main.py --dir <directory> --ext exe,dll,bin,txt
```

### Generate Reports

* JSON:

```bash
python main.py --dir samples/ --report results.json --format json
```

* CSV:

```bash
python main.py --dir samples/ --report results.csv --format csv
```

* HTML:

```bash
python main.py --dir samples/ --report report.html --format html
```

---

## 🖥️ Web UI (Local Dashboard)

A beginner-friendly Flask dashboard that runs **only on your machine**.

### Start it

```bash
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

### What it does

1. Upload a sample file (max 16 MB).
2. Choose a YARA rules path (auto-detected by default).
3. Optionally enable **VirusTotal lookup** (off by default) — see below.
4. Click **Scan** — the file is scanned locally (YARA signatures, entropy, hashes).
5. View results in a clean table: matched rule name, severity, tags, metadata, and status.
6. A small JSON report is written to `reports/`.

### VirusTotal lookup (optional, off by default)

A checkbox lets you look up the file's **SHA256 hash** on VirusTotal to see how
many antivirus engines flag it.

* **Off by default.** This is deliberate: turning it on shares the file's hash
  with a third party. Enable it only for files whose hash you are willing to
  share (e.g. known test samples like EICAR).
* **Hash only, never the file.** VirusTotal receives a 64-character hash
  string — your file bytes are never uploaded anywhere.
* **Requires an API key.** Set `VIRUSTOTAL_API_KEY` in a local `.env` file
  (copy `.env.example`). Without a key, the checkbox is disabled and the scan
  runs with local hashing only.

### Safety

* The app binds to `127.0.0.1` only — never expose it to the internet.
* Uploaded files are **never executed** and **never transmitted** anywhere.
* Uploads are stored in `uploads/` (gitignored) and never committed.
* VirusTotal, when explicitly enabled, queries only the file's SHA256 hash.
* Handle real suspicious files only in an isolated VM/lab. See [SECURITY.md](SECURITY.md).

---

## 🔬 Detection Methods

### 1. Hash-Based Detection

* Algorithms: SHA256 & MD5
* Purpose: Identify known malware using cryptographic fingerprints
* API: VirusTotal v3 (70+ engines)

### 2. Signature-Based Detection

* Engine: YARA v4.3.1
* Rules: 446+ compiled malware signatures
* Purpose: Detect known malware, ransomware, trojans, and exploits

### 3. Entropy Analysis

* Algorithm: Shannon Entropy
* Range: 0.0 – 8.0 bits per byte
* Purpose: Detect encrypted, compressed, or random data patterns

---

## 📊 Threat Scoring System

| Indicator                       | Weight |
| ------------------------------- | ------ |
| VirusTotal Malicious Detection  | 0.8    |
| VirusTotal Suspicious Detection | 0.4    |
| YARA High Severity Match        | 0.7    |
| YARA Medium Severity Match      | 0.5    |
| High Entropy Detection          | 0.6    |
| Suspicious File Extension       | 0.3    |

**Threat Levels:**

* CLEAN (0.0 – 0.39)
* SUSPICIOUS (0.4 – 0.69)
* MALICIOUS (0.7 – 1.0)

---

## 🧪 Testing

* **EICAR Test Virus:**

```bash
python main.py --scan samples/eicar.com
```

Expected: MALICIOUS (Score: 1.0/1.0)

* **Clean File:**

```bash
python main.py --scan samples/clean/hello.py
```

Expected: CLEAN (Score: 0.0/1.0)

* **Encrypted File:**

```bash
python main.py --scan samples/encrypted_large.bin
```

Expected: MALICIOUS or SUSPICIOUS (High entropy detected)

---

## 🚀 Roadmap

The full list of realistic future improvements lives in [ROADMAP.md](ROADMAP.md). Highlights:

* Better CLI options (`--rules`, JSON export, meaningful exit codes)
* Improved YARA rule validation and clearer error reporting
* Tests and GitHub Actions CI
* Safer sample handling and documentation improvements
* Sample report examples

---

## 📁 Project Structure

```
TriFusion/
├── main.py                  # CLI entry point (unchanged workflow)
├── app.py                   # Local Flask web dashboard (127.0.0.1 only)
├── requirements.txt         # Dependencies (yara-python, Flask, rich, ...)
├── expanded_database_rules.yar   # Bundled YARA rule database
├── all-yara-rules-database/      # (Optional) directory of rule files
├── src/
│   ├── scanner.py           # Shared, print-free scan core (CLI + web)
│   ├── signature_scanner.py # YARA signature scanning
│   ├── hash_checker.py      # Local hashes + optional VirusTotal (CLI)
│   ├── entropy_detector.py  # Shannon entropy / behaviour analysis
│   ├── classifier.py        # Combines signals into a threat score
│   ├── display.py           # Rich terminal output (CLI)
│   └── reporter.py          # JSON / CSV / HTML report generation (CLI)
├── templates/               # Web UI templates (base, index, results)
├── static/style.css         # Web UI styling (plain CSS)
├── uploads/                 # Uploaded samples (gitignored, never committed)
├── reports/                 # Generated JSON reports (gitignored)
├── samples/                 # Bundled test samples (EICAR + clean files)
├── outputs/                 # Legacy report output directory
├── tests/                   # Basic scanner + report tests
├── SECURITY.md              # Defensive-use and safe-handling policy
├── ROADMAP.md               # Future improvements
└── CHANGELOG.md             # Versioned change history
```

---

## ⚠️ Limitations

* YARA detection is only as good as its rules — a clean result does **not** guarantee a file is safe.
* Entropy analysis is heuristic; compressed/encrypted files may look similar.
* The web UI performs **no VirusTotal lookups** (local hashes only) by design.
* The bundled rule file may reference external `include` directives that are stripped at load time.
* This tool does not run, unpack, or reverse files — it inspects bytes statically.

---

## 🔒 Security Practices

* Defensive, educational use only (see [SECURITY.md](SECURITY.md)).
* The web UI binds to `127.0.0.1` and is never exposed to the internet.
* API keys stored in `.env` (gitignored).
* Files are **never executed**; only read for hashes/YARA/entropy.
* Uploaded files are **never transmitted** anywhere.
* Chunk-based file reading and YARA scan timeouts.
* Graceful error handling for missing rules or samples.

---

## 🙏 Acknowledgments

* YARA Project – Pattern matching engine
* VirusTotal – Malware detection API
* Rich Library – Beautiful terminal output
* Open Source Community – YARA rule contributions


