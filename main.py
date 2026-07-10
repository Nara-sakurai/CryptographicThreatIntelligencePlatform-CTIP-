#!/usr/bin/env python3
"""
TriThreatFusion – Multi-Layer Malware Detection Platform
Simple and clean malware scanner
"""
import argparse
import sys
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from scanner import Scanner
from display import Display
from reporter import ReportGenerator


class CTIP:
    """Main scanner class that coordinates all detection methods.

    Detection logic lives in the shared Scanner core (src/scanner.py);
    this class keeps the CLI's familiar output and reporting behaviour
    on top of that same logic.
    """

    def __init__(self, rules_path=None):
        # Shared, print-free scan core. The progress callback reproduces the
        # CLI's original stage-by-stage output, in the original order.
        self.scanner = Scanner(
            rules_path=rules_path,
            include_virustotal=True,
            on_progress=self._print_stage,
        )
        self.display = Display()
        self.reporter = ReportGenerator()

    def _print_stage(self, stage):
        """Reproduce the original CLI progress lines for each scan stage."""
        if stage == "hash":
            print("  1️⃣  Checking hash with VirusTotal...")
        elif stage == "signature":
            print("  2️⃣  Scanning for malware signatures...")
        elif stage == "entropy":
            print("  3️⃣  Analyzing file behavior (entropy)...")
    
    def scan_file(self, filepath):
        """Scan a single file using all detection methods"""
        if not Path(filepath).exists():
            print(f"❌ File not found: {filepath}")
            return None

        print(f"\n{'='*60}")
        print(f"🔍 Scanning: {filepath}")
        print(f"{'='*60}")

        # Delegate the detection pipeline to the shared Scanner core.
        # The on_progress callback prints the original 1️⃣/2️⃣/3️⃣ stage lines.
        result = self.scanner.scan_file(filepath)
        if not result:
            return None

        # Display results nicely (CLI-only concern)
        self.display.show(
            filepath,
            result.get("vt_data"),
            result.get("yara_data"),
            result.get("entropy_data"),
            result.get("classification"),
        )
        return result
    
    def scan_directory(self, directory_path, recursive=False, file_extensions=None):
        """Scan all files in a directory"""
        dir_path = Path(directory_path)
        
        if not dir_path.exists():
            print(f"❌ Directory not found: {directory_path}")
            return []
        
        if not dir_path.is_dir():
            print(f"❌ Not a directory: {directory_path}")
            return []
        
        print(f"\n{'='*60}")
        print(f"📁 Scanning directory: {directory_path}")
        print(f"{'='*60}")
        
        # Collect files to scan
        files_to_scan = self._collect_files(dir_path, recursive, file_extensions)
        
        if not files_to_scan:
            print("📭 No files found to scan")
            return []
        
        print(f"📊 Found {len(files_to_scan)} file(s) to scan\n")
        
        # Scan each file
        results = []
        for i, file_path in enumerate(files_to_scan, 1):
            print(f"📄 [{i}/{len(files_to_scan)}] Processing: {file_path.name}")
            
            try:
                result = self.scan_file(str(file_path))
                if result:
                    results.append(result)
            except Exception as e:
                print(f"❌ Error scanning {file_path.name}: {str(e)[:100]}")
        
        return results
    
    def _collect_files(self, dir_path, recursive, file_extensions):
        """Collect files from directory based on criteria"""
        files_to_scan = []
        
        if recursive:
            # Scan all subdirectories
            if file_extensions:
                for ext in file_extensions:
                    pattern = f"**/*.{ext}" if not ext.startswith('.') else f"**/*{ext}"
                    files_to_scan.extend([f for f in dir_path.glob(pattern) if f.is_file()])
            else:
                files_to_scan = [f for f in dir_path.glob("**/*") if f.is_file()]
        else:
            # Scan only current directory
            for file_path in dir_path.iterdir():
                if file_path.is_file():
                    if not file_extensions or file_path.suffix.lower().lstrip('.') in file_extensions:
                        files_to_scan.append(file_path)
        
        return files_to_scan


def main():
    parser = argparse.ArgumentParser(
        description="CTIP v3.0 - Malware Scanner with VirusTotal, YARA, and Entropy Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Scan a single file:
    python main.py --scan samples/eicar.com
  
  Scan a directory:
    python main.py --dir samples/
  
  Scan directory recursively:
    python main.py --dir samples/ --recursive
  
  Scan with specific file types:
    python main.py --dir samples/ --ext exe,bin,txt
  
  Generate reports:
    python main.py --dir samples/ --report results.json --format json
    python main.py --dir samples/ --report results.csv --format csv
    python main.py --dir samples/ --report report.html --format html
        """
    )
    
    # Scan options
    parser.add_argument("--scan", help="Scan a single file")
    parser.add_argument("--dir", "--directory", help="Scan a directory")
    parser.add_argument("--recursive", "-r", action="store_true", help="Scan directory recursively")
    parser.add_argument("--ext", "--extensions", help="File extensions to scan (comma-separated)")
    parser.add_argument("--rules", help="Path to YARA rules file (.yar) or directory (default: auto-detected)")
    
    # Report options
    parser.add_argument("--report", help="Generate report file")
    parser.add_argument("--format", choices=["csv", "html", "json"], help="Report format")
    
    args = parser.parse_args()
    
    # Validate arguments
    if not (args.scan or args.dir):
        print("❌ Error: You must specify either --scan or --dir")
        parser.print_help()
        return 1
    
    if args.report and not args.format:
        print("❌ Error: --format is required when using --report")
        parser.print_help()
        return 1
    
    # Initialize scanner
    ctip = CTIP(rules_path=args.rules)
    results = []
    
    # Run scans
    if args.scan:
        result = ctip.scan_file(args.scan)
        if result:
            results.append(result)
    elif args.dir:
        extensions = None
        if args.ext:
            extensions = [ext.strip().lower().lstrip('.') for ext in args.ext.split(',')]
        results = ctip.scan_directory(args.dir, recursive=args.recursive, file_extensions=extensions)
    
    # Generate report if requested
    if args.report and results and args.format:
        print(f"\n📄 Generating {args.format.upper()} report: {args.report}")
        try:
            report_path = ctip.reporter.generate_report(results, args.format, args.report)
            print(f"✅ Report saved to: {report_path}")
        except Exception as e:
            print(f"❌ Error generating report: {e}")
    
    # Show summary
    if results:
        print(f"\n{'='*60}")
        print("📊 SCAN SUMMARY")
        print(f"{'='*60}")
        
        malicious = sum(1 for r in results if r.get("classification", {}).get("threat_level") == "MALICIOUS")
        suspicious = sum(1 for r in results if r.get("classification", {}).get("threat_level") == "SUSPICIOUS")
        clean = sum(1 for r in results if r.get("classification", {}).get("threat_level") == "CLEAN")
        
        print(f"📄 Files scanned: {len(results)}")
        print(f"🚨 Malicious: {malicious}")
        print(f"⚠️  Suspicious: {suspicious}")
        print(f"✅ Clean: {clean}")
        
        # Show details for small scans
        if len(results) <= 5:
            print(f"\n📋 Detailed Results:")
            for result in results:
                filename = Path(result.get("filepath", "")).name
                classification = result.get("classification", {}).get("threat_level", "UNKNOWN")
                score = result.get("classification", {}).get("score", 0)
                
                if classification == "MALICIOUS":
                    status = "🚨 MALICIOUS"
                elif classification == "SUSPICIOUS":
                    status = "⚠️  SUSPICIOUS"
                else:
                    status = "✅ CLEAN"
                
                print(f"  • {filename}: {status} (Score: {score}/1.0)")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
