"""
Signature Scanner - Scans files using YARA malware signatures
"""
import os
import yara
from pathlib import Path
import re


class SignatureScanner:
    """Scans files for malware signatures using YARA rules"""
    
    def __init__(self, rules_path="all-yara-rules-database"):
        # rules_path may be a single .yar file OR a directory of rules.
        self.rules_dir = Path(rules_path) if str(rules_path).endswith((".yar", ".yara")) else Path(rules_path)
        self.rules_source = Path(rules_path)
        self.rules = None
        self.rule_sources = {}  # Maps rule names to their source files
        self.loaded_file_count = 0
        self.load_error = None  # human-readable reason when rules can't load
        
        print("🔍 Loading YARA malware signatures...")
        self.load_rules()

    def load_rules(self):
        """Load YARA rules from a single file or a directory database"""
        source = self.rules_source

        # Gracefully handle a missing rules path instead of crashing.
        if not source.exists():
            self.load_error = f"Rules path not found: {source}"
            print(f"❌ {self.load_error}")
            return

        # Single-file mode: compile one .yar / .yara bundle directly.
        if source.is_file():
            if source.suffix.lower() not in (".yar", ".yara"):
                self.load_error = f"Not a YARA file (.yar/.yara): {source}"
                print(f"❌ {self.load_error}")
                return
            self.load_single_file(source)
            return

        # Directory mode (original behavior): discover and compile usable files.
        all_files = list(source.rglob("*.yar"))

        if not all_files:
            self.load_error = f"No .yar files found in directory: {source}"
            print(f"❌ {self.load_error}")
            return
        
        print(f"  Found {len(all_files)} .yar files in database")
        
        # Test each file and keep working ones
        working_files = []
        
        for yar_file in all_files:
            try:
                with open(yar_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Skip problematic files
                if 'sync' in content or 'is__elf' in content:
                    continue
                
                # Try to compile
                try:
                    yara.compile(source=content)
                    working_files.append(yar_file)
                except:
                    continue
                    
            except Exception:
                continue
        
        print(f"  ✓ Usable files: {len(working_files)}")
        
        if not working_files:
            print("❌ No working YARA files found")
            return
        
        # Compile all working files
        self.compile_rules(working_files)
    
    def compile_rules(self, working_files):
        """Compile all working YARA files"""
        print(f"  Compiling {len(working_files)} files...")
        
        rules_dict = {}
        self.rule_sources = {}
        
        for i, yar_file in enumerate(working_files):
            try:
                with open(yar_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Remove include statements (they cause issues)
                lines = content.split('\n')
                clean_lines = [line for line in lines if not line.strip().startswith('include "')]
                clean_content = '\n'.join(clean_lines)
                
                # Create namespace for this file
                rel_path = str(yar_file.relative_to(self.rules_dir))
                namespace = f"db_{i:04d}_{Path(rel_path).stem}"
                rules_dict[namespace] = clean_content
                
                # Track which rules came from which file
                rule_names = self.extract_rule_names(clean_content)
                for rule_name in rule_names:
                    full_rule_name = f"{namespace}.{rule_name}"
                    self.rule_sources[full_rule_name] = {
                        "file": rel_path,
                        "category": rel_path.split('/')[0] if '/' in rel_path else "root"
                    }
                    
            except Exception:
                continue
        
        if not rules_dict:
            print("❌ Could not process any files")
            return
        
        try:
            self.rules = yara.compile(sources=rules_dict)
            self.loaded_file_count = len(rules_dict)
            print(f"✅ Loaded {self.loaded_file_count} YARA rule files")
            
        except yara.Error as e:
            self.load_error = f"YARA compilation failed: {str(e)[:120]}"
            print(f"❌ {self.load_error}")

    def load_single_file(self, yar_file):
        """Compile a single .yar / .yara file into one or more namespaces.

        Many bundled rule files are concatenations of originally separate
        ``.yar`` files delimited by ``// Included from:`` / ``// End include:``
        markers. Some of those units reference optional YARA modules (e.g.
        ``cuckoo``) that are not compiled into this yara-python build, which
        would make the *entire* bundle fail to compile. To stay robust we
        compile each delimited unit independently and keep the ones that work,
        mirroring how the directory loader already tolerates bad files.
        """
        try:
            content = yar_file.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            self.load_error = f"Could not read rules file: {e}"
            print(f"❌ {self.load_error}")
            return

        units = self._split_bundle_units(content)
        print(f"  Found {len(units)} rule unit(s) in {yar_file.name}")

        rules_dict = {}
        self.rule_sources = {}
        kept = 0
        skipped = 0

        for i, (label, body) in enumerate(units):
            body = self._strip_includes(body)
            if not body.strip():
                continue
            namespace = f"{Path(yar_file).stem}_{i:04d}_{Path(label).stem}"
            try:
                yara.compile(source=body)
            except Exception:
                # Skip units that need modules we don't have or contain errors.
                skipped += 1
                continue
            rules_dict[namespace] = body
            kept += 1
            for rule_name in self.extract_rule_names(body):
                self.rule_sources[f"{namespace}.{rule_name}"] = {
                    "file": yar_file.name,
                    "category": Path(label).parts[0] if Path(label).parts else "bundle",
                }

        if not rules_dict:
            self.load_error = f"No compilable rule units in {yar_file.name}"
            print(f"❌ {self.load_error}")
            return

        try:
            self.rules = yara.compile(sources=rules_dict)
        except yara.Error as e:
            self.load_error = f"YARA compilation failed: {str(e)[:120]}"
            print(f"❌ {self.load_error}")
            return

        self.loaded_file_count = kept
        print(f"  ✓ Usable units: {kept} (skipped {skipped})")
        print(f"✅ Loaded YARA rules from {yar_file.name}")

    @staticmethod
    def _strip_includes(text):
        """Remove ``include "..."`` directives that reference external files."""
        lines = [ln for ln in text.split('\n') if not ln.strip().startswith('include "')]
        return '\n'.join(lines)

    def _split_bundle_units(self, content):
        """Split a concatenated bundle into (label, body) units.

        A bundle is a series of sections introduced by lines like::

            // Included from: include "./malware/MALW_AZORULT.yar"
            ... rules ...
            // End include: include "./malware/MALW_AZORULT.yar"

        If no markers are present the whole file is returned as one unit.
        """
        units = []
        current_label = "root"
        buffer = []

        for line in content.split('\n'):
            stripped = line.strip()
            if stripped.startswith('// Included from:'):
                # Flush any preceding content as a unit before starting a new one
                if buffer and '\n'.join(buffer).strip():
                    units.append((current_label, '\n'.join(buffer)))
                buffer = []
                # Extract a label like "./malware/MALW_AZORULT.yar"
                marker = stripped.replace('// Included from:', '').strip()
                current_label = marker.replace('include', '').strip().strip('"')
            else:
                buffer.append(line)

        if buffer and '\n'.join(buffer).strip():
            units.append((current_label, '\n'.join(buffer)))

        return units
    
    def extract_rule_names(self, content):
        """Extract rule names from YARA content"""
        rule_names = []
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if line.startswith('rule '):
                # Extract: rule RuleName {
                match = re.match(r'rule\s+(\w+)\s*{', line)
                if match:
                    rule_names.append(match.group(1))
        
        return rule_names
    
    def scan(self, filepath):
        """Scan a file for malware signatures"""
        if not self.rules:
            return {"error": "No YARA rules loaded"}
        
        try:
            # Run YARA scan
            matches = self.rules.match(filepath, timeout=60)
            
            if matches:
                # Process matches
                results = []
                for match in matches:
                    full_rule_name = str(match)
                    rule_name = full_rule_name.split('.')[-1] if '.' in full_rule_name else full_rule_name
                    
                    # Get source information
                    source_info = self.rule_sources.get(full_rule_name, {
                        "file": "unknown",
                        "category": "unknown"
                    })
                    
                    # Get metadata
                    meta_info = {}
                    if hasattr(match, 'meta') and match.meta:
                        meta_info = dict(match.meta)

                    # Get tags (may be absent on some matches)
                    tags = []
                    if hasattr(match, 'tags') and match.tags:
                        tags = list(match.tags)

                    # Determine severity
                    severity = self.determine_severity(rule_name, meta_info)
                    
                    results.append({
                        "rule": rule_name,
                        "description": meta_info.get('description', rule_name),
                        "severity": meta_info.get('severity', severity),
                        "source": source_info["category"],
                        "tags": tags,
                        "meta": meta_info
                    })
                
                return {
                    "matches": results,
                    "found": True,
                    "count": len(matches),
                    "loaded_rules": self.loaded_file_count
                }
            else:
                return {
                    "found": False,
                    "loaded_rules": self.loaded_file_count
                }
                
        except Exception as e:
            return {"error": str(e)}
    
    def determine_severity(self, rule_name, meta_info):
        """Determine rule severity based on name and metadata"""
        rule_lower = rule_name.lower()
        
        # High severity indicators
        high_indicators = ['eicar', 'malware', 'trojan', 'virus', 'ransomware', 'backdoor']
        if any(indicator in rule_lower for indicator in high_indicators):
            return "High"
        
        # Medium severity indicators
        medium_indicators = ['suspicious', 'exploit', 'packed', 'obfuscated']
        if any(indicator in rule_lower for indicator in medium_indicators):
            return "Medium"
        
        # Default
        return "Medium"
