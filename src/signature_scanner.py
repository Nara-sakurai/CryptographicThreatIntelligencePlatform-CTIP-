"""
Signature Scanner - Scans files using YARA malware signatures
"""
import os
import yara
from pathlib import Path
import re


class SignatureScanner:
    """Scans files for malware signatures using YARA rules"""
    
    def __init__(self, rules_dir="all-yara-rules-database"):
        self.rules_dir = Path(rules_dir)
        self.rules = None
        self.rule_sources = {}  # Maps rule names to their source files
        self.loaded_file_count = 0
        
        print("🔍 Loading YARA malware signatures...")
        self.load_rules()
    
    def load_rules(self):
        """Load YARA rules from database"""
        # Find all YARA files
        all_files = list(self.rules_dir.rglob("*.yar"))
        
        if not all_files:
            print("❌ No YARA files found in database")
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
            print(f"❌ Compilation failed: {str(e)[:80]}")
    
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
                    
                    # Determine severity
                    severity = self.determine_severity(rule_name, meta_info)
                    
                    results.append({
                        "rule": rule_name,
                        "description": meta_info.get('description', rule_name),
                        "severity": meta_info.get('severity', severity),
                        "source": source_info["category"],
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
