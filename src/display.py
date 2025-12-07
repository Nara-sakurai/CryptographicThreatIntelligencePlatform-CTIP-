"""
Display Module - Shows scan results in a clean, readable format
"""
import os
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table


class Display:
    """Handles displaying scan results nicely formatted"""
    
    def __init__(self):
        self.console = Console()
    
    def show(self, filepath, vt_data, yara_data, entropy_data, classification):
        """Display complete scan results"""
        filename = os.path.basename(filepath)
        
        # Header
        self.show_header()
        
        # File information
        self.show_file_info(filepath, filename)
        
        # Detection results
        self.show_hash_results(vt_data)
        self.show_signature_results(yara_data)
        self.show_entropy_results(entropy_data)
        
        # Final assessment
        self.show_threat_assessment(classification)
        
        # Footer
        self.show_footer()
    
    def show_header(self):
        """Display header"""
        self.console.print("\n" + "="*70)
        self.console.print("[bold cyan]🔐 CTIP - Cryptographic Threat Intelligence Platform[/bold cyan]")
        self.console.print("[dim]Advanced Malware Detection System[/dim]")
        self.console.print("="*70)
    
    def show_file_info(self, filepath, filename):
        """Display file information"""
        self.console.print(f"\n📁 [bold]File:[/bold] {filename}")
        
        size = os.path.getsize(filepath)
        if size >= 1024:
            size_str = f"{size/1024:.1f} KB"
        else:
            size_str = f"{size} bytes"
        
        self.console.print(f"   [dim]Size: {size_str}[/dim]")
    
    def show_hash_results(self, vt_data):
        """Display VirusTotal hash check results"""
        self.console.print(f"\n[bold cyan]1. 🔑 VirusTotal Hash Check[/bold cyan]")
        
        if not vt_data or "error" in vt_data:
            self.console.print("   [dim]VirusTotal check unavailable[/dim]")
            return
        
        vt_check = vt_data.get("vt_check", {})
        
        if vt_check.get("found"):
            malicious = vt_check.get("malicious", 0)
            total = vt_check.get("total_engines", 0)
            
            if malicious > 0:
                self.console.print(f"   🚨 [bold red]{malicious}/{total} engines detected malware[/bold red]")
            else:
                self.console.print(f"   ✅ [green]Clean ({total} engines checked)[/green]")
        else:
            self.console.print(f"   [dim]File not found in VirusTotal database[/dim]")
    
    def show_signature_results(self, yara_data):
        """Display YARA signature scan results"""
        self.console.print(f"\n[bold cyan]2. 🔍 Malware Signature Detection[/bold cyan]")
        
        if not yara_data or "error" in yara_data:
            self.console.print("   [dim]Signature scan unavailable[/dim]")
            return
        
        if yara_data.get("loaded_rules"):
            self.console.print(f"   [dim]Database: {yara_data['loaded_rules']} rules loaded[/dim]")
        
        if yara_data.get("found"):
            matches = yara_data.get("matches", [])
            self.console.print(f"   🎯 Found {len(matches)} signature match(es)")
            
            # Show high severity matches first
            high_matches = [m for m in matches if m.get("severity") == "High"]
            if high_matches:
                self.console.print(f"\n   [bold red]⚠️  HIGH SEVERITY ({len(high_matches)})[/bold red]")
                for match in high_matches:
                    self.show_signature_match(match)
            
            # Show medium severity matches
            medium_matches = [m for m in matches if m.get("severity") == "Medium"]
            if medium_matches:
                self.console.print(f"\n   [bold yellow]MEDIUM SEVERITY ({len(medium_matches)})[/bold yellow]")
                for match in medium_matches[:2]:
                    self.show_signature_match(match)
                if len(medium_matches) > 2:
                    self.console.print(f"   [dim]+ {len(medium_matches)-2} more medium severity matches[/dim]")
        else:
            self.console.print("   ✅ [green]No malicious signatures detected[/green]")
    
    def show_signature_match(self, match):
        """Display individual signature match details"""
        rule = match.get("rule", "Unknown")
        desc = match.get("description", "")
        source = match.get("source", "unknown")
        
        # Color based on severity
        if match.get("severity") == "High":
            rule_display = f"[bold red]{rule}[/bold red]"
        else:
            rule_display = f"[bold yellow]{rule}[/bold yellow]"
        
        self.console.print(f"   • {rule_display}")
        
        # Show description
        if desc and desc != rule and len(desc) < 80:
            self.console.print(f"     [dim]{desc}[/dim]")
        
        # Show source
        if source != "unknown":
            self.console.print(f"     [dim]Source: {source}[/dim]")
    
    def show_entropy_results(self, entropy_data):
        """Display entropy analysis results"""
        self.console.print(f"\n[bold cyan]3. 📊 File Behavior Analysis (Entropy)[/bold cyan]")
        
        if not entropy_data or "error" in entropy_data:
            self.console.print("   [dim]Entropy analysis unavailable[/dim]")
            return
        
        entropy = entropy_data.get("entropy", 0)
        behavior = entropy_data.get("behavior", "")
        explanation = entropy_data.get("explanation", "")
        
        # Color based on entropy level
        if entropy < 4.0:
            color = "green"
        elif entropy < 6.5:
            color = "yellow"
        elif entropy < 7.5:
            color = "red"
        else:
            color = "bold red"
        
        self.console.print(f"   Entropy: [{color}]{entropy:.2f} bits[/{color}]")
        
        # Show behavior classification
        if "ENCRYPTED" in behavior:
            self.console.print(f"   🔒 [bold red]{behavior}[/bold red]")
        elif "COMPRESSED" in behavior:
            self.console.print(f"   📦 [yellow]{behavior}[/yellow]")
        elif "TEXT" in behavior:
            self.console.print(f"   📝 [green]{behavior}[/green]")
        else:
            self.console.print(f"   📊 {behavior}")
        
        # Show explanation
        if explanation:
            self.console.print(f"   [dim]{explanation}[/dim]")
    
    def show_threat_assessment(self, classification):
        """Display final threat assessment"""
        self.console.print(f"\n[bold cyan]4. 🎯 Final Threat Assessment[/bold cyan]")
        
        threat = classification["threat_level"]
        score = classification["score"]
        indicators = classification.get("indicators", [])
        confidence = classification.get("confidence", "LOW")
        
        # Show threat level panel
        if threat == "MALICIOUS":
            self.console.print(Panel(
                f"[bold red]🚨 MALICIOUS FILE DETECTED[/bold red]\n"
                f"Threat Score: {score}/1.0 | Confidence: {confidence}\n"
                f"Multiple detection methods confirm this file is malicious",
                border_style="red"
            ))
        elif threat == "SUSPICIOUS":
            self.console.print(Panel(
                f"[bold yellow]⚠️  SUSPICIOUS FILE[/bold yellow]\n"
                f"Threat Score: {score}/1.0 | Confidence: {confidence}\n"
                f"Some indicators of suspicious activity detected",
                border_style="yellow"
            ))
        else:
            self.console.print(Panel(
                f"[bold green]✅ CLEAN FILE[/bold green]\n"
                f"Threat Score: {score}/1.0 | Confidence: {confidence}\n"
                f"No significant threats detected",
                border_style="green"
            ))
        
        # Show detection indicators
        if indicators:
            self.console.print(f"\n   [bold]Detection Indicators:[/bold]")
            for indicator in indicators:
                if "VirusTotal" in indicator:
                    self.console.print(f"   🔑 {indicator}")
                elif "Signature" in indicator:
                    self.console.print(f"   🔍 {indicator}")
                elif "Behavior" in indicator:
                    self.console.print(f"   📊 {indicator}")
                elif "File properties" in indicator:
                    self.console.print(f"   📄 {indicator}")
                else:
                    self.console.print(f"   • {indicator}")
    
    def show_footer(self):
        """Display footer"""
        self.console.print("\n" + "="*70)
        self.console.print("[dim]CTIP v3.0 - Advanced Threat Detection[/dim]")
        self.console.print("="*70)
