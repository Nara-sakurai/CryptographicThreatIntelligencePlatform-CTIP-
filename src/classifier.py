"""
Threat Classifier - Combines all detection results into final threat assessment
"""
from pathlib import Path


class ThreatClassifier:
    """Analyzes all detection results and determines final threat level"""
    
    def __init__(self):
        # Detection weights (how much each finding contributes to threat score)
        self.weights = {
            "vt_malicious": 0.8,       # VirusTotal says it's malware
            "vt_suspicious": 0.4,      # VirusTotal is suspicious
            "yara_high_match": 0.7,    # High severity YARA rule matched
            "yara_medium_match": 0.5,  # Medium severity YARA rule matched
            "high_entropy": 0.6,       # Very high entropy (encryption)
            "suspicious_ext": 0.3,     # Suspicious file extension
        }
        
        # Suspicious file extensions (ransomware, encrypted files)
        self.suspicious_exts = [
            ".encrypted", ".locked", ".crypted", ".zepto", ".odin", 
            ".locky", ".ransom", ".crypt", ".enc", ".lockbit", 
            ".blackcat", ".cerber", ".wannacry"
        ]
    
    def classify(self, filepath, vt_data, yara_data, entropy_data):
        """Combine all detection results into final classification"""
        score = 0.0
        indicators = []
        
        # Check VirusTotal results
        score, indicators = self.check_virustotal(vt_data, score, indicators)
        
        # Check YARA signature matches
        score, indicators = self.check_signatures(yara_data, score, indicators)
        
        # Check entropy/behavior analysis
        score, indicators = self.check_entropy(entropy_data, score, indicators)
        
        # Check file properties
        score, indicators = self.check_file_properties(filepath, score, indicators)
        
        # Cap score at 1.0
        score = min(score, 1.0)
        
        # Determine final threat level
        if score >= 0.7:
            threat_level = "MALICIOUS"
            color = "red"
        elif score >= 0.4:
            threat_level = "SUSPICIOUS"
            color = "yellow"
        else:
            threat_level = "CLEAN"
            color = "green"
        
        # Determine confidence based on number of indicators
        if len(indicators) >= 3:
            confidence = "HIGH"
        elif len(indicators) >= 1:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"
        
        return {
            "threat_level": threat_level,
            "score": round(score, 2),
            "confidence": confidence,
            "indicators": indicators,
            "indicator_count": len(indicators),
            "color": color
        }
    
    def check_virustotal(self, vt_data, score, indicators):
        """Check VirusTotal results"""
        if not vt_data or "vt_check" not in vt_data:
            return score, indicators
        
        vt_result = vt_data["vt_check"]
        
        if vt_result.get("malicious", 0) > 0:
            malicious_count = vt_result["malicious"]
            score += self.weights["vt_malicious"]
            indicators.append(f"VirusTotal: {malicious_count} engines detected as malicious")
        
        elif vt_result.get("suspicious", 0) > 0:
            suspicious_count = vt_result["suspicious"]
            score += self.weights["vt_suspicious"]
            indicators.append(f"VirusTotal: {suspicious_count} engines flagged as suspicious")
        
        return score, indicators
    
    def check_signatures(self, yara_data, score, indicators):
        """Check YARA signature matches"""
        if not yara_data or not yara_data.get("found"):
            return score, indicators
        
        matches = yara_data.get("matches", [])
        
        # Count by severity
        high_matches = [m for m in matches if m.get("severity") == "High"]
        medium_matches = [m for m in matches if m.get("severity") == "Medium"]
        
        # High severity matches
        if high_matches:
            score += self.weights["yara_high_match"]
            high_rule_names = [m.get("rule", "Unknown") for m in high_matches[:3]]
            indicators.append(
                f"Signature: {len(high_matches)} high severity rule(s): {', '.join(high_rule_names)}"
            )
        
        # Medium severity matches
        if medium_matches:
            medium_score = self.weights["yara_medium_match"] * min(len(medium_matches), 3) / 3
            score += medium_score
            indicators.append(f"Signature: {len(medium_matches)} medium severity rule(s) matched")
        
        return score, indicators
    
    def check_entropy(self, entropy_data, score, indicators):
        """Check entropy analysis results"""
        if not entropy_data or entropy_data.get("error"):
            return score, indicators
        
        entropy = entropy_data.get("entropy", 0)
        is_encrypted = entropy_data.get("is_encrypted", False)
        behavior = entropy_data.get("behavior", "")
        
        # Check for encryption
        if is_encrypted or "ENCRYPTED" in behavior:
            score += self.weights["high_entropy"]
            indicators.append(
                f"Behavior: High entropy ({entropy:.2f}) - possible encryption detected"
            )
        
        # Check for very high entropy
        elif entropy > 7.0:
            score += self.weights["high_entropy"] * 0.5
            indicators.append(f"Behavior: Very high entropy ({entropy:.2f}) - suspicious")
        
        return score, indicators
    
    def check_file_properties(self, filepath, score, indicators):
        """Check suspicious file properties"""
        filename = Path(filepath).name.lower()
        
        # Check suspicious extensions
        if any(filename.endswith(ext) for ext in self.suspicious_exts):
            score += self.weights["suspicious_ext"]
            indicators.append("File properties: Suspicious file extension")
        
        # Check double extensions (e.g., .pdf.exe)
        parts = filename.split('.')
        if len(parts) > 2:
            last_ext = parts[-1]
            if last_ext in ['exe', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'scr']:
                score += 0.2
                indicators.append(
                    f"File properties: Double extension detected (.{parts[-2]}.{last_ext})"
                )
        
        return score, indicators
