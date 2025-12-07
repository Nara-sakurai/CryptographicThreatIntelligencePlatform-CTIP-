"""
Entropy Detector - Analyzes file randomness to detect encryption
"""
import math
from collections import Counter


class EntropyDetector:
    """Detects encrypted or compressed files using entropy analysis"""
    
    def __init__(self):
        self.sample_size = 8192  # Read first 8KB for analysis
    
    def analyze(self, filepath):
        """Analyze file entropy and determine behavior"""
        try:
            # Read file sample
            with open(filepath, "rb") as f:
                data = f.read(self.sample_size)
            
            file_size = len(data)
            
            # Handle small files
            if file_size < 32:
                return self.analyze_small_file(data)
            
            # Calculate entropy
            entropy = self.calculate_entropy(data)
            
            # Analyze byte distribution
            counter = Counter(data)
            unique_bytes = len(counter)
            total_bytes = len(data)
            
            # Calculate uniformity (how evenly bytes are distributed)
            uniformity = (unique_bytes / min(total_bytes, 256)) * 100
            
            # Interpret what the entropy means
            analysis = self.interpret_entropy(entropy, uniformity, unique_bytes)
            
            return {
                "entropy": round(entropy, 2),
                "classification": analysis["classification"],
                "behavior": analysis["behavior"],
                "unique_bytes": unique_bytes,
                "uniformity": round(uniformity, 1),
                "explanation": analysis["explanation"],
                "is_suspicious": analysis["is_suspicious"],
                "is_encrypted": analysis["is_encrypted"],
                "file_size": file_size
            }
            
        except Exception as e:
            return {"error": f"Analysis failed: {str(e)}"}
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy (measure of randomness)"""
        if len(data) < 16:
            return 0.0
        
        counter = Counter(data)
        total = len(data)
        entropy = 0.0
        
        for count in counter.values():
            probability = count / total
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze_small_file(self, data):
        """Handle very small files separately"""
        if len(data) == 0:
            return {
                "entropy": 0.0,
                "classification": "EMPTY",
                "behavior": "EMPTY_FILE",
                "explanation": "File is empty",
                "is_suspicious": False,
                "is_encrypted": False
            }
        
        entropy = self.calculate_entropy(data)
        
        return {
            "entropy": round(entropy, 2),
            "classification": "SMALL_FILE",
            "behavior": "FILE_TOO_SMALL",
            "explanation": "File too small for reliable entropy analysis",
            "is_suspicious": False,
            "is_encrypted": False,
            "file_size": len(data)
        }
    
    def interpret_entropy(self, entropy, uniformity, unique_bytes):
        """Interpret entropy value and determine file behavior"""
        
        # Low entropy (0-4.0): Plain text, structured data
        if entropy < 4.0:
            return {
                "classification": "LOW",
                "behavior": "TEXT_DATA",
                "explanation": "Low entropy suggests plain text or structured data (documents, code)",
                "is_suspicious": False,
                "is_encrypted": False
            }
        
        # Normal entropy (4.0-6.5): Typical binary files
        elif entropy < 6.5:
            return {
                "classification": "NORMAL", 
                "behavior": "TYPICAL_BINARY",
                "explanation": "Normal entropy for binary files (images, videos, executables)",
                "is_suspicious": False,
                "is_encrypted": False
            }
        
        # High entropy (6.5-7.5): Compressed or packed data
        elif entropy < 7.5:
            if uniformity > 70 and unique_bytes > 200:
                return {
                    "classification": "HIGH",
                    "behavior": "LIKELY_COMPRESSED",
                    "explanation": f"High entropy ({entropy:.1f}) with {uniformity:.0f}% unique bytes suggests compressed data (ZIP, RAR) or packed executables",
                    "is_suspicious": True,
                    "is_encrypted": False
                }
            else:
                return {
                    "classification": "HIGH",
                    "behavior": "COMPRESSED_DATA",
                    "explanation": f"High entropy ({entropy:.1f}) indicates compressed data",
                    "is_suspicious": False,
                    "is_encrypted": False
                }
        
        # Very high entropy (7.5+): Likely encrypted
        else:
            if uniformity > 85 and unique_bytes > 230:
                return {
                    "classification": "VERY_HIGH",
                    "behavior": "LIKELY_ENCRYPTED",
                    "explanation": f"Very high entropy ({entropy:.1f}) with {uniformity:.0f}% unique bytes strongly suggests encryption or ransomware",
                    "is_suspicious": True,
                    "is_encrypted": True
                }
            else:
                return {
                    "classification": "VERY_HIGH",
                    "behavior": "RANDOM_DATA",
                    "explanation": f"Very high entropy ({entropy:.1f}) indicates highly random data",
                    "is_suspicious": True,
                    "is_encrypted": False
                }
