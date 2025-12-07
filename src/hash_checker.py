"""
Hash Checker - Calculates file hashes and checks VirusTotal
"""
import os
import hashlib
import requests
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()


class HashChecker:
    """Checks file hashes against VirusTotal database"""
    
    def __init__(self):
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3"
        self.session = requests.Session()
        
        if self.api_key:
            self.session.headers.update({"x-apikey": self.api_key})
    
    def calculate_hashes(self, filepath):
        """Calculate SHA256 and MD5 hashes for a file"""
        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()
        
        try:
            with open(filepath, "rb") as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(65536), b""):
                    sha256_hash.update(chunk)
                    md5_hash.update(chunk)
            
            return {
                "sha256": sha256_hash.hexdigest(),
                "md5": md5_hash.hexdigest()
            }
        except Exception as e:
            return {"error": f"Hash calculation failed: {e}"}
    
    def check_virustotal(self, file_hash):
        """Check if hash is known to VirusTotal"""
        if not self.api_key:
            return {
                "error": "No VirusTotal API key. Add VIRUSTOTAL_API_KEY to .env file",
                "found": False
            }
        
        try:
            response = self.session.get(
                f"{self.base_url}/files/{file_hash}",
                timeout=15
            )
            
            if response.status_code == 200:
                # File found in VirusTotal
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                
                return {
                    "found": True,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "harmless": stats.get("harmless", 0),
                    "timeout": stats.get("timeout", 0),
                    "total_engines": sum(stats.values())
                }
            
            elif response.status_code == 404:
                # File not in database
                return {
                    "found": False,
                    "message": "Hash not found in VirusTotal database"
                }
            
            else:
                # API error
                return {
                    "error": f"VirusTotal API error: {response.status_code}",
                    "found": False
                }
                
        except requests.exceptions.RequestException as e:
            return {"error": f"Network error: {e}", "found": False}
        except Exception as e:
            return {"error": str(e), "found": False}
    
    def get_file_hashes(self, filepath):
        """Calculate hashes and check VirusTotal (main method)"""
        # Calculate hashes
        hashes = self.calculate_hashes(filepath)
        
        if "error" in hashes:
            return hashes
        
        # Check VirusTotal
        vt_result = self.check_virustotal(hashes["sha256"])
        
        # Return combined results
        return {
            **hashes,
            "vt_check": vt_result,
            "filename": Path(filepath).name
        }
