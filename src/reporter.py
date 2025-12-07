"""
Report Generator - Creates scan reports in multiple formats
"""
import json
import csv
import html
from datetime import datetime
from pathlib import Path


class ReportGenerator:
    """Generates reports from scan results in JSON, CSV, or HTML format"""
    
    def __init__(self):
        pass
    
    def generate_report(self, scan_results, output_format="json", output_file=None):
        """Generate a report from scan results"""
        if not scan_results:
            raise ValueError("No scan results to generate report from")
        
        # Prepare structured report data
        report = self.prepare_report_data(scan_results)
        
        # Generate based on format
        if output_format.lower() == "json":
            return self.generate_json(report, output_file)
        elif output_format.lower() == "csv":
            return self.generate_csv(report, output_file)
        elif output_format.lower() == "html":
            return self.generate_html(report, output_file)
        else:
            raise ValueError(f"Unsupported format: {output_format}")
    
    def prepare_report_data(self, scan_results):
        """Prepare structured report data from scan results"""
        # Handle single result
        if isinstance(scan_results, dict) and 'filepath' in scan_results:
            scan_results = [scan_results]
        
        report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "scanner": "CTIP v3.0 - Cryptographic Threat Intelligence Platform",
                "total_files_scanned": len(scan_results)
            },
            "summary": {
                "malicious": 0,
                "suspicious": 0,
                "clean": 0,
                "total_signatures": 0,
                "total_vt_hits": 0
            },
            "files": []
        }
        
        # Process each scan result
        for result in scan_results:
            file_report = self.process_scan_result(result)
            report["files"].append(file_report)
            
            # Update summary
            classification = file_report["classification"]
            if classification == "MALICIOUS":
                report["summary"]["malicious"] += 1
            elif classification == "SUSPICIOUS":
                report["summary"]["suspicious"] += 1
            else:
                report["summary"]["clean"] += 1
            
            # Count signatures and VT hits
            report["summary"]["total_signatures"] += file_report["details"].get("signature_analysis", {}).get("match_count", 0)
            report["summary"]["total_vt_hits"] += file_report["details"].get("hash_analysis", {}).get("virustotal_malicious", 0)
        
        return report
    
    def process_scan_result(self, result):
        """Process a single scan result into report format"""
        file_report = {
            "filename": Path(result.get("filepath", "")).name,
            "filepath": result.get("filepath", ""),
            "scan_time": result.get("timestamp", datetime.now().isoformat()),
            "classification": result.get("classification", {}).get("threat_level", "UNKNOWN"),
            "threat_score": result.get("classification", {}).get("score", 0),
            "confidence": result.get("classification", {}).get("confidence", "LOW"),
            "indicators": result.get("classification", {}).get("indicators", []),
            "details": {}
        }
        
        # Add hash analysis details
        if "vt_data" in result:
            vt_check = result["vt_data"].get("vt_check", {})
            file_report["details"]["hash_analysis"] = {
                "sha256": result["vt_data"].get("sha256", ""),
                "md5": result["vt_data"].get("md5", ""),
                "virustotal_malicious": vt_check.get("malicious", 0),
                "virustotal_suspicious": vt_check.get("suspicious", 0),
                "virustotal_total": vt_check.get("total_engines", 0),
                "virustotal_found": vt_check.get("found", False)
            }
        
        # Add signature analysis details
        if "yara_data" in result:
            yara_data = result["yara_data"]
            matches = yara_data.get("matches", [])
            
            file_report["details"]["signature_analysis"] = {
                "matches_found": yara_data.get("found", False),
                "match_count": len(matches),
                "rules_loaded": yara_data.get("loaded_rules", 0),
                "signatures": matches
            }
        
        # Add behavior analysis details
        if "entropy_data" in result:
            entropy_data = result["entropy_data"]
            file_report["details"]["behavior_analysis"] = {
                "entropy": entropy_data.get("entropy", 0),
                "classification": entropy_data.get("classification", "UNKNOWN"),
                "behavior": entropy_data.get("behavior", "UNKNOWN"),
                "is_encrypted": entropy_data.get("is_encrypted", False),
                "unique_bytes": entropy_data.get("unique_bytes", 0)
            }
        
        return file_report
    
    def generate_json(self, report, output_file):
        """Generate JSON report"""
        output_path = Path(output_file) if output_file else Path("ctip_report.json")
        if output_path.suffix.lower() != '.json':
            output_path = output_path.with_suffix('.json')
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
        
        return str(output_path)
    
    def generate_csv(self, report, output_file):
        """Generate CSV report"""
        output_path = Path(output_file) if output_file else Path("ctip_report.csv")
        if output_path.suffix.lower() != '.csv':
            output_path = output_path.with_suffix('.csv')
        
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header
            writer.writerow([
                'Filename', 'Filepath', 'Classification', 'Threat Score',
                'VirusTotal Malicious', 'VirusTotal Suspicious', 
                'YARA Matches', 'High Severity', 'Medium Severity',
                'Entropy', 'Encrypted', 'Indicators'
            ])
            
            # Write data rows
            for file_report in report['files']:
                hash_analysis = file_report['details'].get('hash_analysis', {})
                signature_analysis = file_report['details'].get('signature_analysis', {})
                behavior_analysis = file_report['details'].get('behavior_analysis', {})
                
                # Count signature severities
                high_count = 0
                medium_count = 0
                signatures = signature_analysis.get('signatures', [])
                for sig in signatures:
                    if sig.get('severity') == 'High':
                        high_count += 1
                    elif sig.get('severity') == 'Medium':
                        medium_count += 1
                
                writer.writerow([
                    file_report['filename'],
                    file_report['filepath'],
                    file_report['classification'],
                    file_report['threat_score'],
                    hash_analysis.get('virustotal_malicious', 0),
                    hash_analysis.get('virustotal_suspicious', 0),
                    signature_analysis.get('match_count', 0),
                    high_count,
                    medium_count,
                    behavior_analysis.get('entropy', 'N/A'),
                    'YES' if behavior_analysis.get('is_encrypted') else 'NO',
                    '; '.join(file_report['indicators'])
                ])
        
        return str(output_path)
    
    def generate_html(self, report, output_file):
        """Generate HTML report"""
        output_path = Path(output_file) if output_file else Path("ctip_report.html")
        if output_path.suffix.lower() != '.html':
            output_path = output_path.with_suffix('.html')
        
        html_content = self.create_html_template(report)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(output_path)
    
    def create_html_template(self, report):
        """Create HTML report with nice styling"""
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>CTIP v3.0 Scan Report</title>
    <style>
        body {{ 
            font-family: 'Segoe UI', Arial, sans-serif; 
            margin: 40px; 
            background: #f8f9fa; 
            color: #333;
        }}
        .container {{ 
            background: white; 
            padding: 30px; 
            border-radius: 12px; 
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{ 
            text-align: center; 
            margin-bottom: 30px; 
            border-bottom: 3px solid #4a6fa5; 
            padding-bottom: 20px; 
        }}
        .header h1 {{ 
            color: #2c3e50; 
            margin-bottom: 10px;
            font-size: 2.5em;
        }}
        .header h3 {{ 
            color: #7f8c8d; 
            font-weight: normal;
        }}
        .summary {{ 
            display: flex; 
            justify-content: space-around; 
            margin: 30px 0; 
            flex-wrap: wrap;
            gap: 15px;
        }}
        .summary-box {{ 
            text-align: center; 
            padding: 25px; 
            border-radius: 10px; 
            width: 22%; 
            min-width: 200px;
            transition: transform 0.3s ease;
        }}
        .summary-box:hover {{ 
            transform: translateY(-5px);
        }}
        .malicious-box {{ 
            background: linear-gradient(135deg, #ff6b6b, #ff5252); 
            border: 2px solid #ff4444; 
            color: white;
        }}
        .suspicious-box {{ 
            background: linear-gradient(135deg, #ffd93d, #ffc107); 
            border: 2px solid #ffb300; 
            color: #333;
        }}
        .clean-box {{ 
            background: linear-gradient(135deg, #51cf66, #40c057); 
            border: 2px solid #37b24d; 
            color: white;
        }}
        .total-box {{ 
            background: linear-gradient(135deg, #4d96ff, #339af0); 
            border: 2px solid #228be6; 
            color: white;
        }}
        .summary-number {{ 
            font-size: 2.8em; 
            font-weight: bold; 
            margin: 10px 0; 
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }}
        .file-table {{ 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 30px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        .file-table th {{ 
            background: #4a6fa5; 
            color: white;
            padding: 15px; 
            text-align: left; 
            border-bottom: 3px solid #3a5a80;
            font-weight: 600;
        }}
        .file-table td {{ 
            padding: 12px; 
            border-bottom: 1px solid #e9ecef; 
            vertical-align: top;
        }}
        .malicious-row {{ 
            background: #fff5f5; 
            border-left: 4px solid #ff6b6b;
        }}
        .suspicious-row {{ 
            background: #fff9db; 
            border-left: 4px solid #ffd93d;
        }}
        .clean-row {{ 
            background: #ebfbee; 
            border-left: 4px solid #51cf66;
        }}
        .status {{ 
            padding: 6px 12px; 
            border-radius: 6px; 
            font-weight: bold; 
            font-size: 0.9em;
            display: inline-block;
        }}
        .status-malicious {{ 
            background: #ff6b6b; 
            color: white;
        }}
        .status-suspicious {{ 
            background: #ffd93d; 
            color: #333;
        }}
        .status-clean {{ 
            background: #51cf66; 
            color: white;
        }}
        .details-toggle {{
            cursor: pointer;
            color: #4a6fa5;
            font-size: 0.9em;
            margin-left: 10px;
            text-decoration: underline;
        }}
        .details-toggle:hover {{
            color: #2c4a70;
        }}
        .details-content {{
            display: none;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
            margin-top: 5px;
            font-size: 0.85em;
        }}
        .timestamp {{ 
            color: #7f8c8d; 
            font-size: 0.9em; 
            margin-top: 20px;
            text-align: center;
            border-top: 1px solid #eee;
            padding-top: 20px;
        }}
        @media (max-width: 768px) {{
            .summary-box {{ width: 100%; }}
            body {{ margin: 20px; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 CTIP v3.0 Scan Report</h1>
            <h3>Cryptographic Threat Intelligence Platform</h3>
            <p>Generated: {report['metadata']['generated_at']}</p>
        </div>
        
        <div class="summary">
            <div class="summary-box total-box">
                <div class="summary-number">{report['metadata']['total_files_scanned']}</div>
                <div>Total Files</div>
            </div>
            <div class="summary-box malicious-box">
                <div class="summary-number">{report['summary']['malicious']}</div>
                <div>Malicious</div>
            </div>
            <div class="summary-box suspicious-box">
                <div class="summary-number">{report['summary']['suspicious']}</div>
                <div>Suspicious</div>
            </div>
            <div class="summary-box clean-box">
                <div class="summary-number">{report['summary']['clean']}</div>
                <div>Clean</div>
            </div>
        </div>
        
        <table class="file-table">
            <thead>
                <tr>
                    <th>File</th>
                    <th>Status</th>
                    <th>Threat Score</th>
                    <th>VirusTotal</th>
                    <th>YARA</th>
                    <th>Entropy</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {self.generate_file_rows(report['files'])}
            </tbody>
        </table>
        
        <div class="timestamp">
            Report generated by CTIP v3.0 - Advanced Threat Detection System
        </div>
    </div>
    
    <script>
        function toggleDetails(id) {{
            var element = document.getElementById(id);
            if (element.style.display === "block") {{
                element.style.display = "none";
            }} else {{
                element.style.display = "block";
            }}
        }}
    </script>
</body>
</html>
        """
    
    def generate_file_rows(self, files):
        """Generate HTML table rows for files"""
        rows = ""
        
        for i, file_report in enumerate(files):
            # Determine CSS class and status
            if file_report['classification'] == 'MALICIOUS':
                row_class = 'malicious-row'
                status_class = 'status status-malicious'
                status_text = 'MALICIOUS'
            elif file_report['classification'] == 'SUSPICIOUS':
                row_class = 'suspicious-row'
                status_class = 'status status-suspicious'
                status_text = 'SUSPICIOUS'
            else:
                row_class = 'clean-row'
                status_class = 'status status-clean'
                status_text = 'CLEAN'
            
            # Get details
            hash_analysis = file_report['details'].get('hash_analysis', {})
            signature_analysis = file_report['details'].get('signature_analysis', {})
            behavior_analysis = file_report['details'].get('behavior_analysis', {})
            
            vt_malicious = hash_analysis.get('virustotal_malicious', 0)
            yara_matches = signature_analysis.get('match_count', 0)
            entropy = behavior_analysis.get('entropy', 0)
            
            # Format displays
            vt_display = f"🚨 {vt_malicious}" if vt_malicious > 0 else "✅"
            yara_display = f"🔍 {yara_matches}" if yara_matches > 0 else "✅"
            
            if entropy > 7.5:
                entropy_display = f"🔒 {entropy:.1f}"
            elif entropy > 6.5:
                entropy_display = f"📊 {entropy:.1f}"
            else:
                entropy_display = f"📝 {entropy:.1f}"
            
            # Generate indicators list
            indicators_html = self.format_indicators(file_report['indicators'])
            
            rows += f"""
            <tr class="{row_class}">
                <td>{html.escape(file_report['filename'])}</td>
                <td><span class="{status_class}">{status_text}</span></td>
                <td><strong>{file_report['threat_score']}/1.0</strong></td>
                <td>{vt_display}</td>
                <td>{yara_display}</td>
                <td>{entropy_display}</td>
                <td>
                    <span onclick="toggleDetails('details-{i}')" class="details-toggle">Show Details</span>
                    <div id="details-{i}" class="details-content">
                        <strong>Indicators:</strong><br>
                        {indicators_html}
                    </div>
                </td>
            </tr>
            """
        
        return rows
    
    def format_indicators(self, indicators):
        """Format indicators for HTML display"""
        if not indicators:
            return "No indicators"
        
        html_list = "<ul style='margin:5px 0; padding-left:20px;'>"
        for indicator in indicators[:5]:
            html_list += f"<li style='margin:3px 0;'>{html.escape(indicator)}</li>"
        if len(indicators) > 5:
            html_list += f"<li style='color:#868e96;'>+ {len(indicators)-5} more indicators</li>"
        html_list += "</ul>"
        
        return html_list
