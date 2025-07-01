# xss_scanner/report/reporter_fixed.py
"""Fixed report generation with proper template handling."""

import csv
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import html

logger = logging.getLogger(__name__)


class Reporter(ABC):
    """Abstract base class for report generators."""
    
    @abstractmethod
    def generate(self, scan_results: Dict, output_path: Path) -> bool:
        """Generate report from scan results."""
        pass


class HTMLReporter(Reporter):
    """Generate HTML reports with syntax highlighting."""
    
    def generate(self, scan_results: Dict, output_path: Path) -> bool:
        """Generate HTML report."""
        try:
            html_content = self._generate_html(scan_results)
            
            output_file = output_path / 'xss_scan_report.html'
            output_file.write_text(html_content, encoding='utf-8')
            
            logger.info(f"HTML report generated: {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")
            return False
    
    def _generate_html(self, scan_results: Dict) -> str:
        """Generate HTML content."""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        summary = scan_results.get('summary', {})
        scan_info = scan_results.get('scan_info', {})
        
        # Generate vulnerabilities HTML first
        if vulnerabilities:
            vulns_html = ""
            for i, vuln in enumerate(vulnerabilities, 1):
                confirmed_class = "confirmed" if vuln.get('confirmed') else ""
                severity = vuln.get('severity', 'LOW').lower()
                
                vuln_html = f"""
                <div class="vulnerability {confirmed_class}">
                    <div class="vuln-header">
                        <h3>Vulnerability #{i}</h3>
                        <span class="badge {severity}">{vuln.get('severity', 'LOW')}</span>
                    </div>
                    <div class="details">
                        <div class="detail-row">
                            <span class="detail-label">Type:</span>
                            <span class="detail-value">{vuln.get('type', 'Unknown')}</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">URL:</span>
                            <span class="detail-value">{html.escape(vuln.get('url', ''))}</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Method:</span>
                            <span class="detail-value">{vuln.get('method', 'GET')}</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Injection Point:</span>
                            <span class="detail-value">{vuln.get('injection_point', 'Unknown')}</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Context:</span>
                            <span class="detail-value">{vuln.get('context', 'Unknown')}</span>
                        </div>
                        <div class="detail-row">
                            <span class="detail-label">Payload:</span>
                            <span class="detail-value"><code>{html.escape(vuln.get('payload', ''))}</code></span>
                        </div>
                        {self._format_evidence(vuln.get('evidence', ''))}
                    </div>
                </div>
                """
                vulns_html += vuln_html
        else:
            vulns_html = """
            <div class="no-vulns">
                <h3>✅ No XSS vulnerabilities detected!</h3>
                <p>The scan completed successfully without finding any XSS vulnerabilities.</p>
            </div>
            """
        
        # Create the HTML with all values filled in
        html_output = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS Scan Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            padding: 30px;
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .summary-card {{
            background: #f8f9fa;
            border-radius: 6px;
            padding: 20px;
            text-align: center;
            border: 1px solid #e9ecef;
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            font-size: 18px;
        }}
        .summary-card .value {{
            font-size: 36px;
            font-weight: bold;
            color: #3498db;
        }}
        .severity-high {{
            color: #e74c3c !important;
        }}
        .severity-medium {{
            color: #f39c12 !important;
        }}
        .severity-low {{
            color: #27ae60 !important;
        }}
        .vulnerability {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 6px;
            padding: 20px;
            margin: 20px 0;
        }}
        .vulnerability.confirmed {{
            border-color: #e74c3c;
            background: #fff5f5;
        }}
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .badge.high {{
            background: #e74c3c;
            color: white;
        }}
        .badge.medium {{
            background: #f39c12;
            color: white;
        }}
        .badge.low {{
            background: #27ae60;
            color: white;
        }}
        .code-block {{
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 14px;
            margin: 10px 0;
        }}
        .details {{
            margin-top: 15px;
        }}
        .detail-row {{
            display: flex;
            padding: 8px 0;
            border-bottom: 1px solid #e9ecef;
        }}
        .detail-label {{
            font-weight: bold;
            width: 150px;
            color: #495057;
        }}
        .detail-value {{
            flex: 1;
            word-break: break-word;
        }}
        .evidence {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 10px;
            margin: 10px 0;
            font-family: monospace;
            font-size: 13px;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .scan-info {{
            background: #e3f2fd;
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 30px;
        }}
        .no-vulns {{
            text-align: center;
            padding: 60px 20px;
            color: #27ae60;
        }}
        .no-vulns i {{
            font-size: 72px;
            margin-bottom: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ XSS Vulnerability Scan Report</h1>
        
        <div class="scan-info">
            <h2>Scan Information</h2>
            <div class="detail-row">
                <span class="detail-label">Target URL:</span>
                <span class="detail-value">{html.escape(scan_info.get('target_url', 'Unknown'))}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Scan Date:</span>
                <span class="detail-value">{scan_info.get('start_time', datetime.now().isoformat())}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Duration:</span>
                <span class="detail-value">{scan_info.get('duration', 'Unknown')}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">URLs Scanned:</span>
                <span class="detail-value">{scan_info.get('urls_scanned', 0)}</span>
            </div>
        </div>
        
        <h2>Summary</h2>
        <div class="summary">
            <div class="summary-card">
                <h3>Total Vulnerabilities</h3>
                <div class="value">{summary.get('total_vulnerabilities', 0)}</div>
            </div>
            <div class="summary-card">
                <h3>High Severity</h3>
                <div class="value severity-high">{summary.get('severity_breakdown', {}).get('HIGH', 0)}</div>
            </div>
            <div class="summary-card">
                <h3>Medium Severity</h3>
                <div class="value severity-medium">{summary.get('severity_breakdown', {}).get('MEDIUM', 0)}</div>
            </div>
            <div class="summary-card">
                <h3>Low Severity</h3>
                <div class="value severity-low">{summary.get('severity_breakdown', {}).get('LOW', 0)}</div>
            </div>
        </div>
        
        <h2>Vulnerability Details</h2>
        {vulns_html}
    </div>
</body>
</html>"""
        
        return html_output
    
    def _format_evidence(self, evidence: str) -> str:
        """Format evidence with syntax highlighting."""
        if not evidence:
            return ""
        
        return f"""
        <div class="detail-row">
            <span class="detail-label">Evidence:</span>
            <span class="detail-value">
                <div class="evidence">{html.escape(evidence)}</div>
            </span>
        </div>
        """


class JSONReporter(Reporter):
    """Generate JSON reports."""
    
    def generate(self, scan_results: Dict, output_path: Path) -> bool:
        """Generate JSON report."""
        try:
            output_file = output_path / 'xss_scan_report.json'
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(scan_results, f, indent=2, default=str)
            
            logger.info(f"JSON report generated: {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {e}")
            return False


class CSVReporter(Reporter):
    """Generate CSV reports."""
    
    def generate(self, scan_results: Dict, output_path: Path) -> bool:
        """Generate CSV report."""
        try:
            vulnerabilities = scan_results.get('vulnerabilities', [])
            output_file = output_path / 'xss_scan_report.csv'
            
            if not vulnerabilities:
                logger.warning("No vulnerabilities to report")
                # Create empty CSV with headers
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    fieldnames = [
                        'severity', 'type', 'url', 'method', 'injection_point',
                        'context', 'payload', 'confirmed', 'evidence'
                    ]
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                return True
            
            # Define CSV fields
            fieldnames = [
                'severity', 'type', 'url', 'method', 'injection_point',
                'context', 'payload', 'confirmed', 'evidence'
            ]
            
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for vuln in vulnerabilities:
                    row = {
                        'severity': vuln.get('severity', 'LOW'),
                        'type': vuln.get('type', 'Unknown'),
                        'url': vuln.get('url', ''),
                        'method': vuln.get('method', 'GET'),
                        'injection_point': vuln.get('injection_point', ''),
                        'context': vuln.get('context', ''),
                        'payload': vuln.get('payload', ''),
                        'confirmed': 'Yes' if vuln.get('confirmed') else 'No',
                        'evidence': vuln.get('evidence', '')[:100]  # Truncate evidence
                    }
                    writer.writerow(row)
            
            logger.info(f"CSV report generated: {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate CSV report: {e}")
            return False


class NotificationPlugin:
    """Optional notification plugin for alerts."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get('enabled', False)
    
    def send_slack_notification(self, scan_results: Dict) -> bool:
        """Send Slack notification."""
        if not self.enabled or not self.config.get('slack_webhook'):
            return False
        
        try:
            import requests
            
            summary = scan_results.get('summary', {})
            total_vulns = summary.get('total_vulnerabilities', 0)
            
            if total_vulns == 0:
                message = "✅ XSS scan completed - No vulnerabilities found!"
                color = "good"
            else:
                high = summary.get('severity_breakdown', {}).get('HIGH', 0)
                message = f"⚠️ XSS scan completed - Found {total_vulns} vulnerabilities ({high} HIGH severity)"
                color = "danger" if high > 0 else "warning"
            
            payload = {
                "attachments": [{
                    "color": color,
                    "title": "XSS Scan Report",
                    "text": message,
                    "fields": [
                        {
                            "title": "Target",
                            "value": scan_results.get('scan_info', {}).get('target_url', 'Unknown'),
                            "short": True
                        },
                        {
                            "title": "Duration",
                            "value": scan_results.get('scan_info', {}).get('duration', 'Unknown'),
                            "short": True
                        }
                    ],
                    "footer": "XSS Scanner",
                    "ts": int(datetime.now().timestamp())
                }]
            }
            
            response = requests.post(self.config['slack_webhook'], json=payload)
            return response.status_code == 200
            
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return False
    
    def send_email_notification(self, scan_results: Dict) -> bool:
        """Send email notification."""
        if not self.enabled or not self.config.get('smtp_server'):
            return False
        
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            summary = scan_results.get('summary', {})
            total_vulns = summary.get('total_vulnerabilities', 0)
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.config.get('smtp_from', 'xss-scanner@example.com')
            msg['To'] = self.config.get('smtp_to', '')
            msg['Subject'] = f"XSS Scan Report - {total_vulns} vulnerabilities found"
            
            # Email body
            body = f"""
XSS Vulnerability Scan Report
=============================

Target: {scan_results.get('scan_info', {}).get('target_url', 'Unknown')}
Date: {scan_results.get('scan_info', {}).get('start_time', 'Unknown')}
Duration: {scan_results.get('scan_info', {}).get('duration', 'Unknown')}

Summary:
- Total Vulnerabilities: {total_vulns}
- High Severity: {summary.get('severity_breakdown', {}).get('HIGH', 0)}
- Medium Severity: {summary.get('severity_breakdown', {}).get('MEDIUM', 0)}
- Low Severity: {summary.get('severity_breakdown', {}).get('LOW', 0)}

Please check the full report for details.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            with smtplib.SMTP(self.config['smtp_server'], self.config.get('smtp_port', 587)) as server:
                if self.config.get('smtp_tls', True):
                    server.starttls()
                if self.config.get('smtp_username'):
                    server.login(self.config['smtp_username'], self.config['smtp_password'])
                server.send_message(msg)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email notification: {e}")
            return False