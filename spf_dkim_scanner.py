#!/usr/bin/env python3
"""
SPF and DKIM Scanner
Reads domains from a text file and performs SPF and DKIM scans,
generating comprehensive CSV and PDF reports.

Created by: @anir0y
GitHub: https://github.com/anir0y
X: https://x.com/anir0y

Usage: python spf_dkim_scanner.py <input_file> [options]
"""

import sys
import csv
import dns.resolver
import dns.exception
import requests
import re
import socket
from urllib.parse import quote
from datetime import datetime
import argparse
import time
import os
from pathlib import Path
try:
    import weasyprint
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False


class EmailSecurityScanner:
    def __init__(self):
        self.results = []
        
    def check_spf_record(self, domain):
        """Check SPF record for a domain using DNS lookup"""
        try:
            # Query TXT records for SPF
            txt_records = dns.resolver.resolve(domain, 'TXT')
            spf_record = None
            
            for record in txt_records:
                txt_data = str(record).strip('"')
                if txt_data.startswith('v=spf1'):
                    spf_record = txt_data
                    break
            
            if spf_record:
                return {
                    'has_spf': True,
                    'spf_record': spf_record,
                    'spf_status': self._analyze_spf_record(spf_record),
                    'spf_error': None
                }
            else:
                return {
                    'has_spf': False,
                    'spf_record': None,
                    'spf_status': 'No SPF record found',
                    'spf_error': None
                }
                
        except dns.exception.DNSException as e:
            return {
                'has_spf': False,
                'spf_record': None,
                'spf_status': 'DNS Error',
                'spf_error': str(e)
            }
        except Exception as e:
            return {
                'has_spf': False,
                'spf_record': None,
                'spf_status': 'Error',
                'spf_error': str(e)
            }
    
    def _analyze_spf_record(self, spf_record):
        """Analyze SPF record for common issues"""
        issues = []
        
        # Check for all mechanism (should be at the end)
        if 'all' in spf_record:
            if not spf_record.endswith(('~all', '-all', '+all', '?all')):
                issues.append('all mechanism not at end')
            elif spf_record.endswith('+all'):
                issues.append('permissive +all policy')
        else:
            issues.append('no all mechanism')
        
        # Count DNS lookups (include, a, mx, exists, redirect)
        lookup_count = len(re.findall(r'\b(include:|a:|mx:|exists:|redirect=)', spf_record))
        if lookup_count > 10:
            issues.append(f'too many DNS lookups ({lookup_count})')
        
        # Check for nested includes depth
        if spf_record.count('include:') > 5:
            issues.append('many nested includes')
        
        if issues:
            return f"Warning: {', '.join(issues)}"
        else:
            return "Valid SPF record"
    
    def check_dkim_record(self, domain):
        """Check common DKIM selectors for a domain"""
        common_selectors = [
            'default', 'selector1', 'selector2', 'mail', 'dkim',
            'google', 'k1', 's1', 's2', 'mx', 'email', 'smtp',
            'mandrill', 'mailgun', 'sendgrid', 'amazonses'
        ]
        
        found_selectors = []
        dkim_records = []
        
        for selector in common_selectors:
            try:
                dkim_domain = f"{selector}._domainkey.{domain}"
                txt_records = dns.resolver.resolve(dkim_domain, 'TXT')
                
                for record in txt_records:
                    txt_data = str(record).strip('"')
                    if 'v=DKIM1' in txt_data or 'k=' in txt_data or 'p=' in txt_data:
                        found_selectors.append(selector)
                        dkim_records.append({
                            'selector': selector,
                            'record': txt_data,
                            'status': self._analyze_dkim_record(txt_data)
                        })
                        break
                        
            except dns.exception.DNSException:
                continue
            except Exception:
                continue
        
        if found_selectors:
            return {
                'has_dkim': True,
                'dkim_selectors': found_selectors,
                'dkim_records': dkim_records,
                'dkim_status': f"Found {len(found_selectors)} DKIM selector(s)",
                'dkim_error': None
            }
        else:
            return {
                'has_dkim': False,
                'dkim_selectors': [],
                'dkim_records': [],
                'dkim_status': 'No DKIM records found with common selectors',
                'dkim_error': None
            }
    
    def _analyze_dkim_record(self, dkim_record):
        """Analyze DKIM record for issues"""
        issues = []
        
        if 'v=DKIM1' not in dkim_record:
            issues.append('missing version tag')
        
        if 'p=' not in dkim_record:
            issues.append('missing public key')
        elif 'p=' in dkim_record:
            # Extract public key
            p_match = re.search(r'p=([^;]*)', dkim_record)
            if p_match and len(p_match.group(1).strip()) == 0:
                issues.append('empty public key (revoked)')
        
        # Check key type
        if 'k=rsa' not in dkim_record and 'k=' not in dkim_record:
            pass  # RSA is default
        
        # Check hash algorithm
        if 'h=sha1' in dkim_record:
            issues.append('weak SHA1 hash algorithm')
        
        if issues:
            return f"Warning: {', '.join(issues)}"
        else:
            return "Valid DKIM record"
    
    def check_dmarc_record(self, domain):
        """Check DMARC record for a domain"""
        try:
            dmarc_domain = f"_dmarc.{domain}"
            txt_records = dns.resolver.resolve(dmarc_domain, 'TXT')
            
            for record in txt_records:
                txt_data = str(record).strip('"')
                if txt_data.startswith('v=DMARC1'):
                    return {
                        'has_dmarc': True,
                        'dmarc_record': txt_data,
                        'dmarc_status': self._analyze_dmarc_record(txt_data),
                        'dmarc_error': None
                    }
            
            return {
                'has_dmarc': False,
                'dmarc_record': None,
                'dmarc_status': 'No DMARC record found',
                'dmarc_error': None
            }
            
        except dns.exception.DNSException as e:
            return {
                'has_dmarc': False,
                'dmarc_record': None,
                'dmarc_status': 'DNS Error',
                'dmarc_error': str(e)
            }
        except Exception as e:
            return {
                'has_dmarc': False,
                'dmarc_record': None,
                'dmarc_status': 'Error',
                'dmarc_error': str(e)
            }
    
    def _analyze_dmarc_record(self, dmarc_record):
        """Analyze DMARC record"""
        issues = []
        
        # Check policy
        if 'p=none' in dmarc_record:
            issues.append('policy set to none (monitoring only)')
        elif 'p=quarantine' in dmarc_record:
            pass  # Good
        elif 'p=reject' in dmarc_record:
            pass  # Best
        else:
            issues.append('no policy specified')
        
        # Check percentage
        pct_match = re.search(r'pct=(\d+)', dmarc_record)
        if pct_match:
            pct = int(pct_match.group(1))
            if pct < 100:
                issues.append(f'partial enforcement ({pct}%)')
        
        if issues:
            return f"Warning: {', '.join(issues)}"
        else:
            return "Valid DMARC record"
    
    def scan_domain(self, domain):
        """Perform complete scan of a domain"""
        domain = domain.strip().lower()
        if not domain:
            return None
        
        print(f"Scanning {domain}...")
        
        result = {
            'domain': domain,
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }
        
        # Check SPF
        spf_result = self.check_spf_record(domain)
        result.update(spf_result)
        
        # Check DKIM
        dkim_result = self.check_dkim_record(domain)
        result.update(dkim_result)
        
        # Check DMARC
        dmarc_result = self.check_dmarc_record(domain)
        result.update(dmarc_result)
        
        # Overall security score
        result['security_score'] = self._calculate_security_score(result)
        
        # Add delay to be respectful to DNS servers
        time.sleep(0.5)
        
        return result
    
    def _calculate_security_score(self, result):
        """Calculate overall security score"""
        score = 0
        
        # SPF scoring
        if result['has_spf']:
            score += 30
            if 'Valid' in result['spf_status']:
                score += 10
        
        # DKIM scoring
        if result['has_dkim']:
            score += 30
            if len(result['dkim_selectors']) > 0:
                score += 10
        
        # DMARC scoring
        if result['has_dmarc']:
            score += 20
            if 'Valid' in result['dmarc_status']:
                score += 10
        
        return f"{score}/100"
    
    def scan_domains_from_file(self, input_file):
        """Scan all domains from input file"""
        try:
            with open(input_file, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
            
            print(f"Found {len(domains)} domains to scan...")
            
            for domain in domains:
                result = self.scan_domain(domain)
                if result:
                    self.results.append(result)
            
            return self.results
            
        except FileNotFoundError:
            print(f"Error: File '{input_file}' not found")
            return []
        except Exception as e:
            print(f"Error reading file: {e}")
            return []
    
    def export_to_csv(self, output_file):
        """Export results to CSV file"""
        if not self.results:
            print("No results to export")
            return False
        
        fieldnames = [
            'domain', 'scan_date', 'security_score',
            'has_spf', 'spf_record', 'spf_status', 'spf_error',
            'has_dkim', 'dkim_selectors', 'dkim_status', 'dkim_error',
            'has_dmarc', 'dmarc_record', 'dmarc_status', 'dmarc_error'
        ]
        
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for result in self.results:
                    # Prepare row data
                    row = {
                        'domain': result['domain'],
                        'scan_date': result['scan_date'],
                        'security_score': result['security_score'],
                        'has_spf': result['has_spf'],
                        'spf_record': result.get('spf_record', ''),
                        'spf_status': result['spf_status'],
                        'spf_error': result.get('spf_error', ''),
                        'has_dkim': result['has_dkim'],
                        'dkim_selectors': ', '.join(result['dkim_selectors']) if result['dkim_selectors'] else '',
                        'dkim_status': result['dkim_status'],
                        'dkim_error': result.get('dkim_error', ''),
                        'has_dmarc': result['has_dmarc'],
                        'dmarc_record': result.get('dmarc_record', ''),
                        'dmarc_status': result['dmarc_status'],
                        'dmarc_error': result.get('dmarc_error', '')
                    }
                    writer.writerow(row)
            
            print(f"Results exported to {output_file}")
            return True
            
        except Exception as e:
            print(f"Error exporting to CSV: {e}")
            return False
    
    def generate_html_report(self, contact_email=""):
        """Generate HTML report from scan results"""
        if not self.results:
            return None
        
        # Calculate summary statistics
        total_domains = len(self.results)
        spf_count = sum(1 for r in self.results if r['has_spf'])
        dkim_count = sum(1 for r in self.results if r['has_dkim'])
        dmarc_count = sum(1 for r in self.results if r['has_dmarc'])
        
        # Calculate average security score
        total_score = sum(int(r['security_score'].split('/')[0]) for r in self.results)
        avg_score = total_score / total_domains if total_domains > 0 else 0
        
        # Generate current date
        report_date = datetime.now().strftime('%B %d, %Y')
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Security Assessment Report</title>
    <style>
        @page {{
            size: A4;
            margin: 2cm 1.5cm;
        }}
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.4;
            color: #333;
            max-width: 100%;
            margin: 0;
            padding: 0;
            font-size: 11pt;
        }}
        h1 {{ 
            color: #2c3e50; 
            border-bottom: 2px solid #3498db; 
            padding-bottom: 8px;
            margin-bottom: 20px;
            font-size: 18pt;
            page-break-after: avoid;
        }}
        h2 {{ 
            color: #34495e; 
            margin-top: 25px;
            margin-bottom: 15px;
            font-size: 14pt;
            page-break-after: avoid;
        }}
        h3 {{ 
            color: #2c3e50; 
            margin-top: 15px;
            margin-bottom: 10px;
            font-size: 12pt;
            page-break-after: avoid;
        }}
        table {{ 
            border-collapse: collapse; 
            width: 100%; 
            margin: 15px 0;
            page-break-inside: avoid;
            font-size: 10pt;
        }}
        th, td {{ 
            border: 1px solid #ddd; 
            padding: 8px; 
            text-align: left;
            word-wrap: break-word;
        }}
        th {{ 
            background-color: #f2f2f2;
            font-weight: bold;
        }}
        .summary-box {{ 
            background-color: #f8f9fa; 
            padding: 15px; 
            margin: 15px 0; 
            border-left: 4px solid #3498db;
            page-break-inside: avoid;
        }}
        .critical {{ color: #e74c3c; font-weight: bold; }}
        .warning {{ color: #f39c12; font-weight: bold; }}
        .success {{ color: #27ae60; font-weight: bold; }}
        .domain-box {{ 
            background-color: #f8f9fa; 
            padding: 12px; 
            margin: 8px 0; 
            border: 1px solid #ddd;
            page-break-inside: avoid;
        }}
        .score {{ 
            font-size: 14pt; 
            font-weight: bold; 
            margin: 8px 0; 
        }}
        .stats {{ 
            display: table;
            width: 100%;
            margin: 15px 0;
        }}
        .stat-item {{ 
            display: table-cell;
            text-align: center;
            vertical-align: top;
            width: 33.33%;
        }}
        .stat-number {{ 
            font-size: 16pt; 
            font-weight: bold; 
            color: #3498db;
            display: block;
        }}
        .protocol-status {{ margin: 8px 0; }}
        .protocol-pass {{ color: #27ae60; font-weight: bold; }}
        .protocol-fail {{ color: #e74c3c; font-weight: bold; }}
        .risk-high {{ background-color: #ffebee; padding: 4px; border-radius: 3px; }}
        .risk-medium {{ background-color: #fff3e0; padding: 4px; border-radius: 3px; }}
        .risk-low {{ background-color: #e8f5e8; padding: 4px; border-radius: 3px; }}
        .contact-info {{
            background-color: #f8f9fa;
            padding: 15px;
            margin: 20px 0;
            border: 1px solid #ddd;
            border-radius: 5px;
        }}
        .page-break {{
            page-break-before: always;
        }}
        ul, ol {{ 
            margin: 10px 0;
            padding-left: 20px;
        }}
        li {{ 
            margin: 5px 0;
        }}
        p {{ 
            margin: 8px 0;
        }}
    </style>
</head>
<body>
    <h1>Email Security Assessment Report</h1>
    
    <div class="summary-box">
        <p><strong>Report Generated:</strong> {report_date}</p>
        <p><strong>Total Domains Analyzed:</strong> {total_domains}</p>
        <p><strong>Average Security Score:</strong> {avg_score:.1f}/100</p>
    </div>
    
    <h2>Executive Summary</h2>
    
    <div class="stats">
        <div class="stat-item">
            <div class="stat-number">{spf_count}/{total_domains}</div>
            <div>SPF Records</div>
        </div>
        <div class="stat-item">
            <div class="stat-number">{dkim_count}/{total_domains}</div>
            <div>DKIM Records</div>
        </div>
        <div class="stat-item">
            <div class="stat-number">{dmarc_count}/{total_domains}</div>
            <div>DMARC Records</div>
        </div>
    </div>
    
    <div class="summary-box">
        <p>This report presents the findings of a comprehensive email security assessment. The assessment evaluated {total_domains} domains for the presence and configuration of critical email security protocols: SPF (Sender Policy Framework), DKIM (DomainKeys Identified Mail), and DMARC (Domain-based Message Authentication, Reporting, and Conformance).</p>
    </div>
    
    <h2>Detailed Domain Analysis</h2>
"""
        
        # Add domain analysis
        for result in self.results:
            domain = result['domain']
            score = result['security_score']
            
            # Determine risk level based on score
            score_num = int(score.split('/')[0])
            if score_num < 30:
                risk_class = "risk-high"
                risk_level = "HIGH RISK"
            elif score_num < 70:
                risk_class = "risk-medium" 
                risk_level = "MEDIUM RISK"
            else:
                risk_class = "risk-low"
                risk_level = "LOW RISK"
            
            html_content += f"""
    <div class="domain-box">
        <h3>{domain} - Score: {score}</h3>
        <div class="{risk_class}">Risk Level: {risk_level}</div>
        
        <div class="protocol-status">
            <strong>SPF:</strong> <span class="{'protocol-pass' if result['has_spf'] else 'protocol-fail'}">{'Configured' if result['has_spf'] else 'Not Configured'}</span> | 
            <strong>DKIM:</strong> <span class="{'protocol-pass' if result['has_dkim'] else 'protocol-fail'}">{'Configured' if result['has_dkim'] else 'Not Configured'}</span> | 
            <strong>DMARC:</strong> <span class="{'protocol-pass' if result['has_dmarc'] else 'protocol-fail'}">{'Configured' if result['has_dmarc'] else 'Not Configured'}</span>
        </div>"""
            
            # Only show status if there are issues or configurations
            status_items = []
            if result['spf_status'] and result['spf_status'] != 'No SPF record found':
                status_items.append(f"SPF: {result['spf_status']}")
            if result['dkim_status'] and 'No DKIM records found' not in result['dkim_status']:
                status_items.append(f"DKIM: {result['dkim_status']}")
            if result['dmarc_status'] and result['dmarc_status'] != 'No DMARC record found':
                status_items.append(f"DMARC: {result['dmarc_status']}")
            
            if status_items:
                html_content += f"""
        <p><strong>Details:</strong> {' | '.join(status_items)}</p>"""
                
            html_content += """
    </div>
"""
        
        # Add recommendations
        html_content += f"""
    <h2>Security Protocol Summary</h2>
    
    <table>
        <thead>
            <tr>
                <th>Protocol</th>
                <th>Domains Configured</th>
                <th>Coverage</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>SPF</td>
                <td>{spf_count} / {total_domains}</td>
                <td>{(spf_count/total_domains*100):.1f}%</td>
                <td class="{'success' if spf_count > total_domains * 0.8 else 'warning' if spf_count > 0 else 'critical'}">{'Good' if spf_count > total_domains * 0.8 else 'Partial' if spf_count > 0 else 'Critical'}</td>
            </tr>
            <tr>
                <td>DKIM</td>
                <td>{dkim_count} / {total_domains}</td>
                <td>{(dkim_count/total_domains*100):.1f}%</td>
                <td class="{'success' if dkim_count > total_domains * 0.8 else 'warning' if dkim_count > 0 else 'critical'}">{'Good' if dkim_count > total_domains * 0.8 else 'Partial' if dkim_count > 0 else 'Critical'}</td>
            </tr>
            <tr>
                <td>DMARC</td>
                <td>{dmarc_count} / {total_domains}</td>
                <td>{(dmarc_count/total_domains*100):.1f}%</td>
                <td class="{'success' if dmarc_count > total_domains * 0.8 else 'warning' if dmarc_count > 0 else 'critical'}">{'Good' if dmarc_count > total_domains * 0.8 else 'Partial' if dmarc_count > 0 else 'Critical'}</td>
            </tr>
        </tbody>
    </table>
    
    <h2>Recommendations</h2>
    
    <div class="summary-box">
        <h3>Immediate Actions Required</h3>
        <ol>"""
        
        if spf_count < total_domains:
            html_content += f"""
            <li><strong>Implement SPF Records:</strong> {total_domains - spf_count} domain(s) lack SPF protection</li>"""
            
        if dkim_count < total_domains:
            html_content += f"""
            <li><strong>Configure DKIM Signing:</strong> {total_domains - dkim_count} domain(s) lack DKIM authentication</li>"""
            
        if dmarc_count < total_domains:
            html_content += f"""
            <li><strong>Deploy DMARC Policies:</strong> {total_domains - dmarc_count} domain(s) lack DMARC protection</li>"""
        
        html_content += """
        </ol>
        
        <h3>Implementation Priority</h3>
        <ol>
            <li><strong>High Priority:</strong> Domains with 0-30 security score</li>
            <li><strong>Medium Priority:</strong> Domains with 31-70 security score</li>
            <li><strong>Low Priority:</strong> Domains with 71+ security score</li>
        </ol>
    </div>
    
    <h2>Technical Details</h2>
    
    <table>
        <thead>
            <tr>
                <th>Domain</th>
                <th>SPF Record</th>
                <th>DKIM Selectors</th>
                <th>DMARC Policy</th>
                <th>Security Score</th>
            </tr>
        </thead>
        <tbody>"""
        
        for result in self.results:
            spf_record = result.get('spf_record') or 'None'
            if len(spf_record) > 30:
                spf_record = spf_record[:30] + '...'
            
            dkim_selectors = ', '.join(result['dkim_selectors']) if result['dkim_selectors'] else 'None'
            if len(dkim_selectors) > 20:
                dkim_selectors = dkim_selectors[:20] + '...'
            
            dmarc_record = result.get('dmarc_record') or 'None'
            if len(dmarc_record) > 30:
                dmarc_record = dmarc_record[:30] + '...'
            
            html_content += f"""
            <tr>
                <td style="width: 25%;">{result['domain']}</td>
                <td style="width: 25%;">{spf_record}</td>
                <td style="width: 20%;">{dkim_selectors}</td>
                <td style="width: 25%;">{dmarc_record}</td>
                <td style="width: 5%;">{result['security_score']}</td>
            </tr>"""
        
        html_content += f"""
        </tbody>
    </table>
    
    <div class="page-break"></div>
    
    <h2>Contact Information</h2>
    
    <div class="contact-info">
        <p><strong>Assessment Conducted By:</strong> Email Security Scanner v1.0</p>
        <p><strong>Created by:</strong> @anir0y</p>
        <p><strong>GitHub:</strong> https://github.com/anir0y | <strong>X:</strong> https://x.com/anir0y</p>
        <p><strong>Report Generated:</strong> {report_date}</p>"""
        
        if contact_email:
            html_content += f"""        <p><strong>Contact Email:</strong> {contact_email}</p>"""
        
        html_content += """        <p><strong>Next Assessment Due:</strong> January 8, 2026 (Quarterly Review Recommended)</p>
    </div>
    
    <div class="summary-box">
        <p><em>This report contains security-sensitive information. Please distribute only to authorized personnel involved in email security management.</em></p>
    </div>
    
</body>
</html>"""
        
        return html_content
    
    def export_to_pdf(self, output_file, contact_email=""):
        """Export results to PDF file"""
        if not WEASYPRINT_AVAILABLE:
            print("Warning: weasyprint not available. Install with: pip install weasyprint")
            return False
            
        try:
            html_content = self.generate_html_report(contact_email=contact_email)
            if not html_content:
                print("No data available for PDF report generation")
                return False
            
            # Create temporary HTML file
            html_file = output_file.replace('.pdf', '_temp.html')
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            # Generate PDF
            weasyprint.HTML(filename=html_file).write_pdf(output_file)
            
            # Clean up temporary file
            os.remove(html_file)
            
            print(f"PDF report exported to {output_file}")
            return True
            
        except Exception as e:
            print(f"Error generating PDF report: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(description='SPF and DKIM Scanner with CSV and PDF Report Generation')
    parser.add_argument('input_file', help='Input file containing domains (one per line)')
    parser.add_argument('-o', '--output', default='email_security_report',
                       help='Output file prefix (default: email_security_report)')
    parser.add_argument('-e', '--email', default='',
                       help='Contact email for the report (optional)')
    parser.add_argument('--csv-only', action='store_true',
                       help='Generate only CSV report')
    parser.add_argument('--pdf-only', action='store_true', 
                       help='Generate only PDF report')
    parser.add_argument('--no-pdf', action='store_true',
                       help='Skip PDF generation (CSV only)')
    
    args = parser.parse_args()
    
    scanner = EmailSecurityScanner()
    
    print("=" * 60)
    print("     Email Security Scanner v1.0")
    print("     SPF | DKIM | DMARC Assessment Tool")
    print("")
    print("     Created by: @anir0y")
    print("     GitHub: https://github.com/anir0y")
    print("     X (Twitter): https://x.com/anir0y")
    print("=" * 60)
    
    # Check weasyprint availability for PDF generation
    if not WEASYPRINT_AVAILABLE and not args.csv_only and not args.no_pdf:
        print("Warning: weasyprint not installed. PDF generation will be skipped.")
        print("To enable PDF reports, install with: pip install weasyprint")
        args.no_pdf = True
    
    # Scan domains
    results = scanner.scan_domains_from_file(args.input_file)
    
    if results:
        print(f"\nScanned {len(results)} domains successfully")
        
        # Prepare output filenames
        csv_output = f"{args.output}.csv" if not args.output.endswith('.csv') else args.output
        pdf_output = f"{args.output}.pdf" if not args.output.endswith('.pdf') else args.output.replace('.csv', '.pdf')
        
        # Export reports
        reports_generated = []
        
        if not args.pdf_only:
            # Generate CSV report
            if scanner.export_to_csv(csv_output):
                reports_generated.append(f"CSV: {csv_output}")
        
        if not args.csv_only and not args.no_pdf and WEASYPRINT_AVAILABLE:
            # Generate PDF report
            if scanner.export_to_pdf(pdf_output, contact_email=args.email):
                reports_generated.append(f"PDF: {pdf_output}")
        
        # Print summary
        print(f"\nScan Summary:")
        print("=" * 40)
        spf_count = sum(1 for r in results if r['has_spf'])
        dkim_count = sum(1 for r in results if r['has_dkim'])
        dmarc_count = sum(1 for r in results if r['has_dmarc'])
        
        print(f"Domains scanned: {len(results)}")
        print(f"SPF configured: {spf_count} ({spf_count/len(results)*100:.1f}%)")
        print(f"DKIM configured: {dkim_count} ({dkim_count/len(results)*100:.1f}%)")
        print(f"DMARC configured: {dmarc_count} ({dmarc_count/len(results)*100:.1f}%)")
        
        # Security assessment
        total_score = sum(int(r['security_score'].split('/')[0]) for r in results)
        avg_score = total_score / len(results)
        print(f"Average security score: {avg_score:.1f}/100")
        
        if avg_score < 30:
            print("Overall security level: CRITICAL - Immediate action required")
        elif avg_score < 60:
            print("Overall security level: WARNING - Significant improvements needed")
        else:
            print("Overall security level: GOOD - Minor improvements recommended")
        
        print(f"\nReports generated:")
        for report in reports_generated:
            print(f"  - {report}")
            
    else:
        print("No domains were successfully scanned")


if __name__ == "__main__":
    main()
