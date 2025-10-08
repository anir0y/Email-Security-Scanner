# SPF and DKIM Scanner

A Python script that performs comprehensive email security scans on domains, checking for SPF, DKIM, and DMARC records, and generates detailed CSV and PDF reports.

**Created by:** [@anir0y](https://github.com/anir0y)  
**GitHub:** https://github.com/anir0y  
**X (Twitter):** https://x.com/anir0y

## Features

- **SPF Record Analysis**: Checks for SPF records and validates their configuration
- **DKIM Record Detection**: Scans for common DKIM selectors and validates records
- **DMARC Policy Analysis**: Examines DMARC policies and their effectiveness
- **Security Scoring**: Provides an overall security score (0-100) for each domain
- **Dual Report Generation**: Automatically generates both CSV and PDF reports
- **Professional PDF Reports**: Beautiful, executive-ready PDF reports with visual analytics
- **DNS Error Handling**: Gracefully handles DNS resolution issues
- **Batch Processing**: Processes multiple domains from text files
- **Flexible Output Options**: Choose between CSV-only, PDF-only, or both formats

## Installation

1. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage (Generates both CSV and PDF)
```bash
python spf_dkim_scanner.py domains.txt
```

### Specify Output File Prefix
```bash
python spf_dkim_scanner.py domains.txt -o security_report
# Creates: security_report.csv and security_report.pdf
```

### Add Contact Email to PDF Report
```bash
python spf_dkim_scanner.py domains.txt -e your.email@company.com -o report
# Includes contact email in the PDF report
```

### Generate Only CSV Report
```bash
python spf_dkim_scanner.py domains.txt --csv-only
```

### Generate Only PDF Report
```bash
python spf_dkim_scanner.py domains.txt --pdf-only
```

### Skip PDF Generation
```bash
python spf_dkim_scanner.py domains.txt --no-pdf
```

### Help
```bash
python spf_dkim_scanner.py --help
```

## Input Format

Create a text file with one domain per line:
```
example.com
test.example.org
subdomain.example.net
```

## Output Formats

### CSV Report
The script generates a CSV report with the following columns:

- `domain`: The scanned domain
- `scan_date`: When the scan was performed
- `security_score`: Overall security score (0-100)
- `has_spf`: Boolean indicating SPF record presence
- `spf_record`: The actual SPF record text
- `spf_status`: Analysis result for SPF
- `spf_error`: Any errors encountered during SPF lookup
- `has_dkim`: Boolean indicating DKIM record presence
- `dkim_selectors`: Found DKIM selectors
- `dkim_status`: Analysis result for DKIM
- `dkim_error`: Any errors encountered during DKIM lookup
- `has_dmarc`: Boolean indicating DMARC record presence
- `dmarc_record`: The actual DMARC record text
- `dmarc_status`: Analysis result for DMARC
- `dmarc_error`: Any errors encountered during DMARC lookup

### PDF Report
The script also generates a comprehensive PDF report featuring:

- **Executive Summary**: Visual statistics and coverage percentages
- **Domain Analysis**: Individual domain security assessments with risk levels
- **Protocol Summary**: Detailed table showing SPF/DKIM/DMARC status
- **Security Recommendations**: Prioritized action items
- **Technical Details**: Complete technical findings in tabular format
- **Professional Formatting**: Clean, corporate-ready presentation

## Security Analysis

### SPF Analysis
- Validates SPF record syntax
- Checks for proper `all` mechanism placement
- Counts DNS lookups to prevent exceeding limits
- Identifies potential misconfigurations

### DKIM Analysis
- Scans common selectors: default, selector1, selector2, mail, google, etc.
- Validates DKIM record structure
- Checks for revoked keys (empty public keys)
- Identifies weak hash algorithms

### DMARC Analysis
- Validates DMARC policy configuration
- Checks policy strictness (none/quarantine/reject)
- Identifies partial enforcement percentages
- Validates record syntax

### Security Scoring
- SPF: 30 points (+ 10 for valid configuration)
- DKIM: 30 points (+ 10 for multiple selectors)
- DMARC: 20 points (+ 10 for valid configuration)
- Maximum possible score: 100 points

## Example Output

```
Email Security Scanner v1.0
==================================================
Found 7 domains to scan...
Scanning anir0y.in...
Scanning arishtisecurity.com...
...

Scanned 2 domains successfully
Results exported to final_report.csv
PDF report exported to final_report.pdf

Scan Summary:
========================================
Domains scanned: 2
SPF configured: 0 (0.0%)
DKIM configured: 0 (0.0%)
DMARC configured: 1 (14.3%)
Average security score: 4.3/100
Overall security level: CRITICAL - Immediate action required

Reports generated:
  - CSV: final_report.csv
  - PDF: final_report.pdf
```

### Command-Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `-o, --output` | Output file prefix | `-o security_report` |
| `-e, --email` | Contact email for PDF report | `-e admin@company.com` |
| `--csv-only` | Generate only CSV report | `--csv-only` |
| `--pdf-only` | Generate only PDF report | `--pdf-only` |
| `--no-pdf` | Skip PDF generation | `--no-pdf` |

## Common DKIM Selectors

The script checks these common DKIM selectors:
- default, selector1, selector2
- mail, dkim, google
- k1, s1, s2, mx, email, smtp
- mandrill, mailgun, sendgrid, amazonses

## Error Handling

The script handles various DNS errors gracefully:
- Domain not found (NXDOMAIN)
- No TXT records available
- DNS resolution timeouts
- Network connectivity issues

## Rate Limiting

The script includes a 0.5-second delay between domain scans to be respectful to DNS servers.

## Dependencies

- `dnspython`: For DNS resolution and record parsing
- `requests`: For potential future web-based validation features
- `weasyprint`: For PDF report generation (optional, but recommended)

## License

This script is provided as-is for educational and security assessment purposes.
