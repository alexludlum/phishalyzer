# phishalyzer
A full-feature email analysis tool in Python. 

# Phishalyzer

A comprehensive email analysis tool designed to detect phishing attempts, malware, and security threats in email messages. Phishalyzer performs multi-layered analysis of email headers, content, URLs, attachments, and embedded elements to provide detailed security assessments.

## Features

### 🔍 **Multi-Layered Analysis**
- **Header Analysis**: SPF, DKIM, DMARC authentication verification
- **IP Address Analysis**: Geolocation and reputation checking via VirusTotal
- **URL Analysis**: Domain reputation and malicious link detection
- **Email Body Analysis**: Phishing content and social engineering detection
- **Attachment Analysis**: File type spoofing, QR code detection, and content analysis
- **Routing Analysis**: Email delivery path visualization

### 🛡️ **Advanced Threat Detection**
- **Critical Threats**: Spoofed executables, malicious QR codes
- **File Extension Spoofing**: Detects executables disguised as documents
- **QR Code Analysis**: Extracts and analyzes QR codes from PDF attachments
- **Phishing Content**: Identifies credential harvesting and social engineering attempts
- **Business Email Compromise (BEC)**: Detects executive impersonation patterns

### 🎯 **Executive Summary**
- **Risk-Based Assessment**: CRITICAL, HIGH, MEDIUM, LOW threat levels
- **Comprehensive Findings**: Aggregates results from all analysis modules
- **Actionable Intelligence**: Clear threat categorization and recommendations
- **IOC Tracking**: Counts confirmed malicious indicators

### 🔧 **User-Friendly Interface**
- **Interactive Menu System**: Navigate between different analysis views
- **Defanged Output**: Safe display of URLs and IPs to prevent accidental clicks
- **Color-Coded Results**: Visual threat level indicators
- **Detailed Breakdowns**: Drill down into specific findings
- **Universal Compatibility**: Works across different terminal environments

## Installation

### Prerequisites

```bash
# Python 3.7 or higher required
python --version

# Install required packages
pip install -r requirements.txt
```

### Required Dependencies

```
extract-msg        # MSG file parsing
dnspython         # DNS lookups
requests          # HTTP requests for API calls
email-validator   # Email validation
PyMuPDF          # PDF analysis (optional)
Pillow           # Image processing (optional)
opencv-python    # QR code detection (optional)
```

### Optional Dependencies

For enhanced functionality, install these additional packages:

```bash
# For QR code analysis in PDF attachments
pip install PyMuPDF Pillow opencv-python

# For advanced document analysis
pip install python-docx openpyxl python-pptx

# For OCR capabilities
pip install pytesseract
```

## Quick Start

### Basic Usage

```bash
# Analyze an email file
python phishalyzer.py path/to/email.eml

# Interactive mode (will prompt for file)
python phishalyzer.py
```

### Supported File Formats

- **EML files**: Standard email format from most email clients
- **MSG files**: Microsoft Outlook email format
- **Raw email**: RFC822 formatted email messages

## Configuration

### VirusTotal API Setup

1. **Get API Key**: Register at [VirusTotal](https://virustotal.com/gui/my-apikey)
2. **Configure in Phishalyzer**: 
   - Run phishalyzer
   - Select "2: VirusTotal API Settings"
   - Enter your API key

### Output Modes

- **Fanged Mode** (default): Shows URLs and IPs in normal format
- **Defanged Mode**: Shows URLs and IPs in safe format (https[:]//example[.]com)

Access via Main Menu → "3: Output Settings"

## Analysis Modules

### 1. Header Analysis
- **Authentication Check**: SPF, DKIM, DMARC validation
- **Routing Analysis**: Received header examination
- **Sender Validation**: From/Reply-To/Return-Path consistency
- **Security Indicators**: Missing or failed authentication

### 2. IP Address Analysis
- **Geolocation**: Country and ISP identification
- **Reputation Check**: VirusTotal malicious IP detection
- **Private IP Filtering**: Excludes internal network addresses
- **Comprehensive Coverage**: Headers and email body IPs

### 3. URL Analysis
- **Domain Grouping**: Organizes URLs by domain for efficiency
- **Reputation Checking**: VirusTotal URL analysis
- **Link Extraction**: From email body, HTML content, and attachments
- **Defanging Support**: Safe display of malicious URLs

### 4. Email Body Analysis
- **Phishing Patterns**: 14 categories of phishing techniques
- **Risk Scoring**: Weighted scoring based on threat severity
- **Social Engineering**: BEC, urgency manipulation, authority impersonation
- **Content Classification**: High, medium, low risk categorization

### 5. Attachment Analysis
- **File Type Detection**: Magic number-based identification
- **Extension Spoofing**: Detects mismatched file types/extensions
- **VirusTotal Integration**: File hash reputation checking
- **QR Code Extraction**: PDF QR code analysis and URL checking
- **Content Analysis**: Text extraction and phishing detection

## Menu System

### Main Menu Options

1. **Start Analysis**: Analyze an email file
2. **VirusTotal API Settings**: Configure API key
3. **Output Settings**: Toggle defanged/fanged mode
4. **View URL Findings**: Detailed URL analysis results
5. **View Body Analysis**: Phishing content breakdown
6. **View Email Routing**: Received header analysis
7. **Generate Executive Summary**: Comprehensive threat assessment

### Dynamic Menu

Menu options appear based on available analysis results. For example:
- URL findings only appear if URLs were detected
- Body analysis only appears if content was analyzed
- Executive summary appears after any analysis is completed

## Understanding Results

### Risk Levels

- **CRITICAL**: Immediate threat requiring action
  - Spoofed executables disguised as documents
  - Malicious QR codes with confirmed threats
  
- **HIGH**: Significant security concerns
  - Malicious domains/IPs confirmed by VirusTotal
  - Multiple authentication failures
  - QR codes (even unchecked ones)
  - High-risk phishing content

- **MEDIUM**: Moderate risk requiring attention
  - Suspicious indicators from VirusTotal
  - Medium-risk phishing patterns
  - File extension mismatches

- **LOW**: Minor concerns for awareness
  - Unchecked domains/IPs
  - Low-risk phishing patterns
  - Missing non-critical headers

### Threat Categories

#### Critical Threats
- Spoofed executables (.exe files disguised as .pdf)
- Malicious QR codes with confirmed bad destinations

#### Malicious Indicators
- VirusTotal-confirmed malicious domains, IPs, or files
- Counted toward total IOC (Indicators of Compromise)

#### High Risk Findings
- Authentication failures (SPF, DKIM, DMARC)
- QR codes in attachments
- High-risk phishing content
- File extension spoofing

#### Suspicious Indicators
- VirusTotal-flagged suspicious items
- Potentially harmful content

#### Warning Factors
- Unchecked domains/IPs
- Missing headers
- Low-risk phishing patterns

## Sample Output

```
Overall Risk Assessment: HIGH RISK

MALICIOUS INDICATORS:
- Malicious domain: suspicious-bank[.]com (3 URLs)
- Malicious file: security_update.pdf

HIGH RISK FINDINGS:
- Header issue: SPF: missing
- Header issue: DKIM: missing
- Header issue: DMARC: missing
- High-risk phishing content: Credential Harvesting, Payment Redirect Scam
- Unchecked QR code: security_update.pdf

SUSPICIOUS INDICATORS:
- Suspicious domain: fake-support[.]com (1 URL)

Total Malicious Indicators: 2
Total Warning Factors: 3
```

## File Structure

```
phishalyzer/
├── phishalyzer.py              # Main application
├── analyzer/                   # Analysis modules
│   ├── __init__.py
│   ├── parser.py               # Email parsing (EML/MSG)
│   ├── header_analyzer.py      # Header analysis
│   ├── ioc_extractor.py        # IP address analysis
│   ├── url_extractor.py        # URL analysis
│   ├── body_analyzer.py        # Email body analysis
│   ├── attachment_analyzer.py  # Attachment analysis
│   ├── qr_analyzer.py          # QR code detection
│   ├── attachment_content_analyzer.py  # Attachment content analysis
│   ├── defanger.py             # URL/IP defanging
│   └── compatible_output.py    # Universal output system
├── requirements.txt            # Python dependencies
├── samples/                    # Sample email files
└── README.md                   # This file
```

## Advanced Usage

### Batch Analysis

```bash
# Analyze multiple files
for file in samples/*.eml; do
    echo "Analyzing $file"
    python phishalyzer.py "$file" > "results/$(basename $file).txt"
done
```

### Automated Scripting

```python
from analyzer import parser, url_extractor, attachment_analyzer

# Load email
msg_obj, filetype = parser.load_email('email.eml')

# Run specific analysis
url_results = url_extractor.analyze_urls(msg_obj, api_key)
attachment_results = attachment_analyzer.analyze_attachments(msg_obj, api_key)
```

### Configuration Files

Settings are stored in:
- `~/.phishalyzer_vt_api_key`: VirusTotal API key
- `~/.phishalyzer_output_mode`: Output mode (fanged/defanged)

## Troubleshooting

### Common Issues

1. **"No email message object provided"**
   - File is not a valid email format
   - File is corrupted or empty
   - Try with a known good .eml file

2. **"Missing dependencies"**
   - Install required packages: `pip install -r requirements.txt`
   - For full functionality: `pip install PyMuPDF Pillow opencv-python`

3. **VirusTotal API issues**
   - Verify API key is correct
   - Check rate limits (4 requests/minute for free accounts)
   - Ensure network connectivity

4. **QR code analysis not working**
   - Install: `pip install PyMuPDF Pillow opencv-python`
   - Ensure PDF contains actual QR codes

### Debug Mode

```bash
# Debug email parsing issues
python debug_parser.py email.eml

# Check module availability
python -c "from analyzer import *; print('All modules loaded')"
```

## Security Considerations

### Safe Usage
- **Defanged Mode**: Use when sharing results to prevent accidental clicks
- **Isolated Environment**: Run in VM or sandboxed environment for suspicious emails
- **API Key Security**: Keep VirusTotal API key confidential

### Limitations
- **Static Analysis Only**: Does not execute attachments or follow links
- **Point-in-Time**: Results reflect reputation at time of analysis
- **False Positives**: Manual verification recommended for critical decisions

## Contributing

### Development Setup

```bash
git clone https://github.com/your-repo/phishalyzer.git
cd phishalyzer
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

### Adding Analysis Modules

1. Create new module in `analyzer/` directory
2. Import in `phishalyzer.py`
3. Add to analysis workflow in `run_analysis()`
4. Update `compile_summary_findings()` for executive summary

### Testing

```bash
# Test with sample emails
python phishalyzer.py samples/test_email.eml

# Run debug scripts
python debug_parser.py samples/test_email.eml
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- VirusTotal API for reputation data
- PyMuPDF for PDF analysis capabilities
- OpenCV for QR code detection
- Python email library for message parsing

## Support

For issues, feature requests, or questions:
1. Check the troubleshooting section above
2. Review existing issues on GitHub
3. Create a new issue with detailed information

---

**⚠️ Disclaimer**: Phishalyzer is a static analysis tool for educational and defensive purposes. Always exercise caution when analyzing suspicious emails and never execute or interact with potentially malicious content.