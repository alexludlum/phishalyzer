# Phishalyzer

A comprehensive email security analysis tool designed to detect phishing attempts, malware, and security threats in email messages. Phishalyzer performs multi-layered analysis of email headers, content, URLs, attachments, and embedded elements to provide detailed security assessments.

## Overview

Phishalyzer is a Python-based static analysis tool that helps security professionals, IT administrators, and researchers analyze suspicious emails for potential threats. The tool provides automated detection of common phishing techniques, malware delivery methods, and social engineering attempts while maintaining a safe analysis environment.

## Core Features

### Multi-Layered Analysis
- **Header Analysis**: Authentication verification (SPF, DKIM, DMARC) and routing examination
- **IP Address Analysis**: Geolocation mapping and reputation checking via VirusTotal
- **URL Analysis**: Domain reputation assessment and malicious link detection
- **Email Body Analysis**: Phishing content detection and social engineering pattern recognition
- **Attachment Analysis**: File type validation, extension spoofing detection, and content analysis
- **QR Code Analysis**: Extraction and analysis of QR codes from PDF attachments

### Advanced Threat Detection
- File extension spoofing detection (executables disguised as documents)
- Business Email Compromise (BEC) pattern recognition
- Credential harvesting attempt identification
- Payment redirect scam detection
- Executive impersonation analysis
- Malicious QR code identification

### Risk Assessment
- Four-tier risk classification system (CRITICAL, HIGH, MEDIUM, LOW)
- Comprehensive threat categorization
- Actionable intelligence reporting
- Indicators of Compromise (IOC) tracking
- Executive summary generation

### User Interface
- Interactive command-line menu system
- Color-coded threat level indicators
- Defanged output for safe URL and IP display
- Detailed analysis breakdowns
- Universal terminal compatibility

## Installation

### Requirements
- Python 3.7 or higher
- Internet connection for VirusTotal API integration

### Basic Installation
```bash
git clone https://github.com/your-repo/phishalyzer.git
cd phishalyzer
pip install -r requirements.txt
```

### Required Dependencies
```
extract-msg        # Microsoft Outlook MSG file parsing
dnspython         # DNS lookups and validation
requests          # HTTP requests for API integration
email-validator   # Email address validation
```

### Optional Dependencies
```bash
# Enhanced document analysis
pip install PyMuPDF python-docx openpyxl python-pptx

# QR code detection and image processing
pip install opencv-python Pillow

# OCR capabilities for image text extraction
pip install pytesseract
```

## Quick Start

### Basic Usage
```bash
# Analyze a single email file
python phishalyzer.py /path/to/email.eml

# Interactive mode
python phishalyzer.py
```

### Supported File Formats
- EML files (standard email format)
- MSG files (Microsoft Outlook format)
- Raw RFC822 email messages

## Configuration

### VirusTotal Integration
1. Register for a free account at VirusTotal
2. Obtain your API key from the VirusTotal dashboard
3. Configure the API key through the Phishalyzer menu system

### Output Modes
- **Fanged Mode**: Display URLs and IPs in normal format
- **Defanged Mode**: Display URLs and IPs in safe format (https[:]//example[.]com)

## Analysis Workflow

### Header Analysis
Examines email headers for authentication failures, routing anomalies, and sender validation issues. Identifies missing or failed SPF, DKIM, and DMARC records that may indicate spoofing attempts.

### Content Analysis
Scans email body content for phishing keywords, social engineering techniques, and suspicious patterns. Analyzes both plain text and HTML content for malicious indicators.

### URL Analysis
Extracts URLs from headers, body content, and attachments. Groups URLs by domain and checks reputation against VirusTotal database. Identifies redirects and suspicious link patterns.

### Attachment Analysis
Performs deep analysis of email attachments including file type validation, magic number verification, and content extraction. Detects file extension spoofing and analyzes embedded content for threats.

### Risk Assessment
Aggregates findings from all analysis modules to generate comprehensive risk scores and threat categorizations. Provides executive-level summaries for decision making.

## Understanding Results

### Risk Categories
- **CRITICAL**: Immediate threats requiring urgent action
- **HIGH**: Significant security concerns requiring investigation
- **MEDIUM**: Moderate risks requiring attention
- **LOW**: Minor concerns for awareness

### Threat Types
- **Malicious Indicators**: VirusTotal-confirmed threats
- **Suspicious Indicators**: Potentially harmful content
- **Warning Factors**: Items requiring manual review
- **Critical Threats**: Immediate security risks

## Use Cases

### Security Operations
- Incident response and threat hunting
- Email security monitoring
- Phishing campaign analysis
- Threat intelligence gathering

### IT Administration
- Email security assessment
- User awareness training support
- Policy compliance verification
- Security control validation

### Research and Education
- Malware analysis training
- Phishing technique research
- Security awareness demonstrations
- Academic cybersecurity studies

## Safety and Security

### Static Analysis Only
Phishalyzer performs static analysis without executing attachments or following links, maintaining a safe analysis environment.

### Defanged Output
URLs and IP addresses can be displayed in defanged format to prevent accidental clicks during analysis review.

### Isolated Environment
Recommended for use in virtual machines or sandboxed environments when analyzing highly suspicious content.

## Limitations

- Point-in-time analysis based on current threat intelligence
- Requires internet connectivity for VirusTotal integration
- Static analysis may miss dynamic or time-based threats
- Manual verification recommended for critical security decisions

## Project Structure

```
phishalyzer/
├── phishalyzer.py              # Main application
├── analyzer/                   # Core analysis modules
├── requirements.txt            # Python dependencies
├── samples/                    # Sample email files
└── README.md                   # Documentation
```

## Contributing

Contributions are welcome through pull requests. Please ensure code follows the existing style and includes appropriate testing.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Disclaimer

Phishalyzer is designed for educational and defensive security purposes. Users should exercise caution when analyzing suspicious emails and never execute or interact with potentially malicious content. Always follow your organization's security policies and procedures when handling suspicious emails.