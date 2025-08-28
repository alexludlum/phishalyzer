# Phishalyzer

A comprehensive email security analysis tool designed to detect phishing attempts, malware, and security threats in email messages. Phishalyzer performs multi-layered analysis of email headers, content, URLs, attachments, and embedded elements to provide detailed security assessments.

## Overview

Phishalyzer is a Python-based static analysis tool that helps security professionals, IT administrators, and researchers analyze suspicious emails for potential threats. The tool provides automated detection of common phishing techniques, malware delivery methods, and social engineering attempts while maintaining a safe analysis environment.

## Core Features

### Multi-Layered Analysis
- **Header Analysis**: Authentication verification (SPF, DKIM, DMARC) and routing examination
- **IP Address Analysis**: Geolocation mapping and reputation checking via VirusTotal
- **URL Analysis**: Domain reputation assessment and malicious link detection from email body and HTML links
- **Email Body Analysis**: Phishing content detection and social engineering pattern recognition
- **Attachment Analysis**: File type validation, extension spoofing detection, and content analysis
- **QR Code Analysis**: Extraction and analysis of QR codes from PDF and image attachments
- **Attachment Content Analysis**: Text extraction and phishing pattern detection from documents

### Advanced Threat Detection
- File extension spoofing detection (executables disguised as documents)
- Business Email Compromise (BEC) pattern recognition
- Credential harvesting attempt identification
- Payment redirect scam detection
- Executive impersonation analysis
- Malicious QR code identification
- URL extraction from HTML links and form actions
- Comprehensive attachment content scanning

### Risk Assessment
- Four-tier risk classification system (CRITICAL, HIGH, MEDIUM, LOW)
- Comprehensive threat categorization
- Executive summary generation with actionable intelligence
- Indicators of Compromise (IOC) tracking
- Professional report generation for customer delivery

### User Interface
- Interactive command-line menu system
- Color-coded threat level indicators
- Defanged output for safe URL and IP display
- Detailed analysis breakdowns
- Universal terminal compatibility
- Comprehensive report generation

## Installation

### Requirements
- Python 3.7 or higher
- Internet connection for VirusTotal API integration

### Basic Installation
```bash
git clone https://github.com/alexludlum/phishalyzer.git
cd phishalyzer
pip install -r requirements.txt
```

### Required Dependencies
```
extract-msg>=0.41.0    # Microsoft Outlook MSG file parsing
dnspython>=2.3.0       # DNS lookups and validation
requests>=2.28.0       # HTTP requests for API integration
email-validator>=2.0.0 # Email address validation
PyMuPDF>=1.23.0        # PDF analysis and QR code extraction
Pillow>=10.0.0         # Image processing
opencv-python>=4.8.0   # QR code detection
pytesseract>=0.3.10    # OCR capabilities for image text extraction
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
- **Defanged Mode**: Display URLs and IPs in safe format (https[:]//malicious[.]com)

## Features

### Analysis Capabilities
- Comprehensive header authentication analysis
- Complete email routing hop examination
- IP address reputation verification
- URL extraction from email body and HTML content
- Attachment file type verification and content analysis
- QR code detection and URL analysis
- Phishing content pattern recognition
- Extension spoofing detection

### Reporting
- Executive summary generation
- Comprehensive plaintext reports
- Risk assessment with supporting evidence
- IOC extraction and categorization

### Security Features
- Static analysis only (no code execution)
- Safe defanged output option
- Rate limiting for API calls
- Error handling and recovery
- No browser storage dependencies

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
│   ├── parser.py              # Email file parsing
│   ├── header_analyzer.py     # Header authentication analysis
│   ├── ioc_extractor.py       # IP address analysis
│   ├── url_extractor.py       # URL extraction and analysis
│   ├── body_analyzer.py       # Email content analysis
│   ├── attachment_analyzer.py # File analysis and threat detection
│   ├── attachment_content_analyzer.py # Document content analysis
│   ├── qr_analyzer.py         # QR code detection and analysis
│   ├── defanger.py           # Safe output formatting
│   ├── compatible_output.py   # Universal terminal support
│   └── report_generator.py    # Professional report generation
├── requirements.txt            # Python dependencies
└── README.md                  # Documentation
```

## Disclaimer

Phishalyzer is designed for educational and defensive security purposes. Users should exercise caution when analyzing suspicious emails and never execute or interact with potentially malicious content. Always follow your organization's security policies and procedures when handling suspicious emails.