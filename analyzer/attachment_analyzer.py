import re
import time
import hashlib
import requests
import mimetypes
import base64
from email.message import EmailMessage

# Import compatible output system
try:
    from .compatible_output import output, print_status, print_attachment_header, print_filename, print_hash, print_risk_level, print_vt_verdict
    COMPATIBLE_OUTPUT = True
except ImportError:
    COMPATIBLE_OUTPUT = False

from . import qr_analyzer
from . import defanger

# Import the content analysis module
try:
    from . import attachment_content_analyzer
    CONTENT_ANALYSIS_AVAILABLE = True
except ImportError:
    CONTENT_ANALYSIS_AVAILABLE = False

# Network request timeout settings
REQUEST_TIMEOUT = 10
MAX_RETRIES = 3

# File size limits
MAX_ATTACHMENT_SIZE = 100 * 1024 * 1024  # 100MB
LARGE_FILE_WARNING_SIZE = 10 * 1024 * 1024  # 10MB

# ENHANCED File magic number signatures for content-based detection
FILE_SIGNATURES = {
    'pdf': [
        b'%PDF-',  # PDF files - ANY version
        b'\x25\x50\x44\x46\x2D',  # PDF hex representation
    ],
    'msg': [
        b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1',  # Microsoft Compound Document (MSG/DOC/XLS)
    ],
    'jpeg': [
        b'\xff\xd8\xff\xe0',  # JPEG JFIF
        b'\xff\xd8\xff\xe1',  # JPEG EXIF
        b'\xff\xd8\xff\xe2',  # JPEG FPXR
        b'\xff\xd8\xff\xe3',  # JPEG JFXX
        b'\xff\xd8\xff\xe8',  # JPEG SPIFF
        b'\xff\xd8\xff\xdb',  # JPEG
    ],
    'png': [
        b'\x89PNG\r\n\x1a\n',  # PNG
    ],
    'gif': [
        b'GIF87a',  # GIF87a
        b'GIF89a',  # GIF89a
    ],
    'bmp': [
        b'BM',  # Windows Bitmap
    ],
    'zip': [
        b'PK\x03\x04',  # ZIP, also used by docx, xlsx, etc.
        b'PK\x05\x06',  # Empty ZIP
        b'PK\x07\x08',  # ZIP with data descriptor
    ],
    'rar': [
        b'Rar!\x1a\x07\x00',  # RAR archive v1.5+
        b'Rar!\x1a\x07\x01\x00',  # RAR archive v5.0+
    ],
    '7z': [
        b'7z\xbc\xaf\x27\x1c',  # 7-Zip
    ],
    'doc': [
        b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1',  # Microsoft Office (legacy) - same as MSG
    ],
    'exe': [
        b'MZ',  # DOS/Windows executable
    ],
    'elf': [
        b'\x7fELF',  # Linux executable
    ],
    'dmg': [
        b'x\x01\x73\x0d\x62\x62\x60',  # macOS disk image
    ],
    'iso': [
        b'CD001',  # ISO 9660
    ],
    'tar': [
        b'ustar\x00',  # TAR archive
        b'ustar  \x00',  # TAR archive variant
    ],
    'gz': [
        b'\x1f\x8b',  # GZIP
    ],
    'bz2': [
        b'BZ',  # BZIP2
    ],
    'xml': [
        b'<?xml',  # XML files (including SVG)
        b'\xef\xbb\xbf<?xml',  # XML with BOM
    ],
    'svg': [
        b'<svg',  # SVG files
        b'\xef\xbb\xbf<svg',  # SVG with BOM
    ],
    'html': [
        b'<!DOCTYPE html',
        b'<html',
        b'<HTML',
    ],
    'rtf': [
        b'{\\rtf',  # Rich Text Format
    ],
    'ps1': [
        b'#!',  # PowerShell scripts often start with shebang
        b'<#',  # PowerShell comment block
    ],
    'bat': [
        b'@echo',  # Common batch file start
        b'echo',   # Batch echo command
        b'rem',    # Batch comment
        b'REM',    # Batch comment uppercase
    ],
    'vbs': [
        b'Dim ',      # VBScript Dim statement
        b'dim ',      # VBScript dim statement lowercase
        b"'",         # VBScript comment (might be too generic)
    ],
    'js': [
        b'function',  # JavaScript function
        b'var ',      # JavaScript var
        b'let ',      # JavaScript let
        b'const ',    # JavaScript const
    ]
}

# Suspicious file extensions that commonly contain malware
SUSPICIOUS_EXTENSIONS = {
    'exe', 'scr', 'bat', 'cmd', 'com', 'pif', 'vbs', 'js', 'jar', 'app',
    'deb', 'pkg', 'rpm', 'dmg', 'iso', 'img', 'msi', 'ps1', 'psm1',
    'vb', 'vbe', 'ws', 'wsf', 'wsh', 'hta', 'cpl', 'msc', 'gadget'
}

# Extensions that can contain macros or be weaponized
MACRO_EXTENSIONS = {
    'doc', 'docx', 'docm', 'dot', 'dotx', 'dotm', 'xls', 'xlsx', 'xlsm',
    'xlt', 'xltx', 'xltm', 'xlam', 'ppt', 'pptx', 'pptm', 'pot', 'potx',
    'potm', 'ppam', 'pps', 'ppsx', 'ppsm', 'sldx', 'sldm'
}

# Archive formats that could contain malicious files
ARCHIVE_EXTENSIONS = {
    'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'cab', 'ace', 'arj',
    'lzh', 'zoo', 'arc', 'pak', 'pk3', 'pk4', 'lha', 'sea', 'sit', 'sitx'
}

def detect_file_type_from_content(content, max_check_bytes=2048):
    """
    ENHANCED: Detect actual file type from content using magic numbers.
    Returns detected type or None if unknown.
    """
    if not content or len(content) < 4:
        return None
    
    # Check more bytes for better accuracy
    header = content[:max_check_bytes]
    
    # First pass: Check binary signatures (most reliable)
    for file_type, signatures in FILE_SIGNATURES.items():
        for signature in signatures:
            if header.startswith(signature):
                return file_type
    
    # Second pass: Handle text-based files that might not start exactly with signature
    try:
        # Try to decode as text for script detection
        text_content = header.decode('utf-8', errors='ignore').lower()
        
        # Enhanced script detection
        if any(keyword in text_content[:200] for keyword in [
            'function(', 'var ', 'let ', 'const ', 'document.', 'window.'
        ]):
            return 'js'
        
        if any(keyword in text_content[:200] for keyword in [
            'dim ', 'set ', 'wscript.', 'createobject(', 'msgbox'
        ]):
            return 'vbs'
        
        if any(keyword in text_content[:200] for keyword in [
            'param(', '$_', 'get-', 'invoke-', 'write-host'
        ]):
            return 'ps1'
        
        if any(keyword in text_content[:100] for keyword in [
            '@echo', 'echo off', 'rem ', 'set ', 'goto', 'if exist'
        ]):
            return 'bat'
        
        # XML/SVG detection
        if text_content.strip().startswith('<?xml') or text_content.strip().startswith('<svg'):
            if '<svg' in text_content[:500]:
                return 'svg'
            else:
                return 'xml'
        
    except:
        pass
    
    return None

def detect_extension_spoofing(filename, detected_type, claimed_content_type):
    """
    ENHANCED: Detect if file extension doesn't match actual content.
    Returns (is_spoofed, risk_description, threat_level)
    """
    if not filename or not detected_type:
        return False, None, "low"
    
    filename_lower = filename.lower()
    file_ext = filename_lower.split('.')[-1] if '.' in filename_lower else ''
    
    # Define expected extensions for each detected type
    expected_extensions = {
        'pdf': ['pdf'],
        'msg': ['msg', 'eml'],  # MSG files might legitimately be renamed to .eml
        'jpeg': ['jpg', 'jpeg'],
        'png': ['png'],
        'gif': ['gif'],
        'bmp': ['bmp'],
        'zip': ['zip', 'docx', 'xlsx', 'pptx', 'odt', 'ods', 'odp'],
        'exe': ['exe', 'com', 'scr'],
        'svg': ['svg', 'xml'],
        'xml': ['xml', 'svg'],
        'html': ['html', 'htm'],
        'rtf': ['rtf'],
        'rar': ['rar'],
        '7z': ['7z'],
        'tar': ['tar'],
        'gz': ['gz', 'tgz'],
        'bz2': ['bz2'],
        'elf': ['bin', 'out', ''],
        'dmg': ['dmg'],
        'iso': ['iso'],
        'js': ['js'],
        'vbs': ['vbs'],
        'ps1': ['ps1'],
        'bat': ['bat', 'cmd'],
        'doc': ['doc', 'xls', 'ppt', 'docx', 'xlsx', 'pptx'],  # OLE format
    }
    
    expected_exts = expected_extensions.get(detected_type, [])
    
    if expected_exts and file_ext not in expected_exts:
        # This is spoofing - determine threat level
        threat_level = "medium"  # default
        
        # CRITICAL THREAT: Executables disguised as documents
        if detected_type in ['exe', 'bat', 'vbs', 'ps1', 'js']:
            if file_ext in ['pdf', 'doc', 'docx', 'txt', 'msg', 'eml', 'jpg', 'png']:
                threat_level = "critical"
                risk_desc = f"CRITICAL: {detected_type.upper()} executable disguised as .{file_ext} file"
            else:
                threat_level = "high"
                risk_desc = f"HIGH RISK: {detected_type.upper()} executable with .{file_ext} extension"
        
        # HIGH THREAT: PDF with potential QR codes disguised as other formats
        elif detected_type == 'pdf':
            if file_ext in ['msg', 'eml', 'doc', 'docx', 'txt']:
                threat_level = "high"
                risk_desc = f"HIGH RISK: PDF disguised as .{file_ext} - likely contains malicious links/QR codes"
            else:
                threat_level = "medium"
                risk_desc = f"MEDIUM RISK: PDF content disguised as .{file_ext} file"
        
        # HIGH THREAT: Archives disguised as documents
        elif detected_type in ['zip', 'rar', '7z']:
            if file_ext in ['pdf', 'doc', 'docx', 'txt', 'msg', 'eml']:
                threat_level = "high"
                risk_desc = f"HIGH RISK: {detected_type.upper()} archive disguised as .{file_ext} - may contain malware"
            else:
                threat_level = "medium"
                risk_desc = f"Archive content ({detected_type.upper()}) disguised as .{file_ext} file"
        
        # MEDIUM THREAT: Office documents with wrong extensions
        elif detected_type in ['msg', 'doc']:
            if file_ext in ['pdf', 'txt', 'jpg', 'png']:
                threat_level = "medium"
                risk_desc = f"MEDIUM RISK: MSG/Office document disguised as .{file_ext} file"
            else:
                threat_level = "low"
                risk_desc = f"Office document with .{file_ext} extension (possibly renamed)"
        
        # Default cases with enhanced descriptions
        else:
            risk_descriptions = {
                'jpeg': f"Image content ({detected_type.upper()}) disguised as .{file_ext} file",
                'png': f"Image content ({detected_type.upper()}) disguised as .{file_ext} file",
                'html': f"HTML content disguised as .{file_ext} file - potential phishing page",
                'svg': f"SVG content disguised as .{file_ext} file - potential script injection",
            }
            
            risk_desc = risk_descriptions.get(detected_type, 
                f"{detected_type.upper()} content disguised as .{file_ext} file")
        
        return True, risk_desc, threat_level
    
    return False, None, "low"

def analyze_file_by_content(attachment_data, api_key):
    """
    ENHANCED: Analyze attachment based on actual content with improved spoofing detection.
    Returns analysis results including QR codes, embedded content, etc.
    """
    try:
        content = attachment_data.get('content', b'')
        filename = attachment_data.get('filename', 'unknown')
        
        if not content:
            return {
                'content_analysis': None,
                'qr_analysis': None,
                'detected_type': None,
                'spoofing_detected': False,
                'threat_level': 'low'
            }
        
        # Detect actual file type from content
        detected_type = detect_file_type_from_content(content)
        
        # ENHANCED: Check for extension spoofing with threat level
        is_spoofed, spoof_description, threat_level = detect_extension_spoofing(
            filename, detected_type, attachment_data.get('content_type'))
        
        results = {
            'detected_type': detected_type,
            'spoofing_detected': is_spoofed,
            'spoof_description': spoof_description,
            'threat_level': threat_level,
            'content_analysis': None,
            'qr_analysis': None
        }
        
        # ENHANCED: Special alerting for high-risk combinations
        if is_spoofed and detected_type == 'pdf' and filename.lower().endswith('.msg'):
            if COMPATIBLE_OUTPUT:
                print_status(f"SECURITY ALERT: PDF file disguised as MSG attachment: {filename}", "error")
                print_status("This is a common phishing technique - PDF likely contains malicious QR codes or links", "warning")
            else:
                print(f"SECURITY ALERT: PDF file disguised as MSG attachment: {filename}")
                print("This is a common phishing technique - PDF likely contains malicious QR codes or links")
        
        # Perform content-specific analysis based on ACTUAL file type
        if detected_type == 'pdf':
            # PDF analysis regardless of filename extension
            try:
                qr_analysis = qr_analyzer.analyze_pdf_qr_codes(attachment_data, api_key)
                results['qr_analysis'] = qr_analysis
                
                # ENHANCED: If QR codes found in spoofed PDF, escalate threat level
                if qr_analysis.get('qr_found') and is_spoofed:
                    if COMPATIBLE_OUTPUT:
                        print_status(f"CRITICAL: Spoofed PDF contains QR codes - HIGH PHISHING RISK", "error")
                    else:
                        print(f"CRITICAL: Spoofed PDF contains QR codes - HIGH PHISHING RISK")
                    
                    results['threat_level'] = 'critical'
                    results['content_analysis'] = "CRITICAL: Spoofed PDF with QR codes detected"
                elif is_spoofed:
                    if COMPATIBLE_OUTPUT:
                        print_status(f"WARNING: PDF content found in file with .{safe_get_file_extension(filename)} extension", "warning")
                    else:
                        print(f"WARNING: PDF content found in file with .{safe_get_file_extension(filename)} extension")
                    
            except Exception as e:
                if COMPATIBLE_OUTPUT:
                    print_status(f"Error analyzing PDF content: {e}", "error")
                else:
                    print(f"Error analyzing PDF content: {e}")
        
        elif detected_type in ['jpeg', 'png', 'gif', 'bmp', 'svg']:
            # Image analysis - ENHANCED with QR code detection
            try:
                # First check for QR codes
                qr_analysis = qr_analyzer.analyze_image_qr_codes(attachment_data, api_key)
                results['qr_analysis'] = qr_analysis
                
                # ENHANCED: If QR codes found, escalate threat level
                if qr_analysis.get('qr_found'):
                    qr_results = qr_analysis.get('qr_results', [])
                    malicious_qr = any(qr.get('verdict') == 'malicious' for qr in qr_results if isinstance(qr, dict))
                    suspicious_qr = any(qr.get('verdict') == 'suspicious' for qr in qr_results if isinstance(qr, dict))
                    
                    if malicious_qr:
                        if COMPATIBLE_OUTPUT:
                            print_status(f"CRITICAL: Image contains malicious QR codes - HIGH PHISHING RISK", "error")
                        else:
                            print(f"CRITICAL: Image contains malicious QR codes - HIGH PHISHING RISK")
                        
                        results['threat_level'] = 'critical'
                        results['content_analysis'] = "CRITICAL: Image with malicious QR codes detected"
                    elif suspicious_qr:
                        if COMPATIBLE_OUTPUT:
                            print_status(f"WARNING: Image contains suspicious QR codes", "warning")
                        else:
                            print(f"WARNING: Image contains suspicious QR codes")
                        
                        results['threat_level'] = 'high'
                        results['content_analysis'] = "HIGH RISK: Image with suspicious QR codes detected"
                    else:
                        results['threat_level'] = 'high'  # Any QR code is high risk
                        results['content_analysis'] = "HIGH RISK: Image contains QR codes"
                
                # Handle spoofing for images WITHOUT QR codes
                elif is_spoofed:
                    if detected_type == 'svg':
                        results['content_analysis'] = "SVG file with suspicious extension - potential script injection risk"
                    else:
                        results['content_analysis'] = f"Image file ({detected_type.upper()}) with suspicious extension"
                                
            except Exception as e:
                if COMPATIBLE_OUTPUT:
                    print_status(f"Error analyzing image content: {e}", "error")
                else:
                    print(f"Error analyzing image content: {e}")
        
        elif detected_type in ['zip', 'rar', '7z']:
            # Archive analysis
            try:
                if is_spoofed:
                    results['content_analysis'] = f"Archive content ({detected_type.upper()}) with suspicious extension - could contain hidden malware"
                    
            except Exception as e:
                if COMPATIBLE_OUTPUT:
                    print_status(f"Error analyzing archive content: {e}", "error")
                else:
                    print(f"Error analyzing archive content: {e}")
        
        elif detected_type in ['exe', 'elf', 'bat', 'vbs', 'ps1', 'js']:
            # Executable analysis
            try:
                results['content_analysis'] = f"CRITICAL: Executable content ({detected_type.upper()}) detected"
                if is_spoofed:
                    results['content_analysis'] += f" disguised as .{safe_get_file_extension(filename)} file"
                    
            except Exception as e:
                if COMPATIBLE_OUTPUT:
                    print_status(f"Error analyzing executable content: {e}", "error")
                else:
                    print(f"Error analyzing executable content: {e}")
        
        elif detected_type in ['doc', 'msg']:
            # Office document analysis
            try:
                if is_spoofed:
                    results['content_analysis'] = "Office document with suspicious extension - potential macro/exploit risk"
                    
            except Exception as e:
                if COMPATIBLE_OUTPUT:
                    print_status(f"Error analyzing Office document: {e}", "error")
                else:
                    print(f"Error analyzing Office document: {e}")
        
        elif detected_type in ['html', 'xml']:
            # Markup document analysis
            try:
                if is_spoofed:
                    results['content_analysis'] = f"HTML/XML content with suspicious extension - potential script injection risk"
                    
            except Exception as e:
                if COMPATIBLE_OUTPUT:
                    print_status(f"Error analyzing markup content: {e}", "error")
                else:
                    print(f"Error analyzing markup content: {e}")
        
        return results
        
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error in content-based analysis: {e}", "error")
        else:
            print(f"Error in content-based analysis: {e}")
        return {
            'detected_type': None,
            'spoofing_detected': False,
            'spoof_description': None,
            'threat_level': 'low',
            'content_analysis': f"Analysis error: {e}",
            'qr_analysis': None
        }

def safe_get_file_extension(filename):
    """Safely extract file extension from filename with error handling."""
    try:
        if not filename or not isinstance(filename, str):
            return ""
        
        # Handle double extensions like .tar.gz, .doc.exe, etc.
        parts = str(filename).lower().split('.')
        if len(parts) > 1:
            return parts[-1]
        return ""
    except Exception:
        return ""

def safe_categorize_attachment_risk(filename, content_type, size, detected_type=None, is_spoofed=False, spoof_description=None, threat_level="low", content_analysis=None):
    """ENHANCED: Categorize attachment risk with comprehensive error handling and CRITICAL threat-level support."""
    try:
        if not filename:
            return "unknown", "No filename provided"
        
        extension = safe_get_file_extension(filename)
        risk_factors = []
        risk_level = "low"
        
        # HIGHEST PRIORITY: Critical threats from spoofing
        if threat_level == "critical":
            risk_level = "critical"
            risk_factors.append(f"CRITICAL THREAT: {spoof_description}")
        
        # SECOND PRIORITY: Content analysis results
        elif content_analysis and content_analysis.get('risk_score', 0) >= 70:
            risk_factors.append("PHISHING CONTENT: High-risk phrases detected")
            risk_level = "high"
        elif content_analysis and content_analysis.get('risk_score', 0) >= 40:
            risk_factors.append("Suspicious content detected")
            if risk_level == "low":
                risk_level = "medium"
        
        # THIRD PRIORITY: High-level spoofing
        elif threat_level == "high":
            risk_factors.append(f"HIGH RISK SPOOFING: {spoof_description}")
            risk_level = "high"
        
        # Check actual detected content type vs claimed extension
        if detected_type:
            if detected_type in ['exe', 'elf', 'bat', 'vbs', 'ps1', 'js']:
                if not any("executable" in factor.lower() or "critical" in factor.lower() 
                          for factor in risk_factors):
                    risk_factors.append(f"Executable content detected ({detected_type.upper()})")
                    if risk_level not in ["critical", "high"]:
                        risk_level = "high"
            elif detected_type == 'pdf' and extension != 'pdf':
                if not any("pdf" in factor.lower() for factor in risk_factors):
                    risk_factors.append(f"PDF content with .{extension} extension")
                    if risk_level not in ["critical", "high"]:
                        risk_level = "high"
            elif detected_type in ['doc', 'msg', 'zip'] and extension not in MACRO_EXTENSIONS and extension not in ARCHIVE_EXTENSIONS:
                if not any("office" in factor.lower() or "archive" in factor.lower() for factor in risk_factors):
                    risk_factors.append(f"Office/Archive content with unexpected .{extension} extension")
                    if risk_level == "low":
                        risk_level = "medium"
        
        # Add medium-level spoofing if not already covered
        if threat_level == "medium" and not any("spoofing" in factor.lower() or "critical" in factor.lower() 
                                               for factor in risk_factors):
            risk_factors.append(f"EXTENSION SPOOFING: {spoof_description}")
            if risk_level == "low":
                risk_level = "medium"
        
        # Check for suspicious extensions (based on filename)
        try:
            if extension in SUSPICIOUS_EXTENSIONS:
                if not any("executable" in factor.lower() for factor in risk_factors):
                    risk_factors.append(f"Executable file type (.{extension})")
                    if risk_level not in ["critical", "high"]:
                        risk_level = "high"
            elif extension in MACRO_EXTENSIONS:
                risk_factors.append(f"Macro-capable document (.{extension})")
                if risk_level == "low":
                    risk_level = "medium"
            elif extension in ARCHIVE_EXTENSIONS:
                risk_factors.append(f"Archive file (.{extension}) - contents unknown")
                if risk_level == "low":
                    risk_level = "medium"
        except Exception:
            pass
        
        # Content-Type mismatch detection
        try:
            if content_type and filename:
                expected_mime = mimetypes.guess_type(filename)[0]
                if expected_mime and str(content_type).lower() != str(expected_mime).lower():
                    risk_factors.append("MIME type mismatch (possible spoofing)")
                    if risk_level == "low":
                        risk_level = "medium"
        except Exception:
            pass
        
        if not risk_factors:
            risk_factors.append("Standard file type")
        
        return risk_level, "; ".join(risk_factors)
        
    except Exception as e:
        return "unknown", f"Error analyzing risk: {e}"

# Keep all your existing functions for VirusTotal, file extraction, etc.
# (I'll include the key ones but assume you have the rest from your original code)

def safe_extract_attachments(msg_obj):
    """ENHANCED: Extract attachment information with MSG-specific handling."""
    attachments = []
    
    try:
        if not msg_obj:
            return attachments
        
        # Check if this is a non-multipart message (could be conversion issue)
        if not hasattr(msg_obj, 'is_multipart') or not msg_obj.is_multipart():
            # Try to detect if this should have been multipart
            subject = msg_obj.get('Subject', '')
            if 'voice message' in subject.lower() or 'attachment' in subject.lower():
                print("Warning: Non-multipart message but subject suggests attachments")
                print("This might indicate MSG conversion issues")
            return attachments
        
        if not hasattr(msg_obj, 'walk'):
            return attachments
        
        for part in msg_obj.walk():
            try:
                if not hasattr(part, 'get_content_disposition'):
                    continue
                
                disposition = part.get_content_disposition()
                
                # FIXED: Also check for inline attachments that might be treated as attachments
                if disposition in ['attachment', 'inline']:
                    try:
                        filename = part.get_filename() if hasattr(part, 'get_filename') else None
                        content_type = part.get_content_type() if hasattr(part, 'get_content_type') else 'application/octet-stream'
                        
                        # FIXED: Better filename handling
                        if not filename or filename.strip() == '':
                            # Try to extract from Content-Type or Content-Disposition
                            try:
                                cd_header = part.get('Content-Disposition', '')
                                filename_match = re.search(r'filename[*]?=(?:"([^"]+)"|([^;\s]+))', cd_header)
                                if filename_match:
                                    filename = filename_match.group(1) or filename_match.group(2)
                                else:
                                    filename = f"unnamed_attachment_{len(attachments)+1}"
                            except:
                                filename = f"unnamed_attachment_{len(attachments)+1}"
                        
                        # Get file content safely with better error handling
                        content = b""
                        size = 0
                        
                        try:
                            if hasattr(part, 'get_payload'):
                                content = part.get_payload(decode=True)
                                if content is None:
                                    # Try without decoding
                                    raw_content = part.get_payload()
                                    if isinstance(raw_content, str):
                                        # This might be base64 encoded
                                        try:
                                            import base64
                                            content = base64.b64decode(raw_content)
                                        except:
                                            content = raw_content.encode('utf-8', errors='replace')
                                    else:
                                        content = b""
                                
                                # Check for oversized attachments
                                if content and len(content) > MAX_ATTACHMENT_SIZE:
                                    print(f"Warning: Attachment {filename} is very large ({len(content) // (1024*1024)}MB), truncating for analysis")
                                    content = content[:MAX_ATTACHMENT_SIZE]
                                    
                        except Exception as e:
                            print(f"Warning: Could not extract content for {filename}: {e}")
                            content = b""
                        
                        size = len(content) if content else 0
                        
                        # FIXED: Only add valid attachments
                        if filename and (size > 0 or disposition == 'attachment'):
                            attachments.append({
                                'filename': filename,
                                'content_type': content_type,
                                'size': size,
                                'content': content
                            })
                        
                    except Exception as e:
                        print(f"Warning: Error processing attachment: {e}")
                        # Don't add error attachments that confuse the analysis
                        continue
                        
            except Exception as e:
                print(f"Warning: Error processing email part: {e}")
                continue
    
    except Exception as e:
        print(f"Error extracting attachments: {e}")
    
    return attachments

def safe_calculate_file_hash(content):
    """Calculate SHA256 hash with error handling."""
    try:
        if not content:
            return "N/A"
        
        if isinstance(content, str):
            content = content.encode('utf-8')
        elif not isinstance(content, (bytes, bytearray)):
            return "N/A"
        
        return hashlib.sha256(content).hexdigest()
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Warning: Could not calculate file hash: {e}", "warning")
        else:
            print(f"Warning: Could not calculate file hash: {e}")
        return "N/A"

def safe_determine_risk_from_qr(qr_analysis):
    """Determine risk level from QR analysis with error handling."""
    try:
        if not qr_analysis or not isinstance(qr_analysis, dict):
            return None, None
        
        if not qr_analysis.get('qr_found'):
            return None, None
        
        qr_results = qr_analysis.get('qr_results', [])
        if not qr_results:
            return None, None
        
        # Check if any QR URLs are malicious or suspicious
        malicious_qr = any(qr.get('verdict') == 'malicious' for qr in qr_results if isinstance(qr, dict))
        suspicious_qr = any(qr.get('verdict') == 'suspicious' for qr in qr_results if isinstance(qr, dict))
        
        qr_count = len(qr_results)
        qr_text = "QR code" if qr_count == 1 else "QR codes"
        
        if malicious_qr:
            return "high", f"Malicious {qr_text} detected"
        elif suspicious_qr:
            return "high", f"Suspicious {qr_text} detected"
        else:
            return "high", f"{qr_text} detected"
            
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Warning: Error analyzing QR risk: {e}", "warning")
        else:
            print(f"Warning: Error analyzing QR risk: {e}")
        return None, None

def check_file_hash_virustotal(file_hash, api_key, cache):
    """Check file hash against VirusTotal with comprehensive error handling."""
    try:
        if not file_hash or file_hash == "N/A":
            return ("unchecked", "No file hash available")
        
        if file_hash in cache:
            return cache[file_hash]
        
        if not api_key:
            cache[file_hash] = ("unchecked", "File hash will need to be investigated manually")
            return cache[file_hash]

        # Validate API key format
        try:
            if len(api_key.strip()) < 10:
                cache[file_hash] = ("unchecked", "Invalid API key format")
                return cache[file_hash]
        except Exception:
            cache[file_hash] = ("unchecked", "API key validation error")
            return cache[file_hash]
        
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": api_key.strip()}
        
        try:
            response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        except Exception as e:
            cache[file_hash] = ("unchecked", f"Network error: {e}")
            return cache[file_hash]
        
        if response.status_code == 200:
            try:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                
                if malicious > 0:
                    comment = (f"{malicious} vendor flagged this file as malicious"
                              if malicious == 1 else
                              f"{malicious} vendors flagged this file as malicious")
                    cache[file_hash] = ("malicious", comment)
                elif suspicious > 0:
                    comment = (f"{suspicious} vendor flagged this file as suspicious"
                              if suspicious == 1 else
                              f"{suspicious} vendors flagged this file as suspicious")
                    cache[file_hash] = ("suspicious", comment)
                elif harmless > 0:
                    comment = (f"{harmless} vendor reported this file as benign"
                              if harmless == 1 else
                              f"{harmless} vendors reported this file as benign")
                    cache[file_hash] = ("benign", comment)
                else:
                    cache[file_hash] = ("unchecked", "No analysis results available")
                    
            except ValueError as e:
                cache[file_hash] = ("unchecked", f"Invalid JSON response: {e}")
            except KeyError as e:
                cache[file_hash] = ("unchecked", f"Unexpected response format: {e}")
            except Exception as e:
                cache[file_hash] = ("unchecked", f"Response parsing error: {e}")
        
        elif response.status_code == 404:
            cache[file_hash] = ("unknown", "File not found in VirusTotal database")
        elif response.status_code == 401:
            cache[file_hash] = ("unchecked", "Invalid API key")
        elif response.status_code == 403:
            cache[file_hash] = ("unchecked", "API access forbidden")
        else:
            cache[file_hash] = ("unchecked", f"HTTP {response.status_code}")
    
    except Exception as e:
        escaped_hash = output.escape(file_hash[:8]) if COMPATIBLE_OUTPUT and file_hash else 'unknown'
        if COMPATIBLE_OUTPUT:
            print_status(f"Error querying VirusTotal for file hash {escaped_hash}...: {e}", "error")
        else:
            print(f"Error querying VirusTotal for file hash {escaped_hash}...: {e}")
        cache[file_hash] = ("unchecked", "Unexpected error during check")
    
    return cache[file_hash]

def safe_format_file_size(size_bytes):
    """Format file size with error handling."""
    try:
        if not isinstance(size_bytes, (int, float)) or size_bytes < 0:
            return "Unknown size"
        
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB"]
        i = 0
        size = float(size_bytes)
        
        while size >= 1024.0 and i < len(size_names) - 1:
            size /= 1024.0
            i += 1
        
        return f"{size:.1f} {size_names[i]}"
    except Exception:
        return "Unknown size"

def analyze_attachments(msg_obj, api_key):
    """ENHANCED: Main function to analyze email attachments with CRITICAL threat detection."""
    
    try:
        attachments = safe_extract_attachments(msg_obj)
        
        if not attachments:
            if COMPATIBLE_OUTPUT:
                print_status("No attachments found in this email.", "success")
            else:
                print("No attachments found in this email.")
            print()
            return []
        
        # Display attachment count
        try:
            if COMPATIBLE_OUTPUT:
                output.print(f"Found [blue]{len(attachments)}[/blue] attachment{'s' if len(attachments) != 1 else ''}:\n")
            else:
                print(f"Found {len(attachments)} attachment(s):\n")
        except Exception:
            print(f"Found {len(attachments)} attachment(s):\n")
        
        cache = {}
        results = []
        total_qr_count = 0
        spoofing_detected = False
        phishing_content_detected = False
        critical_threats = 0  # Track critical threats
        
        # Process each attachment
        for i, attachment in enumerate(attachments, 1):
            try:
                filename = attachment.get('filename', 'unnamed_attachment')
                content_type = attachment.get('content_type', 'application/octet-stream')
                size = attachment.get('size', 0)
                content = attachment.get('content', b"")
                
                # Check for processing errors
                if 'error' in attachment:
                    escaped_error = output.escape(attachment['error']) if COMPATIBLE_OUTPUT else attachment['error']
                    if COMPATIBLE_OUTPUT:
                        print_status(f"Warning: Attachment {i} had processing errors: {escaped_error}", "warning")
                    else:
                        print(f"Warning: Attachment {i} had processing errors: {escaped_error}")
                
                # ENHANCED: Content-based analysis with threat levels
                content_analysis_results = analyze_file_by_content(attachment, api_key)
                detected_type = content_analysis_results.get('detected_type')
                is_spoofed = content_analysis_results.get('spoofing_detected', False)
                spoof_description = content_analysis_results.get('spoof_description')
                threat_level = content_analysis_results.get('threat_level', 'low')
                qr_analysis = content_analysis_results.get('qr_analysis')
                content_analysis = content_analysis_results.get('content_analysis')
                
                # Track threat levels
                if threat_level == 'critical':
                    critical_threats += 1
                
                # Phishing content analysis
                attachment_content_analysis = None
                if CONTENT_ANALYSIS_AVAILABLE:
                    try:
                        attachment_content_analysis = attachment_content_analyzer.analyze_attachment_content(attachment, api_key)
                        if attachment_content_analysis.get('findings'):
                            phishing_content_detected = True
                    except Exception as e:
                        if COMPATIBLE_OUTPUT:
                            print_status(f"Warning: Content analysis failed for {filename}: {e}", "warning")
                        else:
                            print(f"Warning: Content analysis failed for {filename}: {e}")
                
                if is_spoofed:
                    spoofing_detected = True
                
                # Calculate file hash
                file_hash = safe_calculate_file_hash(content)
                
                # ENHANCED: Risk categorization with threat levels
                base_risk_level, base_risk_reason = safe_categorize_attachment_risk(
                    filename, content_type, size, detected_type, is_spoofed, spoof_description, threat_level, attachment_content_analysis)
                
                # Check with VirusTotal if we have content
                vt_verdict = "unchecked"
                vt_comment = "No content to analyze"
                
                if content and file_hash != "N/A":
                    try:
                        vt_verdict, vt_comment = check_file_hash_virustotal(file_hash, api_key, cache)
                    except Exception as e:
                        escaped_filename = output.escape(filename) if COMPATIBLE_OUTPUT else filename
                        if COMPATIBLE_OUTPUT:
                            print_status(f"Warning: VirusTotal check failed for {escaped_filename}: {e}", "warning")
                        else:
                            print(f"Warning: VirusTotal check failed for {escaped_filename}: {e}")
                        vt_verdict, vt_comment = ("unchecked", f"VT check error: {e}")
                
                # Count QR codes from analysis
                if qr_analysis and qr_analysis.get('qr_found'):
                    qr_results = qr_analysis.get('qr_results', [])
                    total_qr_count += len(qr_results)
                
                # Determine final risk level (considering QR codes and content analysis)
                qr_risk_level, qr_risk_reason = safe_determine_risk_from_qr(qr_analysis)
                
                if qr_risk_level:
                    # QR codes detected - elevate risk
                    if base_risk_level == "low":
                        final_risk_level = qr_risk_level
                        final_risk_reason = qr_risk_reason
                    else:
                        try:
                            risk_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
                            final_risk_level = max(base_risk_level, qr_risk_level, key=lambda x: risk_levels.get(x, 0))
                            final_risk_reason = f"{base_risk_reason}; {qr_risk_reason}"
                        except Exception:
                            final_risk_level = "high"
                            final_risk_reason = f"{base_risk_reason}; {qr_risk_reason}"
                else:
                    # No QR codes
                    final_risk_level = base_risk_level
                    final_risk_reason = base_risk_reason
                
                results.append({
                    'index': i,
                    'filename': filename,
                    'content_type': content_type,
                    'size': size,
                    'hash': file_hash,
                    'detected_type': detected_type,
                    'is_spoofed': is_spoofed,
                    'spoof_description': spoof_description,
                    'threat_level': threat_level,
                    'content_analysis': content_analysis,
                    'attachment_content_analysis': attachment_content_analysis,
                    'base_risk_level': base_risk_level,
                    'final_risk_level': final_risk_level,
                    'final_risk_reason': final_risk_reason,
                    'vt_verdict': vt_verdict,
                    'vt_comment': vt_comment,
                    'qr_analysis': qr_analysis
                })
                
            except Exception as e:
                if COMPATIBLE_OUTPUT:
                    print_status(f"Error processing attachment {i}: {e}", "error")
                else:
                    print(f"Error processing attachment {i}: {e}")
                # Add error result so we don't lose track
                results.append({
                    'index': i,
                    'filename': f'error_attachment_{i}',
                    'content_type': 'unknown',
                    'size': 0,
                    'hash': 'N/A',
                    'detected_type': None,
                    'is_spoofed': False,
                    'spoof_description': None,
                    'threat_level': 'low',
                    'content_analysis': None,
                    'attachment_content_analysis': None,
                    'base_risk_level': 'unknown',
                    'final_risk_level': 'unknown',
                    'final_risk_reason': f'Processing error: {e}',
                    'vt_verdict': 'unchecked',
                    'vt_comment': f'Processing error: {e}',
                    'qr_analysis': None
                })
        
        # ENHANCED: Sort by final risk level and VT verdict with CRITICAL support
        try:
            risk_priority = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
            vt_priority = {"malicious": 0, "suspicious": 1, "unknown": 2, "unchecked": 2, "benign": 3}
            
            results.sort(key=lambda x: (
                risk_priority.get(x.get('final_risk_level', 'unknown'), 5),
                vt_priority.get(x.get('vt_verdict', 'unchecked'), 6)
            ))
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Warning: Could not sort results: {e}", "warning")
            else:
                print(f"Warning: Could not sort results: {e}")
        
        # Display results with CRITICAL threat handling
        try:
            for result in results:
                try:
                    # Attachment header with optimized format
                    if COMPATIBLE_OUTPUT:
                        print_attachment_header(result.get('index', '?'))
                    else:
                        print(f"Attachment {result.get('index', '?')}:")
                    
                    # Basic info with bullet points
                    filename = result.get('filename', 'unknown')
                    if COMPATIBLE_OUTPUT:
                        output.print(f"- Filename: [yellow]{output.escape(filename)}[/yellow]")
                    else:
                        print(f"- Filename: {filename}")
                    
                    # Type (with detected type info)
                    content_type = str(result.get('content_type', 'unknown'))
                    detected_type = result.get('detected_type')
                    
                    if detected_type and detected_type != 'unknown':
                        type_info = f"{content_type} (detected: {detected_type.upper()})"
                    else:
                        type_info = content_type
                    
                    escaped_type_info = output.escape(type_info) if COMPATIBLE_OUTPUT else type_info
                    if COMPATIBLE_OUTPUT:
                        output.print(f"- Type: {escaped_type_info}")
                    else:
                        print(f"- Type: {escaped_type_info}")
                    
                    # Size
                    if COMPATIBLE_OUTPUT:
                        output.print(f"- Size: {safe_format_file_size(result.get('size', 0))}")
                    else:
                        print(f"- Size: {safe_format_file_size(result.get('size', 0))}")
                    
                    # SHA256 (color-coded by VT verdict)
                    if result.get('hash') != "N/A":
                        hash_value = result.get('hash', 'N/A')
                        vt_verdict = result.get('vt_verdict', 'unchecked')
                        
                        # Apply defanging if enabled
                        display_hash = hash_value
                        try:
                            if defanger.should_defang():
                                display_hash = defanger.defang_text(display_hash)
                        except Exception:
                            pass
                        
                        if COMPATIBLE_OUTPUT:
                            hash_colors = {
                                "malicious": "red", "suspicious": "yellow", "benign": "green",
                                "unknown": "orange3", "unchecked": "orange3"
                            }
                            hash_color = hash_colors.get(vt_verdict, "orange3")
                            output.print(f"- SHA256: [{hash_color}]{output.escape(display_hash)}[/{hash_color}]")
                        else:
                            print(f"- SHA256: {display_hash}")
                    
                    # VirusTotal verdict
                    vt_verdict = result.get('vt_verdict', 'unchecked')
                    vt_comment = result.get('vt_comment', 'unknown')
                    
                    if COMPATIBLE_OUTPUT:
                        vt_colors = {
                            "malicious": "red", "suspicious": "yellow", "benign": "green",
                            "unknown": "orange3", "unchecked": "orange3"
                        }
                        vt_color = vt_colors.get(str(vt_verdict).lower(), "orange3")
                        output.print(f"- VirusTotal: [{vt_color}]{str(vt_verdict).upper()}[/{vt_color}] ({output.escape(str(vt_comment))})")
                    else:
                        print(f"- VirusTotal: {str(vt_verdict).upper()} ({vt_comment})")
                    
                    print()  # Blank line after basic info
                    
                    # Content analysis (optimized display)
                    if result.get('attachment_content_analysis') and CONTENT_ANALYSIS_AVAILABLE:
                        attachment_content_analyzer.display_attachment_content_analysis(
                            result.get('index', 0),
                            result.get('filename', 'unknown'),
                            result['attachment_content_analysis']
                        )
                        print()  # Blank line after content analysis
                    
                    # ENHANCED: Extension spoofing warning with threat levels
                    if result.get('is_spoofed'):
                        spoof_desc = result.get('spoof_description', 'Content type mismatch detected')
                        threat_level = result.get('threat_level', 'medium')
                        escaped_spoof = output.escape(spoof_desc) if COMPATIBLE_OUTPUT else spoof_desc
                        
                        if threat_level == 'critical':
                            if COMPATIBLE_OUTPUT:
                                output.print(f"  [red bold]CRITICAL THREAT: {escaped_spoof}[/red bold]")
                            else:
                                print(f"  CRITICAL THREAT: {escaped_spoof}")
                        elif threat_level == 'high':
                            if COMPATIBLE_OUTPUT:
                                output.print(f"  [red]HIGH RISK SPOOFING: {escaped_spoof}[/red]")
                            else:
                                print(f"  HIGH RISK SPOOFING: {escaped_spoof}")
                        else:
                            if COMPATIBLE_OUTPUT:
                                output.print(f"  [orange3]SPOOFING ALERT: {escaped_spoof}[/orange3]")
                            else:
                                print(f"  SPOOFING ALERT: {escaped_spoof}")
                        print()
                    
                    # QR Code analysis (if applicable)
                    if result.get('qr_analysis'):
                        try:
                            qr_analyzer.display_qr_analysis(result.get('index', 0), result['qr_analysis'])
                            print()
                        except Exception as e:
                            if COMPATIBLE_OUTPUT:
                                output.print(f"- [yellow]QR Analysis: Error displaying results - {e}[/yellow]")
                            else:
                                print(f"- QR Analysis: Error displaying results - {e}")
                            print()
                    
                    # CONSOLIDATED RISK ASSESSMENT with CRITICAL support
                    risk_factors = []
                    final_risk_level = result.get('final_risk_level', 'unknown')
                    
                    # Get QR code risks
                    qr_status = ""
                    if result.get('qr_analysis') and result.get('qr_analysis', {}).get('qr_found'):
                        qr_results = result.get('qr_analysis', {}).get('qr_results', [])
                        malicious_qr = any(qr.get('verdict') == 'malicious' for qr in qr_results if isinstance(qr, dict))
                        suspicious_qr = any(qr.get('verdict') == 'suspicious' for qr in qr_results if isinstance(qr, dict))
                        
                        if malicious_qr:
                            qr_status = " (Malicious QR code detected)"
                        elif suspicious_qr:
                            qr_status = " (Suspicious QR code detected)"
                        else:
                            qr_status = " (QR code detected)"
                    
                    # Get content analysis risks
                    if result.get('attachment_content_analysis') and CONTENT_ANALYSIS_AVAILABLE:
                        try:
                            content_risk_factors, content_risk_score = attachment_content_analyzer.get_attachment_content_risk_factors(
                                result['attachment_content_analysis']
                            )
                            risk_factors.extend(content_risk_factors)
                        except Exception:
                            pass
                    
                    # Get spoofing risks with enhanced threat level handling
                    if result.get('is_spoofed'):
                        spoof_desc = result.get('spoof_description', 'Extension spoofing')
                        threat_level = result.get('threat_level', 'medium')
                        if threat_level == 'critical':
                            risk_factors.append(f"CRITICAL SPOOFING: {spoof_desc}")
                        elif threat_level == 'high':
                            risk_factors.append(f"HIGH RISK SPOOFING: {spoof_desc}")
                        else:
                            risk_factors.append(f"EXTENSION SPOOFING: {spoof_desc}")
                    
                    # Get other risks from final_risk_reason
                    final_risk_reason = result.get('final_risk_reason', '')
                    if final_risk_reason and not any(factor in final_risk_reason for factor in ['QR code', 'EXTENSION SPOOFING', 'CRITICAL SPOOFING', 'HIGH RISK SPOOFING']):
                        if not qr_status and not result.get('is_spoofed'):  # Only show if not already covered
                            risk_factors.append(final_risk_reason)
                    
                    # Display consolidated risk assessment with enhanced colors
                    if COMPATIBLE_OUTPUT:
                        output.print("Risk Level:")
                    else:
                        print("Risk Level:")
                    
                    # ENHANCED: Support for CRITICAL risk level
                    if final_risk_level == "critical":
                        risk_color = "red bold"
                    elif final_risk_level == "high":
                        risk_color = "red"
                    elif final_risk_level == "medium":
                        risk_color = "orange3"
                    elif final_risk_level == "low":
                        risk_color = "green"
                    else:
                        risk_color = "orange3"
                    
                    if COMPATIBLE_OUTPUT:
                        output.print(f"- [{risk_color}]{final_risk_level.upper()}{qr_status}[/{risk_color}]")
                    else:
                        print(f"- {final_risk_level.upper()}{qr_status}")
                    
                    # Show specific risk factors with enhanced coloring
                    for factor in risk_factors:
                        if COMPATIBLE_OUTPUT:
                            if factor.startswith('CRITICAL'):
                                output.print(f"- [red bold]{output.escape(factor)}[/red bold]")
                            elif factor.startswith('MALICIOUS') or factor.startswith('HIGH RISK'):
                                output.print(f"- [red]{output.escape(factor)}[/red]")
                            elif factor.startswith('PHISHING CONTENT'):
                                output.print(f"- [red]{output.escape(factor)}[/red]")
                            elif 'suspicious' in factor.lower():
                                output.print(f"- [orange3]{output.escape(factor)}[/orange3]")
                            else:
                                output.print(f"- {output.escape(factor)}")
                        else:
                            print(f"- {factor}")
                    
                    # Add content risk score if available
                    if result.get('attachment_content_analysis') and CONTENT_ANALYSIS_AVAILABLE:
                        content_analysis = result['attachment_content_analysis']
                        if content_analysis.get('findings') or content_analysis.get('url_analysis', {}).get('results'):
                            content_risk_score = content_analysis.get('risk_score', 0)
                            if content_risk_score > 0:
                                if content_risk_score >= 70:
                                    score_color = "red"
                                elif content_risk_score >= 40:
                                    score_color = "orange3"
                                else:
                                    score_color = "yellow"
                                
                                if COMPATIBLE_OUTPUT:
                                    output.print(f"- Content risk score: [{score_color}]{content_risk_score}/100[/{score_color}]")
                                else:
                                    print(f"- Content risk score: {content_risk_score}/100")
                    
                    print()  # Final blank line
                    
                except Exception as e:
                    if COMPATIBLE_OUTPUT:
                        print_status(f"Error displaying attachment {result.get('index', '?')}: {e}", "error")
                    else:
                        print(f"Error displaying attachment {result.get('index', '?')}: {e}")
                    print()
                    
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Error displaying attachment results: {e}", "error")
            else:
                print(f"Error displaying attachment results: {e}")
        
        # ENHANCED: Summary assessment with comprehensive findings and CRITICAL threat support
        try:
            final_high_risk_count = sum(1 for r in results if r.get('final_risk_level') == 'high')
            final_critical_count = sum(1 for r in results if r.get('final_risk_level') == 'critical')
            malicious_count = sum(1 for r in results if r.get('vt_verdict') == 'malicious')
            suspicious_count = sum(1 for r in results if r.get('vt_verdict') == 'suspicious')
            spoofed_count = sum(1 for r in results if r.get('is_spoofed'))
            qr_codes_found = total_qr_count > 0
            
            # Check for phishing content in attachments
            phishing_files_count = sum(1 for r in results if r.get('attachment_content_analysis', {}).get('findings'))
            malicious_url_files = sum(1 for r in results if r.get('attachment_content_analysis', {}).get('url_analysis', {}).get('malicious_count', 0) > 0)
            suspicious_url_files = sum(1 for r in results if r.get('attachment_content_analysis', {}).get('url_analysis', {}).get('suspicious_count', 0) > 0)
            
            # Determine overall threat level with CRITICAL support
            threat_factors = []
            summary_color = "green"  # Default to safe
            
            # HIGHEST PRIORITY: Critical threats
            if final_critical_count > 0:
                threat_factors.append(f"{final_critical_count} CRITICAL threat{'s' if final_critical_count != 1 else ''} (spoofed executables/PDFs)")
                summary_color = "red bold"
            
            if malicious_count > 0:
                threat_factors.append(f"{malicious_count} malicious file{'s' if malicious_count != 1 else ''} (VirusTotal)")
                if summary_color != "red bold":
                    summary_color = "red"
            
            if malicious_url_files > 0:
                threat_factors.append(f"{malicious_url_files} file{'s' if malicious_url_files != 1 else ''} with malicious URLs")
                if summary_color not in ["red bold", "red"]:
                    summary_color = "red"
            
            if spoofed_count > 0:
                threat_factors.append(f"{spoofed_count} spoofed file{'s' if spoofed_count != 1 else ''}")
                if summary_color not in ["red bold", "red"]:
                    summary_color = "red"
            
            if phishing_files_count > 0:
                threat_factors.append(f"{phishing_files_count} file{'s' if phishing_files_count != 1 else ''} with phishing content")
                if summary_color not in ["red bold", "red"]:
                    summary_color = "red"
            
            if qr_codes_found:
                if total_qr_count == 1:
                    threat_factors.append("QR code detected")
                else:
                    threat_factors.append(f"{total_qr_count} QR codes detected")
                if summary_color not in ["red bold", "red"]:
                    summary_color = "red"
            
            if suspicious_count > 0 or suspicious_url_files > 0:
                if suspicious_count > 0:
                    threat_factors.append(f"{suspicious_count} suspicious file{'s' if suspicious_count != 1 else ''} (VirusTotal)")
                if suspicious_url_files > 0:
                    threat_factors.append(f"{suspicious_url_files} file{'s' if suspicious_url_files != 1 else ''} with suspicious URLs")
                if summary_color not in ["red bold", "red"]:
                    summary_color = "orange3"
            
            if final_high_risk_count > 0 and summary_color not in ["red bold", "red", "orange3"]:
                summary_color = "orange3"
            
            # Generate summary text with CRITICAL emphasis
            if threat_factors:
                if final_critical_count > 0:
                    summary_text = f"CRITICAL SECURITY THREAT: {threat_factors[0]}"
                    if len(threat_factors) > 1:
                        summary_text += f" + {len(threat_factors) - 1} more threat{'s' if len(threat_factors) - 1 != 1 else ''}!"
                    else:
                        summary_text += "!"
                elif len(threat_factors) == 1:
                    summary_text = f"HIGH RISK: {threat_factors[0]}!"
                elif len(threat_factors) == 2:
                    summary_text = f"HIGH RISK: {threat_factors[0]} and {threat_factors[1]}!"
                else:
                    summary_text = f"HIGH RISK: {threat_factors[0]}, {threat_factors[1]}, and {len(threat_factors) - 2} more threat{'s' if len(threat_factors) - 2 != 1 else ''}!"
            else:
                summary_text = "Attachments appear benign, but verify manually."
                summary_color = "green"
            
            if COMPATIBLE_OUTPUT:
                output.print(f"[blue bold]ATTACHMENT ASSESSMENT:[/blue bold] [{summary_color}]{summary_text}[/{summary_color}]")
            else:
                print(f"ATTACHMENT ASSESSMENT: {summary_text}")
            
            print()
            
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Error generating summary assessment: {e}", "error")
            else:
                print(f"Error generating summary assessment: {e}")
            print()
        
        return results

    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Critical error in attachment analysis: {e}", "error")
            print_status("Attachment analysis could not be completed.", "warning")
        else:
            print(f"Critical error in attachment analysis: {e}")
            print("Attachment analysis could not be completed.")
        return []