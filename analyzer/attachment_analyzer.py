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

# Network request timeout settings
REQUEST_TIMEOUT = 10
MAX_RETRIES = 3

# File size limits
MAX_ATTACHMENT_SIZE = 100 * 1024 * 1024  # 100MB
LARGE_FILE_WARNING_SIZE = 10 * 1024 * 1024  # 10MB

# File magic number signatures for content-based detection
FILE_SIGNATURES = {
    'pdf': [
        b'%PDF-',  # PDF files
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
        b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1',  # Microsoft Office (legacy)
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

def detect_file_type_from_content(content, max_check_bytes=512):
    """
    NEW: Detect actual file type from content using magic numbers.
    Returns detected type or None if unknown.
    """
    if not content or len(content) < 4:
        return None
    
    # Check first N bytes for magic numbers
    header = content[:max_check_bytes]
    
    for file_type, signatures in FILE_SIGNATURES.items():
        for signature in signatures:
            if header.startswith(signature):
                return file_type
    
    # Special case: Check for XML/SVG content in text
    try:
        # Try to decode as UTF-8 to check for text-based formats
        text_content = header.decode('utf-8', errors='ignore').lower().strip()
        if text_content.startswith('<?xml') or text_content.startswith('<svg'):
            if '<svg' in text_content[:100]:
                return 'svg'
            else:
                return 'xml'
    except:
        pass
    
    return None

def detect_extension_spoofing(filename, detected_type, claimed_content_type):
    """
    NEW: Detect if file extension doesn't match actual content.
    Returns (is_spoofed, risk_description)
    """
    if not filename or not detected_type:
        return False, None
    
    filename_lower = filename.lower()
    file_ext = filename_lower.split('.')[-1] if '.' in filename_lower else ''
    
    # Define expected extensions for each detected type
    expected_extensions = {
        'pdf': ['pdf'],
        'jpeg': ['jpg', 'jpeg'],
        'png': ['png'],
        'gif': ['gif'],
        'bmp': ['bmp'],
        'zip': ['zip', 'docx', 'xlsx', 'pptx', 'odt', 'ods', 'odp'],
        'doc': ['doc', 'xls', 'ppt', 'docx', 'xlsx', 'pptx'],  # OLE format
        'exe': ['exe', 'com', 'scr'],
        'svg': ['svg'],
        'xml': ['xml'],
        'html': ['html', 'htm'],
        'rtf': ['rtf'],
        'rar': ['rar'],
        '7z': ['7z'],
        'tar': ['tar'],
        'gz': ['gz', 'tgz'],
        'bz2': ['bz2'],
        'elf': ['bin', 'out', ''],  # Linux executables often have no extension
        'dmg': ['dmg'],
        'iso': ['iso'],
    }
    
    expected_exts = expected_extensions.get(detected_type, [])
    
    if expected_exts and file_ext not in expected_exts:
        # This is suspicious - file content doesn't match extension
        risk_descriptions = {
            'pdf': f"PDF content disguised as .{file_ext} file",
            'exe': f"Executable content disguised as .{file_ext} file", 
            'doc': f"Office document disguised as .{file_ext} file",
            'zip': f"Archive content disguised as .{file_ext} file",
            'html': f"HTML content disguised as .{file_ext} file",
        }
        
        risk_desc = risk_descriptions.get(detected_type, 
                                        f"{detected_type.upper()} content disguised as .{file_ext} file")
        return True, risk_desc
    
    return False, None

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

def safe_categorize_attachment_risk(filename, content_type, size, detected_type=None, is_spoofed=False, spoof_description=None):
    """Categorize attachment risk with comprehensive error handling and content-based detection."""
    try:
        if not filename:
            return "unknown", "No filename provided"
        
        extension = safe_get_file_extension(filename)
        risk_factors = []
        risk_level = "low"
        
        # HIGHEST PRIORITY: Extension spoofing detection
        if is_spoofed and spoof_description:
            risk_factors.append(f"EXTENSION SPOOFING: {spoof_description}")
            risk_level = "high"
        
        # Check actual detected content type vs claimed extension
        if detected_type:
            if detected_type in ['exe', 'elf']:
                risk_factors.append(f"Executable content detected ({detected_type.upper()})")
                risk_level = "high"
            elif detected_type == 'pdf' and extension != 'pdf':
                risk_factors.append(f"PDF content with .{extension} extension")
                if risk_level != "high":
                    risk_level = "high"
            elif detected_type in ['doc', 'zip'] and extension not in MACRO_EXTENSIONS and extension not in ARCHIVE_EXTENSIONS:
                risk_factors.append(f"Office/Archive content with unexpected .{extension} extension")
                if risk_level == "low":
                    risk_level = "medium"
        
        # Check for suspicious extensions (based on filename)
        try:
            if extension in SUSPICIOUS_EXTENSIONS:
                risk_factors.append(f"Executable file type (.{extension})")
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
        
        # Check for double extensions (common evasion technique)
        try:
            filename_parts = str(filename).lower().split('.')
            if len(filename_parts) > 2:
                # Check if there's a suspicious extension before the final one
                for i, part in enumerate(filename_parts[:-1]):
                    if part in SUSPICIOUS_EXTENSIONS:
                        risk_factors.append("Double extension detected (possible evasion)")
                        risk_level = "high"
                        break
        except Exception:
            pass
        
        # Check for suspicious filenames
        try:
            suspicious_names = [
                'invoice', 'receipt', 'document', 'file', 'attachment', 'urgent',
                'important', 'secure', 'encrypted', 'backup', 'update', 'install'
            ]
            filename_lower = str(filename).lower()
            for name in suspicious_names:
                if name in filename_lower and (extension in SUSPICIOUS_EXTENSIONS or is_spoofed):
                    risk_factors.append(f"Suspicious filename pattern with dangerous content")
                    risk_level = "high"
                    break
        except Exception:
            pass
        
        # Check file size
        try:
            if size is not None and isinstance(size, (int, float)):
                if size < 1024:  # Less than 1KB
                    risk_factors.append("Unusually small file size")
                elif size > 50 * 1024 * 1024:  # Greater than 50MB
                    risk_factors.append("Large file size")
        except Exception:
            pass
        
        # Content-Type mismatch detection (enhanced)
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

def safe_virustotal_request(url, headers, file_hash):
    """Safely make VirusTotal request with retry logic."""
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            return response
        except requests.exceptions.Timeout:
            if attempt < MAX_RETRIES - 1:
                escaped_hash = output.escape(file_hash[:8]) if COMPATIBLE_OUTPUT else file_hash[:8]
                if COMPATIBLE_OUTPUT:
                    print_status(f"Timeout for hash {escaped_hash}..., retrying... (attempt {attempt + 1}/{MAX_RETRIES})", "warning")
                else:
                    print(f"Timeout for hash {escaped_hash}..., retrying... (attempt {attempt + 1}/{MAX_RETRIES})")
                time.sleep(2)
            else:
                escaped_hash = output.escape(file_hash[:8]) if COMPATIBLE_OUTPUT else file_hash[:8]
                if COMPATIBLE_OUTPUT:
                    print_status(f"Final timeout for hash {escaped_hash}... after {MAX_RETRIES} attempts", "warning")
                else:
                    print(f"Final timeout for hash {escaped_hash}... after {MAX_RETRIES} attempts")
                return None
        except requests.exceptions.ConnectionError:
            if attempt < MAX_RETRIES - 1:
                escaped_hash = output.escape(file_hash[:8]) if COMPATIBLE_OUTPUT else file_hash[:8]
                if COMPATIBLE_OUTPUT:
                    print_status(f"Connection error for hash {escaped_hash}..., retrying... (attempt {attempt + 1}/{MAX_RETRIES})", "warning")
                else:
                    print(f"Connection error for hash {escaped_hash}..., retrying... (attempt {attempt + 1}/{MAX_RETRIES})")
                time.sleep(2)
            else:
                escaped_hash = output.escape(file_hash[:8]) if COMPATIBLE_OUTPUT else file_hash[:8]
                if COMPATIBLE_OUTPUT:
                    print_status(f"Final connection error for hash {escaped_hash}... after {MAX_RETRIES} attempts", "warning")
                else:
                    print(f"Final connection error for hash {escaped_hash}... after {MAX_RETRIES} attempts")
                return None
        except Exception as e:
            escaped_hash = output.escape(file_hash[:8]) if COMPATIBLE_OUTPUT and file_hash else 'unknown'
            if COMPATIBLE_OUTPUT:
                print_status(f"Unexpected error querying hash {escaped_hash}...: {e}", "error")
            else:
                print(f"Unexpected error querying hash {escaped_hash}...: {e}")
            return None
    
    return None

def safe_handle_rate_limit():
    """Safely handle VirusTotal rate limiting with user choice."""
    try:
        while True:
            try:
                if COMPATIBLE_OUTPUT:
                    print_status("VirusTotal API rate limit reached.", "warning")
                    choice = input("Type 'wait' to wait 60 seconds, or 'skip' to proceed without checking: ").strip().lower()
                else:
                    choice = input(
                        "VirusTotal API rate limit reached.\n"
                        "Type 'wait' to wait 60 seconds, or 'skip' to proceed without checking: "
                    ).strip().lower()
                
                if choice == "wait":
                    print("Waiting 60 seconds...")
                    time.sleep(60)
                    return "wait"
                elif choice == "skip":
                    return "skip"
                else:
                    print("Invalid input. Please type 'wait' or 'skip'.")
            except (KeyboardInterrupt, EOFError):
                print("\nSkipping due to user interruption.")
                return "skip"
            except Exception as e:
                if COMPATIBLE_OUTPUT:
                    print_status(f"Input error: {e}", "error")
                else:
                    print(f"Input error: {e}")
                return "skip"
    except Exception:
        return "skip"

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
        
        response = safe_virustotal_request(url, headers, file_hash)
        
        if response is None:
            cache[file_hash] = ("unchecked", "Network error - could not reach VirusTotal")
            return cache[file_hash]
        
        if response.status_code == 429:
            action = safe_handle_rate_limit()
            if action == "wait":
                # Try again after waiting
                response = safe_virustotal_request(url, headers, file_hash)
                if response is None or response.status_code == 429:
                    cache[file_hash] = ("unchecked", "Rate limit persists")
                    return cache[file_hash]
            else:  # skip
                cache[file_hash] = ("unchecked", "Skipped due to rate limit")
                return cache[file_hash]
        
        if response.status_code == 200:
            try:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                
                # Get additional file info safely
                try:
                    file_info = data.get("data", {}).get("attributes", {})
                    file_names = file_info.get("names", [])
                except Exception:
                    file_names = []
                
                if malicious > 0:
                    comment = (f"{malicious} vendor flagged this file as malicious"
                              if malicious == 1 else
                              f"{malicious} vendors flagged this file as malicious")
                    if file_names:
                        try:
                            comment += f" (known as: {', '.join(file_names[:3])})"
                        except Exception:
                            pass
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

def safe_extract_attachments(msg_obj):
    """Extract attachment information with comprehensive error handling."""
    attachments = []
    
    try:
        if not msg_obj:
            return attachments
        
        if not hasattr(msg_obj, 'is_multipart') or not msg_obj.is_multipart():
            return attachments
        
        if not hasattr(msg_obj, 'walk'):
            return attachments
        
        for part in msg_obj.walk():
            try:
                if not hasattr(part, 'get_content_disposition'):
                    continue
                
                if part.get_content_disposition() == 'attachment':
                    try:
                        filename = part.get_filename() if hasattr(part, 'get_filename') else None
                        content_type = part.get_content_type() if hasattr(part, 'get_content_type') else 'application/octet-stream'
                        
                        # Get file content safely
                        content = b""
                        size = 0
                        
                        try:
                            if hasattr(part, 'get_payload'):
                                content = part.get_payload(decode=True)
                                if content is None:
                                    content = part.get_payload()
                                    if isinstance(content, str):
                                        content = content.encode('utf-8', errors='replace')
                                
                                if content and len(content) > MAX_ATTACHMENT_SIZE:
                                    escaped_filename = output.escape(filename or 'unnamed') if COMPATIBLE_OUTPUT else (filename or 'unnamed')
                                    if COMPATIBLE_OUTPUT:
                                        print_status(f"Warning: Attachment {escaped_filename} is very large ({len(content) // (1024*1024)}MB), truncating for analysis", "warning")
                                    else:
                                        print(f"Warning: Attachment {escaped_filename} is very large ({len(content) // (1024*1024)}MB), truncating for analysis")
                                    content = content[:MAX_ATTACHMENT_SIZE]
                        except Exception as e:
                            escaped_filename = output.escape(filename or 'unnamed attachment') if COMPATIBLE_OUTPUT else (filename or 'unnamed attachment')
                            if COMPATIBLE_OUTPUT:
                                print_status(f"Warning: Could not extract content for {escaped_filename}: {e}", "warning")
                            else:
                                print(f"Warning: Could not extract content for {escaped_filename}: {e}")
                            content = b""
                        
                        size = len(content) if content else 0
                        
                        attachments.append({
                            'filename': filename or 'unnamed_attachment',
                            'content_type': content_type,
                            'size': size,
                            'content': content
                        })
                        
                    except Exception as e:
                        if COMPATIBLE_OUTPUT:
                            print_status(f"Warning: Error processing attachment: {e}", "warning")
                        else:
                            print(f"Warning: Error processing attachment: {e}")
                        # Add a placeholder for the failed attachment
                        attachments.append({
                            'filename': 'error_processing_attachment',
                            'content_type': 'application/octet-stream',
                            'size': 0,
                            'content': b"",
                            'error': str(e)
                        })
                        
            except Exception as e:
                if COMPATIBLE_OUTPUT:
                    print_status(f"Warning: Error processing email part: {e}", "warning")
                else:
                    print(f"Warning: Error processing email part: {e}")
                continue
    
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error extracting attachments: {e}", "error")
        else:
            print(f"Error extracting attachments: {e}")
    
    return attachments

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

def analyze_file_by_content(attachment_data, api_key):
    """
    NEW: Analyze attachment based on actual content, not just filename.
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
                'spoofing_detected': False
            }
        
        # Detect actual file type from content
        detected_type = detect_file_type_from_content(content)
        
        # Check for extension spoofing
        is_spoofed, spoof_description = detect_extension_spoofing(
            filename, detected_type, attachment_data.get('content_type'))
        
        results = {
            'detected_type': detected_type,
            'spoofing_detected': is_spoofed,
            'spoof_description': spoof_description,
            'content_analysis': None,
            'qr_analysis': None
        }
        
        # Perform content-specific analysis based on ACTUAL file type
        if detected_type == 'pdf':
            # PDF analysis regardless of filename extension
            try:
                qr_analysis = qr_analyzer.analyze_pdf_qr_codes(attachment_data, api_key)
                results['qr_analysis'] = qr_analysis
                
                if COMPATIBLE_OUTPUT and is_spoofed:
                    print_status(f"SECURITY WARNING: PDF content found in file with .{safe_get_file_extension(filename)} extension", "warning")
                elif not COMPATIBLE_OUTPUT and is_spoofed:
                    print(f"SECURITY WARNING: PDF content found in file with .{safe_get_file_extension(filename)} extension")
                    
            except Exception as e:
                if COMPATIBLE_OUTPUT:
                    print_status(f"Error analyzing PDF content: {e}", "error")
                else:
                    print(f"Error analyzing PDF content: {e}")
        
        elif detected_type in ['jpeg', 'png', 'gif', 'bmp', 'svg']:
            # Image analysis for QR codes
            try:
                # For SVG files, we need special handling since they're XML-based
                if detected_type == 'svg':
                    # SVG files are XML, but could contain embedded images or QR patterns
                    # For now, we'll treat them as potential risk due to script injection possibilities
                    if is_spoofed:
                        results['content_analysis'] = "SVG file with suspicious extension - potential script injection risk"
                else:
                    # For raster images, we could add QR detection if qr_analyzer supported it
                    # Currently qr_analyzer only handles PDFs, but this is where we'd extend it
                    if is_spoofed:
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
        
        elif detected_type in ['exe', 'elf']:
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
        
        elif detected_type == 'doc':
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
            'content_analysis': f"Analysis error: {e}",
            'qr_analysis': None
        }

def analyze_attachments(msg_obj, api_key):
    """Main function to analyze email attachments with comprehensive error handling and content-based detection."""
    
    try:
        attachments = safe_extract_attachments(msg_obj)
        
        if not attachments:
            if COMPATIBLE_OUTPUT:
                print_status("No attachments found in this email.", "success")
            else:
                print("No attachments found in this email.")
            print()
            return []
        
        # Create properly colored text for attachment count
        try:
            if COMPATIBLE_OUTPUT:
                output.print(f"Found [blue]{len(attachments)}[/blue] attachment{'s' if len(attachments) != 1 else ''}:\n")
            else:
                print(f"Found {len(attachments)} attachment{'s' if len(attachments) != 1 else ''}:\n")
        except Exception:
            print(f"Found {len(attachments)} attachment(s):\n")
        
        cache = {}
        results = []
        total_qr_count = 0
        spoofing_detected = False
        
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
                
                # NEW: Content-based analysis
                content_analysis_results = analyze_file_by_content(attachment, api_key)
                detected_type = content_analysis_results.get('detected_type')
                is_spoofed = content_analysis_results.get('spoofing_detected', False)
                spoof_description = content_analysis_results.get('spoof_description')
                qr_analysis = content_analysis_results.get('qr_analysis')
                content_analysis = content_analysis_results.get('content_analysis')
                
                if is_spoofed:
                    spoofing_detected = True
                
                # Calculate file hash
                file_hash = safe_calculate_file_hash(content)
                
                # Enhanced risk categorization with content detection
                base_risk_level, base_risk_reason = safe_categorize_attachment_risk(
                    filename, content_type, size, detected_type, is_spoofed, spoof_description)
                
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
                            risk_levels = {"low": 0, "medium": 1, "high": 2}
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
                    'content_analysis': content_analysis,
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
                    'content_analysis': None,
                    'base_risk_level': 'unknown',
                    'final_risk_level': 'unknown',
                    'final_risk_reason': f'Processing error: {e}',
                    'vt_verdict': 'unchecked',
                    'vt_comment': f'Processing error: {e}',
                    'qr_analysis': None
                })
        
        # Sort by final risk level and VT verdict
        try:
            risk_priority = {"high": 0, "medium": 1, "low": 2, "unknown": 3}
            vt_priority = {"malicious": 0, "suspicious": 1, "unknown": 2, "unchecked": 2, "benign": 3}
            
            results.sort(key=lambda x: (
                risk_priority.get(x.get('final_risk_level', 'unknown'), 4),
                vt_priority.get(x.get('vt_verdict', 'unchecked'), 5)
            ))
        except Exception as e:
            if COMPATIBLE_OUTPUT:
                print_status(f"Warning: Could not sort results: {e}", "warning")
            else:
                print(f"Warning: Could not sort results: {e}")
        
        # Display results with consistent color handling
        try:
            for result in results:
                try:
                    # Attachment header
                    if COMPATIBLE_OUTPUT:
                        print_attachment_header(result.get('index', '?'))
                    else:
                        print(f"Attachment {result.get('index', '?')}:")
                    
                    # Filename
                    if COMPATIBLE_OUTPUT:
                        print_filename(result.get('filename', 'unknown'))
                    else:
                        print(f"  Filename: {result.get('filename', 'unknown')}")
                    
                    # Type (with detected type info)
                    content_type = str(result.get('content_type', 'unknown'))
                    detected_type = result.get('detected_type')
                    
                    if detected_type and detected_type != 'unknown':
                        type_info = f"{content_type} (detected: {detected_type.upper()})"
                    else:
                        type_info = content_type
                    
                    escaped_type_info = output.escape(type_info) if COMPATIBLE_OUTPUT else type_info
                    if COMPATIBLE_OUTPUT:
                        output.print(f"  Type: {escaped_type_info}")
                    else:
                        print(f"  Type: {escaped_type_info}")
                    
                    # Size
                    if COMPATIBLE_OUTPUT:
                        output.print(f"  Size: {safe_format_file_size(result.get('size', 0))}")
                    else:
                        print(f"  Size: {safe_format_file_size(result.get('size', 0))}")
                    
                    # SHA256 (color-coded by VT verdict)
                    if result.get('hash') != "N/A":
                        if COMPATIBLE_OUTPUT:
                            print_hash(result.get('hash', 'N/A'), result.get('vt_verdict', 'unchecked'))
                        else:
                            # Apply defanging to hash if enabled (though hashes aren't typically defanged)
                            display_hash = result.get('hash', 'N/A')
                            try:
                                if defanger.should_defang():
                                    display_hash = defanger.defang_text(display_hash)
                            except Exception:
                                pass
                            print(f"  SHA256: {display_hash}")
                    
                    # Extension spoofing warning (HIGH PRIORITY)
                    if result.get('is_spoofed'):
                        spoof_desc = result.get('spoof_description', 'Content type mismatch detected')
                        escaped_spoof = output.escape(spoof_desc) if COMPATIBLE_OUTPUT else spoof_desc
                        if COMPATIBLE_OUTPUT:
                            output.print(f"  [red]SPOOFING ALERT: {escaped_spoof}[/red]")
                        else:
                            print(f"  SPOOFING ALERT: {escaped_spoof}")
                    
                    # Content analysis results
                    if result.get('content_analysis'):
                        escaped_analysis = output.escape(result.get('content_analysis')) if COMPATIBLE_OUTPUT else result.get('content_analysis')
                        if COMPATIBLE_OUTPUT:
                            output.print(f"  [yellow]Content Analysis: {escaped_analysis}[/yellow]")
                        else:
                            print(f"  Content Analysis: {escaped_analysis}")
                    
                    # Risk Level (color-coded consistently)
                    if COMPATIBLE_OUTPUT:
                        print_risk_level(result.get('final_risk_level', 'unknown'), result.get('final_risk_reason', 'unknown'))
                    else:
                        print(f"  Risk Level: {str(result.get('final_risk_level', 'unknown')).upper()} ({result.get('final_risk_reason', 'unknown')})")
                    
                    # VirusTotal verdict (color-coded consistently)
                    if COMPATIBLE_OUTPUT:
                        print_vt_verdict(result.get('vt_verdict', 'unchecked'), result.get('vt_comment', 'unknown'))
                    else:
                        print(f"  VirusTotal: {str(result.get('vt_verdict', 'unchecked')).upper()} ({result.get('vt_comment', 'unknown')})")
                    
                    # QR Code analysis (if applicable)
                    if result.get('qr_analysis'):
                        try:
                            qr_analyzer.display_qr_analysis(result.get('index', 0), result['qr_analysis'])
                        except Exception as e:
                            if COMPATIBLE_OUTPUT:
                                output.print(f"  [yellow]QR Analysis: Error displaying results - {e}[/yellow]")
                            else:
                                print(f"  QR Analysis: Error displaying results - {e}")
                    
                    print()
                    
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
        
        # Enhanced summary assessment
        try:
            final_high_risk_count = sum(1 for r in results if r.get('final_risk_level') == 'high')
            malicious_count = sum(1 for r in results if r.get('vt_verdict') == 'malicious')
            suspicious_count = sum(1 for r in results if r.get('vt_verdict') == 'suspicious')
            spoofed_count = sum(1 for r in results if r.get('is_spoofed'))
            qr_codes_found = total_qr_count > 0
            
            if malicious_count > 0:
                summary_text = "CRITICAL: Malicious attachments detected!"
                summary_color = "red"
            elif spoofed_count > 0:
                summary_text = "CRITICAL: Extension spoofing detected - files disguised with fake extensions!"
                summary_color = "red"
            elif qr_codes_found:
                # Use proper singular/plural for QR codes
                if total_qr_count == 1:
                    summary_text = "WARNING: QR code detected - highly suspicious!"
                else:
                    summary_text = "WARNING: QR codes detected - highly suspicious!"
                summary_color = "red"
            elif final_high_risk_count > 0 or suspicious_count > 0:
                summary_text = "WARNING: Suspicious attachments detected!"
                summary_color = "orange3"
            else:
                summary_text = "Attachments appear benign, but verify manually."
                summary_color = "green"
            
            if COMPATIBLE_OUTPUT:
                output.print(f"[blue bold]ATTACHMENT ASSESSMENT:[/blue bold] [{summary_color}]{summary_text}[/{summary_color}]")
            else:
                print(f"ATTACHMENT ASSESSMENT: {summary_text}")
            
            # Additional warning for spoofing
            if spoofed_count > 0:
                if COMPATIBLE_OUTPUT:
                    output.print(f"[red bold]WARNING: {spoofed_count} file{'s' if spoofed_count != 1 else ''} have content that doesn't match their extension![/red bold]")
                else:
                    print(f"WARNING: {spoofed_count} file{'s' if spoofed_count != 1 else ''} have content that doesn't match their extension!")
            
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