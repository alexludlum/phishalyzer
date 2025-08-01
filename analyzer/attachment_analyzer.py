import re
import time
import hashlib
import requests
from rich import print
from rich.text import Text
import mimetypes
import base64
from email.message import EmailMessage
from . import qr_analyzer
from . import defanger

# Network request timeout settings
REQUEST_TIMEOUT = 10
MAX_RETRIES = 3

# File size limits
MAX_ATTACHMENT_SIZE = 100 * 1024 * 1024  # 100MB
LARGE_FILE_WARNING_SIZE = 10 * 1024 * 1024  # 10MB

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

def safe_categorize_attachment_risk(filename, content_type, size):
    """Categorize attachment risk with comprehensive error handling."""
    try:
        if not filename:
            return "unknown", "No filename provided"
        
        extension = safe_get_file_extension(filename)
        risk_factors = []
        
        # Check for suspicious extensions
        try:
            if extension in SUSPICIOUS_EXTENSIONS:
                risk_factors.append(f"Executable file type (.{extension})")
                risk_level = "high"
            elif extension in MACRO_EXTENSIONS:
                risk_factors.append(f"Macro-capable document (.{extension})")
                risk_level = "medium"
            elif extension in ARCHIVE_EXTENSIONS:
                risk_factors.append(f"Archive file (.{extension}) - contents unknown")
                risk_level = "medium"
            else:
                risk_level = "low"
        except Exception:
            risk_level = "unknown"
        
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
                if name in filename_lower and extension in SUSPICIOUS_EXTENSIONS:
                    risk_factors.append(f"Suspicious filename pattern with executable extension")
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
        print(f"[yellow]Warning: Could not calculate file hash: {e}[/yellow]")
        return "N/A"

def safe_virustotal_request(url, headers, file_hash):
    """Safely make VirusTotal request with retry logic."""
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            return response
        except requests.exceptions.Timeout:
            if attempt < MAX_RETRIES - 1:
                print(f"[yellow]Timeout for hash {file_hash[:8]}..., retrying... (attempt {attempt + 1}/{MAX_RETRIES})[/yellow]")
                time.sleep(2)
            else:
                print(f"[yellow]Final timeout for hash {file_hash[:8]}... after {MAX_RETRIES} attempts[/yellow]")
                return None
        except requests.exceptions.ConnectionError:
            if attempt < MAX_RETRIES - 1:
                print(f"[yellow]Connection error for hash {file_hash[:8]}..., retrying... (attempt {attempt + 1}/{MAX_RETRIES})[/yellow]")
                time.sleep(2)
            else:
                print(f"[yellow]Final connection error for hash {file_hash[:8]}... after {MAX_RETRIES} attempts[/yellow]")
                return None
        except Exception as e:
            print(f"[red]Unexpected error querying hash {file_hash[:8]}...: {e}[/red]")
            return None
    
    return None

def safe_handle_rate_limit():
    """Safely handle VirusTotal rate limiting with user choice."""
    try:
        while True:
            try:
                choice = input(
                    "[yellow]VirusTotal API rate limit reached.[/yellow]\n"
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
                print(f"[red]Input error: {e}[/red]")
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
        print(f"[red]Error querying VirusTotal for file hash {file_hash[:8] if file_hash else 'unknown'}...: {e}[/red]")
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
                                    print(f"[yellow]Warning: Attachment {filename or 'unnamed'} is very large ({len(content) // (1024*1024)}MB), truncating for analysis[/yellow]")
                                    content = content[:MAX_ATTACHMENT_SIZE]
                        except Exception as e:
                            print(f"[yellow]Warning: Could not extract content for {filename or 'unnamed attachment'}: {e}[/yellow]")
                            content = b""
                        
                        size = len(content) if content else 0
                        
                        attachments.append({
                            'filename': filename or 'unnamed_attachment',
                            'content_type': content_type,
                            'size': size,
                            'content': content
                        })
                        
                    except Exception as e:
                        print(f"[yellow]Warning: Error processing attachment: {e}[/yellow]")
                        # Add a placeholder for the failed attachment
                        attachments.append({
                            'filename': 'error_processing_attachment',
                            'content_type': 'application/octet-stream',
                            'size': 0,
                            'content': b"",
                            'error': str(e)
                        })
                        
            except Exception as e:
                print(f"[yellow]Warning: Error processing email part: {e}[/yellow]")
                continue
    
    except Exception as e:
        print(f"[red]Error extracting attachments: {e}[/red]")
    
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
        print(f"[yellow]Warning: Error analyzing QR risk: {e}[/yellow]")
        return None, None

def analyze_attachments(msg_obj, api_key):
    """Main function to analyze email attachments with comprehensive error handling."""
    
    try:
        attachments = safe_extract_attachments(msg_obj)
        
        if not attachments:
            print(Text("No attachments found in this email.", style="green"))
            print()
            return []
        
        # Create properly colored text for attachment count
        try:
            count_text = Text()
            count_text.append("Found ")
            count_text.append(str(len(attachments)), style="blue")
            count_text.append(" attachment")
            if len(attachments) != 1:
                count_text.append("s")
            count_text.append(":\n")
            print(count_text)
        except Exception:
            print(f"Found {len(attachments)} attachment(s):\n")
        
        cache = {}
        results = []
        total_qr_count = 0
        
        # Process each attachment
        for i, attachment in enumerate(attachments, 1):
            try:
                filename = attachment.get('filename', 'unnamed_attachment')
                content_type = attachment.get('content_type', 'application/octet-stream')
                size = attachment.get('size', 0)
                content = attachment.get('content', b"")
                
                # Check for processing errors
                if 'error' in attachment:
                    print(f"[yellow]Warning: Attachment {i} had processing errors: {attachment['error']}[/yellow]")
                
                # Calculate file hash
                file_hash = safe_calculate_file_hash(content)
                
                # Basic risk categorization
                base_risk_level, base_risk_reason = safe_categorize_attachment_risk(filename, content_type, size)
                
                # Check with VirusTotal if we have content
                vt_verdict = "unchecked"
                vt_comment = "No content to analyze"
                
                if content and file_hash != "N/A":
                    try:
                        vt_verdict, vt_comment = check_file_hash_virustotal(file_hash, api_key, cache)
                    except Exception as e:
                        print(f"[yellow]Warning: VirusTotal check failed for {filename}: {e}[/yellow]")
                        vt_verdict, vt_comment = ("unchecked", f"VT check error: {e}")
                
                # QR Code analysis (run once per attachment)
                qr_analysis = None
                try:
                    if filename and str(filename).lower().endswith('.pdf'):
                        qr_analysis = qr_analyzer.analyze_pdf_qr_codes({
                            'filename': filename,
                            'content': content,
                            'content_type': content_type,
                            'size': size,
                            'hash': file_hash
                        }, api_key)
                        
                        if qr_analysis and qr_analysis.get('qr_found'):
                            qr_results = qr_analysis.get('qr_results', [])
                            total_qr_count += len(qr_results)
                except Exception as e:
                    print(f"[yellow]Warning: QR analysis failed for {filename}: {e}[/yellow]")
                    qr_analysis = None
                
                # Determine final risk level (considering QR codes)
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
                    'base_risk_level': base_risk_level,
                    'final_risk_level': final_risk_level,
                    'final_risk_reason': final_risk_reason,
                    'vt_verdict': vt_verdict,
                    'vt_comment': vt_comment,
                    'qr_analysis': qr_analysis
                })
                
            except Exception as e:
                print(f"[red]Error processing attachment {i}: {e}[/red]")
                # Add error result so we don't lose track
                results.append({
                    'index': i,
                    'filename': f'error_attachment_{i}',
                    'content_type': 'unknown',
                    'size': 0,
                    'hash': 'N/A',
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
            print(f"[yellow]Warning: Could not sort results: {e}[/yellow]")
        
        # Display results with consistent color handling
        try:
            for result in results:
                try:
                    # Attachment header
                    header_text = Text()
                    header_text.append(f"Attachment {result.get('index', '?')}:", style="blue bold")
                    print(header_text)
                    
                    # Filename
                    filename_text = Text("  Filename: ")
                    filename_text.append(str(result.get('filename', 'unknown')), style="yellow")
                    print(filename_text)
                    
                    # Type
                    type_text = Text("  Type: ")
                    type_text.append(str(result.get('content_type', 'unknown')))
                    print(type_text)
                    
                    # Size
                    size_text = Text("  Size: ")
                    size_text.append(safe_format_file_size(result.get('size', 0)))
                    print(size_text)
                    
                    # SHA256 (color-coded by VT verdict)
                    if result.get('hash') != "N/A":
                        hash_colors = {
                            "malicious": "red",
                            "suspicious": "yellow", 
                            "benign": "green",
                            "unknown": "orange3",
                            "unchecked": "orange3"
                        }
                        hash_color = hash_colors.get(result.get('vt_verdict', 'unchecked'), "orange3")
                        
                        hash_text = Text("  SHA256: ")
                        # Apply defanging to hash if enabled (though hashes aren't typically defanged)
                        display_hash = result.get('hash', 'N/A')
                        try:
                            if defanger.should_defang():
                                display_hash = defanger.defang_text(display_hash)
                        except Exception:
                            pass
                        hash_text.append(display_hash, style=hash_color)
                        print(hash_text)
                    
                    # Risk Level (color-coded consistently)
                    risk_colors = {"high": "red", "medium": "yellow", "low": "green", "unknown": "orange3"}
                    risk_color = risk_colors.get(result.get('final_risk_level', 'unknown'), "white")
                    
                    risk_text = Text("  Risk Level: ")
                    risk_text.append(str(result.get('final_risk_level', 'unknown')).upper(), style=risk_color)
                    risk_text.append(f" ({result.get('final_risk_reason', 'unknown')})")
                    print(risk_text)
                    
                    # VirusTotal verdict (color-coded consistently)
                    vt_colors = {
                        "malicious": "red",
                        "suspicious": "yellow",
                        "benign": "green", 
                        "unknown": "orange3",
                        "unchecked": "orange3"
                    }
                    vt_color = vt_colors.get(result.get('vt_verdict', 'unchecked'), "orange3")
                    
                    vt_text = Text("  VirusTotal: ")
                    vt_text.append(str(result.get('vt_verdict', 'unchecked')).upper(), style=vt_color)
                    vt_text.append(f" ({result.get('vt_comment', 'unknown')})")
                    print(vt_text)
                    
                    # QR Code analysis (if applicable)
                    if result.get('qr_analysis'):
                        try:
                            qr_analyzer.display_qr_analysis(result.get('index', 0), result['qr_analysis'])
                        except Exception as e:
                            print(f"  [yellow]QR Analysis: Error displaying results - {e}[/yellow]")
                    
                    print()
                    
                except Exception as e:
                    print(f"[red]Error displaying attachment {result.get('index', '?')}: {e}[/red]")
                    print()
                    
        except Exception as e:
            print(f"[red]Error displaying attachment results: {e}[/red]")
        
        # Summary assessment (using final risk levels)
        try:
            final_high_risk_count = sum(1 for r in results if r.get('final_risk_level') == 'high')
            malicious_count = sum(1 for r in results if r.get('vt_verdict') == 'malicious')
            suspicious_count = sum(1 for r in results if r.get('vt_verdict') == 'suspicious')
            qr_codes_found = total_qr_count > 0
            
            if malicious_count > 0:
                summary = Text("CRITICAL: Malicious attachments detected!", style="red")
            elif qr_codes_found:
                # Use proper singular/plural for QR codes
                if total_qr_count == 1:
                    summary = Text("WARNING: QR code detected - highly suspicious!", style="red")
                else:
                    summary = Text("WARNING: QR codes detected - highly suspicious!", style="red")
            elif final_high_risk_count > 0 or suspicious_count > 0:
                summary = Text("WARNING: Suspicious attachments detected!", style="orange3")
            else:
                summary = Text("Attachments appear benign, but verify manually.", style="green")
            
            assessment_text = Text()
            assessment_text.append("ATTACHMENT ASSESSMENT:", style="blue bold")
            assessment_text.append(" ")
            assessment_text.append(summary)
            print(assessment_text)
            print()
            
        except Exception as e:
            print(f"[red]Error generating summary assessment: {e}[/red]")
            print()
        
        return results

    except Exception as e:
        print(f"[red]Critical error in attachment analysis: {e}[/red]")
        print("[yellow]Attachment analysis could not be completed.[/yellow]")
        return []