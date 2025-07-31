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

def get_file_extension(filename):
    """Extract file extension from filename, handling double extensions."""
    if not filename:
        return ""
    
    # Handle double extensions like .tar.gz, .doc.exe, etc.
    parts = filename.lower().split('.')
    if len(parts) > 1:
        return parts[-1]
    return ""

def categorize_attachment_risk(filename, content_type, size):
    """Categorize attachment risk based on filename and content type."""
    if not filename:
        return "unknown", "No filename provided"
    
    extension = get_file_extension(filename)
    risk_factors = []
    
    # Check for suspicious extensions
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
    
    # Check for double extensions (common evasion technique)
    filename_parts = filename.lower().split('.')
    if len(filename_parts) > 2:
        # Check if there's a suspicious extension before the final one
        for i, part in enumerate(filename_parts[:-1]):
            if part in SUSPICIOUS_EXTENSIONS:
                risk_factors.append("Double extension detected (possible evasion)")
                risk_level = "high"
                break
    
    # Check for suspicious filenames
    suspicious_names = [
        'invoice', 'receipt', 'document', 'file', 'attachment', 'urgent',
        'important', 'secure', 'encrypted', 'backup', 'update', 'install'
    ]
    filename_lower = filename.lower()
    for name in suspicious_names:
        if name in filename_lower and extension in SUSPICIOUS_EXTENSIONS:
            risk_factors.append(f"Suspicious filename pattern with executable extension")
            risk_level = "high"
            break
    
    # Check file size (very small or very large files can be suspicious)
    if size is not None:
        if size < 1024:  # Less than 1KB
            risk_factors.append("Unusually small file size")
        elif size > 50 * 1024 * 1024:  # Greater than 50MB
            risk_factors.append("Large file size")
    
    # Content-Type mismatch detection
    if content_type:
        expected_mime = mimetypes.guess_type(filename)[0]
        if expected_mime and content_type.lower() != expected_mime.lower():
            risk_factors.append("MIME type mismatch (possible spoofing)")
            if risk_level == "low":
                risk_level = "medium"
    
    if not risk_factors:
        risk_factors.append("Standard file type")
    
    return risk_level, "; ".join(risk_factors)

def calculate_file_hash(content):
    """Calculate SHA256 hash of file content."""
    if isinstance(content, str):
        content = content.encode('utf-8')
    return hashlib.sha256(content).hexdigest()

def check_file_hash_virustotal(file_hash, api_key, cache):
    """Check file hash against VirusTotal database."""
    if file_hash in cache:
        return cache[file_hash]
    
    if not api_key:
        cache[file_hash] = ("unchecked", "File hash will need to be investigated manually")
        return cache[file_hash]
    
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 429:
            while True:
                choice = input(
                    "[yellow]VirusTotal API rate limit reached.[/yellow]\n"
                    "Type 'wait' to wait 60 seconds, or 'skip' to proceed without checking: "
                ).strip().lower()
                if choice == "wait":
                    print("Waiting 60 seconds...")
                    time.sleep(60)
                    response = requests.get(url, headers=headers, timeout=10)
                    if response.status_code != 429:
                        break
                elif choice == "skip":
                    cache[file_hash] = ("unchecked", "File hash will need to be investigated manually")
                    return cache[file_hash]
                else:
                    print("Invalid input. Please type 'wait' or 'skip'.")
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            
            # Get additional file info
            file_info = data.get("data", {}).get("attributes", {})
            file_names = file_info.get("names", [])
            
            if malicious > 0:
                comment = (f"{malicious} vendor flagged this file as malicious"
                          if malicious == 1 else
                          f"{malicious} vendors flagged this file as malicious")
                if file_names:
                    comment += f" (known as: {', '.join(file_names[:3])})"
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
                cache[file_hash] = ("unchecked", "File hash will need to be investigated manually")
        
        elif response.status_code == 404:
            cache[file_hash] = ("unknown", "File not found in VirusTotal database")
        else:
            cache[file_hash] = ("unchecked", "File hash will need to be investigated manually")
    
    except Exception as e:
        print(f"[red]Error querying VirusTotal for file hash {file_hash}: {e}[/red]")
        cache[file_hash] = ("unchecked", "File hash will need to be investigated manually")
    
    return cache[file_hash]

def extract_attachments(msg_obj):
    """Extract attachment information from email message."""
    attachments = []
    
    if msg_obj.is_multipart():
        for part in msg_obj.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                content_type = part.get_content_type()
                
                # Get file content
                try:
                    content = part.get_payload(decode=True)
                    if content is None:
                        content = part.get_payload()
                        if isinstance(content, str):
                            content = content.encode('utf-8')
                except Exception:
                    content = b""
                
                size = len(content) if content else 0
                
                attachments.append({
                    'filename': filename or 'unnamed_attachment',
                    'content_type': content_type,
                    'size': size,
                    'content': content
                })
    
    return attachments

def format_file_size(size_bytes):
    """Format file size in human readable format."""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB"]
    i = 0
    size = float(size_bytes)
    
    while size >= 1024.0 and i < len(size_names) - 1:
        size /= 1024.0
        i += 1
    
    return f"{size:.1f} {size_names[i]}"

def determine_risk_from_qr(qr_analysis):
    """Determine risk level and reason based on QR analysis results."""
    if not qr_analysis or not qr_analysis.get('qr_found'):
        return None, None
    
    # Check if any QR URLs are malicious or suspicious
    malicious_qr = any(qr.get('verdict') == 'malicious' for qr in qr_analysis.get('qr_results', []))
    suspicious_qr = any(qr.get('verdict') == 'suspicious' for qr in qr_analysis.get('qr_results', []))
    
    qr_count = len(qr_analysis.get('qr_results', []))
    qr_text = "QR code" if qr_count == 1 else "QR codes"
    
    if malicious_qr:
        return "high", f"Malicious {qr_text} detected"
    elif suspicious_qr:
        return "high", f"Suspicious {qr_text} detected"
    else:
        return "high", f"{qr_text} detected"

def analyze_attachments(msg_obj, api_key):
    """Main function to analyze email attachments."""
    
    attachments = extract_attachments(msg_obj)
    
    if not attachments:
        print(Text("No attachments found in this email.", style="green"))
        print()
        return []
    
    # Create properly colored text for attachment count
    count_text = Text()
    count_text.append("Found ")
    count_text.append(str(len(attachments)), style="blue")
    count_text.append(" attachment")
    if len(attachments) != 1:
        count_text.append("s")
    count_text.append(":\n")
    print(count_text)
    
    cache = {}
    results = []
    total_qr_count = 0
    
    # Process each attachment
    for i, attachment in enumerate(attachments, 1):
        filename = attachment['filename']
        content_type = attachment['content_type']
        size = attachment['size']
        content = attachment['content']
        
        # Calculate file hash
        file_hash = calculate_file_hash(content) if content else "N/A"
        
        # Basic risk categorization
        base_risk_level, base_risk_reason = categorize_attachment_risk(filename, content_type, size)
        
        # Check with VirusTotal if we have content
        vt_verdict = "unchecked"
        vt_comment = "No content to analyze"
        
        if content and file_hash != "N/A":
            vt_verdict, vt_comment = check_file_hash_virustotal(file_hash, api_key, cache)
        
        # QR Code analysis (run once per attachment)
        qr_analysis = None
        if filename.lower().endswith('.pdf'):
            qr_analysis = qr_analyzer.analyze_pdf_qr_codes({
                'filename': filename,
                'content': content,
                'content_type': content_type,
                'size': size,
                'hash': file_hash
            }, api_key)
            
            if qr_analysis.get('qr_found'):
                total_qr_count += len(qr_analysis.get('qr_results', []))
        
        # Determine final risk level (considering QR codes)
        qr_risk_level, qr_risk_reason = determine_risk_from_qr(qr_analysis)
        
        if qr_risk_level:
            # QR codes detected - elevate risk
            if base_risk_level == "low":
                final_risk_level = qr_risk_level
                final_risk_reason = qr_risk_reason
            else:
                final_risk_level = max(base_risk_level, qr_risk_level, key=lambda x: {"low": 0, "medium": 1, "high": 2}[x])
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
    
    # Sort by final risk level and VT verdict
    risk_priority = {"high": 0, "medium": 1, "low": 2, "unknown": 3}
    vt_priority = {"malicious": 0, "suspicious": 1, "unknown": 2, "unchecked": 2, "benign": 3}
    
    results.sort(key=lambda x: (
        risk_priority.get(x['final_risk_level'], 4),
        vt_priority.get(x['vt_verdict'], 5)
    ))
    
    # Display results with consistent color handling
    for result in results:
        # Attachment header
        header_text = Text()
        header_text.append(f"Attachment {result['index']}:", style="blue bold")
        print(header_text)
        
        # Filename
        filename_text = Text("  Filename: ")
        filename_text.append(result['filename'], style="yellow")
        print(filename_text)
        
        # Type
        type_text = Text("  Type: ")
        type_text.append(result['content_type'])
        print(type_text)
        
        # Size
        size_text = Text("  Size: ")
        size_text.append(format_file_size(result['size']))
        print(size_text)
        
        # SHA256 (color-coded by VT verdict)
        if result['hash'] != "N/A":
            hash_colors = {
                "malicious": "red",
                "suspicious": "yellow", 
                "benign": "green",
                "unknown": "orange3",
                "unchecked": "orange3"
            }
            hash_color = hash_colors.get(result['vt_verdict'], "orange3")
            
            hash_text = Text("  SHA256: ")
            # Apply defanging to hash if enabled (though hashes aren't typically defanged, keeping for consistency)
            display_hash = defanger.defang_text(result['hash']) if defanger.should_defang() else result['hash']
            hash_text.append(display_hash, style=hash_color)
            print(hash_text)
        
        # Risk Level (color-coded consistently)
        risk_colors = {"high": "red", "medium": "yellow", "low": "green", "unknown": "orange3"}
        risk_color = risk_colors.get(result['final_risk_level'], "white")
        
        risk_text = Text("  Risk Level: ")
        risk_text.append(result['final_risk_level'].upper(), style=risk_color)
        risk_text.append(f" ({result['final_risk_reason']})")
        print(risk_text)
        
        # VirusTotal verdict (color-coded consistently)
        vt_colors = {
            "malicious": "red",
            "suspicious": "yellow",
            "benign": "green", 
            "unknown": "orange3",
            "unchecked": "orange3"
        }
        vt_color = vt_colors.get(result['vt_verdict'], "orange3")
        
        vt_text = Text("  VirusTotal: ")
        vt_text.append(result['vt_verdict'].upper(), style=vt_color)
        vt_text.append(f" ({result['vt_comment']})")
        print(vt_text)
        
        # QR Code analysis (if applicable)
        if result['qr_analysis']:
            qr_analyzer.display_qr_analysis(result['index'], result['qr_analysis'])
        
        print()
    
    # Summary assessment (using final risk levels)
    final_high_risk_count = sum(1 for r in results if r['final_risk_level'] == 'high')
    malicious_count = sum(1 for r in results if r['vt_verdict'] == 'malicious')
    suspicious_count = sum(1 for r in results if r['vt_verdict'] == 'suspicious')
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
    
    return results