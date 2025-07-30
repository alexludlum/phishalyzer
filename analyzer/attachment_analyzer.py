import re
import time
import hashlib
import requests
from rich import print
from rich.text import Text
import shutil
import mimetypes
import base64
from email.message import EmailMessage
from . import qr_analyzer  # Import the new QR analyzer

def print_centered_header(title: str = "ATTACHMENT ANALYSIS"):
    term_width = shutil.get_terminal_size().columns
    max_width = min(term_width, 80)
    header_line = "=" * max_width
    padding = (max_width - len(title)) // 2
    if padding < 0:
        padding = 0
    print(header_line)
    print(" " * padding + title)
    print(header_line + "\n")

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
            first_seen = file_info.get("first_submission_date")
            
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

def analyze_attachments(msg_obj, api_key):
    """Main function to analyze email attachments."""
    print_centered_header()
    
    attachments = extract_attachments(msg_obj)
    
    if not attachments:
        print("[green]No attachments found in this email.[/green]\n")
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
    
    for i, attachment in enumerate(attachments, 1):
        filename = attachment['filename']
        content_type = attachment['content_type']
        size = attachment['size']
        content = attachment['content']
        
        # Calculate file hash
        file_hash = calculate_file_hash(content) if content else "N/A"
        
        # Categorize risk
        risk_level, risk_reason = categorize_attachment_risk(filename, content_type, size)
        
        # Check with VirusTotal if we have content
        vt_verdict = "unchecked"
        vt_comment = "No content to analyze"
        
        if content and file_hash != "N/A":
            vt_verdict, vt_comment = check_file_hash_virustotal(file_hash, api_key, cache)
        
        results.append({
            'index': i,
            'filename': filename,
            'content_type': content_type,
            'size': size,
            'hash': file_hash,
            'risk_level': risk_level,
            'risk_reason': risk_reason,
            'vt_verdict': vt_verdict,
            'vt_comment': vt_comment,
            'content': content  # Store content for QR analysis
        })
    
    # Sort by risk level and VT verdict
    risk_priority = {"high": 0, "medium": 1, "low": 2, "unknown": 3}
    vt_priority = {"malicious": 0, "suspicious": 1, "unknown": 2, "unchecked": 2, "benign": 3}
    
    results.sort(key=lambda x: (
        risk_priority.get(x['risk_level'], 4),
        vt_priority.get(x['vt_verdict'], 5)
    ))
    
    # Display results
    qr_codes_found = False  # Track if any QR codes were found
    total_qr_count = 0  # Track total number of QR codes
    
    for result in results:
        print(f"[blue bold]Attachment {result['index']}:[/blue bold]")
        print(f"  Filename: [yellow]{result['filename']}[/yellow]")
        print(f"  Type: {result['content_type']}")
        
        # Create size line without Rich markup interpretation
        size_line = Text("  Size: ")
        size_line.append(format_file_size(result['size']))
        print(size_line)
        
        if result['hash'] != "N/A":
            # Color the hash based on VirusTotal verdict
            if result['vt_verdict'] == "malicious":
                hash_color = "red"
            elif result['vt_verdict'] == "suspicious":
                hash_color = "yellow"
            elif result['vt_verdict'] == "benign":
                hash_color = "green"
            else:  # unknown or unchecked
                hash_color = "orange3"
            
            print(f"  SHA256: [{hash_color}]{result['hash']}[/{hash_color}]")
        
        # QR Code analysis for PDFs (do this before risk assessment display)
        qr_analysis = None
        if result['filename'].lower().endswith('.pdf'):
            qr_analysis = qr_analyzer.analyze_pdf_qr_codes(result, api_key)
            if qr_analysis['qr_found']:
                qr_codes_found = True
                total_qr_count += len(qr_analysis.get('qr_results', []))
        
        # Risk assessment - updated to account for QR codes
        original_risk_level = result['risk_level']
        original_risk_reason = result['risk_reason']
        
        # Elevate risk if QR codes are found
        if qr_analysis and qr_analysis['qr_found']:
            if original_risk_level == "low":
                display_risk_level = "high"
                display_risk_reason = "QR code detected in attachment"
            else:
                display_risk_level = original_risk_level
                display_risk_reason = f"{original_risk_reason}; QR code detected"
        else:
            display_risk_level = original_risk_level
            display_risk_reason = original_risk_reason
        
        risk_color = {"high": "red", "medium": "yellow", "low": "green", "unknown": "orange3"}
        risk_text = Text(display_risk_level.upper(), style=risk_color.get(display_risk_level, "white"))
        
        # Create risk level line with proper color preservation
        risk_line = Text("  Risk Level: ")
        risk_line.append(risk_text)
        risk_line.append(f" ({display_risk_reason})")
        print(risk_line)
        
        # VirusTotal verdict
        if result['vt_verdict'] == "malicious":
            vt_text = Text("MALICIOUS", style="red")
        elif result['vt_verdict'] == "suspicious":
            vt_text = Text("SUSPICIOUS", style="yellow")
        elif result['vt_verdict'] == "benign":
            vt_text = Text("BENIGN", style="green")
        elif result['vt_verdict'] == "unknown":
            vt_text = Text("UNKNOWN", style="orange3")
        else:
            vt_text = Text("UNCHECKED", style="orange3")
        
        # Create the full VirusTotal line with proper color preservation
        vt_line = Text("  VirusTotal: ")
        vt_line.append(vt_text)
        vt_line.append(f" ({result['vt_comment']})")
        print(vt_line)
        
        # Display QR Code analysis
        if qr_analysis:
            qr_analyzer.display_qr_analysis(result['index'], qr_analysis)
        
        print()
    
    # Summary assessment
    high_risk_count = sum(1 for r in results if r['risk_level'] == 'high')
    malicious_count = sum(1 for r in results if r['vt_verdict'] == 'malicious')
    suspicious_count = sum(1 for r in results if r['vt_verdict'] == 'suspicious')
    
    if malicious_count > 0:
        summary = Text("CRITICAL: Malicious attachments detected!", style="red")
    elif qr_codes_found:
        # Use proper singular/plural for QR codes
        if total_qr_count == 1:
            summary = Text("WARNING: QR code detected - highly suspicious!", style="red")
        else:
            summary = Text("WARNING: QR codes detected - highly suspicious!", style="red")
    elif high_risk_count > 0 or suspicious_count > 0:
        summary = Text("WARNING: Suspicious attachments detected!", style="orange3")
    else:
        summary = Text("Attachments appear benign, but verify manually.", style="green")
    
    print(Text("ATTACHMENT ASSESSMENT:", style="blue bold"), summary)
    print()
    
    return results