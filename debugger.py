#!/usr/bin/env python3
"""
Fixed debug tool for Windows - handles encoding issues
"""

import sys
import os
import email
from email import policy
import extract_msg

# Fix Windows encoding issues
if sys.platform.startswith('win'):
    # Set stdout encoding to handle Unicode
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.detach())

def safe_print(text):
    """Safe print that handles encoding issues on Windows"""
    try:
        print(text)
    except UnicodeEncodeError:
        # Fallback to ASCII-safe characters
        safe_text = text.replace('✓', '[OK]').replace('❌', '[ERROR]').replace('📧', '[EMAIL]').replace('📋', '[LIST]').replace('📊', '[SUMMARY]').replace('🔍', '[SEARCH]')
        print(safe_text.encode('ascii', errors='replace').decode('ascii'))

def debug_attachment_extraction(file_path):
    """Debug attachment extraction step by step - Windows safe version"""
    safe_print("=== ATTACHMENT EXTRACTION DEBUG ===")
    safe_print(f"File: {file_path}")
    safe_print("")
    
    # Step 1: Check file exists and size
    if not os.path.exists(file_path):
        safe_print("[ERROR] File does not exist!")
        return
    
    file_size = os.path.getsize(file_path)
    safe_print(f"[OK] File exists, size: {file_size:,} bytes")
    
    # Step 2: Determine file type
    file_ext = os.path.splitext(file_path)[1].lower()
    safe_print(f"[OK] File extension: {file_ext}")
    
    # Step 3: Try to load the email
    try:
        if file_ext == '.msg':
            safe_print("[EMAIL] Loading as MSG file...")
            msg = extract_msg.Message(file_path)
            
            # Debug MSG properties
            safe_print(f"[EMAIL] MSG loaded. Properties:")
            safe_print(f"   - Subject: {getattr(msg, 'subject', 'No subject')}")
            safe_print(f"   - Sender: {getattr(msg, 'sender', 'No sender')}")
            safe_print(f"   - Has attachments: {hasattr(msg, 'attachments')}")
            
            # Check MSG attachments directly
            if hasattr(msg, 'attachments'):
                msg_attachments = getattr(msg, 'attachments', [])
                safe_print(f"   - MSG attachments count: {len(msg_attachments)}")
                
                for i, att in enumerate(msg_attachments):
                    safe_print(f"      Attachment {i+1}:")
                    if hasattr(att, 'longFilename'):
                        safe_print(f"         Filename: {att.longFilename}")
                    elif hasattr(att, 'shortFilename'):
                        safe_print(f"         Filename: {att.shortFilename}")
                    else:
                        safe_print(f"         Filename: Unknown")
                    
                    if hasattr(att, 'data'):
                        data_size = len(att.data) if att.data else 0
                        safe_print(f"         Size: {data_size} bytes")
                        if att.data and len(att.data) > 0:
                            safe_print(f"         First 16 bytes: {att.data[:16].hex()}")
            
            # Convert MSG to email message for standard processing
            eml_str = msg_to_eml_string(msg)
            eml_bytes = eml_str.encode('utf-8', errors='replace')
            msg_obj = email.message_from_bytes(eml_bytes, policy=policy.default)
            
        elif file_ext == '.eml':
            safe_print("[EMAIL] Loading as EML file...")
            with open(file_path, "rb") as f:
                msg_obj = email.message_from_binary_file(f, policy=policy.default)
        else:
            safe_print(f"[ERROR] Unsupported file type: {file_ext}")
            return
            
        safe_print("[OK] Email converted to standard format")
        
    except Exception as e:
        safe_print(f"[ERROR] Loading email: {e}")
        return
    
    # Step 4: Check if multipart
    safe_print(f"[EMAIL] Email structure analysis:")
    safe_print(f"   - Is multipart: {msg_obj.is_multipart() if hasattr(msg_obj, 'is_multipart') else 'Unknown'}")
    safe_print(f"   - Content-Type: {msg_obj.get_content_type() if hasattr(msg_obj, 'get_content_type') else 'Unknown'}")
    
    if hasattr(msg_obj, 'get_content_maintype'):
        safe_print(f"   - Main type: {msg_obj.get_content_maintype()}")
    
    # Step 5: Walk through all parts
    attachment_count = 0
    part_count = 0
    
    safe_print(f"")
    safe_print(f"[LIST] Walking through email parts:")
    
    if hasattr(msg_obj, 'walk'):
        for part in msg_obj.walk():
            part_count += 1
            safe_print(f"")
            safe_print(f"   Part {part_count}:")
            
            try:
                content_type = part.get_content_type() if hasattr(part, 'get_content_type') else 'unknown'
                safe_print(f"      Content-Type: {content_type}")
                
                if hasattr(part, 'get_content_disposition'):
                    disposition = part.get_content_disposition()
                    safe_print(f"      Content-Disposition: {disposition}")
                    
                    if disposition == 'attachment':
                        attachment_count += 1
                        filename = part.get_filename() if hasattr(part, 'get_filename') else 'No filename'
                        safe_print(f"      [OK] ATTACHMENT FOUND: {filename}")
                        
                        # Try to get payload
                        try:
                            payload = part.get_payload(decode=True) if hasattr(part, 'get_payload') else None
                            if payload:
                                safe_print(f"         Payload size: {len(payload)} bytes")
                                safe_print(f"         First 32 bytes (hex): {payload[:32].hex()}")
                                
                                # Check for PDF magic number
                                if payload.startswith(b'%PDF-'):
                                    safe_print(f"         [OK] PDF MAGIC NUMBER DETECTED!")
                                else:
                                    safe_print(f"         Magic bytes: {payload[:8]}")
                            else:
                                safe_print(f"         [ERROR] No payload found")
                        except Exception as e:
                            safe_print(f"         [ERROR] Error getting payload: {e}")
                    
                    elif disposition == 'inline':
                        safe_print(f"      [INFO] Inline content (not attachment)")
                        filename = part.get_filename() if hasattr(part, 'get_filename') else None
                        if filename:
                            safe_print(f"         Filename: {filename}")
                    
                    else:
                        safe_print(f"      [INFO] Other disposition: {disposition}")
                        
                else:
                    safe_print(f"      [INFO] No content-disposition")
                    
                # Check for Content-Type that might indicate attachment
                if 'application/' in content_type or 'image/' in content_type:
                    safe_print(f"      [INFO] Binary content type detected")
                    
            except Exception as e:
                safe_print(f"      [ERROR] Error processing part: {e}")
    else:
        safe_print("   [ERROR] Email object has no 'walk' method")
    
    safe_print(f"")
    safe_print(f"[SUMMARY] RESULTS:")
    safe_print(f"   Total parts: {part_count}")
    safe_print(f"   Attachments found: {attachment_count}")
    
    if attachment_count == 0:
        safe_print(f"")
        safe_print(f"[SEARCH] No attachments found. Possible reasons:")
        safe_print(f"   1. MSG conversion lost attachment structure")
        safe_print(f"   2. Attachment is embedded as 'inline' not 'attachment'")
        safe_print(f"   3. Attachment is stored as OLE embedded object")
        safe_print(f"   4. File is corrupted or not a standard MSG format")
        safe_print(f"")
        safe_print(f"[SEARCH] Try opening the file in Outlook to verify attachment exists")

def msg_to_eml_string(msg):
    """Convert extract_msg.Message to EML string with better attachment handling"""
    headers = []
    
    try:
        # Basic headers
        header_mappings = {
            'From': 'sender',
            'To': 'to', 
            'Cc': 'cc',
            'Bcc': 'bcc',
            'Subject': 'subject',
            'Date': 'date',
            'Message-ID': 'messageId'
        }
        
        for header_name, attr_name in header_mappings.items():
            try:
                value = getattr(msg, attr_name, None)
                if value:
                    clean_value = str(value).replace('\r', ' ').replace('\n', ' ').strip()
                    if clean_value:
                        headers.append(f"{header_name}: {clean_value}")
            except Exception:
                continue
        
        # CRITICAL: Add multipart headers if attachments exist
        if hasattr(msg, 'attachments') and getattr(msg, 'attachments', []):
            headers.append("MIME-Version: 1.0")
            headers.append("Content-Type: multipart/mixed; boundary=\"attachment-boundary\"")
        
        if not headers:
            headers.append("Subject: [MSG File - Headers Unavailable]")
        
        headers.append("")  # Blank line
        
        # Body
        body_content = ""
        try:
            body = getattr(msg, 'body', None) or getattr(msg, 'htmlBody', None) or ""
            if body:
                body = str(body).replace('\r\n', '\n').replace('\r', '\n')
                if len(body) > 1024 * 1024:
                    body = body[:1024*1024] + "\n[... content truncated ...]"
            else:
                body = "[No body content available]"
            
            # If we have attachments, format as multipart
            if hasattr(msg, 'attachments') and getattr(msg, 'attachments', []):
                body_content += "--attachment-boundary\n"
                body_content += "Content-Type: text/plain\n\n"
                body_content += body + "\n\n"
                
                # Add each attachment
                for att in getattr(msg, 'attachments', []):
                    try:
                        filename = getattr(att, 'longFilename', None) or getattr(att, 'shortFilename', 'unknown')
                        data = getattr(att, 'data', b'')
                        
                        body_content += f"--attachment-boundary\n"
                        body_content += f"Content-Type: application/octet-stream\n"
                        body_content += f"Content-Disposition: attachment; filename=\"{filename}\"\n"
                        body_content += f"Content-Transfer-Encoding: base64\n\n"
                        
                        if data:
                            import base64
                            encoded = base64.b64encode(data).decode('ascii')
                            # Split into 76-character lines (RFC compliant)
                            for i in range(0, len(encoded), 76):
                                body_content += encoded[i:i+76] + "\n"
                        
                        body_content += "\n"
                    except Exception as e:
                        safe_print(f"[ERROR] Error processing attachment in conversion: {e}")
                
                body_content += "--attachment-boundary--\n"
            else:
                body_content = body
                
        except Exception as e:
            body_content = f"[Error reading body content: {e}]"

        return "\r\n".join(headers) + body_content
        
    except Exception as e:
        return f"Subject: [MSG Parsing Error: {e}]\r\n\r\n[Could not parse MSG file content]"

if __name__ == "__main__":
    if len(sys.argv) != 2:
        safe_print("Usage: python debugger.py <email_file_path>")
        sys.exit(1)
    
    debug_attachment_extraction(sys.argv[1])