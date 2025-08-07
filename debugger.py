#!/usr/bin/env python3
"""
Debug tool to diagnose attachment extraction issues
"""

import sys
import os
import email
from email import policy
import extract_msg

def debug_attachment_extraction(file_path):
    """Debug attachment extraction step by step"""
    print("=== ATTACHMENT EXTRACTION DEBUG ===")
    print(f"File: {file_path}")
    print()
    
    # Step 1: Check file exists and size
    if not os.path.exists(file_path):
        print("❌ ERROR: File does not exist!")
        return
    
    file_size = os.path.getsize(file_path)
    print(f"✓ File exists, size: {file_size:,} bytes")
    
    # Step 2: Determine file type
    file_ext = os.path.splitext(file_path)[1].lower()
    print(f"✓ File extension: {file_ext}")
    
    # Step 3: Try to load the email
    try:
        if file_ext == '.msg':
            print("📧 Loading as MSG file...")
            msg = extract_msg.Message(file_path)
            
            # Convert MSG to email message for consistent handling
            eml_str = msg_to_eml_string(msg)
            eml_bytes = eml_str.encode('utf-8', errors='replace')
            msg_obj = email.message_from_bytes(eml_bytes, policy=policy.default)
            
        elif file_ext == '.eml':
            print("📧 Loading as EML file...")
            with open(file_path, "rb") as f:
                msg_obj = email.message_from_binary_file(f, policy=policy.default)
        else:
            print(f"❌ ERROR: Unsupported file type: {file_ext}")
            return
            
        print("✓ Email loaded successfully")
        
    except Exception as e:
        print(f"❌ ERROR loading email: {e}")
        return
    
    # Step 4: Check if multipart
    print(f"📧 Email structure analysis:")
    print(f"   - Is multipart: {msg_obj.is_multipart() if hasattr(msg_obj, 'is_multipart') else 'Unknown'}")
    print(f"   - Content-Type: {msg_obj.get_content_type() if hasattr(msg_obj, 'get_content_type') else 'Unknown'}")
    
    if hasattr(msg_obj, 'get_content_maintype'):
        print(f"   - Main type: {msg_obj.get_content_maintype()}")
    
    # Step 5: Walk through all parts
    attachment_count = 0
    part_count = 0
    
    print(f"\n📋 Walking through email parts:")
    
    if hasattr(msg_obj, 'walk'):
        for part in msg_obj.walk():
            part_count += 1
            print(f"\n   Part {part_count}:")
            
            try:
                content_type = part.get_content_type() if hasattr(part, 'get_content_type') else 'unknown'
                print(f"      Content-Type: {content_type}")
                
                if hasattr(part, 'get_content_disposition'):
                    disposition = part.get_content_disposition()
                    print(f"      Content-Disposition: {disposition}")
                    
                    if disposition == 'attachment':
                        attachment_count += 1
                        filename = part.get_filename() if hasattr(part, 'get_filename') else 'No filename'
                        print(f"      ✓ ATTACHMENT FOUND: {filename}")
                        
                        # Try to get payload
                        try:
                            payload = part.get_payload(decode=True) if hasattr(part, 'get_payload') else None
                            if payload:
                                print(f"         Payload size: {len(payload)} bytes")
                                print(f"         First 32 bytes (hex): {payload[:32].hex()}")
                            else:
                                print(f"         ❌ No payload found")
                        except Exception as e:
                            print(f"         ❌ Error getting payload: {e}")
                else:
                    print(f"      No get_content_disposition method")
                    
            except Exception as e:
                print(f"      ❌ Error processing part: {e}")
    else:
        print("   ❌ Email object has no 'walk' method")
    
    print(f"\n📊 SUMMARY:")
    print(f"   Total parts: {part_count}")
    print(f"   Attachments found: {attachment_count}")
    
    # Step 6: Try alternative attachment detection methods
    print(f"\n🔍 Alternative detection methods:")
    
    # Method 1: Check for specific headers
    try:
        if hasattr(msg_obj, 'get_all'):
            content_types = msg_obj.get_all('Content-Type') or []
            print(f"   Content-Type headers: {len(content_types)}")
            for i, ct in enumerate(content_types[:3]):  # Show first 3
                print(f"      {i+1}: {ct}")
    except Exception as e:
        print(f"   Error checking Content-Type headers: {e}")
    
    # Method 2: Look for attachment-like content types
    try:
        attachment_like_parts = []
        if hasattr(msg_obj, 'walk'):
            for part in msg_obj.walk():
                try:
                    ct = part.get_content_type() if hasattr(part, 'get_content_type') else ''
                    if ct and not ct.startswith('text/') and not ct.startswith('multipart/'):
                        attachment_like_parts.append(ct)
                except:
                    continue
        
        print(f"   Non-text/non-multipart parts: {len(attachment_like_parts)}")
        for ct in attachment_like_parts[:5]:  # Show first 5
            print(f"      - {ct}")
            
    except Exception as e:
        print(f"   Error checking content types: {e}")

def msg_to_eml_string(msg):
    """Convert extract_msg.Message to EML string"""
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
        
        if not headers:
            headers.append("Subject: [MSG File - Headers Unavailable]")
        
        headers.append("")  # Blank line
        
        # Body
        try:
            body = getattr(msg, 'body', None) or getattr(msg, 'htmlBody', None) or ""
            if body:
                body = str(body).replace('\r\n', '\n').replace('\r', '\n')
                if len(body) > 1024 * 1024:
                    body = body[:1024*1024] + "\n[... content truncated ...]"
            else:
                body = "[No body content available]"
        except Exception:
            body = "[Error reading body content]"

        return "\r\n".join(headers) + body
        
    except Exception as e:
        return f"Subject: [MSG Parsing Error: {e}]\r\n\r\n[Could not parse MSG file content]"

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python attachment_debug.py <email_file_path>")
        sys.exit(1)
    
    debug_attachment_extraction(sys.argv[1])