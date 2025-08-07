#!/usr/bin/env python3
"""
Diagnostic tool to debug MSG to EML conversion and attachment preservation
"""

import sys
import os
import email
from email import policy
import extract_msg
import base64
import mimetypes
import re

def debug_conversion_step_by_step(file_path):
    """Debug the entire MSG->EML conversion process"""
    print("=== MSG CONVERSION DIAGNOSTIC ===")
    print("File: " + file_path)
    print("")
    
    try:
        # Step 1: Load MSG
        print("STEP 1: Loading MSG file...")
        msg = extract_msg.Message(file_path)
        print("MSG loaded successfully")
        
        # Step 2: Check MSG attachments
        print("\nSTEP 2: Checking original MSG attachments...")
        if hasattr(msg, 'attachments'):
            attachments = getattr(msg, 'attachments', [])
            print(f"Original attachments: {len(attachments)}")
            
            for i, att in enumerate(attachments):
                print(f"\n  Original Attachment {i+1}:")
                
                # Get all possible filename attributes
                filename_attrs = ['longFilename', 'shortFilename', 'displayName', 'name']
                filename = None
                for attr in filename_attrs:
                    if hasattr(att, attr):
                        val = getattr(att, attr, None)
                        if val:
                            filename = str(val).strip()
                            print(f"    {attr}: {filename}")
                            break
                
                if not filename:
                    filename = "no_filename_found"
                    print(f"    Final filename: {filename}")
                
                # Check data
                if hasattr(att, 'data') and att.data:
                    data_size = len(att.data)
                    print(f"    Data size: {data_size} bytes")
                    print(f"    Magic bytes: {att.data[:8].hex()}")
                    if att.data.startswith(b'%PDF-'):
                        print("    *** PDF DETECTED ***")
                else:
                    print("    No data attribute")
        else:
            print("No 'attachments' attribute in MSG")
            return
        
        # Step 3: Test the conversion
        print("\nSTEP 3: Converting MSG to EML...")
        eml_string = improved_msg_to_eml_string(msg)
        
        # Show first part of EML string for debugging
        print("EML string created, length: " + str(len(eml_string)))
        print("First 500 characters:")
        print(repr(eml_string[:500]))
        print("")
        
        # Step 4: Parse the converted EML
        print("STEP 4: Parsing converted EML...")
        eml_bytes = eml_string.encode('utf-8', errors='replace')
        msg_obj = email.message_from_bytes(eml_bytes, policy=policy.default)
        
        print("Parsed EML properties:")
        print(f"  Is multipart: {msg_obj.is_multipart()}")
        print(f"  Content-Type: {msg_obj.get_content_type()}")
        print(f"  Has walk method: {hasattr(msg_obj, 'walk')}")
        
        # Step 5: Walk through converted parts
        print("\nSTEP 5: Walking through converted email parts...")
        attachment_count = 0
        part_count = 0
        
        if hasattr(msg_obj, 'walk'):
            for part in msg_obj.walk():
                part_count += 1
                print(f"\n  Part {part_count}:")
                
                try:
                    content_type = part.get_content_type()
                    print(f"    Content-Type: {content_type}")
                    
                    if hasattr(part, 'get_content_disposition'):
                        disposition = part.get_content_disposition()
                        print(f"    Content-Disposition: {disposition}")
                        
                        if disposition == 'attachment':
                            attachment_count += 1
                            filename = part.get_filename()
                            print(f"    *** FOUND ATTACHMENT: {filename} ***")
                            
                            # Test payload extraction
                            try:
                                payload = part.get_payload(decode=True)
                                if payload:
                                    print(f"      Payload size: {len(payload)} bytes")
                                    if payload.startswith(b'%PDF-'):
                                        print("      *** PDF MAGIC PRESERVED! ***")
                                    else:
                                        print(f"      Magic: {payload[:8].hex()}")
                                else:
                                    print("      No payload")
                            except Exception as e:
                                print(f"      Payload error: {e}")
                        
                        elif disposition == 'inline':
                            print(f"    Inline content (filename: {part.get_filename()})")
                        
                    else:
                        print("    No Content-Disposition")
                
                except Exception as e:
                    print(f"    Part error: {e}")
        
        # Step 6: Summary
        print(f"\n=== CONVERSION SUMMARY ===")
        print(f"Original MSG attachments: {len(getattr(msg, 'attachments', []))}")
        print(f"Converted EML parts: {part_count}")
        print(f"Detected attachments: {attachment_count}")
        
        if len(getattr(msg, 'attachments', [])) > 0 and attachment_count == 0:
            print("*** PROBLEM: Attachments lost during conversion! ***")
            
            # Debug the EML string structure
            print("\nDEBUGGING EML STRING STRUCTURE:")
            lines = eml_string.split('\n')
            boundary_lines = [i for i, line in enumerate(lines) if 'phishalyzer-boundary' in line]
            print(f"Boundary lines found at: {boundary_lines}")
            
            attachment_lines = [i for i, line in enumerate(lines) if 'Content-Disposition: attachment' in line]
            print(f"Attachment headers at: {attachment_lines}")
            
            if boundary_lines and not attachment_lines:
                print("*** Boundaries exist but no attachment headers - conversion bug ***")
            elif not boundary_lines:
                print("*** No boundaries found - multipart not created ***")
        
    except Exception as e:
        print(f"Error in conversion diagnostic: {e}")

def improved_msg_to_eml_string(msg):
    """Improved MSG to EML conversion with extensive debugging"""
    import base64
    import mimetypes
    
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
        
        # Check attachments
        has_attachments = hasattr(msg, 'attachments') and getattr(msg, 'attachments', [])
        print(f"DEBUG: has_attachments = {has_attachments}")
        
        if has_attachments:
            attachments = getattr(msg, 'attachments', [])
            print(f"DEBUG: Found {len(attachments)} attachments to convert")
            
            # Add multipart headers
            headers.append("MIME-Version: 1.0")
            headers.append("Content-Type: multipart/mixed; boundary=\"phishalyzer-boundary\"")
            print("DEBUG: Added multipart headers")
        
        if not headers:
            headers.append("Subject: [MSG File - Headers Unavailable]")
        
        headers.append("")  # Blank line
        
        # Build body
        body_parts = []
        
        if has_attachments:
            # Main body part
            body_parts.append("--phishalyzer-boundary")
            body_parts.append("Content-Type: text/plain; charset=utf-8")
            body_parts.append("Content-Transfer-Encoding: 8bit")
            body_parts.append("")
            print("DEBUG: Added main body boundary")
        
        # Get body content
        try:
            body = getattr(msg, 'body', None) or getattr(msg, 'htmlBody', None) or ""
            if body:
                body = str(body).replace('\r\n', '\n').replace('\r', '\n')
                if len(body) > 1024 * 1024:
                    body = body[:1024*1024] + "\n[... truncated ...]"
            else:
                body = "[No body content available]"
        except Exception:
            body = "[Error reading body content]"
        
        body_parts.append(body)
        
        # Process attachments
        if has_attachments:
            attachments = getattr(msg, 'attachments', [])
            print(f"DEBUG: Processing {len(attachments)} attachments...")
            
            for att_idx, att in enumerate(attachments):
                try:
                    print(f"DEBUG: Processing attachment {att_idx + 1}")
                    
                    # Get filename
                    filename = None
                    filename_attrs = ['longFilename', 'shortFilename', 'displayName', 'name']
                    for attr in filename_attrs:
                        if hasattr(att, attr):
                            val = getattr(att, attr, None)
                            if val and str(val).strip():
                                filename = str(val).strip()
                                print(f"DEBUG: Got filename '{filename}' from {attr}")
                                break
                    
                    if not filename:
                        filename = f"attachment_{att_idx + 1}"
                        print(f"DEBUG: Using default filename: {filename}")
                    
                    # Get data
                    data = getattr(att, 'data', b'')
                    print(f"DEBUG: Data size: {len(data) if data else 0} bytes")
                    
                    if data and len(data) > 0:
                        # Determine content type
                        content_type = "application/octet-stream"
                        try:
                            guessed_type, encoding = mimetypes.guess_type(filename)
                            if guessed_type:
                                content_type = guessed_type
                        except:
                            pass
                        
                        # Magic number override
                        if data.startswith(b'%PDF-'):
                            content_type = "application/pdf"
                            print(f"DEBUG: Detected PDF magic, setting content-type to application/pdf")
                        
                        print(f"DEBUG: Final content-type: {content_type}")
                        
                        # Add attachment part
                        body_parts.append("")
                        body_parts.append("--phishalyzer-boundary")
                        body_parts.append(f"Content-Type: {content_type}")
                        body_parts.append(f"Content-Disposition: attachment; filename=\"{filename}\"")
                        body_parts.append("Content-Transfer-Encoding: base64")
                        body_parts.append("")
                        
                        # Encode as base64
                        encoded = base64.b64encode(data).decode('ascii')
                        for i in range(0, len(encoded), 76):
                            body_parts.append(encoded[i:i+76])
                        
                        print(f"DEBUG: Added attachment part for {filename}")
                    else:
                        print(f"DEBUG: Skipping attachment {filename} - no data")
                
                except Exception as e:
                    print(f"DEBUG: Error processing attachment {att_idx + 1}: {e}")
                    continue
            
            # Close multipart
            body_parts.append("")
            body_parts.append("--phishalyzer-boundary--")
            print("DEBUG: Closed multipart structure")
        
        final_eml = "\r\n".join(headers) + "\r\n".join(body_parts)
        print(f"DEBUG: Final EML length: {len(final_eml)} characters")
        
        return final_eml
        
    except Exception as e:
        print(f"ERROR in conversion: {e}")
        return f"Subject: [MSG Parsing Error: {e}]\r\n\r\n[Could not parse MSG file content]"

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python conversion_diagnostic.py <msg_file_path>")
        sys.exit(1)
    
    debug_conversion_step_by_step(sys.argv[1])