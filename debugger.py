#!/usr/bin/env python3
"""
Simple diagnostic to find the exact conversion issue
"""

import sys
import os
import email
from email import policy
import extract_msg
import base64

def simple_conversion_test(file_path):
    """Simple test to isolate the conversion issue"""
    print("=== SIMPLE CONVERSION TEST ===")
    
    try:
        # Load MSG
        print("Loading MSG...")
        msg = extract_msg.Message(file_path)
        print("MSG loaded OK")
        
        # Check attachments
        if hasattr(msg, 'attachments'):
            attachments = getattr(msg, 'attachments', [])
            print(f"MSG has {len(attachments)} attachments")
            
            if attachments:
                att = attachments[0]  # Just check first one
                print("First attachment:")
                
                # Check filename
                filename = getattr(att, 'longFilename', None) or getattr(att, 'shortFilename', 'unknown')
                print(f"  Filename: {filename}")
                
                # Check data
                data = getattr(att, 'data', None)
                if data:
                    print(f"  Data size: {len(data)} bytes")
                    print(f"  Magic: {data[:8].hex()}")
                else:
                    print("  No data!")
                    return
        else:
            print("No attachments in MSG")
            return
        
        # Test minimal conversion
        print("\nTesting minimal conversion...")
        
        # Build minimal multipart email
        boundary = "test-boundary"
        
        eml_parts = [
            "Subject: Test conversion",
            "MIME-Version: 1.0",
            f"Content-Type: multipart/mixed; boundary=\"{boundary}\"",
            "",
            f"--{boundary}",
            "Content-Type: text/plain",
            "",
            "Test body",
            "",
            f"--{boundary}",
            f"Content-Type: application/pdf",
            f"Content-Disposition: attachment; filename=\"{filename}\"",
            "Content-Transfer-Encoding: base64",
            "",
        ]
        
        # Add base64 data
        if data:
            encoded = base64.b64encode(data).decode('ascii')
            # Add in chunks
            for i in range(0, len(encoded), 76):
                eml_parts.append(encoded[i:i+76])
        
        eml_parts.extend([
            "",
            f"--{boundary}--"
        ])
        
        eml_string = "\r\n".join(eml_parts)
        print(f"Created EML string, length: {len(eml_string)}")
        
        # Test parsing
        print("Testing parsing...")
        eml_bytes = eml_string.encode('utf-8', errors='replace')
        parsed_msg = email.message_from_bytes(eml_bytes, policy=policy.default)
        
        print(f"Parsed OK, multipart: {parsed_msg.is_multipart()}")
        
        # Count attachments
        attachment_count = 0
        for part in parsed_msg.walk():
            if part.get_content_disposition() == 'attachment':
                attachment_count += 1
                part_filename = part.get_filename()
                print(f"Found attachment: {part_filename}")
                
                # Test payload
                payload = part.get_payload(decode=True)
                if payload:
                    print(f"  Payload size: {len(payload)}")
                    if payload.startswith(b'%PDF-'):
                        print("  PDF magic preserved!")
        
        print(f"\nFinal result: {attachment_count} attachments detected")
        
        if attachment_count == 0:
            print("PROBLEM: No attachments detected after conversion")
            
            # Debug the EML structure
            print("\nEML structure debug:")
            lines = eml_string.split('\n')
            for i, line in enumerate(lines[:20]):  # First 20 lines
                print(f"  {i:2}: {repr(line)}")
            print("  ...")
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python simple_diagnostic.py <msg_file_path>")
        sys.exit(1)
    
    simple_conversion_test(sys.argv[1])