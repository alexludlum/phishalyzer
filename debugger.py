#!/usr/bin/env python3
"""
Working diagnostic that fixes the len() issue
"""

import sys
import os
import email
from email import policy
import extract_msg
import base64

def working_conversion_test(file_path):
    """Fixed conversion test"""
    print("=== WORKING CONVERSION TEST ===")
    
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
                
                # FIXED: Check data without using len() on Message object
                data = getattr(att, 'data', None)
                if data is not None:
                    try:
                        data_size = len(data)  # This should work on bytes
                        print(f"  Data size: {data_size} bytes")
                        if data_size > 0:
                            print(f"  Magic: {data[:8].hex()}")
                            if data.startswith(b'%PDF-'):
                                print("  *** PDF DETECTED! ***")
                        else:
                            print("  Data is empty!")
                            return
                    except Exception as e:
                        print(f"  Error checking data: {e}")
                        return
                else:
                    print("  No data attribute!")
                    return
        else:
            print("No attachments in MSG")
            return
        
        # Test conversion
        print("\nTesting conversion...")
        
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
            "Content-Type: application/pdf",
            f"Content-Disposition: attachment; filename=\"{filename}\"",
            "Content-Transfer-Encoding: base64",
            "",
        ]
        
        # Add base64 data
        if data and len(data) > 0:
            try:
                encoded = base64.b64encode(data).decode('ascii')
                print(f"  Encoded to {len(encoded)} base64 characters")
                
                # Add in 76-character chunks
                for i in range(0, len(encoded), 76):
                    eml_parts.append(encoded[i:i+76])
            except Exception as e:
                print(f"  Error encoding: {e}")
                return
        
        eml_parts.extend([
            "",
            f"--{boundary}--"
        ])
        
        eml_string = "\r\n".join(eml_parts)
        print(f"Created EML string, {len(eml_string)} characters")
        
        # Test parsing
        print("Testing EML parsing...")
        try:
            eml_bytes = eml_string.encode('utf-8', errors='replace')
            parsed_msg = email.message_from_bytes(eml_bytes, policy=policy.default)
            
            print(f"Parsed OK:")
            print(f"  Multipart: {parsed_msg.is_multipart()}")
            print(f"  Content-Type: {parsed_msg.get_content_type()}")
        except Exception as e:
            print(f"  Parsing error: {e}")
            return
        
        # Count attachments in parsed email
        print("Checking for attachments in parsed email...")
        attachment_count = 0
        part_count = 0
        
        try:
            for part in parsed_msg.walk():
                part_count += 1
                print(f"  Part {part_count}: {part.get_content_type()}")
                
                disposition = part.get_content_disposition()
                if disposition == 'attachment':
                    attachment_count += 1
                    part_filename = part.get_filename()
                    print(f"    *** ATTACHMENT FOUND: {part_filename} ***")
                    
                    # Test payload extraction
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            print(f"      Payload: {len(payload)} bytes")
                            if payload.startswith(b'%PDF-'):
                                print("      *** PDF MAGIC PRESERVED! ***")
                            else:
                                print(f"      Magic: {payload[:8].hex()}")
                        else:
                            print("      No payload")
                    except Exception as e:
                        print(f"      Payload error: {e}")
        except Exception as e:
            print(f"  Walk error: {e}")
        
        print(f"\n=== RESULTS ===")
        print(f"Original MSG attachments: 1")
        print(f"Converted email parts: {part_count}")
        print(f"Detected attachments: {attachment_count}")
        
        if attachment_count > 0:
            print("*** SUCCESS: Attachment conversion working! ***")
        else:
            print("*** PROBLEM: No attachments detected ***")
            
            # Show EML structure for debugging
            print("\nFirst 10 lines of EML:")
            lines = eml_string.split('\n')
            for i, line in enumerate(lines[:10]):
                print(f"  {i}: {repr(line)}")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python working_diagnostic.py <msg_file_path>")
        sys.exit(1)
    
    working_conversion_test(sys.argv[1])