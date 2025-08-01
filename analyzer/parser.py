import email
from email import policy
import extract_msg
import os
import sys

def load_email(file_path):
    """
    Load .eml or .msg email file and return a parsed email.message.EmailMessage object.
    Includes comprehensive error handling for various file issues.

    Args:
        file_path (str): Path to the email file.

    Returns:
        email.message.EmailMessage: Parsed email message.
        str: File type detected ('eml' or 'msg').
    
    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If file type is unsupported
        Exception: For other parsing errors
    """
    
    # Validate file path
    if not file_path:
        raise ValueError("No file path provided")
    
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if not os.path.isfile(file_path):
        raise ValueError(f"Path is not a file: {file_path}")
    
    # Check file size
    try:
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            raise ValueError("File is empty")
        if file_size > 500 * 1024 * 1024:  # 500MB limit
            raise ValueError(f"File too large: {file_size / (1024*1024):.1f}MB (max 500MB)")
    except OSError as e:
        raise ValueError(f"Cannot access file: {e}")
    
    # Determine file type
    ext = os.path.splitext(file_path)[1].lower()
    
    if ext == ".eml":
        return _load_eml_file(file_path)
    elif ext == ".msg":
        return _load_msg_file(file_path)
    else:
        # Try to detect format by content if extension is missing/wrong
        try:
            return _detect_and_load_email(file_path)
        except Exception:
            raise ValueError(f"Unsupported file type: {ext}. Supported types: .eml, .msg")

def _load_eml_file(file_path):
    """Load .eml file with error handling."""
    try:
        with open(file_path, "rb") as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
        
        # Validate that we got a valid email object
        if not hasattr(msg, 'get'):
            raise ValueError("File does not appear to be a valid email")
        
        return msg, "eml"
        
    except UnicodeDecodeError as e:
        raise ValueError(f"File encoding error: {e}")
    except email.errors.MessageError as e:
        raise ValueError(f"Email parsing error: {e}")
    except PermissionError:
        raise PermissionError(f"Permission denied reading file: {file_path}")
    except IOError as e:
        raise IOError(f"File I/O error: {e}")
    except Exception as e:
        raise Exception(f"Unexpected error parsing EML file: {e}")

def _load_msg_file(file_path):
    """Load .msg file with error handling."""
    try:
        # Check if extract_msg is available
        if not hasattr(extract_msg, 'Message'):
            raise ImportError("extract_msg library not properly installed")
        
        msg = extract_msg.Message(file_path)
        
        # Validate that we got a valid message object
        if not msg:
            raise ValueError("Could not parse MSG file - file may be corrupted")
        
        # Build an EmailMessage-like object for consistency
        eml_str = _msg_to_eml_string(msg)
        eml_bytes = eml_str.encode('utf-8', errors='replace')
        parsed_msg = email.message_from_bytes(eml_bytes, policy=policy.default)
        
        return parsed_msg, "msg"
        
    except ImportError as e:
        raise ImportError(f"MSG file support not available: {e}")
    except extract_msg.exceptions.UnsupportedMSGType as e:
        raise ValueError(f"Unsupported MSG file type: {e}")
    except extract_msg.exceptions.InvalidFileFormatError as e:
        raise ValueError(f"Invalid MSG file format: {e}")
    except PermissionError:
        raise PermissionError(f"Permission denied reading file: {file_path}")
    except IOError as e:
        raise IOError(f"File I/O error: {e}")
    except Exception as e:
        raise Exception(f"Unexpected error parsing MSG file: {e}")

def _detect_and_load_email(file_path):
    """Attempt to detect and load email file when extension is unclear."""
    
    # Try EML first (more common)
    try:
        return _load_eml_file(file_path)
    except Exception as eml_error:
        pass
    
    # Try MSG format
    try:
        return _load_msg_file(file_path)
    except Exception as msg_error:
        pass
    
    # Try reading as plain text to see if it looks like email headers
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            first_lines = [f.readline().strip() for _ in range(10)]
        
        # Look for email-like headers
        email_headers = ['from:', 'to:', 'subject:', 'date:', 'message-id:']
        header_count = sum(1 for line in first_lines if any(
            line.lower().startswith(header) for header in email_headers
        ))
        
        if header_count >= 2:  # At least 2 email headers found
            return _load_eml_file(file_path)
            
    except Exception:
        pass
    
    raise ValueError("Could not determine email file format or file is corrupted")

def _msg_to_eml_string(msg):
    """
    Converts extract_msg.Message to a simplified RFC822 string for parsing.
    Includes error handling for missing or corrupted data.

    Args:
        msg (extract_msg.Message): Loaded .msg email.

    Returns:
        str: String in RFC822 format.
    """
    headers = []
    
    try:
        # Basic headers with safe extraction
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
                    # Clean the value
                    clean_value = str(value).replace('\r', ' ').replace('\n', ' ').strip()
                    if clean_value:
                        headers.append(f"{header_name}: {clean_value}")
            except Exception:
                # Skip this header if there's an error
                continue
        
        # Add a minimal required header if none found
        if not headers:
            headers.append("Subject: [MSG File - Headers Unavailable]")
        
        headers.append("")  # Blank line to separate headers from body

        # Extract body safely
        try:
            body = getattr(msg, 'body', None) or getattr(msg, 'htmlBody', None) or ""
            if body:
                # Clean the body text
                body = str(body).replace('\r\n', '\n').replace('\r', '\n')
                # Limit body size to prevent memory issues
                if len(body) > 1024 * 1024:  # 1MB limit
                    body = body[:1024*1024] + "\n[... content truncated ...]"
            else:
                body = "[No body content available]"
        except Exception:
            body = "[Error reading body content]"

        return "\r\n".join(headers) + body
        
    except Exception as e:
        # Return minimal valid email if everything fails
        return f"Subject: [MSG Parsing Error: {e}]\r\n\r\n[Could not parse MSG file content]"