import email
from email import policy
import extract_msg
import os

def load_email(file_path):
    """
    Load .eml or .msg email file and return a parsed email.message.EmailMessage object.

    Args:
        file_path (str): Path to the email file.

    Returns:
        email.message.EmailMessage: Parsed email message.
        str: File type detected ('eml' or 'msg').
    """
    ext = os.path.splitext(file_path)[1].lower()

    if ext == ".eml":
        with open(file_path, "rb") as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
        return msg, "eml"

    elif ext == ".msg":
        msg = extract_msg.Message(file_path)
        # Build an EmailMessage-like object for consistency
        eml_str = _msg_to_eml_string(msg)
        eml_bytes = eml_str.encode('utf-8')
        parsed_msg = email.message_from_bytes(eml_bytes, policy=policy.default)
        return parsed_msg, "msg"

    else:
        raise ValueError(f"Unsupported file type: {ext}")

def _msg_to_eml_string(msg):
    """
    Converts extract_msg.Message to a simplified RFC822 string for parsing.

    Args:
        msg (extract_msg.Message): Loaded .msg email.

    Returns:
        str: String in RFC822 format.
    """
    headers = []
    # Basic headers
    for header in ['From', 'To', 'Cc', 'Bcc', 'Subject', 'Date', 'Message-ID']:
        value = getattr(msg, header.lower(), None)
        if value:
            headers.append(f"{header}: {value}")

    headers.append("")  # Blank line to separate headers from body

    body = msg.body or ""
    # For now, ignoring attachments; just plain body text

    return "\r\n".join(headers) + body
