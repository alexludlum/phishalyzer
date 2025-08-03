"""
Compatible output module for phishalyzer.
Falls back from Rich to simple colors for maximum terminal compatibility.
"""

import os
import sys
import re

# Try to import Rich first
try:
    from rich import print as rich_print
    from rich.text import Text
    from rich.markup import escape as rich_escape
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Fallback color system using ANSI codes
class Colors:
    RESET = '\033[0m'
    
    # Basic colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright colors
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Styles
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'

def supports_color():
    """Check if terminal supports colors"""
    # Respect NO_COLOR environment variable
    if os.getenv('NO_COLOR'):
        return False
    
    # Force color if requested
    if os.getenv('FORCE_COLOR') or os.getenv('CLICOLOR_FORCE'):
        return True
    
    # Check if CLICOLOR is explicitly disabled
    if os.getenv('CLICOLOR') == '0':
        return False
    
    # Check if we're in a TTY
    if hasattr(sys.stdout, 'isatty') and sys.stdout.isatty():
        term = os.getenv('TERM', '').lower()
        # Git Bash usually sets TERM to xterm or xterm-256color
        if any(x in term for x in ['xterm', 'color', 'ansi', 'linux', 'screen']):
            return True
        # Windows Terminal, ConEmu, etc.
        if os.getenv('WT_SESSION') or os.getenv('ConEmuPID'):
            return True
        # Basic fallback for unknown terminals
        if term and term != 'dumb':
            return True
    
    return False

class CompatibleOutput:
    """
    Output class that uses Rich when available, falls back to simple colors.
    """
    
    def __init__(self):
        self.use_rich = RICH_AVAILABLE
        self.use_colors = supports_color()
        self._markup_pattern = re.compile(r'\[/?([^\]]*)\]')
    
    def print(self, *args, **kwargs):
        """Compatible print function"""
        if self.use_rich:
            rich_print(*args, **kwargs)
        else:
            # Convert args to strings and process markup
            processed_args = []
            for arg in args:
                text = str(arg)
                if self.use_colors:
                    text = self._convert_markup_to_ansi(text)
                else:
                    text = self._strip_markup(text)
                processed_args.append(text)
            
            print(*processed_args, **kwargs)
    
    def _convert_markup_to_ansi(self, text):
        """Convert Rich markup to ANSI codes"""
        # Rich markup to ANSI mapping
        markup_to_ansi = {
            # Basic colors
            'red': Colors.RED,
            'green': Colors.GREEN,
            'yellow': Colors.YELLOW,
            'blue': Colors.BLUE,
            'magenta': Colors.MAGENTA,
            'cyan': Colors.CYAN,
            'white': Colors.WHITE,
            'black': Colors.BLACK,
            
            # Bright colors
            'bright_red': Colors.BRIGHT_RED,
            'bright_green': Colors.BRIGHT_GREEN,
            'bright_yellow': Colors.BRIGHT_YELLOW,
            'bright_blue': Colors.BRIGHT_BLUE,
            'bright_magenta': Colors.BRIGHT_MAGENTA,
            'bright_cyan': Colors.BRIGHT_CYAN,
            
            # Special mappings for your specific use cases
            'orange3': Colors.BRIGHT_YELLOW,  # Orange approximation
            
            # Styles
            'bold': Colors.BOLD,
            'dim': Colors.DIM,
            'underline': Colors.UNDERLINE,
        }
        
        # Stack to track open tags
        tag_stack = []
        result = []
        last_end = 0
        
        for match in self._markup_pattern.finditer(text):
            # Add text before the tag
            result.append(text[last_end:match.start()])
            
            tag_content = match.group(1)
            
            if tag_content.startswith('/'):
                # Closing tag
                if tag_stack:
                    tag_stack.pop()
                    # Reset and reapply remaining styles
                    result.append(Colors.RESET)
                    for tag in tag_stack:
                        if tag in markup_to_ansi:
                            result.append(markup_to_ansi[tag])
            else:
                # Opening tag - handle combinations like "blue bold"
                tag_parts = tag_content.split()
                valid_tags = []
                
                for part in tag_parts:
                    if part in markup_to_ansi:
                        valid_tags.append(part)
                        result.append(markup_to_ansi[part])
                
                if valid_tags:
                    tag_stack.extend(valid_tags)
            
            last_end = match.end()
        
        # Add remaining text
        result.append(text[last_end:])
        
        # Add final reset if we have any open tags
        if tag_stack:
            result.append(Colors.RESET)
        
        return ''.join(result)
    
    def _strip_markup(self, text):
        """Remove all Rich markup for plain text output"""
        return self._markup_pattern.sub('', text)
    
    def text(self, content, style=None):
        """Create a text object (Rich-compatible)"""
        if self.use_rich:
            return Text(content, style=style)
        else:
            # Return formatted text for non-Rich environments
            if style and self.use_colors:
                # Simple style mapping
                style_map = {
                    'red': Colors.RED,
                    'green': Colors.GREEN,
                    'yellow': Colors.YELLOW,
                    'blue': Colors.BLUE,
                    'magenta': Colors.MAGENTA,
                    'orange3': Colors.BRIGHT_YELLOW,
                    'bold': Colors.BOLD,
                    'blue bold': Colors.BLUE + Colors.BOLD,
                    'red bold': Colors.RED + Colors.BOLD,
                    'green bold': Colors.GREEN + Colors.BOLD,
                    'yellow bold': Colors.YELLOW + Colors.BOLD,
                }
                
                if style in style_map:
                    return f"{style_map[style]}{content}{Colors.RESET}"
            
            return content
    
    def escape(self, text):
        """Escape text for safe display"""
        if self.use_rich:
            return rich_escape(text)
        else:
            # Simple escaping for non-Rich environments
            # Just ensure it's a string and handle basic problematic characters
            text = str(text)
            # Replace characters that might cause issues in terminals
            text = text.replace('\x00', '\\x00')  # Null bytes
            text = text.replace('\x1b', '\\x1b')  # Escape sequences
            return text

# Global instance
output = CompatibleOutput()

# Convenience functions for common phishalyzer patterns
def print_header(title):
    """Print a standardized section header"""
    total_width = 50
    title_with_spaces = f" {title.upper()} "
    padding_needed = total_width - len(title_with_spaces)
    left_padding = padding_needed // 2
    right_padding = padding_needed - left_padding
    
    header_line = "=" * left_padding + title_with_spaces + "=" * right_padding
    
    output.print(f"\n\n[magenta]{header_line}[/magenta]\n")

def print_verdict(text, verdict):
    """Print text with verdict-based coloring"""
    verdict_colors = {
        "malicious": "red",
        "suspicious": "orange3", 
        "benign": "green",
        "unchecked": "orange3",
        "unknown": "orange3"
    }
    
    color = verdict_colors.get(verdict.lower(), "white")
    output.print(f"[{color}]{text.upper()}[/{color}]")

def print_status(text, status_type="info"):
    """Print status message with appropriate coloring"""
    color_map = {
        "info": "blue",
        "warning": "yellow", 
        "error": "red",
        "success": "green"
    }
    
    color = color_map.get(status_type, "blue")
    output.print(f"[{color}]{text}[/{color}]")

def print_ip_result(ip, country, verdict, comment, defang_func=None):
    """Display IP analysis result with compatible formatting"""
    # Apply defanging if function provided
    display_ip = defang_func(ip) if defang_func else ip
    
    verdict_colors = {
        "malicious": "red",
        "suspicious": "orange3",
        "benign": "green",
        "unchecked": "orange3"
    }
    
    verdict_color = verdict_colors.get(verdict, "orange3")
    verdict_text = f"[{verdict_color}]{verdict.upper()}[/{verdict_color}]"
    
    escaped_ip = output.escape(display_ip)
    escaped_country = output.escape(country)
    escaped_comment = output.escape(comment)
    
    output.print(f"IP: [yellow]{escaped_ip}[/yellow] ({escaped_country}) - Verdict: {verdict_text} ({escaped_comment})")

def print_attachment_header(index):
    """Display attachment header"""
    output.print(f"[blue bold]Attachment {index}:[/blue bold]")

def print_filename(filename):
    """Display filename with appropriate styling"""
    escaped_filename = output.escape(str(filename))
    output.print(f"  Filename: [yellow]{escaped_filename}[/yellow]")

def print_hash(file_hash, verdict="unchecked"):
    """Display file hash with color coding based on verdict"""
    hash_colors = {
        "malicious": "red",
        "suspicious": "yellow", 
        "benign": "green",
        "unknown": "orange3",
        "unchecked": "orange3"
    }
    
    hash_color = hash_colors.get(verdict, "orange3")
    escaped_hash = output.escape(file_hash)
    output.print(f"  SHA256: [{hash_color}]{escaped_hash}[/{hash_color}]")

def print_risk_level(risk_level, reason):
    """Display risk level with appropriate coloring"""
    risk_colors = {
        "high": "red", 
        "medium": "yellow", 
        "low": "green", 
        "unknown": "orange3"
    }
    
    risk_color = risk_colors.get(risk_level, "white")
    escaped_reason = output.escape(reason)
    output.print(f"  Risk Level: [{risk_color}]{risk_level.upper()}[/{risk_color}] ({escaped_reason})")

def print_vt_verdict(verdict, comment):
    """Display VirusTotal verdict with appropriate coloring"""
    vt_colors = {
        "malicious": "red",
        "suspicious": "yellow",
        "benign": "green", 
        "unknown": "orange3",
        "unchecked": "orange3"
    }
    
    vt_color = vt_colors.get(verdict, "orange3")
    escaped_comment = output.escape(comment)
    output.print(f"  VirusTotal: [{vt_color}]{verdict.upper()}[/{vt_color}] ({escaped_comment})")

def create_colored_text(text, color="white", bold=False):
    """Create colored text with optional bold styling"""
    style_parts = [color]
    if bold:
        style_parts.append("bold")
    
    style = " ".join(style_parts)
    
    if output.use_rich:
        return Text(text, style=style)
    else:
        return output.text(text, style)

# Test function
def test_compatibility():
    """Test the compatibility system"""
    print(f"Rich available: {RICH_AVAILABLE}")
    print(f"Colors supported: {output.use_colors}")
    print(f"Terminal: {os.getenv('TERM', 'unknown')}")
    print()
    
    print_header("Test Section")
    
    print_verdict("MALICIOUS CONTENT", "malicious")
    print_verdict("SUSPICIOUS CONTENT", "suspicious") 
    print_verdict("BENIGN CONTENT", "benign")
    print_verdict("UNCHECKED CONTENT", "unchecked")
    
    print()
    print_status("This is an info message", "info")
    print_status("This is a warning", "warning")
    print_status("This is an error", "error")
    print_status("This is success", "success")
    
    print()
    print_ip_result("192.168.1.1", "Private", "unchecked", "Private IP address")
    print_ip_result("8.8.8.8", "United States", "benign", "Google DNS server")
    
    print()
    print_attachment_header(1)
    print_filename("suspicious_file.exe")
    print_hash("abc123def456", "malicious")
    print_risk_level("high", "Executable file type")
    print_vt_verdict("malicious", "5 vendors flagged as malicious")

if __name__ == "__main__":
    test_compatibility()