"""
Universal output module for phishalyzer.
Provides consistent formatting and colors across all terminals without any external dependencies.
"""

import os
import sys
import re

# ANSI Color and Style Codes
class Colors:
    # Reset
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
    """Detect if terminal supports ANSI colors"""
    # Respect NO_COLOR environment variable (universal standard)
    if os.getenv('NO_COLOR'):
        return False
    
    # Force color if requested
    if os.getenv('FORCE_COLOR') or os.getenv('CLICOLOR_FORCE'):
        return True
    
    # Check if CLICOLOR is explicitly disabled
    if os.getenv('CLICOLOR') == '0':
        return False
    
    # Windows Command Prompt detection
    if os.name == 'nt':
        # Modern Windows Terminal supports colors
        if os.getenv('WT_SESSION'):
            return True
        # ConEmu and similar
        if os.getenv('ConEmuPID'):
            return True
        # Try to enable ANSI on Windows 10+
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            pass
        # Fallback for older Windows
        return False
    
    # Unix-like systems
    if hasattr(sys.stdout, 'isatty') and sys.stdout.isatty():
        term = os.getenv('TERM', '').lower()
        if any(x in term for x in ['xterm', 'color', 'ansi', 'linux', 'screen', 'tmux']):
            return True
        # Git Bash often reports as xterm
        if 'xterm' in term or term.startswith('screen'):
            return True
        # Basic fallback
        if term and term != 'dumb':
            return True
    
    return False

class UniversalOutput:
    """
    Universal output class that works consistently across all terminals.
    No external dependencies - only uses built-in Python and ANSI codes.
    """
    
    def __init__(self):
        self.use_colors = supports_color()
        self._color_map = {
            # Basic colors
            'red': Colors.RED,
            'green': Colors.GREEN,
            'yellow': Colors.YELLOW,
            'blue': Colors.BLUE,
            'magenta': Colors.MAGENTA,
            'cyan': Colors.CYAN,
            'white': Colors.WHITE,
            'black': Colors.BLACK,
            
            # Bright variants
            'bright_red': Colors.BRIGHT_RED,
            'bright_green': Colors.BRIGHT_GREEN,
            'bright_yellow': Colors.BRIGHT_YELLOW,
            'bright_blue': Colors.BRIGHT_BLUE,
            'bright_magenta': Colors.BRIGHT_MAGENTA,
            'bright_cyan': Colors.BRIGHT_CYAN,
            'bright_white': Colors.BRIGHT_WHITE,
            'bright_black': Colors.BRIGHT_BLACK,
            
            # Aliases for compatibility
            'orange3': Colors.BRIGHT_YELLOW,  # Orange approximation
            'orange': Colors.YELLOW,
            
            # Styles
            'bold': Colors.BOLD,
            'dim': Colors.DIM,
            'underline': Colors.UNDERLINE,
        }
    
    def colorize(self, text, color):
        """Apply color to text if colors are supported"""
        if not self.use_colors:
            return text
        
        if color in self._color_map:
            return f"{self._color_map[color]}{text}{Colors.RESET}"
        return text
    
    def _process_markup_simple(self, text):
        """Simple, reliable markup processing that actually works"""
        if not isinstance(text, str):
            text = str(text)
        
        if not self.use_colors:
            # Strip all markup tags for plain text
            text = re.sub(r'\[/?[^\]]*\]', '', text)
            return text
        
        # Process markup tags one by one, preventing nesting
        # Handle [color]text[/color] patterns
        def replace_color_tag(match):
            full_match = match.group(0)
            
            # Extract the pattern: [color]content[/color] or [color]content[/]
            color_match = re.match(r'\[([^\]]+)\](.*?)\[/[^\]]*\]', full_match)
            if not color_match:
                return full_match  # Return unchanged if pattern doesn't match
            
            color_spec = color_match.group(1).strip().lower()
            content = color_match.group(2)
            
            # Skip if content already has ANSI codes (prevent double-coloring)
            if '\033[' in content:
                return content
            
            # Handle compound styles like "blue bold"
            styles = color_spec.split()
            style_codes = []
            
            for style in styles:
                if style in self._color_map:
                    style_codes.append(self._color_map[style])
            
            if style_codes:
                return f"{''.join(style_codes)}{content}{Colors.RESET}"
            return content
        
        # Apply the replacement using a comprehensive pattern
        # This handles both [color]text[/color] and [color]text[/]
        markup_pattern = re.compile(r'\[([^\]]+)\](.*?)\[/[^\]]*\]')
        
        # Keep applying until no more matches (but prevent infinite loops)
        max_iterations = 10
        iteration = 0
        
        while markup_pattern.search(text) and iteration < max_iterations:
            text = markup_pattern.sub(replace_color_tag, text)
            iteration += 1
        
        return text
    
    def print(self, text="", **kwargs):
        """Universal print function with reliable markup support"""
        processed_text = self._process_markup_simple(str(text))
        print(processed_text, **kwargs)
    
    def escape(self, text):
        """Escape potentially problematic characters while preserving defanged brackets"""
        if not isinstance(text, str):
            text = str(text)
        
        # Handle basic problematic characters but preserve defanged brackets
        # Don't mess with [.] and [:] as they're legitimate defanged content
        text = text.replace('\x00', '\\x00')  # Null bytes
        text = text.replace('\x1b', '\\x1b')  # Escape sequences (if not ours)
        
        # Handle other control characters
        text = ''.join(char if ord(char) >= 32 or char in '\t\n\r' else f'\\x{ord(char):02x}' for char in text)
        
        return text
    
    @property
    def use_rich(self):
        """Compatibility property - always False"""
        return False

# Create global instance
output = UniversalOutput()

# Convenience functions for consistent phishalyzer output
def print_header(title):
    """Print a standardized section header"""
    total_width = 50
    title_with_spaces = f" {title.upper()} "
    padding_needed = total_width - len(title_with_spaces)
    left_padding = padding_needed // 2
    right_padding = padding_needed - left_padding
    
    header_line = "=" * left_padding + title_with_spaces + "=" * right_padding
    output.print(f"\n\n[magenta]{header_line}[/magenta]\n")

def print_status(text, status_type="info"):
    """Print status message with appropriate coloring"""
    color_map = {
        "info": "blue",
        "warning": "yellow", 
        "error": "red",
        "success": "green"
    }
    
    color = color_map.get(status_type, "blue")
    escaped_text = output.escape(str(text))
    output.print(f"[{color}]{escaped_text}[/{color}]")

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
    escaped_text = output.escape(str(text))
    output.print(f"[{color}]{escaped_text.upper()}[/{color}]")

def print_ip_result(ip, country, verdict, comment, defang_func=None):
    """Display IP analysis result with consistent formatting"""
    # Apply defanging if function provided
    display_ip = defang_func(ip) if defang_func else ip
    
    verdict_colors = {
        "malicious": "red",
        "suspicious": "orange3",
        "benign": "green",
        "unchecked": "orange3"
    }
    
    verdict_color = verdict_colors.get(verdict, "orange3")
    
    escaped_ip = output.escape(str(display_ip))
    escaped_country = output.escape(str(country))
    escaped_comment = output.escape(str(comment))
    
    output.print(f"IP: [yellow]{escaped_ip}[/yellow] ({escaped_country}) - Verdict: [{verdict_color}]{verdict.upper()}[/{verdict_color}] ({escaped_comment})")

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
    escaped_hash = output.escape(str(file_hash))
    output.print(f"  SHA256: [{hash_color}]{escaped_hash}[/{hash_color}]")

def print_risk_level(risk_level, reason):
    """Display risk level with appropriate coloring"""
    risk_colors = {
        "high": "red", 
        "medium": "yellow", 
        "low": "green", 
        "unknown": "orange3"
    }
    
    risk_color = risk_colors.get(str(risk_level).lower(), "white")
    escaped_reason = output.escape(str(reason))
    output.print(f"  Risk Level: [{risk_color}]{str(risk_level).upper()}[/{risk_color}] ({escaped_reason})")

def print_vt_verdict(verdict, comment):
    """Display VirusTotal verdict with appropriate coloring"""
    vt_colors = {
        "malicious": "red",
        "suspicious": "yellow",
        "benign": "green", 
        "unknown": "orange3",
        "unchecked": "orange3"
    }
    
    vt_color = vt_colors.get(str(verdict).lower(), "orange3")
    escaped_comment = output.escape(str(comment))
    output.print(f"  VirusTotal: [{vt_color}]{str(verdict).upper()}[/{vt_color}] ({escaped_comment})")

def create_colored_text(text, color="white", bold=False):
    """Create colored text - simplified for compatibility"""
    escaped_text = output.escape(str(text))
    
    if bold:
        return f"[{color} bold]{escaped_text}[/{color} bold]"
    else:
        return f"[{color}]{escaped_text}[/{color}]"

# Test function for verification
def test_compatibility():
    """Test the universal output system"""
    print(f"Color support detected: {output.use_colors}")
    print(f"Terminal: {os.getenv('TERM', 'unknown')}")
    print(f"Platform: {os.name}")
    print()
    
    print_header("Test Section")
    
    output.print("[red]Red text test[/red]")
    output.print("[green]Green text test[/green]")
    output.print("[blue bold]Blue bold text test[/blue bold]")
    output.print("[yellow]Yellow text test[/yellow]")
    output.print("[magenta]Magenta text test[/magenta]")
    
    print()
    print_status("This is an info message", "info")
    print_status("This is a warning", "warning")
    print_status("This is an error", "error")
    print_status("This is success", "success")
    
    print()
    print_verdict("MALICIOUS CONTENT", "malicious")
    print_verdict("SUSPICIOUS CONTENT", "suspicious") 
    print_verdict("BENIGN CONTENT", "benign")
    
    print()
    print_ip_result("192.168.1.1", "Private", "unchecked", "Private IP address")
    print_ip_result("8.8.8.8", "United States", "benign", "Google DNS server")

if __name__ == "__main__":
    test_compatibility()