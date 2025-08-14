"""
Exact Terminal Output Capture HTML Export module for phishalyzer.
Captures the EXACT terminal output and converts it to HTML.
"""

import os
import re
import hashlib
import datetime
import io
import sys
from pathlib import Path

# Import compatible output system
try:
    from .compatible_output import output, print_status
    COMPATIBLE_OUTPUT = True
except ImportError:
    COMPATIBLE_OUTPUT = False

def get_desktop_path():
    """Get the user's desktop path across different operating systems."""
    try:
        home = Path.home()
        
        # Try different desktop paths
        desktop_paths = [
            home / "Desktop",
            home / "desktop", 
            home / "Schreibtisch",  # German
            home / "Bureau",        # French
            home / "Escritorio",    # Spanish
        ]
        
        for desktop_path in desktop_paths:
            if desktop_path.exists() and desktop_path.is_dir():
                return str(desktop_path)
        
        # Fallback to home directory
        return str(home)
        
    except Exception:
        # Ultimate fallback to current directory
        return os.getcwd()

def sanitize_filename(filename):
    """Sanitize filename by removing problematic characters."""
    if not filename:
        return "email_analysis"
    
    # Remove file extension if present
    name_without_ext = os.path.splitext(filename)[0]
    
    # Replace problematic characters with underscores
    sanitized = re.sub(r'[<>:"/\\|?*\s]', '_', name_without_ext)
    
    # Remove multiple consecutive underscores
    sanitized = re.sub(r'_+', '_', sanitized)
    
    # Remove leading/trailing underscores
    sanitized = sanitized.strip('_')
    
    # Ensure it's not empty and not too long
    if not sanitized:
        sanitized = "email_analysis"
    elif len(sanitized) > 50:
        sanitized = sanitized[:50]
    
    return sanitized

def get_unique_filename(base_path, base_name, extension):
    """Generate a unique filename by appending a counter if file exists."""
    counter = 1
    original_path = os.path.join(base_path, f"{base_name}.{extension}")
    
    if not os.path.exists(original_path):
        return original_path
    
    while True:
        new_path = os.path.join(base_path, f"{base_name}_{counter}.{extension}")
        if not os.path.exists(new_path):
            return new_path
        counter += 1

def calculate_file_hash(file_path):
    """Calculate SHA256 hash of the original email file."""
    try:
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256()
            while chunk := f.read(8192):
                file_hash.update(chunk)
        return file_hash.hexdigest()
    except Exception as e:
        return f"Error calculating hash: {e}"

def get_file_size(file_path):
    """Get formatted file size."""
    try:
        size_bytes = os.path.getsize(file_path)
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB"]
        i = 0
        size = float(size_bytes)
        
        while size >= 1024.0 and i < len(size_names) - 1:
            size /= 1024.0
            i += 1
        
        return f"{size:.1f} {size_names[i]}"
    except Exception:
        return "Unknown size"

def apply_defanging_to_output(text, use_defanged):
    """Apply defanging to terminal output if requested."""
    if not use_defanged:
        return text
        
    try:
        from . import defanger
        return defanger.defang_text(str(text))
    except:
        return text

def escape_html(text):
    """Escape HTML special characters but preserve line breaks."""
    if not isinstance(text, str):
        text = str(text)
    
    replacements = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;'
    }
    
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    
    return text

def ansi_to_html(text):
    """Convert ANSI escape sequences to HTML with exact terminal colors."""
    # ANSI color code mappings to exact terminal colors
    ansi_colors = {
        # Regular colors
        '30': '#000000',  # Black
        '31': '#cd3131',  # Red
        '32': '#0dbc79',  # Green
        '33': '#e5e510',  # Yellow
        '34': '#2472c8',  # Blue
        '35': '#bc3fbc',  # Magenta
        '36': '#11a8cd',  # Cyan
        '37': '#e5e5e5',  # White
        
        # Bright colors
        '90': '#666666',  # Bright Black
        '91': '#f14c4c',  # Bright Red
        '92': '#23d18b',  # Bright Green
        '93': '#f5f543',  # Bright Yellow
        '94': '#3b8eea',  # Bright Blue
        '95': '#d670d6',  # Bright Magenta
        '96': '#29b8db',  # Bright Cyan
        '97': '#ffffff',  # Bright White
    }
    
    # Process ANSI escape sequences
    def replace_ansi(match):
        codes = match.group(1).split(';')
        styles = []
        
        for code in codes:
            if code == '0' or code == '':  # Reset
                return '</span>'
            elif code == '1':  # Bold
                styles.append('font-weight: bold')
            elif code in ansi_colors:
                styles.append(f'color: {ansi_colors[code]}')
        
        if styles:
            return f'<span style="{"; ".join(styles)}">'
        return ''
    
    # Replace ANSI escape sequences
    ansi_pattern = re.compile(r'\033\[([0-9;]*)m')
    html_text = ansi_pattern.sub(replace_ansi, text)
    
    # Close any remaining open spans
    open_spans = html_text.count('<span') - html_text.count('</span>')
    if open_spans > 0:
        html_text += '</span>' * open_spans
    
    return html_text

def capture_analysis_output(file_path, file_type, use_defanged):
    """Capture the actual terminal output from running the analysis."""
    
    import sys  # Move the import to function scope to fix scoping issue
    import io
    
    try:
        # Import analysis modules
        from . import parser
        from . import header_analyzer
        from . import ioc_extractor
        from . import url_extractor
        from . import body_analyzer
        from . import attachment_analyzer
        
        # Load the email
        msg_obj, _ = parser.load_email(file_path)
        
        # Capture all output
        captured_sections = []
        
        # Helper function to capture output from analysis functions
        def capture_function_output(func, *args, **kwargs):
            old_stdout = sys.stdout
            sys.stdout = captured_output = io.StringIO()
            
            try:
                result = func(*args, **kwargs)
                output_text = captured_output.getvalue()
                
                # Apply defanging if requested
                if use_defanged:
                    output_text = apply_defanging_to_output(output_text, True)
                
                return output_text, result
            except Exception as e:
                return f"Error capturing output: {e}", None
            finally:
                sys.stdout = old_stdout
        
        # Capture each analysis section
        
        # 1. Header Analysis
        try:
            header_output, _ = capture_function_output(header_analyzer.analyze_headers, msg_obj)
            if header_output and header_output.strip():
                captured_sections.append(("EMAIL HEADER ANALYSIS", header_output))
        except Exception as e:
            captured_sections.append(("EMAIL HEADER ANALYSIS", f"Error: {e}"))
        
        # 2. IP Analysis  
        try:
            ip_output, ip_results = capture_function_output(ioc_extractor.analyze_ips, msg_obj, None)
            if ip_output and ip_output.strip():
                captured_sections.append(("IP ADDRESS ANALYSIS", ip_output))
        except Exception as e:
            captured_sections.append(("IP ADDRESS ANALYSIS", f"Error: {e}"))
        
        # 3. URL Analysis
        try:
            url_output, url_results = capture_function_output(url_extractor.analyze_urls, msg_obj, None)
            if url_output and url_output.strip():
                captured_sections.append(("URL ANALYSIS", url_output))
        except Exception as e:
            captured_sections.append(("URL ANALYSIS", f"Error: {e}"))
        
        # 4. Body Analysis
        try:
            body_output, body_results = capture_function_output(body_analyzer.analyze_email_body, msg_obj, None)
            if body_output and body_output.strip():
                captured_sections.append(("EMAIL BODY ANALYSIS", body_output))
        except Exception as e:
            captured_sections.append(("EMAIL BODY ANALYSIS", f"Error: {e}"))
        
        # 5. Attachment Analysis
        try:
            attachment_output, attachment_results = capture_function_output(attachment_analyzer.analyze_attachments, msg_obj, None)
            if attachment_output and attachment_output.strip():
                captured_sections.append(("ATTACHMENT ANALYSIS", attachment_output))
        except Exception as e:
            captured_sections.append(("ATTACHMENT ANALYSIS", f"Error: {e}"))
        
        # 6. Executive Summary (if available)
        try:
            # Get the main module properly
            main_module = None
            for module_name in ['__main__', 'phishalyzer']:
                if module_name in sys.modules:
                    main_module = sys.modules[module_name]
                    break
            
            if main_module and hasattr(main_module, 'generate_comprehensive_executive_summary'):
                # Store some basic results to enable executive summary generation
                if hasattr(main_module, 'last_url_analysis_results'):
                    setattr(main_module, 'last_url_analysis_results', url_results if 'url_results' in locals() else None)
                if hasattr(main_module, 'last_body_analysis_results'):
                    setattr(main_module, 'last_body_analysis_results', body_results if 'body_results' in locals() else None)
                if hasattr(main_module, 'last_attachment_results'):
                    setattr(main_module, 'last_attachment_results', attachment_results if 'attachment_results' in locals() else None)
                
                # Check if we have any results to generate summary
                has_results = any([
                    getattr(main_module, 'last_url_analysis_results', None),
                    getattr(main_module, 'last_body_analysis_results', None),
                    getattr(main_module, 'last_attachment_results', None)
                ])
                
                if has_results:
                    exec_output, _ = capture_function_output(main_module.generate_comprehensive_executive_summary)
                    if exec_output and exec_output.strip():
                        captured_sections.append(("EXECUTIVE FINDINGS REPORT", exec_output))
        except Exception as e:
            # Don't add error for executive summary as it's optional
            pass
        
        return captured_sections
        
    except Exception as e:
        return [("ERROR", f"Failed to capture analysis output: {e}")]

def generate_exact_terminal_html(file_path, file_type, use_defanged):
    """Generate HTML from exact terminal output capture."""
    
    # Calculate file details
    email_filename = os.path.basename(file_path)
    file_size = get_file_size(file_path)
    file_hash = calculate_file_hash(file_path)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Capture the actual terminal output
    captured_sections = capture_analysis_output(file_path, file_type, use_defanged)
    
    # Build HTML with exact terminal styling
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phishalyzer Analysis Report - {escape_html(email_filename)}</title>
    <style>
        body {{
            background-color: #0c0c0c;
            color: #cccccc;
            font-family: 'Courier New', 'Consolas', 'Monaco', monospace;
            font-size: 14px;
            line-height: 1.4;
            margin: 0;
            padding: 20px;
            white-space: pre-wrap;
        }}
        
        .terminal-container {{
            background-color: #0c0c0c;
            border: 1px solid #333333;
            border-radius: 5px;
            padding: 20px;
            max-width: none;
            overflow-x: auto;
        }}
        
        .report-header {{
            color: #2472c8;
            font-weight: bold;
            border-bottom: 1px solid #333333;
            padding-bottom: 20px;
            margin-bottom: 20px;
        }}
        
        .section-header {{
            color: #bc3fbc;
            font-weight: bold;
            margin: 20px 0 10px 0;
        }}
        
        a {{ color: #3b8eea; }}
    </style>
</head>
<body>
    <div class="terminal-container">
        <div class="report-header">EMAIL ANALYSIS REPORT

Generated: {timestamp}
File: {escape_html(email_filename)}
Size: {file_size}
Type: {file_type.upper()}
SHA256: {file_hash}
Output: {'Defanged' if use_defanged else 'Fanged'}</div>
"""

    # Add each captured section
    for section_title, section_content in captured_sections:
        # Format section header like terminal
        total_width = 50
        title_with_spaces = f" {section_title.upper()} "
        padding_needed = total_width - len(title_with_spaces)
        left_padding = padding_needed // 2
        right_padding = padding_needed - left_padding
        header_line = "=" * left_padding + title_with_spaces + "=" * right_padding
        
        html_content += f'\n\n<div class="section-header">{header_line}</div>\n\n'
        
        # Convert the captured terminal output to HTML
        if section_content.strip():
            # Escape HTML first
            escaped_content = escape_html(section_content)
            # Then convert ANSI codes to HTML
            html_content += ansi_to_html(escaped_content)
        else:
            html_content += '<span style="color: #0dbc79;">No output captured for this section</span>'

    # Close HTML
    html_content += """
    </div>
</body>
</html>"""

    return html_content

def prompt_export_format():
    """Prompt user for export format and defanging preference."""
    try:
        # Format selection
        while True:
            if COMPATIBLE_OUTPUT:
                output.print("\n[blue]Export Format:[/blue]")
                output.print("[blue]1:[/blue] Terminal-style HTML Report")
                output.print("[blue]2:[/blue] Markdown Report (coming soon)")
                output.print("[blue]3:[/blue] Plaintext Report (coming soon)")
                output.print("[blue]4:[/blue] Return to main menu")
            else:
                print("\nExport Format:")
                print("1: Terminal-style HTML Report")
                print("2: Markdown Report (coming soon)")
                print("3: Plaintext Report (coming soon)")
                print("4: Return to main menu")
            
            try:
                choice = input("Enter option [1-4]: ").strip()
                if choice in ['1']:
                    format_type = 'terminal-html'
                    break
                elif choice in ['2', '3']:
                    if COMPATIBLE_OUTPUT:
                        print_status("This format is not yet implemented.", "warning")
                    else:
                        print("This format is not yet implemented.")
                    continue
                elif choice in ['4', '']:
                    return None, None
                else:
                    print("Invalid input. Please enter 1, 2, 3, or 4.")
                    continue
            except (KeyboardInterrupt, EOFError):
                print("\nOperation cancelled.")
                return None, None
        
        # Defanging preference
        while True:
            if COMPATIBLE_OUTPUT:
                output.print("\n[blue]Output Style:[/blue]")
                output.print("[blue]1:[/blue] Fanged (normal URLs/IPs)")
                output.print("[blue]2:[/blue] Defanged (safe URLs/IPs)")
            else:
                print("\nOutput Style:")
                print("1: Fanged (normal URLs/IPs)")
                print("2: Defanged (safe URLs/IPs)")
            
            try:
                style_choice = input("Enter option [1-2]: ").strip()
                if style_choice == '1':
                    use_defanged = False
                    break
                elif style_choice == '2':
                    use_defanged = True
                    break
                else:
                    print("Invalid input. Please enter 1 or 2.")
                    continue
            except (KeyboardInterrupt, EOFError):
                print("\nOperation cancelled.")
                return None, None
        
        return format_type, use_defanged
        
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error in export format selection: {e}", "error")
        else:
            print(f"Error in export format selection: {e}")
        return None, None

def export_analysis_report():
    """Main function to export analysis report with exact terminal output."""
    try:
        # Check if analysis has been run
        import sys
        main_module = sys.modules.get('__main__') or sys.modules.get('phishalyzer')
        if not main_module:
            if COMPATIBLE_OUTPUT:
                print_status("Error: Cannot access analysis results.", "error")
            else:
                print("Error: Cannot access analysis results.")
            return
        
        # Check if we have the original file path
        if not hasattr(main_module, 'last_analyzed_file_path'):
            if COMPATIBLE_OUTPUT:
                print_status("Error: No email file has been analyzed yet. Run an analysis first.", "warning")
            else:
                print("Error: No email file has been analyzed yet. Run an analysis first.")
            return
        
        file_path = getattr(main_module, 'last_analyzed_file_path')
        file_type = getattr(main_module, 'last_analyzed_file_type', 'unknown')
        
        if not file_path or not os.path.exists(file_path):
            if COMPATIBLE_OUTPUT:
                print_status("Error: Original email file not found. Re-run analysis.", "error")
            else:
                print("Error: Original email file not found. Re-run analysis.")
            return
        
        # Get export preferences
        format_type, use_defanged = prompt_export_format()
        if not format_type:
            return  # User cancelled
        
        # Generate report
        if format_type == 'terminal-html':
            if COMPATIBLE_OUTPUT:
                print_status("Generating exact terminal output HTML report...", "info")
            else:
                print("Generating exact terminal output HTML report...")
            
            html_content = generate_exact_terminal_html(file_path, file_type, use_defanged)
            
            # Generate filename
            email_filename = os.path.basename(file_path)
            sanitized_name = sanitize_filename(email_filename)
            timestamp = datetime.datetime.now().strftime("%Y.%m.%d")
            base_filename = f"{sanitized_name}_terminal_report_{timestamp}"
            
            # Get desktop path and create unique filename
            desktop_path = get_desktop_path()
            output_path = get_unique_filename(desktop_path, base_filename, 'html')
            
            # Write file
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                
                if COMPATIBLE_OUTPUT:
                    print_status(f"Terminal-style HTML report saved successfully!", "success")
                    output.print(f"[blue]File location:[/blue] {output_path}")
                    
                    # Show file size
                    file_size = os.path.getsize(output_path)
                    if file_size >= 1024:
                        size_str = f"{file_size / 1024:.1f} KB"
                    else:
                        size_str = f"{file_size} B"
                    output.print(f"[blue]File size:[/blue] {size_str}")
                else:
                    print(f"Terminal-style HTML report saved successfully!")
                    print(f"File location: {output_path}")
                    
                    file_size = os.path.getsize(output_path)
                    if file_size >= 1024:
                        size_str = f"{file_size / 1024:.1f} KB"
                    else:
                        size_str = f"{file_size} B"
                    print(f"File size: {size_str}")
                
            except Exception as e:
                if COMPATIBLE_OUTPUT:
                    print_status(f"Error saving report: {e}", "error")
                else:
                    print(f"Error saving report: {e}")
                return
        
        # Return prompt
        try:
            input("\nPress Enter to return to main menu...")
        except (KeyboardInterrupt, EOFError):
            pass
        
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error generating exact terminal export report: {e}", "error")
        else:
            print(f"Error generating exact terminal export report: {e}")