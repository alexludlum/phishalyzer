"""
Email body content analysis module for phishalyzer.
Detects phishing techniques through keyword analysis and content inspection.
"""

import re
from difflib import SequenceMatcher
from email.message import EmailMessage

# Import compatible output system
try:
    from .compatible_output import output, print_status
    COMPATIBLE_OUTPUT = True
except ImportError:
    COMPATIBLE_OUTPUT = False

from . import defanger

# Phishing technique keyword database
PHISHING_KEYWORDS = {
    "payment_redirect": {
        "name": "Payment Redirect Scam",
        "risk_level": "HIGH",
        "keywords": [
            "wire transfer", "ach transfer", "payment update", "new bank account",
            "update payment method", "change bank details", "routing number changed",
            "payment redirect", "new payment info", "bank account update"
        ],
        "description": "Attempts to redirect legitimate payments to attacker accounts"
    },
    
    "credential_harvesting": {
        "name": "Credential Harvesting",
        "risk_level": "HIGH", 
        "keywords": [
            "reset password", "verify account", "confirm identity", "login credentials",
            "username password", "security verification", "account verification",
            "confirm password", "validate account", "authenticate account"
        ],
        "description": "Attempts to steal login credentials and personal information"
    },
    
    "account_takeover": {
        "name": "Account Takeover",
        "risk_level": "HIGH",
        "keywords": [
            "account suspended", "account locked", "account compromised", "security breach",
            "unauthorized access", "unusual activity", "account frozen", "account blocked",
            "security alert", "suspicious login", "account disabled"
        ],
        "description": "Claims of account compromise to steal credentials"
    },
    
    "executive_impersonation": {
        "name": "Executive Impersonation (BEC)",
        "risk_level": "HIGH",
        "keywords": [
            "ceo urgent", "from management", "executive decision", "board approval",
            "confidential request", "urgent payment", "executive order", "management directive",
            "cfo request", "president urgent", "chairman request"
        ],
        "description": "Impersonates executives to authorize fraudulent transactions"
    },
    
    "malware_delivery": {
        "name": "Malware Delivery",
        "risk_level": "HIGH",
        "keywords": [
            "install update", "security patch", "required software", "system upgrade",
            "download installer", "run executable", "install program", "software update",
            "critical update", "security fix", "patch download"
        ],
        "description": "Attempts to deliver malware through software installation requests"
    },
    
    "invoice_fraud": {
        "name": "Invoice Fraud",
        "risk_level": "MEDIUM",
        "keywords": [
            "outstanding invoice", "payment overdue", "billing discrepancy", "accounting department",
            "invoice attached", "payment due", "final notice", "collection notice",
            "billing error", "account receivable", "payment reminder"
        ],
        "description": "Fraudulent invoices attempting to redirect payments"
    },
    
    "document_lure": {
        "name": "Document Lure",
        "risk_level": "HIGH",
        "keywords": [
            "view document", "download attachment", "open pdf", "shared file",
            "document expires", "file access", "download before", "view attachment",
            "shared document", "file download", "document link", "file shared",
            "compensation review", "view", "click here", "see attachment"
        ],
        "description": "Lures victims to open potentially malicious documents or links"
    },
    
    "tech_support_scam": {
        "name": "Tech Support Scam", 
        "risk_level": "MEDIUM",
        "keywords": [
            "tech support", "system maintenance", "network upgrade", "security scan",
            "virus detected", "computer infected", "call support", "technical issue",
            "system error", "support team", "remote assistance"
        ],
        "description": "Fake technical support requests to gain system access"
    },
    
    "authority_impersonation": {
        "name": "Authority Impersonation",
        "risk_level": "MEDIUM",
        "keywords": [
            "irs notice", "legal action", "court summons", "tax refund",
            "government notice", "official notice", "federal agency", "legal department",
            "compliance violation", "regulatory notice", "official business"
        ],
        "description": "Impersonates government or legal authorities"
    },
    
    "gift_card_scam": {
        "name": "Gift Card Scam",
        "risk_level": "MEDIUM",
        "keywords": [
            "gift card", "itunes card", "google play card", "prepaid card",
            "gift card codes", "redeem card", "card numbers", "steam card",
            "amazon gift card", "visa gift card"
        ],
        "description": "Requests payment through untraceable gift cards"
    },
    
    "cryptocurrency_scam": {
        "name": "Cryptocurrency Scam",
        "risk_level": "MEDIUM",
        "keywords": [
            "bitcoin wallet", "crypto payment", "blockchain transaction", "digital currency",
            "bitcoin address", "cryptocurrency", "btc payment", "ethereum wallet",
            "crypto wallet", "digital payment"
        ],
        "description": "Requests payment through cryptocurrency"
    },
    
    "urgency_manipulation": {
        "name": "Urgency Manipulation",
        "risk_level": "LOW",
        "keywords": [
            "urgent", "immediate", "asap", "expires today", "deadline",
            "act now", "limited time", "final notice", "time sensitive",
            "expires soon", "last chance", "hurry"
        ],
        "description": "Uses urgency to pressure quick decisions"
    },
    
    "general_spam": {
        "name": "General Spam",
        "risk_level": "LOW",
        "keywords": [
            "limited time offer", "buy one get one", "special discount", "act fast",
            "free trial", "no obligation", "money back guarantee", "limited quantities",
            "exclusive offer", "special promotion", "deal expires"
        ],
        "description": "General spam and marketing manipulation tactics"
    },
    
    "prize_lottery_scam": {
        "name": "Prize/Lottery Scam",
        "risk_level": "LOW",
        "keywords": [
            "congratulations winner", "lottery winner", "prize awarded", "you have won",
            "claim prize", "lottery ticket", "sweepstakes winner", "grand prize",
            "claim reward", "prize money", "winning notification"
        ],
        "description": "Fake prize or lottery winnings to collect personal information"
    }
}

def safe_extract_email_body_enhanced(msg_obj):
    """Enhanced body extraction that preserves URLs and button text from HTML"""
    try:
        if not msg_obj:
            return ""
        
        body_content = ""
        extracted_elements = []
        
        # Handle multipart messages
        if hasattr(msg_obj, 'is_multipart') and msg_obj.is_multipart():
            for part in msg_obj.walk():
                try:
                    if part.get_content_type() == "text/html":
                        payload = part.get_payload(decode=True)
                        if payload:
                            html_content = payload.decode('utf-8', errors='ignore')
                            
                            # Extract button/link text BEFORE stripping HTML - this is the key fix!
                            link_text = re.findall(r'<a[^>]*>([^<]+)</a>', html_content, re.IGNORECASE)
                            button_text = re.findall(r'<button[^>]*>([^<]+)</button>', html_content, re.IGNORECASE)
                            
                            # Add extracted text to analysis content
                            extracted_elements.extend(link_text + button_text)
                            
                            # Strip HTML tags for regular text analysis
                            text_content = re.sub(r'<[^>]+>', '', html_content)
                            body_content += text_content + "\n"
                    
                    elif part.get_content_type() == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            plain_content = payload.decode('utf-8', errors='ignore')
                            body_content += plain_content + "\n"
                            
                except Exception:
                    continue
        else:
            # Single part message
            try:
                payload = msg_obj.get_payload(decode=True)
                if payload:
                    if isinstance(payload, bytes):
                        content = payload.decode('utf-8', errors='ignore')
                    else:
                        content = str(payload)
                    
                    # Check if it's HTML and extract elements
                    if '<' in content and '>' in content:
                        link_text = re.findall(r'<a[^>]*>([^<]+)</a>', content, re.IGNORECASE)
                        button_text = re.findall(r'<button[^>]*>([^<]+)</button>', content, re.IGNORECASE)
                        extracted_elements.extend(link_text + button_text)
                        content = re.sub(r'<[^>]+>', '', content)
                    
                    body_content += content
            except Exception:
                try:
                    # Fallback to non-decoded payload
                    payload = msg_obj.get_payload()
                    if payload:
                        body_content = str(payload)
                except Exception:
                    body_content = ""
        
        # Combine body content with extracted button/link text
        final_content = body_content.strip()
        if extracted_elements:
            final_content += " " + " ".join(extracted_elements)
        
        return final_content.strip()
        
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error extracting email body: {e}", "warning")
        else:
            print(f"Error extracting email body: {e}")
        return ""

def extract_meaningful_words(text):
    """Extract words that are likely to be meaningful (not domain parts, IPs, etc.)"""
    # Remove URLs, email addresses, and domains first
    clean_text = re.sub(r'https?://[^\s]+', ' ', text)  # Remove URLs
    clean_text = re.sub(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', ' ', clean_text)  # Remove emails
    clean_text = re.sub(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', ' ', clean_text)  # Remove domains like suspicious.com
    
    # Extract meaningful words (3+ characters, alphabetic)
    words = re.findall(r'\b[a-zA-Z]{3,}\b', clean_text.lower())
    return words

def analyze_email_subject(msg_obj):
    """NEW: Analyze email subject for phishing indicators"""
    try:
        subject = msg_obj.get('Subject', '') if msg_obj else ''
        if not subject:
            return {}
        
        # Apply same keyword analysis to subject line
        return analyze_keywords(subject)
    except Exception:
        return {}

def fuzzy_match(keyword, text, threshold=0.8):
    """Improved fuzzy matching that avoids domain/technical false positives."""
    try:
        if not keyword or not text:
            return False, None
        
        keyword_lower = keyword.lower().strip()
        
        # Extract meaningful words (avoiding domains, emails, IPs)
        words = extract_meaningful_words(text)
        
        # For single word keywords
        if ' ' not in keyword_lower:
            for word in words:
                if len(word) >= 3:  # Avoid very short words
                    similarity = SequenceMatcher(None, keyword_lower, word).ratio()
                    if similarity >= threshold:
                        return True, word
        else:
            # For multi-word phrases
            keyword_words = keyword_lower.split()
            
            if len(keyword_words) == 2:
                for i in range(len(words) - 1):
                    phrase = f"{words[i]} {words[i+1]}"
                    similarity = SequenceMatcher(None, keyword_lower, phrase).ratio()
                    if similarity >= threshold:
                        return True, phrase
            elif len(keyword_words) == 3:
                for i in range(len(words) - 2):
                    phrase = f"{words[i]} {words[i+1]} {words[i+2]}"
                    similarity = SequenceMatcher(None, keyword_lower, phrase).ratio()
                    if similarity >= threshold:
                        return True, phrase
        
        return False, None
        
    except Exception:
        return False, None

def analyze_keywords(body_content):
    """Analyze body content for phishing keywords."""
    try:
        if not body_content or not isinstance(body_content, str):
            return {}
        
        findings = {}
        
        for category_id, category_data in PHISHING_KEYWORDS.items():
            matched_keywords = []
            
            for keyword in category_data["keywords"]:
                is_match, matched_text = fuzzy_match(keyword, body_content)
                if is_match:
                    matched_keywords.append({
                        "keyword": keyword,
                        "matched_text": matched_text,
                        "exact_match": keyword.lower() == matched_text.lower() if matched_text else False
                    })
            
            if matched_keywords:
                findings[category_id] = {
                    "name": category_data["name"],
                    "risk_level": category_data["risk_level"],
                    "description": category_data["description"],
                    "matched_keywords": matched_keywords,
                    "keyword_count": len(matched_keywords)
                }
        
        return findings
        
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error in keyword analysis: {e}", "error")
        else:
            print(f"Error in keyword analysis: {e}")
        return {}

def calculate_risk_score(findings):
    """Calculate overall risk score based on findings."""
    try:
        if not findings:
            return 0
        
        # Determine base score from highest risk level
        risk_levels = [finding["risk_level"] for finding in findings.values()]
        
        if "HIGH" in risk_levels:
            base_score = 70
            max_score = 100
        elif "MEDIUM" in risk_levels:
            base_score = 40
            max_score = 69
        elif "LOW" in risk_levels:
            base_score = 15
            max_score = 39
        else:
            return 0
        
        # Calculate bonus points
        high_risk_count = sum(1 for level in risk_levels if level == "HIGH")
        medium_risk_count = sum(1 for level in risk_levels if level == "MEDIUM")
        low_risk_count = sum(1 for level in risk_levels if level == "LOW")
        
        total_keywords = sum(finding["keyword_count"] for finding in findings.values())
        
        # Bonus calculation
        bonus = 0
        if base_score == 70:  # HIGH risk baseline
            bonus += min(15, (high_risk_count - 1) * 5)  # Additional high risk categories
            bonus += min(10, medium_risk_count * 2)      # Medium risk categories
            bonus += min(5, total_keywords - high_risk_count)  # Keyword density
        elif base_score == 40:  # MEDIUM risk baseline  
            bonus += min(20, (medium_risk_count - 1) * 5)  # Additional medium risk categories
            bonus += min(9, low_risk_count * 2)            # Low risk categories
            bonus += min(5, total_keywords - medium_risk_count)  # Keyword density
        else:  # LOW risk baseline
            bonus += min(15, (low_risk_count - 1) * 3)     # Additional low risk categories
            bonus += min(9, total_keywords - low_risk_count)  # Keyword density
        
        final_score = min(max_score, base_score + bonus)
        return final_score
        
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error calculating risk score: {e}", "error")
        else:
            print(f"Error calculating risk score: {e}")
        return 0

def format_summary_line(finding, max_line_length=80):
    """Format a single finding line for the summary, ensuring it doesn't exceed length."""
    try:
        name = finding["name"]
        risk_level = finding["risk_level"]
        matched_keywords = finding["matched_keywords"]
        
        # Start building the line
        prefix = f"- [{risk_level}]: {name}: "
        remaining_length = max_line_length - len(prefix) - 10  # Buffer for "+X more"
        
        # Add keywords until we run out of space
        keyword_parts = []
        total_length = 0
        
        for i, match in enumerate(matched_keywords):
            if match["exact_match"]:
                keyword_text = f'"{match["keyword"]}"'
            else:
                keyword_text = f'"{match["matched_text"]}"'
            
            if i > 0:
                keyword_text = ", " + keyword_text
            
            if total_length + len(keyword_text) <= remaining_length:
                keyword_parts.append(keyword_text)
                total_length += len(keyword_text)
            else:
                # Add "+X more" if there are remaining keywords
                remaining_count = len(matched_keywords) - i
                if remaining_count > 0:
                    keyword_parts.append(f", +{remaining_count} more")
                break
        
        keywords_text = "".join(keyword_parts)
        return f"{prefix}{keywords_text}"
        
    except Exception:
        return f"- [{finding.get('risk_level', 'UNKNOWN')}]: {finding.get('name', 'Unknown')}: Error formatting"

def display_body_analysis_summary(findings, risk_score):
    """Display concise body analysis summary."""
    try:
        if not findings:
            if COMPATIBLE_OUTPUT:
                output.print("[green]No phishing indicators detected in email body.[/green]")
            else:
                print("No phishing indicators detected in email body.")
            return
        
        # Determine risk score color
        if risk_score >= 70:
            score_color = "red"
        elif risk_score >= 40:
            score_color = "orange3"
        else:
            score_color = "yellow"
        
        # Header with risk score
        if COMPATIBLE_OUTPUT:
            output.print(f"Found potential phishing content (Risk score: [{score_color}]{risk_score}/100[/{score_color}]):")
        else:
            print(f"Found potential phishing content (Risk score: {risk_score}/100):")
        
        # Sort findings by risk level and display
        risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        sorted_findings = sorted(findings.values(), key=lambda x: (risk_order.get(x["risk_level"], 3), x["name"]))
        
        for finding in sorted_findings:
            risk_level = finding["risk_level"]
            
            # Determine color for risk level
            if risk_level == "HIGH":
                risk_color = "red"
            elif risk_level == "MEDIUM":
                risk_color = "orange3"
            else:
                risk_color = "yellow"
            
            summary_line = format_summary_line(finding)
            
            if COMPATIBLE_OUTPUT:
                # Color the risk level portion
                colored_line = summary_line.replace(f"[{risk_level}]", f"[{risk_color}]{risk_level}[/{risk_color}]")
                output.print(colored_line)
            else:
                print(summary_line)
        
        # No blank line here - let the section header handle spacing
        
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error displaying body analysis summary: {e}", "error")
        else:
            print(f"Error displaying body analysis summary: {e}")

def analyze_email_body(msg_obj, api_key=None):
    """Main function to analyze email body content with enhanced subject analysis."""
    try:
        # Extract body content using enhanced method
        body_content = safe_extract_email_body_enhanced(msg_obj)
        
        if not body_content or len(body_content.strip()) == 0:
            if COMPATIBLE_OUTPUT:
                print_status("No email body content found to analyze.", "warning")
            else:
                print("No email body content found to analyze.")
            return None
        
        # NEW: Analyze subject line
        subject_findings = analyze_email_subject(msg_obj)
        
        # Analyze body keywords
        body_findings = analyze_keywords(body_content)
        
        # Combine body and subject findings
        findings = body_findings.copy()
        for category_id, finding in subject_findings.items():
            if category_id in findings:
                # Merge keywords if category already exists
                findings[category_id]['matched_keywords'].extend(finding['matched_keywords'])
                findings[category_id]['keyword_count'] += finding['keyword_count']
            else:
                # Add new category from subject
                findings[category_id] = finding
        
        # Calculate risk score on combined findings
        risk_score = calculate_risk_score(findings)
        
        # Prepare results
        results = {
            "findings": findings,
            "risk_score": risk_score,
            "body_length": len(body_content),
            "categories_found": len(findings),
            "subject_analyzed": len(subject_findings) > 0
        }
        
        # Display summary
        display_body_analysis_summary(findings, risk_score)
        
        return results
        
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Critical error in email body analysis: {e}", "error")
            print_status("Body analysis could not be completed.", "warning")
        else:
            print(f"Critical error in email body analysis: {e}")
            print("Body analysis could not be completed.")
        return None

def display_detailed_body_analysis(results):
    """Display detailed breakdown of body analysis results."""
    try:
        if not results or not results.get("findings"):
            if COMPATIBLE_OUTPUT:
                print_status("No body analysis results available. Run an analysis first.", "warning")
            else:
                print("No body analysis results available. Run an analysis first.")
            return
        
        findings = results["findings"]
        risk_score = results["risk_score"]
        
        if COMPATIBLE_OUTPUT:
            output.print("\n[magenta]===== DETAILED BODY ANALYSIS =====[/magenta]\n")
        else:
            print("\n===== DETAILED BODY ANALYSIS =====\n")
        
        # Sort findings by risk level
        risk_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        sorted_findings = sorted(findings.values(), key=lambda x: (risk_order.get(x["risk_level"], 3), x["name"]))
        
        for finding in sorted_findings:
            risk_level = finding["risk_level"]
            name = finding["name"]
            description = finding["description"]
            matched_keywords = finding["matched_keywords"]
            
            # Determine color for risk level
            if risk_level == "HIGH":
                risk_color = "red"
            elif risk_level == "MEDIUM":
                risk_color = "orange3"
            else:
                risk_color = "yellow"
            
            # Display category header
            if COMPATIBLE_OUTPUT:
                output.print(f"[{risk_color}][{risk_level}] {name}:[/{risk_color}]")
                escaped_description = output.escape(description)
                output.print(f"  Description: {escaped_description}")
            else:
                print(f"[{risk_level}] {name}:")
                print(f"  Description: {description}")
            
            # Display matched keywords
            for match in matched_keywords:
                keyword = match["keyword"]
                matched_text = match["matched_text"]
                exact_match = match["exact_match"]
                
                if exact_match:
                    match_info = "exact match"
                else:
                    match_info = f'found: "{matched_text}"'
                
                escaped_keyword = output.escape(keyword) if COMPATIBLE_OUTPUT else keyword
                escaped_match_info = output.escape(match_info) if COMPATIBLE_OUTPUT else match_info
                
                print(f"  - \"{escaped_keyword}\" ({escaped_match_info})")
            
            print()  # Blank line between categories
        
        # Risk score calculation breakdown
        if COMPATIBLE_OUTPUT:
            output.print("[blue]Risk Score Calculation:[/blue]")
        else:
            print("Risk Score Calculation:")
        
        # Determine base score explanation
        risk_levels = [finding["risk_level"] for finding in findings.values()]
        if "HIGH" in risk_levels:
            base_explanation = "70 (HIGH RISK detected)"
        elif "MEDIUM" in risk_levels:
            base_explanation = "40 (MEDIUM RISK detected)"
        elif "LOW" in risk_levels:
            base_explanation = "15 (LOW RISK detected)"
        else:
            base_explanation = "0 (No risks detected)"
        
        bonus = risk_score - (70 if "HIGH" in risk_levels else 40 if "MEDIUM" in risk_levels else 15 if "LOW" in risk_levels else 0)
        
        print(f"- Base score: {base_explanation}")
        if bonus > 0:
            print(f"- Bonus: +{bonus} (multiple categories + keyword density)")
        
        # Final score with color
        if risk_score >= 70:
            score_color = "red"
        elif risk_score >= 40:
            score_color = "orange3"
        else:
            score_color = "yellow"
        
        if COMPATIBLE_OUTPUT:
            output.print(f"- Final score: [{score_color}]{risk_score}/100[/{score_color}]")
        else:
            print(f"- Final score: {risk_score}/100")
        
        # Return prompt
        try:
            input("\nPress Enter to return to main menu...")
        except (KeyboardInterrupt, EOFError):
            pass
        
    except Exception as e:
        if COMPATIBLE_OUTPUT:
            print_status(f"Error displaying detailed body analysis: {e}", "error")
        else:
            print(f"Error displaying detailed body analysis: {e}")