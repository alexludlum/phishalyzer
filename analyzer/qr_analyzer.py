import io
import time
import requests
from rich import print
from rich.text import Text
import base64
from urllib.parse import urlparse
from . import defanger

try:
    import fitz  # PyMuPDF
    PYMUPDF_AVAILABLE = True
except ImportError:
    PYMUPDF_AVAILABLE = False

try:
    import cv2
    import numpy as np
    from PIL import Image
    QR_LIBRARIES_AVAILABLE = True
except ImportError:
    QR_LIBRARIES_AVAILABLE = False

def check_qr_dependencies():
    """Check if required libraries for QR code analysis are available."""
    missing = []
    if not PYMUPDF_AVAILABLE:
        missing.append("PyMuPDF (pip install PyMuPDF)")
    if not QR_LIBRARIES_AVAILABLE:
        missing.append("opencv-python and Pillow (pip install opencv-python Pillow)")
    
    return missing

def extract_images_from_pdf(pdf_content):
    """Extract images from PDF content."""
    if not PYMUPDF_AVAILABLE:
        return []
    
    try:
        # Open PDF from bytes
        pdf_document = fitz.open(stream=pdf_content, filetype="pdf")
        images = []
        
        for page_num in range(len(pdf_document)):
            page = pdf_document.load_page(page_num)
            image_list = page.get_images()
            
            for img_index, img in enumerate(image_list):
                # Get image data
                xref = img[0]
                base_image = pdf_document.extract_image(xref)
                image_bytes = base_image["image"]
                
                # Convert to PIL Image
                try:
                    pil_image = Image.open(io.BytesIO(image_bytes))
                    images.append({
                        'page': page_num + 1,
                        'index': img_index + 1,
                        'image': pil_image,
                        'format': base_image.get("ext", "unknown")
                    })
                except Exception:
                    continue
        
        pdf_document.close()
        return images
    
    except Exception as e:
        print(f"[red]Error extracting images from PDF: {e}[/red]")
        return []

def detect_qr_codes_in_image(pil_image):
    """Detect and decode QR codes in a PIL Image using OpenCV."""
    if not QR_LIBRARIES_AVAILABLE:
        return []
    
    try:
        # Convert PIL image to OpenCV format
        if pil_image.mode == 'RGBA':
            pil_image = pil_image.convert('RGB')
        
        # Convert to numpy array
        opencv_image = np.array(pil_image)
        
        # Convert RGB to BGR (OpenCV uses BGR)
        if len(opencv_image.shape) == 3:
            opencv_image = cv2.cvtColor(opencv_image, cv2.COLOR_RGB2BGR)
        
        # Convert to grayscale for QR detection
        gray = cv2.cvtColor(opencv_image, cv2.COLOR_BGR2GRAY)
        
        # Initialize QR code detector
        qr_detector = cv2.QRCodeDetector()
        
        # Detect and decode QR codes
        data, points, straight_qrcode = qr_detector.detectAndDecode(gray)
        
        results = []
        
        if data:
            # QR code found and decoded
            results.append({
                'type': 'QRCODE',
                'data': data,
                'position': points.tolist() if points is not None else None
            })
        
        return results
    
    except Exception as e:
        print(f"[red]Error detecting QR codes with OpenCV: {e}[/red]")
        return []

def check_url_virustotal_qr(url, api_key, cache):
    """Check URL from QR code against VirusTotal (reusing logic from url_extractor)."""
    if url in cache:
        return cache[url]

    if not api_key:
        cache[url] = ("unchecked", "URL will need to be investigated manually")
        return cache[url]

    def url_to_id(url):
        b64 = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return b64

    url_id = url_to_id(url)
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        if response.status_code == 429:
            while True:
                choice = input(
                    "[yellow]VirusTotal API rate limit reached.[/yellow]\n"
                    "Type 'wait' to wait 60 seconds, or 'skip' to proceed without checking: "
                ).strip().lower()
                if choice == "wait":
                    print("Waiting 60 seconds...")
                    time.sleep(60)
                    response = requests.get(api_url, headers=headers, timeout=10)
                    if response.status_code != 429:
                        break
                elif choice == "skip":
                    cache[url] = ("unchecked", "URL will need to be investigated manually")
                    return cache[url]
                else:
                    print("Invalid input. Please type 'wait' or 'skip'.")

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)

            if malicious > 0:
                comment = (f"{malicious} vendor flagged this URL as malicious"
                           if malicious == 1 else
                           f"{malicious} vendors flagged this URL as malicious")
                cache[url] = ("malicious", comment)
            elif suspicious > 0:
                comment = (f"{suspicious} vendor flagged this URL as suspicious"
                           if suspicious == 1 else
                           f"{suspicious} vendors flagged this URL as suspicious")
                cache[url] = ("suspicious", comment)
            elif harmless > 0:
                comment = (f"{harmless} vendor reported this URL as benign"
                           if harmless == 1 else
                           f"{harmless} vendors reported this URL as benign")
                cache[url] = ("benign", comment)
            else:
                cache[url] = ("unchecked", "URL will need to be investigated manually")
        else:
            cache[url] = ("unchecked", "URL will need to be investigated manually")
    except Exception as e:
        print(f"[red]Error querying VirusTotal for QR URL {url}: {e}[/red]")
        cache[url] = ("unchecked", "URL will need to be investigated manually")

    return cache[url]

def is_url(data):
    """Check if QR code data looks like a URL."""
    try:
        result = urlparse(data)
        return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
    except Exception:
        return False

def analyze_pdf_qr_codes(attachment_result, api_key):
    """Analyze PDF attachment for QR codes and return findings."""
    # Check dependencies
    missing_deps = check_qr_dependencies()
    if missing_deps:
        return {
            'qr_found': False,
            'error': f"Missing dependencies: {', '.join(missing_deps)}",
            'qr_results': [],
            'urls_found': []
        }
    
    # Only analyze PDFs
    if not attachment_result['filename'].lower().endswith('.pdf'):
        return {
            'qr_found': False, 
            'error': None, 
            'qr_results': [],
            'urls_found': []
        }
    
    # Get PDF content from the attachment
    content = attachment_result.get('content')
    if not content:
        return {
            'qr_found': False, 
            'error': "No PDF content available", 
            'qr_results': [],
            'urls_found': []
        }
    
    # Extract images from PDF
    images = extract_images_from_pdf(content)
    if not images:
        return {
            'qr_found': False, 
            'error': "No images found in PDF", 
            'qr_results': [],
            'urls_found': []
        }
    
    # Scan images for QR codes
    qr_results = []
    url_cache = {}
    
    for img_info in images:
        qr_codes = detect_qr_codes_in_image(img_info['image'])
        
        for qr in qr_codes:
            qr_data = qr['data']
            
            # Check if QR contains a URL
            if is_url(qr_data):
                verdict, comment = check_url_virustotal_qr(qr_data, api_key, url_cache)
                
                qr_results.append({
                    'page': img_info['page'],
                    'type': qr['type'],
                    'url': qr_data,
                    'verdict': verdict,
                    'comment': comment
                })
            else:
                # Non-URL QR code data
                qr_results.append({
                    'page': img_info['page'],
                    'type': qr['type'],
                    'data': qr_data,
                    'verdict': 'info',
                    'comment': 'Non-URL QR code data'
                })
    
    return {
        'qr_found': len(qr_results) > 0,
        'error': None,
        'qr_results': qr_results,
        'urls_found': [r for r in qr_results if 'url' in r]
    }

def display_qr_analysis(attachment_index, qr_analysis):
    """Display QR code analysis results with proper formatting."""
    if qr_analysis.get('error'):
        error_text = Text("  QR Analysis: ")
        if "Missing dependencies" in qr_analysis['error']:
            error_text.append(qr_analysis['error'], style="orange3")
        else:
            error_text.append(qr_analysis['error'])
        print(error_text)
        return
    
    if not qr_analysis.get('qr_found'):
        no_qr_text = Text("  QR Analysis: No QR codes detected")
        print(no_qr_text)
        return
    
    # QR codes detected header
    header_text = Text("  ")
    header_text.append("QR Code Detected! Details:", style="red")
    print(header_text)
    
    # Display each QR code
    for i, qr in enumerate(qr_analysis.get('qr_results', []), 1):
        if 'url' in qr:
            # URL QR code
            url = qr['url']
            verdict = qr['verdict']
            comment = qr['comment']
            
            # QR code URL line with "Destination:"
            display_url = defanger.defang_url(url) if defanger.should_defang() else url
            qr_url_text = Text(f"    QR {i} (Page {qr['page']}) Destination: ")
            qr_url_text.append(display_url, style="yellow")
            print(qr_url_text)
            
            # Verdict line with consistent color scheme
            verdict_colors = {
                "malicious": "red",
                "suspicious": "yellow",
                "benign": "green",
                "unchecked": "orange3"
            }
            verdict_color = verdict_colors.get(verdict, "orange3")
            
            verdict_text = Text("    Verdict: ")
            verdict_text.append(verdict.upper(), style=verdict_color)
            verdict_text.append(f" ({comment})")
            print(verdict_text)
        else:
            # Non-URL QR code
            non_url_text = Text(f"    QR {i} (Page {qr['page']}) Data: {qr['data']}")
            print(non_url_text)
            
            type_text = Text(f"    Type: {qr['type']}")
            print(type_text)