import requests
import time

def check_url_vt(url, api_key):
    headers = {"x-apikey": api_key}
    scan_url = "https://www.virustotal.com/api/v3/urls"

    # Step 1: Get the URL ID by sending a POST request
    resp = requests.post(scan_url, headers=headers, data={"url": url})
    if resp.status_code != 200:
        raise Exception(f"VT scan request failed: {resp.text}")
    
    url_id = resp.json()["data"]["id"]

    # Step 2: Use the URL ID to get the analysis report
    report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    time.sleep(2)  # Wait briefly to ensure scan is processed
    resp = requests.get(report_url, headers=headers)
    if resp.status_code != 200:
        raise Exception(f"VT report fetch failed: {resp.text}")
    
    data = resp.json()["data"]["attributes"]["last_analysis_stats"]
    return {
        "malicious": data.get("malicious", 0),
        "suspicious": data.get("suspicious", 0)
    }
