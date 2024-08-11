import requests
import time
from config import URLSCAN_IO_API_KEY

def scan_url_urlscan(url, scan_type='public'):
    headers = {
        'Content-Type': 'application/json',
        'API-Key': URLSCAN_IO_API_KEY
    }
    data = {
        "url": url,
        "visibility": scan_type
    }
    
    try:
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data)
        response.raise_for_status()
        result = response.json()
        
        if 'successful' in result.get('message', ''):
            # Wait for scan to complete
            time.sleep(30)
            
            # Fetch results
            result_url = f"https://urlscan.io/api/v1/result/{result['uuid']}/"
            result_response = requests.get(result_url)
            result_response.raise_for_status()
            final_result = result_response.json()
            
            return {
                'overall_score': final_result['verdicts']['overall']['score'],
                'malicious': final_result['verdicts']['overall']['malicious'],
                'categories': final_result['verdicts']['urlscan'].get('categories', []),
                'screenshot_url': final_result['task']['screenshotURL'],
                'report_url': final_result['task']['reportURL'],
                'ip_address': final_result['page'].get('ip', 'Unknown'),
                'server': final_result['page'].get('server', 'Unknown'),
                'domain': final_result['page'].get('domain', 'Unknown')
            }
    except requests.RequestException as e:
        return {'error': f"URLScan.io API error: {str(e)}"}