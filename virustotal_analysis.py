import requests
import time
from utils import VIRUSTOTAL_API_KEY, check_virustotal_rate_limit

def scan_url(url):
    check_virustotal_rate_limit()
    
    api_url = 'https://www.virustotal.com/api/v3/urls'
    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    data = {"url": url}
    
    try:
        response = requests.post(api_url, headers=headers, data=data)
        response.raise_for_status()
        result = response.json()
        
        analysis_id = result['data']['id']
        
        # Wait for analysis to complete
        time.sleep(15)  # Adjust this delay as needed
        
        # Get the analysis results
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        response = requests.get(analysis_url, headers=headers)
        response.raise_for_status()
        analysis_result = response.json()
        
        stats = analysis_result['data']['attributes']['stats']
        return {
            'malicious': stats['malicious'],
            'suspicious': stats['suspicious'],
            'harmless': stats['harmless'],
            'undetected': stats['undetected']
        }
    except requests.exceptions.RequestException as e:
        return f"Error scanning URL: {str(e)}"
    except (KeyError, ValueError) as e:
        return f"Error processing VirusTotal response: {str(e)}"