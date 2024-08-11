import requests
from config import ABUSEIPDB_API_KEY

def check_ip_abuseipdb(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '180'
    }
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers, params=querystring)
        response.raise_for_status()
        result = response.json()
        return {
            'ip_address': result['data']['ipAddress'],
            'abuse_confidence_score': result['data']['abuseConfidenceScore'],
            'total_reports': result['data']['totalReports'],
            'last_reported_at': result['data']['lastReportedAt'],
            'country_code': result['data']['countryCode'],
            'isp': result['data'].get('isp', 'Unknown')
        }
    except requests.RequestException as e:
        return {'error': f"AbuseIPDB API error: {str(e)}"}