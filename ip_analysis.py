from utils import check_virustotal_rate_limit, VIRUSTOTAL_API_KEY
import requests

def analyze_ip(ip):
    results = []
    
    # VirusTotal IP analysis
    vt_ip_info = get_virustotal_ip_info(ip)
    if vt_ip_info:
        results.append(f"VirusTotal results for IP {ip}:")
        results.append(f"  AS Owner: {vt_ip_info['as_owner']}")
        results.append(f"  Country: {vt_ip_info['country']}")
        results.append(f"  Reputation: {vt_ip_info['reputation']}")
        results.append(f"  Last analysis stats: {vt_ip_info['last_analysis_stats']}")
        results.append(f"  Tags: {', '.join(vt_ip_info['tags'])}")
    else:
        results.append(f"Unable to retrieve VirusTotal results for IP {ip}")
    
    return results

def get_virustotal_ip_info(ip):
    check_virustotal_rate_limit()
    
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            data = result['data']['attributes']
            return {
                'as_owner': data.get('as_owner'),
                'country': data.get('country'),
                'reputation': data.get('reputation'),
                'last_analysis_stats': data.get('last_analysis_stats'),
                'tags': data.get('tags', [])
            }
        else:
            print(f"Error checking VirusTotal for IP {ip}: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error checking VirusTotal for IP {ip}: {str(e)}")
        return None