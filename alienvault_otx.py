from OTXv2 import OTXv2, IndicatorTypes
from config import ALIENVAULT_OTX_API_KEY

otx = OTXv2(ALIENVAULT_OTX_API_KEY)

def check_ip_alienvault(ip):
    try:
        results = otx.get_indicator_details_full(IndicatorTypes.IPv4, ip)
        return {
            'pulse_count': results['general']['pulse_info']['count'],
            'reputation': results['general']['reputation'],
            'country': results.get('geo', {}).get('country_name', 'Unknown'),
            'city': results.get('geo', {}).get('city', 'Unknown'),
            'asn': results.get('geo', {}).get('asn', 'Unknown'),
            'malware_samples': len(results.get('malware', {}).get('samples', [])),
        }
    except Exception as e:
        return {'error': f"AlienVault OTX API error: {str(e)}"}

def check_url_alienvault(url):
    try:
        results = otx.get_indicator_details_full(IndicatorTypes.URL, url)
        return {
            'pulse_count': results['general']['pulse_info']['count'],
            'alexa': results.get('general', {}).get('alexa', 'Unknown'),
            'malware_samples': len(results.get('malware', {}).get('samples', [])),
            'url_list': len(results.get('url_list', {}).get('url_list', [])),
            'categories': results.get('general', {}).get('categories', [])
        }
    except Exception as e:
        return {'error': f"AlienVault OTX API error: {str(e)}"}