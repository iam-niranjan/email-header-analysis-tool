import requests
from urllib.parse import urlparse

def unshorten_url(url):
    try:
        response = requests.get(url, allow_redirects=True, timeout=10)
        return response.url
    except requests.RequestException:
        return url  # Return original URL if there's an error

def is_shortened_url(url):
    parsed = urlparse(url)
    shortening_services = [
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
        'is.gd', 'buff.ly', 'adf.ly', 'j.mp', 'tr.im',
        'cl.ly', 'po.st', 'eepurl.com', 'ift.tt', 'soo.gd',
        'qr.ae', 'cutt.ly', 'ht.ly', 'urlz.fr', 'snip.ly',
        'shorturl.at'
    ]
    return parsed.netloc in shortening_services

def unshorten_urls(urls):
    unshortened = {}
    for url in urls:
        if is_shortened_url(url):
            unshortened[url] = unshorten_url(url)
        else:
            unshortened[url] = url
    return unshortened