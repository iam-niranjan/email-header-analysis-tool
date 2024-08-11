import time
import re
from email import message_from_bytes
from email.policy import default
from config import VIRUSTOTAL_API_KEY

VT_REQUEST_LIMIT = 4  # requests per minute
VT_DAILY_LIMIT = 500  # requests per day

vt_request_count = 0
vt_last_request_time = 0

def check_virustotal_rate_limit():
    global vt_request_count, vt_last_request_time
    current_time = time.time()
    if current_time - vt_last_request_time < 60:
        if vt_request_count >= VT_REQUEST_LIMIT:
            wait_time = 60 - (current_time - vt_last_request_time)
            return wait_time
    else:
        vt_request_count = 0
        vt_last_request_time = current_time
    
    vt_request_count += 1
    return 0

def parse_email_addresses(header_list):
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = set()
    for header in header_list:
        found_ips = re.findall(ip_pattern, header)
        ips.update(found_ips)
    return list(ips)

def extract_email_address(email_string):
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    match = re.search(email_pattern, email_string)
    if match:
        return match.group()
    return None

def extract_urls_from_email(eml_content):
    msg = message_from_bytes(eml_content, policy=default)
    urls = []
    
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                urls.extend(extract_urls_from_text(body))
    else:
        body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        urls.extend(extract_urls_from_text(body))
    
    return list(set(urls))

def extract_urls_from_text(text):
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    return re.findall(url_pattern, text)