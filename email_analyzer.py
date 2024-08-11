import os
import time
import re
import logging
from email import message_from_bytes
from email.policy import default
from email_authentication import analyze_email_authentication
from ip_analysis import analyze_ip
from domain_analysis import analyze_domain, get_domain_age
from malware_analysis import analyze_file
from utils import parse_email_addresses, extract_email_address, extract_urls_from_email, check_virustotal_rate_limit
from virustotal_analysis import scan_url
from url_unshortener import unshorten_urls
from difflib import SequenceMatcher
from datetime import datetime, timezone
from config import *
from tqdm import tqdm

class EmailAnalyzer:
    def __init__(self):
        self.api_call_count = 0
        self.api_cache = {}

    def increment_api_call(self):
        self.api_call_count += 1
        logging.info(f"API call count: {self.api_call_count}")

    @staticmethod
    def format_section(title, content):
        separator = "=" * len(title)
        return f"\n{separator}\n{title}\n{separator}\n{content}\n"

    @staticmethod
    def similar(a, b):
        return SequenceMatcher(None, a, b).ratio()

    def assess_email_risk(self, analysis_data, eml_content_decoded):
        risk_score = 0
        risk_factors = []
        safety_factors = []

        # Domain analysis
        domain_stats = analysis_data.get('domain_stats', {})
        if domain_stats.get('malicious', 0) > 0:
            risk_score += 30
            risk_factors.append("Domain flagged as malicious by VirusTotal")
        elif domain_stats.get('suspicious', 0) > 0:
            risk_score += 15
            risk_factors.append("Domain flagged as suspicious by VirusTotal")
        else:
            safety_factors.append("Domain not flagged by VirusTotal")

        # Email authentication
        auth_results = analysis_data.get('auth_results', {})
        if 'Error checking SPF' in auth_results.get('spf', '') or '[FAIL]' in auth_results.get('spf', ''):
            risk_score += 20
            risk_factors.append("SPF check failed or encountered an error")
        else:
            safety_factors.append("SPF check passed")

        if 'Error checking DMARC' in auth_results.get('dmarc', '') or '[FAIL]' in auth_results.get('dmarc', ''):
            risk_score += 20
            risk_factors.append("DMARC check failed or encountered an error")
        else:
            safety_factors.append("DMARC check passed")

        if 'Error checking DKIM' in auth_results.get('dkim', '') or '[FAIL]' in auth_results.get('dkim', ''):
            risk_score += 20
            risk_factors.append("DKIM check failed or encountered an error")
        else:
            safety_factors.append("DKIM check passed")

        # IP analysis
        ip_stats = analysis_data.get('ip_stats', {})
        if ip_stats.get('malicious', 0) > 0:
            risk_score += 30
            risk_factors.append("Sender IP flagged as malicious by VirusTotal")
        elif ip_stats.get('suspicious', 0) > 0:
            risk_score += 15
            risk_factors.append("Sender IP flagged as suspicious by VirusTotal")
        else:
            safety_factors.append("Sender IP not flagged by VirusTotal")

        # Attachments
        if analysis_data.get('attachments', 0) > 0:
            risk_score += 10
            risk_factors.append("Email contains attachments")

        # URLs
        urls = analysis_data.get('urls', 0)
        if urls > 0:
            risk_score += 5 * urls  # Increase risk for each URL
            risk_factors.append(f"Email contains {urls} URLs")

        # Load trusted domains
        trusted_domains = self.load_trusted_domains()

        # Check for display name spoofing
        display_name = analysis_data.get('display_name', '').lower()
        sender_email = analysis_data.get('sender_email', '').lower()
        if display_name and sender_email:
            if self.check_display_name_spoofing(display_name, sender_email):
                risk_score += 30
                risk_factors.append("Possible display name spoofing detected")
            else:
                safety_factors.append("No display name spoofing detected")

        # Check for domain spoofing
        sender_domain = sender_email.split('@')[-1] if sender_email else ''
        if sender_domain:
            spoofed_domain = self.check_domain_spoofing(sender_domain, trusted_domains)
            if spoofed_domain:
                risk_score += 40
                risk_factors.append(f"Possible domain spoofing detected: {sender_domain} similar to {spoofed_domain}")
            else:
                safety_factors.append("No domain spoofing detected")

        # Check for reply-to spoofing
        reply_to = analysis_data.get('reply_to', '').lower()
        if reply_to and reply_to != sender_email:
            risk_score += 25
            risk_factors.append(f"Reply-To address ({reply_to}) differs from sender ({sender_email})")

        # Check for unicode spoofing in email address
        if self.check_unicode_spoofing(sender_email):
            risk_score += 35
            risk_factors.append("Possible unicode spoofing detected in email address")

        # Check for suspicious keywords in the subject
        subject = analysis_data.get('subject', '').lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in subject:
                risk_score += 15
                risk_factors.append(f"Suspicious keyword '{keyword}' found in subject")
                break

        # Check domain age
        domain_age = analysis_data.get('domain_age')
        if domain_age is not None:
            if domain_age < 30:
                risk_score += 20
                risk_factors.append(f"Sender domain is very new (registered {domain_age} days ago)")
            elif domain_age < DOMAIN_AGE_THRESHOLD:
                risk_score += 10
                risk_factors.append(f"Sender domain is relatively new (registered {domain_age} days ago)")
            else:
                safety_factors.append(f"Sender domain is well-established (registered {domain_age} days ago)")
        else:
            risk_factors.append("Unable to determine domain age")

        # Assess risk level and confidence
        if risk_score >= 50:
            risk_level = "High"
            confidence = min(100, risk_score)
        elif risk_score >= 30:
            risk_level = "Medium"
            confidence = min(80, risk_score)
        elif risk_score >= 10:
            risk_level = "Low"
            confidence = min(60, risk_score)
        else:
            risk_level = "Very Low"
            confidence = max(20, risk_score)

        # Determine final assessment
        if risk_level in ["High", "Medium"]:
            final_assessment = "Likely Phishing"
        elif risk_level == "Low":
            final_assessment = "Suspicious - Check with IT Team"
        else:
            final_assessment = "Likely Legitimate"

        return {
            'Risk Score': risk_score,
            'Risk Level': risk_level,
            'Risk Factors': risk_factors,
            'Safety Factors': safety_factors,
            'Confidence': confidence,
            'Final Assessment': final_assessment
        }

    def load_trusted_domains(self):
        trusted_domains = []
        try:
            with open(TRUSTED_DOMAINS_FILE, 'r') as f:
                trusted_domains = [line.strip().lower() for line in f if line.strip()]
        except FileNotFoundError:
            logging.warning(f"{TRUSTED_DOMAINS_FILE} not found. Proceeding without trusted domains list.")
        return trusted_domains

    def check_display_name_spoofing(self, display_name, email):
        email_parts = email.split('@')
        if len(email_parts) != 2:
            return False
        
        username, domain = email_parts
        display_name_parts = re.findall(r'\w+', display_name)
        
        for part in display_name_parts:
            if len(part) > 2 and part.lower() not in username.lower() and part.lower() not in domain.lower():
                return True
        return False

    def check_domain_spoofing(self, sender_domain, trusted_domains):
        for trusted_domain in trusted_domains:
            if sender_domain != trusted_domain and self.similar(sender_domain, trusted_domain) > SIMILARITY_THRESHOLD:
                return trusted_domain
        return None

    def check_unicode_spoofing(self, email):
        ascii_email = email.encode('ascii', errors='ignore').decode('ascii')
        return ascii_email != email

    def analyze_email(self, file_path):
        logging.info(f"Starting analysis of {file_path}")

        # Create a progress bar
        progress_bar = tqdm(total=100, desc="Analyzing email", unit="%")

        with open(file_path, 'rb') as file:
            eml_content = file.read()
        logging.info("Email file read successfully")
        progress_bar.update(10)

        # Decode the eml_content
        try:
            eml_content_decoded = eml_content.decode('utf-8')
        except UnicodeDecodeError:
            try:
                eml_content_decoded = eml_content.decode('iso-8859-1')
            except UnicodeDecodeError:
                logging.warning("Unable to decode email content. Proceeding with partial analysis.")
                eml_content_decoded = eml_content.decode('utf-8', errors='ignore')

        parsed_header = message_from_bytes(eml_content, policy=default)
        logging.info("Email header parsed")
        progress_bar.update(10)

        sender = parsed_header['From']
        recipient = parsed_header['To']
        subject = parsed_header['Subject']
        date = parsed_header['Date']
        message_id = parsed_header['Message-ID']
        reply_to = parsed_header['Reply-To']

        received_headers = parsed_header.get_all('Received', [])
        received_ips = parse_email_addresses(received_headers)
        logging.info("Basic email information extracted")
        progress_bar.update(10)

        analysis_data = {
            'domain_stats': {},
            'auth_results': {},
            'ip_stats': {},
            'attachments': 0,
            'urls': 0,
            'sender_email': extract_email_address(sender),
            'subject': subject,
            'display_name': sender.split('<')[0].strip() if '<' in sender else '',
            'reply_to': extract_email_address(reply_to) if reply_to else ''
        }

        # Basic Information
        logging.info("Adding basic information to results")
        basic_info = (
            f"File: {os.path.basename(file_path)}\n"
            f"Sender: {sender}\n"
            f"Recipient: {recipient}\n"
            f"Subject: {subject}\n"
            f"Date: {date}\n"
            f"Message-ID: {message_id}\n"
            f"Reply-To: {reply_to}\n"
            f"Received IPs: {', '.join(received_ips)}"
        )

        # Analyze sender domain
        domain_results = []
        if sender:
            sender_email = extract_email_address(sender)
            if sender_email:
                logging.info(f"Analyzing sender domain: {sender_email}")
                sender_domain = sender_email.split('@')[-1]
                
                # Check cache for domain results
                if sender_domain in self.api_cache.get('domain', {}):
                    domain_results = self.api_cache['domain'][sender_domain]
                    logging.info(f"Using cached results for domain: {sender_domain}")
                else:
                    domain_results = analyze_domain(sender_domain)
                    self.increment_api_call()
                    # Cache the results
                    if 'domain' not in self.api_cache:
                        self.api_cache['domain'] = {}
                    self.api_cache['domain'][sender_domain] = domain_results

                # Parse domain results to extract last_analysis_stats
                for result in domain_results:
                    if 'Last analysis stats:' in result:
                        try:
                            stats_str = result.split('Last analysis stats: ')[1]
                            analysis_data['domain_stats'] = eval(stats_str)
                        except:
                            logging.error("Failed to parse domain stats")
                            analysis_data['domain_stats'] = {}
                        break
                else:
                    analysis_data['domain_stats'] = {}

                # Extract DKIM selector from email headers
                dkim_selector = 'default'
                for header, value in parsed_header.items():
                    if header.lower() == 'dkim-signature':
                        match = re.search(r's=([^;]+)', value)
                        if match:
                            dkim_selector = match.group(1)
                            break

                # Add email authentication analysis
                logging.info("Performing email authentication analysis")
                auth_results = analyze_email_authentication(sender_domain, dkim_selector)
                analysis_data['auth_results'] = {
                    'spf': next((r for r in auth_results if 'SPF' in r), ''),
                    'dmarc': next((r for r in auth_results if 'DMARC' in r), ''),
                    'dkim': next((r for r in auth_results if 'DKIM' in r), '')
                }

                # Get domain age
                domain_age = get_domain_age(sender_domain)
                analysis_data['domain_age'] = domain_age
            else:
                logging.warning(f"Unable to extract email from sender: {sender}")

        progress_bar.update(20)  # After domain analysis

        # Analyze IP addresses
        logging.info("Analyzing IP addresses")
        ip_analysis_results = []
        for ip in received_ips:
            logging.info(f"Analyzing IP: {ip}")
            
            # Check cache for IP results
            if ip in self.api_cache.get('ip', {}):
                ip_results = self.api_cache['ip'][ip]
                logging.info(f"Using cached results for IP: {ip}")
            else:
                ip_results = analyze_ip(ip)
                self.increment_api_call()
                # Cache the results
                if 'ip' not in self.api_cache:
                    self.api_cache['ip'] = {}
                self.api_cache['ip'][ip] = ip_results

            ip_analysis_results.extend([f"Results for IP {ip}:"] + ip_results + ["\n"])

            # Parse IP results to extract last_analysis_stats
            for result in ip_results:
                if 'Last analysis stats:' in result:
                    try:
                        stats_str = result.split('Last analysis stats: ')[1]
                        analysis_data['ip_stats'] = eval(stats_str)
                    except:
                        logging.error("Failed to parse IP stats")
                        analysis_data['ip_stats'] = {}
                    break
            else:
                analysis_data['ip_stats'] = {}

        progress_bar.update(10)  # After IP analysis

        # Analyze attachments
        logging.info("Checking for attachments")
        attachments = []
        for part in parsed_header.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') is None:
                continue

            filename = part.get_filename()
            if filename:
                file_content = part.get_payload(decode=True)
                attachments.append((filename, file_content))

        attachment_analysis_results = []
        if attachments:
            logging.info(f"Found {len(attachments)} attachment(s)")
            for filename, content in attachments:
                logging.info(f"Analyzing attachment: {filename}")
                attachment_results = analyze_file(filename, content)
                self.increment_api_call()
                attachment_analysis_results.extend([f"Results for attachment {filename}:"] + attachment_results + ["\n"])

        analysis_data['attachments'] = len(attachments)

        progress_bar.update(10)  # After attachment analysis

        # Analyze URLs in the email body
        logging.info("Extracting URLs from email body")
        urls = list(set(extract_urls_from_email(eml_content)))  # Remove duplicates

        # Unshorten URLs
        logging.info("Unshortening URLs")
        unshortened_urls = unshorten_urls(urls)

        url_analysis_results = []
        if urls:
            logging.info(f"Found {len(urls)} unique URL(s)")
            for url in urls:
                logging.info(f"Scanning URL: {url}")
                vt_results = scan_url(url)
                self.increment_api_call()

                unshortened = unshortened_urls[url]
                if unshortened != url:
                    url_analysis_results.extend([
                        f"Results for URL {url}:",
                        f"Unshortened URL: {unshortened}",
                        f"VirusTotal results: {vt_results}",
                        "\n"
                    ])
                else:
                    url_analysis_results.extend([
                        f"Results for URL {url}:",
                        f"VirusTotal results: {vt_results}",
                        "\n"
                    ])

                # Check rate limit and wait if necessary
                wait_time = check_virustotal_rate_limit()
                if wait_time > 0:
                    logging.info(f"Rate limit reached. Waiting for {wait_time} seconds...")
                    time.sleep(wait_time)

        analysis_data['urls'] = len(urls)
        analysis_data['unshortened_urls'] = unshortened_urls

        progress_bar.update(20)  # After URL analysis

        logging.info("Analysis complete")
        logging.info(f"Total API calls made: {self.api_call_count}")

        # Perform risk assessment
        risk_assessment = self.assess_email_risk(analysis_data, eml_content_decoded)

        progress_bar.update(10)  # After risk assessment

        # Close the progress bar
        progress_bar.close()

        analysis_results = {
            "Basic Information": basic_info,
            "Domain Analysis": "".join(domain_results) if domain_results else "N/A",
            "Email Authentication Analysis": "\n".join(auth_results) if 'auth_results' in locals() else "N/A",
            "IP Analysis": "\n".join(ip_analysis_results) if ip_analysis_results else "N/A",
            "Attachment Analysis": "\n".join(attachment_analysis_results) if attachments else "No attachments found",
            "URL Analysis": "\n".join(url_analysis_results) if urls else "No URLs found in email body",
            "Unshortened URLs": unshortened_urls,
            "Risk Assessment": risk_assessment,
            "Analysis Summary": {
                "Total API calls": self.api_call_count,
                "Attachments analyzed": len(attachments),
                "URLs analyzed": len(urls),
                "IPs analyzed": len(received_ips)
            }
        }
        return analysis_results

def process_batch(file_paths):
    analyzer = EmailAnalyzer()
    results = []
    for file_path in tqdm(file_paths, desc="Processing emails", unit="email"):
        try:
            result = analyzer.analyze_email(file_path)
            results.append({"file": file_path, "analysis": result})
        except Exception as e:
            logging.error(f"Error processing file {file_path}: {str(e)}")
            results.append({"file": file_path, "error": str(e)})
    return results