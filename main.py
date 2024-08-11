import os
import time
import logging
import argparse
from email import message_from_bytes
from email.policy import default
from config import *
from tqdm import tqdm
from abuseipdb import check_ip_abuseipdb
from alienvault_otx import check_ip_alienvault, check_url_alienvault
from urlscan_io import scan_url_urlscan
from virustotal_analysis import scan_url
from utils import extract_urls_from_email, extract_email_address, parse_email_addresses
from url_unshortener import unshorten_urls
from email_authentication import analyze_email_authentication
from domain_analysis import analyze_domain, get_domain_age
from malware_analysis import analyze_file

# Setup logging
logging.basicConfig(
    filename=LOG_FILE,
    level=LOG_LEVEL,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

class EmailAnalyzer:
    def __init__(self):
        self.api_call_count = 0
        self.api_cache = {}

    def increment_api_call(self):
        self.api_call_count += 1
        logging.info(f"API call count: {self.api_call_count}")

    def analyze_email(self, file_path):
        logging.info(f"Starting analysis of {file_path}")
        progress_bar = tqdm(total=100, desc="Analyzing email", unit="%")
        with open(file_path, "rb") as file:
            eml_content = file.read()
        logging.info("Email file read successfully")
        progress_bar.update(10)
        parsed_header = message_from_bytes(eml_content, policy=default)
        logging.info("Email header parsed")
        progress_bar.update(10)
        sender = parsed_header["From"]
        recipient = parsed_header["To"]
        subject = parsed_header["Subject"]
        date = parsed_header["Date"]
        message_id = parsed_header["Message-ID"]
        reply_to = parsed_header["Reply-To"]
        received_headers = parsed_header.get_all("Received", [])
        received_ips = parse_email_addresses(received_headers)
        logging.info("Basic email information extracted")
        progress_bar.update(10)
        analysis_data = {
            "domain_stats": {},
            "auth_results": [],
            "ip_stats": {},
            "attachments": 0,
            "urls": 0,
            "sender_email": extract_email_address(sender),
            "subject": subject,
            "display_name": sender.split("<")[0].strip() if "<" in sender else "",
            "reply_to": extract_email_address(reply_to) if reply_to else "",
        }
        # Basic Information
        basic_info = {
            "File": os.path.basename(file_path),
            "Sender": sender,
            "Recipient": recipient,
            "Subject": subject,
            "Date": date,
            "Message-ID": message_id,
            "Reply-To": reply_to,
            "Received IPs": ", ".join(received_ips),
        }
        # Analyze sender domain
        domain_results = {}
        if sender:
            sender_email = extract_email_address(sender)
            if sender_email:
                sender_domain = sender_email.split("@")[-1]
                logging.info(f"Analyzing sender domain: {sender_domain}")
                domain_results = self.analyze_domain(sender_domain)
                self.increment_api_call()
                # Add email authentication analysis
                auth_results = analyze_email_authentication(file_path)
                analysis_data["auth_results"] = {
                    "spf": next(
                        (r.split(": ")[1]
                         for r in auth_results if r.startswith("SPF")),
                        "None",
                    ),
                    "dkim": next(
                        (
                            r.split(": ")[1]
                            for r in auth_results
                            if r.startswith("DKIM")
                        ),
                        "None",
                    ),
                    "dmarc": next(
                        (
                            r.split(": ")[1]
                            for r in auth_results
                            if r.startswith("DMARC")
                        ),
                        "None",
                    ),
                }
                # Get domain age
                domain_age = get_domain_age(sender_domain)
                analysis_data["domain_age"] = domain_age
        progress_bar.update(20)
        # Analyze IP addresses
        ip_analysis_results = {}
        for ip in received_ips:
            logging.info(f"Analyzing IP: {ip}")
            ip_results = self.analyze_ip(ip)
            ip_analysis_results[ip] = ip_results
        analysis_data["ip_stats"] = ip_analysis_results
        progress_bar.update(10)
        # Analyze attachments
        attachments = []
        for part in parsed_header.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get("Content-Disposition") is None:
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
                attachment_analysis_results.append(
                    {"filename": filename, "analysis": attachment_results}
                )
        analysis_data["attachments"] = len(attachments)
        progress_bar.update(10)
        # Analyze URLs in the email body
        urls = list(set(extract_urls_from_email(eml_content)))
        unshortened_urls = unshorten_urls(urls)
        url_analysis_results = []
        if urls:
            logging.info(f"Found {len(urls)} unique URL(s)")
            for url in urls:
                logging.info(f"Scanning URL: {url}")
                url_results = self.analyze_url(
                    url, unshortened_urls.get(url, url))
                url_analysis_results.append(url_results)
        analysis_data["urls"] = len(urls)
        analysis_data["url_analysis"] = url_analysis_results
        progress_bar.update(20)
        logging.info("Analysis complete")
        logging.info(f"Total API calls made: {self.api_call_count}")
        # Perform risk assessment
        risk_assessment = self.assess_email_risk(analysis_data)
        progress_bar.update(10)
        progress_bar.close()
        analysis_results = {
            "Basic Information": basic_info,
            "Domain Analysis": domain_results,
            "Email Authentication Analysis": auth_results,
            "IP Analysis": ip_analysis_results,
            "Attachment Analysis": attachment_analysis_results,
            "URL Analysis": url_analysis_results,
            "Risk Assessment": risk_assessment,
            "Analysis Summary": {
                "Total API calls": self.api_call_count,
                "Attachments analyzed": len(attachments),
                "URLs analyzed": len(urls),
                "IPs analyzed": len(received_ips),
            },
        }
        return analysis_results

    def analyze_domain(self, domain):
        return analyze_domain(domain)

    def analyze_ip(self, ip):
        abuseipdb_result = check_ip_abuseipdb(ip)
        alienvault_result = check_ip_alienvault(ip)
        return {"abuseipdb": abuseipdb_result, "alienvault": alienvault_result}

    def analyze_url(self, original_url, unshortened_url):
        urlscan_result = scan_url_urlscan(unshortened_url)
        alienvault_result = check_url_alienvault(unshortened_url)
        virustotal_result = scan_url(unshortened_url)
        return {
            "original_url": original_url,
            "unshortened_url": unshortened_url,
            "urlscan": urlscan_result,
            "alienvault": alienvault_result,
            "virustotal": virustotal_result,
        }

    def assess_email_risk(self, analysis_data):
        risk_score = 0
        risk_factors = []
        safety_factors = []
        # Domain analysis
        if analysis_data["domain_stats"].get("malicious", 0) > 0:
            risk_score += 30
            risk_factors.append("Domain flagged as malicious by VirusTotal")
        else:
            safety_factors.append(
                "Domain not flagged as malicious by VirusTotal")
        # Email authentication
        auth_results = analysis_data["auth_results"]
        if auth_results["spf"] == "Pass":
            safety_factors.append("SPF check passed")
        else:
            risk_score += 20
            risk_factors.append(
                f"SPF check failed or inconclusive: {auth_results['spf']}"
            )
        if auth_results["dkim"] == "Pass":
            safety_factors.append("DKIM check passed")
        else:
            risk_score += 20
            risk_factors.append(
                f"DKIM check failed or inconclusive: {auth_results['dkim']}"
            )
        if auth_results["dmarc"] == "Pass":
            safety_factors.append("DMARC check passed")
        else:
            risk_score += 20
            risk_factors.append(
                f"DMARC check failed or inconclusive: {auth_results['dmarc']}"
            )
        # IP analysis
        for ip, ip_data in analysis_data["ip_stats"].items():
            if ip_data["abuseipdb"].get("abuse_confidence_score", 0) > 50:
                risk_score += 25
                risk_factors.append(f"IP {ip} has high abuse confidence score")
            else:
                safety_factors.append(f"IP {ip} not flagged as malicious")
        # URL analysis
        for url_data in analysis_data["url_analysis"]:
            if url_data["virustotal"].get("malicious", 0) > 0:
                risk_score += 15
                risk_factors.append(
                    f"Malicious URL detected: {url_data['original_url']}"
                )
        # Domain age
        domain_age = analysis_data.get("domain_age")
        if domain_age:
            if domain_age > 365:
                safety_factors.append(
                    f"Domain is well-established (age: {domain_age} days)"
                )
            elif domain_age < 30:
                risk_score += 20
                risk_factors.append(
                    f"Domain is very new (age: {domain_age} days)")
        # Determine risk level and confidence
        if risk_score >= 50:
            risk_level = "High"
            confidence = min(100, risk_score)
        elif risk_score >= 30:
            risk_level = "Medium"
            confidence = min(80, risk_score)
        else:
            risk_level = "Low"
            confidence = max(60, 100 - risk_score)
        # Determine final assessment
        if risk_level == "High":
            final_assessment = "Likely Phishing"
        elif risk_level == "Medium":
            final_assessment = "Suspicious - Proceed with Caution"
        else:
            final_assessment = "Likely Legitimate"
        return {
            "Risk Score": risk_score,
            "Risk Level": risk_level,
            "Risk Factors": risk_factors,
            "Safety Factors": safety_factors,
            "Confidence": confidence,
            "Final Assessment": final_assessment,
        }

    @staticmethod
    def print_section(title, content):
        print(f"\n{'-' * len(title)}")
        print(title)
        print(f"{'-' * len(title)}")
        if isinstance(content, dict):
            for key, value in content.items():
                print(f"{key}: {value}")
        elif isinstance(content, list):
            for item in content:
                print(item)
        else:
            print(content)

    @staticmethod
    def print_analysis_results(results):
        for result in results:
            print(f"\nAnalysis Results for: {result['file']}")
            print("=" * 40)
            analysis = result["analysis"]
            EmailAnalyzer.print_section("Basic Information", analysis["Basic Information"])
            EmailAnalyzer.print_section("Domain Analysis", analysis["Domain Analysis"])
            EmailAnalyzer.print_section(
                "Email Authentication Analysis",
                analysis["Email Authentication Analysis"],
            )
            EmailAnalyzer.print_section("IP Analysis", "")
            for ip, ip_data in analysis["IP Analysis"].items():
                print(f"IP: {ip}")
                print("  AbuseIPDB:")
                for key, value in ip_data["abuseipdb"].items():
                    print(f"    {key}: {value}")
                print("  AlienVault OTX:")
                for key, value in ip_data["alienvault"].items():
                    print(f"    {key}: {value}")
                print()
            if analysis["Attachment Analysis"]:
                EmailAnalyzer.print_section("Attachment Analysis", "")
                for attachment in analysis["Attachment Analysis"]:
                    print(f"Filename: {attachment['filename']}")
                    for key, value in attachment["analysis"].items():
                        print(f"  {key}: {value}")
                    print()
            else:
                EmailAnalyzer.print_section("Attachment Analysis", "No attachments found")
            EmailAnalyzer.print_section("URL Analysis", "")
            for url_data in analysis["URL Analysis"]:
                print(f"Original URL: {url_data['original_url']}")
                print(f"Unshortened URL: {url_data['unshortened_url']}")
                print("URLScan.io Results:")
                for key, value in url_data["urlscan"].items():
                    print(f"  {key}: {value}")
                print("AlienVault OTX Results:")
                for key, value in url_data["alienvault"].items():
                    print(f"  {key}: {value}")
                print("VirusTotal Results:")
                for key, value in url_data["virustotal"].items():
                    print(f"  {key}: {value}")
                print()
            EmailAnalyzer.print_section("Risk Assessment", "")
            risk = analysis["Risk Assessment"]
            print(f"Risk Score: {risk['Risk Score']}")
            print(f"Risk Level: {risk['Risk Level']}")
            print(f"Confidence: {risk['Confidence']}%")
            print(f"Final Assessment: {risk['Final Assessment']}")
            print("Risk Factors:")
            for factor in risk["Risk Factors"]:
                print(f"  - {factor}")
            print("Safety Factors:")
            for factor in risk["Safety Factors"]:
                print(f"  - {factor}")
            EmailAnalyzer.print_section("Analysis Summary", analysis["Analysis Summary"])

    @staticmethod
    def main():
        parser = argparse.ArgumentParser(
            description="Analyze email headers from EML files."
        )
        parser.add_argument(
            "eml_files", nargs="+", help="Path to the EML file(s) to analyze"
        )
        parser.add_argument(
            "--output", help="Path to save the analysis results (text format)"
        )
        args = parser.parse_args()
        analyzer = EmailAnalyzer()
        results = []
        for eml_file in args.eml_files:
            if not os.path.exists(eml_file):
                print(f"Error: File '{eml_file}' not found.")
                continue
            result = analyzer.analyze_email(eml_file)
            results.append({"file": eml_file, "analysis": result})
        if args.output:
            with open(args.output, "w") as f:
                EmailAnalyzer.print_analysis_results(results, file=f)
            print(f"Analysis results saved to {args.output}")
        else:
            EmailAnalyzer.print_analysis_results(results)

if __name__ == "__main__":
    EmailAnalyzer.main()