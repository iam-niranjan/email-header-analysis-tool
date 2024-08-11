import sys
import email
from email import policy
from email.parser import BytesParser
import re
import dns.resolver
import dkim
import spf
from datetime import datetime


def analyze_email_authentication(file_path):
    with open(file_path, "rb") as f:
        email_data = f.read()
        msg = email.message_from_bytes(email_data, policy=policy.default)

    domain_name = extract_domain(msg["From"])
    auth_results = msg.get("Authentication-Results")

    spf_result = verify_spf(auth_results, msg, email_data)
    dkim_result = verify_dkim(email_data, msg.get_all("DKIM-Signature"), auth_results)
    dmarc_result = verify_dmarc(auth_results, domain_name)

    return [f"SPF: {spf_result}", f"DKIM: {dkim_result}", f"DMARC: {dmarc_result}"]


def extract_domain(email_address):
    match = re.search(r"@([\w.-]+)", email_address)
    return match.group(1) if match else None


def verify_spf(auth_results, msg, email_data):
    if auth_results:
        spf_match = re.search(
            r"spf=(pass|fail|softfail|neutral|none)", auth_results, re.IGNORECASE
        )
        if spf_match:
            return spf_match.group(1).capitalize()

    received_spf = msg.get("Received-SPF")
    if received_spf:
        spf_match = re.search(
            r"(pass|fail|softfail|neutral|none)", received_spf, re.IGNORECASE
        )
        if spf_match:
            return spf_match.group(1).capitalize()

    sender = msg.get("From")
    if sender:
        sender_domain = extract_domain(sender)
        if sender_domain:
            try:
                result, explanation = spf.check2(i="0.0.0.0", s=sender, h=sender_domain)
                return result.capitalize()
            except Exception as e:
                return f"Error: {str(e)}"

    return "None"


def verify_dkim(email_data, dkim_signatures, auth_results):
    if auth_results:
        dkim_matches = re.findall(
            r"dkim=(pass|fail|neutral|none)", auth_results, re.IGNORECASE
        )
        if dkim_matches:
            return (
                "Pass"
                if "pass" in [match.lower() for match in dkim_matches]
                else dkim_matches[0].capitalize()
            )

    if dkim_signatures:
        try:
            for signature in dkim_signatures:
                d = dkim.DKIM(email_data)
                if d.verify():
                    return "Pass"
            return "Fail"
        except Exception as e:
            return f"Error: {str(e)}"

    return "None"


def verify_dmarc(auth_results, domain):
    if auth_results:
        dmarc_match = re.search(
            r"dmarc=(pass|fail|neutral|none)", auth_results, re.IGNORECASE
        )
        if dmarc_match:
            return dmarc_match.group(1).capitalize()

    if domain:
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(dmarc_domain, "TXT")
            for rdata in answers:
                if "v=DMARC1" in rdata.to_text():
                    return "Pass"
            return "Fail"
        except dns.resolver.NXDOMAIN:
            return "Fail"
        except Exception as e:
            return f"Error: {str(e)}"
    return "None"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python email_authentication.py </path/to/email.eml>")
        sys.exit(1)

    file_path = sys.argv[1]
    results = analyze_email_authentication(file_path)
    for result in results:
        print(result)
