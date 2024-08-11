from utils import check_virustotal_rate_limit, VIRUSTOTAL_API_KEY
import requests
import whois
from datetime import datetime, timezone


def analyze_domain(domain):
    results = []

    # VirusTotal domain analysis
    vt_domain_info = get_virustotal_domain_info(domain)
    if vt_domain_info:
        results.append(f"VirusTotal results for domain {domain}:")

        # Convert creation date to human-readable format
        creation_date = vt_domain_info["creation_date"]
        if creation_date:
            readable_date = datetime.utcfromtimestamp(creation_date).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )
            results.append(f"  Creation Date: {readable_date}")
        else:
            results.append("  Creation Date: Unknown")

        results.append(f"  Reputation: {vt_domain_info['reputation']}")

        # Format last analysis stats
        stats = vt_domain_info["last_analysis_stats"]
        results.append("  Last analysis stats:")
        for key, value in stats.items():
            results.append(f"    {key.capitalize()}: {value}")

        # Format tags
        tags = vt_domain_info["tags"]
        if tags:
            results.append(f"  Tags: {', '.join(tags)}")
        else:
            results.append("  Tags: None")

        # Format categories
        categories = vt_domain_info["categories"]
        if categories:
            results.append("  Categories:")
            for provider, category in categories.items():
                results.append(f"    {provider}: {category}")
        else:
            results.append("  Categories: None")
    else:
        results.append(f"Unable to retrieve VirusTotal results for domain {domain}")

    # Get domain age
    domain_age = get_domain_age(domain)
    if domain_age is not None:
        results.append(f"Domain age: {domain_age} days")
    else:
        results.append("Unable to determine domain age")

    return "\n".join(results)


def get_virustotal_domain_info(domain):
    check_virustotal_rate_limit()

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            result = response.json()
            data = result["data"]["attributes"]
            return {
                "creation_date": data.get("creation_date"),
                "reputation": data.get("reputation"),
                "last_analysis_stats": data.get("last_analysis_stats"),
                "tags": data.get("tags", []),
                "categories": data.get("categories", {}),
            }
        else:
            print(
                f"Error checking VirusTotal for domain {domain}: {response.status_code}"
            )
            return None
    except Exception as e:
        print(f"Error checking VirusTotal for domain {domain}: {str(e)}")
        return None


def get_domain_age(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        # Handle cases where creation_date is a list or a single value
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        # Check if creation_date is already a datetime object
        if isinstance(creation_date, datetime):
            age = (
                datetime.now(timezone.utc) - creation_date.replace(tzinfo=timezone.utc)
            ).days
        elif isinstance(creation_date, (int, float)):
            # Assume it's a Unix timestamp
            creation_datetime = datetime.fromtimestamp(creation_date, tz=timezone.utc)
            age = (datetime.now(timezone.utc) - creation_datetime).days
        else:
            print(f"Unexpected creation_date format: {type(creation_date)}")
            return None

        return age
    except Exception as e:
        print(f"Error getting domain age: {str(e)}")
        return None
