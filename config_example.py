import os

# API Keys
ABUSEIPDB_API_KEY = "your_abuseipdb_api_key"
ALIENVAULT_OTX_API_KEY = "your_alienvault_otx_api_key"
URLSCAN_IO_API_KEY = "your_urlscan_io_api_key"
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"

# API Limits
VT_REQUEST_LIMIT = 4  # requests per minute
VT_DAILY_LIMIT = 500  # requests per day

# File Paths
TRUSTED_DOMAINS_FILE = 'trusted_domains.txt'

# Logging
LOG_FILE = 'email_analysis.log'
LOG_LEVEL = 'INFO'

# Thresholds
DOMAIN_AGE_THRESHOLD = 180  # days
SIMILARITY_THRESHOLD = 0.8  # for domain spoofing detection

# Suspicious Keywords
SUSPICIOUS_KEYWORDS = [
    "urgent", "action required", "account suspended", 
    "verify your account", "login attempt", "unusual activity",
    "password expired", "security alert", "payment overdue"
]

# Project root directory
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

# Risk score thresholds
HIGH_RISK_THRESHOLD = 50
MEDIUM_RISK_THRESHOLD = 30
LOW_RISK_THRESHOLD = 10

# API cache settings
API_CACHE_EXPIRY = 3600  # seconds (1 hour)

# URL analysis
MAX_REDIRECT_DEPTH = 5  # maximum number of redirects to follow when unshortening URLs

# Attachment analysis
MAX_ATTACHMENT_SIZE = 5 * 1024 * 1024  # 5 MB, maximum size of attachment to analyze
