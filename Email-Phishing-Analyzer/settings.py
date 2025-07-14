# settings.py

# --- API Keys (Replace with your actual keys) ---
ABUSEIPDB_API_KEY = ""
VT_API_KEY = ""

# --- Scoring Thresholds for Verdict ---
# Adjusted to reflect potentially higher scores from revised weights
SCORE_THRESHOLDS = {
    'likely_safe_max': 3,     # Scores <= this are 'Likely Safe'
    'suspicious_min': 4,      # Scores >= this and < likely_phishing_min are 'Suspicious'
    'likely_phishing_min': 12 # Scores >= this are 'Likely Phishing'
}

# --- Scoring Weights (Revised) ---
HEADER_SCORING = {
    'dmarc_fail': 4,  # Increased
    'dmarc_pass_reject_quarantine': -2, # Good signal
    'dmarc_pass_none': -1,
    'dmarc_none': 2, # More significant if DMARC is missing or 'none' for important domains
    'spf_fail': 3,    # Increased
    'spf_pass': -1,
    'spf_weak': 1,    # Neutral, softfail, none
    'spf_error': 2,   # SPF configuration errors are a notable issue
    'dkim_fail': 3,   # Increased
    'dkim_pass': -1,
    'dkim_none': 1,
    'dkim_error': 2,  # DKIM configuration errors
    'from_return_path_mismatch': 3, # If domains differ significantly and not trusted
    'suspicious_reply_to': 3,       # If domains differ significantly and not trusted
    'missing_return_path': 1,
    # Custom scores for MISCELLANEOUS_HEADER_CHECKS will be defined within that dict
}

IP_SCORING = {
    'abuse_high': 5,    # High risk IP is a strong indicator
    'abuse_medium': 3,
    'abuse_low': 1,
    'api_failure': 0
}

URL_SCORING = {
    'suspicious_keyword': 1,         # Per keyword instance, but perform_url_analysis might sum these. Let's assume it's per URL.
    'suspicious_tld': 3,             # Increased
    'domain_mismatch_not_trusted': 2, # Increased
    'domain_not_trusted_sender_unknown': 1,
    'ip_in_url': 3,                  # Increased
    'punycode': 2,                   # Increased
    'url_shortener': 1,              # Can be legitimate, but also used for obfuscation
    'suspicious_path_keyword': 1,
    'too_many_subdomains': 2,        # Increased
    'too_deep_path': 1,
    'multiple_slashes_in_path': 1,
    'risky_file_extension_in_url': 3, # Increased
}

ATTACHMENT_SCORING = {
    'dangerous_type': 4, # Increased
    'vt_hit': 5,         # Increased significantly if VT flags it
}

CONTENT_SCORING = {
    'suspicious_subject_keyword': 2,
    # For categorized body keywords, scores are in SUSPICIOUS_BODY_KEYWORDS_CATEGORIZED
    'urgency_phrase': 2, # Increased
    'link_text_domain_mismatch': 3, # Increased, this is a common phishing tactic
    'sensitive_link_text_external_domain': 2, # Increased
    'suspicious_form_action': 4,   # Increased, forms submitting to odd places are very risky
    'tiny_font_text': 2,           # Increased
    'display_none_with_content': 2,# Increased
}


# --- IP Reputation ---
IP_ABUSE_THRESHOLDS = { # Confidence score from AbuseIPDB
    'low': 20,    # Lowered slightly to be more sensitive
    'medium': 50,
    'high': 80    # Increased threshold for "high" to be more certain
}

# --- URL Analysis ---
COMMON_SLDS_FOR_TLD_CHECK = {"co", "com", "org", "net", "gov", "edu", "ac", "sch", "biz", "info"} # Added biz, info

TRUSTED_DOMAINS = [
    "google.com", "youtube.com", "gmail.com", "googleusercontent.com", "goo.gl", "googlemail.com", "android.com", "googlefiber.net",
    "microsoft.com", "live.com", "outlook.com", "office.com", "windows.com", "office365.com", "skype.com", "bing.com", "msn.com",
    "apple.com", "icloud.com",
    "amazon.com", "aws.amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.jp",
    "paypal.com", "paypal-community.com",
    "facebook.com", "fb.com", "instagram.com", "whatsapp.com",
    "twitter.com", "t.co",
    "linkedin.com",
    "wordpress.org", "wordpress.com",
    "github.com", "github.io", "gitlab.com",
    "dropbox.com", "box.com", "onedrive.live.com",
    "salesforce.com", "force.com", "salesforceliveagent.com", "service-now.com",
    "wikipedia.org", "wikimedia.org",
    "godaddy.com", "namecheap.com", "cloudflare.com", "akamaihd.net", "cloudfront.net", "fastly.net",
    "stackexchange.com", "stackoverflow.com",
    "yourcompany.com", "yourorg.org" # Placeholder - replace with your actual organization's domains
]
SUSPICIOUS_URL_KEYWORDS = [
    "login", "verify", "account", "update", "secure", "support", "billing", "admin",
    "confirm", "password", "signin", "banking", "ebayisapi", "webscr", "recover",
    "unlock", "authenticate", "validate", "credential", "payment", "invoice", "refund",
    "security", "alert", "warning", "suspicious", "activity", "service", "portal",
    # Common file extensions often linked directly in phishing
    ".exe", ".zip", ".rar", ".js", ".vbs", ".docm", ".xlsm", ".pdf" # pdf can be used but also for legit docs. Context matters.
]
SUSPICIOUS_TLDS = [ # Patterns, be careful with short ones.
    ".xyz", ".top", ".info", ".biz", ".club", ".site", ".online", ".live", ".digital",
    ".link", ".click", ".download", ".loan", ".stream", ".pw", ".work", ".party", ".win",
    ".ga", ".cf", ".tk", ".ml", ".gq", # Freenom TLDs known for abuse
    ".ru", ".cn", ".br", ".in", # Countries often associated with high spam/phishing volumes
    ".cc", ".ws", ".icu", ".cam", ".fun", ".uno", ".monster", ".rest", ".beauty"
]
LEGITIMATE_HOSTS_ON_SUSPICIOUS_TLDS = [
    # "specific.trusted-site.xyz" # Example
]
COMMON_URL_SHORTENERS = [
    "bit.ly", "t.co", "tinyurl.com", "is.gd", "buff.ly", "ow.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc"
]
SUSPICIOUS_PATH_KEYWORDS = [
    "admin", "administrator", "login", "secure", "account", "update", "verify", "recovery", "reset",
    "payment", "billing", "signin", "cmd", "shell", "powershell", "download", "exec",
    "confirm", "setup", "access", "client", "portal", "manage", "user", "customer",
    ".php", ".asp", ".aspx", ".cgi", # Scripting extensions in paths can sometimes be indicative if not expected
    "includes", "libraries", "components", "modules", "plugins", # Common paths, but sometimes exploited
    "wp-admin", "wp-login", "cpanel", "webmail" # Specific application paths often targeted
]
MAX_SUBDOMAINS_IN_URL = 6 # Allowing one more than before
MAX_PATH_DEPTH_IN_URL = 8
RISKY_FILE_EXTENSIONS_IN_URLS = [
    ".exe", ".dll", ".bat", ".cmd", ".sh", ".msi", ".vbs", ".js", ".jar", ".ps1",
    ".docm", ".xlsm", ".pptm", ".hta",
    ".zip", ".rar", ".7z", ".iso", ".img", ".apk" # Archives and disk images
]

# --- Attachment Analysis ---
DANGEROUS_ATTACHMENT_TYPES = [
    ".exe", ".pif", ".application", ".gadget", ".msi", ".msp", ".com", ".scr",
    ".hta", ".cpl", ".msc", ".jar", ".bat", ".cmd", ".vb", ".vbs", ".vbe",
    ".js", ".jse", ".ws", ".wsf", ".wsc", ".wsh", ".ps1", ".ps1xml", ".ps2",
    ".ps2xml", ".psc1", ".psc2", ".scf", ".lnk", ".inf", ".reg",
    ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam", ".sldm",
    ".ade", ".adp", ".app", ".bas", ".chm", ".crt", ".der", ".hlp", ".ins",
    ".isp", ".jse", ".mst", ".ops", ".pcd", ".sct", ".shb", ".shs", ".u3p",
    ".xbap", ".html", ".htm", # HTML attachments can be malicious
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".ace", ".arj", ".cab", ".iso", ".img" # Common archive formats
]
VT_MALICIOUS_THRESHOLD = 1 # Lowered: 1 or more VT detections is now considered a hit for scoring

# --- Content Analysis ---
SUSPICIOUS_SUBJECT_KEYWORDS = [
    "urgent", "action required", "important notification", "security alert", "verify your account",
    "password reset", "account suspended", "invoice", "payment due", "confirm your details",
    "suspicious activity", "unusual sign-in", "prize", "winner", "lottery", "congratulations",
    "transaction", "shipping confirmation", "delivery status", "problem with your order",
    "final warning", "account verification", "immediate response needed", "critical update",
    "you've won", "claim your reward", "undelivered mail", "delivery failure"
]

SUSPICIOUS_BODY_KEYWORDS_CATEGORIZED = {
    "account_compromise": {
        "keywords": ["account suspended", "unusual login", "security alert", "compromised", "verify your identity", "unauthorized access", "locked account", "suspicious sign-in", "login attempt failed"],
        "score": 3 # Increased
    },
    "financial_urgency": {
        "keywords": ["payment overdue", "invoice attached", "billing error", "refund pending", "wire transfer", "urgent payment", "outstanding balance", "tax information required", "unpaid invoice"],
        "score": 3 # Increased
    },
    "credential_harvesting": {
        "keywords": ["update your details", "confirm your password", "login to view", "click here to access", "validate your information", "re-enter your credentials", "secure your account now"],
        "score": 2 # Increased
    },
    "generic_lure": {
        "keywords": ["important document", "shared file", "you have a new message", "notification", "alert", "confidential message", "secure document attached", "review required"],
        "score": 1
    },
    "scare_tactics": {
        "keywords": ["legal action", "account closure imminent", "immediate termination", "security breach detected", "your data may be at risk"],
        "score": 2
    }
}
URGENCY_PHRASES = [
    "act now", "limited time only", "expires soon", "immediate action required", "within 24 hours",
    "final notice", "don't delay", "respond immediately", "offer ends today", "last chance"
]
SUSPICIOUS_LINK_TEXT_KEYWORDS = [
    "login", "log in", "signin", "sign in", "my account", "portal", "access", "website",
    "verify", "confirm", "update", "click here", "view document", "download file", "open",
    "unsubscribe", "manage preferences", "view details", "continue", "proceed",
    # Common brand names often impersonated in link text
    "bank", "paypal", "microsoft", "google", "apple", "amazon", "dhl", "fedex", "ups", "irs", "netflix", "facebook", "instagram", "linkedin"
]
TINY_FONT_SIZE_PX_THRESHOLD = 1 # More sensitive to tiny fonts
TINY_FONT_SIZE_PT_THRESHOLD = 1
MIN_LENGTH_FOR_HIDDEN_TEXT_ALERT = 15 # Lowered

# --- Miscellaneous Header Checks ---
MISCELLANEOUS_HEADER_CHECKS = {
    'X-Mailer': {
        'contains': {
            'php': {'score': 1, 'reason': "Email sent using generic PHP mailer, could indicate scripting."},
            'outlook express': {'score': 1, 'reason': "Email sent using outdated Outlook Express, less common now."},
            # Common bulk mailers or known spam tools could be added here with higher scores
            # e.g. "SpamToolName": {'score': 3, 'reason': "Known spam tool identified in X-Mailer."}
        }
    },
    'X-Priority': {
        'contains': {
            '1': {'score': 1, 'reason': "Email marked with highest priority (X-Priority: 1)."},
            'high': {'score': 1, 'reason': "Email marked with high priority."}
        }
    },
    'X-Spam-Flag': { # Check common spam assassin flags
        'contains': {
            'YES': {'score': 4, 'reason': "Marked as SPAM by an upstream filter (X-Spam-Flag: YES)."}
        }
    },
    'X-Spam-Status': {
         'contains': { # Check if spam score is high if X-Spam-Status is available
            # This requires more complex regex to extract the score, e.g. 'score=10.5'
            # For now, a simple 'YES' check as above is more direct if X-Spam-Flag is present
            # Example for future: 'score=([5-9]|[1-9][0-9])\.': {'score': 3, 'reason': "High spam score detected in X-Spam-Status."} (regex needs testing)
        }
    },
    'List-Unsubscribe': {
        # Lack of List-Unsubscribe is more a sign of poorly managed bulk mail than direct phishing,
        # but can be an indicator if other flags are present.
        # This logic is harder to apply universally, so keeping it commented or low impact.
        # 'not_contains': {
        #     '<mailto:': {'score': 0, 'reason': "INFO: Potentially bulk email missing List-Unsubscribe header (or not using mailto)."}}
    },
    'Content-Language': {
        # Example: Flagging if language doesn't match expected for recipient, harder to generalize
    },
    'X-PHP-Originating-Script': {
        'contains': { # If this header is present, it means PHP was used, often from web servers
            '.php': {'score': 1, 'reason': "Email originated from a PHP script."}
        }
    }
}
