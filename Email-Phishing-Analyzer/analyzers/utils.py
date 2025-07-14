# analyzers/utils.py
import re
import hashlib
import ipaddress
import requests
from urllib.parse import urlparse, unquote
from bs4 import BeautifulSoup
import email.utils # For parseaddr in from_header parsing if needed elsewhere
import settings # For TRUSTED_DOMAINS etc. if used directly by utils

# --- Utility Functions from original phishing_analyzer.py ---

def defang_ip(ip_address):
    return str(ip_address).replace('.', '[.]') if ip_address else ""

def defang_url(url_string):
    return str(url_string).replace('http://', 'hxxp[://]').replace('https://', 'hxxps[://]').replace('.', '[.]') if url_string else ""

def is_valid_ip(ip_str):
    try:
        ip_obj = ipaddress.ip_address(str(ip_str))
        return ip_obj.is_global and not ip_obj.is_multicast and not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_link_local and not ip_obj.is_reserved
    except ValueError:
        return False

def get_registrable_domain_parts(domain_name_input):
    if not domain_name_input: return "", ""
    domain_name = str(domain_name_input).lower().strip()
    if "://" in domain_name:
        parsed_url_for_domain = urlparse(domain_name)
        domain_name = parsed_url_for_domain.netloc if parsed_url_for_domain.netloc else domain_name
    
    # Remove port number if present
    domain_name = domain_name.split(':')[0]

    parts = [part for part in domain_name.split('.') if part]
    if not parts: return "", ""
    if len(parts) == 1: return parts[0], parts[0] # Handle single-label domains e.g. 'localhost'

    # Simplified TLD/SLD checking - for a robust solution, a library like 'tldextract' is better
    # This is a basic heuristic
    common_slds = {"co", "com", "org", "net", "gov", "edu", "ac", "ltd", "plc", "me", "biz", "info", "name", "sch", "nom", "info"}
    # Common ccTLDs that might look like gTLDs or are often part of second-level registrations
    known_pseudo_gtlds_or_cctlds = {"uk", "au", "ca", "de", "jp", "us", "in", "nz", "za", "fr", "eu", "cn", "ru", "br", "it", "es", "nl", "ch", "se", "no", "fi", "dk", "pl", "at", "be"}

    if len(parts) > 2 and parts[-2] in common_slds and (len(parts[-1]) == 2 or parts[-1] in known_pseudo_gtlds_or_cctlds) :
        # e.g. domain.co.uk -> (domain, domain.co.uk)
        # e.g. domain.com.au -> (domain, domain.com.au)
        return parts[-3], ".".join(parts[-3:])
    
    # e.g. domain.com -> (domain, domain.com)
    # e.g. domain.co -> (domain, domain.co) (assuming 'co' can be a TLD here by itself)
    return parts[-2], ".".join(parts[-2:]) if len(parts) >= 2 else (parts[0], parts[0])


def is_related_domain(domain1_input, domain2_input):
    if not domain1_input or not domain2_input: return False
    _, registrable1 = get_registrable_domain_parts(str(domain1_input))
    _, registrable2 = get_registrable_domain_parts(str(domain2_input))
    return bool(registrable1 and registrable1 == registrable2)

def is_trusted_domain(domain_to_check_input):
    if not domain_to_check_input: return False
    _, registrable_to_check = get_registrable_domain_parts(str(domain_to_check_input))
    if not registrable_to_check or '.' not in registrable_to_check: return False # Must be at least like example.com
    
    for trusted_pattern_item in settings.TRUSTED_DOMAINS:
        # Assuming TRUSTED_DOMAINS contains registrable domains or patterns that get_registrable_domain_parts can handle
        _, registrable_trusted = get_registrable_domain_parts(str(trusted_pattern_item))
        if registrable_to_check == registrable_trusted:
            return True
    return False

def extract_ips_from_text(text_input):
    return set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', str(text_input))) if text_input else set()

def extract_urls_from_text(text_input):
    # Improved regex to capture more URL variations and avoid trailing punctuation issues.
    # Handles http, https, ftp, and common www. patterns without a scheme.
    # It's complex to cover all edge cases perfectly with regex alone.
    url_pattern = r"""
        (?:(?:https?|ftp)://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/) # Scheme or www. or domain/
        (?:[^\s()<>"]+|\(([^\s()<>"]+|(\([^\s()<>"]+\)))*\))+ # URL path and query, allows for balanced parentheses
        (?:\(([^\s()<>"]+|(\([^\s()<>"]+\)))*\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]) # Exclude trailing punctuation
    """
    return set(re.findall(url_pattern, str(text_input), re.VERBOSE | re.IGNORECASE)) if text_input else set()


def extract_text_from_html(html_payload_input):
    if not html_payload_input: return ""
    try:
        soup = BeautifulSoup(str(html_payload_input), 'html.parser')
        for element in soup(["script", "style", "head", "title", "meta", "[document]"]):
            element.decompose()
        
        text = soup.get_text(separator=' ', strip=True)
        # Further unquote HTML entities that might remain if BeautifulSoup didn't handle all.
        # This is generally handled well by get_text, but unquote can catch others.
        try:
            text = unquote(text)
        except Exception:
            pass # unquote might fail on complex strings, proceed with BS text
        return text
    except Exception as e:
        print(f"Error extracting text from HTML: {e}")
        return ""

def expand_url(url_in, timeout=5):
    if not url_in: return url_in # Return original if None or empty
    url = str(url_in)
    try:
        # Ensure the URL has a scheme, default to http if missing for requests library
        req_url = url
        if not url.lower().startswith(('http://', 'https://', 'ftp://')):
            req_url = 'http://' + url

        # Use a common user-agent
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 PhishingAnalyzer/1.0'}
        
        response = requests.head(req_url, allow_redirects=True, timeout=timeout, headers=headers)
        return response.url # This will be the final URL after all redirects
    except requests.exceptions.RequestException:
        # If any request error (timeout, connection error, too many redirects, etc.), return the original URL
        return url
    except Exception:
        # Catch any other unexpected error
        return url

def virustotal_file_check(file_hash, vt_api_key):
    if not vt_api_key or vt_api_key == "YOUR_VIRUSTOTAL_API_KEY" or not file_hash:
        return 0 # Return 0 if no key or hash
    
    url = f"https://www.virustotal.com/api/v3/files/{str(file_hash)}"
    headers = {"x-apikey": vt_api_key}
    
    try:
        response = requests.get(url, headers=headers, timeout=10) # 10 seconds timeout
        if response.status_code == 200:
            json_response = response.json()
            # Navigate safely through the JSON structure
            malicious_count = json_response.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
            return malicious_count
        elif response.status_code == 404: # Hash not found on VT
            return 0
        else:
            # Log other errors if needed, e.g., print(f"VT API Error {response.status_code}: {response.text}")
            return 0 # Treat other errors as non-malicious for scoring to avoid false positives from API issues
    except requests.exceptions.RequestException as e:
        # print(f"VirusTotal request failed: {e}")
        return 0 # Network or request error
    except Exception as e:
        # print(f"Error processing VirusTotal response: {e}")
        return 0 # Other errors like JSON parsing

def abuseipdb_check(ip_address, abuse_api_key):
    if not abuse_api_key or abuse_api_key == "YOUR_ABUSEIPDB_API_KEY" or not ip_address:
        return None # Return None if no key or IP

    url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        'ipAddress': str(ip_address),
        'maxAgeInDays': '90', # Look back 90 days
        'verbose': '' # Include extra information like country, ISP
    }
    headers = {
        'Accept': 'application/json',
        'Key': abuse_api_key
    }

    try:
        response = requests.get(url, params=params, headers=headers, timeout=10) # 10 seconds timeout
        if response.status_code == 200:
            data = response.json().get('data', {})
            # Ensure all expected keys are present with defaults
            return {
                'abuse_score': data.get('abuseConfidenceScore', 0),
                'total_reports': data.get('totalReports', 0),
                'country': data.get('countryCode', 'N/A'),
                'isp': data.get('isp', 'N/A'),
                'domain': data.get('domain', 'N/A') # Associated domain if reported
            }
        else:
            # Log other errors: print(f"AbuseIPDB API Error {response.status_code}: {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        # print(f"AbuseIPDB request failed: {e}")
        return None
    except Exception as e:
        # print(f"Error processing AbuseIPDB response: {e}")
        return None

def ip_info_lookup(ip_address, timeout=5):
    if not ip_address or not is_valid_ip(ip_address): # Also validate IP here
        return None
    
    try:
        # Using a common user-agent
        headers = {'User-Agent': 'Mozilla/5.0 PhishingAnalyzer/1.0'}
        response = requests.get(f"https://ipinfo.io/{str(ip_address)}/json", timeout=timeout, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return {
                'city': data.get('city', 'N/A'),
                'region': data.get('region', 'N/A'),
                'country': data.get('country', 'N/A'),
                'isp': data.get('org', 'N/A'), # 'org' usually contains ISP info
                'hostname': data.get('hostname', 'N/A')
            }
        else:
            return None
    except requests.exceptions.RequestException:
        return None
    except Exception:
        return None