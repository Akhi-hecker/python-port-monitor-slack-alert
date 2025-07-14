# analyzers/url_analyzer.py
import settings
from .utils import (
    expand_url, get_registrable_domain_parts, is_related_domain, 
    is_trusted_domain, is_valid_ip, defang_ip, defang_url
)
from urllib.parse import urlparse
import re

def check_single_url_reputation(url_to_check, original_url, sender_domain, is_expanded):
    """
    Analyzes a single URL for phishing indicators.
    Returns a score delta and a list of reasons for this specific URL.
    """
    url_score = 0
    url_reasons = []

    parsed_url = urlparse(url_to_check)
    domain = parsed_url.netloc.lower().split(':')[0] # Remove port
    path = parsed_url.path.lower()
    query = parsed_url.query.lower()
    full_url_lower = url_to_check.lower()


    if not domain: # Should not happen for valid http/https URLs but check
        return 0, []

    # Get registrable domain for the current URL being checked
    _, reg_dom = get_registrable_domain_parts(domain)

    # 1. Suspicious Keywords in URL (domain, path, or query)
    for kw in settings.SUSPICIOUS_URL_KEYWORDS:
        if kw.lower() in full_url_lower:
            url_score += settings.URL_SCORING.get('suspicious_keyword', 1)
            url_reasons.append(f"URL '{defang_url(url_to_check)}' contains suspicious keyword: '{kw}'.")
            break # Only score once per URL for keywords to avoid over-penalizing

    # 2. Suspicious TLD
    if reg_dom:
        # Extract TLD part correctly (e.g. for domain.co.uk, tld is .co.uk)
        tld_parts = reg_dom.split('.')
        actual_tld = "." + ".".join(tld_parts[-(2 if len(tld_parts)>2 and tld_parts[-2] in settings.COMMON_SLDS_FOR_TLD_CHECK else 1):])

        is_legit_on_susp_tld = any(domain.endswith(lh_pattern) for lh_pattern in settings.LEGITIMATE_HOSTS_ON_SUSPICIOUS_TLDS if domain.endswith(lh_pattern))
        
        if not is_legit_on_susp_tld:
            for susp_tld in settings.SUSPICIOUS_TLDS:
                if reg_dom.endswith(susp_tld): # Check if the registrable domain ends with a suspicious TLD pattern
                    url_score += settings.URL_SCORING.get('suspicious_tld', 2)
                    url_reasons.append(f"URL domain '{reg_dom}' uses a suspicious TLD: '{susp_tld}'.")
                    break 
    
    # 3. Domain Mismatch (if sender_domain is known) and Not Trusted
    if reg_dom and '.' in reg_dom: # Ensure it's a proper domain
        if sender_domain and not is_related_domain(sender_domain, reg_dom) and not is_trusted_domain(reg_dom):
            url_score += settings.URL_SCORING.get('domain_mismatch_not_trusted', 1)
            url_reasons.append(f"URL domain '{reg_dom}' mismatches sender domain ('{sender_domain}') and is not in trusted list.")
        elif not sender_domain and not is_trusted_domain(reg_dom): # No sender domain to compare, check if URL domain is trusted
            url_score += settings.URL_SCORING.get('domain_not_trusted_sender_unknown', 1)
            url_reasons.append(f"URL domain '{reg_dom}' is not in trusted list (sender domain unknown).")

    # 4. URL uses IP Address directly
    if is_valid_ip(domain): # The domain part of URL is an IP
        url_score += settings.URL_SCORING.get('ip_in_url', 2)
        url_reasons.append(f"URL uses a direct IP address: {defang_ip(domain)}.")

    # 5. Punycode (IDN homograph attack)
    if "xn--" in domain:
        url_score += settings.URL_SCORING.get('punycode', 1)
        url_reasons.append(f"URL domain '{domain}' contains Punycode (potential IDN homograph attack).")

    # 6. URL Shortener (applied to original_url if not already expanded)
    original_domain = urlparse(original_url).netloc.lower().split(':')[0]
    if not is_expanded and any(shortener_domain in original_domain for shortener_domain in settings.COMMON_URL_SHORTENERS):
        url_score += settings.URL_SCORING.get('url_shortener', 1)
        url_reasons.append(f"URL '{defang_url(original_url)}' appears to be from a common URL shortener.")

    # 7. Suspicious Path Keywords
    for kw in settings.SUSPICIOUS_PATH_KEYWORDS:
        if kw.lower() in path:
            url_score += settings.URL_SCORING.get('suspicious_path_keyword', 1)
            url_reasons.append(f"URL path '{path}' contains suspicious keyword: '{kw}'.")
            break 

    # 8. Excessive Number of Subdomains/Parts
    # Count dots in the domain part only
    if domain.count('.') + 1 > settings.MAX_SUBDOMAINS_IN_URL: # e.g. a.b.c.example.com has 4 dots, 5 parts
        url_score += settings.URL_SCORING.get('too_many_subdomains', 1)
        url_reasons.append(f"URL domain '{domain}' has an excessive number of subdomains/parts ({domain.count('.') + 1}).")
        
    # 9. Excessive Path Depth
    path_segments = [s for s in path.split('/') if s] # Filter out empty segments
    if len(path_segments) > settings.MAX_PATH_DEPTH_IN_URL and not is_trusted_domain(reg_dom):
        url_score += settings.URL_SCORING.get('too_deep_path', 1)
        url_reasons.append(f"URL '{defang_url(url_to_check)}' has an excessive path depth ({len(path_segments)}).")
        
    # 10. Multiple Slashes in path (often obfuscation)
    if "//" in path.replace("://", ":--"): # Temporarily replace :// to not count scheme slashes
        url_score += settings.URL_SCORING.get('multiple_slashes_in_path', 1)
        url_reasons.append(f"URL path '{path}' contains multiple consecutive slashes (potential obfuscation).")

    # 11. Check for common file extensions in URL path/query that might indicate direct file download links of risky types
    for risky_ext in settings.RISKY_FILE_EXTENSIONS_IN_URLS:
        if risky_ext in path or risky_ext in query:
            url_score += settings.URL_SCORING.get('risky_file_extension_in_url', 2)
            url_reasons.append(f"URL '{defang_url(url_to_check)}' contains a risky file extension '{risky_ext}'.")
            break # Score once per URL

    return url_score, list(set(url_reasons)) # Return unique reasons

def perform_url_analysis(analysis_results, extracted_urls_raw, sender_domain):
    """
    Analyzes all extracted URLs from the email.
    Modifies analysis_results with score, reasons, and url_analysis list.
    """
    if not extracted_urls_raw:
        analysis_results['url_analysis'] = []
        return

    processed_urls_info = []
    total_url_score_delta = 0

    for original_url_str in extracted_urls_raw:
        if not original_url_str or not isinstance(original_url_str, str): # Skip if None or not a string
            continue

        expanded_url_str = expand_url(original_url_str.strip()) # Ensure leading/trailing whitespace is removed
        is_expanded_flag = original_url_str.strip().lower().rstrip('/') != expanded_url_str.lower().rstrip('/')
        
        current_url_to_analyze = expanded_url_str if expanded_url_str else original_url_str.strip()
        if not current_url_to_analyze: # If somehow still empty, skip
            continue

        url_score_impact, url_reasons_list = check_single_url_reputation(
            current_url_to_analyze, 
            original_url_str.strip(), 
            sender_domain, 
            is_expanded_flag
        )
        
        if url_score_impact > 0:
            total_url_score_delta += url_score_impact
            analysis_results['reasons'].extend(url_reasons_list) # Add specific reasons to main list

        processed_urls_info.append({
            'original': original_url_str.strip(),
            'expanded': current_url_to_analyze, # Use the one that was analyzed
            'was_expanded': is_expanded_flag,
            'score_impact': url_score_impact,
            'reasons': url_reasons_list
        })

    analysis_results['score'] += total_url_score_delta
    analysis_results['url_analysis'] = processed_urls_info