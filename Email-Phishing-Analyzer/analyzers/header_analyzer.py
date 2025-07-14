# analyzers/header_analyzer.py
import settings
from .utils import get_registrable_domain_parts, is_related_domain, is_trusted_domain
import email.utils # For parsing Reply-To

def perform_header_analysis(analysis_results, headers_dict, sender_domain, parsed_from_email):
    """
    Analyzes email headers for phishing indicators.
    Modifies analysis_results with score and reasons.
    """
    auth_val = (
        str(headers_dict.get("Authentication-Results", "")) or
        str(headers_dict.get("X-Authentication-Results", "")) or # Common alternative
        str(headers_dict.get("ARC-Authentication-Results", "")) # For forwarded mail chains
    ).lower()
    
    score_delta = 0
    reasons = []

    # DMARC Analysis
    if "dmarc=fail" in auth_val:
        score_delta += settings.HEADER_SCORING.get('dmarc_fail', 3)
        reasons.append("DMARC verification failed.")
    elif "dmarc=pass" in auth_val:
        # Check DMARC policy (p=reject or p=quarantine are stronger)
        if "p=reject" in auth_val or "p=quarantine" in auth_val:
            score_delta += settings.HEADER_SCORING.get('dmarc_pass_reject_quarantine', -3)
        else: # p=none or no explicit policy mentioned alongside pass
            score_delta += settings.HEADER_SCORING.get('dmarc_pass_none', -1)
    elif "dmarc=none" in auth_val or ("dmarc=" not in auth_val and "dmarc" in auth_val): # Covers cases where DMARC record exists but is 'none' or header is present but no clear pass/fail
        score_delta += settings.HEADER_SCORING.get('dmarc_none', 1)
        reasons.append("DMARC policy is 'none', not configured, or result unclear.")

    # SPF Analysis
    if "spf=fail" in auth_val:
        score_delta += settings.HEADER_SCORING.get('spf_fail', 2)
        reasons.append("SPF verification failed.")
    elif "spf=pass" in auth_val:
        score_delta += settings.HEADER_SCORING.get('spf_pass', -1)
    elif "spf=neutral" in auth_val or "spf=softfail" in auth_val or "spf=none" in auth_val or \
         ("spf=pass" not in auth_val and "spf=" in auth_val and "permerror" not in auth_val and "temperror" not in auth_val): # Covers neutral, softfail, none, or unclear SPF results
        score_delta += settings.HEADER_SCORING.get('spf_weak', 1)
        reasons.append("SPF result is weak (neutral, softfail, none) or unclear.")
    elif "spf=permerror" in auth_val or "spf=temperror" in auth_val:
        score_delta += settings.HEADER_SCORING.get('spf_error', 1) # SPF configuration error
        reasons.append("SPF record has a permanent or temporary error.")


    # DKIM Analysis
    if "dkim=fail" in auth_val:
        score_delta += settings.HEADER_SCORING.get('dkim_fail', 2)
        reasons.append("DKIM signature verification failed.")
    elif "dkim=pass" in auth_val:
        score_delta += settings.HEADER_SCORING.get('dkim_pass', -1)
    elif "dkim=none" in auth_val or \
         ("dkim=pass" not in auth_val and "dkim=" in auth_val and "permerror" not in auth_val and "temperror" not in auth_val): # DKIM not present or not configured
        score_delta += settings.HEADER_SCORING.get('dkim_none', 1)
        reasons.append("DKIM signature missing, not configured, or result unclear.")
    elif "dkim=permerror" in auth_val or "dkim=temperror" in auth_val:
        score_delta += settings.HEADER_SCORING.get('dkim_error', 1) # DKIM configuration error
        reasons.append("DKIM check resulted in a permanent or temporary error.")


    # Return-Path vs From
    return_path_header = str(headers_dict.get("Return-Path", "")).strip()
    # Return-Path is often enclosed in <>, sometimes not.
    return_path_email = return_path_header.strip('<>').lower() if return_path_header else ""

    if return_path_email:
        if parsed_from_email and return_path_email != parsed_from_email:
            reasons.append(f"INFO: Return-Path address ({return_path_email}) differs from From address ({parsed_from_email}). This can be legitimate for mailing lists.")
        
        if sender_domain: # sender_domain is the registrable domain of the 'From' address
            rp_domain_part = return_path_email.split('@')[-1] if '@' in return_path_email else return_path_email
            _, return_path_registrable_domain = get_registrable_domain_parts(rp_domain_part)
            
            if return_path_registrable_domain and not is_related_domain(sender_domain, return_path_registrable_domain) and \
               not is_trusted_domain(return_path_registrable_domain):
                score_delta += settings.HEADER_SCORING.get('from_return_path_mismatch', 2)
                reasons.append(f"SCORE: From domain ('{sender_domain}') and Return-Path domain ('{return_path_registrable_domain}') are different and not trusted/related.")
    else:
        score_delta += settings.HEADER_SCORING.get('missing_return_path', 1) # Missing Return-Path can be suspicious
        reasons.append("WARNING: Return-Path header is missing.")

    # Reply-To vs From
    reply_to_header_val = str(headers_dict.get("Reply-To", ""))
    if reply_to_header_val:
        _, reply_to_email_parsed = email.utils.parseaddr(reply_to_header_val) # parseaddr gets the bare email
        reply_to_email_parsed = reply_to_email_parsed.lower()

        if reply_to_email_parsed:
            if parsed_from_email and reply_to_email_parsed != parsed_from_email:
                reasons.append(f"INFO: Reply-To address ({reply_to_email_parsed}) differs from From address ({parsed_from_email}).")

            if sender_domain: # sender_domain is the registrable domain of the 'From' address
                rt_domain_part = reply_to_email_parsed.split('@')[-1] if '@' in reply_to_email_parsed else reply_to_email_parsed
                _, reply_to_registrable_domain = get_registrable_domain_parts(rt_domain_part)

                if reply_to_registrable_domain and not is_related_domain(sender_domain, reply_to_registrable_domain) and \
                   not is_trusted_domain(reply_to_registrable_domain):
                    score_delta += settings.HEADER_SCORING.get('suspicious_reply_to', 2)
                    reasons.append(f"SCORE: From domain ('{sender_domain}') and Reply-To domain ('{reply_to_registrable_domain}') are different and not trusted/related.")
    
    # Add other header checks from settings.MISCELLANEOUS_HEADER_CHECKS if defined
    for header_name, checks in settings.MISCELLANEOUS_HEADER_CHECKS.items():
        header_value = str(headers_dict.get(header_name, "")).lower()
        if header_value: # Only check if header exists
            for check_type, patterns_scores in checks.items():
                for pattern, score_value_reason in patterns_scores.items():
                    score_value = score_value_reason['score']
                    reason_text = score_value_reason['reason']
                    
                    is_match = False
                    if check_type == "contains":
                        is_match = pattern.lower() in header_value
                    elif check_type == "not_contains":
                        is_match = pattern.lower() not in header_value
                    elif check_type == "matches_regex":
                        try:
                            if re.search(pattern, header_value, re.IGNORECASE):
                                is_match = True
                        except re.error:
                            reasons.append(f"CONFIG_ERROR: Invalid regex in MISCELLANEOUS_HEADER_CHECKS for {header_name}: {pattern}")
                    
                    if is_match:
                        score_delta += score_value
                        reasons.append(f"{reason_text} (Header: {header_name})")


    analysis_results['score'] += score_delta
    analysis_results['reasons'].extend(reasons)