# analyzers/content_analyzer.py
import settings
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from .utils import get_registrable_domain_parts, is_related_domain, is_trusted_domain, defang_url
import re

def analyze_html_specifics(analysis_results, html_body, sender_domain, analyzed_urls_details):
    """
    Analyzes specific HTML content like links and forms.
    Modifies analysis_results with score and reasons.
    'analyzed_urls_details' is the list from url_analyzer.perform_url_analysis
    """
    if not html_body:
        return

    score_delta = 0
    reasons = []
    soup = None
    try:
        soup = BeautifulSoup(html_body, 'html.parser')
    except Exception as e:
        reasons.append(f"HTML_PARSING_ERROR: Could not parse HTML body: {e}")
        analysis_results['reasons'].extend(reasons)
        return # Cannot proceed if HTML parsing fails

    # --- Link-Text Mismatch Analysis ---
    # Get a set of all registrable domains from already analyzed (and expanded) URLs in the email
    email_link_domains_registrables = set()
    if analyzed_urls_details:
        for url_detail in analyzed_urls_details:
            expanded_url = url_detail.get('expanded', '')
            if expanded_url:
                parsed_expanded_url = urlparse(expanded_url)
                _, reg_link_dom = get_registrable_domain_parts(parsed_expanded_url.netloc)
                if reg_link_dom:
                    email_link_domains_registrables.add(reg_link_dom)

    for a_tag in soup.find_all('a', href=True):
        link_text = a_tag.get_text(strip=True)
        href = str(a_tag.get('href', '')).strip()

        if not href or href.lower().startswith(("mailto:", "tel:", "javascript:")): # Ignore mailto, tel, javascript links
            continue
        
        # Try to parse the href to get its domain
        parsed_href = urlparse(href)
        href_netloc = parsed_href.netloc.lower().split(':')[0] # Get domain, remove port
        
        if not href_netloc: # If href is relative or has no domain, skip
            continue 
            
        _, reg_href_dom = get_registrable_domain_parts(href_netloc)
        if not reg_href_dom or '.' not in reg_href_dom: # Ensure it's a proper domain
            continue

        # Check 1: Link text itself looks like a domain but mismatches href domain
        # Regex to find domain-like patterns in link text
        text_domain_match = re.search(
            r'([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.(?:[a-zA-Z]{2,10}|[a-zA-Z0-9\-]{2,}\.[a-zA-Z]{2,10}))', 
            link_text, re.IGNORECASE
        )
        if text_domain_match:
            text_domain_candidate = text_domain_match.group(1).lower()
            _, reg_text_dom = get_registrable_domain_parts(text_domain_candidate)
            if reg_text_dom and reg_text_dom != reg_href_dom and \
               not is_related_domain(reg_text_dom, reg_href_dom) and \
               not is_trusted_domain(reg_href_dom):
                score_delta += settings.CONTENT_SCORING.get('link_text_domain_mismatch', 2)
                reasons.append(f"HTML Link/Text Mismatch: Text '{link_text}' suggests domain '{reg_text_dom}', but links to '{reg_href_dom}'. Link: {defang_url(href)}")
        
        # Check 2: Common phishing keywords in link text pointing to non-sender/untrusted domains
        elif any(keyword.lower() in link_text.lower() for keyword in settings.SUSPICIOUS_LINK_TEXT_KEYWORDS):
            if sender_domain and not is_related_domain(sender_domain, reg_href_dom) and not is_trusted_domain(reg_href_dom):
                score_delta += settings.CONTENT_SCORING.get('sensitive_link_text_external_domain', 1)
                reasons.append(f"HTML Link: Sensitive text '{link_text}' links to external/untrusted domain '{reg_href_dom}'. Link: {defang_url(href)}")
            elif not sender_domain and not is_trusted_domain(reg_href_dom): # No sender domain, link goes to untrusted
                 score_delta += settings.CONTENT_SCORING.get('sensitive_link_text_external_domain', 1) # Same score as above
                 reasons.append(f"HTML Link: Sensitive text '{link_text}' links to untrusted domain '{reg_href_dom}' (sender domain unknown). Link: {defang_url(href)}")


    # --- Suspicious Form Actions ---
    for form_tag in soup.find_all('form', action=True):
        action_url = str(form_tag.get('action', '')).strip()
        if not action_url or not (action_url.lower().startswith(('http://', 'https://')) or not urlparse(action_url).scheme): # Check if it's an HTTP/S URL or relative
            continue # Ignore non-HTTP/S absolute URLs or non-URL actions

        parsed_action = urlparse(action_url)
        action_netloc = parsed_action.netloc.lower().split(':')[0] if parsed_action.netloc else None # Get domain, remove port

        if action_netloc: # Only if form action points to an absolute URL with a domain
            _, reg_action_dom = get_registrable_domain_parts(action_netloc)
            if reg_action_dom and '.' in reg_action_dom:
                is_action_domain_suspicious = True # Assume suspicious unless proven otherwise
                if sender_domain and is_related_domain(sender_domain, reg_action_dom):
                    is_action_domain_suspicious = False
                elif is_trusted_domain(reg_action_dom):
                    is_action_domain_suspicious = False
                elif reg_action_dom in email_link_domains_registrables: # Check if form action domain was already a link in the email
                    is_action_domain_suspicious = False
                
                if is_action_domain_suspicious:
                    score_delta += settings.CONTENT_SCORING.get('suspicious_form_action', 3)
                    reasons.append(f"HTML Form submits data to an external/untrusted domain: '{reg_action_dom}'. Action URL: {defang_url(action_url)}")

    # --- Tiny text / Hidden text (basic check for very small font sizes) ---
    for element in soup.find_all(style=True):
        style = element['style'].lower()
        if 'font-size' in style:
            match = re.search(r'font-size\s*:\s*(\d+)(px|pt)', style)
            if match:
                size = int(match.group(1))
                unit = match.group(2)
                # Convert pt to px roughly (1pt = 1.33px, or simply check against small pt values)
                if (unit == 'px' and size <= settings.TINY_FONT_SIZE_PX_THRESHOLD) or \
                   (unit == 'pt' and size <= settings.TINY_FONT_SIZE_PT_THRESHOLD) :
                    # Check if element contains some text
                    if element.get_text(strip=True):
                        score_delta += settings.CONTENT_SCORING.get('tiny_font_text', 1)
                        reasons.append(f"Potential hidden text using tiny font size ({size}{unit}) found. Content preview: '{element.get_text(strip=True)[:50]}...'")
                        break # Score once for tiny text

    # --- Check for 'display:none' with significant content ---
    for element in soup.find_all(style=lambda s: s and 'display:none' in s.lower()):
        hidden_text = element.get_text(strip=True)
        if len(hidden_text) > settings.MIN_LENGTH_FOR_HIDDEN_TEXT_ALERT: # Check if there's substantial text hidden
            score_delta += settings.CONTENT_SCORING.get('display_none_with_content', 1)
            reasons.append(f"Potentially hidden content using 'display:none' with significant text found. Preview: '{hidden_text[:50]}...'")
            break # Score once

    analysis_results['score'] += score_delta
    analysis_results['reasons'].extend(reasons)


def perform_content_analysis(analysis_results, subject, body_plain, html_body, sender_domain, analyzed_urls_details):
    """
    Analyzes email subject, plain text body, and HTML specifics.
    Modifies analysis_results with score and reasons.
    """
    score_delta = 0
    reasons = []

    # 1. Subject Line Analysis
    if subject:
        subject_lower = subject.lower()
        for kw in settings.SUSPICIOUS_SUBJECT_KEYWORDS:
            if kw.lower() in subject_lower:
                score_delta += settings.CONTENT_SCORING.get('suspicious_subject_keyword', 2)
                reasons.append(f"Suspicious keyword '{kw}' found in subject.")
                break # Score once for subject keywords

    # 2. Plain Text Body Analysis
    if body_plain:
        body_plain_lower = body_plain.lower()
        # Count occurrences of keywords to potentially increase score for multiple distinct keywords
        found_body_keywords = set()
        for kw_list_name, kw_list_details in settings.SUSPICIOUS_BODY_KEYWORDS_CATEGORIZED.items():
            for kw in kw_list_details["keywords"]:
                if kw.lower() in body_plain_lower:
                    found_body_keywords.add(kw_list_name) # Add category name
        
        for category_name in found_body_keywords:
            score_delta += settings.SUSPICIOUS_BODY_KEYWORDS_CATEGORIZED[category_name]["score"]
            reasons.append(f"Suspicious keyword category '{category_name}' detected in email body.")

        # Urgency/Scare Tactics (if not covered by categorized keywords)
        # This can be a more complex NLP task, for now, simple keyword check
        for phrase in settings.URGENCY_PHRASES:
            if phrase.lower() in body_plain_lower:
                score_delta += settings.CONTENT_SCORING.get('urgency_phrase', 1)
                reasons.append(f"Urgency-inducing phrase found in email body: '{phrase}'.")
                break


    analysis_results['score'] += score_delta
    analysis_results['reasons'].extend(reasons) # Add reasons from subject/body keywords first

    # 3. HTML Specific Analysis (if HTML body exists)
    # This function will further modify analysis_results['score'] and analysis_results['reasons']
    if html_body:
        analyze_html_specifics(analysis_results, html_body, sender_domain, analyzed_urls_details)