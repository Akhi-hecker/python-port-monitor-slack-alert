# analyzer_engine.py
import email
from email import policy
from email.parser import BytesParser
import re
import sys # For CLI use if any, not strictly for library part
import hashlib
import ipaddress # For initial sender IP parsing
from urllib.parse import urlparse, unquote # For initial From header domain parsing
from bs4 import BeautifulSoup # For extract_email_artifacts

import settings # Main settings import

# Import analyzer modules and utils
from analyzers import utils # This now contains many helper functions
from analyzers import header_analyzer
from analyzers import ip_analyzer
from analyzers import url_analyzer
from analyzers import attachment_analyzer
from analyzers import content_analyzer

def get_email_message_from_bytes(email_bytes):
    """Parses email bytes into an EmailMessage object."""
    try:
        return BytesParser(policy=policy.default).parsebytes(email_bytes)
    except Exception as e:
        # Consider logging this error
        # print(f"Error parsing email bytes: {e}")
        return None

def extract_email_artifacts(msg_object):
    """
    Extracts various artifacts like IPs, URLs, attachments, and body parts from the email message.
    This is a crucial first step after parsing the email.
    """
    artifacts = {
        'ips': set(), 
        'urls': set(), 
        'attachments': [], 
        'body_plain': "", 
        'body_html': ""
    }
    plain_parts, html_parts = [], []

    # Extract from headers first
    for header_name, header_value in msg_object.items():
        header_value_str = str(header_value)
        artifacts['ips'].update(utils.extract_ips_from_text(header_value_str))
        artifacts['urls'].update(utils.extract_urls_from_text(header_value_str))

    # Walk through MIME parts
    for part in msg_object.walk():
        content_type = part.get_content_type()
        content_disposition = str(part.get("Content-Disposition", "")).lower()
        
        is_attachment_by_disposition = "attachment" in content_disposition
        # Some clients might not set Content-Disposition but it's still an attachment if not text/html or text/plain
        # and not multipart. This can be tricky. For now, rely on Content-Disposition or is_attachment().
        is_attachment_by_method = part.is_attachment()

        if is_attachment_by_disposition or is_attachment_by_method:
            filename = part.get_filename()
            if filename: # Ensure there is a filename
                try:
                    attachment_content = part.get_payload(decode=True)
                    if attachment_content: # Ensure content is not None
                        artifacts['attachments'].append({
                            'filename': filename,
                            'content_type': content_type,
                            'sha256': hashlib.sha256(attachment_content).hexdigest(),
                            'size': len(attachment_content)
                        })
                except Exception as e:
                    # print(f"Warning: Could not decode or hash attachment '{filename}': {e}")
                    artifacts['attachments'].append({
                        'filename': filename,
                        'content_type': content_type,
                        'sha256': 'Error decoding/hashing',
                        'size': 'N/A',
                        'error': str(e)
                    })
        elif part.is_multipart(): # Skip multipart parent containers themselves for body text
            continue
        else: # Process non-attachment parts for body text and embedded artifacts
            try:
                payload_bytes = part.get_payload(decode=True) # Decode if encoded (e.g., base64)
                charset = part.get_content_charset() or 'utf-8' # Guess charset or default to utf-8
                payload_str = payload_bytes.decode(charset, errors='replace')

                # Extract IPs/URLs from this part's content as well
                artifacts['ips'].update(utils.extract_ips_from_text(payload_str))
                artifacts['urls'].update(utils.extract_urls_from_text(payload_str))

                if content_type == 'text/plain':
                    plain_parts.append(payload_str)
                elif content_type == 'text/html':
                    html_parts.append(payload_str)
            except Exception as e:
                # print(f"Warning: Could not process part content type {content_type}: {e}")
                pass # Ignore parts that can't be decoded/processed

    artifacts['body_html'] = "\n".join(html_parts)
    if plain_parts:
        artifacts['body_plain'] = "\n".join(plain_parts)
    elif artifacts['body_html']: # If no plain text part, try to extract from HTML
        artifacts['body_plain'] = utils.extract_text_from_html(artifacts['body_html'])
    
    # Filter and sort IPs
    artifacts['ips'] = sorted([ip for ip in artifacts['ips'] if utils.is_valid_ip(ip)])
    artifacts['urls'] = sorted(list(artifacts['urls'])) # Convert set to sorted list

    return artifacts


def analyze_email_object(msg_object):
    """
    Main orchestration function to analyze a parsed EmailMessage object.
    """
    analysis_results = {
        'score': 0,
        'reasons': [],
        'verdict': "Likely Safe", # Default verdict
        'headers': {k: str(v) for k, v in msg_object.items()},
        'subject': str(msg_object.get("Subject", "N/A")),
        'from_full_address_header': str(msg_object.get("From", "N/A")),
        'to': str(msg_object.get("To", "N/A")), # Consider parsing multiple recipients if needed
        'date': str(msg_object.get("Date", "N/A")),
        'message_id': str(msg_object.get("Message-ID", "N/A")),
        'sender_ip': None, # To be determined
        'sender_domain': None, # Registrable domain of the From address
        'full_from_email': "", # Parsed email from the From header
        'extracted_ips': [], # IPs found in content (excluding primary sender IP)
        'extracted_urls_raw': [],
        'url_analysis': [],
        'attachment_analysis': [],
        'sender_ip_reputation': {},
        'body_plain_text_preview': "N/A",
        'body_html_present': False,
        'all_received_headers': [str(h) for h in msg_object.get_all('Received', [])]
    }

    # --- 1. Initial Information Extraction (From, Sender Domain, Sender IP) ---
    from_header_val = analysis_results['from_full_address_header']
    parsed_from_email_for_logic = ""
    sender_registrable_domain = None

    if from_header_val and from_header_val != "N/A":
        # Prioritize email within <> using regex, then fallback to parseaddr
        match = re.search(r'<(.*?)>', from_header_val)
        if match and match.group(1) and match.group(1).strip(): # Ensure something valid is inside
            parsed_from_email_for_logic = match.group(1).strip().lower()
        else:
            _, email_addr_part_fallback = email.utils.parseaddr(from_header_val) # email.utils from Python's library
            parsed_from_email_for_logic = email_addr_part_fallback.lower()
        
        analysis_results['full_from_email'] = parsed_from_email_for_logic
        
        if "@" in parsed_from_email_for_logic:
            domain_part_from = parsed_from_email_for_logic.split('@')[-1]
            _, sender_registrable_domain = utils.get_registrable_domain_parts(domain_part_from)
            if not sender_registrable_domain and domain_part_from: # Fallback if get_registrable_domain_parts is empty
                 sender_registrable_domain = domain_part_from 
        analysis_results['sender_domain'] = sender_registrable_domain
    
    # Attempt to extract Sender IP from common headers
    # Order of preference can be important. X-Sender-IP is often reliable if present.
    potential_ip_headers = ["X-Sender-IP", "X-Originating-IP", "X-Real-IP"]
    found_sender_ip = None
    for header_key in potential_ip_headers:
        ip_header_val = analysis_results['headers'].get(header_key)
        if ip_header_val:
            # Header might contain multiple IPs or other text, extract first valid global IP
            # Regex to find IPs: \b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b
            # Ensure it's not a private/reserved IP for "sender IP"
            ip_candidates = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', str(ip_header_val))
            for ip_cand in ip_candidates:
                if utils.is_valid_ip(ip_cand): # is_valid_ip checks for global, non-private etc.
                    found_sender_ip = ip_cand
                    break
            if found_sender_ip:
                break
    
    # Fallback: Try to get from the FIRST 'Received' header (last hop before recipient's MTA)
    # This is heuristic and can be spoofed or complex to parse reliably for *external sender IP*.
    # The "first" received header in msg.get_all('Received') is the one added most recently (closest to recipient).
    # The "last" one is often the originating MTA. Let's try to parse the most recent external hop.
    if not found_sender_ip and analysis_results['all_received_headers']:
        for rec_header_str in reversed(analysis_results['all_received_headers']): # Iterate from oldest (origin) to newest
            # Look for IP in square brackets or after 'from'
            # This regex is a basic attempt; 'Received' headers are complex.
            ip_match = re.search(r'(?:from|by)\s+(?:[^(\s]+?\s+)?(?:\[(ipv6:)?(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)\]|(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b))', rec_header_str, re.IGNORECASE)
            if ip_match:
                # ip_match.group(2) is for IPv4 in brackets, ip_match.group(3) is for IPv4 not in brackets
                potential_ip = ip_match.group(3) or ip_match.group(4) # Group 2 is ipv6 prefix, 3 is IP in [], 4 is IP not in []
                if potential_ip and utils.is_valid_ip(potential_ip):
                    # Check if this IP belongs to a trusted internal relay based on settings
                    # For simplicity, we assume any valid global IP found this way could be the sender,
                    # but in real-world, you'd skip known internal relay IPs.
                    found_sender_ip = potential_ip
                    # We take the first valid global IP from the oldest relevant "Received" header.
                    # However, usually, the IP of the *external* sender is in one of the earlier (chronologically) Received headers.
                    # The logic here might need refinement based on common 'Received' header patterns.
                    # For now, taking the first valid global IP from *any* 'Received' header as a fallback.
                    break # Found a candidate from Received headers
    analysis_results['sender_ip'] = found_sender_ip


    # --- 2. Extract All Artifacts (URLs, Body, Attachments) ---
    artifacts = extract_email_artifacts(msg_object)
    analysis_results.update({
        'extracted_ips': artifacts['ips'], # IPs found in content generally
        'extracted_urls_raw': artifacts['urls'],
        'body_plain_text_preview': (artifacts['body_plain'][:500] + '...' if len(artifacts['body_plain']) > 500 else artifacts['body_plain']) or "No plain text available.",
        'body_html_present': bool(artifacts['body_html'])
    })


    # --- 3. Perform Analysis using Specialized Modules ---
    header_analyzer.perform_header_analysis(
        analysis_results,
        analysis_results['headers'],
        analysis_results['sender_domain'],
        analysis_results['full_from_email']
    )

    if analysis_results['sender_ip']: # Only analyze if a sender_ip was determined
        ip_analyzer.perform_ip_reputation_analysis(
            analysis_results,
            analysis_results['sender_ip']
        )
    else:
        analysis_results['sender_ip_reputation'] = {'ip': 'Not Found', 'error': 'Sender IP could not be determined from headers.'}
        analysis_results['reasons'].append("INFO: Sender IP could not be reliably determined from headers.")


    url_analyzer.perform_url_analysis(
        analysis_results,
        artifacts['urls'], # Pass all URLs extracted from the email
        analysis_results['sender_domain']
    )

    attachment_analyzer.perform_attachment_analysis(
        analysis_results,
        artifacts['attachments'] # Pass extracted attachment details
    )

    content_analyzer.perform_content_analysis(
        analysis_results,
        analysis_results['subject'],
        artifacts['body_plain'],
        artifacts['body_html'],
        analysis_results['sender_domain'],
        analysis_results.get('url_analysis', []) # Pass URL analysis results for HTML link context
    )

    # --- 4. Finalize Score and Verdict ---
    # The verdict is set based on the final score.
    # Ensure score is an integer or float.
    current_score = analysis_results.get('score', 0)
    if not isinstance(current_score, (int, float)):
        current_score = 0 # Default to 0 if score is not a number for some reason
        analysis_results['reasons'].append("INTERNAL_ERROR: Score calculation resulted in a non-numeric value.")
    
    analysis_results['score'] = round(current_score) # Round the score


    if analysis_results['score'] >= settings.SCORE_THRESHOLDS.get('likely_phishing_min', 10): # High score
        analysis_results['verdict'] = "Likely Phishing"
    elif analysis_results['score'] >= settings.SCORE_THRESHOLDS.get('suspicious_min', 5): # Medium score
        analysis_results['verdict'] = "Suspicious"
    else: # Low score
        analysis_results['verdict'] = "Likely Safe"
    
    analysis_results['reasons'] = sorted(list(set(analysis_results['reasons']))) # Unique sorted reasons
    return analysis_results


def perform_analysis_dict(email_bytes):
    """
    Top-level function called by the web app.
    Takes email content as bytes, returns an analysis dictionary.
    """
    msg_object = get_email_message_from_bytes(email_bytes)
    if not msg_object:
        # Ensure the error dictionary has keys expected by result.html
        return {
            'error': "Could not parse email file. The file may be malformed or not a valid EML.",
            'score': 0, 
            'verdict': "Error",
            'reasons': ["Email parsing failed."],
            'headers': {}, 
            'all_received_headers': [],
            'subject': 'N/A',
            'from_full_address_header': 'N/A',
            'to': 'N/A',
            'date': 'N/A',
            'full_from_email': 'N/A', # Added for template consistency on error
            'sender_domain': 'N/A',
            'sender_ip': 'N/A',
            'sender_ip_reputation': {'error': 'Parsing Failed'},
            'url_analysis': [],
            'attachment_analysis': [],
            'body_plain_text_preview': 'N/A',
            'body_html_present': False,
            'message_id': 'N/A',
            'extracted_ips': []
        }
    return analyze_email_object(msg_object)

def format_analysis_to_string(results, original_filename="email.eml"):
    """Formats the analysis results dictionary into a human-readable string report."""
    report_lines = [
        f"Phishing Analysis Report for: {original_filename}\n",
        "="*60,
        f"Overall Phishing Score: {results.get('score', 'N/A')}",
        f"Verdict: {results.get('verdict', 'Error')}",
        "\n--- General Information ---",
        f"Subject: {results.get('subject', 'N/A')}",
        f"From (Original Header): {results.get('from_full_address_header', 'N/A')}",
        f"Parsed From Email: {results.get('full_from_email', 'N/A')}",
        f"To: {results.get('to', 'N/A')}",
        f"Date: {results.get('date', 'N/A')}",
        f"Message-ID: {results.get('message_id', 'N/A')}",
        f"Sender Registrable Domain: {results.get('sender_domain', 'N/A')}",
        f"Detected Sender IP: {utils.defang_ip(results.get('sender_ip', 'Not Found'))}"
    ]

    ip_rep = results.get('sender_ip_reputation', {})
    if ip_rep and (ip_rep.get('ip') and ip_rep['ip'] not in ['Not Found', 'N/A']):
        report_lines.append("\n--- Sender IP Reputation (AbuseIPDB) ---")
        report_lines.append(f"  IP: {utils.defang_ip(ip_rep['ip'])}")
        if 'error' in ip_rep and ip_rep['error']: report_lines.append(f"  Status: {ip_rep['error']}")
        else:
            report_lines.append(f"  Country: {ip_rep.get('country', 'N/A')}, ISP: {ip_rep.get('isp', 'N/A')}, Domain: {ip_rep.get('domain', 'N/A')}")
            report_lines.append(f"  Abuse Score: {ip_rep.get('abuse_score', 'N/A')}, Total Reports: {ip_rep.get('total_reports', 'N/A')}")
    elif ip_rep.get('error'):
         report_lines.extend(["\n--- Sender IP Reputation ---", f"  Status: {ip_rep['error']}"])
    elif results.get('sender_ip') and results.get('sender_ip') != 'Not Found': # If IP was found but no AbuseIPDB data
        report_lines.extend(["\n--- Sender IP Reputation ---", f"  AbuseIPDB data not available for {utils.defang_ip(results.get('sender_ip'))}."])


    if results.get('extracted_ips'):
        report_lines.append("\n--- Other Extracted IPs (from headers/body) ---")
        unique_other_ips = set(results['extracted_ips']) - {results.get('sender_ip')} # Exclude sender IP if already listed
        if unique_other_ips:
            for ip_addr in sorted(list(unique_other_ips)):
                geo_info = utils.ip_info_lookup(ip_addr) # Fetch geo info for these too
                defanged_ip_addr = utils.defang_ip(ip_addr)
                if geo_info:
                    report_lines.append(f"  {defanged_ip_addr} - Country: {geo_info.get('country','N/A')}, ISP: {geo_info.get('isp','N/A')}, Hostname: {geo_info.get('hostname','N/A')}")
                else:
                    report_lines.append(f"  {defanged_ip_addr} - (Geolocation info not available)")
        else:
            report_lines.append("  No additional unique IPs found in content.")
    else:
        report_lines.append("\n--- Other Extracted IPs (from headers/body) ---")
        report_lines.append("  No additional IPs found in content.")


    if results.get('url_analysis'):
        report_lines.append("\n--- URL Analysis ---")
        for url_info in results['url_analysis']:
            report_lines.append(f"  Original: {utils.defang_url(url_info.get('original','N/A'))}")
            if url_info.get('was_expanded', False):
                report_lines.append(f"  Expanded: {utils.defang_url(url_info.get('expanded','N/A'))}")
            if url_info.get('reasons'):
                report_lines.append(f"    Score Impact: +{url_info.get('score_impact', 0)}")
                for reason in url_info['reasons']: report_lines.append(f"    - {reason}")
            elif url_info.get('score_impact',0) == 0 :
                 report_lines.append("    (No specific risks detected for this URL)")
    else:
        report_lines.append("\n--- URL Analysis ---")
        report_lines.append("  No URLs found or analyzed in content.")

    if results.get('attachment_analysis'):
        report_lines.append("\n--- Attachment Analysis ---")
        for att in results['attachment_analysis']:
            report_lines.append(f"  Filename: {att.get('filename', 'N/A')} (Type: {att.get('content_type', 'N/A')}, Size: {att.get('size', 'N/A')} bytes)")
            report_lines.append(f"    SHA256: {att.get('sha256', 'N/A')}")
            vt_dets = att.get('vt_malicious_detections', 'Not Checked')
            report_lines.append(f"    VT Detections: {vt_dets if isinstance(vt_dets, str) else vt_dets}") # Handle "Not Checked" string
            if att.get('analysis_reasons'):
                report_lines.append(f"    Score Impact: +{att.get('analysis_score', 0)}")
                for reason in att['analysis_reasons']: report_lines.append(f"    - {reason}")
            elif att.get('analysis_score', 0) == 0:
                 report_lines.append("    (No specific risks detected for this attachment)")
    else:
        report_lines.append("\n--- Attachment Analysis ---")
        report_lines.append("  No attachments found.")

    report_lines.append("\n--- Contributing Reasons (Unique) ---")
    if results.get('reasons'):
        for i, reason_text in enumerate(results['reasons']):
            report_lines.append(f"  {i+1}. {reason_text}")
    else:
        report_lines.append("  No specific phishing indicators triggered a positive score.")

    report_lines.append("\n" + "="*60)
    return "\n".join(report_lines)

# Example for CLI usage (optional, can be removed if only used as a library for Flask)
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <email_file.eml>")
        sys.exit(1)
    email_file_path = sys.argv[1]
    try:
        with open(email_file_path, 'rb') as f:
            email_content_bytes = f.read()
        analysis_results_dict_cli = perform_analysis_dict(email_content_bytes)
        
        if 'error' in analysis_results_dict_cli and analysis_results_dict_cli['error']:
            print(f"Error: {analysis_results_dict_cli['error']}")
        else:
            print(format_analysis_to_string(analysis_results_dict_cli, email_file_path))
            
    except FileNotFoundError:
        print(f"Error: File not found {email_file_path}")
        sys.exit(1)
    except Exception as e_cli:
        print(f"An unexpected error occurred: {e_cli}")
        sys.exit(1)