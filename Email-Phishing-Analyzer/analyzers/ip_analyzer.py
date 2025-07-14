# analyzers/ip_analyzer.py
import settings
from .utils import abuseipdb_check, defang_ip # is_valid_ip is used by analyzer_engine before calling this

def perform_ip_reputation_analysis(analysis_results, sender_ip):
    """
    Analyzes sender IP reputation using AbuseIPDB.
    Modifies analysis_results with score, reasons, and sender_ip_reputation field.
    Assumes sender_ip is already validated as a global IP by the caller.
    """
    if not sender_ip: # Should have been caught by caller, but double check
        analysis_results['sender_ip_reputation'] = {'ip': str(sender_ip) or 'N/A', 'error': 'Invalid or no sender IP provided to analyzer.'}
        return

    abuse_info = abuseipdb_check(sender_ip, settings.ABUSEIPDB_API_KEY)
    
    current_ip_reputation_details = {'ip': str(sender_ip)} # Initialize with IP

    if abuse_info:
        current_ip_reputation_details.update(abuse_info) # Add all fields from abuse_info
        score_delta = 0
        reasons = []
        
        abuse_score = abuse_info.get('abuse_score', 0) # Default to 0 if not present

        if abuse_score >= settings.IP_ABUSE_THRESHOLDS.get('high', 75): # Default high threshold
            score_delta += settings.IP_SCORING.get('abuse_high', 3)
            reasons.append(f"Sender IP {defang_ip(sender_ip)} is HIGH RISK (AbuseIPDB score: {abuse_score}).")
        elif abuse_score >= settings.IP_ABUSE_THRESHOLDS.get('medium', 40): # Default medium threshold
            score_delta += settings.IP_SCORING.get('abuse_medium', 2)
            reasons.append(f"Sender IP {defang_ip(sender_ip)} is MEDIUM RISK (AbuseIPDB score: {abuse_score}).")
        elif abuse_score >= settings.IP_ABUSE_THRESHOLDS.get('low', 10): # Default low threshold
            score_delta += settings.IP_SCORING.get('abuse_low', 1)
            reasons.append(f"Sender IP {defang_ip(sender_ip)} is LOW RISK / suspicious (AbuseIPDB score: {abuse_score}).")
        
        analysis_results['score'] += score_delta
        analysis_results['reasons'].extend(reasons)
    else:
        current_ip_reputation_details['error'] = "Could not fetch AbuseIPDB data or API key missing/invalid."
        # Optionally add a small penalty if API is expected but fails
        # analysis_results['score'] += settings.IP_SCORING.get('api_failure', 0) 
        # analysis_results['reasons'].append("INFO: Failed to get AbuseIPDB data for sender IP.")

    analysis_results['sender_ip_reputation'] = current_ip_reputation_details