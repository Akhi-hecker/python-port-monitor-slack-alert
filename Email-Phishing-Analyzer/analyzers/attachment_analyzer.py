# analyzers/attachment_analyzer.py
import settings
from .utils import virustotal_file_check # Assuming utils has virustotal_file_check

def perform_attachment_analysis(analysis_results, attachments_artifacts):
    """
    Analyzes email attachments for phishing indicators.
    Modifies analysis_results with score, reasons, and attachment_analysis list.
    """
    if not attachments_artifacts:
        analysis_results['attachment_analysis'] = []
        return

    attachment_details_list = []
    total_attachment_score_delta = 0

    for att_artifact in attachments_artifacts:
        att_score_for_this_attachment = 0
        att_reasons_for_this_attachment = []
        
        filename = str(att_artifact.get('filename', '')).lower() # Ensure lowercase for extension checks
        file_hash_sha256 = att_artifact.get('sha256', '')
        
        # 1. Dangerous Attachment Type by Extension
        if filename: # Only check if filename exists
            for dangerous_ext in settings.DANGEROUS_ATTACHMENT_TYPES:
                if filename.endswith(dangerous_ext.lower()):
                    att_score_for_this_attachment += settings.ATTACHMENT_SCORING.get('dangerous_type', 3)
                    att_reasons_for_this_attachment.append(f"Attachment '{att_artifact.get('filename', 'N/A')}' has a potentially dangerous file type ('{dangerous_ext}').")
                    break # Score once per attachment for type

        # 2. VirusTotal Check (if hash and API key are available)
        vt_malicious_detections = 0 # Default to 0
        if file_hash_sha256 and settings.VT_API_KEY and settings.VT_API_KEY != "YOUR_VIRUSTOTAL_API_KEY":
            vt_malicious_detections = virustotal_file_check(file_hash_sha256, settings.VT_API_KEY)
            att_artifact['vt_malicious_detections'] = vt_malicious_detections # Store detections count

            if vt_malicious_detections >= settings.VT_MALICIOUS_THRESHOLD:
                att_score_for_this_attachment += settings.ATTACHMENT_SCORING.get('vt_hit', 4)
                att_reasons_for_this_attachment.append(f"Attachment '{att_artifact.get('filename', 'N/A')}' flagged by VirusTotal with {vt_malicious_detections} detections.")
            elif vt_malicious_detections > 0: # Some detections but below threshold
                 att_reasons_for_this_attachment.append(f"INFO: Attachment '{att_artifact.get('filename', 'N/A')}' has {vt_malicious_detections} VirusTotal detections (below threshold of {settings.VT_MALICIOUS_THRESHOLD}).")

        else:
            att_artifact['vt_malicious_detections'] = "Not Checked (No API Key or Hash)"
            if not file_hash_sha256:
                 att_reasons_for_this_attachment.append(f"INFO: Attachment '{att_artifact.get('filename', 'N/A')}' SHA256 hash not available for VT check.")


        # Add other attachment checks here if any (e.g., password-protected zips, specific filenames)

        if att_score_for_this_attachment > 0:
            total_attachment_score_delta += att_score_for_this_attachment
            analysis_results['reasons'].extend(att_reasons_for_this_attachment)

        # Update the artifact dictionary with analysis results for this attachment
        att_artifact['analysis_score'] = att_score_for_this_attachment
        att_artifact['analysis_reasons'] = att_reasons_for_this_attachment
        attachment_details_list.append(att_artifact)

    analysis_results['score'] += total_attachment_score_delta
    analysis_results['attachment_analysis'] = attachment_details_list