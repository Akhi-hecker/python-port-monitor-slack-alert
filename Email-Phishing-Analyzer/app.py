# app.py
from flask import Flask, render_template, request, redirect, url_for, Response
import os

# Import from the new analyzer_engine and analyzers.utils
from analyzer_engine import perform_analysis_dict, format_analysis_to_string
from analyzers.utils import defang_ip, defang_url # For use in template

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads' # Create this folder if you want to save uploads temporarily
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload size

# Ensure the upload folder exists (optional, if you save files)
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Globals to store the last analysis result for download.
# WARNING: Not suitable for multi-user production environments.
LAST_ANALYSIS_DICT = None
LAST_FILENAME = None

@app.route('/', methods=['GET'])
def index():
    # Pass an empty error if none, or the error from redirect
    error_message = request.args.get('error')
    return render_template('index.html', error=error_message)

@app.route('/analyze', methods=['POST'])
def analyze():
    global LAST_ANALYSIS_DICT, LAST_FILENAME 

    if 'email_file' not in request.files:
        return render_template('index.html', error="No file part in the request.")

    file = request.files['email_file']

    if file.filename == '':
        return render_template('index.html', error="No file selected for uploading.")

    if file and file.filename.endswith(('.eml', '.msg')): # Allow .msg too if you plan to support later
        try:
            original_filename = file.filename
            email_bytes = file.read()
            
            analysis_results = perform_analysis_dict(email_bytes) # Call the engine
            
            LAST_ANALYSIS_DICT = analysis_results
            LAST_FILENAME = original_filename 
            
            # Pass defang functions to the template context
            return render_template('result.html', 
                                   results=analysis_results, 
                                   defang_ip=defang_ip, 
                                   defang_url=defang_url)
        except Exception as e:
            app.logger.error(f"Error during analysis or rendering: {e}", exc_info=True) 
            # A more robust error result for the template
            error_result = {
                'error': f"An unexpected error occurred: {str(e)}. Check server logs.",
                'score': 0, 'verdict': 'Error', 'reasons': [f"Server error: {str(e)}"],
                'headers': {}, 'all_received_headers': [], 'subject': 'N/A',
                'from_full_address_header': 'N/A', 'to': 'N/A', 'date': 'N/A',
                'full_from_email': 'N/A', 'sender_domain': 'N/A', 'sender_ip': 'N/A',
                'sender_ip_reputation': {'error': 'Analysis Failed'},
                'url_analysis': [], 'attachment_analysis': [],
                'body_plain_text_preview': 'N/A', 'body_html_present': False,
                'message_id': 'N/A', 'extracted_ips': []
            }
            return render_template('result.html', results=error_result, defang_ip=defang_ip, defang_url=defang_url)
    else:
        return render_template('index.html', error="Invalid file type. Please upload a .eml or .msg file.")

@app.route('/download_report')
def download_report():
    global LAST_ANALYSIS_DICT, LAST_FILENAME
    if LAST_ANALYSIS_DICT and LAST_FILENAME:
        if LAST_ANALYSIS_DICT.get('error'): # Don't download report if analysis itself had an error
             return redirect(url_for('index', error="Cannot download report due to analysis error."))
        try:
            report_str = format_analysis_to_string(LAST_ANALYSIS_DICT, LAST_FILENAME)
            
            download_filename_base = os.path.splitext(LAST_FILENAME)[0]
            safe_basename = "".join(c if c.isalnum() or c in ['_', '-'] else '_' for c in download_filename_base)
            download_filename = f"{safe_basename}_analysis_report.txt"

            return Response(
                report_str,
                mimetype="text/plain",
                headers={"Content-disposition": f"attachment; filename=\"{download_filename}\""} # Ensure filename is quoted
            )
        except Exception as e:
            app.logger.error(f"Error generating download report: {e}", exc_info=True)
            return redirect(url_for('index', error="Could not generate report for download."))
    else:
        return redirect(url_for('index', error="No analysis found to download."))

if __name__ == '__main__':
    # For development, debug=True is fine. For production, use a proper WSGI server.
    app.run(debug=True)