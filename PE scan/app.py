"""
PE Malware Static Analyzer - Main Application
A web-based tool for static analysis of Windows PE files
"""

from flask import Flask, render_template, request, jsonify, send_file
import os
import tempfile
from werkzeug.utils import secure_filename
from analyzer import PEAnalyzer

# Flask app configuration
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB limit
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

# Allowed file extensions
ALLOWED_EXTENSIONS = {'exe', 'dll'}


def allowed_file(filename):
    """Check if file has allowed extension"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def index():
    """Render main page"""
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    """Handle file upload and analysis"""
    # Check if file was uploaded
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    
    # Check if file was selected
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Validate file type
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Only .exe and .dll files are allowed'}), 400
    
    try:
        # Save file temporarily
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Perform analysis
        analyzer = PEAnalyzer(filepath)
        results = analyzer.analyze()
        
        # Clean up temporary file
        os.remove(filepath)
        
        return jsonify(results)
        
    except Exception as e:
        # Clean up on error
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500


@app.route('/download_report', methods=['POST'])
def download_report():
    """Generate and download report in specified format"""
    data = request.get_json()
    report_format = data.get('format', 'txt')
    analysis_data = data.get('data', {})
    
    # Create temporary report file
    temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=f'.{report_format}')
    
    if report_format == 'json':
        import json
        json.dump(analysis_data, temp_file, indent=2)
    else:
        # Generate TXT report
        temp_file.write("=" * 60 + "\n")
        temp_file.write("PE MALWARE STATIC ANALYSIS REPORT\n")
        temp_file.write("=" * 60 + "\n\n")
        
        # File info
        file_info = analysis_data.get('file_info', {})
        temp_file.write(f"File Name: {file_info.get('file_name', 'N/A')}\n")
        temp_file.write(f"File Type: {file_info.get('file_type', 'N/A')}\n")
        temp_file.write(f"File Size: {file_info.get('file_size', 'N/A')} bytes\n")
        temp_file.write(f"MD5 Hash: {file_info.get('md5_hash', 'N/A')}\n\n")
        
        # PE Header info
        pe_info = analysis_data.get('pe_info', {})
        temp_file.write("-" * 40 + "\n")
        temp_file.write("PE HEADER INFORMATION\n")
        temp_file.write("-" * 40 + "\n")
        temp_file.write(f"Entry Point: {pe_info.get('entry_point', 'N/A')}\n")
        temp_file.write(f"Image Base: {pe_info.get('image_base', 'N/A')}\n")
        temp_file.write(f"Compilation Time: {pe_info.get('compilation_time', 'N/A')}\n")
        temp_file.write(f"Number of Sections: {pe_info.get('num_sections', 'N/A')}\n\n")
        
        # Suspicious APIs
        temp_file.write("-" * 40 + "\n")
        temp_file.write("SUSPICIOUS API CALLS\n")
        temp_file.write("-" * 40 + "\n")
        apis = analysis_data.get('suspicious_apis', [])
        if apis:
            for api in apis:
                temp_file.write(f"[WARNING] {api}\n")
        else:
            temp_file.write("No suspicious APIs detected\n")
        temp_file.write("\n")
        
        # Section analysis
        temp_file.write("-" * 40 + "\n")
        temp_file.write("SECTION ANALYSIS\n")
        temp_file.write("-" * 40 + "\n")
        sections = analysis_data.get('sections', [])
        for section in sections:
            temp_file.write(f"\nSection: {section.get('name', 'N/A')}\n")
            temp_file.write(f"  Virtual Size: {section.get('virtual_size', 'N/A')}\n")
            temp_file.write(f"  Raw Size: {section.get('raw_size', 'N/A')}\n")
            temp_file.write(f"  Entropy: {section.get('entropy', 'N/A')}")
            if section.get('suspicious', False):
                temp_file.write(" [HIGH ENTROPY - POSSIBLY PACKED]")
            temp_file.write("\n")
        temp_file.write("\n")
        
        # Suspicious strings
        temp_file.write("-" * 40 + "\n")
        temp_file.write("SUSPICIOUS STRINGS\n")
        temp_file.write("-" * 40 + "\n")
        strings = analysis_data.get('suspicious_strings', [])
        if strings:
            for string in strings[:20]:  # Limit to 20 strings
                temp_file.write(f"  - {string}\n")
            if len(strings) > 20:
                temp_file.write(f"  ... and {len(strings) - 20} more\n")
        else:
            temp_file.write("No suspicious strings detected\n")
        temp_file.write("\n")
        
        # Risk assessment
        temp_file.write("=" * 60 + "\n")
        temp_file.write("RISK ASSESSMENT\n")
        temp_file.write("=" * 60 + "\n")
        risk = analysis_data.get('risk_level', 'Unknown')
        temp_file.write(f"Risk Level: {risk}\n")
        temp_file.write(f"Risk Score: {analysis_data.get('risk_score', 0)}/100\n")
        
        behaviors = analysis_data.get('possible_behaviors', [])
        if behaviors:
            temp_file.write("\nPossible Malicious Behaviors:\n")
            for behavior in behaviors:
                temp_file.write(f"  - {behavior}\n")
        
        temp_file.write("\n" + "=" * 60 + "\n")
        temp_file.write("End of Report\n")
        temp_file.write("=" * 60 + "\n")
    
    temp_file.close()
    
    return send_file(temp_file.name, as_attachment=True, download_name=f"malware_analysis_report.{report_format}")


if __name__ == '__main__':
    # Create uploads directory if it doesn't exist
    os.makedirs('uploads', exist_ok=True)
    # Run in debug mode for development
    app.run(debug=True, host='0.0.0.0', port=5000)