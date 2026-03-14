from flask import Flask, render_template, request, jsonify, send_file
import json
import os
from datetime import datetime
from modules.whois_module import WhoisLookup
from modules.dns_module import DNSRecon
from modules.github_module import GitHubOSINT
from modules.breach_module import BreachChecker
from modules.search_module import SearchIntel
from modules.archive_module import ArchiveLookup

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Ensure directories exist
os.makedirs('static/reports', exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form.get('target', '').strip()
    
    if not target:
        return jsonify({'error': 'Please enter a target domain'}), 400
    
    # Clean target (remove http/https)
    target = target.replace('https://', '').replace('http://', '').split('/')[0]
    
    results = {
        'target': target,
        'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'whois': {},
        'dns': {},
        'github': {},
        'breaches': {},
        'search': {},
        'archive': {}
    }
    
    try:
        # WHOIS Lookup
        whois_lookup = WhoisLookup()
        results['whois'] = whois_lookup.get_info(target)
    except Exception as e:
        results['whois'] = {'error': str(e)}
    
    try:
        # DNS Reconnaissance
        dns_recon = DNSRecon()
        results['dns'] = dns_recon.get_records(target)
    except Exception as e:
        results['dns'] = {'error': str(e)}
    
    try:
        # GitHub OSINT
        github_osint = GitHubOSINT()
        results['github'] = github_osint.search_target(target)
    except Exception as e:
        results['github'] = {'error': str(e)}
    
    try:
        # Breach Check
        breach_checker = BreachChecker()
        results['breaches'] = breach_checker.check_domain(target)
    except Exception as e:
        results['breaches'] = {'error': str(e)}
    
    try:
        # Search Intelligence
        search_intel = SearchIntel()
        results['search'] = search_intel.dork_target(target)
    except Exception as e:
        results['search'] = {'error': str(e)}
    
    try:
        # Archive Lookup
        archive_lookup = ArchiveLookup()
        results['archive'] = archive_lookup.get_snapshots(target)
    except Exception as e:
        results['archive'] = {'error': str(e)}
    
    # Save results to file for report generation
    report_file = f"static/reports/{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    return render_template('results.html', results=results, report_file=report_file)

@app.route('/download_report/<path:filename>')
def download_report(filename):
    try:
        return send_file(filename, as_attachment=True)
    except Exception as e:
        return jsonify({'error': 'Report not found'}), 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)