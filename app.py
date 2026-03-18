from flask import Flask, render_template, request, redirect, url_for, send_from_directory
import os
from core.scanner import Scanner
from report.generator import ReportGenerator
from config import config
from utils.logger import logger

app = Flask(__name__)
app.config.from_object(config)
config.init_app()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def run_scan():
    target_url = request.form.get('target_url')
    username = request.form.get('username')
    password = request.form.get('password')
    headers_raw = request.form.get('headers')
    cookies_raw = request.form.get('cookies')
    
    # Simple parsing of headers/cookies if provided
    extra_headers = {}
    if headers_raw:
        for line in headers_raw.split('\n'):
            if ':' in line:
                k, v = line.split(':', 1)
                extra_headers[k.strip()] = v.strip()
                
    extra_cookies = {}
    if cookies_raw:
        for pair in cookies_raw.split(';'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                extra_cookies[k.strip()] = v.strip()

    logger.info(f"Received scan request for {target_url}")
    
    scanner = Scanner(target_url, username, password, extra_headers, extra_cookies)
    vulnerabilities = scanner.run_scan()
    
    report_gen = ReportGenerator(target_url, vulnerabilities)
    json_path = report_gen.generate_json()
    html_path = report_gen.generate_html()
    
    report_filename = os.path.basename(html_path)
    
    return render_template('result.html', 
                           target=target_url, 
                           vulnerabilities=vulnerabilities, 
                           report_file=report_filename)

@app.route('/reports/<filename>')
def download_report(filename):
    return send_from_directory(config.REPORT_DIR, filename)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
