from bs4 import BeautifulSoup
from config import config
from utils.helpers import extract_forms
import urllib.parse
import requests

def scan(url, session=None):
    results = []
    try:
        if session:
            response = session.get(url, timeout=10)
        else:
            response = requests.get(url, timeout=10)
            
        forms = extract_forms(response.text)
        
        for form in forms:
            action = form.get('action') or ''
            method = form.get('method', 'get').lower()
            inputs = form.find_all(['input', 'textarea', 'select'])
            
            form_url = urllib.parse.urljoin(url, action)
            
            for payload in config.XSS_PAYLOADS:
                data = {}
                for input_tag in inputs:
                    name = input_tag.get('name')
                    if name:
                        data[name] = payload
                
                if not data: continue

                try:
                    if method == 'post':
                        resp = (session or requests).post(form_url, data=data, timeout=10)
                    else:
                        resp = (session or requests).get(form_url, params=data, timeout=10)
                    
                    if resp and payload in resp.text:
                        results.append({
                            'name': 'Reflected Cross-Site Scripting (XSS)',
                            'severity': 'High',
                            'url': form_url,
                            'description': "User input is reflected in the HTML response without proper sanitization, allowing arbitrary JavaScript execution.",
                            'impact': "Attackers can steal session cookies, deface the site, or redirect users to malicious domains.",
                            'steps_to_reproduce': f"1. Submit form at {form_url} with payload {payload}.\n2. Observe the script executing in the browser.",
                            'poc': f"Payload '{payload}' reflected in response from {form_url}",
                            'recommendation': "Implement context-aware output encoding (e.g., HTML entity encoding) and use a strong Content Security Policy (CSP).",
                            'technical_fix': "In Python/Jinja2: {{ user_input }} (escapes by default). Manual: html.escape(input_string)"
                        })
                        break 
                except: continue
    except: pass
    return results
