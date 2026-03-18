from bs4 import BeautifulSoup
from config import config
from utils.helpers import extract_forms

def scan(url, session=None):
    results = []
    try:
        if session:
            response = session.get(url, timeout=10)
        else:
            import requests
            response = requests.get(url, timeout=10)
            
        forms = extract_forms(response.text)
        
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            # Simple XSS check on each input field
            for payload in config.XSS_PAYLOADS:
                data = {}
                for input_tag in inputs:
                    name = input_tag.get('name')
                    if name:
                        data[name] = payload
                
                # Submit form
                import urllib.parse
                form_url = urllib.parse.urljoin(url, action)
                
                if method == 'post':
                    if session:
                        resp = session.post(form_url, data=data, timeout=10)
                    else:
                        resp = requests.post(form_url, data=data, timeout=10)
                else:
                    if session:
                        resp = session.get(form_url, params=data, timeout=10)
                    else:
                        resp = requests.get(form_url, params=data, timeout=10)
                
                if resp and payload in resp.text:
                    results.append({
                        'name': 'Reflected Cross-Site Scripting (XSS)',
                        'severity': 'High',
                        'description': f"Input reflection found in form at {form_url}",
                        'poc': f"Form submission to {form_url} with payload {payload}",
                        'recommendation': "Implement input validation and output encoding to prevent XSS attacks."
                    })
                    break # One payload found is enough for this form
                    
    except Exception as e:
        pass
        
    return results
