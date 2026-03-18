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
        
        # SQL Injection patterns in error messages
        sqli_errors = [
            "you have an error in your sql syntax",
            "unclosed quotation mark after the character string",
            "mysql_fetch_array()",
            "supplied argument is not a valid mysql result resource",
            "invalid query",
            "microsoft ole db provider for sql server"
        ]
        
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            for payload in config.SQLI_PAYLOADS:
                data = {}
                for input_tag in inputs:
                    name = input_tag.get('name')
                    if name:
                        data[name] = payload
                
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
                
                if resp:
                    for error in sqli_errors:
                        if error.lower() in resp.text.lower():
                            results.append({
                                'name': 'SQL Injection Detected',
                                'severity': 'Critical',
                                'description': f"Potential SQL Injection vulnerability in form at {form_url}",
                                'poc': f"Form submission with payload {payload} resulted in SQL error: {error}",
                                'recommendation': "Use prepared statements and parameterized queries."
                            })
                            return results # One payload is enough
                            
    except Exception as e:
        pass
        
    return results
