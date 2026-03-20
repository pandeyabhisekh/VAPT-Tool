from config import config
from utils.helpers import extract_forms
import requests
import urllib.parse

def scan(url, session=None):
    results = []
    try:
        response = (session or requests).get(url, timeout=10)
        forms = extract_forms(response.text)
        
        sqli_errors = ["mysql_fetch", "syntax error", "sql error", "oracle error", "postgresql error"]
        
        for form in forms:
            action = form.get('action') or ''
            method = form.get('method', 'get').lower()
            inputs = form.find_all(['input', 'textarea', 'select'])
            form_url = urllib.parse.urljoin(url, action)
            
            for payload in config.SQLI_PAYLOADS:
                data = {inp.get('name'): payload for inp in inputs if inp.get('name')}
                if not data: continue

                try:
                    resp = (session or requests).post(form_url, data=data, timeout=10) if method == 'post' else (session or requests).get(form_url, params=data, timeout=10)
                    
                    if resp and any(err in resp.text.lower() for err in sqli_errors):
                        results.append({
                            'name': 'SQL Injection Detected',
                            'severity': 'Critical',
                            'url': form_url,
                            'description': "The application appears to be vulnerable to SQL injection, as evidenced by database error messages in the response.",
                            'impact': "Full database compromise, including theft of sensitive user data, credentials, and potential remote code execution.",
                            'steps_to_reproduce': f"1. Submit payload '{payload}' in a form field on {form_url}.\n2. Observe an SQL error message in the server's response.",
                            'proof_of_concept': f"The application returned a database error after injecting the payload '{payload}', indicating improper handling of user-supplied input.",
                            'recommendation': "Use parameterized queries (prepared statements) for all database operations to ensure user input is treated as data, not code.",
                            'technical_fix': "Use ORMs (like SQLAlchemy) or prepared statements: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
                        })
                        return results # Confirmation found
                except: continue
    except: pass
    return results
