from config import config
from utils.helpers import safe_request

def scan(url, session=None):
    results = []
    try:
        base_url = url.rstrip('/')
        
        for directory in config.COMMON_DIRECTORIES:
            full_url = f"{base_url}{directory}"
            
            if session:
                response = session.get(full_url, timeout=5, allow_redirects=False)
            else:
                import requests
                response = requests.get(full_url, timeout=5, allow_redirects=False)
                
            if response.status_code in [200, 301, 302, 403]:
                severity = 'Medium' if response.status_code == 200 else 'Low'
                results.append({
                    'name': 'Interesting Directory/File Found',
                    'severity': severity,
                    'description': f"Found a potentially sensitive path: {full_url} (HTTP {response.status_code})",
                    'poc': f"GET {full_url} returned {response.status_code}",
                    'recommendation': "Ensure sensitive directories are not publicly accessible and use proper access controls."
                })
                
    except Exception as e:
        pass
        
    return results
