from config import config

def scan(url, session=None):
    results = []
    try:
        if session:
            response = session.get(url, timeout=10)
        else:
            import requests
            response = requests.get(url, timeout=10)
            
        headers = response.headers
        missing_headers = []
        
        for header in config.SECURITY_HEADERS:
            if header not in headers:
                missing_headers.append(header)
                
        if missing_headers:
            results.append({
                'name': 'Missing Security Headers',
                'severity': 'Low',
                'description': f"The following security headers are missing: {', '.join(missing_headers)}",
                'poc': f"GET {url}\n\nResponse Headers:\n{headers}",
                'recommendation': "Implement the missing security headers to enhance web application security."
            })
            
    except Exception as e:
        pass # Handle or log error
        
    return results
