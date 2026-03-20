from config import config
import requests

def scan(url, session=None):
    results = []
    try:
        response = (session or requests).get(url, timeout=10)
        headers = response.headers
        
        for header in config.SECURITY_HEADERS:
            if header not in headers:
                # Custom Recommendation per header
                rec_map = {
                    "Content-Security-Policy": "Implement CSP to restrict sources of scripts/content and mitigate XSS.",
                    "X-Frame-Options": "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking attacks.",
                    "X-Content-Type-Options": "Use nosniff to prevent the browser from MIME-sniffing away from the declared content-type.",
                    "Strict-Transport-Security": "Enable HSTS to force connections over HTTPS and prevent SSL stripping.",
                    "Referrer-Policy": "Configure Referrer-Policy to control how much referrer information is shared.",
                    "Permissions-Policy": "Define a Permissions-Policy to restrict browser features like camera or geolocation."
                }
                
                results.append({
                    'name': f'Missing Security Header: {header}',
                    'severity': 'Low',
                    'url': url,
                    'description': f"The security-enhancing header '{header}' is not present in the HTTP response.",
                    'impact': "Attackers can exploit the lack of browser-side security controls to perform XSS, clickjacking, or data leakage.",
                    'steps_to_reproduce': f"1. Send a GET request to {url}.\n2. Inspect headers in the response.",
                    'proof_of_concept': f"Header '{header}' missing from response at {url}",
                    'recommendation': rec_map.get(header, f"Configure the server to include the {header} header in all responses."),
                    'technical_fix': f"In Nginx: add_header {header} 'value';\nIn Flask: response.headers['{header}'] = 'value'"
                })
    except: pass
    return results
