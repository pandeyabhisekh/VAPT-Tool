from config import config
import requests

def scan(url, session=None):
    results = []
    try:
        base_url = url.rstrip('/')
        
        for directory in config.COMMON_DIRECTORIES:
            full_url = f"{base_url}{directory}"
            
            try:
                if session:
                    response = session.get(full_url, timeout=5, allow_redirects=False)
                else:
                    response = requests.get(full_url, timeout=5, allow_redirects=False)
                    
                if response.status_code in [200, 301, 302, 403]:
                    # Specific Logic for each finding
                    if ".git" in directory:
                        results.append({
                            'name': 'Exposed Git Repository',
                            'severity': 'High',
                            'url': full_url,
                            'description': "The .git directory is accessible, allowing attackers to download the entire source code history and internal configurations.",
                            'impact': "Source code theft, exposure of hardcoded secrets, and full reverse engineering of the application logic.",
                            'steps_to_reproduce': f"1. Access {full_url}/config or {full_url}/index in a browser.\n2. Use 'git-dumper' to pull the full repository.",
                            'proof_of_concept': f"Exposed git directory found at {full_url} (HTTP {response.status_code})",
                            'recommendation': "Block access to the .git directory immediately and clean any leaked secrets from the repository history before redeploying.",
                            'technical_fix': "Nginx: location ~ /\\.git { deny all; }\nApache: <Directory ~ \"/\\.git\"> Order allow,deny Deny from all </Directory>"
                        })
                    elif ".env" in directory:
                        results.append({
                            'name': 'Exposed Environment File (.env)',
                            'severity': 'Critical',
                            'url': full_url,
                            'description': "The .env file containing sensitive environment variables like DB credentials and API keys is publicly accessible.",
                            'impact': "Immediate full system compromise. Attackers can access databases, third-party services, and cloud infrastructure.",
                            'steps_to_reproduce': f"1. Send a GET request to {full_url}.\n2. Read sensitive keys like DB_PASSWORD or AWS_SECRET.",
                            'proof_of_concept': f"Successfully accessed {full_url} with content length {len(response.content)}",
                            'recommendation': "Move the .env file outside of the web root and rotate all secrets contained within it immediately.",
                            'technical_fix': "Move .env to a parent directory not served by the web server. Use environment variables injected by the OS or Docker instead of a file."
                        })
                    elif "admin" in directory.lower():
                        results.append({
                            'name': 'Exposed Administrative Panel',
                            'severity': 'Medium',
                            'url': full_url,
                            'description': "An administrative login or dashboard was discovered at a common path.",
                            'impact': "Provides a direct target for brute-force attacks and unauthorized administrative access if weak credentials are used.",
                            'steps_to_reproduce': f"1. Navigate to {full_url}.\n2. Observe the administrative login interface.",
                            'proof_of_concept': f"Found login form at {full_url}",
                            'recommendation': "Restrict access to the admin panel using IP whitelisting or a VPN. Change the default /admin path to a non-obvious URL.",
                            'technical_fix': "Nginx: allow 192.168.1.0/24; deny all; inside the admin location block."
                        })
                    else:
                        results.append({
                            'name': f'Interesting Path Discovered: {directory}',
                            'severity': 'Low',
                            'url': full_url,
                            'description': f"A resource was found at {directory} which may contain sensitive information or internal logic.",
                            'impact': "Information disclosure that assists in further reconnaissance.",
                            'steps_to_reproduce': f"1. Request {full_url}.\n2. Inspect the content for internal details.",
                            'proof_of_concept': f"Path {full_url} exists (HTTP {response.status_code})",
                            'recommendation': "Review the necessity of this path being public. If not required, disable access or require authentication.",
                            'technical_fix': "Options -Indexes in Apache or autoindex off in Nginx to prevent directory listing."
                        })
            except:
                continue
                
    except Exception as e:
        pass
        
    return results
