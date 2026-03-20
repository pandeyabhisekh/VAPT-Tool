import requests
from utils.logger import logger

def scan(url, session=None):
    results = []
    fuzz_list = [
        ".bak", ".old", ".tmp", ".temp", ".swp", ".swo",
        "~", "_backup", "_old", "_dev", "_test",
        ".zip", ".tar.gz", ".7z", ".rar"
    ]

    # Fuzz the base URL and common variations
    base_url = url.rstrip('/')
    url_variations = [base_url]
    if '/' in base_url.split('//')[-1]:
        file_part = base_url.split('/')[-1]
        if '.' in file_part:
            # e.g., http://site.com/login.php -> http://site.com/login
            url_variations.append(base_url.rsplit('.', 1)[0])

    for u in url_variations:
        for extension in fuzz_list:
            fuzz_url = f"{u}{extension}"
            try:
                response = (session or requests).head(fuzz_url, timeout=5, allow_redirects=False)
                if response.status_code == 200:
                    results.append({
                        'name': 'Hidden/Backup File Discovered (Fuzzing)',
                        'severity': 'Medium',
                        'url': fuzz_url,
                        'description': f"A potentially sensitive backup or temporary file was discovered at {fuzz_url}. These files often contain old source code, credentials, or configuration details.",
                        'impact': "Source code leakage, exposure of hardcoded secrets, or understanding of application logic that can aid further attacks.",
                        'steps_to_reproduce': f"1. Send a HEAD or GET request to {fuzz_url}.\n2. Observe the HTTP 200 OK response.",
                        'proof_of_concept': f"The URL {fuzz_url} responded with HTTP 200, confirming its existence.",
                        'recommendation': "Ensure that backup, temporary, and compressed files are never stored within the web root. Implement a strict policy to clean up such files during deployment.",
                        'technical_fix': "Use a .gitignore file to exclude these file types from your repository. Configure your deployment script to remove any temporary or backup files after a successful build."
                    })
            except requests.RequestException:
                continue

    return results
