import requests
import time
import re
from utils.logger import logger
from bs4 import BeautifulSoup
import urllib.parse

def scan(url, session=None, login_info=None):
    results = []
    if not login_info or not login_info.get('form_url'):
        return results

    form_url = login_info['form_url']
    user_field = login_info['user_field']
    pass_field = login_info['pass_field']
    test_username = login_info['test_username']
    
    # Use the provided session or a new one
    test_session = session or requests.Session()

    logger.info(f"Analyzing login form for advanced security controls: {form_url}")

    # 1. Login Page Analysis (Initial Fetch)
    try:
        response = test_session.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
    except Exception as e:
        logger.error(f"Failed to fetch login page for analysis: {e}")
        return results

    # --- Advanced Feature Detection ---
    
    # A. Advanced CAPTCHA Detection
    captcha_detected = False
    captcha_type = "Generic"
    
    # Specific Indicators: AXD endpoints, GUIDs in params, Image sources
    axd_endpoints = ['/CaptchaImage.axd', '/Captcha.axd']
    guid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    
    # Check <img> tags for AXD or "captcha" keywords
    captcha_imgs = soup.find_all('img', src=True)
    for img in captcha_imgs:
        src = img['src'].lower()
        if any(axd.lower() in src for axd in axd_endpoints) or 'captcha' in src:
            captcha_detected = True
            captcha_type = "Dynamic CAPTCHA (non-bypassable via simple automation)"
            if re.search(guid_pattern, src):
                captcha_type = "Advanced Dynamic CAPTCHA (GUID Tokenized)"
            break

    # Check text and keywords in the whole page
    if not captcha_detected:
        captcha_keywords = ['captcha', 'recaptcha', 'g-recaptcha', 'robot', 'human verification']
        if any(k in response.text.lower() for k in captcha_keywords):
            captcha_detected = True
            captcha_type = "Keyword-based CAPTCHA"
    
    # Check for specific reCAPTCHA scripts
    if not captcha_detected:
        if soup.find('script', src=lambda s: s and 'recaptcha' in s.lower()):
            captcha_detected = True
            captcha_type = "Google reCAPTCHA Widget"

    # B. ASP.NET Deep Form Intelligence
    # Extracting standard and custom hidden fields (VIEWSTATE, EVENTVALIDATION, etc.)
    asp_fields = {}
    hidden_inputs = soup.find_all('input', type='hidden')
    for inp in hidden_inputs:
        name = inp.get('name')
        if name and (name.startswith('__') or name.startswith('_ASPVIEWSTATE')):
            asp_fields[name] = inp.get('value', '')

    is_asp_net = len(asp_fields) > 0

    # C. Client-Side Encryption/Obfuscation Detection
    encryption_patterns = [
        r'process\s*\(', r'aes\.js', r'crypto-js', r'sha256', r'encrypt\s*\(', r'decrypt\s*\(', r'asmcrypto\.js', r'Process\s*\('
    ]
    scripts = soup.find_all('script')
    found_obfuscation = False
    obfuscation_tech = []
    
    for script in scripts:
        script_content = (script.get('src') or '') + ' ' + (script.text or '')
        for pattern in encryption_patterns:
            if re.search(pattern, script_content, re.IGNORECASE):
                found_obfuscation = True
                tech_name = pattern.replace('\\', '').replace('\s*', '')
                obfuscation_tech.append(tech_name)
                
    # 2. Smart Logic: Handling Protections & Risk Classification
    if captcha_detected:
        results.append({
            'name': 'CAPTCHA Protection Enabled',
            'severity': 'Low',
            'url': form_url,
            'description': f"The application uses {captcha_type} to protect the login endpoint. The authentication process is 'Protected against automation'.",
            'impact': "Automated brute-force and credential stuffing attacks are effectively mitigated. The CAPTCHA ensures that each login attempt requires human verification or complex bypass techniques.",
            'steps_to_reproduce': "1. Navigate to the login page.\n2. Observe the CAPTCHA image, widget, or specific endpoint (/CaptchaImage.axd).",
            'proof_of_concept': f"Detected {captcha_type} at {form_url}. Source indicators: {captcha_type}.",
            'recommendation': "Brute-force attack not feasible due to active CAPTCHA. Manual testing or CAPTCHA bypass required for further testing.",
            'technical_fix': "N/A - Defensive controls are active and functioning as intended."
        })
        logger.info(f"Advanced CAPTCHA detected ({captcha_type}). Marking as 'Protected against automation' and skipping brute-force.")
    else:
        # 3. Session-Aware Testing (Rate Limit Check)
        logger.info("No CAPTCHA detected. Proceeding with session-aware rate-limit testing.")
        
        start_time = time.time()
        rapid_attempts = 5
        lockout_detected = False
        lockout_keywords = ['account locked', 'too many attempts', 'temporary block', 'wait 15 minutes', 'ip blocked']
        
        for i in range(rapid_attempts):
            # ALWAYS fetch fresh tokens (VIEWSTATE, etc.) before each attempt
            current_payload = {}
            try:
                refresh_resp = test_session.get(url, timeout=5)
                refresh_soup = BeautifulSoup(refresh_resp.text, 'html.parser')
                for hidden in refresh_soup.find_all('input', type='hidden'):
                    name = hidden.get('name')
                    if name:
                        current_payload[name] = hidden.get('value', '')
            except: pass

            current_payload[user_field] = test_username
            current_payload[pass_field] = f"invalid_password_{i}"
            
            try:
                resp = test_session.post(form_url, data=current_payload, timeout=5)
                if any(keyword in resp.text.lower() for keyword in lockout_keywords):
                    lockout_detected = True
                    break
            except: pass

        duration = time.time() - start_time

        if lockout_detected:
            results.append({
                'name': 'Account Lockout Mechanism Detected',
                'severity': 'Low',
                'url': form_url,
                'description': "The application enforces an account lockout policy or IP-based rate limiting after multiple failed attempts.",
                'impact': "Protects against automated credential guessing by disabling access after a pre-defined threshold of failures.",
                'steps_to_reproduce': f"1. Submit {i+1} incorrect login attempts to {form_url}.\n2. Observe the 'Account Locked' or 'Too many attempts' message.",
                'proof_of_concept': f"Account lockout triggered after {i+1} failed attempts.",
                'recommendation': "The lockout policy is an effective control. Ensure it cannot be bypassed by rotating source IPs or through session manipulation.",
                'technical_fix': "N/A - Protection is active."
            })
        elif duration < 1.5: # Rapid completion with no lockout
            severity = 'High' if not is_asp_net else 'Medium'
            results.append({
                'name': 'Missing Rate-Limiting / Account Lockout',
                'severity': severity,
                'url': form_url,
                'description': "The login endpoint does not enforce rate-limiting or account lockout, making it susceptible to high-speed automated attacks.",
                'impact': "High risk of successful account takeover through brute-force or credential stuffing.",
                'steps_to_reproduce': f"1. Send {rapid_attempts} rapid login requests to {form_url}.\n2. Observe that all requests are processed without delay.",
                'proof_of_concept': f"Completed {rapid_attempts} attempts in {duration:.2f} seconds with no defensive reaction from the server.",
                'recommendation': "Implement a multi-layered defense: Web server rate limiting (limit_req), application-level account lockout, and CAPTCHA implementation after 3-5 failed attempts.",
                'technical_fix': "Nginx: limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;"
            })

    # 4. Info Findings for Infrastructure/Client-Side Tech
    if is_asp_net:
        results.append({
            'name': 'ASP.NET State Management Detected',
            'severity': 'Info',
            'url': url,
            'description': "The application uses ASP.NET state management tokens (__VIEWSTATE, __EVENTVALIDATION, etc.) for session and integrity control.",
            'impact': "Increases the complexity for basic automated tools and provides a baseline for CSRF protection.",
            'proof_of_concept': f"Found tokens: {', '.join(asp_fields.keys())}",
            'recommendation': "Ensure VIEWSTATE is signed (MAC) and encrypted to prevent manipulation.",
            'technical_fix': "<pages viewStateEncryptionMode='Always' enableViewStateMac='true' />"
        })

    if found_obfuscation:
        results.append({
            'name': 'Client-Side Obfuscation Detected',
            'severity': 'Info',
            'url': url,
            'description': "The application uses client-side JavaScript (e.g., Process(), asmcrypto.js) to process or obfuscate data before submission.",
            'impact': "Provides a layer of obfuscation that can hinder basic automation and network-level cleartext inspection.",
            'proof_of_concept': f"Detected scripts/functions: {', '.join(set(obfuscation_tech))}",
            'recommendation': "Do not rely on client-side obfuscation for security. Ensure robust server-side hashing and HTTPS enforcement.",
            'technical_fix': "Always use strong server-side hashing (Argon2/BCrypt) and enforce TLS for all authentication traffic."
        })

    return results
