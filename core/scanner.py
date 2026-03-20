import concurrent.futures
from core.crawler import Crawler
from core.auth import AuthHandler
from modules import xss, sqli, headers, iis_checks, dir_bruteforce, functional, brute_force, fuzzer
from integrations import nmap_scan
from utils.logger import logger
from config import config
import requests
from bs4 import BeautifulSoup
import urllib.parse

class Scanner:
    def __init__(self, target_url, username=None, password=None, extra_headers=None, extra_cookies=None):
        self.target_url = target_url
        self.auth = AuthHandler(target_url, username, password, extra_headers, extra_cookies)
        self.session = self.auth.get_session()
        self.vulnerabilities = []
        self.login_info = {}

    def run_scan(self):
        logger.info(f"Starting Professional VAPT Lifecycle for {self.target_url}")

        # Phase 1: Reconnaissance
        self._run_reconnaissance()

        # Phase 2: Authentication & Brute-Force Testing
        self._handle_authentication_and_brute_force()

        # Phase 3: Crawling and Endpoint Discovery
        links = self._run_crawling()

        # Phase 4: Vulnerability Scanning (on all discovered links)
        self._run_vulnerability_scans(links)

        logger.info(f"Scan completed. Total findings: {len(self.vulnerabilities)}")
        return self.vulnerabilities

    def _run_reconnaissance(self):
        logger.info("[Phase 1] Running Reconnaissance...")
        nmap_results = nmap_scan.scan(self.target_url)
        self.vulnerabilities.extend(nmap_results)

    def _handle_authentication_and_brute_force(self):
        logger.info("[Phase 2] Handling Authentication and Brute-Force Testing...")
        if not self.auth.username:
            logger.info("No credentials provided, skipping authentication and brute-force tests.")
            return

        try:
            resp = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            form = soup.find('form')
            if not form:
                logger.warning("No login form found on the target page.")
                return

            user_field, pass_field, base_payload = self._extract_form_details(form)
            form_url = urllib.parse.urljoin(self.target_url, form.get('action', ''))

            self.login_info = {
                'form_url': form_url,
                'user_field': user_field,
                'pass_field': pass_field,
                'base_payload': base_payload,
                'test_username': self.auth.username
            }

            # Run brute-force and rate-limit tests BEFORE logging in
            brute_force_results = brute_force.scan(self.target_url, session=self.session, login_info=self.login_info)
            self.vulnerabilities.extend(brute_force_results)

            # Check if we should skip login if CAPTCHA was already reported by the module
            if any(v['name'] == 'CAPTCHA Protection Enabled' for v in brute_force_results):
                logger.info("Skipping automated login due to CAPTCHA.")
                return

            # Now, perform the actual login
            login_payload = base_payload.copy()
            login_payload[user_field] = self.auth.username
            login_payload[pass_field] = self.auth.password
            
            # Re-fetch fresh tokens right before login for accuracy
            try:
                fresh_resp = self.session.get(self.target_url, timeout=10)
                fresh_soup = BeautifulSoup(fresh_resp.text, 'html.parser')
                fresh_form = fresh_soup.find('form', id=form.get('id')) or fresh_soup.find('form')
                if fresh_form:
                    for hidden in fresh_form.find_all('input', type='hidden'):
                        name = hidden.get('name')
                        if name: login_payload[name] = hidden.get('value', '')
            except: pass

            auth_resp = self.session.post(form_url, data=login_payload, timeout=10, allow_redirects=True)

            # Intelligent Success Detection
            success_keywords = ['logout', 'signout', 'my account', 'dashboard', 'welcome']
            is_success = any(k in auth_resp.text.lower() for k in success_keywords) or auth_resp.status_code == 302
            
            if is_success:
                logger.info(f"Authentication successful for user '{self.auth.username}'.")
                self.vulnerabilities.append({
                    'name': 'Authentication Successful',
                    'severity': 'Info',
                    'url': form_url,
                    'description': f"Successfully authenticated as user '{self.auth.username}'. The session is now active and will be used for all subsequent scans.",
                    'impact': "Authenticated scanning provides deeper coverage of the application's internal functionality.",
                    'proof_of_concept': f"Redirected to {auth_resp.url} with status {auth_resp.status_code}. Content match: {next((k for k in success_keywords if k in auth_resp.text.lower()), 'N/A')}",
                    'recommendation': "No action required. Authentication is working as expected.",
                    'technical_fix': "N/A"
                })
            else:
                logger.warning(f"Authentication failed for user '{self.auth.username}'.")
                self.vulnerabilities.append({
                    'name': 'Authentication Failed',
                    'severity': 'Info',
                    'url': form_url,
                    'description': f"Automated login failed for user '{self.auth.username}'. The scan will continue in unauthenticated mode.",
                    'impact': "Scanning may miss pages and vulnerabilities that are only accessible to logged-in users.",
                    'proof_of_concept': f"Login POST to {form_url} returned status {auth_resp.status_code} with no success indicators.",
                    'recommendation': "Verify the credentials provided and ensure the login form is compatible with automated testing.",
                    'technical_fix': "N/A"
                })

        except Exception as e:
            logger.error(f"Authentication phase failed: {e}")

    def _extract_form_details(self, form):
        user_field, pass_field = 'username', 'password'
        base_payload = {}
        for inp in form.find_all('input'):
            name = inp.get('name')
            if not name: continue
            if inp.get('type') == 'hidden':
                base_payload[name] = inp.get('value', '')
            if 'user' in name.lower(): user_field = name
            if 'pass' in name.lower(): pass_field = name
        return user_field, pass_field, base_payload

    def _run_crawling(self):
        logger.info("[Phase 3] Starting Crawling and Endpoint Discovery...")
        crawler = Crawler(self.target_url, session=self.session)
        return crawler.crawl()

    def _run_vulnerability_scans(self, links):
        logger.info(f"[Phase 4] Running Vulnerability Scans on {len(links)} discovered links...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=config.MAX_THREADS) as executor:
            future_to_url = {executor.submit(self._scan_url, url): url for url in links}
            for future in concurrent.futures.as_completed(future_to_url):
                try:
                    self.vulnerabilities.extend(future.result())
                except Exception as exc:
                    logger.error(f"URL scan generated an exception: {exc}")

    def _scan_url(self, url):
        logger.info(f"Scanning URL: {url}")
        url_vulns = []
        url_vulns.extend(headers.scan(url, self.session))
        url_vulns.extend(iis_checks.scan(url, self.session))
        url_vulns.extend(xss.scan(url, self.session))
        url_vulns.extend(sqli.scan(url, self.session))
        url_vulns.extend(dir_bruteforce.scan(url, self.session))
        url_vulns.extend(functional.scan(url, self.session))
        url_vulns.extend(fuzzer.scan(url, self.session))
        return url_vulns
