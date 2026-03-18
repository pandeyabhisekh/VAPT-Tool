import concurrent.futures
from core.crawler import Crawler
from core.auth import AuthHandler
from modules import xss, sqli, headers, iis_checks, dir_bruteforce
from integrations import nmap_scan
from utils.logger import logger
from config import config

class Scanner:
    def __init__(self, target_url, username=None, password=None, extra_headers=None, extra_cookies=None):
        self.target_url = target_url
        self.auth = AuthHandler(target_url, username, password, extra_headers, extra_cookies)
        self.session = self.auth.get_session()
        self.results = []
        self.vulnerabilities = []

    def run_scan(self):
        logger.info(f"Starting full VAPT scan on {self.target_url}")
        
        # 1. Nmap Scan (Infrastructure)
        nmap_results = nmap_scan.scan(self.target_url)
        self.vulnerabilities.extend(nmap_results)
        
        # 2. Crawl to find pages
        crawler = Crawler(self.target_url, session=self.session)
        links = crawler.crawl()
        
        # 3. Run modules on discovered links using multi-threading
        with concurrent.futures.ThreadPoolExecutor(max_workers=config.MAX_THREADS) as executor:
            future_to_url = {executor.submit(self._scan_url, url): url for url in links}
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    vulns = future.result()
                    if vulns:
                        self.vulnerabilities.extend(vulns)
                except Exception as exc:
                    logger.error(f"{url} generated an exception: {exc}")
                    
        logger.info(f"Scan completed. Total vulnerabilities found: {len(self.vulnerabilities)}")
        return self.vulnerabilities

    def _scan_url(self, url):
        """Run all vulnerability modules for a single URL"""
        logger.info(f"Scanning URL: {url}")
        url_vulns = []
        
        # Run modules
        url_vulns.extend(headers.scan(url, self.session))
        url_vulns.extend(iis_checks.scan(url, self.session))
        url_vulns.extend(xss.scan(url, self.session))
        url_vulns.extend(sqli.scan(url, self.session))
        url_vulns.extend(dir_bruteforce.scan(url, self.session))
        
        return url_vulns
