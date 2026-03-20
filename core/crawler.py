from bs4 import BeautifulSoup
from utils.logger import logger
from utils.helpers import is_valid_url, get_base_domain, normalize_url, safe_request
from collections import deque
import re

class Crawler:
    def __init__(self, target_url, session=None, max_depth=3):
        self.target_url = target_url
        self.session = session
        self.max_depth = max_depth
        self.base_domain = get_base_domain(target_url)
        self.visited = set()
        self.to_visit = deque([(target_url, 0)])
        self.internal_links = set()
        self.interactive_elements = []
        
        # Professional Exclusions
        self.logout_keywords = ['logout', 'signout', 'exit', 'quit', 'log-out', 'sign-out']
        self.static_extensions = ('.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.pdf', '.zip', '.exe')

    def crawl(self):
        logger.info(f"Starting professional authenticated crawler for {self.target_url}")
        
        while self.to_visit:
            url, depth = self.to_visit.popleft()
            
            # 1. Duplicate & Depth Control
            clean_url = url.split('#')[0].split('?')[0].rstrip('/')
            if clean_url in self.visited or depth > self.max_depth:
                continue
                
            # 2. Skip Logout & Static Assets
            if any(k in url.lower() for k in self.logout_keywords):
                logger.info(f"Skipping potential logout URL: {url}")
                continue
            if url.lower().endswith(self.static_extensions):
                continue

            self.visited.add(clean_url)
            logger.info(f"Crawling: {url} (Depth: {depth})")
            
            try:
                if self.session:
                    response = self.session.get(url, timeout=10)
                else:
                    response = safe_request('GET', url)
                    
                if response and response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                    self.internal_links.add(url)
                    self._extract_interactive_elements(response.text, url)
                    self._extract_links(response.text, url, depth)
            except Exception as e:
                logger.error(f"Error crawling {url}: {e}")

        logger.info(f"Discovery complete: {len(self.internal_links)} routes, {len(self.interactive_elements)} elements.")
        return list(self.internal_links)

    def _extract_interactive_elements(self, html_content, current_url):
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Discover forms and their actions as potential endpoints
        for form in soup.find_all('form'):
            action = form.get('action')
            if action:
                full_action_url = normalize_url(current_url, action)
                self._add_to_visit(full_action_url, 1) # Treat as immediate next step
            
            self.interactive_elements.append({
                'tag': 'FORM',
                'id': form.get('id', 'N/A'),
                'class': form.get('class', 'N/A'),
                'text': f"Action: {action} | Method: {form.get('method', 'GET')}",
                'parent_url': current_url
            })

    def _extract_links(self, html_content, current_url, current_depth):
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # 1. Standard A tags
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            full_url = normalize_url(current_url, href)
            self._add_to_visit(full_url, current_depth)

        # 2. Discover endpoints in Scripts (Regex)
        script_urls = re.findall(r'["\'](/[a-zA-Z0-9_\-/]+)["\']', html_content)
        for path in script_urls:
            full_url = normalize_url(current_url, path)
            self._add_to_visit(full_url, current_depth)

    def _add_to_visit(self, full_url, current_depth):
        if is_valid_url(full_url) and get_base_domain(full_url) == self.base_domain:
            clean_url = full_url.split('#')[0].split('?')[0].rstrip('/')
            if clean_url not in self.visited:
                self.to_visit.append((full_url, current_depth + 1))
