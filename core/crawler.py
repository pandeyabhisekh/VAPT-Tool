from bs4 import BeautifulSoup
from utils.logger import logger
from utils.helpers import is_valid_url, get_base_domain, normalize_url, safe_request
from collections import deque

class Crawler:
    def __init__(self, target_url, session=None, max_depth=2):
        self.target_url = target_url
        self.session = session
        self.max_depth = max_depth
        self.base_domain = get_base_domain(target_url)
        self.visited = set()
        self.to_visit = deque([(target_url, 0)])
        self.internal_links = set()

    def crawl(self):
        logger.info(f"Starting crawl of {self.target_url}")
        
        while self.to_visit:
            url, depth = self.to_visit.popleft()
            
            if url in self.visited or depth > self.max_depth:
                continue
                
            self.visited.add(url)
            
            try:
                if self.session:
                    response = self.session.get(url, timeout=10)
                else:
                    response = safe_request('GET', url)
                    
                if response and response.status_code == 200:
                    self.internal_links.add(url)
                    self._extract_links(response.text, url, depth)
            except Exception as e:
                logger.error(f"Error crawling {url}: {e}")

        logger.info(f"Crawl completed. Found {len(self.internal_links)} internal links.")
        return list(self.internal_links)

    def _extract_links(self, html_content, current_url, current_depth):
        soup = BeautifulSoup(html_content, 'html.parser')
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            full_url = normalize_url(current_url, href)
            
            if is_valid_url(full_url) and get_base_domain(full_url) == self.base_domain:
                if full_url not in self.visited:
                    self.to_visit.append((full_url, current_depth + 1))
