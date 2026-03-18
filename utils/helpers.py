from urllib.parse import urlparse, urljoin
import requests
from utils.logger import logger

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def get_base_domain(url):
    try:
        return urlparse(url).netloc
    except:
        return None

def normalize_url(base, link):
    return urljoin(base, link)

def safe_request(method, url, **kwargs):
    try:
        response = requests.request(method, url, timeout=10, **kwargs)
        return response
    except requests.RequestException as e:
        logger.error(f"Error making request to {url}: {e}")
        return None

def extract_forms(html_content):
    # This will be used by modules to find input fields
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html_content, 'html.parser')
    return soup.find_all('form')
