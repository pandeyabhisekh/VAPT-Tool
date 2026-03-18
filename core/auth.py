import requests
from utils.logger import logger
from utils.helpers import safe_request

class AuthHandler:
    def __init__(self, target_url, username=None, password=None, headers=None, cookies=None):
        self.target_url = target_url
        self.username = username
        self.password = password
        self.headers = headers or {}
        self.session = requests.Session()
        
        if cookies:
            self.session.cookies.update(cookies)
            
        if self.headers:
            self.session.headers.update(self.headers)

    def login(self, login_url, data_fields):
        """
        data_fields: dictionary like {'user_field': 'username', 'pass_field': 'password'}
        """
        if not self.username or not self.password:
            logger.info("No credentials provided, skipping login.")
            return False
            
        payload = {
            data_fields.get('user_field', 'username'): self.username,
            data_fields.get('pass_field', 'password'): self.password
        }
        
        try:
            response = self.session.post(login_url, data=payload, timeout=10)
            if response.status_code == 200:
                logger.info(f"Login successful for {self.username}")
                return True
            else:
                logger.warning(f"Login failed for {self.username}. Status code: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Error during login: {e}")
            return False

    def get_session(self):
        return self.session

    def check_auth_status(self, check_url):
        response = safe_request('GET', check_url, session=self.session)
        if response and response.status_code == 200:
            return True
        return False
