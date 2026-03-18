import os

class Config:
    # Flask Settings
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev_secret_key_vapt_tool_2024')
    
    # Scan Settings
    MAX_THREADS = 10
    REQUEST_TIMEOUT = 10
    DEFAULT_USER_AGENT = "VAPT-Tool-Scanner/1.0"
    
    # Payloads
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "'\"><script>alert(1)</script>"
    ]
    
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1 --",
        "admin' --",
        "' UNION SELECT NULL,NULL,NULL--"
    ]
    
    COMMON_DIRECTORIES = [
        "/admin", "/login", "/config", "/backup", "/.git", "/.env", "/phpinfo.php",
        "/robots.txt", "/wp-admin", "/manage", "/dashboard", "/server-status"
    ]
    
    SECURITY_HEADERS = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    # Paths
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    REPORT_DIR = os.path.join(BASE_DIR, 'reports')
    SCAN_DATA_DIR = os.path.join(BASE_DIR, 'scans')

    @staticmethod
    def init_app():
        if not os.path.exists(Config.REPORT_DIR):
            os.makedirs(Config.REPORT_DIR)
        if not os.path.exists(Config.SCAN_DATA_DIR):
            os.makedirs(Config.SCAN_DATA_DIR)

config = Config()
