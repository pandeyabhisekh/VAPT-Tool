import json
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from config import config
from utils.logger import logger

class ReportGenerator:
    def __init__(self, target_url, vulnerabilities):
        self.target_url = target_url
        self.vulnerabilities = vulnerabilities
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.report_name = f"vapt_report_{self.timestamp}"

    def generate_json(self):
        data = {
            "target": self.target_url,
            "timestamp": self.timestamp,
            "vulnerabilities_count": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities
        }
        
        file_path = os.path.join(config.REPORT_DIR, f"{self.report_name}.json")
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)
        logger.info(f"JSON report generated: {file_path}")
        return file_path

    def generate_html(self):
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template('report.html')
        
        html_content = template.render(
            target=self.target_url,
            timestamp=self.timestamp,
            vulnerabilities=self.vulnerabilities
        )
        
        file_path = os.path.join(config.REPORT_DIR, f"{self.report_name}.html")
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        logger.info(f"HTML report generated: {file_path}")
        return file_path
