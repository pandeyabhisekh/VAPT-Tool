import logging
import os
from datetime import datetime

class Logger:
    def __init__(self, name="vapt_tool", log_dir="logs"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        # Console Handler
        c_handler = logging.StreamHandler()
        c_handler.setLevel(logging.INFO)
        c_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        c_handler.setFormatter(c_format)
        
        # File Handler
        log_file = os.path.join(log_dir, f"{datetime.now().strftime('%Y-%m-%d')}.log")
        f_handler = logging.FileHandler(log_file)
        f_handler.setLevel(logging.DEBUG)
        f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        f_handler.setFormatter(f_format)
        
        # Add handlers to the logger
        if not self.logger.handlers:
            self.logger.addHandler(c_handler)
            self.logger.addHandler(f_handler)

    def get_logger(self):
        return self.logger

# Global logger instance
logger = Logger().get_logger()
