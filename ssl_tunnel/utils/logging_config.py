# logging_config.py

import logging
from logging.handlers import RotatingFileHandler
import sys

def setup_logging():
    try:
        # Log file path and format setup
        log_file = '/var/log/ssl-tunnel.log'
        log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        file_handler = RotatingFileHandler(log_file, maxBytes=1048576, backupCount=5)
        file_handler.setFormatter(log_formatter)

        logger = logging.getLogger('ssl-tunnel')
        logger.setLevel(logging.INFO)
        logger.addHandler(file_handler)

        return logger
    except Exception as e:
        sys.exit(f'❌ Log setup error: {e}')

# Global logger instance
logger = setup_logging()

def log(message, log_level='info', to_log=True, console=True):
    if console:
        print(message)
    if to_log:
        loggers = {
            'info': logger.info,
            'warning': logger.warning,
            'error': logger.error,
            'critical': logger.critical,
            'debug': logger.debug,
        }
        loggers.get(log_level.lower(), logger.info)(message)
