# logging_config.py

import logging
from logging.handlers import RotatingFileHandler
import sys


class CustomLogger(logging.Logger):
    def __init__(self, name, log_file='/var/log/ssl-tunnel.log'):
        super().__init__(name)

        try:
            
            file_handler = RotatingFileHandler(log_file, maxBytes=1048576, backupCount=5)
            file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(file_formatter)
            self.addHandler(file_handler)
            
        except Exception as e:
            print(f'❌ Log setup error: {e}')
            sys.exit(1)

    def _log(self, level, msg, console, logfile, args, **kwargs):
        if console:
            print(msg)

        if logfile:
            super()._log(level, msg, args, **kwargs)

    def info(self, msg, console=True, logfile=True, *args, **kwargs):
        self._log(logging.INFO, msg, console, logfile, args, **kwargs)

    def warning(self, msg, console=True, logfile=True, *args, **kwargs):
        self._log(logging.WARNING, msg, console, logfile, args, **kwargs)

    def error(self, msg, console=True, logfile=True, *args, **kwargs):
        self._log(logging.ERROR, msg, console, logfile, args, **kwargs)

    def critical(self, msg, console=True, logfile=True, *args, **kwargs):
        self._log(logging.CRITICAL, msg, console, logfile, args, **kwargs)

    def debug(self, msg, console=True, logfile=True, *args, **kwargs):
        self._log(logging.DEBUG, msg, console, logfile, args, **kwargs)


logger = CustomLogger('ssl-tunnel')
