import os
import sys
import threading
import logging
import logging.handlers
try:
    import coloredlogs
except ImportError:
    print("An error occurred while importing coloredlogs, output will be plain")
try:
    from cStringIO import StringIO
except ImportError:
    from io import StringIO


class ListHandler(logging.Handler):
    def __init__(self, buffer_size):
        logging.Handler.__init__(self)
        self.log_list = []
        self.buffer_size = buffer_size

    def emit(self, record: logging.LogRecord):
        if len(self.log_list) >= self.buffer_size:
            self.log_list.pop(0)
        self.log_list.append([record.levelname.lower(), self.format(record)])

    def get_log(self):
        log = self.log_list
        self.log_list = []
        return log


def create_console_logger(name, stream=None, level=logging.INFO, colorized=True):
    if "coloredlogs" in sys.modules and colorized:
        if stream is None:
            stream = sys.stdout
        logger = logging.getLogger(name)
        coloredlogs.install(
            level=level,
            stream=stream,
            logger=logger,
            fmt="[%(asctime)s] : %(levelname)s : %(message)s ",
        )
    else:
        if stream is None:
            handler = logging.StreamHandler(sys.stdout)
        else:
            handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.Formatter("[%(asctime)s] : %(levelname)s : %(message)s "))
        logger = logging.getLogger(name)
        logger.addHandler(handler)
        logger.setLevel(level)
    return logger


def create_rotating_logger(name, filename, level=logging.INFO, max_bytes=1024*1024*16, backup_count=3):
    handler = logging.handlers.RotatingFileHandler(filename, max_bytes, backup_count, encoding="utf8")
    handler.setFormatter(logging.Formatter("[%(asctime)s] : %(levelname)s : %(message)s "))
    logger = logging.getLogger(name)
    logger.addHandler(handler)
    logger.setLevel(level)
    return logger


def create_online_logger(name, level=logging.INFO, max_buffer_line=1024):
    handler = ListHandler(max_buffer_line)
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(message)s "))
    logger = logging.getLogger(name)
    logger.addHandler(handler)
    logger.setLevel(level)
    _online_handlers[name] = handler
    return logger


def get_online_log(name):
    global _online_handlers
    return _online_handlers[name].get_log()


_online_handlers = {}
default_logger = create_console_logger("default_logger", colorized=True)
default_online_logger = create_online_logger("default_online_logger")
