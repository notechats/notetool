import logging

default_level = logging.INFO

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(process)d-%(processName)s - %(filename)s-%(funcName)s[line:%(lineno)d] - %(levelname)s: %(message)s')


def set_default_level(level):
    global default_level
    default_level = level


def log(name=None, level=default_level):
    logger = logging.getLogger(name)
    logger.setLevel(level)

    return logger
