import logging

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(process)d-%(processName)s - %(filename)s-%(funcName)s[line:%(lineno)d] - %(levelname)s: %(message)s')


def log(name=None, level=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)

    return logger
