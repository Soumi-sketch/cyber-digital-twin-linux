import logging
import os

from logging.handlers import RotatingFileHandler


LOG_DIR = "/var/log/cyber-digital-twin"

APP_LOG = os.path.join(LOG_DIR, "application.log")
SECURITY_LOG = os.path.join(LOG_DIR, "security.log")

LOG_FORMAT = (
    "%(asctime)s | %(levelname)s | "
    "%(name)s | %(message)s"
)

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


class SecureRotatingFileHandler(RotatingFileHandler):
    def _open(self):
        stream = super()._open()
        os.chmod(self.baseFilename, 0o640)
        return stream

def create_handler(log_file):

    handler = SecureRotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8"
    )

    handler.setLevel(logging.INFO)

    formatter = logging.Formatter(
        LOG_FORMAT,
        datefmt=DATE_FORMAT
    )

    handler.setFormatter(formatter)

    return handler


def configure_logging():

    os.makedirs(
        LOG_DIR,
        mode=0o750,
        exist_ok=True
    )

    app_logger = logging.getLogger("cyber_twin")
    app_logger.setLevel(logging.INFO)
    app_logger.propagate = False

    security_logger = logging.getLogger(
        "cyber_twin.security"
    )

    security_logger.setLevel(logging.INFO)
    security_logger.propagate = False

    if not app_logger.handlers:
        app_logger.addHandler(
            create_handler(APP_LOG)
        )

    if not security_logger.handlers:
        security_logger.addHandler(
            create_handler(SECURITY_LOG)
        )

    return app_logger, security_logger


def get_app_logger():
    return logging.getLogger("cyber_twin")


def get_security_logger():
    return logging.getLogger("cyber_twin.security")
