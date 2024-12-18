import logging
from logging.handlers import RotatingFileHandler
class Logger:
    def __new__(cls, name: str):
        if name in cls._loggers:
            return cls._loggers[name]
        instance = super().__new__(cls)
        instance._initialize(name)
        cls.loggers[name] = instance
        return instance

    def _initialize(self, name: str):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)

        if not self.logger.hasHandlers():
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )

            stream_handler = logging.StreamHandler()
            stream_handler.setLevel(logging.INFO)
            stream_handler.setFormatter(formatter)
            self.logger.addHandler(stream_handler)

            file_handler = logging.FileHandler("app.log")
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

            rotating_file_handler = RotatingFileHandler(
                "app_rotating.log", maxBytes=5 * 1024 * 1024, backupCount=3
            )
            rotating_file_handler.setLevel(logging.ERROR)
            rotating_file_handler.setFormatter(formatter)
            self.logger.addHandler(rotating_file_handler)
    
    def log_info(self, message: str):
        self.logger.info(message)

    def log_debug(self, message: str):
        self.logger.debug(message)

    def log_warning(self, message: str):
        self.logger.warning(message)

    def log_error(self, message: str):
        self.logger.error(message)

    def log_critical(self, message: str):
        self.logger.critical(message)
