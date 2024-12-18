from .logger import Logger

class UserLogger:
    def __init__(self):
        self.logger = Logger("user_logger")
    
    def login_failed_for_username(self):
        self.logger.log_warning("Login failed for username")

    def login_failed(self, error: str):
        self.logger.log_error(f"Login failed: {error}")

    def register_failed(self, error: str):
        self.logger.log_error(f"Register failed: {error}")

    def authenticate_failed(self, error: str):
        self.logger.log_error(f"Authenticate failed: {error}")

user_logger = UserLogger()