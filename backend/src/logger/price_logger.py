from .logger import Logger

class PriceLogger:
    def __init__(self):
        self.logger = Logger("price_logger")

    def no_parameters_provided(self):
        self.logger.log_warning("No parameters provided for category or commodity.")
    
    def no_data(self):
        self.logger.log_info("No data found")
    
    def get_price_failed(self, error: str):
        self.logger.log_error(f"Failed to get price: {error}")
price_logger = PriceLogger()