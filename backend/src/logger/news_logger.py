from .logger import Logger

class NewsLogger:
    def __init__(self):
        self.logger = Logger("news_logger")
    
    def no_news(self):
        self.logger.log_info("No news articles found.")

    def read_news_failed(self, error: str):
        self.logger.log_error(f"Failed to read news: {error}")
    
    def no_news_for_user(self):
        self.logger.log_info("No news articles for user")

    def fetch_user_news_failed(self, error: str):
        self.logger.log_error(f"Failed to fetch user news: {error}")
        
    def miss_fields(self):
        self.logger.log_warning("Missing fields in article")
    
    def extract_keywords_failed(self):
        self.logger.log_warning(f"Failed to extract keywords")

    def search_news_failed(self, error: str):
        self.logger.log_error(f"Failed to search news: {error}")

    def generate_summary_failed(self, error: str):
        self.logger.log_error(f"Failed to generate summary: {error}")

    def generate_custom_model_summary_failed(self, error: str):
        self.logger.log_error(f"Failed to generate custom model summary: {error}")

    def upvote_article_failed(self, error: str):
        self.logger.log_error(f"Failed to upvote article: {error}")
news_logger = NewsLogger()