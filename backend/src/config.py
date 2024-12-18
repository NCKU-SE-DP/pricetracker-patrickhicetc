import os
from dotenv import load_dotenv

from pydantic_settings import BaseSettings

dotenv_path = os.path.join(os.path.dirname(__file__), "./.env") 
load_dotenv(dotenv_path)

class Config:

    class GlobalSettings(BaseSettings):
        SENTRY_DSN: str = "https://79ba84419197d3dbaa0fe0968b8a7408@o4508454865993728.ingest.us.sentry.io/4508454875234304"
        TRACES_SAMPLE_RATE: float = 1.0
        PROFILES_SAMPLE_RATE: float = 1.0
        FASTAPI_PREFIX: str = "/api/v1"

    class OpenAI():
        OPENAI_KEY = os.getenv("OPENAI_KEY", "")

    class Anthropic():
        ANTHROPIC_KEY = os.getenv("ANTHROPIC_KEY", "")