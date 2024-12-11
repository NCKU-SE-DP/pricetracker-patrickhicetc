import os
from dotenv import load_dotenv

from pydantic_settings import BaseSettings

dotenv_path = os.path.join(os.path.dirname(__file__), "./.env") 
load_dotenv(dotenv_path)

class Config:

    class GlobalSettings(BaseSettings):
        SENTRY_DSN: str = "https://4001ffe917ccb261aa0e0c34026dc343@o4505702629834752.ingest.us.sentry.io/4507694792704000"
        TRACES_SAMPLE_RATE: float = 1.0
        PROFILES_SAMPLE_RATE: float = 1.0
        FASTAPI_PREFIX: str = "/api/v1"

    class OpenAI():
        OPENAI_KEY = os.getenv("OPENAI_KEY", "")

    class Anthropic():
        ANTHROPIC_KEY = os.getenv("ANTHROPIC_KEY", "")