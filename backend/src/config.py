from pydantic_settings import BaseSettings

class GlobalSettings(BaseSettings):
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        env_prefix = "AUTH_"
        extra = "ignore"

    SENTRY_DSN: str = "https://4001ffe917ccb261aa0e0c34026dc343@o4505702629834752.ingest.us.sentry.io/4507694792704000"
    TRACES_SAMPLE_RATE: float = 1.0
    PROFILES_SAMPLE_RATE: float = 1.0
    FASTAPI_PREFIX: str = "/api/v1"
