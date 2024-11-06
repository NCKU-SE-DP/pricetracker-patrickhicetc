import sentry_sdk
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import sessionmaker
from fastapi import FastAPI

from .model import NewsArticle
from .database import engine
from .config import GlobalSettings
from .news.service import get_new
from .news.router import router as news_router
from .user.router import router as user_router
from .price.router import router as price_router


sentry_sdk.init(
    dsn = GlobalSettings().SENTRY_DSN,
    traces_sample_rate = GlobalSettings().TRACES_SAMPLE_RATE,
    profiles_sample_rate = GlobalSettings().PROFILES_SAMPLE_RATE,
)

app = FastAPI()
Scheduler = BackgroundScheduler()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

app.add_middleware(
    CORSMiddleware,  # noqa
    allow_origins=["http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def start_scheduler():
    db = SessionLocal()
    if db.query(NewsArticle).count() == 0:
        # should change into simple factory pattern
        get_new()
    db.close()
    Scheduler.add_job(get_new, "interval", minutes=100)
    Scheduler.start()


@app.on_event("shutdown")
def shutdown_scheduler():
    Scheduler.shutdown()

app.include_router(news_router, prefix = GlobalSettings().FASTAPI_PREFIX)
app.include_router(user_router, prefix = GlobalSettings().FASTAPI_PREFIX)
app.include_router(price_router, prefix = GlobalSettings().FASTAPI_PREFIX)