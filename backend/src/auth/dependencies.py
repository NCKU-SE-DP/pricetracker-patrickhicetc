from sqlalchemy.orm import Session
from ..database import engine

def session_opener():
    session = Session(bind=engine)
    try:
        yield session
    finally:
        session.close()