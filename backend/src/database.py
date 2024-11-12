from .model import Base
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import (Column, ForeignKey, Integer, String, Table, Text,
                        create_engine)

engine = create_engine("sqlite:///news_database.db", echo=True)

Base.metadata.create_all(engine)

Session = sessionmaker(bind=engine)