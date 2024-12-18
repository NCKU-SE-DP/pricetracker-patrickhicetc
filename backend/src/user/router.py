from fastapi import APIRouter, HTTPException, Query, Depends, status, FastAPI
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from sqlalchemy.orm import Session, sessionmaker
from pydantic import BaseModel, Field, AnyHttpUrl

from ..auth.dependencies import session_opener
from ..auth.service import check_user_password_is_correct, create_access_token, pwd_context, authenticate_user_token
from ..model import User
from .schemas import UserAuthSchema
from ..logger.user_logger import user_logger

router = APIRouter(
    prefix = "/user",
    tags = ["user"],
    responses = {404: {"description": "Not found"}},
)

@router.post("/login")
async def login_for_access_token(
        form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(session_opener)
):
    """login"""
    try:
        user = check_user_password_is_correct(db, form_data.username, form_data.password)
        if not user:
            user_logger.login_failed_for_username()
        access_token = create_access_token(
            data={"sub": str(user.username)}, expires_delta=timedelta(minutes=30)
        )
        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        user_logger.login_failed(str(e))
        raise HTTPException(status_code=500, detail="An unexpected error occurred during login")

@router.post("/register")
def create_user(user: UserAuthSchema, db: Session = Depends(session_opener)):
    """create user"""
    try:
        hashed_password = pwd_context.hash(user.password)
        db_user = User(username=user.username, hashed_password=hashed_password)
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
    except Exception as e:
        user_logger.register_failed(str(e))
        raise HTTPException(status_code=500, detail="An unexpected error occurred during registration")


@router.get("/me")
def read_users_me(user=Depends(authenticate_user_token)):
    try:
        return {"username": user.username}
    except Exception as e:
        user_logger.authenticate_failed(str(e))
        raise HTTPException(status_code=401, detail="User authentication failed")