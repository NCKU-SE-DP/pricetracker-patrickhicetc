from passlib.context import CryptContext
from fastapi import APIRouter, HTTPException, Query, Depends, status, FastAPI
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from jose import JWTError, jwt

from ..model import User
from .dependencies import session_opener

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/users/login")

def verify(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def check_user_password_is_correct(db, username, password):
    user_record = db.query(User).filter(User.username == username).first()
    if not verify(password, user_record.hashed_password):
        return False
    return user_record

def authenticate_user_token(
    token = Depends(oauth2_scheme),
    db = Depends(session_opener)
):
    payload = jwt.decode(token, '1892dhianiandowqd0n', algorithms=["HS256"])
    return db.query(User).filter(User.username == payload.get("sub")).first()

def create_access_token(data, expires_delta=None):
    """create access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    print(to_encode)
    encoded_jwt = jwt.encode(to_encode, '1892dhianiandowqd0n', algorithm="HS256")
    return encoded_jwt