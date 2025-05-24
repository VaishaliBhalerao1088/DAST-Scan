from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import timedelta

from stackguardian.stackguardian.core.database import get_db
from stackguardian.stackguardian.schemas.user import UserCreate, User as UserSchema, Token
from stackguardian.stackguardian.models.user import User as UserModel
from stackguardian.stackguardian.core.security import create_access_token, get_password_hash, verify_password
from stackguardian.stackguardian.api.deps import get_current_user
from stackguardian.stackguardian.core.config import settings

router = APIRouter()

@router.post("/register", response_model=UserSchema, status_code=status.HTTP_201_CREATED)
async def register_user(user_in: UserCreate, db: Session = Depends(get_db)):
    db_user_by_username = db.query(UserModel).filter(UserModel.username == user_in.username).first()
    if db_user_by_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )
    db_user_by_email = db.query(UserModel).filter(UserModel.email == user_in.email).first()
    if db_user_by_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )
    
    hashed_password = get_password_hash(user_in.password)
    db_user = UserModel(
        username=user_in.username,
        email=user_in.email,
        hashed_password=hashed_password,
        role=user_in.role,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

from fastapi.security import OAuth2PasswordRequestForm

@router.post("/login", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/me", response_model=UserSchema)
async def read_users_me(current_user: UserModel = Depends(get_current_user)):
    return current_user
