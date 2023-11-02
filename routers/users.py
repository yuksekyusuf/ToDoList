from fastapi import APIRouter, Depends, HTTPException, Path
from database import Sessionlocal
from models import Todos, Users
from typing import Annotated
from sqlalchemy.orm import Session
from starlette import status
from pydantic import BaseModel, Field
from .auth import get_current_user
from passlib.context import CryptContext



router = APIRouter(
    prefix='/users',
    tags=['users']
)



def get_db():
    db = Sessionlocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated = 'auto')

class PasswordRequest(BaseModel):
    currentPassword: str
    newPassword: str = Field(min_length=5)


@router.get('/get_user')
async def get_user(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail='authentication failed')
    return db.query(Users).filter(Users.id == user.get('id')).all()

@router.put('/change_password')
async def change_password(user: user_dependency, db: db_dependency, passwordRequest: PasswordRequest):
    if user is None:
        raise HTTPException(status_code=401, detail='authentication failed')
    user_model = db.query(Users).filter(Users.id == user.get('id')).first()
    if not bcrypt_context.verify(passwordRequest.currentPassword, user_model.hashed_password):
        raise HTTPException(status_code=401, detail='Error on password change')
    user_model.hashed_password = bcrypt_context.hash(passwordRequest.newPassword)
    db.add(user_model)
    db.commit()
