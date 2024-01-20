from typing import Annotated

from passlib.context import CryptContext
from sqlalchemy.orm import Session
from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response, Form
from fastapi.responses import HTMLResponse
from starlette.responses import RedirectResponse

from models import Todos, Users
from database import SessionLocal
from starlette import status
from pydantic import BaseModel, Field
from .auth import get_current_user, get_password_hash, verify_password
from fastapi.templating import Jinja2Templates

router = APIRouter(
    prefix='/users',
    tags=['users']
)

templates = Jinja2Templates(directory="templates")
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


class UserVerification(BaseModel):
    username: str
    password: str
    new_password: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/edit-password", response_class=HTMLResponse)
async def get_all_info(request: Request):
    user = await get_current_user(request)
    if user is None:
        return RedirectResponse(url="/auth", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("password.html", {"request": request, "user": user})


@router.post("/edit-password", response_class=HTMLResponse)
async def change_password(request: Request, username: str = Form(...),
                          password: str = Form(...), password2: str = Form(...),
                          db: Session = Depends(get_db)):
    user = await get_current_user(request)
    if user is None:
        return RedirectResponse(url="/auth", status_code=status.HTTP_302_FOUND)
    user_data = db.query(Users).filter(Users.username == username).first()
    msg = "Invalid Username or Password"

    # if not bcrypt_context.verify(user_verify.password, user_data.hashed_password):
    #     raise HTTPException(status_code=401, detail='Error on changing password')
    if user_data is not None:
        if user_data.username == username and verify_password(password, user_data.hashed_password):
            user_data.hashed_password = get_password_hash(password2)
            db.add(user_data)
            db.commit()
            msg = "Password Updated"
    return templates.TemplateResponse("password.html", {"request": request, "user": user, "msg": msg})
