from fastapi import APIRouter, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas.auth import (
    LoginInput,
    LoginResponse,
    RegisterInput,
    RegisterResponse,
    VerifyResponse,
)
from app.services.auth import AuthService
from app.services.register import RegisterService

router = APIRouter(prefix="/auth", tags=["auth"])
security = HTTPBearer()


@router.post("/register", response_model=RegisterResponse)
async def create_user(input: RegisterInput, db: AsyncSession = Depends(get_db)):
    svc = RegisterService(db)
    user = await svc.create_user(input)
    return user


@router.post("/login", response_model=LoginResponse)
async def login(input: LoginInput, db: AsyncSession = Depends(get_db)):
    svc = AuthService(db)
    token, expires_in = await svc.authenticate(input.email, input.password)
    return LoginResponse(access_token=token, expires_in=expires_in)


@router.post("/verify", response_model=VerifyResponse)
async def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
):
    svc = AuthService(db)
    result = await svc.verify(credentials.credentials)
    return result


@router.post("/logout", status_code=204)
async def logout(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db),
):
    svc = AuthService(db)
    await svc.logout(credentials.credentials)
