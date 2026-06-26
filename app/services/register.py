from fastapi import HTTPException
from passlib.hash import bcrypt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.users import User
from app.schemas.auth import RegisterInput


class RegisterService:
    def __init__(self, db: AsyncSession):
        self.db = db
    async def create_user(self, input: RegisterInput) -> User:
        # 1. Check duplicate
        result = await self.db.execute(
            select(User).where(User.email == input.email)
        )
        if result.scalar_one_or_none():
            raise HTTPException(409, "Email already registered")
        # 2. Hash password
        hashed = bcrypt.hash(input.password)
        # 3. Create user object
        user = User(
            email=input.email,
            password_hash=hashed,
            name=input.name,
            last_name=input.last_name,
            avatar=input.avatar,
        )
        # 4. Persist
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        # 5. Return
        return user
