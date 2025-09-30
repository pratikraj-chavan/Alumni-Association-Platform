from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db
from models import User

router = APIRouter()

@router.post("/admin/verify_user/{user_id}")
async def admin_verify_user(user_id: int, db: AsyncSession = Depends(get_db)):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.is_verified:
        raise HTTPException(status_code=400, detail="User has not verified OTP yet")

    user.is_admin_verified = True
    await db.commit()
    await db.refresh(user)

    return {"message": f"User {user.username} verified by admin successfully"}
