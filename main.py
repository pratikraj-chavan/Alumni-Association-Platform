from fastapi import FastAPI, Depends,HTTPException,Request,BackgroundTasks,Query,Body
from fastapi.responses import JSONResponse
from jose import JWTError,jwt
from sqlalchemy import text
from auth import SECRET_KEY,ALGORITHM
from sqlalchemy.future import select
from schemas import UserCreate, UserLogin, UserResponse, TokenResponse,UserUpdateResponse,OTPVerifyRequest,ResetPasswordRequest,ForgotPasswordRequest
from datetime import datetime
from models import User
from database import Base, get_db,engine
from auth import hash_password, verify_password, create_access_token
from sqlalchemy.ext.asyncio import AsyncSession
from utils.otp import generate_otp, get_otp_expiry
from utils.email import send_email
from fastapi.staticfiles import StaticFiles



app=FastAPI()

app.mount("/source", StaticFiles(directory="source"), name="source")


@app.middleware("http")
async def jwt_middleware(request: Request, call_next):
    # Skip auth for register, login, docs
    if request.url.path in ["/login", "/register", "/verify-otp", "/forgot-password", "/reset-password", "/docs", "/openapi.json"]:
        return await call_next(request)

    # Check Authorization header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "Authorization required"})

    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        request.state.user = payload.get("sub")  # store email for later use
    except JWTError:
        return JSONResponse(status_code=401, content={"detail": "Invalid or expired token"})

    return await call_next(request)

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)




@app.post("/register", response_model=UserResponse)
async def register_user(
    user: UserCreate,
     background_tasks: BackgroundTasks, 
    db: AsyncSession = Depends(get_db),
    
):
    # check if email already exists
    result = await db.execute(select(User).where(User.email == user.email))
    existing_user = result.scalars().first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already exists")

    # check if username already exists
    result = await db.execute(select(User).where(User.username == user.username))
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="Username already exists")

    # check if PRN number already exists
    result = await db.execute(select(User).where(User.prn_no == user.prn_no))
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="PRN No already exists")

    
    # ... duplicate checks

    # Generate OTP
    otp = generate_otp()
    otp_expiry = get_otp_expiry()
    db_user = User(
        username=user.username,
        email=user.email,
        password=hash_password(user.password),
        prn_no=user.prn_no,
        name=user.name,
        dob=user.dob,
        gender=user.gender,
        address=user.address,
        phone=user.phone,
        linkedin=user.linkedin,
        github=user.github,
        ug_degree=user.ug_degree,
        ug_institute=user.ug_institute,
        ug_graduation_year=user.ug_graduation_year,
        pg_degree=user.pg_degree,
        pg_institute=user.pg_institute,
        pg_graduation_year=user.pg_graduation_year,
        department=user.department,
        company=user.company,
        experience=user.experience,
        position=user.position,
        skills=user.skills,
        emergency_contact=user.emergency_contact,
        job_profile=user.job_profile,
        profile_picture=user.profile_picture,
        status="inactive",
        is_verified=False,
        otp_code=otp,
        otp_expires_at=otp_expiry
    )

    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)

    background_tasks.add_task(
        send_email, 
        user.email, 
        "Your OTP Code", 
        f"Your OTP is {otp}. It expires in 5 minutes."
    )
    return db_user


@app.post("/verify-otp")
async def verify_otp(payload: OTPVerifyRequest, db: AsyncSession = Depends(get_db)):
    user_id = payload.user_id
    otp_code = payload.otp_code    
    result = await db.get(User, user_id)
    if not result:
        raise HTTPException(status_code=404, detail="User not found")

    # Check OTP & expiry
    now_ts = int(datetime.utcnow().timestamp())
    if result.otp_code != otp_code or result.otp_expires_at < now_ts:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    elif result.otp_expires_at < now_ts:
        raise HTTPException(status_code=400, detail="expired OTP")

    # Mark user as verified
    result.is_verified = True
    result.otp_code = None
    result.otp_expires_at = None
    result.status = "active"  # optional
    await db.commit()
    await db.refresh(result)

    return {"message": "User verified successfully. Pending for the admin approval"}
async def get_current_admin(request: Request, db: AsyncSession = Depends(get_db)):
    email = request.state.user
    user = (await db.execute(select(User).where(User.email == email))).scalars().first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

@app.post("/register-admin")
async def register_admin(user: UserCreate, current_user: User = Depends(get_current_admin), db: AsyncSession = Depends(get_db)):
    db_user = User(
        username=user.username,
        email=user.email,
        password=hash_password(user.password),
        is_admin=True
        # ... other fields
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return {"message": "Admin created successfully"}


@app.post("/admin/verify_user/{user_id}")
async def admin_verify_user(
    user_id: int, 
    current_admin: User = Depends(get_current_admin), 
    db: AsyncSession = Depends(get_db)
):
    # Only admin reaches here
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.is_verified:
        raise HTTPException(status_code=400, detail="User has not verified OTP yet")

    user.is_admin_verified = True
    user.status = "active"
    await db.commit()
    await db.refresh(user)

    return {"message": f"User {user.username} verified by admin successfully"}

@app.post("/login",response_model=TokenResponse)
async def login_user(user:UserLogin, db:AsyncSession=Depends(get_db)):
    result = await db.execute(select(User).where(User.email==user.email))
    db_user = result.scalars().first()

    if not db_user or not db_user.is_verified:
        raise HTTPException(status_code=401, detail="OTP not verified")

    if not db_user.is_admin_verified:
        raise HTTPException(status_code=403, detail="Admin approval required")

    if not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token=create_access_token({"sub":db_user.email})
    if token:
        query=text("UPDATE users SET is_active = true where email = :email")
        new=await db.execute(query, {"email":user.email})
        await db.commit()
    return {"access_token":token, "token_type":"bearer"}

@app.get("/user", response_model=list[UserResponse])
async def get_users(
    page: int = Query(1, ge=1, description="Page number (starts from 1)"),
    limit: int = Query(10, ge=1, le=100, description="Number of users per page"),
    db: AsyncSession = Depends(get_db)
):
    offset = (page - 1) * limit
    result = await db.execute(select(User).offset(offset).limit(limit))
    users = result.scalars().all()

    # Also get total count for frontend
    total_count = (await db.execute(text("SELECT COUNT(*) FROM users"))).scalar()

    return {
        "page": page,
        "limit": limit,
        "total_users": total_count,
        "total_pages": (total_count + limit - 1) // limit,  # ceiling division
        "users": users
    }

@app.get("/user/{id}",response_model=UserResponse)
async def get_user(id:int, db:AsyncSession=Depends(get_db)):
    result=await db.get(User,id)
    if not result:
        raise HTTPException(status_code=404, detail="User not found")
    return result

@app.put("/user/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    update_data: UserUpdateResponse,
    db: AsyncSession = Depends(get_db)
):
    # Fetch the existing user
    result = await db.execute(select(User).where(User.id == user_id))
    db_user = result.scalars().first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Only update fields actually sent in the request
    update_dict = update_data.dict(exclude_unset=True)

    for key, value in update_dict.items():
        setattr(db_user, key, value)

    await db.commit()
    await db.refresh(db_user)

    return db_user

@app.get("/me")
async def get_me(request:Request):
    return {"logged_in_as":request.state.user}

@app.get("/user_logout/{id}")
async def logout_user(id:int, db:AsyncSession=Depends(get_db)):
    result=await db.get(User,id)
    if not result:
        raise HTTPException(status_code=404,detail="User not found")
    query=text("UPDATE users SET is_active = false where id = :id")
    new=await db.execute(query, {"id":id})
    await db.commit()
    return "Successfully Logout"

@app.get("/active_status")
async def get_active_status(db:AsyncSession=Depends(get_db)):
    # result=await db.execute(select(User).where (User.is_active == True))
    query=text("SELECT COUNT(*) FROM users where is_active= true")
    results=await db.execute(query)
    count = results.scalar()
    return {"Active Users Count is:":count}



@app.post("/forgot-password")
async def forgot_password(background_tasks: BackgroundTasks, payload: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)):
    email = payload.email 
    # 1. Check if user exists
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # 2. Generate OTP and expiry
    otp = generate_otp()
    otp_expiry = get_otp_expiry()  # reuse existing function, e.g., 5 min from now

    # 3. Store OTP in DB
    user.otp_code = otp
    user.otp_expires_at = otp_expiry
    await db.commit()
    await db.refresh(user)

    # 4. Send OTP via email
    background_tasks.add_task(
        send_email,
        email,
        "Reset Your Password OTP",
        f"Your OTP for password reset is {otp}. It expires in 5 minutes."
    )

    return {"message": "OTP sent to your email."}


@app.post("/reset-password")
async def reset_password(payload: ResetPasswordRequest, db: AsyncSession = Depends(get_db)):
    # 1. Fetch user
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # 2. Verify OTP & expiry
    now_ts = int(datetime.utcnow().timestamp())
    if user.otp_code != payload.otp_code or user.otp_expires_at < now_ts:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    # 3. Update password and clear OTP
    user.password = hash_password(payload.new_password)
    user.otp_code = None
    user.otp_expires_at = None
    await db.commit()
    await db.refresh(user)

    return {"message": "Password reset successfully. You can now login."}
