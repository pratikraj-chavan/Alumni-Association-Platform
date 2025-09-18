from fastapi import FastAPI, Depends,HTTPException,Request
from fastapi.responses import JSONResponse
from jose import JWTError,jwt
from auth import SECRET_KEY,ALGORITHM
from sqlalchemy.future import select
from schemas import UserCreate, UserLogin, UserResponse, TokenResponse
from models import User
from database import Base, get_db,engine
from auth import hash_password, verify_password, create_access_token
from sqlalchemy.ext.asyncio import AsyncSession

app=FastAPI()

@app.middleware("http")
async def jwt_middleware(request: Request, call_next):
    # Skip auth for register, login, docs
    if request.url.path in ["/login", "/register", "/docs", "/openapi.json"]:
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
async def register_user(user:UserCreate,db:AsyncSession=Depends(get_db)):
    db_user=User(username=user.username, email=user.email, password=hash_password(user.password))
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user

@app.post("/login",response_model=TokenResponse)
async def login_user(user:UserLogin, db:AsyncSession=Depends(get_db)):
    result=await db.execute(select(User).where(User.email==user.email))
    db_user=result.scalars().first()
    if not db_user or not verify_password(user.password,db_user.password):
        raise HTTPException(status_code=401, detail="Invalid Credentials")
    token=create_access_token({"sub":db_user.email})
    return {"access_token":token, "token_type":"bearer"}

@app.get("/user",response_model=list[UserResponse])
async def get_users(db:AsyncSession=Depends(get_db)):
    result=await db.execute(select(User))
    users=result.scalars().all()
    return users

@app.get("/user/{id}",response_model=UserResponse)
async def get_user(id:int, db:AsyncSession=Depends(get_db)):
    result=await db.get(User,id)
    if not result:
        raise HTTPException(status_code=404, detail="User not found")
    return result

@app.get("/me")
async def get_me(request:Request):
    return {"logged_in_as":request.state.user}
