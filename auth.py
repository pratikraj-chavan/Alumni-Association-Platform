from datetime import datetime, timedelta
from jose import JWTError,jwt
from passlib.context import CryptContext

SECRET_KEY = "secret_key21"
ALGORITHM = "HS256"
ACCESS_TOKEN_TIME = 15

pwd_context = CryptContext(schemes=['bcrypt'], deprecated="auto")

def hash_password(password:str) ->str:
    return pwd_context.hash(password)

def verify_password(plain_password,hashed_password)->bool:
    return pwd_context.verify(plain_password,hashed_password)

def create_access_token(data:dict,expiry_time:int=ACCESS_TOKEN_TIME):
    to_encode=data.copy()
    expire=datetime.utcnow()+timedelta(minutes=expiry_time)
    to_encode.update({"exp":expire})
    return jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM)
