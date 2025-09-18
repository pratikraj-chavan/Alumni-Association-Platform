from pydantic import BaseModel
from typing import Optional

class UserCreate(BaseModel):
    username:str
    email:str
    password:str

class UserLogin(BaseModel):
    email:str
    password:str

class UserResponse(BaseModel):
    id:int
    username:str
    email:str

class TokenResponse(BaseModel):
    access_token:str
    token_type:str

