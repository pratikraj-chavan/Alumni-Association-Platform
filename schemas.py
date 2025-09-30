from pydantic import BaseModel, StringConstraints
from typing import Annotated, Optional

class UserCreate(BaseModel):
    username:str
    email:str
    password:str
    # mobNo:Optional[Annotated[str, StringConstraints(pattern=r'^\+?[1-9]\d{9,14}$')]]=None

class UserLogin(BaseModel):
    email:str
    password:str

class UserResponse(BaseModel):
    id:int
    username:str
    email:str

class UserUpdateResponse(BaseModel):
    email:str
    username:str


class TokenResponse(BaseModel):
    access_token:str
    token_type:str

