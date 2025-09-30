from pydantic import BaseModel, StringConstraints,EmailStr, validator
from typing import Annotated, Optional,List
from datetime import date
import re


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    name: str
    dob: date
    gender: str
    address: str
    phone: str
    linkedin: Optional[str] = None
    github: Optional[str] = None
    ug_degree: str
    ug_institute: str
    ug_graduation_year: int
    pg_degree: str
    pg_institute: str
    pg_graduation_year: int
    department: str
    prn_no: str
    company: Optional[str] = None
    experience: Optional[float] = None
    position: Optional[str] = None
    skills: Optional[List[str]] = []
    emergency_contact: Optional[str] = None
    job_profile: Optional[str] = None
    profile_picture: Optional[str] = None
    profile_picture: str
    @validator("phone")
    def validate_phone(cls, v):
        pattern = r"^[6-9]\d{9}$"  # starts with 6-9, 10 digits
        if not re.match(pattern, v):
            raise ValueError("Invalid phone number format. Must be a 10-digit Indian number.")
        return v

class UserLogin(BaseModel):
    email:EmailStr
    password:str

class UserResponse(BaseModel):
    id:int
    username:str
    email:str

class UserUpdateResponse(BaseModel):
    name: Optional[str] = None
    dob: Optional[date] = None
    address: Optional[str] = None
    phone: Optional[str] = None
    linkedin: Optional[str] = None
    github: Optional[str] = None
    ug_degree: Optional[str] = None
    ug_institute: Optional[str] = None
    ug_graduation_year: Optional[int] = None
    pg_degree: Optional[str] = None
    pg_institute: Optional[str] = None
    pg_graduation_year: Optional[int] = None
    department: Optional[str] = None
    company: Optional[str] = None
    experience: Optional[float] = None
    position: Optional[str] = None
    skills: Optional[List[str]] = None
    emergency_contact: Optional[str] = None
    job_profile: Optional[str] = None
    profile_picture: Optional[str] = None


class TokenResponse(BaseModel):
    access_token:str
    token_type:str

