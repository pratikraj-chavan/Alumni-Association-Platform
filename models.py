from sqlalchemy import Column, Integer, String, Date, Float, Boolean
from sqlalchemy.dialects.postgresql import ARRAY
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    is_admin_verified = Column(Boolean, default=False)  # Admin verified
    is_verified = Column(Boolean, default=False)  # ✅ OTP verification status
    otp_code = Column(String, nullable=True)       # ✅ store OTP temporarily
    otp_expires_at = Column(Integer, nullable=True) # timestamp for expiry

    prn_no = Column(String, unique=True, nullable=False)
    name = Column(String, nullable=False)
    dob = Column(Date, nullable=False)
    gender = Column(String, nullable=False)
    address = Column(String, nullable=False)
    phone = Column(String, nullable=False)
    linkedin = Column(String)
    github = Column(String)

    ug_degree = Column(String, nullable=False)
    ug_institute = Column(String, nullable=False)
    ug_graduation_year = Column(Integer, nullable=False)

    pg_degree = Column(String, nullable=True)
    pg_institute = Column(String, nullable=True)
    pg_graduation_year = Column(Integer, nullable=True)

    department = Column(String, nullable=False)

    company = Column(String, nullable=True)
    experience = Column(Float, nullable=True)
    position = Column(String, nullable=True)
    skills = Column(ARRAY(String), nullable=False)

    emergency_contact = Column(String, nullable=False)
    job_profile = Column(String, nullable=False)
    profile_picture = Column(String, nullable=True)

    status = Column(String, nullable=False, default="inactive")
    is_active = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False)

