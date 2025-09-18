from sqlalchemy import Integer, String, Column
from database import Base


class User(Base):
    __tablename__="users"
    id=Column(Integer, primary_key=True)
    username=Column(String, nullable=False)
    email=Column(String)
    password=Column(String, nullable=False)

