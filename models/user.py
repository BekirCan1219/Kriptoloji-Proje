from sqlalchemy import Column, Integer, String, DateTime, func
from db import Base  # db.py içinde Base = declarative_base() olmalı

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(16), nullable=False, default="user")  # user/admin
    created_at = Column(DateTime, server_default=func.now())
