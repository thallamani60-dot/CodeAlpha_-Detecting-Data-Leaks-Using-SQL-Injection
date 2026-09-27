from sqlalchemy import Column,Integer,String,DateTime
from datetime import datetime, timezone
from .database import Base
class User(Base):
    __tablename__="users"
    id=Column(Integer,primary_key=True)
    username=Column(String(80),unique=True,index=True,nullable=False)
    password_hash=Column(String(255),nullable=False)
    email_encrypted=Column(String,nullable=False)
    created_at=Column(DateTime,default=lambda: datetime.now(timezone.utc))
class SecurityEvent(Base):
    __tablename__="security_events"
    id=Column(Integer,primary_key=True)
    source=Column(String(100),nullable=False)
    reason=Column(String(255),nullable=False)
    created_at=Column(DateTime,default=lambda: datetime.now(timezone.utc))
