import enum
from sqlalchemy import Column, Integer, String, Enum as SQLAlchemyEnum
from stackguardian.stackguardian.core.database import Base

class UserRole(enum.Enum):
    ADMIN = "admin"
    VIEWER = "viewer"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(SQLAlchemyEnum(UserRole), nullable=False, default=UserRole.VIEWER)
