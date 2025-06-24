import { BackendTemplate } from '../types';

export const fastApiTemplate: BackendTemplate = {
  id: 'fastapi-py',
  name: 'FastAPI + Python',
  description: 'Modern FastAPI server with async support, automatic OpenAPI docs, dependency injection, and SQLAlchemy',
  framework: 'fastapi',
  language: 'python',
  version: '1.0.0',
  tags: ['fastapi', 'python', 'async', 'openapi', 'pydantic', 'sqlalchemy', 'rest-api'],
  dependencies: {
    fastapi: '^0.104.1',
    uvicorn: '^0.24.0',
    pydantic: '^2.5.0',
    'pydantic[email]': '^2.5.0',
    sqlalchemy: '^2.0.23',
    alembic: '^1.13.0',
    'python-jose[cryptography]': '^3.3.0',
    'python-multipart': '^0.0.6',
    'python-dotenv': '^1.0.0',
    psycopg2: '^2.9.9',
    redis: '^5.0.1',
    celery: '^5.3.4',
    httpx: '^0.25.2',
    'slowapi': '^0.1.9'
  },
  devDependencies: {
    pytest: '^7.4.3',
    'pytest-asyncio': '^0.21.1',
    'pytest-cov': '^4.1.0',
    black: '^23.11.0',
    isort: '^5.12.0',
    mypy: '^1.7.1',
    flake8: '^6.1.0',
    'pre-commit': '^3.6.0'
  },
  files: {
    'requirements.txt': `fastapi==0.104.1
uvicorn[standard]==0.24.0
pydantic[email]==2.5.0
sqlalchemy==2.0.23
alembic==1.13.0
python-jose[cryptography]==3.3.0
python-multipart==0.0.6
python-dotenv==1.0.0
psycopg2==2.9.9
redis==5.0.1
celery==5.3.4
httpx==0.25.2
slowapi==0.1.9`,
    'requirements-dev.txt': `pytest==7.4.3
pytest-asyncio==0.21.1
pytest-cov==4.1.0
black==23.11.0
isort==5.12.0
mypy==1.7.1
flake8==6.1.0
pre-commit==3.6.0`,
    'main.py': `"""
FastAPI Application Entry Point
"""
import uvicorn
from app.core.config import settings

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="debug" if settings.DEBUG else "info",
    )`,
    'app/__init__.py': '',
    'app/main.py': `"""
FastAPI Application Main Module
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import time
import logging

from app.api.api_v1.api import api_router
from app.core.config import settings
from app.db.init_db import init_db

# Configure logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)

# FastAPI app instance
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=settings.DESCRIPTION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json" if settings.DEBUG else None,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
)

# Rate limiting error handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    
    # Log request
    logger.info(
        f"{request.method} {request.url.path} - "
        f"{response.status_code} - {process_time:.4f}s"
    )
    return response

# Include API routes
app.include_router(api_router, prefix=settings.API_V1_STR)

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    logger.info("Starting up...")
    await init_db()
    logger.info("Database initialized")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("Shutting down...")

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": f"Welcome to {settings.PROJECT_NAME}",
        "version": settings.VERSION,
        "docs": "/docs" if settings.DEBUG else "Documentation disabled in production",
    }

@app.get("/health")
@limiter.limit("100/minute")
async def health_check(request: Request):
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "version": settings.VERSION,
    }`,
    'app/core/__init__.py': '',
    'app/core/config.py': `"""
Application Configuration
"""
import os
from typing import List, Optional
from pydantic import BaseSettings, AnyHttpUrl, validator

class Settings(BaseSettings):
    # Basic app settings
    PROJECT_NAME: str = "{{projectName}}"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "FastAPI application with async support and auto-docs"
    API_V1_STR: str = "/api/v1"
    
    # Server settings
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False
    
    # Security settings
    SECRET_KEY: str = "your-secret-key-change-this-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALGORITHM: str = "HS256"
    
    # Database settings
    DATABASE_URL: Optional[str] = None
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_DB: str = "{{projectName}}"
    POSTGRES_PORT: str = "5432"
    
    # Redis settings
    REDIS_URL: str = "redis://localhost:6379"
    
    # CORS settings
    ALLOWED_ORIGINS: List[AnyHttpUrl] = ["http://localhost:3000", "http://localhost:8080"]
    ALLOWED_HOSTS: List[str] = ["localhost", "127.0.0.1"]
    
    # Email settings (for notifications)
    SMTP_TLS: bool = True
    SMTP_PORT: Optional[int] = None
    SMTP_HOST: Optional[str] = None
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    EMAILS_FROM_EMAIL: Optional[str] = None
    EMAILS_FROM_NAME: Optional[str] = None
    
    # Celery settings
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/0"
    
    @validator("DATABASE_URL", pre=True)
    def assemble_db_connection(cls, v: Optional[str], values: dict) -> str:
        if isinstance(v, str):
            return v
        return (
            f"postgresql://{values.get('POSTGRES_USER')}:"
            f"{values.get('POSTGRES_PASSWORD')}@"
            f"{values.get('POSTGRES_SERVER')}:"
            f"{values.get('POSTGRES_PORT')}/"
            f"{values.get('POSTGRES_DB')}"
        )
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()`,
    'app/core/security.py': `"""
Security utilities for authentication and authorization
"""
from datetime import datetime, timedelta
from typing import Optional, Union, Any
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import HTTPException, status

from app.core.config import settings

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_access_token(
    subject: Union[str, Any], expires_delta: Optional[timedelta] = None
) -> str:
    """Create JWT access token"""
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    
    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt

def create_refresh_token(subject: Union[str, Any]) -> str:
    """Create JWT refresh token"""
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode = {"exp": expire, "sub": str(subject), "type": "refresh"}
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt

def verify_token(token: str) -> Optional[str]:
    """Verify JWT token and return subject"""
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        subject: str = payload.get("sub")
        if subject is None:
            return None
        return subject
    except JWTError:
        return None

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Get password hash"""
    return pwd_context.hash(password)`,
    'app/core/deps.py': `"""
Dependency injection utilities
"""
from typing import Generator, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.core.security import verify_token
from app.models.user import User
from app.crud.user import user as user_crud

# Security scheme
security = HTTPBearer()

def get_db() -> Generator:
    """Database session dependency"""
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """Get current authenticated user"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    token = credentials.credentials
    username = verify_token(token)
    if username is None:
        raise credentials_exception
    
    user = user_crud.get_by_email(db, email=username)
    if user is None:
        raise credentials_exception
    
    return user

async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current active user"""
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

async def get_current_superuser(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current superuser"""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=400, detail="The user doesn't have enough privileges"
        )
    return current_user`,
    'app/db/__init__.py': '',
    'app/db/base.py': `"""
Database base class and imports
"""
from app.db.base_class import Base
from app.models.user import User
from app.models.item import Item`,
    'app/db/base_class.py': `"""
SQLAlchemy Base Class
"""
from typing import Any
from sqlalchemy.ext.declarative import as_declarative, declared_attr

@as_declarative()
class Base:
    id: Any
    __name__: str
    
    # Generate tablename automatically
    @declared_attr
    def __tablename__(cls) -> str:
        return cls.__name__.lower()`,
    'app/db/session.py': `"""
Database session configuration
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings

# Create SQLAlchemy engine
engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

# Create SessionLocal class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)`,
    'app/db/init_db.py': `"""
Database initialization
"""
import logging
from sqlalchemy.orm import Session

from app.db.session import SessionLocal, engine
from app.db.base import Base
from app.crud.user import user as user_crud
from app.schemas.user import UserCreate
from app.core.config import settings

logger = logging.getLogger(__name__)

async def init_db() -> None:
    """Initialize database with tables and default data"""
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    # Create default superuser if it doesn't exist
    db = SessionLocal()
    try:
        user = user_crud.get_by_email(db, email="admin@example.com")
        if not user:
            user_in = UserCreate(
                email="admin@example.com",
                password="admin123!",
                full_name="Admin User",
                is_superuser=True,
            )
            user = user_crud.create(db, obj_in=user_in)
            logger.info("Created default superuser")
    finally:
        db.close()`,
    'app/models/__init__.py': '',
    'app/models/user.py': `"""
User SQLAlchemy model
"""
from sqlalchemy import Boolean, Column, Integer, String, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.db.base_class import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, index=True)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    items = relationship("Item", back_populates="owner")`,
    'app/models/item.py': `"""
Item SQLAlchemy model
"""
from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.db.base_class import Base

class Item(Base):
    __tablename__ = "items"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True, nullable=False)
    description = Column(Text)
    owner_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    owner = relationship("User", back_populates="items")`,
    'app/schemas/__init__.py': '',
    'app/schemas/user.py': `"""
User Pydantic schemas
"""
from typing import Optional
from pydantic import BaseModel, EmailStr
from datetime import datetime

# Shared properties
class UserBase(BaseModel):
    email: Optional[EmailStr] = None
    is_active: Optional[bool] = True
    is_superuser: Optional[bool] = False
    full_name: Optional[str] = None

# Properties to receive via API on creation
class UserCreate(UserBase):
    email: EmailStr
    password: str

# Properties to receive via API on update
class UserUpdate(UserBase):
    password: Optional[str] = None

class UserInDBBase(UserBase):
    id: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        orm_mode = True

# Additional properties to return via API
class User(UserInDBBase):
    pass

# Additional properties stored in DB
class UserInDB(UserInDBBase):
    hashed_password: str`,
    'app/schemas/item.py': `"""
Item Pydantic schemas
"""
from typing import Optional
from pydantic import BaseModel
from datetime import datetime

# Shared properties
class ItemBase(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None

# Properties to receive on item creation
class ItemCreate(ItemBase):
    title: str

# Properties to receive on item update
class ItemUpdate(ItemBase):
    pass

# Properties shared by models stored in DB
class ItemInDBBase(ItemBase):
    id: int
    title: str
    owner_id: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    class Config:
        orm_mode = True

# Properties to return to client
class Item(ItemInDBBase):
    pass

# Properties stored in DB
class ItemInDB(ItemInDBBase):
    pass`,
    'app/schemas/token.py': `"""
Token Pydantic schemas
"""
from typing import Optional
from pydantic import BaseModel

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class TokenPayload(BaseModel):
    sub: Optional[str] = None

class RefreshToken(BaseModel):
    refresh_token: str`,
    'app/crud/__init__.py': '',
    'app/crud/base.py': `"""
Base CRUD class
"""
from typing import Any, Dict, Generic, List, Optional, Type, TypeVar, Union
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.base_class import Base

ModelType = TypeVar("ModelType", bound=Base)
CreateSchemaType = TypeVar("CreateSchemaType", bound=BaseModel)
UpdateSchemaType = TypeVar("UpdateSchemaType", bound=BaseModel)

class CRUDBase(Generic[ModelType, CreateSchemaType, UpdateSchemaType]):
    def __init__(self, model: Type[ModelType]):
        """
        CRUD object with default methods to Create, Read, Update, Delete (CRUD).
        """
        self.model = model

    def get(self, db: Session, id: Any) -> Optional[ModelType]:
        return db.query(self.model).filter(self.model.id == id).first()

    def get_multi(
        self, db: Session, *, skip: int = 0, limit: int = 100
    ) -> List[ModelType]:
        return db.query(self.model).offset(skip).limit(limit).all()

    def create(self, db: Session, *, obj_in: CreateSchemaType) -> ModelType:
        obj_in_data = jsonable_encoder(obj_in)
        db_obj = self.model(**obj_in_data)
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj

    def update(
        self,
        db: Session,
        *,
        db_obj: ModelType,
        obj_in: Union[UpdateSchemaType, Dict[str, Any]]
    ) -> ModelType:
        obj_data = jsonable_encoder(db_obj)
        if isinstance(obj_in, dict):
            update_data = obj_in
        else:
            update_data = obj_in.dict(exclude_unset=True)
        for field in obj_data:
            if field in update_data:
                setattr(db_obj, field, update_data[field])
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj

    def remove(self, db: Session, *, id: int) -> ModelType:
        obj = db.query(self.model).get(id)
        db.delete(obj)
        db.commit()
        return obj`,
    'app/crud/user.py': `"""
User CRUD operations
"""
from typing import Any, Dict, Optional, Union
from sqlalchemy.orm import Session

from app.core.security import get_password_hash, verify_password
from app.crud.base import CRUDBase
from app.models.user import User
from app.schemas.user import UserCreate, UserUpdate

class CRUDUser(CRUDBase[User, UserCreate, UserUpdate]):
    def get_by_email(self, db: Session, *, email: str) -> Optional[User]:
        return db.query(User).filter(User.email == email).first()

    def create(self, db: Session, *, obj_in: UserCreate) -> User:
        db_obj = User(
            email=obj_in.email,
            hashed_password=get_password_hash(obj_in.password),
            full_name=obj_in.full_name,
            is_superuser=obj_in.is_superuser,
        )
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj

    def update(
        self, db: Session, *, db_obj: User, obj_in: Union[UserUpdate, Dict[str, Any]]
    ) -> User:
        if isinstance(obj_in, dict):
            update_data = obj_in
        else:
            update_data = obj_in.dict(exclude_unset=True)
        if update_data.get("password"):
            hashed_password = get_password_hash(update_data["password"])
            del update_data["password"]
            update_data["hashed_password"] = hashed_password
        return super().update(db, db_obj=db_obj, obj_in=update_data)

    def authenticate(self, db: Session, *, email: str, password: str) -> Optional[User]:
        user = self.get_by_email(db, email=email)
        if not user:
            return None
        if not verify_password(password, user.hashed_password):
            return None
        return user

    def is_active(self, user: User) -> bool:
        return user.is_active

    def is_superuser(self, user: User) -> bool:
        return user.is_superuser

user = CRUDUser(User)`,
    'app/crud/item.py': `"""
Item CRUD operations
"""
from typing import List
from sqlalchemy.orm import Session

from app.crud.base import CRUDBase
from app.models.item import Item
from app.schemas.item import ItemCreate, ItemUpdate

class CRUDItem(CRUDBase[Item, ItemCreate, ItemUpdate]):
    def create_with_owner(
        self, db: Session, *, obj_in: ItemCreate, owner_id: int
    ) -> Item:
        obj_in_data = obj_in.dict()
        db_obj = self.model(**obj_in_data, owner_id=owner_id)
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj

    def get_multi_by_owner(
        self, db: Session, *, owner_id: int, skip: int = 0, limit: int = 100
    ) -> List[Item]:
        return (
            db.query(self.model)
            .filter(Item.owner_id == owner_id)
            .offset(skip)
            .limit(limit)
            .all()
        )

item = CRUDItem(Item)`,
    'app/api/__init__.py': '',
    'app/api/api_v1/__init__.py': '',
    'app/api/api_v1/api.py': `"""
API V1 Router
"""
from fastapi import APIRouter

from app.api.api_v1.endpoints import auth, users, items, utils

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(items.router, prefix="/items", tags=["items"])
api_router.include_router(utils.router, prefix="/utils", tags=["utils"])`,
    'app/api/api_v1/endpoints/__init__.py': '',
    'app/api/api_v1/endpoints/auth.py': `"""
Authentication endpoints
"""
from datetime import timedelta
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core import security
from app.core.config import settings
from app.core.deps import get_db
from app.crud.user import user as user_crud
from app.schemas.token import Token

router = APIRouter()

@router.post("/login", response_model=Token)
def login_access_token(
    db: Session = Depends(get_db), form_data: OAuth2PasswordRequestForm = Depends()
) -> Any:
    """
    OAuth2 compatible token login, get an access token for future requests
    """
    user = user_crud.authenticate(
        db, email=form_data.username, password=form_data.password
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    elif not user_crud.is_active(user):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token = security.create_refresh_token(subject=user.email)
    return {
        "access_token": security.create_access_token(
            user.email, expires_delta=access_token_expires
        ),
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }

@router.post("/refresh", response_model=Token)
def refresh_token(
    refresh_token: str,
    db: Session = Depends(get_db)
) -> Any:
    """
    Refresh access token using refresh token
    """
    email = security.verify_token(refresh_token)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    user = user_crud.get_by_email(db, email=email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    new_refresh_token = security.create_refresh_token(subject=user.email)
    
    return {
        "access_token": security.create_access_token(
            user.email, expires_delta=access_token_expires
        ),
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
    }`,
    'app/api/api_v1/endpoints/users.py': `"""
User management endpoints
"""
from typing import Any, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.deps import get_db, get_current_active_user, get_current_superuser
from app.crud.user import user as user_crud
from app.models.user import User
from app.schemas.user import User as UserSchema, UserCreate, UserUpdate

router = APIRouter()

@router.get("/", response_model=List[UserSchema])
def read_users(
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_superuser),
) -> Any:
    """
    Retrieve users (superuser only)
    """
    users = user_crud.get_multi(db, skip=skip, limit=limit)
    return users

@router.post("/", response_model=UserSchema)
def create_user(
    *,
    db: Session = Depends(get_db),
    user_in: UserCreate,
    current_user: User = Depends(get_current_superuser),
) -> Any:
    """
    Create new user (superuser only)
    """
    user = user_crud.get_by_email(db, email=user_in.email)
    if user:
        raise HTTPException(
            status_code=400,
            detail="The user with this email already exists in the system.",
        )
    user = user_crud.create(db, obj_in=user_in)
    return user

@router.get("/me", response_model=UserSchema)
def read_user_me(
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    Get current user
    """
    return current_user

@router.put("/me", response_model=UserSchema)
def update_user_me(
    *,
    db: Session = Depends(get_db),
    password: str = None,
    full_name: str = None,
    email: str = None,
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    Update own user
    """
    current_user_data = UserUpdate(**current_user.__dict__)
    if password is not None:
        current_user_data.password = password
    if full_name is not None:
        current_user_data.full_name = full_name
    if email is not None:
        current_user_data.email = email
    user = user_crud.update(db, db_obj=current_user, obj_in=current_user_data)
    return user

@router.get("/{user_id}", response_model=UserSchema)
def read_user_by_id(
    user_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> Any:
    """
    Get a specific user by id
    """
    user = user_crud.get(db, id=user_id)
    if user == current_user:
        return user
    if not user_crud.is_superuser(current_user):
        raise HTTPException(
            status_code=400, detail="The user doesn't have enough privileges"
        )
    return user

@router.put("/{user_id}", response_model=UserSchema)
def update_user(
    *,
    db: Session = Depends(get_db),
    user_id: int,
    user_in: UserUpdate,
    current_user: User = Depends(get_current_superuser),
) -> Any:
    """
    Update a user (superuser only)
    """
    user = user_crud.get(db, id=user_id)
    if not user:
        raise HTTPException(
            status_code=404,
            detail="The user with this id does not exist in the system",
        )
    user = user_crud.update(db, db_obj=user, obj_in=user_in)
    return user`,
    'app/api/api_v1/endpoints/items.py': `"""
Item management endpoints
"""
from typing import Any, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.deps import get_db, get_current_active_user
from app.crud.item import item as item_crud
from app.models.user import User
from app.schemas.item import Item, ItemCreate, ItemUpdate

router = APIRouter()

@router.get("/", response_model=List[Item])
def read_items(
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    Retrieve items owned by current user
    """
    items = item_crud.get_multi_by_owner(
        db=db, owner_id=current_user.id, skip=skip, limit=limit
    )
    return items

@router.post("/", response_model=Item)
def create_item(
    *,
    db: Session = Depends(get_db),
    item_in: ItemCreate,
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    Create new item
    """
    item = item_crud.create_with_owner(db=db, obj_in=item_in, owner_id=current_user.id)
    return item

@router.put("/{item_id}", response_model=Item)
def update_item(
    *,
    db: Session = Depends(get_db),
    item_id: int,
    item_in: ItemUpdate,
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    Update an item
    """
    item = item_crud.get(db=db, id=item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    if item.owner_id != current_user.id:
        raise HTTPException(status_code=400, detail="Not enough permissions")
    item = item_crud.update(db=db, db_obj=item, obj_in=item_in)
    return item

@router.get("/{item_id}", response_model=Item)
def read_item(
    *,
    db: Session = Depends(get_db),
    item_id: int,
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    Get item by ID
    """
    item = item_crud.get(db=db, id=item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    if item.owner_id != current_user.id:
        raise HTTPException(status_code=400, detail="Not enough permissions")
    return item

@router.delete("/{item_id}", response_model=Item)
def delete_item(
    *,
    db: Session = Depends(get_db),
    item_id: int,
    current_user: User = Depends(get_current_active_user),
) -> Any:
    """
    Delete an item
    """
    item = item_crud.get(db=db, id=item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    if item.owner_id != current_user.id:
        raise HTTPException(status_code=400, detail="Not enough permissions")
    item = item_crud.remove(db=db, id=item_id)
    return item`,
    'app/api/api_v1/endpoints/utils.py': `"""
Utility endpoints
"""
from typing import Any
from fastapi import APIRouter, Depends
from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import Request

from app.core.config import settings

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

@router.get("/health")
@limiter.limit("100/minute")
def health_check(request: Request) -> Any:
    """
    Health check endpoint
    """
    return {
        "status": "healthy",
        "version": settings.VERSION,
        "project": settings.PROJECT_NAME,
    }

@router.get("/info")
def get_info() -> Any:
    """
    Get application info
    """
    return {
        "project_name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "description": settings.DESCRIPTION,
        "api_version": settings.API_V1_STR,
    }`,
    'app/tests/__init__.py': '',
    'app/tests/conftest.py': `"""
Test configuration and fixtures
"""
import pytest
from typing import Generator
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.core.deps import get_db
from app.db.base import Base
from app.core.config import settings

# Create test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="session")
def db() -> Generator:
    Base.metadata.create_all(bind=engine)
    yield TestingSessionLocal()
    Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="module")
def client() -> Generator:
    with TestClient(app) as c:
        yield c

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db`,
    'app/tests/test_main.py': `"""
Test main application
"""
from fastapi.testclient import TestClient

def test_read_main(client: TestClient):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert "version" in data

def test_health_check(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"`,
    'app/tests/test_auth.py': `"""
Test authentication
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.crud.user import user as user_crud
from app.schemas.user import UserCreate

def test_login(client: TestClient, db: Session):
    # Create test user
    user_in = UserCreate(
        email="test@example.com",
        password="testpass123",
        full_name="Test User"
    )
    user_crud.create(db, obj_in=user_in)
    
    # Test login
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "test@example.com", "password": "testpass123"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"

def test_login_invalid_credentials(client: TestClient):
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "invalid@example.com", "password": "wrongpass"}
    )
    assert response.status_code == 401`,
    '.env.example': `# Application Settings
PROJECT_NAME={{projectName}}
VERSION=1.0.0
DESCRIPTION=FastAPI application with async support and auto-docs
DEBUG=true
HOST=0.0.0.0
PORT=8000

# Security
SECRET_KEY=your-secret-key-change-this-in-production
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
ALGORITHM=HS256

# Database
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/{{projectName}}
POSTGRES_SERVER=localhost
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB={{projectName}}
POSTGRES_PORT=5432

# Redis
REDIS_URL=redis://localhost:6379

# CORS
ALLOWED_ORIGINS=["http://localhost:3000","http://localhost:8080"]
ALLOWED_HOSTS=["localhost","127.0.0.1"]

# Celery
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0

# Email (optional)
SMTP_TLS=true
SMTP_PORT=587
SMTP_HOST=
SMTP_USER=
SMTP_PASSWORD=
EMAILS_FROM_EMAIL=
EMAILS_FROM_NAME=`,
    'alembic.ini': `# A generic, single database configuration.

[alembic]
# path to migration scripts
script_location = alembic

# template used to generate migration files
# file_template = %%(rev)s_%%(slug)s

# sys.path path, will be prepended to sys.path if present.
# defaults to the current working directory.
prepend_sys_path = .

# timezone to use when rendering the date within the migration file
# as well as the filename.
# If specified, requires the python-dateutil library that can be
# installed by adding \`alembic[tz]\` to the pip requirements
# string value is passed to dateutil.tz.gettz()
# leave blank for localtime
# timezone =

# max length of characters to apply to the
# "slug" field
# truncate_slug_length = 40

# set to 'true' to run the environment during
# the 'revision' command, regardless of autogenerate
# revision_environment = false

# set to 'true' to allow .pyc and .pyo files without
# a source .py file to be detected as revisions in the
# versions/ directory
# sourceless = false

# version path separator; As mentioned above, this is the character used to split
# version_locations. The default within new alembic.ini files is "os", which uses
# os.pathsep. If this key is omitted entirely, it falls back to the legacy
# behavior of splitting on spaces and/or commas.
# Valid values for version_path_separator are:
#
# version_path_separator = :
# version_path_separator = ;
# version_path_separator = space
version_path_separator = os

# the output encoding used when revision files
# are written from script.py.mako
# output_encoding = utf-8

sqlalchemy.url = postgresql://postgres:postgres@localhost:5432/{{projectName}}

[post_write_hooks]
# post_write_hooks defines scripts or Python functions that are run
# on newly generated revision scripts.  See the documentation for further
# detail and examples

# format using "black" - use the console_scripts runner, against the "black" entrypoint
# hooks = black
# black.type = console_scripts
# black.entrypoint = black
# black.options = -l 79 REVISION_SCRIPT_FILENAME

# Logging configuration
[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console
qualname =

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S`,
    'alembic/env.py': `from logging.config import fileConfig
from sqlalchemy import engine_from_config
from sqlalchemy import pool
from alembic import context
import os
import sys

# this is the Alembic Config object
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here for 'autogenerate' support
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from app.db.base import Base
target_metadata = Base.metadata

def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()`,
    'alembic/script.py.mako': `"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

"""
from alembic import op
import sqlalchemy as sa
${imports if imports else ""}

# revision identifiers, used by Alembic.
revision = ${repr(up_revision)}
down_revision = ${repr(down_revision)}
branch_labels = ${repr(branch_labels)}
depends_on = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}`,
    'Dockerfile': `FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update \\
    && apt-get install -y --no-install-recommends \\
        postgresql-client \\
        build-essential \\
        libpq-dev \\
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Create non-root user
RUN adduser --disabled-password --gecos '' appuser
RUN chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\
    CMD python -c "import requests; requests.get('http://localhost:8000/health')"

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]`,
    'docker-compose.yml': `version: '3.8'

services:
  web:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://postgres:postgres@db:5432/{{projectName}}
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis
    volumes:
      - .:/app
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

  db:
    image: postgres:15
    environment:
      - POSTGRES_DB={{projectName}}
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

  celery:
    build: .
    command: celery -A app.core.celery worker --loglevel=info
    volumes:
      - .:/app
    environment:
      - DATABASE_URL=postgresql://postgres:postgres@db:5432/{{projectName}}
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis

volumes:
  postgres_data:
  redis_data:`,
    'pyproject.toml': `[tool.black]
line-length = 88
target-version = ['py311']
include = '\\.pyi?$'
extend-exclude = '''
/(
  # directories
  \\.eggs
  | \\.git
  | \\.hg
  | \\.mypy_cache
  | \\.tox
  | \\.venv
  | build
  | dist
)/
'''

[tool.isort]
multi_line_output = 3
include_trailing_comma = true
force_grid_wrap = 0
line_length = 88
known_first_party = ["app"]

[tool.mypy]
python_version = "3.11"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_incomplete_defs = true
check_untyped_defs = true
disallow_untyped_decorators = true
no_implicit_optional = true
warn_redundant_casts = true
warn_unused_ignores = true
warn_no_return = true
warn_unreachable = true
strict_equality = true

[[tool.mypy.overrides]]
module = [
    "sqlalchemy.*",
    "alembic.*",
    "jose.*",
    "passlib.*",
    "slowapi.*",
]
ignore_missing_imports = true

[tool.pytest.ini_options]
minversion = "6.0"
addopts = "-ra -q --strict-markers --strict-config"
testpaths = ["app/tests"]
python_files = ["test_*.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]`,
    'README.md': `# {{projectName}}

FastAPI application with async support, automatic OpenAPI documentation, and comprehensive features.

## Features

- ⚡ **FastAPI** - Modern, fast web framework for building APIs
- 🔄 **Async Support** - Full async/await support throughout the application
- 📚 **Auto Documentation** - Automatic OpenAPI/Swagger documentation
- 🔐 **JWT Authentication** - Secure authentication with access and refresh tokens
- 🗄️ **SQLAlchemy 2.0** - Modern Python SQL toolkit and ORM
- 🔄 **Alembic Migrations** - Database schema versioning
- ✅ **Pydantic V2** - Data validation using Python type annotations
- 🧪 **Pytest** - Comprehensive testing framework
- 🐳 **Docker** - Containerized deployment
- 🔧 **Code Quality** - Black, isort, mypy, flake8 for code formatting and linting
- 📊 **Rate Limiting** - Built-in request rate limiting
- 🔒 **Security** - CORS, trusted hosts, and security headers
- 📝 **Logging** - Structured logging with request tracking

## Quick Start

### Prerequisites

- Python 3.11+
- PostgreSQL
- Redis (optional, for caching and Celery)

### Installation

1. **Create virtual environment:**
   \`\`\`bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\\Scripts\\activate
   \`\`\`

2. **Install dependencies:**
   \`\`\`bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # For development
   \`\`\`

3. **Set up environment variables:**
   \`\`\`bash
   cp .env.example .env
   # Edit .env with your configuration
   \`\`\`

4. **Set up database:**
   \`\`\`bash
   # Create database migration
   alembic revision --autogenerate -m "Initial migration"
   
   # Run migrations
   alembic upgrade head
   \`\`\`

5. **Run the application:**
   \`\`\`bash
   python main.py
   # Or with uvicorn directly:
   uvicorn app.main:app --reload
   \`\`\`

### Docker Setup

1. **Run with Docker Compose:**
   \`\`\`bash
   docker-compose up -d
   \`\`\`

2. **Run database migrations:**
   \`\`\`bash
   docker-compose exec web alembic upgrade head
   \`\`\`

## API Documentation

Once the application is running, visit:

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc
- **OpenAPI JSON:** http://localhost:8000/api/v1/openapi.json

## Development

### Code Quality

\`\`\`bash
# Format code
black .
isort .

# Type checking
mypy .

# Linting
flake8 .

# Run all quality checks
black . && isort . && mypy . && flake8 .
\`\`\`

### Testing

\`\`\`bash
# Run tests
pytest

# Run tests with coverage
pytest --cov=app

# Run specific test file
pytest app/tests/test_auth.py
\`\`\`

### Database Migrations

\`\`\`bash
# Create new migration
alembic revision --autogenerate -m "Add new table"

# Apply migrations
alembic upgrade head

# Downgrade migration
alembic downgrade -1

# View migration history
alembic history
\`\`\`

## Project Structure

\`\`\`
app/
├── api/                 # API routes
│   └── api_v1/
│       ├── api.py      # API router
│       └── endpoints/   # Endpoint modules
├── core/               # Core functionality
│   ├── config.py       # Configuration
│   ├── deps.py         # Dependencies
│   └── security.py     # Authentication/security
├── crud/               # CRUD operations
├── db/                 # Database configuration
├── models/             # SQLAlchemy models
├── schemas/            # Pydantic schemas
└── tests/              # Test files
alembic/                # Database migrations
requirements.txt        # Python dependencies
requirements-dev.txt    # Development dependencies
docker-compose.yml      # Docker compose configuration
Dockerfile             # Docker image configuration
pyproject.toml         # Tool configuration
.env.example           # Environment variables template
\`\`\`

## Authentication

The API uses JWT tokens for authentication:

1. **Login:** POST \`/api/v1/auth/login\` with email/password
2. **Get tokens:** Receive access_token and refresh_token
3. **Use token:** Include in Authorization header: \`Bearer <access_token>\`
4. **Refresh:** POST \`/api/v1/auth/refresh\` with refresh_token

### Default Admin User

- **Email:** admin@example.com
- **Password:** admin123!

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| PROJECT_NAME | Application name | {{projectName}} |
| DEBUG | Enable debug mode | false |
| HOST | Server host | 0.0.0.0 |
| PORT | Server port | 8000 |
| SECRET_KEY | JWT secret key | (required) |
| DATABASE_URL | PostgreSQL connection URL | (required) |
| REDIS_URL | Redis connection URL | redis://localhost:6379 |
| ALLOWED_ORIGINS | CORS allowed origins | ["http://localhost:3000"] |

## Performance Features

- **Async/Await:** Full async support for database and external API calls
- **Connection Pooling:** SQLAlchemy connection pooling for database efficiency
- **Rate Limiting:** Built-in request rate limiting to prevent abuse
- **Caching:** Redis integration for caching frequently accessed data
- **Request Logging:** Comprehensive request/response logging with timing

## Security Features

- **JWT Authentication:** Secure token-based authentication
- **Password Hashing:** bcrypt password hashing
- **CORS Protection:** Configurable CORS policies
- **Rate Limiting:** Request rate limiting per IP
- **Security Headers:** Automatic security headers
- **Input Validation:** Pydantic data validation
- **SQL Injection Prevention:** SQLAlchemy ORM protection

## Deployment

### Production Checklist

- [ ] Set strong SECRET_KEY
- [ ] Configure production database
- [ ] Set DEBUG=false
- [ ] Configure ALLOWED_ORIGINS
- [ ] Set up SSL/TLS
- [ ] Configure logging
- [ ] Set up monitoring
- [ ] Configure backup strategy

### Docker Production

\`\`\`bash
# Build production image
docker build -t {{projectName}} .

# Run with production settings
docker run -p 8000:8000 -e DEBUG=false {{projectName}}
\`\`\`

## Contributing

1. Fork the repository
2. Create feature branch (\`git checkout -b feature/amazing-feature\`)
3. Commit changes (\`git commit -m 'Add amazing feature'\`)
4. Push to branch (\`git push origin feature/amazing-feature\`)
5. Open Pull Request

## License

This project is licensed under the MIT License.`,
    '.gitignore': `# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class

# C extensions
*.so

# Distribution / packaging
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
share/python-wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# PyInstaller
#  Usually these files are written by a python script from a template
#  before PyInstaller builds the exe, so as to inject date/other infos into it.
*.manifest
*.spec

# Installer logs
pip-log.txt
pip-delete-this-directory.txt

# Unit test / coverage reports
htmlcov/
.tox/
.nox/
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
*.py,cover
.hypothesis/
.pytest_cache/
cover/

# Translations
*.mo
*.pot

# Django stuff:
*.log
local_settings.py
db.sqlite3
db.sqlite3-journal

# Flask stuff:
instance/
.webassets-cache

# Scrapy stuff:
.scrapy

# Sphinx documentation
docs/_build/

# PyBuilder
.pybuilder/
target/

# Jupyter Notebook
.ipynb_checkpoints

# IPython
profile_default/
ipython_config.py

# pyenv
#   For a library or package, you might want to ignore these files since the code is
#   intended to run in multiple environments; otherwise, check them in:
# .python-version

# pipenv
#   According to pypa/pipenv#598, it is recommended to include Pipfile.lock in version control.
#   However, in case of collaboration, if having platform-specific dependencies or dependencies
#   having no cross-platform support, pipenv may install dependencies that don't work, or not
#   install all needed dependencies.
#Pipfile.lock

# poetry
#   Similar to Pipfile.lock, it is generally recommended to include poetry.lock in version control.
#   This is especially recommended for binary packages to ensure reproducibility, and is more
#   commonly ignored for libraries.
#   https://python-poetry.org/docs/basic-usage/#commit-your-poetrylock-file-to-version-control
#poetry.lock

# pdm
#   Similar to Pipfile.lock, it is generally recommended to include pdm.lock in version control.
#pdm.lock
#   pdm stores project-wide configurations in .pdm.toml, but it is recommended to not include it
#   in version control.
#   https://pdm.fming.dev/#use-with-ide
.pdm.toml

# PEP 582; used by e.g. github.com/David-OConnor/pyflow and github.com/pdm-project/pdm
__pypackages__/

# Celery stuff
celerybeat-schedule
celerybeat.pid

# SageMath parsed files
*.sage.py

# Environments
.env
.venv
env/
venv/
ENV/
env.bak/
venv.bak/

# Spyder project settings
.spyderproject
.spyproject

# Rope project settings
.ropeproject

# mkdocs documentation
/site

# mypy
.mypy_cache/
.dmypy.json
dmypy.json

# Pyre type checker
.pyre/

# pytype static type analyzer
.pytype/

# Cython debug symbols
cython_debug/

# IDEs
.vscode/
.idea/
*.swp
*.swo

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Test database
test.db
*.db`,
    'Makefile': `.PHONY: help install dev test lint format type-check clean docker-build docker-run

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \\033[36m%-15s\\033[0m %s\\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install dependencies
	pip install -r requirements.txt
	pip install -r requirements-dev.txt

dev: ## Run development server
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test: ## Run tests
	pytest -v

test-cov: ## Run tests with coverage
	pytest --cov=app --cov-report=html --cov-report=term

lint: ## Run linting
	flake8 app

format: ## Format code
	black .
	isort .

type-check: ## Run type checking
	mypy .

quality: format type-check lint ## Run all code quality checks

clean: ## Clean cache files
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .coverage htmlcov/ .pytest_cache/

docker-build: ## Build Docker image
	docker build -t {{projectName}} .

docker-run: ## Run Docker container
	docker run -p 8000:8000 {{projectName}}

docker-compose-up: ## Start services with docker-compose
	docker-compose up -d

docker-compose-down: ## Stop services with docker-compose
	docker-compose down

migrate: ## Run database migrations
	alembic upgrade head

migrate-create: ## Create new migration
	alembic revision --autogenerate -m "$(name)"

migrate-downgrade: ## Downgrade database by one migration
	alembic downgrade -1`
  },
  prompts: [
    {
      type: 'input',
      name: 'projectName',
      message: 'What is your project name?',
      default: 'fastapi-app'
    }
  ],
  postInstall: [
    'python -m venv venv',
    'source venv/bin/activate',
    'pip install -r requirements.txt',
    'pip install -r requirements-dev.txt',
    'cp .env.example .env',
    'echo "✅ FastAPI application created successfully!"',
    'echo ""',
    'echo "📝 Next steps:"',
    'echo "   1. Activate virtual environment: source venv/bin/activate"',
    'echo "   2. Update .env with your database configuration"',
    'echo "   3. Run database migrations: alembic upgrade head"',
    'echo "   4. Start development server: python main.py"',
    'echo "   5. Visit http://localhost:8000/docs for API documentation"',
    'echo ""',
    'echo "🐳 Docker option:"',
    'echo "   docker-compose up -d"',
    'echo ""',
    'echo "🧪 Run tests:"',
    'echo "   pytest"'
  ]
};