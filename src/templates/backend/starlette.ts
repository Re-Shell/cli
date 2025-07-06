import { BackendTemplate } from '../../types';

export const starletteTemplate: BackendTemplate = {
  id: 'starlette',
  name: 'Starlette',
  description: 'Lightweight ASGI framework for high-performance asyncio services',
  category: 'backend',
  language: 'python',
  features: [
    'ASGI framework',
    'WebSocket support',
    'GraphQL with Ariadne',
    'Session middleware',
    'CORS middleware',
    'Authentication',
    'Static files',
    'Jinja2 templating',
    'Background tasks',
    'SQLAlchemy integration',
    'pytest testing',
    'Docker support'
  ],
  dependencies: {
    production: {
      'starlette': '^0.37.2',
      'uvicorn[standard]': '^0.30.1',
      'python-multipart': '^0.0.9',
      'jinja2': '^3.1.4',
      'itsdangerous': '^2.2.0',
      'sqlalchemy': '^2.0.30',
      'alembic': '^1.13.1',
      'asyncpg': '^0.29.0',
      'ariadne': '^0.23.0',
      'python-jose[cryptography]': '^3.3.0',
      'passlib[bcrypt]': '^1.7.4',
      'python-dotenv': '^1.0.1',
      'httpx': '^0.27.0',
      'redis': '^5.0.3',
      'aiofiles': '^23.2.1'
    },
    development: {
      'pytest': '^8.2.0',
      'pytest-asyncio': '^0.23.7',
      'pytest-cov': '^5.0.0',
      'black': '^24.4.2',
      'flake8': '^7.0.0',
      'mypy': '^1.10.0',
      'isort': '^5.13.2',
      'pre-commit': '^3.7.1'
    }
  },
  structure: {
    'src/': {
      '__init__.py': '',
      'main.py': `import os
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.routing import Mount
from starlette.staticfiles import StaticFiles

from .config import settings
from .database import database
from .middleware import AuthenticationMiddleware, RequestIdMiddleware
from .routes import api_routes, websocket_routes, graphql_app
from .templates import templates

# Configure middleware
middleware = [
    Middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.ALLOWED_HOSTS
    ),
    Middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    ),
    Middleware(
        SessionMiddleware,
        secret_key=settings.SECRET_KEY,
        https_only=settings.HTTPS_ONLY,
        same_site="lax"
    ),
    Middleware(RequestIdMiddleware),
    Middleware(AuthenticationMiddleware),
]

# Create application
app = Starlette(
    debug=settings.DEBUG,
    middleware=middleware,
    on_startup=[database.connect],
    on_shutdown=[database.disconnect],
)

# Mount routes
app.mount("/api", api_routes, name="api")
app.mount("/ws", websocket_routes, name="websocket")
app.mount("/graphql", graphql_app, name="graphql")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Add template routes
@app.route("/")
async def homepage(request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "title": "Starlette App"}
    )

@app.route("/health")
async def health_check(request):
    return {"status": "healthy", "service": "starlette-backend"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
    )`,
      'config.py': `import os
from typing import List
from functools import lru_cache
from pydantic import BaseSettings, Field

class Settings(BaseSettings):
    # Application
    APP_NAME: str = "Starlette Backend"
    DEBUG: bool = Field(False, env="DEBUG")
    LOG_LEVEL: str = Field("INFO", env="LOG_LEVEL")
    SECRET_KEY: str = Field(..., env="SECRET_KEY")
    
    # Server
    ALLOWED_HOSTS: List[str] = Field(["*"], env="ALLOWED_HOSTS")
    CORS_ORIGINS: List[str] = Field(["http://localhost:3000"], env="CORS_ORIGINS")
    HTTPS_ONLY: bool = Field(False, env="HTTPS_ONLY")
    
    # Database
    DATABASE_URL: str = Field(..., env="DATABASE_URL")
    DATABASE_POOL_SIZE: int = Field(10, env="DATABASE_POOL_SIZE")
    DATABASE_MAX_OVERFLOW: int = Field(20, env="DATABASE_MAX_OVERFLOW")
    
    # Redis
    REDIS_URL: str = Field("redis://localhost:6379", env="REDIS_URL")
    
    # JWT
    JWT_SECRET_KEY: str = Field(..., env="JWT_SECRET_KEY")
    JWT_ALGORITHM: str = Field("HS256", env="JWT_ALGORITHM")
    JWT_EXPIRATION_MINUTES: int = Field(30, env="JWT_EXPIRATION_MINUTES")
    
    # External Services
    SMTP_HOST: str = Field("", env="SMTP_HOST")
    SMTP_PORT: int = Field(587, env="SMTP_PORT")
    SMTP_USERNAME: str = Field("", env="SMTP_USERNAME")
    SMTP_PASSWORD: str = Field("", env="SMTP_PASSWORD")
    
    class Config:
        env_file = ".env"
        case_sensitive = True

@lru_cache()
def get_settings() -> Settings:
    return Settings()

settings = get_settings()`,
      'database.py': `from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from databases import Database

from .config import settings

# Database setup
database = Database(settings.DATABASE_URL)
metadata = MetaData()

# SQLAlchemy setup
engine = create_engine(
    settings.DATABASE_URL,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Dependency
async def get_db():
    async with database.transaction():
        yield database`,
      'models/': {
        '__init__.py': `from .user import User
from .session import Session

__all__ = ["User", "Session"]`,
        'user.py': `from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import relationship

from ..database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")`,
        'session.py': `from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship

from ..database import Base

class Session(Base):
    __tablename__ = "sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="sessions")`
      },
      'schemas/': {
        '__init__.py': `from .user import UserCreate, UserUpdate, UserResponse
from .auth import LoginRequest, LoginResponse, TokenData

__all__ = [
    "UserCreate", "UserUpdate", "UserResponse",
    "LoginRequest", "LoginResponse", "TokenData"
]`,
        'user.py': `from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field

class UserBase(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    password: Optional[str] = Field(None, min_length=8)

class UserResponse(UserBase):
    id: int
    is_active: bool
    is_verified: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        orm_mode = True`,
        'auth.py': `from typing import Optional
from pydantic import BaseModel, EmailStr

class LoginRequest(BaseModel):
    username: str  # Can be email or username
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class TokenData(BaseModel):
    sub: Optional[str] = None
    exp: Optional[int] = None`
      },
      'routes/': {
        '__init__.py': `from starlette.routing import Mount, Route
from starlette.applications import Starlette

from .auth import auth_routes
from .users import user_routes
from .websocket import websocket_endpoint, websocket_routes
from .graphql import graphql_app

# API Routes
api_routes = Starlette(routes=[
    Mount("/auth", app=auth_routes, name="auth"),
    Mount("/users", app=user_routes, name="users"),
])

__all__ = ["api_routes", "websocket_routes", "graphql_app"]`,
        'auth.py': `from starlette.applications import Starlette
from starlette.routing import Route
from starlette.responses import JSONResponse
from starlette.exceptions import HTTPException

from ..schemas import LoginRequest, LoginResponse
from ..services.auth import AuthService
from ..utils.dependencies import get_auth_service

async def login(request):
    data = await request.json()
    login_data = LoginRequest(**data)
    auth_service = get_auth_service()
    
    try:
        token_response = await auth_service.authenticate_user(
            login_data.username,
            login_data.password
        )
        return JSONResponse(token_response.dict())
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

async def logout(request):
    # Get token from header
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    auth_service = get_auth_service()
    await auth_service.revoke_token(token)
    
    return JSONResponse({"message": "Successfully logged out"})

async def refresh(request):
    # Get refresh token from request
    data = await request.json()
    refresh_token = data.get("refresh_token")
    
    if not refresh_token:
        raise HTTPException(status_code=400, detail="Refresh token required")
    
    auth_service = get_auth_service()
    try:
        token_response = await auth_service.refresh_token(refresh_token)
        return JSONResponse(token_response.dict())
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

auth_routes = Starlette(routes=[
    Route("/login", login, methods=["POST"]),
    Route("/logout", logout, methods=["POST"]),
    Route("/refresh", refresh, methods=["POST"]),
])`,
        'users.py': `from starlette.applications import Starlette
from starlette.routing import Route
from starlette.responses import JSONResponse
from starlette.exceptions import HTTPException

from ..schemas import UserCreate, UserUpdate, UserResponse
from ..services.user import UserService
from ..utils.dependencies import get_user_service, require_auth

async def create_user(request):
    data = await request.json()
    user_data = UserCreate(**data)
    user_service = get_user_service()
    
    try:
        user = await user_service.create_user(user_data)
        return JSONResponse(
            UserResponse.from_orm(user).dict(),
            status_code=201
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@require_auth
async def get_current_user(request):
    user = request.state.user
    return JSONResponse(UserResponse.from_orm(user).dict())

@require_auth
async def update_user(request):
    user = request.state.user
    data = await request.json()
    update_data = UserUpdate(**data)
    user_service = get_user_service()
    
    try:
        updated_user = await user_service.update_user(user.id, update_data)
        return JSONResponse(UserResponse.from_orm(updated_user).dict())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@require_auth
async def delete_user(request):
    user = request.state.user
    user_service = get_user_service()
    
    await user_service.delete_user(user.id)
    return JSONResponse({"message": "User deleted successfully"})

user_routes = Starlette(routes=[
    Route("/", create_user, methods=["POST"]),
    Route("/me", get_current_user, methods=["GET"]),
    Route("/me", update_user, methods=["PUT"]),
    Route("/me", delete_user, methods=["DELETE"]),
])`,
        'websocket.py': `from starlette.applications import Starlette
from starlette.routing import WebSocketRoute
from starlette.websockets import WebSocket
from starlette.exceptions import WebSocketException
import json
import asyncio
from typing import Dict, Set

# Connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}
    
    async def connect(self, websocket: WebSocket, room: str = "default"):
        await websocket.accept()
        if room not in self.active_connections:
            self.active_connections[room] = set()
        self.active_connections[room].add(websocket)
    
    def disconnect(self, websocket: WebSocket, room: str = "default"):
        if room in self.active_connections:
            self.active_connections[room].discard(websocket)
            if not self.active_connections[room]:
                del self.active_connections[room]
    
    async def broadcast(self, message: dict, room: str = "default"):
        if room in self.active_connections:
            # Create tasks for all sends
            tasks = []
            for connection in self.active_connections[room]:
                tasks.append(connection.send_json(message))
            # Send to all connections concurrently
            await asyncio.gather(*tasks, return_exceptions=True)

manager = ConnectionManager()

async def websocket_endpoint(websocket: WebSocket):
    room = websocket.query_params.get("room", "default")
    await manager.connect(websocket, room)
    
    try:
        while True:
            # Receive message
            data = await websocket.receive_json()
            
            # Process message based on type
            message_type = data.get("type", "message")
            
            if message_type == "message":
                # Broadcast to room
                await manager.broadcast({
                    "type": "message",
                    "data": data.get("data"),
                    "sender": websocket.client.host,
                    "room": room
                }, room)
            
            elif message_type == "join":
                new_room = data.get("room", "default")
                manager.disconnect(websocket, room)
                await manager.connect(websocket, new_room)
                room = new_room
                
                await websocket.send_json({
                    "type": "room_joined",
                    "room": room
                })
            
            elif message_type == "ping":
                await websocket.send_json({"type": "pong"})
                
    except Exception as e:
        manager.disconnect(websocket, room)
        raise
    finally:
        manager.disconnect(websocket, room)

websocket_routes = Starlette(routes=[
    WebSocketRoute("/", websocket_endpoint),
])`,
        'graphql.py': `from ariadne import QueryType, MutationType, make_executable_schema
from ariadne.asgi import GraphQL
from starlette.authentication import requires

from ..services.user import UserService
from ..utils.dependencies import get_user_service

# Type definitions
type_defs = """
    type Query {
        me: User
        user(id: ID!): User
        users(limit: Int = 10, offset: Int = 0): [User!]!
    }
    
    type Mutation {
        createUser(input: CreateUserInput!): User!
        updateUser(id: ID!, input: UpdateUserInput!): User!
        deleteUser(id: ID!): Boolean!
    }
    
    type User {
        id: ID!
        email: String!
        username: String!
        isActive: Boolean!
        isVerified: Boolean!
        createdAt: String!
        updatedAt: String!
    }
    
    input CreateUserInput {
        email: String!
        username: String!
        password: String!
    }
    
    input UpdateUserInput {
        email: String
        username: String
        password: String
    }
"""

# Resolvers
query = QueryType()
mutation = MutationType()

@query.field("me")
@requires("authenticated")
async def resolve_me(obj, info):
    user = info.context["request"].state.user
    return user

@query.field("user")
async def resolve_user(obj, info, id):
    user_service = get_user_service()
    return await user_service.get_user(int(id))

@query.field("users")
async def resolve_users(obj, info, limit=10, offset=0):
    user_service = get_user_service()
    return await user_service.list_users(limit=limit, offset=offset)

@mutation.field("createUser")
async def resolve_create_user(obj, info, input):
    user_service = get_user_service()
    return await user_service.create_user(input)

@mutation.field("updateUser")
@requires("authenticated")
async def resolve_update_user(obj, info, id, input):
    user_service = get_user_service()
    return await user_service.update_user(int(id), input)

@mutation.field("deleteUser")
@requires("authenticated")
async def resolve_delete_user(obj, info, id):
    user_service = get_user_service()
    await user_service.delete_user(int(id))
    return True

# Create executable schema
schema = make_executable_schema(type_defs, query, mutation)

# Create GraphQL app
graphql_app = GraphQL(schema, debug=True)`
      },
      'services/': {
        '__init__.py': '',
        'auth.py': `from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext

from ..config import settings
from ..database import database
from ..models import User, Session
from ..schemas import LoginResponse, TokenData

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class AuthService:
    def __init__(self):
        self.secret_key = settings.JWT_SECRET_KEY
        self.algorithm = settings.JWT_ALGORITHM
        self.expiration_minutes = settings.JWT_EXPIRATION_MINUTES
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(self, password: str) -> str:
        return pwd_context.hash(password)
    
    def create_access_token(self, data: dict) -> str:
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(minutes=self.expiration_minutes)
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
    
    async def authenticate_user(self, username: str, password: str) -> LoginResponse:
        # Check if username is email or username
        query = """
            SELECT * FROM users 
            WHERE email = :username OR username = :username
        """
        user = await database.fetch_one(query=query, values={"username": username})
        
        if not user or not self.verify_password(password, user["hashed_password"]):
            raise ValueError("Invalid credentials")
        
        if not user["is_active"]:
            raise ValueError("User account is inactive")
        
        # Create token
        access_token = self.create_access_token(data={"sub": str(user["id"])})
        
        # Store session
        expires_at = datetime.utcnow() + timedelta(minutes=self.expiration_minutes)
        query = """
            INSERT INTO sessions (token, user_id, expires_at)
            VALUES (:token, :user_id, :expires_at)
        """
        await database.execute(
            query=query,
            values={
                "token": access_token,
                "user_id": user["id"],
                "expires_at": expires_at
            }
        )
        
        return LoginResponse(
            access_token=access_token,
            expires_in=self.expiration_minutes * 60
        )
    
    async def get_current_user(self, token: str) -> Optional[User]:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            user_id: str = payload.get("sub")
            if user_id is None:
                return None
        except JWTError:
            return None
        
        # Check if session is valid
        query = """
            SELECT u.* FROM users u
            JOIN sessions s ON u.id = s.user_id
            WHERE s.token = :token 
            AND s.is_active = true 
            AND s.expires_at > :now
        """
        user = await database.fetch_one(
            query=query,
            values={"token": token, "now": datetime.utcnow()}
        )
        
        return user
    
    async def revoke_token(self, token: str):
        query = """
            UPDATE sessions 
            SET is_active = false 
            WHERE token = :token
        """
        await database.execute(query=query, values={"token": token})`,
        'user.py': `from typing import List, Optional
from sqlalchemy import select, update, delete

from ..database import database
from ..models import User
from ..schemas import UserCreate, UserUpdate
from .auth import AuthService

class UserService:
    def __init__(self):
        self.auth_service = AuthService()
    
    async def create_user(self, user_data: UserCreate) -> User:
        # Check if user exists
        query = select(User).where(
            (User.email == user_data.email) | (User.username == user_data.username)
        )
        existing = await database.fetch_one(query)
        if existing:
            raise ValueError("User with this email or username already exists")
        
        # Hash password
        hashed_password = self.auth_service.get_password_hash(user_data.password)
        
        # Create user
        query = """
            INSERT INTO users (email, username, hashed_password)
            VALUES (:email, :username, :hashed_password)
            RETURNING *
        """
        user = await database.fetch_one(
            query=query,
            values={
                "email": user_data.email,
                "username": user_data.username,
                "hashed_password": hashed_password
            }
        )
        
        return user
    
    async def get_user(self, user_id: int) -> Optional[User]:
        query = select(User).where(User.id == user_id)
        return await database.fetch_one(query)
    
    async def list_users(self, limit: int = 10, offset: int = 0) -> List[User]:
        query = select(User).limit(limit).offset(offset)
        return await database.fetch_all(query)
    
    async def update_user(self, user_id: int, update_data: UserUpdate) -> User:
        values = {}
        
        if update_data.email:
            # Check if email is taken
            query = select(User).where(
                (User.email == update_data.email) & (User.id != user_id)
            )
            if await database.fetch_one(query):
                raise ValueError("Email already taken")
            values["email"] = update_data.email
        
        if update_data.username:
            # Check if username is taken
            query = select(User).where(
                (User.username == update_data.username) & (User.id != user_id)
            )
            if await database.fetch_one(query):
                raise ValueError("Username already taken")
            values["username"] = update_data.username
        
        if update_data.password:
            values["hashed_password"] = self.auth_service.get_password_hash(
                update_data.password
            )
        
        if not values:
            # No updates
            return await self.get_user(user_id)
        
        # Update user
        query = f"""
            UPDATE users 
            SET {', '.join(f'{k} = :{k}' for k in values.keys())}, 
                updated_at = CURRENT_TIMESTAMP
            WHERE id = :user_id
            RETURNING *
        """
        values["user_id"] = user_id
        
        user = await database.fetch_one(query=query, values=values)
        if not user:
            raise ValueError("User not found")
        
        return user
    
    async def delete_user(self, user_id: int):
        query = delete(User).where(User.id == user_id)
        result = await database.execute(query)
        if result == 0:
            raise ValueError("User not found")`
      },
      'middleware/': {
        '__init__.py': `from .auth import AuthenticationMiddleware
from .request_id import RequestIdMiddleware

__all__ = ["AuthenticationMiddleware", "RequestIdMiddleware"]`,
        'auth.py': `from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from ..services.auth import AuthService

class AuthenticationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # Skip auth for public routes
        public_paths = ["/", "/health", "/api/auth/login", "/api/auth/refresh", "/static"]
        if any(request.url.path.startswith(path) for path in public_paths):
            return await call_next(request)
        
        # Get token from header
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                {"detail": "Invalid authentication credentials"},
                status_code=401
            )
        
        token = auth_header.replace("Bearer ", "")
        auth_service = AuthService()
        
        # Validate token and get user
        user = await auth_service.get_current_user(token)
        if not user:
            return JSONResponse(
                {"detail": "Invalid or expired token"},
                status_code=401
            )
        
        # Add user to request state
        request.state.user = user
        request.state.token = token
        
        response = await call_next(request)
        return response`,
        'request_id.py': `import uuid
from starlette.middleware.base import BaseHTTPMiddleware

class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        # Generate request ID
        request_id = str(uuid.uuid4())
        
        # Add to request state
        request.state.request_id = request_id
        
        # Process request
        response = await call_next(request)
        
        # Add to response headers
        response.headers["X-Request-ID"] = request_id
        
        return response`
      },
      'utils/': {
        '__init__.py': '',
        'dependencies.py': `from functools import wraps
from starlette.exceptions import HTTPException

from ..services.auth import AuthService
from ..services.user import UserService

# Service instances (could be replaced with DI container)
_auth_service = None
_user_service = None

def get_auth_service() -> AuthService:
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service

def get_user_service() -> UserService:
    global _user_service
    if _user_service is None:
        _user_service = UserService()
    return _user_service

# Decorator for routes that require authentication
def require_auth(func):
    @wraps(func)
    async def wrapper(request, *args, **kwargs):
        if not hasattr(request.state, "user"):
            raise HTTPException(status_code=401, detail="Not authenticated")
        return await func(request, *args, **kwargs)
    return wrapper

# Decorator for routes that require specific permissions
def require_permission(permission: str):
    def decorator(func):
        @wraps(func)
        async def wrapper(request, *args, **kwargs):
            if not hasattr(request.state, "user"):
                raise HTTPException(status_code=401, detail="Not authenticated")
            
            # Check permission (implement your permission logic)
            # For now, just pass through
            return await func(request, *args, **kwargs)
        return wrapper
    return decorator`,
        'background.py': `import asyncio
from typing import Callable, Any
from starlette.background import BackgroundTask

class BackgroundTaskManager:
    def __init__(self):
        self.tasks = []
    
    def add_task(self, func: Callable, *args, **kwargs):
        """Add a background task to be executed"""
        task = BackgroundTask(func, *args, **kwargs)
        self.tasks.append(task)
        return task
    
    async def run_task_async(self, func: Callable, *args, **kwargs):
        """Run an async task in the background"""
        loop = asyncio.get_event_loop()
        loop.create_task(func(*args, **kwargs))

# Global task manager
task_manager = BackgroundTaskManager()

# Example background tasks
async def send_email_async(to: str, subject: str, body: str):
    """Send email in background"""
    # Implement email sending logic
    await asyncio.sleep(1)  # Simulate work
    print(f"Email sent to {to}: {subject}")

async def cleanup_expired_sessions():
    """Clean up expired sessions periodically"""
    from ..database import database
    
    while True:
        try:
            query = """
                DELETE FROM sessions 
                WHERE expires_at < CURRENT_TIMESTAMP
            """
            await database.execute(query)
            await asyncio.sleep(3600)  # Run every hour
        except Exception as e:
            print(f"Error cleaning sessions: {e}")
            await asyncio.sleep(300)  # Retry in 5 minutes`
      },
      'templates.py': `from starlette.templating import Jinja2Templates

# Configure Jinja2
templates = Jinja2Templates(directory="templates")

# Add custom filters
@templates.env.filter
def datetime_format(value, format="%Y-%m-%d %H:%M:%S"):
    """Format datetime objects"""
    if value is None:
        return ""
    return value.strftime(format)

@templates.env.filter
def currency(value):
    """Format currency values"""
    return f"${value:,.2f}"

# Add global template variables
templates.env.globals.update({
    "app_name": "Starlette Backend",
    "current_year": 2024,
})`
    },
    'templates/': {
      'base.html': `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}{{ title|default(app_name) }}{% endblock %}</title>
    <link rel="stylesheet" href="{{ url_for('static', path='/css/style.css') }}">
    {% block extra_css %}{% endblock %}
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <a href="/" class="brand">{{ app_name }}</a>
            <ul class="nav-links">
                <li><a href="/">Home</a></li>
                <li><a href="/api/docs">API Docs</a></li>
                <li><a href="/graphql">GraphQL</a></li>
            </ul>
        </div>
    </nav>
    
    <main class="main-content">
        <div class="container">
            {% block content %}{% endblock %}
        </div>
    </main>
    
    <footer class="footer">
        <div class="container">
            <p>&copy; {{ current_year }} {{ app_name }}. All rights reserved.</p>
        </div>
    </footer>
    
    <script src="{{ url_for('static', path='/js/main.js') }}"></script>
    {% block extra_js %}{% endblock %}
</body>
</html>`,
      'index.html': `{% extends "base.html" %}

{% block content %}
<div class="hero">
    <h1>Welcome to {{ app_name }}</h1>
    <p class="lead">A lightweight ASGI framework for high-performance asyncio services</p>
    
    <div class="features">
        <div class="feature">
            <h3>⚡ Fast & Lightweight</h3>
            <p>Built on ASGI for maximum performance</p>
        </div>
        <div class="feature">
            <h3>🔄 WebSocket Support</h3>
            <p>Real-time communication built-in</p>
        </div>
        <div class="feature">
            <h3>🎯 GraphQL Ready</h3>
            <p>Modern API development with Ariadne</p>
        </div>
    </div>
    
    <div class="cta">
        <a href="/api/docs" class="btn btn-primary">Explore API</a>
        <a href="/graphql" class="btn btn-secondary">Try GraphQL</a>
    </div>
</div>

<div class="demo">
    <h2>WebSocket Demo</h2>
    <div id="ws-demo">
        <input type="text" id="message-input" placeholder="Type a message...">
        <button id="send-btn">Send</button>
        <div id="messages"></div>
    </div>
</div>

<script>
// WebSocket demo
const ws = new WebSocket('ws://localhost:8000/ws/?room=demo');
const messagesDiv = document.getElementById('messages');
const messageInput = document.getElementById('message-input');
const sendBtn = document.getElementById('send-btn');

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.type === 'message') {
        const messageEl = document.createElement('div');
        messageEl.className = 'message';
        messageEl.textContent = data.data;
        messagesDiv.appendChild(messageEl);
    }
};

sendBtn.onclick = () => {
    const message = messageInput.value.trim();
    if (message) {
        ws.send(JSON.stringify({
            type: 'message',
            data: message
        }));
        messageInput.value = '';
    }
};

messageInput.onkeypress = (e) => {
    if (e.key === 'Enter') {
        sendBtn.click();
    }
};
</script>
{% endblock %}`
    },
    'static/': {
      'css/': {
        'style.css': `/* Starlette App Styles */
:root {
    --primary-color: #5352ed;
    --secondary-color: #ff6348;
    --bg-color: #f8f9fa;
    --text-color: #2c3e50;
    --border-color: #dfe6e9;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    color: var(--text-color);
    background-color: var(--bg-color);
    line-height: 1.6;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 20px;
}

/* Navigation */
.navbar {
    background: white;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    padding: 1rem 0;
}

.navbar .container {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.brand {
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--primary-color);
    text-decoration: none;
}

.nav-links {
    display: flex;
    list-style: none;
    gap: 2rem;
}

.nav-links a {
    color: var(--text-color);
    text-decoration: none;
    transition: color 0.3s;
}

.nav-links a:hover {
    color: var(--primary-color);
}

/* Main Content */
.main-content {
    min-height: calc(100vh - 120px);
    padding: 2rem 0;
}

/* Hero Section */
.hero {
    text-align: center;
    padding: 4rem 0;
}

.hero h1 {
    font-size: 3rem;
    margin-bottom: 1rem;
    color: var(--primary-color);
}

.lead {
    font-size: 1.25rem;
    color: #718096;
    margin-bottom: 3rem;
}

/* Features */
.features {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 2rem;
    margin-bottom: 3rem;
}

.feature {
    background: white;
    padding: 2rem;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    text-align: center;
}

.feature h3 {
    font-size: 1.5rem;
    margin-bottom: 1rem;
    color: var(--primary-color);
}

/* Buttons */
.cta {
    display: flex;
    gap: 1rem;
    justify-content: center;
    flex-wrap: wrap;
}

.btn {
    padding: 0.75rem 2rem;
    border-radius: 4px;
    text-decoration: none;
    font-weight: 500;
    transition: all 0.3s;
    display: inline-block;
}

.btn-primary {
    background: var(--primary-color);
    color: white;
}

.btn-primary:hover {
    background: #4342d4;
    transform: translateY(-2px);
}

.btn-secondary {
    background: var(--secondary-color);
    color: white;
}

.btn-secondary:hover {
    background: #ff5232;
    transform: translateY(-2px);
}

/* WebSocket Demo */
.demo {
    margin-top: 4rem;
    padding: 2rem;
    background: white;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}

#ws-demo {
    margin-top: 1rem;
}

#message-input {
    width: 70%;
    padding: 0.5rem;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    font-size: 1rem;
}

#send-btn {
    width: 25%;
    padding: 0.5rem;
    margin-left: 1%;
    background: var(--primary-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 1rem;
}

#send-btn:hover {
    background: #4342d4;
}

#messages {
    margin-top: 1rem;
    max-height: 300px;
    overflow-y: auto;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    padding: 1rem;
    background: #f8f9fa;
}

.message {
    padding: 0.5rem;
    margin-bottom: 0.5rem;
    background: white;
    border-radius: 4px;
    box-shadow: 0 1px 2px rgba(0,0,0,0.1);
}

/* Footer */
.footer {
    background: white;
    padding: 2rem 0;
    text-align: center;
    border-top: 1px solid var(--border-color);
    margin-top: 4rem;
}

.footer p {
    color: #718096;
}`
      },
      'js/': {
        'main.js': `// Starlette App JavaScript
console.log('Starlette app loaded');

// Add active class to current nav item
document.addEventListener('DOMContentLoaded', () => {
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-links a');
    
    navLinks.forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });
});`
      }
    },
    'tests/': {
      '__init__.py': '',
      'conftest.py': `import pytest
import asyncio
from typing import AsyncGenerator
from httpx import AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.main import app
from src.database import Base, database
from src.config import settings

# Test database URL
TEST_DATABASE_URL = "sqlite:///./test.db"

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
async def setup_database():
    """Setup test database"""
    # Create test database
    engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    
    # Override database URL
    settings.DATABASE_URL = TEST_DATABASE_URL
    
    # Connect to test database
    await database.connect()
    
    yield
    
    # Cleanup
    await database.disconnect()
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
async def client(setup_database) -> AsyncGenerator[AsyncClient, None]:
    """Create test client"""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac

@pytest.fixture
async def authenticated_client(client: AsyncClient) -> AsyncClient:
    """Create authenticated test client"""
    # Create test user
    response = await client.post(
        "/api/users/",
        json={
            "email": "test@example.com",
            "username": "testuser",
            "password": "testpass123"
        }
    )
    assert response.status_code == 201
    
    # Login
    response = await client.post(
        "/api/auth/login",
        json={
            "username": "testuser",
            "password": "testpass123"
        }
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    
    # Add auth header
    client.headers["Authorization"] = f"Bearer {token}"
    
    return client`,
      'test_auth.py': `import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_login_success(client: AsyncClient):
    # Create user
    await client.post(
        "/api/users/",
        json={
            "email": "auth@example.com",
            "username": "authuser",
            "password": "password123"
        }
    )
    
    # Login
    response = await client.post(
        "/api/auth/login",
        json={
            "username": "authuser",
            "password": "password123"
        }
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0

@pytest.mark.asyncio
async def test_login_invalid_credentials(client: AsyncClient):
    response = await client.post(
        "/api/auth/login",
        json={
            "username": "nonexistent",
            "password": "wrongpass"
        }
    )
    
    assert response.status_code == 401
    assert "Invalid credentials" in response.json()["detail"]

@pytest.mark.asyncio
async def test_logout(authenticated_client: AsyncClient):
    response = await authenticated_client.post("/api/auth/logout")
    assert response.status_code == 200
    
    # Try to access protected route
    response = await authenticated_client.get("/api/users/me")
    assert response.status_code == 401`,
      'test_users.py': `import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_create_user(client: AsyncClient):
    response = await client.post(
        "/api/users/",
        json={
            "email": "new@example.com",
            "username": "newuser",
            "password": "password123"
        }
    )
    
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "new@example.com"
    assert data["username"] == "newuser"
    assert "hashed_password" not in data

@pytest.mark.asyncio
async def test_create_duplicate_user(client: AsyncClient):
    # Create first user
    await client.post(
        "/api/users/",
        json={
            "email": "dup@example.com",
            "username": "dupuser",
            "password": "password123"
        }
    )
    
    # Try to create duplicate
    response = await client.post(
        "/api/users/",
        json={
            "email": "dup@example.com",
            "username": "dupuser2",
            "password": "password123"
        }
    )
    
    assert response.status_code == 400
    assert "already exists" in response.json()["detail"]

@pytest.mark.asyncio
async def test_get_current_user(authenticated_client: AsyncClient):
    response = await authenticated_client.get("/api/users/me")
    
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "test@example.com"
    assert data["username"] == "testuser"

@pytest.mark.asyncio
async def test_update_user(authenticated_client: AsyncClient):
    response = await authenticated_client.put(
        "/api/users/me",
        json={"email": "updated@example.com"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "updated@example.com"

@pytest.mark.asyncio
async def test_delete_user(authenticated_client: AsyncClient):
    response = await authenticated_client.delete("/api/users/me")
    assert response.status_code == 200
    
    # Try to get deleted user
    response = await authenticated_client.get("/api/users/me")
    assert response.status_code == 401`,
      'test_websocket.py': `import pytest
import asyncio
from starlette.testclient import TestClient
from src.main import app

def test_websocket_connection():
    client = TestClient(app)
    
    with client.websocket_connect("/ws/") as websocket:
        # Send message
        websocket.send_json({
            "type": "message",
            "data": "Hello, WebSocket!"
        })
        
        # Receive broadcast
        data = websocket.receive_json()
        assert data["type"] == "message"
        assert data["data"] == "Hello, WebSocket!"

def test_websocket_rooms():
    client = TestClient(app)
    
    with client.websocket_connect("/ws/?room=test-room") as websocket:
        # Join different room
        websocket.send_json({
            "type": "join",
            "room": "another-room"
        })
        
        # Receive confirmation
        data = websocket.receive_json()
        assert data["type"] == "room_joined"
        assert data["room"] == "another-room"

def test_websocket_ping_pong():
    client = TestClient(app)
    
    with client.websocket_connect("/ws/") as websocket:
        # Send ping
        websocket.send_json({"type": "ping"})
        
        # Receive pong
        data = websocket.receive_json()
        assert data["type"] == "pong"`
    },
    'alembic/': {
      'alembic.ini': `# Alembic Configuration
[alembic]
script_location = alembic
prepend_sys_path = .
version_path_separator = os
sqlalchemy.url = driver://user:pass@localhost/dbname

[post_write_hooks]
hooks = black
black.type = console_scripts
black.entrypoint = black
black.options = -l 88 REVISION_SCRIPT_FILENAME

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
      'env.py': `from logging.config import fileConfig
from sqlalchemy import engine_from_config
from sqlalchemy import pool
from alembic import context
import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from src.database import Base
from src.config import settings

# this is the Alembic Config object
config = context.config

# Set database URL from settings
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Add model's MetaData object for 'autogenerate' support
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
      'versions/': {
        '.gitkeep': ''
      }
    },
    '.env.example': `# Application
DEBUG=true
LOG_LEVEL=INFO
SECRET_KEY=your-secret-key-here

# Server
ALLOWED_HOSTS=["*"]
CORS_ORIGINS=["http://localhost:3000"]
HTTPS_ONLY=false

# Database
DATABASE_URL=postgresql://user:password@localhost/dbname
DATABASE_POOL_SIZE=10
DATABASE_MAX_OVERFLOW=20

# Redis
REDIS_URL=redis://localhost:6379

# JWT
JWT_SECRET_KEY=your-jwt-secret-key
JWT_ALGORITHM=HS256
JWT_EXPIRATION_MINUTES=30

# Email
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password`,
    'requirements.txt': `# Production dependencies
starlette==0.37.2
uvicorn[standard]==0.30.1
python-multipart==0.0.9
jinja2==3.1.4
itsdangerous==2.2.0
sqlalchemy==2.0.30
alembic==1.13.1
asyncpg==0.29.0
databases==0.9.0
ariadne==0.23.0
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
python-dotenv==1.0.1
httpx==0.27.0
redis==5.0.3
aiofiles==23.2.1

# Development dependencies
pytest==8.2.0
pytest-asyncio==0.23.7
pytest-cov==5.0.0
black==24.4.2
flake8==7.0.0
mypy==1.10.0
isort==5.13.2
pre-commit==3.7.1`,
    'Dockerfile': `FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VERSION=1.7.1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    postgresql-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Run migrations and start server
CMD ["sh", "-c", "alembic upgrade head && uvicorn src.main:app --host 0.0.0.0 --port 8000"]`,
    'docker-compose.yml': `version: '3.8'

services:
  app:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/starlette_db
      - REDIS_URL=redis://redis:6379
      - SECRET_KEY=your-secret-key-here
      - JWT_SECRET_KEY=your-jwt-secret-key
      - DEBUG=true
    depends_on:
      - db
      - redis
    volumes:
      - ./src:/app/src
      - ./templates:/app/templates
      - ./static:/app/static
    command: uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload

  db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=starlette_db
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

  adminer:
    image: adminer
    ports:
      - "8080:8080"
    depends_on:
      - db

volumes:
  postgres_data:
  redis_data:`,
    '.gitignore': `# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
ENV/
VENV/
pip-log.txt
pip-delete-this-directory.txt
.pytest_cache/
.coverage
htmlcov/
.tox/
.mypy_cache/
.dmypy.json
dmypy.json

# Environment
.env
.env.local
.env.*.local

# Database
*.db
*.sqlite
*.sqlite3

# Alembic
alembic/versions/*.py
!alembic/versions/.gitkeep

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Logs
*.log

# Static files
staticfiles/
media/

# Testing
test.db`,
    'pyproject.toml': `[tool.black]
line-length = 88
target-version = ['py311']
include = '\\.pyi?$'

[tool.isort]
profile = "black"
line_length = 88

[tool.mypy]
python_version = "3.11"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
ignore_missing_imports = true

[tool.pytest.ini_options]
minversion = "6.0"
addopts = "-ra -q --strict-markers"
testpaths = ["tests"]
pythonpath = ["."]

[tool.coverage.run]
source = ["src"]
omit = ["*/tests/*", "*/migrations/*"]

[tool.coverage.report]
precision = 2
show_missing = true
skip_covered = false`,
    'README.md': `# Starlette Backend

A lightweight ASGI framework backend built with Starlette.

## Features

- ⚡ High-performance ASGI framework
- 🔄 WebSocket support for real-time features
- 🎯 GraphQL API with Ariadne
- 🔐 JWT authentication
- 🗄️ SQLAlchemy ORM with async support
- 🧪 Comprehensive test suite with pytest
- 🐳 Docker support

## Getting Started

### Prerequisites

- Python 3.11+
- PostgreSQL
- Redis (optional, for caching)

### Installation

1. Clone the repository
2. Create a virtual environment:
   \`\`\`bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\\Scripts\\activate
   \`\`\`

3. Install dependencies:
   \`\`\`bash
   pip install -r requirements.txt
   \`\`\`

4. Copy environment variables:
   \`\`\`bash
   cp .env.example .env
   \`\`\`

5. Run migrations:
   \`\`\`bash
   alembic upgrade head
   \`\`\`

6. Start the server:
   \`\`\`bash
   uvicorn src.main:app --reload
   \`\`\`

## API Documentation

- REST API: http://localhost:8000/api/docs
- GraphQL: http://localhost:8000/graphql
- WebSocket: ws://localhost:8000/ws/

## Testing

Run tests:
\`\`\`bash
pytest
\`\`\`

With coverage:
\`\`\`bash
pytest --cov=src --cov-report=html
\`\`\`

## Docker

Build and run with Docker Compose:
\`\`\`bash
docker-compose up --build
\`\`\`

## Project Structure

\`\`\`
src/
├── main.py          # Application entry point
├── config.py        # Configuration management
├── database.py      # Database setup
├── models/          # SQLAlchemy models
├── schemas/         # Pydantic schemas
├── routes/          # API routes
├── services/        # Business logic
├── middleware/      # Custom middleware
└── utils/           # Utilities
\`\`\`

## License

MIT`
  }
};`