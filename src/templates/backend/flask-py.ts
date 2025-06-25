import { BackendTemplate } from '../types';

export const flaskTemplate: BackendTemplate = {
  id: 'flask-py',
  name: 'Flask + SQLAlchemy',
  description: 'Flask web framework with blueprints, extensions, SQLAlchemy ORM, and comprehensive API features',
  framework: 'flask',
  language: 'python',
  version: '1.0.0',
  tags: ['flask', 'python', 'sqlalchemy', 'blueprints', 'rest-api', 'jwt', 'alembic'],
  dependencies: {
    flask: '^3.0.0',
    'flask-sqlalchemy': '^3.1.1',
    'flask-migrate': '^4.0.5',
    'flask-jwt-extended': '^4.6.0',
    'flask-cors': '^4.0.0',
    'flask-restful': '^0.3.10',
    'flask-marshmallow': '^0.15.0',
    'marshmallow-sqlalchemy': '^0.29.0',
    'flask-limiter': '^3.5.0',
    'flask-caching': '^2.1.0',
    'flask-mail': '^0.9.1',
    psycopg2: '^2.9.9',
    redis: '^5.0.1',
    celery: '^5.3.4',
    'python-dotenv': '^1.0.0',
    gunicorn: '^21.2.0',
    'flask-admin': '^1.6.1'
  },
  devDependencies: {
    pytest: '^7.4.3',
    'pytest-flask': '^1.3.0',
    'pytest-cov': '^4.1.0',
    'factory-boy': '^3.3.0',
    black: '^23.11.0',
    isort: '^5.12.0',
    flake8: '^6.1.0',
    mypy: '^1.7.1',
    'flask-testing': '^0.8.1'
  },
  files: {
    'requirements.txt': `Flask==3.0.0
Flask-SQLAlchemy==3.1.1
Flask-Migrate==4.0.5
Flask-JWT-Extended==4.6.0
Flask-CORS==4.0.0
Flask-RESTful==0.3.10
Flask-Marshmallow==0.15.0
marshmallow-sqlalchemy==0.29.0
Flask-Limiter==3.5.0
Flask-Caching==2.1.0
Flask-Mail==0.9.1
psycopg2==2.9.9
redis==5.0.1
celery==5.3.4
python-dotenv==1.0.0
gunicorn==21.2.0
Flask-Admin==1.6.1`,
    'requirements-dev.txt': `pytest==7.4.3
pytest-flask==1.3.0
pytest-cov==4.1.0
factory-boy==3.3.0
black==23.11.0
isort==5.12.0
flake8==6.1.0
mypy==1.7.1
Flask-Testing==0.8.1`,
    'app.py': `"""
Flask Application Entry Point
"""
import os
from app import create_app

app = create_app(os.getenv('FLASK_ENV', 'development'))

if __name__ == '__main__':
    app.run(
        host=os.getenv('HOST', '0.0.0.0'),
        port=int(os.getenv('PORT', 5000)),
        debug=app.config.get('DEBUG', False)
    )`,
    'wsgi.py': `"""
WSGI Entry Point for Production
"""
import os
from app import create_app

application = create_app(os.getenv('FLASK_ENV', 'production'))

if __name__ == "__main__":
    application.run()`,
    'app/__init__.py': `"""
Flask Application Factory
"""
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_marshmallow import Marshmallow
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from flask_mail import Mail
from flask_admin import Admin
import redis
from celery import Celery

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
cors = CORS()
ma = Marshmallow()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["1000 per hour"]
)
cache = Cache()
mail = Mail()
admin = Admin()

def create_celery(app):
    """Create Celery instance"""
    celery = Celery(
        app.import_name,
        backend=app.config['CELERY_RESULT_BACKEND'],
        broker=app.config['CELERY_BROKER_URL']
    )
    celery.conf.update(app.config)
    
    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    
    celery.Task = ContextTask
    return celery

def create_app(config_name='development'):
    """Application factory pattern"""
    app = Flask(__name__)
    
    # Load configuration
    if config_name == 'development':
        app.config.from_object('app.config.DevelopmentConfig')
    elif config_name == 'production':
        app.config.from_object('app.config.ProductionConfig')
    elif config_name == 'testing':
        app.config.from_object('app.config.TestingConfig')
    else:
        app.config.from_object('app.config.DevelopmentConfig')
    
    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    cors.init_app(app)
    ma.init_app(app)
    limiter.init_app(app)
    cache.init_app(app)
    mail.init_app(app)
    admin.init_app(app)
    
    # Initialize Celery
    app.celery = create_celery(app)
    
    # Register blueprints
    from app.auth import auth_bp
    from app.users import users_bp
    from app.blog import blog_bp
    from app.main import main_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/api/v1/auth')
    app.register_blueprint(users_bp, url_prefix='/api/v1/users')
    app.register_blueprint(blog_bp, url_prefix='/api/v1/blog')
    
    # Setup Flask-Admin views
    from app.admin_views import setup_admin
    setup_admin(admin, db)
    
    # Register error handlers
    from app.errors import register_error_handlers
    register_error_handlers(app)
    
    # Register JWT handlers
    from app.auth.handlers import register_jwt_handlers
    register_jwt_handlers(jwt)
    
    return app`,
    'app/config.py': `"""
Flask Configuration Classes
"""
import os
from datetime import timedelta

class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-change-this'
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://postgres:postgres@localhost:5432/{{projectName}}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,
        'pool_recycle': 3600,
        'pool_pre_ping': True
    }
    
    # JWT Configuration
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or SECRET_KEY
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']
    
    # CORS
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://localhost:3000').split(',')
    
    # Cache Configuration
    CACHE_TYPE = 'RedisCache'
    CACHE_REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'
    CACHE_DEFAULT_TIMEOUT = 300
    
    # Celery Configuration
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL') or 'redis://localhost:6379/1'
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND') or 'redis://localhost:6379/1'
    
    # Mail Configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')
    
    # Pagination
    POSTS_PER_PAGE = 20
    USERS_PER_PAGE = 50
    
    # File Upload
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    UPLOAD_FOLDER = 'uploads'

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    
    # Use SQLite for development if PostgreSQL not available
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///{{projectName}}_dev.db'
    
    # Cache configuration for development
    CACHE_TYPE = 'SimpleCache'
    CACHE_DEFAULT_TIMEOUT = 60

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    
    # Security settings
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Logging
    LOG_LEVEL = 'INFO'

class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    WTF_CSRF_ENABLED = False
    
    # Use in-memory SQLite for testing
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Cache configuration for testing
    CACHE_TYPE = 'NullCache'
    
    # JWT settings for testing
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=1)`,
    'app/models/__init__.py': `"""
Database Models
"""
from app.models.user import User, Role
from app.models.blog import Category, Tag, Post, Comment

__all__ = ['User', 'Role', 'Category', 'Tag', 'Post', 'Comment']`,
    'app/models/base.py': `"""
Base Model Class
"""
from app import db
from datetime import datetime
import uuid

class BaseModel(db.Model):
    """Base model with common fields"""
    __abstract__ = True
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    def save(self):
        """Save instance to database"""
        db.session.add(self)
        db.session.commit()
        return self
    
    def delete(self):
        """Delete instance from database"""
        db.session.delete(self)
        db.session.commit()
    
    def to_dict(self):
        """Convert model instance to dictionary"""
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}`,
    'app/models/user.py': `"""
User Models
"""
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from app.models.base import BaseModel

# Association table for user roles
user_roles = db.Table('user_roles',
    db.Column('user_id', db.String(36), db.ForeignKey('users.id'), primary_key=True),
    db.Column('role_id', db.String(36), db.ForeignKey('roles.id'), primary_key=True)
)

class Role(BaseModel):
    """User roles"""
    __tablename__ = 'roles'
    
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))
    
    def __repr__(self):
        return f'<Role {self.name}>'

class User(BaseModel):
    """User model"""
    __tablename__ = 'users'
    
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(80))
    last_name = db.Column(db.String(80))
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    avatar_url = db.Column(db.String(255))
    bio = db.Column(db.Text)
    location = db.Column(db.String(100))
    website = db.Column(db.String(255))
    last_login = db.Column(db.DateTime)
    
    # Relationships
    roles = db.relationship('Role', secondary=user_roles, lazy='subquery',
                           backref=db.backref('users', lazy=True))
    posts = db.relationship('Post', backref='author', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password against hash"""
        return check_password_hash(self.password_hash, password)
    
    @property
    def full_name(self):
        """Get full name"""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.username
    
    def has_role(self, role_name):
        """Check if user has specific role"""
        return any(role.name == role_name for role in self.roles)
    
    def add_role(self, role):
        """Add role to user"""
        if role not in self.roles:
            self.roles.append(role)
    
    def remove_role(self, role):
        """Remove role from user"""
        if role in self.roles:
            self.roles.remove(role)`,
    'app/models/blog.py': `"""
Blog Models
"""
from app import db
from app.models.base import BaseModel
from sqlalchemy.ext.hybrid import hybrid_property
from datetime import datetime

# Association table for post tags
post_tags = db.Table('post_tags',
    db.Column('post_id', db.String(36), db.ForeignKey('posts.id'), primary_key=True),
    db.Column('tag_id', db.String(36), db.ForeignKey('tags.id'), primary_key=True)
)

class Category(BaseModel):
    """Blog category model"""
    __tablename__ = 'categories'
    
    name = db.Column(db.String(100), unique=True, nullable=False)
    slug = db.Column(db.String(100), unique=True, nullable=False, index=True)
    description = db.Column(db.Text)
    color = db.Column(db.String(7), default='#6366f1')  # Hex color
    
    # Relationships
    posts = db.relationship('Post', backref='category', lazy=True)
    
    def __repr__(self):
        return f'<Category {self.name}>'
    
    @hybrid_property
    def posts_count(self):
        return len([post for post in self.posts if post.status == 'published'])

class Tag(BaseModel):
    """Blog tag model"""
    __tablename__ = 'tags'
    
    name = db.Column(db.String(50), unique=True, nullable=False)
    slug = db.Column(db.String(50), unique=True, nullable=False, index=True)
    description = db.Column(db.Text)
    
    def __repr__(self):
        return f'<Tag {self.name}>'
    
    @hybrid_property
    def posts_count(self):
        return len([post for post in self.posts if post.status == 'published'])

class Post(BaseModel):
    """Blog post model"""
    __tablename__ = 'posts'
    
    title = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(200), unique=True, nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    excerpt = db.Column(db.Text)
    status = db.Column(db.String(20), default='draft', nullable=False)  # draft, published, archived
    featured_image = db.Column(db.String(255))
    meta_description = db.Column(db.String(160))
    published_at = db.Column(db.DateTime)
    views_count = db.Column(db.Integer, default=0, nullable=False)
    likes_count = db.Column(db.Integer, default=0, nullable=False)
    
    # Foreign Keys
    author_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    category_id = db.Column(db.String(36), db.ForeignKey('categories.id'))
    
    # Relationships
    tags = db.relationship('Tag', secondary=post_tags, lazy='subquery',
                          backref=db.backref('posts', lazy=True))
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Post {self.title}>'
    
    def publish(self):
        """Publish the post"""
        self.status = 'published'
        self.published_at = datetime.utcnow()
    
    def unpublish(self):
        """Unpublish the post"""
        self.status = 'draft'
        self.published_at = None
    
    @hybrid_property
    def is_published(self):
        return self.status == 'published'
    
    @hybrid_property
    def comments_count(self):
        return len([comment for comment in self.comments if comment.is_approved])

class Comment(BaseModel):
    """Blog comment model"""
    __tablename__ = 'comments'
    
    content = db.Column(db.Text, nullable=False)
    is_approved = db.Column(db.Boolean, default=False, nullable=False)
    
    # Foreign Keys
    post_id = db.Column(db.String(36), db.ForeignKey('posts.id'), nullable=False)
    author_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    parent_id = db.Column(db.String(36), db.ForeignKey('comments.id'))
    
    # Relationships
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side='Comment.id'), lazy=True)
    
    def __repr__(self):
        return f'<Comment by {self.author.username}>'
    
    def approve(self):
        """Approve the comment"""
        self.is_approved = True
    
    def reject(self):
        """Reject the comment"""
        self.is_approved = False`,
    'app/schemas/__init__.py': `"""
Marshmallow Schemas
"""
from app.schemas.user import UserSchema, RoleSchema
from app.schemas.blog import CategorySchema, TagSchema, PostSchema, CommentSchema

__all__ = ['UserSchema', 'RoleSchema', 'CategorySchema', 'TagSchema', 'PostSchema', 'CommentSchema']`,
    'app/schemas/user.py': `"""
User Schemas
"""
from marshmallow import fields, validate, validates, ValidationError, post_load
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from app import ma, db
from app.models.user import User, Role

class RoleSchema(SQLAlchemyAutoSchema):
    """Role schema"""
    class Meta:
        model = Role
        load_instance = True
        sqla_session = db.session

class UserSchema(SQLAlchemyAutoSchema):
    """User schema"""
    class Meta:
        model = User
        load_instance = True
        sqla_session = db.session
        exclude = ['password_hash']
    
    password = fields.String(write_only=True, validate=validate.Length(min=8))
    full_name = fields.String(dump_only=True)
    roles = fields.Nested(RoleSchema, many=True, dump_only=True)
    
    @validates('email')
    def validate_email(self, value):
        """Validate email uniqueness"""
        if self.instance and self.instance.email == value:
            return
        if User.query.filter_by(email=value).first():
            raise ValidationError('Email already exists')
    
    @validates('username')
    def validate_username(self, value):
        """Validate username uniqueness"""
        if self.instance and self.instance.username == value:
            return
        if User.query.filter_by(username=value).first():
            raise ValidationError('Username already exists')
    
    @post_load
    def set_password(self, data, **kwargs):
        """Hash password after loading"""
        if 'password' in data:
            password = data.pop('password')
            if self.instance:
                self.instance.set_password(password)
            else:
                data['password_hash'] = password
        return data

class UserCreateSchema(ma.Schema):
    """Schema for user creation"""
    username = fields.String(required=True, validate=validate.Length(min=3, max=80))
    email = fields.Email(required=True)
    password = fields.String(required=True, validate=validate.Length(min=8))
    first_name = fields.String(validate=validate.Length(max=80))
    last_name = fields.String(validate=validate.Length(max=80))

class UserUpdateSchema(ma.Schema):
    """Schema for user updates"""
    first_name = fields.String(validate=validate.Length(max=80))
    last_name = fields.String(validate=validate.Length(max=80))
    bio = fields.String()
    location = fields.String(validate=validate.Length(max=100))
    website = fields.Url()

class ChangePasswordSchema(ma.Schema):
    """Schema for password change"""
    current_password = fields.String(required=True)
    new_password = fields.String(required=True, validate=validate.Length(min=8))`,
    'app/schemas/blog.py': `"""
Blog Schemas
"""
from marshmallow import fields, validate, validates, ValidationError
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from app import ma, db
from app.models.blog import Category, Tag, Post, Comment
from app.schemas.user import UserSchema

class CategorySchema(SQLAlchemyAutoSchema):
    """Category schema"""
    class Meta:
        model = Category
        load_instance = True
        sqla_session = db.session
    
    posts_count = fields.Integer(dump_only=True)

class TagSchema(SQLAlchemyAutoSchema):
    """Tag schema"""
    class Meta:
        model = Tag
        load_instance = True
        sqla_session = db.session
    
    posts_count = fields.Integer(dump_only=True)

class CommentSchema(SQLAlchemyAutoSchema):
    """Comment schema"""
    class Meta:
        model = Comment
        load_instance = True
        sqla_session = db.session
    
    author = fields.Nested(UserSchema, dump_only=True, only=['id', 'username', 'full_name'])
    replies = fields.Nested('self', many=True, dump_only=True)

class PostSchema(SQLAlchemyAutoSchema):
    """Post schema"""
    class Meta:
        model = Post
        load_instance = True
        sqla_session = db.session
    
    author = fields.Nested(UserSchema, dump_only=True, only=['id', 'username', 'full_name'])
    category = fields.Nested(CategorySchema, dump_only=True)
    tags = fields.Nested(TagSchema, many=True, dump_only=True)
    comments = fields.Nested(CommentSchema, many=True, dump_only=True)
    comments_count = fields.Integer(dump_only=True)
    is_published = fields.Boolean(dump_only=True)
    
    @validates('slug')
    def validate_slug(self, value):
        """Validate slug uniqueness"""
        if self.instance and self.instance.slug == value:
            return
        if Post.query.filter_by(slug=value).first():
            raise ValidationError('Slug already exists')

class PostCreateSchema(ma.Schema):
    """Schema for post creation"""
    title = fields.String(required=True, validate=validate.Length(min=1, max=200))
    slug = fields.String(required=True, validate=validate.Length(min=1, max=200))
    content = fields.String(required=True)
    excerpt = fields.String()
    status = fields.String(validate=validate.OneOf(['draft', 'published', 'archived']))
    category_id = fields.String()
    tag_ids = fields.List(fields.String())
    meta_description = fields.String(validate=validate.Length(max=160))

class PostUpdateSchema(ma.Schema):
    """Schema for post updates"""
    title = fields.String(validate=validate.Length(min=1, max=200))
    content = fields.String()
    excerpt = fields.String()
    status = fields.String(validate=validate.OneOf(['draft', 'published', 'archived']))
    category_id = fields.String()
    tag_ids = fields.List(fields.String())
    meta_description = fields.String(validate=validate.Length(max=160))`,
    'app/auth/__init__.py': `"""
Authentication Blueprint
"""
from flask import Blueprint

auth_bp = Blueprint('auth', __name__)

from app.auth import routes`,
    'app/auth/routes.py': `"""
Authentication Routes
"""
from flask import request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required,
    get_jwt_identity, get_jwt
)
from marshmallow import ValidationError
from app.auth import auth_bp
from app import db, limiter
from app.models.user import User
from app.schemas.user import UserCreateSchema, ChangePasswordSchema
from app.auth.utils import create_tokens

@auth_bp.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    """User registration"""
    schema = UserCreateSchema()
    
    try:
        data = schema.load(request.json)
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400
    
    # Check if user exists
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 400
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already taken'}), 400
    
    # Create user
    user = User(
        username=data['username'],
        email=data['email'],
        first_name=data.get('first_name'),
        last_name=data.get('last_name')
    )
    user.set_password(data['password'])
    user.save()
    
    # Create tokens
    tokens = create_tokens(user)
    
    return jsonify({
        'message': 'User registered successfully',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email
        },
        **tokens
    }), 201

@auth_bp.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    """User login"""
    data = request.json
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password required'}), 400
    
    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not user.is_active:
        return jsonify({'error': 'Account is disabled'}), 401
    
    # Update last login
    from datetime import datetime
    user.last_login = datetime.utcnow()
    user.save()
    
    # Create tokens
    tokens = create_tokens(user)
    
    return jsonify({
        'message': 'Login successful',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'full_name': user.full_name
        },
        **tokens
    }), 200

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token"""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user or not user.is_active:
        return jsonify({'error': 'User not found or inactive'}), 404
    
    new_token = create_access_token(identity=user.id)
    
    return jsonify({
        'access_token': new_token
    }), 200

@auth_bp.route('/logout', methods=['DELETE'])
@jwt_required()
def logout():
    """Logout user (blacklist token)"""
    # Note: In a real app, you'd want to implement token blacklisting
    # For now, we'll just return success (client should discard token)
    return jsonify({'message': 'Logout successful'}), 200

@auth_bp.route('/change-password', methods=['PUT'])
@jwt_required()
def change_password():
    """Change user password"""
    schema = ChangePasswordSchema()
    
    try:
        data = schema.load(request.json)
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400
    
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user.check_password(data['current_password']):
        return jsonify({'error': 'Current password is incorrect'}), 400
    
    user.set_password(data['new_password'])
    user.save()
    
    return jsonify({'message': 'Password changed successfully'}), 200`,
    'app/auth/utils.py': `"""
Authentication Utilities
"""
from flask_jwt_extended import create_access_token, create_refresh_token

def create_tokens(user):
    """Create access and refresh tokens for user"""
    additional_claims = {
        'username': user.username,
        'email': user.email,
        'roles': [role.name for role in user.roles]
    }
    
    access_token = create_access_token(
        identity=user.id,
        additional_claims=additional_claims
    )
    refresh_token = create_refresh_token(identity=user.id)
    
    return {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'Bearer'
    }`,
    'app/auth/handlers.py': `"""
JWT Event Handlers
"""
from flask import jsonify
from flask_jwt_extended import get_jwt_identity
from app.models.user import User

def register_jwt_handlers(jwt):
    """Register JWT event handlers"""
    
    @jwt.user_identity_loader
    def user_identity_lookup(user):
        return user.id if hasattr(user, 'id') else user
    
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        identity = jwt_data["sub"]
        return User.query.filter_by(id=identity).one_or_none()
    
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({'error': 'Token has expired'}), 401
    
    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({'error': 'Invalid token'}), 401
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({'error': 'Authorization token required'}), 401`,
    'app/users/__init__.py': `"""
Users Blueprint
"""
from flask import Blueprint

users_bp = Blueprint('users', __name__)

from app.users import routes`,
    'app/users/routes.py': `"""
User Routes
"""
from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, current_user
from marshmallow import ValidationError
from app.users import users_bp
from app import db, limiter
from app.models.user import User
from app.schemas.user import UserSchema, UserUpdateSchema

user_schema = UserSchema()
users_schema = UserSchema(many=True)

@users_bp.route('/', methods=['GET'])
@jwt_required()
@limiter.limit("100 per hour")
def get_users():
    """Get all users (paginated)"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    users = User.query.paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'users': users_schema.dump(users.items),
        'pagination': {
            'page': users.page,
            'pages': users.pages,
            'per_page': users.per_page,
            'total': users.total,
            'has_next': users.has_next,
            'has_prev': users.has_prev
        }
    }), 200

@users_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current user profile"""
    return jsonify({'user': user_schema.dump(current_user)}), 200

@users_bp.route('/me', methods=['PUT'])
@jwt_required()
def update_current_user():
    """Update current user profile"""
    schema = UserUpdateSchema()
    
    try:
        data = schema.load(request.json)
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400
    
    # Update user fields
    for field, value in data.items():
        setattr(current_user, field, value)
    
    current_user.save()
    
    return jsonify({
        'message': 'Profile updated successfully',
        'user': user_schema.dump(current_user)
    }), 200

@users_bp.route('/<user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    """Get user by ID"""
    user = User.query.get_or_404(user_id)
    return jsonify({'user': user_schema.dump(user)}), 200

@users_bp.route('/<user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    """Update user (admin only)"""
    # Check if current user is admin
    if not current_user.has_role('admin'):
        return jsonify({'error': 'Admin access required'}), 403
    
    user = User.query.get_or_404(user_id)
    schema = UserUpdateSchema()
    
    try:
        data = schema.load(request.json)
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400
    
    # Update user fields
    for field, value in data.items():
        setattr(user, field, value)
    
    user.save()
    
    return jsonify({
        'message': 'User updated successfully',
        'user': user_schema.dump(user)
    }), 200

@users_bp.route('/<user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    """Delete user (admin only)"""
    # Check if current user is admin
    if not current_user.has_role('admin'):
        return jsonify({'error': 'Admin access required'}), 403
    
    user = User.query.get_or_404(user_id)
    
    # Don't allow deleting self
    if user.id == current_user.id:
        return jsonify({'error': 'Cannot delete own account'}), 400
    
    user.delete()
    
    return jsonify({'message': 'User deleted successfully'}), 200`,
    'app/blog/__init__.py': `"""
Blog Blueprint
"""
from flask import Blueprint

blog_bp = Blueprint('blog', __name__)

from app.blog import routes`,
    'app/blog/routes.py': `"""
Blog Routes
"""
from flask import request, jsonify
from flask_jwt_extended import jwt_required, current_user, get_jwt_identity
from marshmallow import ValidationError
from app.blog import blog_bp
from app import db, limiter
from app.models.blog import Category, Tag, Post, Comment
from app.schemas.blog import (
    CategorySchema, TagSchema, PostSchema, CommentSchema,
    PostCreateSchema, PostUpdateSchema
)

# Schema instances
category_schema = CategorySchema()
categories_schema = CategorySchema(many=True)
tag_schema = TagSchema()
tags_schema = TagSchema(many=True)
post_schema = PostSchema()
posts_schema = PostSchema(many=True)
comment_schema = CommentSchema()
comments_schema = CommentSchema(many=True)

# Categories
@blog_bp.route('/categories', methods=['GET'])
def get_categories():
    """Get all categories"""
    categories = Category.query.all()
    return jsonify({'categories': categories_schema.dump(categories)}), 200

@blog_bp.route('/categories', methods=['POST'])
@jwt_required()
def create_category():
    """Create new category"""
    if not current_user.has_role('admin'):
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        category = category_schema.load(request.json)
        category.save()
        return jsonify({
            'message': 'Category created successfully',
            'category': category_schema.dump(category)
        }), 201
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400

# Tags
@blog_bp.route('/tags', methods=['GET'])
def get_tags():
    """Get all tags"""
    tags = Tag.query.all()
    return jsonify({'tags': tags_schema.dump(tags)}), 200

@blog_bp.route('/tags', methods=['POST'])
@jwt_required()
def create_tag():
    """Create new tag"""
    try:
        tag = tag_schema.load(request.json)
        tag.save()
        return jsonify({
            'message': 'Tag created successfully',
            'tag': tag_schema.dump(tag)
        }), 201
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400

# Posts
@blog_bp.route('/posts', methods=['GET'])
@limiter.limit("100 per hour")
def get_posts():
    """Get all published posts (paginated)"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    status = request.args.get('status', 'published')
    
    query = Post.query
    
    # Filter by status (only show published posts to non-authenticated users)
    if status == 'published' or not get_jwt_identity():
        query = query.filter_by(status='published')
    elif get_jwt_identity():
        # Authenticated users can see their own posts in any status
        user_id = get_jwt_identity()
        if status != 'all':
            query = query.filter(
                (Post.status == status) | (Post.author_id == user_id)
            )
    
    # Filter by category
    category_slug = request.args.get('category')
    if category_slug:
        category = Category.query.filter_by(slug=category_slug).first()
        if category:
            query = query.filter_by(category_id=category.id)
    
    # Filter by tag
    tag_slug = request.args.get('tag')
    if tag_slug:
        tag = Tag.query.filter_by(slug=tag_slug).first()
        if tag:
            query = query.filter(Post.tags.contains(tag))
    
    posts = query.order_by(Post.published_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'posts': posts_schema.dump(posts.items),
        'pagination': {
            'page': posts.page,
            'pages': posts.pages,
            'per_page': posts.per_page,
            'total': posts.total,
            'has_next': posts.has_next,
            'has_prev': posts.has_prev
        }
    }), 200

@blog_bp.route('/posts', methods=['POST'])
@jwt_required()
def create_post():
    """Create new post"""
    schema = PostCreateSchema()
    
    try:
        data = schema.load(request.json)
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400
    
    # Create post
    post = Post(
        title=data['title'],
        slug=data['slug'],
        content=data['content'],
        excerpt=data.get('excerpt'),
        status=data.get('status', 'draft'),
        category_id=data.get('category_id'),
        meta_description=data.get('meta_description'),
        author_id=current_user.id
    )
    
    # Add tags
    if 'tag_ids' in data:
        tags = Tag.query.filter(Tag.id.in_(data['tag_ids'])).all()
        post.tags = tags
    
    post.save()
    
    return jsonify({
        'message': 'Post created successfully',
        'post': post_schema.dump(post)
    }), 201

@blog_bp.route('/posts/<slug>', methods=['GET'])
def get_post(slug):
    """Get post by slug"""
    post = Post.query.filter_by(slug=slug).first_or_404()
    
    # Only show published posts to non-authenticated users
    if post.status != 'published' and not get_jwt_identity():
        return jsonify({'error': 'Post not found'}), 404
    
    # Increment view count
    post.views_count += 1
    post.save()
    
    return jsonify({'post': post_schema.dump(post)}), 200

@blog_bp.route('/posts/<slug>', methods=['PUT'])
@jwt_required()
def update_post(slug):
    """Update post"""
    post = Post.query.filter_by(slug=slug).first_or_404()
    
    # Check if user can edit this post
    if post.author_id != current_user.id and not current_user.has_role('admin'):
        return jsonify({'error': 'Permission denied'}), 403
    
    schema = PostUpdateSchema()
    
    try:
        data = schema.load(request.json)
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400
    
    # Update post fields
    for field, value in data.items():
        if field == 'tag_ids':
            tags = Tag.query.filter(Tag.id.in_(value)).all()
            post.tags = tags
        else:
            setattr(post, field, value)
    
    post.save()
    
    return jsonify({
        'message': 'Post updated successfully',
        'post': post_schema.dump(post)
    }), 200

@blog_bp.route('/posts/<slug>', methods=['DELETE'])
@jwt_required()
def delete_post(slug):
    """Delete post"""
    post = Post.query.filter_by(slug=slug).first_or_404()
    
    # Check if user can delete this post
    if post.author_id != current_user.id and not current_user.has_role('admin'):
        return jsonify({'error': 'Permission denied'}), 403
    
    post.delete()
    
    return jsonify({'message': 'Post deleted successfully'}), 200

@blog_bp.route('/posts/<slug>/like', methods=['POST'])
@jwt_required()
@limiter.limit("10 per minute")
def like_post(slug):
    """Like a post"""
    post = Post.query.filter_by(slug=slug).first_or_404()
    
    post.likes_count += 1
    post.save()
    
    return jsonify({
        'message': 'Post liked successfully',
        'likes_count': post.likes_count
    }), 200

# Comments
@blog_bp.route('/posts/<slug>/comments', methods=['GET'])
def get_post_comments(slug):
    """Get comments for a post"""
    post = Post.query.filter_by(slug=slug).first_or_404()
    
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    comments = Comment.query.filter_by(
        post_id=post.id,
        is_approved=True,
        parent_id=None
    ).order_by(Comment.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'comments': comments_schema.dump(comments.items),
        'pagination': {
            'page': comments.page,
            'pages': comments.pages,
            'per_page': comments.per_page,
            'total': comments.total
        }
    }), 200

@blog_bp.route('/posts/<slug>/comments', methods=['POST'])
@jwt_required()
@limiter.limit("5 per minute")
def create_comment(slug):
    """Create comment on a post"""
    post = Post.query.filter_by(slug=slug).first_or_404()
    
    data = request.json
    if not data or not data.get('content'):
        return jsonify({'error': 'Content is required'}), 400
    
    comment = Comment(
        content=data['content'],
        post_id=post.id,
        author_id=current_user.id,
        parent_id=data.get('parent_id'),
        is_approved=True  # Auto-approve for now
    )
    comment.save()
    
    return jsonify({
        'message': 'Comment created successfully',
        'comment': comment_schema.dump(comment)
    }), 201`,
    'app/main/__init__.py': `"""
Main Blueprint
"""
from flask import Blueprint

main_bp = Blueprint('main', __name__)

from app.main import routes`,
    'app/main/routes.py': `"""
Main Routes
"""
from flask import jsonify, current_app
from app.main import main_bp
from app import limiter

@main_bp.route('/')
def index():
    """API root endpoint"""
    return jsonify({
        'message': f'Welcome to {current_app.config.get("APP_NAME", "Flask API")}',
        'version': '1.0.0',
        'docs': '/admin/',
        'status': 'healthy'
    }), 200

@main_bp.route('/health')
@limiter.limit("100 per minute")
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Flask API',
        'version': '1.0.0'
    }), 200`,
    'app/admin_views.py': `"""
Flask-Admin Views
"""
from flask_admin.contrib.sqla import ModelView
from flask_admin import AdminIndexView, expose
from flask_jwt_extended import jwt_required, current_user
from flask import redirect, url_for, request, flash
from app.models.user import User, Role
from app.models.blog import Category, Tag, Post, Comment

class SecureModelView(ModelView):
    """Base model view with authentication"""
    
    def is_accessible(self):
        """Check if user can access admin"""
        try:
            return current_user and current_user.has_role('admin')
        except:
            return False
    
    def inaccessible_callback(self, name, **kwargs):
        """Redirect to login if not accessible"""
        flash('Please log in to access admin panel.', 'error')
        return redirect(url_for('auth.login', next=request.url))

class UserView(SecureModelView):
    """User admin view"""
    column_list = ['username', 'email', 'full_name', 'is_active', 'is_verified', 'created_at']
    column_searchable_list = ['username', 'email', 'first_name', 'last_name']
    column_filters = ['is_active', 'is_verified', 'created_at']
    form_excluded_columns = ['password_hash', 'posts', 'comments']

class PostView(SecureModelView):
    """Post admin view"""
    column_list = ['title', 'author', 'status', 'category', 'created_at', 'views_count']
    column_searchable_list = ['title', 'content']
    column_filters = ['status', 'category', 'created_at']
    form_excluded_columns = ['views_count', 'likes_count', 'comments']

class CommentView(SecureModelView):
    """Comment admin view"""
    column_list = ['content', 'author', 'post', 'is_approved', 'created_at']
    column_filters = ['is_approved', 'created_at']

class AdminIndex(AdminIndexView):
    """Custom admin index"""
    
    @expose('/')
    def index(self):
        if not self.is_accessible():
            return self.inaccessible_callback('index')
        
        # Get some stats
        from app.models.user import User
        from app.models.blog import Post, Comment
        
        stats = {
            'total_users': User.query.count(),
            'total_posts': Post.query.count(),
            'published_posts': Post.query.filter_by(status='published').count(),
            'total_comments': Comment.query.count(),
            'approved_comments': Comment.query.filter_by(is_approved=True).count()
        }
        
        return self.render('admin/index.html', stats=stats)
    
    def is_accessible(self):
        try:
            return current_user and current_user.has_role('admin')
        except:
            return False

def setup_admin(admin, db):
    """Setup Flask-Admin views"""
    admin.index_view = AdminIndex()
    
    # Add model views
    admin.add_view(UserView(User, db.session, name='Users'))
    admin.add_view(SecureModelView(Role, db.session, name='Roles'))
    admin.add_view(SecureModelView(Category, db.session, name='Categories'))
    admin.add_view(SecureModelView(Tag, db.session, name='Tags'))
    admin.add_view(PostView(Post, db.session, name='Posts'))
    admin.add_view(CommentView(Comment, db.session, name='Comments'))`,
    'app/errors.py': `"""
Error Handlers
"""
from flask import jsonify
from marshmallow import ValidationError
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import HTTPException

def register_error_handlers(app):
    """Register error handlers"""
    
    @app.errorhandler(ValidationError)
    def handle_validation_error(e):
        return jsonify({'errors': e.messages}), 400
    
    @app.errorhandler(IntegrityError)
    def handle_integrity_error(e):
        return jsonify({'error': 'Database integrity error'}), 409
    
    @app.errorhandler(404)
    def handle_not_found(e):
        return jsonify({'error': 'Resource not found'}), 404
    
    @app.errorhandler(403)
    def handle_forbidden(e):
        return jsonify({'error': 'Access forbidden'}), 403
    
    @app.errorhandler(401)
    def handle_unauthorized(e):
        return jsonify({'error': 'Unauthorized access'}), 401
    
    @app.errorhandler(500)
    def handle_internal_error(e):
        return jsonify({'error': 'Internal server error'}), 500
    
    @app.errorhandler(HTTPException)
    def handle_http_exception(e):
        return jsonify({'error': e.description}), e.code`,
    'app/cli.py': `"""
Flask CLI Commands
"""
import click
from flask.cli import with_appcontext
from app import db
from app.models.user import User, Role

@click.command()
@click.option('--username', prompt=True, help='Admin username')
@click.option('--email', prompt=True, help='Admin email')
@click.option('--password', prompt=True, hide_input=True, help='Admin password')
@with_appcontext
def create_admin(username, email, password):
    """Create admin user"""
    # Create admin role if it doesn't exist
    admin_role = Role.query.filter_by(name='admin').first()
    if not admin_role:
        admin_role = Role(name='admin', description='Administrator')
        admin_role.save()
    
    # Check if admin user already exists
    if User.query.filter_by(email=email).first():
        click.echo(f'User with email {email} already exists!')
        return
    
    # Create admin user
    admin_user = User(
        username=username,
        email=email,
        is_active=True,
        is_verified=True
    )
    admin_user.set_password(password)
    admin_user.add_role(admin_role)
    admin_user.save()
    
    click.echo(f'Admin user {username} created successfully!')

@click.command()
@with_appcontext
def init_db():
    """Initialize database with sample data"""
    db.create_all()
    
    # Create default roles
    roles_data = [
        {'name': 'admin', 'description': 'Administrator'},
        {'name': 'editor', 'description': 'Content Editor'},
        {'name': 'author', 'description': 'Content Author'},
        {'name': 'user', 'description': 'Regular User'}
    ]
    
    for role_data in roles_data:
        if not Role.query.filter_by(name=role_data['name']).first():
            role = Role(**role_data)
            role.save()
    
    click.echo('Database initialized successfully!')

def register_commands(app):
    """Register CLI commands"""
    app.cli.add_command(create_admin)
    app.cli.add_command(init_db)`,
    'app/tasks.py': `"""
Celery Tasks
"""
from celery import Celery
from flask_mail import Message
from app import mail

def send_email_task(subject, recipients, body, html_body=None):
    """Send email task"""
    msg = Message(
        subject=subject,
        recipients=recipients,
        body=body,
        html=html_body
    )
    mail.send(msg)
    return f"Email sent to {recipients}"

def process_data_task(data):
    """Process data task"""
    # Example background task
    import time
    time.sleep(5)  # Simulate processing
    return f"Processed {len(data)} items"`,
    'tests/__init__.py': `"""
Test Package
"""`,
    'tests/conftest.py': `"""
Test Configuration
"""
import pytest
import tempfile
import os
from app import create_app, db
from app.models.user import User, Role
from app.models.blog import Category, Tag, Post

@pytest.fixture
def app():
    """Create application for testing"""
    db_fd, db_path = tempfile.mkstemp()
    
    app = create_app('testing')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.app_context():
        db.create_all()
        yield app
        
    os.close(db_fd)
    os.unlink(db_path)

@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()

@pytest.fixture
def runner(app):
    """Create test CLI runner"""
    return app.test_cli_runner()

@pytest.fixture
def auth_headers(client):
    """Create authenticated user and return headers"""
    # Create user role
    user_role = Role(name='user', description='Regular User')
    user_role.save()
    
    # Create test user
    user = User(
        username='testuser',
        email='test@example.com',
        is_active=True,
        is_verified=True
    )
    user.set_password('testpass123')
    user.add_role(user_role)
    user.save()
    
    # Login and get token
    response = client.post('/api/v1/auth/login', json={
        'email': 'test@example.com',
        'password': 'testpass123'
    })
    
    token = response.json['access_token']
    return {'Authorization': f'Bearer {token}'}

@pytest.fixture
def admin_headers(client):
    """Create admin user and return headers"""
    # Create admin role
    admin_role = Role(name='admin', description='Administrator')
    admin_role.save()
    
    # Create admin user
    admin = User(
        username='admin',
        email='admin@example.com',
        is_active=True,
        is_verified=True
    )
    admin.set_password('adminpass123')
    admin.add_role(admin_role)
    admin.save()
    
    # Login and get token
    response = client.post('/api/v1/auth/login', json={
        'email': 'admin@example.com',
        'password': 'adminpass123'
    })
    
    token = response.json['access_token']
    return {'Authorization': f'Bearer {token}'}

@pytest.fixture
def sample_data():
    """Create sample data for tests"""
    # Create category
    category = Category(
        name='Technology',
        slug='technology',
        description='Tech posts'
    )
    category.save()
    
    # Create tag
    tag = Tag(
        name='Python',
        slug='python',
        description='Python programming'
    )
    tag.save()
    
    return {
        'category': category,
        'tag': tag
    }`,
    'tests/test_auth.py': `"""
Authentication Tests
"""
import pytest
from app.models.user import User

def test_register_success(client):
    """Test successful registration"""
    response = client.post('/api/v1/auth/register', json={
        'username': 'newuser',
        'email': 'new@example.com',
        'password': 'newpass123',
        'first_name': 'New',
        'last_name': 'User'
    })
    
    assert response.status_code == 201
    assert 'access_token' in response.json
    assert response.json['user']['username'] == 'newuser'

def test_register_duplicate_email(client):
    """Test registration with duplicate email"""
    # Create first user
    client.post('/api/v1/auth/register', json={
        'username': 'user1',
        'email': 'test@example.com',
        'password': 'pass123'
    })
    
    # Try to create second user with same email
    response = client.post('/api/v1/auth/register', json={
        'username': 'user2',
        'email': 'test@example.com',
        'password': 'pass123'
    })
    
    assert response.status_code == 400
    assert 'Email already registered' in response.json['error']

def test_login_success(client, auth_headers):
    """Test successful login"""
    response = client.post('/api/v1/auth/login', json={
        'email': 'test@example.com',
        'password': 'testpass123'
    })
    
    assert response.status_code == 200
    assert 'access_token' in response.json
    assert response.json['user']['email'] == 'test@example.com'

def test_login_invalid_credentials(client):
    """Test login with invalid credentials"""
    response = client.post('/api/v1/auth/login', json={
        'email': 'wrong@example.com',
        'password': 'wrongpass'
    })
    
    assert response.status_code == 401
    assert 'Invalid credentials' in response.json['error']

def test_change_password(client, auth_headers):
    """Test password change"""
    response = client.put('/api/v1/auth/change-password', 
                         json={
                             'current_password': 'testpass123',
                             'new_password': 'newpass123'
                         },
                         headers=auth_headers)
    
    assert response.status_code == 200
    assert 'Password changed successfully' in response.json['message']`,
    'tests/test_users.py': `"""
User Tests
"""
import pytest

def test_get_current_user(client, auth_headers):
    """Test get current user profile"""
    response = client.get('/api/v1/users/me', headers=auth_headers)
    
    assert response.status_code == 200
    assert response.json['user']['username'] == 'testuser'

def test_update_current_user(client, auth_headers):
    """Test update current user profile"""
    response = client.put('/api/v1/users/me', 
                         json={
                             'first_name': 'Updated',
                             'last_name': 'Name',
                             'bio': 'Updated bio'
                         },
                         headers=auth_headers)
    
    assert response.status_code == 200
    assert response.json['user']['first_name'] == 'Updated'
    assert response.json['user']['bio'] == 'Updated bio'

def test_get_users_list(client, auth_headers):
    """Test get users list"""
    response = client.get('/api/v1/users/', headers=auth_headers)
    
    assert response.status_code == 200
    assert 'users' in response.json
    assert 'pagination' in response.json

def test_admin_delete_user(client, admin_headers):
    """Test admin can delete user"""
    # Create a user to delete
    from app.models.user import User
    user = User(username='todelete', email='delete@example.com')
    user.set_password('pass123')
    user.save()
    
    response = client.delete(f'/api/v1/users/{user.id}', headers=admin_headers)
    
    assert response.status_code == 200
    assert 'User deleted successfully' in response.json['message']`,
    'tests/test_blog.py': `"""
Blog Tests
"""
import pytest

def test_get_categories(client):
    """Test get categories"""
    response = client.get('/api/v1/blog/categories')
    
    assert response.status_code == 200
    assert 'categories' in response.json

def test_create_category_admin(client, admin_headers):
    """Test admin can create category"""
    response = client.post('/api/v1/blog/categories',
                          json={
                              'name': 'New Category',
                              'slug': 'new-category',
                              'description': 'A new category'
                          },
                          headers=admin_headers)
    
    assert response.status_code == 201
    assert response.json['category']['name'] == 'New Category'

def test_create_post(client, auth_headers, sample_data):
    """Test create blog post"""
    response = client.post('/api/v1/blog/posts',
                          json={
                              'title': 'Test Post',
                              'slug': 'test-post',
                              'content': 'Test content',
                              'status': 'published',
                              'category_id': sample_data['category'].id
                          },
                          headers=auth_headers)
    
    assert response.status_code == 201
    assert response.json['post']['title'] == 'Test Post'

def test_get_posts(client, sample_data):
    """Test get published posts"""
    response = client.get('/api/v1/blog/posts')
    
    assert response.status_code == 200
    assert 'posts' in response.json
    assert 'pagination' in response.json

def test_like_post(client, auth_headers, sample_data):
    """Test like a post"""
    # First create a post
    from app.models.blog import Post
    from app.models.user import User
    
    user = User.query.filter_by(username='testuser').first()
    post = Post(
        title='Test Post',
        slug='test-post',
        content='Test content',
        status='published',
        author_id=user.id,
        category_id=sample_data['category'].id
    )
    post.save()
    
    response = client.post(f'/api/v1/blog/posts/{post.slug}/like',
                          headers=auth_headers)
    
    assert response.status_code == 200
    assert response.json['likes_count'] == 1`,
    'tests/test_models.py': `"""
Model Tests
"""
import pytest
from app.models.user import User, Role
from app.models.blog import Category, Tag, Post, Comment

def test_user_model():
    """Test User model"""
    user = User(username='testuser', email='test@example.com')
    user.set_password('testpass')
    
    assert user.username == 'testuser'
    assert user.check_password('testpass')
    assert not user.check_password('wrongpass')

def test_user_roles():
    """Test user roles"""
    user = User(username='testuser', email='test@example.com')
    admin_role = Role(name='admin', description='Administrator')
    
    user.add_role(admin_role)
    
    assert user.has_role('admin')
    assert not user.has_role('user')

def test_post_model():
    """Test Post model"""
    user = User(username='author', email='author@example.com')
    user.save()
    
    post = Post(
        title='Test Post',
        slug='test-post',
        content='Test content',
        author_id=user.id,
        status='draft'
    )
    
    assert not post.is_published
    
    post.publish()
    assert post.is_published
    assert post.status == 'published'

def test_category_posts_count():
    """Test category posts count"""
    category = Category(name='Tech', slug='tech')
    category.save()
    
    user = User(username='author', email='author@example.com')
    user.save()
    
    # Create published post
    post = Post(
        title='Published Post',
        slug='published-post',
        content='Content',
        author_id=user.id,
        category_id=category.id,
        status='published'
    )
    post.save()
    
    # Create draft post
    draft = Post(
        title='Draft Post',
        slug='draft-post',
        content='Content',
        author_id=user.id,
        category_id=category.id,
        status='draft'
    )
    draft.save()
    
    # Only published posts should count
    assert category.posts_count == 1`,
    '.env.example': `# Flask Configuration
FLASK_ENV=development
SECRET_KEY=your-secret-key-change-this-in-production
JWT_SECRET_KEY=your-jwt-secret-key-change-this

# Database Configuration
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/{{projectName}}

# Redis Configuration
REDIS_URL=redis://localhost:6379/0

# Celery Configuration
CELERY_BROKER_URL=redis://localhost:6379/1
CELERY_RESULT_BACKEND=redis://localhost:6379/1

# CORS Configuration
CORS_ORIGINS=http://localhost:3000,http://localhost:3001

# Mail Configuration
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=true
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=your-email@gmail.com

# Application Settings
APP_NAME={{projectName}}
HOST=0.0.0.0
PORT=5000`,
    'docker-compose.yml': `version: '3.8'

services:
  app:
    build: .
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=development
      - DATABASE_URL=postgresql://postgres:postgres@db:5432/{{projectName}}
      - REDIS_URL=redis://redis:6379/0
      - CELERY_BROKER_URL=redis://redis:6379/1
      - CELERY_RESULT_BACKEND=redis://redis:6379/1
    depends_on:
      - db
      - redis
    volumes:
      - .:/app
      - /app/venv
    command: python app.py

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

  celery:
    build: .
    environment:
      - FLASK_ENV=development
      - DATABASE_URL=postgresql://postgres:postgres@db:5432/{{projectName}}
      - REDIS_URL=redis://redis:6379/0
      - CELERY_BROKER_URL=redis://redis:6379/1
      - CELERY_RESULT_BACKEND=redis://redis:6379/1
    depends_on:
      - db
      - redis
    volumes:
      - .:/app
      - /app/venv
    command: celery -A app.celery worker --loglevel=info

volumes:
  postgres_data:`,
    'Dockerfile': `FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc \\
    libpq-dev \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements*.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -r requirements-dev.txt

# Copy application code
COPY . .

# Create directories
RUN mkdir -p instance uploads logs

# Expose port
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]`,
    '.dockerignore': `__pycache__
*.pyc
*.pyo
*.pyd
.Python
env
pip-log.txt
pip-delete-this-directory.txt
.tox
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
*.log
.git
.mypy_cache
.pytest_cache
.hypothesis
venv/
.env
.venv
env/
ENV/
.DS_Store
*.db
*.sqlite3
node_modules/
.vscode/
.idea/`,
    'pytest.ini': `[tool:pytest]
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts = -v --tb=short --strict-markers
markers =
    slow: marks tests as slow (deselect with '-m "not slow"')
    integration: marks tests as integration tests`,
    'pyproject.toml': `[tool.black]
line-length = 100
target-version = ['py311']
include = '\\.pyi?$'
extend-exclude = '''/(migrations|venv|env|\\.env)/'''

[tool.isort]
profile = "black"
line_length = 100
multi_line_output = 3
include_trailing_comma = true
force_grid_wrap = 0
use_parentheses = true
ensure_newline_before_comments = true
skip_glob = ["*/migrations/*", "venv/*", "env/*"]

[tool.mypy]
python_version = "3.11"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
ignore_missing_imports = true
exclude = ["migrations/", "venv/", "env/"]

[tool.flake8]
max-line-length = 100
extend-ignore = E203, W503
exclude = migrations,venv,env,.env,__pycache__`,
    'migrations/.gitkeep': `# This file ensures the migrations directory is tracked by git`,
    'instance/.gitkeep': `# This file ensures the instance directory is tracked by git`,
    'uploads/.gitkeep': `# This file ensures the uploads directory is tracked by git`,
    'logs/.gitkeep': `# This file ensures the logs directory is tracked by git`,
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
pip-wheel-metadata/
share/python-wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# PyInstaller
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
target/

# Jupyter Notebook
.ipynb_checkpoints

# IPython
profile_default/
ipython_config.py

# pyenv
.python-version

# pipenv
Pipfile.lock

# PEP 582
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

# Flask
*.db
*.sqlite3
uploads/
logs/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db`,
    'README.md': `# {{projectName}}

A Flask web application with SQLAlchemy, JWT authentication, and comprehensive API features.

## Features

- **Flask Application Factory**: Modular application structure with blueprints
- **SQLAlchemy ORM**: Database models with relationships and migrations
- **JWT Authentication**: Secure authentication with access and refresh tokens
- **Role-Based Access Control**: User roles and permissions
- **RESTful API**: Complete CRUD operations for users and blog system
- **Flask-Admin**: Administrative interface for content management
- **Marshmallow Schemas**: Data validation and serialization
- **Background Tasks**: Celery integration for asynchronous processing
- **Caching**: Redis caching support
- **Rate Limiting**: API rate limiting with Flask-Limiter
- **Testing**: Comprehensive test suite with pytest
- **Docker Support**: Containerized deployment with Docker Compose
- **Code Quality**: Black, isort, flake8, and mypy integration

## Quick Start

### Local Development

1. **Clone and setup**:
   \`\`\`bash
   git clone <repository-url>
   cd {{projectName}}
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\\Scripts\\activate
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   \`\`\`

2. **Environment setup**:
   \`\`\`bash
   cp .env.example .env
   # Edit .env with your database and other configurations
   \`\`\`

3. **Database setup**:
   \`\`\`bash
   flask db init
   flask db migrate -m "Initial migration"
   flask db upgrade
   flask init-db
   flask create-admin
   \`\`\`

4. **Run the application**:
   \`\`\`bash
   python app.py
   \`\`\`

### Docker Development

\`\`\`bash
docker-compose up -d
\`\`\`

## API Documentation

### Authentication Endpoints

- \`POST /api/v1/auth/register\` - User registration
- \`POST /api/v1/auth/login\` - User login
- \`POST /api/v1/auth/refresh\` - Refresh access token
- \`DELETE /api/v1/auth/logout\` - User logout
- \`PUT /api/v1/auth/change-password\` - Change password

### User Endpoints

- \`GET /api/v1/users/\` - Get all users (paginated)
- \`GET /api/v1/users/me\` - Get current user profile
- \`PUT /api/v1/users/me\` - Update current user profile
- \`GET /api/v1/users/{id}\` - Get user by ID
- \`PUT /api/v1/users/{id}\` - Update user (admin only)
- \`DELETE /api/v1/users/{id}\` - Delete user (admin only)

### Blog Endpoints

- \`GET /api/v1/blog/categories\` - Get all categories
- \`POST /api/v1/blog/categories\` - Create category (admin only)
- \`GET /api/v1/blog/tags\` - Get all tags
- \`POST /api/v1/blog/tags\` - Create tag
- \`GET /api/v1/blog/posts\` - Get all posts (paginated)
- \`POST /api/v1/blog/posts\` - Create post
- \`GET /api/v1/blog/posts/{slug}\` - Get post by slug
- \`PUT /api/v1/blog/posts/{slug}\` - Update post
- \`DELETE /api/v1/blog/posts/{slug}\` - Delete post
- \`POST /api/v1/blog/posts/{slug}/like\` - Like post
- \`GET /api/v1/blog/posts/{slug}/comments\` - Get post comments
- \`POST /api/v1/blog/posts/{slug}/comments\` - Create comment

## Testing

\`\`\`bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app

# Run specific test file
pytest tests/test_auth.py

# Run with verbose output
pytest -v
\`\`\`

## Code Quality

\`\`\`bash
# Format code
black .
isort .

# Lint code
flake8 .

# Type checking
mypy .
\`\`\`

## Database Migrations

\`\`\`bash
# Create migration
flask db migrate -m "Description of changes"

# Apply migration
flask db upgrade

# Downgrade migration
flask db downgrade
\`\`\`

## Background Tasks

Start Celery worker:

\`\`\`bash
celery -A app.celery worker --loglevel=info
\`\`\`

Start Celery beat (for scheduled tasks):

\`\`\`bash
celery -A app.celery beat --loglevel=info
\`\`\`

## Admin Interface

Access the admin interface at \`http://localhost:5000/admin/\` after creating an admin user.

## Project Structure

\`\`\`
{{projectName}}/
├── app/
│   ├── __init__.py          # Application factory
│   ├── config.py            # Configuration classes
│   ├── models/              # Database models
│   ├── schemas/             # Marshmallow schemas
│   ├── auth/                # Authentication blueprint
│   ├── users/               # Users blueprint
│   ├── blog/                # Blog blueprint
│   ├── main/                # Main blueprint
│   ├── admin_views.py       # Flask-Admin views
│   ├── errors.py            # Error handlers
│   ├── cli.py               # CLI commands
│   └── tasks.py             # Celery tasks
├── tests/                   # Test suite
├── migrations/              # Database migrations
├── instance/                # Instance-specific files
├── uploads/                 # File uploads
├── logs/                    # Application logs
├── requirements.txt         # Python dependencies
├── requirements-dev.txt     # Development dependencies
├── docker-compose.yml       # Docker Compose configuration
├── Dockerfile               # Docker image configuration
└── README.md               # This file
\`\`\`

## Environment Variables

See \`.env.example\` for all available environment variables.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for your changes
5. Run the test suite
6. Submit a pull request

## License

This project is licensed under the MIT License.`
  },
  prompts: [
    {
      type: 'input',
      name: 'projectName',
      message: 'What is your project name?',
      default: 'flask-app'
    }
  ],
  postInstall: [
    'python -m venv venv',
    'source venv/bin/activate',
    'pip install -r requirements.txt',
    'pip install -r requirements-dev.txt',
    'cp .env.example .env',
    'mkdir -p instance uploads logs',
    'echo "✅ Flask application created successfully!"',
    'echo ""',
    'echo "📝 Next steps:"',
    'echo "   1. Activate virtual environment: source venv/bin/activate"',
    'echo "   2. Update .env with your database configuration"',
    'echo "   3. Initialize database: flask db init && flask db migrate && flask db upgrade"',
    'echo "   4. Create admin user: flask create-admin"',
    'echo "   5. Start development server: python app.py"',
    'echo "   6. Visit http://localhost:5000/admin/ for admin panel"',
    'echo ""',
    'echo "🐳 Docker option:"',
    'echo "   docker-compose up -d"',
    'echo ""',
    'echo "🧪 Run tests:"',
    'echo "   pytest"'
  ]
};