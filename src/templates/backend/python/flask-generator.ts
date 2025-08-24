import { PythonBackendGenerator } from './python-base-generator';

export class FlaskGenerator extends PythonBackendGenerator {
  constructor() {
    super('Flask');
  }
  
  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'flask': '^3.0.2',
      'flask-restful': '^0.3.10',
      'flask-sqlalchemy': '^3.1.1',
      'flask-migrate': '^4.0.7',
      'flask-marshmallow': '^1.2.1',
      'marshmallow-sqlalchemy': '^1.0.0',
      'flask-jwt-extended': '^4.6.0',
      'flask-cors': '^4.0.0',
      'flask-limiter': '^3.5.1',
      'flask-caching': '^2.1.0',
      'flask-mail': '^0.9.1',
      'flask-socketio': '^5.3.6',
      'python-socketio': '^5.11.1',
      'celery[redis]': '^5.3.6',
      'redis': '^5.0.3',
      'psycopg2-binary': '^2.9.9',
      'python-dotenv': '^1.0.1',
      'gunicorn': '^21.2.0',
      'eventlet': '^0.35.2'
    };
  }
  
  protected getFrameworkDevDependencies(): Record<string, string> {
    return {
      'pytest': '^8.1.1',
      'pytest-flask': '^1.3.0',
      'pytest-cov': '^5.0.0',
      'pytest-mock': '^3.12.0',
      'factory-boy': '^3.3.0',
      'faker': '^24.0.0',
      'black': '^24.3.0',
      'isort': '^5.13.2',
      'flake8': '^7.0.0',
      'mypy': '^1.9.0',
      'bandit[toml]': '^1.7.8',
      'pre-commit': '^3.6.2',
      'flask-debugtoolbar': '^0.14.1'
    };
  }
  
  protected generateMainFile(): string {
    return [
      'import os',
      'import sys',
      'from pathlib import Path',
      '',
      '# Add the project root to the Python path',
      'sys.path.insert(0, str(Path(__file__).parent))',
      '',
      'from app import create_app',
      'from app.extensions import db',
      '',
      'app = create_app(os.getenv(\'FLASK_ENV\', \'development\'))',
      '',
      'if __name__ == \'__main__\':',
      '    with app.app_context():',
      '        db.create_all()',
      '    app.run(host=\'0.0.0.0\', port=int(os.getenv(\'PORT\', 5000)))'
    ].join('\n');
  }
  
  protected generateConfigFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'config.py',
        content: this.generateConfigContent()
      },
      {
        path: 'app/__init__.py',
        content: this.generateAppInitContent()
      },
      {
        path: 'app/extensions.py',
        content: this.generateExtensionsContent()
      },
      {
        path: 'wsgi.py',
        content: this.generateWSGIContent()
      }
    ];
  }
  
  private generateConfigContent(): string {
    return [
      'import os',
      'from datetime import timedelta',
      'from pathlib import Path',
      '',
      'basedir = Path(__file__).parent',
      '',
      '',
      'class Config:',
      '    """Base configuration."""',
      '    SECRET_KEY = os.getenv(\'SECRET_KEY\', \'dev-secret-key-change-this\')',
      '    SQLALCHEMY_TRACK_MODIFICATIONS = False',
      '    SQLALCHEMY_RECORD_QUERIES = True',
      '    ',
      '    # JWT Configuration',
      '    JWT_SECRET_KEY = os.getenv(\'JWT_SECRET_KEY\', SECRET_KEY)',
      '    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)',
      '    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)',
      '    JWT_BLACKLIST_ENABLED = True',
      '    JWT_BLACKLIST_TOKEN_CHECKS = [\'access\', \'refresh\']',
      '    ',
      '    # Mail Configuration',
      '    MAIL_SERVER = os.getenv(\'MAIL_SERVER\', \'smtp.gmail.com\')',
      '    MAIL_PORT = int(os.getenv(\'MAIL_PORT\', 587))',
      '    MAIL_USE_TLS = os.getenv(\'MAIL_USE_TLS\', \'true\').lower() == \'true\'',
      '    MAIL_USERNAME = os.getenv(\'MAIL_USERNAME\')',
      '    MAIL_PASSWORD = os.getenv(\'MAIL_PASSWORD\')',
      '    MAIL_DEFAULT_SENDER = os.getenv(\'MAIL_DEFAULT_SENDER\', \'noreply@example.com\')',
      '    ',
      '    # Redis Configuration',
      '    REDIS_URL = os.getenv(\'REDIS_URL\', \'redis://localhost:6379/0\')',
      '    ',
      '    # Celery Configuration',
      '    CELERY_BROKER_URL = os.getenv(\'CELERY_BROKER_URL\', REDIS_URL)',
      '    CELERY_RESULT_BACKEND = os.getenv(\'CELERY_RESULT_BACKEND\', REDIS_URL)',
      '    ',
      '    # Cache Configuration',
      '    CACHE_TYPE = \'redis\'',
      '    CACHE_REDIS_URL = REDIS_URL',
      '    CACHE_DEFAULT_TIMEOUT = 300',
      '    ',
      '    # Rate Limiting',
      '    RATELIMIT_STORAGE_URI = REDIS_URL',
      '    RATELIMIT_DEFAULT = "100 per hour"',
      '    ',
      '    # File Upload',
      '    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB',
      '    UPLOAD_FOLDER = basedir / \'uploads\'',
      '    ALLOWED_EXTENSIONS = {\'txt\', \'pdf\', \'png\', \'jpg\', \'jpeg\', \'gif\'}',
      '',
      '',
      'class DevelopmentConfig(Config):',
      '    """Development configuration."""',
      '    DEBUG = True',
      '    SQLALCHEMY_DATABASE_URI = os.getenv(',
      '        \'DATABASE_URL\',',
      '        f\'postgresql://postgres:postgres@localhost:5432/{os.getenv("DB_NAME", "flask_dev")}\'',
      '    )',
      '    SQLALCHEMY_ECHO = True',
      '',
      '',
      'class TestingConfig(Config):',
      '    """Testing configuration."""',
      '    TESTING = True',
      '    SQLALCHEMY_DATABASE_URI = \'sqlite:///:memory:\'',
      '    WTF_CSRF_ENABLED = False',
      '',
      '',
      'class ProductionConfig(Config):',
      '    """Production configuration."""',
      '    DEBUG = False',
      '    SQLALCHEMY_DATABASE_URI = os.getenv(\'DATABASE_URL\')',
      '    SQLALCHEMY_ENGINE_OPTIONS = {',
      '        \'pool_size\': 10,',
      '        \'pool_recycle\': 3600,',
      '        \'pool_pre_ping\': True,',
      '    }',
      '',
      '',
      'config = {',
      '    \'development\': DevelopmentConfig,',
      '    \'testing\': TestingConfig,',
      '    \'production\': ProductionConfig,',
      '    \'default\': DevelopmentConfig',
      '}'
    ].join('\n');
  }
  
  private generateAppInitContent(): string {
    return [
      'from flask import Flask',
      'from flask_cors import CORS',
      '',
      'from config import config',
      'from app.extensions import (',
      '    db, migrate, ma, jwt, cors, limiter, cache, mail, socketio',
      ')',
      '',
      '',
      'def create_app(config_name=\'development\'):',
      '    """Application factory pattern."""',
      '    app = Flask(__name__)',
      '    app.config.from_object(config[config_name])',
      '    ',
      '    # Initialize extensions',
      '    db.init_app(app)',
      '    migrate.init_app(app, db)',
      '    ma.init_app(app)',
      '    jwt.init_app(app)',
      '    CORS(app)',
      '    limiter.init_app(app)',
      '    cache.init_app(app)',
      '    mail.init_app(app)',
      '    socketio.init_app(app, cors_allowed_origins="*")',
      '    ',
      '    # Register blueprints',
      '    from app.api import api_bp',
      '    app.register_blueprint(api_bp, url_prefix=\'/api/v1\')',
      '    ',
      '    from app.auth import auth_bp',
      '    app.register_blueprint(auth_bp, url_prefix=\'/api/v1/auth\')',
      '    ',
      '    from app.websocket import ws_bp',
      '    app.register_blueprint(ws_bp)',
      '    ',
      '    # Register error handlers',
      '    from app.errors import register_error_handlers',
      '    register_error_handlers(app)',
      '    ',
      '    # Register CLI commands',
      '    from app.commands import register_commands',
      '    register_commands(app)',
      '    ',
      '    # Health check',
      '    @app.route(\'/health\')',
      '    def health_check():',
      '        return {\'status\': \'healthy\'}, 200',
      '    ',
      '    return app'
    ].join('\n');
  }
  
  private generateExtensionsContent(): string {
    return [
      '"""Flask extensions initialization."""',
      'from flask_sqlalchemy import SQLAlchemy',
      'from flask_migrate import Migrate',
      'from flask_marshmallow import Marshmallow',
      'from flask_jwt_extended import JWTManager',
      'from flask_cors import CORS',
      'from flask_limiter import Limiter',
      'from flask_limiter.util import get_remote_address',
      'from flask_caching import Cache',
      'from flask_mail import Mail',
      'from flask_socketio import SocketIO',
      '',
      '# Database',
      'db = SQLAlchemy()',
      'migrate = Migrate()',
      '',
      '# Serialization',
      'ma = Marshmallow()',
      '',
      '# Authentication',
      'jwt = JWTManager()',
      '',
      '# CORS',
      'cors = CORS()',
      '',
      '# Rate limiting',
      'limiter = Limiter(',
      '    key_func=get_remote_address,',
      '    default_limits=["200 per day", "50 per hour"]',
      ')',
      '',
      '# Caching',
      'cache = Cache()',
      '',
      '# Email',
      'mail = Mail()',
      '',
      '# WebSocket',
      'socketio = SocketIO()'
    ].join('\n');
  }
  
  private generateWSGIContent(): string {
    return [
      '"""WSGI entry point."""',
      'import os',
      'from app import create_app',
      '',
      'app = create_app(os.getenv(\'FLASK_ENV\', \'production\'))',
      '',
      'if __name__ == \'__main__\':',
      '    app.run()'
    ].join('\n');
  }
  
  protected generateModelFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'app/models/__init__.py',
        content: 'from .user import User\nfrom .base import BaseModel'
      },
      {
        path: 'app/models/base.py',
        content: this.generateBaseModelContent()
      },
      {
        path: 'app/models/user.py',
        content: this.generateUserModelContent()
      }
    ];
  }
  
  private generateBaseModelContent(): string {
    return [
      'from datetime import datetime',
      'from app.extensions import db',
      '',
      '',
      'class BaseModel(db.Model):',
      '    """Base model with common fields."""',
      '    __abstract__ = True',
      '    ',
      '    id = db.Column(db.Integer, primary_key=True)',
      '    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)',
      '    updated_at = db.Column(',
      '        db.DateTime,',
      '        default=datetime.utcnow,',
      '        onupdate=datetime.utcnow,',
      '        nullable=False',
      '    )',
      '    ',
      '    def save(self):',
      '        """Save the model."""',
      '        db.session.add(self)',
      '        db.session.commit()',
      '    ',
      '    def delete(self):',
      '        """Delete the model."""',
      '        db.session.delete(self)',
      '        db.session.commit()',
      '    ',
      '    @classmethod',
      '    def get_by_id(cls, id):',
      '        """Get model by ID."""',
      '        return cls.query.get(id)'
    ].join('\n');
  }
  
  private generateUserModelContent(): string {
    return [
      'from datetime import datetime',
      'from werkzeug.security import generate_password_hash, check_password_hash',
      'from app.extensions import db',
      'from .base import BaseModel',
      '',
      '',
      'class User(BaseModel):',
      '    """User model."""',
      '    __tablename__ = \'users\'',
      '    ',
      '    username = db.Column(db.String(80), unique=True, nullable=False, index=True)',
      '    email = db.Column(db.String(120), unique=True, nullable=False, index=True)',
      '    password_hash = db.Column(db.String(255), nullable=False)',
      '    first_name = db.Column(db.String(80))',
      '    last_name = db.Column(db.String(80))',
      '    is_active = db.Column(db.Boolean, default=True)',
      '    is_verified = db.Column(db.Boolean, default=False)',
      '    last_login = db.Column(db.DateTime)',
      '    ',
      '    def __repr__(self):',
      '        return f\'<User {self.username}>\'',
      '    ',
      '    def set_password(self, password):',
      '        """Set password hash."""',
      '        self.password_hash = generate_password_hash(password)',
      '    ',
      '    def check_password(self, password):',
      '        """Check password against hash."""',
      '        return check_password_hash(self.password_hash, password)',
      '    ',
      '    def update_last_login(self):',
      '        """Update last login timestamp."""',
      '        self.last_login = datetime.utcnow()',
      '        db.session.commit()',
      '    ',
      '    @classmethod',
      '    def get_by_username(cls, username):',
      '        """Get user by username."""',
      '        return cls.query.filter_by(username=username).first()',
      '    ',
      '    @classmethod',
      '    def get_by_email(cls, email):',
      '        """Get user by email."""',
      '        return cls.query.filter_by(email=email).first()'
    ].join('\n');
  }
  
  protected generateAPIFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'app/api/__init__.py',
        content: this.generateAPIInitContent()
      },
      {
        path: 'app/api/users.py',
        content: this.generateUsersAPIContent()
      },
      {
        path: 'app/auth/__init__.py',
        content: this.generateAuthInitContent()
      },
      {
        path: 'app/auth/views.py',
        content: this.generateAuthViewsContent()
      }
    ];
  }
  
  private generateAPIInitContent(): string {
    return [
      'from flask import Blueprint',
      '',
      'api_bp = Blueprint(\'api\', __name__)',
      '',
      'from . import users'
    ].join('\n');
  }
  
  private generateUsersAPIContent(): string {
    return [
      'from flask import jsonify, request',
      'from flask_jwt_extended import jwt_required, get_jwt_identity',
      'from app.api import api_bp',
      'from app.models import User',
      'from app.schemas import UserSchema',
      'from app.extensions import db, cache, limiter',
      '',
      'user_schema = UserSchema()',
      'users_schema = UserSchema(many=True)',
      '',
      '',
      '@api_bp.route(\'/users\', methods=[\'GET\'])',
      '@jwt_required()',
      '@limiter.limit("30 per minute")',
      '@cache.cached(timeout=60)',
      'def get_users():',
      '    """Get all users."""',
      '    page = request.args.get(\'page\', 1, type=int)',
      '    per_page = request.args.get(\'per_page\', 20, type=int)',
      '    ',
      '    users = User.query.paginate(page=page, per_page=per_page)',
      '    return {',
      '        \'users\': users_schema.dump(users.items),',
      '        \'total\': users.total,',
      '        \'pages\': users.pages,',
      '        \'current_page\': page',
      '    }',
      '',
      '',
      '@api_bp.route(\'/users/<int:id>\', methods=[\'GET\'])',
      '@jwt_required()',
      'def get_user(id):',
      '    """Get user by ID."""',
      '    user = User.get_by_id(id)',
      '    if not user:',
      '        return {\'message\': \'User not found\'}, 404',
      '    return user_schema.dump(user)',
      '',
      '',
      '@api_bp.route(\'/users/me\', methods=[\'GET\'])',
      '@jwt_required()',
      'def get_current_user():',
      '    """Get current user."""',
      '    user_id = get_jwt_identity()',
      '    user = User.get_by_id(user_id)',
      '    return user_schema.dump(user)',
      '',
      '',
      '@api_bp.route(\'/users/<int:id>\', methods=[\'PUT\'])',
      '@jwt_required()',
      'def update_user(id):',
      '    """Update user."""',
      '    current_user_id = get_jwt_identity()',
      '    if current_user_id != id:',
      '        return {\'message\': \'Unauthorized\'}, 403',
      '    ',
      '    user = User.get_by_id(id)',
      '    if not user:',
      '        return {\'message\': \'User not found\'}, 404',
      '    ',
      '    data = request.get_json()',
      '    user.first_name = data.get(\'first_name\', user.first_name)',
      '    user.last_name = data.get(\'last_name\', user.last_name)',
      '    user.save()',
      '    ',
      '    cache.delete_memoized(get_users)',
      '    return user_schema.dump(user)'
    ].join('\n');
  }
  
  private generateAuthInitContent(): string {
    return [
      'from flask import Blueprint',
      '',
      'auth_bp = Blueprint(\'auth\', __name__)',
      '',
      'from . import views'
    ].join('\n');
  }
  
  private generateAuthViewsContent(): string {
    return [
      'from flask import request, jsonify',
      'from flask_jwt_extended import (',
      '    create_access_token, create_refresh_token,',
      '    jwt_required, get_jwt_identity, get_jwt',
      ')',
      'from app.auth import auth_bp',
      'from app.models import User',
      'from app.schemas import UserSchema',
      'from app.extensions import db, jwt, limiter',
      '',
      'user_schema = UserSchema()',
      '',
      '# Token blacklist storage (in production, use Redis)',
      'blacklist = set()',
      '',
      '',
      '@jwt.token_in_blocklist_loader',
      'def check_if_token_in_blacklist(jwt_header, jwt_payload):',
      '    return jwt_payload[\'jti\'] in blacklist',
      '',
      '',
      '@auth_bp.route(\'/register\', methods=[\'POST\'])',
      '@limiter.limit("5 per hour")',
      'def register():',
      '    """Register a new user."""',
      '    data = request.get_json()',
      '    ',
      '    # Validate required fields',
      '    required = [\'username\', \'email\', \'password\']',
      '    if not all(field in data for field in required):',
      '        return {\'message\': \'Missing required fields\'}, 400',
      '    ',
      '    # Check if user exists',
      '    if User.get_by_username(data[\'username\']):',
      '        return {\'message\': \'Username already exists\'}, 400',
      '    if User.get_by_email(data[\'email\']):',
      '        return {\'message\': \'Email already registered\'}, 400',
      '    ',
      '    # Create user',
      '    user = User(',
      '        username=data[\'username\'],',
      '        email=data[\'email\'],',
      '        first_name=data.get(\'first_name\', \'\'),',
      '        last_name=data.get(\'last_name\', \'\')',
      '    )',
      '    user.set_password(data[\'password\'])',
      '    user.save()',
      '    ',
      '    return {',
      '        \'message\': \'User created successfully\',',
      '        \'user\': user_schema.dump(user)',
      '    }, 201',
      '',
      '',
      '@auth_bp.route(\'/login\', methods=[\'POST\'])',
      '@limiter.limit("10 per hour")',
      'def login():',
      '    """Login user."""',
      '    data = request.get_json()',
      '    username = data.get(\'username\')',
      '    password = data.get(\'password\')',
      '    ',
      '    if not username or not password:',
      '        return {\'message\': \'Username and password required\'}, 400',
      '    ',
      '    user = User.get_by_username(username)',
      '    if not user or not user.check_password(password):',
      '        return {\'message\': \'Invalid credentials\'}, 401',
      '    ',
      '    if not user.is_active:',
      '        return {\'message\': \'Account deactivated\'}, 401',
      '    ',
      '    user.update_last_login()',
      '    ',
      '    access_token = create_access_token(identity=user.id)',
      '    refresh_token = create_refresh_token(identity=user.id)',
      '    ',
      '    return {',
      '        \'access_token\': access_token,',
      '        \'refresh_token\': refresh_token,',
      '        \'user\': user_schema.dump(user)',
      '    }',
      '',
      '',
      '@auth_bp.route(\'/refresh\', methods=[\'POST\'])',
      '@jwt_required(refresh=True)',
      'def refresh():',
      '    """Refresh access token."""',
      '    identity = get_jwt_identity()',
      '    access_token = create_access_token(identity=identity)',
      '    return {\'access_token\': access_token}',
      '',
      '',
      '@auth_bp.route(\'/logout\', methods=[\'POST\'])',
      '@jwt_required()',
      'def logout():',
      '    """Logout user."""',
      '    jti = get_jwt()[\'jti\']',
      '    blacklist.add(jti)',
      '    return {\'message\': \'Successfully logged out\'}'
    ].join('\n');
  }
  
  protected generateCRUDFiles(): { path: string; content: string }[] {
    return [];
  }
  
  protected generateSchemaFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'app/schemas/__init__.py',
        content: 'from .user import UserSchema'
      },
      {
        path: 'app/schemas/user.py',
        content: this.generateUserSchemaContent()
      }
    ];
  }
  
  private generateUserSchemaContent(): string {
    return [
      'from marshmallow import Schema, fields, validate',
      '',
      '',
      'class UserSchema(Schema):',
      '    """User schema for serialization."""',
      '    id = fields.Int(dump_only=True)',
      '    username = fields.Str(',
      '        required=True,',
      '        validate=validate.Length(min=3, max=80)',
      '    )',
      '    email = fields.Email(required=True)',
      '    password = fields.Str(',
      '        required=True,',
      '        load_only=True,',
      '        validate=validate.Length(min=6)',
      '    )',
      '    first_name = fields.Str(validate=validate.Length(max=80))',
      '    last_name = fields.Str(validate=validate.Length(max=80))',
      '    is_active = fields.Bool(dump_only=True)',
      '    is_verified = fields.Bool(dump_only=True)',
      '    created_at = fields.DateTime(dump_only=True)',
      '    updated_at = fields.DateTime(dump_only=True)',
      '    last_login = fields.DateTime(dump_only=True)'
    ].join('\n');
  }
  
  protected generateServiceFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'app/services/__init__.py',
        content: ''
      },
      {
        path: 'app/tasks.py',
        content: this.generateTasksContent()
      },
      {
        path: 'celery_app.py',
        content: this.generateCeleryContent()
      }
    ];
  }
  
  private generateTasksContent(): string {
    return [
      'from celery import shared_task',
      'from flask_mail import Message',
      'from app.extensions import mail',
      '',
      '',
      '@shared_task',
      'def send_email_task(subject, recipient, body, html=None):',
      '    """Send email asynchronously."""',
      '    msg = Message(',
      '        subject=subject,',
      '        recipients=[recipient],',
      '        body=body,',
      '        html=html',
      '    )',
      '    mail.send(msg)',
      '    return f\'Email sent to {recipient}\'',
      '',
      '',
      '@shared_task',
      'def example_task(x, y):',
      '    """Example Celery task."""',
      '    return x + y'
    ].join('\n');
  }
  
  private generateCeleryContent(): string {
    return [
      'import os',
      'from celery import Celery',
      '',
      '',
      'def make_celery(app_name=__name__):',
      '    """Create Celery instance."""',
      '    return Celery(',
      '        app_name,',
      '        broker=os.getenv(\'CELERY_BROKER_URL\', \'redis://localhost:6379/0\'),',
      '        backend=os.getenv(\'CELERY_RESULT_BACKEND\', \'redis://localhost:6379/0\'),',
      '        include=[\'app.tasks\']',
      '    )',
      '',
      '',
      'celery = make_celery(\'app\')'
    ].join('\n');
  }
  
  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'app/errors.py',
        content: this.generateErrorsContent()
      },
      {
        path: 'app/utils.py',
        content: this.generateUtilsContent()
      }
    ];
  }
  
  private generateErrorsContent(): string {
    return [
      'from flask import jsonify',
      'from werkzeug.exceptions import HTTPException',
      '',
      '',
      'def register_error_handlers(app):',
      '    """Register error handlers."""',
      '    ',
      '    @app.errorhandler(HTTPException)',
      '    def handle_exception(e):',
      '        """Handle HTTP exceptions."""',
      '        return jsonify({',
      '            \'code\': e.code,',
      '            \'message\': e.description,',
      '        }), e.code',
      '    ',
      '    @app.errorhandler(404)',
      '    def not_found(e):',
      '        """Handle 404 errors."""',
      '        return jsonify({\'message\': \'Resource not found\'}), 404',
      '    ',
      '    @app.errorhandler(500)',
      '    def internal_error(e):',
      '        """Handle 500 errors."""',
      '        return jsonify({\'message\': \'Internal server error\'}), 500'
    ].join('\n');
  }
  
  private generateUtilsContent(): string {
    return [
      'import os',
      'from functools import wraps',
      'from flask import current_app',
      '',
      '',
      'def allowed_file(filename):',
      '    """Check if file extension is allowed."""',
      '    return \'.\' in filename and \\',
      '        filename.rsplit(\'.\', 1)[1].lower() in current_app.config[\'ALLOWED_EXTENSIONS\']',
      '',
      '',
      'def get_file_extension(filename):',
      '    """Get file extension."""',
      '    return filename.rsplit(\'.\', 1)[1].lower() if \'.\' in filename else \'\'',
      '',
      '',
      'def create_upload_folder():',
      '    """Create upload folder if it doesn\'t exist."""',
      '    upload_folder = current_app.config[\'UPLOAD_FOLDER\']',
      '    if not os.path.exists(upload_folder):',
      '        os.makedirs(upload_folder)'
    ].join('\n');
  }
  
  protected generateUtilFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'app/websocket/__init__.py',
        content: this.generateWebSocketInitContent()
      },
      {
        path: 'app/websocket/events.py',
        content: this.generateWebSocketEventsContent()
      },
      {
        path: 'app/commands.py',
        content: this.generateCommandsContent()
      }
    ];
  }
  
  private generateWebSocketInitContent(): string {
    return [
      'from flask import Blueprint',
      '',
      'ws_bp = Blueprint(\'websocket\', __name__)',
      '',
      'from . import events'
    ].join('\n');
  }
  
  private generateWebSocketEventsContent(): string {
    return [
      'from flask import request',
      'from flask_socketio import emit, join_room, leave_room',
      'from flask_jwt_extended import jwt_required, get_jwt_identity',
      'from app.extensions import socketio',
      '',
      '',
      '@socketio.on(\'connect\')',
      '@jwt_required()',
      'def handle_connect():',
      '    """Handle client connection."""',
      '    user_id = get_jwt_identity()',
      '    join_room(f\'user_{user_id}\')',
      '    emit(\'connected\', {\'message\': \'Connected successfully\'})',
      '',
      '',
      '@socketio.on(\'disconnect\')',
      'def handle_disconnect():',
      '    """Handle client disconnection."""',
      '    emit(\'disconnected\', {\'message\': \'Disconnected\'})',
      '',
      '',
      '@socketio.on(\'join_room\')',
      '@jwt_required()',
      'def handle_join_room(data):',
      '    """Join a room."""',
      '    room = data.get(\'room\')',
      '    if room:',
      '        join_room(room)',
      '        emit(\'joined_room\', {\'room\': room}, room=room)',
      '',
      '',
      '@socketio.on(\'leave_room\')',
      '@jwt_required()',
      'def handle_leave_room(data):',
      '    """Leave a room."""',
      '    room = data.get(\'room\')',
      '    if room:',
      '        leave_room(room)',
      '        emit(\'left_room\', {\'room\': room}, room=room)',
      '',
      '',
      '@socketio.on(\'message\')',
      '@jwt_required()',
      'def handle_message(data):',
      '    """Handle incoming message."""',
      '    room = data.get(\'room\')',
      '    message = data.get(\'message\')',
      '    user_id = get_jwt_identity()',
      '    ',
      '    if room and message:',
      '        emit(\'new_message\', {',
      '            \'user_id\': user_id,',
      '            \'message\': message',
      '        }, room=room)'
    ].join('\n');
  }
  
  private generateCommandsContent(): string {
    return [
      'import click',
      'from flask.cli import with_appcontext',
      'from app.extensions import db',
      'from app.models import User',
      '',
      '',
      'def register_commands(app):',
      '    """Register CLI commands."""',
      '    ',
      '    @app.cli.command()',
      '    @with_appcontext',
      '    def init_db():',
      '        """Initialize the database."""',
      '        db.create_all()',
      '        click.echo(\'Initialized the database.\')',
      '    ',
      '    @app.cli.command()',
      '    @with_appcontext',
      '    def seed_db():',
      '        """Seed the database."""',
      '        # Create admin user',
      '        admin = User(',
      '            username=\'admin\',',
      '            email=\'admin@example.com\',',
      '            first_name=\'Admin\',',
      '            last_name=\'User\',',
      '            is_verified=True',
      '        )',
      '        admin.set_password(\'admin123\')',
      '        admin.save()',
      '        ',
      '        click.echo(\'Database seeded.\')',
      '    ',
      '    @app.cli.command()',
      '    @click.argument(\'username\')',
      '    @click.argument(\'email\')',
      '    @click.argument(\'password\')',
      '    @with_appcontext',
      '    def create_user(username, email, password):',
      '        """Create a new user."""',
      '        user = User(username=username, email=email)',
      '        user.set_password(password)',
      '        user.save()',
      '        click.echo(f\'User {username} created.\')'
    ].join('\n');
  }
}