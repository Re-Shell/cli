import { BackendTemplate } from '../../types';

export const djangoTemplate: BackendTemplate = {
  id: 'django',
  name: 'Django',
  description: 'Python\'s most popular web framework with batteries included',
  features: [
    'Django REST Framework',
    'PostgreSQL with Django ORM',
    'JWT Authentication',
    'Swagger/OpenAPI Documentation',
    'Celery for Async Tasks',
    'Redis Caching',
    'Admin Interface',
    'Email Backend',
    'Static/Media Files',
    'Docker Support'
  ],
  dependencies: {
    runtime: [
      'django==5.0.1',
      'djangorestframework==3.14.0',
      'django-cors-headers==4.3.1',
      'djangorestframework-simplejwt==5.3.1',
      'drf-spectacular==0.27.0',
      'celery==5.3.4',
      'redis==5.0.1',
      'django-redis==5.4.0',
      'psycopg2-binary==2.9.9',
      'pillow==10.2.0',
      'django-environ==0.11.2',
      'gunicorn==21.2.0',
      'whitenoise==6.6.0'
    ],
    development: [
      'django-debug-toolbar==4.2.0',
      'pytest==7.4.4',
      'pytest-django==4.7.0',
      'pytest-cov==4.1.0',
      'black==23.12.1',
      'flake8==7.0.0',
      'isort==5.13.2',
      'factory-boy==3.3.0',
      'faker==22.0.0'
    ]
  },
  structure: {
    'backend/': {
      'manage.py': `#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys


def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
`,
      'requirements.txt': `# Production dependencies
django==5.0.1
djangorestframework==3.14.0
django-cors-headers==4.3.1
djangorestframework-simplejwt==5.3.1
drf-spectacular==0.27.0
celery==5.3.4
redis==5.0.1
django-redis==5.4.0
psycopg2-binary==2.9.9
pillow==10.2.0
django-environ==0.11.2
gunicorn==21.2.0
whitenoise==6.6.0
`,
      'requirements-dev.txt': `# Development dependencies
-r requirements.txt
django-debug-toolbar==4.2.0
pytest==7.4.4
pytest-django==4.7.0
pytest-cov==4.1.0
black==23.12.1
flake8==7.0.0
isort==5.13.2
factory-boy==3.3.0
faker==22.0.0
`,
      '.env.example': `# Django settings
DEBUG=True
SECRET_KEY=your-secret-key-here
ALLOWED_HOSTS=localhost,127.0.0.1

# Database
DATABASE_URL=postgres://postgres:password@localhost:5432/{{service_name}}

# Redis
REDIS_URL=redis://localhost:6379/0

# Celery
CELERY_BROKER_URL=redis://localhost:6379/1
CELERY_RESULT_BACKEND=redis://localhost:6379/2

# Email
EMAIL_HOST=localhost
EMAIL_PORT=1025
EMAIL_USE_TLS=False
DEFAULT_FROM_EMAIL=noreply@example.com

# CORS
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001

# JWT
ACCESS_TOKEN_LIFETIME_MINUTES=60
REFRESH_TOKEN_LIFETIME_DAYS=7
`,
      'pytest.ini': `[tool:pytest]
DJANGO_SETTINGS_MODULE = config.settings.test
python_files = tests.py test_*.py *_tests.py
addopts = 
    --verbose
    --strict-markers
    --tb=short
    --cov=.
    --cov-report=term-missing:skip-covered
    --cov-report=html
    --cov-report=xml
testpaths = tests
`,
      'setup.cfg': `[flake8]
max-line-length = 88
extend-ignore = E203, W503
exclude = 
    .git,
    __pycache__,
    migrations,
    .venv,
    venv

[isort]
profile = black
known_django = django
sections = FUTURE,STDLIB,DJANGO,THIRDPARTY,FIRSTPARTY,LOCALFOLDER
`,
      'config/': {
        '__init__.py': '',
        'settings/': {
          '__init__.py': `from .base import *  # noqa

# Load environment-specific settings
import os

env = os.environ.get('DJANGO_ENV', 'development')

if env == 'production':
    from .production import *  # noqa
elif env == 'test':
    from .test import *  # noqa
else:
    from .development import *  # noqa
`,
          'base.py': `"""
Django base settings for {{service_name}} project.
"""
import os
from datetime import timedelta
from pathlib import Path

import environ

# Build paths inside the project
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Environment variables
env = environ.Env(
    DEBUG=(bool, False),
    ALLOWED_HOSTS=(list, ['localhost', '127.0.0.1']),
    CORS_ALLOWED_ORIGINS=(list, []),
)
environ.Env.read_env(os.path.join(BASE_DIR, '.env'))

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = env('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = env('DEBUG')

ALLOWED_HOSTS = env('ALLOWED_HOSTS')

# Application definition
DJANGO_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

THIRD_PARTY_APPS = [
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
    'drf_spectacular',
    'django_redis',
]

LOCAL_APPS = [
    'apps.users',
    'apps.api',
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

# Database
DATABASES = {
    'default': env.db()
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Custom user model
AUTH_USER_MODEL = 'users.User'

# REST Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
}

# JWT Settings
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(
        minutes=env.int('ACCESS_TOKEN_LIFETIME_MINUTES', default=60)
    ),
    'REFRESH_TOKEN_LIFETIME': timedelta(
        days=env.int('REFRESH_TOKEN_LIFETIME_DAYS', default=7)
    ),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
}

# CORS Settings
CORS_ALLOWED_ORIGINS = env('CORS_ALLOWED_ORIGINS')
CORS_ALLOW_CREDENTIALS = True

# Celery Configuration
CELERY_BROKER_URL = env('CELERY_BROKER_URL', default='redis://localhost:6379/1')
CELERY_RESULT_BACKEND = env('CELERY_RESULT_BACKEND', default='redis://localhost:6379/2')
CELERY_ACCEPT_CONTENT = ['application/json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 30 * 60  # 30 minutes

# Cache Configuration
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': env('REDIS_URL', default='redis://localhost:6379/0'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

# Email Configuration
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = env('EMAIL_HOST', default='localhost')
EMAIL_PORT = env.int('EMAIL_PORT', default=1025)
EMAIL_USE_TLS = env.bool('EMAIL_USE_TLS', default=False)
EMAIL_USE_SSL = env.bool('EMAIL_USE_SSL', default=False)
EMAIL_HOST_USER = env('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD', default='')
DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_EMAIL', default='noreply@example.com')

# Spectacular Settings (OpenAPI)
SPECTACULAR_SETTINGS = {
    'TITLE': '{{service_name}} API',
    'DESCRIPTION': 'API documentation for {{service_name}}',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
    'SWAGGER_UI_SETTINGS': {
        'deepLinking': True,
        'persistAuthorization': True,
        'displayOperationId': True,
    },
    'COMPONENT_SPLIT_REQUEST': True,
    'SCHEMA_PATH_PREFIX': '/api/',
}

# Logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'filters': {
        'require_debug_true': {
            '()': 'django.utils.log.RequireDebugTrue',
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'filters': ['require_debug_true'],
            'class': 'logging.StreamHandler',
            'formatter': 'simple'
        },
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': BASE_DIR / 'logs' / 'django.log',
            'maxBytes': 1024 * 1024 * 15,  # 15MB
            'backupCount': 10,
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console', 'file'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}
`,
          'development.py': `"""
Development-specific settings.
"""
from .base import *  # noqa

# Debug toolbar
INSTALLED_APPS += ['debug_toolbar']  # noqa
MIDDLEWARE = ['debug_toolbar.middleware.DebugToolbarMiddleware'] + MIDDLEWARE  # noqa

# Debug toolbar settings
INTERNAL_IPS = ['127.0.0.1', 'localhost']
DEBUG_TOOLBAR_CONFIG = {
    'SHOW_TOOLBAR_CALLBACK': lambda request: DEBUG,  # noqa
}

# Email backend for development
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# CORS - Allow all origins in development
CORS_ALLOW_ALL_ORIGINS = True

# Celery - Use eager mode in development
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True
`,
          'production.py': `"""
Production-specific settings.
"""
from .base import *  # noqa

# Security settings
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Force DEBUG to False
DEBUG = False

# Email backend for production
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'

# Logging - More detailed in production
LOGGING['handlers']['file']['level'] = 'WARNING'  # noqa
LOGGING['loggers']['django']['level'] = 'WARNING'  # noqa
`,
          'test.py': `"""
Test-specific settings.
"""
from .base import *  # noqa

# Use in-memory database for tests
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

# Disable migrations during tests
class DisableMigrations:
    def __contains__(self, item):
        return True

    def __getitem__(self, item):
        return None

MIGRATION_MODULES = DisableMigrations()

# Use dummy cache
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.dummy.DummyCache',
    }
}

# Password hasher for faster tests
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]

# Email backend for tests
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'

# Celery - Use eager mode in tests
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True
`,
        },
        'urls.py': `"""
URL configuration for {{service_name}} project.
"""
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)

urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),
    
    # API
    path('api/', include('apps.api.urls')),
    path('api/auth/', include('apps.users.urls')),
    
    # API Documentation
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/swagger/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    
    # Debug toolbar
    import debug_toolbar
    urlpatterns = [
        path('__debug__/', include(debug_toolbar.urls)),
    ] + urlpatterns
`,
        'wsgi.py': `"""
WSGI config for {{service_name}} project.
"""
import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

application = get_wsgi_application()
`,
        'asgi.py': `"""
ASGI config for {{service_name}} project.
"""
import os

from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

application = get_asgi_application()
`,
        'celery.py': `"""
Celery configuration for {{service_name}} project.
"""
import os

from celery import Celery

# Set the default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

# Create Celery app
app = Celery('{{service_name}}')

# Load configuration from Django settings
app.config_from_object('django.conf:settings', namespace='CELERY')

# Auto-discover tasks from all registered Django apps
app.autodiscover_tasks()
`,
        '__init__.py': `# This will make sure the app is always imported when
# Django starts so that shared_task will use this app.
from .celery import app as celery_app

__all__ = ('celery_app',)
`,
      },
      'apps/': {
        '__init__.py': '',
        'users/': {
          '__init__.py': '',
          'apps.py': `from django.apps import AppConfig


class UsersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.users'
    verbose_name = 'Users'
`,
          'models.py': `from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """Custom user model."""
    
    email = models.EmailField(unique=True)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    
    class Meta:
        db_table = 'users'
        ordering = ['-created_at']
        
    def __str__(self):
        return self.email
`,
          'serializers.py': `from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken

from .models import User


class UserSerializer(serializers.ModelSerializer):
    """User serializer."""
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 
                  'is_verified', 'created_at', 'updated_at']
        read_only_fields = ['id', 'is_verified', 'created_at', 'updated_at']


class RegisterSerializer(serializers.ModelSerializer):
    """Registration serializer."""
    
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password_confirm', 
                  'first_name', 'last_name']
        
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = User.objects.create_user(**validated_data)
        return user


class LoginSerializer(serializers.Serializer):
    """Login serializer."""
    
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        
        if email and password:
            user = authenticate(username=email, password=password)
            
            if not user:
                raise serializers.ValidationError('Invalid credentials')
                
            if not user.is_active:
                raise serializers.ValidationError('User account is disabled')
                
        else:
            raise serializers.ValidationError('Must include "email" and "password"')
            
        attrs['user'] = user
        return attrs


class TokenSerializer(serializers.Serializer):
    """JWT token serializer."""
    
    access = serializers.CharField(read_only=True)
    refresh = serializers.CharField(read_only=True)
    
    def create(self, validated_data):
        user = validated_data['user']
        refresh = RefreshToken.for_user(user)
        
        return {
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        }
`,
          'views.py': `from django.contrib.auth import login
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .models import User
from .serializers import (
    LoginSerializer,
    RegisterSerializer,
    TokenSerializer,
    UserSerializer,
)


class RegisterView(generics.CreateAPIView):
    """User registration endpoint."""
    
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        # Auto-login after registration
        refresh = TokenSerializer().create({'user': user})
        
        return Response({
            'user': UserSerializer(user).data,
            'tokens': refresh
        }, status=status.HTTP_201_CREATED)


class LoginView(generics.GenericAPIView):
    """User login endpoint."""
    
    serializer_class = LoginSerializer
    permission_classes = [permissions.AllowAny]
    
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        
        # Login user
        login(request, user)
        
        # Generate tokens
        tokens = TokenSerializer().create({'user': user})
        
        return Response({
            'user': UserSerializer(user).data,
            'tokens': tokens
        })


class ProfileView(generics.RetrieveUpdateAPIView):
    """User profile endpoint."""
    
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):
        return self.request.user


class CustomTokenObtainPairView(TokenObtainPairView):
    """Custom JWT token obtain view."""
    pass


class CustomTokenRefreshView(TokenRefreshView):
    """Custom JWT token refresh view."""
    pass
`,
          'urls.py': `from django.urls import path

from .views import (
    CustomTokenObtainPairView,
    CustomTokenRefreshView,
    LoginView,
    ProfileView,
    RegisterView,
)

app_name = 'users'

urlpatterns = [
    # Authentication
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('profile/', ProfileView.as_view(), name='profile'),
    
    # JWT Token endpoints
    path('token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
]
`,
          'admin.py': `from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """User admin configuration."""
    
    list_display = ['email', 'username', 'first_name', 'last_name', 
                    'is_verified', 'is_staff', 'created_at']
    list_filter = ['is_verified', 'is_staff', 'is_superuser', 'is_active']
    search_fields = ['email', 'username', 'first_name', 'last_name']
    ordering = ['-created_at']
    
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Additional Info', {'fields': ('is_verified',)}),
    )
    
    add_fieldsets = BaseUserAdmin.add_fieldsets + (
        ('Additional Info', {'fields': ('email', 'is_verified',)}),
    )
`,
          'migrations/': {
            '__init__.py': '',
          },
          'tests/': {
            '__init__.py': '',
            'test_models.py': `import pytest
from django.contrib.auth import get_user_model

User = get_user_model()


@pytest.mark.django_db
class TestUserModel:
    """Test User model."""
    
    def test_create_user(self):
        """Test creating a user."""
        user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        assert user.username == 'testuser'
        assert user.email == 'test@example.com'
        assert user.check_password('testpass123')
        assert not user.is_staff
        assert not user.is_superuser
        assert not user.is_verified
        
    def test_create_superuser(self):
        """Test creating a superuser."""
        user = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='adminpass123'
        )
        
        assert user.is_staff
        assert user.is_superuser
        
    def test_str_representation(self):
        """Test string representation."""
        user = User(email='test@example.com')
        assert str(user) == 'test@example.com'
`,
            'test_views.py': `import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

User = get_user_model()


@pytest.mark.django_db
class TestAuthenticationViews:
    """Test authentication views."""
    
    @pytest.fixture
    def api_client(self):
        return APIClient()
    
    @pytest.fixture
    def user(self):
        return User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
    
    def test_register(self, api_client):
        """Test user registration."""
        url = reverse('users:register')
        data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'newpass123',
            'password_confirm': 'newpass123',
            'first_name': 'New',
            'last_name': 'User'
        }
        
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_201_CREATED
        assert 'user' in response.data
        assert 'tokens' in response.data
        assert response.data['user']['email'] == 'newuser@example.com'
        assert User.objects.filter(email='newuser@example.com').exists()
    
    def test_login(self, api_client, user):
        """Test user login."""
        url = reverse('users:login')
        data = {
            'email': 'test@example.com',
            'password': 'testpass123'
        }
        
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_200_OK
        assert 'user' in response.data
        assert 'tokens' in response.data
        assert response.data['user']['email'] == 'test@example.com'
    
    def test_profile(self, api_client, user):
        """Test user profile."""
        api_client.force_authenticate(user=user)
        url = reverse('users:profile')
        
        # Get profile
        response = api_client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert response.data['email'] == 'test@example.com'
        
        # Update profile
        data = {'first_name': 'Updated'}
        response = api_client.patch(url, data, format='json')
        assert response.status_code == status.HTTP_200_OK
        assert response.data['first_name'] == 'Updated'
`,
          },
        },
        'api/': {
          '__init__.py': '',
          'apps.py': `from django.apps import AppConfig


class ApiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.api'
    verbose_name = 'API'
`,
          'models.py': `from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()


class BaseModel(models.Model):
    """Abstract base model with common fields."""
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        abstract = True


class Example(BaseModel):
    """Example model."""
    
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='examples'
    )
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'examples'
        ordering = ['-created_at']
        
    def __str__(self):
        return self.title
`,
          'serializers.py': `from rest_framework import serializers

from .models import Example


class ExampleSerializer(serializers.ModelSerializer):
    """Example serializer."""
    
    user = serializers.ReadOnlyField(source='user.email')
    
    class Meta:
        model = Example
        fields = ['id', 'title', 'description', 'user', 'is_active',
                  'created_at', 'updated_at']
        read_only_fields = ['id', 'user', 'created_at', 'updated_at']
`,
          'views.py': `from rest_framework import viewsets, permissions, filters
from django_filters.rest_framework import DjangoFilterBackend

from .models import Example
from .serializers import ExampleSerializer
from .permissions import IsOwnerOrReadOnly


class ExampleViewSet(viewsets.ModelViewSet):
    """Example API endpoint."""
    
    serializer_class = ExampleSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, 
                       filters.OrderingFilter]
    filterset_fields = ['is_active']
    search_fields = ['title', 'description']
    ordering_fields = ['created_at', 'updated_at', 'title']
    ordering = ['-created_at']
    
    def get_queryset(self):
        """Filter queryset to user's own objects."""
        return Example.objects.filter(user=self.request.user)
    
    def perform_create(self, serializer):
        """Set user on create."""
        serializer.save(user=self.request.user)
`,
          'permissions.py': `from rest_framework import permissions


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    """
    
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request
        if request.method in permissions.SAFE_METHODS:
            return True
            
        # Write permissions are only allowed to the owner
        return obj.user == request.user
`,
          'urls.py': `from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import ExampleViewSet

app_name = 'api'

router = DefaultRouter()
router.register(r'examples', ExampleViewSet, basename='example')

urlpatterns = [
    path('', include(router.urls)),
]
`,
          'admin.py': `from django.contrib import admin

from .models import Example


@admin.register(Example)
class ExampleAdmin(admin.ModelAdmin):
    """Example admin configuration."""
    
    list_display = ['title', 'user', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['title', 'description', 'user__email']
    readonly_fields = ['created_at', 'updated_at']
    ordering = ['-created_at']
    
    fieldsets = (
        (None, {
            'fields': ('title', 'description', 'user', 'is_active')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
`,
          'tasks.py': `from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings


@shared_task
def send_notification_email(user_email, subject, message):
    """Send notification email task."""
    send_mail(
        subject,
        message,
        settings.DEFAULT_FROM_EMAIL,
        [user_email],
        fail_silently=False,
    )
    return f"Email sent to {user_email}"


@shared_task
def process_example(example_id):
    """Process example task."""
    from .models import Example
    
    try:
        example = Example.objects.get(id=example_id)
        # Perform some processing
        example.description = f"Processed: {example.description}"
        example.save()
        return f"Example {example_id} processed successfully"
    except Example.DoesNotExist:
        return f"Example {example_id} not found"
`,
          'migrations/': {
            '__init__.py': '',
          },
          'tests/': {
            '__init__.py': '',
            'test_api.py': `import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from apps.api.models import Example

User = get_user_model()


@pytest.mark.django_db
class TestExampleAPI:
    """Test Example API endpoints."""
    
    @pytest.fixture
    def api_client(self):
        return APIClient()
    
    @pytest.fixture
    def user(self):
        return User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
    
    @pytest.fixture
    def example(self, user):
        return Example.objects.create(
            title='Test Example',
            description='Test description',
            user=user
        )
    
    def test_list_examples(self, api_client, user, example):
        """Test listing examples."""
        api_client.force_authenticate(user=user)
        url = reverse('api:example-list')
        
        response = api_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) == 1
        assert response.data['results'][0]['title'] == 'Test Example'
    
    def test_create_example(self, api_client, user):
        """Test creating an example."""
        api_client.force_authenticate(user=user)
        url = reverse('api:example-list')
        data = {
            'title': 'New Example',
            'description': 'New description',
            'is_active': True
        }
        
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['title'] == 'New Example'
        assert Example.objects.filter(title='New Example').exists()
    
    def test_update_example(self, api_client, user, example):
        """Test updating an example."""
        api_client.force_authenticate(user=user)
        url = reverse('api:example-detail', kwargs={'pk': example.pk})
        data = {'title': 'Updated Example'}
        
        response = api_client.patch(url, data, format='json')
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['title'] == 'Updated Example'
    
    def test_delete_example(self, api_client, user, example):
        """Test deleting an example."""
        api_client.force_authenticate(user=user)
        url = reverse('api:example-detail', kwargs={'pk': example.pk})
        
        response = api_client.delete(url)
        
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not Example.objects.filter(pk=example.pk).exists()
    
    def test_unauthorized_access(self, api_client):
        """Test unauthorized access."""
        url = reverse('api:example-list')
        
        response = api_client.get(url)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
`,
          },
        },
      },
      'static/': {
        '.gitkeep': '',
      },
      'media/': {
        '.gitkeep': '',
      },
      'logs/': {
        '.gitkeep': '',
      },
      'templates/': {
        '.gitkeep': '',
      },
      'tests/': {
        '__init__.py': '',
        'conftest.py': `import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

User = get_user_model()


@pytest.fixture
def api_client():
    """Provide API client for tests."""
    return APIClient()


@pytest.fixture
def user():
    """Create a test user."""
    return User.objects.create_user(
        username='testuser',
        email='test@example.com',
        password='testpass123'
    )


@pytest.fixture
def authenticated_client(api_client, user):
    """Provide authenticated API client."""
    api_client.force_authenticate(user=user)
    return api_client
`,
      },
      'docker-compose.yml': `version: '3.8'

services:
  db:
    image: postgres:16-alpine
    volumes:
      - postgres_data:/var/lib/postgresql/data
    environment:
      POSTGRES_DB: {{service_name}}
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  web:
    build: .
    command: >
      sh -c "python manage.py migrate &&
             python manage.py collectstatic --noinput &&
             gunicorn config.wsgi:application --bind 0.0.0.0:8000"
    volumes:
      - .:/app
      - static_volume:/app/staticfiles
      - media_volume:/app/media
    ports:
      - "8000:8000"
    env_file:
      - .env
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy

  celery:
    build: .
    command: celery -A config worker -l info
    volumes:
      - .:/app
    env_file:
      - .env
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy

  celery-beat:
    build: .
    command: celery -A config beat -l info
    volumes:
      - .:/app
    env_file:
      - .env
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy

  mailhog:
    image: mailhog/mailhog
    ports:
      - "1025:1025"  # SMTP server
      - "8025:8025"  # Web UI

volumes:
  postgres_data:
  static_volume:
  media_volume:
`,
      'Dockerfile': `FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=config.settings

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

# Copy project
COPY . .

# Create necessary directories
RUN mkdir -p /app/staticfiles /app/media /app/logs

# Create non-root user
RUN useradd -m -u 1000 django && chown -R django:django /app

# Switch to non-root user
USER django

# Run the application
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000"]
`,
      '.dockerignore': `# Python
__pycache__
*.pyc
*.pyo
*.pyd
.Python
pip-log.txt
pip-delete-this-directory.txt
.tox/
.coverage
.coverage.*
.cache
.pytest_cache/
coverage.xml
*.cover
*.log
.git
.gitignore
.mypy_cache
.hypothesis

# Django
*.sqlite3
media/
staticfiles/
logs/

# Environment
.env
.env.*
venv/
env/
ENV/

# IDEs
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
Thumbs.db

# Project specific
docker-compose.override.yml
`,
      '.gitignore': `# Python
__pycache__/
*.py[cod]
*$py.class
*.so
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
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# Django
*.log
*.pot
*.pyc
local_settings.py
db.sqlite3
media/
staticfiles/

# Environment
.env
.env.*
venv/
env/
ENV/
env.bak/
venv.bak/

# IDEs
.vscode/
.idea/
*.swp
*.swo
*~
.project
.pydevproject

# Testing
.tox/
.coverage
.coverage.*
.cache
.pytest_cache/
nosetests.xml
coverage.xml
*.cover
.hypothesis/
htmlcov/

# OS
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Project specific
logs/
celerybeat-schedule
celerybeat.pid
`,
      'README.md': `# {{service_name}}

A Django REST API service with authentication, Celery tasks, and Redis caching.

## Features

- Django REST Framework for API development
- PostgreSQL database with Django ORM
- JWT authentication with djangorestframework-simplejwt
- Swagger/OpenAPI documentation with drf-spectacular
- Celery for asynchronous task processing
- Redis for caching and Celery broker
- Docker support for development and production
- Comprehensive test suite with pytest

## Quick Start

### Local Development

1. Create a virtual environment:
   \`\`\`bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\\Scripts\\activate
   \`\`\`

2. Install dependencies:
   \`\`\`bash
   pip install -r requirements-dev.txt
   \`\`\`

3. Set up environment variables:
   \`\`\`bash
   cp .env.example .env
   # Edit .env with your configuration
   \`\`\`

4. Run migrations:
   \`\`\`bash
   python manage.py migrate
   \`\`\`

5. Create a superuser:
   \`\`\`bash
   python manage.py createsuperuser
   \`\`\`

6. Run the development server:
   \`\`\`bash
   python manage.py runserver
   \`\`\`

### Docker Development

1. Build and start services:
   \`\`\`bash
   docker-compose up --build
   \`\`\`

2. Run migrations:
   \`\`\`bash
   docker-compose exec web python manage.py migrate
   \`\`\`

3. Create a superuser:
   \`\`\`bash
   docker-compose exec web python manage.py createsuperuser
   \`\`\`

## API Documentation

- Swagger UI: http://localhost:8000/api/swagger/
- ReDoc: http://localhost:8000/api/redoc/
- OpenAPI Schema: http://localhost:8000/api/schema/

## Admin Interface

Django Admin is available at: http://localhost:8000/admin/

## Testing

Run tests with pytest:
\`\`\`bash
pytest
\`\`\`

Run tests with coverage:
\`\`\`bash
pytest --cov
\`\`\`

## Project Structure

\`\`\`
backend/
├── config/              # Project configuration
│   ├── settings/       # Environment-specific settings
│   ├── urls.py         # URL configuration
│   └── celery.py       # Celery configuration
├── apps/               # Django applications
│   ├── users/          # User authentication app
│   └── api/            # Main API app
├── static/             # Static files
├── media/              # User-uploaded files
├── templates/          # HTML templates
├── tests/              # Test suite
├── manage.py           # Django management script
└── docker-compose.yml  # Docker configuration
\`\`\`

## Environment Variables

See \`.env.example\` for all available environment variables.

## Deployment

For production deployment:

1. Set \`DEBUG=False\` in environment
2. Configure a proper database
3. Set up a reverse proxy (nginx)
4. Configure static file serving
5. Set up SSL certificates
6. Configure email backend

## License

MIT License
`,
    }
  }
};