import { BackendTemplate } from '../types';

export const djangoTemplate: BackendTemplate = {
  id: 'django',
  name: 'django',
  displayName: 'Django',
  description: 'Python\'s most popular web framework with batteries included',
  language: 'python',
  framework: 'django',
  version: '5.0.1',
  tags: ['python', 'django', 'rest-framework', 'orm', 'admin', 'batteries-included'],
  port: 8000,
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
    'django': '5.0.1',
    'djangorestframework': '3.14.0',
    'django-cors-headers': '4.3.1',
    'djangorestframework-simplejwt': '5.3.1',
    'drf-spectacular': '0.27.0',
    'celery': '5.3.4',
    'redis': '5.0.1',
    'django-redis': '5.4.0',
    'psycopg2-binary': '2.9.9',
    'pillow': '10.2.0',
    'django-environ': '0.11.2',
    'gunicorn': '21.2.0',
    'whitenoise': '6.6.0',
    'django-debug-toolbar': '4.2.0',
    'pytest': '7.4.4',
    'pytest-django': '4.7.0',
    'pytest-cov': '4.1.0',
    'black': '23.12.1',
    'flake8': '7.0.0',
    'isort': '5.13.2',
    'factory-boy': '3.3.0',
    'faker': '22.0.0'
  },
  files: {
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
    'config/__init__.py': '',
    'config/settings/__init__.py': `from .base import *  # noqa

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
    'config/settings/base.py': `"""
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
    'default': env.db(),
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
STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Media files
MEDIA_URL = 'media/'
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
    'DEFAULT_FILTER_BACKENDS': [
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
}

# JWT Settings
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=env.int('ACCESS_TOKEN_LIFETIME_MINUTES', 60)),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=env.int('REFRESH_TOKEN_LIFETIME_DAYS', 7)),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'USER_AUTHENTICATION_RULE': 'rest_framework_simplejwt.authentication.default_user_authentication_rule',
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
    'JTI_CLAIM': 'jti',
}

# CORS
CORS_ALLOWED_ORIGINS = env('CORS_ALLOWED_ORIGINS')
CORS_ALLOW_CREDENTIALS = True

# Celery Configuration
CELERY_BROKER_URL = env('CELERY_BROKER_URL', default='redis://localhost:6379/1')
CELERY_RESULT_BACKEND = env('CELERY_RESULT_BACKEND', default='redis://localhost:6379/2')
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE
CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers:DatabaseScheduler'

# Cache
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': env('REDIS_URL', default='redis://localhost:6379/0'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

# Email
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = env('EMAIL_HOST', default='localhost')
EMAIL_PORT = env.int('EMAIL_PORT', default=1025)
EMAIL_USE_TLS = env.bool('EMAIL_USE_TLS', default=False)
EMAIL_HOST_USER = env('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD', default='')
DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_EMAIL', default='noreply@example.com')

# Spectacular Settings
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
    'SCHEMA_PATH_PREFIX': '/api/v1',
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
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
}
`,
    'config/settings/development.py': `"""
Development settings
"""
from .base import *  # noqa

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

# Django Debug Toolbar
INSTALLED_APPS += ['debug_toolbar']  # noqa
MIDDLEWARE.insert(0, 'debug_toolbar.middleware.DebugToolbarMiddleware')  # noqa

# Debug toolbar config
INTERNAL_IPS = [
    '127.0.0.1',
    'localhost',
]

# Email backend for development
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Disable caching in development
CACHES = {
    'default': {
        'BACKEND': 'django.core.backends.dummy.DummyCache',
    }
}

# Allow all origins in development
CORS_ALLOW_ALL_ORIGINS = True
`,
    'config/settings/production.py': `"""
Production settings
"""
from .base import *  # noqa

# Security
DEBUG = False
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Use production email backend
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'

# Sentry error tracking
import sentry_sdk
from sentry_sdk.integrations.django import DjangoIntegration

sentry_sdk.init(
    dsn=env('SENTRY_DSN'),
    integrations=[DjangoIntegration()],
    traces_sample_rate=0.1,
    send_default_pii=True
)
`,
    'config/settings/test.py': `"""
Test settings
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
        'BACKEND': 'django.core.backends.dummy.DummyCache',
    }
}

# Disable Celery during tests
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True

# Speed up password hashing
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]

# Email backend
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'
`,
    'config/urls.py': `"""
URL Configuration for {{service_name}}
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
    path('api/v1/', include('apps.api.urls')),
    
    # API Documentation
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/swagger/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    
    # Debug toolbar
    if 'debug_toolbar' in settings.INSTALLED_APPS:
        import debug_toolbar
        urlpatterns = [
            path('__debug__/', include(debug_toolbar.urls)),
        ] + urlpatterns
`,
    'config/wsgi.py': `"""
WSGI config for {{service_name}} project.
"""
import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

application = get_wsgi_application()
`,
    'config/asgi.py': `"""
ASGI config for {{service_name}} project.
"""
import os

from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

application = get_asgi_application()
`,
    'config/celery.py': `"""
Celery configuration for {{service_name}}
"""
import os

from celery import Celery

# Set default Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

# Create Celery app
app = Celery('{{service_name}}')

# Load configuration from Django settings
app.config_from_object('django.conf:settings', namespace='CELERY')

# Auto-discover tasks from all registered Django apps
app.autodiscover_tasks()
`,
    'config/celery_init.py': `# This will make sure the app is always imported when
# Django starts so that shared_task will use this app.
from .celery import app as celery_app

__all__ = ('celery_app',)
`,
    'apps/__init__.py': '',
    'apps/users/__init__.py': '',
    'apps/users/apps.py': `from django.apps import AppConfig


class UsersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.users'
    verbose_name = 'Users'
`,
    'apps/users/models.py': `from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """
    Custom User model
    """
    email = models.EmailField(unique=True)
    bio = models.TextField(blank=True)
    avatar = models.ImageField(upload_to='avatars/', blank=True, null=True)
    phone_number = models.CharField(max_length=20, blank=True)
    date_of_birth = models.DateField(blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    
    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        ordering = ['-created_at']
    
    def __str__(self):
        return self.email
`,
    'apps/users/admin.py': `from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ['email', 'username', 'first_name', 'last_name', 'is_active', 'is_staff']
    list_filter = ['is_active', 'is_staff', 'is_superuser', 'is_verified']
    search_fields = ['email', 'username', 'first_name', 'last_name']
    ordering = ['-created_at']
    
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Additional Info', {
            'fields': ('bio', 'avatar', 'phone_number', 'date_of_birth', 'is_verified')
        }),
    )
    
    add_fieldsets = BaseUserAdmin.add_fieldsets + (
        ('Additional Info', {
            'fields': ('email', 'bio', 'avatar', 'phone_number', 'date_of_birth')
        }),
    )
`,
    'apps/users/serializers.py': `from django.contrib.auth import get_user_model
from rest_framework import serializers

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    """
    User serializer
    """
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'bio', 'avatar', 'phone_number', 'date_of_birth',
            'is_verified', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'is_verified']


class UserCreateSerializer(serializers.ModelSerializer):
    """
    User registration serializer
    """
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password_confirm', 'first_name', 'last_name']
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        return User.objects.create_user(**validated_data)


class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for password change
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, min_length=8)
    
    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError('Invalid password')
        return value
`,
    'apps/users/views.py': `from django.contrib.auth import get_user_model
from rest_framework import generics, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from .serializers import (
    ChangePasswordSerializer,
    UserCreateSerializer,
    UserSerializer,
)

User = get_user_model()


class UserViewSet(ModelViewSet):
    """
    User viewset
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        return super().get_serializer_class()
    
    def get_permissions(self):
        if self.action == 'create':
            return [permissions.AllowAny()]
        return super().get_permissions()
    
    @action(detail=False, methods=['get'])
    def me(self, request):
        """Get current user"""
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def change_password(self, request):
        """Change password"""
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        
        return Response({'detail': 'Password changed successfully'}, status=status.HTTP_200_OK)
`,
    'apps/users/urls.py': `from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import UserViewSet

router = DefaultRouter()
router.register('users', UserViewSet)

urlpatterns = [
    path('', include(router.urls)),
]
`,
    'apps/users/migrations/__init__.py': '',
    'apps/users/tests/__init__.py': '',
    'apps/users/tests/test_models.py': `import pytest
from django.contrib.auth import get_user_model

User = get_user_model()


@pytest.mark.django_db
class TestUserModel:
    def test_create_user(self):
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
    
    def test_create_superuser(self):
        user = User.objects.create_superuser(
            username='admin',
            email='admin@example.com',
            password='adminpass123'
        )
        assert user.is_staff
        assert user.is_superuser
    
    def test_str_representation(self):
        user = User(email='user@example.com')
        assert str(user) == 'user@example.com'
`,
    'apps/users/tests/test_views.py': `import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

User = get_user_model()


@pytest.mark.django_db
class TestUserViews:
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
    
    def test_register_user(self, api_client):
        url = reverse('user-list')
        data = {
            'username': 'newuser',
            'email': 'new@example.com',
            'password': 'newpass123',
            'password_confirm': 'newpass123',
            'first_name': 'New',
            'last_name': 'User'
        }
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_201_CREATED
        assert User.objects.filter(email='new@example.com').exists()
    
    def test_get_current_user(self, api_client, user):
        api_client.force_authenticate(user=user)
        url = reverse('user-me')
        response = api_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['email'] == user.email
    
    def test_change_password(self, api_client, user):
        api_client.force_authenticate(user=user)
        url = reverse('user-change-password')
        data = {
            'old_password': 'testpass123',
            'new_password': 'newpass123'
        }
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_200_OK
        user.refresh_from_db()
        assert user.check_password('newpass123')
`,
    'apps/api/__init__.py': '',
    'apps/api/apps.py': `from django.apps import AppConfig


class ApiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.api'
    verbose_name = 'API'
`,
    'apps/api/urls.py': `from django.urls import include, path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

from .views import HealthCheckView

urlpatterns = [
    # Health check
    path('health/', HealthCheckView.as_view(), name='health-check'),
    
    # Authentication
    path('auth/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    
    # Apps
    path('', include('apps.users.urls')),
]
`,
    'apps/api/views.py': `from django.db import connection
from django.core.cache import cache
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
import redis
from django.conf import settings


class HealthCheckView(APIView):
    """
    Health check endpoint
    """
    permission_classes = [AllowAny]
    
    def get(self, request):
        health_status = {
            'status': 'healthy',
            'services': {}
        }
        
        # Check database
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            health_status['services']['database'] = 'healthy'
        except Exception as e:
            health_status['services']['database'] = f'unhealthy: {str(e)}'
            health_status['status'] = 'unhealthy'
        
        # Check cache/Redis
        try:
            cache.set('health_check', 'ok', 1)
            if cache.get('health_check') == 'ok':
                health_status['services']['cache'] = 'healthy'
            else:
                health_status['services']['cache'] = 'unhealthy'
                health_status['status'] = 'unhealthy'
        except Exception as e:
            health_status['services']['cache'] = f'unhealthy: {str(e)}'
            health_status['status'] = 'unhealthy'
        
        # Check Redis directly for Celery
        try:
            r = redis.from_url(settings.CELERY_BROKER_URL)
            r.ping()
            health_status['services']['celery_broker'] = 'healthy'
        except Exception as e:
            health_status['services']['celery_broker'] = f'unhealthy: {str(e)}'
            health_status['status'] = 'unhealthy'
        
        status_code = status.HTTP_200_OK if health_status['status'] == 'healthy' else status.HTTP_503_SERVICE_UNAVAILABLE
        return Response(health_status, status=status_code)
`,
    'apps/api/pagination.py': `from rest_framework.pagination import PageNumberPagination


class StandardResultsSetPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


class LargeResultsSetPagination(PageNumberPagination):
    page_size = 100
    page_size_query_param = 'page_size'
    max_page_size = 1000
`,
    'apps/api/permissions.py': `from rest_framework import permissions


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Object-level permission to only allow owners of an object to edit it.
    """
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions are only allowed to the owner
        return obj.owner == request.user


class IsOwner(permissions.BasePermission):
    """
    Object-level permission to only allow owners of an object to view/edit it.
    """
    def has_object_permission(self, request, view, obj):
        return obj.owner == request.user
`,
    'apps/api/exceptions.py': `from rest_framework.views import exception_handler
from rest_framework.exceptions import ValidationError
import logging

logger = logging.getLogger(__name__)


def custom_exception_handler(exc, context):
    """
    Custom exception handler that logs errors
    """
    response = exception_handler(exc, context)
    
    if response is not None:
        # Log the error
        logger.error(
            f"API Error: {exc.__class__.__name__} - {str(exc)}",
            extra={
                'status_code': response.status_code,
                'request_path': context['request'].path,
                'request_method': context['request'].method,
                'user': str(context['request'].user) if context['request'].user.is_authenticated else 'Anonymous'
            }
        )
        
        # Customize error format
        if isinstance(exc, ValidationError) and isinstance(response.data, dict):
            errors = []
            for field, messages in response.data.items():
                if isinstance(messages, list):
                    for message in messages:
                        errors.append({
                            'field': field,
                            'message': str(message)
                        })
                else:
                    errors.append({
                        'field': field,
                        'message': str(messages)
                    })
            
            response.data = {
                'error': 'Validation failed',
                'errors': errors
            }
    
    return response
`,
    'apps/api/middleware.py': `import time
import uuid
from django.utils.deprecation import MiddlewareMixin
import logging

logger = logging.getLogger(__name__)


class RequestIdMiddleware(MiddlewareMixin):
    """
    Add a unique request ID to each request
    """
    def process_request(self, request):
        request.id = request.META.get('HTTP_X_REQUEST_ID', str(uuid.uuid4()))
        request.META['HTTP_X_REQUEST_ID'] = request.id
    
    def process_response(self, request, response):
        if hasattr(request, 'id'):
            response['X-Request-ID'] = request.id
        return response


class RequestLoggingMiddleware(MiddlewareMixin):
    """
    Log all API requests
    """
    def process_request(self, request):
        request.start_time = time.time()
    
    def process_response(self, request, response):
        if hasattr(request, 'start_time'):
            duration = time.time() - request.start_time
            
            logger.info(
                f"{request.method} {request.path} - {response.status_code}",
                extra={
                    'request_id': getattr(request, 'id', None),
                    'method': request.method,
                    'path': request.path,
                    'status_code': response.status_code,
                    'duration': round(duration * 1000, 2),  # in milliseconds
                    'user': str(request.user) if request.user.is_authenticated else 'Anonymous',
                    'ip': self.get_client_ip(request)
                }
            )
        
        return response
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
`,
    'apps/api/migrations/__init__.py': '',
    'apps/api/tests/__init__.py': '',
    'apps/api/tests/test_api.py': `import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient


@pytest.mark.django_db
class TestHealthCheck:
    def test_health_check(self):
        client = APIClient()
        url = reverse('health-check')
        response = client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['status'] in ['healthy', 'unhealthy']
        assert 'services' in response.data
`,
    'tests/__init__.py': '',
    'tests/conftest.py': `import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

User = get_user_model()


@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def user():
    return User.objects.create_user(
        username='testuser',
        email='test@example.com',
        password='testpass123'
    )


@pytest.fixture
def authenticated_client(api_client, user):
    api_client.force_authenticate(user=user)
    return api_client


@pytest.fixture
def admin_user():
    return User.objects.create_superuser(
        username='admin',
        email='admin@example.com',
        password='adminpass123'
    )


@pytest.fixture
def admin_client(api_client, admin_user):
    api_client.force_authenticate(user=admin_user)
    return api_client
`,
    'tests/test_integration.py': `import pytest
from django.urls import reverse
from rest_framework import status


@pytest.mark.django_db
class TestUserFlow:
    def test_complete_user_flow(self, api_client):
        # Register
        register_url = reverse('user-list')
        register_data = {
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'newpass123',
            'password_confirm': 'newpass123'
        }
        response = api_client.post(register_url, register_data, format='json')
        assert response.status_code == status.HTTP_201_CREATED
        
        # Login
        login_url = reverse('token_obtain_pair')
        login_data = {
            'email': 'newuser@example.com',
            'password': 'newpass123'
        }
        response = api_client.post(login_url, login_data, format='json')
        assert response.status_code == status.HTTP_200_OK
        access_token = response.data['access']
        
        # Get profile
        api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        profile_url = reverse('user-me')
        response = api_client.get(profile_url)
        assert response.status_code == status.HTTP_200_OK
        assert response.data['email'] == 'newuser@example.com'
`,
    'Dockerfile': `FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1 \\
    POETRY_VERSION=1.7.1 \\
    POETRY_HOME="/opt/poetry" \\
    POETRY_VIRTUALENVS_CREATE=false

# Install system dependencies
RUN apt-get update \\
    && apt-get install -y --no-install-recommends \\
        build-essential \\
        libpq-dev \\
        curl \\
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python3 -
ENV PATH="$POETRY_HOME/bin:$PATH"

# Set work directory
WORKDIR /app

# Copy dependency files
COPY pyproject.toml poetry.lock* ./

# Install dependencies
RUN poetry install --no-interaction --no-ansi --no-root --only main

# Copy project
COPY . .

# Collect static files
RUN python manage.py collectstatic --noinput

# Run gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "3", "config.wsgi:application"]
`,
    'docker-compose.yml': `version: '3.8'

services:
  web:
    build: .
    command: python manage.py runserver 0.0.0.0:8000
    volumes:
      - .:/app
    ports:
      - "8000:8000"
    env_file:
      - .env
    depends_on:
      - db
      - redis
    restart: unless-stopped

  db:
    image: postgres:15-alpine
    volumes:
      - postgres_data:/var/lib/postgresql/data
    environment:
      - POSTGRES_DB={{service_name}}
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
    ports:
      - "5432:5432"
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    restart: unless-stopped

  celery:
    build: .
    command: celery -A config worker -l info
    volumes:
      - .:/app
    env_file:
      - .env
    depends_on:
      - db
      - redis
    restart: unless-stopped

  celery-beat:
    build: .
    command: celery -A config beat -l info
    volumes:
      - .:/app
    env_file:
      - .env
    depends_on:
      - db
      - redis
    restart: unless-stopped

  flower:
    build: .
    command: celery -A config flower
    volumes:
      - .:/app
    env_file:
      - .env
    ports:
      - "5555:5555"
    depends_on:
      - celery
    restart: unless-stopped

volumes:
  postgres_data:
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

# Virtual Environment
venv/
ENV/
env/
.venv

# Django
*.log
local_settings.py
db.sqlite3
db.sqlite3-journal
media/
staticfiles/

# Environment variables
.env
.env.*

# IDE
.idea/
.vscode/
*.swp
*.swo
*~
.DS_Store

# Testing
.coverage
.pytest_cache/
htmlcov/
.tox/
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover

# Celery
celerybeat-schedule
celerybeat.pid

# Migrations
# migrations/

# Production
*.pid
`,
    'README.md': `# {{service_name}}

Django REST API with JWT authentication, Celery background tasks, and Redis caching.

## Features

- Django REST Framework
- JWT Authentication
- PostgreSQL database
- Redis caching
- Celery async tasks
- Swagger/ReDoc API documentation
- Docker support
- Comprehensive test suite

## Quick Start

1. Clone the repository
2. Copy \`.env.example\` to \`.env\` and update values
3. Run with Docker:
   \`\`\`bash
   docker-compose up
   \`\`\`

4. Or run locally:
   \`\`\`bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\\Scripts\\activate
   pip install -r requirements.txt
   python manage.py migrate
   python manage.py createsuperuser
   python manage.py runserver
   \`\`\`

## API Documentation

- Swagger UI: http://localhost:8000/api/swagger/
- ReDoc: http://localhost:8000/api/redoc/
- Admin: http://localhost:8000/admin/

## Testing

Run tests:
\`\`\`bash
pytest
\`\`\`

With coverage:
\`\`\`bash
pytest --cov
\`\`\`

## Development

1. Install development dependencies:
   \`\`\`bash
   pip install -r requirements-dev.txt
   \`\`\`

2. Run code formatting:
   \`\`\`bash
   black .
   isort .
   \`\`\`

3. Run linting:
   \`\`\`bash
   flake8
   \`\`\`

## Deployment

1. Update environment variables
2. Collect static files: \`python manage.py collectstatic\`
3. Run migrations: \`python manage.py migrate\`
4. Start with gunicorn: \`gunicorn config.wsgi:application\`

## Project Structure

\`\`\`
backend/
├── apps/           # Django apps
├── config/         # Settings and configuration
├── tests/          # Test suite
├── manage.py       # Django management script
└── docker-compose.yml
\`\`\`

## License

MIT License
`
  }
};