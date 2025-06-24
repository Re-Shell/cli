import { BackendTemplate } from '../types';

export const djangoRestTemplate: BackendTemplate = {
  id: 'django-rest-py',
  name: 'Django REST Framework',
  description: 'Django REST Framework with viewsets, serializers, permissions, and comprehensive API features',
  framework: 'django-rest',
  language: 'python',
  version: '1.0.0',
  tags: ['django', 'django-rest-framework', 'python', 'orm', 'admin', 'viewsets', 'serializers'],
  dependencies: {
    django: '^4.2.7',
    djangorestframework: '^3.14.0',
    'django-cors-headers': '^4.3.1',
    'django-filter': '^23.5',
    'djangorestframework-simplejwt': '^5.3.0',
    'django-extensions': '^3.2.3',
    'django-environ': '^0.11.2',
    psycopg2: '^2.9.9',
    redis: '^5.0.1',
    celery: '^5.3.4',
    'django-celery-beat': '^2.5.0',
    'django-celery-results': '^2.5.1',
    pillow: '^10.1.0',
    'django-storages': '^1.14.2',
    'django-debug-toolbar': '^4.2.0',
    'django-silk': '^5.0.4'
  },
  devDependencies: {
    pytest: '^7.4.3',
    'pytest-django': '^4.7.0',
    'pytest-cov': '^4.1.0',
    'factory-boy': '^3.3.0',
    black: '^23.11.0',
    isort: '^5.12.0',
    flake8: '^6.1.0',
    'flake8-django': '^1.4.0',
    mypy: '^1.7.1',
    'django-stubs': '^4.2.7'
  },
  files: {
    'requirements.txt': `Django==4.2.7
djangorestframework==3.14.0
django-cors-headers==4.3.1
django-filter==23.5
djangorestframework-simplejwt==5.3.0
django-extensions==3.2.3
django-environ==0.11.2
psycopg2==2.9.9
redis==5.0.1
celery==5.3.4
django-celery-beat==2.5.0
django-celery-results==2.5.1
Pillow==10.1.0
django-storages==1.14.2
django-debug-toolbar==4.2.0
django-silk==5.0.4`,
    'requirements-dev.txt': `pytest==7.4.3
pytest-django==4.7.0
pytest-cov==4.1.0
factory-boy==3.3.0
black==23.11.0
isort==5.12.0
flake8==6.1.0
flake8-django==1.4.0
mypy==1.7.1
django-stubs==4.2.7`,
    'manage.py': `#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys

if __name__ == '__main__':
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', '{{projectName}}.settings.development')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)`,
    '{{projectName}}/__init__.py': `# Django project package`,
    '{{projectName}}/wsgi.py': `"""
WSGI config for {{projectName}} project.
"""
import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', '{{projectName}}.settings.production')

application = get_wsgi_application()`,
    '{{projectName}}/asgi.py': `"""
ASGI config for {{projectName}} project.
"""
import os
from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', '{{projectName}}.settings.production')

application = get_asgi_application()`,
    '{{projectName}}/urls.py': `"""
URL configuration for {{projectName}} project.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework.routers import DefaultRouter
from rest_framework.documentation import include_docs_urls
from rest_framework_simplejwt.views import TokenRefreshView

from apps.authentication.views import CustomTokenObtainPairView
from apps.users.views import UserViewSet
from apps.core.views import health_check

# API Router
router = DefaultRouter()
router.register(r'users', UserViewSet)

urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),
    
    # API endpoints
    path('api/v1/', include(router.urls)),
    path('api/v1/auth/login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/v1/auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # App URLs
    path('api/v1/users/', include('apps.users.urls')),
    path('api/v1/blog/', include('apps.blog.urls')),
    
    # Utility endpoints
    path('health/', health_check, name='health_check'),
    path('docs/', include_docs_urls(title='{{projectName}} API')),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    
    # Debug toolbar
    if 'debug_toolbar' in settings.INSTALLED_APPS:
        import debug_toolbar
        urlpatterns = [
            path('__debug__/', include(debug_toolbar.urls)),
        ] + urlpatterns`,
    '{{projectName}}/settings/__init__.py': '',
    '{{projectName}}/settings/base.py': `"""
Base Django settings for {{projectName}} project.
"""
import environ
from pathlib import Path

# Build paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
APPS_DIR = BASE_DIR / "apps"

# Environment variables
env = environ.Env(
    DEBUG=(bool, False),
)

# Read environment variables from .env file
environ.Env.read_env(BASE_DIR / '.env')

# Security
SECRET_KEY = env('SECRET_KEY')
DEBUG = env('DEBUG')
ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=[])

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
    'django_filters',
    'django_extensions',
    'django_celery_beat',
    'django_celery_results',
]

LOCAL_APPS = [
    'apps.core',
    'apps.users',
    'apps.authentication',
    'apps.blog',
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = '{{projectName}}.urls'

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

WSGI_APPLICATION = '{{projectName}}.wsgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': env('DB_NAME'),
        'USER': env('DB_USER'),
        'PASSWORD': env('DB_PASSWORD'),
        'HOST': env('DB_HOST', default='localhost'),
        'PORT': env('DB_PORT', default='5432'),
        'CONN_MAX_AGE': env.int('DB_CONN_MAX_AGE', default=60),
    }
}

# Custom User Model
AUTH_USER_MODEL = 'users.User'

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
TIME_ZONE = env('TIME_ZONE', default='UTC')
USE_I18N = True
USE_TZ = True

# Static files
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [
    BASE_DIR / 'static',
]

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# REST Framework configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
        'rest_framework.parsers.FormParser',
        'rest_framework.parsers.MultiPartParser',
    ],
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour'
    }
}

# JWT Configuration
from datetime import timedelta

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=env.int('ACCESS_TOKEN_LIFETIME_MINUTES', default=60)),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=env.int('REFRESH_TOKEN_LIFETIME_DAYS', default=7)),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'VERIFYING_KEY': None,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
}

# CORS Configuration
CORS_ALLOWED_ORIGINS = env.list('CORS_ALLOWED_ORIGINS', default=[
    'http://localhost:3000',
    'http://127.0.0.1:3000',
])

CORS_ALLOW_CREDENTIALS = True

# Cache Configuration
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': env('REDIS_URL', default='redis://127.0.0.1:6379/1'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        },
        'KEY_PREFIX': '{{projectName}}',
        'TIMEOUT': 300,
    }
}

# Session Configuration
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'

# Celery Configuration
CELERY_BROKER_URL = env('CELERY_BROKER_URL', default='redis://127.0.0.1:6379/0')
CELERY_RESULT_BACKEND = env('CELERY_RESULT_BACKEND', default='redis://127.0.0.1:6379/0')
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = TIME_ZONE
CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers:DatabaseScheduler'

# Logging Configuration
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
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'logs' / 'django.log',
            'formatter': 'verbose',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': False,
        },
        '{{projectName}}': {
            'handlers': ['file', 'console'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False,
        },
    },
}`,
    '{{projectName}}/settings/development.py': `"""
Development settings for {{projectName}} project.
"""
from .base import *

# Debug mode
DEBUG = True

# Development apps
INSTALLED_APPS += [
    'debug_toolbar',
    'silk',
]

# Development middleware
MIDDLEWARE += [
    'debug_toolbar.middleware.DebugToolbarMiddleware',
    'silk.middleware.SilkyMiddleware',
]

# Debug toolbar configuration
INTERNAL_IPS = [
    '127.0.0.1',
    'localhost',
]

# Email backend for development
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Silk profiling
SILKY_PYTHON_PROFILER = True
SILKY_PYTHON_PROFILER_BINARY = True

# Cache (use local memory for development)
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
    }
}

# Override any production-specific settings
SECURE_SSL_REDIRECT = False
SECURE_HSTS_SECONDS = 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = False
SECURE_HSTS_PRELOAD = False`,
    '{{projectName}}/settings/production.py': `"""
Production settings for {{projectName}} project.
"""
from .base import *

# Security settings
DEBUG = False
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_HTTPONLY = True

# Production middleware
MIDDLEWARE.insert(1, 'whitenoise.middleware.WhiteNoiseMiddleware')

# Static files (whitenoise)
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Email backend for production
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = env('EMAIL_HOST')
EMAIL_PORT = env.int('EMAIL_PORT', default=587)
EMAIL_HOST_USER = env('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD')
EMAIL_USE_TLS = env.bool('EMAIL_USE_TLS', default=True)
DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_EMAIL')

# Database connection pooling
DATABASES['default']['CONN_MAX_AGE'] = 600

# Logging for production
LOGGING['handlers']['file']['filename'] = '/var/log/{{projectName}}/django.log'`,
    '{{projectName}}/settings/testing.py': `"""
Testing settings for {{projectName}} project.
"""
from .base import *

# Test database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

# Disable migrations for testing
class DisableMigrations:
    def __contains__(self, item):
        return True
    
    def __getitem__(self, item):
        return None

MIGRATION_MODULES = DisableMigrations()

# Cache
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'test-cache',
    }
}

# Password hashers (fast for testing)
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.MD5PasswordHasher',
]

# Email backend for testing
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'

# Celery (synchronous for testing)
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True`,
    'apps/__init__.py': '',
    'apps/core/__init__.py': '',
    'apps/core/apps.py': `from django.apps import AppConfig

class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.core'`,
    'apps/core/models.py': `"""
Core models for the application
"""
from django.db import models
import uuid

class TimestampedModel(models.Model):
    """
    An abstract base class model that provides self-updating
    'created_at' and 'updated_at' fields.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True`,
    'apps/core/views.py': `"""
Core views for the application
"""
from django.http import JsonResponse
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status

@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """
    Health check endpoint
    """
    return JsonResponse({
        'status': 'healthy',
        'timestamp': timezone.now().isoformat(),
        'version': '1.0.0',
    })`,
    'apps/core/permissions.py': `"""
Custom permissions for the application
"""
from rest_framework import permissions

class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    """

    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed for any request,
        # so we'll always allow GET, HEAD or OPTIONS requests.
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write permissions are only allowed to the owner of the object.
        return obj.owner == request.user

class IsAuthorOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow authors of an object to edit it.
    """

    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed for any request
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write permissions are only allowed to the author of the object.
        return obj.author == request.user`,
    'apps/core/pagination.py': `"""
Custom pagination classes
"""
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response

class StandardResultsSetPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100

    def get_paginated_response(self, data):
        return Response({
            'links': {
                'next': self.get_next_link(),
                'previous': self.get_previous_link()
            },
            'count': self.page.paginator.count,
            'page_size': self.page_size,
            'results': data
        })

class LargeResultsSetPagination(PageNumberPagination):
    page_size = 50
    page_size_query_param = 'page_size'
    max_page_size = 200`,
    'apps/users/__init__.py': '',
    'apps/users/apps.py': `from django.apps import AppConfig

class UsersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.users'`,
    'apps/users/models.py': `"""
User models
"""
from django.contrib.auth.models import AbstractUser
from django.db import models
from apps.core.models import TimestampedModel

class User(AbstractUser, TimestampedModel):
    """
    Custom User model
    """
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    is_verified = models.BooleanField(default=False)
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)
    bio = models.TextField(max_length=500, blank=True)
    birth_date = models.DateField(null=True, blank=True)
    location = models.CharField(max_length=100, blank=True)
    website = models.URLField(blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def __str__(self):
        return self.email

    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

class UserProfile(TimestampedModel):
    """
    Extended user profile information
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    phone_number = models.CharField(max_length=20, blank=True)
    address = models.TextField(blank=True)
    company = models.CharField(max_length=100, blank=True)
    job_title = models.CharField(max_length=100, blank=True)
    social_links = models.JSONField(default=dict, blank=True)
    preferences = models.JSONField(default=dict, blank=True)
    
    class Meta:
        db_table = 'user_profiles'
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'

    def __str__(self):
        return f"{self.user.email} Profile"`,
    'apps/users/serializers.py': `"""
User serializers
"""
from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from .models import User, UserProfile

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['phone_number', 'address', 'company', 'job_title', 'social_links', 'preferences']

class UserSerializer(serializers.ModelSerializer):
    profile = UserProfileSerializer(read_only=True)
    password = serializers.CharField(write_only=True, validators=[validate_password])
    full_name = serializers.ReadOnlyField()

    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name', 'full_name',
            'is_verified', 'avatar', 'bio', 'birth_date', 'location', 'website',
            'date_joined', 'last_login', 'profile'
        ]
        read_only_fields = ['id', 'date_joined', 'last_login', 'is_verified']

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()
        
        # Create user profile
        UserProfile.objects.create(user=user)
        
        return user

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        if password:
            instance.set_password(password)
        
        instance.save()
        return instance

class UserCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password])
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
        password = validated_data.pop('password')
        user = User.objects.create_user(**validated_data)
        user.set_password(password)
        user.save()
        
        # Create user profile
        UserProfile.objects.create(user=user)
        
        return user

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'bio', 'birth_date', 'location', 'website', 'avatar']

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_password])
    new_password_confirm = serializers.CharField(required=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("New passwords don't match")
        return attrs`,
    'apps/users/views.py': `"""
User views
"""
from rest_framework import generics, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter

from .models import User, UserProfile
from .serializers import (
    UserSerializer, UserCreateSerializer, UserUpdateSerializer,
    ChangePasswordSerializer, UserProfileSerializer
)
from apps.core.permissions import IsOwnerOrReadOnly
from apps.core.pagination import StandardResultsSetPagination

class UserViewSet(ModelViewSet):
    """
    ViewSet for User model with full CRUD operations
    """
    queryset = User.objects.all().select_related('profile')
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['username', 'email', 'first_name', 'last_name']
    ordering_fields = ['date_joined', 'last_login', 'username']
    ordering = ['-date_joined']
    filterset_fields = ['is_active', 'is_verified']

    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return UserUpdateSerializer
        return UserSerializer

    def get_permissions(self):
        """
        Instantiates and returns the list of permissions that this view requires.
        """
        if self.action == 'create':
            permission_classes = [permissions.AllowAny]
        elif self.action in ['update', 'partial_update', 'destroy']:
            permission_classes = [IsOwnerOrReadOnly]
        else:
            permission_classes = [permissions.IsAuthenticated]
        
        return [permission() for permission in permission_classes]

    @action(detail=False, methods=['get', 'put', 'patch'])
    def me(self, request):
        """
        Get or update current user profile
        """
        if request.method == 'GET':
            serializer = self.get_serializer(request.user)
            return Response(serializer.data)
        
        elif request.method in ['PUT', 'PATCH']:
            partial = request.method == 'PATCH'
            serializer = UserUpdateSerializer(request.user, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(UserSerializer(request.user).data)

    @action(detail=False, methods=['post'])
    def change_password(self, request):
        """
        Change user password
        """
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        if not user.check_password(serializer.validated_data['old_password']):
            return Response(
                {'old_password': 'Invalid password'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        
        return Response({'message': 'Password changed successfully'})

    @action(detail=True, methods=['get', 'put', 'patch'])
    def profile(self, request, pk=None):
        """
        Get or update user profile
        """
        user = self.get_object()
        
        if request.method == 'GET':
            serializer = UserProfileSerializer(user.profile)
            return Response(serializer.data)
        
        elif request.method in ['PUT', 'PATCH']:
            partial = request.method == 'PATCH'
            serializer = UserProfileSerializer(
                user.profile, data=request.data, partial=partial
            )
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data)`,
    'apps/users/urls.py': `"""
User URL patterns
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import UserViewSet

router = DefaultRouter()
router.register(r'', UserViewSet)

urlpatterns = [
    path('', include(router.urls)),
]`,
    'apps/users/admin.py': `"""
User admin configuration
"""
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, UserProfile

class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Profile'

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    inlines = [UserProfileInline]
    list_display = ['email', 'username', 'first_name', 'last_name', 'is_verified', 'is_active', 'date_joined']
    list_filter = ['is_active', 'is_staff', 'is_superuser', 'is_verified', 'date_joined']
    search_fields = ['email', 'username', 'first_name', 'last_name']
    ordering = ['-date_joined']
    
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Additional Info', {
            'fields': ('bio', 'birth_date', 'location', 'website', 'avatar', 'is_verified')
        }),
    )
    
    add_fieldsets = BaseUserAdmin.add_fieldsets + (
        ('Additional Info', {
            'fields': ('email', 'first_name', 'last_name')
        }),
    )

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'phone_number', 'company', 'job_title']
    search_fields = ['user__email', 'user__username', 'company', 'job_title']
    list_filter = ['company']`,
    'apps/authentication/__init__.py': '',
    'apps/authentication/apps.py': `from django.apps import AppConfig

class AuthenticationConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.authentication'`,
    'apps/authentication/views.py': `"""
Authentication views
"""
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom JWT serializer to include additional user data
    """
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        
        # Add custom claims
        token['username'] = user.username
        token['email'] = user.email
        token['is_verified'] = user.is_verified
        
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        
        # Add user data to response
        data['user'] = {
            'id': str(self.user.id),
            'username': self.user.username,
            'email': self.user.email,
            'first_name': self.user.first_name,
            'last_name': self.user.last_name,
            'is_verified': self.user.is_verified,
        }
        
        return data

class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Custom JWT login view
    """
    serializer_class = CustomTokenObtainPairSerializer`,
    'apps/blog/__init__.py': '',
    'apps/blog/apps.py': `from django.apps import AppConfig

class BlogConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.blog'`,
    'apps/blog/models.py': `"""
Blog models
"""
from django.db import models
from django.conf import settings
from apps.core.models import TimestampedModel

class Category(TimestampedModel):
    """
    Blog category model
    """
    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(unique=True)
    description = models.TextField(blank=True)
    
    class Meta:
        db_table = 'blog_categories'
        verbose_name = 'Category'
        verbose_name_plural = 'Categories'
        ordering = ['name']

    def __str__(self):
        return self.name

class Tag(TimestampedModel):
    """
    Blog tag model
    """
    name = models.CharField(max_length=50, unique=True)
    slug = models.SlugField(unique=True)
    
    class Meta:
        db_table = 'blog_tags'
        verbose_name = 'Tag'
        verbose_name_plural = 'Tags'
        ordering = ['name']

    def __str__(self):
        return self.name

class Post(TimestampedModel):
    """
    Blog post model
    """
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('published', 'Published'),
        ('archived', 'Archived'),
    ]
    
    title = models.CharField(max_length=200)
    slug = models.SlugField(unique=True)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='posts')
    content = models.TextField()
    excerpt = models.TextField(blank=True, help_text='Short description of the post')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='draft')
    featured_image = models.ImageField(upload_to='blog/images/', null=True, blank=True)
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, related_name='posts')
    tags = models.ManyToManyField(Tag, blank=True, related_name='posts')
    published_at = models.DateTimeField(null=True, blank=True)
    views_count = models.PositiveIntegerField(default=0)
    likes_count = models.PositiveIntegerField(default=0)
    meta_description = models.CharField(max_length=160, blank=True)
    
    class Meta:
        db_table = 'blog_posts'
        verbose_name = 'Post'
        verbose_name_plural = 'Posts'
        ordering = ['-published_at', '-created_at']

    def __str__(self):
        return self.title

class Comment(TimestampedModel):
    """
    Blog comment model
    """
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='comments')
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    content = models.TextField()
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='replies')
    is_approved = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'blog_comments'
        verbose_name = 'Comment'
        verbose_name_plural = 'Comments'
        ordering = ['-created_at']

    def __str__(self):
        return f'Comment by {self.author.username} on {self.post.title}'`,
    'apps/blog/serializers.py': `"""
Blog serializers
"""
from rest_framework import serializers
from .models import Category, Tag, Post, Comment

class CategorySerializer(serializers.ModelSerializer):
    posts_count = serializers.SerializerMethodField()

    class Meta:
        model = Category
        fields = ['id', 'name', 'slug', 'description', 'posts_count', 'created_at']

    def get_posts_count(self, obj):
        return obj.posts.filter(status='published').count()

class TagSerializer(serializers.ModelSerializer):
    posts_count = serializers.SerializerMethodField()

    class Meta:
        model = Tag
        fields = ['id', 'name', 'slug', 'posts_count', 'created_at']

    def get_posts_count(self, obj):
        return obj.posts.filter(status='published').count()

class CommentSerializer(serializers.ModelSerializer):
    author_name = serializers.CharField(source='author.username', read_only=True)
    replies = serializers.SerializerMethodField()

    class Meta:
        model = Comment
        fields = ['id', 'content', 'author', 'author_name', 'parent', 'replies', 'created_at', 'is_approved']
        read_only_fields = ['author', 'is_approved']

    def get_replies(self, obj):
        if obj.replies.exists():
            return CommentSerializer(obj.replies.filter(is_approved=True), many=True).data
        return []

class PostListSerializer(serializers.ModelSerializer):
    author_name = serializers.CharField(source='author.username', read_only=True)
    category_name = serializers.CharField(source='category.name', read_only=True)
    tags = TagSerializer(many=True, read_only=True)
    comments_count = serializers.SerializerMethodField()

    class Meta:
        model = Post
        fields = [
            'id', 'title', 'slug', 'author', 'author_name', 'excerpt',
            'status', 'featured_image', 'category', 'category_name', 'tags',
            'published_at', 'views_count', 'likes_count', 'comments_count', 'created_at'
        ]

    def get_comments_count(self, obj):
        return obj.comments.filter(is_approved=True).count()

class PostDetailSerializer(serializers.ModelSerializer):
    author_name = serializers.CharField(source='author.username', read_only=True)
    category = CategorySerializer(read_only=True)
    tags = TagSerializer(many=True, read_only=True)
    comments = serializers.SerializerMethodField()
    comments_count = serializers.SerializerMethodField()

    class Meta:
        model = Post
        fields = [
            'id', 'title', 'slug', 'author', 'author_name', 'content', 'excerpt',
            'status', 'featured_image', 'category', 'tags', 'published_at',
            'views_count', 'likes_count', 'meta_description', 'comments',
            'comments_count', 'created_at', 'updated_at'
        ]

    def get_comments(self, obj):
        comments = obj.comments.filter(is_approved=True, parent=None)
        return CommentSerializer(comments, many=True).data

    def get_comments_count(self, obj):
        return obj.comments.filter(is_approved=True).count()

class PostCreateUpdateSerializer(serializers.ModelSerializer):
    tags = serializers.PrimaryKeyRelatedField(queryset=Tag.objects.all(), many=True, required=False)

    class Meta:
        model = Post
        fields = [
            'title', 'slug', 'content', 'excerpt', 'status', 'featured_image',
            'category', 'tags', 'published_at', 'meta_description'
        ]

    def create(self, validated_data):
        tags = validated_data.pop('tags', [])
        post = Post.objects.create(**validated_data)
        post.tags.set(tags)
        return post

    def update(self, instance, validated_data):
        tags = validated_data.pop('tags', None)
        
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        instance.save()
        
        if tags is not None:
            instance.tags.set(tags)
        
        return instance`,
    'apps/blog/views.py': `"""
Blog views
"""
from rest_framework import generics, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter
from django.utils import timezone

from .models import Category, Tag, Post, Comment
from .serializers import (
    CategorySerializer, TagSerializer, PostListSerializer,
    PostDetailSerializer, PostCreateUpdateSerializer, CommentSerializer
)
from apps.core.permissions import IsAuthorOrReadOnly
from apps.core.pagination import StandardResultsSetPagination

class CategoryViewSet(ModelViewSet):
    """
    ViewSet for Category model
    """
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    lookup_field = 'slug'

class TagViewSet(ModelViewSet):
    """
    ViewSet for Tag model
    """
    queryset = Tag.objects.all()
    serializer_class = TagSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    lookup_field = 'slug'

class PostViewSet(ModelViewSet):
    """
    ViewSet for Post model
    """
    queryset = Post.objects.select_related('author', 'category').prefetch_related('tags')
    permission_classes = [permissions.IsAuthenticatedOrReadOnly, IsAuthorOrReadOnly]
    pagination_class = StandardResultsSetPagination
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    search_fields = ['title', 'content', 'excerpt']
    ordering_fields = ['created_at', 'published_at', 'views_count', 'likes_count']
    ordering = ['-published_at']
    filterset_fields = ['status', 'category', 'tags', 'author']
    lookup_field = 'slug'

    def get_serializer_class(self):
        if self.action == 'list':
            return PostListSerializer
        elif self.action in ['create', 'update', 'partial_update']:
            return PostCreateUpdateSerializer
        return PostDetailSerializer

    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Non-authenticated users and non-authors can only see published posts
        if not self.request.user.is_authenticated:
            return queryset.filter(status='published')
        
        # Authors can see their own posts in any status
        if self.action in ['list']:
            return queryset.filter(
                models.Q(status='published') | 
                models.Q(author=self.request.user)
            )
        
        return queryset

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)

    def retrieve(self, request, *args, **kwargs):
        response = super().retrieve(request, *args, **kwargs)
        
        # Increment view count
        instance = self.get_object()
        instance.views_count += 1
        instance.save(update_fields=['views_count'])
        
        return response

    @action(detail=True, methods=['post'])
    def like(self, request, slug=None):
        """
        Like a post
        """
        post = self.get_object()
        post.likes_count += 1
        post.save(update_fields=['likes_count'])
        
        return Response({
            'message': 'Post liked successfully',
            'likes_count': post.likes_count
        })

    @action(detail=True, methods=['post'])
    def publish(self, request, slug=None):
        """
        Publish a draft post
        """
        post = self.get_object()
        
        if post.status != 'draft':
            return Response(
                {'message': 'Only draft posts can be published'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        post.status = 'published'
        post.published_at = timezone.now()
        post.save(update_fields=['status', 'published_at'])
        
        return Response({'message': 'Post published successfully'})

class CommentViewSet(ModelViewSet):
    """
    ViewSet for Comment model
    """
    serializer_class = CommentSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

    def get_queryset(self):
        post_slug = self.kwargs.get('post_slug')
        return Comment.objects.filter(
            post__slug=post_slug,
            is_approved=True
        ).select_related('author', 'post')

    def perform_create(self, serializer):
        post_slug = self.kwargs.get('post_slug')
        post = Post.objects.get(slug=post_slug)
        serializer.save(author=self.request.user, post=post)`,
    'apps/blog/urls.py': `"""
Blog URL patterns
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_nested import routers
from .views import CategoryViewSet, TagViewSet, PostViewSet, CommentViewSet

router = DefaultRouter()
router.register(r'categories', CategoryViewSet)
router.register(r'tags', TagViewSet)
router.register(r'posts', PostViewSet)

# Nested router for comments
posts_router = routers.NestedDefaultRouter(router, r'posts', lookup='post')
posts_router.register(r'comments', CommentViewSet, basename='post-comments')

urlpatterns = [
    path('', include(router.urls)),
    path('', include(posts_router.urls)),
]`,
    'apps/blog/admin.py': `"""
Blog admin configuration
"""
from django.contrib import admin
from .models import Category, Tag, Post, Comment

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'slug', 'created_at']
    prepopulated_fields = {'slug': ('name',)}
    search_fields = ['name']

@admin.register(Tag)
class TagAdmin(admin.ModelAdmin):
    list_display = ['name', 'slug', 'created_at']
    prepopulated_fields = {'slug': ('name',)}
    search_fields = ['name']

@admin.register(Post)
class PostAdmin(admin.ModelAdmin):
    list_display = ['title', 'author', 'status', 'category', 'published_at', 'views_count']
    list_filter = ['status', 'category', 'created_at', 'published_at']
    search_fields = ['title', 'content']
    prepopulated_fields = {'slug': ('title',)}
    filter_horizontal = ['tags']
    date_hierarchy = 'published_at'
    
    fieldsets = (
        ('Content', {
            'fields': ('title', 'slug', 'author', 'content', 'excerpt')
        }),
        ('Meta', {
            'fields': ('status', 'category', 'tags', 'featured_image', 'meta_description')
        }),
        ('Publishing', {
            'fields': ('published_at',)
        }),
        ('Stats', {
            'fields': ('views_count', 'likes_count'),
            'classes': ('collapse',)
        })
    )

@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
    list_display = ['post', 'author', 'content', 'is_approved', 'created_at']
    list_filter = ['is_approved', 'created_at']
    search_fields = ['content', 'author__username', 'post__title']
    actions = ['approve_comments', 'reject_comments']
    
    def approve_comments(self, request, queryset):
        queryset.update(is_approved=True)
        self.message_user(request, f"{queryset.count()} comments approved.")
    
    def reject_comments(self, request, queryset):
        queryset.update(is_approved=False)
        self.message_user(request, f"{queryset.count()} comments rejected.")`,
    'celery_app.py': `"""
Celery configuration
"""
import os
from celery import Celery

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', '{{projectName}}.settings.development')

app = Celery('{{projectName}}')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')`,
    '.env.example': `# Django Settings
SECRET_KEY=your-super-secret-key-change-this-in-production
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database
DB_NAME={{projectName}}
DB_USER=postgres
DB_PASSWORD=postgres
DB_HOST=localhost
DB_PORT=5432
DB_CONN_MAX_AGE=60

# JWT Settings
ACCESS_TOKEN_LIFETIME_MINUTES=60
REFRESH_TOKEN_LIFETIME_DAYS=7

# CORS
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

# Cache & Session
REDIS_URL=redis://127.0.0.1:6379/1

# Celery
CELERY_BROKER_URL=redis://127.0.0.1:6379/0
CELERY_RESULT_BACKEND=redis://127.0.0.1:6379/0

# Email (Production)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
EMAIL_USE_TLS=True
DEFAULT_FROM_EMAIL=noreply@{{projectName}}.com

# Time Zone
TIME_ZONE=UTC`,
    'pytest.ini': `[tool:pytest]
DJANGO_SETTINGS_MODULE = {{projectName}}.settings.testing
addopts = --nomigrations --cov=. --cov-report=html --cov-report=term-missing
testpaths = tests`,
    'tests/__init__.py': '',
    'tests/test_users.py': `"""
Tests for user functionality
"""
import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status

User = get_user_model()

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def user_data():
    return {
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'testpass123',
        'password_confirm': 'testpass123',
        'first_name': 'Test',
        'last_name': 'User'
    }

@pytest.mark.django_db
def test_user_registration(api_client, user_data):
    url = reverse('user-list')
    response = api_client.post(url, user_data)
    
    assert response.status_code == status.HTTP_201_CREATED
    assert User.objects.filter(email=user_data['email']).exists()

@pytest.mark.django_db
def test_user_login(api_client, user_data):
    # Create user
    user = User.objects.create_user(
        username=user_data['username'],
        email=user_data['email'],
        password=user_data['password']
    )
    
    # Login
    url = reverse('token_obtain_pair')
    login_data = {
        'username': user_data['email'],
        'password': user_data['password']
    }
    response = api_client.post(url, login_data)
    
    assert response.status_code == status.HTTP_200_OK
    assert 'access' in response.data
    assert 'refresh' in response.data`,
    'tests/test_blog.py': `"""
Tests for blog functionality
"""
import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from apps.blog.models import Category, Tag, Post

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
def category():
    return Category.objects.create(
        name='Test Category',
        slug='test-category'
    )

@pytest.fixture
def tag():
    return Tag.objects.create(
        name='Test Tag',
        slug='test-tag'
    )

@pytest.mark.django_db
def test_create_post(api_client, user, category, tag):
    api_client.force_authenticate(user=user)
    
    url = reverse('post-list')
    post_data = {
        'title': 'Test Post',
        'slug': 'test-post',
        'content': 'This is a test post content.',
        'status': 'published',
        'category': category.id,
        'tags': [tag.id]
    }
    
    response = api_client.post(url, post_data)
    
    assert response.status_code == status.HTTP_201_CREATED
    assert Post.objects.filter(slug='test-post').exists()

@pytest.mark.django_db
def test_list_posts(api_client, user, category):
    # Create a published post
    Post.objects.create(
        title='Published Post',
        slug='published-post',
        content='Content',
        status='published',
        author=user,
        category=category
    )
    
    # Create a draft post
    Post.objects.create(
        title='Draft Post',
        slug='draft-post',
        content='Content',
        status='draft',
        author=user,
        category=category
    )
    
    url = reverse('post-list')
    response = api_client.get(url)
    
    assert response.status_code == status.HTTP_200_OK
    # Only published posts should be visible to unauthenticated users
    assert len(response.data['results']) == 1`,
    'conftest.py': `"""
Pytest configuration
"""
import pytest
from django.conf import settings
from django.test.utils import get_runner

def pytest_configure():
    settings.DEBUG = False
    settings.PASSWORD_HASHERS = [
        'django.contrib.auth.hashers.MD5PasswordHasher',
    ]

@pytest.fixture(scope='session')
def django_db_setup():
    settings.DATABASES['default'] = {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:'
    }`,
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

# Create logs directory
RUN mkdir -p logs

# Collect static files
RUN python manage.py collectstatic --noinput

# Create non-root user
RUN adduser --disabled-password --gecos '' appuser
RUN chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\
    CMD python manage.py check --deploy

# Run the application
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "{{projectName}}.wsgi:application"]`,
    'docker-compose.yml': `version: '3.8'

services:
  web:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DEBUG=False
      - SECRET_KEY=your-production-secret-key
      - DB_NAME={{projectName}}
      - DB_USER=postgres
      - DB_PASSWORD=postgres
      - DB_HOST=db
      - DB_PORT=5432
      - REDIS_URL=redis://redis:6379/1
      - CELERY_BROKER_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis
    volumes:
      - .:/app
      - static_volume:/app/staticfiles
      - media_volume:/app/media

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
    command: celery -A celery_app worker --loglevel=info
    volumes:
      - .:/app
    environment:
      - DEBUG=False
      - SECRET_KEY=your-production-secret-key
      - DB_NAME={{projectName}}
      - DB_USER=postgres
      - DB_PASSWORD=postgres
      - DB_HOST=db
      - DB_PORT=5432
      - REDIS_URL=redis://redis:6379/1
      - CELERY_BROKER_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis

  celery-beat:
    build: .
    command: celery -A celery_app beat --loglevel=info
    volumes:
      - .:/app
    environment:
      - DEBUG=False
      - SECRET_KEY=your-production-secret-key
      - DB_NAME={{projectName}}
      - DB_USER=postgres
      - DB_PASSWORD=postgres
      - DB_HOST=db
      - DB_PORT=5432
      - REDIS_URL=redis://redis:6379/1
      - CELERY_BROKER_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis

volumes:
  postgres_data:
  redis_data:
  static_volume:
  media_volume:`,
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
  | migrations
)/
'''

[tool.isort]
profile = "black"
multi_line_output = 3
line_length = 88
known_django = ["django"]
known_first_party = ["apps", "{{projectName}}"]
sections = ["FUTURE", "STDLIB", "DJANGO", "THIRDPARTY", "FIRSTPARTY", "LOCALFOLDER"]

[tool.mypy]
python_version = "3.11"
check_untyped_defs = true
ignore_missing_imports = true
warn_unused_ignores = true
warn_redundant_casts = true
warn_unused_configs = true
plugins = ["mypy_django_plugin.main"]

[tool.django-stubs]
django_settings_module = "{{projectName}}.settings.development"`,
    'README.md': `# {{projectName}}

Django REST Framework application with comprehensive API features, authentication, and modern development practices.

## Features

- 🚀 **Django REST Framework** - Powerful and flexible toolkit for building Web APIs
- 🔐 **JWT Authentication** - Secure authentication with access and refresh tokens
- 👥 **User Management** - Custom user model with profiles and permissions
- 📝 **Blog System** - Complete blog with posts, categories, tags, and comments
- 🔍 **Advanced Filtering** - Search, filtering, and pagination for all endpoints
- 📊 **Django Admin** - Enhanced admin interface for content management
- 🗄️ **PostgreSQL** - Robust database with optimized queries
- 📦 **Celery** - Background task processing with Redis broker
- 🧪 **Comprehensive Testing** - pytest with factory-boy and coverage
- 🐳 **Docker** - Containerized deployment with docker-compose
- 📚 **API Documentation** - Automatic API documentation
- 🔧 **Code Quality** - Black, isort, mypy, flake8 for code quality

## Quick Start

### Prerequisites

- Python 3.11+
- PostgreSQL
- Redis

### Installation

1. **Clone and setup:**
   \`\`\`bash
   git clone <repository-url>
   cd {{projectName}}
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\\Scripts\\activate
   \`\`\`

2. **Install dependencies:**
   \`\`\`bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # For development
   \`\`\`

3. **Environment configuration:**
   \`\`\`bash
   cp .env.example .env
   # Edit .env with your database and other settings
   \`\`\`

4. **Database setup:**
   \`\`\`bash
   python manage.py makemigrations
   python manage.py migrate
   python manage.py createsuperuser
   \`\`\`

5. **Run development server:**
   \`\`\`bash
   python manage.py runserver
   \`\`\`

### Docker Setup

1. **Run with Docker Compose:**
   \`\`\`bash
   docker-compose up -d
   \`\`\`

2. **Setup database:**
   \`\`\`bash
   docker-compose exec web python manage.py migrate
   docker-compose exec web python manage.py createsuperuser
   \`\`\`

## API Documentation

Once running, access:

- **API Root:** http://localhost:8000/api/v1/
- **Admin Panel:** http://localhost:8000/admin/
- **API Docs:** http://localhost:8000/docs/
- **Health Check:** http://localhost:8000/health/

## API Endpoints

### Authentication
- \`POST /api/v1/auth/login/\` - Login with email/password
- \`POST /api/v1/auth/refresh/\` - Refresh access token

### Users
- \`GET /api/v1/users/\` - List users
- \`POST /api/v1/users/\` - Create user
- \`GET /api/v1/users/me/\` - Current user profile
- \`PUT /api/v1/users/me/\` - Update profile
- \`POST /api/v1/users/change_password/\` - Change password

### Blog
- \`GET /api/v1/blog/posts/\` - List posts
- \`POST /api/v1/blog/posts/\` - Create post
- \`GET /api/v1/blog/posts/{slug}/\` - Get post detail
- \`PUT /api/v1/blog/posts/{slug}/\` - Update post
- \`POST /api/v1/blog/posts/{slug}/like/\` - Like post
- \`POST /api/v1/blog/posts/{slug}/publish/\` - Publish draft

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

# Run all checks
black . && isort . && mypy . && flake8 .
\`\`\`

### Testing

\`\`\`bash
# Run tests
pytest

# Run with coverage
pytest --cov

# Run specific app tests
pytest tests/test_users.py
\`\`\`

### Database Operations

\`\`\`bash
# Create migrations
python manage.py makemigrations

# Apply migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Load sample data (if fixtures exist)
python manage.py loaddata fixtures/sample_data.json
\`\`\`

### Celery Tasks

\`\`\`bash
# Start Celery worker
celery -A celery_app worker --loglevel=info

# Start Celery beat (for scheduled tasks)
celery -A celery_app beat --loglevel=info

# Monitor tasks
celery -A celery_app flower
\`\`\`

## Project Structure

\`\`\`
{{projectName}}/
├── {{projectName}}/          # Django project settings
│   ├── settings/
│   │   ├── base.py          # Base settings
│   │   ├── development.py   # Development settings
│   │   ├── production.py    # Production settings
│   │   └── testing.py       # Test settings
│   ├── urls.py             # Main URL configuration
│   ├── wsgi.py             # WSGI configuration
│   └── asgi.py             # ASGI configuration
├── apps/                   # Django applications
│   ├── core/               # Core functionality
│   ├── users/              # User management
│   ├── authentication/     # Auth views
│   └── blog/               # Blog application
├── tests/                  # Test files
├── static/                 # Static files
├── media/                  # User uploads
├── templates/              # HTML templates
├── requirements.txt        # Python dependencies
├── requirements-dev.txt    # Development dependencies
├── manage.py              # Django management script
├── celery_app.py          # Celery configuration
└── docker-compose.yml     # Docker services
\`\`\`

## Authentication

The API uses JWT tokens:

1. **Login:** POST to \`/api/v1/auth/login/\` with email and password
2. **Response:** Contains \`access\` and \`refresh\` tokens
3. **Usage:** Include in headers: \`Authorization: Bearer <access_token>\`
4. **Refresh:** POST to \`/api/v1/auth/refresh/\` with refresh token

## Permissions

- **Public endpoints:** Health check, login, user registration
- **Authenticated required:** Most API endpoints
- **Object-level permissions:** Users can only edit their own content
- **Admin permissions:** Full access via Django admin

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| SECRET_KEY | Django secret key | (required) |
| DEBUG | Enable debug mode | False |
| DB_NAME | Database name | (required) |
| DB_USER | Database user | postgres |
| DB_PASSWORD | Database password | (required) |
| DB_HOST | Database host | localhost |
| REDIS_URL | Redis connection URL | redis://127.0.0.1:6379/1 |
| CORS_ALLOWED_ORIGINS | CORS allowed origins | (required) |

## Performance Features

- **Database optimization:** Select/prefetch related for efficient queries
- **Caching:** Redis caching for sessions and frequently accessed data
- **Pagination:** Efficient pagination for large datasets
- **Throttling:** Rate limiting to prevent API abuse
- **Background tasks:** Celery for time-consuming operations

## Security Features

- **JWT authentication:** Secure token-based authentication
- **Password validation:** Strong password requirements
- **CORS protection:** Configurable cross-origin resource sharing
- **Security headers:** Protection against common attacks
- **Input validation:** DRF serializers with comprehensive validation
- **Permission classes:** Fine-grained access control

## Deployment

### Production Checklist

- [ ] Set strong SECRET_KEY
- [ ] Configure production database
- [ ] Set DEBUG=False
- [ ] Configure ALLOWED_HOSTS
- [ ] Set up SSL/TLS
- [ ] Configure static file serving
- [ ] Set up monitoring and logging
- [ ] Configure backup strategy
- [ ] Set up Celery workers
- [ ] Configure email backend

### Docker Production

\`\`\`bash
# Build production image
docker build -t {{projectName}} .

# Run with production settings
docker run -p 8000:8000 -e DEBUG=False {{projectName}}
\`\`\`

## Contributing

1. Fork the repository
2. Create feature branch (\`git checkout -b feature/amazing-feature\`)
3. Run tests (\`pytest\`)
4. Commit changes (\`git commit -m 'Add amazing feature'\`)
5. Push to branch (\`git push origin feature/amazing-feature\`)
6. Open Pull Request

## License

This project is licensed under the MIT License.`,
    '.gitignore': `# Django
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

# Django specific
*.log
local_settings.py
db.sqlite3
db.sqlite3-journal
media/

# Environment variables
.env
.venv
env/
venv/
ENV/
env.bak/
venv.bak/

# Static files
/static/
/staticfiles/

# Logs
logs/
*.log

# Coverage reports
htmlcov/
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
.hypothesis/
.pytest_cache/

# mypy
.mypy_cache/
.dmypy.json
dmypy.json

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

# Celery
celerybeat-schedule
celerybeat.pid

# Redis dump
dump.rdb`
  },
  prompts: [
    {
      type: 'input',
      name: 'projectName',
      message: 'What is your project name?',
      default: 'django-api'
    }
  ],
  postInstall: [
    'python -m venv venv',
    'source venv/bin/activate',
    'pip install -r requirements.txt',
    'pip install -r requirements-dev.txt',
    'cp .env.example .env',
    'mkdir -p logs static media',
    'echo "✅ Django REST Framework application created successfully!"',
    'echo ""',
    'echo "📝 Next steps:"',
    'echo "   1. Activate virtual environment: source venv/bin/activate"',
    'echo "   2. Update .env with your database configuration"',
    'echo "   3. Run migrations: python manage.py migrate"',
    'echo "   4. Create superuser: python manage.py createsuperuser"',
    'echo "   5. Start development server: python manage.py runserver"',
    'echo "   6. Visit http://localhost:8000/admin/ for admin panel"',
    'echo ""',
    'echo "🐳 Docker option:"',
    'echo "   docker-compose up -d"',
    'echo ""',
    'echo "🧪 Run tests:"',
    'echo "   pytest"'
  ]
};