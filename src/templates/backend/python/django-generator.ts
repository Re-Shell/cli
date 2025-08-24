import { PythonBackendGenerator } from './python-base-generator';
import * as path from 'path';
import { promises as fs } from 'fs';

export class DjangoGenerator extends PythonBackendGenerator {
  private projectName: string = 'project';
  
  constructor() {
    super('Django');
  }
  
  protected async generateLanguageFiles(projectPath: string, options: any): Promise<void> {
    this.projectName = options.name || 'project';
    await super.generateLanguageFiles(projectPath, options);
  }
  
  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Generate manage.py instead of main.py for Django
    await this.writeFile(path.join(projectPath, 'manage.py'), this.generateMainFile());
    
    // Create app directory structure
    const appName = 'app';
    const appPath = path.join(projectPath, appName);
    await fs.mkdir(appPath, { recursive: true });
    
    // Generate app/__init__.py
    await this.writeFile(path.join(appPath, '__init__.py'), '');
    
    // Generate API files
    const apiFiles = this.generateAPIFiles();
    for (const file of apiFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate model files
    const modelFiles = this.generateModelFiles();
    for (const file of modelFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate CRUD files
    const crudFiles = this.generateCRUDFiles();
    for (const file of crudFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate schema files
    const schemaFiles = this.generateSchemaFiles();
    for (const file of schemaFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate service files
    const serviceFiles = this.generateServiceFiles();
    for (const file of serviceFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate middleware files
    const middlewareFiles = this.generateMiddlewareFiles();
    for (const file of middlewareFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate util files
    const utilFiles = this.generateUtilFiles();
    for (const file of utilFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate config files
    const configFiles = this.generateConfigFiles();
    for (const file of configFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
  }
  
  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'django': '^5.0.3',
      'djangorestframework': '^3.15.1',
      'django-cors-headers': '^4.3.1',
      'django-environ': '^0.12.0',
      'django-extensions': '^3.2.3',
      'django-filter': '^24.2',
      'djangorestframework-simplejwt': '^5.3.1',
      'djoser': '^2.2.2',
      'django-redis': '^5.4.0',
      'celery[redis]': '^5.3.6',
      'django-celery-beat': '^2.6.0',
      'django-celery-results': '^2.5.1',
      'psycopg2-binary': '^2.9.9',
      'drf-spectacular': '^0.27.1',
      'Pillow': '^10.2.0',
      'django-storages[boto3]': '^1.14.2',
      'gunicorn': '^21.2.0',
      'whitenoise': '^6.6.0',
      'channels[daphne]': '^4.0.0',
      'channels-redis': '^4.2.0'
    };
  }
  
  protected getFrameworkDevDependencies(): Record<string, string> {
    return {
      'pytest': '^8.1.1',
      'pytest-django': '^4.8.0',
      'pytest-cov': '^5.0.0',
      'pytest-asyncio': '^0.23.5',
      'factory-boy': '^3.3.0',
      'faker': '^24.0.0',
      'black': '^24.3.0',
      'isort': '^5.13.2',
      'flake8': '^7.0.0',
      'flake8-django': '^1.4',
      'mypy': '^1.9.0',
      'django-stubs[compatible-mypy]': '^4.2.7',
      'djangorestframework-stubs[compatible-mypy]': '^3.14.5',
      'bandit[toml]': '^1.7.8',
      'pre-commit': '^3.6.2',
      'django-debug-toolbar': '^4.3.0',
      'django-silk': '^5.1.0',
      'ipython': '^8.22.2'
    };
  }
  
  protected generateMainFile(): string {
    return [
      '#!/usr/bin/env python',
      '"""Django\'s command-line utility for administrative tasks."""',
      'import os',
      'import sys',
      '',
      '',
      'def main():',
      '    """Run administrative tasks."""',
      '    os.environ.setdefault(\'DJANGO_SETTINGS_MODULE\', \'config.settings.development\')',
      '    try:',
      '        from django.core.management import execute_from_command_line',
      '    except ImportError as exc:',
      '        raise ImportError(',
      '            "Couldn\'t import Django. Are you sure it\'s installed and "',
      '            "available on your PYTHONPATH environment variable? Did you "',
      '            "forget to activate a virtual environment?"',
      '        ) from exc',
      '    execute_from_command_line(sys.argv)',
      '',
      '',
      'if __name__ == \'__main__\':',
      '    main()'
    ].join('\n');
  }
  
  protected generateConfigFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'config/__init__.py',
        content: ''
      },
      {
        path: 'config/asgi.py',
        content: this.generateASGIContent()
      },
      {
        path: 'config/wsgi.py',
        content: this.generateWSGIContent()
      },
      {
        path: 'config/urls.py',
        content: this.generateURLsContent()
      },
      {
        path: 'config/settings/__init__.py',
        content: ''
      },
      {
        path: 'config/settings/base.py',
        content: this.generateBaseSettingsContent()
      },
      {
        path: 'config/settings/development.py',
        content: this.generateDevSettingsContent()
      },
      {
        path: 'config/settings/production.py',
        content: this.generateProdSettingsContent()
      },
      {
        path: 'config/celery_app.py',
        content: this.generateCeleryContent()
      }
    ];
  }
  
  private generateASGIContent(): string {
    return [
      '"""',
      'ASGI config for this project.',
      '',
      'It exposes the ASGI callable as a module-level variable named ``application``.',
      '',
      'For more information on this file, see',
      'https://docs.djangoproject.com/en/5.0/howto/deployment/asgi/',
      '"""',
      '',
      'import os',
      '',
      'from channels.auth import AuthMiddlewareStack',
      'from channels.routing import ProtocolTypeRouter, URLRouter',
      'from channels.security.websocket import AllowedHostsOriginValidator',
      'from django.core.asgi import get_asgi_application',
      '',
      'os.environ.setdefault(\'DJANGO_SETTINGS_MODULE\', \'config.settings.development\')',
      '',
      '# Initialize Django ASGI application early to ensure the AppRegistry',
      '# is populated before importing code that may import ORM models.',
      'django_asgi_app = get_asgi_application()',
      '',
      'from apps.websocket import routing  # noqa',
      '',
      'application = ProtocolTypeRouter({',
      '    "http": django_asgi_app,',
      '    "websocket": AllowedHostsOriginValidator(',
      '        AuthMiddlewareStack(URLRouter(routing.websocket_urlpatterns))',
      '    ),',
      '})'
    ].join('\n');
  }
  
  private generateWSGIContent(): string {
    return [
      '"""',
      `WSGI config for ${this.projectName} project.`,
      '',
      'It exposes the WSGI callable as a module-level variable named ``application``.',
      '',
      'For more information on this file, see',
      'https://docs.djangoproject.com/en/5.0/howto/deployment/wsgi/',
      '"""',
      '',
      'import os',
      '',
      'from django.core.wsgi import get_wsgi_application',
      '',
      'os.environ.setdefault(\'DJANGO_SETTINGS_MODULE\', \'config.settings.development\')',
      '',
      'application = get_wsgi_application()'
    ].join('\n');
  }
  
  private generateURLsContent(): string {
    return [
      '"""',
      `URL configuration for ${this.projectName} project.`,
      '"""',
      'from django.conf import settings',
      'from django.conf.urls.static import static',
      'from django.contrib import admin',
      'from django.urls import include, path',
      'from drf_spectacular.views import (',
      '    SpectacularAPIView,',
      '    SpectacularRedocView,',
      '    SpectacularSwaggerView,',
      ')',
      '',
      'urlpatterns = [',
      '    # Django admin',
      '    path(\'admin/\', admin.site.urls),',
      '    ',
      '    # API URLs',
      '    path(\'api/v1/\', include(\'apps.api.urls\')),',
      '    ',
      '    # DRF auth',
      '    path(\'api/v1/auth/\', include(\'djoser.urls\')),',
      '    path(\'api/v1/auth/\', include(\'djoser.urls.jwt\')),',
      '    ',
      '    # API documentation',
      '    path(\'api/schema/\', SpectacularAPIView.as_view(), name=\'schema\'),',
      '    path(\'api/docs/\', SpectacularSwaggerView.as_view(url_name=\'schema\'), name=\'swagger-ui\'),',
      '    path(\'api/redoc/\', SpectacularRedocView.as_view(url_name=\'schema\'), name=\'redoc\'),',
      ']',
      '',
      'if settings.DEBUG:',
      '    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)',
      '    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)',
      '    ',
      '    # Debug toolbar',
      '    if \'debug_toolbar\' in settings.INSTALLED_APPS:',
      '        import debug_toolbar',
      '        urlpatterns = [path(\'__debug__/\', include(debug_toolbar.urls))] + urlpatterns',
      '    ',
      '    # Silk profiler',
      '    if \'silk\' in settings.INSTALLED_APPS:',
      '        urlpatterns += [path(\'silk/\', include(\'silk.urls\', namespace=\'silk\'))]'
    ].join('\n');
  }
  
  private generateBaseSettingsContent(): string {
    return [
      '"""',
      `Django settings for ${this.projectName} project.`,
      '',
      'For more information on this file, see',
      'https://docs.djangoproject.com/en/5.0/topics/settings/',
      '',
      'For the full list of settings and their values, see',
      'https://docs.djangoproject.com/en/5.0/ref/settings/',
      '"""',
      '',
      'from pathlib import Path',
      '',
      'import environ',
      '',
      '# Build paths inside the project',
      'BASE_DIR = Path(__file__).resolve().parent.parent.parent',
      '',
      '# Environment variables',
      'env = environ.Env(',
      '    DEBUG=(bool, False)',
      ')',
      '',
      '# Read environment variables from .env file',
      'environ.Env.read_env(BASE_DIR / \'.env\')',
      '',
      '# SECURITY WARNING: keep the secret key used in production secret!',
      'SECRET_KEY = env(\'SECRET_KEY\')',
      '',
      '# SECURITY WARNING: don\'t run with debug turned on in production!',
      'DEBUG = env(\'DEBUG\')',
      '',
      'ALLOWED_HOSTS = env.list(\'ALLOWED_HOSTS\', default=[])',
      '',
      '# Application definition',
      'DJANGO_APPS = [',
      '    \'django.contrib.admin\',',
      '    \'django.contrib.auth\',',
      '    \'django.contrib.contenttypes\',',
      '    \'django.contrib.sessions\',',
      '    \'django.contrib.messages\',',
      '    \'django.contrib.staticfiles\',',
      ']',
      '',
      'THIRD_PARTY_APPS = [',
      '    \'rest_framework\',',
      '    \'rest_framework_simplejwt\',',
      '    \'django_filters\',',
      '    \'corsheaders\',',
      '    \'djoser\',',
      '    \'channels\',',
      '    \'django_extensions\',',
      '    \'django_celery_beat\',',
      '    \'django_celery_results\',',
      '    \'drf_spectacular\',',
      '    \'storages\',',
      ']',
      '',
      'LOCAL_APPS = [',
      '    \'apps.accounts\',',
      '    \'apps.api\',',
      '    \'apps.websocket\',',
      ']',
      '',
      'INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS',
      '',
      'MIDDLEWARE = [',
      '    \'django.middleware.security.SecurityMiddleware\',',
      '    \'whitenoise.middleware.WhiteNoiseMiddleware\',',
      '    \'corsheaders.middleware.CorsMiddleware\',',
      '    \'django.contrib.sessions.middleware.SessionMiddleware\',',
      '    \'django.middleware.common.CommonMiddleware\',',
      '    \'django.middleware.csrf.CsrfViewMiddleware\',',
      '    \'django.contrib.auth.middleware.AuthenticationMiddleware\',',
      '    \'django.contrib.messages.middleware.MessageMiddleware\',',
      '    \'django.middleware.clickjacking.XFrameOptionsMiddleware\',',
      ']',
      '',
      'ROOT_URLCONF = \'config.urls\'',
      '',
      'TEMPLATES = [',
      '    {',
      '        \'BACKEND\': \'django.template.backends.django.DjangoTemplates\',',
      '        \'DIRS\': [BASE_DIR / \'templates\'],',
      '        \'APP_DIRS\': True,',
      '        \'OPTIONS\': {',
      '            \'context_processors\': [',
      '                \'django.template.context_processors.debug\',',
      '                \'django.template.context_processors.request\',',
      '                \'django.contrib.auth.context_processors.auth\',',
      '                \'django.contrib.messages.context_processors.messages\',',
      '            ],',
      '        },',
      '    },',
      ']',
      '',
      'WSGI_APPLICATION = \'config.wsgi.application\'',
      'ASGI_APPLICATION = \'config.asgi.application\'',
      '',
      '# Password validation',
      'AUTH_PASSWORD_VALIDATORS = [',
      '    {',
      '        \'NAME\': \'django.contrib.auth.password_validation.UserAttributeSimilarityValidator\',',
      '    },',
      '    {',
      '        \'NAME\': \'django.contrib.auth.password_validation.MinimumLengthValidator\',',
      '    },',
      '    {',
      '        \'NAME\': \'django.contrib.auth.password_validation.CommonPasswordValidator\',',
      '    },',
      '    {',
      '        \'NAME\': \'django.contrib.auth.password_validation.NumericPasswordValidator\',',
      '    },',
      ']',
      '',
      '# Internationalization',
      'LANGUAGE_CODE = \'en-us\'',
      'TIME_ZONE = \'UTC\'',
      'USE_I18N = True',
      'USE_TZ = True',
      '',
      '# Static files (CSS, JavaScript, Images)',
      'STATIC_URL = \'/static/\'',
      'STATIC_ROOT = BASE_DIR / \'staticfiles\'',
      'STATICFILES_STORAGE = \'whitenoise.storage.CompressedManifestStaticFilesStorage\'',
      '',
      '# Media files',
      'MEDIA_URL = \'/media/\'',
      'MEDIA_ROOT = BASE_DIR / \'media\'',
      '',
      '# Default primary key field type',
      'DEFAULT_AUTO_FIELD = \'django.db.models.BigAutoField\'',
      '',
      '# Custom user model',
      'AUTH_USER_MODEL = \'accounts.User\'',
      '',
      '# REST Framework',
      'REST_FRAMEWORK = {',
      '    \'DEFAULT_AUTHENTICATION_CLASSES\': (',
      '        \'rest_framework_simplejwt.authentication.JWTAuthentication\',',
      '    ),',
      '    \'DEFAULT_PERMISSION_CLASSES\': [',
      '        \'rest_framework.permissions.IsAuthenticated\',',
      '    ],',
      '    \'DEFAULT_FILTER_BACKENDS\': [',
      '        \'django_filters.rest_framework.DjangoFilterBackend\',',
      '        \'rest_framework.filters.SearchFilter\',',
      '        \'rest_framework.filters.OrderingFilter\',',
      '    ],',
      '    \'DEFAULT_PAGINATION_CLASS\': \'rest_framework.pagination.PageNumberPagination\',',
      '    \'PAGE_SIZE\': 20,',
      '    \'DEFAULT_SCHEMA_CLASS\': \'drf_spectacular.openapi.AutoSchema\',',
      '}',
      '',
      '# JWT Settings',
      'from datetime import timedelta',
      '',
      'SIMPLE_JWT = {',
      '    \'ACCESS_TOKEN_LIFETIME\': timedelta(minutes=60),',
      '    \'REFRESH_TOKEN_LIFETIME\': timedelta(days=7),',
      '    \'ROTATE_REFRESH_TOKENS\': True,',
      '    \'BLACKLIST_AFTER_ROTATION\': True,',
      '    \'UPDATE_LAST_LOGIN\': True,',
      '}',
      '',
      '# CORS',
      'CORS_ALLOWED_ORIGINS = env.list(\'CORS_ALLOWED_ORIGINS\', default=[])',
      'CORS_ALLOW_CREDENTIALS = True',
      '',
      '# Celery',
      'CELERY_BROKER_URL = env(\'REDIS_URL\', default=\'redis://localhost:6379/0\')',
      'CELERY_RESULT_BACKEND = env(\'REDIS_URL\', default=\'redis://localhost:6379/0\')',
      'CELERY_ACCEPT_CONTENT = [\'json\']',
      'CELERY_TASK_SERIALIZER = \'json\'',
      'CELERY_RESULT_SERIALIZER = \'json\'',
      'CELERY_TIMEZONE = TIME_ZONE',
      '',
      '# Channel layers',
      'CHANNEL_LAYERS = {',
      '    \'default\': {',
      '        \'BACKEND\': \'channels_redis.core.RedisChannelLayer\',',
      '        \'CONFIG\': {',
      '            "hosts": [env(\'REDIS_URL\', default=\'redis://127.0.0.1:6379/0\')],',
      '        },',
      '    },',
      '}',
      '',
      '# Caching',
      'CACHES = {',
      '    \'default\': {',
      '        \'BACKEND\': \'django_redis.cache.RedisCache\',',
      '        \'LOCATION\': env(\'REDIS_URL\', default=\'redis://127.0.0.1:6379/1\'),',
      '        \'OPTIONS\': {',
      '            \'CLIENT_CLASS\': \'django_redis.client.DefaultClient\',',
      '        }',
      '    }',
      '}',
      '',
      '# Security',
      'SECURE_BROWSER_XSS_FILTER = True',
      'X_FRAME_OPTIONS = \'DENY\'',
      '',
      '# API Documentation',
      'SPECTACULAR_SETTINGS = {',
      `    'TITLE': '${this.projectName} API',`,
      `    'DESCRIPTION': 'API documentation for ${this.projectName}',`,
      '    \'VERSION\': \'1.0.0\',',
      '    \'SERVE_INCLUDE_SCHEMA\': False,',
      '}'
    ].join('\n');
  }
  
  private generateDevSettingsContent(): string {
    return [
      'from .base import *  # noqa',
      '',
      '# SECURITY WARNING: don\'t run with debug turned on in production!',
      'DEBUG = True',
      '',
      '# Database',
      'DATABASES = {',
      '    \'default\': {',
      '        \'ENGINE\': \'django.db.backends.postgresql\',',
      `        'NAME': env('DB_NAME', default='${this.projectName}_dev'),`,
      '        \'USER\': env(\'DB_USER\', default=\'postgres\'),',
      '        \'PASSWORD\': env(\'DB_PASSWORD\', default=\'postgres\'),',
      '        \'HOST\': env(\'DB_HOST\', default=\'localhost\'),',
      '        \'PORT\': env(\'DB_PORT\', default=\'5432\'),',
      '    }',
      '}',
      '',
      '# Email backend for development',
      'EMAIL_BACKEND = \'django.core.mail.backends.console.EmailBackend\'',
      '',
      '# Debug toolbar',
      'INSTALLED_APPS += [\'debug_toolbar\', \'silk\']',
      '',
      'MIDDLEWARE.insert(0, \'silk.middleware.SilkyMiddleware\')',
      'MIDDLEWARE.insert(1, \'debug_toolbar.middleware.DebugToolbarMiddleware\')',
      '',
      'INTERNAL_IPS = [\'127.0.0.1\', \'localhost\']',
      '',
      '# CORS - Allow all origins in development',
      'CORS_ALLOW_ALL_ORIGINS = True',
      '',
      '# Celery - Use eager mode for debugging',
      'CELERY_TASK_ALWAYS_EAGER = env.bool(\'CELERY_TASK_ALWAYS_EAGER\', False)',
      'CELERY_TASK_EAGER_PROPAGATES = True'
    ].join('\n');
  }
  
  private generateProdSettingsContent(): string {
    return [
      'from .base import *  # noqa',
      '',
      'import sentry_sdk',
      'from sentry_sdk.integrations.django import DjangoIntegration',
      'from sentry_sdk.integrations.celery import CeleryIntegration',
      'from sentry_sdk.integrations.redis import RedisIntegration',
      '',
      '# Security',
      'DEBUG = False',
      '',
      '# Database',
      'DATABASES = {',
      '    \'default\': {',
      '        \'ENGINE\': \'django.db.backends.postgresql\',',
      '        \'NAME\': env(\'DB_NAME\'),',
      '        \'USER\': env(\'DB_USER\'),',
      '        \'PASSWORD\': env(\'DB_PASSWORD\'),',
      '        \'HOST\': env(\'DB_HOST\'),',
      '        \'PORT\': env(\'DB_PORT\', default=\'5432\'),',
      '        \'CONN_MAX_AGE\': 60,',
      '    }',
      '}',
      '',
      '# Security settings',
      'SECURE_SSL_REDIRECT = True',
      'SESSION_COOKIE_SECURE = True',
      'CSRF_COOKIE_SECURE = True',
      'SECURE_HSTS_SECONDS = 31536000',
      'SECURE_HSTS_INCLUDE_SUBDOMAINS = True',
      'SECURE_HSTS_PRELOAD = True',
      '',
      '# Email',
      'EMAIL_BACKEND = \'django.core.mail.backends.smtp.EmailBackend\'',
      'EMAIL_HOST = env(\'EMAIL_HOST\')',
      'EMAIL_PORT = env.int(\'EMAIL_PORT\', 587)',
      'EMAIL_HOST_USER = env(\'EMAIL_HOST_USER\')',
      'EMAIL_HOST_PASSWORD = env(\'EMAIL_HOST_PASSWORD\')',
      'EMAIL_USE_TLS = True',
      'DEFAULT_FROM_EMAIL = env(\'DEFAULT_FROM_EMAIL\')',
      '',
      '# Sentry',
      'sentry_sdk.init(',
      '    dsn=env(\'SENTRY_DSN\'),',
      '    integrations=[',
      '        DjangoIntegration(),',
      '        CeleryIntegration(),',
      '        RedisIntegration(),',
      '    ],',
      '    traces_sample_rate=env.float(\'SENTRY_TRACES_SAMPLE_RATE\', 0.1),',
      '    send_default_pii=False,',
      ')',
      '',
      '# File storage',
      'DEFAULT_FILE_STORAGE = \'storages.backends.s3boto3.S3Boto3Storage\'',
      'AWS_ACCESS_KEY_ID = env(\'AWS_ACCESS_KEY_ID\')',
      'AWS_SECRET_ACCESS_KEY = env(\'AWS_SECRET_ACCESS_KEY\')',
      'AWS_STORAGE_BUCKET_NAME = env(\'AWS_STORAGE_BUCKET_NAME\')',
      'AWS_S3_REGION_NAME = env(\'AWS_S3_REGION_NAME\', default=\'us-east-1\')',
      'AWS_S3_CUSTOM_DOMAIN = f\'{AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com\'',
      'AWS_S3_OBJECT_PARAMETERS = {',
      '    \'CacheControl\': \'max-age=86400\',',
      '}',
      '',
      '# Logging',
      'LOGGING = {',
      '    \'version\': 1,',
      '    \'disable_existing_loggers\': False,',
      '    \'formatters\': {',
      '        \'verbose\': {',
      '            \'format\': \'{levelname} {asctime} {module} {process:d} {thread:d} {message}\',',
      '            \'style\': \'{\',',
      '        },',
      '    },',
      '    \'handlers\': {',
      '        \'console\': {',
      '            \'class\': \'logging.StreamHandler\',',
      '            \'formatter\': \'verbose\',',
      '        },',
      '    },',
      '    \'root\': {',
      '        \'handlers\': [\'console\'],',
      '        \'level\': \'INFO\',',
      '    },',
      '    \'loggers\': {',
      '        \'django\': {',
      '            \'handlers\': [\'console\'],',
      '            \'level\': env(\'DJANGO_LOG_LEVEL\', default=\'INFO\'),',
      '            \'propagate\': False,',
      '        },',
      '    },',
      '}'
    ].join('\n');
  }
  
  private generateCeleryContent(): string {
    return [
      'import os',
      '',
      'from celery import Celery',
      '',
      '# Set the default Django settings module for the \'celery\' program.',
      'os.environ.setdefault(\'DJANGO_SETTINGS_MODULE\', \'config.settings.development\')',
      '',
      'app = Celery(\'config\')',
      '',
      '# Using a string here means the worker doesn\'t have to serialize',
      '# the configuration object to child processes.',
      'app.config_from_object(\'django.conf:settings\', namespace=\'CELERY\')',
      '',
      '# Load task modules from all registered Django apps.',
      'app.autodiscover_tasks()',
      '',
      '',
      '@app.task(bind=True, ignore_result=True)',
      'def debug_task(self):',
      '    print(f\'Request: {self.request!r}\')'
    ].join('\n');
  }
  
  protected generateModelFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'apps/__init__.py',
        content: ''
      },
      {
        path: 'apps/accounts/__init__.py',
        content: ''
      },
      {
        path: 'apps/accounts/models.py',
        content: [
          'from django.contrib.auth.models import AbstractUser',
          'from django.db import models',
          '',
          '',
          'class User(AbstractUser):',
          '    """Custom user model."""',
          '    email = models.EmailField(unique=True)',
          '    is_verified = models.BooleanField(default=False)',
          '    phone_number = models.CharField(max_length=20, blank=True)',
          '    bio = models.TextField(blank=True)',
          '    avatar = models.ImageField(upload_to=\'avatars/\', blank=True, null=True)',
          '    created_at = models.DateTimeField(auto_now_add=True)',
          '    updated_at = models.DateTimeField(auto_now=True)',
          '    ',
          '    USERNAME_FIELD = \'email\'',
          '    REQUIRED_FIELDS = [\'username\']',
          '    ',
          '    class Meta:',
          '        db_table = \'users\'',
          '        verbose_name = \'User\'',
          '        verbose_name_plural = \'Users\''
        ].join('\n')
      },
      {
        path: 'apps/accounts/admin.py',
        content: [
          'from django.contrib import admin',
          'from django.contrib.auth.admin import UserAdmin as BaseUserAdmin',
          '',
          'from .models import User',
          '',
          '',
          '@admin.register(User)',
          'class UserAdmin(BaseUserAdmin):',
          '    list_display = [\'email\', \'username\', \'is_verified\', \'is_staff\', \'date_joined\']',
          '    list_filter = [\'is_verified\', \'is_staff\', \'is_superuser\', \'is_active\']',
          '    search_fields = [\'email\', \'username\', \'first_name\', \'last_name\']',
          '    ordering = [\'-date_joined\']'
        ].join('\n')
      },
      {
        path: 'apps/accounts/apps.py',
        content: [
          'from django.apps import AppConfig',
          '',
          '',
          'class AccountsConfig(AppConfig):',
          '    default_auto_field = \'django.db.models.BigAutoField\'',
          '    name = \'apps.accounts\'',
          '    verbose_name = \'Accounts\''
        ].join('\n')
      }
    ];
  }
  
  protected generateAPIFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'apps/api/__init__.py',
        content: ''
      },
      {
        path: 'apps/api/apps.py',
        content: [
          'from django.apps import AppConfig',
          '',
          '',
          'class ApiConfig(AppConfig):',
          '    default_auto_field = \'django.db.models.BigAutoField\'',
          '    name = \'apps.api\'',
          '    verbose_name = \'API\''
        ].join('\n')
      },
      {
        path: 'apps/api/urls.py',
        content: [
          'from django.urls import include, path',
          '',
          'from .views import HealthCheckView',
          '',
          'app_name = \'api\'',
          '',
          'urlpatterns = [',
          '    path(\'health/\', HealthCheckView.as_view(), name=\'health-check\'),',
          '    # Add your API endpoints here',
          ']'
        ].join('\n')
      },
      {
        path: 'apps/api/views.py',
        content: [
          'from django.db import connection',
          'from rest_framework import status',
          'from rest_framework.permissions import AllowAny',
          'from rest_framework.response import Response',
          'from rest_framework.views import APIView',
          '',
          '',
          'class HealthCheckView(APIView):',
          '    """Health check endpoint."""',
          '    permission_classes = [AllowAny]',
          '    ',
          '    def get(self, request):',
          '        """Check application health."""',
          '        health_status = {',
          '            \'status\': \'healthy\',',
          '            \'database\': \'unknown\',',
          '            \'cache\': \'unknown\',',
          '        }',
          '        ',
          '        # Check database',
          '        try:',
          '            with connection.cursor() as cursor:',
          '                cursor.execute("SELECT 1")',
          '            health_status[\'database\'] = \'healthy\'',
          '        except Exception:',
          '            health_status[\'database\'] = \'unhealthy\'',
          '            health_status[\'status\'] = \'unhealthy\'',
          '        ',
          '        # Check cache',
          '        try:',
          '            from django.core.cache import cache',
          '            cache.set(\'health_check\', \'ok\', 1)',
          '            if cache.get(\'health_check\') == \'ok\':',
          '                health_status[\'cache\'] = \'healthy\'',
          '        except Exception:',
          '            health_status[\'cache\'] = \'unhealthy\'',
          '        ',
          '        status_code = (',
          '            status.HTTP_200_OK if health_status[\'status\'] == \'healthy\'',
          '            else status.HTTP_503_SERVICE_UNAVAILABLE',
          '        )',
          '        ',
          '        return Response(health_status, status=status_code)'
        ].join('\n')
      }
    ];
  }
  
  protected generateCRUDFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'apps/api/serializers.py',
        content: [
          'from rest_framework import serializers',
          '',
          'from apps.accounts.models import User',
          '',
          '',
          'class UserSerializer(serializers.ModelSerializer):',
          '    """User serializer."""',
          '    ',
          '    class Meta:',
          '        model = User',
          '        fields = [',
          '            \'id\', \'username\', \'email\', \'first_name\', \'last_name\',',
          '            \'is_verified\', \'bio\', \'avatar\', \'created_at\', \'updated_at\'',
          '        ]',
          '        read_only_fields = [\'id\', \'created_at\', \'updated_at\']'
        ].join('\n')
      },
      {
        path: 'apps/api/viewsets.py',
        content: [
          'from rest_framework import viewsets',
          'from rest_framework.permissions import IsAuthenticated',
          '',
          'from apps.accounts.models import User',
          'from .serializers import UserSerializer',
          '',
          '',
          'class UserViewSet(viewsets.ModelViewSet):',
          '    """User viewset."""',
          '    queryset = User.objects.all()',
          '    serializer_class = UserSerializer',
          '    permission_classes = [IsAuthenticated]',
          '    ',
          '    def get_queryset(self):',
          '        """Filter queryset based on user permissions."""',
          '        if self.request.user.is_staff:',
          '            return User.objects.all()',
          '        return User.objects.filter(id=self.request.user.id)'
        ].join('\n')
      }
    ];
  }
  
  protected generateSchemaFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'apps/api/schemas.py',
        content: [
          'from drf_spectacular.utils import extend_schema, OpenApiParameter',
          'from drf_spectacular.types import OpenApiTypes',
          '',
          '# Define your API schemas here',
          '# Example:',
          '# user_list_schema = extend_schema(',
          '#     summary="List users",',
          '#     description="Get a paginated list of users",',
          '#     parameters=[',
          '#         OpenApiParameter(',
          '#             name="search",',
          '#             type=OpenApiTypes.STR,',
          '#             location=OpenApiParameter.QUERY,',
          '#             description="Search users by username or email"',
          '#         )',
          '#     ]',
          '# )'
        ].join('\n')
      }
    ];
  }
  
  protected generateServiceFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'apps/api/services.py',
        content: [
          '"""Core business logic services."""'
        ].join('\n')
      },
      {
        path: 'apps/api/tasks.py',
        content: [
          'from celery import shared_task',
          '',
          '',
          '@shared_task',
          'def sample_task(x, y):',
          '    """Sample Celery task."""',
          '    return x + y',
          '',
          '',
          '@shared_task',
          'def send_email_task(recipient, subject, message):',
          '    """Send email asynchronously."""',
          '    from django.core.mail import send_mail',
          '    ',
          '    send_mail(',
          '        subject,',
          '        message,',
          '        \'noreply@example.com\',',
          '        [recipient],',
          '        fail_silently=False,',
          '    )'
        ].join('\n')
      }
    ];
  }
  
  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'apps/api/middleware.py',
        content: [
          '"""Custom middleware for the application."""'
        ].join('\n')
      }
    ];
  }
  
  protected generateUtilFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'apps/api/utils.py',
        content: [
          '"""Utility functions for the application."""'
        ].join('\n')
      },
      {
        path: 'apps/api/exceptions.py',
        content: [
          '"""Custom exceptions for the application."""'
        ].join('\n')
      },
      {
        path: 'apps/websocket/__init__.py',
        content: ''
      },
      {
        path: 'apps/websocket/consumers.py',
        content: [
          'import json',
          '',
          'from channels.generic.websocket import AsyncWebsocketConsumer',
          '',
          '',
          'class ChatConsumer(AsyncWebsocketConsumer):',
          '    """WebSocket consumer for chat functionality."""',
          '    ',
          '    async def connect(self):',
          '        self.room_name = self.scope[\'url_route\'][\'kwargs\'][\'room_name\']',
          '        self.room_group_name = f\'chat_{self.room_name}\'',
          '        ',
          '        # Join room group',
          '        await self.channel_layer.group_add(',
          '            self.room_group_name,',
          '            self.channel_name',
          '        )',
          '        ',
          '        await self.accept()',
          '    ',
          '    async def disconnect(self, close_code):',
          '        # Leave room group',
          '        await self.channel_layer.group_discard(',
          '            self.room_group_name,',
          '            self.channel_name',
          '        )',
          '    ',
          '    async def receive(self, text_data):',
          '        text_data_json = json.loads(text_data)',
          '        message = text_data_json[\'message\']',
          '        ',
          '        # Send message to room group',
          '        await self.channel_layer.group_send(',
          '            self.room_group_name,',
          '            {',
          '                \'type\': \'chat_message\',',
          '                \'message\': message',
          '            }',
          '        )',
          '    ',
          '    async def chat_message(self, event):',
          '        message = event[\'message\']',
          '        ',
          '        # Send message to WebSocket',
          '        await self.send(text_data=json.dumps({',
          '            \'message\': message',
          '        }))'
        ].join('\n')
      },
      {
        path: 'apps/websocket/routing.py',
        content: [
          'from django.urls import re_path',
          '',
          'from . import consumers',
          '',
          'websocket_urlpatterns = [',
          '    re_path(r\'ws/chat/(?P<room_name>\\w+)/$\', consumers.ChatConsumer.as_asgi()),',
          ']'
        ].join('\n')
      }
    ];
  }
}