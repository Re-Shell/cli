import { BackendTemplateGenerator } from '../shared/backend-template-generator';
import * as path from 'path';
import { promises as fs } from 'fs';

export abstract class PhpBackendGenerator extends BackendTemplateGenerator {
  protected options: any;
  
  constructor() {
    super({
      language: 'PHP',
      framework: 'PHP Framework',
      packageManager: 'composer',
      buildTool: 'composer',
      testFramework: 'phpunit',
      features: [
        'Object-oriented programming',
        'Modern PHP 8.2+ features',
        'PSR-12 coding standards',
        'JWT Authentication',
        'MySQL/PostgreSQL Database',
        'Redis Cache',
        'Docker Support',
        'RESTful API design',
        'Comprehensive testing'
      ],
      dependencies: {},
      devDependencies: {},
      scripts: {
        dev: 'php -S localhost:8000 -t public',
        test: 'vendor/bin/phpunit',
        lint: 'vendor/bin/phpcs',
        'lint:fix': 'vendor/bin/phpcbf'
      }
    });
  }
  
  async generate(projectPath: string, options: any): Promise<void> {
    this.options = options;
    await super.generate(projectPath, options);
  }
  
  protected abstract getFrameworkDependencies(): Record<string, string>;
  protected abstract generateMainFile(): string;
  protected abstract generateRoutingFile(): string;
  protected abstract generateServiceFiles(): { path: string; content: string }[];
  protected abstract generateRepositoryFiles(): { path: string; content: string }[];
  protected abstract generateModelFiles(): { path: string; content: string }[];
  protected abstract generateConfigFiles(): { path: string; content: string }[];
  protected abstract generateMiddlewareFiles(): { path: string; content: string }[];
  protected abstract generateTestFiles(): { path: string; content: string }[];
  
  protected generateComposerJson(): string {
    const dependencies = {
      'php': '^8.2',
      ...this.getFrameworkDependencies()
    };

    const devDependencies = {
      'phpunit/phpunit': '^10.0',
      'squizlabs/php_codesniffer': '^3.7',
      'friendsofphp/php-cs-fixer': '^3.21',
      'phpstan/phpstan': '^1.10',
      'vimeo/psalm': '^5.15'
    };

    return JSON.stringify({
      name: this.options?.name || 'php-service',
      description: this.options?.description || 'PHP backend service',
      type: 'project',
      require: dependencies,
      'require-dev': devDependencies,
      autoload: {
        'psr-4': {
          'App\\\\': 'src/'
        }
      },
      'autoload-dev': {
        'psr-4': {
          'Tests\\\\': 'tests/'
        }
      },
      scripts: {
        'test': 'phpunit',
        'test:coverage': 'phpunit --coverage-html coverage',
        'lint': 'phpcs src tests --standard=PSR12',
        'lint:fix': 'phpcbf src tests --standard=PSR12',
        'analyse': 'phpstan analyse src tests',
        'psalm': 'psalm',
        'serve': 'php -S localhost:8000 -t public'
      },
      config: {
        'optimize-autoloader': true,
        'preferred-install': 'dist',
        'sort-packages': true
      },
      'minimum-stability': 'stable',
      'prefer-stable': true
    }, null, 2);
  }

  protected generatePhpUnitXml(): string {
    return `<?xml version="1.0" encoding="UTF-8"?>
<phpunit xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:noNamespaceSchemaLocation="vendor/phpunit/phpunit/phpunit.xsd"
         bootstrap="vendor/autoload.php"
         colors="true"
         testdox="true">
    <testsuites>
        <testsuite name="Unit Tests">
            <directory suffix="Test.php">./tests/Unit</directory>
        </testsuite>
        <testsuite name="Feature Tests">
            <directory suffix="Test.php">./tests/Feature</directory>
        </testsuite>
    </testsuites>
    <source>
        <include>
            <directory suffix=".php">./src</directory>
        </include>
        <exclude>
            <directory>./src/Config</directory>
        </exclude>
    </source>
    <logging>
        <junit outputFile="coverage/junit.xml"/>
        <clover outputFile="coverage/clover.xml"/>
        <html outputDirectory="coverage/html"/>
    </logging>
</phpunit>`;
  }

  protected generatePhpCsXml(): string {
    return `<?xml version="1.0"?>
<ruleset name="PSR12">
    <description>PSR-12 coding standard with custom rules</description>
    
    <!-- Use PSR-12 as base -->
    <rule ref="PSR12"/>
    
    <!-- Paths to check -->
    <file>src</file>
    <file>tests</file>
    
    <!-- Exclude certain files or patterns -->
    <exclude-pattern>*/vendor/*</exclude-pattern>
    <exclude-pattern>*/storage/*</exclude-pattern>
    <exclude-pattern>*/bootstrap/cache/*</exclude-pattern>
    
    <!-- Additional rules -->
    <rule ref="Generic.Arrays.DisallowLongArraySyntax"/>
    <rule ref="Generic.Commenting.Todo"/>
    <rule ref="Generic.Commenting.Fixme"/>
    
    <!-- Show warnings and errors -->
    <arg name="colors"/>
    <arg name="parallel" value="8"/>
    <arg value="p"/>
</ruleset>`;
  }

  protected generatePhpStanNeon(): string {
    return `parameters:
    level: 8
    paths:
        - src
        - tests
    ignoreErrors:
        - '#Call to an undefined method.*#'
    excludePaths:
        - vendor
    checkMissingIterableValueType: false
    checkGenericClassInNonGenericObjectType: false
`;
  }

  protected generatePsalmXml(): string {
    return `<?xml version="1.0"?>
<psalm
    errorLevel="3"
    resolveFromConfigFile="true"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns="https://getpsalm.org/schema/config"
    xsi:schemaLocation="https://getpsalm.org/schema/config vendor/vimeo/psalm/config.xsd"
>
    <projectFiles>
        <directory name="src" />
        <directory name="tests" />
        <ignoreFiles>
            <directory name="vendor" />
        </ignoreFiles>
    </projectFiles>
</psalm>`;
  }

  protected generateGitignoreContent(): string {
    return `# Composer
/vendor/
composer.lock

# IDE
.idea/
.vscode/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Application
.env
.env.local
.env.*.local
storage/logs/*.log
storage/cache/*
storage/sessions/*
storage/uploads/*
!storage/cache/.gitkeep
!storage/logs/.gitkeep
!storage/sessions/.gitkeep
!storage/uploads/.gitkeep

# Testing
/coverage/
.phpunit.result.cache
/phpunit.xml

# Tools
/.phpcs-cache
/.php-cs-fixer.cache
/.phpstan.cache
/.psalm.cache

# Docker
docker-compose.override.yml

# Temporary files
*.tmp
*.temp
*.pid
*.seed
*.pid.lock`;
  }

  protected generateDockerfile(): string {
    return `# Build stage
FROM composer:2.6 AS build
WORKDIR /app

# Copy composer files
COPY composer.json composer.lock ./
RUN composer install --no-dev --optimize-autoloader --no-scripts

# Runtime stage  
FROM php:8.2-fpm-alpine AS runtime
WORKDIR /app

# Install system dependencies
RUN apk add --no-cache \\
    nginx \\
    supervisor \\
    curl \\
    postgresql-dev \\
    mysql-client \\
    redis \\
    && docker-php-ext-install \\
    pdo \\
    pdo_mysql \\
    pdo_pgsql \\
    opcache \\
    bcmath

# Install Redis extension
RUN pecl install redis && docker-php-ext-enable redis

# Configure PHP
COPY docker/php.ini /usr/local/etc/php/conf.d/99-custom.ini
COPY docker/opcache.ini /usr/local/etc/php/conf.d/10-opcache.ini

# Configure Nginx
COPY docker/nginx.conf /etc/nginx/nginx.conf
COPY docker/default.conf /etc/nginx/http.d/default.conf

# Configure Supervisor
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Copy application
COPY . .
COPY --from=build /app/vendor ./vendor

# Set permissions
RUN chown -R www-data:www-data /app \\
    && chmod -R 755 /app/storage \\
    && chmod -R 755 /app/bootstrap/cache

# Create required directories
RUN mkdir -p storage/logs storage/cache storage/sessions storage/uploads \\
    && chown -R www-data:www-data storage \\
    && chmod -R 775 storage

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD curl -f http://localhost/health || exit 1

# Expose port
EXPOSE 80

# Start services
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]`;
  }

  protected generateDockerCompose(): string {
    return `version: '3.8'

services:
  app:
    build: .
    ports:
      - "\${APP_PORT:-8080}:80"
    environment:
      - DB_HOST=db
      - DB_PORT=5432
      - DB_DATABASE=\${DB_NAME:-app_db}
      - DB_USERNAME=\${DB_USER:-postgres}
      - DB_PASSWORD=\${DB_PASSWORD:-postgres}
      - REDIS_HOST=redis
      - REDIS_PORT=6379
      - JWT_SECRET=\${JWT_SECRET:-your-secret-key-change-in-production}
      - APP_ENV=\${APP_ENV:-development}
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
    volumes:
      - ./storage:/app/storage
      - ./logs:/app/logs
    networks:
      - app-network
    restart: unless-stopped

  db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_DB=\${DB_NAME:-app_db}
      - POSTGRES_USER=\${DB_USER:-postgres}
      - POSTGRES_PASSWORD=\${DB_PASSWORD:-postgres}
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./docker/init.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - app-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    networks:
      - app-network
    command: redis-server --appendonly yes
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./docker/nginx.conf:/etc/nginx/nginx.conf
      - ./public:/var/www/html/public
    depends_on:
      - app
    networks:
      - app-network

volumes:
  postgres_data:
  redis_data:

networks:
  app-network:
    driver: bridge`;
  }

  protected generateDockerConfig(): { path: string; content: string }[] {
    return [
      {
        path: 'docker/php.ini',
        content: `[PHP]
memory_limit = 256M
post_max_size = 64M
upload_max_filesize = 64M
max_execution_time = 30
max_input_time = 60
default_socket_timeout = 60

[Date]
date.timezone = UTC

[Session]
session.cookie_secure = 1
session.cookie_httponly = 1
session.cookie_samesite = "Strict"

[Security]
expose_php = Off
allow_url_fopen = Off
allow_url_include = Off`
      },
      {
        path: 'docker/opcache.ini',
        content: `[opcache]
opcache.enable=1
opcache.memory_consumption=256
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=20000
opcache.validate_timestamps=0
opcache.fast_shutdown=1
opcache.enable_cli=1`
      },
      {
        path: 'docker/nginx.conf',
        content: `user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    access_log /var/log/nginx/access.log main;
    
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    
    include /etc/nginx/conf.d/*.conf;
}`
      },
      {
        path: 'docker/default.conf',
        content: `server {
    listen 80;
    server_name localhost;
    root /var/www/html/public;
    index index.php index.html;
    
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
    
    location ~ \\.php$ {
        fastcgi_pass app:9000;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }
    
    location ~ /\\.ht {
        deny all;
    }
    
    location /health {
        access_log off;
        return 200 "healthy\\n";
        add_header Content-Type text/plain;
    }
}`
      },
      {
        path: 'docker/supervisord.conf',
        content: `[supervisord]
nodaemon=true
user=root
logfile=/var/log/supervisor/supervisord.log
pidfile=/var/run/supervisord.pid

[program:php-fpm]
command=php-fpm
autostart=true
autorestart=true
stderr_logfile=/var/log/supervisor/php-fpm.err.log
stdout_logfile=/var/log/supervisor/php-fpm.out.log

[program:nginx]
command=nginx -g "daemon off;"
autostart=true
autorestart=true
stderr_logfile=/var/log/supervisor/nginx.err.log
stdout_logfile=/var/log/supervisor/nginx.out.log`
      },
      {
        path: 'docker/init.sql',
        content: `-- Initial database setup
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create refresh_tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(512) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);`
      }
    ];
  }

  protected generateReadmeContent(): string {
    return `# ${this.options?.name || 'php-service'}

A modern PHP backend application built with ${this.options?.framework || 'PHP Framework'}.

## 🚀 Features

- **Modern PHP**: PHP 8.2+ with strict types and modern features
- **PSR Standards**: PSR-12 coding standards and PSR-4 autoloading
- **RESTful API**: Well-structured endpoints with proper HTTP methods
- **Authentication**: JWT-based authentication and authorization
- **Database**: PostgreSQL with PDO abstraction layer
- **Caching**: Redis integration for high-performance caching
- **Testing**: Comprehensive test suite with PHPUnit
- **Docker**: Containerized application with Docker Compose
- **Code Quality**: PHPStan, Psalm, and PHP CS Fixer integration
- **Monitoring**: Health checks and metrics endpoints
- **Logging**: Structured logging with PSR-3 compliance

## 📋 Prerequisites

- PHP 8.2 or higher
- Composer 2.0+
- Docker and Docker Compose (optional)
- PostgreSQL 15+ (if running locally)
- Redis 6+ (if running locally)

## 🛠️ Development Setup

### Local Development

1. Clone the repository:
   \`\`\`bash
   git clone <repository-url>
   cd ${this.options?.name || 'php-service'}
   \`\`\`

2. Install dependencies:
   \`\`\`bash
   composer install
   \`\`\`

3. Set up environment variables:
   \`\`\`bash
   cp .env.example .env
   # Edit .env with your configuration
   \`\`\`

4. Run database migrations:
   \`\`\`bash
   php bin/migrate.php
   \`\`\`

5. Start the development server:
   \`\`\`bash
   composer serve
   # or
   php -S localhost:8000 -t public
   \`\`\`

### Docker Development

1. Build and run with Docker Compose:
   \`\`\`bash
   docker-compose up --build
   \`\`\`

2. The application will be available at \`http://localhost:8080\`

## 🧪 Testing

Run all tests:
\`\`\`bash
composer test
\`\`\`

Run tests with coverage:
\`\`\`bash
composer test:coverage
\`\`\`

Run specific test file:
\`\`\`bash
vendor/bin/phpunit tests/Unit/UserServiceTest.php
\`\`\`

## 🔍 Code Quality

Lint code:
\`\`\`bash
composer lint
\`\`\`

Fix code style:
\`\`\`bash
composer lint:fix
\`\`\`

Static analysis:
\`\`\`bash
composer analyse
composer psalm
\`\`\`

## 📚 API Documentation

### Authentication

All authenticated endpoints require a JWT token in the Authorization header:
\`\`\`
Authorization: Bearer <token>
\`\`\`

### Endpoints

#### Health Check
\`\`\`
GET /health
\`\`\`

#### Authentication
\`\`\`
POST /api/auth/register
POST /api/auth/login
POST /api/auth/refresh
POST /api/auth/logout
\`\`\`

#### Users
\`\`\`
GET    /api/users        # Get all users (admin only)
GET    /api/users/:id    # Get user by ID
PUT    /api/users/:id    # Update user
DELETE /api/users/:id    # Delete user (admin only)
GET    /api/users/me     # Get current user
\`\`\`

## 🏗️ Project Structure

\`\`\`
src/
├── Config/                 # Configuration classes
├── Controllers/            # HTTP controllers
├── Services/               # Business logic
├── Repositories/           # Data access layer
├── Models/                 # Domain models
├── Middleware/             # HTTP middleware
├── Utils/                  # Utility classes
├── Exceptions/             # Custom exceptions
└── Database/               # Database migrations and seeders

public/
└── index.php              # Application entry point

tests/
├── Unit/                   # Unit tests
├── Feature/                # Feature tests
└── Fixtures/               # Test fixtures

docker/                     # Docker configuration
├── php.ini
├── nginx.conf
└── supervisord.conf
\`\`\`

## 🚀 Deployment

### Building for Production

1. Optimize autoloader:
   \`\`\`bash
   composer install --no-dev --optimize-autoloader
   \`\`\`

2. Build Docker image:
   \`\`\`bash
   docker build -t ${this.options?.name || 'php-service'} .
   \`\`\`

3. Run the container:
   \`\`\`bash
   docker run -d \\
     -p 8080:80 \\
     -e DB_HOST=your-db-host \\
     -e DB_PASSWORD=your-db-password \\
     -e JWT_SECRET=your-jwt-secret \\
     ${this.options?.name || 'php-service'}
   \`\`\`

## 🔧 Configuration

Configuration is managed through environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| \`APP_ENV\` | Application environment | development |
| \`APP_PORT\` | Application port | 8080 |
| \`DB_HOST\` | Database host | localhost |
| \`DB_PORT\` | Database port | 5432 |
| \`DB_NAME\` | Database name | app_db |
| \`DB_USER\` | Database username | postgres |
| \`DB_PASSWORD\` | Database password | postgres |
| \`REDIS_HOST\` | Redis host | localhost |
| \`REDIS_PORT\` | Redis port | 6379 |
| \`JWT_SECRET\` | JWT signing secret | change-me |
| \`JWT_EXPIRATION\` | JWT expiration time | 3600 |
| \`LOG_LEVEL\` | Logging level | info |

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.`;
  }

  protected generateEnvExample(): string {
    return `# Application Configuration
APP_ENV=development
APP_PORT=8080
APP_URL=http://localhost:8080

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=app_db
DB_USER=postgres
DB_PASSWORD=postgres

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# JWT Configuration
JWT_SECRET=your-secret-key-change-in-production
JWT_EXPIRATION=3600
JWT_REFRESH_EXPIRATION=86400

# Logging
LOG_LEVEL=info
LOG_FILE=storage/logs/app.log

# Email Configuration (optional)
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=2525
MAIL_USERNAME=
MAIL_PASSWORD=
MAIL_FROM_ADDRESS=noreply@example.com
MAIL_FROM_NAME="App Name"

# Rate Limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=3600`;
  }

  async generateTemplate(projectPath: string): Promise<void> {
    // Create directory structure
    const directories = [
      'src/Config',
      'src/Controllers',
      'src/Services', 
      'src/Repositories',
      'src/Models',
      'src/Middleware',
      'src/Utils',
      'src/Exceptions',
      'src/Database/Migrations',
      'src/Database/Seeders',
      'public',
      'tests/Unit',
      'tests/Feature',
      'tests/Fixtures',
      'storage/logs',
      'storage/cache',
      'storage/sessions',
      'storage/uploads',
      'docker',
      'bin'
    ];

    for (const dir of directories) {
      await fs.mkdir(path.join(projectPath, dir), { recursive: true });
    }

    // Generate base files
    const files = [
      { path: 'composer.json', content: this.generateComposerJson() },
      { path: 'phpunit.xml', content: this.generatePhpUnitXml() },
      { path: 'phpcs.xml', content: this.generatePhpCsXml() },
      { path: 'phpstan.neon', content: this.generatePhpStanNeon() },
      { path: 'psalm.xml', content: this.generatePsalmXml() },
      { path: '.gitignore', content: this.generateGitignoreContent() },
      { path: 'Dockerfile', content: this.generateDockerfile() },
      { path: 'docker-compose.yml', content: this.generateDockerCompose() },
      { path: 'README.md', content: this.generateReadmeContent() },
      { path: '.env.example', content: this.generateEnvExample() },
      
      // Main application file
      { path: 'public/index.php', content: this.generateMainFile() },
      
      // Framework-specific files
      ...this.generateServiceFiles(),
      ...this.generateRepositoryFiles(),
      ...this.generateModelFiles(),
      ...this.generateConfigFiles(),
      ...this.generateMiddlewareFiles(),
      ...this.generateTestFiles(),
      ...this.generateDockerConfig()
    ];

    // Write all files
    for (const file of files) {
      const fullPath = path.join(projectPath, file.path);
      // Ensure parent directory exists
      await fs.mkdir(path.dirname(fullPath), { recursive: true });
      await fs.writeFile(fullPath, file.content);
    }
  }
  
  // Implement abstract methods from BackendTemplateGenerator
  protected async generateLanguageFiles(projectPath: string, options: any): Promise<void> {
    await this.generateTemplate(projectPath);
  }
  
  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Framework-specific files are generated in generateTemplate
  }
  
  protected async generateTestStructure(projectPath: string, options: any): Promise<void> {
    // Test files are generated in generateTemplate
  }
  
  protected async generateHealthCheck(projectPath: string): Promise<void> {
    // Health check is part of controller files
  }
  
  protected async generateAPIDocs(projectPath: string): Promise<void> {
    // API docs are generated as part of the framework
  }
  
  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    await fs.writeFile(path.join(projectPath, 'Dockerfile'), this.generateDockerfile());
    await fs.writeFile(path.join(projectPath, 'docker-compose.yml'), this.generateDockerCompose());
  }
  
  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    await fs.writeFile(path.join(projectPath, 'README.md'), this.generateReadmeContent());
  }
  
  protected getLanguageSpecificIgnorePatterns(): string[] {
    return [
      '/vendor/',
      'composer.lock',
      '.env',
      'storage/logs/*.log',
      'storage/cache/*',
      'storage/sessions/*',
      '/coverage/',
      '.phpunit.result.cache'
    ];
  }
  
  protected getLanguagePrerequisites(): string {
    return 'PHP 8.2+, Composer 2.0+';
  }
  
  protected getInstallCommand(): string {
    return 'composer install';
  }
  
  protected getDevCommand(): string {
    return 'composer serve';
  }
  
  protected getProdCommand(): string {
    return 'php public/index.php';
  }
  
  protected getTestCommand(): string {
    return 'composer test';
  }
  
  protected getCoverageCommand(): string {
    return 'composer test:coverage';
  }
  
  protected getLintCommand(): string {
    return 'composer lint';
  }
  
  protected getBuildCommand(): string {
    return 'composer install --no-dev --optimize-autoloader';
  }
  
  protected getSetupAction(): string {
    return 'composer install';
  }
}