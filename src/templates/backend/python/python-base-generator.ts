import { BackendTemplateGenerator, BackendTemplateConfig } from '../shared/backend-template-generator';
import * as path from 'path';
import { promises as fs } from 'fs';

export abstract class PythonBackendGenerator extends BackendTemplateGenerator {
  protected options: any;
  
  constructor(framework: string) {
    const config: BackendTemplateConfig = {
      language: 'Python',
      framework: framework,
      packageManager: 'poetry',
      buildTool: 'poetry',
      testFramework: 'pytest',
      features: [
        'Async/Await Support',
        'JWT Authentication',
        'PostgreSQL Database',
        'Redis Cache',
        'Docker Support',
        'API Documentation',
        'Real-time WebSocket',
        'File Upload Support',
        'Email Service',
        'Rate Limiting',
        'Comprehensive Testing',
        'Type Hints',
        'Background Tasks'
      ],
      dependencies: {},
      devDependencies: {},
      scripts: {
        dev: 'uvicorn main:app --reload',
        start: 'uvicorn main:app --host 0.0.0.0 --port 8000',
        test: 'pytest',
        lint: 'flake8 app tests',
        format: 'black . && isort .',
        typecheck: 'mypy .',
        'security-scan': 'bandit -r app/'
      },
      dockerConfig: {
        baseImage: 'python:3.11-slim',
        workDir: '/app',
        exposedPorts: [8000],
        buildSteps: ['poetry install --no-dev', 'poetry run alembic upgrade head'],
        runCommand: 'uvicorn main:app --host 0.0.0.0 --port 8000',
        multistage: true
      },
      envVars: {
        APP_NAME: '{{projectName}}',
        DEBUG: 'true',
        ENVIRONMENT: 'development',
        SECRET_KEY: 'your-secret-key-here',
        DATABASE_URL: 'postgresql+asyncpg://user:password@localhost:5432/dbname',
        REDIS_URL: 'redis://localhost:6379/0'
      }
    };
    super(config);
  }
  
  // Framework-specific abstract methods
  protected abstract getFrameworkDependencies(): Record<string, string>;
  protected abstract getFrameworkDevDependencies(): Record<string, string>;
  protected abstract generateMainFile(): string;
  protected abstract generateConfigFiles(): { path: string; content: string }[];
  protected abstract generateModelFiles(): { path: string; content: string }[];
  protected abstract generateAPIFiles(): { path: string; content: string }[];
  protected abstract generateCRUDFiles(): { path: string; content: string }[];
  protected abstract generateSchemaFiles(): { path: string; content: string }[];
  protected abstract generateServiceFiles(): { path: string; content: string }[];
  protected abstract generateMiddlewareFiles(): { path: string; content: string }[];
  protected abstract generateUtilFiles(): { path: string; content: string }[];
  
  // Implementation of required abstract methods from BackendTemplateGenerator
  protected async generateLanguageFiles(projectPath: string, options: any): Promise<void> {
    this.options = options;
    
    // Generate pyproject.toml
    await this.writeFile(path.join(projectPath, 'pyproject.toml'), this.generatePyProject());
    
    // Generate environment file
    await this.writeFile(path.join(projectPath, '.env.example'), this.generateEnvironmentFile());
    
    // Generate Alembic configuration
    await this.writeFile(path.join(projectPath, 'alembic.ini'), this.generateAlembicConfig());
    
    // Generate requirements.txt (fallback for non-Poetry environments)
    await this.writeFile(path.join(projectPath, 'requirements.txt'), this.generateRequirements());
  }
  
  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Generate main application file
    await this.writeFile(path.join(projectPath, 'main.py'), this.generateMainFile());
    
    // Create app directory structure
    await fs.mkdir(path.join(projectPath, 'app'), { recursive: true });
    await this.writeFile(path.join(projectPath, 'app/__init__.py'), '');
    
    // Generate config files
    const configFiles = this.generateConfigFiles();
    for (const file of configFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate model files
    const modelFiles = this.generateModelFiles();
    for (const file of modelFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate API files
    const apiFiles = this.generateAPIFiles();
    for (const file of apiFiles) {
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
    
    // Generate utility files
    const utilFiles = this.generateUtilFiles();
    for (const file of utilFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
  }
  
  protected async generateTestStructure(projectPath: string, options: any): Promise<void> {
    // Create test directories
    await fs.mkdir(path.join(projectPath, 'tests'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'tests/unit'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'tests/integration'), { recursive: true });
    
    // Generate test configuration
    await this.writeFile(
      path.join(projectPath, 'tests/__init__.py'),
      ''
    );
    
    // Generate pytest configuration
    await this.writeFile(
      path.join(projectPath, 'pytest.ini'),
      this.generatePytestConfig()
    );
    
    // Generate test utilities
    await this.writeFile(
      path.join(projectPath, 'tests/conftest.py'),
      this.generateTestConftest()
    );
    
    // Generate sample test
    await this.writeFile(
      path.join(projectPath, 'tests/test_main.py'),
      this.generateSampleTest()
    );
  }
  
  protected async generateHealthCheck(projectPath: string): Promise<void> {
    // Health check is included in the API files
    // No separate file needed for Python frameworks
  }
  
  protected async generateAPIDocs(projectPath: string): Promise<void> {
    // API docs configuration is included in config files
    // No separate generation needed as it's handled in framework files
  }
  
  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    await this.writeFile(path.join(projectPath, 'Dockerfile'), this.generateDockerfile());
    await this.writeFile(path.join(projectPath, 'docker-compose.yml'), this.generateDockerCompose());
    await this.writeFile(path.join(projectPath, '.dockerignore'), this.generateDockerIgnore());
  }
  
  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    await this.writeFile(path.join(projectPath, 'README.md'), this.generateReadmeContent());
  }
  
  // Helper method implementations
  protected getLanguageSpecificIgnorePatterns(): string[] {
    return [
      '__pycache__/',
      '*.py[cod]',
      '*$py.class',
      '*.so',
      '.Python',
      'build/',
      'develop-eggs/',
      'dist/',
      'downloads/',
      'eggs/',
      '.eggs/',
      'lib/',
      'lib64/',
      'parts/',
      'sdist/',
      'var/',
      'wheels/',
      'share/python-wheels/',
      '*.egg-info/',
      '.installed.cfg',
      '*.egg',
      'MANIFEST',
      '.env',
      '.venv',
      'env/',
      'venv/',
      'ENV/',
      'env.bak/',
      'venv.bak/',
      '.coverage',
      '.pytest_cache/',
      '.hypothesis/',
      'htmlcov/',
      '.tox/',
      '.cache',
      'nosetests.xml',
      'coverage.xml',
      '*.cover',
      '*.py,cover',
      '.coverage.*',
      'celerybeat-schedule',
      'celerybeat.pid',
      '*.log'
    ];
  }
  
  protected getLanguagePrerequisites(): string {
    return 'Python 3.11+, Poetry, PostgreSQL, and Redis';
  }
  
  protected getInstallCommand(): string {
    return 'poetry install';
  }
  
  protected getDevCommand(): string {
    return 'poetry run uvicorn main:app --reload';
  }
  
  protected getProdCommand(): string {
    return 'poetry run uvicorn main:app --host 0.0.0.0 --port 8000';
  }
  
  protected getTestCommand(): string {
    return 'poetry run pytest';
  }
  
  protected getCoverageCommand(): string {
    return 'poetry run pytest --cov=app --cov-report=html';
  }
  
  protected getLintCommand(): string {
    return 'poetry run flake8 app tests';
  }
  
  protected getBuildCommand(): string {
    return 'poetry build';
  }
  
  protected getSetupAction(): string {
    return 'poetry install && poetry run alembic upgrade head';
  }
  
  protected generatePyProject(): string {
    const dependencies = this.getFrameworkDependencies();
    const devDependencies = this.getFrameworkDevDependencies();
    
    const deps = Object.entries(dependencies)
      .map(([name, version]) => `${name} = "${version}"`)
      .join('\n');
      
    const devDeps = Object.entries(devDependencies)
      .map(([name, version]) => `${name} = "${version}"`)
      .join('\n');

    return `[tool.poetry]
name = "${this.options.name}"
version = "0.1.0"
description = "${this.config.framework} backend service with async support and automatic documentation"
authors = ["Your Name <you@example.com>"]
readme = "README.md"

[tool.poetry.dependencies]
python = "^3.11"
${deps}

[tool.poetry.group.dev.dependencies]
${devDeps}

[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"

[tool.black]
line-length = 100
target-version = ['py311']
include = '\\.pyi?$'

[tool.isort]
profile = "black"
line_length = 100

[tool.mypy]
python_version = "3.11"
warn_return_any = true
warn_unused_configs = true
ignore_missing_imports = true

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py", "*_test.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]
addopts = "-ra -q --strict-markers"
markers = [
    "slow: marks tests as slow (deselect with '-m \\"not slow\\"')",
    "integration: marks tests as integration tests",
    "unit: marks tests as unit tests",
]

[tool.coverage.run]
source = ["app"]
omit = ["*/tests/*", "*/migrations/*"]

[tool.coverage.report]
precision = 2
show_missing = true
skip_covered = false

[tool.pylint.messages_control]
disable = "C0330, C0326"

[tool.pylint.format]
max-line-length = "100"`;
  }
  
  protected generateEnvironmentFile(): string {
    return Object.entries(this.config.envVars || {})
      .map(([key, value]) => `${key}=${value}`)
      .join('\n');
  }
  
  protected generateAlembicConfig(): string {
    return `[alembic]
script_location = alembic
prepend_sys_path = .
version_path_separator = os
sqlalchemy.url = postgresql+asyncpg://user:password@localhost/dbname

[post_write_hooks]
hooks = black
black.type = console_scripts
black.entrypoint = black
black.options = -l 100

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
datefmt = %H:%M:%S`;
  }
  
  protected generateRequirements(): string {
    const dependencies = this.getFrameworkDependencies();
    return Object.entries(dependencies)
      .map(([name, version]) => `${name}${version}`)
      .join('\n');
  }
  
  protected generateDockerfile(): string {
    return `# Build stage
FROM python:3.11-slim AS builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1 \\
    POETRY_VERSION=1.8.2 \\
    POETRY_HOME="/opt/poetry" \\
    POETRY_VIRTUALENVS_CREATE=false \\
    POETRY_NO_INTERACTION=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \\
    gcc \\
    g++ \\
    libpq-dev \\
    curl \\
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python3 -
ENV PATH="$POETRY_HOME/bin:$PATH"

WORKDIR /app

# Copy dependency files
COPY pyproject.toml poetry.lock* ./

# Install dependencies
RUN poetry install --no-dev --no-root

# Production stage
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \\
    libpq5 \\
    curl \\
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY --chown=appuser:appuser . .

# Create necessary directories
RUN mkdir -p uploads logs && chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]`;
  }
  
  protected generateDockerCompose(): string {
    return `version: '3.8'

services:
  app:
    build: .
    container_name: ${this.options.name}-api
    ports:
      - "\${PORT:-8000}:8000"
    environment:
      - DATABASE_URL=postgresql+asyncpg://\${DB_USER:-postgres}:\${DB_PASSWORD:-postgres}@postgres:5432/\${DB_NAME:-${this.options.name}}
      - REDIS_URL=redis://redis:6379/0
    env_file:
      - .env
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    volumes:
      - ./uploads:/app/uploads
      - ./logs:/app/logs
    restart: unless-stopped
    networks:
      - app-network

  postgres:
    image: postgres:16-alpine
    container_name: ${this.options.name}-db
    environment:
      - POSTGRES_USER=\${DB_USER:-postgres}
      - POSTGRES_PASSWORD=\${DB_PASSWORD:-postgres}
      - POSTGRES_DB=\${DB_NAME:-${this.options.name}}
    ports:
      - "\${DB_PORT:-5432}:5432"
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U \${DB_USER:-postgres}"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped
    networks:
      - app-network

  redis:
    image: redis:7-alpine
    container_name: ${this.options.name}-redis
    command: redis-server --appendonly yes
    ports:
      - "\${REDIS_PORT:-6379}:6379"
    volumes:
      - redis-data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped
    networks:
      - app-network

volumes:
  postgres-data:
  redis-data:

networks:
  app-network:
    driver: bridge`;
  }
  
  protected generateDockerIgnore(): string {
    return `__pycache__
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
.venv
.env
Dockerfile
.dockerignore
README.md
.gitignore
.editorconfig`;
  }
  
  protected generatePytestConfig(): string {
    return `[pytest]
testpaths = tests
python_files = test_*.py *_test.py
python_classes = Test*
python_functions = test_*
addopts = -ra -q --strict-markers
markers =
    slow: marks tests as slow (deselect with '-m "not slow"')
    integration: marks tests as integration tests
    unit: marks tests as unit tests`;
  }
  
  protected generateTestConftest(): string {
    return `import asyncio
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.core.database import Base, get_db
from main import app

# Test database URL
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"

# Create test engine
test_engine = create_async_engine(TEST_DATABASE_URL, echo=True)
TestingSessionLocal = sessionmaker(
    test_engine, class_=AsyncSession, expire_on_commit=False
)


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def test_db():
    """Create test database tables."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def db_session(test_db):
    """Create a fresh database session for each test."""
    async with TestingSessionLocal() as session:
        yield session


@pytest.fixture
async def client(db_session):
    """Create test client with database dependency override."""
    def override_get_db():
        yield db_session
    
    app.dependency_overrides[get_db] = override_get_db
    
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
    
    app.dependency_overrides.clear()`;
  }
  
  protected generateSampleTest(): string {
    return `import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_root_endpoint(client: AsyncClient):
    """Test root endpoint."""
    response = await client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "message" in data


@pytest.mark.asyncio
async def test_health_check(client: AsyncClient):
    """Test health check endpoint."""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"`;
  }
  
  protected generateReadmeContent(): string {
    return `# ${this.options.name}

${this.config.framework} backend service built with Python, featuring async support, authentication, and comprehensive documentation.

## Features

- 🚀 **${this.config.framework}** with async/await support
- 🔐 **JWT Authentication** with OAuth2 flow
- 🗄️ **SQLAlchemy 2.0** with async PostgreSQL support
- 🚦 **Redis** for caching and rate limiting
- 📚 **Automatic API Documentation** with Swagger/ReDoc
- 🔄 **WebSocket** support for real-time features
- 🧪 **Pytest** for testing with async support
- 🐳 **Docker** support with multi-stage builds
- 📊 **Structured Logging** with JSON format
- 🛡️ **Security** features (CORS, rate limiting, etc.)
- 📤 **File uploads** with validation
- ✉️ **Email** support with templates
- 🔄 **Background tasks** with Celery
- 📈 **Monitoring** with Prometheus metrics
- 🎯 **Type hints** throughout the codebase

## Getting Started

### Prerequisites

- Python 3.11+
- PostgreSQL
- Redis
- Docker (optional)

### Installation

1. Clone the repository
2. Install Poetry:
   \`\`\`bash
   curl -sSL https://install.python-poetry.org | python3 -
   \`\`\`

3. Install dependencies:
   \`\`\`bash
   poetry install
   \`\`\`

4. Set up environment variables:
   \`\`\`bash
   cp .env.example .env
   \`\`\`

5. Run database migrations:
   \`\`\`bash
   poetry run alembic upgrade head
   \`\`\`

6. Start the development server:
   \`\`\`bash
   poetry run uvicorn main:app --reload
   \`\`\`

### Running with Docker

\`\`\`bash
docker-compose up
\`\`\`

## API Documentation

Once the server is running, visit:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- OpenAPI JSON: http://localhost:8000/openapi.json

## Testing

\`\`\`bash
# Run tests
poetry run pytest

# Run tests with coverage
poetry run pytest --cov=app --cov-report=html

# Run tests in watch mode
poetry run pytest-watch

# Run specific test file
poetry run pytest tests/test_auth.py
\`\`\`

## Scripts

- \`poetry run dev\` - Start development server with hot reload
- \`poetry run start\` - Start production server
- \`poetry run test\` - Run tests
- \`poetry run lint\` - Run linting
- \`poetry run format\` - Format code with Black and isort
- \`poetry run typecheck\` - Type check with mypy

## Project Structure

\`\`\`
app/
├── api/            # API endpoints
├── core/           # Core configuration
├── crud/           # CRUD operations
├── models/         # SQLAlchemy models
├── schemas/        # Pydantic schemas
├── services/       # Business logic
├── utils/          # Utilities
└── tests/          # Test files
\`\`\`

## License

MIT`;
  }
  
  protected async writeFile(filePath: string, content: string): Promise<void> {
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, content, 'utf-8');
  }
}