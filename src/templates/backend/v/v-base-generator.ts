import { BackendTemplateGenerator } from '../shared/backend-template-generator';
import * as fs from 'fs/promises';
import * as path from 'path';

export abstract class VBackendGenerator extends BackendTemplateGenerator {
  protected options: any;
  
  constructor() {
    super({
      language: 'V',
      framework: 'V Framework',
      packageManager: 'v',
      buildTool: 'v',
      testFramework: 'v test',
      features: [
        'Memory safe without GC',
        'Fast compilation',
        'Simple Go-like syntax',
        'Built-in ORM',
        'Cross-platform',
        'Hot reloading',
        'C interop',
        'Small binaries',
        'No dependencies',
        'Docker support'
      ],
      dependencies: {},
      devDependencies: {},
      scripts: {
        'build': 'v -prod .',
        'dev': 'v watch run .',
        'test': 'v test .',
        'fmt': 'v fmt -w .',
        'check': 'v vet .',
        'docs': 'v doc -f html .'
      }
    });
  }

  protected abstract getFrameworkDependencies(): string[];
  protected abstract generateMainFile(): string;
  protected abstract generateServerFile(): string;
  protected abstract generateRouterFile(): string;
  protected abstract generateMiddlewareFiles(): { path: string; content: string }[];
  protected abstract generateControllerFiles(): { path: string; content: string }[];
  protected abstract generateModelFiles(): { path: string; content: string }[];
  protected abstract generateUtilFiles(): { path: string; content: string }[];
  protected abstract generateConfigFile(): string;
  protected abstract generateTestFiles(): { path: string; content: string }[];

  async generate(projectPath: string, options: any): Promise<void> {
    this.options = options;
    await super.generate(projectPath, options);
  }

  protected async generateLanguageFiles(projectPath: string, options: any): Promise<void> {
    // Generate v.mod file (V module file)
    await fs.writeFile(
      path.join(projectPath, 'v.mod'),
      this.generateVModFile(options)
    );

    // Generate .gitignore
    await this.generateGitignore(projectPath);

    // Create directory structure
    await fs.mkdir(path.join(projectPath, 'src'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'src', 'controllers'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'src', 'models'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'src', 'middleware'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'src', 'utils'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'src', 'views'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'tests'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'config'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'public'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'public', 'css'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'public', 'js'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'public', 'images'), { recursive: true });

    // Generate main.v
    await fs.writeFile(
      path.join(projectPath, 'main.v'),
      this.generateMainFile()
    );

    // Generate server.v
    await fs.writeFile(
      path.join(projectPath, 'src', 'server.v'),
      this.generateServerFile()
    );

    // Generate router.v
    await fs.writeFile(
      path.join(projectPath, 'src', 'router.v'),
      this.generateRouterFile()
    );

    // Generate config.v
    await fs.writeFile(
      path.join(projectPath, 'src', 'config.v'),
      this.generateConfigFile()
    );

    // Generate middleware files
    const middlewareFiles = this.generateMiddlewareFiles();
    for (const file of middlewareFiles) {
      const filePath = path.join(projectPath, file.path);
      await fs.mkdir(path.dirname(filePath), { recursive: true });
      await fs.writeFile(filePath, file.content);
    }

    // Generate controller files
    const controllerFiles = this.generateControllerFiles();
    for (const file of controllerFiles) {
      const filePath = path.join(projectPath, file.path);
      await fs.mkdir(path.dirname(filePath), { recursive: true });
      await fs.writeFile(filePath, file.content);
    }

    // Generate model files
    const modelFiles = this.generateModelFiles();
    for (const file of modelFiles) {
      const filePath = path.join(projectPath, file.path);
      await fs.mkdir(path.dirname(filePath), { recursive: true });
      await fs.writeFile(filePath, file.content);
    }

    // Generate utility files
    const utilFiles = this.generateUtilFiles();
    for (const file of utilFiles) {
      const filePath = path.join(projectPath, file.path);
      await fs.mkdir(path.dirname(filePath), { recursive: true });
      await fs.writeFile(filePath, file.content);
    }

    // Generate test files
    const testFiles = this.generateTestFiles();
    for (const file of testFiles) {
      const filePath = path.join(projectPath, file.path);
      await fs.mkdir(path.dirname(filePath), { recursive: true });
      await fs.writeFile(filePath, file.content);
    }

    // Generate Makefile
    await fs.writeFile(
      path.join(projectPath, 'Makefile'),
      this.generateMakefile(options)
    );
  }

  protected async generateHealthCheck(projectPath: string): Promise<void> {
    // Health check is implemented in the controller
  }

  protected async generateAPIDocs(projectPath: string): Promise<void> {
    const apiDocs = `# API Documentation

## Overview
This is a V-based web service using modern web framework patterns.

## Base URL
\`\`\`
http://localhost:${this.options?.port || 8080}
\`\`\`

## Endpoints

### Health Check
- **GET** \`/health\`
- Returns server health status

### Authentication
- **POST** \`/api/auth/register\` - Register new user
- **POST** \`/api/auth/login\` - User login
- **POST** \`/api/auth/refresh\` - Refresh token
- **POST** \`/api/auth/logout\` - User logout

### Users
- **GET** \`/api/users\` - List users (requires auth)
- **GET** \`/api/users/:id\` - Get user by ID
- **PUT** \`/api/users/:id\` - Update user
- **DELETE** \`/api/users/:id\` - Delete user

## Authentication
The API uses JWT tokens for authentication. Include the token in the Authorization header:
\`\`\`
Authorization: Bearer <your-token>
\`\`\`

## Response Format
All responses are in JSON format with the following structure:
\`\`\`json
{
  "success": true,
  "data": {},
  "message": "Success message"
}
\`\`\`

Error responses:
\`\`\`json
{
  "success": false,
  "error": "Error message",
  "code": "ERROR_CODE"
}
\`\`\`
`;

    await fs.writeFile(path.join(projectPath, 'docs', 'api.md'), apiDocs);
  }

  protected generateVModFile(options: any): string {
    const deps = this.getFrameworkDependencies();
    const depsString = deps.length > 0 ? `\ndependencies: [${deps.map(d => `'${d}'`).join(', ')}]` : '';

    return `Module {
    name: '${options.name}'
    description: '${options.description || 'A web service built with V'}'
    version: '0.1.0'
    license: 'MIT'${depsString}
}
`;
  }

  protected async generateGitignore(projectPath: string): Promise<void> {
    const gitignoreContent = `# V
*.exe
*.o
*.so
*.dylib
*.dll
*.a
*.d
*.tmp.c
*.tmp.js
vls.log

# Build
/bin/
/build/
${this.options?.name || 'app'}

# Environment
.env
.env.local
.env.*.local

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
logs/

# Test coverage
coverage/
*.gcov
*.gcda
*.gcno

# Dependencies
modules/
.vmodules/
`;
    
    await fs.writeFile(path.join(projectPath, '.gitignore'), gitignoreContent);
  }

  protected generateMakefile(options: any): string {
    const appName = options.name || 'app';

    return `.PHONY: build dev test clean fmt check run install

# Variables
V = v
APP_NAME = ${appName}
SRC_DIR = src
TEST_DIR = tests
PORT = ${options.port || 8080}

# Default target
all: build

# Install V dependencies
install:
\tv install

# Build for production
build:
\t@echo "Building production binary..."
\t$(V) -prod -o $(APP_NAME) .
\t@echo "Build complete: $(APP_NAME)"

# Development mode with hot reload
dev:
\t@echo "Starting development server with hot reload..."
\t$(V) watch run .

# Run tests
test:
\t@echo "Running tests..."
\t$(V) test .

# Format code
fmt:
\t@echo "Formatting code..."
\t$(V) fmt -w .

# Check code (vet)
check:
\t@echo "Checking code..."
\t$(V) vet .

# Clean build artifacts
clean:
\t@echo "Cleaning build artifacts..."
\t@rm -f $(APP_NAME) *.exe *.tmp.c
\t@echo "Clean complete"

# Run the server
run: build
\t@echo "Starting server on port $(PORT)..."
\t@./$(APP_NAME)

# Generate documentation
docs:
\t@echo "Generating documentation..."
\t@mkdir -p docs
\t$(V) doc -f html -o docs .
\t@echo "Documentation generated in docs/"

# Docker build
docker-build:
\t@echo "Building Docker image..."
\tdocker build -t $(APP_NAME) .

# Docker run
docker-run:
\tdocker run -p $(PORT):$(PORT) -e PORT=$(PORT) $(APP_NAME)

# Install with optimizations
install-prod:
\t$(V) -prod -cc clang -cflags "-O3 -flto" .
`;
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Framework-specific files are handled by the language-specific generation
    // This is empty in the base class as framework files are generated in generateLanguageFiles
  }

  protected async generateTestStructure(projectPath: string, options: any): Promise<void> {
    // Test structure is generated in generateLanguageFiles
  }

  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    const dockerContent = `# Multi-stage build for V application
FROM thevlang/vlang:alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev openssl-dev sqlite-dev

# Set working directory
WORKDIR /app

# Copy v.mod and install dependencies
COPY v.mod ./
RUN v install

# Copy source code
COPY . .

# Build the application
RUN v -prod -o server .

# Production stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache openssl sqlite-libs

# Create non-root user
RUN addgroup -g 1000 app && \\
    adduser -D -u 1000 -G app app

# Set working directory
WORKDIR /app

# Copy built binary and assets
COPY --from=builder --chown=app:app /app/server /app/server
COPY --from=builder --chown=app:app /app/public /app/public
COPY --from=builder --chown=app:app /app/config /app/config

# Copy configuration files
COPY --chown=app:app .env.example .env

# Create necessary directories
RUN mkdir -p /app/logs && chown app:app /app/logs
RUN mkdir -p /app/data && chown app:app /app/data

# Switch to non-root user
USER app

# Expose port
EXPOSE ${options.port || 8080}

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD wget --no-verbose --tries=1 --spider http://localhost:${options.port || 8080}/health || exit 1

# Start the application
CMD ["./server"]
`;

    await fs.writeFile(path.join(projectPath, 'Dockerfile'), dockerContent);

    // Generate docker-compose.yml
    const dockerComposeContent = `version: '3.8'

services:
  app:
    build: .
    container_name: ${options.name}
    ports:
      - "\${PORT:-${options.port || 8080}}:${options.port || 8080}"
    environment:
      - APP_ENV=production
      - HOST=0.0.0.0
      - PORT=${options.port || 8080}
      - DATABASE_URL=sqlite:///app/data/app.db
      - JWT_SECRET=\${JWT_SECRET}
      - CORS_ORIGINS=\${CORS_ORIGINS:-*}
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:${options.port || 8080}/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - v-network

  # Optional: Add Redis for caching
  redis:
    image: redis:7-alpine
    container_name: ${options.name}-redis
    restart: unless-stopped
    networks:
      - v-network

  # Optional: Add PostgreSQL for production database
  postgres:
    image: postgres:15-alpine
    container_name: ${options.name}-postgres
    environment:
      - POSTGRES_DB=\${DB_NAME:-vapp}
      - POSTGRES_USER=\${DB_USER:-vapp}
      - POSTGRES_PASSWORD=\${DB_PASSWORD}
    volumes:
      - postgres-data:/var/lib/postgresql/data
    restart: unless-stopped
    networks:
      - v-network

networks:
  v-network:
    driver: bridge

volumes:
  postgres-data:
`;

    await fs.writeFile(path.join(projectPath, 'docker-compose.yml'), dockerComposeContent);

    // Generate .dockerignore
    const dockerignoreContent = `# V
*.exe
*.o
*.tmp.c
vls.log

# Development
.env
.env.local
*.log
logs/

# IDE
.vscode/
.idea/

# Git
.git/
.gitignore

# Tests
tests/
coverage/

# Documentation
docs/
*.md
`;

    await fs.writeFile(path.join(projectPath, '.dockerignore'), dockerignoreContent);
  }

  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    const readme = `# ${options.name || 'V Backend Service'}

${options.description || 'A backend service built with V'}

## Tech Stack
- **Language**: V
- **Framework**: ${this.options?.framework || 'V Framework'}
- **Database**: SQLite (with built-in ORM)
- **Cache**: Redis (optional)
- **Authentication**: JWT

## Prerequisites
- V language (latest version)
- SQLite
- Redis (optional, for caching)

## Getting Started

### Installation
\`\`\`bash
# Install V dependencies
v install

# Copy environment variables
cp .env.example .env
\`\`\`

### Development
\`\`\`bash
# Run with hot reload
v watch run .

# Or use make
make dev
\`\`\`

### Testing
\`\`\`bash
# Run all tests
v test .

# Or use make
make test
\`\`\`

### Building for Production
\`\`\`bash
# Build optimized binary
v -prod .

# Or use make
make build

# Build with additional optimizations
v -prod -cc clang -cflags "-O3 -flto" .
\`\`\`

## Project Structure
\`\`\`
${options.name}/
├── main.v                # Application entry point
├── v.mod                 # V module configuration
├── src/
│   ├── server.v          # Server initialization
│   ├── router.v          # Route definitions
│   ├── config.v          # Configuration management
│   ├── controllers/      # Request handlers
│   ├── models/           # Data models
│   ├── middleware/       # Middleware functions
│   ├── utils/            # Utility functions
│   └── views/            # Templates (if applicable)
├── tests/                # Test files
├── public/               # Static files
├── config/               # Configuration files
├── docs/                 # Documentation
├── Dockerfile            # Docker configuration
├── docker-compose.yml    # Docker Compose setup
├── Makefile              # Build automation
└── README.md             # This file
\`\`\`

## Configuration
Configuration is managed through environment variables. See \`.env.example\` for available options.

## API Documentation
See [API Documentation](docs/api.md) for detailed endpoint information.

## Docker Support
\`\`\`bash
# Build Docker image
docker build -t ${options.name} .

# Run with Docker
docker run -p ${options.port || 8080}:${options.port || 8080} ${options.name}

# Use Docker Compose
docker-compose up
\`\`\`

## Performance
V compiles to native code and produces small, fast binaries:
- Zero-cost abstractions
- No garbage collector overhead
- Minimal memory footprint
- Fast startup time

## License
MIT
`;

    await fs.writeFile(path.join(projectPath, 'README.md'), readme);
  }

  protected async generateEnvironmentFiles(projectPath: string, options: any): Promise<void> {
    const envExample = `# Application Configuration
APP_ENV=development
HOST=0.0.0.0
PORT=${options.port || 8080}

# Database
DATABASE_URL=sqlite://./data/app.db
# For PostgreSQL: DATABASE_URL=postgresql://user:password@localhost:5432/dbname

# Security
JWT_SECRET=your-secret-key-change-in-production
JWT_EXPIRES_IN=3600
REFRESH_TOKEN_EXPIRES_IN=604800

# CORS
CORS_ORIGINS=http://localhost:3000,http://localhost:5173

# Rate Limiting
RATE_LIMIT_MAX=100
RATE_LIMIT_WINDOW=60000

# Logging
LOG_LEVEL=info
LOG_FILE=./logs/app.log

# Redis (optional)
REDIS_URL=redis://localhost:6379

# Email (optional)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your-email@example.com
SMTP_PASS=your-password
SMTP_FROM=noreply@example.com
`;

    await fs.writeFile(path.join(projectPath, '.env.example'), envExample);
    await fs.writeFile(path.join(projectPath, '.env'), envExample);
  }

  protected getLanguageSpecificIgnorePatterns(): string[] {
    return [
      '*.exe',
      '*.o',
      '*.so',
      '*.dylib',
      '*.dll',
      '*.a',
      '*.tmp.c',
      'vls.log',
      '.vmodules/'
    ];
  }

  protected getLanguagePrerequisites(): string {
    return 'V language (latest version)';
  }

  protected getInstallCommand(): string {
    return 'v install';
  }

  protected getDevCommand(): string {
    return 'v watch run .';
  }

  protected getProdCommand(): string {
    return './server';
  }

  protected getTestCommand(): string {
    return 'v test .';
  }

  protected getCoverageCommand(): string {
    return 'v test -stats .';
  }

  protected getLintCommand(): string {
    return 'v vet .';
  }

  protected getBuildCommand(): string {
    return 'v -prod .';
  }

  protected getSetupAction(): string {
    return 'v install';
  }
}