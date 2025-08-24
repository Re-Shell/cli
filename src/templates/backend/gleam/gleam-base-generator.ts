import { BackendTemplateGenerator } from '../shared/backend-template-generator';
import * as fs from 'fs/promises';
import * as path from 'path';

export abstract class GleamBackendGenerator extends BackendTemplateGenerator {
  protected options: any;
  
  constructor() {
    super({
      language: 'Gleam',
      framework: 'Gleam Framework',
      packageManager: 'gleam',
      buildTool: 'gleam',
      testFramework: 'gleeunit',
      features: [
        'Type-safe functional programming',
        'Runs on BEAM (Erlang VM)',
        'Actor model concurrency',
        'Fault-tolerant systems',
        'Hot code reloading',
        'Pattern matching',
        'Immutable data',
        'No null or undefined',
        'JavaScript compilation',
        'Docker support'
      ],
      dependencies: {},
      devDependencies: {},
      scripts: {
        'build': 'gleam build',
        'dev': 'gleam run',
        'test': 'gleam test',
        'format': 'gleam format',
        'check': 'gleam check',
        'docs': 'gleam docs build'
      }
    });
  }

  protected abstract getFrameworkDependencies(): Record<string, string>;
  protected abstract generateMainFile(): string;
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
    // Generate gleam.toml file
    await fs.writeFile(
      path.join(projectPath, 'gleam.toml'),
      this.generateGleamToml(options)
    );

    // Generate .gitignore
    await this.generateGitignore(projectPath);

    // Create directory structure
    await fs.mkdir(path.join(projectPath, 'src'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'src', 'controllers'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'src', 'models'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'src', 'middleware'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'src', 'utils'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'src', 'config'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'test'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'priv'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'priv', 'static'), { recursive: true });

    // Generate main application file
    const appName = this.getAppModuleName(options.name);
    await fs.writeFile(
      path.join(projectPath, 'src', `${appName}.gleam`),
      this.generateMainFile()
    );

    // Generate router
    await fs.writeFile(
      path.join(projectPath, 'src', 'router.gleam'),
      this.generateRouterFile()
    );

    // Generate config
    await fs.writeFile(
      path.join(projectPath, 'src', 'config', 'config.gleam'),
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

    // Generate manifest.toml (for releases)
    await fs.writeFile(
      path.join(projectPath, 'manifest.toml'),
      this.generateManifest(options)
    );
  }

  protected async generateHealthCheck(projectPath: string): Promise<void> {
    // Health check is implemented in the controller
  }

  protected async generateAPIDocs(projectPath: string): Promise<void> {
    const apiDocs = `# API Documentation

## Overview
This is a Gleam-based web service built with modern functional programming patterns.

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

  protected generateGleamToml(options: any): string {
    const appName = this.getAppModuleName(options.name);
    const deps = this.getFrameworkDependencies();
    
    let depsString = '';
    for (const [name, version] of Object.entries(deps)) {
      depsString += `${name} = "${version}"\n`;
    }

    return `name = "${appName}"
version = "1.0.0"
description = "${options.description || 'A web service built with Gleam'}"
licences = ["MIT"]
repository = { type = "github", user = "username", repo = "${appName}" }

# Gleam dependencies
[dependencies]
gleam_stdlib = "~> 0.34"
gleam_erlang = "~> 0.25"
gleam_otp = "~> 0.10"
gleam_http = "~> 3.6"
gleam_json = "~> 1.0"
gleam_crypto = "~> 1.3"
${depsString}

# Dev dependencies
[dev-dependencies]
gleeunit = "~> 1.0"

# Documentation
[documentation]
links = [
  { title = "API Documentation", href = "/api" },
  { title = "Getting Started", href = "/guide" }
]
`;
  }

  protected generateManifest(options: any): string {
    return `# This file was generated by Gleam
# You typically do not need to edit this file

packages = [
  { name = "gleam_stdlib", version = "0.34.0", build_tools = ["gleam"], requirements = [], source = "hex" },
  { name = "gleam_erlang", version = "0.25.0", build_tools = ["gleam"], requirements = ["gleam_stdlib"], source = "hex" },
  { name = "gleam_otp", version = "0.10.0", build_tools = ["gleam"], requirements = ["gleam_erlang", "gleam_stdlib"], source = "hex" },
  { name = "gleam_http", version = "3.6.0", build_tools = ["gleam"], requirements = ["gleam_stdlib"], source = "hex" },
  { name = "gleam_json", version = "1.0.0", build_tools = ["gleam"], requirements = ["gleam_stdlib"], source = "hex" },
  { name = "gleam_crypto", version = "1.3.0", build_tools = ["gleam"], requirements = ["gleam_stdlib"], source = "hex" },
  { name = "gleeunit", version = "1.0.0", build_tools = ["gleam"], requirements = ["gleam_stdlib"], source = "hex" },
]

[requirements]
gleam_crypto = { version = "~> 1.3" }
gleam_erlang = { version = "~> 0.25" }
gleam_http = { version = "~> 3.6" }
gleam_json = { version = "~> 1.0" }
gleam_otp = { version = "~> 0.10" }
gleam_stdlib = { version = "~> 0.34" }
gleeunit = { version = "~> 1.0" }
`;
  }

  protected async generateGitignore(projectPath: string): Promise<void> {
    const gitignoreContent = `# Gleam
build/
*.beam
*.ez
erl_crash.dump

# Dependencies
_build/
_checkouts/
deps/

# Development
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
cover/
_build/test/

# Documentation
doc/
docs/build/

# Temporary files
*.tmp
tmp/

# Erlang/OTP
.erlang.cookie
ebin/
.rebar/
.rebar3/
rebar.lock
`;
    
    await fs.writeFile(path.join(projectPath, '.gitignore'), gitignoreContent);
  }

  protected getAppModuleName(projectName: string): string {
    // Convert kebab-case to snake_case for Gleam module names
    return projectName.toLowerCase().replace(/-/g, '_');
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Framework-specific files are handled by subclasses
  }

  protected async generateTestStructure(projectPath: string, options: any): Promise<void> {
    // Test structure is generated in generateLanguageFiles
  }

  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    const dockerContent = `# Multi-stage build for Gleam application
FROM ghcr.io/gleam-lang/gleam:v1.0.0-erlang-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git build-base

# Set working directory
WORKDIR /app

# Copy gleam.toml and manifest.toml
COPY gleam.toml manifest.toml ./

# Download dependencies
RUN gleam deps download

# Copy source code
COPY . .

# Build the application
RUN gleam build

# Production stage
FROM erlang:26-alpine

# Install runtime dependencies
RUN apk add --no-cache openssl ncurses-libs

# Create non-root user
RUN addgroup -g 1000 app && \\
    adduser -D -u 1000 -G app app

# Set working directory
WORKDIR /app

# Copy built application
COPY --from=builder --chown=app:app /app/build /app/build
COPY --from=builder --chown=app:app /app/priv /app/priv

# Copy configuration files
COPY --chown=app:app .env.example .env

# Create necessary directories
RUN mkdir -p /app/logs && chown app:app /app/logs

# Switch to non-root user
USER app

# Expose port
EXPOSE ${options.port || 8080}

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD wget --no-verbose --tries=1 --spider http://localhost:${options.port || 8080}/health || exit 1

# Start the application
CMD ["gleam", "run"]
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
      - NODE_ENV=production
      - PORT=${options.port || 8080}
      - DATABASE_URL=\${DATABASE_URL:-postgresql://postgres:postgres@db:5432/app}
      - JWT_SECRET=\${JWT_SECRET}
      - CORS_ORIGINS=\${CORS_ORIGINS:-*}
    volumes:
      - ./logs:/app/logs
    restart: unless-stopped
    depends_on:
      - db
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:${options.port || 8080}/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - gleam-network

  # PostgreSQL database
  db:
    image: postgres:16-alpine
    container_name: ${options.name}-db
    environment:
      - POSTGRES_DB=\${DB_NAME:-app}
      - POSTGRES_USER=\${DB_USER:-postgres}
      - POSTGRES_PASSWORD=\${DB_PASSWORD:-postgres}
    volumes:
      - postgres-data:/var/lib/postgresql/data
    restart: unless-stopped
    networks:
      - gleam-network

networks:
  gleam-network:
    driver: bridge

volumes:
  postgres-data:
`;

    await fs.writeFile(path.join(projectPath, 'docker-compose.yml'), dockerComposeContent);

    // Generate .dockerignore
    const dockerignoreContent = `# Gleam
build/
*.beam
erl_crash.dump

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
test/
cover/

# Documentation
docs/
*.md
`;

    await fs.writeFile(path.join(projectPath, '.dockerignore'), dockerignoreContent);
  }

  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    const readme = `# ${options.name || 'Gleam Backend Service'}

${options.description || 'A backend service built with Gleam'}

## Tech Stack
- **Language**: Gleam
- **Runtime**: BEAM (Erlang VM)
- **Framework**: ${this.config.framework}
- **Database**: PostgreSQL
- **Authentication**: JWT

## Prerequisites
- Gleam 1.0+
- Erlang/OTP 26+
- PostgreSQL (optional, for database)

## Getting Started

### Installation
\`\`\`bash
# Download dependencies
gleam deps download

# Copy environment variables
cp .env.example .env
\`\`\`

### Development
\`\`\`bash
# Run development server
gleam run

# Run tests
gleam test

# Format code
gleam format

# Type check
gleam check
\`\`\`

### Building for Production
\`\`\`bash
# Build the project
gleam build

# Build and export as Erlang application
gleam export erlang-shipment
\`\`\`

## Project Structure
\`\`\`
${options.name}/
├── gleam.toml            # Project configuration
├── manifest.toml         # Dependency lock file
├── src/
│   ├── ${this.getAppModuleName(options.name)}.gleam  # Main application
│   ├── router.gleam      # Route definitions
│   ├── config/           # Configuration
│   ├── controllers/      # Request handlers
│   ├── models/           # Data models
│   ├── middleware/       # Middleware functions
│   └── utils/            # Utility functions
├── test/                 # Test files
├── priv/                 # Static assets
├── Dockerfile            # Docker configuration
├── docker-compose.yml    # Docker Compose setup
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

## Testing
\`\`\`bash
# Run all tests
gleam test

# Run specific test module
gleam test -- test/my_module_test.gleam

# Run with coverage
gleam test --coverage
\`\`\`

## Deployment
The application can be deployed as:
- Erlang release
- Docker container
- Kubernetes deployment
- Fly.io application

## Performance
Gleam on BEAM provides:
- Lightweight processes (millions of concurrent processes)
- Fault tolerance with supervision trees
- Hot code reloading
- Low latency and high throughput

## License
MIT
`;

    await fs.writeFile(path.join(projectPath, 'README.md'), readme);
  }

  protected async generateEnvironmentFiles(projectPath: string, options: any): Promise<void> {
    const envExample = `# Application Configuration
NODE_ENV=development
HOST=0.0.0.0
PORT=${options.port || 8080}

# Database
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/app
# Or use individual settings:
# DB_HOST=localhost
# DB_PORT=5432
# DB_NAME=app
# DB_USER=postgres
# DB_PASSWORD=postgres

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

# Email (optional)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your-email@example.com
SMTP_PASS=your-password
SMTP_FROM=noreply@example.com

# External Services (optional)
REDIS_URL=redis://localhost:6379
ELASTICSEARCH_URL=http://localhost:9200
`;

    await fs.writeFile(path.join(projectPath, '.env.example'), envExample);
    await fs.writeFile(path.join(projectPath, '.env'), envExample);
  }

  protected getLanguageSpecificIgnorePatterns(): string[] {
    return [
      '*.beam',
      '*.ez',
      'erl_crash.dump',
      'build/',
      '_build/',
      'deps/',
      'doc/',
      '.erlang.cookie',
      'ebin/',
      'manifest.toml.lock'
    ];
  }

  protected getLanguagePrerequisites(): string {
    return 'Gleam 1.0+ and Erlang/OTP 26+';
  }

  protected getInstallCommand(): string {
    return 'gleam deps download';
  }

  protected getDevCommand(): string {
    return 'gleam run';
  }

  protected getProdCommand(): string {
    return 'gleam run --target erlang';
  }

  protected getTestCommand(): string {
    return 'gleam test';
  }

  protected getCoverageCommand(): string {
    return 'gleam test --coverage';
  }

  protected getLintCommand(): string {
    return 'gleam check';
  }

  protected getBuildCommand(): string {
    return 'gleam build';
  }

  protected getSetupAction(): string {
    return 'gleam deps download';
  }
}