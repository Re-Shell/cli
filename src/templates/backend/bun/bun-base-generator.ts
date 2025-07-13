/**
 * Bun Backend Template Base Generator
 * Shared functionality for all Bun web frameworks
 */

import { BackendTemplateGenerator, BackendTemplateConfig } from '../shared/backend-template-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export abstract class BunBackendGenerator extends BackendTemplateGenerator {
  constructor(framework: string) {
    const config: BackendTemplateConfig = {
      language: 'TypeScript',
      framework,
      packageManager: 'bun',
      buildTool: 'bun',
      testFramework: 'bun test',
      features: [
        'Blazing fast runtime',
        'TypeScript by default',
        'JSX support',
        'Built-in bundler',
        'Native ESM',
        'Built-in test runner',
        'Hot reloading',
        'WebSocket support',
        'SQLite built-in',
        'Web APIs compatible'
      ],
      dependencies: {},
      devDependencies: {},
      scripts: {
        'dev': 'bun run --watch src/index.ts',
        'start': 'bun run src/index.ts',
        'build': 'bun build src/index.ts --target=bun --outdir=dist',
        'test': 'bun test',
        'test:watch': 'bun test --watch',
        'typecheck': 'tsc --noEmit',
        'lint': 'eslint src --ext .ts,.tsx',
        'format': 'prettier --write .',
        'docker:build': 'docker build -t {{projectName}} .',
        'docker:run': 'docker run -p {{port}}:{{port}} {{projectName}}'
      },
      dockerConfig: {
        baseImage: 'oven/bun:1.0-alpine',
        workDir: '/app',
        exposedPorts: [3000],
        buildSteps: [
          'COPY package.json bun.lockb* ./',
          'RUN bun install --frozen-lockfile',
          'COPY . .',
          'RUN bun run build'
        ],
        runCommand: 'bun run dist/index.js',
        multistage: true
      },
      envVars: {
        'PORT': '3000',
        'HOST': '0.0.0.0',
        'NODE_ENV': 'development',
        'LOG_LEVEL': 'info',
        'DATABASE_URL': 'sqlite://./data/app.db',
        'JWT_SECRET': 'your-secret-key',
        'CORS_ORIGIN': '*'
      }
    };
    super(config);
  }

  protected async generateLanguageFiles(projectPath: string, options: any): Promise<void> {
    // Generate package.json
    await this.generatePackageJson(projectPath, options);

    // Generate TypeScript config
    await this.generateTsConfig(projectPath);

    // Generate bunfig.toml
    await this.generateBunConfig(projectPath);

    // Generate .gitignore
    await this.generateBunGitignore(projectPath);

    // Generate VS Code settings
    await this.generateVSCodeSettings(projectPath);

    // Create directory structure
    const directories = [
      'src',
      'src/controllers',
      'src/services',
      'src/models',
      'src/middleware',
      'src/utils',
      'src/config',
      'src/types',
      'src/routes',
      'tests',
      'tests/unit',
      'tests/integration',
      'scripts',
      'data'
    ];

    for (const dir of directories) {
      await fs.mkdir(path.join(projectPath, dir), { recursive: true });
    }
  }

  private async generatePackageJson(projectPath: string, options: any): Promise<void> {
    const packageJson = {
      name: options.name,
      version: "1.0.0",
      description: `${this.config.framework} API built with Bun`,
      main: "src/index.ts",
      type: "module",
      scripts: this.config.scripts,
      dependencies: {
        ...this.config.dependencies,
        "@types/bun": "latest",
        "zod": "^3.22.4",
        "dotenv": "^16.4.5"
      },
      devDependencies: {
        ...this.config.devDependencies,
        "typescript": "^5.4.5",
        "@typescript-eslint/eslint-plugin": "^7.7.1",
        "@typescript-eslint/parser": "^7.7.1",
        "eslint": "^8.57.0",
        "prettier": "^3.2.5",
        "@types/node": "^20.12.7"
      },
      engines: {
        "bun": ">=1.0.0"
      }
    };

    await fs.writeFile(
      path.join(projectPath, 'package.json'),
      JSON.stringify(packageJson, null, 2)
    );
  }

  private async generateTsConfig(projectPath: string): Promise<void> {
    const tsConfig = {
      compilerOptions: {
        lib: ["ESNext"],
        module: "esnext",
        target: "esnext",
        moduleResolution: "bundler",
        moduleDetection: "force",
        allowImportingTsExtensions: true,
        noEmit: true,
        composite: true,
        strict: true,
        downlevelIteration: true,
        skipLibCheck: true,
        jsx: "react-jsx",
        allowSyntheticDefaultImports: true,
        forceConsistentCasingInFileNames: true,
        allowJs: true,
        types: ["bun-types"],
        esModuleInterop: true,
        resolveJsonModule: true,
        isolatedModules: true,
        baseUrl: ".",
        paths: {
          "@/*": ["src/*"]
        }
      },
      include: ["src/**/*", "tests/**/*"],
      exclude: ["node_modules", "dist"]
    };

    await fs.writeFile(
      path.join(projectPath, 'tsconfig.json'),
      JSON.stringify(tsConfig, null, 2)
    );
  }

  private async generateBunConfig(projectPath: string): Promise<void> {
    const bunConfig = `# Bun configuration file
# https://bun.sh/docs/runtime/bunfig

# Telemetry
telemetry = false

# Test runner
[test]
# Test timeout in milliseconds
timeout = 5000
# Run tests in watch mode by default
watch = false
# Coverage reporting
coverage = true
coverageThreshold = 80

# Install configuration
[install]
# Use exact versions
exact = true
# Save peer dependencies
peer = true
# Production mode
production = false

# Install cache
[install.cache]
# Cache directory
dir = "~/.bun/install/cache"
# Disable cache
disable = false

# Registry configuration
[install.registry]
default = "https://registry.npmjs.org"

# Development server
[debug]
# Enable source maps
sourcemap = "external"

# Macros
[macros]
# Define compile-time constants
NODE_ENV = "development"

# Bundle configuration
[bundle]
# Bundle target
target = "bun"
# Enable source maps
sourcemap = "external"
# Minify output
minify = false
`;

    await fs.writeFile(
      path.join(projectPath, 'bunfig.toml'),
      bunConfig
    );
  }

  private async generateBunGitignore(projectPath: string): Promise<void> {
    const gitignoreContent = `# Dependencies
node_modules/
bun.lockb

# Build output
dist/
build/
*.tsbuildinfo

# Environment
.env
.env.local
.env.*.local

# Editor
.vscode/*
!.vscode/settings.json
!.vscode/extensions.json
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
bun-error.log

# Test coverage
coverage/
.coverage/
*.lcov

# Temporary files
tmp/
temp/
.tmp/

# Database
data/*.db
data/*.db-journal
data/*.db-wal
*.sqlite

# Debug
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Misc
.cache/
`;

    await fs.writeFile(
      path.join(projectPath, '.gitignore'),
      gitignoreContent
    );
  }

  private async generateVSCodeSettings(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, '.vscode'), { recursive: true });

    const settings = {
      "editor.formatOnSave": true,
      "editor.defaultFormatter": "esbenp.prettier-vscode",
      "[typescript]": {
        "editor.defaultFormatter": "esbenp.prettier-vscode"
      },
      "[typescriptreact]": {
        "editor.defaultFormatter": "esbenp.prettier-vscode"
      },
      "typescript.tsdk": "node_modules/typescript/lib",
      "typescript.enablePromptUseWorkspaceTsdk": true,
      "files.exclude": {
        "**/node_modules": true,
        "**/dist": true,
        "**/.coverage": true
      },
      "search.exclude": {
        "**/node_modules": true,
        "**/dist": true,
        "**/bun.lockb": true
      }
    };

    await fs.writeFile(
      path.join(projectPath, '.vscode', 'settings.json'),
      JSON.stringify(settings, null, 2)
    );

    const extensions = {
      recommendations: [
        "oven.bun-vscode",
        "dbaeumer.vscode-eslint",
        "esbenp.prettier-vscode",
        "ms-vscode.vscode-typescript-next"
      ]
    };

    await fs.writeFile(
      path.join(projectPath, '.vscode', 'extensions.json'),
      JSON.stringify(extensions, null, 2)
    );
  }

  protected async generateCommonFiles(projectPath: string, options: any): Promise<void> {
    await super.generateCommonFiles(projectPath, options);

    // Generate Bun-specific common files
    await this.generateMakefile(projectPath);
    await this.generateDevContainer(projectPath);
  }

  private async generateMakefile(projectPath: string): Promise<void> {
    const makefileContent = `.PHONY: dev start test test-watch build typecheck lint format clean help install docker-build docker-run

# Default target
.DEFAULT_GOAL := help

# Help command
help:
	@echo "Available commands:"
	@echo "  make install       - Install dependencies"
	@echo "  make dev          - Run development server with hot reload"
	@echo "  make start        - Run production server"
	@echo "  make test         - Run tests"
	@echo "  make test-watch   - Run tests in watch mode"
	@echo "  make build        - Build for production"
	@echo "  make typecheck    - Run TypeScript type checking"
	@echo "  make lint         - Lint code"
	@echo "  make format       - Format code"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make docker-build - Build Docker image"
	@echo "  make docker-run   - Run Docker container"

install:
	bun install

dev:
	bun run dev

start:
	bun run start

test:
	bun test

test-watch:
	bun test --watch

build:
	bun run build

typecheck:
	bun run typecheck

lint:
	bun run lint

format:
	bun run format

clean:
	rm -rf dist coverage .coverage bun.lockb node_modules

docker-build:
	docker build -t ${this.config.framework.toLowerCase()}-app .

docker-run:
	docker run -p 3000:3000 ${this.config.framework.toLowerCase()}-app
`;

    await fs.writeFile(
      path.join(projectPath, 'Makefile'),
      makefileContent
    );
  }

  private async generateDevContainer(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, '.devcontainer'), { recursive: true });

    const devContainerConfig = {
      name: `${this.config.framework} Bun Development`,
      image: "oven/bun:1.0",
      customizations: {
        vscode: {
          extensions: [
            "oven.bun-vscode",
            "dbaeumer.vscode-eslint",
            "esbenp.prettier-vscode"
          ],
          settings: {
            "terminal.integrated.defaultProfile.linux": "bash"
          }
        }
      },
      features: {
        "ghcr.io/devcontainers/features/git:1": {},
        "ghcr.io/devcontainers/features/github-cli:1": {}
      },
      postCreateCommand: "bun install",
      forwardPorts: [3000],
      remoteUser: "bun"
    };

    await fs.writeFile(
      path.join(projectPath, '.devcontainer', 'devcontainer.json'),
      JSON.stringify(devContainerConfig, null, 2)
    );
  }

  protected async generateTestStructure(projectPath: string, options: any): Promise<void> {
    // Generate test utilities
    const testUtilsContent = `import { expect, test, describe, beforeEach, afterEach, mock } from 'bun:test';

export { expect, test, describe, beforeEach, afterEach, mock };

// Test helpers
export async function setupTestDb() {
  // Setup test database
  const db = new Database(':memory:');
  // Run migrations
  return db;
}

export async function cleanupTestDb(db: any) {
  // Cleanup test database
  db.close();
}

export function createTestUser() {
  return {
    id: crypto.randomUUID(),
    email: 'test@example.com',
    name: 'Test User',
    createdAt: new Date(),
    updatedAt: new Date()
  };
}

// HTTP test helpers
export async function testRequest(
  path: string,
  options?: RequestInit
): Promise<Response> {
  const baseUrl = process.env.TEST_URL || 'http://localhost:3000';
  return fetch(\`\${baseUrl}\${path}\`, options);
}
`;

    await fs.writeFile(
      path.join(projectPath, 'tests', 'test-utils.ts'),
      testUtilsContent
    );

    // Generate example test
    const exampleTestContent = `import { expect, test, describe } from './test-utils';

describe('Example Test Suite', () => {
  test('should pass a simple test', () => {
    expect(1 + 1).toBe(2);
  });

  test('should handle async operations', async () => {
    const result = await Promise.resolve('success');
    expect(result).toBe('success');
  });

  test('should test API endpoint', async () => {
    const response = await fetch('http://localhost:3000/health');
    expect(response.status).toBe(200);
    
    const data = await response.json();
    expect(data.status).toBe('healthy');
  });
});
`;

    await fs.writeFile(
      path.join(projectPath, 'tests', 'example.test.ts'),
      exampleTestContent
    );
  }

  protected async generateHealthCheck(projectPath: string): Promise<void> {
    const healthCheckContent = `import type { Context } from '../types';

export async function healthCheck(ctx: Context) {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    service: '${this.config.framework.toLowerCase()}-service',
    runtime: 'Bun v' + Bun.version,
    uptime: process.uptime(),
    memory: process.memoryUsage()
  };

  return ctx.json(health);
}

export async function readinessCheck(ctx: Context) {
  try {
    // Add your readiness checks here
    // e.g., database connection, external services
    
    return ctx.json({
      status: 'ready',
      checks: {
        database: 'ok',
        cache: 'ok'
      }
    });
  } catch (error) {
    return ctx.json({
      status: 'not ready',
      error: error.message
    }, 503);
  }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'controllers', 'health.ts'),
      healthCheckContent
    );
  }

  protected async generateAPIDocs(projectPath: string): Promise<void> {
    const apiDocsContent = `# API Documentation

## Overview

This is a RESTful API built with ${this.config.framework} on Bun runtime.

## Base URL

\`\`\`
http://localhost:3000/api/v1
\`\`\`

## Authentication

The API uses JWT (JSON Web Tokens) for authentication. Include the token in the Authorization header:

\`\`\`
Authorization: Bearer <your-jwt-token>
\`\`\`

## Endpoints

### Health Check

\`\`\`http
GET /health
\`\`\`

Returns the health status of the API.

**Response:**
\`\`\`json
{
  "status": "healthy",
  "timestamp": "2024-01-01T00:00:00.000Z",
  "version": "1.0.0",
  "service": "${this.config.framework.toLowerCase()}-service",
  "runtime": "Bun v1.0.0",
  "uptime": 3600,
  "memory": {
    "rss": 123456789,
    "heapTotal": 123456789,
    "heapUsed": 123456789
  }
}
\`\`\`

### Authentication

#### Register
\`\`\`http
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123",
  "name": "John Doe"
}
\`\`\`

#### Login
\`\`\`http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123"
}
\`\`\`

### Users

#### Get Current User
\`\`\`http
GET /api/v1/users/me
Authorization: Bearer <access-token>
\`\`\`

#### Update User
\`\`\`http
PUT /api/v1/users/:id
Authorization: Bearer <access-token>
Content-Type: application/json

{
  "name": "Jane Doe",
  "email": "jane@example.com"
}
\`\`\`

## Error Responses

All error responses follow this format:

\`\`\`json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {}
  }
}
\`\`\`

### Common Error Codes

- \`UNAUTHORIZED\` - Authentication required
- \`FORBIDDEN\` - Insufficient permissions
- \`NOT_FOUND\` - Resource not found
- \`VALIDATION_ERROR\` - Request validation failed
- \`INTERNAL_ERROR\` - Internal server error

## Rate Limiting

The API implements rate limiting:
- 100 requests per minute for authenticated users
- 20 requests per minute for unauthenticated users

## Performance

Bun provides exceptional performance:
- Fast startup times
- Low memory footprint
- Native TypeScript execution
- Built-in SQLite support
`;

    await fs.writeFile(
      path.join(projectPath, 'docs', 'API.md'),
      apiDocsContent
    );
  }

  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    const dockerContent = `# Multi-stage Dockerfile for Bun ${this.config.framework} application

# Build stage
FROM oven/bun:1.0-alpine AS builder

WORKDIR /app

# Copy package files
COPY package.json bun.lockb* ./

# Install dependencies
RUN bun install --frozen-lockfile --production

# Copy source code
COPY . .

# Build application
RUN bun run build

# Runtime stage
FROM oven/bun:1.0-alpine

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

# Create non-root user
RUN addgroup -g 1001 bunapp && \\
    adduser -u 1001 -G bunapp -s /bin/sh -D bunapp

WORKDIR /app

# Copy built application
COPY --from=builder --chown=bunapp:bunapp /app/dist ./dist
COPY --from=builder --chown=bunapp:bunapp /app/node_modules ./node_modules
COPY --from=builder --chown=bunapp:bunapp /app/package.json ./

# Create data directory
RUN mkdir -p /app/data && chown -R bunapp:bunapp /app/data

# Switch to non-root user
USER bunapp

# Expose port
EXPOSE ${options.port || 3000}

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD bun run healthcheck.js || exit 1

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Run the application
CMD ["bun", "run", "dist/index.js"]
`;

    await fs.writeFile(
      path.join(projectPath, 'Dockerfile'),
      dockerContent
    );

    // Docker Compose
    const dockerComposeContent = `version: '3.8'

services:
  app:
    build: .
    ports:
      - "\${PORT:-3000}:3000"
    environment:
      - NODE_ENV=production
      - PORT=3000
      - DATABASE_URL=sqlite:///app/data/app.db
      - JWT_SECRET=\${JWT_SECRET}
    volumes:
      - app-data:/app/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "bun", "run", "healthcheck.js"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 5s

  # Optional: Add Redis for caching
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    restart: unless-stopped

volumes:
  app-data:
  redis-data:
`;

    await fs.writeFile(
      path.join(projectPath, 'docker-compose.yml'),
      dockerComposeContent
    );

    // Health check script
    const healthCheckContent = `// Health check script for Docker
const response = await fetch('http://localhost:3000/health');
if (response.ok) {
  process.exit(0);
} else {
  process.exit(1);
}
`;

    await fs.writeFile(
      path.join(projectPath, 'healthcheck.js'),
      healthCheckContent
    );

    // .dockerignore
    const dockerignoreContent = `node_modules
.git
.gitignore
.env
.env.*
coverage
.coverage
*.log
.DS_Store
.vscode
.idea
*.swp
*.swo
README.md
docs
tests
.devcontainer
Makefile
`;

    await fs.writeFile(
      path.join(projectPath, '.dockerignore'),
      dockerignoreContent
    );
  }

  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    const readmeContent = `# ${options.name}

A ${this.config.framework} web application built with Bun.

## 🚀 Features

- ⚡ Blazing fast Bun runtime
- 🔥 Hot reload in development
- 📘 TypeScript by default
- 🧪 Built-in test runner
- 🔒 JWT authentication
- 📦 SQLite built-in
- 🐳 Docker support
- 🌐 Production ready

## 📋 Prerequisites

- Bun 1.0.0 or higher

## 🛠️ Installation

1. Clone the repository:
\`\`\`bash
git clone <repository-url>
cd ${options.name}
\`\`\`

2. Install Bun (if not already installed):
\`\`\`bash
# macOS/Linux
curl -fsSL https://bun.sh/install | bash

# Windows
powershell -c "irm bun.sh/install.ps1 | iex"
\`\`\`

3. Install dependencies:
\`\`\`bash
bun install
\`\`\`

4. Copy environment variables:
\`\`\`bash
cp .env.example .env
\`\`\`

## 🏃 Running the Application

### Development

\`\`\`bash
bun run dev
# or
make dev
\`\`\`

The application will start at http://localhost:${options.port || 3000} with hot reload enabled.

### Production

\`\`\`bash
bun run build
bun run start
# or
make build && make start
\`\`\`

### Docker

\`\`\`bash
# Build and run with Docker Compose
docker-compose up

# Or build and run manually
docker build -t ${options.name} .
docker run -p ${options.port || 3000}:${options.port || 3000} ${options.name}
\`\`\`

## 🧪 Testing

\`\`\`bash
# Run all tests
bun test

# Run tests in watch mode
bun test --watch

# Run with coverage
bun test --coverage
\`\`\`

## 📝 Available Scripts

- \`bun run dev\` - Start development server with hot reload
- \`bun run start\` - Start production server
- \`bun run build\` - Build for production
- \`bun test\` - Run tests
- \`bun run typecheck\` - Check TypeScript types
- \`bun run lint\` - Lint code
- \`bun run format\` - Format code

## 🚀 Deployment

### Railway

\`\`\`bash
# Install Railway CLI
bun add -g @railway/cli

# Deploy
railway login
railway init
railway up
\`\`\`

### Fly.io

\`\`\`bash
# Install Fly CLI
curl -L https://fly.io/install.sh | sh

# Deploy
fly launch
fly deploy
\`\`\`

### Docker

\`\`\`bash
# Build image
docker build -t ${options.name} .

# Push to registry
docker tag ${options.name} your-registry/${options.name}:latest
docker push your-registry/${options.name}:latest
\`\`\`

## 📁 Project Structure

\`\`\`
.
├── src/                # Source code
│   ├── index.ts       # Application entry point
│   ├── controllers/   # Route controllers
│   ├── services/      # Business logic
│   ├── models/        # Data models
│   ├── middleware/    # Middleware functions
│   ├── routes/        # Route definitions
│   ├── utils/         # Utility functions
│   ├── config/        # Configuration
│   └── types/         # TypeScript types
├── tests/             # Test files
├── data/              # SQLite database
├── scripts/           # Utility scripts
└── docs/              # Documentation
\`\`\`

## 🔧 Configuration

The application uses environment variables for configuration. See \`.env.example\` for available options.

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (\`git checkout -b feature/amazing-feature\`)
3. Run tests (\`bun test\`)
4. Commit your changes (\`git commit -m 'Add amazing feature'\`)
5. Push to the branch (\`git push origin feature/amazing-feature\`)
6. Open a Pull Request

## 📝 License

This project is licensed under the MIT License.

---

Built with ❤️ using [Bun](https://bun.sh) and [${this.config.framework}](https://github.com/${this.config.framework.toLowerCase()})
`;

    await fs.writeFile(
      path.join(projectPath, 'README.md'),
      readmeContent
    );
  }

  protected getLanguageSpecificIgnorePatterns(): string[] {
    return [
      'bun.lockb',
      'node_modules/',
      'dist/',
      'coverage/',
      '.coverage/',
      'data/*.db',
      'data/*.db-journal',
      'data/*.db-wal'
    ];
  }

  protected getLanguagePrerequisites(): string {
    return 'Bun 1.0.0+';
  }

  protected getInstallCommand(): string {
    return 'bun install';
  }

  protected getDevCommand(): string {
    return 'bun run dev';
  }

  protected getProdCommand(): string {
    return 'bun run start';
  }

  protected getTestCommand(): string {
    return 'bun test';
  }

  protected getCoverageCommand(): string {
    return 'bun test --coverage';
  }

  protected getLintCommand(): string {
    return 'bun run lint';
  }

  protected getBuildCommand(): string {
    return 'bun run build';
  }

  protected getSetupAction(): string {
    return 'oven-sh/setup-bun@v1';
  }

  protected async generateBuildScript(projectPath: string, options: any): Promise<void> {
    const buildScriptContent = `#!/usr/bin/env bun
// Build script for ${this.config.framework} application

import { $ } from 'bun';
import { mkdir, rm } from 'fs/promises';
import { existsSync } from 'fs';

console.log('🔨 Building ${this.config.framework} application...');

// Clean dist directory
if (existsSync('./dist')) {
  await rm('./dist', { recursive: true });
}
await mkdir('./dist', { recursive: true });

// Run TypeScript compiler for type checking
console.log('📝 Type checking...');
await $\`bun run typecheck\`;

// Build the application
console.log('📦 Building application...');
await $\`bun build src/index.ts --target=bun --outdir=dist --minify\`;

// Copy static files if needed
// await $\`cp -r public dist/\`;

console.log('✅ Build complete!');
`;

    await fs.writeFile(
      path.join(projectPath, 'scripts', 'build.ts'),
      buildScriptContent
    );

    await fs.chmod(path.join(projectPath, 'scripts', 'build.ts'), 0o755);
  }
}