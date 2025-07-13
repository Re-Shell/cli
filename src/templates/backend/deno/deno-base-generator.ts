/**
 * Deno Backend Template Base Generator
 * Shared functionality for all Deno web frameworks
 */

import { BackendTemplateGenerator, BackendTemplateConfig } from '../shared/backend-template-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export abstract class DenoBackendGenerator extends BackendTemplateGenerator {
  constructor(framework: string) {
    const config: BackendTemplateConfig = {
      language: 'TypeScript',
      framework,
      packageManager: 'deno',
      buildTool: 'deno',
      testFramework: 'deno test',
      features: [
        'TypeScript by default',
        'No node_modules',
        'URL imports',
        'Built-in testing',
        'Top-level await',
        'Secure by default',
        'Web standards APIs',
        'Built-in formatter',
        'Built-in linter',
        'Deploy to edge'
      ],
      dependencies: {},
      devDependencies: {},
      scripts: {
        'dev': 'deno run --watch --allow-net --allow-read --allow-env --allow-write main.ts',
        'start': 'deno run --allow-net --allow-read --allow-env main.ts',
        'test': 'deno test --allow-net --allow-read --allow-env',
        'test:coverage': 'deno test --allow-net --allow-read --allow-env --coverage=coverage',
        'fmt': 'deno fmt',
        'lint': 'deno lint',
        'compile': 'deno compile --allow-net --allow-read --allow-env --output=app main.ts',
        'cache': 'deno cache deps.ts',
        'check': 'deno check main.ts',
        'bench': 'deno bench'
      },
      dockerConfig: {
        baseImage: 'denoland/deno:alpine-1.40.0',
        workDir: '/app',
        exposedPorts: [8000],
        buildSteps: [
          'COPY deps.ts .',
          'RUN deno cache deps.ts',
          'COPY . .',
          'RUN deno cache main.ts'
        ],
        runCommand: 'deno run --allow-net --allow-read --allow-env main.ts',
        multistage: true
      },
      envVars: {
        'PORT': '8000',
        'HOST': '0.0.0.0',
        'ENV': 'development',
        'LOG_LEVEL': 'info',
        'DATABASE_URL': 'postgresql://user:password@localhost:5432/deno_db',
        'REDIS_URL': 'redis://localhost:6379',
        'JWT_SECRET': 'your-secret-key',
        'CORS_ORIGIN': '*'
      }
    };
    super(config);
  }

  protected async generateLanguageFiles(projectPath: string, options: any): Promise<void> {
    // Generate deno.json
    await this.generateDenoConfig(projectPath, options);

    // Generate import map
    await this.generateImportMap(projectPath);

    // Generate deps.ts
    await this.generateDeps(projectPath);

    // Generate .gitignore
    await this.generateDenoGitignore(projectPath);

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
      'tests',
      'tests/unit',
      'tests/integration',
      'scripts',
      'static'
    ];

    for (const dir of directories) {
      await fs.mkdir(path.join(projectPath, dir), { recursive: true });
    }
  }

  private async generateDenoConfig(projectPath: string, options: any): Promise<void> {
    const denoConfig = {
      "tasks": {
        "dev": "deno run --watch --allow-net --allow-read --allow-env --allow-write main.ts",
        "start": "deno run --allow-net --allow-read --allow-env main.ts",
        "test": "deno test --allow-net --allow-read --allow-env",
        "test:coverage": "deno test --allow-net --allow-read --allow-env --coverage=coverage",
        "fmt": "deno fmt",
        "lint": "deno lint",
        "compile": `deno compile --allow-net --allow-read --allow-env --output=${options.name} main.ts`,
        "cache": "deno cache deps.ts",
        "check": "deno check main.ts",
        "bench": "deno bench",
        "deploy": "deployctl deploy --project=${options.name} main.ts"
      },
      "imports": {
        "@/": "./src/",
        "@std/": "https://deno.land/std@0.212.0/",
        "@oak": "https://deno.land/x/oak@v12.6.2/mod.ts",
        "@fresh": "https://deno.land/x/fresh@1.6.1/mod.ts",
        "@aleph": "https://deno.land/x/aleph@1.0.0-rc.1/mod.ts"
      },
      "lint": {
        "include": ["src/", "tests/"],
        "exclude": ["static/"],
        "rules": {
          "tags": ["recommended"],
          "include": ["ban-untagged-todo"],
          "exclude": ["no-unused-vars"]
        }
      },
      "fmt": {
        "include": ["src/", "tests/"],
        "exclude": ["static/"],
        "options": {
          "useTabs": false,
          "lineWidth": 100,
          "indentWidth": 2,
          "singleQuote": true,
          "proseWrap": "preserve"
        }
      },
      "test": {
        "include": ["tests/"],
        "exclude": ["static/"]
      },
      "compilerOptions": {
        "jsx": "react-jsx",
        "jsxImportSource": "preact",
        "lib": ["deno.window", "deno.unstable"]
      },
      "nodeModulesDir": false,
      "lock": false
    };

    await fs.writeFile(
      path.join(projectPath, 'deno.json'),
      JSON.stringify(denoConfig, null, 2)
    );
  }

  private async generateImportMap(projectPath: string): Promise<void> {
    const importMap = {
      "imports": {
        "$std/": "https://deno.land/std@0.212.0/",
        "$fresh/": "https://deno.land/x/fresh@1.6.1/",
        "preact": "https://esm.sh/preact@10.19.2",
        "preact/": "https://esm.sh/preact@10.19.2/",
        "@preact/signals": "https://esm.sh/*@preact/signals@1.2.1",
        "@preact/signals-core": "https://esm.sh/*@preact/signals-core@1.5.0",
        "postgres": "https://deno.land/x/postgres@v0.19.3/mod.ts",
        "redis": "https://deno.land/x/redis@v0.32.1/mod.ts",
        "djwt": "https://deno.land/x/djwt@v3.0.1/mod.ts",
        "bcrypt": "https://deno.land/x/bcrypt@v0.4.1/mod.ts",
        "zod": "https://deno.land/x/zod@v3.22.4/mod.ts",
        "dotenv": "https://deno.land/x/dotenv@v3.2.2/load.ts"
      }
    };

    await fs.writeFile(
      path.join(projectPath, 'import_map.json'),
      JSON.stringify(importMap, null, 2)
    );
  }

  private async generateDeps(projectPath: string): Promise<void> {
    const depsContent = `// Central dependency management
export * as path from "https://deno.land/std@0.212.0/path/mod.ts";
export * as fs from "https://deno.land/std@0.212.0/fs/mod.ts";
export * as log from "https://deno.land/std@0.212.0/log/mod.ts";
export * as datetime from "https://deno.land/std@0.212.0/datetime/mod.ts";
export * as crypto from "https://deno.land/std@0.212.0/crypto/mod.ts";
export * as uuid from "https://deno.land/std@0.212.0/uuid/mod.ts";
export * as testing from "https://deno.land/std@0.212.0/testing/mod.ts";
export * as asserts from "https://deno.land/std@0.212.0/assert/mod.ts";
export * as async from "https://deno.land/std@0.212.0/async/mod.ts";
export * as http from "https://deno.land/std@0.212.0/http/mod.ts";

// Third-party dependencies
export { z } from "https://deno.land/x/zod@v3.22.4/mod.ts";
export { config } from "https://deno.land/x/dotenv@v3.2.2/mod.ts";
export * as bcrypt from "https://deno.land/x/bcrypt@v0.4.1/mod.ts";
export * as djwt from "https://deno.land/x/djwt@v3.0.1/mod.ts";
export { Pool } from "https://deno.land/x/postgres@v0.19.3/mod.ts";
export { connect as connectRedis } from "https://deno.land/x/redis@v0.32.1/mod.ts";

// Framework-specific exports are handled in each framework's deps file
`;

    await fs.writeFile(
      path.join(projectPath, 'deps.ts'),
      depsContent
    );
  }

  private async generateDenoGitignore(projectPath: string): Promise<void> {
    const gitignoreContent = `# Deno
.deno/
coverage/
*.orig
*.pyc
*.swp

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

# Build output
app
${this.config.framework.toLowerCase()}-app
*.exe

# Test coverage
coverage/
.coverage/

# Temporary files
tmp/
temp/
.tmp/

# Deno Deploy
.deno-deploy/
`;

    await fs.writeFile(
      path.join(projectPath, '.gitignore'),
      gitignoreContent
    );
  }

  private async generateVSCodeSettings(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, '.vscode'), { recursive: true });

    const settings = {
      "deno.enable": true,
      "deno.lint": true,
      "deno.unstable": true,
      "deno.suggest.imports.hosts": {
        "https://deno.land": true,
        "https://esm.sh": true,
        "https://cdn.skypack.dev": true
      },
      "editor.formatOnSave": true,
      "editor.defaultFormatter": "denoland.vscode-deno",
      "[typescript]": {
        "editor.defaultFormatter": "denoland.vscode-deno"
      },
      "[typescriptreact]": {
        "editor.defaultFormatter": "denoland.vscode-deno"
      }
    };

    await fs.writeFile(
      path.join(projectPath, '.vscode', 'settings.json'),
      JSON.stringify(settings, null, 2)
    );

    const extensions = {
      "recommendations": [
        "denoland.vscode-deno"
      ]
    };

    await fs.writeFile(
      path.join(projectPath, '.vscode', 'extensions.json'),
      JSON.stringify(extensions, null, 2)
    );
  }

  protected async generateCommonFiles(projectPath: string, options: any): Promise<void> {
    await super.generateCommonFiles(projectPath, options);

    // Generate Deno-specific common files
    await this.generateMakefile(projectPath);
    await this.generateDeployConfig(projectPath, options);
    await this.generateDevContainer(projectPath);
  }

  private async generateMakefile(projectPath: string): Promise<void> {
    const makefileContent = `.PHONY: dev start test test-coverage fmt lint compile cache check bench deploy clean help

# Default target
.DEFAULT_GOAL := help

# Help command
help:
	@echo "Available commands:"
	@echo "  make dev          - Run development server with hot reload"
	@echo "  make start        - Run production server"
	@echo "  make test         - Run tests"
	@echo "  make test-coverage - Run tests with coverage"
	@echo "  make fmt          - Format code"
	@echo "  make lint         - Lint code"
	@echo "  make compile      - Compile to executable"
	@echo "  make cache        - Cache dependencies"
	@echo "  make check        - Type check"
	@echo "  make bench        - Run benchmarks"
	@echo "  make deploy       - Deploy to Deno Deploy"
	@echo "  make clean        - Clean build artifacts"

dev:
	deno task dev

start:
	deno task start

test:
	deno task test

test-coverage:
	deno task test:coverage
	fmt:
	deno task fmt

lint:
	deno task lint

compile:
	deno task compile

cache:
	deno task cache

check:
	deno task check

bench:
	deno task bench

deploy:
	deno task deploy

clean:
	rm -rf .deno coverage app *.exe

# Docker commands
docker-build:
	docker build -t ${this.config.framework.toLowerCase()}-app .

docker-run:
	docker run -p 8000:8000 ${this.config.framework.toLowerCase()}-app
`;

    await fs.writeFile(
      path.join(projectPath, 'Makefile'),
      makefileContent
    );
  }

  private async generateDeployConfig(projectPath: string, options: any): Promise<void> {
    // Deno Deploy configuration
    const deployContent = `// Deno Deploy configuration
export default {
  project: "${options.name}",
  exclude: [
    "**/node_modules",
    "**/.git",
    "**/coverage",
    "**/tests",
    "**/*.test.ts",
    "**/*.bench.ts"
  ],
  include: [
    "main.ts",
    "src/**/*.ts",
    "static/**/*",
    "deps.ts",
    "deno.json"
  ]
};
`;

    await fs.writeFile(
      path.join(projectPath, 'deploy.ts'),
      deployContent
    );
  }

  private async generateDevContainer(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, '.devcontainer'), { recursive: true });

    const devContainerConfig = {
      "name": `${this.config.framework} Deno Development`,
      "image": "denoland/deno:latest",
      "customizations": {
        "vscode": {
          "extensions": [
            "denoland.vscode-deno",
            "esbenp.prettier-vscode",
            "dbaeumer.vscode-eslint"
          ],
          "settings": {
            "deno.enable": true,
            "deno.lint": true,
            "deno.unstable": true
          }
        }
      },
      "forwardPorts": [8000],
      "postCreateCommand": "deno cache deps.ts",
      "remoteUser": "deno"
    };

    await fs.writeFile(
      path.join(projectPath, '.devcontainer', 'devcontainer.json'),
      JSON.stringify(devContainerConfig, null, 2)
    );
  }

  protected async generateTestStructure(projectPath: string, options: any): Promise<void> {
    // Generate test utilities
    const testUtilsContent = `import { assertEquals, assertExists, assertThrows } from "https://deno.land/std@0.212.0/assert/mod.ts";
import { describe, it, beforeEach, afterEach } from "https://deno.land/std@0.212.0/testing/bdd.ts";
import { spy, stub } from "https://deno.land/std@0.212.0/testing/mock.ts";

export { assertEquals, assertExists, assertThrows, describe, it, beforeEach, afterEach, spy, stub };

// Test helpers
export async function setupTestDb() {
  // Setup test database
}

export async function cleanupTestDb() {
  // Cleanup test database
}

export function createTestUser() {
  return {
    id: crypto.randomUUID(),
    email: "test@example.com",
    name: "Test User",
    createdAt: new Date(),
    updatedAt: new Date()
  };
}
`;

    await fs.writeFile(
      path.join(projectPath, 'tests', 'test_utils.ts'),
      testUtilsContent
    );

    // Generate example test
    const exampleTestContent = `import { assertEquals, describe, it } from "./test_utils.ts";

describe("Example Test Suite", () => {
  it("should pass a simple test", () => {
    assertEquals(1 + 1, 2);
  });

  it("should handle async operations", async () => {
    const result = await Promise.resolve("success");
    assertEquals(result, "success");
  });
});
`;

    await fs.writeFile(
      path.join(projectPath, 'tests', 'example.test.ts'),
      exampleTestContent
    );
  }

  protected async generateHealthCheck(projectPath: string): Promise<void> {
    const healthCheckContent = `import { Router } from "../deps.ts";

const router = new Router();

router.get("/health", (ctx) => {
  ctx.response.body = {
    status: "healthy",
    timestamp: new Date().toISOString(),
    version: "1.0.0",
    service: "${this.config.framework.toLowerCase()}-service"
  };
});

router.get("/ready", async (ctx) => {
  // Check database connection
  try {
    // Add your readiness checks here
    ctx.response.body = {
      status: "ready",
      checks: {
        database: "ok",
        redis: "ok"
      }
    };
  } catch (error) {
    ctx.response.status = 503;
    ctx.response.body = {
      status: "not ready",
      error: error.message
    };
  }
});

export default router;
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'controllers', 'health.ts'),
      healthCheckContent
    );
  }

  protected async generateAPIDocs(projectPath: string): Promise<void> {
    const apiDocsContent = `# API Documentation

## Overview

This is a RESTful API built with ${this.config.framework} on Deno runtime.

## Base URL

\`\`\`
http://localhost:8000/api/v1
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

## Rate Limiting

The API implements rate limiting:
- 100 requests per minute for authenticated users
- 20 requests per minute for unauthenticated users
`;

    await fs.writeFile(
      path.join(projectPath, 'docs', 'API.md'),
      apiDocsContent
    );
  }

  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    const dockerContent = `# Multi-stage Dockerfile for Deno ${this.config.framework} application

# Build stage
FROM denoland/deno:alpine-1.40.0 AS builder

WORKDIR /app

# Copy dependency files
COPY deps.ts deno.json ./

# Cache dependencies
RUN deno cache deps.ts

# Copy source code
COPY . .

# Cache main application
RUN deno cache main.ts

# Compile application (optional)
# RUN deno compile --allow-net --allow-read --allow-env --output=app main.ts

# Runtime stage
FROM denoland/deno:alpine-1.40.0

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

# Create non-root user
RUN addgroup -g 1000 deno && \\
    adduser -u 1000 -G deno -s /bin/sh -D deno

WORKDIR /app

# Copy application from builder
COPY --from=builder --chown=deno:deno /app .

# Switch to non-root user
USER deno

# Expose port
EXPOSE 8000

# Set environment
ENV DENO_DIR=/app/.deno
ENV PORT=8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD deno run --allow-net health_check.ts || exit 1

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Run the application
CMD ["deno", "run", "--allow-net", "--allow-read", "--allow-env", "main.ts"]
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
      - "\${PORT:-8000}:8000"
    environment:
      - PORT=8000
      - ENV=production
      - DATABASE_URL=postgresql://postgres:postgres@db:5432/deno_db
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis
    restart: unless-stopped
    volumes:
      - deno-cache:/app/.deno

  db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_DB=deno_db
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

volumes:
  postgres_data:
  redis_data:
  deno-cache:
`;

    await fs.writeFile(
      path.join(projectPath, 'docker-compose.yml'),
      dockerComposeContent
    );

    // Health check script
    const healthCheckContent = `#!/usr/bin/env -S deno run --allow-net

try {
  const response = await fetch("http://localhost:8000/health");
  if (response.ok) {
    Deno.exit(0);
  } else {
    Deno.exit(1);
  }
} catch {
  Deno.exit(1);
}
`;

    await fs.writeFile(
      path.join(projectPath, 'health_check.ts'),
      healthCheckContent
    );
  }

  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    const readmeContent = `# ${options.name}

A ${this.config.framework} web application built with Deno.

## 🚀 Features

- 🦕 Built with Deno - secure, modern JavaScript/TypeScript runtime
- 🔒 Secure by default with explicit permissions
- 📦 No node_modules - dependencies cached globally
- 🔥 Hot reload in development
- 🧪 Built-in testing framework
- 🎯 Type safety with TypeScript
- 🚀 Deploy to Deno Deploy with one command
- 🐳 Docker support for containerized deployment

## 📋 Prerequisites

- Deno 1.40.0 or higher
- PostgreSQL 12+ (optional)
- Redis (optional)

## 🛠️ Installation

1. Clone the repository:
\`\`\`bash
git clone <repository-url>
cd ${options.name}
\`\`\`

2. Install Deno (if not already installed):
\`\`\`bash
# macOS/Linux
curl -fsSL https://deno.land/install.sh | sh

# Windows
irm https://deno.land/install.ps1 | iex
\`\`\`

3. Cache dependencies:
\`\`\`bash
deno task cache
\`\`\`

4. Copy environment variables:
\`\`\`bash
cp .env.example .env
\`\`\`

## 🏃 Running the Application

### Development

\`\`\`bash
deno task dev
# or
make dev
\`\`\`

The application will start at http://localhost:8000

### Production

\`\`\`bash
deno task start
# or
make start
\`\`\`

### Docker

\`\`\`bash
# Build and run with Docker Compose
docker-compose up

# Or build and run manually
docker build -t ${options.name} .
docker run -p 8000:8000 ${options.name}
\`\`\`

## 🧪 Testing

\`\`\`bash
# Run all tests
deno task test

# Run tests with coverage
deno task test:coverage

# Run specific test file
deno test tests/example.test.ts
\`\`\`

## 📝 Available Scripts

- \`deno task dev\` - Start development server with hot reload
- \`deno task start\` - Start production server
- \`deno task test\` - Run tests
- \`deno task test:coverage\` - Run tests with coverage
- \`deno task fmt\` - Format code
- \`deno task lint\` - Lint code
- \`deno task compile\` - Compile to executable
- \`deno task deploy\` - Deploy to Deno Deploy

## 🚀 Deployment

### Deno Deploy

1. Install deployctl:
\`\`\`bash
deno install -A -f https://deno.land/x/deploy/deployctl.ts
\`\`\`

2. Deploy:
\`\`\`bash
deno task deploy
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
├── main.ts              # Application entry point
├── deps.ts              # Centralized dependencies
├── deno.json           # Deno configuration
├── import_map.json     # Import map (optional)
├── src/
│   ├── controllers/    # Route controllers
│   ├── services/       # Business logic
│   ├── models/         # Data models
│   ├── middleware/     # Middleware functions
│   ├── utils/          # Utility functions
│   ├── config/         # Configuration
│   └── types/          # TypeScript types
├── tests/              # Test files
├── static/             # Static assets
└── docs/               # Documentation
\`\`\`

## 🔒 Security

Deno is secure by default. The application requires explicit permissions:

- \`--allow-net\` - Network access
- \`--allow-read\` - File system read access
- \`--allow-env\` - Environment variable access
- \`--allow-write\` - File system write access (development only)

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (\`git checkout -b feature/amazing-feature\`)
3. Run tests and ensure they pass
4. Format your code (\`deno task fmt\`)
5. Commit your changes (\`git commit -m 'Add amazing feature'\`)
6. Push to the branch (\`git push origin feature/amazing-feature\`)
7. Open a Pull Request

## 📝 License

This project is licensed under the MIT License.

---

Built with ❤️ using [Deno](https://deno.land) and [${this.config.framework}](https://github.com/${this.config.framework.toLowerCase()})
`;

    await fs.writeFile(
      path.join(projectPath, 'README.md'),
      readmeContent
    );
  }

  protected getLanguageSpecificIgnorePatterns(): string[] {
    return [
      '.deno/',
      'coverage/',
      '*.orig',
      'app',
      '*.exe',
      'deno.lock'
    ];
  }

  protected getLanguagePrerequisites(): string {
    return 'Deno 1.40.0+';
  }

  protected getInstallCommand(): string {
    return 'deno cache deps.ts';
  }

  protected getDevCommand(): string {
    return 'deno task dev';
  }

  protected getProdCommand(): string {
    return 'deno task start';
  }

  protected getTestCommand(): string {
    return 'deno task test';
  }

  protected getCoverageCommand(): string {
    return 'deno task test:coverage';
  }

  protected getLintCommand(): string {
    return 'deno task lint';
  }

  protected getBuildCommand(): string {
    return 'deno task compile';
  }

  protected getSetupAction(): string {
    return 'denoland/setup-deno@v1';
  }
}
