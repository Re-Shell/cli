import { BackendTemplateGenerator } from '../shared/backend-template-generator';
import * as fs from 'fs/promises';
import * as path from 'path';

export abstract class CrystalBackendGenerator extends BackendTemplateGenerator {
  protected options: any;
  
  constructor() {
    super({
      language: 'Crystal',
      framework: 'Crystal Framework',
      packageManager: 'shards',
      buildTool: 'crystal',
      testFramework: 'crystal spec',
      features: [
        'High performance',
        'Type safety',
        'Compile-time checks',
        'JWT Authentication',
        'PostgreSQL Database',
        'Redis Cache',
        'Docker Support',
        'WebSocket support',
        'JSON API responses'
      ],
      dependencies: {},
      devDependencies: {},
      scripts: {
        dev: 'crystal run src/main.cr',
        build: 'crystal build src/main.cr --release',
        test: 'crystal spec',
        clean: 'rm -rf bin/',
        install: 'shards install'
      }
    });
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

  async generate(projectPath: string, options: any): Promise<void> {
    this.options = options;
    await super.generate(projectPath, options);
  }

  // Implement required abstract methods from BackendTemplateGenerator

  protected async generateLanguageFiles(projectPath: string, options: any): Promise<void> {
    // Generate shard.yml (Crystal dependency file)
    await fs.writeFile(
      path.join(projectPath, 'shard.yml'),
      this.generateShardsYml(options)
    );

    // Generate main application file
    await fs.writeFile(
      path.join(projectPath, 'src/main.cr'),
      this.generateMainFile()
    );

    // Generate development scripts
    await fs.mkdir(path.join(projectPath, 'scripts'), { recursive: true });
    await fs.writeFile(
      path.join(projectPath, 'scripts/dev.sh'),
      this.generateDevScript()
    );
    await fs.writeFile(
      path.join(projectPath, 'scripts/build.sh'),
      this.generateBuildScript()
    );

    // Make scripts executable
    await fs.chmod(path.join(projectPath, 'scripts/dev.sh'), 0o755);
    await fs.chmod(path.join(projectPath, 'scripts/build.sh'), 0o755);

    // Generate environment files
    await fs.writeFile(
      path.join(projectPath, '.env'),
      this.generateEnvFile(options)
    );
    await fs.writeFile(
      path.join(projectPath, '.env.example'),
      this.generateEnvExample(options)
    );
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Generate framework-specific files
    const serviceFiles = this.generateServiceFiles();
    const repositoryFiles = this.generateRepositoryFiles();
    const modelFiles = this.generateModelFiles();
    const configFiles = this.generateConfigFiles();
    const middlewareFiles = this.generateMiddlewareFiles();

    const allFiles = [...serviceFiles, ...repositoryFiles, ...modelFiles, ...configFiles, ...middlewareFiles];

    for (const file of allFiles) {
      const fullPath = path.join(projectPath, file.path);
      await fs.mkdir(path.dirname(fullPath), { recursive: true });
      await fs.writeFile(fullPath, file.content);
    }
  }

  protected async generateTestStructure(projectPath: string, options: any): Promise<void> {
    const testFiles = this.generateTestFiles();

    for (const file of testFiles) {
      const fullPath = path.join(projectPath, file.path);
      await fs.mkdir(path.dirname(fullPath), { recursive: true });
      await fs.writeFile(fullPath, file.content);
    }
  }

  protected async generateHealthCheck(projectPath: string): Promise<void> {
    // Health check is included in the main application file
    // No separate file needed for Crystal frameworks
  }

  protected async generateAPIDocs(projectPath: string): Promise<void> {
    const apiDocs = `# API Documentation

## Health Check
- \`GET /health\` - Returns service health status

## Authentication
- \`POST /api/auth/register\` - Register new user
- \`POST /api/auth/login\` - Login user
- \`POST /api/auth/refresh\` - Refresh JWT token
- \`GET /api/auth/me\` - Get current user (requires auth)

## Users
- \`GET /api/users\` - List users (requires auth)
- \`POST /api/users\` - Create user (requires admin)
- \`GET /api/users/:id\` - Get user by ID (requires auth)
- \`PUT /api/users/:id\` - Update user (requires auth)
- \`DELETE /api/users/:id\` - Delete user (requires admin)
`;

    await fs.writeFile(path.join(projectPath, 'docs/api.md'), apiDocs);
  }

  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    // Generate Dockerfile
    await fs.writeFile(
      path.join(projectPath, 'Dockerfile'),
      this.generateDockerfile()
    );

    // Generate docker-compose.yml
    await fs.writeFile(
      path.join(projectPath, 'docker-compose.yml'),
      this.generateDockerCompose(options)
    );
  }

  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    // README is generated by base class
    // Additional documentation
    const setupGuide = this.generateSetupGuide(options);
    await fs.writeFile(path.join(projectPath, 'docs/setup.md'), setupGuide);
  }

  protected getLanguageSpecificIgnorePatterns(): string[] {
    return [
      '# Crystal',
      '/bin/',
      '/lib/',
      '/.shards/',
      'shard.lock',
      '',
      '# Crystal development',
      '*.log',
      '.env.local',
    ];
  }

  protected getLanguagePrerequisites(): string {
    return `- Crystal 1.9.2+
- PostgreSQL 15+
- Redis 7+`;
  }

  protected getInstallCommand(): string {
    return 'shards install';
  }

  protected getDevCommand(): string {
    return 'crystal run src/main.cr';
  }

  protected getProdCommand(): string {
    return './bin/app';
  }

  protected getTestCommand(): string {
    return 'crystal spec';
  }

  protected getCoverageCommand(): string {
    return 'crystal spec --coverage';
  }

  protected getLintCommand(): string {
    return 'bin/ameba';
  }

  protected getBuildCommand(): string {
    return 'crystal build src/main.cr --release -o bin/app';
  }

  protected getSetupAction(): string {
    return `1. Install dependencies: \`shards install\`
2. Setup database: Configure DATABASE_URL in .env
3. Start development server: \`crystal run src/main.cr\``;
  }

  protected generateSetupGuide(options: any): string {
    return `# Setup Guide

## Prerequisites
${this.getLanguagePrerequisites()}

## Installation

1. Install Crystal dependencies:
   \`\`\`bash
   ${this.getInstallCommand()}
   \`\`\`

2. Setup environment:
   \`\`\`bash
   cp .env.example .env
   # Edit .env with your configuration
   \`\`\`

3. Setup database:
   \`\`\`bash
   createdb ${options.name || 'crystal-app'}_db
   \`\`\`

## Development

- Start development server: \`${this.getDevCommand()}\`
- Run tests: \`${this.getTestCommand()}\`
- Build for production: \`${this.getBuildCommand()}\`
- Lint code: \`${this.getLintCommand()}\`

## Docker

\`\`\`bash
docker-compose up
\`\`\`
`;
  }

  protected generateShardsYml(options: any): string {
    const frameworkDeps = this.getFrameworkDependencies();
    const deps = Object.entries(frameworkDeps)
      .map(([name, version]) => `  ${name}:\n    version: "${version}"`)
      .join('\n');

    return `name: ${options.name || 'crystal-app'}
version: 0.1.0
description: ${options.description || 'Crystal backend service'}

authors:
  - ${options.author || 'Developer <dev@example.com>'}

crystal: 1.9.2

dependencies:
${deps}

development_dependencies:
  spec:
    version: "~> 0.1.0"
  ameba:
    github: crystal-ameba/ameba
    version: ~> 1.5.0

targets:
  ${options.name || 'crystal-app'}:
    main: src/main.cr

license: MIT`;
  }

  protected generateDockerfile(): string {
    return `# Build stage
FROM crystallang/crystal:1.9.2-alpine as builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache \\
    build-base \\
    yaml-dev \\
    openssl-dev \\
    zlib-dev \\
    libxml2-dev \\
    sqlite-dev \\
    postgresql-dev

# Copy dependency files
COPY shard.yml shard.lock* ./
RUN shards install --production

# Copy source code
COPY src/ src/
COPY spec/ spec/

# Build the application
RUN crystal build src/main.cr --release --static -o bin/app

# Runtime stage
FROM alpine:3.18

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache \\
    openssl \\
    ca-certificates \\
    tzdata

# Copy the built application
COPY --from=builder /app/bin/app /usr/local/bin/app

# Create non-root user
RUN adduser -D -s /bin/sh crystal
USER crystal

EXPOSE 8080

CMD ["app"]`;
  }

  protected generateDockerCompose(options: any): string {
    const serviceName = options.name || 'crystal-app';
    const port = options.port || 8080;

    return `version: '3.8'

services:
  ${serviceName}:
    build: .
    ports:
      - "${port}:8080"
    environment:
      - CRYSTAL_ENV=development
      - DATABASE_URL=postgres://postgres:postgres@postgres:5432/${serviceName}_db
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis
    volumes:
      - .:/app
      - crystal_cache:/tmp/crystal

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: ${serviceName}_db
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./docker/postgres/init.sql:/docker-entrypoint-initdb.d/init.sql
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
  crystal_cache:`;
  }

  protected generateDevScript(): string {
    return `#!/bin/bash
set -e

echo "🔨 Installing dependencies..."
shards install

echo "🧪 Running tests..."
crystal spec

echo "🔍 Running linter..."
bin/ameba

echo "🚀 Starting development server..."
crystal run src/main.cr`;
  }

  protected generateBuildScript(): string {
    return `#!/bin/bash
set -e

echo "🔨 Installing dependencies..."
shards install --production

echo "🧪 Running tests..."
crystal spec

echo "🔍 Running linter..."
bin/ameba

echo "📦 Building release..."
crystal build src/main.cr --release -o bin/app

echo "✅ Build complete! Executable: bin/app"`;
  }

  protected generateEnvFile(options: any): string {
    const port = options.port || 8080;
    return `# Application
CRYSTAL_ENV=development
PORT=${port}
HOST=0.0.0.0

# Database
DATABASE_URL=postgres://postgres:postgres@localhost:5432/${options.name || 'crystal-app'}_db

# Redis
REDIS_URL=redis://localhost:6379

# Security
JWT_SECRET=your-jwt-secret-key
CORS_ORIGIN=*

# Logging
LOG_LEVEL=debug`;
  }

  protected generateEnvExample(options: any): string {
    const port = options.port || 8080;
    return `# Application
CRYSTAL_ENV=development
PORT=${port}
HOST=0.0.0.0

# Database
DATABASE_URL=postgres://user:password@localhost:5432/database_name

# Redis
REDIS_URL=redis://localhost:6379

# Security
JWT_SECRET=your-jwt-secret-key
CORS_ORIGIN=*

# Logging
LOG_LEVEL=debug`;
  }
}