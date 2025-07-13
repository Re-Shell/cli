/**
 * Zig Backend Template Base Generator
 * Shared functionality for all Zig web frameworks
 */

import { BackendTemplateGenerator, BackendTemplateConfig } from '../shared/backend-template-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export abstract class ZigBackendGenerator extends BackendTemplateGenerator {
  constructor(framework: string) {
    const config: BackendTemplateConfig = {
      language: 'Zig',
      framework,
      packageManager: 'zig',
      buildTool: 'zig build',
      testFramework: 'zig test',
      features: [
        'Manual memory management',
        'Compile-time code execution',
        'No hidden control flow',
        'Error handling built-in',
        'C interoperability',
        'Cross-compilation',
        'Small binaries',
        'Fast compilation',
        'No runtime overhead',
        'Built-in testing'
      ],
      dependencies: {},
      devDependencies: {},
      scripts: {
        'build': 'zig build',
        'build:release': 'zig build -Doptimize=ReleaseFast',
        'build:safe': 'zig build -Doptimize=ReleaseSafe',
        'build:small': 'zig build -Doptimize=ReleaseSmall',
        'run': 'zig build run',
        'test': 'zig build test',
        'fmt': 'zig fmt .',
        'clean': 'rm -rf zig-cache zig-out',
        'check': 'zig build check'
      },
      dockerConfig: {
        baseImage: 'alpine:3.19',
        workDir: '/app',
        exposedPorts: [8080],
        buildSteps: [
          'RUN apk add --no-cache zig',
          'COPY . .',
          'RUN zig build -Doptimize=ReleaseSafe'
        ],
        runCommand: './zig-out/bin/app',
        multistage: true
      },
      envVars: {
        'PORT': '8080',
        'HOST': '0.0.0.0',
        'LOG_LEVEL': 'info',
        'DATABASE_URL': 'sqlite://./data/app.db',
        'JWT_SECRET': 'your-secret-key',
        'CORS_ORIGIN': '*'
      }
    };
    super(config);
  }

  protected async generateLanguageFiles(projectPath: string, options: any): Promise<void> {
    // Generate build.zig
    await this.generateBuildZig(projectPath, options);

    // Generate build.zig.zon
    await this.generateBuildZon(projectPath, options);

    // Generate .gitignore
    await this.generateZigGitignore(projectPath);

    // Generate VS Code settings
    await this.generateVSCodeSettings(projectPath);

    // Create directory structure
    const directories = [
      'src',
      'src/handlers',
      'src/middleware',
      'src/models',
      'src/utils',
      'src/config',
      'test',
      'test/unit',
      'test/integration',
      'scripts',
      'data'
    ];

    for (const dir of directories) {
      await fs.mkdir(path.join(projectPath, dir), { recursive: true });
    }
  }

  private async generateBuildZig(projectPath: string, options: any): Promise<void> {
    const buildZigContent = `const std = @import("std");

pub fn build(b: *std.Build) void {
    // Standard target options allows the person running 'zig build' to choose
    // what target to build for
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running 'zig build' to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall
    const optimize = b.standardOptimizeOption(.{});

    // Create the executable
    const exe = b.addExecutable(.{
        .name = "${options.name}",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    // Add dependencies
    // const deps = @import("deps.zig");
    // deps.addAllTo(exe);

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step
    b.installArtifact(exe);

    // Create a run step
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    // Allow the user to pass arguments to the application
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // Create a step for running the app
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Create the test executable
    const unit_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);

    // Create a step for running tests
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // Create a check step for type checking
    const check = b.addExecutable(.{
        .name = "check",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    
    const check_step = b.step("check", "Check if code compiles");
    check_step.dependOn(&check.step);
}
`;

    await fs.writeFile(
      path.join(projectPath, 'build.zig'),
      buildZigContent
    );
  }

  private async generateBuildZon(projectPath: string, options: any): Promise<void> {
    const buildZonContent = `.{
    .name = "${options.name}",
    .version = "0.1.0",

    .dependencies = .{
        // Add dependencies here
        // Example:
        // .zap = .{
        //     .url = "https://github.com/zigzap/zap/archive/refs/tags/v0.1.0.tar.gz",
        //     .hash = "...",
        // },
    },

    .paths = .{
        "build.zig",
        "build.zig.zon",
        "src",
        "LICENSE",
        "README.md",
    },
}
`;

    await fs.writeFile(
      path.join(projectPath, 'build.zig.zon'),
      buildZonContent
    );
  }

  private async generateZigGitignore(projectPath: string): Promise<void> {
    const gitignoreContent = `# Zig
zig-cache/
zig-out/
build/
build-*/

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

# Database
data/*.db
data/*.db-journal
data/*.db-wal
*.sqlite

# Test coverage
coverage/
*.lcov

# Temporary files
tmp/
temp/
.tmp/

# Debug
core
vgcore.*
*.pdb
`;

    await fs.writeFile(
      path.join(projectPath, '.gitignore'),
      gitignoreContent
    );
  }

  private async generateVSCodeSettings(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, '.vscode'), { recursive: true });

    const settings = {
      "files.associations": {
        "*.zig": "zig",
        "*.zon": "zig"
      },
      "editor.formatOnSave": true,
      "[zig]": {
        "editor.defaultFormatter": "ziglang.vscode-zig"
      },
      "zig.buildOnSave": true,
      "zig.checkOnSave": true,
      "zig.formattingProvider": "on",
      "files.exclude": {
        "**/zig-cache": true,
        "**/zig-out": true
      }
    };

    await fs.writeFile(
      path.join(projectPath, '.vscode', 'settings.json'),
      JSON.stringify(settings, null, 2)
    );

    const extensions = {
      recommendations: [
        "ziglang.vscode-zig",
        "vadimcn.vscode-lldb"
      ]
    };

    await fs.writeFile(
      path.join(projectPath, '.vscode', 'extensions.json'),
      JSON.stringify(extensions, null, 2)
    );
  }

  protected async generateCommonFiles(projectPath: string, options: any): Promise<void> {
    await super.generateCommonFiles(projectPath, options);

    // Generate Zig-specific common files
    await this.generateMakefile(projectPath);
    await this.generateDevContainer(projectPath);
  }

  private async generateMakefile(projectPath: string): Promise<void> {
    const makefileContent = `.PHONY: build run test fmt clean help install docker-build docker-run

# Default target
.DEFAULT_GOAL := help

# Help command
help:
	@echo "Available commands:"
	@echo "  make build         - Build the application"
	@echo "  make build-release - Build optimized release version"
	@echo "  make run          - Run the application"
	@echo "  make test         - Run tests"
	@echo "  make fmt          - Format code"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make check        - Type check code"
	@echo "  make docker-build - Build Docker image"
	@echo "  make docker-run   - Run Docker container"

build:
	zig build

build-release:
	zig build -Doptimize=ReleaseFast

build-safe:
	zig build -Doptimize=ReleaseSafe

build-small:
	zig build -Doptimize=ReleaseSmall

run:
	zig build run

test:
	zig build test

fmt:
	zig fmt .

clean:
	rm -rf zig-cache zig-out

check:
	zig build check

install:
	zig build install

docker-build:
	docker build -t ${this.config.framework.toLowerCase()}-app .

docker-run:
	docker run -p 8080:8080 ${this.config.framework.toLowerCase()}-app
`;

    await fs.writeFile(
      path.join(projectPath, 'Makefile'),
      makefileContent
    );
  }

  private async generateDevContainer(projectPath: string): Promise<void> {
    await fs.mkdir(path.join(projectPath, '.devcontainer'), { recursive: true });

    const devContainerConfig = {
      name: `${this.config.framework} Zig Development`,
      image: "mcr.microsoft.com/devcontainers/base:ubuntu",
      features: {
        "ghcr.io/devcontainers-contrib/features/zig:1": {
          "version": "latest"
        }
      },
      customizations: {
        vscode: {
          extensions: [
            "ziglang.vscode-zig",
            "vadimcn.vscode-lldb"
          ]
        }
      },
      postCreateCommand: "zig version",
      forwardPorts: [8080],
      remoteUser: "vscode"
    };

    await fs.writeFile(
      path.join(projectPath, '.devcontainer', 'devcontainer.json'),
      JSON.stringify(devContainerConfig, null, 2)
    );
  }

  protected async generateTestStructure(projectPath: string, options: any): Promise<void> {
    // Generate test utilities
    const testUtilsContent = `const std = @import("std");
const testing = std.testing;

pub fn expectEqual(expected: anytype, actual: anytype) !void {
    try testing.expectEqual(expected, actual);
}

pub fn expectEqualStrings(expected: []const u8, actual: []const u8) !void {
    try testing.expectEqualStrings(expected, actual);
}

pub fn expectError(expected_error: anyerror, actual: anytype) !void {
    try testing.expectError(expected_error, actual);
}

pub fn createTestAllocator() std.mem.Allocator {
    return std.testing.allocator;
}

pub fn createTestUser() User {
    return User{
        .id = "test-id",
        .email = "test@example.com",
        .name = "Test User",
        .role = "user",
    };
}

const User = struct {
    id: []const u8,
    email: []const u8,
    name: []const u8,
    role: []const u8,
};
`;

    await fs.writeFile(
      path.join(projectPath, 'test', 'test_utils.zig'),
      testUtilsContent
    );

    // Generate example test
    const exampleTestContent = `const std = @import("std");
const testing = std.testing;
const test_utils = @import("test_utils.zig");

test "example test" {
    try test_utils.expectEqual(2, 1 + 1);
}

test "string test" {
    const expected = "Hello, Zig!";
    const actual = "Hello, Zig!";
    try test_utils.expectEqualStrings(expected, actual);
}

test "allocator test" {
    const allocator = test_utils.createTestAllocator();
    const data = try allocator.alloc(u8, 100);
    defer allocator.free(data);
    
    try testing.expect(data.len == 100);
}

test "user creation" {
    const user = test_utils.createTestUser();
    try test_utils.expectEqualStrings("test@example.com", user.email);
}
`;

    await fs.writeFile(
      path.join(projectPath, 'test', 'example_test.zig'),
      exampleTestContent
    );
  }

  protected async generateHealthCheck(projectPath: string): Promise<void> {
    const healthCheckContent = `const std = @import("std");
const http = std.http;
const json = std.json;

pub fn handleHealth(allocator: std.mem.Allocator, request: *http.Server.Request) !void {
    const health_status = .{
        .status = "healthy",
        .timestamp = std.time.timestamp(),
        .version = "1.0.0",
        .service = "${this.config.framework.toLowerCase()}-service",
    };

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try json.stringify(health_status, .{}, buffer.writer());

    try request.respond(buffer.items, .{
        .status = .ok,
        .headers = &[_]http.Header{
            .{ .name = "content-type", .value = "application/json" },
        },
    });
}

pub fn handleReady(allocator: std.mem.Allocator, request: *http.Server.Request) !void {
    // Check database connection and other dependencies
    const ready = checkDependencies();
    
    const ready_status = if (ready) .{
        .status = "ready",
        .checks = .{
            .database = "ok",
            .cache = "ok",
        },
    } else .{
        .status = "not ready",
        .checks = .{
            .database = "error",
            .cache = "ok",
        },
    };

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try json.stringify(ready_status, .{}, buffer.writer());

    try request.respond(buffer.items, .{
        .status = if (ready) .ok else .service_unavailable,
        .headers = &[_]http.Header{
            .{ .name = "content-type", .value = "application/json" },
        },
    });
}

fn checkDependencies() bool {
    // TODO: Implement actual health checks
    return true;
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'handlers', 'health.zig'),
      healthCheckContent
    );
  }

  protected async generateAPIDocs(projectPath: string): Promise<void> {
    const apiDocsContent = `# API Documentation

## Overview

This is a RESTful API built with ${this.config.framework} on Zig.

## Base URL

\`\`\`
http://localhost:8080/api/v1
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
  "timestamp": 1234567890,
  "version": "1.0.0",
  "service": "${this.config.framework.toLowerCase()}-service"
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

## Performance

Zig provides exceptional performance:
- Zero-cost abstractions
- Manual memory management
- Compile-time optimizations
- Small binary size
- Low memory footprint
`;

    await fs.writeFile(
      path.join(projectPath, 'docs', 'API.md'),
      apiDocsContent
    );
  }

  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    const dockerContent = `# Multi-stage Dockerfile for Zig ${this.config.framework} application

# Build stage
FROM alpine:3.19 AS builder

# Install Zig
RUN apk add --no-cache zig

WORKDIR /app

# Copy source code
COPY . .

# Build the application
RUN zig build -Doptimize=ReleaseSafe

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    && addgroup -g 1001 appuser \
    && adduser -u 1001 -G appuser -s /bin/sh -D appuser

WORKDIR /app

# Copy the binary from builder
COPY --from=builder --chown=appuser:appuser /app/zig-out/bin/${options.name} .

# Create data directory
RUN mkdir -p /app/data && chown -R appuser:appuser /app/data

# Switch to non-root user
USER appuser

# Expose port
EXPOSE ${options.port || 8080}

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:${options.port || 8080}/health || exit 1

# Run the application
CMD ["./${options.name}"]
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
      - "\${PORT:-8080}:8080"
    environment:
      - PORT=8080
      - HOST=0.0.0.0
      - LOG_LEVEL=info
      - DATABASE_URL=sqlite:///app/data/app.db
      - JWT_SECRET=\${JWT_SECRET}
    volumes:
      - app-data:/app/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/health"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 5s

volumes:
  app-data:
`;

    await fs.writeFile(
      path.join(projectPath, 'docker-compose.yml'),
      dockerComposeContent
    );

    // .dockerignore
    const dockerignoreContent = `zig-cache/
zig-out/
.git/
.gitignore
.env
.env.*
*.log
.DS_Store
.vscode/
.idea/
README.md
docs/
test/
.devcontainer/
Makefile
`;

    await fs.writeFile(
      path.join(projectPath, '.dockerignore'),
      dockerignoreContent
    );
  }

  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    const readmeContent = `# ${options.name}

A ${this.config.framework} web application built with Zig.

## 🚀 Features

- ⚡ Blazing fast performance
- 🔒 Memory safe without garbage collection
- 📦 Small binary size
- 🧪 Built-in testing framework
- 🔧 C interoperability
- 🎯 Compile-time code execution
- 🐳 Docker support
- 🌐 Production ready

## 📋 Prerequisites

- Zig 0.11.0 or higher

## 🛠️ Installation

1. Clone the repository:
\`\`\`bash
git clone <repository-url>
cd ${options.name}
\`\`\`

2. Install Zig (if not already installed):
\`\`\`bash
# macOS (using Homebrew)
brew install zig

# Linux
wget https://ziglang.org/download/0.11.0/zig-linux-x86_64-0.11.0.tar.xz
tar -xf zig-linux-x86_64-0.11.0.tar.xz
export PATH=$PATH:$(pwd)/zig-linux-x86_64-0.11.0

# Windows
# Download from https://ziglang.org/download/
\`\`\`

3. Build the project:
\`\`\`bash
zig build
\`\`\`

## 🏃 Running the Application

### Development

\`\`\`bash
zig build run
# or
make run
\`\`\`

The application will start at http://localhost:${options.port || 8080}

### Production

\`\`\`bash
zig build -Doptimize=ReleaseFast
./zig-out/bin/${options.name}
\`\`\`

### Docker

\`\`\`bash
# Build and run with Docker Compose
docker-compose up

# Or build and run manually
docker build -t ${options.name} .
docker run -p ${options.port || 8080}:${options.port || 8080} ${options.name}
\`\`\`

## 🧪 Testing

\`\`\`bash
# Run all tests
zig build test

# Run specific test file
zig test test/example_test.zig
\`\`\`

## 📝 Available Commands

- \`zig build\` - Build the application
- \`zig build run\` - Build and run the application
- \`zig build test\` - Run tests
- \`zig fmt .\` - Format code
- \`zig build -Doptimize=ReleaseFast\` - Build optimized version
- \`zig build check\` - Type check without building

## 🚀 Deployment

### Binary Deployment

\`\`\`bash
# Build for production
zig build -Doptimize=ReleaseFast

# Copy binary to server
scp zig-out/bin/${options.name} user@server:/path/to/app/
\`\`\`

### Docker Deployment

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
├── build.zig          # Build configuration
├── build.zig.zon      # Package manifest
├── src/               # Source code
│   ├── main.zig      # Application entry point
│   ├── handlers/     # Request handlers
│   ├── middleware/   # Middleware functions
│   ├── models/       # Data models
│   ├── utils/        # Utility functions
│   └── config/       # Configuration
├── test/             # Test files
├── data/             # Database files
└── docs/             # Documentation
\`\`\`

## 🔧 Configuration

The application uses environment variables for configuration. See \`.env.example\` for available options.

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (\`git checkout -b feature/amazing-feature\`)
3. Run tests (\`zig build test\`)
4. Format code (\`zig fmt .\`)
5. Commit your changes (\`git commit -m 'Add amazing feature'\`)
6. Push to the branch (\`git push origin feature/amazing-feature\`)
7. Open a Pull Request

## 📝 License

This project is licensed under the MIT License.

---

Built with ❤️ using [Zig](https://ziglang.org) and [${this.config.framework}](https://github.com/${this.config.framework.toLowerCase()})
`;

    await fs.writeFile(
      path.join(projectPath, 'README.md'),
      readmeContent
    );
  }

  protected getLanguageSpecificIgnorePatterns(): string[] {
    return [
      'zig-cache/',
      'zig-out/',
      'build/',
      'build-*/',
      '*.pdb',
      'core',
      'vgcore.*'
    ];
  }

  protected getLanguagePrerequisites(): string {
    return 'Zig 0.11.0+';
  }

  protected getInstallCommand(): string {
    return 'zig build';
  }

  protected getDevCommand(): string {
    return 'zig build run';
  }

  protected getProdCommand(): string {
    return './zig-out/bin/app';
  }

  protected getTestCommand(): string {
    return 'zig build test';
  }

  protected getCoverageCommand(): string {
    return 'zig build test --summary all';
  }

  protected getLintCommand(): string {
    return 'zig fmt --check .';
  }

  protected getBuildCommand(): string {
    return 'zig build -Doptimize=ReleaseFast';
  }

  protected getSetupAction(): string {
    return 'goto-bus-stop/setup-zig@v2';
  }

  protected async generateBuildScript(projectPath: string, options: any): Promise<void> {
    const buildScriptContent = `#!/bin/sh
# Build script for ${this.config.framework} application

echo "🔨 Building ${this.config.framework} application..."

# Clean previous builds
rm -rf zig-cache zig-out

# Format code
echo "📝 Formatting code..."
zig fmt .

# Run tests
echo "🧪 Running tests..."
zig build test || exit 1

# Build release version
echo "📦 Building release version..."
zig build -Doptimize=ReleaseSafe || exit 1

echo "✅ Build complete!"
echo "Binary location: ./zig-out/bin/${options.name}"
`;

    await fs.writeFile(
      path.join(projectPath, 'scripts', 'build.sh'),
      buildScriptContent
    );

    await fs.chmod(path.join(projectPath, 'scripts', 'build.sh'), 0o755);
  }
}