import { BackendTemplateGenerator } from '../shared/backend-template-generator';
import * as fs from 'fs/promises';
import * as path from 'path';

export abstract class NimBackendGenerator extends BackendTemplateGenerator {
  protected options: any;
  
  constructor() {
    super({
      language: 'Nim',
      framework: 'Nim Framework',
      packageManager: 'nimble',
      buildTool: 'nim',
      testFramework: 'unittest',
      features: [
        'Compiled to C/C++/JS',
        'Python-like syntax',
        'Memory safe with GC',
        'Zero-cost abstractions',
        'Powerful macro system',
        'Async/await support',
        'Cross-platform',
        'Fast compilation',
        'Small binaries',
        'Docker support'
      ],
      dependencies: {},
      devDependencies: {},
      scripts: {
        'build': 'nim c -d:release src/main.nim',
        'dev': 'nim c -r src/main.nim',
        'test': 'nim c -r tests/test_all.nim',
        'clean': 'rm -rf nimcache bin',
        'format': 'nimpretty src/**/*.nim',
        'docs': 'nim doc --project src/main.nim'
      }
    });
  }

  protected abstract getFrameworkDependencies(): string[];
  protected abstract generateMainFile(): string;
  protected abstract generateRouterFile(): string;
  protected abstract generateMiddlewareFiles(): { path: string; content: string }[];
  protected abstract generateControllerFiles(): { path: string; content: string }[];
  protected abstract generateModelFiles(): { path: string; content: string }[];
  protected abstract generateViewFiles(): { path: string; content: string }[];
  protected abstract generateConfigFile(): string;
  protected abstract generateTestFiles(): { path: string; content: string }[];

  async generate(projectPath: string, options: any): Promise<void> {
    this.options = options;
    await super.generate(projectPath, options);
  }

  protected async generateLanguageFiles(projectPath: string, options: any): Promise<void> {
    // Generate .nimble file (Nim package file)
    await fs.writeFile(
      path.join(projectPath, `${options.name}.nimble`),
      this.generateNimbleFile(options)
    );

    // Generate nim.cfg
    await fs.writeFile(
      path.join(projectPath, 'nim.cfg'),
      this.generateNimConfig()
    );

    // Generate .gitignore
    await this.generateGitignore(projectPath);

    // Create directory structure
    await fs.mkdir(path.join(projectPath, 'src'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'src', 'controllers'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'src', 'models'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'src', 'views'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'src', 'middleware'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'src', 'utils'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'tests'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'bin'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'config'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'public'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'public', 'css'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'public', 'js'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'public', 'images'), { recursive: true });

    // Generate main.nim
    await fs.writeFile(
      path.join(projectPath, 'src', 'main.nim'),
      this.generateMainFile()
    );

    // Generate router
    await fs.writeFile(
      path.join(projectPath, 'src', 'router.nim'),
      this.generateRouterFile()
    );

    // Generate config
    await fs.writeFile(
      path.join(projectPath, 'src', 'config.nim'),
      this.generateConfigFile()
    );

    // Generate middleware files
    const middlewareFiles = this.generateMiddlewareFiles();
    for (const file of middlewareFiles) {
      await fs.writeFile(path.join(projectPath, file.path), file.content);
    }

    // Generate controller files
    const controllerFiles = this.generateControllerFiles();
    for (const file of controllerFiles) {
      await fs.writeFile(path.join(projectPath, file.path), file.content);
    }

    // Generate model files
    const modelFiles = this.generateModelFiles();
    for (const file of modelFiles) {
      await fs.writeFile(path.join(projectPath, file.path), file.content);
    }

    // Generate view files
    const viewFiles = this.generateViewFiles();
    for (const file of viewFiles) {
      await fs.writeFile(path.join(projectPath, file.path), file.content);
    }

    // Generate test files
    const testFiles = this.generateTestFiles();
    for (const file of testFiles) {
      await fs.writeFile(path.join(projectPath, file.path), file.content);
    }

    // Generate utility files
    await fs.writeFile(
      path.join(projectPath, 'src', 'utils', 'helpers.nim'),
      this.generateHelpers()
    );

    await fs.writeFile(
      path.join(projectPath, 'src', 'utils', 'validators.nim'),
      this.generateValidators()
    );

    // Generate test runner
    await fs.writeFile(
      path.join(projectPath, 'tests', 'test_all.nim'),
      this.generateTestRunner()
    );

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
This is a Nim-based web service using modern web framework patterns.

## Base URL
\`\`\`
http://localhost:${this.options?.port || 5000}
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

  protected generateNimbleFile(options: any): string {
    const deps = this.getFrameworkDependencies();
    const depsString = deps.map(dep => `requires "${dep}"`).join('\n');

    return `# Package

version       = "0.1.0"
author        = "${options.author || 'Anonymous'}"
description   = "${options.description || 'A web service built with Nim'}"
license       = "MIT"
srcDir        = "src"
bin           = @["main"]
binDir        = "bin"

# Dependencies

requires "nim >= 2.0.0"
${depsString}

# Tasks

task test, "Run tests":
  exec "nim c -r tests/test_all.nim"

task build, "Build the project":
  exec "nim c -d:release -o:bin/server src/main.nim"

task dev, "Run in development mode":
  exec "nim c -r src/main.nim"

task docs, "Generate documentation":
  exec "nim doc --project --index:on --git.url:https://github.com/user/repo --git.commit:master -o:docs src/main.nim"

task clean, "Clean build artifacts":
  exec "rm -rf nimcache bin"
`;
  }

  protected generateNimConfig(): string {
    return `# Nim configuration

--threads:on
--opt:speed
--stackTrace:on
--lineTrace:on
--debugger:native
--warnings:on
--hints:on
--path:"src"

# Release mode optimizations
@if release:
  --opt:size
  --passC:"-flto"
  --passL:"-flto"
  --panics:on
@end

# Development mode
@if debug:
  --debuginfo:on
  --linedir:on
@end
`;
  }

  protected async generateGitignore(projectPath: string): Promise<void> {
    const gitignoreContent = `# Nim
nimcache/
nimblecache/
htmldocs/
bin/
*.exe

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
nimble.lock
`;
    
    await fs.writeFile(path.join(projectPath, '.gitignore'), gitignoreContent);
  }

  protected generateHelpers(): string {
    return `# Utility helper functions

import std/[times, strutils, json, tables, options]
import std/[httpcore, cookies]

proc generateUUID*(): string =
  ## Generate a simple UUID v4
  import std/[random, strformat]
  randomize()
  result = fmt"{rand(0xFFFFFFFF):08x}-{rand(0xFFFF):04x}-4{rand(0xFFF):03x}-{rand(0x3FFF) or 0x8000:04x}-{rand(0xFFFFFFFFFFFF):012x}"

proc hashPassword*(password: string): string =
  ## Hash password using SHA256
  import std/sha256
  result = $secureHash(password)

proc verifyPassword*(password, hash: string): bool =
  ## Verify password against hash
  import std/sha256
  result = $secureHash(password) == hash

proc parseJWT*(token: string): Option[JsonNode] =
  ## Parse JWT token (simplified - use proper JWT library in production)
  let parts = token.split('.')
  if parts.len != 3:
    return none(JsonNode)
  
  try:
    let payload = parts[1]
    # Add padding if needed
    let padded = payload & "=".repeat((4 - payload.len mod 4) mod 4)
    let decoded = decode(padded)
    result = some(parseJson(decoded))
  except:
    result = none(JsonNode)

proc generateJWT*(payload: JsonNode, secret: string): string =
  ## Generate JWT token (simplified - use proper JWT library in production)
  import std/[base64, hmac, sha256]
  
  let header = %*{"alg": "HS256", "typ": "JWT"}
  let headerEncoded = encode($header, safe = true).strip(chars = {'='})
  let payloadEncoded = encode($payload, safe = true).strip(chars = {'='})
  
  let message = headerEncoded & "." & payloadEncoded
  let signature = encode($hmac_sha256(secret, message), safe = true).strip(chars = {'='})
  
  result = message & "." & signature

proc getCurrentTimestamp*(): int64 =
  ## Get current Unix timestamp
  toUnix(getTime())

proc formatTimestamp*(timestamp: int64): string =
  ## Format Unix timestamp to string
  format(fromUnix(timestamp), "yyyy-MM-dd HH:mm:ss")

proc sanitizeInput*(input: string): string =
  ## Sanitize user input
  result = input.strip()
  result = result.replace("<", "&lt;")
  result = result.replace(">", "&gt;")
  result = result.replace("\"", "&quot;")
  result = result.replace("'", "&#x27;")
  result = result.replace("/", "&#x2F;")

proc paginate*[T](items: seq[T], page, pageSize: int): tuple[items: seq[T], totalPages: int] =
  ## Paginate a sequence
  let totalItems = items.len
  let totalPages = (totalItems + pageSize - 1) div pageSize
  let startIdx = (page - 1) * pageSize
  let endIdx = min(startIdx + pageSize, totalItems)
  
  if startIdx >= totalItems:
    result = (items: @[], totalPages: totalPages)
  else:
    result = (items: items[startIdx..<endIdx], totalPages: totalPages)

proc setCookie*(name, value: string, maxAge = 3600): string =
  ## Create cookie header
  result = fmt"{name}={value}; Max-Age={maxAge}; Path=/; HttpOnly; SameSite=Strict"
  
proc getCookie*(cookies: string, name: string): Option[string] =
  ## Extract cookie value
  for cookie in cookies.split("; "):
    let parts = cookie.split("=", 1)
    if parts.len == 2 and parts[0] == name:
      return some(parts[1])
  return none(string)
`;
  }

  protected generateValidators(): string {
    return `# Input validation functions

import std/[strutils, re, options]

type
  ValidationError* = object
    field*: string
    message*: string

proc validateEmail*(email: string): Option[ValidationError] =
  ## Validate email format
  if email.len == 0:
    return some(ValidationError(field: "email", message: "Email is required"))
  
  let emailRegex = re(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
  if not email.match(emailRegex):
    return some(ValidationError(field: "email", message: "Invalid email format"))
  
  return none(ValidationError)

proc validatePassword*(password: string): Option[ValidationError] =
  ## Validate password strength
  if password.len < 8:
    return some(ValidationError(field: "password", message: "Password must be at least 8 characters"))
  
  if not password.contains(re"[A-Z]"):
    return some(ValidationError(field: "password", message: "Password must contain at least one uppercase letter"))
  
  if not password.contains(re"[a-z]"):
    return some(ValidationError(field: "password", message: "Password must contain at least one lowercase letter"))
  
  if not password.contains(re"[0-9]"):
    return some(ValidationError(field: "password", message: "Password must contain at least one number"))
  
  return none(ValidationError)

proc validateUsername*(username: string): Option[ValidationError] =
  ## Validate username
  if username.len < 3:
    return some(ValidationError(field: "username", message: "Username must be at least 3 characters"))
  
  if username.len > 20:
    return some(ValidationError(field: "username", message: "Username must not exceed 20 characters"))
  
  let usernameRegex = re"^[a-zA-Z0-9_]+$"
  if not username.match(usernameRegex):
    return some(ValidationError(field: "username", message: "Username can only contain letters, numbers, and underscores"))
  
  return none(ValidationError)

proc validateRequired*(value: string, field: string): Option[ValidationError] =
  ## Validate required field
  if value.strip().len == 0:
    return some(ValidationError(field: field, message: fmt"{field} is required"))
  
  return none(ValidationError)

proc validateLength*(value: string, field: string, minLen = 0, maxLen = int.high): Option[ValidationError] =
  ## Validate string length
  let length = value.len
  
  if length < minLen:
    return some(ValidationError(field: field, message: fmt"{field} must be at least {minLen} characters"))
  
  if length > maxLen:
    return some(ValidationError(field: field, message: fmt"{field} must not exceed {maxLen} characters"))
  
  return none(ValidationError)

proc validateInteger*(value: string, field: string, minVal = int.low, maxVal = int.high): Option[ValidationError] =
  ## Validate integer value
  try:
    let intVal = parseInt(value)
    if intVal < minVal:
      return some(ValidationError(field: field, message: fmt"{field} must be at least {minVal}"))
    
    if intVal > maxVal:
      return some(ValidationError(field: field, message: fmt"{field} must not exceed {maxVal}"))
    
    return none(ValidationError)
  except ValueError:
    return some(ValidationError(field: field, message: fmt"{field} must be a valid integer"))

proc validateFloat*(value: string, field: string, minVal = float.low, maxVal = float.high): Option[ValidationError] =
  ## Validate float value
  try:
    let floatVal = parseFloat(value)
    if floatVal < minVal:
      return some(ValidationError(field: field, message: fmt"{field} must be at least {minVal}"))
    
    if floatVal > maxVal:
      return some(ValidationError(field: field, message: fmt"{field} must not exceed {maxVal}"))
    
    return none(ValidationError)
  except ValueError:
    return some(ValidationError(field: field, message: fmt"{field} must be a valid number"))

proc validateURL*(url: string): Option[ValidationError] =
  ## Validate URL format
  if url.len == 0:
    return some(ValidationError(field: "url", message: "URL is required"))
  
  let urlRegex = re"^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$"
  if not url.match(urlRegex):
    return some(ValidationError(field: "url", message: "Invalid URL format"))
  
  return none(ValidationError)

proc validateDate*(date: string, format = "yyyy-MM-dd"): Option[ValidationError] =
  ## Validate date format
  import std/times
  
  try:
    discard parse(date, format)
    return none(ValidationError)
  except TimeParseError:
    return some(ValidationError(field: "date", message: fmt"Invalid date format, expected {format}"))
`;
  }

  protected generateTestRunner(): string {
    return `# Test runner - runs all tests

import unittest
import std/[os, strutils]

# Import all test modules
import test_helpers
import test_validators
import test_controllers
import test_models
import test_middleware

# Run all tests
when isMainModule:
  echo "Running all tests..."
  
  # Set test environment
  putEnv("APP_ENV", "test")
  
  # Run tests
  runTests()
  
  echo "All tests completed!"
`;
  }

  protected generateMakefile(options: any): string {
    const appName = options.name || 'app';

    return `.PHONY: build dev test clean docs install run

# Variables
NIM = nim
NIMBLE = nimble
SRC_DIR = src
BIN_DIR = bin
TEST_DIR = tests
MAIN = $(SRC_DIR)/main.nim
BINARY = $(BIN_DIR)/${appName}

# Default target
all: build

# Install dependencies
install:
\t$(NIMBLE) install -y

# Build for production
build:
\t@echo "Building production binary..."
\t@mkdir -p $(BIN_DIR)
\t$(NIM) c -d:release -d:ssl --opt:size -o:$(BINARY) $(MAIN)
\t@echo "Build complete: $(BINARY)"

# Build for development
dev:
\t@echo "Running in development mode..."
\t$(NIM) c -r -d:ssl $(MAIN)

# Run tests
test:
\t@echo "Running tests..."
\t$(NIM) c -r $(TEST_DIR)/test_all.nim

# Clean build artifacts
clean:
\t@echo "Cleaning build artifacts..."
\t@rm -rf nimcache nimblecache $(BIN_DIR)
\t@echo "Clean complete"

# Generate documentation
docs:
\t@echo "Generating documentation..."
\t@mkdir -p docs
\t$(NIM) doc --project --index:on -o:docs $(MAIN)
\t@echo "Documentation generated in docs/"

# Format code
format:
\tnimpretty $(SRC_DIR)/**/*.nim $(TEST_DIR)/**/*.nim

# Run the server
run: build
\t@echo "Starting server..."
\t@$(BINARY)

# Development with auto-reload (requires watchexec)
watch:
\t@echo "Starting development server with auto-reload..."
\twatchexec -r -e nim -- make dev

# Docker build
docker-build:
\t@echo "Building Docker image..."
\tdocker build -t ${appName} .

# Docker run
docker-run:
\tdocker run -p ${options.port || 5000}:${options.port || 5000} ${appName}
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
    // Docker files are generated in the framework-specific generators
    // This is handled by JesterGenerator.generateDockerfile() and PrologueGenerator.generateDockerfile()
  }

  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    const readme = `# ${options.name || 'Nim Backend Service'}

${options.description || 'A backend service built with Nim'}

## Tech Stack
- **Language**: Nim ${this.options?.framework === 'Jester' ? '2.0+' : '1.6+'}
- **Framework**: ${this.options?.framework || 'Nim Framework'}
- **Database**: SQLite (with Norm ORM)
- **Cache**: Redis
- **Authentication**: JWT

## Prerequisites
- Nim ${this.options?.framework === 'Jester' ? '2.0+' : '1.6+'} 
- Nimble package manager
- SQLite
- Redis (optional, for caching)

## Getting Started

### Installation
\`\`\`bash
# Install dependencies
nimble install

# Copy environment variables
cp .env.example .env
\`\`\`

### Development
\`\`\`bash
# Run in development mode
nim c -r src/main.nim

# Or use nimble
nimble run

# Or use make
make dev
\`\`\`

### Testing
\`\`\`bash
# Run all tests
nimble test

# Or use nim directly
nim c -r tests/test_all.nim

# Or use make
make test
\`\`\`

### Building for Production
\`\`\`bash
# Build optimized binary
nim c -d:release -d:ssl --opt:size -o:server src/main.nim

# Or use make
make build
\`\`\`

## Project Structure
\`\`\`
${options.name}/
├── src/
│   ├── main.nim          # Application entry point
│   ├── config.nim        # Configuration management
│   ├── router.nim        # Route definitions
│   ├── controllers/      # Request handlers
│   ├── models/           # Data models
│   ├── middleware/       # Middleware functions
│   ├── utils/            # Utility functions
│   └── views/            # View templates (if applicable)
├── tests/                # Test files
├── public/               # Static files
├── docs/                 # Documentation
├── Dockerfile            # Docker configuration
├── docker-compose.yml    # Docker Compose setup
├── Makefile              # Build automation
├── project.nimble        # Nimble configuration
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
docker run -p ${options.port || 5000}:${options.port || 5000} ${options.name}

# Use Docker Compose
docker-compose up
\`\`\`

## License
MIT
`;

    await fs.writeFile(path.join(projectPath, 'README.md'), readme);
  }

  protected getLanguageSpecificIgnorePatterns(): string[] {
    return [
      'nimcache/',
      'nimblecache/',
      '*.exe',
      '*.dll',
      '*.so',
      '*.dylib',
      'bin/',
      'htmldocs/'
    ];
  }

  protected getLanguagePrerequisites(): string {
    return 'Nim 1.6+ and Nimble package manager';
  }

  protected getInstallCommand(): string {
    return 'nimble install';
  }

  protected getDevCommand(): string {
    return 'nim c -r src/main.nim';
  }

  protected getProdCommand(): string {
    return './server';
  }

  protected getTestCommand(): string {
    return 'nimble test';
  }

  protected getCoverageCommand(): string {
    return 'nim c -r --debugger:native --passC:--coverage tests/test_all.nim';
  }

  protected getLintCommand(): string {
    return 'nim check src/main.nim';
  }

  protected getBuildCommand(): string {
    return 'nim c -d:release -d:ssl --opt:size -o:server src/main.nim';
  }

  protected getSetupAction(): string {
    return 'nimble install -y';
  }
}