/**
 * ReScript Base Backend Generator
 * Base class for all ReScript backend framework generators
 */

import { BackendTemplateGenerator } from '../shared/backend-template-generator';
import type { FileTemplate } from '../../types';
import { promises as fs } from 'fs';
import * as path from 'path';

export abstract class ReScriptBackendGenerator extends BackendTemplateGenerator {
  constructor() {
    super({
      language: 'ReScript',
      framework: 'ReScript Framework',
      packageManager: 'npm',
      buildTool: 'rescript',
      testFramework: 'jest',
      dependencies: {},
      devDependencies: {},
      scripts: {},
      features: [
        'Type-safe JavaScript',
        'Fast compilation',
        'Excellent type inference',
        'Seamless JavaScript interop',
        'Pattern matching',
        'Variant types',
        'Module system',
        'Belt standard library',
        'React bindings available',
        'Docker support'
      ]
    });
  }

  // Abstract methods that concrete implementations must provide
  protected abstract getFrameworkDependencies(): Record<string, string>;
  protected abstract getFrameworkDevDependencies(): Record<string, string>;
  protected abstract getFrameworkSpecificFiles(): FileTemplate[];

  protected async generateLanguageFiles(projectPath: string, options: any): Promise<void> {
    const files = [
      {
        path: 'package.json',
        content: this.generatePackageJson(options)
      },
      {
        path: 'bsconfig.json',
        content: this.generateBsConfig(options)
      },
      {
        path: 'src/main.res',
        content: this.generateMainFile(options)
      },
      {
        path: 'src/config/Config.res',
        content: this.generateConfigFile(options)
      },
      {
        path: 'src/middleware/Logger.res',
        content: this.generateLoggerMiddleware()
      },
      {
        path: 'src/middleware/ErrorHandler.res',
        content: this.generateErrorHandlerMiddleware()
      },
      {
        path: 'src/controllers/HealthController.res',
        content: this.generateHealthController()
      },
      {
        path: 'src/controllers/InfoController.res',
        content: this.generateInfoController(options)
      },
      {
        path: 'src/models/User.res',
        content: this.generateUserModel()
      },
      {
        path: 'src/services/UserService.res',
        content: this.generateUserService()
      },
      {
        path: 'src/utils/Response.res',
        content: this.generateResponseUtils()
      },
      {
        path: 'src/utils/Validation.res',
        content: this.generateValidationUtils()
      },
      {
        path: 'src/bindings/NodeJs.res',
        content: this.generateNodeBindings()
      },
      {
        path: 'src/bindings/Process.res',
        content: this.generateProcessBindings()
      }
    ];

    for (const file of files) {
      const filePath = path.join(projectPath, file.path);
      await fs.mkdir(path.dirname(filePath), { recursive: true });
      await fs.writeFile(filePath, file.content);
    }
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    const files = this.getFrameworkSpecificFiles();
    
    for (const file of files) {
      const filePath = path.join(projectPath, file.path);
      await fs.mkdir(path.dirname(filePath), { recursive: true });
      await fs.writeFile(filePath, file.content);
    }
  }

  protected async generateTestStructure(projectPath: string, options: any): Promise<void> {
    const testFiles = [
      {
        path: 'tests/HealthController_test.res',
        content: this.generateHealthControllerTest()
      },
      {
        path: 'tests/UserService_test.res',
        content: this.generateUserServiceTest()
      },
      {
        path: 'jest.config.js',
        content: this.generateJestConfig()
      }
    ];

    for (const file of testFiles) {
      const filePath = path.join(projectPath, file.path);
      await fs.mkdir(path.dirname(filePath), { recursive: true });
      await fs.writeFile(filePath, file.content);
    }
  }

  protected async generateHealthCheck(projectPath: string): Promise<void> {
    // Health check is already generated in generateLanguageFiles
  }

  protected async generateAPIDocs(projectPath: string): Promise<void> {
    const content = `# ${this.config.framework} API Documentation

This service provides RESTful API endpoints for backend operations.

## Authentication

Most endpoints require JWT authentication. Include the token in the Authorization header:

\`\`\`
Authorization: Bearer <your-jwt-token>
\`\`\`

## Endpoints

### Health Check
- \`GET /health\` - Service health status
- \`GET /ready\` - Readiness probe
- \`GET /info\` - Service information

### User Management
- \`POST /api/users/register\` - Register new user
- \`POST /api/users/login\` - User login
- \`GET /api/users\` - List users (authenticated)
- \`GET /api/users/profile\` - Get user profile (authenticated)
- \`GET /api/users/:id\` - Get user by ID (authenticated)
- \`PUT /api/users/:id\` - Update user (authenticated)
- \`DELETE /api/users/:id\` - Delete user (admin only)

## Response Format

All API responses follow this format:

\`\`\`json
{
  "success": true|false,
  "data": <response-data>,
  "error": <error-message>,
  "timestamp": "<ISO-string>"
}
\`\`\`

## Error Codes

- \`400\` - Bad Request
- \`401\` - Unauthorized
- \`403\` - Forbidden
- \`404\` - Not Found
- \`429\` - Too Many Requests
- \`500\` - Internal Server Error
`;

    await fs.writeFile(path.join(projectPath, 'docs/API.md'), content);
  }

  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    const dockerfile = `# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY bsconfig.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY src ./src

# Build ReScript
RUN npm run build

# Production stage
FROM node:20-alpine

WORKDIR /app

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

# Create non-root user
RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001

# Copy package files
COPY package*.json ./

# Install production dependencies only
RUN npm ci --production && npm cache clean --force

# Copy compiled JavaScript from builder
COPY --from=builder /app/lib ./lib

# Copy static files if any
COPY --from=builder /app/bsconfig.json ./

# Set ownership
RUN chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE ${options.port || 3000}

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start the application
CMD ["node", "lib/js/src/main.bs.js"]`;

    const dockerCompose = `version: '3.8'

services:
  ${options.name}:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "\${PORT:-${options.port || 3000}}:${options.port || 3000}"
    environment:
      - NODE_ENV=production
      - PORT=${options.port || 3000}
      - SERVICE_NAME=${options.name}
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:${options.port || 3000}/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - app-network

networks:
  app-network:
    driver: bridge`;

    await fs.writeFile(path.join(projectPath, 'Dockerfile'), dockerfile);
    await fs.writeFile(path.join(projectPath, 'docker-compose.yml'), dockerCompose);
  }

  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    // API docs are generated in generateAPIDocs
    // README is generated by the base class
  }

  protected getBuildCommand(): string {
    return 'npm run build';
  }

  protected getDevCommand(): string {
    return 'npm run dev';
  }

  protected getProdCommand(): string {
    return 'npm start';
  }

  protected getTestCommand(): string {
    return 'npm test';
  }

  protected getCoverageCommand(): string {
    return 'npm run test -- --coverage';
  }

  protected getLintCommand(): string {
    return 'npm run format';
  }

  protected getInstallCommand(): string {
    return 'npm install';
  }

  protected getSetupAction(): string {
    return 'Install dependencies and compile ReScript';
  }

  protected getLanguagePrerequisites(): string {
    return 'Node.js >= 18.0.0, npm >= 8.0.0';
  }

  protected getLanguageSpecificIgnorePatterns(): string[] {
    return [
      '# ReScript',
      'lib/',
      '.bsb.lock',
      '.merlin',
      '*.bs.js',
      '',
      '# Dependencies',
      'node_modules/',
      'npm-debug.log*',
      '',
      '# Environment',
      '.env',
      '.env.local',
      '',
      '# Build',
      'dist/',
      'build/',
      '',
      '# Testing',
      'coverage/'
    ];
  }

  // Helper methods for generating ReScript-specific content
  protected generatePackageJson(options: any): string {
    const dependencies = this.getFrameworkDependencies();
    const devDependencies = this.getFrameworkDevDependencies();

    return `{
  "name": "${options.name}",
  "version": "1.0.0",
  "description": "${options.description}",
  "main": "lib/js/src/main.bs.js",
  "scripts": {
    "build": "rescript build",
    "clean": "rescript clean",
    "dev": "concurrently \\"rescript build -w\\" \\"nodemon lib/js/src/main.bs.js\\"",
    "start": "node lib/js/src/main.bs.js",
    "test": "jest",
    "test:watch": "jest --watch",
    "format": "rescript format -all",
    "docker:build": "docker build -t ${options.name} .",
    "docker:run": "docker run -p ${options.port || 3000}:${options.port || 3000} ${options.name}"
  },
  "dependencies": {
    ${Object.entries(dependencies).map(([name, version]) => `"${name}": "${version}"`).join(',\n    ')}
  },
  "devDependencies": {
    "rescript": "^11.0.0",
    "@rescript/core": "^0.5.0",
    "concurrently": "^7.6.0",
    "nodemon": "^3.0.0",
    "@types/node": "^20.0.0",
    ${Object.entries(devDependencies).map(([name, version]) => `"${name}": "${version}"`).join(',\n    ')}
  },
  "engines": {
    "node": ">=18.0.0"
  }
}`;
  }

  protected generateBsConfig(options: any): string {
    return `{
  "name": "${options.name}",
  "version": "1.0.0",
  "sources": [
    {
      "dir": "src",
      "subdirs": true
    },
    {
      "dir": "tests",
      "subdirs": true,
      "type": "dev"
    }
  ],
  "package-specs": {
    "module": "commonjs",
    "in-source": false
  },
  "suffix": ".bs.js",
  "namespace": true,
  "bs-dependencies": [
    "@rescript/core"
  ],
  "warnings": {
    "error": "+101+102"
  },
  "bsc-flags": ["-bs-super-errors", "-bs-no-version-header"]
}`;
  }

  // Abstract methods for concrete implementations to override
  protected abstract generateMainFile(options: any): string;
  protected abstract generateConfigFile(options: any): string;

  // Common ReScript utility methods
  protected generateLoggerMiddleware(): string {
    return `// Logger middleware
open NodeJs

type logLevel = Debug | Info | Warn | Error

let levelToString = (level: logLevel): string => {
  switch level {
  | Debug => "DEBUG"
  | Info => "INFO"
  | Warn => "WARN"
  | Error => "ERROR"
  }
}

let log = (level: logLevel, message: string): unit => {
  let timestamp = Date.now()->Date.toISOString
  let logLevel = levelToString(level)
  Console.log(\`[\${timestamp}] [\${logLevel}] \${message}\`)
}

let debug = (message: string) => log(Debug, message)
let info = (message: string) => log(Info, message)
let warn = (message: string) => log(Warn, message)
let error = (message: string) => log(Error, message)`;
  }

  protected generateErrorHandlerMiddleware(): string {
    return `// Error handler middleware
open NodeJs

type appError = {
  message: string,
  status: int,
  code: option<string>,
}

let createError = (~message: string, ~status: int=500, ~code: option<string>=None, ()): appError => {
  { message, status, code }
}

let handleError = (err: exn): appError => {
  switch err {
  | Js.Exn.Error(obj) => 
    let message = switch Js.Exn.message(obj) {
    | Some(msg) => msg
    | None => "Internal server error"
    }
    createError(~message, ())
  | _ => createError(~message="Unknown error", ())
  }
}`;
  }

  protected generateHealthController(): string {
    return `// Health check controller
open NodeJs

type healthStatus = {
  status: string,
  timestamp: string,
  service: string,
  uptime: float,
}

let getHealthStatus = (): healthStatus => {
  {
    status: "healthy",
    timestamp: Date.now()->Date.toISOString,
    service: Config.config.serviceName,
    uptime: Process.uptime(),
  }
}

let getReadinessStatus = (): bool => {
  // Add actual readiness checks here
  true
}`;
  }

  protected generateInfoController(options: any): string {
    return `// Service info controller
open NodeJs

type serviceInfo = {
  name: string,
  version: string,
  description: string,
  framework: string,
  language: string,
  nodeVersion: string,
  environment: string,
  port: int,
}

let getServiceInfo = (): serviceInfo => {
  {
    name: Config.config.serviceName,
    version: "1.0.0",
    description: "${options.description}",
    framework: "${this.config.framework}",
    language: "ReScript",
    nodeVersion: Process.version,
    environment: Config.config.env,
    port: Config.config.port,
  }
}`;
  }

  protected generateUserModel(): string {
    return `// User model
type user = {
  id: string,
  email: string,
  name: string,
  role: userRole,
  createdAt: float,
  updatedAt: float,
}

and userRole = Admin | User | Guest

let roleToString = (role: userRole): string => {
  switch role {
  | Admin => "admin"
  | User => "user"
  | Guest => "guest"
  }
}

let roleFromString = (str: string): option<userRole> => {
  switch str {
  | "admin" => Some(Admin)
  | "user" => Some(User)
  | "guest" => Some(Guest)
  | _ => None
  }
}

let create = (~email: string, ~name: string, ~role: userRole=User, ()): user => {
  let now = Date.now()
  {
    id: \`user_\${now->Float.toString}\`,
    email,
    name,
    role,
    createdAt: now,
    updatedAt: now,
  }
}

let toJson = (user: user): Js.Json.t => {
  Js.Json.object_([
    ("id", Js.Json.string(user.id)),
    ("email", Js.Json.string(user.email)),
    ("name", Js.Json.string(user.name)),
    ("role", Js.Json.string(roleToString(user.role))),
    ("createdAt", Js.Json.number(user.createdAt)),
    ("updatedAt", Js.Json.number(user.updatedAt)),
  ])
}`;
  }

  protected generateUserService(): string {
    return `// User service
open User

// In-memory storage for demo
let users = ref(Belt.Map.String.empty)

let findById = (id: string): option<user> => {
  users.contents->Belt.Map.String.get(id)
}

let findByEmail = (email: string): option<user> => {
  users.contents
  ->Belt.Map.String.valuesToArray
  ->Array.find(user => user.email == email)
}

let create = (~email: string, ~name: string, ~role: userRole=User, ()): result<user, string> => {
  switch findByEmail(email) {
  | Some(_) => Error("User with this email already exists")
  | None => 
    let user = User.create(~email, ~name, ~role, ())
    users := users.contents->Belt.Map.String.set(user.id, user)
    Ok(user)
  }
}

let listAll = (): array<user> => {
  users.contents->Belt.Map.String.valuesToArray
}`;
  }

  protected generateResponseUtils(): string {
    return `// Response utilities
open NodeJs

type apiResponse<'a> = {
  success: bool,
  data: option<'a>,
  error: option<string>,
  timestamp: string,
}

let success = (~data: 'a): apiResponse<'a> => {
  {
    success: true,
    data: Some(data),
    error: None,
    timestamp: Date.now()->Date.toISOString,
  }
}

let error = (~message: string): apiResponse<'a> => {
  {
    success: false,
    data: None,
    error: Some(message),
    timestamp: Date.now()->Date.toISOString,
  }
}`;
  }

  protected generateValidationUtils(): string {
    return `// Validation utilities

let isEmail = (email: string): bool => {
  let emailRegex = %re("/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/")
  emailRegex->Js.Re.test_(email)
}

let isStrongPassword = (password: string): bool => {
  // At least 8 characters, one uppercase, one lowercase, one number
  let passwordRegex = %re("/^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)[a-zA-Z\\d@$!%*?&]{8,}$/")
  passwordRegex->Js.Re.test_(password)
}`;
  }

  protected generateNodeBindings(): string {
    return `// Node.js bindings

type process = {
  env: Js.Dict.t<string>,
  version: string,
  platform: string,
  arch: string,
  pid: int,
  exit: int => unit,
  uptime: unit => float,
}

@val external process: process = "process"

module Process = {
  type signal = [#SIGTERM | #SIGINT | #SIGUSR1 | #SIGUSR2]
  
  @send external on: (process, signal, unit => unit) => unit = "on"
  @send external exit: (process, int) => unit = "exit"
  
  let env = process.env
  let version = process.version
  let uptime = process.uptime
  let exit = code => process->exit(code)
  let on = (signal, callback) => process->on(signal, callback)
}

module Console = {
  @val external log: string => unit = "console.log"
  @val external error: string => unit = "console.error"
  @val external warn: string => unit = "console.warn"
  @val external info: string => unit = "console.info"
}

module Date = {
  type t
  
  @new external make: unit => t = "Date"
  @val external now: unit => float = "Date.now"
  @send external toISOString: t => string = "toISOString"
}

module Int = {
  @val external fromString: string => option<int> = "parseInt"
  @send external toString: int => string = "toString"
}

module Float = {
  @val external fromString: string => option<float> = "parseFloat"
  @send external toString: float => string = "toString"
}`;
  }

  protected generateProcessBindings(): string {
    return `// Process-specific bindings (extends NodeJs.Process)

// Re-export from NodeJs
include NodeJs.Process

// Additional process utilities
let isProduction = (): bool => {
  switch env->Js.Dict.get("NODE_ENV") {
  | Some("production") => true
  | _ => false
  }
}

let isDevelopment = (): bool => {
  switch env->Js.Dict.get("NODE_ENV") {
  | Some("development") => true
  | None => true // Default to development
  | _ => false
  }
}`;
  }

  protected generateHealthControllerTest(): string {
    return `// Health controller tests
open Jest

describe("HealthController", () => {
  test("should return healthy status", () => {
    let status = HealthController.getHealthStatus()
    expect(status.status)->toBe("healthy")
  })
})`;
  }

  protected generateUserServiceTest(): string {
    return `// User service tests
open Jest
open User

describe("UserService", () => {
  test("should create a new user", () => {
    let result = UserService.create(~email="test@example.com", ~name="Test User", ())
    
    switch result {
    | Ok(user) => {
      expect(user.email)->toBe("test@example.com")
      expect(user.name)->toBe("Test User")
    }
    | Error(_) => fail("Should create user successfully")
    }
  })
})`;
  }

  protected generateJestConfig(): string {
    return `module.exports = {
  testEnvironment: 'node',
  testMatch: ['<rootDir>/lib/js/tests/**/*_test.bs.js'],
  moduleFileExtensions: ['js', 'json'],
  coverageDirectory: 'coverage',
  collectCoverageFrom: [
    'lib/js/src/**/*.bs.js',
    '!lib/js/src/main.bs.js'
  ]
};`;
  }
}