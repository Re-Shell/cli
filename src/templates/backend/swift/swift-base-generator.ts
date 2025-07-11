/**
 * Swift Backend Template Base Generator
 * Shared functionality for all Swift web frameworks
 */

import { BackendTemplateGenerator, BackendTemplateConfig } from '../shared/backend-template-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export abstract class SwiftBackendGenerator extends BackendTemplateGenerator {
  constructor(framework: string) {
    const config: BackendTemplateConfig = {
      language: 'Swift',
      framework,
      packageManager: 'swift-package-manager',
      testFramework: 'XCTest',
      features: [
        'Async/Await support',
        'Type-safe routing',
        'Middleware pipeline',
        'JSON encoding/decoding',
        'WebSocket support',
        'Database integration',
        'Authentication & Authorization',
        'Structured logging',
        'Environment configuration',
        'Docker support'
      ],
      dependencies: {},
      devDependencies: {},
      scripts: {
        'build': 'swift build',
        'run': 'swift run',
        'test': 'swift test',
        'release': 'swift build -c release',
        'clean': 'swift package clean',
        'update': 'swift package update',
        'generate-xcodeproj': 'swift package generate-xcodeproj'
      },
      dockerConfig: {
        baseImage: 'swift:5.9-slim',
        workDir: '/app',
        exposedPorts: [8080],
        buildSteps: [
          'COPY . .',
          'RUN swift build -c release'
        ],
        runCommand: '.build/release/App',
        multistage: true
      },
      envVars: {
        'PORT': '8080',
        'ENVIRONMENT': 'development',
        'LOG_LEVEL': 'info',
        'DATABASE_URL': 'postgresql://user:password@localhost:5432/dbname',
        'JWT_SECRET': 'your-secret-key',
        'REDIS_URL': 'redis://localhost:6379'
      }
    };
    super(config);
  }

  protected async generateLanguageFiles(projectPath: string, options: any): Promise<void> {
    // Generate Package.swift
    await this.generatePackageSwift(projectPath, options);

    // Generate .swiftlint.yml
    await this.generateSwiftLint(projectPath);

    // Generate .swift-version
    await fs.writeFile(path.join(projectPath, '.swift-version'), '5.9');
  }

  protected async generatePackageSwift(projectPath: string, options: any): Promise<void> {
    const packageContent = `// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "${options.name}",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "App", targets: ["App"]),
    ],
    dependencies: [
        ${this.getFrameworkDependencies().join(',\\n        ')}
    ],
    targets: [
        .executableTarget(
            name: "App",
            dependencies: ${this.getTargetDependencies()},
            path: "Sources/App"
        ),
        .testTarget(
            name: "AppTests",
            dependencies: [
                .target(name: "App"),
                ${this.getTestDependencies()}
            ],
            path: "Tests/AppTests"
        ),
    ]
)
`;

    await fs.writeFile(path.join(projectPath, 'Package.swift'), packageContent);
  }

  protected async generateSwiftLint(projectPath: string): Promise<void> {
    const config = `disabled_rules:
  - trailing_whitespace
  - line_length

opt_in_rules:
  - empty_count
  - closure_spacing
  - collection_alignment
  - contains_over_first_not_nil
  - empty_string
  - first_where
  - force_unwrapping
  - implicitly_unwrapped_optional
  - last_where
  - literal_expression_end_indentation
  - multiline_arguments
  - multiline_function_chains
  - multiline_parameters
  - operator_usage_whitespace
  - prefer_self_type_over_type_of_self
  - redundant_nil_coalescing
  - sorted_first_last
  - trailing_closure
  - unneeded_parentheses_in_closure_argument
  - vertical_parameter_alignment_on_call
  - yoda_condition

excluded:
  - .build
  - .swiftpm
  - Package.swift

line_length: 120

type_body_length:
  warning: 300
  error: 400

file_length:
  warning: 500
  error: 1200

function_body_length:
  warning: 40
  error: 100

cyclomatic_complexity:
  warning: 10
  error: 20

nesting:
  type_level:
    warning: 2
  function_level:
    warning: 3
`;

    await fs.writeFile(path.join(projectPath, '.swiftlint.yml'), config);
  }

  protected async generateTestStructure(projectPath: string, options: any): Promise<void> {
    // Create test directories
    const testDirs = [
      'Tests/AppTests',
      'Tests/AppTests/Controllers',
      'Tests/AppTests/Services',
      'Tests/AppTests/Models',
      'Tests/AppTests/Utils'
    ];

    for (const dir of testDirs) {
      await fs.mkdir(path.join(projectPath, dir), { recursive: true });
    }

    // Generate base test file
    const baseTest = `import XCTest
@testable import App

class AppTestCase: XCTestCase {
    var app: Application!
    
    override func setUp() async throws {
        try await super.setUp()
        app = try await Application.testable()
    }
    
    override func tearDown() async throws {
        try await app.shutdown()
        try await super.tearDown()
    }
}

extension Application {
    static func testable() async throws -> Application {
        let app = Application()
        try await configure(app)
        return app
    }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'Tests/AppTests/AppTestCase.swift'),
      baseTest
    );

    // Generate example test
    const exampleTest = `import XCTest
@testable import App

final class HealthCheckTests: AppTestCase {
    func testHealthCheck() async throws {
        try await app.test(.GET, "/health") { response in
            XCTAssertEqual(response.status, .ok)
            
            struct HealthResponse: Codable {
                let status: String
                let timestamp: Date
                let version: String
            }
            
            let health = try response.content.decode(HealthResponse.self)
            XCTAssertEqual(health.status, "healthy")
        }
    }
    
    func testReadiness() async throws {
        try await app.test(.GET, "/ready") { response in
            XCTAssertEqual(response.status, .ok)
        }
    }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'Tests/AppTests/Controllers/HealthCheckTests.swift'),
      exampleTest
    );
  }

  protected async generateHealthCheck(projectPath: string): Promise<void> {
    const healthController = `import Foundation

struct HealthController {
    struct HealthResponse: Codable {
        let status: String
        let timestamp: Date
        let version: String
        let uptime: TimeInterval
        let environment: String
        let checks: [String: Bool]
    }
    
    static func health() async throws -> HealthResponse {
        let startTime = ProcessInfo.processInfo.systemUptime
        
        // Perform health checks
        let checks = [
            "database": await checkDatabase(),
            "redis": await checkRedis(),
            "filesystem": checkFilesystem()
        ]
        
        return HealthResponse(
            status: checks.values.allSatisfy { $0 } ? "healthy" : "degraded",
            timestamp: Date(),
            version: getVersion(),
            uptime: ProcessInfo.processInfo.systemUptime - startTime,
            environment: Environment.current.rawValue,
            checks: checks
        )
    }
    
    static func readiness() async throws -> [String: Any] {
        return [
            "ready": true,
            "timestamp": Date().timeIntervalSince1970
        ]
    }
    
    private static func checkDatabase() async -> Bool {
        // Implement database connectivity check
        return true
    }
    
    private static func checkRedis() async -> Bool {
        // Implement Redis connectivity check
        return true
    }
    
    private static func checkFilesystem() -> Bool {
        // Check if we can write to temp directory
        let tempFile = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        
        do {
            try "test".write(to: tempFile, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(at: tempFile)
            return true
        } catch {
            return false
        }
    }
    
    private static func getVersion() -> String {
        return Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0"
    }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'Sources/App/Controllers/HealthController.swift'),
      healthController
    );
  }

  protected async generateAPIDocs(projectPath: string): Promise<void> {
    // Generate OpenAPI specification
    const openAPISpec = `openapi: 3.0.0
info:
  title: ${this.config.framework} API
  description: API documentation for ${this.config.framework} microservice
  version: 1.0.0
  contact:
    name: API Support
    email: support@example.com
  license:
    name: MIT
    url: https://opensource.org/licenses/MIT

servers:
  - url: http://localhost:8080
    description: Development server
  - url: https://api.example.com
    description: Production server

tags:
  - name: Health
    description: Health check endpoints
  - name: Auth
    description: Authentication endpoints
  - name: Users
    description: User management

paths:
  /health:
    get:
      tags:
        - Health
      summary: Health check
      description: Returns the health status of the service
      responses:
        '200':
          description: Service is healthy
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/HealthResponse'

  /ready:
    get:
      tags:
        - Health
      summary: Readiness check
      description: Returns whether the service is ready to accept requests
      responses:
        '200':
          description: Service is ready
          content:
            application/json:
              schema:
                type: object
                properties:
                  ready:
                    type: boolean
                  timestamp:
                    type: number

  /auth/login:
    post:
      tags:
        - Auth
      summary: User login
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/LoginRequest'
      responses:
        '200':
          description: Login successful
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/LoginResponse'
        '401':
          description: Invalid credentials

  /auth/register:
    post:
      tags:
        - Auth
      summary: User registration
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/RegisterRequest'
      responses:
        '201':
          description: Registration successful
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'
        '400':
          description: Invalid registration data

  /users/me:
    get:
      tags:
        - Users
      summary: Get current user
      security:
        - bearerAuth: []
      responses:
        '200':
          description: Current user information
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/User'
        '401':
          description: Unauthorized

components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

  schemas:
    HealthResponse:
      type: object
      properties:
        status:
          type: string
          enum: [healthy, degraded, unhealthy]
        timestamp:
          type: string
          format: date-time
        version:
          type: string
        uptime:
          type: number
        environment:
          type: string
        checks:
          type: object
          additionalProperties:
            type: boolean

    LoginRequest:
      type: object
      required:
        - email
        - password
      properties:
        email:
          type: string
          format: email
        password:
          type: string
          minLength: 8

    LoginResponse:
      type: object
      properties:
        token:
          type: string
        refreshToken:
          type: string
        expiresIn:
          type: integer
        user:
          $ref: '#/components/schemas/User'

    RegisterRequest:
      type: object
      required:
        - email
        - password
        - name
      properties:
        email:
          type: string
          format: email
        password:
          type: string
          minLength: 8
        name:
          type: string
          minLength: 2

    User:
      type: object
      properties:
        id:
          type: string
          format: uuid
        email:
          type: string
          format: email
        name:
          type: string
        createdAt:
          type: string
          format: date-time
        updatedAt:
          type: string
          format: date-time
`;

    await fs.writeFile(
      path.join(projectPath, 'docs/openapi.yaml'),
      openAPISpec
    );
  }

  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    // Multi-stage Dockerfile
    const dockerfile = `# ================================
# Build Stage
# ================================
FROM swift:5.9-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    libssl-dev \\
    libsqlite3-dev \\
    libpq-dev \\
    libmysqlclient-dev \\
    curl \\
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy package files
COPY Package.* ./

# Resolve dependencies
RUN swift package resolve

# Copy source code
COPY . .

# Build for release
RUN swift build -c release --static-swift-stdlib

# ================================
# Runtime Stage
# ================================
FROM ubuntu:22.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \\
    libssl-dev \\
    libsqlite3-dev \\
    libpq-dev \\
    libmysqlclient-dev \\
    ca-certificates \\
    tzdata \\
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1001 -s /bin/bash vapor

# Set working directory
WORKDIR /app

# Copy built executable
COPY --from=builder /app/.build/release/App /app/App

# Copy resources if needed
COPY --from=builder /app/Public ./Public
COPY --from=builder /app/Resources ./Resources

# Set ownership
RUN chown -R vapor:vapor /app

# Switch to non-root user
USER vapor

# Expose port
EXPOSE ${options.port || 8080}

# Set environment
ENV ENVIRONMENT=production

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:${options.port || 8080}/health || exit 1

# Run the application
CMD ["./App"]
`;

    await fs.writeFile(path.join(projectPath, 'Dockerfile'), dockerfile);

    // Docker compose for local development
    const dockerCompose = `version: '3.8'

services:
  app:
    build: .
    ports:
      - "\${PORT:-8080}:8080"
    environment:
      - ENVIRONMENT=development
      - DATABASE_URL=postgresql://postgres:postgres@db:5432/${options.name}
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis
    volumes:
      - .:/app
      - /app/.build
    command: swift run

  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_DB=${options.name}
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
`;

    await fs.writeFile(path.join(projectPath, 'docker-compose.yml'), dockerCompose);

    // .dockerignore
    const dockerignore = `.build/
.swiftpm/
*.xcodeproj
.git/
.gitignore
.dockerignore
Dockerfile
docker-compose.yml
README.md
.env
.env.*
Tests/
docs/
`;

    await fs.writeFile(path.join(projectPath, '.dockerignore'), dockerignore);
  }

  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    // API documentation guide
    const apiGuide = `# API Documentation

## Overview

This ${this.config.framework} API provides a robust foundation for building microservices with Swift.

## Authentication

The API uses JWT (JSON Web Tokens) for authentication. Include the token in the Authorization header:

\`\`\`
Authorization: Bearer <your-jwt-token>
\`\`\`

## Rate Limiting

API endpoints are rate-limited to prevent abuse:
- Anonymous requests: 100 requests per hour
- Authenticated requests: 1000 requests per hour

## Error Handling

The API returns consistent error responses:

\`\`\`json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": {
      "field": "email",
      "reason": "Invalid email format"
    }
  }
}
\`\`\`

## Common HTTP Status Codes

- \`200 OK\`: Request successful
- \`201 Created\`: Resource created successfully
- \`400 Bad Request\`: Invalid request data
- \`401 Unauthorized\`: Authentication required
- \`403 Forbidden\`: Access denied
- \`404 Not Found\`: Resource not found
- \`429 Too Many Requests\`: Rate limit exceeded
- \`500 Internal Server Error\`: Server error

## Pagination

List endpoints support pagination:

\`\`\`
GET /api/users?page=1&limit=20
\`\`\`

Response includes pagination metadata:

\`\`\`json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 100,
    "pages": 5
  }
}
\`\`\`

## Filtering and Sorting

Most list endpoints support filtering and sorting:

\`\`\`
GET /api/users?filter[name]=john&sort=-created_at
\`\`\`

## WebSocket Support

WebSocket connections are available at \`ws://localhost:8080/ws\`

### Events

- \`connection\`: Client connected
- \`message\`: New message received
- \`disconnect\`: Client disconnected

## Development

### Running Tests

\`\`\`bash
swift test
\`\`\`

### Code Style

This project uses SwiftLint for code style enforcement:

\`\`\`bash
swiftlint
\`\`\`

### Database Migrations

Run migrations before starting the application:

\`\`\`bash
swift run App migrate
\`\`\`

## Deployment

### Environment Variables

- \`PORT\`: Server port (default: 8080)
- \`ENVIRONMENT\`: Environment mode (development, staging, production)
- \`DATABASE_URL\`: PostgreSQL connection string
- \`REDIS_URL\`: Redis connection string
- \`JWT_SECRET\`: Secret key for JWT signing
- \`LOG_LEVEL\`: Logging level (debug, info, warning, error)

### Health Checks

- \`GET /health\`: Comprehensive health check
- \`GET /ready\`: Simple readiness check

## Security

### Best Practices

1. Always use HTTPS in production
2. Keep dependencies updated
3. Use environment variables for secrets
4. Enable CORS only for trusted origins
5. Implement proper input validation
6. Use prepared statements for database queries
7. Enable security headers

### Security Headers

The following security headers are enabled by default:

- \`X-Content-Type-Options: nosniff\`
- \`X-Frame-Options: DENY\`
- \`X-XSS-Protection: 1; mode=block\`
- \`Strict-Transport-Security: max-age=31536000; includeSubDomains\`
- \`Content-Security-Policy: default-src 'self'\`
`;

    await fs.writeFile(path.join(projectPath, 'docs/API.md'), apiGuide);

    // Development guide
    const devGuide = `# Development Guide

## Prerequisites

- Swift 5.9+
- Docker & Docker Compose
- PostgreSQL 15+ (or use Docker)
- Redis 7+ (or use Docker)

## Setup

1. Clone the repository:
   \`\`\`bash
   git clone <repository-url>
   cd ${options.name}
   \`\`\`

2. Install dependencies:
   \`\`\`bash
   swift package resolve
   \`\`\`

3. Setup environment:
   \`\`\`bash
   cp .env.example .env
   # Edit .env with your configuration
   \`\`\`

4. Start dependencies:
   \`\`\`bash
   docker-compose up -d db redis
   \`\`\`

5. Run migrations:
   \`\`\`bash
   swift run App migrate
   \`\`\`

6. Start the application:
   \`\`\`bash
   swift run
   \`\`\`

## Project Structure

\`\`\`
Sources/
├── App/
│   ├── Controllers/      # HTTP request handlers
│   ├── Models/          # Data models and DTOs
│   ├── Services/        # Business logic
│   ├── Middleware/      # Custom middleware
│   ├── Config/          # Configuration
│   ├── Utils/           # Utilities
│   └── main.swift       # Application entry point
\`\`\`

## Coding Standards

### Naming Conventions

- Use PascalCase for types and protocols
- Use camelCase for functions, variables, and properties
- Use UPPER_SNAKE_CASE for constants
- Prefix protocols with their purpose (e.g., \`UserServiceProtocol\`)

### File Organization

- One type per file
- File name matches the primary type name
- Group related files in subdirectories

### Comments and Documentation

- Use \`///\` for public API documentation
- Use \`//\` for implementation comments
- Document complex algorithms and business logic

## Testing

### Unit Tests

\`\`\`bash
swift test --filter AppTests.UserServiceTests
\`\`\`

### Integration Tests

\`\`\`bash
swift test --filter AppTests.IntegrationTests
\`\`\`

### Test Coverage

\`\`\`bash
swift test --enable-code-coverage
\`\`\`

## Debugging

### Xcode

Generate Xcode project:
\`\`\`bash
swift package generate-xcodeproj
open *.xcodeproj
\`\`\`

### LLDB

\`\`\`bash
lldb .build/debug/App
(lldb) run
\`\`\`

### Logging

Configure log level in environment:
\`\`\`bash
LOG_LEVEL=debug swift run
\`\`\`

## Performance

### Profiling

Use Instruments for performance profiling:
\`\`\`bash
instruments -t "Time Profiler" .build/release/App
\`\`\`

### Benchmarking

Run benchmarks:
\`\`\`bash
swift test --filter AppTests.BenchmarkTests
\`\`\`

## Troubleshooting

### Common Issues

1. **Port already in use**
   \`\`\`bash
   lsof -i :8080
   kill -9 <PID>
   \`\`\`

2. **Database connection failed**
   - Check DATABASE_URL format
   - Ensure PostgreSQL is running
   - Verify credentials

3. **Swift package resolution failed**
   \`\`\`bash
   swift package clean
   rm -rf .build
   swift package resolve
   \`\`\`
`;

    await fs.writeFile(path.join(projectPath, 'docs/DEVELOPMENT.md'), devGuide);
  }

  // Utility methods
  protected getLanguageSpecificIgnorePatterns(): string[] {
    return [
      '.build/',
      '.swiftpm/',
      '*.xcodeproj',
      '*.xcworkspace',
      '*.playground',
      'DerivedData/',
      '*.moved-aside',
      '*.pbxuser',
      '!default.pbxuser',
      '*.mode1v3',
      '!default.mode1v3',
      '*.mode2v3',
      '!default.mode2v3',
      '*.perspectivev3',
      '!default.perspectivev3'
    ];
  }

  protected getLanguagePrerequisites(): string {
    return 'Swift 5.9+ (install via https://swift.org/download/)';
  }

  protected getInstallCommand(): string {
    return 'swift package resolve';
  }

  protected getDevCommand(): string {
    return 'swift run';
  }

  protected getProdCommand(): string {
    return 'swift build -c release && .build/release/App';
  }

  protected getTestCommand(): string {
    return 'swift test';
  }

  protected getCoverageCommand(): string {
    return 'swift test --enable-code-coverage';
  }

  protected getLintCommand(): string {
    return 'swiftlint';
  }

  protected getBuildCommand(): string {
    return 'swift build -c release';
  }

  protected getSetupAction(): string {
    return 'swift-actions/setup-swift@v1';
  }

  // Abstract methods to be implemented by specific frameworks
  protected abstract getFrameworkDependencies(): string[];
  protected abstract getTargetDependencies(): string;
  protected abstract getTestDependencies(): string;
  protected abstract generateFrameworkFiles(projectPath: string, options: any): Promise<void>;
}