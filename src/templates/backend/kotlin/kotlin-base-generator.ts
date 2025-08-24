import { BackendTemplateGenerator } from '../shared/backend-template-generator';
import * as path from 'path';
import { promises as fs } from 'fs';

export abstract class KotlinBackendGenerator extends BackendTemplateGenerator {
  protected options: any;
  
  constructor() {
    super({
      language: 'Kotlin',
      framework: 'Kotlin Framework',
      packageManager: 'gradle',
      buildTool: 'gradle',
      testFramework: 'kotest',
      features: [
        'JWT Authentication',
        'PostgreSQL Database',
        'Redis Cache',
        'Docker Support',
        'OpenAPI Documentation',
        'Coroutines Support'
      ],
      dependencies: {},
      devDependencies: {},
      scripts: {
        dev: './gradlew run',
        build: './gradlew build',
        test: './gradlew test',
        clean: './gradlew clean'
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
  
  protected generateBuildGradle(): string {
    const dependencies = this.getFrameworkDependencies();
    const depList = Object.entries(dependencies)
      .map(([name, version]) => `    implementation "${name}:${version}"`)
      .join('\n');

    return `import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("org.springframework.boot") version "3.2.0" apply false
    id("io.spring.dependency-management") version "1.1.4" apply false
    kotlin("jvm") version "1.9.21"
    kotlin("plugin.spring") version "1.9.21" apply false
    kotlin("plugin.serialization") version "1.9.21"
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "com.example"
version = "0.0.1-SNAPSHOT"

java {
    sourceCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenCentral()
}

dependencies {
${depList}
    
    // Common dependencies
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.2")
    
    // Logging
    implementation("io.github.microutils:kotlin-logging-jvm:3.0.5")
    implementation("ch.qos.logback:logback-classic:1.4.14")
    
    // Database
    implementation("org.postgresql:postgresql:42.7.1")
    implementation("com.zaxxer:HikariCP:5.1.0")
    implementation("org.jetbrains.exposed:exposed-core:0.45.0")
    implementation("org.jetbrains.exposed:exposed-dao:0.45.0")
    implementation("org.jetbrains.exposed:exposed-jdbc:0.45.0")
    implementation("org.jetbrains.exposed:exposed-java-time:0.45.0")
    
    // JWT
    implementation("com.auth0:java-jwt:4.4.0")
    
    // Validation
    implementation("io.konform:konform:0.4.0")
    
    // Testing
    testImplementation("org.jetbrains.kotlin:kotlin-test")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
    testImplementation("io.mockk:mockk:1.13.8")
    testImplementation("io.kotest:kotest-runner-junit5:5.8.0")
    testImplementation("io.kotest:kotest-assertions-core:5.8.0")
    testImplementation("io.kotest:kotest-property:5.8.0")
}

tasks.withType<KotlinCompile> {
    kotlinOptions {
        freeCompilerArgs += "-Xjsr305=strict"
        jvmTarget = "17"
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}

tasks.shadowJar {
    archiveBaseName.set("app")
    archiveClassifier.set("")
    archiveVersion.set("")
    manifest {
        attributes["Main-Class"] = "com.example.ApplicationKt"
    }
}`;
  }

  protected generateGradleProperties(): string {
    return `kotlin.code.style=official
org.gradle.jvmargs=-Xmx2048m -XX:MaxPermSize=512m -XX:+HeapDumpOnOutOfMemoryError -Dfile.encoding=UTF-8
org.gradle.parallel=true
org.gradle.caching=true`;
  }

  protected generateSettingsGradle(): string {
    return `rootProject.name = "${this.options.name}"`;
  }

  protected generateGitignoreContent(): string {
    return `.gradle
build/
!gradle/wrapper/gradle-wrapper.jar
!**/src/main/**/build/
!**/src/test/**/build/

### STS ###
.apt_generated
.classpath
.factorypath
.project
.settings
.springBeans
.sts4-cache
bin/
!**/src/main/**/bin/
!**/src/test/**/bin/

### IntelliJ IDEA ###
.idea
*.iws
*.iml
*.ipr
out/
!**/src/main/**/out/
!**/src/test/**/out/

### NetBeans ###
/nbproject/private/
/nbbuild/
/dist/
/nbdist/
/.nb-gradle/

### VS Code ###
.vscode/

### macOS ###
.DS_Store

### Application ###
*.log
*.pid
*.seed
*.pid.lock
logs/
data/`;
  }

  protected generateDockerfile(): string {
    return `# Build stage
FROM gradle:8.5-jdk17 AS build
WORKDIR /app
COPY build.gradle.kts settings.gradle.kts gradle.properties ./
COPY gradle gradle
RUN gradle dependencies --no-daemon
COPY src ./src
RUN gradle shadowJar --no-daemon

# Runtime stage
FROM openjdk:17-slim
WORKDIR /app

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Copy built artifact
COPY --from=build /app/build/libs/app.jar ./app.jar

# Copy wait-for-it script for database readiness
COPY wait-for-it.sh ./
RUN chmod +x wait-for-it.sh

# Create necessary directories
RUN mkdir -p logs data && chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD curl -f http://localhost:8080/health || exit 1

# Run application
ENTRYPOINT ["java", "-jar", "app.jar"]`;
  }

  protected generateDockerCompose(): string {
    return `version: '3.8'

services:
  app:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=jdbc:postgresql://db:5432/\${DB_NAME:-app_db}
      - DATABASE_USER=\${DB_USER:-postgres}
      - DATABASE_PASSWORD=\${DB_PASSWORD:-postgres}
      - JWT_SECRET=\${JWT_SECRET:-your-secret-key-change-in-production}
      - LOG_LEVEL=\${LOG_LEVEL:-INFO}
    depends_on:
      db:
        condition: service_healthy
    volumes:
      - ./logs:/app/logs
      - ./data:/app/data
    networks:
      - app-network
    restart: unless-stopped

  db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_DB=\${DB_NAME:-app_db}
      - POSTGRES_USER=\${DB_USER:-postgres}
      - POSTGRES_PASSWORD=\${DB_PASSWORD:-postgres}
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - app-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    networks:
      - app-network
    command: redis-server --appendonly yes

volumes:
  postgres_data:
  redis_data:

networks:
  app-network:
    driver: bridge`;
  }

  protected generateWaitForItScript(): string {
    return `#!/usr/bin/env bash
# Wait for a service to be ready
# https://github.com/vishnubob/wait-for-it

set -e

TIMEOUT=15
QUIET=0
HOST=""
PORT=""

usage() {
  echo "Usage: $0 host:port [-t timeout] [-- command args]"
  exit 1
}

wait_for() {
  if [[ $TIMEOUT -gt 0 ]]; then
    echo "Waiting $TIMEOUT seconds for $HOST:$PORT..."
  else
    echo "Waiting for $HOST:$PORT without timeout..."
  fi
  
  start_ts=$(date +%s)
  while :; do
    if nc -z "$HOST" "$PORT" >/dev/null 2>&1; then
      end_ts=$(date +%s)
      echo "$HOST:$PORT is available after $((end_ts - start_ts)) seconds"
      break
    fi
    sleep 1
  done
  return 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    *:* )
      HOST=$(echo $1 | cut -d: -f1)
      PORT=$(echo $1 | cut -d: -f2)
      shift 1
      ;;
    -t)
      TIMEOUT="$2"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    *)
      usage
      ;;
  esac
done

if [[ -z "$HOST" || -z "$PORT" ]]; then
  usage
fi

wait_for

exec "$@"`;
  }

  protected generateReadmeContent(): string {
    return `# \\${this.options.name}

A Kotlin backend application built with \\${this.options.framework}.

## 🚀 Features

- **Modern Kotlin**: Leveraging coroutines, data classes, and extension functions
- **RESTful API**: Well-structured endpoints with proper HTTP methods
- **Authentication**: JWT-based authentication and authorization
- **Database**: PostgreSQL with Exposed ORM and migrations
- **Validation**: Request validation using Konform
- **Testing**: Comprehensive test suite with Kotest and MockK
- **Docker**: Containerized application with Docker Compose
- **Monitoring**: Health checks and metrics endpoints
- **Logging**: Structured logging with Kotlin Logging
- **Documentation**: API documentation with OpenAPI/Swagger

## 📋 Prerequisites

- JDK 17 or higher
- Gradle 8.5 or higher
- Docker and Docker Compose (optional)
- PostgreSQL 15+ (if running locally)

## 🛠️ Development Setup

### Local Development

1. Clone the repository:
   \`\`\`bash
   git clone <repository-url>
   cd \${this.options.name}
   \`\`\`

2. Set up environment variables:
   \`\`\`bash
   cp .env.example .env
   # Edit .env with your configuration
   \`\`\`

3. Run PostgreSQL (if not using Docker):
   \`\`\`bash
   # Using Docker
   docker run -d \\
     --name postgres \\
     -e POSTGRES_DB=app_db \\
     -e POSTGRES_USER=postgres \\
     -e POSTGRES_PASSWORD=postgres \\
     -p 5432:5432 \\
     postgres:16-alpine
   \`\`\`

4. Run the application:
   \`\`\`bash
   ./gradlew run
   \`\`\`

### Docker Development

1. Build and run with Docker Compose:
   \`\`\`bash
   docker-compose up --build
   \`\`\`

2. The application will be available at \`http://localhost:8080\`

## 🧪 Testing

Run all tests:
\`\`\`bash
./gradlew test
\`\`\`

Run tests with coverage:
\`\`\`bash
./gradlew test jacocoTestReport
\`\`\`

Run specific test class:
\`\`\`bash
./gradlew test --tests "com.example.UserServiceTest"
\`\`\`

## 📚 API Documentation

### Authentication

All authenticated endpoints require a JWT token in the Authorization header:
\`\`\`
Authorization: Bearer <token>
\`\`\`

### Endpoints

#### Health Check
\`\`\`
GET /health
\`\`\`

#### Authentication
\`\`\`
POST /api/auth/register
POST /api/auth/login
POST /api/auth/refresh
POST /api/auth/logout
\`\`\`

#### Users
\`\`\`
GET    /api/users        # Get all users (admin only)
GET    /api/users/:id    # Get user by ID
PUT    /api/users/:id    # Update user
DELETE /api/users/:id    # Delete user (admin only)
GET    /api/users/me     # Get current user
\`\`\`

## 🏗️ Project Structure

\`\`\`
src/
├── main/
│   ├── kotlin/
│   │   └── com/example/
│   │       ├── Application.kt         # Main application entry
│   │       ├── config/               # Configuration classes
│   │       ├── controllers/          # REST controllers
│   │       ├── services/             # Business logic
│   │       ├── repositories/         # Data access layer
│   │       ├── models/               # Domain models
│   │       ├── dto/                  # Data transfer objects
│   │       ├── middleware/           # Middleware components
│   │       ├── exceptions/           # Custom exceptions
│   │       └── utils/                # Utility classes
│   └── resources/
│       ├── application.yml           # Application configuration
│       ├── logback.xml              # Logging configuration
│       └── db/migration/            # Database migrations
└── test/
    └── kotlin/
        └── com/example/             # Test classes
\`\`\`

## 🚀 Deployment

### Building for Production

1. Build the JAR:
   \`\`\`bash
   ./gradlew shadowJar
   \`\`\`

2. The JAR will be in \`build/libs/app.jar\`

### Docker Deployment

1. Build the Docker image:
   \`\`\`bash
   docker build -t \${this.options.name} .
   \`\`\`

2. Run the container:
   \`\`\`bash
   docker run -d \\
     -p 8080:8080 \\
     -e DATABASE_URL=jdbc:postgresql://db:5432/app_db \\
     -e DATABASE_USER=postgres \\
     -e DATABASE_PASSWORD=postgres \\
     -e JWT_SECRET=your-secret-key \\
     \${this.options.name}
   \`\`\`

## 🔧 Configuration

Configuration is managed through environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| \`SERVER_PORT\` | Server port | 8080 |
| \`DATABASE_URL\` | PostgreSQL connection URL | jdbc:postgresql://localhost:5432/app_db |
| \`DATABASE_USER\` | Database username | postgres |
| \`DATABASE_PASSWORD\` | Database password | postgres |
| \`JWT_SECRET\` | JWT signing secret | change-me |
| \`JWT_EXPIRATION\` | JWT expiration time | 86400 |
| \`LOG_LEVEL\` | Logging level | INFO |
| \`CORS_ALLOWED_ORIGINS\` | CORS allowed origins | * |

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.`;
  }

  protected generateEnvExample(): string {
    return `# Server Configuration
SERVER_PORT=8080
SERVER_HOST=0.0.0.0

# Database Configuration
DATABASE_URL=jdbc:postgresql://localhost:5432/app_db
DATABASE_USER=postgres
DATABASE_PASSWORD=postgres
DATABASE_MAX_POOL_SIZE=10

# JWT Configuration
JWT_SECRET=your-secret-key-change-in-production
JWT_EXPIRATION=86400
JWT_REFRESH_EXPIRATION=604800

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/app.log

# CORS
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
CORS_ALLOWED_METHODS=GET,POST,PUT,DELETE,OPTIONS
CORS_ALLOWED_HEADERS=*
CORS_ALLOW_CREDENTIALS=true

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60

# Environment
NODE_ENV=development`;
  }

  protected generateCommonModels(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/kotlin/com/example/models/User.kt',
        content: `package com.example.models

import org.jetbrains.exposed.dao.id.IntIdTable
import org.jetbrains.exposed.sql.javatime.timestamp
import java.time.Instant

object Users : IntIdTable() {
    val email = varchar("email", 255).uniqueIndex()
    val password = varchar("password", 255)
    val name = varchar("name", 255)
    val role = varchar("role", 50).default("user")
    val isActive = bool("is_active").default(true)
    val createdAt = timestamp("created_at").default(Instant.now())
    val updatedAt = timestamp("updated_at").default(Instant.now())
}

data class User(
    val id: Int,
    val email: String,
    val password: String,
    val name: String,
    val role: String,
    val isActive: Boolean,
    val createdAt: Instant,
    val updatedAt: Instant
)

enum class UserRole {
    USER,
    ADMIN,
    MODERATOR
}`
      },
      {
        path: 'src/main/kotlin/com/example/dto/UserDto.kt',
        content: `package com.example.dto

import kotlinx.serialization.Serializable
import java.time.Instant

@Serializable
data class CreateUserRequest(
    val email: String,
    val password: String,
    val name: String
)

@Serializable
data class UpdateUserRequest(
    val name: String? = null,
    val email: String? = null,
    val password: String? = null
)

@Serializable
data class LoginRequest(
    val email: String,
    val password: String
)

@Serializable
data class UserResponse(
    val id: Int,
    val email: String,
    val name: String,
    val role: String,
    val isActive: Boolean,
    val createdAt: String,
    val updatedAt: String
)

@Serializable
data class AuthResponse(
    val token: String,
    val refreshToken: String,
    val user: UserResponse
)

@Serializable
data class RefreshTokenRequest(
    val refreshToken: String
)

@Serializable
data class MessageResponse(
    val message: String
)`
      }
    ];
  }

  protected generateCommonUtils(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/kotlin/com/example/utils/JwtUtils.kt',
        content: `package com.example.utils

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.DecodedJWT
import com.example.models.User
import java.util.*

class JwtUtils(private val secret: String, private val expirationTime: Long) {
    private val algorithm = Algorithm.HMAC256(secret)
    private val verifier: JWTVerifier = JWT.require(algorithm).build()

    fun generateToken(user: User): String {
        return JWT.create()
            .withSubject(user.id.toString())
            .withClaim("email", user.email)
            .withClaim("role", user.role)
            .withExpiresAt(Date(System.currentTimeMillis() + expirationTime * 1000))
            .withIssuedAt(Date())
            .sign(algorithm)
    }

    fun generateRefreshToken(user: User): String {
        return JWT.create()
            .withSubject(user.id.toString())
            .withExpiresAt(Date(System.currentTimeMillis() + expirationTime * 7 * 1000))
            .withIssuedAt(Date())
            .sign(algorithm)
    }

    fun verifyToken(token: String): DecodedJWT? {
        return try {
            verifier.verify(token)
        } catch (e: JWTVerificationException) {
            null
        }
    }

    fun getUserIdFromToken(token: String): Int? {
        return verifyToken(token)?.subject?.toIntOrNull()
    }

    fun getRoleFromToken(token: String): String? {
        return verifyToken(token)?.getClaim("role")?.asString()
    }
}`
      },
      {
        path: 'src/main/kotlin/com/example/utils/PasswordUtils.kt',
        content: `package com.example.utils

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

object PasswordUtils {
    private const val SALT_LENGTH = 32
    private const val ITERATIONS = 10000
    private const val KEY_LENGTH = 256

    fun hashPassword(password: String): String {
        val salt = generateSalt()
        val hash = pbkdf2(password, salt, ITERATIONS, KEY_LENGTH)
        return "$ITERATIONS:\${Base64.getEncoder().encodeToString(salt)}:\${Base64.getEncoder().encodeToString(hash)}"
    }

    fun verifyPassword(password: String, storedHash: String): Boolean {
        val parts = storedHash.split(":")
        if (parts.size != 3) return false
        
        val iterations = parts[0].toIntOrNull() ?: return false
        val salt = Base64.getDecoder().decode(parts[1])
        val hash = Base64.getDecoder().decode(parts[2])
        
        val testHash = pbkdf2(password, salt, iterations, hash.size * 8)
        return hash.contentEquals(testHash)
    }

    private fun generateSalt(): ByteArray {
        val random = SecureRandom()
        val salt = ByteArray(SALT_LENGTH)
        random.nextBytes(salt)
        return salt
    }

    private fun pbkdf2(password: String, salt: ByteArray, iterations: Int, keyLength: Int): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        var hash = password.toByteArray() + salt
        
        repeat(iterations) {
            hash = digest.digest(hash)
        }
        
        return hash.take(keyLength / 8).toByteArray()
    }
}`
      },
      {
        path: 'src/main/kotlin/com/example/utils/ValidationUtils.kt',
        content: `package com.example.utils

import io.konform.validation.Validation
import io.konform.validation.jsonschema.minLength
import io.konform.validation.jsonschema.pattern

object ValidationUtils {
    val emailRegex = "^[A-Za-z0-9+_.-]+@([A-Za-z0-9.-]+\\.[A-Za-z]{2,})$".toRegex()
    
    fun isValidEmail(email: String): Boolean {
        return emailRegex.matches(email)
    }
    
    fun isValidPassword(password: String): Boolean {
        return password.length >= 8 && 
               password.any { it.isUpperCase() } &&
               password.any { it.isLowerCase() } &&
               password.any { it.isDigit() }
    }
    
    val userValidation = Validation<CreateUserRequest> {
        CreateUserRequest::email {
            pattern(emailRegex.pattern) hint "Invalid email format"
        }
        CreateUserRequest::password {
            minLength(8) hint "Password must be at least 8 characters"
        }
        CreateUserRequest::name {
            minLength(2) hint "Name must be at least 2 characters"
        }
    }
}`
      }
    ];
  }

  protected generateCommonMiddleware(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/kotlin/com/example/middleware/AuthMiddleware.kt',
        content: `package com.example.middleware

import com.example.services.UserService
import com.example.utils.JwtUtils
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.http.*

class AuthMiddleware(
    private val jwtUtils: JwtUtils,
    private val userService: UserService
) {
    suspend fun authenticate(call: ApplicationCall): User? {
        val token = call.request.headers["Authorization"]
            ?.removePrefix("Bearer ")
            ?: return null
            
        val userId = jwtUtils.getUserIdFromToken(token) ?: return null
        return userService.findById(userId)
    }
    
    suspend fun requireAuth(call: ApplicationCall, block: suspend (User) -> Unit) {
        val user = authenticate(call)
        if (user == null) {
            call.respond(HttpStatusCode.Unauthorized, mapOf("error" to "Unauthorized"))
            return
        }
        block(user)
    }
    
    suspend fun requireRole(call: ApplicationCall, role: String, block: suspend (User) -> Unit) {
        requireAuth(call) { user ->
            if (user.role != role) {
                call.respond(HttpStatusCode.Forbidden, mapOf("error" to "Insufficient permissions"))
                return@requireAuth
            }
            block(user)
        }
    }
}`
      },
      {
        path: 'src/main/kotlin/com/example/middleware/ErrorHandler.kt',
        content: `package com.example.middleware

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.http.*
import mu.KotlinLogging
import kotlinx.serialization.Serializable

private val logger = KotlinLogging.logger {}

@Serializable
data class ErrorResponse(
    val error: String,
    val message: String,
    val timestamp: Long = System.currentTimeMillis()
)

class ValidationException(message: String) : Exception(message)
class NotFoundException(message: String) : Exception(message)
class UnauthorizedException(message: String) : Exception(message)
class ForbiddenException(message: String) : Exception(message)

suspend fun handleError(call: ApplicationCall, cause: Throwable) {
    logger.error(cause) { "Error handling request: \${call.request.uri}" }
    
    val (status, error) = when (cause) {
        is ValidationException -> HttpStatusCode.BadRequest to ErrorResponse(
            error = "Validation Error",
            message = cause.message ?: "Invalid request data"
        )
        is NotFoundException -> HttpStatusCode.NotFound to ErrorResponse(
            error = "Not Found",
            message = cause.message ?: "Resource not found"
        )
        is UnauthorizedException -> HttpStatusCode.Unauthorized to ErrorResponse(
            error = "Unauthorized",
            message = cause.message ?: "Authentication required"
        )
        is ForbiddenException -> HttpStatusCode.Forbidden to ErrorResponse(
            error = "Forbidden",
            message = cause.message ?: "Insufficient permissions"
        )
        else -> HttpStatusCode.InternalServerError to ErrorResponse(
            error = "Internal Server Error",
            message = "An unexpected error occurred"
        )
    }
    
    call.respond(status, error)
}`
      }
    ];
  }

  async generate(projectPath: string, options: any): Promise<void> {
    this.options = options;
    await super.generate(projectPath, options);
  }
  
  async generateTemplate(projectPath: string): Promise<void> {
    // Create directory structure
    const directories = [
      'src/main/kotlin/com/example/config',
      'src/main/kotlin/com/example/controllers',
      'src/main/kotlin/com/example/services',
      'src/main/kotlin/com/example/repositories',
      'src/main/kotlin/com/example/models',
      'src/main/kotlin/com/example/dto',
      'src/main/kotlin/com/example/middleware',
      'src/main/kotlin/com/example/utils',
      'src/main/kotlin/com/example/exceptions',
      'src/main/resources/db/migration',
      'src/test/kotlin/com/example',
      'gradle/wrapper',
      'logs',
      'data'
    ];

    for (const dir of directories) {
      await fs.mkdir(path.join(projectPath, dir), { recursive: true });
    }

    // Generate base files
    const files = [
      { path: 'build.gradle.kts', content: this.generateBuildGradle() },
      { path: 'gradle.properties', content: this.generateGradleProperties() },
      { path: 'settings.gradle.kts', content: this.generateSettingsGradle() },
      { path: '.gitignore', content: this.generateGitignoreContent() },
      { path: 'Dockerfile', content: this.generateDockerfile() },
      { path: 'docker-compose.yml', content: this.generateDockerCompose() },
      { path: 'wait-for-it.sh', content: this.generateWaitForItScript() },
      { path: 'README.md', content: this.generateReadmeContent() },
      { path: '.env.example', content: this.generateEnvExample() },
      
      // Main application file
      { path: 'src/main/kotlin/com/example/Application.kt', content: this.generateMainFile() },
      
      // Routing
      { path: 'src/main/kotlin/com/example/routes/Routes.kt', content: this.generateRoutingFile() },
      
      // Common models and utils
      ...this.generateCommonModels(),
      ...this.generateCommonUtils(),
      ...this.generateCommonMiddleware(),
      
      // Framework-specific files
      ...this.generateServiceFiles(),
      ...this.generateRepositoryFiles(),
      ...this.generateModelFiles(),
      ...this.generateConfigFiles(),
      ...this.generateMiddlewareFiles(),
      ...this.generateTestFiles()
    ];

    // Write all files
    for (const file of files) {
      const fullPath = path.join(projectPath, file.path);
      // Ensure parent directory exists
      await fs.mkdir(path.dirname(fullPath), { recursive: true });
      await fs.writeFile(fullPath, file.content);
    }

    // Generate Gradle wrapper
    await this.generateGradleWrapper(projectPath);
  }

  private async generateGradleWrapper(projectPath: string): Promise<void> {
    const wrapperFiles = [
      {
        path: 'gradle/wrapper/gradle-wrapper.properties',
        content: `distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionUrl=https://services.gradle.org/distributions/gradle-8.5-bin.zip
networkTimeout=10000
validateDistributionUrl=true
zipStoreBase=GRADLE_USER_HOME
zipStorePath=wrapper/dists`
      },
      {
        path: 'gradlew',
        content: `#!/bin/sh
# Gradle wrapper script
exec gradle "\$@"`
      },
      {
        path: 'gradlew.bat',
        content: `@echo off
gradle %*`
      }
    ];

    for (const file of wrapperFiles) {
      const fullPath = path.join(projectPath, file.path);
      // Ensure parent directory exists
      await fs.mkdir(path.dirname(fullPath), { recursive: true });
      await fs.writeFile(fullPath, file.content);
    }

    // Make gradlew executable
    await fs.chmod(path.join(projectPath, 'gradlew'), 0o755);
  }
  
  // Implement abstract methods from BackendTemplateGenerator
  protected async generateLanguageFiles(projectPath: string, options: any): Promise<void> {
    await this.generateTemplate(projectPath);
  }
  
  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Framework-specific files are generated in generateTemplate
  }
  
  protected async generateTestStructure(projectPath: string, options: any): Promise<void> {
    // Test files are generated in generateTemplate
  }
  
  protected async generateHealthCheck(projectPath: string): Promise<void> {
    // Health check is part of controller files
  }
  
  protected async generateAPIDocs(projectPath: string): Promise<void> {
    // API docs are generated as part of the framework
  }
  
  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    await fs.writeFile(path.join(projectPath, 'Dockerfile'), this.generateDockerfile());
    await fs.writeFile(path.join(projectPath, 'docker-compose.yml'), this.generateDockerCompose());
  }
  
  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    await fs.writeFile(path.join(projectPath, 'README.md'), this.generateReadmeContent());
  }
  
  protected getLanguageSpecificIgnorePatterns(): string[] {
    return [
      '.gradle/',
      'build/',
      '.idea/',
      '*.iml',
      '*.ipr',
      '*.iws',
      'out/',
      '.kotlin/'
    ];
  }
  
  protected getLanguagePrerequisites(): string {
    return 'JDK 17 or higher, Gradle 8.5+';
  }
  
  protected getInstallCommand(): string {
    return './gradlew dependencies';
  }
  
  protected getDevCommand(): string {
    return './gradlew run';
  }
  
  protected getProdCommand(): string {
    return 'java -jar build/libs/app.jar';
  }
  
  protected getTestCommand(): string {
    return './gradlew test';
  }
  
  protected getCoverageCommand(): string {
    return './gradlew test jacocoTestReport';
  }
  
  protected getLintCommand(): string {
    return './gradlew ktlintCheck';
  }
  
  protected getBuildCommand(): string {
    return './gradlew build';
  }
  
  protected getSetupAction(): string {
    return 'chmod +x gradlew && ./gradlew dependencies';
  }
}