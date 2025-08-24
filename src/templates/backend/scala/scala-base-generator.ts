import { BackendTemplateGenerator } from '../shared/backend-template-generator';
import * as path from 'path';
import { promises as fs } from 'fs';

export abstract class ScalaBackendGenerator extends BackendTemplateGenerator {
  protected options: any;
  
  constructor() {
    super({
      language: 'Scala',
      framework: 'Scala Framework',
      packageManager: 'sbt',
      buildTool: 'sbt',
      testFramework: 'scalatest',
      features: [
        'Type-safe programming',
        'Functional programming',
        'Actor model support',
        'JWT Authentication',
        'PostgreSQL Database',
        'Redis Cache',
        'Docker Support',
        'Reactive Streams',
        'JSON handling with Circe'
      ],
      dependencies: {},
      devDependencies: {},
      scripts: {
        dev: 'sbt run',
        build: 'sbt compile',
        test: 'sbt test',
        clean: 'sbt clean'
      }
    });
  }
  
  async generate(projectPath: string, options: any): Promise<void> {
    this.options = options;
    await super.generate(projectPath, options);
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
  
  protected generateBuildSbt(): string {
    const dependencies = this.getFrameworkDependencies();
    const depList = Object.entries(dependencies)
      .map(([nameWithGroup, version]) => {
        const [groupId, artifactId] = nameWithGroup.split('::');
        return `    "${groupId}" %% "${artifactId}" % "${version}"`;
      })
      .join(',\n');

    return `ThisBuild / version := "0.1.0-SNAPSHOT"
ThisBuild / scalaVersion := "2.13.12"

lazy val root = (project in file("."))
  .settings(
    name := "${this.options?.name || 'scala-service'}",
    libraryDependencies ++= Seq(
${depList},
      
      // Common Scala dependencies
      "org.typelevel" %% "cats-core" % "2.10.0",
      "org.typelevel" %% "cats-effect" % "3.5.2",
      "io.circe" %% "circe-core" % "0.14.6",
      "io.circe" %% "circe-generic" % "0.14.6",
      "io.circe" %% "circe-parser" % "0.14.6",
      
      // Database
      "org.postgresql" % "postgresql" % "42.7.1",
      "com.zaxxer" % "HikariCP" % "5.1.0",
      "org.tpolecat" %% "doobie-core" % "1.0.0-RC4",
      "org.tpolecat" %% "doobie-postgres" % "1.0.0-RC4",
      "org.tpolecat" %% "doobie-hikari" % "1.0.0-RC4",
      
      // Logging
      "ch.qos.logback" % "logback-classic" % "1.4.14",
      "org.typelevel" %% "log4cats-slf4j" % "2.6.0",
      
      // Configuration
      "com.github.pureconfig" %% "pureconfig" % "0.17.4",
      
      // JWT
      "com.github.jwt-scala" %% "jwt-circe" % "9.4.4",
      
      // Testing
      "org.scalatest" %% "scalatest" % "3.2.17" % Test,
      "org.scalatestplus" %% "mockito-4-6" % "3.2.15.0" % Test,
      "org.typelevel" %% "cats-effect-testing-scalatest" % "1.5.0" % Test
    ),
    
    // Compiler options
    scalacOptions ++= Seq(
      "-deprecation",
      "-encoding", "UTF-8",
      "-language:higherKinds",
      "-language:postfixOps",
      "-feature",
      "-Xfatal-warnings"
    ),
    
    // Assembly plugin for fat JAR
    assembly / mainClass := Some("com.example.Main"),
    assembly / assemblyJarName := "app.jar",
    assembly / assemblyMergeStrategy := {
      case "META-INF/services/org.apache.spark.sql.sources.DataSourceRegister" => MergeStrategy.concat
      case PathList("META-INF", xs @ _*) => MergeStrategy.discard
      case _ => MergeStrategy.first
    }
  )

// Add assembly plugin
addSbtPlugin("com.eed3si9n" % "sbt-assembly" % "2.1.3")
`;
  }

  protected generateProjectBuild(): string {
    return `addSbtPlugin("com.eed3si9n" % "sbt-assembly" % "2.1.3")
addSbtPlugin("org.scalameta" % "sbt-scalafmt" % "2.5.2")
addSbtPlugin("ch.epfl.scala" % "sbt-scalafix" % "0.11.1")
addSbtPlugin("org.scoverage" % "sbt-scoverage" % "2.0.9")`;
  }

  protected generateGitignoreContent(): string {
    return `# sbt
target/
project/project/
project/target/
.bsp/

# IDE
.idea/
.vscode/
*.swp
*.swo

# Scala
*.class
*.log
.cache
.history
.lib/

# OS
.DS_Store
Thumbs.db

# Application
*.pid
*.seed
*.pid.lock
logs/
data/
.env
.env.local

# Docker
docker-compose.override.yml

# Metals
.metals/
.bloop/
metals.sbt`;
  }

  protected generateDockerfile(): string {
    return `# Build stage
FROM hseeberger/scala-sbt:17.0.2_1.8.2_2.13.10 AS build
WORKDIR /app

# Copy build files
COPY build.sbt .
COPY project/ project/
RUN sbt update

# Copy source and build
COPY src/ src/
RUN sbt assembly

# Runtime stage
FROM openjdk:17-slim
WORKDIR /app

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Copy built artifact
COPY --from=build /app/target/scala-*/app.jar ./app.jar

# Copy wait-for-it script
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
    return `# \${this.options?.name || 'scala-service'}

A Scala backend application built with \${this.options?.framework || 'Scala Framework'}.

## 🚀 Features

- **Modern Scala**: Leveraging functional programming, type safety, and immutability
- **RESTful API**: Well-structured endpoints with proper HTTP methods
- **Authentication**: JWT-based authentication and authorization
- **Database**: PostgreSQL with Doobie functional database access
- **Functional Programming**: Built with Cats Effect and functional principles
- **JSON Handling**: Circe for type-safe JSON encoding/decoding
- **Testing**: Comprehensive test suite with ScalaTest
- **Docker**: Containerized application with Docker Compose
- **Monitoring**: Health checks and metrics endpoints
- **Logging**: Structured logging with Log4Cats
- **Configuration**: Type-safe configuration with PureConfig

## 📋 Prerequisites

- JDK 17 or higher
- SBT 1.8+ 
- Docker and Docker Compose (optional)
- PostgreSQL 15+ (if running locally)

## 🛠️ Development Setup

### Local Development

1. Clone the repository:
   \`\`\`bash
   git clone <repository-url>
   cd \${this.options?.name || 'scala-service'}
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
   sbt run
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
sbt test
\`\`\`

Run tests with coverage:
\`\`\`bash
sbt coverage test coverageReport
\`\`\`

Run specific test class:
\`\`\`bash
sbt "testOnly com.example.UserServiceSpec"
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
│   ├── scala/
│   │   └── com/example/
│   │       ├── Main.scala              # Application entry point
│   │       ├── config/                 # Configuration classes
│   │       ├── controllers/            # HTTP route handlers
│   │       ├── services/               # Business logic
│   │       ├── repositories/           # Data access layer
│   │       ├── models/                 # Domain models
│   │       ├── dto/                    # Data transfer objects
│   │       ├── middleware/             # Middleware components
│   │       └── utils/                  # Utility classes
│   └── resources/
│       ├── application.conf            # Application configuration
│       └── logback.xml                 # Logging configuration
└── test/
    └── scala/
        └── com/example/                # Test classes
\`\`\`

## 🚀 Deployment

### Building for Production

1. Build the JAR:
   \`\`\`bash
   sbt assembly
   \`\`\`

2. The JAR will be in \`target/scala-*/app.jar\`

### Docker Deployment

1. Build the Docker image:
   \`\`\`bash
   docker build -t \${this.options?.name || 'scala-service'} .
   \`\`\`

2. Run the container:
   \`\`\`bash
   docker run -d \\
     -p 8080:8080 \\
     -e DATABASE_URL=jdbc:postgresql://db:5432/app_db \\
     -e DATABASE_USER=postgres \\
     -e DATABASE_PASSWORD=postgres \\
     -e JWT_SECRET=your-secret-key \\
     \${this.options?.name || 'scala-service'}
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

# Environment
ENVIRONMENT=development`;
  }

  protected generateCommonModels(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/scala/com/example/models/User.scala',
        content: `package com.example.models

import java.time.Instant
import io.circe.{Decoder, Encoder}
import io.circe.generic.semiauto._

case class User(
  id: Int,
  email: String,
  password: String,
  name: String,
  role: String,
  isActive: Boolean,
  createdAt: Instant,
  updatedAt: Instant
)

object User {
  implicit val userEncoder: Encoder[User] = deriveEncoder
  implicit val userDecoder: Decoder[User] = deriveDecoder
}

case class UserResponse(
  id: Int,
  email: String,
  name: String,
  role: String,
  isActive: Boolean,
  createdAt: String,
  updatedAt: String
)

object UserResponse {
  implicit val userResponseEncoder: Encoder[UserResponse] = deriveEncoder
  implicit val userResponseDecoder: Decoder[UserResponse] = deriveDecoder
  
  def fromUser(user: User): UserResponse = UserResponse(
    id = user.id,
    email = user.email,
    name = user.name,
    role = user.role,
    isActive = user.isActive,
    createdAt = user.createdAt.toString,
    updatedAt = user.updatedAt.toString
  )
}

sealed trait UserRole
object UserRole {
  case object User extends UserRole
  case object Admin extends UserRole
  case object Moderator extends UserRole
  
  def fromString(role: String): Option[UserRole] = role.toLowerCase match {
    case "user" => Some(User)
    case "admin" => Some(Admin)
    case "moderator" => Some(Moderator)
    case _ => None
  }
  
  def toString(role: UserRole): String = role match {
    case User => "user"
    case Admin => "admin"
    case Moderator => "moderator"
  }
}`
      },
      {
        path: 'src/main/scala/com/example/dto/AuthDto.scala',
        content: `package com.example.dto

import com.example.models.UserResponse
import io.circe.{Decoder, Encoder}
import io.circe.generic.semiauto._

case class CreateUserRequest(
  email: String,
  password: String,
  name: String
)

object CreateUserRequest {
  implicit val createUserRequestEncoder: Encoder[CreateUserRequest] = deriveEncoder
  implicit val createUserRequestDecoder: Decoder[CreateUserRequest] = deriveDecoder
}

case class UpdateUserRequest(
  name: Option[String] = None,
  email: Option[String] = None,
  password: Option[String] = None
)

object UpdateUserRequest {
  implicit val updateUserRequestEncoder: Encoder[UpdateUserRequest] = deriveEncoder
  implicit val updateUserRequestDecoder: Decoder[UpdateUserRequest] = deriveDecoder
}

case class LoginRequest(
  email: String,
  password: String
)

object LoginRequest {
  implicit val loginRequestEncoder: Encoder[LoginRequest] = deriveEncoder
  implicit val loginRequestDecoder: Decoder[LoginRequest] = deriveDecoder
}

case class AuthResponse(
  token: String,
  refreshToken: String,
  user: UserResponse
)

object AuthResponse {
  implicit val authResponseEncoder: Encoder[AuthResponse] = deriveEncoder
  implicit val authResponseDecoder: Decoder[AuthResponse] = deriveDecoder
}

case class RefreshTokenRequest(
  refreshToken: String
)

object RefreshTokenRequest {
  implicit val refreshTokenRequestEncoder: Encoder[RefreshTokenRequest] = deriveEncoder
  implicit val refreshTokenRequestDecoder: Decoder[RefreshTokenRequest] = deriveDecoder
}

case class MessageResponse(
  message: String
)

object MessageResponse {
  implicit val messageResponseEncoder: Encoder[MessageResponse] = deriveEncoder
  implicit val messageResponseDecoder: Decoder[MessageResponse] = deriveDecoder
}

case class ErrorResponse(
  error: String,
  message: String,
  timestamp: Long = System.currentTimeMillis()
)

object ErrorResponse {
  implicit val errorResponseEncoder: Encoder[ErrorResponse] = deriveEncoder
  implicit val errorResponseDecoder: Decoder[ErrorResponse] = deriveDecoder
}`
      }
    ];
  }

  protected generateCommonUtils(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/scala/com/example/utils/JwtUtils.scala',
        content: `package com.example.utils

import cats.effect.Sync
import cats.implicits._
import com.example.models.User
import pdi.jwt.{Jwt, JwtAlgorithm, JwtCirce, JwtClaim}
import io.circe.syntax._
import io.circe.parser._
import java.time.Instant
import scala.util.{Success, Failure, Try}

class JwtUtils[F[_]: Sync](secret: String, expirationTime: Long) {
  
  private val algorithm = JwtAlgorithm.HS256
  
  def generateToken(user: User): F[String] = Sync[F].delay {
    val claims = JwtClaim(
      subject = Some(user.id.toString),
      expiration = Some(Instant.now.getEpochSecond + expirationTime),
      issuedAt = Some(Instant.now.getEpochSecond)
    ).+("email", user.email)
     .+("role", user.role)
    
    Jwt.encode(claims, secret, algorithm)
  }
  
  def generateRefreshToken(user: User): F[String] = Sync[F].delay {
    val claims = JwtClaim(
      subject = Some(user.id.toString),
      expiration = Some(Instant.now.getEpochSecond + expirationTime * 7),
      issuedAt = Some(Instant.now.getEpochSecond)
    )
    
    Jwt.encode(claims, secret, algorithm)
  }
  
  def verifyToken(token: String): F[Option[JwtClaim]] = Sync[F].delay {
    Jwt.decode(token, secret, Seq(algorithm)) match {
      case Success(claim) => Some(claim)
      case Failure(_) => None
    }
  }
  
  def getUserIdFromToken(token: String): F[Option[Int]] = 
    verifyToken(token).map(_.flatMap(_.subject.flatMap(_.toIntOption)))
  
  def getRoleFromToken(token: String): F[Option[String]] = 
    verifyToken(token).map(_.flatMap(claim => 
      for {
        content <- claim.content.toOption
        json <- parse(content).toOption
        role <- json.hcursor.get[String]("role").toOption
      } yield role
    ))
}`
      },
      {
        path: 'src/main/scala/com/example/utils/PasswordUtils.scala',
        content: `package com.example.utils

import cats.effect.Sync
import cats.implicits._
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.spec.PBEKeySpec
import javax.crypto.SecretKeyFactory

object PasswordUtils {
  
  private val SaltLength = 32
  private val Iterations = 10000
  private val KeyLength = 256
  private val Algorithm = "PBKDF2WithHmacSHA256"
  
  def hashPassword[F[_]: Sync](password: String): F[String] = Sync[F].delay {
    val salt = generateSalt()
    val hash = pbkdf2(password, salt, Iterations, KeyLength)
    s"${'$'}Iterations:${'$'}{Base64.getEncoder.encodeToString(salt)}:${'$'}{Base64.getEncoder.encodeToString(hash)}"
  }
  
  def verifyPassword[F[_]: Sync](password: String, storedHash: String): F[Boolean] = Sync[F].delay {
    storedHash.split(":") match {
      case Array(iterationsStr, saltStr, hashStr) =>
        for {
          iterations <- iterationsStr.toIntOption
          salt <- scala.util.Try(Base64.getDecoder.decode(saltStr)).toOption
          hash <- scala.util.Try(Base64.getDecoder.decode(hashStr)).toOption
        } yield {
          val testHash = pbkdf2(password, salt, iterations, hash.length * 8)
          java.util.Arrays.equals(hash, testHash)
        }
      case _ => Some(false)
    }.getOrElse(false)
  }
  
  private def generateSalt(): Array[Byte] = {
    val random = new SecureRandom()
    val salt = new Array[Byte](SaltLength)
    random.nextBytes(salt)
    salt
  }
  
  private def pbkdf2(password: String, salt: Array[Byte], iterations: Int, keyLength: Int): Array[Byte] = {
    val spec = new PBEKeySpec(password.toCharArray, salt, iterations, keyLength)
    val factory = SecretKeyFactory.getInstance(Algorithm)
    factory.generateSecret(spec).getEncoded
  }
}`
      },
      {
        path: 'src/main/scala/com/example/utils/ValidationUtils.scala',
        content: `package com.example.utils

import cats.effect.Sync
import cats.implicits._
import com.example.dto.CreateUserRequest
import scala.util.matching.Regex

object ValidationUtils {
  
  private val EmailRegex: Regex = "^[A-Za-z0-9+_.-]+@([A-Za-z0-9.-]+\\.[A-Za-z]{2,})$".r
  
  def isValidEmail(email: String): Boolean = EmailRegex.matches(email)
  
  def isValidPassword(password: String): Boolean = {
    password.length >= 8 &&
    password.exists(_.isUpper) &&
    password.exists(_.isLower) &&
    password.exists(_.isDigit)
  }
  
  def validateCreateUserRequest[F[_]: Sync](request: CreateUserRequest): F[Either[String, CreateUserRequest]] = 
    Sync[F].delay {
      if (!isValidEmail(request.email)) {
        Left("Invalid email format")
      } else if (!isValidPassword(request.password)) {
        Left("Password must be at least 8 characters with uppercase, lowercase, and digit")
      } else if (request.name.length < 2) {
        Left("Name must be at least 2 characters")
      } else {
        Right(request)
      }
    }
}`
      }
    ];
  }

  protected generateCommonMiddleware(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/scala/com/example/middleware/ErrorHandler.scala',
        content: `package com.example.middleware

import cats.effect.Sync
import cats.implicits._
import com.example.dto.ErrorResponse
import org.typelevel.log4cats.Logger
import io.circe.syntax._

sealed trait AppError extends Throwable {
  def message: String
  def statusCode: Int
}

case class ValidationError(message: String) extends AppError {
  val statusCode: Int = 400
}

case class NotFoundError(message: String) extends AppError {
  val statusCode: Int = 404
}

case class UnauthorizedError(message: String) extends AppError {
  val statusCode: Int = 401
}

case class ForbiddenError(message: String) extends AppError {
  val statusCode: Int = 403
}

case class InternalServerError(message: String) extends AppError {
  val statusCode: Int = 500
}

object ErrorHandler {
  
  def handleError[F[_]: Sync: Logger](error: Throwable): F[ErrorResponse] = {
    val appError = error match {
      case e: AppError => e
      case _ => InternalServerError("An unexpected error occurred")
    }
    
    for {
      _ <- Logger[F].error(error)(s"Error handling request: \${appError.message}")
      response = ErrorResponse(
        error = appError.getClass.getSimpleName.replace("Error", "").replace("$", ""),
        message = appError.message
      )
    } yield response
  }
}`
      }
    ];
  }

  async generateTemplate(projectPath: string): Promise<void> {
    // Create directory structure
    const directories = [
      'src/main/scala/com/example/config',
      'src/main/scala/com/example/controllers',
      'src/main/scala/com/example/services',
      'src/main/scala/com/example/repositories',
      'src/main/scala/com/example/models',
      'src/main/scala/com/example/dto',
      'src/main/scala/com/example/middleware',
      'src/main/scala/com/example/utils',
      'src/main/resources',
      'src/test/scala/com/example',
      'project',
      'logs',
      'data'
    ];

    for (const dir of directories) {
      await fs.mkdir(path.join(projectPath, dir), { recursive: true });
    }

    // Generate base files
    const files = [
      { path: 'build.sbt', content: this.generateBuildSbt() },
      { path: 'project/plugins.sbt', content: this.generateProjectBuild() },
      { path: '.gitignore', content: this.generateGitignoreContent() },
      { path: 'Dockerfile', content: this.generateDockerfile() },
      { path: 'docker-compose.yml', content: this.generateDockerCompose() },
      { path: 'wait-for-it.sh', content: this.generateWaitForItScript() },
      { path: 'README.md', content: this.generateReadmeContent() },
      { path: '.env.example', content: this.generateEnvExample() },
      
      // Main application file
      { path: 'src/main/scala/com/example/Main.scala', content: this.generateMainFile() },
      
      // Routing
      { path: 'src/main/scala/com/example/routes/Routes.scala', content: this.generateRoutingFile() },
      
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
      'target/',
      'project/project/',
      'project/target/',
      '.bsp/',
      '.idea/',
      '.metals/',
      '.bloop/',
      '*.class',
      '*.log'
    ];
  }
  
  protected getLanguagePrerequisites(): string {
    return 'JDK 17 or higher, SBT 1.8+';
  }
  
  protected getInstallCommand(): string {
    return 'sbt update';
  }
  
  protected getDevCommand(): string {
    return 'sbt run';
  }
  
  protected getProdCommand(): string {
    return 'java -jar target/scala-*/app.jar';
  }
  
  protected getTestCommand(): string {
    return 'sbt test';
  }
  
  protected getCoverageCommand(): string {
    return 'sbt coverage test coverageReport';
  }
  
  protected getLintCommand(): string {
    return 'sbt scalafmtCheck';
  }
  
  protected getBuildCommand(): string {
    return 'sbt assembly';
  }
  
  protected getSetupAction(): string {
    return 'sbt update';
  }
}