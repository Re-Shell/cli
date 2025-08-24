import { BackendTemplateGenerator, BackendTemplateConfig } from '../shared/backend-template-generator';
import * as path from 'path';
import { promises as fs } from 'fs';

export abstract class RustBackendGenerator extends BackendTemplateGenerator {
  protected options: any;
  
  constructor(framework: string) {
    const config: BackendTemplateConfig = {
      language: 'Rust',
      framework: framework,
      packageManager: 'cargo',
      buildTool: 'cargo',
      testFramework: 'built-in',
      features: [
        'Async/await support',
        'Type safety',
        'Memory safety',
        'Zero-cost abstractions',
        'JWT authentication',
        'PostgreSQL with SQLx',
        'Redis support',
        'Docker support',
        'OpenAPI documentation',
        'WebSocket support',
        'Graceful shutdown',
        'Error handling',
        'Logging with tracing',
        'Environment configuration'
      ],
      dependencies: {},
      devDependencies: {},
      scripts: {
        dev: 'cargo watch -x run',
        build: 'cargo build --release',
        start: './target/release/{{projectName}}',
        test: 'cargo test',
        lint: 'cargo clippy -- -D warnings',
        format: 'cargo fmt',
        'db:migrate': 'sqlx migrate run',
        'db:create': 'sqlx database create',
        'db:drop': 'sqlx database drop'
      },
      dockerConfig: {
        baseImage: 'rust:1.75-slim',
        workDir: '/app',
        exposedPorts: [8080],
        buildSteps: [
          'RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*',
          'COPY Cargo.toml Cargo.lock ./',
          'RUN cargo fetch',
          'COPY . .',
          'RUN cargo build --release'
        ],
        runCommand: './target/release/{{projectName}}',
        multistage: true
      },
      envVars: {
        APP_NAME: '{{projectName}}',
        APP_ENV: 'development',
        APP_PORT: '8080',
        DATABASE_URL: 'postgres://user:password@localhost:5432/{{projectName}}_dev',
        REDIS_URL: 'redis://127.0.0.1:6379',
        JWT_SECRET: 'your-secret-key-change-in-production',
        JWT_EXPIRATION: '86400',
        LOG_LEVEL: 'debug',
        RUST_LOG: '{{projectName}}=debug,tower_http=debug',
        SMTP_HOST: 'smtp.gmail.com',
        SMTP_PORT: '587',
        SMTP_USER: '',
        SMTP_PASS: '',
        SMTP_FROM: 'noreply@example.com'
      }
    };
    super(config);
  }
  
  // Framework-specific abstract methods
  protected abstract getFrameworkDependencies(): Record<string, string>;
  protected abstract generateMainFile(): string;
  protected abstract generateServerFile(): string;
  protected abstract generateRouterFile(): string;
  protected abstract generateHandlerFiles(): { path: string; content: string }[];
  protected abstract generateMiddlewareFiles(): { path: string; content: string }[];
  protected abstract generateConfigFile(): string;
  protected abstract generateErrorFile(): string;
  
  // Implementation of required abstract methods from BackendTemplateGenerator
  protected async generateLanguageFiles(projectPath: string, options: any): Promise<void> {
    this.options = options;
    
    // Generate Cargo.toml
    await this.writeFile(path.join(projectPath, 'Cargo.toml'), this.generateCargoToml());
    
    // Generate .env.example
    await this.writeFile(path.join(projectPath, '.env.example'), this.generateEnvironmentFile());
    
    // Generate sqlx-data.json for offline compile-time verification
    await this.writeFile(path.join(projectPath, 'sqlx-data.json'), '{}');
    
    // Generate rust-toolchain.toml
    await this.writeFile(path.join(projectPath, 'rust-toolchain.toml'), this.generateRustToolchain());
    
    // Generate clippy.toml
    await this.writeFile(path.join(projectPath, 'clippy.toml'), this.generateClippyConfig());
    
    // Generate rustfmt.toml
    await this.writeFile(path.join(projectPath, 'rustfmt.toml'), this.generateRustfmtConfig());
  }
  
  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Generate main.rs
    await this.writeFile(path.join(projectPath, 'src/main.rs'), this.generateMainFile());
    
    // Generate server module
    await this.writeFile(path.join(projectPath, 'src/server.rs'), this.generateServerFile());
    
    // Generate config module
    await this.writeFile(path.join(projectPath, 'src/config.rs'), this.generateConfigFile());
    
    // Generate error handling
    await this.writeFile(path.join(projectPath, 'src/error.rs'), this.generateErrorFile());
    
    // Generate router
    await this.writeFile(path.join(projectPath, 'src/router.rs'), this.generateRouterFile());
    
    // Generate handlers
    const handlerFiles = this.generateHandlerFiles();
    for (const file of handlerFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate middleware
    const middlewareFiles = this.generateMiddlewareFiles();
    for (const file of middlewareFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate models
    const modelFiles = this.generateModelFiles();
    for (const file of modelFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate services
    const serviceFiles = this.generateServiceFiles();
    for (const file of serviceFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate database module
    await this.writeFile(path.join(projectPath, 'src/db.rs'), this.generateDatabaseFile());
    
    // Generate utils
    const utilFiles = this.generateUtilFiles();
    for (const file of utilFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
  }
  
  protected async generateTestStructure(projectPath: string, options: any): Promise<void> {
    // Create tests directory
    await fs.mkdir(path.join(projectPath, 'tests'), { recursive: true });
    
    // Generate integration tests
    await this.writeFile(
      path.join(projectPath, 'tests/health_check.rs'),
      this.generateHealthCheckTest()
    );
    
    await this.writeFile(
      path.join(projectPath, 'tests/auth.rs'),
      this.generateAuthTest()
    );
    
    // Generate test helpers
    await this.writeFile(
      path.join(projectPath, 'tests/helpers/mod.rs'),
      this.generateTestHelpers()
    );
  }
  
  protected async generateHealthCheck(projectPath: string): Promise<void> {
    // Health check is included in handlers
  }
  
  protected async generateAPIDocs(projectPath: string): Promise<void> {
    // API docs are generated via OpenAPI annotations in the code
  }
  
  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    await this.writeFile(path.join(projectPath, 'Dockerfile'), this.generateDockerfile());
    await this.writeFile(path.join(projectPath, 'docker-compose.yml'), this.generateDockerCompose());
    await this.writeFile(path.join(projectPath, '.dockerignore'), this.generateDockerIgnore());
  }
  
  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    await this.writeFile(path.join(projectPath, 'README.md'), this.generateReadmeContent());
  }
  
  // Helper method implementations
  protected getLanguageSpecificIgnorePatterns(): string[] {
    return [
      'target/',
      'Cargo.lock',
      '**/*.rs.bk',
      '*.pdb',
      '.env',
      '*.log',
      'sqlx-data.json'
    ];
  }
  
  protected getLanguagePrerequisites(): string {
    return 'Rust 1.75+ and Cargo';
  }
  
  protected getInstallCommand(): string {
    return 'cargo build';
  }
  
  protected getDevCommand(): string {
    return 'cargo watch -x run';
  }
  
  protected getProdCommand(): string {
    return './target/release/' + (this.options?.name || 'app');
  }
  
  protected getTestCommand(): string {
    return 'cargo test';
  }
  
  protected getCoverageCommand(): string {
    return 'cargo tarpaulin';
  }
  
  protected getLintCommand(): string {
    return 'cargo clippy -- -D warnings';
  }
  
  protected getBuildCommand(): string {
    return 'cargo build --release';
  }
  
  protected getSetupAction(): string {
    return 'actions-rs/toolchain@v1\\n      with:\\n        toolchain: stable\\n        override: true\\n        components: rustfmt, clippy';
  }
  
  // Rust-specific file generators
  private generateCargoToml(): string {
    const deps = this.getFrameworkDependencies();
    const dependencies = Object.entries(deps)
      .map(([name, version]) => `${name} = ${version}`)
      .join('\n');
      
    return `[package]
name = "${this.options.name || 'backend-service'}"
version = "0.1.0"
edition = "2021"

[dependencies]
${dependencies}
tokio = { version = "1", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
sqlx = { version = "0.7", features = ["runtime-tokio-rustls", "postgres", "uuid", "time", "migrate"] }
redis = { version = "0.24", features = ["tokio-comp", "connection-manager"] }
uuid = { version = "1.6", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
jsonwebtoken = "9"
bcrypt = "0.15"
validator = { version = "0.16", features = ["derive"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
tracing-appender = "0.2"
dotenv = "0.15"
thiserror = "1.0"
anyhow = "1.0"
once_cell = "1.19"
lettre = { version = "0.11", features = ["tokio1-native-tls", "builder"] }

[dev-dependencies]
reqwest = { version = "0.11", features = ["json"] }
fake = "2.9"
rand = "0.8"

[profile.release]
opt-level = 3
lto = true
codegen-units = 1`;
  }
  
  private generateEnvironmentFile(): string {
    return Object.entries(this.config.envVars || {})
      .map(([key, value]) => `${key}=${value}`)
      .join('\n');
  }
  
  private generateRustToolchain(): string {
    return `[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]`;
  }
  
  private generateClippyConfig(): string {
    return `msrv = "1.75.0"

# Warn on all pedantic lints
warn-by-default = true`;
  }
  
  private generateRustfmtConfig(): string {
    return `edition = "2021"
max_width = 100
use_field_init_shorthand = true
use_try_shorthand = true`;
  }
  
  protected generateModelFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/models/user.rs',
        content: `use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub first_name: String,
    pub last_name: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 6))]
    pub password: String,
    #[validate(length(min = 1))]
    pub first_name: String,
    #[validate(length(min = 1))]
    pub last_name: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        UserResponse {
            id: user.id,
            email: user.email,
            first_name: user.first_name,
            last_name: user.last_name,
            is_active: user.is_active,
            created_at: user.created_at,
        }
    }
}`
      },
      {
        path: 'src/models/token.rs',
        content: `use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AppError;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub email: String,
    pub exp: i64,
    pub iat: i64,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

impl Claims {
    pub fn new(user_id: Uuid, email: String, expiration_hours: i64) -> Self {
        let now = Utc::now();
        let exp = (now + Duration::hours(expiration_hours)).timestamp();
        
        Self {
            sub: user_id,
            email,
            exp,
            iat: now.timestamp(),
        }
    }
}

pub fn encode_jwt(claims: &Claims, secret: &str) -> Result<String, AppError> {
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
    .map_err(|_| AppError::TokenCreation)
}

pub fn decode_jwt(token: &str, secret: &str) -> Result<Claims, AppError> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|_| AppError::InvalidToken)
}`
      },
      {
        path: 'src/models/mod.rs',
        content: `pub mod user;
pub mod token;

pub use user::*;
pub use token::*;`
      }
    ];
  }
  
  protected generateServiceFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/services/user_service.rs',
        content: `use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    error::AppError,
    models::{User, RegisterRequest},
};

pub struct UserService {
    pool: PgPool,
}

impl UserService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    
    pub async fn create_user(&self, req: &RegisterRequest) -> Result<User, AppError> {
        // Check if user exists
        let existing = sqlx::query!("SELECT id FROM users WHERE email = $1", req.email)
            .fetch_optional(&self.pool)
            .await?;
            
        if existing.is_some() {
            return Err(AppError::UserAlreadyExists);
        }
        
        // Hash password
        let password_hash = bcrypt::hash(&req.password, bcrypt::DEFAULT_COST)
            .map_err(|_| AppError::InternalServerError)?;
        
        // Create user
        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (email, password_hash, first_name, last_name)
            VALUES ($1, $2, $3, $4)
            RETURNING *
            "#,
            req.email,
            password_hash,
            req.first_name,
            req.last_name
        )
        .fetch_one(&self.pool)
        .await?;
        
        Ok(user)
    }
    
    pub async fn get_user_by_email(&self, email: &str) -> Result<User, AppError> {
        let user = sqlx::query_as!(
            User,
            "SELECT * FROM users WHERE email = $1",
            email
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AppError::UserNotFound)?;
        
        Ok(user)
    }
    
    pub async fn get_user_by_id(&self, id: Uuid) -> Result<User, AppError> {
        let user = sqlx::query_as!(
            User,
            "SELECT * FROM users WHERE id = $1",
            id
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(AppError::UserNotFound)?;
        
        Ok(user)
    }
    
    pub async fn verify_password(&self, user: &User, password: &str) -> Result<(), AppError> {
        bcrypt::verify(password, &user.password_hash)
            .map_err(|_| AppError::InvalidCredentials)?
            .then_some(())
            .ok_or(AppError::InvalidCredentials)
    }
}`
      },
      {
        path: 'src/services/auth_service.rs',
        content: `use crate::{
    config::Config,
    error::AppError,
    models::{Claims, LoginRequest, RegisterRequest, TokenResponse, User, encode_jwt},
    services::UserService,
};

pub struct AuthService {
    user_service: UserService,
    config: Config,
}

impl AuthService {
    pub fn new(user_service: UserService, config: Config) -> Self {
        Self { user_service, config }
    }
    
    pub async fn register(&self, req: &RegisterRequest) -> Result<TokenResponse, AppError> {
        let user = self.user_service.create_user(req).await?;
        self.generate_token(&user)
    }
    
    pub async fn login(&self, req: &LoginRequest) -> Result<TokenResponse, AppError> {
        let user = self.user_service.get_user_by_email(&req.email).await?;
        
        if !user.is_active {
            return Err(AppError::UserNotActive);
        }
        
        self.user_service.verify_password(&user, &req.password).await?;
        self.generate_token(&user)
    }
    
    fn generate_token(&self, user: &User) -> Result<TokenResponse, AppError> {
        let claims = Claims::new(
            user.id,
            user.email.clone(),
            self.config.jwt_expiration,
        );
        
        let token = encode_jwt(&claims, &self.config.jwt_secret)?;
        
        Ok(TokenResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.jwt_expiration * 3600,
        })
    }
}`
      },
      {
        path: 'src/services/mod.rs',
        content: `pub mod user_service;
pub mod auth_service;

pub use user_service::UserService;
pub use auth_service::AuthService;`
      }
    ];
  }
  
  private generateDatabaseFile(): string {
    return `use sqlx::{
    postgres::{PgPool, PgPoolOptions},
    Error,
};
use std::time::Duration;

use crate::config::Config;

pub async fn create_pool(config: &Config) -> Result<PgPool, Error> {
    PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&config.database_url)
        .await
}

pub async fn run_migrations(pool: &PgPool) -> Result<(), Error> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await?;
    Ok(())
}`;
  }
  
  protected generateUtilFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/utils/mod.rs',
        content: `pub mod password;

pub use password::*;`
      },
      {
        path: 'src/utils/password.rs',
        content: `use bcrypt::{hash, verify, DEFAULT_COST};

pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash(password, DEFAULT_COST)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hash)
}`
      }
    ];
  }
  
  private generateDockerfile(): string {
    return `# Build stage
FROM rust:1.75-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \\
    pkg-config \\
    libssl-dev \\
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

# Copy source code
COPY . .

# Build application
RUN touch src/main.rs
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \\
    ca-certificates \\
    libssl3 \\
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/${this.options.name || 'app'} ./app

# Create non-root user
RUN useradd -m -u 1001 -s /bin/bash app
USER app

EXPOSE 8080

CMD ["./app"]`;
  }
  
  private generateDockerCompose(): string {
    return `version: '3.8'

services:
  app:
    build: .
    container_name: ${this.options.name || 'app'}-api
    ports:
      - "\${APP_PORT:-8080}:8080"
    environment:
      - DATABASE_URL=postgres://\${DB_USER:-user}:\${DB_PASSWORD:-password}@postgres:5432/\${DB_NAME:-app}
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis
    restart: unless-stopped
    networks:
      - app-network

  postgres:
    image: postgres:16-alpine
    container_name: ${this.options.name || 'app'}-db
    environment:
      - POSTGRES_USER=\${DB_USER:-user}
      - POSTGRES_PASSWORD=\${DB_PASSWORD:-password}
      - POSTGRES_DB=\${DB_NAME:-app}
    ports:
      - "\${DB_PORT:-5432}:5432"
    volumes:
      - postgres-data:/var/lib/postgresql/data
    restart: unless-stopped
    networks:
      - app-network

  redis:
    image: redis:7-alpine
    container_name: ${this.options.name || 'app'}-redis
    command: redis-server --appendonly yes
    ports:
      - "\${REDIS_PORT:-6379}:6379"
    volumes:
      - redis-data:/data
    restart: unless-stopped
    networks:
      - app-network

volumes:
  postgres-data:
  redis-data:

networks:
  app-network:
    driver: bridge`;
  }
  
  private generateDockerIgnore(): string {
    return `target/
Cargo.lock
.env
.git/
.gitignore
README.md
*.log`;
  }
  
  protected generateReadmeContent(): string {
    return `# ${this.options.name || 'Rust Backend Service'}

A ${this.config.framework} web service built with Rust.

## Features

${this.config.features.map(f => `- ${f}`).join('\n')}

## Prerequisites

- Rust 1.75+
- PostgreSQL
- Redis
- SQLx CLI: \`cargo install sqlx-cli\`
- cargo-watch (optional): \`cargo install cargo-watch\`

## Getting Started

1. Clone the repository
2. Copy \`.env.example\` to \`.env\` and update values
3. Create database: \`sqlx database create\`
4. Run migrations: \`sqlx migrate run\`
5. Run the server: \`cargo run\`

## Development

\`\`\`bash
# Run with auto-reload
cargo watch -x run

# Run tests
cargo test

# Run linter
cargo clippy -- -D warnings

# Format code
cargo fmt
\`\`\`

## Docker

\`\`\`bash
# Build and run with docker-compose
docker-compose up

# Build image
docker build -t ${this.options.name || 'app'} .

# Run container
docker run -p 8080:8080 ${this.options.name || 'app'}
\`\`\`

## API Documentation

Once running, visit:
- Swagger UI: http://localhost:8080/swagger-ui/
- OpenAPI JSON: http://localhost:8080/api-doc/openapi.json

## Project Structure

\`\`\`
src/
├── config.rs       # Configuration
├── db.rs          # Database setup
├── error.rs       # Error handling
├── main.rs        # Entry point
├── router.rs      # Routes
├── server.rs      # Server setup
├── handlers/      # Request handlers
├── middleware/    # Middleware
├── models/        # Data models
├── services/      # Business logic
└── utils/         # Utilities
\`\`\`

## Environment Variables

${Object.entries(this.config.envVars || {})
  .map(([key, value]) => `- \`${key}\`: ${value.includes('password') || value.includes('secret') ? 'Your ' + key.toLowerCase().replace(/_/g, ' ') : value}`)
  .join('\n')}

## License

MIT`;
  }
  
  private generateHealthCheckTest(): string {
    return `use ${this.options.name?.replace(/-/g, '_') || 'app'}::create_app;
use sqlx::PgPool;

#[tokio::test]
async fn health_check_works() {
    let app = spawn_app().await;
    
    let client = reqwest::Client::new();
    let response = client
        .get(&format!("{}/health", &app.address))
        .send()
        .await
        .expect("Failed to execute request.");
        
    assert!(response.status().is_success());
    assert_eq!(Some(0), response.content_length());
}

async fn spawn_app() -> TestApp {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("Failed to bind random port");
    let port = listener.local_addr().unwrap().port();
    let address = format!("http://127.0.0.1:{}", port);
    
    let configuration = get_configuration().expect("Failed to read configuration.");
    let connection_pool = configure_database(&configuration.database).await;
    
    let server = run(listener, connection_pool.clone())
        .expect("Failed to bind address");
    let _ = tokio::spawn(server);
    
    TestApp {
        address,
        db_pool: connection_pool,
    }
}

struct TestApp {
    pub address: String,
    pub db_pool: PgPool,
}`;
  }
  
  private generateAuthTest(): string {
    return `use ${this.options.name?.replace(/-/g, '_') || 'app'}::models::{LoginRequest, RegisterRequest};

#[tokio::test]
async fn register_returns_200_for_valid_form_data() {
    let app = spawn_app().await;
    let client = reqwest::Client::new();
    
    let body = RegisterRequest {
        email: "test@example.com".to_string(),
        password: "password123".to_string(),
        first_name: "Test".to_string(),
        last_name: "User".to_string(),
    };
    
    let response = client
        .post(&format!("{}/api/v1/auth/register", &app.address))
        .json(&body)
        .send()
        .await
        .expect("Failed to execute request.");
        
    assert_eq!(201, response.status().as_u16());
    
    let saved = sqlx::query!("SELECT email FROM users WHERE email = $1", body.email)
        .fetch_one(&app.db_pool)
        .await
        .expect("Failed to fetch saved user.");
        
    assert_eq!(saved.email, body.email);
}

#[tokio::test]
async fn register_returns_400_when_data_is_invalid() {
    let app = spawn_app().await;
    let client = reqwest::Client::new();
    
    let test_cases = vec![
        (serde_json::json!({"email": "test@example.com"}), "missing password"),
        (serde_json::json!({"password": "password123"}), "missing email"),
        (serde_json::json!({"email": "not-an-email", "password": "password123"}), "invalid email"),
    ];
    
    for (invalid_body, error_message) in test_cases {
        let response = client
            .post(&format!("{}/api/v1/auth/register", &app.address))
            .json(&invalid_body)
            .send()
            .await
            .expect("Failed to execute request.");
            
        assert_eq!(
            400,
            response.status().as_u16(),
            "The API did not fail with 400 Bad Request when the payload was {}.",
            error_message
        );
    }
}`;
  }
  
  private generateTestHelpers(): string {
    return `use once_cell::sync::Lazy;
use sqlx::{Connection, Executor, PgConnection, PgPool};
use uuid::Uuid;

use ${this.options.name?.replace(/-/g, '_') || 'app'}::{
    config::{Config, DatabaseSettings},
    telemetry::{get_subscriber, init_subscriber},
};

static TRACING: Lazy<()> = Lazy::new(|| {
    let default_filter_level = "info".to_string();
    let subscriber_name = "test".to_string();
    
    if std::env::var("TEST_LOG").is_ok() {
        let subscriber = get_subscriber(subscriber_name, default_filter_level, std::io::stdout);
        init_subscriber(subscriber);
    } else {
        let subscriber = get_subscriber(subscriber_name, default_filter_level, std::io::sink);
        init_subscriber(subscriber);
    }
});

pub struct TestApp {
    pub address: String,
    pub db_pool: PgPool,
}

pub async fn spawn_app() -> TestApp {
    Lazy::force(&TRACING);
    
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("Failed to bind random port");
    let port = listener.local_addr().unwrap().port();
    let address = format!("http://127.0.0.1:{}", port);
    
    let mut configuration = Config::new().expect("Failed to read configuration.");
    configuration.database.database_name = Uuid::new_v4().to_string();
    let connection_pool = configure_database(&configuration.database).await;
    
    let server = run(listener, connection_pool.clone())
        .expect("Failed to bind address");
    let _ = tokio::spawn(server);
    
    TestApp {
        address,
        db_pool: connection_pool,
    }
}

async fn configure_database(config: &DatabaseSettings) -> PgPool {
    let mut connection = PgConnection::connect_with(&config.without_db())
        .await
        .expect("Failed to connect to Postgres");
        
    connection
        .execute(format!(r#"CREATE DATABASE "{}""#, config.database_name).as_str())
        .await
        .expect("Failed to create database.");
        
    let connection_pool = PgPool::connect_with(config.with_db())
        .await
        .expect("Failed to connect to Postgres.");
        
    sqlx::migrate!("./migrations")
        .run(&connection_pool)
        .await
        .expect("Failed to migrate the database");
        
    connection_pool
}`;
  }
  
  protected async writeFile(filePath: string, content: string): Promise<void> {
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, content, 'utf-8');
  }
}
