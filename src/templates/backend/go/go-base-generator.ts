import { BackendTemplateGenerator, BackendTemplateConfig } from '../shared/backend-template-generator';
import * as path from 'path';
import { promises as fs } from 'fs';

export abstract class GoBackendGenerator extends BackendTemplateGenerator {
  protected options: any;
  
  constructor(framework: string) {
    const config: BackendTemplateConfig = {
      language: 'Go',
      framework: framework,
      packageManager: 'go',
      buildTool: 'go',
      testFramework: 'testing',
      features: [
        'RESTful API',
        'JWT Authentication',
        'PostgreSQL Database',
        'Redis Cache',
        'Docker Support',
        'Swagger Documentation',
        'WebSocket Support',
        'File Upload',
        'Email Service',
        'Rate Limiting',
        'Graceful Shutdown',
        'Middleware Chain',
        'Database Migrations',
        'Unit & Integration Tests'
      ],
      dependencies: {},
      devDependencies: {},
      scripts: {
        dev: 'air',
        build: 'go build -o bin/server cmd/server/main.go',
        start: './bin/server',
        test: 'go test ./...',
        'test:coverage': 'go test -cover ./...',
        lint: 'golangci-lint run',
        format: 'go fmt ./...',
        'db:migrate': 'migrate -path ./migrations -database $DATABASE_URL up',
        'db:rollback': 'migrate -path ./migrations -database $DATABASE_URL down 1',
        'swagger:generate': 'swag init -g cmd/server/main.go'
      },
      dockerConfig: {
        baseImage: 'golang:1.21-alpine',
        workDir: '/app',
        exposedPorts: [8080],
        buildSteps: [
          'RUN apk add --no-cache git',
          'COPY go.mod go.sum ./',
          'RUN go mod download',
          'COPY . .',
          'RUN go build -o server cmd/server/main.go'
        ],
        runCommand: './server',
        multistage: true
      },
      envVars: {
        APP_NAME: '{{projectName}}',
        APP_ENV: 'development',
        APP_PORT: '8080',
        DATABASE_URL: 'postgres://user:password@localhost:5432/{{projectName}}_dev?sslmode=disable',
        REDIS_URL: 'redis://localhost:6379/0',
        JWT_SECRET: 'your-secret-key-change-in-production',
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
  protected abstract getFrameworkDependencies(): string[];
  protected abstract generateMainFile(): string;
  protected abstract generateRouteFiles(): { path: string; content: string }[];
  protected abstract generateHandlerFiles(): { path: string; content: string }[];
  protected abstract generateMiddlewareFiles(): { path: string; content: string }[];
  protected abstract generateConfigFile(): string;
  protected abstract generateServerFile(): string;
  
  // Implementation of required abstract methods from BackendTemplateGenerator
  protected async generateLanguageFiles(projectPath: string, options: any): Promise<void> {
    this.options = options;
    
    // Generate go.mod
    await this.writeFile(path.join(projectPath, 'go.mod'), this.generateGoMod());
    
    // Generate go.sum (will be populated by go mod download)
    await this.writeFile(path.join(projectPath, 'go.sum'), '');
    
    // Generate .air.toml for hot reload
    await this.writeFile(path.join(projectPath, '.air.toml'), this.generateAirConfig());
    
    // Generate Makefile
    await this.writeFile(path.join(projectPath, 'Makefile'), this.generateMakefile());
  }
  
  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Generate main application file
    await this.writeFile(path.join(projectPath, 'cmd/server/main.go'), this.generateMainFile());
    
    // Generate server file
    await this.writeFile(path.join(projectPath, 'internal/server/server.go'), this.generateServerFile());
    
    // Generate config file
    await this.writeFile(path.join(projectPath, 'internal/config/config.go'), this.generateConfigFile());
    
    // Generate route files
    const routeFiles = this.generateRouteFiles();
    for (const file of routeFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate handler files
    const handlerFiles = this.generateHandlerFiles();
    for (const file of handlerFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate middleware files
    const middlewareFiles = this.generateMiddlewareFiles();
    for (const file of middlewareFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate model files
    const modelFiles = this.generateModelFiles();
    for (const file of modelFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate service files
    const serviceFiles = this.generateServiceFiles();
    for (const file of serviceFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate database files
    const dbFiles = this.generateDatabaseFiles();
    for (const file of dbFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
    
    // Generate util files
    const utilFiles = this.generateUtilFiles();
    for (const file of utilFiles) {
      await this.writeFile(path.join(projectPath, file.path), file.content);
    }
  }
  
  protected async generateTestStructure(projectPath: string, options: any): Promise<void> {
    // Generate test files for handlers
    await this.writeFile(
      path.join(projectPath, 'internal/handlers/auth_handler_test.go'),
      this.generateAuthHandlerTest()
    );
    
    // Generate test files for services
    await this.writeFile(
      path.join(projectPath, 'internal/services/user_service_test.go'),
      this.generateUserServiceTest()
    );
    
    // Generate test utilities
    await this.writeFile(
      path.join(projectPath, 'internal/test/helpers.go'),
      this.generateTestHelpers()
    );
  }
  
  protected async generateHealthCheck(projectPath: string): Promise<void> {
    await this.writeFile(
      path.join(projectPath, 'internal/handlers/health_handler.go'),
      this.generateHealthHandler()
    );
  }
  
  // Helper method implementations
  private generateGoMod(): string {
    const projectName = this.options.name || 'backend-service';
    const deps = this.getFrameworkDependencies();
    
    return `module ${projectName}

go 1.21

require (
${deps.map(dep => `\t${dep}`).join('\n')}
)`;
  }
  
  private generateAirConfig(): string {
    return `root = "."
testdata_dir = "testdata"
tmp_dir = "tmp"

[build]
  args_bin = []
  bin = "./tmp/main"
  cmd = "go build -o ./tmp/main ./cmd/server"
  delay = 1000
  exclude_dir = ["assets", "tmp", "vendor", "testdata"]
  exclude_file = []
  exclude_regex = ["_test.go"]
  exclude_unchanged = false
  follow_symlink = false
  full_bin = ""
  include_dir = []
  include_ext = ["go", "tpl", "tmpl", "html"]
  kill_delay = "0s"
  log = "build-errors.log"
  send_interrupt = false
  stop_on_error = true

[color]
  app = ""
  build = "yellow"
  main = "magenta"
  runner = "green"
  watcher = "cyan"

[log]
  time = false

[misc]
  clean_on_exit = false

[screen]
  clear_on_rebuild = false`;
  }
  
  private generateMakefile(): string {
    return `.PHONY: dev build test lint format migrate rollback swagger clean

# Development
dev:
\tair

# Build
build:
\tgo build -o bin/server cmd/server/main.go

# Run
run: build
\t./bin/server

# Test
test:
\tgo test ./...

test-coverage:
\tgo test -cover ./...

# Lint
lint:
\tgolangci-lint run

# Format
format:
\tgo fmt ./...

# Database
migrate:
\tmigrate -path ./migrations -database $(DATABASE_URL) up

rollback:
\tmigrate -path ./migrations -database $(DATABASE_URL) down 1

# Swagger
swagger:
\tswag init -g cmd/server/main.go

# Docker
docker-build:
\tdocker build -t $(APP_NAME) .

docker-run:
\tdocker run -p 8080:8080 $(APP_NAME)

# Clean
clean:
\trm -rf bin/ tmp/`;
  }
  
  protected generateModelFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'internal/models/user.go',
        content: `package models

import (
\t"time"
\t"gorm.io/gorm"
)

type User struct {
\tID           uint           \`json:"id" gorm:"primaryKey"\`
\tEmail        string         \`json:"email" gorm:"uniqueIndex;not null"\`
\tPasswordHash string         \`json:"-" gorm:"not null"\`
\tFirstName    string         \`json:"first_name"\`
\tLastName     string         \`json:"last_name"\`
\tIsActive     bool           \`json:"is_active" gorm:"default:true"\`
\tCreatedAt    time.Time      \`json:"created_at"\`
\tUpdatedAt    time.Time      \`json:"updated_at"\`
\tDeletedAt    gorm.DeletedAt \`json:"-" gorm:"index"\`
}

type LoginRequest struct {
\tEmail    string \`json:"email" binding:"required,email"\`
\tPassword string \`json:"password" binding:"required,min=6"\`
}

type RegisterRequest struct {
\tEmail     string \`json:"email" binding:"required,email"\`
\tPassword  string \`json:"password" binding:"required,min=6"\`
\tFirstName string \`json:"first_name" binding:"required"\`
\tLastName  string \`json:"last_name" binding:"required"\`
}

type UserResponse struct {
\tID        uint      \`json:"id"\`
\tEmail     string    \`json:"email"\`
\tFirstName string    \`json:"first_name"\`
\tLastName  string    \`json:"last_name"\`
\tIsActive  bool      \`json:"is_active"\`
\tCreatedAt time.Time \`json:"created_at"\`
}`
      },
      {
        path: 'internal/models/token.go',
        content: `package models

import "github.com/golang-jwt/jwt/v5"

type TokenClaims struct {
\tUserID uint   \`json:"user_id"\`
\tEmail  string \`json:"email"\`
\tjwt.RegisteredClaims
}

type TokenResponse struct {
\tAccessToken string \`json:"access_token"\`
\tTokenType   string \`json:"token_type"\`
\tExpiresIn   int    \`json:"expires_in"\`
}`
      }
    ];
  }
  
  protected generateServiceFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'internal/services/user_service.go',
        content: `package services

import (
\t"errors"
\t"golang.org/x/crypto/bcrypt"
\t"gorm.io/gorm"
\t"${this.options.name}/internal/models"
)

type UserService struct {
\tdb *gorm.DB
}

func NewUserService(db *gorm.DB) *UserService {
\treturn &UserService{db: db}
}

func (s *UserService) CreateUser(req *models.RegisterRequest) (*models.User, error) {
\t// Check if user exists
\tvar existingUser models.User
\tif err := s.db.Where("email = ?", req.Email).First(&existingUser).Error; err == nil {
\t\treturn nil, errors.New("user already exists")
\t}

\t// Hash password
\thashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
\tif err != nil {
\t\treturn nil, err
\t}

\t// Create user
\tuser := &models.User{
\t\tEmail:        req.Email,
\t\tPasswordHash: string(hashedPassword),
\t\tFirstName:    req.FirstName,
\t\tLastName:     req.LastName,
\t}

\tif err := s.db.Create(user).Error; err != nil {
\t\treturn nil, err
\t}

\treturn user, nil
}

func (s *UserService) GetUserByEmail(email string) (*models.User, error) {
\tvar user models.User
\tif err := s.db.Where("email = ?", email).First(&user).Error; err != nil {
\t\treturn nil, err
\t}
\treturn &user, nil
}

func (s *UserService) GetUserByID(id uint) (*models.User, error) {
\tvar user models.User
\tif err := s.db.First(&user, id).Error; err != nil {
\t\treturn nil, err
\t}
\treturn &user, nil
}

func (s *UserService) ValidatePassword(user *models.User, password string) error {
\treturn bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
}

func (s *UserService) UpdateUser(id uint, updates map[string]interface{}) (*models.User, error) {
\tvar user models.User
\tif err := s.db.First(&user, id).Error; err != nil {
\t\treturn nil, err
\t}

\tif err := s.db.Model(&user).Updates(updates).Error; err != nil {
\t\treturn nil, err
\t}

\treturn &user, nil
}

func (s *UserService) DeleteUser(id uint) error {
\treturn s.db.Delete(&models.User{}, id).Error
}`
      },
      {
        path: 'internal/services/auth_service.go',
        content: `package services

import (
\t"errors"
\t"time"
\t"github.com/golang-jwt/jwt/v5"
\t"${this.options.name}/internal/config"
\t"${this.options.name}/internal/models"
)

type AuthService struct {
\tuserService *UserService
\tconfig      *config.Config
}

func NewAuthService(userService *UserService, cfg *config.Config) *AuthService {
\treturn &AuthService{
\t\tuserService: userService,
\t\tconfig:      cfg,
\t}
}

func (s *AuthService) Login(req *models.LoginRequest) (*models.TokenResponse, error) {
\tuser, err := s.userService.GetUserByEmail(req.Email)
\tif err != nil {
\t\treturn nil, errors.New("invalid credentials")
\t}

\tif err := s.userService.ValidatePassword(user, req.Password); err != nil {
\t\treturn nil, errors.New("invalid credentials")
\t}

\tif !user.IsActive {
\t\treturn nil, errors.New("user account is disabled")
\t}

\treturn s.generateToken(user)
}

func (s *AuthService) Register(req *models.RegisterRequest) (*models.TokenResponse, error) {
\tuser, err := s.userService.CreateUser(req)
\tif err != nil {
\t\treturn nil, err
\t}

\treturn s.generateToken(user)
}

func (s *AuthService) generateToken(user *models.User) (*models.TokenResponse, error) {
\tclaims := &models.TokenClaims{
\t\tUserID: user.ID,
\t\tEmail:  user.Email,
\t\tRegisteredClaims: jwt.RegisteredClaims{
\t\t\tExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
\t\t\tIssuedAt:  jwt.NewNumericDate(time.Now()),
\t\t\tNotBefore: jwt.NewNumericDate(time.Now()),
\t\t},
\t}

\ttoken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
\ttokenString, err := token.SignedString([]byte(s.config.JWTSecret))
\tif err != nil {
\t\treturn nil, err
\t}

\treturn &models.TokenResponse{
\t\tAccessToken: tokenString,
\t\tTokenType:   "Bearer",
\t\tExpiresIn:   86400, // 24 hours
\t}, nil
}`
      }
    ];
  }
  
  protected generateDatabaseFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'internal/database/database.go',
        content: `package database

import (
\t"fmt"
\t"log"
\t"gorm.io/driver/postgres"
\t"gorm.io/gorm"
\t"gorm.io/gorm/logger"
\t"${this.options.name}/internal/config"
\t"${this.options.name}/internal/models"
)

func Initialize(cfg *config.Config) (*gorm.DB, error) {
\tvar logLevel logger.LogLevel
\tif cfg.AppEnv == "production" {
\t\tlogLevel = logger.Error
\t} else {
\t\tlogLevel = logger.Info
\t}

\tdb, err := gorm.Open(postgres.Open(cfg.DatabaseURL), &gorm.Config{
\t\tLogger: logger.Default.LogMode(logLevel),
\t})
\tif err != nil {
\t\treturn nil, fmt.Errorf("failed to connect to database: %w", err)
\t}

\t// Run migrations
\tif err := db.AutoMigrate(
\t\t&models.User{},
\t); err != nil {
\t\treturn nil, fmt.Errorf("failed to migrate database: %w", err)
\t}

\tlog.Println("Database connected and migrated successfully")
\treturn db, nil
}`
      },
      {
        path: 'internal/database/redis.go',
        content: `package database

import (
\t"context"
\t"github.com/redis/go-redis/v9"
\t"${this.options.name}/internal/config"
)

func InitializeRedis(cfg *config.Config) (*redis.Client, error) {
\topt, err := redis.ParseURL(cfg.RedisURL)
\tif err != nil {
\t\treturn nil, err
\t}

\tclient := redis.NewClient(opt)
\t
\t// Test connection
\tctx := context.Background()
\tif err := client.Ping(ctx).Err(); err != nil {
\t\treturn nil, err
\t}

\treturn client, nil
}`
      }
    ];
  }
  
  protected generateUtilFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'internal/utils/response.go',
        content: `package utils

import (
\t"net/http"
\t"github.com/gin-gonic/gin"
)

type ErrorResponse struct {
\tError   string \`json:"error"\`
\tMessage string \`json:"message,omitempty"\`
\tCode    string \`json:"code,omitempty"\`
}

type SuccessResponse struct {
\tData    interface{} \`json:"data,omitempty"\`
\tMessage string      \`json:"message,omitempty"\`
}

func RespondWithError(c *gin.Context, code int, message string) {
\tc.JSON(code, ErrorResponse{
\t\tError: http.StatusText(code),
\t\tMessage: message,
\t})
}

func RespondWithJSON(c *gin.Context, code int, data interface{}) {
\tc.JSON(code, SuccessResponse{
\t\tData: data,
\t})
}

func RespondWithMessage(c *gin.Context, code int, message string) {
\tc.JSON(code, SuccessResponse{
\t\tMessage: message,
\t})
}`
      },
      {
        path: 'internal/utils/validator.go',
        content: `package utils

import (
\t"regexp"
\t"strings"
)

var emailRegex = regexp.MustCompile(\`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$\`)

func IsValidEmail(email string) bool {
\treturn emailRegex.MatchString(strings.ToLower(email))
}

func IsValidPassword(password string) bool {
\treturn len(password) >= 6
}`
      }
    ];
  }
  
  private generateHealthHandler(): string {
    return `package handlers

import (
\t"net/http"
\t"time"
\t"github.com/gin-gonic/gin"
\t"gorm.io/gorm"
)

type HealthHandler struct {
\tdb *gorm.DB
}

func NewHealthHandler(db *gorm.DB) *HealthHandler {
\treturn &HealthHandler{db: db}
}

type HealthResponse struct {
\tStatus   string \`json:"status"\`
\tDatabase string \`json:"database"\`
\tUptime   string \`json:"uptime"\`
}

var startTime = time.Now()

func (h *HealthHandler) Check(c *gin.Context) {
\thealth := HealthResponse{
\t\tStatus: "healthy",
\t\tUptime: time.Since(startTime).String(),
\t}

\t// Check database connection
\tsqlDB, err := h.db.DB()
\tif err != nil {
\t\thealth.Database = "unhealthy"
\t\thealth.Status = "degraded"
\t} else if err := sqlDB.Ping(); err != nil {
\t\thealth.Database = "unhealthy"
\t\thealth.Status = "degraded"
\t} else {
\t\thealth.Database = "healthy"
\t}

\tif health.Status == "healthy" {
\t\tc.JSON(http.StatusOK, health)
\t} else {
\t\tc.JSON(http.StatusServiceUnavailable, health)
\t}
}`;
  }
  
  private generateAuthHandlerTest(): string {
    return `package handlers_test

import (
\t"bytes"
\t"encoding/json"
\t"net/http"
\t"net/http/httptest"
\t"testing"
\t"github.com/stretchr/testify/assert"
\t"${this.options.name}/internal/models"
)

func TestAuthHandler_Register(t *testing.T) {
\trouter := setupTestRouter()

\tt.Run("successful registration", func(t *testing.T) {
\t\treqBody := models.RegisterRequest{
\t\t\tEmail:     "test@example.com",
\t\t\tPassword:  "password123",
\t\t\tFirstName: "Test",
\t\t\tLastName:  "User",
\t\t}

\t\tbody, _ := json.Marshal(reqBody)
\t\tw := httptest.NewRecorder()
\t\treq, _ := http.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(body))
\t\treq.Header.Set("Content-Type", "application/json")

\t\trouter.ServeHTTP(w, req)

\t\tassert.Equal(t, http.StatusCreated, w.Code)

\t\tvar response models.TokenResponse
\t\terr := json.Unmarshal(w.Body.Bytes(), &response)
\t\tassert.NoError(t, err)
\t\tassert.NotEmpty(t, response.AccessToken)
\t})

\tt.Run("duplicate email", func(t *testing.T) {
\t\t// First registration
\t\treqBody := models.RegisterRequest{
\t\t\tEmail:     "duplicate@example.com",
\t\t\tPassword:  "password123",
\t\t\tFirstName: "Test",
\t\t\tLastName:  "User",
\t\t}

\t\tbody, _ := json.Marshal(reqBody)
\t\tw := httptest.NewRecorder()
\t\treq, _ := http.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(body))
\t\treq.Header.Set("Content-Type", "application/json")
\t\trouter.ServeHTTP(w, req)

\t\t// Second registration with same email
\t\tw = httptest.NewRecorder()
\t\treq, _ = http.NewRequest("POST", "/api/v1/auth/register", bytes.NewBuffer(body))
\t\treq.Header.Set("Content-Type", "application/json")
\t\trouter.ServeHTTP(w, req)

\t\tassert.Equal(t, http.StatusBadRequest, w.Code)
\t})
}`;
  }
  
  private generateUserServiceTest(): string {
    return `package services_test

import (
\t"testing"
\t"github.com/stretchr/testify/assert"
\t"gorm.io/driver/sqlite"
\t"gorm.io/gorm"
\t"${this.options.name}/internal/models"
\t"${this.options.name}/internal/services"
)

func setupTestDB() *gorm.DB {
\tdb, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
\tdb.AutoMigrate(&models.User{})
\treturn db
}

func TestUserService_CreateUser(t *testing.T) {
\tdb := setupTestDB()
\tuserService := services.NewUserService(db)

\tt.Run("create user successfully", func(t *testing.T) {
\t\treq := &models.RegisterRequest{
\t\t\tEmail:     "test@example.com",
\t\t\tPassword:  "password123",
\t\t\tFirstName: "Test",
\t\t\tLastName:  "User",
\t\t}

\t\tuser, err := userService.CreateUser(req)
\t\tassert.NoError(t, err)
\t\tassert.NotNil(t, user)
\t\tassert.Equal(t, req.Email, user.Email)
\t\tassert.NotEmpty(t, user.PasswordHash)
\t})

\tt.Run("duplicate email error", func(t *testing.T) {
\t\treq := &models.RegisterRequest{
\t\t\tEmail:     "duplicate@example.com",
\t\t\tPassword:  "password123",
\t\t\tFirstName: "Test",
\t\t\tLastName:  "User",
\t\t}

\t\t_, err := userService.CreateUser(req)
\t\tassert.NoError(t, err)

\t\t_, err = userService.CreateUser(req)
\t\tassert.Error(t, err)
\t\tassert.Contains(t, err.Error(), "already exists")
\t})
}`;
  }
  
  private generateTestHelpers(): string {
    return `package test

import (
\t"github.com/gin-gonic/gin"
\t"gorm.io/driver/sqlite"
\t"gorm.io/gorm"
\t"${this.options.name}/internal/models"
)

func SetupTestDB() *gorm.DB {
\tdb, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
\tdb.AutoMigrate(&models.User{})
\treturn db
}

func SetupTestRouter() *gin.Engine {
\tgin.SetMode(gin.TestMode)
\trouter := gin.New()
\treturn router
}

func CreateTestUser(db *gorm.DB) *models.User {
\tuser := &models.User{
\t\tEmail:        "test@example.com",
\t\tPasswordHash: "$2a$10$XQq2o2Y2YMh0mCCbGXGX.OZ6gJV3F6J9R0nSFBGb7M5I2xwRO4xLG", // password123
\t\tFirstName:    "Test",
\t\tLastName:     "User",
\t\tIsActive:     true,
\t}
\tdb.Create(user)
\treturn user
}`;
  }
  
  protected async writeFile(filePath: string, content: string): Promise<void> {
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, content, 'utf-8');
  }
}