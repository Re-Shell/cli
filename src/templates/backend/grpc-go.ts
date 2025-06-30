import { BackendTemplate } from '../types';

export const grpcGoTemplate: BackendTemplate = {
  id: 'grpc-go',
  name: 'grpc-go',
  displayName: 'gRPC Server (Go)',
  description: 'High-performance gRPC server with Protocol Buffers, streaming support, and interceptors',
  language: 'go',
  framework: 'grpc',
  version: '1.60.1',
  tags: ['go', 'grpc', 'protobuf', 'microservices', 'rpc', 'streaming', 'high-performance'],
  port: 50051,
  dependencies: {},
  features: ['authentication', 'validation', 'logging', 'monitoring', 'microservices', 'documentation'],
  
  files: {
    // Go module configuration
    'go.mod': `module {{projectName}}

go 1.21

require (
	google.golang.org/grpc v1.60.1
	google.golang.org/protobuf v1.32.0
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.18.1
	github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.0.1
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/envoyproxy/protoc-gen-validate v1.0.2
	github.com/bufbuild/buf v1.28.1
	github.com/golang-jwt/jwt/v5 v5.2.0
	github.com/joho/godotenv v1.5.1
	github.com/go-playground/validator/v10 v10.16.0
	github.com/rs/zerolog v1.31.0
	github.com/prometheus/client_golang v1.18.0
	github.com/stretchr/testify v1.8.4
	gorm.io/gorm v1.25.5
	gorm.io/driver/postgres v1.5.4
	gorm.io/driver/mysql v1.5.2
	gorm.io/driver/sqlite v1.5.4
	golang.org/x/crypto v0.17.0
	github.com/google/uuid v1.5.0
	github.com/redis/go-redis/v9 v9.3.1
	go.opentelemetry.io/otel v1.21.0
	go.opentelemetry.io/otel/trace v1.21.0
	go.opentelemetry.io/otel/exporters/jaeger v1.17.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/gabriel-vasile/mimetype v1.4.3 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20231201235250-de7065d80cb9 // indirect
	github.com/jackc/pgx/v5 v5.5.1 // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/leodido/go-urn v1.2.4 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-sqlite3 v1.14.19 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common v0.45.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	golang.org/x/net v0.19.0 // indirect
	golang.org/x/sync v0.5.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto v0.0.0-20231212172506-995d672761c0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20231212172506-995d672761c0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20231212172506-995d672761c0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
`,

    // Main application entry point
    'main.go': `package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"{{projectName}}/config"
	"{{projectName}}/database"
	"{{projectName}}/internal/interceptors"
	"{{projectName}}/internal/services"
	pb "{{projectName}}/proto/gen"

	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

// @title {{projectName}} gRPC Service
// @version 1.0
// @description High-performance gRPC service with Protocol Buffers
// @contact.name API Support
// @contact.email support@example.com
// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found")
	}

	// Initialize configuration
	cfg := config.Load()

	// Initialize logger
	logger := initLogger(cfg.LogLevel)

	// Initialize database
	db, err := database.Initialize(cfg.DatabaseURL)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to initialize database")
	}

	// Run migrations
	if err := database.Migrate(db); err != nil {
		logger.Fatal().Err(err).Msg("Failed to run migrations")
	}

	// Create gRPC server with interceptors
	serverOpts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(
			interceptors.LoggingUnaryInterceptor(logger),
			interceptors.AuthUnaryInterceptor(cfg.JWTSecret),
			interceptors.ValidationUnaryInterceptor(),
			interceptors.RecoveryUnaryInterceptor(logger),
			interceptors.MetricsUnaryInterceptor(),
		),
		grpc.ChainStreamInterceptor(
			interceptors.LoggingStreamInterceptor(logger),
			interceptors.AuthStreamInterceptor(cfg.JWTSecret),
			interceptors.RecoveryStreamInterceptor(logger),
			interceptors.MetricsStreamInterceptor(),
		),
	}

	grpcServer := grpc.NewServer(serverOpts...)

	// Register services
	userService := services.NewUserService(db, logger)
	pb.RegisterUserServiceServer(grpcServer, userService)

	productService := services.NewProductService(db, logger)
	pb.RegisterProductServiceServer(grpcServer, productService)

	// Register health check
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	// Register reflection for grpcurl
	reflection.Register(grpcServer)

	// Create listener
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create listener")
	}

	// Start server in goroutine
	go func() {
		logger.Info().Int("port", cfg.Port).Msg("Starting gRPC server")
		if err := grpcServer.Serve(listener); err != nil {
			logger.Fatal().Err(err).Msg("Failed to serve")
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	logger.Info().Msg("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	grpcServer.GracefulStop()

	logger.Info().Msg("Server exited")
}

func initLogger(level string) *zerolog.Logger {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	logLevel, err := zerolog.ParseLevel(level)
	if err != nil {
		logLevel = zerolog.InfoLevel
	}

	logger := zerolog.New(os.Stdout).
		Level(logLevel).
		With().
		Timestamp().
		Caller().
		Logger()

	return &logger
}
`,

    // Configuration
    'config/config.go': `package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port        int
	DatabaseURL string
	JWTSecret   string
	LogLevel    string
	RedisURL    string
}

func Load() *Config {
	return &Config{
		Port:        getEnvAsInt("PORT", 50051),
		DatabaseURL: getEnv("DATABASE_URL", "postgres://user:password@localhost/dbname?sslmode=disable"),
		JWTSecret:   getEnv("JWT_SECRET", "your-secret-key"),
		LogLevel:    getEnv("LOG_LEVEL", "info"),
		RedisURL:    getEnv("REDIS_URL", "redis://localhost:6379/0"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	valueStr := getEnv(key, "")
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return defaultValue
}
`,

    // Protocol Buffers definitions
    'proto/user.proto': `syntax = "proto3";

package {{projectName}}.v1;

option go_package = "{{projectName}}/proto/gen;pb";

import "google/api/annotations.proto";
import "google/protobuf/timestamp.proto";
import "google/protobuf/empty.proto";
import "validate/validate.proto";

// User service for managing users
service UserService {
  // Create a new user
  rpc CreateUser(CreateUserRequest) returns (User) {
    option (google.api.http) = {
      post: "/api/v1/users"
      body: "*"
    };
  }

  // Get a user by ID
  rpc GetUser(GetUserRequest) returns (User) {
    option (google.api.http) = {
      get: "/api/v1/users/{id}"
    };
  }

  // Update a user
  rpc UpdateUser(UpdateUserRequest) returns (User) {
    option (google.api.http) = {
      put: "/api/v1/users/{id}"
      body: "*"
    };
  }

  // Delete a user
  rpc DeleteUser(DeleteUserRequest) returns (google.protobuf.Empty) {
    option (google.api.http) = {
      delete: "/api/v1/users/{id}"
    };
  }

  // List users with pagination
  rpc ListUsers(ListUsersRequest) returns (ListUsersResponse) {
    option (google.api.http) = {
      get: "/api/v1/users"
    };
  }

  // Login user
  rpc Login(LoginRequest) returns (LoginResponse) {
    option (google.api.http) = {
      post: "/api/v1/auth/login"
      body: "*"
    };
  }

  // Stream user updates
  rpc StreamUserUpdates(StreamUserUpdatesRequest) returns (stream User) {}
}

// User message
message User {
  string id = 1;
  string email = 2;
  string name = 3;
  UserRole role = 4;
  bool active = 5;
  google.protobuf.Timestamp created_at = 6;
  google.protobuf.Timestamp updated_at = 7;
}

// User role enum
enum UserRole {
  USER_ROLE_UNSPECIFIED = 0;
  USER_ROLE_USER = 1;
  USER_ROLE_ADMIN = 2;
  USER_ROLE_MODERATOR = 3;
}

// Create user request
message CreateUserRequest {
  string email = 1 [(validate.rules).string = {email: true, min_len: 1}];
  string password = 2 [(validate.rules).string = {min_len: 8}];
  string name = 3 [(validate.rules).string = {min_len: 1}];
  UserRole role = 4;
}

// Get user request
message GetUserRequest {
  string id = 1 [(validate.rules).string = {uuid: true}];
}

// Update user request
message UpdateUserRequest {
  string id = 1 [(validate.rules).string = {uuid: true}];
  string email = 2 [(validate.rules).string = {email: true}];
  string name = 3;
  UserRole role = 4;
  bool active = 5;
}

// Delete user request
message DeleteUserRequest {
  string id = 1 [(validate.rules).string = {uuid: true}];
}

// List users request
message ListUsersRequest {
  int32 page = 1 [(validate.rules).int32 = {gte: 1}];
  int32 limit = 2 [(validate.rules).int32 = {gte: 1, lte: 100}];
  string search = 3;
  UserRole role = 4;
}

// List users response
message ListUsersResponse {
  repeated User users = 1;
  int32 total = 2;
  int32 page = 3;
  int32 limit = 4;
}

// Login request
message LoginRequest {
  string email = 1 [(validate.rules).string = {email: true, min_len: 1}];
  string password = 2 [(validate.rules).string = {min_len: 1}];
}

// Login response
message LoginResponse {
  string access_token = 1;
  string refresh_token = 2;
  User user = 3;
}

// Stream user updates request
message StreamUserUpdatesRequest {
  repeated string user_ids = 1;
}
`,

    'proto/product.proto': `syntax = "proto3";

package {{projectName}}.v1;

option go_package = "{{projectName}}/proto/gen;pb";

import "google/api/annotations.proto";
import "google/protobuf/timestamp.proto";
import "google/protobuf/empty.proto";
import "validate/validate.proto";

// Product service for managing products
service ProductService {
  // Create a new product
  rpc CreateProduct(CreateProductRequest) returns (Product) {
    option (google.api.http) = {
      post: "/api/v1/products"
      body: "*"
    };
  }

  // Get a product by ID
  rpc GetProduct(GetProductRequest) returns (Product) {
    option (google.api.http) = {
      get: "/api/v1/products/{id}"
    };
  }

  // Update a product
  rpc UpdateProduct(UpdateProductRequest) returns (Product) {
    option (google.api.http) = {
      put: "/api/v1/products/{id}"
      body: "*"
    };
  }

  // Delete a product
  rpc DeleteProduct(DeleteProductRequest) returns (google.protobuf.Empty) {
    option (google.api.http) = {
      delete: "/api/v1/products/{id}"
    };
  }

  // List products with pagination
  rpc ListProducts(ListProductsRequest) returns (ListProductsResponse) {
    option (google.api.http) = {
      get: "/api/v1/products"
    };
  }

  // Batch create products
  rpc BatchCreateProducts(stream CreateProductRequest) returns (stream Product) {}
}

// Product message
message Product {
  string id = 1;
  string name = 2;
  string description = 3;
  double price = 4;
  int32 stock = 5;
  string category = 6;
  bool active = 7;
  google.protobuf.Timestamp created_at = 8;
  google.protobuf.Timestamp updated_at = 9;
}

// Create product request
message CreateProductRequest {
  string name = 1 [(validate.rules).string = {min_len: 1, max_len: 100}];
  string description = 2 [(validate.rules).string = {max_len: 1000}];
  double price = 3 [(validate.rules).double = {gt: 0}];
  int32 stock = 4 [(validate.rules).int32 = {gte: 0}];
  string category = 5 [(validate.rules).string = {min_len: 1}];
}

// Get product request
message GetProductRequest {
  string id = 1 [(validate.rules).string = {uuid: true}];
}

// Update product request
message UpdateProductRequest {
  string id = 1 [(validate.rules).string = {uuid: true}];
  string name = 2 [(validate.rules).string = {min_len: 1, max_len: 100}];
  string description = 3 [(validate.rules).string = {max_len: 1000}];
  double price = 4 [(validate.rules).double = {gt: 0}];
  int32 stock = 5 [(validate.rules).int32 = {gte: 0}];
  string category = 6;
  bool active = 7;
}

// Delete product request
message DeleteProductRequest {
  string id = 1 [(validate.rules).string = {uuid: true}];
}

// List products request
message ListProductsRequest {
  int32 page = 1 [(validate.rules).int32 = {gte: 1}];
  int32 limit = 2 [(validate.rules).int32 = {gte: 1, lte: 100}];
  string search = 3;
  string category = 4;
  double min_price = 5;
  double max_price = 6;
}

// List products response
message ListProductsResponse {
  repeated Product products = 1;
  int32 total = 2;
  int32 page = 3;
  int32 limit = 4;
}
`,

    // Buf configuration
    'buf.yaml': `version: v1
breaking:
  use:
    - FILE
lint:
  use:
    - DEFAULT
  except:
    - FIELD_LOWER_SNAKE_CASE
  rpc_allow_same_request_response: false
  rpc_allow_google_protobuf_empty_requests: true
  rpc_allow_google_protobuf_empty_responses: true
`,

    'buf.gen.yaml': `version: v1
managed:
  enabled: true
  go_package_prefix:
    default: {{projectName}}/proto/gen
plugins:
  - plugin: go
    out: proto/gen
    opt: paths=source_relative
  - plugin: go-grpc
    out: proto/gen
    opt: 
      - paths=source_relative
      - require_unimplemented_servers=false
  - plugin: grpc-gateway
    out: proto/gen
    opt: 
      - paths=source_relative
      - generate_unbound_methods=true
  - plugin: openapiv2
    out: docs/openapi
    opt:
      - allow_merge=true
      - merge_file_name={{projectName}}
`,

    // Models
    'models/user.go': `package models

import (
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	ID        string         \`gorm:"type:uuid;primary_key"\`
	Email     string         \`gorm:"uniqueIndex;not null"\`
	Password  string         \`gorm:"not null"\`
	Name      string         \`gorm:"not null"\`
	Role      string         \`gorm:"not null;default:'user'"\`
	Active    bool           \`gorm:"default:true"\`
	CreatedAt time.Time      \`gorm:"not null"\`
	UpdatedAt time.Time      \`gorm:"not null"\`
	DeletedAt gorm.DeletedAt \`gorm:"index"\`
}

func (u *User) BeforeCreate(tx *gorm.DB) error {
	u.ID = uuid.New().String()
	u.CreatedAt = time.Now()
	u.UpdatedAt = time.Now()
	return nil
}

func (u *User) BeforeUpdate(tx *gorm.DB) error {
	u.UpdatedAt = time.Now()
	return nil
}

func (u *User) SetPassword(password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.Password = string(hashedPassword)
	return nil
}

func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	return err == nil
}
`,

    'models/product.go': `package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Product struct {
	ID          string         \`gorm:"type:uuid;primary_key"\`
	Name        string         \`gorm:"not null"\`
	Description string         \`gorm:"type:text"\`
	Price       float64        \`gorm:"not null;check:price >= 0"\`
	Stock       int            \`gorm:"not null;check:stock >= 0"\`
	Category    string         \`gorm:"not null"\`
	Active      bool           \`gorm:"default:true"\`
	CreatedAt   time.Time      \`gorm:"not null"\`
	UpdatedAt   time.Time      \`gorm:"not null"\`
	DeletedAt   gorm.DeletedAt \`gorm:"index"\`
}

func (p *Product) BeforeCreate(tx *gorm.DB) error {
	p.ID = uuid.New().String()
	p.CreatedAt = time.Now()
	p.UpdatedAt = time.Now()
	return nil
}

func (p *Product) BeforeUpdate(tx *gorm.DB) error {
	p.UpdatedAt = time.Now()
	return nil
}
`,

    // Services
    'internal/services/user_service.go': `package services

import (
	"context"
	"errors"

	"{{projectName}}/models"
	pb "{{projectName}}/proto/gen"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
)

type UserService struct {
	pb.UnimplementedUserServiceServer
	db     *gorm.DB
	logger *zerolog.Logger
}

func NewUserService(db *gorm.DB, logger *zerolog.Logger) *UserService {
	return &UserService{
		db:     db,
		logger: logger,
	}
}

func (s *UserService) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.User, error) {
	user := &models.User{
		Email: req.Email,
		Name:  req.Name,
		Role:  req.Role.String(),
	}

	if err := user.SetPassword(req.Password); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to hash password: %v", err)
	}

	if err := s.db.Create(user).Error; err != nil {
		s.logger.Error().Err(err).Msg("Failed to create user")
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return nil, status.Error(codes.AlreadyExists, "user with this email already exists")
		}
		return nil, status.Errorf(codes.Internal, "failed to create user: %v", err)
	}

	return s.userToProto(user), nil
}

func (s *UserService) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.User, error) {
	var user models.User
	if err := s.db.First(&user, "id = ?", req.Id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to get user: %v", err)
	}

	return s.userToProto(&user), nil
}

func (s *UserService) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.User, error) {
	var user models.User
	if err := s.db.First(&user, "id = ?", req.Id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to get user: %v", err)
	}

	updates := map[string]interface{}{
		"email":  req.Email,
		"name":   req.Name,
		"role":   req.Role.String(),
		"active": req.Active,
	}

	if err := s.db.Model(&user).Updates(updates).Error; err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update user: %v", err)
	}

	return s.userToProto(&user), nil
}

func (s *UserService) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*emptypb.Empty, error) {
	result := s.db.Delete(&models.User{}, "id = ?", req.Id)
	if result.Error != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete user: %v", result.Error)
	}

	if result.RowsAffected == 0 {
		return nil, status.Error(codes.NotFound, "user not found")
	}

	return &emptypb.Empty{}, nil
}

func (s *UserService) ListUsers(ctx context.Context, req *pb.ListUsersRequest) (*pb.ListUsersResponse, error) {
	var users []models.User
	var total int64

	query := s.db.Model(&models.User{})

	if req.Search != "" {
		query = query.Where("name ILIKE ? OR email ILIKE ?", "%"+req.Search+"%", "%"+req.Search+"%")
	}

	if req.Role != pb.UserRole_USER_ROLE_UNSPECIFIED {
		query = query.Where("role = ?", req.Role.String())
	}

	query.Count(&total)

	offset := (req.Page - 1) * req.Limit
	if err := query.Offset(int(offset)).Limit(int(req.Limit)).Find(&users).Error; err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list users: %v", err)
	}

	userProtos := make([]*pb.User, len(users))
	for i, user := range users {
		userProtos[i] = s.userToProto(&user)
	}

	return &pb.ListUsersResponse{
		Users: userProtos,
		Total: int32(total),
		Page:  req.Page,
		Limit: req.Limit,
	}, nil
}

func (s *UserService) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	var user models.User
	if err := s.db.First(&user, "email = ?", req.Email).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}
		return nil, status.Errorf(codes.Internal, "failed to get user: %v", err)
	}

	if !user.CheckPassword(req.Password) {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	if !user.Active {
		return nil, status.Error(codes.PermissionDenied, "account is inactive")
	}

	// Generate tokens
	accessToken, err := s.generateToken(user.ID, "access", 15*60) // 15 minutes
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate access token: %v", err)
	}

	refreshToken, err := s.generateToken(user.ID, "refresh", 7*24*60*60) // 7 days
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate refresh token: %v", err)
	}

	return &pb.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         s.userToProto(&user),
	}, nil
}

func (s *UserService) StreamUserUpdates(req *pb.StreamUserUpdatesRequest, stream pb.UserService_StreamUserUpdatesServer) error {
	// This is a simplified example - in production you'd use a message queue or change data capture
	s.logger.Info().Strs("user_ids", req.UserIds).Msg("Starting user update stream")

	// Simulate streaming updates
	// In a real implementation, you'd subscribe to database changes or a message queue
	for {
		select {
		case <-stream.Context().Done():
			return nil
		default:
			// Check for updates periodically
			// This is just for demonstration - use proper change detection in production
		}
	}
}

func (s *UserService) userToProto(user *models.User) *pb.User {
	role := pb.UserRole_USER_ROLE_USER
	switch user.Role {
	case "ADMIN":
		role = pb.UserRole_USER_ROLE_ADMIN
	case "MODERATOR":
		role = pb.UserRole_USER_ROLE_MODERATOR
	}

	return &pb.User{
		Id:        user.ID,
		Email:     user.Email,
		Name:      user.Name,
		Role:      role,
		Active:    user.Active,
		CreatedAt: timestamppb.New(user.CreatedAt),
		UpdatedAt: timestamppb.New(user.UpdatedAt),
	}
}

func (s *UserService) generateToken(userID string, tokenType string, expirySeconds int) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"type":    tokenType,
		"exp":     time.Now().Add(time.Duration(expirySeconds) * time.Second).Unix(),
		"iat":     time.Now().Unix(),
		"jti":     uuid.New().String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}
`,

    'internal/services/product_service.go': `package services

import (
	"context"
	"errors"
	"io"

	"{{projectName}}/models"
	pb "{{projectName}}/proto/gen"

	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
)

type ProductService struct {
	pb.UnimplementedProductServiceServer
	db     *gorm.DB
	logger *zerolog.Logger
}

func NewProductService(db *gorm.DB, logger *zerolog.Logger) *ProductService {
	return &ProductService{
		db:     db,
		logger: logger,
	}
}

func (s *ProductService) CreateProduct(ctx context.Context, req *pb.CreateProductRequest) (*pb.Product, error) {
	product := &models.Product{
		Name:        req.Name,
		Description: req.Description,
		Price:       req.Price,
		Stock:       int(req.Stock),
		Category:    req.Category,
	}

	if err := s.db.Create(product).Error; err != nil {
		s.logger.Error().Err(err).Msg("Failed to create product")
		return nil, status.Errorf(codes.Internal, "failed to create product: %v", err)
	}

	return s.productToProto(product), nil
}

func (s *ProductService) GetProduct(ctx context.Context, req *pb.GetProductRequest) (*pb.Product, error) {
	var product models.Product
	if err := s.db.First(&product, "id = ?", req.Id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "product not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to get product: %v", err)
	}

	return s.productToProto(&product), nil
}

func (s *ProductService) UpdateProduct(ctx context.Context, req *pb.UpdateProductRequest) (*pb.Product, error) {
	var product models.Product
	if err := s.db.First(&product, "id = ?", req.Id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, status.Error(codes.NotFound, "product not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to get product: %v", err)
	}

	updates := map[string]interface{}{
		"name":        req.Name,
		"description": req.Description,
		"price":       req.Price,
		"stock":       req.Stock,
		"category":    req.Category,
		"active":      req.Active,
	}

	if err := s.db.Model(&product).Updates(updates).Error; err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update product: %v", err)
	}

	return s.productToProto(&product), nil
}

func (s *ProductService) DeleteProduct(ctx context.Context, req *pb.DeleteProductRequest) (*emptypb.Empty, error) {
	result := s.db.Delete(&models.Product{}, "id = ?", req.Id)
	if result.Error != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete product: %v", result.Error)
	}

	if result.RowsAffected == 0 {
		return nil, status.Error(codes.NotFound, "product not found")
	}

	return &emptypb.Empty{}, nil
}

func (s *ProductService) ListProducts(ctx context.Context, req *pb.ListProductsRequest) (*pb.ListProductsResponse, error) {
	var products []models.Product
	var total int64

	query := s.db.Model(&models.Product{})

	if req.Search != "" {
		query = query.Where("name ILIKE ? OR description ILIKE ?", "%"+req.Search+"%", "%"+req.Search+"%")
	}

	if req.Category != "" {
		query = query.Where("category = ?", req.Category)
	}

	if req.MinPrice > 0 {
		query = query.Where("price >= ?", req.MinPrice)
	}

	if req.MaxPrice > 0 {
		query = query.Where("price <= ?", req.MaxPrice)
	}

	query.Count(&total)

	offset := (req.Page - 1) * req.Limit
	if err := query.Offset(int(offset)).Limit(int(req.Limit)).Find(&products).Error; err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list products: %v", err)
	}

	productProtos := make([]*pb.Product, len(products))
	for i, product := range products {
		productProtos[i] = s.productToProto(&product)
	}

	return &pb.ListProductsResponse{
		Products: productProtos,
		Total:    int32(total),
		Page:     req.Page,
		Limit:    req.Limit,
	}, nil
}

func (s *ProductService) BatchCreateProducts(stream pb.ProductService_BatchCreateProductsServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return status.Errorf(codes.Internal, "failed to receive request: %v", err)
		}

		product := &models.Product{
			Name:        req.Name,
			Description: req.Description,
			Price:       req.Price,
			Stock:       int(req.Stock),
			Category:    req.Category,
		}

		if err := s.db.Create(product).Error; err != nil {
			s.logger.Error().Err(err).Msg("Failed to create product in batch")
			continue // Skip failed products in batch
		}

		if err := stream.Send(s.productToProto(product)); err != nil {
			return status.Errorf(codes.Internal, "failed to send response: %v", err)
		}
	}
}

func (s *ProductService) productToProto(product *models.Product) *pb.Product {
	return &pb.Product{
		Id:          product.ID,
		Name:        product.Name,
		Description: product.Description,
		Price:       product.Price,
		Stock:       int32(product.Stock),
		Category:    product.Category,
		Active:      product.Active,
		CreatedAt:   timestamppb.New(product.CreatedAt),
		UpdatedAt:   timestamppb.New(product.UpdatedAt),
	}
}
`,

    // Interceptors
    'internal/interceptors/auth.go': `package interceptors

import (
	"context"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// List of methods that don't require authentication
var publicMethods = map[string]bool{
	"/{{projectName}}.v1.UserService/Login":  true,
	"/{{projectName}}.v1.UserService/CreateUser": true,
	"/grpc.health.v1.Health/Check":         true,
}

func AuthUnaryInterceptor(jwtSecret string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Skip auth for public methods
		if publicMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		// Extract token from metadata
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		authorization := md.Get("authorization")
		if len(authorization) == 0 {
			return nil, status.Error(codes.Unauthenticated, "missing authorization header")
		}

		// Parse Bearer token
		tokenString := strings.TrimPrefix(authorization[0], "Bearer ")
		if tokenString == authorization[0] {
			return nil, status.Error(codes.Unauthenticated, "invalid authorization format")
		}

		// Verify token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, status.Error(codes.Unauthenticated, "invalid signing method")
			}
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}

		// Extract claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "invalid token claims")
		}

		// Add user ID to context
		userID, ok := claims["user_id"].(string)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing user_id in token")
		}

		ctx = context.WithValue(ctx, "user_id", userID)

		return handler(ctx, req)
	}
}

func AuthStreamInterceptor(jwtSecret string) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Skip auth for public methods
		if publicMethods[info.FullMethod] {
			return handler(srv, ss)
		}

		// Extract token from metadata
		md, ok := metadata.FromIncomingContext(ss.Context())
		if !ok {
			return status.Error(codes.Unauthenticated, "missing metadata")
		}

		authorization := md.Get("authorization")
		if len(authorization) == 0 {
			return status.Error(codes.Unauthenticated, "missing authorization header")
		}

		// Parse Bearer token
		tokenString := strings.TrimPrefix(authorization[0], "Bearer ")
		if tokenString == authorization[0] {
			return status.Error(codes.Unauthenticated, "invalid authorization format")
		}

		// Verify token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, status.Error(codes.Unauthenticated, "invalid signing method")
			}
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			return status.Error(codes.Unauthenticated, "invalid token")
		}

		// Extract claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return status.Error(codes.Unauthenticated, "invalid token claims")
		}

		// Add user ID to context
		userID, ok := claims["user_id"].(string)
		if !ok {
			return status.Error(codes.Unauthenticated, "missing user_id in token")
		}

		// Create a new context with user ID
		ctx := context.WithValue(ss.Context(), "user_id", userID)

		// Wrap the stream with the new context
		wrappedStream := &wrappedServerStream{
			ServerStream: ss,
			ctx:          ctx,
		}

		return handler(srv, wrappedStream)
	}
}

type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}
`,

    'internal/interceptors/logging.go': `package interceptors

import (
	"context"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

func LoggingUnaryInterceptor(logger *zerolog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()

		// Call the handler
		resp, err := handler(ctx, req)

		// Log the request
		duration := time.Since(start)
		statusCode := codes.OK
		if err != nil {
			if s, ok := status.FromError(err); ok {
				statusCode = s.Code()
			}
		}

		logger.Info().
			Str("method", info.FullMethod).
			Dur("duration", duration).
			Str("status", statusCode.String()).
			Err(err).
			Msg("gRPC request")

		return resp, err
	}
}

func LoggingStreamInterceptor(logger *zerolog.Logger) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()

		// Call the handler
		err := handler(srv, ss)

		// Log the request
		duration := time.Since(start)
		statusCode := codes.OK
		if err != nil {
			if s, ok := status.FromError(err); ok {
				statusCode = s.Code()
			}
		}

		logger.Info().
			Str("method", info.FullMethod).
			Dur("duration", duration).
			Str("status", statusCode.String()).
			Bool("is_client_stream", info.IsClientStream).
			Bool("is_server_stream", info.IsServerStream).
			Err(err).
			Msg("gRPC stream")

		return err
	}
}
`,

    'internal/interceptors/validation.go': `package interceptors

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Validator interface that proto messages with validation implement
type Validator interface {
	Validate() error
}

func ValidationUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Check if request implements Validator
		if validator, ok := req.(Validator); ok {
			if err := validator.Validate(); err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "validation failed: %v", err)
			}
		}

		return handler(ctx, req)
	}
}
`,

    'internal/interceptors/recovery.go': `package interceptors

import (
	"context"
	"runtime/debug"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func RecoveryUnaryInterceptor(logger *zerolog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error().
					Interface("panic", r).
					Str("stack", string(debug.Stack())).
					Str("method", info.FullMethod).
					Msg("Recovered from panic")
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()

		return handler(ctx, req)
	}
}

func RecoveryStreamInterceptor(logger *zerolog.Logger) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error().
					Interface("panic", r).
					Str("stack", string(debug.Stack())).
					Str("method", info.FullMethod).
					Msg("Recovered from panic in stream")
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()

		return handler(srv, ss)
	}
}
`,

    'internal/interceptors/metrics.go': `package interceptors

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

var (
	grpcDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "grpc_request_duration_seconds",
		Help: "Duration of gRPC requests in seconds",
	}, []string{"method", "status"})

	grpcRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "grpc_requests_total",
		Help: "Total number of gRPC requests",
	}, []string{"method", "status"})
)

func MetricsUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()

		resp, err := handler(ctx, req)

		statusCode := "OK"
		if err != nil {
			if s, ok := status.FromError(err); ok {
				statusCode = s.Code().String()
			}
		}

		duration := time.Since(start).Seconds()
		grpcDuration.WithLabelValues(info.FullMethod, statusCode).Observe(duration)
		grpcRequests.WithLabelValues(info.FullMethod, statusCode).Inc()

		return resp, err
	}
}

func MetricsStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()

		err := handler(srv, ss)

		statusCode := "OK"
		if err != nil {
			if s, ok := status.FromError(err); ok {
				statusCode = s.Code().String()
			}
		}

		duration := time.Since(start).Seconds()
		grpcDuration.WithLabelValues(info.FullMethod, statusCode).Observe(duration)
		grpcRequests.WithLabelValues(info.FullMethod, statusCode).Inc()

		return err
	}
}
`,

    // Database
    'database/database.go': `package database

import (
	"fmt"

	"{{projectName}}/models"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func Initialize(databaseURL string) (*gorm.DB, error) {
	var db *gorm.DB
	var err error

	// Parse database URL to determine driver
	switch {
	case contains(databaseURL, "postgres://") || contains(databaseURL, "postgresql://"):
		db, err = gorm.Open(postgres.Open(databaseURL), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Info),
		})
	case contains(databaseURL, "mysql://"):
		db, err = gorm.Open(mysql.Open(databaseURL), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Info),
		})
	case contains(databaseURL, "sqlite://") || databaseURL == ":memory:":
		db, err = gorm.Open(sqlite.Open(databaseURL), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Info),
		})
	default:
		return nil, fmt.Errorf("unsupported database URL: %s", databaseURL)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return db, nil
}

func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&models.User{},
		&models.Product{},
	)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr
}
`,

    // Tests
    'internal/services/user_service_test.go': `package services

import (
	"context"
	"testing"

	"{{projectName}}/models"
	pb "{{projectName}}/proto/gen"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.User{})
	require.NoError(t, err)

	return db
}

func TestUserService_CreateUser(t *testing.T) {
	db := setupTestDB(t)
	logger := zerolog.Nop()
	service := NewUserService(db, &logger)

	ctx := context.Background()
	req := &pb.CreateUserRequest{
		Email:    "test@example.com",
		Password: "password123",
		Name:     "Test User",
		Role:     pb.UserRole_USER_ROLE_USER,
	}

	user, err := service.CreateUser(ctx, req)
	require.NoError(t, err)
	assert.NotEmpty(t, user.Id)
	assert.Equal(t, req.Email, user.Email)
	assert.Equal(t, req.Name, user.Name)

	// Test duplicate email
	_, err = service.CreateUser(ctx, req)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.AlreadyExists, st.Code())
}

func TestUserService_GetUser(t *testing.T) {
	db := setupTestDB(t)
	logger := zerolog.Nop()
	service := NewUserService(db, &logger)

	// Create a user first
	testUser := &models.User{
		Email: "test@example.com",
		Name:  "Test User",
		Role:  "USER_ROLE_USER",
	}
	testUser.SetPassword("password123")
	db.Create(testUser)

	ctx := context.Background()
	req := &pb.GetUserRequest{
		Id: testUser.ID,
	}

	user, err := service.GetUser(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, testUser.ID, user.Id)
	assert.Equal(t, testUser.Email, user.Email)

	// Test non-existent user
	req.Id = "non-existent-id"
	_, err = service.GetUser(ctx, req)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestUserService_Login(t *testing.T) {
	db := setupTestDB(t)
	logger := zerolog.Nop()
	service := NewUserService(db, &logger)

	// Create a user first
	testUser := &models.User{
		Email:  "test@example.com",
		Name:   "Test User",
		Role:   "USER_ROLE_USER",
		Active: true,
	}
	testUser.SetPassword("password123")
	db.Create(testUser)

	ctx := context.Background()
	req := &pb.LoginRequest{
		Email:    "test@example.com",
		Password: "password123",
	}

	resp, err := service.Login(ctx, req)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.Equal(t, testUser.ID, resp.User.Id)

	// Test invalid password
	req.Password = "wrongpassword"
	_, err = service.Login(ctx, req)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())

	// Test inactive user
	testUser.Active = false
	db.Save(testUser)
	req.Password = "password123"
	_, err = service.Login(ctx, req)
	require.Error(t, err)
	st, ok = status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code())
}
`,

    // Docker configuration
    'Dockerfile': `# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o server .

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 -S app && \
    adduser -u 1000 -S app -G app

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/server .
COPY --chown=app:app .env.example .env

# Change ownership
RUN chown -R app:app /app

# Switch to non-root user
USER app

# Expose port
EXPOSE 50051

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD grpc_health_probe -addr=:50051 || exit 1

# Run the application
CMD ["./server"]
`,

    'docker-compose.yml': `version: '3.8'

services:
  app:
    build: .
    ports:
      - "50051:50051"
    environment:
      - PORT=50051
      - DATABASE_URL=postgres://postgres:password@postgres:5432/{{projectName}}?sslmode=disable
      - JWT_SECRET=your-secret-key
      - LOG_LEVEL=info
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - app-network
    restart: unless-stopped

  postgres:
    image: postgres:16-alpine
    ports:
      - "5432:5432"
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB={{projectName}}
    volumes:
      - postgres-data:/var/lib/postgresql/data
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
      - redis-data:/data
    networks:
      - app-network
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
    networks:
      - app-network

volumes:
  postgres-data:
  redis-data:
  prometheus-data:

networks:
  app-network:
    driver: bridge
`,

    // Makefile
    'Makefile': `.PHONY: all build run test clean proto lint fmt vet

# Variables
BINARY_NAME=server
DOCKER_IMAGE={{projectName}}:latest
GO_FILES=$(shell find . -name '*.go' -type f)
PROTO_FILES=$(shell find proto -name '*.proto' -type f)

# Build the application
all: clean build

build:
	@echo "Building..."
	go build -o $(BINARY_NAME) -v

# Run the application
run: build
	@echo "Running..."
	./$(BINARY_NAME)

# Run with hot reload
dev:
	@echo "Running with hot reload..."
	air

# Clean build artifacts
clean:
	@echo "Cleaning..."
	go clean
	rm -f $(BINARY_NAME)
	rm -rf proto/gen

# Run tests
test:
	@echo "Running tests..."
	go test -v -race -cover ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Generate protobuf files
proto:
	@echo "Generating protobuf files..."
	buf generate

# Lint the code
lint:
	@echo "Linting..."
	golangci-lint run

# Format the code
fmt:
	@echo "Formatting..."
	go fmt ./...

# Run go vet
vet:
	@echo "Vetting..."
	go vet ./...

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod download
	go install github.com/cosmtrek/air@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/bufbuild/buf/cmd/buf@latest
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@latest
	go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@latest
	go install github.com/envoyproxy/protoc-gen-validate@latest

# Docker commands
docker-build:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE) .

docker-run:
	@echo "Running Docker container..."
	docker run -p 50051:50051 $(DOCKER_IMAGE)

docker-compose-up:
	@echo "Starting services with docker-compose..."
	docker-compose up -d

docker-compose-down:
	@echo "Stopping services..."
	docker-compose down

# Database migrations
migrate-up:
	@echo "Running migrations..."
	go run main.go migrate up

migrate-down:
	@echo "Rolling back migrations..."
	go run main.go migrate down

# Security scan
security:
	@echo "Running security scan..."
	gosec ./...

# Performance profiling
profile:
	@echo "Running CPU profile..."
	go test -cpuprofile cpu.prof -bench .
	go tool pprof cpu.prof

# gRPC health check
health:
	@echo "Checking gRPC health..."
	grpc_health_probe -addr=:50051
`,

    '.air.toml': `root = "."
testdata_dir = "testdata"
tmp_dir = "tmp"

[build]
  args_bin = []
  bin = "./tmp/main"
  cmd = "go build -o ./tmp/main ."
  delay = 1000
  exclude_dir = ["assets", "tmp", "vendor", "testdata", "proto/gen", "docs"]
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
  clear_on_rebuild = false
`,

    '.env.example': `# Server configuration
PORT=50051

# Database configuration
DATABASE_URL=postgres://user:password@localhost/dbname?sslmode=disable
# DATABASE_URL=mysql://user:password@tcp(localhost:3306)/dbname
# DATABASE_URL=sqlite:///path/to/database.db

# JWT configuration
JWT_SECRET=your-secret-key-change-this-in-production

# Logging
LOG_LEVEL=info

# Redis configuration
REDIS_URL=redis://localhost:6379/0

# Monitoring
JAEGER_ENDPOINT=http://localhost:14268/api/traces
`,

    '.gitignore': `# Binaries for programs and plugins
*.exe
*.exe~
*.dll
*.so
*.dylib

# Test binary, built with go test -c
*.test

# Output of the go coverage tool
*.out
coverage.html

# Dependency directories
vendor/

# Go workspace file
go.work

# Environment files
.env
.env.local
.env.*.local

# IDE files
.idea/
.vscode/
*.swp
*.swo
*~

# OS files
.DS_Store
Thumbs.db

# Build output
server
{{projectName}}
/tmp
/dist

# Generated files
proto/gen/
docs/openapi/

# Logs
*.log

# Profiling data
*.prof
*.pprof

# Air tmp directory
tmp/
`,

    'prometheus.yml': `global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'grpc-server'
    static_configs:
      - targets: ['app:50051']
`,

    'README.md': `# {{projectName}}

High-performance gRPC server with Protocol Buffers, built with Go.

## Features

- gRPC server with Protocol Buffers
- Unary and streaming RPC support
- JWT authentication with refresh tokens
- Request validation using protoc-gen-validate
- Comprehensive interceptor chain:
  - Authentication
  - Logging with Zerolog
  - Panic recovery
  - Metrics collection
  - Request validation
- Database integration with GORM
- Redis for caching and rate limiting
- Health checks
- Prometheus metrics
- OpenAPI documentation generation
- Docker and Docker Compose setup
- Hot reload development with Air
- Comprehensive test suite

## Prerequisites

- Go 1.21 or higher
- Protocol Buffers compiler (protoc)
- Docker and Docker Compose (optional)
- PostgreSQL, MySQL, or SQLite

## Quick Start

1. Clone the repository:
   \`\`\`bash
   git clone <repository-url>
   cd {{projectName}}
   \`\`\`

2. Install dependencies:
   \`\`\`bash
   make deps
   \`\`\`

3. Copy environment variables:
   \`\`\`bash
   cp .env.example .env
   \`\`\`

4. Generate Protocol Buffers:
   \`\`\`bash
   make proto
   \`\`\`

5. Run with Docker Compose:
   \`\`\`bash
   docker-compose up
   \`\`\`

   Or run locally:
   \`\`\`bash
   make run
   \`\`\`

## Development

### Hot Reload

Run the server with hot reload:
\`\`\`bash
make dev
\`\`\`

### Testing

Run tests:
\`\`\`bash
make test
\`\`\`

Run tests with coverage:
\`\`\`bash
make test-coverage
\`\`\`

### Linting

\`\`\`bash
make lint
\`\`\`

## API Documentation

The gRPC service definitions are in the \`proto/\` directory. After running \`make proto\`, OpenAPI documentation is generated in \`docs/openapi/\`.

### Using gRPCurl

List services:
\`\`\`bash
grpcurl -plaintext localhost:50051 list
\`\`\`

Describe a service:
\`\`\`bash
grpcurl -plaintext localhost:50051 describe {{projectName}}.v1.UserService
\`\`\`

Call a method:
\`\`\`bash
# Create user
grpcurl -plaintext -d '{
  "email": "user@example.com",
  "password": "password123",
  "name": "Test User",
  "role": "USER_ROLE_USER"
}' localhost:50051 {{projectName}}.v1.UserService/CreateUser

# Login
grpcurl -plaintext -d '{
  "email": "user@example.com",
  "password": "password123"
}' localhost:50051 {{projectName}}.v1.UserService/Login
\`\`\`

## Architecture

- \`proto/\` - Protocol Buffer definitions
- \`proto/gen/\` - Generated Go code from protobuf
- \`internal/\` - Internal packages
  - \`interceptors/\` - gRPC interceptors
  - \`services/\` - Business logic implementation
- \`models/\` - Database models
- \`database/\` - Database connection and migrations
- \`config/\` - Configuration management

## Security

- JWT-based authentication with access and refresh tokens
- Secure password hashing with bcrypt
- Request validation at the protocol level
- Rate limiting and DoS protection
- TLS support for production deployments

## Monitoring

Prometheus metrics are exposed at \`http://localhost:50051/metrics\` including:
- Request duration
- Request count by method and status
- Active connections
- Custom business metrics

## License

[Your License]
`
  }
};