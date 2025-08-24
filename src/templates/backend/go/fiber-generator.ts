import { GoBackendGenerator } from './go-base-generator';

export class FiberGenerator extends GoBackendGenerator {
  constructor() {
    super('Fiber');
  }
  
  // Override getOptions to store options
  async generate(projectPath: string, options: any): Promise<void> {
    this.options = options;
    await super.generate(projectPath, options);
  }
  
  protected getFrameworkDependencies(): string[] {
    return [
      'github.com/gofiber/fiber/v2 v2.52.0',
      'github.com/gofiber/contrib/jwt v1.0.8',
      'github.com/gofiber/contrib/swagger v1.0.0',
      'github.com/gofiber/websocket/v2 v2.2.1',
      'github.com/gofiber/storage/redis/v3 v3.1.0',
      'github.com/swaggo/swag v1.16.2',
      'github.com/swaggo/files v1.0.1',
      'gorm.io/gorm v1.25.5',
      'gorm.io/driver/postgres v1.5.4',
      'github.com/redis/go-redis/v9 v9.3.0',
      'github.com/golang-jwt/jwt/v5 v5.2.0',
      'golang.org/x/crypto v0.16.0',
      'github.com/go-playground/validator/v10 v10.16.0',
      'github.com/spf13/viper v1.18.1',
      'github.com/sirupsen/logrus v1.9.3',
      'github.com/jordan-wright/email v4.0.1-0.20210109023952-943e75fe5223+incompatible',
      'github.com/go-redis/redis_rate/v10 v10.0.1',
      'github.com/golang-migrate/migrate/v4 v4.17.0'
    ];
  }
  
  protected generateMainFile(): string {
    return `package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"${this.options.name}/internal/config"
	"${this.options.name}/internal/database"
	"${this.options.name}/internal/server"

	_ "${this.options.name}/docs" // swagger docs
)

// @title           ${this.options.name} API
// @version         1.0
// @description     A Fiber-based microservice API
// @termsOfService  http://swagger.io/terms/

// @contact.name   API Support
// @contact.url    http://www.swagger.io/support
// @contact.email  support@swagger.io

// @license.name  MIT
// @license.url   https://opensource.org/licenses/MIT

// @host      localhost:8080
// @BasePath  /api/v1

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize database
	db, err := database.Initialize(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Initialize Redis
	redisClient, err := database.InitializeRedis(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize Redis: %v", err)
	}

	// Create server
	srv := server.New(cfg, db, redisClient)

	// Start server in a goroutine
	go func() {
		if err := srv.Start(); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	log.Printf("🚀 Server started on port %s", cfg.AppPort)

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	// Close database connection
	sqlDB, err := db.DB()
	if err == nil {
		sqlDB.Close()
	}

	// Close Redis connection
	if err := redisClient.Close(); err != nil {
		log.Printf("Error closing Redis: %v", err)
	}

	log.Println("Server exited")
}`;
  }
  
  protected generateRouteFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'internal/routes/routes.go',
        content: `package routes

import (
	"${this.options.name}/internal/handlers"
	"${this.options.name}/internal/middleware"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
	"github.com/redis/go-redis/v9"
)

func Setup(app *fiber.App, db *gorm.DB, redis *redis.Client) {
	// Initialize handlers
	healthHandler := handlers.NewHealthHandler(db)
	authHandler := handlers.NewAuthHandler(db)
	userHandler := handlers.NewUserHandler(db)

	// API routes group
	api := app.Group("/api/v1")

	// Public routes
	api.Get("/health", healthHandler.Check)

	// Auth routes
	auth := api.Group("/auth")
	auth.Post("/register", authHandler.Register)
	auth.Post("/login", authHandler.Login)
	auth.Post("/refresh", authHandler.RefreshToken)
	auth.Post("/logout", authHandler.Logout)

	// Protected routes
	protected := api.Group("")
	protected.Use(middleware.JWTAuth())
	
	// User routes
	users := protected.Group("/users")
	users.Get("/profile", userHandler.GetProfile)
	users.Put("/profile", userHandler.UpdateProfile)
	users.Delete("/profile", userHandler.DeleteAccount)
	users.Post("/change-password", userHandler.ChangePassword)

	// Admin routes
	admin := api.Group("/admin")
	admin.Use(middleware.JWTAuth())
	admin.Use(middleware.RequireRole("admin"))
	admin.Get("/users", userHandler.ListUsers)
	admin.Get("/users/:id", userHandler.GetUser)
	admin.Put("/users/:id", userHandler.UpdateUser)
	admin.Delete("/users/:id", userHandler.DeleteUser)

	// WebSocket routes
	ws := app.Group("/ws")
	ws.Use(middleware.JWTAuth())
	ws.Get("/connect", middleware.WebSocketUpgrade(), handlers.WebSocketHandler)
}`
      }
    ];
  }
  
  protected generateHandlerFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'internal/handlers/auth_handler.go',
        content: `package handlers

import (
	"time"

	"${this.options.name}/internal/models"
	"${this.options.name}/internal/services"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

type AuthHandler struct {
	db          *gorm.DB
	userService *services.UserService
	authService *services.AuthService
}

func NewAuthHandler(db *gorm.DB) *AuthHandler {
	return &AuthHandler{
		db:          db,
		userService: services.NewUserService(db),
		authService: services.NewAuthService(services.NewUserService(db), nil),
	}
}

func (h *AuthHandler) Register(c *fiber.Ctx) error {
	var req models.RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Validate request
	if err := validate.Struct(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	tokenResponse, err := h.authService.Register(&req)
	if err != nil {
		if err.Error() == "user already exists" {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to register user",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(tokenResponse)
}

func (h *AuthHandler) Login(c *fiber.Ctx) error {
	var req models.LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Validate request
	if err := validate.Struct(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	tokenResponse, err := h.authService.Login(&req)
	if err != nil {
		if err.Error() == "invalid credentials" || err.Error() == "user account is disabled" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to login",
		})
	}

	// Set secure cookie
	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    tokenResponse.RefreshToken,
		Expires:  time.Now().Add(7 * 24 * time.Hour),
		HTTPOnly: true,
		SameSite: "Lax",
		Secure:   false, // Should be true in production with HTTPS
	})

	return c.JSON(tokenResponse)
}

func (h *AuthHandler) RefreshToken(c *fiber.Ctx) error {
	refreshToken := c.Cookies("refresh_token")
	if refreshToken == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Refresh token not found",
		})
	}

	tokenResponse, err := h.authService.RefreshToken(refreshToken)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid refresh token",
		})
	}

	return c.JSON(tokenResponse)
}

func (h *AuthHandler) Logout(c *fiber.Ctx) error {
	// Clear refresh token cookie
	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
	})

	return c.JSON(fiber.Map{
		"message": "Logged out successfully",
	})
}`
      },
      {
        path: 'internal/handlers/user_handler.go',
        content: `package handlers

import (
	"strconv"

	"${this.options.name}/internal/models"
	"${this.options.name}/internal/services"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

type UserHandler struct {
	db          *gorm.DB
	userService *services.UserService
}

func NewUserHandler(db *gorm.DB) *UserHandler {
	return &UserHandler{
		db:          db,
		userService: services.NewUserService(db),
	}
}

func (h *UserHandler) GetProfile(c *fiber.Ctx) error {
	userID := c.Locals("userID").(uint)
	
	user, err := h.userService.GetUserByID(userID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "User not found",
		})
	}

	response := models.UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		IsActive:  user.IsActive,
		CreatedAt: user.CreatedAt,
	}

	return c.JSON(response)
}

func (h *UserHandler) UpdateProfile(c *fiber.Ctx) error {
	userID := c.Locals("userID").(uint)
	
	var req models.UpdateUserRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	updates := map[string]interface{}{}
	if req.FirstName != "" {
		updates["first_name"] = req.FirstName
	}
	if req.LastName != "" {
		updates["last_name"] = req.LastName
	}

	user, err := h.userService.UpdateUser(userID, updates)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update profile",
		})
	}

	response := models.UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		IsActive:  user.IsActive,
		CreatedAt: user.CreatedAt,
	}

	return c.JSON(response)
}

func (h *UserHandler) ChangePassword(c *fiber.Ctx) error {
	userID := c.Locals("userID").(uint)
	
	var req models.ChangePasswordRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Validate request
	if err := validate.Struct(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	if err := h.userService.ChangePassword(userID, req.OldPassword, req.NewPassword); err != nil {
		if err.Error() == "invalid old password" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to change password",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Password changed successfully",
	})
}

func (h *UserHandler) DeleteAccount(c *fiber.Ctx) error {
	userID := c.Locals("userID").(uint)
	
	if err := h.userService.DeleteUser(userID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete account",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Account deleted successfully",
	})
}

// Admin handlers
func (h *UserHandler) ListUsers(c *fiber.Ctx) error {
	page, _ := strconv.Atoi(c.Query("page", "1"))
	limit, _ := strconv.Atoi(c.Query("limit", "10"))

	users, total, err := h.userService.ListUsers(page, limit)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to list users",
		})
	}

	return c.JSON(fiber.Map{
		"users": users,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

func (h *UserHandler) GetUser(c *fiber.Ctx) error {
	id, err := strconv.ParseUint(c.Params("id"), 10, 32)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID",
		})
	}

	user, err := h.userService.GetUserByID(uint(id))
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "User not found",
		})
	}

	return c.JSON(user)
}

func (h *UserHandler) UpdateUser(c *fiber.Ctx) error {
	id, err := strconv.ParseUint(c.Params("id"), 10, 32)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID",
		})
	}

	var req map[string]interface{}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	user, err := h.userService.UpdateUser(uint(id), req)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update user",
		})
	}

	return c.JSON(user)
}

func (h *UserHandler) DeleteUser(c *fiber.Ctx) error {
	id, err := strconv.ParseUint(c.Params("id"), 10, 32)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID",
		})
	}

	if err := h.userService.DeleteUser(uint(id)); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete user",
		})
	}

	return c.JSON(fiber.Map{
		"message": "User deleted successfully",
	})
}`
      },
      {
        path: 'internal/handlers/health_handler.go',
        content: `package handlers

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

type HealthHandler struct {
	db *gorm.DB
}

func NewHealthHandler(db *gorm.DB) *HealthHandler {
	return &HealthHandler{db: db}
}

type HealthResponse struct {
	Status   string \`json:"status"\`
	Database string \`json:"database"\`
	Uptime   string \`json:"uptime"\`
}

var startTime = time.Now()

func (h *HealthHandler) Check(c *fiber.Ctx) error {
	health := HealthResponse{
		Status: "healthy",
		Uptime: time.Since(startTime).String(),
	}

	// Check database connection
	sqlDB, err := h.db.DB()
	if err != nil {
		health.Database = "unhealthy"
		health.Status = "degraded"
	} else if err := sqlDB.Ping(); err != nil {
		health.Database = "unhealthy"
		health.Status = "degraded"
	} else {
		health.Database = "healthy"
	}

	if health.Status == "healthy" {
		return c.JSON(health)
	}
	return c.Status(fiber.StatusServiceUnavailable).JSON(health)
}`
      },
      {
        path: 'internal/handlers/websocket_handler.go',
        content: `package handlers

import (
	"log"

	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
)

type Message struct {
	Type    string      \`json:"type"\`
	Payload interface{} \`json:"payload"\`
}

func WebSocketHandler(c *websocket.Conn) {
	userID := c.Locals("userID").(uint)
	log.Printf("WebSocket connection established for user %d", userID)

	// Send welcome message
	welcome := Message{
		Type: "welcome",
		Payload: map[string]interface{}{
			"message": "Connected to WebSocket",
			"userID":  userID,
		},
	}

	if err := c.WriteJSON(welcome); err != nil {
		log.Printf("Error sending welcome message: %v", err)
		return
	}

	// Handle incoming messages
	for {
		var msg Message
		if err := c.ReadJSON(&msg); err != nil {
			log.Printf("WebSocket read error: %v", err)
			break
		}

		// Process message based on type
		switch msg.Type {
		case "ping":
			pong := Message{
				Type:    "pong",
				Payload: msg.Payload,
			}
			if err := c.WriteJSON(pong); err != nil {
				log.Printf("Error sending pong: %v", err)
				break
			}
		case "broadcast":
			// Implement broadcast logic here
			log.Printf("Broadcast message from user %d: %v", userID, msg.Payload)
		default:
			log.Printf("Unknown message type: %s", msg.Type)
		}
	}
}`
      },
      {
        path: 'internal/handlers/validator.go',
        content: `package handlers

import (
	"github.com/go-playground/validator/v10"
)

// Global validator instance
var validate = validator.New()`
      }
    ];
  }
  
  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'internal/middleware/auth.go',
        content: `package middleware

import (
	"strings"

	"${this.options.name}/internal/config"
	"${this.options.name}/internal/models"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

func JWTAuth() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authorization header missing",
			})
		}

		// Extract token from "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid authorization header format",
			})
		}

		tokenString := parts[1]
		
		// Parse and validate token
		cfg, _ := config.Load()
		token, err := jwt.ParseWithClaims(tokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.JWTSecret), nil
		})

		if err != nil || !token.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid or expired token",
			})
		}

		// Extract claims
		claims, ok := token.Claims.(*models.TokenClaims)
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid token claims",
			})
		}

		// Set user ID in context
		c.Locals("userID", claims.UserID)
		c.Locals("email", claims.Email)
		return c.Next()
	}
}

func RequireRole(role string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// This is a placeholder - implement role checking logic
		// You would typically check the user's role from the database
		// or include it in the JWT claims
		return c.Next()
	}
}`
      },
      {
        path: 'internal/middleware/cors.go',
        content: `package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

func CORS() fiber.Handler {
	return cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000, http://localhost:5173",
		AllowMethods:     "GET,POST,PUT,PATCH,DELETE,OPTIONS",
		AllowHeaders:     "Origin,Content-Type,Accept,Authorization",
		ExposeHeaders:    "Content-Length",
		AllowCredentials: true,
		MaxAge:           86400,
	})
}`
      },
      {
        path: 'internal/middleware/rate_limit.go',
        content: `package middleware

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis_rate/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
)

func RateLimit(redisClient *redis.Client, limit int, window time.Duration) fiber.Handler {
	limiter := redis_rate.NewLimiter(redisClient)
	
	return func(c *fiber.Ctx) error {
		ctx := context.Background()
		
		// Use IP address as key
		key := fmt.Sprintf("rate_limit:%s", c.IP())
		
		// Check rate limit
		res, err := limiter.Allow(ctx, key, redis_rate.PerDuration(limit, window))
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Rate limit error",
			})
		}
		
		if !res.Allowed {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "Rate limit exceeded",
			})
		}
		
		// Add rate limit headers
		c.Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
		c.Set("X-RateLimit-Remaining", fmt.Sprintf("%d", res.Remaining))
		c.Set("X-RateLimit-Reset", fmt.Sprintf("%d", res.ResetAfter.Unix()))
		
		return c.Next()
	}
}`
      },
      {
        path: 'internal/middleware/logger.go',
        content: `package middleware

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

func Logger(log *logrus.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()

		// Process request
		err := c.Next()

		// Log request details
		latency := time.Since(start)
		status := c.Response().StatusCode()

		entry := log.WithFields(logrus.Fields{
			"status":     status,
			"method":     c.Method(),
			"path":       c.Path(),
			"ip":         c.IP(),
			"latency":    latency,
			"user-agent": c.Get("User-Agent"),
		})

		if status >= 500 {
			entry.Error("Server error")
		} else if status >= 400 {
			entry.Warn("Client error")
		} else {
			entry.Info("Request completed")
		}

		return err
	}
}`
      },
      {
        path: 'internal/middleware/recovery.go',
        content: `package middleware

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

func Recovery(log *logrus.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		defer func() {
			if r := recover(); r != nil {
				err, ok := r.(error)
				if !ok {
					err = fmt.Errorf("%v", r)
				}

				log.WithFields(logrus.Fields{
					"error":      err,
					"request":    c.Path(),
					"method":     c.Method(),
					"client_ip":  c.IP(),
					"user_agent": c.Get("User-Agent"),
				}).Error("Panic recovered")

				c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "Internal server error",
				})
			}
		}()
		return c.Next()
	}
}`
      },
      {
        path: 'internal/middleware/websocket.go',
        content: `package middleware

import (
	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
)

func WebSocketUpgrade() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if websocket.IsWebSocketUpgrade(c) {
			return c.Next()
		}
		return fiber.ErrUpgradeRequired
	}
}`
      }
    ];
  }
  
  protected generateConfigFile(): string {
    return `package config

import (
	"github.com/spf13/viper"
)

type Config struct {
	AppName     string
	AppEnv      string
	AppPort     string
	DatabaseURL string
	RedisURL    string
	JWTSecret   string
	SMTPHost    string
	SMTPPort    int
	SMTPUser    string
	SMTPPass    string
	SMTPFrom    string
}

func Load() (*Config, error) {
	viper.SetConfigFile(".env")
	viper.AutomaticEnv()

	// Set defaults
	viper.SetDefault("APP_NAME", "fiber-service")
	viper.SetDefault("APP_ENV", "development")
	viper.SetDefault("APP_PORT", "8080")

	if err := viper.ReadInConfig(); err != nil {
		// It's okay if the .env file doesn't exist
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	config := &Config{
		AppName:     viper.GetString("APP_NAME"),
		AppEnv:      viper.GetString("APP_ENV"),
		AppPort:     viper.GetString("APP_PORT"),
		DatabaseURL: viper.GetString("DATABASE_URL"),
		RedisURL:    viper.GetString("REDIS_URL"),
		JWTSecret:   viper.GetString("JWT_SECRET"),
		SMTPHost:    viper.GetString("SMTP_HOST"),
		SMTPPort:    viper.GetInt("SMTP_PORT"),
		SMTPUser:    viper.GetString("SMTP_USER"),
		SMTPPass:    viper.GetString("SMTP_PASS"),
		SMTPFrom:    viper.GetString("SMTP_FROM"),
	}

	return config, nil
}`;
  }
  
  protected generateServerFile(): string {
    return `package server

import (
	"context"
	"fmt"
	"time"

	"${this.options.name}/internal/config"
	"${this.options.name}/internal/middleware"
	"${this.options.name}/internal/routes"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/gofiber/swagger"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"github.com/redis/go-redis/v9"
)

type Server struct {
	config     *config.Config
	app        *fiber.App
	db         *gorm.DB
	redis      *redis.Client
	logger     *logrus.Logger
}

func New(cfg *config.Config, db *gorm.DB, redis *redis.Client) *Server {
	// Create logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName:      cfg.AppName,
		CaseSensitive: true,
		StrictRouting: true,
		ServerHeader:  "Fiber",
		BodyLimit:     10 * 1024 * 1024, // 10MB
	})

	// Global middleware
	app.Use(middleware.Recovery(logger))
	app.Use(middleware.Logger(logger))
	app.Use(requestid.New())
	app.Use(middleware.CORS())
	app.Use(compress.New(compress.Config{
		Level: compress.LevelBestSpeed,
	}))
	app.Use(middleware.RateLimit(redis, 100, time.Minute))

	// Swagger documentation
	if cfg.AppEnv != "production" {
		app.Get("/swagger/*", swagger.HandlerDefault)
	}

	// Setup routes
	routes.Setup(app, db, redis)

	return &Server{
		config: cfg,
		app:    app,
		db:     db,
		redis:  redis,
		logger: logger,
	}
}

func (s *Server) Start() error {
	address := fmt.Sprintf(":%s", s.config.AppPort)
	return s.app.Listen(address)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.app.ShutdownWithContext(ctx)
}`;
  }
  
  // Implement abstract methods from BackendTemplateGenerator
  protected async generateAPIDocs(projectPath: string): Promise<void> {
    // API docs are generated via Swagger annotations in the code
    // No additional generation needed as swag init is called via Makefile
  }
  
  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    // Docker files are already generated in GoBackendGenerator
    // No additional Docker files needed for Fiber
  }
  
  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    // Documentation is already generated in GoBackendGenerator
    // No additional documentation needed for Fiber
  }
  
  protected getLanguageSpecificIgnorePatterns(): string[] {
    return [
      'bin/',
      'tmp/',
      '*.exe',
      '*.dll',
      '*.so',
      '*.dylib',
      'vendor/',
      'go.sum',
      '.air.toml.tmp',
      'build-errors.log'
    ];
  }
  
  protected getLanguagePrerequisites(): string {
    return 'Go 1.21+';
  }
  
  protected getInstallCommand(): string {
    return 'go mod download';
  }
  
  protected getDevCommand(): string {
    return 'air';
  }
  
  protected getProdCommand(): string {
    return './bin/server';
  }
  
  protected getTestCommand(): string {
    return 'go test ./...';
  }
  
  protected getCoverageCommand(): string {
    return 'go test -cover ./...';
  }
  
  protected getLintCommand(): string {
    return 'golangci-lint run';
  }
  
  protected getBuildCommand(): string {
    return 'go build -o bin/server cmd/server/main.go';
  }
  
  protected getSetupAction(): string {
    return 'actions/setup-go@v4\\n      with:\\n        go-version: 1.21';
  }
}
