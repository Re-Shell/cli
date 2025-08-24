import { GoBackendGenerator } from './go-base-generator';

export class EchoGenerator extends GoBackendGenerator {
  constructor() {
    super('Echo');
  }
  
  // Override getOptions to store options
  async generate(projectPath: string, options: any): Promise<void> {
    this.options = options;
    await super.generate(projectPath, options);
  }
  
  protected getFrameworkDependencies(): string[] {
    return [
      'github.com/labstack/echo/v4 v4.11.3',
      'github.com/labstack/echo/v4/middleware v4.11.3',
      'github.com/swaggo/echo-swagger v1.4.1',
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
      'github.com/gorilla/websocket v1.5.1',
      'github.com/go-redis/redis_rate/v10 v10.0.1',
      'github.com/golang-migrate/migrate/v4 v4.17.0'
    ];
  }
  
  protected generateMainFile(): string {
    return `package main

import (
	"context"
	"log"
	"net/http"
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
// @description     An Echo-based microservice API
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

	// Start server
	go func() {
		if err := srv.Start(); err != nil && err != http.ErrServerClosed {
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
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
	"github.com/redis/go-redis/v9"
)

func Setup(e *echo.Echo, db *gorm.DB, redis *redis.Client) {
	// Initialize handlers
	healthHandler := handlers.NewHealthHandler(db)
	authHandler := handlers.NewAuthHandler(db)
	userHandler := handlers.NewUserHandler(db)

	// API routes group
	api := e.Group("/api/v1")

	// Public routes
	api.GET("/health", healthHandler.Check)

	// Auth routes
	auth := api.Group("/auth")
	auth.POST("/register", authHandler.Register)
	auth.POST("/login", authHandler.Login)
	auth.POST("/refresh", authHandler.RefreshToken)
	auth.POST("/logout", authHandler.Logout)

	// Protected routes
	protected := api.Group("")
	protected.Use(middleware.JWTAuth())
	
	// User routes
	users := protected.Group("/users")
	users.GET("/profile", userHandler.GetProfile)
	users.PUT("/profile", userHandler.UpdateProfile)
	users.DELETE("/profile", userHandler.DeleteAccount)
	users.POST("/change-password", userHandler.ChangePassword)

	// Admin routes
	admin := api.Group("/admin")
	admin.Use(middleware.JWTAuth())
	admin.Use(middleware.RequireRole("admin"))
	admin.GET("/users", userHandler.ListUsers)
	admin.GET("/users/:id", userHandler.GetUser)
	admin.PUT("/users/:id", userHandler.UpdateUser)
	admin.DELETE("/users/:id", userHandler.DeleteUser)

	// WebSocket routes
	ws := e.Group("/ws")
	ws.Use(middleware.JWTAuth())
	ws.GET("/connect", handlers.WebSocketHandler)
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
	"net/http"
	"time"

	"${this.options.name}/internal/models"
	"${this.options.name}/internal/services"
	"github.com/labstack/echo/v4"
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

func (h *AuthHandler) Register(c echo.Context) error {
	var req models.RegisterRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
	}

	tokenResponse, err := h.authService.Register(&req)
	if err != nil {
		if err.Error() == "user already exists" {
			return c.JSON(http.StatusConflict, map[string]string{
				"error": err.Error(),
			})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to register user",
		})
	}

	return c.JSON(http.StatusCreated, tokenResponse)
}

func (h *AuthHandler) Login(c echo.Context) error {
	var req models.LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
	}

	tokenResponse, err := h.authService.Login(&req)
	if err != nil {
		if err.Error() == "invalid credentials" || err.Error() == "user account is disabled" {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"error": err.Error(),
			})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to login",
		})
	}

	// Set secure cookie
	cookie := new(http.Cookie)
	cookie.Name = "refresh_token"
	cookie.Value = tokenResponse.RefreshToken
	cookie.Expires = time.Now().Add(7 * 24 * time.Hour)
	cookie.Path = "/"
	cookie.HttpOnly = true
	cookie.SameSite = http.SameSiteLaxMode
	cookie.Secure = false // Should be true in production with HTTPS
	c.SetCookie(cookie)

	return c.JSON(http.StatusOK, tokenResponse)
}

func (h *AuthHandler) RefreshToken(c echo.Context) error {
	cookie, err := c.Cookie("refresh_token")
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "Refresh token not found",
		})
	}

	tokenResponse, err := h.authService.RefreshToken(cookie.Value)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "Invalid refresh token",
		})
	}

	return c.JSON(http.StatusOK, tokenResponse)
}

func (h *AuthHandler) Logout(c echo.Context) error {
	// Clear refresh token cookie
	cookie := new(http.Cookie)
	cookie.Name = "refresh_token"
	cookie.Value = ""
	cookie.Expires = time.Now().Add(-time.Hour)
	cookie.Path = "/"
	cookie.HttpOnly = true
	c.SetCookie(cookie)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Logged out successfully",
	})
}`
      },
      {
        path: 'internal/handlers/user_handler.go',
        content: `package handlers

import (
	"net/http"
	"strconv"

	"${this.options.name}/internal/models"
	"${this.options.name}/internal/services"
	"github.com/labstack/echo/v4"
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

func (h *UserHandler) GetProfile(c echo.Context) error {
	userID := c.Get("userID").(uint)
	
	user, err := h.userService.GetUserByID(userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{
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

	return c.JSON(http.StatusOK, response)
}

func (h *UserHandler) UpdateProfile(c echo.Context) error {
	userID := c.Get("userID").(uint)
	
	var req models.UpdateUserRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
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
		return c.JSON(http.StatusInternalServerError, map[string]string{
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

	return c.JSON(http.StatusOK, response)
}

func (h *UserHandler) ChangePassword(c echo.Context) error {
	userID := c.Get("userID").(uint)
	
	var req models.ChangePasswordRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	if err := c.Validate(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
	}

	if err := h.userService.ChangePassword(userID, req.OldPassword, req.NewPassword); err != nil {
		if err.Error() == "invalid old password" {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": err.Error(),
			})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to change password",
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Password changed successfully",
	})
}

func (h *UserHandler) DeleteAccount(c echo.Context) error {
	userID := c.Get("userID").(uint)
	
	if err := h.userService.DeleteUser(userID); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to delete account",
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Account deleted successfully",
	})
}

// Admin handlers
func (h *UserHandler) ListUsers(c echo.Context) error {
	page, _ := strconv.Atoi(c.QueryParam("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(c.QueryParam("limit"))
	if limit < 1 {
		limit = 10
	}

	users, total, err := h.userService.ListUsers(page, limit)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to list users",
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"users": users,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

func (h *UserHandler) GetUser(c echo.Context) error {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid user ID",
		})
	}

	user, err := h.userService.GetUserByID(uint(id))
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{
			"error": "User not found",
		})
	}

	return c.JSON(http.StatusOK, user)
}

func (h *UserHandler) UpdateUser(c echo.Context) error {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid user ID",
		})
	}

	var req map[string]interface{}
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid request body",
		})
	}

	user, err := h.userService.UpdateUser(uint(id), req)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to update user",
		})
	}

	return c.JSON(http.StatusOK, user)
}

func (h *UserHandler) DeleteUser(c echo.Context) error {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{
			"error": "Invalid user ID",
		})
	}

	if err := h.userService.DeleteUser(uint(id)); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "Failed to delete user",
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "User deleted successfully",
	})
}`
      },
      {
        path: 'internal/handlers/health_handler.go',
        content: `package handlers

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
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

func (h *HealthHandler) Check(c echo.Context) error {
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
		return c.JSON(http.StatusOK, health)
	}
	return c.JSON(http.StatusServiceUnavailable, health)
}`
      },
      {
        path: 'internal/handlers/websocket_handler.go',
        content: `package handlers

import (
	"log"

	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v4"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

type Message struct {
	Type    string      \`json:"type"\`
	Payload interface{} \`json:"payload"\`
}

func WebSocketHandler(c echo.Context) error {
	ws, err := upgrader.Upgrade(c.Response(), c.Request(), nil)
	if err != nil {
		return err
	}
	defer ws.Close()

	userID := c.Get("userID").(uint)
	log.Printf("WebSocket connection established for user %d", userID)

	// Send welcome message
	welcome := Message{
		Type: "welcome",
		Payload: map[string]interface{}{
			"message": "Connected to WebSocket",
			"userID":  userID,
		},
	}

	if err := ws.WriteJSON(welcome); err != nil {
		log.Printf("Error sending welcome message: %v", err)
		return err
	}

	// Handle incoming messages
	for {
		var msg Message
		if err := ws.ReadJSON(&msg); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		// Process message based on type
		switch msg.Type {
		case "ping":
			pong := Message{
				Type:    "pong",
				Payload: msg.Payload,
			}
			if err := ws.WriteJSON(pong); err != nil {
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

	return nil
}`
      }
    ];
  }
  
  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'internal/middleware/auth.go',
        content: `package middleware

import (
	"net/http"
	"strings"

	"${this.options.name}/internal/config"
	"${this.options.name}/internal/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

func JWTAuth() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "Authorization header missing",
				})
			}

			// Extract token from "Bearer <token>"
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				return c.JSON(http.StatusUnauthorized, map[string]string{
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
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "Invalid or expired token",
				})
			}

			// Extract claims
			claims, ok := token.Claims.(*models.TokenClaims)
			if !ok {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "Invalid token claims",
				})
			}

			// Set user ID in context
			c.Set("userID", claims.UserID)
			c.Set("email", claims.Email)
			return next(c)
		}
	}
}

func RequireRole(role string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// This is a placeholder - implement role checking logic
			// You would typically check the user's role from the database
			// or include it in the JWT claims
			return next(c)
		}
	}
}`
      },
      {
        path: 'internal/middleware/cors.go',
        content: `package middleware

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func CORS() echo.MiddlewareFunc {
	return middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{"http://localhost:3000", "http://localhost:5173"},
		AllowMethods:     []string{echo.GET, echo.POST, echo.PUT, echo.PATCH, echo.DELETE, echo.OPTIONS},
		AllowHeaders:     []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
		ExposeHeaders:    []string{echo.HeaderContentLength},
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
	"net/http"
	"time"

	"github.com/go-redis/redis_rate/v10"
	"github.com/labstack/echo/v4"
	"github.com/redis/go-redis/v9"
)

func RateLimit(redisClient *redis.Client, limit int, window time.Duration) echo.MiddlewareFunc {
	limiter := redis_rate.NewLimiter(redisClient)
	
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx := context.Background()
			
			// Use IP address as key
			key := fmt.Sprintf("rate_limit:%s", c.RealIP())
			
			// Check rate limit
			res, err := limiter.Allow(ctx, key, redis_rate.PerDuration(limit, window))
			if err != nil {
				return c.JSON(http.StatusInternalServerError, map[string]string{
					"error": "Rate limit error",
				})
			}
			
			if !res.Allowed {
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error": "Rate limit exceeded",
				})
			}
			
			// Add rate limit headers
			c.Response().Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
			c.Response().Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", res.Remaining))
			c.Response().Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", res.ResetAfter.Unix()))
			
			return next(c)
		}
	}
}`
      },
      {
        path: 'internal/middleware/logger.go',
        content: `package middleware

import (
	"time"

	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

func Logger(log *logrus.Logger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()

			// Process request
			err := next(c)

			// Log request details
			latency := time.Since(start)
			status := c.Response().Status
			if err != nil {
				status = err.(*echo.HTTPError).Code
			}

			entry := log.WithFields(logrus.Fields{
				"status":     status,
				"method":     c.Request().Method,
				"path":       c.Request().URL.Path,
				"ip":         c.RealIP(),
				"latency":    latency,
				"user-agent": c.Request().UserAgent(),
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
	}
}`
      },
      {
        path: 'internal/middleware/recovery.go',
        content: `package middleware

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

func Recovery(log *logrus.Logger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			defer func() {
				if r := recover(); r != nil {
					err, ok := r.(error)
					if !ok {
						err = fmt.Errorf("%v", r)
					}

					log.WithFields(logrus.Fields{
						"error":      err,
						"request":    c.Request().URL.Path,
						"method":     c.Request().Method,
						"client_ip":  c.RealIP(),
						"user_agent": c.Request().UserAgent(),
					}).Error("Panic recovered")

					c.JSON(http.StatusInternalServerError, map[string]string{
						"error": "Internal server error",
					})
				}
			}()
			return next(c)
		}
	}
}`
      },
      {
        path: 'internal/middleware/validator.go',
        content: `package middleware

import (
	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
)

type CustomValidator struct {
	validator *validator.Validate
}

func (cv *CustomValidator) Validate(i interface{}) error {
	return cv.validator.Struct(i)
}

func NewValidator() *CustomValidator {
	return &CustomValidator{
		validator: validator.New(),
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
	viper.SetDefault("APP_NAME", "echo-service")
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
	"net/http"
	"time"

	"${this.options.name}/internal/config"
	"${this.options.name}/internal/middleware"
	"${this.options.name}/internal/routes"
	"github.com/labstack/echo/v4"
	echoSwagger "github.com/swaggo/echo-swagger"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"github.com/redis/go-redis/v9"
)

type Server struct {
	config     *config.Config
	echo       *echo.Echo
	db         *gorm.DB
	redis      *redis.Client
	logger     *logrus.Logger
}

func New(cfg *config.Config, db *gorm.DB, redis *redis.Client) *Server {
	// Create logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Create Echo instance
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	// Set custom validator
	e.Validator = middleware.NewValidator()

	// Global middleware
	e.Pre(middleware.RemoveTrailingSlash())
	e.Use(middleware.Recovery(logger))
	e.Use(middleware.Logger(logger))
	e.Use(middleware.RequestID())
	e.Use(middleware.CORS())
	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{
		Level: 5,
	}))
	e.Use(middleware.RateLimit(redis, 100, time.Minute))

	// Swagger documentation
	if cfg.AppEnv != "production" {
		e.GET("/swagger/*", echoSwagger.WrapHandler)
	}

	// Setup routes
	routes.Setup(e, db, redis)

	return &Server{
		config: cfg,
		echo:   e,
		db:     db,
		redis:  redis,
		logger: logger,
	}
}

func (s *Server) Start() error {
	address := fmt.Sprintf(":%s", s.config.AppPort)
	return s.echo.Start(address)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.echo.Shutdown(ctx)
}`;
  }
  
  // Implement abstract methods from BackendTemplateGenerator
  protected async generateAPIDocs(projectPath: string): Promise<void> {
    // API docs are generated via Swagger annotations in the code
    // No additional generation needed as swag init is called via Makefile
  }
  
  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    // Docker files are already generated in GoBackendGenerator
    // No additional Docker files needed for Echo
  }
  
  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    // Documentation is already generated in GoBackendGenerator
    // No additional documentation needed for Echo
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
