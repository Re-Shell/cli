import { GoBackendGenerator } from './go-base-generator';

export class GinGenerator extends GoBackendGenerator {
  constructor() {
    super('Gin');
  }
  
  // Override getOptions to store options
  async generate(projectPath: string, options: any): Promise<void> {
    this.options = options;
    await super.generate(projectPath, options);
  }
  
  protected getFrameworkDependencies(): string[] {
    return [
      'github.com/gin-gonic/gin v1.9.1',
      'github.com/gin-contrib/cors v1.5.0',
      'github.com/gin-contrib/sessions v0.0.5',
      'github.com/gin-contrib/requestid v0.0.6',
      'github.com/gin-contrib/gzip v0.0.6',
      'github.com/gin-contrib/timeout v0.0.3',
      'github.com/gin-contrib/pprof v1.4.0',
      'github.com/swaggo/gin-swagger v1.6.0',
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
// @description     A Gin-based microservice API
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
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"github.com/redis/go-redis/v9"
)

func Setup(router *gin.Engine, db *gorm.DB, redis *redis.Client) {
	// Initialize handlers
	healthHandler := handlers.NewHealthHandler(db)
	authHandler := handlers.NewAuthHandler(db)
	userHandler := handlers.NewUserHandler(db)

	// Public routes
	public := router.Group("/api/v1")
	{
		public.GET("/health", healthHandler.Check)
		
		// Auth routes
		auth := public.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.POST("/refresh", authHandler.RefreshToken)
		}
	}

	// Protected routes
	protected := router.Group("/api/v1")
	protected.Use(middleware.JWTAuth())
	{
		// User routes
		users := protected.Group("/users")
		{
			users.GET("/profile", userHandler.GetProfile)
			users.PUT("/profile", userHandler.UpdateProfile)
			users.DELETE("/profile", userHandler.DeleteAccount)
			users.POST("/change-password", userHandler.ChangePassword)
		}
	}

	// Admin routes
	admin := router.Group("/api/v1/admin")
	admin.Use(middleware.JWTAuth())
	admin.Use(middleware.RequireRole("admin"))
	{
		admin.GET("/users", userHandler.ListUsers)
		admin.GET("/users/:id", userHandler.GetUser)
		admin.PUT("/users/:id", userHandler.UpdateUser)
		admin.DELETE("/users/:id", userHandler.DeleteUser)
	}

	// WebSocket routes
	ws := router.Group("/ws")
	ws.Use(middleware.JWTAuth())
	{
		ws.GET("/connect", handlers.WebSocketHandler)
	}
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
	"${this.options.name}/internal/utils"
	"github.com/gin-gonic/gin"
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

func (h *AuthHandler) Register(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, "Invalid request body")
		return
	}

	tokenResponse, err := h.authService.Register(&req)
	if err != nil {
		if err.Error() == "user already exists" {
			utils.RespondWithError(c, http.StatusConflict, err.Error())
			return
		}
		utils.RespondWithError(c, http.StatusInternalServerError, "Failed to register user")
		return
	}

	utils.RespondWithJSON(c, http.StatusCreated, tokenResponse)
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, "Invalid request body")
		return
	}

	tokenResponse, err := h.authService.Login(&req)
	if err != nil {
		if err.Error() == "invalid credentials" || err.Error() == "user account is disabled" {
			utils.RespondWithError(c, http.StatusUnauthorized, err.Error())
			return
		}
		utils.RespondWithError(c, http.StatusInternalServerError, "Failed to login")
		return
	}

	// Set secure cookie
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		"refresh_token",
		tokenResponse.RefreshToken,
		60*60*24*7, // 7 days
		"/",
		"",
		false, // Should be true in production with HTTPS
		true,  // HttpOnly
	)

	utils.RespondWithJSON(c, http.StatusOK, tokenResponse)
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, "Refresh token not found")
		return
	}

	tokenResponse, err := h.authService.RefreshToken(refreshToken)
	if err != nil {
		utils.RespondWithError(c, http.StatusUnauthorized, "Invalid refresh token")
		return
	}

	utils.RespondWithJSON(c, http.StatusOK, tokenResponse)
}

func (h *AuthHandler) Logout(c *gin.Context) {
	// Clear refresh token cookie
	c.SetCookie(
		"refresh_token",
		"",
		-1,
		"/",
		"",
		false,
		true,
	)

	utils.RespondWithMessage(c, http.StatusOK, "Logged out successfully")
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
	"${this.options.name}/internal/utils"
	"github.com/gin-gonic/gin"
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

func (h *UserHandler) GetProfile(c *gin.Context) {
	userID := c.GetUint("userID")
	
	user, err := h.userService.GetUserByID(userID)
	if err != nil {
		utils.RespondWithError(c, http.StatusNotFound, "User not found")
		return
	}

	utils.RespondWithJSON(c, http.StatusOK, models.UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		IsActive:  user.IsActive,
		CreatedAt: user.CreatedAt,
	})
}

func (h *UserHandler) UpdateProfile(c *gin.Context) {
	userID := c.GetUint("userID")
	
	var req models.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, "Invalid request body")
		return
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
		utils.RespondWithError(c, http.StatusInternalServerError, "Failed to update profile")
		return
	}

	utils.RespondWithJSON(c, http.StatusOK, models.UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		IsActive:  user.IsActive,
		CreatedAt: user.CreatedAt,
	})
}

func (h *UserHandler) ChangePassword(c *gin.Context) {
	userID := c.GetUint("userID")
	
	var req models.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := h.userService.ChangePassword(userID, req.OldPassword, req.NewPassword); err != nil {
		if err.Error() == "invalid old password" {
			utils.RespondWithError(c, http.StatusBadRequest, err.Error())
			return
		}
		utils.RespondWithError(c, http.StatusInternalServerError, "Failed to change password")
		return
	}

	utils.RespondWithMessage(c, http.StatusOK, "Password changed successfully")
}

func (h *UserHandler) DeleteAccount(c *gin.Context) {
	userID := c.GetUint("userID")
	
	if err := h.userService.DeleteUser(userID); err != nil {
		utils.RespondWithError(c, http.StatusInternalServerError, "Failed to delete account")
		return
	}

	utils.RespondWithMessage(c, http.StatusOK, "Account deleted successfully")
}

// Admin handlers
func (h *UserHandler) ListUsers(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))

	users, total, err := h.userService.ListUsers(page, limit)
	if err != nil {
		utils.RespondWithError(c, http.StatusInternalServerError, "Failed to list users")
		return
	}

	response := map[string]interface{}{
		"users": users,
		"total": total,
		"page":  page,
		"limit": limit,
	}

	utils.RespondWithJSON(c, http.StatusOK, response)
}

func (h *UserHandler) GetUser(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, "Invalid user ID")
		return
	}

	user, err := h.userService.GetUserByID(uint(id))
	if err != nil {
		utils.RespondWithError(c, http.StatusNotFound, "User not found")
		return
	}

	utils.RespondWithJSON(c, http.StatusOK, user)
}

func (h *UserHandler) UpdateUser(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, "Invalid user ID")
		return
	}

	var req map[string]interface{}
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, "Invalid request body")
		return
	}

	user, err := h.userService.UpdateUser(uint(id), req)
	if err != nil {
		utils.RespondWithError(c, http.StatusInternalServerError, "Failed to update user")
		return
	}

	utils.RespondWithJSON(c, http.StatusOK, user)
}

func (h *UserHandler) DeleteUser(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 32)
	if err != nil {
		utils.RespondWithError(c, http.StatusBadRequest, "Invalid user ID")
		return
	}

	if err := h.userService.DeleteUser(uint(id)); err != nil {
		utils.RespondWithError(c, http.StatusInternalServerError, "Failed to delete user")
		return
	}

	utils.RespondWithMessage(c, http.StatusOK, "User deleted successfully")
}`
      },
      {
        path: 'internal/handlers/websocket_handler.go',
        content: `package handlers

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// Allow connections from any origin in development
		// In production, implement proper origin checking
		return true
	},
}

type Message struct {
	Type    string      \`json:"type"\`
	Payload interface{} \`json:"payload"\`
}

func WebSocketHandler(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	userID := c.GetUint("userID")
	log.Printf("WebSocket connection established for user %d", userID)

	// Send welcome message
	welcome := Message{
		Type: "welcome",
		Payload: map[string]interface{}{
			"message": "Connected to WebSocket",
			"userID":  userID,
		},
	}

	if err := conn.WriteJSON(welcome); err != nil {
		log.Printf("Error sending welcome message: %v", err)
		return
	}

	// Handle incoming messages
	for {
		var msg Message
		if err := conn.ReadJSON(&msg); err != nil {
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
			if err := conn.WriteJSON(pong); err != nil {
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
	"${this.options.name}/internal/utils"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func JWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			utils.RespondWithError(c, http.StatusUnauthorized, "Authorization header missing")
			c.Abort()
			return
		}

		// Extract token from "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			utils.RespondWithError(c, http.StatusUnauthorized, "Invalid authorization header format")
			c.Abort()
			return
		}

		tokenString := parts[1]
		
		// Parse and validate token
		cfg, _ := config.Load()
		token, err := jwt.ParseWithClaims(tokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(cfg.JWTSecret), nil
		})

		if err != nil || !token.Valid {
			utils.RespondWithError(c, http.StatusUnauthorized, "Invalid or expired token")
			c.Abort()
			return
		}

		// Extract claims
		claims, ok := token.Claims.(*models.TokenClaims)
		if !ok {
			utils.RespondWithError(c, http.StatusUnauthorized, "Invalid token claims")
			c.Abort()
			return
		}

		// Set user ID in context
		c.Set("userID", claims.UserID)
		c.Set("email", claims.Email)
		c.Next()
	}
}

func RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// This is a placeholder - implement role checking logic
		// You would typically check the user's role from the database
		// or include it in the JWT claims
		c.Next()
	}
}`
      },
      {
        path: 'internal/middleware/cors.go',
        content: `package middleware

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"time"
)

func CORS() gin.HandlerFunc {
	return cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000", "http://localhost:5173"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
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

	"${this.options.name}/internal/utils"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis_rate/v10"
	"github.com/redis/go-redis/v9"
)

func RateLimit(redisClient *redis.Client, limit int, window time.Duration) gin.HandlerFunc {
	limiter := redis_rate.NewLimiter(redisClient)
	
	return func(c *gin.Context) {
		ctx := context.Background()
		
		// Use IP address as key
		key := fmt.Sprintf("rate_limit:%s", c.ClientIP())
		
		// Check rate limit
		res, err := limiter.Allow(ctx, key, redis_rate.PerDuration(limit, window))
		if err != nil {
			utils.RespondWithError(c, http.StatusInternalServerError, "Rate limit error")
			c.Abort()
			return
		}
		
		if !res.Allowed {
			utils.RespondWithError(c, http.StatusTooManyRequests, "Rate limit exceeded")
			c.Abort()
			return
		}
		
		// Add rate limit headers
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", res.Remaining))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", res.ResetAfter.Unix()))
		
		c.Next()
	}
}`
      },
      {
        path: 'internal/middleware/logger.go',
        content: `package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func Logger(log *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		// Log request details
		latency := time.Since(start)
		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()

		if raw != "" {
			path = path + "?" + raw
		}

		entry := log.WithFields(logrus.Fields{
			"status":     statusCode,
			"method":     method,
			"path":       path,
			"ip":         clientIP,
			"latency":    latency,
			"user-agent": c.Request.UserAgent(),
		})

		if statusCode >= 500 {
			entry.Error("Server error")
		} else if statusCode >= 400 {
			entry.Warn("Client error")
		} else {
			entry.Info("Request completed")
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

	"${this.options.name}/internal/utils"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func Recovery(log *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				log.WithFields(logrus.Fields{
					"error":      err,
					"request":    c.Request.URL.Path,
					"method":     c.Request.Method,
					"client_ip":  c.ClientIP(),
					"user_agent": c.Request.UserAgent(),
				}).Error("Panic recovered")

				utils.RespondWithError(c, http.StatusInternalServerError, "Internal server error")
				c.Abort()
			}
		}()
		c.Next()
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
	viper.SetDefault("APP_NAME", "gin-service")
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
	"github.com/gin-contrib/gzip"
	"github.com/gin-contrib/requestid"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"github.com/redis/go-redis/v9"
)

type Server struct {
	config      *config.Config
	router      *gin.Engine
	db          *gorm.DB
	redis       *redis.Client
	httpServer  *http.Server
	logger      *logrus.Logger
}

func New(cfg *config.Config, db *gorm.DB, redis *redis.Client) *Server {
	// Configure Gin mode
	if cfg.AppEnv == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Create router
	router := gin.New()

	// Global middleware
	router.Use(middleware.Recovery(logger))
	router.Use(middleware.Logger(logger))
	router.Use(requestid.New())
	router.Use(middleware.CORS())
	router.Use(gzip.Gzip(gzip.DefaultCompression))
	router.Use(middleware.RateLimit(redis, 100, time.Minute))

	// Swagger documentation
	if cfg.AppEnv != "production" {
		router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	}

	// Setup routes
	routes.Setup(router, db, redis)

	return &Server{
		config: cfg,
		router: router,
		db:     db,
		redis:  redis,
		logger: logger,
	}
}

func (s *Server) Start() error {
	s.httpServer = &http.Server{
		Addr:           fmt.Sprintf(":%s", s.config.AppPort),
		Handler:        s.router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}`;
  }
  
  // Implement abstract methods from BackendTemplateGenerator
  protected async generateAPIDocs(projectPath: string): Promise<void> {
    // API docs are generated via Swagger annotations in the code
    // No additional generation needed as swag init is called via Makefile
  }
  
  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    // Docker files are already generated in GoBackendGenerator
    // No additional Docker files needed for Gin
  }
  
  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    // Documentation is already generated in GoBackendGenerator
    // No additional documentation needed for Gin
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
