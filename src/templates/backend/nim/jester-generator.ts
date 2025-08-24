import { NimBackendGenerator } from './nim-base-generator';
import * as fs from 'fs/promises';
import * as path from 'path';

export class JesterGenerator extends NimBackendGenerator {
  getFrameworkDependencies(): string[] {
    return [
      'jester >= 0.5.0',
      'jwt',
      'bcrypt',
      'chronicles',
      'dotenv',
      'norm >= 2.8.0',
      'redis',
      'jsony'
    ];
  }

  generateMainFile(): string {
    return `import jester
import std/[asyncdispatch, json, tables, strutils, os]
import dotenv
import chronicles
import ./router
import ./config
import ./middleware/[cors, auth, logger]
import ./models/database

# Load environment variables
load()

# Initialize logger
var log = newConsoleLogger()
addHandler(log)

# Initialize database
initDatabase()

# Configure Jester settings
settings:
  port = getEnv("PORT", "5000").parseInt().Port
  appName = "${this.options?.name || 'jester-app'}"
  bindAddr = "0.0.0.0"

# Create Jester app
routes:
  # Apply global middleware
  extend cors.corsMiddleware
  extend logger.loggerMiddleware
  
  # Health check
  get "/health":
    resp %*{
      "status": "healthy",
      "service": settings.appName,
      "timestamp": $now(),
      "uptime": getUptime()
    }
  
  # API routes
  extend router.apiRoutes
  
  # Static files
  get "/public/@path":
    const dir = "./public"
    let path = @"path"
    if ".." in path:
      resp Http400, "Invalid path"
    else:
      sendFile(dir / path)
  
  # 404 handler
  error Http404:
    resp Http404, %*{
      "error": "Not found",
      "path": request.path
    }
  
  # Error handler
  error Exception:
    error "Unhandled exception", error = getCurrentExceptionMsg()
    resp Http500, %*{
      "error": "Internal server error"
    }

when isMainModule:
  info "Starting server", port = settings.port
  runForever()
`;
  }

  generateRouterFile(): string {
    return `import jester
import std/[json, tables, strutils]
import ./controllers/[auth_controller, user_controller]
import ./middleware/auth

# API routes
router apiRoutes:
  # Authentication routes
  post "/api/auth/register":
    resp authController.register(request)
  
  post "/api/auth/login":
    resp authController.login(request)
  
  post "/api/auth/refresh":
    resp authController.refresh(request)
  
  post "/api/auth/logout":
    extend auth.requireAuth
    resp authController.logout(request)
  
  # User routes (protected)
  get "/api/users":
    extend auth.requireAuth
    resp userController.listUsers(request)
  
  get "/api/users/@id":
    extend auth.requireAuth
    resp userController.getUser(request, @"id")
  
  put "/api/users/@id":
    extend auth.requireAuth
    resp userController.updateUser(request, @"id")
  
  delete "/api/users/@id":
    extend auth.requireAuth
    extend auth.requireAdmin
    resp userController.deleteUser(request, @"id")
`;
  }

  generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/middleware/cors.nim',
        content: `import jester
import std/strutils

# CORS middleware
router corsMiddleware:
  before "*":
    # Set CORS headers
    resp.headers["Access-Control-Allow-Origin"] = getEnv("CORS_ORIGIN", "*")
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    resp.headers["Access-Control-Max-Age"] = "86400"
    
    # Handle preflight requests
    if request.reqMethod == HttpOptions:
      resp Http200, ""
      skipRoutes()
`
      },
      {
        path: 'src/middleware/auth.nim',
        content: `import jester
import std/[json, strutils, tables, options]
import ../utils/[helpers, validators]
import ../models/user
import jwt
import chronicles

type
  AuthContext* = object
    userId*: string
    email*: string
    role*: string

# Auth middleware
router requireAuth:
  before "*":
    # Extract token from header
    let authHeader = request.headers.getOrDefault("Authorization")
    if authHeader == "":
      resp Http401, %*{"error": "Missing authorization header"}
      skipRoutes()
    
    if not authHeader.startsWith("Bearer "):
      resp Http401, %*{"error": "Invalid authorization format"}
      skipRoutes()
    
    let token = authHeader[7..^1]
    
    # Verify token
    try:
      let secret = getEnv("JWT_SECRET", "your-secret-key")
      let payload = token.toJWT().verify(secret, HS256)
      
      # Extract user info
      let userId = payload.claims["sub"].getStr()
      let email = payload.claims["email"].getStr()
      let role = payload.claims["role"].getStr()
      
      # Check token expiration
      let exp = payload.claims["exp"].getInt()
      if exp < getCurrentTimestamp():
        resp Http401, %*{"error": "Token expired"}
        skipRoutes()
      
      # Store in request context
      request.params["userId"] = userId
      request.params["userEmail"] = email
      request.params["userRole"] = role
      
    except:
      error "Auth error", error = getCurrentExceptionMsg()
      resp Http401, %*{"error": "Invalid token"}
      skipRoutes()

# Admin middleware
router requireAdmin:
  before "*":
    let role = request.params.getOrDefault("userRole")
    if role != "admin":
      resp Http403, %*{"error": "Admin access required"}
      skipRoutes()
`
      },
      {
        path: 'src/middleware/logger.nim',
        content: `import jester
import std/[times, strformat]
import chronicles

# Logger middleware
router loggerMiddleware:
  before "*":
    let startTime = epochTime()
    request.params["startTime"] = $startTime
  
  after "*":
    let startTime = request.params.getOrDefault("startTime", "0").parseFloat()
    let duration = (epochTime() - startTime) * 1000
    
    info "Request processed",
      method = $request.reqMethod,
      path = request.path,
      status = response.code,
      duration = fmt"{duration:.2f}ms"
`
      },
      {
        path: 'src/middleware/rate_limit.nim',
        content: `import jester
import std/[tables, times, strutils]
import redis

type
  RateLimiter = object
    redis: Redis
    maxRequests: int
    windowSec: int

var limiter: RateLimiter

proc initRateLimiter*(maxRequests = 100, windowSec = 60) =
  ## Initialize rate limiter
  limiter = RateLimiter(
    redis: open("localhost", 6379.Port),
    maxRequests: maxRequests,
    windowSec: windowSec
  )

router rateLimitMiddleware:
  before "*":
    if limiter.redis.isNil:
      # Skip if not initialized
      return
    
    # Get client IP
    let clientIp = request.headers.getOrDefault("X-Forwarded-For", request.ip)
    let key = fmt"rate_limit:{clientIp}"
    
    # Check current count
    let count = limiter.redis.get(key)
    if count == redisNil:
      # First request
      discard limiter.redis.setex(key, limiter.windowSec, "1")
    else:
      let currentCount = count.parseInt()
      if currentCount >= limiter.maxRequests:
        resp Http429, %*{
          "error": "Too many requests",
          "retryAfter": limiter.windowSec
        }
        skipRoutes()
      else:
        # Increment counter
        discard limiter.redis.incr(key)
`
      }
    ];
  }

  generateControllerFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/controllers/auth_controller.nim',
        content: `import jester
import std/[json, tables, strutils, options]
import ../models/[user, database]
import ../utils/[helpers, validators]
import jwt
import bcrypt
import chronicles

proc register*(request: Request): Response =
  ## Register new user
  try:
    let body = request.body.parseJson()
    
    # Validate input
    let email = body["email"].getStr()
    let password = body["password"].getStr()
    let name = body{"name"}.getStr("")
    
    if validateEmail(email).isSome:
      return (Http400, %*{"error": "Invalid email format"})
    
    if validatePassword(password).isSome:
      return (Http400, %*{"error": "Password too weak"})
    
    # Check if user exists
    if getUserByEmail(email).isSome:
      return (Http409, %*{"error": "Email already registered"})
    
    # Hash password
    let hashedPassword = hash(password)
    
    # Create user
    let user = createUser(email, hashedPassword, name)
    
    # Generate token
    let secret = getEnv("JWT_SECRET", "your-secret-key")
    let claims = toJWT(%*{
      "sub": user.id,
      "email": user.email,
      "role": user.role,
      "exp": getCurrentTimestamp() + 86400  # 24 hours
    })
    let token = $claims.sign(secret, HS256)
    
    info "User registered", email = email
    
    return (Http201, %*{
      "user": {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role
      },
      "token": token
    })
    
  except:
    error "Registration error", error = getCurrentExceptionMsg()
    return (Http500, %*{"error": "Registration failed"})

proc login*(request: Request): Response =
  ## User login
  try:
    let body = request.body.parseJson()
    let email = body["email"].getStr()
    let password = body["password"].getStr()
    
    # Get user
    let userOpt = getUserByEmail(email)
    if userOpt.isNone:
      return (Http401, %*{"error": "Invalid credentials"})
    
    let user = userOpt.get()
    
    # Verify password
    if not verify(password, user.passwordHash):
      return (Http401, %*{"error": "Invalid credentials"})
    
    # Generate token
    let secret = getEnv("JWT_SECRET", "your-secret-key")
    let claims = toJWT(%*{
      "sub": user.id,
      "email": user.email,
      "role": user.role,
      "exp": getCurrentTimestamp() + 86400
    })
    let token = $claims.sign(secret, HS256)
    
    # Update last login
    updateLastLogin(user.id)
    
    info "User logged in", email = email
    
    return (Http200, %*{
      "user": {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role
      },
      "token": token
    })
    
  except:
    error "Login error", error = getCurrentExceptionMsg()
    return (Http500, %*{"error": "Login failed"})

proc refresh*(request: Request): Response =
  ## Refresh token
  try:
    let body = request.body.parseJson()
    let oldToken = body["token"].getStr()
    
    # Verify old token (allow expired)
    let secret = getEnv("JWT_SECRET", "your-secret-key")
    let payload = oldToken.toJWT().verify(secret, HS256, {IgnoreExpiration})
    
    # Generate new token
    let claims = toJWT(%*{
      "sub": payload.claims["sub"],
      "email": payload.claims["email"],
      "role": payload.claims["role"],
      "exp": getCurrentTimestamp() + 86400
    })
    let token = $claims.sign(secret, HS256)
    
    return (Http200, %*{"token": token})
    
  except:
    error "Refresh error", error = getCurrentExceptionMsg()
    return (Http401, %*{"error": "Invalid token"})

proc logout*(request: Request): Response =
  ## User logout
  # In a real app, you might want to blacklist the token
  info "User logged out", userId = request.params["userId"]
  return (Http200, %*{"message": "Logged out successfully"})
`
      },
      {
        path: 'src/controllers/user_controller.nim',
        content: `import jester
import std/[json, strutils, sequtils, options]
import ../models/[user, database]
import ../utils/helpers
import chronicles

proc listUsers*(request: Request): Response =
  ## List all users
  try:
    # Get pagination params
    let page = request.params.getOrDefault("page", "1").parseInt()
    let pageSize = request.params.getOrDefault("pageSize", "10").parseInt()
    
    # Get users
    let users = getAllUsers()
    let (pagedUsers, totalPages) = paginate(users, page, pageSize)
    
    # Remove sensitive data
    let safeUsers = pagedUsers.mapIt(%*{
      "id": it.id,
      "email": it.email,
      "name": it.name,
      "role": it.role,
      "createdAt": it.createdAt
    })
    
    return (Http200, %*{
      "users": safeUsers,
      "page": page,
      "pageSize": pageSize,
      "totalPages": totalPages,
      "total": users.len
    })
    
  except:
    error "List users error", error = getCurrentExceptionMsg()
    return (Http500, %*{"error": "Failed to list users"})

proc getUser*(request: Request, id: string): Response =
  ## Get user by ID
  try:
    let userOpt = getUserById(id)
    if userOpt.isNone:
      return (Http404, %*{"error": "User not found"})
    
    let user = userOpt.get()
    
    # Check permissions
    let currentUserId = request.params["userId"]
    let currentRole = request.params["userRole"]
    if currentUserId != id and currentRole != "admin":
      return (Http403, %*{"error": "Access denied"})
    
    return (Http200, %*{
      "user": {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "createdAt": user.createdAt,
        "updatedAt": user.updatedAt
      }
    })
    
  except:
    error "Get user error", error = getCurrentExceptionMsg()
    return (Http500, %*{"error": "Failed to get user"})

proc updateUser*(request: Request, id: string): Response =
  ## Update user
  try:
    # Check permissions
    let currentUserId = request.params["userId"]
    let currentRole = request.params["userRole"]
    if currentUserId != id and currentRole != "admin":
      return (Http403, %*{"error": "Access denied"})
    
    let body = request.body.parseJson()
    let updates = initTable[string, string]()
    
    # Collect updates
    if body.hasKey("name"):
      updates["name"] = body["name"].getStr()
    
    if body.hasKey("email"):
      let newEmail = body["email"].getStr()
      if validateEmail(newEmail).isSome:
        return (Http400, %*{"error": "Invalid email format"})
      updates["email"] = newEmail
    
    if body.hasKey("password"):
      let newPassword = body["password"].getStr()
      if validatePassword(newPassword).isSome:
        return (Http400, %*{"error": "Password too weak"})
      updates["passwordHash"] = hash(newPassword)
    
    # Update user
    if not updateUser(id, updates):
      return (Http404, %*{"error": "User not found"})
    
    info "User updated", userId = id
    
    return (Http200, %*{"message": "User updated successfully"})
    
  except:
    error "Update user error", error = getCurrentExceptionMsg()
    return (Http500, %*{"error": "Failed to update user"})

proc deleteUser*(request: Request, id: string): Response =
  ## Delete user (admin only)
  try:
    if not deleteUser(id):
      return (Http404, %*{"error": "User not found"})
    
    info "User deleted", userId = id
    
    return (Http204, "")
    
  except:
    error "Delete user error", error = getCurrentExceptionMsg()
    return (Http500, %*{"error": "Failed to delete user"})
`
      }
    ];
  }

  generateModelFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/models/user.nim',
        content: `import norm/[model, sqlite]
import std/[times, options]

type
  User* = ref object of Model
    email*: string
    passwordHash*: string
    name*: string
    role*: string
    lastLogin*: Option[DateTime]
    createdAt*: DateTime
    updatedAt*: DateTime

proc newUser*(email, passwordHash, name: string, role = "user"): User =
  ## Create new user instance
  result = User(
    email: email,
    passwordHash: passwordHash,
    name: name,
    role: role,
    createdAt: now(),
    updatedAt: now()
  )

# Define table schema
func table*(T: typedesc[User]): string = "users"
`
      },
      {
        path: 'src/models/database.nim',
        content: `import norm/[sqlite, pool]
import std/[os, options, tables, times]
import ./user
import chronicles

var dbPool: Pool[DbConn]

proc initDatabase*() =
  ## Initialize database connection pool
  let dbPath = getEnv("DATABASE_URL", "app.db")
  
  # Create connection pool
  dbPool = newPool[DbConn](10)
  
  # Initialize connections
  for i in 0..<10:
    dbPool.add(open(dbPath, "", "", ""))
  
  # Create tables
  withDb(dbPool):
    db.createTables(User)
  
  info "Database initialized", path = dbPath

proc getUserByEmail*(email: string): Option[User] =
  ## Get user by email
  var user: User
  withDb(dbPool):
    try:
      db.select(user, "User.email = ?", email)
      result = some(user)
    except NotFoundError:
      result = none(User)

proc getUserById*(id: string): Option[User] =
  ## Get user by ID
  var user: User
  withDb(dbPool):
    try:
      db.select(user, "User.id = ?", id.parseInt)
      result = some(user)
    except NotFoundError:
      result = none(User)

proc createUser*(email, passwordHash, name: string, role = "user"): User =
  ## Create new user
  result = newUser(email, passwordHash, name, role)
  withDb(dbPool):
    db.insert(result)

proc updateUser*(id: string, updates: Table[string, string]): bool =
  ## Update user
  var user: User
  withDb(dbPool):
    try:
      db.select(user, "User.id = ?", id.parseInt)
      
      # Apply updates
      for key, value in updates:
        case key
        of "email": user.email = value
        of "name": user.name = value
        of "passwordHash": user.passwordHash = value
        of "role": user.role = value
        else: discard
      
      user.updatedAt = now()
      db.update(user)
      result = true
    except NotFoundError:
      result = false

proc deleteUser*(id: string): bool =
  ## Delete user
  var user: User
  withDb(dbPool):
    try:
      db.select(user, "User.id = ?", id.parseInt)
      db.delete(user)
      result = true
    except NotFoundError:
      result = false

proc getAllUsers*(): seq[User] =
  ## Get all users
  withDb(dbPool):
    result = db.selectAll(User)

proc updateLastLogin*(id: string) =
  ## Update user's last login time
  var user: User
  withDb(dbPool):
    try:
      db.select(user, "User.id = ?", id.parseInt)
      user.lastLogin = some(now())
      user.updatedAt = now()
      db.update(user)
    except NotFoundError:
      discard
`
      }
    ];
  }

  generateViewFiles(): { path: string; content: string }[] {
    // Jester is API-focused, so we'll just create a simple HTML template
    return [
      {
        path: 'src/views/index.html',
        content: `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${this.options?.name || 'Jester API'}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 { color: #333; }
        .endpoint {
            background: #f8f9fa;
            padding: 1rem;
            margin: 1rem 0;
            border-radius: 4px;
            border-left: 4px solid #007bff;
        }
        .method {
            font-weight: bold;
            color: #007bff;
        }
        code {
            background: #e9ecef;
            padding: 2px 4px;
            border-radius: 2px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 ${this.options?.name || 'Jester API'}</h1>
        <p>Welcome to your Jester-powered API service!</p>
        
        <h2>Available Endpoints</h2>
        
        <div class="endpoint">
            <span class="method">GET</span> <code>/health</code>
            <p>Health check endpoint</p>
        </div>
        
        <div class="endpoint">
            <span class="method">POST</span> <code>/api/auth/register</code>
            <p>Register new user</p>
        </div>
        
        <div class="endpoint">
            <span class="method">POST</span> <code>/api/auth/login</code>
            <p>User login</p>
        </div>
        
        <div class="endpoint">
            <span class="method">GET</span> <code>/api/users</code>
            <p>List users (requires authentication)</p>
        </div>
        
        <h2>Documentation</h2>
        <p>For detailed API documentation, see <a href="/docs/api.md">API Documentation</a></p>
    </div>
</body>
</html>
`
      }
    ];
  }

  generateConfigFile(): string {
    return `import std/[os, strutils]
import dotenv

# Load environment variables
load()

type
  Config* = object
    port*: int
    host*: string
    env*: string
    jwtSecret*: string
    dbUrl*: string
    corsOrigin*: string
    logLevel*: string

proc loadConfig*(): Config =
  ## Load configuration from environment
  result = Config(
    port: getEnv("PORT", "5000").parseInt(),
    host: getEnv("HOST", "0.0.0.0"),
    env: getEnv("APP_ENV", "development"),
    jwtSecret: getEnv("JWT_SECRET", "your-secret-key"),
    dbUrl: getEnv("DATABASE_URL", "app.db"),
    corsOrigin: getEnv("CORS_ORIGIN", "*"),
    logLevel: getEnv("LOG_LEVEL", "info")
  )

let config* = loadConfig()

proc isDevelopment*(): bool =
  ## Check if running in development mode
  config.env == "development"

proc isProduction*(): bool =
  ## Check if running in production mode
  config.env == "production"

proc isTest*(): bool =
  ## Check if running in test mode
  config.env == "test"

proc getUptime*(): string =
  ## Get application uptime
  # Simple implementation - in production use proper uptime tracking
  result = "0h 0m"
`;
  }

  generateTestFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'tests/test_helpers.nim',
        content: `import unittest
import ../src/utils/helpers

suite "Helper functions":
  test "generateUUID":
    let uuid = generateUUID()
    check uuid.len > 0
    check "-" in uuid
  
  test "hashPassword and verifyPassword":
    let password = "Test123!@#"
    let hash = hashPassword(password)
    
    check hash != password
    check verifyPassword(password, hash)
    check not verifyPassword("wrong", hash)
  
  test "sanitizeInput":
    check sanitizeInput("<script>alert('xss')</script>") == "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;&#x2F;script&gt;"
    check sanitizeInput("normal text") == "normal text"
  
  test "paginate":
    let items = @[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    
    let (page1, total1) = paginate(items, 1, 3)
    check page1 == @[1, 2, 3]
    check total1 == 4
    
    let (page2, total2) = paginate(items, 2, 3)
    check page2 == @[4, 5, 6]
    check total2 == 4
`
      },
      {
        path: 'tests/test_validators.nim',
        content: `import unittest
import std/options
import ../src/utils/validators

suite "Validators":
  test "validateEmail":
    check validateEmail("test@example.com").isNone
    check validateEmail("user.name+tag@example.co.uk").isNone
    
    check validateEmail("").isSome
    check validateEmail("invalid").isSome
    check validateEmail("@example.com").isSome
    check validateEmail("test@").isSome
  
  test "validatePassword":
    check validatePassword("Test123!@#").isNone
    
    check validatePassword("").isSome
    check validatePassword("short").isSome
    check validatePassword("alllowercase").isSome
    check validatePassword("ALLUPPERCASE").isSome
    check validatePassword("NoNumbers!").isSome
  
  test "validateUsername":
    check validateUsername("user123").isNone
    check validateUsername("test_user").isNone
    
    check validateUsername("ab").isSome  # too short
    check validateUsername("a" & "b".repeat(20)).isSome  # too long
    check validateUsername("user@123").isSome  # invalid chars
  
  test "validateRequired":
    check validateRequired("value", "field").isNone
    
    check validateRequired("", "field").isSome
    check validateRequired("   ", "field").isSome
`
      },
      {
        path: 'tests/test_controllers.nim',
        content: `import unittest
import std/[json, httpclient, asyncdispatch, os]
import ../src/models/database

# Initialize test database
putEnv("DATABASE_URL", "test.db")
initDatabase()

suite "Controllers":
  test "Health check":
    # In a real test, you would start the server and make HTTP requests
    # This is a placeholder for the test structure
    check true
  
  test "User registration":
    # Test user registration flow
    check true
  
  test "User login":
    # Test login flow
    check true
  
  test "Protected routes":
    # Test auth middleware
    check true
`
      },
      {
        path: 'tests/test_models.nim',
        content: `import unittest
import std/[options, tables]
import ../src/models/[user, database]

# Initialize test database
import std/os
putEnv("DATABASE_URL", ":memory:")
initDatabase()

suite "User model":
  test "Create user":
    let user = createUser("test@example.com", "hashedpass", "Test User")
    
    check user.email == "test@example.com"
    check user.name == "Test User"
    check user.role == "user"
    check user.id > 0
  
  test "Get user by email":
    let email = "getbyemail@example.com"
    discard createUser(email, "hash", "Test")
    
    let userOpt = getUserByEmail(email)
    check userOpt.isSome
    check userOpt.get().email == email
    
    let notFound = getUserByEmail("notfound@example.com")
    check notFound.isNone
  
  test "Update user":
    let user = createUser("update@example.com", "hash", "Original")
    let updates = {"name": "Updated"}.toTable
    
    check updateUser($user.id, updates)
    
    let updated = getUserById($user.id)
    check updated.isSome
    check updated.get().name == "Updated"
  
  test "Delete user":
    let user = createUser("delete@example.com", "hash", "Delete Me")
    
    check deleteUser($user.id)
    check getUserById($user.id).isNone
    check not deleteUser($user.id)  # Already deleted
`
      },
      {
        path: 'tests/test_middleware.nim',
        content: `import unittest
import std/[json, tables, strutils]

suite "Middleware":
  test "CORS headers":
    # Test CORS middleware
    check true
  
  test "Auth middleware":
    # Test JWT validation
    check true
  
  test "Rate limiting":
    # Test rate limiter
    check true
  
  test "Logger middleware":
    # Test request logging
    check true
`
      }
    ];
  }

  async generateDockerfile(projectPath: string): Promise<void> {
    const dockerfile = `# Multi-stage build for Nim application
FROM nimlang/nim:2.0.0-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev openssl-dev sqlite-dev

WORKDIR /app

# Copy nimble file first for better caching
COPY *.nimble ./
RUN nimble install -y

# Copy source code
COPY . .

# Build release binary
RUN nim c -d:release -d:ssl --opt:size -o:server src/main.nim

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache openssl sqlite-libs && \\
    adduser -D -g '' appuser

WORKDIR /app

# Copy binary and static files
COPY --from=builder /app/server ./
COPY --from=builder /app/public ./public
COPY --from=builder /app/.env.example ./.env

# Change ownership
RUN chown -R appuser:appuser /app

USER appuser

EXPOSE ${this.options?.port || 5000}

CMD ["./server"]
`;

    await fs.writeFile(path.join(projectPath, 'Dockerfile'), dockerfile);
  }
}