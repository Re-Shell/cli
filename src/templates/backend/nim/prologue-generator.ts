import { NimBackendGenerator } from './nim-base-generator';
import * as fs from 'fs/promises';
import * as path from 'path';

export class PrologueGenerator extends NimBackendGenerator {
  getFrameworkDependencies(): string[] {
    return [
      'prologue >= 0.6.0',
      'jwt',
      'bcrypt',
      'chronicles',
      'dotenv',
      'norm >= 2.8.0',
      'redis',
      'karax',
      'mustache'
    ];
  }

  generateMainFile(): string {
    return `import prologue
import prologue/middlewares/[staticfile, cors, csrf]
import std/[os, strutils]
import dotenv
import chronicles
import ./config
import ./routes
import ./middleware/[auth, logger, rate_limit]
import ./models/database

# Load environment variables
load()

# Initialize logger
var log = newConsoleLogger()
addHandler(log)

# Initialize database
initDatabase()

# Create Prologue app
let app = newApp(
  settings = newSettings(
    appName = "${this.options?.name || 'prologue-app'}",
    debug = isDevelopment(),
    port = Port(config.port),
    address = config.host,
    secretKey = config.jwtSecret
  )
)

# Configure middleware
app.use(
  # CORS middleware
  cors(
    allowOrigins = @[config.corsOrigin],
    allowMethods = @["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowHeaders = @["Content-Type", "Authorization"],
    maxAge = 86400
  )
)

# Logger middleware
app.use(loggerMiddleware())

# CSRF protection for web routes
if not isApiOnly():
  app.use(csrf())

# Static files
app.use(staticFileMiddleware("public", "/static"))

# Rate limiting
app.use(rateLimitMiddleware())

# Register routes
registerRoutes(app)

# Error handlers
app.registerErrorHandler(
  Http404,
  proc (ctx: Context) {.async.} =
    if ctx.request.path.startsWith("/api"):
      resp jsonResponse(%*{"error": "Not found"}, Http404)
    else:
      resp htmlResponse("<h1>404 - Page Not Found</h1>", Http404)
)

app.registerErrorHandler(
  Http500,
  proc (ctx: Context) {.async.} =
    error "Internal server error", error = getCurrentExceptionMsg()
    resp jsonResponse(%*{"error": "Internal server error"}, Http500)
)

when isMainModule:
  info "Starting Prologue server",
    port = app.settings.port,
    env = config.env
  
  app.run()
`;
  }

  generateRouterFile(): string {
    return `import prologue
import std/[json, asyncdispatch]
import ./controllers/[auth_controller, user_controller, web_controller]
import ./middleware/auth

proc registerRoutes*(app: Prologue) =
  ## Register all application routes
  
  # Web routes
  app.get("/", webController.index)
  app.get("/about", webController.about)
  app.get("/docs", webController.docs)
  
  # Health check
  app.get("/health", proc(ctx: Context) {.async.} =
    resp jsonResponse(%*{
      "status": "healthy",
      "service": app.settings.appName,
      "timestamp": $now(),
      "version": "1.0.0"
    })
  )
  
  # API routes group
  let api = newGroup(app, "/api", @[])
  
  # Authentication routes
  api.post("/auth/register", authController.register)
  api.post("/auth/login", authController.login)
  api.post("/auth/refresh", authController.refresh)
  api.post("/auth/logout", authController.logout, @[requireAuth()])
  
  # User routes (protected)
  api.get("/users", userController.listUsers, @[requireAuth()])
  api.get("/users/{id}", userController.getUser, @[requireAuth()])
  api.put("/users/{id}", userController.updateUser, @[requireAuth()])
  api.delete("/users/{id}", userController.deleteUser, @[requireAuth(), requireAdmin()])
  
  # Profile routes
  api.get("/profile", userController.getProfile, @[requireAuth()])
  api.put("/profile", userController.updateProfile, @[requireAuth()])
  
  # Additional API endpoints can be added here
  
proc isApiOnly*(): bool =
  ## Check if running in API-only mode
  getEnv("API_ONLY", "false") == "true"
`;
  }

  generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/middleware/auth.nim',
        content: `import prologue
import std/[json, strutils, options, times]
import jwt
import ../models/user
import ../utils/helpers
import chronicles

type
  AuthUser* = object
    id*: string
    email*: string
    role*: string

proc requireAuth*(): HandlerAsync =
  ## Authentication middleware
  result = proc(ctx: Context) {.async.} =
    # Extract token from header
    let authHeader = ctx.request.getHeader("Authorization")
    if authHeader.len == 0:
      resp jsonResponse(%*{"error": "Missing authorization header"}, Http401)
      return
    
    if not authHeader.startsWith("Bearer "):
      resp jsonResponse(%*{"error": "Invalid authorization format"}, Http401)
      return
    
    let token = authHeader[7..^1]
    
    try:
      # Verify token
      let secret = getEnv("JWT_SECRET", "your-secret-key")
      let payload = token.toJWT().verify(secret, HS256)
      
      # Check expiration
      let exp = payload.claims["exp"].getInt()
      if exp < getCurrentTimestamp():
        resp jsonResponse(%*{"error": "Token expired"}, Http401)
        return
      
      # Set user context
      ctx.set("userId", payload.claims["sub"].getStr())
      ctx.set("userEmail", payload.claims["email"].getStr())
      ctx.set("userRole", payload.claims["role"].getStr())
      
      await switch(ctx)
      
    except:
      error "Auth error", error = getCurrentExceptionMsg()
      resp jsonResponse(%*{"error": "Invalid token"}, Http401)

proc requireAdmin*(): HandlerAsync =
  ## Admin authorization middleware
  result = proc(ctx: Context) {.async.} =
    let role = ctx.get("userRole", "")
    if role != "admin":
      resp jsonResponse(%*{"error": "Admin access required"}, Http403)
      return
    
    await switch(ctx)

proc requireRole*(roles: varargs[string]): HandlerAsync =
  ## Role-based authorization middleware
  result = proc(ctx: Context) {.async.} =
    let userRole = ctx.get("userRole", "")
    if userRole notin roles:
      resp jsonResponse(%*{"error": "Insufficient permissions"}, Http403)
      return
    
    await switch(ctx)

proc optionalAuth*(): HandlerAsync =
  ## Optional authentication - sets user context if token is valid
  result = proc(ctx: Context) {.async.} =
    let authHeader = ctx.request.getHeader("Authorization")
    if authHeader.len > 0 and authHeader.startsWith("Bearer "):
      let token = authHeader[7..^1]
      
      try:
        let secret = getEnv("JWT_SECRET", "your-secret-key")
        let payload = token.toJWT().verify(secret, HS256)
        
        let exp = payload.claims["exp"].getInt()
        if exp >= getCurrentTimestamp():
          ctx.set("userId", payload.claims["sub"].getStr())
          ctx.set("userEmail", payload.claims["email"].getStr())
          ctx.set("userRole", payload.claims["role"].getStr())
      except:
        discard  # Invalid token is ok for optional auth
    
    await switch(ctx)
`
      },
      {
        path: 'src/middleware/logger.nim',
        content: `import prologue
import std/[times, strformat, json]
import chronicles

proc loggerMiddleware*(): HandlerAsync =
  ## Request/response logger middleware
  result = proc(ctx: Context) {.async.} =
    let startTime = epochTime()
    let method = $ctx.request.reqMethod
    let path = ctx.request.path
    
    # Log request
    info "Request started",
      method = method,
      path = path,
      ip = ctx.request.ip
    
    # Process request
    await switch(ctx)
    
    # Log response
    let duration = (epochTime() - startTime) * 1000
    let status = ctx.response.code
    
    info "Request completed",
      method = method,
      path = path,
      status = status.int,
      duration = fmt"{duration:.2f}ms"

proc accessLogMiddleware*(logFile: string): HandlerAsync =
  ## Access log middleware (writes to file)
  result = proc(ctx: Context) {.async.} =
    let startTime = epochTime()
    
    await switch(ctx)
    
    let duration = (epochTime() - startTime) * 1000
    let logEntry = %*{
      "timestamp": $now(),
      "method": $ctx.request.reqMethod,
      "path": ctx.request.path,
      "status": ctx.response.code.int,
      "duration": duration,
      "ip": ctx.request.ip,
      "userAgent": ctx.request.getHeader("User-Agent")
    }
    
    # Append to log file
    let f = open(logFile, fmAppend)
    f.writeLine($logEntry)
    f.close()
`
      },
      {
        path: 'src/middleware/rate_limit.nim',
        content: `import prologue
import std/[tables, times, strformat, json]
import redis

type
  RateLimiter = ref object
    redis: Redis
    maxRequests: int
    windowSec: int
    keyPrefix: string

var limiter: RateLimiter

proc initRateLimiter*(maxRequests = 100, windowSec = 60, keyPrefix = "rate_limit") =
  ## Initialize rate limiter
  try:
    limiter = RateLimiter(
      redis: open(getEnv("REDIS_HOST", "localhost"), Port(getEnv("REDIS_PORT", "6379").parseInt())),
      maxRequests: maxRequests,
      windowSec: windowSec,
      keyPrefix: keyPrefix
    )
  except:
    echo "Warning: Redis connection failed, rate limiting disabled"
    limiter = nil

proc rateLimitMiddleware*(maxRequests = 100, windowSec = 60): HandlerAsync =
  ## Rate limiting middleware
  result = proc(ctx: Context) {.async.} =
    if limiter.isNil:
      # Rate limiting disabled
      await switch(ctx)
      return
    
    # Get client identifier
    let clientId = ctx.request.getHeader("X-Forwarded-For", ctx.request.ip)
    let key = fmt"{limiter.keyPrefix}:{clientId}"
    
    try:
      # Check current count
      let count = limiter.redis.get(key)
      if count == redisNil:
        # First request
        discard limiter.redis.setex(key, limiter.windowSec, "1")
      else:
        let currentCount = count.parseInt()
        if currentCount >= limiter.maxRequests:
          ctx.response.setHeader("X-RateLimit-Limit", $limiter.maxRequests)
          ctx.response.setHeader("X-RateLimit-Remaining", "0")
          ctx.response.setHeader("X-RateLimit-Reset", $(epochTime().int + limiter.windowSec))
          
          resp jsonResponse(%*{
            "error": "Too many requests",
            "retryAfter": limiter.windowSec
          }, Http429)
          return
        else:
          # Increment counter
          discard limiter.redis.incr(key)
          ctx.response.setHeader("X-RateLimit-Limit", $limiter.maxRequests)
          ctx.response.setHeader("X-RateLimit-Remaining", $(limiter.maxRequests - currentCount - 1))
      
      await switch(ctx)
      
    except:
      # Redis error, allow request
      await switch(ctx)

proc apiRateLimitMiddleware*(): HandlerAsync =
  ## Stricter rate limiting for API endpoints
  rateLimitMiddleware(maxRequests = 60, windowSec = 60)
`
      },
      {
        path: 'src/middleware/validation.nim',
        content: `import prologue
import std/[json, tables, strutils, options]
import ../utils/validators

type
  ValidationRules = Table[string, seq[proc(value: string): Option[ValidationError]]]

proc validate*(rules: ValidationRules): HandlerAsync =
  ## Request validation middleware
  result = proc(ctx: Context) {.async.} =
    var errors = initTable[string, seq[string]]()
    let body = ctx.request.body.parseJson()
    
    for field, validators in rules:
      if body.hasKey(field):
        let value = body[field].getStr()
        for validator in validators:
          let error = validator(value)
          if error.isSome:
            if not errors.hasKey(field):
              errors[field] = @[]
            errors[field].add(error.get().message)
      else:
        # Field is missing
        if not errors.hasKey(field):
          errors[field] = @[]
        errors[field].add(fmt"{field} is required")
    
    if errors.len > 0:
      resp jsonResponse(%*{
        "error": "Validation failed",
        "errors": errors
      }, Http400)
      return
    
    await switch(ctx)

# Common validation rules
proc required*(field: string): proc(value: string): Option[ValidationError] =
  result = proc(value: string): Option[ValidationError] =
    validateRequired(value, field)

proc email*(): proc(value: string): Option[ValidationError] =
  result = proc(value: string): Option[ValidationError] =
    validateEmail(value)

proc password*(): proc(value: string): Option[ValidationError] =
  result = proc(value: string): Option[ValidationError] =
    validatePassword(value)

proc minLength*(min: int, field: string): proc(value: string): Option[ValidationError] =
  result = proc(value: string): Option[ValidationError] =
    validateLength(value, field, minLen = min)

proc maxLength*(max: int, field: string): proc(value: string): Option[ValidationError] =
  result = proc(value: string): Option[ValidationError] =
    validateLength(value, field, maxLen = max)
`
      }
    ];
  }

  generateControllerFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/controllers/auth_controller.nim',
        content: `import prologue
import std/[json, tables, strutils, options, asyncdispatch]
import jwt
import bcrypt
import ../models/[user, database]
import ../utils/[helpers, validators]
import chronicles

proc register*(ctx: Context) {.async.} =
  ## Register new user
  try:
    let body = ctx.request.body.parseJson()
    
    # Extract data
    let email = body["email"].getStr()
    let password = body["password"].getStr()
    let name = body{"name"}.getStr("")
    
    # Validate
    var errors: seq[string] = @[]
    if validateEmail(email).isSome:
      errors.add("Invalid email format")
    if validatePassword(password).isSome:
      errors.add("Password must be at least 8 characters with uppercase, lowercase, and numbers")
    
    if errors.len > 0:
      resp jsonResponse(%*{"errors": errors}, Http400)
      return
    
    # Check if user exists
    if getUserByEmail(email).isSome:
      resp jsonResponse(%*{"error": "Email already registered"}, Http409)
      return
    
    # Create user
    let hashedPassword = hash(password)
    let user = createUser(email, hashedPassword, name)
    
    # Generate token
    let claims = %*{
      "sub": user.id,
      "email": user.email,
      "role": user.role,
      "exp": getCurrentTimestamp() + 86400
    }
    let token = $claims.toJWT().sign(ctx.getSettings().secretKey, HS256)
    
    info "User registered", email = email
    
    resp jsonResponse(%*{
      "user": {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role
      },
      "token": token
    }, Http201)
    
  except:
    error "Registration error", error = getCurrentExceptionMsg()
    resp jsonResponse(%*{"error": "Registration failed"}, Http500)

proc login*(ctx: Context) {.async.} =
  ## User login
  try:
    let body = ctx.request.body.parseJson()
    let email = body["email"].getStr()
    let password = body["password"].getStr()
    
    # Get user
    let userOpt = getUserByEmail(email)
    if userOpt.isNone:
      resp jsonResponse(%*{"error": "Invalid credentials"}, Http401)
      return
    
    let user = userOpt.get()
    
    # Verify password
    if not verify(password, user.passwordHash):
      resp jsonResponse(%*{"error": "Invalid credentials"}, Http401)
      return
    
    # Generate token
    let claims = %*{
      "sub": user.id,
      "email": user.email,
      "role": user.role,
      "exp": getCurrentTimestamp() + 86400
    }
    let token = $claims.toJWT().sign(ctx.getSettings().secretKey, HS256)
    
    # Update last login
    updateLastLogin(user.id)
    
    info "User logged in", email = email
    
    resp jsonResponse(%*{
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
    resp jsonResponse(%*{"error": "Login failed"}, Http500)

proc refresh*(ctx: Context) {.async.} =
  ## Refresh JWT token
  try:
    let body = ctx.request.body.parseJson()
    let oldToken = body["token"].getStr()
    
    # Verify old token (allow expired)
    let payload = oldToken.toJWT().verify(ctx.getSettings().secretKey, HS256, {IgnoreExpiration})
    
    # Generate new token
    let claims = %*{
      "sub": payload.claims["sub"],
      "email": payload.claims["email"],
      "role": payload.claims["role"],
      "exp": getCurrentTimestamp() + 86400
    }
    let token = $claims.toJWT().sign(ctx.getSettings().secretKey, HS256)
    
    resp jsonResponse(%*{"token": token})
    
  except:
    error "Refresh error", error = getCurrentExceptionMsg()
    resp jsonResponse(%*{"error": "Invalid token"}, Http401)

proc logout*(ctx: Context) {.async.} =
  ## User logout
  let userId = ctx.get("userId")
  info "User logged out", userId = userId
  
  # In production, you might want to blacklist the token
  resp jsonResponse(%*{"message": "Logged out successfully"})

proc forgotPassword*(ctx: Context) {.async.} =
  ## Request password reset
  try:
    let body = ctx.request.body.parseJson()
    let email = body["email"].getStr()
    
    let userOpt = getUserByEmail(email)
    if userOpt.isSome:
      # Generate reset token
      let resetToken = generateUUID()
      # In production, store this token and send email
      info "Password reset requested", email = email
    
    # Always return success to prevent email enumeration
    resp jsonResponse(%*{"message": "If the email exists, a reset link has been sent"})
    
  except:
    error "Forgot password error", error = getCurrentExceptionMsg()
    resp jsonResponse(%*{"error": "Request failed"}, Http500)
`
      },
      {
        path: 'src/controllers/user_controller.nim',
        content: `import prologue
import std/[json, strutils, sequtils, tables, options, asyncdispatch]
import ../models/[user, database]
import ../utils/helpers
import chronicles

proc listUsers*(ctx: Context) {.async.} =
  ## List all users with pagination
  try:
    # Get query parameters
    let page = ctx.getQueryParam("page", "1").parseInt()
    let pageSize = ctx.getQueryParam("pageSize", "10").parseInt()
    let search = ctx.getQueryParam("search", "")
    let role = ctx.getQueryParam("role", "")
    
    # Get filtered users
    var users = getAllUsers()
    
    # Apply filters
    if search.len > 0:
      users = users.filterIt(
        search in it.email.toLower() or 
        search in it.name.toLower()
      )
    
    if role.len > 0:
      users = users.filterIt(it.role == role)
    
    # Paginate
    let (pagedUsers, totalPages) = paginate(users, page, pageSize)
    
    # Prepare response
    let safeUsers = pagedUsers.mapIt(%*{
      "id": it.id,
      "email": it.email,
      "name": it.name,
      "role": it.role,
      "createdAt": it.createdAt,
      "lastLogin": it.lastLogin
    })
    
    resp jsonResponse(%*{
      "users": safeUsers,
      "pagination": {
        "page": page,
        "pageSize": pageSize,
        "totalPages": totalPages,
        "total": users.len
      }
    })
    
  except:
    error "List users error", error = getCurrentExceptionMsg()
    resp jsonResponse(%*{"error": "Failed to list users"}, Http500)

proc getUser*(ctx: Context) {.async.} =
  ## Get user by ID
  let id = ctx.getPathParam("id")
  let currentUserId = ctx.get("userId")
  let currentRole = ctx.get("userRole")
  
  try:
    let userOpt = getUserById(id)
    if userOpt.isNone:
      resp jsonResponse(%*{"error": "User not found"}, Http404)
      return
    
    let user = userOpt.get()
    
    # Check permissions
    if currentUserId != id and currentRole != "admin":
      resp jsonResponse(%*{"error": "Access denied"}, Http403)
      return
    
    resp jsonResponse(%*{
      "user": {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "createdAt": user.createdAt,
        "updatedAt": user.updatedAt,
        "lastLogin": user.lastLogin
      }
    })
    
  except:
    error "Get user error", error = getCurrentExceptionMsg()
    resp jsonResponse(%*{"error": "Failed to get user"}, Http500)

proc updateUser*(ctx: Context) {.async.} =
  ## Update user
  let id = ctx.getPathParam("id")
  let currentUserId = ctx.get("userId")
  let currentRole = ctx.get("userRole")
  
  # Check permissions
  if currentUserId != id and currentRole != "admin":
    resp jsonResponse(%*{"error": "Access denied"}, Http403)
    return
  
  try:
    let body = ctx.request.body.parseJson()
    var updates = initTable[string, string]()
    
    # Collect updates
    if body.hasKey("name"):
      updates["name"] = body["name"].getStr()
    
    if body.hasKey("email"):
      let newEmail = body["email"].getStr()
      if validateEmail(newEmail).isSome:
        resp jsonResponse(%*{"error": "Invalid email format"}, Http400)
        return
      
      # Check if email is taken
      let existing = getUserByEmail(newEmail)
      if existing.isSome and existing.get().id != id:
        resp jsonResponse(%*{"error": "Email already in use"}, Http409)
        return
      
      updates["email"] = newEmail
    
    if body.hasKey("password"):
      let newPassword = body["password"].getStr()
      if validatePassword(newPassword).isSome:
        resp jsonResponse(%*{"error": "Password too weak"}, Http400)
        return
      updates["passwordHash"] = hash(newPassword)
    
    # Only admin can change roles
    if body.hasKey("role") and currentRole == "admin":
      updates["role"] = body["role"].getStr()
    
    # Update user
    if not updateUser(id, updates):
      resp jsonResponse(%*{"error": "User not found"}, Http404)
      return
    
    info "User updated", userId = id
    
    resp jsonResponse(%*{"message": "User updated successfully"})
    
  except:
    error "Update user error", error = getCurrentExceptionMsg()
    resp jsonResponse(%*{"error": "Failed to update user"}, Http500)

proc deleteUser*(ctx: Context) {.async.} =
  ## Delete user (admin only)
  let id = ctx.getPathParam("id")
  
  try:
    if not deleteUser(id):
      resp jsonResponse(%*{"error": "User not found"}, Http404)
      return
    
    info "User deleted", userId = id
    
    resp noContent()
    
  except:
    error "Delete user error", error = getCurrentExceptionMsg()
    resp jsonResponse(%*{"error": "Failed to delete user"}, Http500)

proc getProfile*(ctx: Context) {.async.} =
  ## Get current user profile
  let userId = ctx.get("userId")
  
  try:
    let userOpt = getUserById(userId)
    if userOpt.isNone:
      resp jsonResponse(%*{"error": "User not found"}, Http404)
      return
    
    let user = userOpt.get()
    
    resp jsonResponse(%*{
      "profile": {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "createdAt": user.createdAt,
        "lastLogin": user.lastLogin
      }
    })
    
  except:
    error "Get profile error", error = getCurrentExceptionMsg()
    resp jsonResponse(%*{"error": "Failed to get profile"}, Http500)

proc updateProfile*(ctx: Context) {.async.} =
  ## Update current user profile
  let userId = ctx.get("userId")
  
  try:
    let body = ctx.request.body.parseJson()
    var updates = initTable[string, string]()
    
    if body.hasKey("name"):
      updates["name"] = body["name"].getStr()
    
    if body.hasKey("password"):
      let newPassword = body["password"].getStr()
      if validatePassword(newPassword).isSome:
        resp jsonResponse(%*{"error": "Password too weak"}, Http400)
        return
      updates["passwordHash"] = hash(newPassword)
    
    if updates.len > 0:
      discard updateUser(userId, updates)
    
    resp jsonResponse(%*{"message": "Profile updated successfully"})
    
  except:
    error "Update profile error", error = getCurrentExceptionMsg()
    resp jsonResponse(%*{"error": "Failed to update profile"}, Http500)
`
      },
      {
        path: 'src/controllers/web_controller.nim',
        content: `import prologue
import std/[asyncdispatch, strformat]
import karax/[karaxdsl, vdom]
import ../views/[layout, pages]

proc index*(ctx: Context) {.async.} =
  ## Home page
  let userId = ctx.get("userId", "")
  let isAuthenticated = userId.len > 0
  
  let content = indexPage(isAuthenticated)
  let html = renderLayout("Home", content)
  
  resp htmlResponse(html)

proc about*(ctx: Context) {.async.} =
  ## About page
  let content = aboutPage()
  let html = renderLayout("About", content)
  
  resp htmlResponse(html)

proc docs*(ctx: Context) {.async.} =
  ## Documentation page
  let content = docsPage()
  let html = renderLayout("Documentation", content)
  
  resp htmlResponse(html)

proc dashboard*(ctx: Context) {.async.} =
  ## User dashboard (requires auth)
  let userId = ctx.get("userId")
  let userEmail = ctx.get("userEmail")
  
  let content = dashboardPage(userEmail)
  let html = renderLayout("Dashboard", content)
  
  resp htmlResponse(html)
`
      }
    ];
  }

  generateModelFiles(): { path: string; content: string }[] {
    // Same as Jester - reuse the model files
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
    return [
      {
        path: 'src/views/layout.nim',
        content: `import karax/[karaxdsl, vdom]

proc renderLayout*(title: string, content: VNode): string =
  ## Main layout template
  let html = buildHtml(html):
    head:
      meta(charset = "utf-8")
      meta(name = "viewport", content = "width=device-width, initial-scale=1.0")
      title: text title & " - ${this.options?.name || 'Prologue App'}"
      link(rel = "stylesheet", href = "/static/css/style.css")
    
    body:
      header(class = "header"):
        nav(class = "nav"):
          a(href = "/", class = "logo"): text "${this.options?.name || 'Prologue'}"
          ul(class = "nav-links"):
            li: a(href = "/"): text "Home"
            li: a(href = "/about"): text "About"
            li: a(href = "/docs"): text "Docs"
            li: a(href = "/api/health"): text "API"
      
      main(class = "main"):
        content
      
      footer(class = "footer"):
        p: text "© 2024 ${this.options?.name || 'Prologue App'}. Built with Nim & Prologue."
      
      script(src = "/static/js/app.js")
  
  result = "<!DOCTYPE html>\\n" & $html
`
      },
      {
        path: 'src/views/pages.nim',
        content: `import karax/[karaxdsl, vdom]

proc indexPage*(isAuthenticated: bool): VNode =
  ## Home page content
  result = buildHtml(tdiv(class = "container")):
    h1: text "Welcome to ${this.options?.name || 'Prologue'}"
    p(class = "lead"): 
      text "A powerful web application built with Nim and Prologue framework."
    
    if isAuthenticated:
      p: text "You are logged in!"
      a(href = "/dashboard", class = "btn"): text "Go to Dashboard"
    else:
      tdiv(class = "cta"):
        a(href = "/api/docs", class = "btn btn-primary"): text "API Documentation"
        a(href = "/about", class = "btn btn-secondary"): text "Learn More"

proc aboutPage*(): VNode =
  ## About page content
  result = buildHtml(tdiv(class = "container")):
    h1: text "About"
    p: text "This application demonstrates the power of Nim with Prologue web framework."
    
    h2: text "Features"
    ul:
      li: text "Fast and efficient web server"
      li: text "JWT authentication"
      li: text "RESTful API"
      li: text "Database integration with Norm ORM"
      li: text "Server-side rendering with Karax"
      li: text "Middleware system"
      li: text "Rate limiting"
    
    h2: text "Technology Stack"
    ul:
      li: text "Nim - Systems programming language"
      li: text "Prologue - Web framework"
      li: text "SQLite - Database"
      li: text "Redis - Caching and rate limiting"
      li: text "JWT - Authentication"

proc docsPage*(): VNode =
  ## Documentation page content
  result = buildHtml(tdiv(class = "container")):
    h1: text "API Documentation"
    
    h2: text "Authentication"
    tdiv(class = "endpoint"):
      h3: text "POST /api/auth/register"
      p: text "Register a new user"
      pre: code: text """{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "name": "John Doe"
}"""
    
    tdiv(class = "endpoint"):
      h3: text "POST /api/auth/login"
      p: text "Login with email and password"
      pre: code: text """{
  "email": "user@example.com",
  "password": "SecurePass123!"
}"""
    
    h2: text "Users"
    tdiv(class = "endpoint"):
      h3: text "GET /api/users"
      p: text "List all users (requires authentication)"
      p: text "Query parameters: page, pageSize, search, role"
    
    tdiv(class = "endpoint"):
      h3: text "GET /api/users/:id"
      p: text "Get user details (requires authentication)"
    
    tdiv(class = "endpoint"):
      h3: text "PUT /api/users/:id"
      p: text "Update user (requires authentication)"
    
    tdiv(class = "endpoint"):
      h3: text "DELETE /api/users/:id"
      p: text "Delete user (requires admin role)"

proc dashboardPage*(userEmail: string): VNode =
  ## Dashboard page content
  result = buildHtml(tdiv(class = "container")):
    h1: text "Dashboard"
    p: text "Welcome back, " & userEmail & "!"
    
    tdiv(class = "dashboard-cards"):
      tdiv(class = "card"):
        h3: text "Profile"
        p: text "Manage your profile settings"
        a(href = "/profile", class = "btn btn-small"): text "Edit Profile"
      
      tdiv(class = "card"):
        h3: text "API Keys"
        p: text "Manage your API access tokens"
        a(href = "/api-keys", class = "btn btn-small"): text "Manage Keys"
      
      tdiv(class = "card"):
        h3: text "Activity"
        p: text "View your recent activity"
        a(href = "/activity", class = "btn btn-small"): text "View Activity"
`
      },
      {
        path: 'public/css/style.css',
        content: `/* Basic CSS for Prologue app */
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  line-height: 1.6;
  color: #333;
  background: #f5f5f5;
}

.container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 2rem;
}

/* Header */
.header {
  background: #2c3e50;
  color: white;
  padding: 1rem 0;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.nav {
  display: flex;
  justify-content: space-between;
  align-items: center;
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 2rem;
}

.logo {
  font-size: 1.5rem;
  font-weight: bold;
  color: white;
  text-decoration: none;
}

.nav-links {
  display: flex;
  list-style: none;
  gap: 2rem;
}

.nav-links a {
  color: white;
  text-decoration: none;
  transition: opacity 0.3s;
}

.nav-links a:hover {
  opacity: 0.8;
}

/* Main content */
.main {
  min-height: calc(100vh - 120px);
  background: white;
  margin: 2rem auto;
  max-width: 1200px;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

/* Footer */
.footer {
  background: #34495e;
  color: white;
  text-align: center;
  padding: 1rem 0;
}

/* Typography */
h1, h2, h3 {
  margin-bottom: 1rem;
  color: #2c3e50;
}

h1 { font-size: 2.5rem; }
h2 { font-size: 2rem; }
h3 { font-size: 1.5rem; }

p {
  margin-bottom: 1rem;
}

.lead {
  font-size: 1.25rem;
  color: #666;
}

/* Buttons */
.btn {
  display: inline-block;
  padding: 0.75rem 1.5rem;
  margin: 0.5rem;
  border: none;
  border-radius: 4px;
  text-decoration: none;
  cursor: pointer;
  transition: background-color 0.3s;
}

.btn-primary {
  background: #3498db;
  color: white;
}

.btn-primary:hover {
  background: #2980b9;
}

.btn-secondary {
  background: #95a5a6;
  color: white;
}

.btn-secondary:hover {
  background: #7f8c8d;
}

.btn-small {
  padding: 0.5rem 1rem;
  font-size: 0.9rem;
}

/* Cards */
.dashboard-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 2rem;
  margin-top: 2rem;
}

.card {
  background: #f8f9fa;
  padding: 1.5rem;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

/* Endpoints */
.endpoint {
  background: #f8f9fa;
  padding: 1.5rem;
  margin: 1rem 0;
  border-radius: 4px;
  border-left: 4px solid #3498db;
}

.endpoint h3 {
  color: #3498db;
  margin-bottom: 0.5rem;
}

pre {
  background: #2c3e50;
  color: white;
  padding: 1rem;
  border-radius: 4px;
  overflow-x: auto;
  margin: 1rem 0;
}

code {
  font-family: 'Consolas', 'Monaco', monospace;
}

/* CTA */
.cta {
  margin: 2rem 0;
  text-align: center;
}

/* Responsive */
@media (max-width: 768px) {
  .nav {
    flex-direction: column;
    gap: 1rem;
  }
  
  .nav-links {
    flex-direction: column;
    text-align: center;
    gap: 1rem;
  }
  
  .dashboard-cards {
    grid-template-columns: 1fr;
  }
}
`
      },
      {
        path: 'public/js/app.js',
        content: `// Client-side JavaScript for Prologue app
document.addEventListener('DOMContentLoaded', function() {
  console.log('${this.options?.name || 'Prologue'} app loaded');
  
  // Add any client-side functionality here
  // For example: form validation, AJAX requests, etc.
});
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
    redisHost*: string
    redisPort*: int

proc loadConfig*(): Config =
  ## Load configuration from environment
  result = Config(
    port: getEnv("PORT", "5000").parseInt(),
    host: getEnv("HOST", "0.0.0.0"),
    env: getEnv("APP_ENV", "development"),
    jwtSecret: getEnv("JWT_SECRET", "your-secret-key"),
    dbUrl: getEnv("DATABASE_URL", "app.db"),
    corsOrigin: getEnv("CORS_ORIGIN", "*"),
    logLevel: getEnv("LOG_LEVEL", "info"),
    redisHost: getEnv("REDIS_HOST", "localhost"),
    redisPort: getEnv("REDIS_PORT", "6379").parseInt()
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
`;
  }

  generateTestFiles(): { path: string; content: string }[] {
    // Similar test files as Jester
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
  
  test "validatePassword":
    check validatePassword("Test123!@#").isNone
    
    check validatePassword("").isSome
    check validatePassword("short").isSome
    check validatePassword("alllowercase").isSome
`
      }
    ];
  }

  async generateDockerfile(projectPath: string): Promise<void> {
    const dockerfile = `# Multi-stage build for Nim Prologue application
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

# Copy binary and assets
COPY --from=builder /app/server ./
COPY --from=builder /app/public ./public
COPY --from=builder /app/.env.example ./.env

# Create necessary directories
RUN mkdir -p logs && \\
    chown -R appuser:appuser /app

USER appuser

EXPOSE ${this.options?.port || 5000}

CMD ["./server"]
`;

    await fs.writeFile(path.join(projectPath, 'Dockerfile'), dockerfile);
  }
}