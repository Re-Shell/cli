import { NimBackendGenerator } from './nim-base-generator';
import * as fs from 'fs/promises';
import * as path from 'path';

export class HappyXGenerator extends NimBackendGenerator {
  constructor() {
    super();
    this.config.framework = 'HappyX';
    this.config.features.push(
      'Full-stack framework',
      'Server-side rendering',
      'Client-side SPA',
      'WebSocket support',
      'Built-in ORM',
      'Template engine',
      'Hot reload',
      'TypeScript-like syntax',
      'Component system',
      'Reactive state'
    );
  }

  protected getFrameworkDependencies(): string[] {
    return [
      'happyx >= 4.0.0',
      'ws',
      'db_connector',
      'nimcrypto',
      'jwt',
      'dotenv',
      'argparse'
    ];
  }

  protected generateMainFile(): string {
    return `# HappyX Full-Stack Application
import happyx
import std/[asyncdispatch, json, times, logging, os]
import ./config
import ./router
import ./middleware/[cors, auth, error_handler, rate_limiter]
import ./database

# Initialize logging
var logger = newConsoleLogger(fmtStr = "[$time] - $levelname: ")
addHandler(logger)

# Create HappyX application
var app = newApp()

# Configure static file serving
app.staticDir("/static", "public")
app.staticDir("/assets", "assets")

# Apply global middleware
app.use(corsMiddleware())
app.use(errorHandlerMiddleware())
app.use(rateLimiterMiddleware(maxRequests = 100, windowMs = 60000))

# Initialize database
initDatabase()

# Mount routes
app.mount("/api", apiRouter())
app.mount("/auth", authRouter())
app.mount("/ws", websocketRouter())

# Server-side rendering routes
app.get("/"):
  ## Home page with SSR
  return buildHtml:
    tDiv(class = "container"):
      h1: "Welcome to HappyX"
      p: "A full-stack Nim framework"
      tDiv(id = "app"):
        "Loading..."

# SPA route handler
app.get("/*"):
  ## Catch-all route for SPA
  return buildHtml:
    tDiv(id = "app"):
      "Loading application..."
    script(src = "/assets/bundle.js")

# Health check endpoint
app.get("/health"):
  return %*{
    "status": "healthy",
    "timestamp": now().toUnix(),
    "service": "happyx-service",
    "version": "1.0.0"
  }

# Error handlers
app.notFound:
  return %*{
    "error": "Not Found",
    "message": "The requested resource was not found",
    "status": 404
  }

app.error(Exception):
  error "Internal server error: ", getCurrentExceptionMsg()
  return %*{
    "error": "Internal Server Error",
    "message": "An unexpected error occurred",
    "status": 500
  }

# Start server
when isMainModule:
  let port = parseInt(getEnv("PORT", "5000"))
  let host = getEnv("HOST", "0.0.0.0")
  
  info "Starting HappyX server on ", host, ":", port
  
  # Enable hot reload in development
  when defined(debug):
    app.enableHotReload()
  
  # Start the server
  app.serve(host, port)
`;
  }

  protected generateRouterFile(): string {
    return `# Router configuration for HappyX
import happyx
import std/[json, strutils, times]
import ./controllers/[user_controller, auth_controller, product_controller]
import ./middleware/auth
import ./models/user

# API Router
proc apiRouter*(): Router =
  var router = newRouter()
  
  # Public routes
  router.get("/"):
    return %*{
      "message": "HappyX API",
      "version": "1.0.0",
      "timestamp": now().toUnix()
    }
  
  # User routes (protected)
  router.group("/users", @[authMiddleware()]):
    get("/"):
      return userController.listUsers(request)
    
    get("/{id:int}"):
      return userController.getUser(request, id)
    
    post("/"):
      return userController.createUser(request)
    
    put("/{id:int}"):
      return userController.updateUser(request, id)
    
    delete("/{id:int}"):
      return userController.deleteUser(request, id)
  
  # Product routes
  router.group("/products"):
    get("/"):
      return productController.listProducts(request)
    
    get("/{id:int}"):
      return productController.getProduct(request, id)
    
    post("/", @[authMiddleware()]):
      return productController.createProduct(request)
    
    put("/{id:int}", @[authMiddleware()]):
      return productController.updateProduct(request, id)
    
    delete("/{id:int}", @[authMiddleware(role = "admin")]):
      return productController.deleteProduct(request, id)
  
  result = router

# Auth Router
proc authRouter*(): Router =
  var router = newRouter()
  
  router.post("/register"):
    return authController.register(request)
  
  router.post("/login"):
    return authController.login(request)
  
  router.post("/refresh"):
    return authController.refreshToken(request)
  
  router.post("/logout", @[authMiddleware()]):
    return authController.logout(request)
  
  router.get("/me", @[authMiddleware()]):
    return authController.getCurrentUser(request)
  
  result = router

# WebSocket Router
proc websocketRouter*(): Router =
  var router = newRouter()
  
  router.ws("/chat"):
    ## WebSocket chat endpoint
    echo "New WebSocket connection: ", ws.key
    
    ws.on("message"):
      let msg = parseJson(data)
      
      # Broadcast message to all connected clients
      for client in ws.clients:
        await client.send($(%*{
          "type": "message",
          "user": msg["user"].getStr(),
          "text": msg["text"].getStr(),
          "timestamp": now().toUnix()
        }))
    
    ws.on("close"):
      echo "WebSocket disconnected: ", ws.key
  
  router.ws("/notifications", @[authMiddleware()]):
    ## Real-time notifications
    let userId = request.user.id
    
    ws.on("subscribe"):
      # Subscribe to user notifications
      await subscribeToNotifications(userId, ws)
    
    ws.on("unsubscribe"):
      # Unsubscribe from notifications
      await unsubscribeFromNotifications(userId, ws)
  
  result = router
`;
  }

  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/middleware/cors.nim',
        content: `# CORS middleware for HappyX
import happyx
import std/[strutils, sequtils]

proc corsMiddleware*(
  origins: seq[string] = @["*"],
  methods: seq[string] = @["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  headers: seq[string] = @["Content-Type", "Authorization"],
  credentials: bool = true
): Middleware =
  return proc(request: Request, response: Response, next: Next) {.async.} =
    let origin = request.headers.getOrDefault("Origin", "*")
    
    # Set CORS headers
    if origins.contains("*") or origins.contains(origin):
      response.headers["Access-Control-Allow-Origin"] = origin
    else:
      response.headers["Access-Control-Allow-Origin"] = origins[0]
    
    response.headers["Access-Control-Allow-Methods"] = methods.join(", ")
    response.headers["Access-Control-Allow-Headers"] = headers.join(", ")
    
    if credentials:
      response.headers["Access-Control-Allow-Credentials"] = "true"
    
    # Handle preflight requests
    if request.reqMethod == HttpOptions:
      response.status = Http204
      return
    
    await next()
`
      },
      {
        path: 'src/middleware/auth.nim',
        content: `# Authentication middleware for HappyX
import happyx
import std/[json, strutils, times, options]
import ../utils/jwt_utils
import ../models/user

proc authMiddleware*(role: string = ""): Middleware =
  return proc(request: Request, response: Response, next: Next) {.async.} =
    # Extract token from header
    let authHeader = request.headers.getOrDefault("Authorization", "")
    if not authHeader.startsWith("Bearer "):
      response.status = Http401
      response.send(%*{
        "error": "Unauthorized",
        "message": "Missing or invalid authorization header"
      })
      return
    
    let token = authHeader[7..^1]
    
    # Verify token
    let payload = verifyToken(token)
    if payload.isNone:
      response.status = Http401
      response.send(%*{
        "error": "Unauthorized",
        "message": "Invalid or expired token"
      })
      return
    
    # Check token expiration
    let exp = payload.get()["exp"].getInt()
    if exp < getCurrentTimestamp():
      response.status = Http401
      response.send(%*{
        "error": "Unauthorized",
        "message": "Token has expired"
      })
      return
    
    # Load user from database
    let userId = payload.get()["sub"].getStr()
    let user = await getUserById(userId)
    if user.isNone:
      response.status = Http401
      response.send(%*{
        "error": "Unauthorized",
        "message": "User not found"
      })
      return
    
    # Check role if specified
    if role != "" and user.get().role != role:
      response.status = Http403
      response.send(%*{
        "error": "Forbidden",
        "message": "Insufficient permissions"
      })
      return
    
    # Attach user to request
    request.user = user.get()
    
    await next()
`
      },
      {
        path: 'src/middleware/error_handler.nim',
        content: `# Error handling middleware for HappyX
import happyx
import std/[json, logging]

proc errorHandlerMiddleware*(): Middleware =
  return proc(request: Request, response: Response, next: Next) {.async.} =
    try:
      await next()
    except ValidationError as e:
      warn "Validation error: ", e.msg
      response.status = Http400
      response.send(%*{
        "error": "Validation Error",
        "message": e.msg,
        "field": e.field
      })
    except NotFoundError as e:
      info "Not found: ", e.msg
      response.status = Http404
      response.send(%*{
        "error": "Not Found",
        "message": e.msg
      })
    except UnauthorizedError as e:
      warn "Unauthorized access: ", e.msg
      response.status = Http401
      response.send(%*{
        "error": "Unauthorized",
        "message": e.msg
      })
    except Exception as e:
      error "Unhandled error: ", e.msg
      response.status = Http500
      response.send(%*{
        "error": "Internal Server Error",
        "message": "An unexpected error occurred"
      })
`
      },
      {
        path: 'src/middleware/rate_limiter.nim',
        content: `# Rate limiting middleware for HappyX
import happyx
import std/[json, tables, times, strutils]

type
  RateLimitEntry = object
    requests: int
    resetTime: int64

var rateLimitStore = initTable[string, RateLimitEntry]()

proc rateLimiterMiddleware*(maxRequests: int = 100, windowMs: int = 60000): Middleware =
  return proc(request: Request, response: Response, next: Next) {.async.} =
    let clientId = request.headers.getOrDefault("X-Forwarded-For", request.ip)
    let currentTime = getCurrentTimestamp()
    let windowStart = currentTime - (windowMs div 1000)
    
    # Clean up old entries
    var keysToDelete: seq[string] = @[]
    for key, entry in rateLimitStore:
      if entry.resetTime < windowStart:
        keysToDelete.add(key)
    for key in keysToDelete:
      rateLimitStore.del(key)
    
    # Check rate limit
    if clientId in rateLimitStore:
      var entry = rateLimitStore[clientId]
      if entry.resetTime > currentTime:
        if entry.requests >= maxRequests:
          response.status = Http429
          response.headers["X-RateLimit-Limit"] = $maxRequests
          response.headers["X-RateLimit-Remaining"] = "0"
          response.headers["X-RateLimit-Reset"] = $entry.resetTime
          response.send(%*{
            "error": "Too Many Requests",
            "message": "Rate limit exceeded. Please try again later.",
            "retryAfter": entry.resetTime - currentTime
          })
          return
        else:
          entry.requests += 1
          rateLimitStore[clientId] = entry
      else:
        # Reset window
        rateLimitStore[clientId] = RateLimitEntry(
          requests: 1,
          resetTime: currentTime + (windowMs div 1000)
        )
    else:
      # New client
      rateLimitStore[clientId] = RateLimitEntry(
        requests: 1,
        resetTime: currentTime + (windowMs div 1000)
      )
    
    # Set rate limit headers
    let entry = rateLimitStore[clientId]
    response.headers["X-RateLimit-Limit"] = $maxRequests
    response.headers["X-RateLimit-Remaining"] = $(maxRequests - entry.requests)
    response.headers["X-RateLimit-Reset"] = $entry.resetTime
    
    await next()
`
      }
    ];
  }

  protected generateControllerFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/controllers/user_controller.nim',
        content: `# User controller for HappyX
import happyx
import std/[json, strutils, options]
import ../models/user
import ../utils/validators

proc listUsers*(request: Request): JsonNode =
  ## List all users with pagination
  let page = parseInt(request.query.getOrDefault("page", "1"))
  let limit = parseInt(request.query.getOrDefault("limit", "10"))
  let search = request.query.getOrDefault("search", "")
  
  let (users, total) = getUsersPaginated(page, limit, search)
  
  return %*{
    "data": users.map(u => u.toPublicJson()),
    "pagination": {
      "page": page,
      "limit": limit,
      "total": total,
      "pages": (total + limit - 1) div limit
    }
  }

proc getUser*(request: Request, id: int): JsonNode =
  ## Get user by ID
  let user = getUserById($id)
  if user.isNone:
    raise newException(NotFoundError, "User not found")
  
  return %*{
    "data": user.get().toPublicJson()
  }

proc createUser*(request: Request): JsonNode =
  ## Create new user
  let body = request.body.parseJson()
  
  # Validate input
  let emailError = validateEmail(body["email"].getStr())
  if emailError.isSome:
    raise newException(ValidationError, emailError.get().message)
  
  let passwordError = validatePassword(body["password"].getStr())
  if passwordError.isSome:
    raise newException(ValidationError, passwordError.get().message)
  
  # Check if user exists
  if getUserByEmail(body["email"].getStr()).isSome:
    raise newException(ValidationError, "Email already registered")
  
  # Create user
  var user = User(
    email: body["email"].getStr(),
    username: body["username"].getStr(),
    role: body.getOrDefault("role", %"user").getStr()
  )
  user.setPassword(body["password"].getStr())
  
  let savedUser = createUser(user)
  
  return %*{
    "data": savedUser.toPublicJson(),
    "message": "User created successfully"
  }

proc updateUser*(request: Request, id: int): JsonNode =
  ## Update user
  let body = request.body.parseJson()
  var user = getUserById($id)
  if user.isNone:
    raise newException(NotFoundError, "User not found")
  
  var userObj = user.get()
  
  # Update fields
  if body.hasKey("username"):
    userObj.username = body["username"].getStr()
  
  if body.hasKey("email"):
    let emailError = validateEmail(body["email"].getStr())
    if emailError.isSome:
      raise newException(ValidationError, emailError.get().message)
    userObj.email = body["email"].getStr()
  
  if body.hasKey("role") and request.user.role == "admin":
    userObj.role = body["role"].getStr()
  
  let updatedUser = updateUser(userObj)
  
  return %*{
    "data": updatedUser.toPublicJson(),
    "message": "User updated successfully"
  }

proc deleteUser*(request: Request, id: int): JsonNode =
  ## Delete user
  if request.user.id != $id and request.user.role != "admin":
    raise newException(UnauthorizedError, "Cannot delete other users")
  
  let user = getUserById($id)
  if user.isNone:
    raise newException(NotFoundError, "User not found")
  
  deleteUser($id)
  
  return %*{
    "message": "User deleted successfully"
  }
`
      },
      {
        path: 'src/controllers/auth_controller.nim',
        content: `# Authentication controller for HappyX
import happyx
import std/[json, strutils, times, options]
import ../models/user
import ../utils/[validators, jwt_utils]

proc register*(request: Request): JsonNode =
  ## Register new user
  let body = request.body.parseJson()
  
  # Validate input
  let emailError = validateEmail(body["email"].getStr())
  if emailError.isSome:
    raise newException(ValidationError, emailError.get().message)
  
  let passwordError = validatePassword(body["password"].getStr())
  if passwordError.isSome:
    raise newException(ValidationError, passwordError.get().message)
  
  # Check if user exists
  if getUserByEmail(body["email"].getStr()).isSome:
    raise newException(ValidationError, "Email already registered")
  
  # Create user
  var user = User(
    email: body["email"].getStr(),
    username: body["username"].getStr(),
    role: "user"
  )
  user.setPassword(body["password"].getStr())
  
  let savedUser = createUser(user)
  
  # Generate tokens
  let accessToken = generateAccessToken(savedUser)
  let refreshToken = generateRefreshToken(savedUser)
  
  # Save refresh token
  saveRefreshToken(savedUser.id, refreshToken)
  
  return %*{
    "data": {
      "user": savedUser.toPublicJson(),
      "accessToken": accessToken,
      "refreshToken": refreshToken
    },
    "message": "Registration successful"
  }

proc login*(request: Request): JsonNode =
  ## User login
  let body = request.body.parseJson()
  let email = body["email"].getStr()
  let password = body["password"].getStr()
  
  # Find user
  let user = getUserByEmail(email)
  if user.isNone:
    raise newException(UnauthorizedError, "Invalid credentials")
  
  # Verify password
  if not user.get().verifyPassword(password):
    raise newException(UnauthorizedError, "Invalid credentials")
  
  # Generate tokens
  let accessToken = generateAccessToken(user.get())
  let refreshToken = generateRefreshToken(user.get())
  
  # Save refresh token
  saveRefreshToken(user.get().id, refreshToken)
  
  return %*{
    "data": {
      "user": user.get().toPublicJson(),
      "accessToken": accessToken,
      "refreshToken": refreshToken
    },
    "message": "Login successful"
  }

proc refreshToken*(request: Request): JsonNode =
  ## Refresh access token
  let body = request.body.parseJson()
  let refreshToken = body["refreshToken"].getStr()
  
  # Verify refresh token
  let payload = verifyRefreshToken(refreshToken)
  if payload.isNone:
    raise newException(UnauthorizedError, "Invalid refresh token")
  
  # Check if token is stored
  let userId = payload.get()["sub"].getStr()
  if not isRefreshTokenValid(userId, refreshToken):
    raise newException(UnauthorizedError, "Invalid refresh token")
  
  # Get user
  let user = getUserById(userId)
  if user.isNone:
    raise newException(UnauthorizedError, "User not found")
  
  # Generate new access token
  let accessToken = generateAccessToken(user.get())
  
  return %*{
    "data": {
      "accessToken": accessToken
    },
    "message": "Token refreshed successfully"
  }

proc logout*(request: Request): JsonNode =
  ## User logout
  # Invalidate refresh token
  invalidateRefreshTokens(request.user.id)
  
  return %*{
    "message": "Logout successful"
  }

proc getCurrentUser*(request: Request): JsonNode =
  ## Get current authenticated user
  return %*{
    "data": request.user.toPublicJson()
  }
`
      },
      {
        path: 'src/controllers/product_controller.nim',
        content: `# Product controller for HappyX
import happyx
import std/[json, strutils, options]
import ../models/product
import ../utils/validators

proc listProducts*(request: Request): JsonNode =
  ## List all products
  let page = parseInt(request.query.getOrDefault("page", "1"))
  let limit = parseInt(request.query.getOrDefault("limit", "10"))
  let category = request.query.getOrDefault("category", "")
  let search = request.query.getOrDefault("search", "")
  
  let (products, total) = getProductsPaginated(page, limit, category, search)
  
  return %*{
    "data": products.map(p => p.toJson()),
    "pagination": {
      "page": page,
      "limit": limit,
      "total": total,
      "pages": (total + limit - 1) div limit
    }
  }

proc getProduct*(request: Request, id: int): JsonNode =
  ## Get product by ID
  let product = getProductById($id)
  if product.isNone:
    raise newException(NotFoundError, "Product not found")
  
  return %*{
    "data": product.get().toJson()
  }

proc createProduct*(request: Request): JsonNode =
  ## Create new product
  let body = request.body.parseJson()
  
  # Validate input
  if body["name"].getStr().len < 3:
    raise newException(ValidationError, "Product name must be at least 3 characters")
  
  if body["price"].getFloat() < 0:
    raise newException(ValidationError, "Price cannot be negative")
  
  # Create product
  let product = Product(
    name: body["name"].getStr(),
    description: body.getOrDefault("description", %"").getStr(),
    price: body["price"].getFloat(),
    category: body.getOrDefault("category", %"general").getStr(),
    stock: body.getOrDefault("stock", %0).getInt(),
    userId: request.user.id
  )
  
  let savedProduct = createProduct(product)
  
  return %*{
    "data": savedProduct.toJson(),
    "message": "Product created successfully"
  }

proc updateProduct*(request: Request, id: int): JsonNode =
  ## Update product
  let body = request.body.parseJson()
  var product = getProductById($id)
  if product.isNone:
    raise newException(NotFoundError, "Product not found")
  
  var productObj = product.get()
  
  # Check ownership
  if productObj.userId != request.user.id and request.user.role != "admin":
    raise newException(UnauthorizedError, "Cannot update other users' products")
  
  # Update fields
  if body.hasKey("name"):
    productObj.name = body["name"].getStr()
  
  if body.hasKey("description"):
    productObj.description = body["description"].getStr()
  
  if body.hasKey("price"):
    if body["price"].getFloat() < 0:
      raise newException(ValidationError, "Price cannot be negative")
    productObj.price = body["price"].getFloat()
  
  if body.hasKey("category"):
    productObj.category = body["category"].getStr()
  
  if body.hasKey("stock"):
    productObj.stock = body["stock"].getInt()
  
  let updatedProduct = updateProduct(productObj)
  
  return %*{
    "data": updatedProduct.toJson(),
    "message": "Product updated successfully"
  }

proc deleteProduct*(request: Request, id: int): JsonNode =
  ## Delete product (admin only)
  let product = getProductById($id)
  if product.isNone:
    raise newException(NotFoundError, "Product not found")
  
  deleteProduct($id)
  
  return %*{
    "message": "Product deleted successfully"
  }
`
      }
    ];
  }

  protected generateModelFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/models/user.nim',
        content: `# User model for HappyX
import happyx/model
import std/[times, json, options, strutils]
import nimcrypto/sha256
import ../database

type
  User* = ref object of Model
    id*: string
    email*: string
    username*: string
    passwordHash*: string
    role*: string
    createdAt*: int64
    updatedAt*: int64

# Database table definition
defineTable(User, "users"):
  id: primary(string)
  email: unique(string)
  username: string
  passwordHash: string
  role: string = "user"
  createdAt: int64
  updatedAt: int64

proc setPassword*(user: var User, password: string) =
  ## Set user password (hashed)
  user.passwordHash = $sha256.digest(password)

proc verifyPassword*(user: User, password: string): bool =
  ## Verify user password
  return user.passwordHash == $sha256.digest(password)

proc toPublicJson*(user: User): JsonNode =
  ## Convert user to public JSON (without password)
  return %*{
    "id": user.id,
    "email": user.email,
    "username": user.username,
    "role": user.role,
    "createdAt": user.createdAt,
    "updatedAt": user.updatedAt
  }

# Database operations
proc getUserById*(id: string): Option[User] =
  ## Get user by ID
  return User.find(id)

proc getUserByEmail*(email: string): Option[User] =
  ## Get user by email
  return User.findBy("email", email)

proc getUsersPaginated*(page: int, limit: int, search: string = ""): tuple[users: seq[User], total: int] =
  ## Get paginated users
  var query = User.query()
  
  if search != "":
    query = query.where("username LIKE ? OR email LIKE ?", ["%$#%" % search, "%$#%" % search])
  
  let total = query.count()
  let users = query.limit(limit).offset((page - 1) * limit).all()
  
  return (users: users, total: total)

proc createUser*(user: User): User =
  ## Create new user
  user.id = generateUUID()
  user.createdAt = getCurrentTimestamp()
  user.updatedAt = user.createdAt
  user.save()
  return user

proc updateUser*(user: User): User =
  ## Update user
  user.updatedAt = getCurrentTimestamp()
  user.save()
  return user

proc deleteUser*(id: string) =
  ## Delete user
  User.delete(id)

# Token storage
var refreshTokens = initTable[string, seq[string]]()

proc saveRefreshToken*(userId: string, token: string) =
  ## Save refresh token for user
  if userId notin refreshTokens:
    refreshTokens[userId] = @[]
  refreshTokens[userId].add(token)

proc isRefreshTokenValid*(userId: string, token: string): bool =
  ## Check if refresh token is valid
  if userId notin refreshTokens:
    return false
  return token in refreshTokens[userId]

proc invalidateRefreshTokens*(userId: string) =
  ## Invalidate all refresh tokens for user
  if userId in refreshTokens:
    refreshTokens.del(userId)
`
      },
      {
        path: 'src/models/product.nim',
        content: `# Product model for HappyX
import happyx/model
import std/[times, json, options, strutils]
import ../database

type
  Product* = ref object of Model
    id*: string
    name*: string
    description*: string
    price*: float
    category*: string
    stock*: int
    userId*: string
    createdAt*: int64
    updatedAt*: int64

# Database table definition
defineTable(Product, "products"):
  id: primary(string)
  name: string
  description: text
  price: float
  category: string = "general"
  stock: int = 0
  userId: foreign(User)
  createdAt: int64
  updatedAt: int64

proc toJson*(product: Product): JsonNode =
  ## Convert product to JSON
  return %*{
    "id": product.id,
    "name": product.name,
    "description": product.description,
    "price": product.price,
    "category": product.category,
    "stock": product.stock,
    "userId": product.userId,
    "createdAt": product.createdAt,
    "updatedAt": product.updatedAt
  }

# Database operations
proc getProductById*(id: string): Option[Product] =
  ## Get product by ID
  return Product.find(id)

proc getProductsPaginated*(page: int, limit: int, category: string = "", search: string = ""): tuple[products: seq[Product], total: int] =
  ## Get paginated products
  var query = Product.query()
  
  if category != "":
    query = query.where("category = ?", category)
  
  if search != "":
    query = query.where("name LIKE ? OR description LIKE ?", ["%$#%" % search, "%$#%" % search])
  
  let total = query.count()
  let products = query.limit(limit).offset((page - 1) * limit).all()
  
  return (products: products, total: total)

proc createProduct*(product: Product): Product =
  ## Create new product
  product.id = generateUUID()
  product.createdAt = getCurrentTimestamp()
  product.updatedAt = product.createdAt
  product.save()
  return product

proc updateProduct*(product: Product): Product =
  ## Update product
  product.updatedAt = getCurrentTimestamp()
  product.save()
  return product

proc deleteProduct*(id: string) =
  ## Delete product
  Product.delete(id)
`
      }
    ];
  }

  protected generateViewFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/views/layout.nim',
        content: `# Layout template for HappyX SSR
import happyx

template layout*(title: string, content: VNode): VNode =
  buildHtml:
    tHtml:
      tHead:
        tTitle: title
        meta(charset = "utf-8")
        meta(name = "viewport", content = "width=device-width, initial-scale=1.0")
        link(rel = "stylesheet", href = "/static/css/style.css")
        script(src = "/static/js/htmx.min.js")
      tBody:
        tDiv(class = "container"):
          header:
            nav:
              a(href = "/"): "Home"
              a(href = "/products"): "Products"
              a(href = "/about"): "About"
          
          main:
            content
          
          footer:
            p: "© 2024 HappyX Application"
`
      },
      {
        path: 'src/views/components.nim',
        content: `# Reusable components for HappyX
import happyx
import std/[strformat, json]

# Button component
component Button[msg]:
  text: string = "Click me"
  onClick: proc(): msg
  variant: string = "primary"
  disabled: bool = false
  
  \`template\`:
    button(
      class = fmt"btn btn-{self.variant}",
      onclick = self.onClick,
      disabled = self.disabled
    ):
      {self.text}

# Card component
component Card:
  title: string
  content: string
  imageUrl: string = ""
  
  \`template\`:
    tDiv(class = "card"):
      if self.imageUrl != "":
        img(src = self.imageUrl, alt = self.title, class = "card-img")
      tDiv(class = "card-body"):
        h3(class = "card-title"): {self.title}
        p(class = "card-content"): {self.content}

# Form input component
component Input[msg]:
  label: string
  value: string
  onChange: proc(value: string): msg
  inputType: string = "text"
  placeholder: string = ""
  required: bool = false
  
  \`template\`:
    tDiv(class = "form-group"):
      if self.label != "":
        label: {self.label}
      input(
        type = self.inputType,
        value = self.value,
        placeholder = self.placeholder,
        required = self.required,
        onchange = proc(e: Event) = self.onChange(e.target.value)
      )

# Alert component
component Alert:
  message: string
  alertType: string = "info"
  dismissible: bool = true
  
  \`template\`:
    tDiv(class = fmt"alert alert-{self.alertType}"):
      {self.message}
      if self.dismissible:
        button(class = "alert-close", onclick = proc() = self.hide()):
          "&times;"

# Loading spinner component
component Spinner:
  size: string = "medium"
  
  \`template\`:
    tDiv(class = fmt"spinner spinner-{self.size}"):
      tDiv(class = "spinner-circle")
`
      }
    ];
  }

  protected generateConfigFile(): string {
    return `# Configuration for HappyX application
import std/[os, strutils, json]
import dotenv

# Load environment variables
load()

type
  Config* = object
    port*: int
    host*: string
    environment*: string
    databaseUrl*: string
    jwtSecret*: string
    jwtExpiresIn*: int
    refreshTokenExpiresIn*: int
    logLevel*: string
    corsOrigins*: seq[string]
    rateLimitMax*: int
    rateLimitWindow*: int

proc loadConfig*(): Config =
  ## Load configuration from environment
  result = Config(
    port: parseInt(getEnv("PORT", "5000")),
    host: getEnv("HOST", "0.0.0.0"),
    environment: getEnv("NODE_ENV", "development"),
    databaseUrl: getEnv("DATABASE_URL", "sqlite://./data/app.db"),
    jwtSecret: getEnv("JWT_SECRET", "your-secret-key-change-in-production"),
    jwtExpiresIn: parseInt(getEnv("JWT_EXPIRES_IN", "3600")),
    refreshTokenExpiresIn: parseInt(getEnv("REFRESH_TOKEN_EXPIRES_IN", "604800")),
    logLevel: getEnv("LOG_LEVEL", "info"),
    corsOrigins: getEnv("CORS_ORIGINS", "*").split(","),
    rateLimitMax: parseInt(getEnv("RATE_LIMIT_MAX", "100")),
    rateLimitWindow: parseInt(getEnv("RATE_LIMIT_WINDOW", "60000"))
  )

# Global config instance
let config* = loadConfig()

# Helper functions
proc isDevelopment*(): bool =
  return config.environment == "development"

proc isProduction*(): bool =
  return config.environment == "production"

proc isTest*(): bool =
  return config.environment == "test"
`;
  }

  protected generateTestFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'tests/test_controllers.nim',
        content: `# Tests for HappyX controllers
import unittest
import happyx/test
import std/[json, strutils]
import ../src/controllers/[user_controller, auth_controller, product_controller]
import ../src/models/[user, product]

suite "User Controller Tests":
  setup:
    # Setup test database
    initTestDatabase()
  
  teardown:
    # Clean up test data
    cleanupTestDatabase()
  
  test "list users returns paginated results":
    # Create test users
    for i in 1..15:
      createTestUser(email = fmt"user{i}@example.com")
    
    let request = mockRequest(query = {"page": "2", "limit": "10"})
    let response = listUsers(request)
    
    check:
      response["data"].len == 5
      response["pagination"]["page"].getInt() == 2
      response["pagination"]["total"].getInt() == 15
  
  test "get user returns user data":
    let user = createTestUser()
    let request = mockRequest()
    let response = getUser(request, parseInt(user.id))
    
    check:
      response["data"]["id"].getStr() == user.id
      response["data"]["email"].getStr() == user.email
  
  test "create user validates input":
    let request = mockRequest(body = %*{
      "email": "invalid-email",
      "password": "weak",
      "username": "testuser"
    })
    
    expect ValidationError:
      discard createUser(request)

suite "Auth Controller Tests":
  setup:
    initTestDatabase()
  
  teardown:
    cleanupTestDatabase()
  
  test "register creates new user":
    let request = mockRequest(body = %*{
      "email": "newuser@example.com",
      "password": "SecurePassword123!",
      "username": "newuser"
    })
    
    let response = register(request)
    
    check:
      response["data"]["user"]["email"].getStr() == "newuser@example.com"
      response["data"].hasKey("accessToken")
      response["data"].hasKey("refreshToken")
  
  test "login returns tokens for valid credentials":
    let user = createTestUser(password = "TestPassword123!")
    let request = mockRequest(body = %*{
      "email": user.email,
      "password": "TestPassword123!"
    })
    
    let response = login(request)
    
    check:
      response["data"]["user"]["id"].getStr() == user.id
      response["data"].hasKey("accessToken")
      response["data"].hasKey("refreshToken")
  
  test "login fails for invalid credentials":
    let request = mockRequest(body = %*{
      "email": "nonexistent@example.com",
      "password": "wrongpassword"
    })
    
    expect UnauthorizedError:
      discard login(request)

suite "Product Controller Tests":
  setup:
    initTestDatabase()
    # Create test user for authentication
    let testUser = createTestUser()
  
  teardown:
    cleanupTestDatabase()
  
  test "list products returns filtered results":
    # Create test products
    for i in 1..5:
      createTestProduct(name = fmt"Product {i}", category = "electronics")
    for i in 6..10:
      createTestProduct(name = fmt"Product {i}", category = "books")
    
    let request = mockRequest(query = {"category": "electronics"})
    let response = listProducts(request)
    
    check:
      response["data"].len == 5
      response["data"][0]["category"].getStr() == "electronics"
  
  test "create product requires authentication":
    let request = mockRequest(body = %*{
      "name": "New Product",
      "price": 19.99,
      "category": "test"
    })
    request.user = testUser
    
    let response = createProduct(request)
    
    check:
      response["data"]["name"].getStr() == "New Product"
      response["data"]["price"].getFloat() == 19.99
`
      },
      {
        path: 'tests/test_models.nim',
        content: `# Tests for HappyX models
import unittest
import std/[options, strutils, times]
import ../src/models/[user, product]
import ../src/database

suite "User Model Tests":
  setup:
    initTestDatabase()
  
  teardown:
    cleanupTestDatabase()
  
  test "create user with password":
    var user = User(
      email: "test@example.com",
      username: "testuser",
      role: "user"
    )
    user.setPassword("SecurePassword123!")
    
    let savedUser = createUser(user)
    
    check:
      savedUser.id != ""
      savedUser.email == "test@example.com"
      savedUser.verifyPassword("SecurePassword123!")
      not savedUser.verifyPassword("wrongpassword")
  
  test "find user by email":
    let user = createTestUser(email = "findme@example.com")
    let found = getUserByEmail("findme@example.com")
    
    check:
      found.isSome
      found.get().id == user.id
  
  test "update user data":
    var user = createTestUser()
    user.username = "updatedname"
    
    let updated = updateUser(user)
    
    check:
      updated.username == "updatedname"
      updated.updatedAt > user.createdAt

suite "Product Model Tests":
  setup:
    initTestDatabase()
    let testUser = createTestUser()
  
  teardown:
    cleanupTestDatabase()
  
  test "create product":
    let product = Product(
      name: "Test Product",
      description: "A test product",
      price: 29.99,
      category: "test",
      stock: 10,
      userId: testUser.id
    )
    
    let saved = createProduct(product)
    
    check:
      saved.id != ""
      saved.name == "Test Product"
      saved.price == 29.99
  
  test "get products with pagination":
    # Create test products
    for i in 1..25:
      createTestProduct(name = fmt"Product {i}")
    
    let (products, total) = getProductsPaginated(page = 2, limit = 10)
    
    check:
      products.len == 10
      total == 25
  
  test "search products":
    createTestProduct(name = "Gaming Laptop", description = "High performance laptop")
    createTestProduct(name = "Office Desktop", description = "Business computer")
    createTestProduct(name = "Gaming Mouse", description = "RGB gaming mouse")
    
    let (products, total) = getProductsPaginated(page = 1, limit = 10, search = "gaming")
    
    check:
      total == 2
      products[0].name.contains("Gaming")
`
      },
      {
        path: 'tests/test_middleware.nim',
        content: `# Tests for HappyX middleware
import unittest
import happyx/test
import std/[json, asyncdispatch, strutils]
import ../src/middleware/[auth, cors, rate_limiter, error_handler]
import ../src/utils/jwt_utils

suite "Auth Middleware Tests":
  test "blocks requests without token":
    let middleware = authMiddleware()
    let request = mockRequest()
    let response = mockResponse()
    var nextCalled = false
    
    waitFor middleware(request, response, proc() {.async.} =
      nextCalled = true
    )
    
    check:
      not nextCalled
      response.status == Http401
  
  test "allows requests with valid token":
    let user = createTestUser()
    let token = generateAccessToken(user)
    let middleware = authMiddleware()
    let request = mockRequest(headers = {"Authorization": "Bearer " & token})
    let response = mockResponse()
    var nextCalled = false
    
    waitFor middleware(request, response, proc() {.async.} =
      nextCalled = true
    )
    
    check:
      nextCalled
      request.user.id == user.id
  
  test "enforces role requirements":
    let user = createTestUser(role = "user")
    let token = generateAccessToken(user)
    let middleware = authMiddleware(role = "admin")
    let request = mockRequest(headers = {"Authorization": "Bearer " & token})
    let response = mockResponse()
    var nextCalled = false
    
    waitFor middleware(request, response, proc() {.async.} =
      nextCalled = true
    )
    
    check:
      not nextCalled
      response.status == Http403

suite "CORS Middleware Tests":
  test "sets CORS headers":
    let middleware = corsMiddleware(origins = @["https://example.com"])
    let request = mockRequest(headers = {"Origin": "https://example.com"})
    let response = mockResponse()
    
    waitFor middleware(request, response, proc() {.async.} = discard)
    
    check:
      response.headers["Access-Control-Allow-Origin"] == "https://example.com"
      response.headers.hasKey("Access-Control-Allow-Methods")
      response.headers.hasKey("Access-Control-Allow-Headers")
  
  test "handles preflight requests":
    let middleware = corsMiddleware()
    let request = mockRequest(reqMethod = HttpOptions)
    let response = mockResponse()
    var nextCalled = false
    
    waitFor middleware(request, response, proc() {.async.} =
      nextCalled = true
    )
    
    check:
      not nextCalled
      response.status == Http204

suite "Rate Limiter Tests":
  test "allows requests within limit":
    let middleware = rateLimiterMiddleware(maxRequests = 5, windowMs = 1000)
    let request = mockRequest(ip = "127.0.0.1")
    let response = mockResponse()
    
    for i in 1..5:
      var nextCalled = false
      waitFor middleware(request, response, proc() {.async.} =
        nextCalled = true
      )
      check nextCalled
  
  test "blocks requests over limit":
    let middleware = rateLimiterMiddleware(maxRequests = 2, windowMs = 1000)
    let request = mockRequest(ip = "127.0.0.1")
    let response = mockResponse()
    
    # First two requests should pass
    for i in 1..2:
      waitFor middleware(request, response, proc() {.async.} = discard)
    
    # Third request should be blocked
    var nextCalled = false
    waitFor middleware(request, response, proc() {.async.} =
      nextCalled = true
    )
    
    check:
      not nextCalled
      response.status == Http429
      response.headers.hasKey("X-RateLimit-Limit")
      response.headers["X-RateLimit-Remaining"] == "0"
`
      }
    ];
  }

  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    const dockerContent = `# Multi-stage build for HappyX application
FROM nimlang/nim:2.0.2-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev openssl-dev sqlite-dev

# Set working directory
WORKDIR /app

# Copy nimble file and install dependencies
COPY *.nimble ./
RUN nimble install -y

# Copy source code
COPY . .

# Build the application
RUN nim c -d:release -d:ssl --opt:size -o:server src/main.nim

# Build frontend assets
RUN cd client && \\
    nimble install -y && \\
    nim js -d:release -o:../public/assets/bundle.js src/app.nim

# Production stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache openssl sqlite-libs libgcc

# Create non-root user
RUN addgroup -g 1000 app && \\
    adduser -D -u 1000 -G app app

# Set working directory
WORKDIR /app

# Copy built binary and assets
COPY --from=builder --chown=app:app /app/server /app/server
COPY --from=builder --chown=app:app /app/public /app/public
COPY --from=builder --chown=app:app /app/assets /app/assets

# Copy configuration files
COPY --chown=app:app .env.example .env

# Create data directory
RUN mkdir -p /app/data && chown app:app /app/data

# Switch to non-root user
USER app

# Expose port
EXPOSE ${options.port || 5000}

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD wget --no-verbose --tries=1 --spider http://localhost:${options.port || 5000}/health || exit 1

# Start the application
CMD ["./server"]
`;

    await fs.writeFile(path.join(projectPath, 'Dockerfile'), dockerContent);

    // Generate docker-compose.yml
    const dockerComposeContent = `version: '3.8'

services:
  app:
    build: .
    container_name: ${options.name}
    ports:
      - "\${PORT:-${options.port || 5000}}:${options.port || 5000}"
    environment:
      - NODE_ENV=production
      - HOST=0.0.0.0
      - PORT=${options.port || 5000}
      - DATABASE_URL=sqlite:///app/data/app.db
      - JWT_SECRET=\${JWT_SECRET}
      - CORS_ORIGINS=\${CORS_ORIGINS:-*}
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:${options.port || 5000}/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - happyx-network

  # Optional: Add Redis for caching
  redis:
    image: redis:7-alpine
    container_name: ${options.name}-redis
    restart: unless-stopped
    networks:
      - happyx-network

  # Optional: Add PostgreSQL for production database
  postgres:
    image: postgres:15-alpine
    container_name: ${options.name}-postgres
    environment:
      - POSTGRES_DB=\${DB_NAME:-happyx}
      - POSTGRES_USER=\${DB_USER:-happyx}
      - POSTGRES_PASSWORD=\${DB_PASSWORD}
    volumes:
      - postgres-data:/var/lib/postgresql/data
    restart: unless-stopped
    networks:
      - happyx-network

networks:
  happyx-network:
    driver: bridge

volumes:
  postgres-data:
`;

    await fs.writeFile(path.join(projectPath, 'docker-compose.yml'), dockerComposeContent);

    // Generate .dockerignore
    const dockerignoreContent = `# Nim
nimcache/
nimblecache/
bin/
*.exe

# Development
.env
.env.local
*.log
logs/

# IDE
.vscode/
.idea/

# Git
.git/
.gitignore

# Tests
tests/
coverage/

# Documentation
docs/
*.md

# Build artifacts
client/nimcache/
client/nimblecache/
`;

    await fs.writeFile(path.join(projectPath, '.dockerignore'), dockerignoreContent);
  }

  protected async generateEnvironmentFiles(projectPath: string, options: any): Promise<void> {
    const envExample = `# HappyX Application Configuration

# Server
NODE_ENV=development
HOST=0.0.0.0
PORT=${options.port || 5000}

# Database
DATABASE_URL=sqlite://./data/app.db
# For PostgreSQL: DATABASE_URL=postgresql://user:password@localhost:5432/dbname

# Security
JWT_SECRET=your-secret-key-change-in-production
JWT_EXPIRES_IN=3600
REFRESH_TOKEN_EXPIRES_IN=604800

# CORS
CORS_ORIGINS=http://localhost:3000,http://localhost:5173

# Rate Limiting
RATE_LIMIT_MAX=100
RATE_LIMIT_WINDOW=60000

# Logging
LOG_LEVEL=info

# Redis (optional)
REDIS_URL=redis://localhost:6379

# Email (optional)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your-email@example.com
SMTP_PASS=your-password
SMTP_FROM=noreply@example.com

# External Services (optional)
STRIPE_API_KEY=
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
`;

    await fs.writeFile(path.join(projectPath, '.env.example'), envExample);
    await fs.writeFile(path.join(projectPath, '.env'), envExample);
  }

  protected async generateProjectStructure(projectPath: string, options: any): Promise<void> {
    // Create additional directories
    await fs.mkdir(path.join(projectPath, 'client'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'client', 'src'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'assets'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'data'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'logs'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'scripts'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'src', 'services'), { recursive: true });

    // Generate client-side app entry point
    const clientAppContent = `# HappyX Client-Side Application
import happyx
import std/[dom, json]
import ./components/[app, router, store]

# Initialize client-side app
when defined(js):
  var app = App()
  
  # Mount to DOM
  app.mount(document.getElementById("app"))
  
  # Initialize router
  initRouter(app)
  
  # Initialize store
  initStore(app)
  
  # Start the application
  app.start()
`;

    await fs.writeFile(path.join(projectPath, 'client', 'src', 'app.nim'), clientAppContent);

    // Generate client nimble file
    const clientNimbleContent = `# Client-side package

version       = "0.1.0"
author        = "${options.author || 'Anonymous'}"
description   = "HappyX client-side application"
license       = "MIT"
srcDir        = "src"

# Dependencies
requires "nim >= 2.0.0"
requires "happyx >= 4.0.0"

# Tasks
task build, "Build client-side bundle":
  exec "nim js -d:release -o:../public/assets/bundle.js src/app.nim"

task dev, "Build development bundle":
  exec "nim js -o:../public/assets/bundle.js src/app.nim"

task watch, "Watch and rebuild on changes":
  exec "watchexec -e nim -- nimble dev"
`;

    await fs.writeFile(path.join(projectPath, 'client', 'client.nimble'), clientNimbleContent);

    // Generate database initialization script
    const dbInitContent = `# Database initialization and management
import std/[os, strutils]
import db_connector/db_sqlite

proc initDatabase*() =
  ## Initialize database with tables
  let db = open("data/app.db", "", "", "")
  defer: db.close()
  
  # Create users table
  db.exec(sql"""
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      username TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'user',
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    )
  """)
  
  # Create products table
  db.exec(sql"""
    CREATE TABLE IF NOT EXISTS products (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      price REAL NOT NULL,
      category TEXT DEFAULT 'general',
      stock INTEGER DEFAULT 0,
      user_id TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  """)
  
  # Create indices
  db.exec(sql"CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
  db.exec(sql"CREATE INDEX IF NOT EXISTS idx_products_category ON products(category)")
  db.exec(sql"CREATE INDEX IF NOT EXISTS idx_products_user ON products(user_id)")

when isMainModule:
  echo "Initializing database..."
  initDatabase()
  echo "Database initialized successfully!"
`;

    await fs.writeFile(path.join(projectPath, 'src', 'database.nim'), dbInitContent);

    // Generate JWT utils
    const jwtUtilsContent = `# JWT utility functions
import std/[json, times, strutils, options, base64]
import nimcrypto/[hmac, sha256]
import ./config

proc generateToken(payload: JsonNode, secret: string, expiresIn: int): string =
  ## Generate JWT token
  let header = %*{"alg": "HS256", "typ": "JWT"}
  
  # Add expiration
  payload["exp"] = %(getCurrentTimestamp() + expiresIn)
  payload["iat"] = %getCurrentTimestamp()
  
  let headerEncoded = encode($header, safe = true).strip(chars = {'='})
  let payloadEncoded = encode($payload, safe = true).strip(chars = {'='})
  
  let message = headerEncoded & "." & payloadEncoded
  let signature = encode($hmac_sha256(secret, message), safe = true).strip(chars = {'='})
  
  result = message & "." & signature

proc verifyToken*(token: string, secret: string = config.jwtSecret): Option[JsonNode] =
  ## Verify and decode JWT token
  let parts = token.split('.')
  if parts.len != 3:
    return none(JsonNode)
  
  try:
    let message = parts[0] & "." & parts[1]
    let signature = parts[2]
    
    # Verify signature
    let expectedSignature = encode($hmac_sha256(secret, message), safe = true).strip(chars = {'='})
    if signature != expectedSignature:
      return none(JsonNode)
    
    # Decode payload
    let payload = parts[1]
    let padded = payload & "=".repeat((4 - payload.len mod 4) mod 4)
    let decoded = decode(padded)
    result = some(parseJson(decoded))
  except:
    result = none(JsonNode)

proc generateAccessToken*(user: User): string =
  ## Generate access token for user
  let payload = %*{
    "sub": user.id,
    "email": user.email,
    "role": user.role
  }
  return generateToken(payload, config.jwtSecret, config.jwtExpiresIn)

proc generateRefreshToken*(user: User): string =
  ## Generate refresh token for user
  let payload = %*{
    "sub": user.id,
    "type": "refresh"
  }
  return generateToken(payload, config.jwtSecret, config.refreshTokenExpiresIn)

proc verifyRefreshToken*(token: string): Option[JsonNode] =
  ## Verify refresh token
  let payload = verifyToken(token)
  if payload.isNone:
    return none(JsonNode)
  
  if payload.get().getOrDefault("type", %"").getStr() != "refresh":
    return none(JsonNode)
  
  return payload

proc getCurrentTimestamp*(): int64 =
  ## Get current Unix timestamp
  toUnix(getTime())
`;

    await fs.writeFile(path.join(projectPath, 'src', 'utils', 'jwt_utils.nim'), jwtUtilsContent);

    // Generate development script
    const devScriptContent = `#!/bin/bash
# Development script for HappyX

# Colors for output
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m' # No Color

echo -e "\${GREEN}Starting HappyX development environment...\${NC}"

# Check if nimble is installed
if ! command -v nimble &> /dev/null; then
    echo -e "\${YELLOW}Nimble is not installed. Please install Nim first.\${NC}"
    exit 1
fi

# Install dependencies
echo -e "\${GREEN}Installing dependencies...\${NC}"
nimble install -y

# Initialize database
echo -e "\${GREEN}Initializing database...\${NC}"
nim c -r src/database.nim

# Build client assets
echo -e "\${GREEN}Building client assets...\${NC}"
cd client && nimble dev && cd ..

# Start development server with hot reload
echo -e "\${GREEN}Starting development server with hot reload...\${NC}"
watchexec -r -e nim,js,css,html -- nim c -r src/main.nim
`;

    await fs.writeFile(path.join(projectPath, 'scripts', 'dev.sh'), devScriptContent);
    await fs.chmod(path.join(projectPath, 'scripts', 'dev.sh'), '755');

    // Generate production build script
    const buildScriptContent = `#!/bin/bash
# Production build script for HappyX

set -e

echo "Building HappyX for production..."

# Build server
echo "Building server..."
nim c -d:release -d:ssl --opt:size -o:server src/main.nim

# Build client
echo "Building client..."
cd client && nimble build && cd ..

# Minify assets
echo "Optimizing assets..."
# Add asset optimization commands here

echo "Production build complete!"
echo "Run './server' to start the application"
`;

    await fs.writeFile(path.join(projectPath, 'scripts', 'build.sh'), buildScriptContent);
    await fs.chmod(path.join(projectPath, 'scripts', 'build.sh'), '755');
  }
}