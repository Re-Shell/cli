/**
 * Vapor Framework Template Generator
 * Modern web framework for Swift with async/await support
 */

import { SwiftBackendGenerator } from './swift-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class VaporGenerator extends SwiftBackendGenerator {
  constructor() {
    super('Vapor');
  }

  protected getFrameworkDependencies(): string[] {
    return [
      '// 💧 Vapor framework',
      '.package(url: "https://github.com/vapor/vapor.git", from: "4.89.0"),',
      '// 🗄️ Fluent ORM',
      '.package(url: "https://github.com/vapor/fluent.git", from: "4.8.0"),',
      '.package(url: "https://github.com/vapor/fluent-postgres-driver.git", from: "2.8.0"),',
      '.package(url: "https://github.com/vapor/fluent-sqlite-driver.git", from: "4.5.0"),',
      '// 🔐 Authentication',
      '.package(url: "https://github.com/vapor/jwt.git", from: "4.2.2"),',
      '// 🔄 Redis',
      '.package(url: "https://github.com/vapor/redis.git", from: "4.10.0"),',
      '// 📧 Email',
      '.package(url: "https://github.com/vapor/queues.git", from: "1.13.0"),',
      '.package(url: "https://github.com/vapor/queues-redis-driver.git", from: "1.1.1"),',
      '// 🔍 Validation',
      '.package(url: "https://github.com/vapor/leaf.git", from: "4.2.4")'
    ];
  }

  protected getTargetDependencies(): string {
    return `[
                .product(name: "Vapor", package: "vapor"),
                .product(name: "Fluent", package: "fluent"),
                .product(name: "FluentPostgresDriver", package: "fluent-postgres-driver"),
                .product(name: "JWT", package: "jwt"),
                .product(name: "Redis", package: "redis"),
                .product(name: "Queues", package: "queues"),
                .product(name: "QueuesRedisDriver", package: "queues-redis-driver"),
                .product(name: "Leaf", package: "leaf")
            ]`;
  }

  protected getTestDependencies(): string {
    return '.product(name: "XCTVapor", package: "vapor"),';
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Create Vapor-specific directory structure
    const vaporDirs = [
      'Sources/App',
      'Sources/App/Controllers',
      'Sources/App/Models',
      'Sources/App/Migrations',
      'Sources/App/Middleware',
      'Sources/App/Services',
      'Sources/App/Utils',
      'Sources/App/DTOs',
      'Sources/App/Jobs',
      'Resources/Views',
      'Public'
    ];

    for (const dir of vaporDirs) {
      await fs.mkdir(path.join(projectPath, dir), { recursive: true });
    }

    // Generate main.swift
    await this.generateMain(projectPath);

    // Generate configure.swift
    await this.generateConfigure(projectPath, options);

    // Generate routes.swift
    await this.generateRoutes(projectPath);

    // Generate User model with authentication
    await this.generateUserModel(projectPath);

    // Generate Auth controller
    await this.generateAuthController(projectPath);

    // Generate middleware
    await this.generateMiddleware(projectPath);

    // Generate migrations
    await this.generateMigrations(projectPath);

    // Generate services
    await this.generateServices(projectPath);

    // Generate DTOs
    await this.generateDTOs(projectPath);

    // Generate environment configuration
    await this.generateEnvironment(projectPath);
  }

  private async generateMain(projectPath: string): Promise<void> {
    const mainContent = `import Vapor
import Logging

// Configure logging
var env = try Environment.detect()
try LoggingSystem.bootstrap(from: &env)

// Create application
let app = Application(env)
defer { app.shutdown() }

// Configure application
try configure(app)

// Run application
try app.run()
`;

    await fs.writeFile(
      path.join(projectPath, 'Sources/App/main.swift'),
      mainContent
    );
  }

  private async generateConfigure(projectPath: string, options: any): Promise<void> {
    const configureContent = `import Fluent
import FluentPostgresDriver
import JWT
import Leaf
import Queues
import QueuesRedisDriver
import Redis
import Vapor

/// Configure your application
public func configure(_ app: Application) async throws {
    // MARK: - Server Configuration
    app.http.server.configuration.hostname = "0.0.0.0"
    app.http.server.configuration.port = Environment.get("PORT").flatMap(Int.init) ?? ${options.port || 8080}
    
    // MARK: - Middleware
    app.middleware.use(FileMiddleware(publicDirectory: app.directory.publicDirectory))
    app.middleware.use(ErrorMiddleware.default(environment: app.environment))
    app.middleware.use(CORSMiddleware(configuration: .init(
        allowedOrigin: .all,
        allowedMethods: [.GET, .POST, .PUT, .DELETE, .OPTIONS, .PATCH],
        allowedHeaders: [.accept, .authorization, .contentType, .origin, .xRequestedWith]
    )))
    
    // Custom middleware
    app.middleware.use(LoggingMiddleware())
    app.middleware.use(RateLimitMiddleware())
    
    // MARK: - Database
    if let databaseURL = Environment.get("DATABASE_URL") {
        try app.databases.use(.postgres(url: databaseURL), as: .psql)
    } else {
        app.databases.use(.postgres(
            hostname: Environment.get("DB_HOST") ?? "localhost",
            port: Environment.get("DB_PORT").flatMap(Int.init) ?? 5432,
            username: Environment.get("DB_USER") ?? "vapor",
            password: Environment.get("DB_PASSWORD") ?? "password",
            database: Environment.get("DB_NAME") ?? "vapor"
        ), as: .psql)
    }
    
    // MARK: - Migrations
    app.migrations.add(CreateUser())
    app.migrations.add(CreateTodo())
    app.migrations.add(CreatePasswordReset())
    
    try await app.autoMigrate()
    
    // MARK: - Redis
    if let redisURL = Environment.get("REDIS_URL") {
        try app.redis.configuration = RedisConfiguration(url: redisURL)
    } else {
        app.redis.configuration = try RedisConfiguration(
            hostname: Environment.get("REDIS_HOST") ?? "localhost",
            port: Environment.get("REDIS_PORT").flatMap(Int.init) ?? 6379
        )
    }
    
    // MARK: - Queues
    app.queues.use(.redis(app.redis.configuration!))
    
    // Register jobs
    app.queues.add(EmailJob())
    app.queues.add(CleanupJob())
    
    // Start queue workers in production
    if app.environment == .production {
        try app.queues.startInProcessJobs()
    }
    
    // MARK: - JWT
    let jwtSecret = Environment.get("JWT_SECRET") ?? "secret-key-change-in-production"
    app.jwt.signers.use(.hs256(key: jwtSecret))
    
    // MARK: - Views
    app.views.use(.leaf)
    
    // MARK: - Sessions
    app.sessions.use(.redis)
    
    // MARK: - Services
    app.register(singleton: UserService.self) { app in
        UserService(app: app)
    }
    
    app.register(singleton: EmailService.self) { app in
        EmailService(app: app)
    }
    
    app.register(singleton: CacheService.self) { app in
        CacheService(app: app)
    }
    
    // MARK: - Routes
    try routes(app)
    
    // MARK: - Lifecycle
    app.lifecycle.use(ApplicationLifecycle())
}

// MARK: - Application Lifecycle
struct ApplicationLifecycle: LifecycleHandler {
    func didBoot(_ app: Application) throws {
        app.logger.info("Application started successfully")
        app.logger.info("Environment: \\(app.environment.name)")
        app.logger.info("Server: http://\\(app.http.server.configuration.hostname):\\(app.http.server.configuration.port)")
    }
    
    func shutdown(_ app: Application) {
        app.logger.info("Application shutting down...")
    }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'Sources/App/configure.swift'),
      configureContent
    );
  }

  private async generateRoutes(projectPath: string): Promise<void> {
    const routesContent = `import Fluent
import Vapor

/// Register your application's routes
func routes(_ app: Application) throws {
    // MARK: - Health Checks
    app.get("health") { req async throws -> HealthController.HealthResponse in
        try await HealthController.health(req)
    }
    
    app.get("ready") { req async throws -> HTTPStatus in
        .ok
    }
    
    // MARK: - API Version
    app.get("version") { req async throws -> [String: String] in
        [
            "version": "1.0.0",
            "name": req.application.environment.name,
            "swift": "5.9"
        ]
    }
    
    // MARK: - API Routes
    let api = app.grouped("api", "v1")
    
    // Public routes
    let publicAPI = api.grouped(LoggingMiddleware())
    try publicAPI.register(collection: AuthController())
    
    // Protected routes
    let protected = api.grouped(
        UserAuthenticator(),
        User.guardMiddleware(),
        LoggingMiddleware()
    )
    
    try protected.register(collection: UserController())
    try protected.register(collection: TodoController())
    
    // Admin routes
    let admin = protected.grouped(AdminMiddleware())
    try admin.register(collection: AdminController())
    
    // MARK: - WebSocket
    app.webSocket("ws") { req, ws in
        await WebSocketController().handle(req: req, ws: ws)
    }
    
    // MARK: - File Upload
    app.on(.POST, "upload", body: .collect(maxSize: "10mb")) { req async throws -> UploadResponse in
        try await FileController().upload(req)
    }
    
    // MARK: - Catch-all
    app.all("*") { req async throws -> HTTPStatus in
        throw Abort(.notFound, reason: "Route not found")
    }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'Sources/App/routes.swift'),
      routesContent
    );
  }

  private async generateUserModel(projectPath: string): Promise<void> {
    const userModelContent = `import Fluent
import JWT
import Vapor

/// User model with authentication support
final class User: Model, Content, Authenticatable {
    static let schema = "users"
    
    @ID(key: .id)
    var id: UUID?
    
    @Field(key: "email")
    var email: String
    
    @Field(key: "password_hash")
    var passwordHash: String
    
    @Field(key: "name")
    var name: String
    
    @OptionalField(key: "avatar_url")
    var avatarURL: String?
    
    @Field(key: "is_active")
    var isActive: Bool
    
    @Field(key: "is_admin")
    var isAdmin: Bool
    
    @OptionalField(key: "email_verified_at")
    var emailVerifiedAt: Date?
    
    @OptionalField(key: "last_login_at")
    var lastLoginAt: Date?
    
    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?
    
    @Timestamp(key: "updated_at", on: .update)
    var updatedAt: Date?
    
    @Children(for: \\.$user)
    var todos: [Todo]
    
    init() {}
    
    init(
        id: UUID? = nil,
        email: String,
        passwordHash: String,
        name: String,
        isActive: Bool = true,
        isAdmin: Bool = false
    ) {
        self.id = id
        self.email = email
        self.passwordHash = passwordHash
        self.name = name
        self.isActive = isActive
        self.isAdmin = isAdmin
    }
}

// MARK: - Authentication
extension User {
    func generateToken(_ app: Application) throws -> String {
        let payload = UserJWTPayload(
            subject: .init(value: self.id!.uuidString),
            expiration: .init(value: Date().addingTimeInterval(86400)), // 24 hours
            userId: self.id!,
            email: self.email,
            isAdmin: self.isAdmin
        )
        
        return try app.jwt.signers.sign(payload)
    }
    
    static func verify(password: String, hash: String) throws -> Bool {
        try Bcrypt.verify(password, created: hash)
    }
    
    static func hashPassword(_ password: String) throws -> String {
        try Bcrypt.hash(password)
    }
}

// MARK: - JWT Payload
struct UserJWTPayload: JWTPayload {
    enum CodingKeys: String, CodingKey {
        case subject = "sub"
        case expiration = "exp"
        case userId = "uid"
        case email = "email"
        case isAdmin = "admin"
    }
    
    var subject: SubjectClaim
    var expiration: ExpirationClaim
    var userId: UUID
    var email: String
    var isAdmin: Bool
    
    func verify(using signer: JWTSigner) throws {
        try self.expiration.verifyNotExpired()
    }
}

// MARK: - Authenticator
struct UserAuthenticator: AsyncBearerAuthenticator {
    func authenticate(bearer: BearerAuthorization, for request: Request) async throws {
        let payload = try request.jwt.verify(bearer.token, as: UserJWTPayload.self)
        
        guard let user = try await User.find(payload.userId, on: request.db) else {
            throw Abort(.unauthorized)
        }
        
        guard user.isActive else {
            throw Abort(.forbidden, reason: "Account is deactivated")
        }
        
        request.auth.login(user)
    }
}

// MARK: - Public Response
extension User {
    struct Public: Content {
        let id: UUID
        let email: String
        let name: String
        let avatarURL: String?
        let isAdmin: Bool
        let createdAt: Date?
    }
    
    var asPublic: Public {
        Public(
            id: id!,
            email: email,
            name: name,
            avatarURL: avatarURL,
            isAdmin: isAdmin,
            createdAt: createdAt
        )
    }
}

// MARK: - Validations
extension User: Validatable {
    static func validations(_ validations: inout Validations) {
        validations.add("email", as: String.self, is: .email)
        validations.add("password", as: String.self, is: .count(8...))
        validations.add("name", as: String.self, is: .count(2...100))
    }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'Sources/App/Models/User.swift'),
      userModelContent
    );

    // Generate Todo model as example
    const todoModelContent = `import Fluent
import Vapor

/// Example Todo model
final class Todo: Model, Content {
    static let schema = "todos"
    
    @ID(key: .id)
    var id: UUID?
    
    @Field(key: "title")
    var title: String
    
    @OptionalField(key: "description")
    var description: String?
    
    @Field(key: "is_completed")
    var isCompleted: Bool
    
    @OptionalField(key: "due_date")
    var dueDate: Date?
    
    @Parent(key: "user_id")
    var user: User
    
    @Timestamp(key: "created_at", on: .create)
    var createdAt: Date?
    
    @Timestamp(key: "updated_at", on: .update)
    var updatedAt: Date?
    
    init() {}
    
    init(
        id: UUID? = nil,
        title: String,
        description: String? = nil,
        isCompleted: Bool = false,
        dueDate: Date? = nil,
        userID: UUID
    ) {
        self.id = id
        self.title = title
        self.description = description
        self.isCompleted = isCompleted
        self.dueDate = dueDate
        self.$user.id = userID
    }
}

// MARK: - Validations
extension Todo: Validatable {
    static func validations(_ validations: inout Validations) {
        validations.add("title", as: String.self, is: .count(1...255))
        validations.add("description", as: String.self, is: .count(...1000), required: false)
    }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'Sources/App/Models/Todo.swift'),
      todoModelContent
    );
  }

  private async generateAuthController(projectPath: string): Promise<void> {
    const authControllerContent = `import Fluent
import JWT
import Vapor

/// Authentication endpoints
struct AuthController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let auth = routes.grouped("auth")
        
        auth.post("register", use: register)
        auth.post("login", use: login)
        auth.post("refresh", use: refresh)
        auth.post("logout", use: logout)
        auth.post("forgot-password", use: forgotPassword)
        auth.post("reset-password", use: resetPassword)
        auth.get("verify-email", ":token", use: verifyEmail)
    }
    
    // MARK: - Register
    func register(req: Request) async throws -> AuthResponse {
        // Validate request
        try RegisterRequest.validate(content: req)
        let registerReq = try req.content.decode(RegisterRequest.self)
        
        // Check if user exists
        let existingUser = try await User.query(on: req.db)
            .filter(\\.$email == registerReq.email.lowercased())
            .first()
        
        guard existingUser == nil else {
            throw Abort(.badRequest, reason: "Email already registered")
        }
        
        // Create user
        let passwordHash = try User.hashPassword(registerReq.password)
        let user = User(
            email: registerReq.email.lowercased(),
            passwordHash: passwordHash,
            name: registerReq.name
        )
        
        try await user.save(on: req.db)
        
        // Send verification email
        try await req.queue.dispatch(
            EmailJob.self,
            EmailJob.Payload(
                to: user.email,
                subject: "Verify your email",
                template: "verify-email",
                data: ["name": user.name, "token": UUID().uuidString]
            )
        )
        
        // Generate tokens
        let token = try user.generateToken(req.application)
        let refreshToken = try generateRefreshToken(for: user, on: req)
        
        return AuthResponse(
            user: user.asPublic,
            token: token,
            refreshToken: refreshToken,
            expiresIn: 86400
        )
    }
    
    // MARK: - Login
    func login(req: Request) async throws -> AuthResponse {
        // Validate request
        let loginReq = try req.content.decode(LoginRequest.self)
        
        // Find user
        guard let user = try await User.query(on: req.db)
            .filter(\\.$email == loginReq.email.lowercased())
            .first() else {
            throw Abort(.unauthorized, reason: "Invalid credentials")
        }
        
        // Verify password
        guard try User.verify(password: loginReq.password, hash: user.passwordHash) else {
            throw Abort(.unauthorized, reason: "Invalid credentials")
        }
        
        // Check if active
        guard user.isActive else {
            throw Abort(.forbidden, reason: "Account is deactivated")
        }
        
        // Update last login
        user.lastLoginAt = Date()
        try await user.save(on: req.db)
        
        // Generate tokens
        let token = try user.generateToken(req.application)
        let refreshToken = try generateRefreshToken(for: user, on: req)
        
        return AuthResponse(
            user: user.asPublic,
            token: token,
            refreshToken: refreshToken,
            expiresIn: 86400
        )
    }
    
    // MARK: - Refresh Token
    func refresh(req: Request) async throws -> AuthResponse {
        let refreshReq = try req.content.decode(RefreshRequest.self)
        
        // Verify refresh token
        guard let tokenData = try await req.redis.get(
            RedisKey("refresh_token:\\(refreshReq.refreshToken)"),
            as: String.self
        ) else {
            throw Abort(.unauthorized, reason: "Invalid refresh token")
        }
        
        // Get user
        guard let userId = UUID(uuidString: tokenData),
              let user = try await User.find(userId, on: req.db) else {
            throw Abort(.unauthorized)
        }
        
        // Check if active
        guard user.isActive else {
            throw Abort(.forbidden, reason: "Account is deactivated")
        }
        
        // Delete old refresh token
        try await req.redis.delete(RedisKey("refresh_token:\\(refreshReq.refreshToken)"))
        
        // Generate new tokens
        let token = try user.generateToken(req.application)
        let refreshToken = try generateRefreshToken(for: user, on: req)
        
        return AuthResponse(
            user: user.asPublic,
            token: token,
            refreshToken: refreshToken,
            expiresIn: 86400
        )
    }
    
    // MARK: - Logout
    func logout(req: Request) async throws -> HTTPStatus {
        guard let user = req.auth.get(User.self) else {
            throw Abort(.unauthorized)
        }
        
        // Invalidate tokens (implement token blacklist if needed)
        req.auth.logout(User.self)
        
        return .noContent
    }
    
    // MARK: - Forgot Password
    func forgotPassword(req: Request) async throws -> GenericResponse {
        let forgotReq = try req.content.decode(ForgotPasswordRequest.self)
        
        // Find user
        guard let user = try await User.query(on: req.db)
            .filter(\\.$email == forgotReq.email.lowercased())
            .first() else {
            // Return success even if user not found (security)
            return GenericResponse(message: "If the email exists, a reset link has been sent")
        }
        
        // Generate reset token
        let resetToken = UUID().uuidString
        let expiry = Date().addingTimeInterval(3600) // 1 hour
        
        // Store in Redis
        try await req.redis.setex(
            RedisKey("password_reset:\\(resetToken)"),
            to: user.id!.uuidString,
            expirationInSeconds: 3600
        )
        
        // Send email
        try await req.queue.dispatch(
            EmailJob.self,
            EmailJob.Payload(
                to: user.email,
                subject: "Reset your password",
                template: "reset-password",
                data: [
                    "name": user.name,
                    "resetLink": "https://example.com/reset-password?token=\\(resetToken)"
                ]
            )
        )
        
        return GenericResponse(message: "If the email exists, a reset link has been sent")
    }
    
    // MARK: - Reset Password
    func resetPassword(req: Request) async throws -> GenericResponse {
        let resetReq = try req.content.decode(ResetPasswordRequest.self)
        
        // Verify token
        guard let userIdString = try await req.redis.get(
            RedisKey("password_reset:\\(resetReq.token)"),
            as: String.self
        ) else {
            throw Abort(.badRequest, reason: "Invalid or expired reset token")
        }
        
        // Get user
        guard let userId = UUID(uuidString: userIdString),
              let user = try await User.find(userId, on: req.db) else {
            throw Abort(.badRequest, reason: "Invalid or expired reset token")
        }
        
        // Update password
        user.passwordHash = try User.hashPassword(resetReq.newPassword)
        try await user.save(on: req.db)
        
        // Delete reset token
        try await req.redis.delete(RedisKey("password_reset:\\(resetReq.token)"))
        
        // Send confirmation email
        try await req.queue.dispatch(
            EmailJob.self,
            EmailJob.Payload(
                to: user.email,
                subject: "Password reset successful",
                template: "password-reset-success",
                data: ["name": user.name]
            )
        )
        
        return GenericResponse(message: "Password reset successful")
    }
    
    // MARK: - Verify Email
    func verifyEmail(req: Request) async throws -> GenericResponse {
        guard let token = req.parameters.get("token") else {
            throw Abort(.badRequest)
        }
        
        // Verify token and update user
        // Implementation depends on your verification strategy
        
        return GenericResponse(message: "Email verified successfully")
    }
    
    // MARK: - Helpers
    private func generateRefreshToken(for user: User, on req: Request) async throws -> String {
        let token = UUID().uuidString
        let expiry = 86400 * 30 // 30 days
        
        try await req.redis.setex(
            RedisKey("refresh_token:\\(token)"),
            to: user.id!.uuidString,
            expirationInSeconds: expiry
        )
        
        return token
    }
}

// MARK: - Request/Response Models
struct RegisterRequest: Content, Validatable {
    let email: String
    let password: String
    let name: String
    
    static func validations(_ validations: inout Validations) {
        validations.add("email", as: String.self, is: .email)
        validations.add("password", as: String.self, is: .count(8...))
        validations.add("name", as: String.self, is: .count(2...100))
    }
}

struct LoginRequest: Content {
    let email: String
    let password: String
}

struct RefreshRequest: Content {
    let refreshToken: String
}

struct ForgotPasswordRequest: Content {
    let email: String
}

struct ResetPasswordRequest: Content {
    let token: String
    let newPassword: String
}

struct AuthResponse: Content {
    let user: User.Public
    let token: String
    let refreshToken: String
    let expiresIn: Int
}

struct GenericResponse: Content {
    let message: String
}
`;

    await fs.writeFile(
      path.join(projectPath, 'Sources/App/Controllers/AuthController.swift'),
      authControllerContent
    );
  }

  private async generateMiddleware(projectPath: string): Promise<void> {
    // Logging middleware
    const loggingMiddleware = `import Vapor

/// Logs all incoming requests
struct LoggingMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        let start = Date()
        let method = request.method.rawValue
        let path = request.url.path
        
        do {
            let response = try await next.respond(to: request)
            
            let duration = Date().timeIntervalSince(start) * 1000
            request.logger.info(
                "\\(method) \\(path) - \\(response.status.code) (\\(String(format: "%.2f", duration))ms)",
                metadata: [
                    "method": .string(method),
                    "path": .string(path),
                    "status": .stringConvertible(response.status.code),
                    "duration_ms": .stringConvertible(duration),
                    "ip": .string(request.remoteAddress?.hostname ?? "unknown")
                ]
            )
            
            return response
        } catch {
            let duration = Date().timeIntervalSince(start) * 1000
            request.logger.error(
                "\\(method) \\(path) - ERROR (\\(String(format: "%.2f", duration))ms): \\(error)",
                metadata: [
                    "method": .string(method),
                    "path": .string(path),
                    "duration_ms": .stringConvertible(duration),
                    "error": .string(String(describing: error))
                ]
            )
            throw error
        }
    }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'Sources/App/Middleware/LoggingMiddleware.swift'),
      loggingMiddleware
    );

    // Rate limiting middleware
    const rateLimitMiddleware = `import Vapor
import Redis

/// Rate limiting middleware using Redis
struct RateLimitMiddleware: AsyncMiddleware {
    let limit: Int
    let window: Int // seconds
    
    init(limit: Int = 100, window: Int = 3600) {
        self.limit = limit
        self.window = window
    }
    
    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        let key = getRateLimitKey(for: request)
        
        // Get current count
        let count = try await request.redis.get(RedisKey(key), as: Int.self) ?? 0
        
        if count >= limit {
            throw Abort(
                .tooManyRequests,
                reason: "Rate limit exceeded. Try again later.",
                headers: [
                    "X-RateLimit-Limit": "\\(limit)",
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": "\\(Date().addingTimeInterval(Double(window)).timeIntervalSince1970)"
                ]
            )
        }
        
        // Increment counter
        if count == 0 {
            try await request.redis.setex(RedisKey(key), to: 1, expirationInSeconds: window)
        } else {
            try await request.redis.increment(RedisKey(key))
        }
        
        // Add rate limit headers
        let response = try await next.respond(to: request)
        response.headers.add(name: "X-RateLimit-Limit", value: "\\(limit)")
        response.headers.add(name: "X-RateLimit-Remaining", value: "\\(max(0, limit - count - 1))")
        response.headers.add(name: "X-RateLimit-Reset", value: "\\(Date().addingTimeInterval(Double(window)).timeIntervalSince1970)")
        
        return response
    }
    
    private func getRateLimitKey(for request: Request) -> String {
        // Use authenticated user ID if available, otherwise IP
        if let userId = request.auth.get(User.self)?.id {
            return "rate_limit:user:\\(userId)"
        } else {
            let ip = request.remoteAddress?.hostname ?? "unknown"
            return "rate_limit:ip:\\(ip)"
        }
    }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'Sources/App/Middleware/RateLimitMiddleware.swift'),
      rateLimitMiddleware
    );

    // Admin middleware
    const adminMiddleware = `import Vapor

/// Ensures the authenticated user is an admin
struct AdminMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        guard let user = request.auth.get(User.self) else {
            throw Abort(.unauthorized)
        }
        
        guard user.isAdmin else {
            throw Abort(.forbidden, reason: "Admin access required")
        }
        
        return try await next.respond(to: request)
    }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'Sources/App/Middleware/AdminMiddleware.swift'),
      adminMiddleware
    );
  }

  private async generateMigrations(projectPath: string): Promise<void> {
    // User migration
    const userMigration = `import Fluent

struct CreateUser: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("users")
            .id()
            .field("email", .string, .required)
            .field("password_hash", .string, .required)
            .field("name", .string, .required)
            .field("avatar_url", .string)
            .field("is_active", .bool, .required, .sql(.default(true)))
            .field("is_admin", .bool, .required, .sql(.default(false)))
            .field("email_verified_at", .datetime)
            .field("last_login_at", .datetime)
            .field("created_at", .datetime, .required)
            .field("updated_at", .datetime, .required)
            .unique(on: "email")
            .create()
        
        // Create indexes
        try await database.schema("users")
            .field(.custom("CREATE INDEX idx_users_email ON users(email)"))
            .update()
    }
    
    func revert(on database: Database) async throws {
        try await database.schema("users").delete()
    }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'Sources/App/Migrations/CreateUser.swift'),
      userMigration
    );

    // Todo migration
    const todoMigration = `import Fluent

struct CreateTodo: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("todos")
            .id()
            .field("title", .string, .required)
            .field("description", .string)
            .field("is_completed", .bool, .required, .sql(.default(false)))
            .field("due_date", .datetime)
            .field("user_id", .uuid, .required, .references("users", "id", onDelete: .cascade))
            .field("created_at", .datetime, .required)
            .field("updated_at", .datetime, .required)
            .create()
        
        // Create indexes
        try await database.schema("todos")
            .field(.custom("CREATE INDEX idx_todos_user_id ON todos(user_id)"))
            .field(.custom("CREATE INDEX idx_todos_due_date ON todos(due_date)"))
            .update()
    }
    
    func revert(on database: Database) async throws {
        try await database.schema("todos").delete()
    }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'Sources/App/Migrations/CreateTodo.swift'),
      todoMigration
    );

    // Password reset migration
    const passwordResetMigration = `import Fluent

struct CreatePasswordReset: AsyncMigration {
    func prepare(on database: Database) async throws {
        try await database.schema("password_resets")
            .id()
            .field("email", .string, .required)
            .field("token", .string, .required)
            .field("expires_at", .datetime, .required)
            .field("created_at", .datetime, .required)
            .unique(on: "token")
            .create()
        
        // Create indexes
        try await database.schema("password_resets")
            .field(.custom("CREATE INDEX idx_password_resets_email ON password_resets(email)"))
            .field(.custom("CREATE INDEX idx_password_resets_token ON password_resets(token)"))
            .update()
    }
    
    func revert(on database: Database) async throws {
        try await database.schema("password_resets").delete()
    }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'Sources/App/Migrations/CreatePasswordReset.swift'),
      passwordResetMigration
    );
  }

  private async generateServices(projectPath: string): Promise<void> {
    // User service
    const userService = `import Fluent
import Vapor

/// Service for user-related operations
protocol UserServiceProtocol {
    func find(_ id: UUID, on db: Database) async throws -> User?
    func findByEmail(_ email: String, on db: Database) async throws -> User?
    func create(_ data: CreateUserData, on db: Database) async throws -> User
    func update(_ user: User, with data: UpdateUserData, on db: Database) async throws -> User
    func delete(_ user: User, on db: Database) async throws
    func search(query: String, on db: Database) async throws -> [User]
}

final class UserService: UserServiceProtocol {
    let app: Application
    
    init(app: Application) {
        self.app = app
    }
    
    func find(_ id: UUID, on db: Database) async throws -> User? {
        try await User.find(id, on: db)
    }
    
    func findByEmail(_ email: String, on db: Database) async throws -> User? {
        try await User.query(on: db)
            .filter(\\.$email == email.lowercased())
            .first()
    }
    
    func create(_ data: CreateUserData, on db: Database) async throws -> User {
        let user = User(
            email: data.email.lowercased(),
            passwordHash: try User.hashPassword(data.password),
            name: data.name
        )
        
        try await user.save(on: db)
        return user
    }
    
    func update(_ user: User, with data: UpdateUserData, on db: Database) async throws -> User {
        if let name = data.name {
            user.name = name
        }
        
        if let avatarURL = data.avatarURL {
            user.avatarURL = avatarURL
        }
        
        if let password = data.password {
            user.passwordHash = try User.hashPassword(password)
        }
        
        try await user.save(on: db)
        return user
    }
    
    func delete(_ user: User, on db: Database) async throws {
        try await user.delete(on: db)
    }
    
    func search(query: String, on db: Database) async throws -> [User] {
        try await User.query(on: db)
            .group(.or) { group in
                group
                    .filter(\\.$name ~~ query)
                    .filter(\\.$email ~~ query)
            }
            .limit(20)
            .all()
    }
}

// MARK: - Data Models
struct CreateUserData {
    let email: String
    let password: String
    let name: String
}

struct UpdateUserData {
    let name: String?
    let avatarURL: String?
    let password: String?
}
`;

    await fs.writeFile(
      path.join(projectPath, 'Sources/App/Services/UserService.swift'),
      userService
    );

    // Email service
    const emailService = `import Queues
import Vapor

/// Service for sending emails
protocol EmailServiceProtocol {
    func send(to: String, subject: String, body: String) async throws
    func sendTemplate(to: String, subject: String, template: String, data: [String: Any]) async throws
}

final class EmailService: EmailServiceProtocol {
    let app: Application
    
    init(app: Application) {
        self.app = app
    }
    
    func send(to: String, subject: String, body: String) async throws {
        // Queue email job
        try await app.queues.queue.dispatch(
            EmailJob.self,
            EmailJob.Payload(
                to: to,
                subject: subject,
                body: body
            )
        )
    }
    
    func sendTemplate(to: String, subject: String, template: String, data: [String: Any]) async throws {
        // Render template and send
        let body = try await renderTemplate(template: template, data: data)
        try await send(to: to, subject: subject, body: body)
    }
    
    private func renderTemplate(template: String, data: [String: Any]) async throws -> String {
        // Use Leaf or another templating engine
        // This is a simplified example
        return "Email content for template: \\(template)"
    }
}

// MARK: - Email Job
struct EmailJob: AsyncJob {
    struct Payload: Codable {
        let to: String
        let subject: String
        var body: String?
        var template: String?
        var data: [String: String]?
    }
    
    func dequeue(_ context: QueueContext, _ payload: Payload) async throws {
        context.logger.info("Sending email to \\(payload.to)")
        
        // Implement actual email sending logic here
        // This could use SendGrid, AWS SES, Mailgun, etc.
        
        // Simulate email sending
        try await Task.sleep(nanoseconds: 1_000_000_000) // 1 second
        
        context.logger.info("Email sent successfully to \\(payload.to)")
    }
    
    func error(_ context: QueueContext, _ error: Error, _ payload: Payload) async throws {
        context.logger.error("Failed to send email to \\(payload.to): \\(error)")
        
        // Implement retry logic or error handling
    }
}

// MARK: - Cleanup Job
struct CleanupJob: AsyncScheduledJob {
    func run(context: QueueContext) async throws {
        context.logger.info("Running cleanup job")
        
        // Implement cleanup logic
        // - Delete expired sessions
        // - Clean up temporary files
        // - Remove old logs
        
        context.logger.info("Cleanup job completed")
    }
    
    var schedule: String {
        // Run every day at midnight
        "0 0 * * *"
    }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'Sources/App/Services/EmailService.swift'),
      emailService
    );

    // Cache service
    const cacheService = `import Redis
import Vapor

/// Service for caching operations
protocol CacheServiceProtocol {
    func get<T: Codable>(_ key: String, as type: T.Type) async throws -> T?
    func set<T: Codable>(_ key: String, to value: T, expiresIn seconds: Int?) async throws
    func delete(_ key: String) async throws
    func exists(_ key: String) async throws -> Bool
    func clear(pattern: String) async throws
}

final class CacheService: CacheServiceProtocol {
    let app: Application
    private let keyPrefix = "cache:"
    
    init(app: Application) {
        self.app = app
    }
    
    func get<T: Codable>(_ key: String, as type: T.Type) async throws -> T? {
        let fullKey = RedisKey(keyPrefix + key)
        
        guard let data = try await app.redis.get(fullKey, as: Data.self) else {
            return nil
        }
        
        return try JSONDecoder().decode(type, from: data)
    }
    
    func set<T: Codable>(_ key: String, to value: T, expiresIn seconds: Int? = nil) async throws {
        let fullKey = RedisKey(keyPrefix + key)
        let data = try JSONEncoder().encode(value)
        
        if let seconds = seconds {
            try await app.redis.setex(fullKey, to: data, expirationInSeconds: seconds)
        } else {
            try await app.redis.set(fullKey, to: data)
        }
    }
    
    func delete(_ key: String) async throws {
        let fullKey = RedisKey(keyPrefix + key)
        _ = try await app.redis.delete(fullKey)
    }
    
    func exists(_ key: String) async throws -> Bool {
        let fullKey = RedisKey(keyPrefix + key)
        return try await app.redis.exists(fullKey) > 0
    }
    
    func clear(pattern: String) async throws {
        // Use SCAN to find and delete keys matching pattern
        // This is a simplified implementation
        app.logger.info("Clearing cache with pattern: \\(pattern)")
    }
}

// MARK: - Cache Helpers
extension Request {
    var cache: CacheService {
        self.application.cache
    }
}

extension Application {
    var cache: CacheService {
        self.services.resolve()!
    }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'Sources/App/Services/CacheService.swift'),
      cacheService
    );
  }

  private async generateDTOs(projectPath: string): Promise<void> {
    const paginationDTO = `import Vapor

/// Pagination request parameters
struct PaginationRequest: Content {
    let page: Int?
    let limit: Int?
    let sort: String?
    let order: SortOrder?
    
    var validatedPage: Int {
        max(1, page ?? 1)
    }
    
    var validatedLimit: Int {
        min(100, max(1, limit ?? 20))
    }
    
    var offset: Int {
        (validatedPage - 1) * validatedLimit
    }
    
    enum SortOrder: String, Content {
        case asc = "asc"
        case desc = "desc"
    }
}

/// Paginated response wrapper
struct PaginatedResponse<T: Content>: Content {
    let data: [T]
    let pagination: PaginationMetadata
}

struct PaginationMetadata: Content {
    let page: Int
    let limit: Int
    let total: Int
    let pages: Int
}

/// Error response
struct ErrorResponse: Content {
    let error: ErrorDetail
}

struct ErrorDetail: Content {
    let code: String
    let message: String
    let details: [String: String]?
}

/// Upload response
struct UploadResponse: Content {
    let url: String
    let filename: String
    let size: Int
    let mimeType: String
}

/// Generic filter request
struct FilterRequest: Content {
    let search: String?
    let status: String?
    let from: Date?
    let to: Date?
    let tags: [String]?
}
`;

    await fs.writeFile(
      path.join(projectPath, 'Sources/App/DTOs/Common.swift'),
      paginationDTO
    );
  }

  private async generateEnvironment(projectPath: string): Promise<void> {
    const environmentContent = `import Vapor

/// Application environment configuration
enum Environment: String, CaseIterable {
    case development
    case staging
    case production
    case testing
    
    static var current: Environment {
        guard let env = ProcessInfo.processInfo.environment["ENVIRONMENT"],
              let environment = Environment(rawValue: env) else {
            return .development
        }
        return environment
    }
    
    var isDevelopment: Bool {
        self == .development
    }
    
    var isProduction: Bool {
        self == .production
    }
    
    var isTesting: Bool {
        self == .testing
    }
}

/// Environment variable helpers
extension Environment {
    static func get(_ key: String) -> String? {
        ProcessInfo.processInfo.environment[key]
    }
    
    static func require(_ key: String) throws -> String {
        guard let value = get(key) else {
            throw Abort(.internalServerError, reason: "Missing required environment variable: \\(key)")
        }
        return value
    }
}

/// Configuration struct
struct AppConfiguration {
    let port: Int
    let host: String
    let environment: Environment
    
    // Database
    let databaseURL: String
    
    // Redis
    let redisURL: String
    
    // JWT
    let jwtSecret: String
    let jwtExpiresIn: Int
    
    // Email
    let emailFrom: String
    let emailProvider: EmailProvider
    
    // Storage
    let storageProvider: StorageProvider
    let storageBucket: String
    
    // Features
    let enableSwagger: Bool
    let enableMetrics: Bool
    let enableHealthCheck: Bool
    
    enum EmailProvider: String {
        case sendgrid
        case ses
        case mailgun
        case smtp
    }
    
    enum StorageProvider: String {
        case s3
        case gcs
        case local
    }
    
    static func load() throws -> AppConfiguration {
        AppConfiguration(
            port: Int(Environment.get("PORT") ?? "8080") ?? 8080,
            host: Environment.get("HOST") ?? "0.0.0.0",
            environment: .current,
            databaseURL: try Environment.require("DATABASE_URL"),
            redisURL: Environment.get("REDIS_URL") ?? "redis://localhost:6379",
            jwtSecret: try Environment.require("JWT_SECRET"),
            jwtExpiresIn: Int(Environment.get("JWT_EXPIRES_IN") ?? "86400") ?? 86400,
            emailFrom: Environment.get("EMAIL_FROM") ?? "noreply@example.com",
            emailProvider: EmailProvider(rawValue: Environment.get("EMAIL_PROVIDER") ?? "smtp") ?? .smtp,
            storageProvider: StorageProvider(rawValue: Environment.get("STORAGE_PROVIDER") ?? "local") ?? .local,
            storageBucket: Environment.get("STORAGE_BUCKET") ?? "uploads",
            enableSwagger: Bool(Environment.get("ENABLE_SWAGGER") ?? "true") ?? true,
            enableMetrics: Bool(Environment.get("ENABLE_METRICS") ?? "true") ?? true,
            enableHealthCheck: Bool(Environment.get("ENABLE_HEALTH_CHECK") ?? "true") ?? true
        )
    }
}
`;

    await fs.writeFile(
      path.join(projectPath, 'Sources/App/Utils/Environment.swift'),
      environmentContent
    );
  }
}

// Export for use in template system
export default VaporGenerator;