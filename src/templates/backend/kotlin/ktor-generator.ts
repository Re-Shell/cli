import { KotlinBackendGenerator } from './kotlin-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class KtorGenerator extends KotlinBackendGenerator {
  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'io.ktor:ktor-server-core': '2.3.7',
      'io.ktor:ktor-server-netty': '2.3.7',
      'io.ktor:ktor-server-host-common': '2.3.7',
      'io.ktor:ktor-server-status-pages': '2.3.7',
      'io.ktor:ktor-server-cors': '2.3.7',
      'io.ktor:ktor-server-call-logging': '2.3.7',
      'io.ktor:ktor-server-call-id': '2.3.7',
      'io.ktor:ktor-server-content-negotiation': '2.3.7',
      'io.ktor:ktor-serialization-kotlinx-json': '2.3.7',
      'io.ktor:ktor-server-auth': '2.3.7',
      'io.ktor:ktor-server-auth-jwt': '2.3.7',
      'io.ktor:ktor-server-compression': '2.3.7',
      'io.ktor:ktor-server-auto-head-response': '2.3.7',
      'io.ktor:ktor-server-caching-headers': '2.3.7',
      'io.ktor:ktor-server-partial-content': '2.3.7',
      'io.ktor:ktor-server-metrics-micrometer': '2.3.7',
      'io.ktor:ktor-server-swagger': '2.3.7',
      'io.ktor:ktor-server-openapi': '2.3.7',
      'io.micrometer:micrometer-registry-prometheus': '1.12.0'
    };
  }

  protected generateMainFile(): string {
    return `package com.example

import com.example.config.configureDatabase
import com.example.config.configureDependencyInjection
import com.example.config.configureMonitoring
import com.example.config.configureRouting
import com.example.config.configureSecurity
import com.example.config.configureSerialization
import com.example.plugins.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import com.typesafe.config.ConfigFactory

fun main() {
    val config = ConfigFactory.load()
    val port = config.getString("ktor.deployment.port").toInt()
    val host = config.getString("ktor.deployment.host")
    
    embeddedServer(
        Netty,
        port = port,
        host = host,
        module = Application::module
    ).start(wait = true)
}

fun Application.module() {
    // Configure application
    configureDependencyInjection()
    configureDatabase()
    configureSecurity()
    configureSerialization()
    configureMonitoring()
    configureHTTP()
    configureRouting()
    
    println(\\\\"Application started successfully\\\\")
}`
  }

  protected generateRoutingFile(): string {
    return `package com.example.config

import com.example.controllers.*
import com.example.middleware.AuthMiddleware
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.http.*
import org.koin.ktor.ext.inject

fun Application.configureRouting() {
    val authController by inject<AuthController>()
    val userController by inject<UserController>()
    val healthController by inject<HealthController>()
    val authMiddleware by inject<AuthMiddleware>()
    
    routing {
        // Health check
        get("/health") {
            healthController.health(call)
        }
        
        // API routes
        route("/api") {
            // Auth routes
            route("/auth") {
                post("/register") {
                    authController.register(call)
                }
                post("/login") {
                    authController.login(call)
                }
                post("/refresh") {
                    authController.refresh(call)
                }
                post("/logout") {
                    authMiddleware.requireAuth(call) {
                        authController.logout(call)
                    }
                }
            }
            
            // User routes
            route("/users") {
                get {
                    authMiddleware.requireRole(call, "admin") {
                        userController.getAllUsers(call)
                    }
                }
                get("/{id}") {
                    authMiddleware.requireAuth(call) {
                        userController.getUserById(call)
                    }
                }
                get("/me") {
                    authMiddleware.requireAuth(call) { user ->
                        userController.getCurrentUser(call, user)
                    }
                }
                put("/{id}") {
                    authMiddleware.requireAuth(call) {
                        userController.updateUser(call)
                    }
                }
                delete("/{id}") {
                    authMiddleware.requireRole(call, "admin") {
                        userController.deleteUser(call)
                    }
                }
            }
        }
        
        // Static files and SPA support
        get("/") {
            call.respondText("Welcome to \${this@configureRouting.environment.config.property(\"ktor.application.name\").getString()}", ContentType.Text.Plain)
        }
    }
}`
  }

  protected generateServiceFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/kotlin/com/example/services/UserService.kt',
        content: `package com.example.services

import com.example.dto.*
import com.example.models.User
import com.example.repositories.UserRepository
import com.example.utils.PasswordUtils
import com.example.middleware.NotFoundException
import com.example.middleware.ValidationException
import org.koin.core.annotation.Single

@Single
class UserService(private val userRepository: UserRepository) {
    
    suspend fun createUser(request: CreateUserRequest): User {
        // Validate email uniqueness
        if (userRepository.findByEmail(request.email) != null) {
            throw ValidationException("Email already exists")
        }
        
        // Hash password
        val hashedPassword = PasswordUtils.hashPassword(request.password)
        
        // Create user
        return userRepository.create(
            email = request.email,
            password = hashedPassword,
            name = request.name
        )
    }
    
    suspend fun findById(id: Int): User? {
        return userRepository.findById(id)
    }
    
    suspend fun findByEmail(email: String): User? {
        return userRepository.findByEmail(email)
    }
    
    suspend fun getAllUsers(page: Int = 0, size: Int = 20): List<User> {
        return userRepository.findAll(page, size)
    }
    
    suspend fun updateUser(id: Int, request: UpdateUserRequest): User {
        val user = userRepository.findById(id) 
            ?: throw NotFoundException("User not found")
        
        val updates = mutableMapOf<String, Any>()
        
        request.name?.let { updates["name"] = it }
        request.email?.let { 
            // Check email uniqueness if changing
            if (it != user.email && userRepository.findByEmail(it) != null) {
                throw ValidationException("Email already exists")
            }
            updates["email"] = it 
        }
        request.password?.let { 
            updates["password"] = PasswordUtils.hashPassword(it) 
        }
        
        return userRepository.update(id, updates)
    }
    
    suspend fun deleteUser(id: Int) {
        if (userRepository.findById(id) == null) {
            throw NotFoundException("User not found")
        }
        userRepository.delete(id)
    }
    
    suspend fun validateCredentials(email: String, password: String): User? {
        val user = userRepository.findByEmail(email) ?: return null
        
        return if (PasswordUtils.verifyPassword(password, user.password)) {
            user
        } else {
            null
        }
    }
}`
      },
      {
        path: 'src/main/kotlin/com/example/services/AuthService.kt',
        content: `package com.example.services

import com.example.dto.*
import com.example.models.User
import com.example.utils.JwtUtils
import com.example.middleware.UnauthorizedException
import com.example.middleware.ValidationException
import org.koin.core.annotation.Single
import java.util.concurrent.ConcurrentHashMap

@Single
class AuthService(
    private val userService: UserService,
    private val jwtUtils: JwtUtils
) {
    // In-memory refresh token storage (use Redis in production)
    private val refreshTokens = ConcurrentHashMap<String, Int>()
    
    suspend fun register(request: CreateUserRequest): AuthResponse {
        val user = userService.createUser(request)
        return generateAuthResponse(user)
    }
    
    suspend fun login(request: LoginRequest): AuthResponse {
        val user = userService.validateCredentials(request.email, request.password)
            ?: throw UnauthorizedException("Invalid email or password")
        
        if (!user.isActive) {
            throw UnauthorizedException("Account is disabled")
        }
        
        return generateAuthResponse(user)
    }
    
    suspend fun refreshToken(request: RefreshTokenRequest): AuthResponse {
        val userId = refreshTokens[request.refreshToken]
            ?: throw UnauthorizedException("Invalid refresh token")
        
        val user = userService.findById(userId)
            ?: throw UnauthorizedException("User not found")
        
        // Remove old refresh token
        refreshTokens.remove(request.refreshToken)
        
        return generateAuthResponse(user)
    }
    
    suspend fun logout(refreshToken: String) {
        refreshTokens.remove(refreshToken)
    }
    
    private fun generateAuthResponse(user: User): AuthResponse {
        val token = jwtUtils.generateToken(user)
        val refreshToken = jwtUtils.generateRefreshToken(user)
        
        // Store refresh token
        refreshTokens[refreshToken] = user.id
        
        return AuthResponse(
            token = token,
            refreshToken = refreshToken,
            user = UserResponse(
                id = user.id,
                email = user.email,
                name = user.name,
                role = user.role,
                isActive = user.isActive,
                createdAt = user.createdAt.toString(),
                updatedAt = user.updatedAt.toString()
            )
        )
    }
}`
      }
    ];
  }

  protected generateRepositoryFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/kotlin/com/example/repositories/UserRepository.kt',
        content: `package com.example.repositories

import com.example.models.User
import com.example.models.Users
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.transactions.transaction
import org.koin.core.annotation.Single
import java.time.Instant

@Single
class UserRepository {
    
    suspend fun create(email: String, password: String, name: String, role: String = "user"): User = transaction {
        val id = Users.insertAndGetId {
            it[this.email] = email
            it[this.password] = password
            it[this.name] = name
            it[this.role] = role
            it[isActive] = true
            it[createdAt] = Instant.now()
            it[updatedAt] = Instant.now()
        }
        
        findById(id.value)!!
    }
    
    suspend fun findById(id: Int): User? = transaction {
        Users.select { Users.id eq id }
            .map { rowToUser(it) }
            .singleOrNull()
    }
    
    suspend fun findByEmail(email: String): User? = transaction {
        Users.select { Users.email eq email }
            .map { rowToUser(it) }
            .singleOrNull()
    }
    
    suspend fun findAll(page: Int = 0, size: Int = 20): List<User> = transaction {
        Users.selectAll()
            .limit(size, offset = (page * size).toLong())
            .orderBy(Users.createdAt to SortOrder.DESC)
            .map { rowToUser(it) }
    }
    
    suspend fun update(id: Int, updates: Map<String, Any>): User = transaction {
        Users.update({ Users.id eq id }) {
            updates.forEach { (key, value) ->
                when (key) {
                    "email" -> it[email] = value as String
                    "password" -> it[password] = value as String
                    "name" -> it[name] = value as String
                    "role" -> it[role] = value as String
                    "isActive" -> it[isActive] = value as Boolean
                }
            }
            it[updatedAt] = Instant.now()
        }
        
        findById(id)!!
    }
    
    suspend fun delete(id: Int) = transaction {
        Users.deleteWhere { Users.id eq id }
    }
    
    private fun rowToUser(row: ResultRow): User = User(
        id = row[Users.id].value,
        email = row[Users.email],
        password = row[Users.password],
        name = row[Users.name],
        role = row[Users.role],
        isActive = row[Users.isActive],
        createdAt = row[Users.createdAt],
        updatedAt = row[Users.updatedAt]
    )
}`
      }
    ];
  }

  protected generateModelFiles(): { path: string; content: string }[] {
    return [];
  }

  protected generateConfigFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/kotlin/com/example/config/DatabaseConfig.kt',
        content: `package com.example.config

import com.example.models.Users
import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import io.ktor.server.application.*
import org.jetbrains.exposed.sql.Database
import org.jetbrains.exposed.sql.SchemaUtils
import org.jetbrains.exposed.sql.transactions.transaction

fun Application.configureDatabase() {
    val dbUrl = environment.config.property(\\"database.url\\").getString()
    val dbUser = environment.config.property(\\"database.user\\").getString()
    val dbPassword = environment.config.property(\\"database.password\\").getString()
    val maxPoolSize = environment.config.property(\\"database.maxPoolSize\\").getString().toInt()
    
    val hikariConfig = HikariConfig().apply {
        jdbcUrl = dbUrl
        username = dbUser
        password = dbPassword
        maximumPoolSize = maxPoolSize
        isAutoCommit = false
        transactionIsolation = "TRANSACTION_REPEATABLE_READ"
        validate()
    }
    
    val dataSource = HikariDataSource(hikariConfig)
    Database.connect(dataSource)
    
    // Create tables
    transaction {
        SchemaUtils.create(Users)
    }
}`
      },
      {
        path: 'src/main/kotlin/com/example/config/DependencyInjection.kt',
        content: `package com.example.config

import com.example.utils.JwtUtils
import io.ktor.server.application.*
import org.koin.core.context.startKoin
import org.koin.core.module.dsl.singleOf
import org.koin.dsl.module
import org.koin.ksp.generated.module
import com.example.controllers.*
import com.example.services.*
import com.example.repositories.*
import com.example.middleware.*

fun Application.configureDependencyInjection() {
    val appModule = module {
        // Configuration
        single {
            JwtUtils(
                secret = environment.config.property(\\"jwt.secret\\").getString(),
                expirationTime = environment.config.property(\\"jwt.expiration\\").getString().toLong()
            )
        }
        
        // Repositories
        singleOf(::UserRepository)
        
        // Services
        singleOf(::UserService)
        singleOf(::AuthService)
        
        // Middleware
        singleOf(::AuthMiddleware)
        
        // Controllers
        singleOf(::AuthController)
        singleOf(::UserController)
        singleOf(::HealthController)
    }
    
    startKoin {
        modules(appModule)
    }
}`
      },
      {
        path: 'src/main/kotlin/com/example/config/SecurityConfig.kt',
        content: `package com.example.config

import com.example.utils.JwtUtils
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.plugins.cors.routing.*
import org.koin.ktor.ext.inject

fun Application.configureSecurity() {
    val jwtUtils by inject<JwtUtils>()
    
    install(CORS) {
        allowMethod(HttpMethod.Options)
        allowMethod(HttpMethod.Get)
        allowMethod(HttpMethod.Post)
        allowMethod(HttpMethod.Put)
        allowMethod(HttpMethod.Delete)
        allowMethod(HttpMethod.Patch)
        allowHeader(HttpHeaders.Authorization)
        allowHeader(HttpHeaders.ContentType)
        allowCredentials = true
        anyHost() // Configure for production
    }
    
    authentication {
        jwt("auth-jwt") {
            verifier(jwtUtils.verifier)
            validate { credential ->
                if (credential.payload.subject != null) {
                    JWTPrincipal(credential.payload)
                } else {
                    null
                }
            }
            challenge { _, _ ->
                call.respond(HttpStatusCode.Unauthorized, \\\\"Token is not valid or has expired\\\\")
            }
        }
    }
}`
      },
      {
        path: 'src/main/kotlin/com/example/config/SerializationConfig.kt',
        content: `package com.example.config

import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.plugins.contentnegotiation.*
import kotlinx.serialization.json.Json

fun Application.configureSerialization() {
    install(ContentNegotiation) {
        json(Json {
            prettyPrint = true
            isLenient = true
            ignoreUnknownKeys = true
            encodeDefaults = true
        })
    }
}`
      },
      {
        path: 'src/main/kotlin/com/example/config/MonitoringConfig.kt',
        content: `package com.example.config

import io.ktor.server.application.*
import io.ktor.server.metrics.micrometer.*
import io.ktor.server.plugins.callloging.*
import io.ktor.server.plugins.callid.*
import io.ktor.server.request.*
import io.micrometer.prometheus.PrometheusConfig
import io.micrometer.prometheus.PrometheusMeterRegistry
import org.slf4j.event.Level
import java.util.UUID

fun Application.configureMonitoring() {
    val appMicrometerRegistry = PrometheusMeterRegistry(PrometheusConfig.DEFAULT)
    
    install(MicrometerMetrics) {
        registry = appMicrometerRegistry
    }
    
    install(CallLogging) {
        level = Level.INFO
        filter { call -> call.request.path().startsWith("/api") }
        callIdMdc("call-id")
    }
    
    install(CallId) {
        header(HttpHeaders.XRequestId)
        verify { callId: String ->
            callId.isNotEmpty()
        }
        generate {
            UUID.randomUUID().toString()
        }
    }
}`
      },
      {
        path: 'src/main/kotlin/com/example/plugins/HTTP.kt',
        content: `package com.example.plugins

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.compression.*
import io.ktor.server.plugins.autohead.*
import io.ktor.server.plugins.cachingheaders.*
import io.ktor.server.plugins.partialcontent.*
import io.ktor.server.plugins.statuspages.*
import com.example.middleware.handleError

fun Application.configureHTTP() {
    install(Compression) {
        gzip {
            priority = 1.0
        }
        deflate {
            priority = 10.0
            minimumSize(1024)
        }
    }
    
    install(AutoHeadResponse)
    
    install(CachingHeaders) {
        options { _, outgoingContent ->
            when (outgoingContent.contentType?.withoutParameters()) {
                ContentType.Text.CSS -> CachingOptions(CacheControl.MaxAge(maxAgeSeconds = 3600))
                ContentType.Text.JavaScript -> CachingOptions(CacheControl.MaxAge(maxAgeSeconds = 3600))
                else -> null
            }
        }
    }
    
    install(PartialContent) {
        maxRangeCount = 10
    }
    
    install(StatusPages) {
        exception<Throwable> { call, cause ->
            handleError(call, cause)
        }
    }
}`
      },
      {
        path: 'src/main/resources/application.conf',
        content: `ktor {
    deployment {
        port = 8080
        port = \${?SERVER_PORT}
        host = "0.0.0.0"
        host = \${?SERVER_HOST}
    }
    
    application {
        name = "\\${this.options.name}"
        modules = [ com.example.ApplicationKt.module ]
    }
}

database {
    url = "jdbc:postgresql://localhost:5432/app_db"
    url = \${?DATABASE_URL}
    user = "postgres"
    user = \${?DATABASE_USER}
    password = "postgres"
    password = \${?DATABASE_PASSWORD}
    maxPoolSize = "10"
    maxPoolSize = \${?DATABASE_MAX_POOL_SIZE}
}

jwt {
    secret = "your-secret-key-change-in-production"
    secret = \${?JWT_SECRET}
    expiration = "86400"
    expiration = \${?JWT_EXPIRATION}
}

redis {
    host = "localhost"
    host = \${?REDIS_HOST}
    port = "6379"
    port = \${?REDIS_PORT}
    password = ""
    password = \${?REDIS_PASSWORD}
}`
      }
    ];
  }

  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [];
  }

  protected generateTestFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/test/kotlin/com/example/ApplicationTest.kt',
        content: `package com.example

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlin.test.*

class ApplicationTest {
    @Test
    fun testHealth() = testApplication {
        application {
            module()
        }
        
        client.get("/health").apply {
            assertEquals(HttpStatusCode.OK, status)
            val response = bodyAsText()
            assertTrue(response.contains("status"))
            assertTrue(response.contains("OK"))
        }
    }
    
    @Test
    fun testRoot() = testApplication {
        application {
            module()
        }
        
        client.get("/").apply {
            assertEquals(HttpStatusCode.OK, status)
        }
    }
}`
      }
    ];
  }
  
  async generateTemplate(projectPath: string): Promise<void> {
    await super.generateTemplate(projectPath);
    
    // Generate controller files
    const controllerFiles = this.generateControllerFiles();
    for (const file of controllerFiles) {
      await fs.writeFile(path.join(projectPath, file.path), file.content);
    }
  }

  protected generateControllerFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/kotlin/com/example/controllers/AuthController.kt',
        content: `package com.example.controllers

import com.example.dto.*
import com.example.services.AuthService
import com.example.utils.ValidationUtils
import com.example.middleware.ValidationException
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.http.*
import io.konform.validation.Invalid
import org.koin.core.annotation.Single

@Single
class AuthController(private val authService: AuthService) {
    
    suspend fun register(call: ApplicationCall) {
        val request = call.receive<CreateUserRequest>()
        
        // Validate request
        val validationResult = ValidationUtils.userValidation(request)
        if (validationResult is Invalid) {
            throw ValidationException(validationResult.errors.first().message)
        }
        
        val response = authService.register(request)
        call.respond(HttpStatusCode.Created, response)
    }
    
    suspend fun login(call: ApplicationCall) {
        val request = call.receive<LoginRequest>()
        val response = authService.login(request)
        call.respond(HttpStatusCode.OK, response)
    }
    
    suspend fun refresh(call: ApplicationCall) {
        val request = call.receive<RefreshTokenRequest>()
        val response = authService.refreshToken(request)
        call.respond(HttpStatusCode.OK, response)
    }
    
    suspend fun logout(call: ApplicationCall) {
        val refreshToken = call.request.header("X-Refresh-Token")
        if (refreshToken != null) {
            authService.logout(refreshToken)
        }
        call.respond(HttpStatusCode.OK, MessageResponse(\\\\"Logged out successfully\\\\"))
    }
}`
      },
      {
        path: 'src/main/kotlin/com/example/controllers/UserController.kt',
        content: `package com.example.controllers

import com.example.dto.*
import com.example.models.User
import com.example.services.UserService
import com.example.middleware.ForbiddenException
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.http.*
import org.koin.core.annotation.Single

@Single
class UserController(private val userService: UserService) {
    
    suspend fun getAllUsers(call: ApplicationCall) {
        val page = call.request.queryParameters["page"]?.toIntOrNull() ?: 0
        val size = call.request.queryParameters["size"]?.toIntOrNull() ?: 20
        
        val users = userService.getAllUsers(page, size)
        val response = users.map { user ->
            UserResponse(
                id = user.id,
                email = user.email,
                name = user.name,
                role = user.role,
                isActive = user.isActive,
                createdAt = user.createdAt.toString(),
                updatedAt = user.updatedAt.toString()
            )
        }
        
        call.respond(HttpStatusCode.OK, response)
    }
    
    suspend fun getUserById(call: ApplicationCall) {
        val id = call.parameters["id"]?.toIntOrNull() 
            ?: throw ValidationException("Invalid user ID")
        
        val user = userService.findById(id)
            ?: throw NotFoundException("User not found")
        
        val response = UserResponse(
            id = user.id,
            email = user.email,
            name = user.name,
            role = user.role,
            isActive = user.isActive,
            createdAt = user.createdAt.toString(),
            updatedAt = user.updatedAt.toString()
        )
        
        call.respond(HttpStatusCode.OK, response)
    }
    
    suspend fun getCurrentUser(call: ApplicationCall, user: User) {
        val response = UserResponse(
            id = user.id,
            email = user.email,
            name = user.name,
            role = user.role,
            isActive = user.isActive,
            createdAt = user.createdAt.toString(),
            updatedAt = user.updatedAt.toString()
        )
        
        call.respond(HttpStatusCode.OK, response)
    }
    
    suspend fun updateUser(call: ApplicationCall) {
        val id = call.parameters["id"]?.toIntOrNull() 
            ?: throw ValidationException("Invalid user ID")
        
        val request = call.receive<UpdateUserRequest>()
        val updatedUser = userService.updateUser(id, request)
        
        val response = UserResponse(
            id = updatedUser.id,
            email = updatedUser.email,
            name = updatedUser.name,
            role = updatedUser.role,
            isActive = updatedUser.isActive,
            createdAt = updatedUser.createdAt.toString(),
            updatedAt = updatedUser.updatedAt.toString()
        )
        
        call.respond(HttpStatusCode.OK, response)
    }
    
    suspend fun deleteUser(call: ApplicationCall) {
        val id = call.parameters["id"]?.toIntOrNull() 
            ?: throw ValidationException("Invalid user ID")
        
        userService.deleteUser(id)
        call.respond(HttpStatusCode.NoContent)
    }
}`
      },
      {
        path: 'src/main/kotlin/com/example/controllers/HealthController.kt',
        content: `package com.example.controllers

import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.http.*
import kotlinx.serialization.Serializable
import org.koin.core.annotation.Single
import java.lang.management.ManagementFactory

@Serializable
data class HealthResponse(
    val status: String,
    val uptime: Long,
    val memory: MemoryInfo,
    val timestamp: Long = System.currentTimeMillis()
)

@Serializable
data class MemoryInfo(
    val total: Long,
    val free: Long,
    val used: Long,
    val percentage: Double
)

@Single
class HealthController {
    
    suspend fun health(call: ApplicationCall) {
        val runtime = Runtime.getRuntime()
        val totalMemory = runtime.totalMemory()
        val freeMemory = runtime.freeMemory()
        val usedMemory = totalMemory - freeMemory
        val memoryPercentage = (usedMemory.toDouble() / totalMemory.toDouble()) * 100
        
        val uptime = ManagementFactory.getRuntimeMXBean().uptime
        
        val response = HealthResponse(
            status = "OK",
            uptime = uptime,
            memory = MemoryInfo(
                total = totalMemory,
                free = freeMemory,
                used = usedMemory,
                percentage = memoryPercentage
            )
        )
        
        call.respond(HttpStatusCode.OK, response)
    }
}`
      }
    ];
  }
}