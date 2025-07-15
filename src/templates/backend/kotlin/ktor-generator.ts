import { KotlinBackendGenerator } from './kotlin-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class KtorGenerator extends KotlinBackendGenerator {
  constructor() {
    super('Ktor');
  }

  protected getFrameworkPlugins(): string {
    return `kotlin("plugin.serialization") version "1.9.20"
    id("io.ktor.plugin") version "2.3.6"`;
  }

  protected getFrameworkDependencies(): string {
    return `implementation("io.ktor:ktor-server-core:2.3.6")
    implementation("io.ktor:ktor-server-netty:2.3.6")
    implementation("io.ktor:ktor-server-host-common:2.3.6")
    implementation("io.ktor:ktor-server-status-pages:2.3.6")
    implementation("io.ktor:ktor-server-cors:2.3.6")
    implementation("io.ktor:ktor-server-call-logging:2.3.6")
    implementation("io.ktor:ktor-server-call-id:2.3.6")
    implementation("io.ktor:ktor-server-metrics-micrometer:2.3.6")
    implementation("io.ktor:ktor-server-content-negotiation:2.3.6")
    implementation("io.ktor:ktor-serialization-kotlinx-json:2.3.6")
    implementation("io.ktor:ktor-server-auth:2.3.6")
    implementation("io.ktor:ktor-server-auth-jwt:2.3.6")
    implementation("io.ktor:ktor-server-websockets:2.3.6")
    implementation("io.ktor:ktor-server-compression:2.3.6")
    implementation("io.ktor:ktor-server-swagger:2.3.6")
    implementation("io.ktor:ktor-server-openapi:2.3.6")
    implementation("io.ktor:ktor-server-rate-limit:2.3.6")
    implementation("io.ktor:ktor-client-core:2.3.6")
    implementation("io.ktor:ktor-client-cio:2.3.6")
    implementation("io.ktor:ktor-client-content-negotiation:2.3.6")
    implementation("io.ktor:ktor-client-serialization:2.3.6")
    implementation("org.jetbrains.exposed:exposed-core:0.44.1")
    implementation("org.jetbrains.exposed:exposed-dao:0.44.1")
    implementation("org.jetbrains.exposed:exposed-jdbc:0.44.1")
    implementation("org.jetbrains.exposed:exposed-java-time:0.44.1")
    implementation("com.github.ben-manes.caffeine:caffeine:3.1.8")
    implementation("io.insert-koin:koin-ktor:3.5.1")
    implementation("io.github.smiley4:ktor-swagger-ui:2.7.1")
    implementation("at.favre.lib:bcrypt:0.10.2")
    testImplementation("io.ktor:ktor-server-tests:2.3.6")
    testImplementation("io.ktor:ktor-client-mock:2.3.6")`;
  }

  protected getFrameworkTasks(): string {
    return `application {
    mainClass.set("com.example.MainKt")
}

ktor {
    fatJar {
        archiveFileName.set("app.jar")
    }
}`;
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    const srcDir = path.join(projectPath, 'src/main/kotlin');
    await fs.mkdir(srcDir, { recursive: true });

    await this.generateMainApplication(srcDir, options);
    await this.generateConfiguration(srcDir);
    await this.generateDatabase(srcDir);
    await this.generateModels(srcDir);
    await this.generateServices(srcDir);
    await this.generateRepositories(srcDir);
    await this.generateRoutes(srcDir);
    await this.generateMiddleware(srcDir);
    await this.generateAuth(srcDir);
    await this.generateWebSocket(srcDir);
    await this.generateUtils(srcDir);
    await this.generateApplicationConf(projectPath);
    await this.generateTests(projectPath);
  }

  private async generateMainApplication(srcDir: string, options: any): Promise<void> {
    const mainContent = `package com.example

import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import org.koin.ktor.plugin.Koin
import org.koin.logger.slf4jLogger
import com.example.config.*
import com.example.routes.*
import com.example.websocket.*

fun main() {
    embeddedServer(
        Netty,
        port = System.getenv("PORT")?.toInt() ?: 8080,
        host = "0.0.0.0",
        module = Application::module
    ).start(wait = true)
}

fun Application.module() {
    configureDI()
    configureDatabase()
    configureSerialization()
    configureHTTP()
    configureAuth()
    configureMonitoring()
    configureWebSockets()
    configureRouting()
}

fun Application.configureDI() {
    install(Koin) {
        slf4jLogger()
        modules(appModule)
    }
}`;

    await fs.writeFile(
      path.join(srcDir, 'Main.kt'),
      mainContent
    );
  }

  private async generateConfiguration(srcDir: string): Promise<void> {
    const configDir = path.join(srcDir, 'config');
    await fs.mkdir(configDir, { recursive: true });

    const appModuleContent = `package com.example.config

import org.koin.dsl.module
import com.example.services.*
import com.example.repositories.*
import com.example.auth.*
import com.example.database.*

val appModule = module {
    single { DatabaseConfig() }
    single { RedisConfig() }
    single { JwtConfig() }
    
    single { UserRepository() }
    single { UserService(get()) }
    single { AuthService(get(), get()) }
    single { TokenService(get()) }
}`;

    await fs.writeFile(
      path.join(configDir, 'AppModule.kt'),
      appModuleContent
    );

    const serializationContent = `package com.example.config

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
        })
    }
}`;

    await fs.writeFile(
      path.join(configDir, 'Serialization.kt'),
      serializationContent
    );

    const httpContent = `package com.example.config

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.plugins.compression.*
import io.ktor.server.plugins.callloging.*
import io.ktor.server.plugins.callid.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.plugins.ratelimit.*
import io.ktor.server.response.*
import io.ktor.server.request.*
import kotlin.time.Duration.Companion.seconds

fun Application.configureHTTP() {
    install(CORS) {
        allowMethod(HttpMethod.Options)
        allowMethod(HttpMethod.Put)
        allowMethod(HttpMethod.Delete)
        allowMethod(HttpMethod.Patch)
        allowHeader(HttpHeaders.Authorization)
        allowHeader(HttpHeaders.ContentType)
        anyHost()
    }
    
    install(Compression) {
        gzip {
            priority = 1.0
        }
        deflate {
            priority = 10.0
            minimumSize(1024)
        }
    }
    
    install(CallLogging) {
        level = org.slf4j.event.Level.INFO
        filter { call -> call.request.path().startsWith("/") }
        callIdMdc("call-id")
    }
    
    install(CallId) {
        header(HttpHeaders.XRequestId)
        verify { callId: String ->
            callId.isNotEmpty()
        }
    }
    
    install(StatusPages) {
        exception<Throwable> { call, cause ->
            call.respondText(text = "500: $cause", status = HttpStatusCode.InternalServerError)
        }
    }
    
    install(RateLimit) {
        register(RateLimitName("api")) {
            rateLimiter(limit = 100, refillPeriod = 60.seconds)
        }
    }
}`;

    await fs.writeFile(
      path.join(configDir, 'HTTP.kt'),
      httpContent
    );

    const monitoringContent = `package com.example.config

import io.ktor.server.application.*
import io.ktor.server.metrics.micrometer.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.micrometer.prometheus.*
import io.micrometer.core.instrument.binder.jvm.*
import io.micrometer.core.instrument.binder.system.*

fun Application.configureMonitoring() {
    val appMicrometerRegistry = PrometheusMeterRegistry(PrometheusConfig.DEFAULT)

    install(MicrometerMetrics) {
        registry = appMicrometerRegistry
        meterBinders = listOf(
            JvmMemoryMetrics(),
            JvmGcMetrics(),
            ProcessorMetrics(),
            JvmThreadMetrics(),
            FileDescriptorMetrics()
        )
    }

    routing {
        get("/metrics") {
            call.respond(appMicrometerRegistry.scrape())
        }
        
        get("/health") {
            call.respond(mapOf(
                "status" to "UP",
                "timestamp" to System.currentTimeMillis()
            ))
        }
    }
}`;

    await fs.writeFile(
      path.join(configDir, 'Monitoring.kt'),
      monitoringContent
    );

    const databaseConfigContent = `package com.example.config

import com.example.database.DatabaseConfig
import io.ktor.server.application.*

fun Application.configureDatabase() {
    val dbConfig = DatabaseConfig()
    // Database is initialized in DatabaseConfig constructor
}`;

    await fs.writeFile(
      path.join(configDir, 'Database.kt'),
      databaseConfigContent
    );
  }

  private async generateDatabase(srcDir: string): Promise<void> {
    const dbDir = path.join(srcDir, 'database');
    await fs.mkdir(dbDir, { recursive: true });

    const dbConfigContent = `package com.example.database

import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.transactions.transaction

class DatabaseConfig {
    private val hikariConfig = HikariConfig().apply {
        driverClassName = "org.postgresql.Driver"
        jdbcUrl = System.getenv("DB_URL") ?: "jdbc:postgresql://localhost:5432/app_db"
        username = System.getenv("DB_USER") ?: "postgres"
        password = System.getenv("DB_PASSWORD") ?: "postgres"
        maximumPoolSize = 10
        isAutoCommit = false
        transactionIsolation = "TRANSACTION_REPEATABLE_READ"
        validate()
    }

    private val dataSource = HikariDataSource(hikariConfig)
    val database = Database.connect(dataSource)

    init {
        transaction(database) {
            SchemaUtils.create(Users, Sessions, ApiKeys)
        }
    }
}`;

    await fs.writeFile(
      path.join(dbDir, 'DatabaseConfig.kt'),
      dbConfigContent
    );

    const tablesContent = `package com.example.database

import org.jetbrains.exposed.dao.id.UUIDTable
import org.jetbrains.exposed.sql.javatime.timestamp

object Users : UUIDTable("users") {
    val email = varchar("email", 255).uniqueIndex()
    val passwordHash = varchar("password_hash", 255)
    val name = varchar("name", 255)
    val isActive = bool("is_active").default(true)
    val createdAt = timestamp("created_at")
    val updatedAt = timestamp("updated_at")
}

object Sessions : UUIDTable("sessions") {
    val userId = reference("user_id", Users)
    val token = varchar("token", 512).uniqueIndex()
    val expiresAt = timestamp("expires_at")
    val createdAt = timestamp("created_at")
}

object ApiKeys : UUIDTable("api_keys") {
    val userId = reference("user_id", Users)
    val key = varchar("key", 255).uniqueIndex()
    val name = varchar("name", 255)
    val permissions = text("permissions")
    val lastUsedAt = timestamp("last_used_at").nullable()
    val createdAt = timestamp("created_at")
}`;

    await fs.writeFile(
      path.join(dbDir, 'Tables.kt'),
      tablesContent
    );

    const redisConfigContent = `package com.example.database

import redis.clients.jedis.JedisPool
import redis.clients.jedis.JedisPoolConfig

class RedisConfig {
    private val poolConfig = JedisPoolConfig().apply {
        maxTotal = 50
        maxIdle = 10
        minIdle = 5
        testOnBorrow = true
    }

    val pool = JedisPool(
        poolConfig,
        System.getenv("REDIS_HOST") ?: "localhost",
        System.getenv("REDIS_PORT")?.toInt() ?: 6379,
        2000,
        System.getenv("REDIS_PASSWORD")
    )

    fun <T> use(block: (redis: redis.clients.jedis.Jedis) -> T): T {
        return pool.resource.use(block)
    }
}`;

    await fs.writeFile(
      path.join(dbDir, 'RedisConfig.kt'),
      redisConfigContent
    );
  }

  private async generateModels(srcDir: string): Promise<void> {
    const modelsDir = path.join(srcDir, 'models');
    await fs.mkdir(modelsDir, { recursive: true });

    const userModelContent = `package com.example.models

import kotlinx.serialization.Serializable
import java.util.UUID

@Serializable
data class User(
    val id: String,
    val email: String,
    val name: String,
    val isActive: Boolean,
    val createdAt: Long,
    val updatedAt: Long
) {
    val passwordHash: String = ""
}

@Serializable
data class CreateUserRequest(
    val email: String,
    val password: String,
    val name: String
)

@Serializable
data class UpdateUserRequest(
    val name: String? = null,
    val email: String? = null
)

@Serializable
data class LoginRequest(
    val email: String,
    val password: String
)

@Serializable
data class TokenResponse(
    val accessToken: String,
    val refreshToken: String,
    val expiresIn: Long
)

@Serializable
data class RefreshTokenRequest(
    val refreshToken: String
)

@Serializable
data class ApiResponse<T>(
    val success: Boolean,
    val data: T? = null,
    val error: String? = null,
    val timestamp: Long = System.currentTimeMillis()
)`;

    await fs.writeFile(
      path.join(modelsDir, 'User.kt'),
      userModelContent
    );
  }

  private async generateServices(srcDir: string): Promise<void> {
    const servicesDir = path.join(srcDir, 'services');
    await fs.mkdir(servicesDir, { recursive: true });

    const userServiceContent = `package com.example.services

import com.example.models.*
import com.example.repositories.UserRepository
import java.util.UUID

class UserService(private val userRepository: UserRepository) {
    suspend fun findById(id: String): User? {
        return userRepository.findById(UUID.fromString(id))
    }

    suspend fun findByEmail(email: String): User? {
        return userRepository.findByEmail(email)
    }

    suspend fun create(request: CreateUserRequest): User {
        return userRepository.create(request)
    }

    suspend fun update(id: String, request: UpdateUserRequest): User? {
        return userRepository.update(UUID.fromString(id), request)
    }

    suspend fun delete(id: String): Boolean {
        return userRepository.delete(UUID.fromString(id))
    }

    suspend fun list(page: Int, size: Int): List<User> {
        return userRepository.list(page, size)
    }
}`;

    await fs.writeFile(
      path.join(servicesDir, 'UserService.kt'),
      userServiceContent
    );
  }

  private async generateRepositories(srcDir: string): Promise<void> {
    const repoDir = path.join(srcDir, 'repositories');
    await fs.mkdir(repoDir, { recursive: true });

    const userRepoContent = `package com.example.repositories

import com.example.database.Users
import com.example.models.*
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.transactions.transaction
import java.time.Instant
import java.util.UUID

class UserRepository {
    fun findById(id: UUID): User? = transaction {
        Users.select { Users.id eq id }
            .map { toUser(it) }
            .singleOrNull()
    }

    fun findByEmail(email: String): User? = transaction {
        Users.select { Users.email eq email }
            .map { toUser(it) }
            .singleOrNull()
    }

    fun create(request: CreateUserRequest): User = transaction {
        val id = UUID.randomUUID()
        val now = Instant.now()
        
        Users.insert {
            it[Users.id] = id
            it[email] = request.email
            it[passwordHash] = request.password // Already hashed by service
            it[name] = request.name
            it[isActive] = true
            it[createdAt] = now
            it[updatedAt] = now
        }
        
        findById(id)!!
    }

    fun update(id: UUID, request: UpdateUserRequest): User? = transaction {
        val updated = Users.update({ Users.id eq id }) {
            request.name?.let { name -> it[Users.name] = name }
            request.email?.let { email -> it[Users.email] = email }
            it[updatedAt] = Instant.now()
        }
        
        if (updated > 0) findById(id) else null
    }

    fun delete(id: UUID): Boolean = transaction {
        Users.deleteWhere { Users.id eq id } > 0
    }

    fun list(page: Int, size: Int): List<User> = transaction {
        Users.selectAll()
            .limit(size, offset = ((page - 1) * size).toLong())
            .map { toUser(it) }
    }

    private fun toUser(row: ResultRow): User = User(
        id = row[Users.id].toString(),
        email = row[Users.email],
        name = row[Users.name],
        isActive = row[Users.isActive],
        createdAt = row[Users.createdAt].toEpochMilli(),
        updatedAt = row[Users.updatedAt].toEpochMilli()
    )
}`;

    await fs.writeFile(
      path.join(repoDir, 'UserRepository.kt'),
      userRepoContent
    );
  }

  private async generateRoutes(srcDir: string): Promise<void> {
    const routesDir = path.join(srcDir, 'routes');
    await fs.mkdir(routesDir, { recursive: true });

    const routingContent = `package com.example.routes

import io.ktor.server.application.*
import io.ktor.server.routing.*
import io.github.smiley4.ktorswaggerui.SwaggerUI

fun Application.configureRouting() {
    install(SwaggerUI) {
        swagger {
            swaggerUrl = "swagger-ui"
            forwardRoot = true
        }
        info {
            title = "Ktor API"
            version = "1.0.0"
            description = "Ktor backend API documentation"
        }
        server {
            url = "http://localhost:8080"
            description = "Development Server"
        }
    }

    routing {
        route("/api/v1") {
            authRoutes()
            userRoutes()
        }
    }
}`;

    await fs.writeFile(
      path.join(routesDir, 'Routing.kt'),
      routingContent
    );

    const userRoutesContent = `package com.example.routes

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.koin.ktor.ext.inject
import com.example.models.*
import com.example.services.UserService

fun Route.userRoutes() {
    val userService by inject<UserService>()

    authenticate("auth-jwt") {
        route("/users") {
            get {
                val page = call.request.queryParameters["page"]?.toIntOrNull() ?: 1
                val size = call.request.queryParameters["size"]?.toIntOrNull() ?: 10
                val users = userService.list(page, size)
                call.respond(ApiResponse(true, users))
            }

            get("/{id}") {
                val id = call.parameters["id"] ?: return@get call.respond(
                    HttpStatusCode.BadRequest,
                    ApiResponse<User>(false, error = "ID required")
                )
                
                val user = userService.findById(id)
                if (user != null) {
                    call.respond(ApiResponse(true, user))
                } else {
                    call.respond(
                        HttpStatusCode.NotFound,
                        ApiResponse<User>(false, error = "User not found")
                    )
                }
            }

            put("/{id}") {
                val id = call.parameters["id"] ?: return@put call.respond(
                    HttpStatusCode.BadRequest,
                    ApiResponse<User>(false, error = "ID required")
                )
                
                val request = call.receive<UpdateUserRequest>()
                val user = userService.update(id, request)
                
                if (user != null) {
                    call.respond(ApiResponse(true, user))
                } else {
                    call.respond(
                        HttpStatusCode.NotFound,
                        ApiResponse<User>(false, error = "User not found")
                    )
                }
            }

            delete("/{id}") {
                val id = call.parameters["id"] ?: return@delete call.respond(
                    HttpStatusCode.BadRequest,
                    ApiResponse<Boolean>(false, error = "ID required")
                )
                
                val deleted = userService.delete(id)
                if (deleted) {
                    call.respond(HttpStatusCode.NoContent)
                } else {
                    call.respond(
                        HttpStatusCode.NotFound,
                        ApiResponse<Boolean>(false, error = "User not found")
                    )
                }
            }
        }
    }
}`;

    await fs.writeFile(
      path.join(routesDir, 'UserRoutes.kt'),
      userRoutesContent
    );

    const authRoutesContent = `package com.example.routes

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import org.koin.ktor.ext.inject
import com.example.models.*
import com.example.auth.AuthService

fun Route.authRoutes() {
    val authService by inject<AuthService>()

    route("/auth") {
        post("/register") {
            val request = call.receive<CreateUserRequest>()
            try {
                val user = authService.register(request)
                call.respond(HttpStatusCode.Created, ApiResponse(true, user))
            } catch (e: Exception) {
                call.respond(
                    HttpStatusCode.BadRequest,
                    ApiResponse<User>(false, error = e.message)
                )
            }
        }

        post("/login") {
            val request = call.receive<LoginRequest>()
            val token = authService.login(request.email, request.password)
            
            if (token != null) {
                call.respond(ApiResponse(true, token))
            } else {
                call.respond(
                    HttpStatusCode.Unauthorized,
                    ApiResponse<TokenResponse>(false, error = "Invalid credentials")
                )
            }
        }

        post("/refresh") {
            val request = call.receive<RefreshTokenRequest>()
            val token = authService.refreshToken(request.refreshToken)
            
            if (token != null) {
                call.respond(ApiResponse(true, token))
            } else {
                call.respond(
                    HttpStatusCode.Unauthorized,
                    ApiResponse<TokenResponse>(false, error = "Invalid refresh token")
                )
            }
        }
    }
}`;

    await fs.writeFile(
      path.join(routesDir, 'AuthRoutes.kt'),
      authRoutesContent
    );
  }

  private async generateMiddleware(srcDir: string): Promise<void> {
    const middlewareDir = path.join(srcDir, 'middleware');
    await fs.mkdir(middlewareDir, { recursive: true });

    const errorHandlerContent = `package com.example.middleware

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.response.*
import com.example.models.ApiResponse

fun Application.configureErrorHandling() {
    install(StatusPages) {
        exception<ValidationException> { call, cause ->
            call.respond(
                HttpStatusCode.BadRequest,
                ApiResponse<Nothing>(false, error = cause.message)
            )
        }
        
        exception<AuthenticationException> { call, cause ->
            call.respond(
                HttpStatusCode.Unauthorized,
                ApiResponse<Nothing>(false, error = cause.message)
            )
        }
        
        exception<AuthorizationException> { call, cause ->
            call.respond(
                HttpStatusCode.Forbidden,
                ApiResponse<Nothing>(false, error = cause.message)
            )
        }
        
        exception<NotFoundException> { call, cause ->
            call.respond(
                HttpStatusCode.NotFound,
                ApiResponse<Nothing>(false, error = cause.message)
            )
        }
        
        exception<Throwable> { call, cause ->
            call.application.log.error("Unhandled exception", cause)
            call.respond(
                HttpStatusCode.InternalServerError,
                ApiResponse<Nothing>(false, error = "Internal server error")
            )
        }
    }
}

class ValidationException(message: String) : Exception(message)
class AuthenticationException(message: String) : Exception(message)
class AuthorizationException(message: String) : Exception(message)
class NotFoundException(message: String) : Exception(message)`;

    await fs.writeFile(
      path.join(middlewareDir, 'ErrorHandler.kt'),
      errorHandlerContent
    );
  }

  private async generateAuth(srcDir: string): Promise<void> {
    const authDir = path.join(srcDir, 'auth');
    await fs.mkdir(authDir, { recursive: true });

    const authConfigContent = `package com.example.auth

import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.example.config.configureAuth as parentConfigureAuth
import java.util.*

fun Application.configureAuth() {
    val jwtConfig = JwtConfig()
    
    authentication {
        jwt("auth-jwt") {
            realm = jwtConfig.realm
            verifier(
                JWT
                    .require(Algorithm.HMAC256(jwtConfig.secret))
                    .withAudience(jwtConfig.audience)
                    .withIssuer(jwtConfig.issuer)
                    .build()
            )
            validate { credential ->
                if (credential.payload.getClaim("email").asString() != "") {
                    JWTPrincipal(credential.payload)
                } else null
            }
        }
    }
}

class JwtConfig {
    val secret = System.getenv("JWT_SECRET") ?: "secret"
    val issuer = System.getenv("JWT_ISSUER") ?: "http://0.0.0.0:8080/"
    val audience = System.getenv("JWT_AUDIENCE") ?: "http://0.0.0.0:8080/api"
    val realm = System.getenv("JWT_REALM") ?: "Access to API"
    val expiration = System.getenv("JWT_EXPIRATION")?.toLong() ?: 3600000L
}`;

    await fs.writeFile(
      path.join(authDir, 'AuthConfig.kt'),
      authConfigContent
    );

    const authServiceContent = `package com.example.auth

import com.example.models.*
import com.example.services.UserService
import com.example.database.RedisConfig
import at.favre.lib.crypto.bcrypt.BCrypt

class AuthService(
    private val userService: UserService,
    private val tokenService: TokenService
) {
    suspend fun register(request: CreateUserRequest): User {
        val existingUser = userService.findByEmail(request.email)
        if (existingUser != null) {
            throw IllegalArgumentException("Email already registered")
        }
        
        val hashedPassword = BCrypt.withDefaults().hashToString(12, request.password.toCharArray())
        return userService.create(request.copy(password = hashedPassword))
    }

    suspend fun login(email: String, password: String): TokenResponse? {
        val user = userService.findByEmail(email) ?: return null
        
        // Note: In real implementation, get passwordHash from database
        // This is simplified for the template
        if (!verifyPassword(password, user.passwordHash)) {
            return null
        }
        
        return tokenService.generateTokens(user)
    }

    suspend fun refreshToken(refreshToken: String): TokenResponse? {
        return tokenService.refreshAccessToken(refreshToken)
    }

    private fun verifyPassword(password: String, hash: String): Boolean {
        return BCrypt.verifyer().verify(password.toCharArray(), hash).verified
    }
}`;

    await fs.writeFile(
      path.join(authDir, 'AuthService.kt'),
      authServiceContent
    );

    const tokenServiceContent = `package com.example.auth

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import java.util.*
import com.example.models.*
import com.example.database.RedisConfig

class TokenService(private val jwtConfig: JwtConfig) {
    private val algorithm = Algorithm.HMAC256(jwtConfig.secret)
    
    fun generateTokens(user: User): TokenResponse {
        val accessToken = generateAccessToken(user)
        val refreshToken = generateRefreshToken(user)
        
        return TokenResponse(
            accessToken = accessToken,
            refreshToken = refreshToken,
            expiresIn = jwtConfig.expiration
        )
    }
    
    private fun generateAccessToken(user: User): String {
        return JWT.create()
            .withAudience(jwtConfig.audience)
            .withIssuer(jwtConfig.issuer)
            .withClaim("id", user.id)
            .withClaim("email", user.email)
            .withExpiresAt(Date(System.currentTimeMillis() + jwtConfig.expiration))
            .sign(algorithm)
    }
    
    private fun generateRefreshToken(user: User): String {
        val token = UUID.randomUUID().toString()
        // Store in Redis with 7 day expiration
        return token
    }
    
    suspend fun refreshAccessToken(refreshToken: String): TokenResponse? {
        // Validate refresh token from Redis
        // Generate new access token
        return null
    }
}`;

    await fs.writeFile(
      path.join(authDir, 'TokenService.kt'),
      tokenServiceContent
    );
  }

  private async generateWebSocket(srcDir: string): Promise<void> {
    const wsDir = path.join(srcDir, 'websocket');
    await fs.mkdir(wsDir, { recursive: true });

    const wsConfigContent = `package com.example.websocket

import io.ktor.server.application.*
import io.ktor.server.routing.*
import io.ktor.server.websocket.*
import io.ktor.websocket.*
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import java.time.Duration
import java.util.concurrent.ConcurrentHashMap

fun Application.configureWebSockets() {
    install(WebSockets) {
        pingPeriod = Duration.ofSeconds(15)
        timeout = Duration.ofSeconds(15)
        maxFrameSize = Long.MAX_VALUE
        masking = false
    }
    
    routing {
        val connections = ConcurrentHashMap<String, WebSocketSession>()
        
        webSocket("/ws") {
            val sessionId = call.request.headers["X-Session-Id"] ?: "anonymous"
            connections[sessionId] = this
            
            try {
                send("Connected to WebSocket")
                
                for (frame in incoming) {
                    when (frame) {
                        is Frame.Text -> {
                            val text = frame.readText()
                            // Broadcast to all connections
                            connections.values.forEach { connection ->
                                connection.send(text)
                            }
                        }
                        else -> {}
                    }
                }
            } catch (e: ClosedReceiveChannelException) {
                println("WebSocket closed: $sessionId")
            } catch (e: Throwable) {
                println("WebSocket error: \${e.localizedMessage}")
            } finally {
                connections.remove(sessionId)
            }
        }
    }
}`;

    await fs.writeFile(
      path.join(wsDir, 'WebSocketConfig.kt'),
      wsConfigContent
    );
  }

  private async generateUtils(srcDir: string): Promise<void> {
    const utilsDir = path.join(srcDir, 'utils');
    await fs.mkdir(utilsDir, { recursive: true });

    const validationContent = `package com.example.utils

fun String.isValidEmail(): Boolean {
    val emailRegex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\$".toRegex()
    return this.matches(emailRegex)
}

fun String.isStrongPassword(): Boolean {
    return this.length >= 8 &&
           this.any { it.isUpperCase() } &&
           this.any { it.isLowerCase() } &&
           this.any { it.isDigit() }
}

fun String.sanitize(): String {
    return this.trim()
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#x27;")
}`;

    await fs.writeFile(
      path.join(utilsDir, 'Validation.kt'),
      validationContent
    );
  }

  private async generateApplicationConf(projectPath: string): Promise<void> {
    const resourcesDir = path.join(projectPath, 'src/main/resources');
    await fs.mkdir(resourcesDir, { recursive: true });

    const applicationConf = `ktor {
    deployment {
        port = 8080
        port = \${?PORT}
    }
    application {
        modules = [ com.example.MainKt.module ]
    }
}

jwt {
    secret = \${JWT_SECRET}
    issuer = "http://0.0.0.0:8080/"
    audience = "http://0.0.0.0:8080/api"
    realm = "Access to API"
}`;

    await fs.writeFile(
      path.join(resourcesDir, 'application.conf'),
      applicationConf
    );

    const logbackContent = `<configuration>
    <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
        <encoder class="net.logstash.logback.encoder.LogstashEncoder"/>
    </appender>
    
    <root level="INFO">
        <appender-ref ref="STDOUT"/>
    </root>
    
    <logger name="io.ktor" level="INFO"/>
    <logger name="Exposed" level="INFO"/>
</configuration>`;

    await fs.writeFile(
      path.join(resourcesDir, 'logback.xml'),
      logbackContent
    );
  }

  private async generateTests(projectPath: string): Promise<void> {
    const testDir = path.join(projectPath, 'src/test/kotlin');
    await fs.mkdir(testDir, { recursive: true });

    const appTestContent = `package com.example

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlin.test.*

class ApplicationTest {
    @Test
    fun testRoot() = testApplication {
        application {
            module()
        }
        
        val response = client.get("/health")
        assertEquals(HttpStatusCode.OK, response.status)
        assertTrue(response.bodyAsText().contains("UP"))
    }
    
    @Test
    fun testMetrics() = testApplication {
        application {
            module()
        }
        
        val response = client.get("/metrics")
        assertEquals(HttpStatusCode.OK, response.status)
    }
}`;

    await fs.writeFile(
      path.join(testDir, 'ApplicationTest.kt'),
      appTestContent
    );
  }
}

export default KtorGenerator;