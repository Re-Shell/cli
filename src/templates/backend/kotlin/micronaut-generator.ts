import { KotlinBackendGenerator } from './kotlin-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class MicronautGenerator extends KotlinBackendGenerator {
  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'io.micronaut:micronaut-http-server-netty': '',
      'io.micronaut:micronaut-http-client': '',
      'io.micronaut.data:micronaut-data-jdbc': '',
      'io.micronaut.data:micronaut-data-processor': '',
      'io.micronaut.security:micronaut-security-jwt': '',
      'io.micronaut.redis:micronaut-redis-lettuce': '',
      'io.micronaut.cache:micronaut-cache-caffeine': '',
      'io.micronaut.openapi:micronaut-openapi': '',
      'io.micronaut.micrometer:micronaut-micrometer-core': '',
      'io.micronaut.micrometer:micronaut-micrometer-registry-prometheus': '',
      'io.micronaut.validation:micronaut-validation': '',
      'jakarta.annotation:jakarta.annotation-api': '',
      'io.micronaut.serde:micronaut-serde-jackson': ''
    };
  }

  protected generateBuildGradle(): string {
    return `plugins {
    id("org.jetbrains.kotlin.jvm") version "1.9.21"
    id("org.jetbrains.kotlin.plugin.allopen") version "1.9.21"
    id("org.jetbrains.kotlin.kapt") version "1.9.21"
    id("com.github.johnrengelman.shadow") version "8.1.1"
    id("io.micronaut.application") version "4.2.1"
    id("io.micronaut.aot") version "4.2.1"
}

version = "0.1"
group = "com.example"

repositories {
    mavenCentral()
}

dependencies {
    kapt("io.micronaut.data:micronaut-data-processor")
    kapt("io.micronaut:micronaut-http-validation")
    kapt("io.micronaut.serde:micronaut-serde-processor")
    kapt("io.micronaut.validation:micronaut-validation-processor")
    kapt("io.micronaut.openapi:micronaut-openapi")
    
    implementation("io.micronaut.kotlin:micronaut-kotlin-runtime")
    implementation("io.micronaut:micronaut-http-server-netty")
    implementation("io.micronaut.serde:micronaut-serde-jackson")
    implementation("io.micronaut.data:micronaut-data-jdbc")
    implementation("io.micronaut.sql:micronaut-jdbc-hikari")
    implementation("io.micronaut.liquibase:micronaut-liquibase")
    implementation("io.micronaut.security:micronaut-security-jwt")
    implementation("io.micronaut.reactor:micronaut-reactor")
    implementation("io.micronaut.reactor:micronaut-reactor-http-client")
    implementation("io.micronaut.redis:micronaut-redis-lettuce")
    implementation("io.micronaut.cache:micronaut-cache-caffeine")
    implementation("io.micronaut.micrometer:micronaut-micrometer-core")
    implementation("io.micronaut.micrometer:micronaut-micrometer-registry-prometheus")
    implementation("io.micronaut.validation:micronaut-validation")
    implementation("io.micronaut.views:micronaut-views-velocity")
    implementation("jakarta.annotation:jakarta.annotation-api")
    implementation("org.jetbrains.kotlin:kotlin-reflect:\\\${kotlinVersion}")
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8:\\\${kotlinVersion}")
    
    // Database
    runtimeOnly("org.postgresql:postgresql")
    
    // Logging
    runtimeOnly("ch.qos.logback:logback-classic")
    implementation("io.github.microutils:kotlin-logging-jvm:3.0.5")
    
    // Testing
    testImplementation("io.micronaut:micronaut-http-client")
    testImplementation("io.micronaut.test:micronaut-test-junit5")
    testImplementation("org.junit.jupiter:junit-jupiter-api")
    testImplementation("io.mockk:mockk:1.13.8")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.0")
}

application {
    mainClass.set("com.example.ApplicationKt")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

graalvmNative {
    toolchainDetection = false
}

micronaut {
    runtime("netty")
    testRuntime("junit5")
    processing {
        incremental(true)
        annotations("com.example.*")
    }
    aot {
        optimizeServiceLoading = false
        convertYamlToJava = false
        precomputeOperations = true
        cacheEnvironment = true
        optimizeClassLoading = true
        deduceEnvironment = true
        optimizeNetty = true
        replaceLogbackXml = true
    }
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    kotlinOptions {
        jvmTarget = "17"
        javaParameters = true
    }
}`;
  }

  protected generateMainFile(): string {
    return `package com.example

import io.micronaut.runtime.Micronaut
import io.swagger.v3.oas.annotations.OpenAPIDefinition
import io.swagger.v3.oas.annotations.info.Info
import io.swagger.v3.oas.annotations.info.License

@OpenAPIDefinition(
    info = Info(
        title = "\${this.options.name}",
        version = "1.0",
        description = "Micronaut REST API",
        license = License(name = "MIT", url = "https://opensource.org/licenses/MIT")
    )
)
object Application {
    @JvmStatic
    fun main(args: Array<String>) {
        Micronaut.run(*args)
    }
}`;
  }

  protected generateRoutingFile(): string {
    return `package com.example.controller

import com.example.dto.*
import com.example.service.AuthService
import com.example.service.UserService
import io.micronaut.data.model.Page
import io.micronaut.data.model.Pageable
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.*
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.micronaut.validation.Validated
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import java.security.Principal

@Controller("/api/auth")
@Validated
@Tag(name = "Authentication")
class AuthController(
    private val authService: AuthService
) {
    @Post("/register")
    @Status(HttpStatus.CREATED)
    @Operation(summary = "Register a new user")
    @Secured(SecurityRule.IS_ANONYMOUS)
    fun register(@Body @Valid request: CreateUserRequest): HttpResponse<AuthResponse> {
        return HttpResponse.created(authService.register(request))
    }
    
    @Post("/login")
    @Operation(summary = "Login user")
    @Secured(SecurityRule.IS_ANONYMOUS)
    fun login(@Body @Valid request: LoginRequest): HttpResponse<AuthResponse> {
        return HttpResponse.ok(authService.login(request))
    }
    
    @Post("/refresh")
    @Operation(summary = "Refresh access token")
    @Secured(SecurityRule.IS_ANONYMOUS)
    fun refresh(@Body @Valid request: RefreshTokenRequest): HttpResponse<AuthResponse> {
        return HttpResponse.ok(authService.refreshToken(request))
    }
    
    @Post("/logout")
    @Operation(
        summary = "Logout user",
        security = [SecurityRequirement(name = "BearerAuth")]
    )
    @Secured(SecurityRule.IS_AUTHENTICATED)
    fun logout(@Header("X-Refresh-Token") refreshToken: String?): HttpResponse<MessageResponse> {
        refreshToken?.let { authService.logout(it) }
        return HttpResponse.ok(MessageResponse("Logged out successfully"))
    }
}

@Controller("/api/users")
@Validated
@Tag(name = "Users")
@Secured(SecurityRule.IS_AUTHENTICATED)
class UserController(
    private val userService: UserService
) {
    @Get("{?pageable*}")
    @Operation(
        summary = "Get all users",
        security = [SecurityRequirement(name = "BearerAuth")]
    )
    @Secured("ADMIN")
    fun getAllUsers(pageable: Pageable): HttpResponse<Page<UserResponse>> {
        return HttpResponse.ok(userService.getAllUsers(pageable))
    }
    
    @Get("/{id}")
    @Operation(
        summary = "Get user by ID",
        security = [SecurityRequirement(name = "BearerAuth")]
    )
    fun getUserById(@PathVariable id: Long): HttpResponse<UserResponse> {
        return HttpResponse.ok(userService.getUserById(id))
    }
    
    @Get("/me")
    @Operation(
        summary = "Get current user",
        security = [SecurityRequirement(name = "BearerAuth")]
    )
    fun getCurrentUser(principal: Principal): HttpResponse<UserResponse> {
        return HttpResponse.ok(userService.getCurrentUser(principal.name))
    }
    
    @Put("/{id}")
    @Operation(
        summary = "Update user",
        security = [SecurityRequirement(name = "BearerAuth")]
    )
    fun updateUser(
        @PathVariable id: Long,
        @Body @Valid request: UpdateUserRequest,
        principal: Principal
    ): HttpResponse<UserResponse> {
        // Check if user is updating themselves or is admin
        val currentUser = userService.getCurrentUser(principal.name)
        if (currentUser.id != id && currentUser.role != "ADMIN") {
            return HttpResponse.status(HttpStatus.FORBIDDEN)
        }
        return HttpResponse.ok(userService.updateUser(id, request))
    }
    
    @Delete("/{id}")
    @Status(HttpStatus.NO_CONTENT)
    @Operation(
        summary = "Delete user",
        security = [SecurityRequirement(name = "BearerAuth")]
    )
    @Secured("ADMIN")
    fun deleteUser(@PathVariable id: Long): HttpResponse<Void> {
        userService.deleteUser(id)
        return HttpResponse.noContent()
    }
}

@Controller("/health")
@Tag(name = "Health")
class HealthController {
    @Get
    @Operation(summary = "Health check")
    @Secured(SecurityRule.IS_ANONYMOUS)
    fun health(): HttpResponse<Map<String, Any>> {
        return HttpResponse.ok(mapOf(
            "status" to "UP",
            "timestamp" to System.currentTimeMillis(),
            "service" to "\${this.options.name}",
            "version" to "1.0.0"
        ))
    }
}`;
  }

  protected generateServiceFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/kotlin/com/example/service/UserService.kt',
        content: `package com.example.service

import com.example.dto.*
import com.example.entity.User
import com.example.exception.ResourceNotFoundException
import com.example.exception.ValidationException
import com.example.repository.UserRepository
import io.micronaut.data.model.Page
import io.micronaut.data.model.Pageable
import jakarta.inject.Singleton
import jakarta.transaction.Transactional
import org.mindrot.jbcrypt.BCrypt

@Singleton
@Transactional
open class UserService(
    private val userRepository: UserRepository
) {
    open fun createUser(request: CreateUserRequest): User {
        if (userRepository.existsByEmail(request.email)) {
            throw ValidationException("Email already exists")
        }
        
        val hashedPassword = BCrypt.hashpw(request.password, BCrypt.gensalt())
        
        val user = User(
            email = request.email,
            password = hashedPassword,
            name = request.name
        )
        
        return userRepository.save(user)
    }
    
    open fun getUserById(id: Long): UserResponse {
        val user = userRepository.findById(id)
            .orElseThrow { ResourceNotFoundException("User not found") }
        return user.toResponse()
    }
    
    open fun getUserByEmail(email: String): User {
        return userRepository.findByEmail(email)
            .orElseThrow { ResourceNotFoundException("User not found") }
    }
    
    open fun getCurrentUser(email: String): UserResponse {
        val user = getUserByEmail(email)
        return user.toResponse()
    }
    
    open fun getAllUsers(pageable: Pageable): Page<UserResponse> {
        return userRepository.findAll(pageable).map { it.toResponse() }
    }
    
    open fun updateUser(id: Long, request: UpdateUserRequest): UserResponse {
        val user = userRepository.findById(id)
            .orElseThrow { ResourceNotFoundException("User not found") }
        
        request.name?.let { user.name = it }
        request.email?.let { email ->
            if (email != user.email && userRepository.existsByEmail(email)) {
                throw ValidationException("Email already exists")
            }
            user.email = email
        }
        request.password?.let { 
            user.password = BCrypt.hashpw(it, BCrypt.gensalt())
        }
        
        return userRepository.update(user).toResponse()
    }
    
    open fun deleteUser(id: Long) {
        if (!userRepository.existsById(id)) {
            throw ResourceNotFoundException("User not found")
        }
        userRepository.deleteById(id)
    }
    
    open fun validateCredentials(email: String, password: String): User? {
        val user = userRepository.findByEmail(email).orElse(null) ?: return null
        
        return if (BCrypt.checkpw(password, user.password) && user.isActive) {
            user
        } else {
            null
        }
    }
    
    private fun User.toResponse() = UserResponse(
        id = id!!,
        email = email,
        name = name,
        role = role.name,
        isActive = isActive,
        createdAt = createdAt.toString(),
        updatedAt = updatedAt.toString()
    )
}`
      },
      {
        path: 'src/main/kotlin/com/example/service/AuthService.kt',
        content: `package com.example.service

import com.example.dto.*
import com.example.exception.UnauthorizedException
import com.example.security.JwtTokenGenerator
import io.lettuce.core.api.StatefulRedisConnection
import io.lettuce.core.api.sync.RedisCommands
import jakarta.inject.Singleton
import java.util.UUID

@Singleton
open class AuthService(
    private val userService: UserService,
    private val jwtTokenGenerator: JwtTokenGenerator,
    private val redisConnection: StatefulRedisConnection<String, String>
) {
    private val syncCommands: RedisCommands<String, String> = redisConnection.sync()
    
    open fun register(request: CreateUserRequest): AuthResponse {
        val user = userService.createUser(request)
        return generateAuthResponse(user.email)
    }
    
    open fun login(request: LoginRequest): AuthResponse {
        val user = userService.validateCredentials(request.email, request.password)
            ?: throw UnauthorizedException("Invalid email or password")
        
        return generateAuthResponse(user.email)
    }
    
    open fun refreshToken(request: RefreshTokenRequest): AuthResponse {
        val email = syncCommands.get("refresh:\\\${request.refreshToken}")
            ?: throw UnauthorizedException("Invalid refresh token")
        
        // Delete old refresh token
        syncCommands.del("refresh:\\\${request.refreshToken}")
        
        return generateAuthResponse(email)
    }
    
    open fun logout(refreshToken: String) {
        syncCommands.del("refresh:\\$refreshToken")
    }
    
    private fun generateAuthResponse(email: String): AuthResponse {
        val user = userService.getUserByEmail(email)
        val accessToken = jwtTokenGenerator.generateToken(user)
        val refreshToken = UUID.randomUUID().toString()
        
        // Store refresh token in Redis with expiration (7 days)
        syncCommands.setex("refresh:\\$refreshToken", 604800, email)
        
        return AuthResponse(
            token = accessToken,
            refreshToken = refreshToken,
            user = UserResponse(
                id = user.id!!,
                email = user.email,
                name = user.name,
                role = user.role.name,
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
        path: 'src/main/kotlin/com/example/repository/UserRepository.kt',
        content: `package com.example.repository

import com.example.entity.User
import io.micronaut.data.annotation.Repository
import io.micronaut.data.jpa.repository.JpaRepository
import java.util.Optional

@Repository
interface UserRepository : JpaRepository<User, Long> {
    fun findByEmail(email: String): Optional<User>
    fun existsByEmail(email: String): Boolean
}`
      }
    ];
  }

  protected generateModelFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/kotlin/com/example/entity/User.kt',
        content: `package com.example.entity

import io.micronaut.data.annotation.DateCreated
import io.micronaut.data.annotation.DateUpdated
import io.micronaut.serde.annotation.Serdeable
import jakarta.persistence.*
import java.time.LocalDateTime

@Entity
@Table(name = "users")
@Serdeable
data class User(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    var id: Long? = null,
    
    @Column(unique = true, nullable = false)
    var email: String,
    
    @Column(nullable = false)
    var password: String,
    
    @Column(nullable = false)
    var name: String,
    
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    var role: UserRole = UserRole.USER,
    
    @Column(name = "is_active", nullable = false)
    var isActive: Boolean = true,
    
    @DateCreated
    @Column(name = "created_at", nullable = false, updatable = false)
    var createdAt: LocalDateTime = LocalDateTime.now(),
    
    @DateUpdated
    @Column(name = "updated_at", nullable = false)
    var updatedAt: LocalDateTime = LocalDateTime.now()
)

enum class UserRole {
    USER,
    ADMIN,
    MODERATOR
}`
      }
    ];
  }

  protected generateConfigFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/kotlin/com/example/security/JwtTokenGenerator.kt',
        content: `package com.example.security

import com.example.entity.User
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.micronaut.context.annotation.Value
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.token.generator.TokenGenerator
import jakarta.inject.Singleton
import java.time.Instant
import java.util.*

@Singleton
class JwtTokenGenerator(
    @Value("\\\${jwt.secret}") private val secret: String,
    @Value("\\\${jwt.expiration}") private val expiration: Long
) : TokenGenerator<User> {
    
    override fun generateToken(user: User): String {
        val signer = MACSigner(secret)
        
        val claimsSet = JWTClaimsSet.Builder()
            .subject(user.email)
            .issuer("\${this.options.name}")
            .expirationTime(Date.from(Instant.now().plusSeconds(expiration)))
            .issueTime(Date())
            .claim("id", user.id)
            .claim("role", user.role.name)
            .build()
        
        val signedJWT = SignedJWT(JWSHeader(JWSAlgorithm.HS256), claimsSet)
        signedJWT.sign(signer)
        
        return signedJWT.serialize()
    }
    
    fun generateToken(authentication: Authentication): String {
        val claimsSet = JWTClaimsSet.Builder()
            .subject(authentication.name)
            .issuer("\${this.options.name}")
            .expirationTime(Date.from(Instant.now().plusSeconds(expiration)))
            .issueTime(Date())
            .claim("roles", authentication.roles)
            .build()
        
        val signer = MACSigner(secret)
        val signedJWT = SignedJWT(JWSHeader(JWSAlgorithm.HS256), claimsSet)
        signedJWT.sign(signer)
        
        return signedJWT.serialize()
    }
}`
      },
      {
        path: 'src/main/kotlin/com/example/security/AuthenticationProviderUserPassword.kt',
        content: `package com.example.security

import com.example.service.UserService
import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.*
import jakarta.inject.Singleton
import reactor.core.publisher.Mono

@Singleton
class AuthenticationProviderUserPassword(
    private val userService: UserService
) : AuthenticationProvider<HttpRequest<*>, UsernamePasswordCredentials, Authentication> {
    
    override fun authenticate(
        httpRequest: HttpRequest<*>?,
        authenticationRequest: UsernamePasswordCredentials
    ): Mono<Authentication> {
        return Mono.create { emitter ->
            val user = userService.validateCredentials(
                authenticationRequest.username,
                authenticationRequest.password
            )
            
            if (user != null) {
                emitter.success(
                    Authentication.build(
                        user.email,
                        listOf(user.role.name),
                        mapOf(
                            "id" to user.id,
                            "name" to user.name
                        )
                    )
                )
            } else {
                emitter.error(AuthenticationException(AuthenticationResponse.failure()))
            }
        }
    }
}`
      },
      {
        path: 'src/main/kotlin/com/example/config/RedisConfig.kt',
        content: `package com.example.config

import io.lettuce.core.RedisClient
import io.lettuce.core.api.StatefulRedisConnection
import io.micronaut.context.annotation.Bean
import io.micronaut.context.annotation.Factory
import io.micronaut.context.annotation.Value
import jakarta.inject.Singleton

@Factory
class RedisConfig {
    
    @Bean(preDestroy = "shutdown")
    @Singleton
    fun redisClient(@Value("\\\${redis.uri}") uri: String): RedisClient {
        return RedisClient.create(uri)
    }
    
    @Bean(preDestroy = "close")
    @Singleton
    fun redisConnection(redisClient: RedisClient): StatefulRedisConnection<String, String> {
        return redisClient.connect()
    }
}`
      },
      {
        path: 'src/main/kotlin/com/example/exception/GlobalExceptionHandler.kt',
        content: `package com.example.exception

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.Produces
import io.micronaut.http.server.exceptions.ExceptionHandler
import io.micronaut.serde.annotation.Serdeable
import jakarta.inject.Singleton
import java.time.LocalDateTime

@Produces
@Singleton
@Requires(classes = [ValidationException::class])
class ValidationExceptionHandler : ExceptionHandler<ValidationException, HttpResponse<ErrorResponse>> {
    override fun handle(request: HttpRequest<*>, exception: ValidationException): HttpResponse<ErrorResponse> {
        return HttpResponse.badRequest(
            ErrorResponse(
                error = "Validation Error",
                message = exception.message ?: "Invalid request data",
                timestamp = LocalDateTime.now()
            )
        )
    }
}

@Produces
@Singleton
@Requires(classes = [ResourceNotFoundException::class])
class ResourceNotFoundExceptionHandler : ExceptionHandler<ResourceNotFoundException, HttpResponse<ErrorResponse>> {
    override fun handle(request: HttpRequest<*>, exception: ResourceNotFoundException): HttpResponse<ErrorResponse> {
        return HttpResponse.notFound(
            ErrorResponse(
                error = "Not Found",
                message = exception.message ?: "Resource not found",
                timestamp = LocalDateTime.now()
            )
        )
    }
}

@Produces
@Singleton
@Requires(classes = [UnauthorizedException::class])
class UnauthorizedExceptionHandler : ExceptionHandler<UnauthorizedException, HttpResponse<ErrorResponse>> {
    override fun handle(request: HttpRequest<*>, exception: UnauthorizedException): HttpResponse<ErrorResponse> {
        return HttpResponse.unauthorized<ErrorResponse>().body(
            ErrorResponse(
                error = "Unauthorized",
                message = exception.message ?: "Authentication required",
                timestamp = LocalDateTime.now()
            )
        )
    }
}

@Serdeable
data class ErrorResponse(
    val error: String,
    val message: String,
    val timestamp: LocalDateTime
)

class ValidationException(message: String) : RuntimeException(message)
class ResourceNotFoundException(message: String) : RuntimeException(message)
class UnauthorizedException(message: String) : RuntimeException(message)`
      },
      {
        path: 'src/main/resources/application.yml',
        content: `micronaut:
  application:
    name: \${this.options.name}
  server:
    port: \${SERVER_PORT:8080}
    cors:
      enabled: true
      configurations:
        web:
          allowed-origins:
            - http://localhost:3000
            - http://localhost:5173
          allowed-methods:
            - GET
            - POST
            - PUT
            - DELETE
            - OPTIONS
          allowed-headers:
            - Content-Type
            - Authorization
          exposed-headers:
            - Authorization
          allow-credentials: true
  security:
    enabled: true
    endpoints:
      login:
        enabled: false
      logout:
        enabled: false
    token:
      jwt:
        enabled: true
        signatures:
          secret:
            generator:
              secret: \${JWT_SECRET:your-secret-key-change-in-production}
        generator:
          access-token:
            expiration: \${JWT_EXPIRATION:86400}
    intercept-url-map:
      - pattern: /swagger/**
        access:
          - isAnonymous()
      - pattern: /rapidoc/**
        access:
          - isAnonymous()
      - pattern: /health
        access:
          - isAnonymous()
  router:
    static-resources:
      swagger:
        paths: classpath:META-INF/swagger
        mapping: /swagger/**
      rapidoc:
        paths: classpath:META-INF/swagger/views/rapidoc
        mapping: /rapidoc/**

datasources:
  default:
    url: \${DATABASE_URL:jdbc:postgresql://localhost:5432/app_db}
    username: \${DATABASE_USER:postgres}
    password: \${DATABASE_PASSWORD:postgres}
    driver-class-name: org.postgresql.Driver
    dialect: POSTGRES
    maximum-pool-size: \${DATABASE_MAX_POOL_SIZE:10}

jpa:
  default:
    properties:
      hibernate:
        hbm2ddl:
          auto: validate
        show_sql: false
        format_sql: true

liquibase:
  datasources:
    default:
      change-log: classpath:db/liquibase-changelog.xml

redis:
  uri: redis://\${REDIS_HOST:localhost}:\${REDIS_PORT:6379}

jwt:
  secret: \${JWT_SECRET:your-secret-key-change-in-production}
  expiration: \${JWT_EXPIRATION:86400}

endpoints:
  health:
    enabled: true
    sensitive: false
  metrics:
    enabled: true
    sensitive: false
  prometheus:
    enabled: true
    sensitive: false

jackson:
  serialization:
    write-dates-as-timestamps: false
  deserialization:
    fail-on-unknown-properties: false`
      },
      {
        path: 'src/main/resources/logback.xml',
        content: `<configuration>
    <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>
    
    <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>\${LOG_FILE:-logs/app.log}</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <fileNamePattern>logs/app-%d{yyyy-MM-dd}.log</fileNamePattern>
            <maxHistory>30</maxHistory>
        </rollingPolicy>
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>
    
    <root level="\${LOG_LEVEL:-INFO}">
        <appender-ref ref="STDOUT" />
        <appender-ref ref="FILE" />
    </root>
    
    <logger name="com.example" level="DEBUG"/>
    <logger name="io.micronaut.http" level="DEBUG"/>
    <logger name="io.micronaut.data" level="DEBUG"/>
</configuration>`
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

import io.micronaut.runtime.EmbeddedApplication
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import jakarta.inject.Inject
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

@MicronautTest
class ApplicationTest {
    
    @Inject
    lateinit var application: EmbeddedApplication<*>
    
    @Test
    fun testItWorks() {
        assertTrue(application.isRunning)
    }
}`
      },
      {
        path: 'src/test/kotlin/com/example/controller/AuthControllerTest.kt',
        content: `package com.example.controller

import com.example.dto.CreateUserRequest
import com.example.dto.LoginRequest
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import jakarta.inject.Inject
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

@MicronautTest
class AuthControllerTest {
    
    @Inject
    @field:Client("/")
    lateinit var client: HttpClient
    
    @Test
    fun testRegisterUser() {
        val request = CreateUserRequest(
            email = "test@example.com",
            password = "password123",
            name = "Test User"
        )
        
        val response = client.toBlocking().exchange(
            HttpRequest.POST("/api/auth/register", request),
            Map::class.java
        )
        
        assertEquals(HttpStatus.CREATED, response.status)
        assertNotNull(response.body())
        assertTrue(response.body()!!.containsKey("token"))
        assertTrue(response.body()!!.containsKey("refreshToken"))
    }
    
    @Test
    fun testHealthEndpoint() {
        val response = client.toBlocking().exchange(
            HttpRequest.GET<Any>("/health"),
            Map::class.java
        )
        
        assertEquals(HttpStatus.OK, response.status)
        assertEquals("UP", response.body()!!["status"])
    }
}`
      }
    ];
  }

  protected generateDtoFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/kotlin/com/example/dto/UserDto.kt',
        content: `package com.example.dto

import io.micronaut.core.annotation.Introspected
import io.micronaut.serde.annotation.Serdeable
import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size

@Serdeable
@Introspected
data class CreateUserRequest(
    @field:NotBlank(message = "Email is required")
    @field:Email(message = "Invalid email format")
    val email: String,
    
    @field:NotBlank(message = "Password is required")
    @field:Size(min = 8, message = "Password must be at least 8 characters")
    val password: String,
    
    @field:NotBlank(message = "Name is required")
    @field:Size(min = 2, max = 100, message = "Name must be between 2 and 100 characters")
    val name: String
)

@Serdeable
@Introspected
data class UpdateUserRequest(
    @field:Email(message = "Invalid email format")
    val email: String? = null,
    
    @field:Size(min = 8, message = "Password must be at least 8 characters")
    val password: String? = null,
    
    @field:Size(min = 2, max = 100, message = "Name must be between 2 and 100 characters")
    val name: String? = null
)

@Serdeable
@Introspected
data class LoginRequest(
    @field:NotBlank(message = "Email is required")
    @field:Email(message = "Invalid email format")
    val email: String,
    
    @field:NotBlank(message = "Password is required")
    val password: String
)

@Serdeable
@Introspected
data class UserResponse(
    val id: Long,
    val email: String,
    val name: String,
    val role: String,
    val isActive: Boolean,
    val createdAt: String,
    val updatedAt: String
)

@Serdeable
@Introspected
data class AuthResponse(
    val token: String,
    val refreshToken: String,
    val user: UserResponse
)

@Serdeable
@Introspected
data class RefreshTokenRequest(
    @field:NotBlank(message = "Refresh token is required")
    val refreshToken: String
)

@Serdeable
@Introspected
data class MessageResponse(
    val message: String
)`
      }
    ];
  }

  protected generateLiquibaseFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/resources/db/liquibase-changelog.xml',
        content: `<?xml version="1.0" encoding="UTF-8"?>
<databaseChangeLog
    xmlns="http://www.liquibase.org/xml/ns/dbchangelog"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://www.liquibase.org/xml/ns/dbchangelog
        http://www.liquibase.org/xml/ns/dbchangelog/dbchangelog-4.20.xsd">

    <changeSet id="001" author="system">
        <createTable tableName="users">
            <column name="id" type="BIGSERIAL">
                <constraints primaryKey="true" nullable="false"/>
            </column>
            <column name="email" type="VARCHAR(255)">
                <constraints nullable="false" unique="true"/>
            </column>
            <column name="password" type="VARCHAR(255)">
                <constraints nullable="false"/>
            </column>
            <column name="name" type="VARCHAR(255)">
                <constraints nullable="false"/>
            </column>
            <column name="role" type="VARCHAR(50)" defaultValue="USER">
                <constraints nullable="false"/>
            </column>
            <column name="is_active" type="BOOLEAN" defaultValueBoolean="true">
                <constraints nullable="false"/>
            </column>
            <column name="created_at" type="TIMESTAMP" defaultValueComputed="CURRENT_TIMESTAMP">
                <constraints nullable="false"/>
            </column>
            <column name="updated_at" type="TIMESTAMP" defaultValueComputed="CURRENT_TIMESTAMP">
                <constraints nullable="false"/>
            </column>
        </createTable>
        
        <createIndex tableName="users" indexName="idx_users_email">
            <column name="email"/>
        </createIndex>
        
        <createIndex tableName="users" indexName="idx_users_role">
            <column name="role"/>
        </createIndex>
    </changeSet>
</databaseChangeLog>`
      }
    ];
  }

  async generateTemplate(projectPath: string): Promise<void> {
    await super.generateTemplate(projectPath);
    
    // Generate additional Micronaut specific files
    const additionalFiles = [
      ...this.generateDtoFiles(),
      ...this.generateLiquibaseFiles()
    ];
    
    for (const file of additionalFiles) {
      await fs.writeFile(path.join(projectPath, file.path), file.content);
    }
  }
}