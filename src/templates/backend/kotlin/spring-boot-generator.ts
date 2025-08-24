import { KotlinBackendGenerator } from './kotlin-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class SpringBootKotlinGenerator extends KotlinBackendGenerator {
  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'org.springframework.boot:spring-boot-starter-web': '',
      'org.springframework.boot:spring-boot-starter-security': '',
      'org.springframework.boot:spring-boot-starter-data-jpa': '',
      'org.springframework.boot:spring-boot-starter-validation': '',
      'org.springframework.boot:spring-boot-starter-actuator': '',
      'org.springframework.boot:spring-boot-starter-cache': '',
      'org.springframework.boot:spring-boot-starter-data-redis': '',
      'org.springframework.boot:spring-boot-starter-webflux': '',
      'com.fasterxml.jackson.module:jackson-module-kotlin': '',
      'org.springdoc:springdoc-openapi-starter-webmvc-ui': '2.3.0',
      'io.jsonwebtoken:jjwt-api': '0.12.3',
      'io.jsonwebtoken:jjwt-impl': '0.12.3',
      'io.jsonwebtoken:jjwt-jackson': '0.12.3'
    };
  }

  protected generateBuildGradle(): string {
    return `import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("org.springframework.boot") version "3.2.0"
    id("io.spring.dependency-management") version "1.1.4"
    kotlin("jvm") version "1.9.21"
    kotlin("plugin.spring") version "1.9.21"
    kotlin("plugin.jpa") version "1.9.21"
    kotlin("plugin.allopen") version "1.9.21"
    kotlin("kapt") version "1.9.21"
}

group = "com.example"
version = "0.0.1-SNAPSHOT"

java {
    sourceCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenCentral()
}

dependencies {
    // Spring Boot
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("org.springframework.boot:spring-boot-starter-cache")
    implementation("org.springframework.boot:spring-boot-starter-data-redis")
    
    // Kotlin
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    implementation("org.jetbrains.kotlin:kotlin-stdlib-jdk8")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-reactor")
    
    // Database
    implementation("org.postgresql:postgresql")
    implementation("org.liquibase:liquibase-core")
    
    // Security & JWT
    implementation("io.jsonwebtoken:jjwt-api:0.12.3")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.3")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.12.3")
    
    // Documentation
    implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.3.0")
    
    // Monitoring
    implementation("io.micrometer:micrometer-registry-prometheus")
    
    // Development
    developmentOnly("org.springframework.boot:spring-boot-devtools")
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")
    
    // Testing
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("io.mockk:mockk:1.13.8")
    testImplementation("com.ninja-squad:springmockk:4.0.2")
    testImplementation("io.kotest:kotest-runner-junit5:5.8.0")
    testImplementation("io.kotest:kotest-assertions-core:5.8.0")
    testImplementation("io.kotest.extensions:kotest-extensions-spring:1.1.3")
}

allOpen {
    annotation("jakarta.persistence.Entity")
    annotation("jakarta.persistence.Embeddable")
    annotation("jakarta.persistence.MappedSuperclass")
}

tasks.withType<KotlinCompile> {
    kotlinOptions {
        freeCompilerArgs += "-Xjsr305=strict"
        jvmTarget = "17"
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}`;
  }

  protected generateMainFile(): string {
    return `package com.example

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.cache.annotation.EnableCaching
import org.springframework.data.jpa.repository.config.EnableJpaAuditing
import org.springframework.scheduling.annotation.EnableAsync
import org.springframework.scheduling.annotation.EnableScheduling

@SpringBootApplication
@EnableJpaAuditing
@EnableCaching
@EnableAsync
@EnableScheduling
class Application

fun main(args: Array<String>) {
    runApplication<Application>(*args)
}`;
  }

  protected generateRoutingFile(): string {
    return `package com.example.controller

import com.example.dto.*
import com.example.service.AuthService
import com.example.service.UserService
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import org.springframework.data.domain.Page
import org.springframework.data.domain.Pageable
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication", description = "Authentication endpoints")
class AuthController(
    private val authService: AuthService
) {
    @PostMapping("/register")
    @Operation(summary = "Register a new user")
    fun register(@Valid @RequestBody request: CreateUserRequest): ResponseEntity<AuthResponse> {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request))
    }
    
    @PostMapping("/login")
    @Operation(summary = "Login user")
    fun login(@Valid @RequestBody request: LoginRequest): ResponseEntity<AuthResponse> {
        return ResponseEntity.ok(authService.login(request))
    }
    
    @PostMapping("/refresh")
    @Operation(summary = "Refresh access token")
    fun refresh(@Valid @RequestBody request: RefreshTokenRequest): ResponseEntity<AuthResponse> {
        return ResponseEntity.ok(authService.refreshToken(request))
    }
    
    @PostMapping("/logout")
    @Operation(summary = "Logout user", security = [SecurityRequirement(name = "bearer-jwt")])
    @PreAuthorize("isAuthenticated()")
    fun logout(@RequestHeader("X-Refresh-Token") refreshToken: String?): ResponseEntity<MessageResponse> {
        refreshToken?.let { authService.logout(it) }
        return ResponseEntity.ok(MessageResponse("Logged out successfully"))
    }
}

@RestController
@RequestMapping("/api/users")
@Tag(name = "Users", description = "User management endpoints")
@SecurityRequirement(name = "bearer-jwt")
class UserController(
    private val userService: UserService
) {
    @GetMapping
    @Operation(summary = "Get all users")
    @PreAuthorize("hasRole('ADMIN')")
    fun getAllUsers(pageable: Pageable): ResponseEntity<Page<UserResponse>> {
        return ResponseEntity.ok(userService.getAllUsers(pageable))
    }
    
    @GetMapping("/{id}")
    @Operation(summary = "Get user by ID")
    @PreAuthorize("isAuthenticated()")
    fun getUserById(@PathVariable id: Long): ResponseEntity<UserResponse> {
        return ResponseEntity.ok(userService.getUserById(id))
    }
    
    @GetMapping("/me")
    @Operation(summary = "Get current user")
    @PreAuthorize("isAuthenticated()")
    fun getCurrentUser(): ResponseEntity<UserResponse> {
        return ResponseEntity.ok(userService.getCurrentUser())
    }
    
    @PutMapping("/{id}")
    @Operation(summary = "Update user")
    @PreAuthorize("isAuthenticated() and (#id == authentication.principal.id or hasRole('ADMIN'))")
    fun updateUser(
        @PathVariable id: Long,
        @Valid @RequestBody request: UpdateUserRequest
    ): ResponseEntity<UserResponse> {
        return ResponseEntity.ok(userService.updateUser(id, request))
    }
    
    @DeleteMapping("/{id}")
    @Operation(summary = "Delete user")
    @PreAuthorize("hasRole('ADMIN')")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun deleteUser(@PathVariable id: Long) {
        userService.deleteUser(id)
    }
}

@RestController
@Tag(name = "Health", description = "Health check endpoint")
class HealthController {
    @GetMapping("/health")
    @Operation(summary = "Health check")
    fun health(): ResponseEntity<Map<String, Any>> {
        return ResponseEntity.ok(mapOf(
            "status" to "UP",
            "timestamp" to System.currentTimeMillis()
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
import com.example.security.getCurrentUserId
import org.springframework.data.domain.Page
import org.springframework.data.domain.Pageable
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
@Transactional
class UserService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder
) {
    fun createUser(request: CreateUserRequest): User {
        if (userRepository.existsByEmail(request.email)) {
            throw ValidationException("Email already exists")
        }
        
        val user = User(
            email = request.email,
            password = passwordEncoder.encode(request.password),
            name = request.name
        )
        
        return userRepository.save(user)
    }
    
    @Transactional(readOnly = true)
    fun getUserById(id: Long): UserResponse {
        val user = userRepository.findById(id)
            .orElseThrow { ResourceNotFoundException("User not found") }
        return user.toResponse()
    }
    
    @Transactional(readOnly = true)
    fun getCurrentUser(): UserResponse {
        val userId = getCurrentUserId()
        return getUserById(userId)
    }
    
    @Transactional(readOnly = true)
    fun getAllUsers(pageable: Pageable): Page<UserResponse> {
        return userRepository.findAll(pageable).map { it.toResponse() }
    }
    
    fun updateUser(id: Long, request: UpdateUserRequest): UserResponse {
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
            user.password = passwordEncoder.encode(it)
        }
        
        return userRepository.save(user).toResponse()
    }
    
    fun deleteUser(id: Long) {
        if (!userRepository.existsById(id)) {
            throw ResourceNotFoundException("User not found")
        }
        userRepository.deleteById(id)
    }
    
    @Transactional(readOnly = true)
    fun getUserByEmail(email: String): UserResponse {
        val user = userRepository.findByEmail(email)
            .orElseThrow { ResourceNotFoundException("User not found") }
        return user.toResponse()
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
import com.example.security.JwtTokenProvider
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Service
import java.util.concurrent.TimeUnit

@Service
class AuthService(
    private val userService: UserService,
    private val authenticationManager: AuthenticationManager,
    private val jwtTokenProvider: JwtTokenProvider,
    private val redisTemplate: StringRedisTemplate
) {
    fun register(request: CreateUserRequest): AuthResponse {
        val user = userService.createUser(request)
        return generateAuthResponse(user.email)
    }
    
    fun login(request: LoginRequest): AuthResponse {
        try {
            val authentication = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken(request.email, request.password)
            )
            SecurityContextHolder.getContext().authentication = authentication
            return generateAuthResponse(request.email)
        } catch (e: Exception) {
            throw UnauthorizedException("Invalid email or password")
        }
    }
    
    fun refreshToken(request: RefreshTokenRequest): AuthResponse {
        val email = redisTemplate.opsForValue().get("refresh:\\\${request.refreshToken}")
            ?: throw UnauthorizedException("Invalid refresh token")
        
        // Delete old refresh token
        redisTemplate.delete("refresh:\\\${request.refreshToken}")
        
        return generateAuthResponse(email)
    }
    
    fun logout(refreshToken: String) {
        redisTemplate.delete("refresh:\\$refreshToken")
    }
    
    private fun generateAuthResponse(email: String): AuthResponse {
        val accessToken = jwtTokenProvider.createToken(email)
        val refreshToken = jwtTokenProvider.createRefreshToken()
        
        // Store refresh token in Redis with expiration
        redisTemplate.opsForValue().set(
            "refresh:\\$refreshToken",
            email,
            7,
            TimeUnit.DAYS
        )
        
        val user = userService.getUserByEmail(email)
        
        return AuthResponse(
            token = accessToken,
            refreshToken = refreshToken,
            user = user
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
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository
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

import jakarta.persistence.*
import org.springframework.data.annotation.CreatedDate
import org.springframework.data.annotation.LastModifiedDate
import org.springframework.data.jpa.domain.support.AuditingEntityListener
import java.time.LocalDateTime

@Entity
@Table(name = "users")
@EntityListeners(AuditingEntityListener::class)
class User(
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
    
    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    var createdAt: LocalDateTime = LocalDateTime.now(),
    
    @LastModifiedDate
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
        path: 'src/main/kotlin/com/example/config/SecurityConfig.kt',
        content: `package com.example.config

import com.example.security.JwtAuthenticationFilter
import com.example.security.JwtTokenProvider
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
class SecurityConfig(
    private val jwtTokenProvider: JwtTokenProvider
) {
    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()
    
    @Bean
    fun authenticationManager(authConfig: AuthenticationConfiguration): AuthenticationManager =
        authConfig.authenticationManager
    
    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .csrf { it.disable() }
            .cors { it.configurationSource(corsConfigurationSource()) }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .authorizeHttpRequests { auth ->
                auth
                    .requestMatchers("/api/auth/**").permitAll()
                    .requestMatchers("/health").permitAll()
                    .requestMatchers("/swagger-ui/**").permitAll()
                    .requestMatchers("/v3/api-docs/**").permitAll()
                    .requestMatchers("/actuator/**").permitAll()
                    .anyRequest().authenticated()
            }
            .addFilterBefore(
                jwtAuthenticationFilter(),
                UsernamePasswordAuthenticationFilter::class.java
            )
        
        return http.build()
    }
    
    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource {
        val configuration = CorsConfiguration().apply {
            allowedOrigins = listOf("http://localhost:3000", "http://localhost:5173")
            allowedMethods = listOf("GET", "POST", "PUT", "DELETE", "OPTIONS")
            allowedHeaders = listOf("*")
            allowCredentials = true
        }
        
        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", configuration)
        return source
    }
    
    @Bean
    fun jwtAuthenticationFilter(): JwtAuthenticationFilter {
        return JwtAuthenticationFilter(jwtTokenProvider)
    }
}`
      },
      {
        path: 'src/main/kotlin/com/example/config/OpenApiConfig.kt',
        content: `package com.example.config

import io.swagger.v3.oas.models.Components
import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.oas.models.info.Info
import io.swagger.v3.oas.models.info.License
import io.swagger.v3.oas.models.security.SecurityScheme
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class OpenApiConfig {
    @Bean
    fun openAPI(): OpenAPI {
        return OpenAPI()
            .info(
                Info()
                    .title("Spring Boot Kotlin API")
                    .description("REST API documentation")
                    .version("1.0.0")
                    .license(License().name("MIT").url("https://opensource.org/licenses/MIT"))
            )
            .components(
                Components()
                    .addSecuritySchemes(
                        "bearer-jwt",
                        SecurityScheme()
                            .type(SecurityScheme.Type.HTTP)
                            .scheme("bearer")
                            .bearerFormat("JWT")
                            .description("JWT authentication")
                    )
            )
    }
}`
      },
      {
        path: 'src/main/kotlin/com/example/config/RedisConfig.kt',
        content: `package com.example.config

import org.springframework.boot.autoconfigure.data.redis.RedisProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.redis.connection.RedisConnectionFactory
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory
import org.springframework.data.redis.core.RedisTemplate
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer
import org.springframework.data.redis.serializer.StringRedisSerializer

@Configuration
class RedisConfig {
    @Bean
    fun redisConnectionFactory(redisProperties: RedisProperties): RedisConnectionFactory {
        return LettuceConnectionFactory(redisProperties.host, redisProperties.port)
    }
    
    @Bean
    fun redisTemplate(connectionFactory: RedisConnectionFactory): RedisTemplate<String, Any> {
        return RedisTemplate<String, Any>().apply {
            this.connectionFactory = connectionFactory
            keySerializer = StringRedisSerializer()
            valueSerializer = GenericJackson2JsonRedisSerializer()
            hashKeySerializer = StringRedisSerializer()
            hashValueSerializer = GenericJackson2JsonRedisSerializer()
            afterPropertiesSet()
        }
    }
    
    @Bean
    fun stringRedisTemplate(connectionFactory: RedisConnectionFactory): StringRedisTemplate {
        return StringRedisTemplate(connectionFactory)
    }
}`
      },
      {
        path: 'src/main/resources/application.yml',
        content: `spring:
  application:
    name: spring-boot-kotlin-service
  
  datasource:
    url: \${DATABASE_URL:jdbc:postgresql://localhost:5432/app_db}
    username: \${DATABASE_USER:postgres}
    password: \${DATABASE_PASSWORD:postgres}
    driver-class-name: org.postgresql.Driver
    hikari:
      maximum-pool-size: \${DATABASE_MAX_POOL_SIZE:10}
      minimum-idle: 2
      connection-timeout: 30000
      idle-timeout: 600000
      max-lifetime: 1800000
  
  jpa:
    hibernate:
      ddl-auto: validate
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect
        format_sql: true
        use_sql_comments: true
    show-sql: false
  
  liquibase:
    change-log: classpath:db/changelog/db.changelog-master.xml
  
  redis:
    host: \${REDIS_HOST:localhost}
    port: \${REDIS_PORT:6379}
    password: \${REDIS_PASSWORD:}
    timeout: 2000ms
    lettuce:
      pool:
        max-active: 8
        max-idle: 8
        min-idle: 0
  
  cache:
    type: redis
    redis:
      time-to-live: 3600000
      cache-null-values: false

server:
  port: \${SERVER_PORT:8080}
  compression:
    enabled: true
    mime-types: text/html,text/xml,text/plain,text/css,text/javascript,application/javascript,application/json
    min-response-size: 1024

jwt:
  secret: \${JWT_SECRET:your-secret-key-change-in-production}
  expiration: \${JWT_EXPIRATION:86400}

management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
  endpoint:
    health:
      show-details: when-authorized
  metrics:
    export:
      prometheus:
        enabled: true

logging:
  level:
    root: INFO
    com.example: DEBUG
    org.springframework.web: DEBUG
    org.hibernate.SQL: DEBUG
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} - %msg%n"
    file: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"
  file:
    name: \${LOG_FILE:logs/app.log}

springdoc:
  api-docs:
    path: /v3/api-docs
  swagger-ui:
    path: /swagger-ui.html
    enabled: true`
      }
    ];
  }

  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/kotlin/com/example/security/JwtTokenProvider.kt',
        content: `package com.example.security

import io.jsonwebtoken.*
import io.jsonwebtoken.security.Keys
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Component
import java.util.*
import javax.crypto.SecretKey

@Component
class JwtTokenProvider(
    @Value("\\\${jwt.secret}")
    private val jwtSecret: String,
    
    @Value("\\\${jwt.expiration}")
    private val jwtExpiration: Long
) {
    private val key: SecretKey = Keys.hmacShaKeyFor(jwtSecret.toByteArray())
    
    fun createToken(email: String): String {
        val now = Date()
        val expiryDate = Date(now.time + jwtExpiration * 1000)
        
        return Jwts.builder()
            .setSubject(email)
            .setIssuedAt(now)
            .setExpiration(expiryDate)
            .signWith(key)
            .compact()
    }
    
    fun createRefreshToken(): String {
        return UUID.randomUUID().toString()
    }
    
    fun getEmailFromToken(token: String): String {
        val claims = Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token)
            .body
        
        return claims.subject
    }
    
    fun validateToken(token: String): Boolean {
        try {
            Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
            return true
        } catch (ex: SecurityException) {
            logger.error("Invalid JWT signature")
        } catch (ex: MalformedJwtException) {
            logger.error("Invalid JWT token")
        } catch (ex: ExpiredJwtException) {
            logger.error("Expired JWT token")
        } catch (ex: UnsupportedJwtException) {
            logger.error("Unsupported JWT token")
        } catch (ex: IllegalArgumentException) {
            logger.error("JWT claims string is empty")
        }
        return false
    }
    
    companion object {
        private val logger = org.slf4j.LoggerFactory.getLogger(JwtTokenProvider::class.java)
    }
}`
      },
      {
        path: 'src/main/kotlin/com/example/security/JwtAuthenticationFilter.kt',
        content: `package com.example.security

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class JwtAuthenticationFilter(
    private val jwtTokenProvider: JwtTokenProvider
) : OncePerRequestFilter() {
    
    @Autowired
    private lateinit var userDetailsService: UserDetailsService
    
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val token = getJwtFromRequest(request)
        
        if (token != null && jwtTokenProvider.validateToken(token)) {
            val email = jwtTokenProvider.getEmailFromToken(token)
            val userDetails = userDetailsService.loadUserByUsername(email)
            
            val authentication = UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.authorities
            )
            authentication.details = WebAuthenticationDetailsSource().buildDetails(request)
            
            SecurityContextHolder.getContext().authentication = authentication
        }
        
        filterChain.doFilter(request, response)
    }
    
    private fun getJwtFromRequest(request: HttpServletRequest): String? {
        val bearerToken = request.getHeader("Authorization")
        return if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            bearerToken.substring(7)
        } else null
    }
}`
      },
      {
        path: 'src/main/kotlin/com/example/security/UserDetailsServiceImpl.kt',
        content: `package com.example.security

import com.example.repository.UserRepository
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

@Service
class UserDetailsServiceImpl(
    private val userRepository: UserRepository
) : UserDetailsService {
    
    override fun loadUserByUsername(username: String): UserDetails {
        val user = userRepository.findByEmail(username)
            .orElseThrow { UsernameNotFoundException("User not found with email: $username") }
        
        return User.builder()
            .username(user.email)
            .password(user.password)
            .authorities(SimpleGrantedAuthority("ROLE_\\\${user.role}"))
            .accountExpired(false)
            .accountLocked(false)
            .credentialsExpired(false)
            .disabled(!user.isActive)
            .build()
    }
}`
      },
      {
        path: 'src/main/kotlin/com/example/security/SecurityUtils.kt',
        content: `package com.example.security

import com.example.exception.UnauthorizedException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetails

fun getCurrentUserEmail(): String {
    val authentication = SecurityContextHolder.getContext().authentication
    return when (val principal = authentication?.principal) {
        is UserDetails -> principal.username
        is String -> principal
        else -> throw UnauthorizedException("User not authenticated")
    }
}

fun getCurrentUserId(): Long {
    // This would typically involve looking up the user by email
    // For simplicity, we're throwing an exception
    throw NotImplementedError("Implement user ID lookup")
}`
      }
    ];
  }

  protected generateTestFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/test/kotlin/com/example/ApplicationTests.kt',
        content: `package com.example

import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest

@SpringBootTest
class ApplicationTests {
    @Test
    fun contextLoads() {
    }
}`
      },
      {
        path: 'src/test/kotlin/com/example/controller/AuthControllerTest.kt',
        content: `package com.example.controller

import com.example.dto.CreateUserRequest
import com.example.dto.LoginRequest
import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.*

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerTest {
    @Autowired
    private lateinit var mockMvc: MockMvc
    
    @Autowired
    private lateinit var objectMapper: ObjectMapper
    
    @Test
    fun \`should register new user\`() {
        val request = CreateUserRequest(
            email = "test@example.com",
            password = "password123",
            name = "Test User"
        )
        
        mockMvc.perform(
            post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request))
        )
            .andExpect(status().isCreated)
            .andExpect(jsonPath("\$.token").exists())
            .andExpect(jsonPath("\$.refreshToken").exists())
            .andExpect(jsonPath("\$.user.email").value(request.email))
    }
    
    @Test
    fun \`should login user\`() {
        val request = LoginRequest(
            email = "test@example.com",
            password = "password123"
        )
        
        mockMvc.perform(
            post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request))
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("\$.token").exists())
            .andExpect(jsonPath("\$.refreshToken").exists())
    }
}`
      }
    ];
  }

  protected generateExceptionFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/kotlin/com/example/exception/GlobalExceptionHandler.kt',
        content: `package com.example.exception

import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.validation.FieldError
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import java.time.LocalDateTime

@RestControllerAdvice
class GlobalExceptionHandler {
    
    @ExceptionHandler(ValidationException::class)
    fun handleValidationException(ex: ValidationException): ResponseEntity<ErrorResponse> {
        return ResponseEntity.badRequest().body(
            ErrorResponse(
                error = "Validation Error",
                message = ex.message ?: "Invalid request data",
                timestamp = LocalDateTime.now()
            )
        )
    }
    
    @ExceptionHandler(ResourceNotFoundException::class)
    fun handleResourceNotFoundException(ex: ResourceNotFoundException): ResponseEntity<ErrorResponse> {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
            ErrorResponse(
                error = "Not Found",
                message = ex.message ?: "Resource not found",
                timestamp = LocalDateTime.now()
            )
        )
    }
    
    @ExceptionHandler(UnauthorizedException::class)
    fun handleUnauthorizedException(ex: UnauthorizedException): ResponseEntity<ErrorResponse> {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
            ErrorResponse(
                error = "Unauthorized",
                message = ex.message ?: "Authentication required",
                timestamp = LocalDateTime.now()
            )
        )
    }
    
    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun handleMethodArgumentNotValid(ex: MethodArgumentNotValidException): ResponseEntity<ErrorResponse> {
        val errors = ex.bindingResult.allErrors.map { error ->
            val fieldName = (error as? FieldError)?.field ?: "unknown"
            val errorMessage = error.defaultMessage ?: "Invalid value"
            "$fieldName: $errorMessage"
        }.joinToString(", ")
        
        return ResponseEntity.badRequest().body(
            ErrorResponse(
                error = "Validation Error",
                message = errors,
                timestamp = LocalDateTime.now()
            )
        )
    }
    
    @ExceptionHandler(Exception::class)
    fun handleGenericException(ex: Exception): ResponseEntity<ErrorResponse> {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
            ErrorResponse(
                error = "Internal Server Error",
                message = "An unexpected error occurred",
                timestamp = LocalDateTime.now()
            )
        )
    }
}

data class ErrorResponse(
    val error: String,
    val message: String,
    val timestamp: LocalDateTime
)

class ValidationException(message: String) : RuntimeException(message)
class ResourceNotFoundException(message: String) : RuntimeException(message)
class UnauthorizedException(message: String) : RuntimeException(message)`
      }
    ];
  }

  protected generateDtoFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/kotlin/com/example/dto/UserDto.kt',
        content: `package com.example.dto

import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size

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

data class UpdateUserRequest(
    @field:Email(message = "Invalid email format")
    val email: String? = null,
    
    @field:Size(min = 8, message = "Password must be at least 8 characters")
    val password: String? = null,
    
    @field:Size(min = 2, max = 100, message = "Name must be between 2 and 100 characters")
    val name: String? = null
)

data class LoginRequest(
    @field:NotBlank(message = "Email is required")
    @field:Email(message = "Invalid email format")
    val email: String,
    
    @field:NotBlank(message = "Password is required")
    val password: String
)

data class UserResponse(
    val id: Long,
    val email: String,
    val name: String,
    val role: String,
    val isActive: Boolean,
    val createdAt: String,
    val updatedAt: String
)

data class AuthResponse(
    val token: String,
    val refreshToken: String,
    val user: UserResponse
)

data class RefreshTokenRequest(
    @field:NotBlank(message = "Refresh token is required")
    val refreshToken: String
)

data class MessageResponse(
    val message: String
)`
      }
    ];
  }

  protected generateLiquibaseFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/resources/db/changelog/db.changelog-master.xml',
        content: `<?xml version="1.0" encoding="UTF-8"?>
<databaseChangeLog
    xmlns="http://www.liquibase.org/xml/ns/dbchangelog"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://www.liquibase.org/xml/ns/dbchangelog
        http://www.liquibase.org/xml/ns/dbchangelog/dbchangelog-4.20.xsd">

    <include file="db/changelog/changes/001-create-users-table.xml"/>
</databaseChangeLog>`
      },
      {
        path: 'src/main/resources/db/changelog/changes/001-create-users-table.xml',
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
            <column name="role" type="VARCHAR(50)">
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
    </changeSet>
</databaseChangeLog>`
      }
    ];
  }

  protected generateReadmeContent(): string {
    return `# ${this.options?.name || 'Spring Boot Kotlin Service'}

A Spring Boot Kotlin backend application with modern features and enterprise-grade architecture.

## 🚀 Features

- **Spring Boot 3.2**: Latest Spring Boot with Java 17 support
- **Kotlin**: Modern JVM language with coroutines and null safety
- **PostgreSQL**: Reliable relational database with JPA/Hibernate
- **Redis**: High-performance caching and session storage
- **JWT Authentication**: Secure token-based authentication
- **OpenAPI/Swagger**: Interactive API documentation
- **Docker**: Containerized deployment with Docker Compose
- **Testing**: Comprehensive test suite with Kotest and MockK

## 🛠️ Development Setup

### Prerequisites
- JDK 17 or higher
- Gradle 8.5 or higher
- PostgreSQL 15+
- Redis 7+

### Quick Start

1. Clone and setup:
   \`\`\`bash
   git clone <repository>
   cd ${this.options?.name || 'spring-boot-kotlin-service'}
   cp .env.example .env
   \`\`\`

2. Start dependencies:
   \`\`\`bash
   docker-compose up -d db redis
   \`\`\`

3. Run the application:
   \`\`\`bash
   ./gradlew bootRun
   \`\`\`

4. Visit: http://localhost:8080/swagger-ui.html

## 📚 API Documentation

The application provides a comprehensive REST API with the following endpoints:

### Authentication
- \`POST /api/auth/register\` - Register new user
- \`POST /api/auth/login\` - User login
- \`POST /api/auth/refresh\` - Refresh access token
- \`POST /api/auth/logout\` - User logout

### Users
- \`GET /api/users\` - List users (admin only)
- \`GET /api/users/{id}\` - Get user by ID
- \`GET /api/users/me\` - Get current user profile
- \`PUT /api/users/{id}\` - Update user
- \`DELETE /api/users/{id}\` - Delete user (admin only)

### Health
- \`GET /health\` - Health check endpoint

## 🧪 Testing

Run tests:
\`\`\`bash
./gradlew test
\`\`\`

Run with coverage:
\`\`\`bash
./gradlew test jacocoTestReport
\`\`\`

## 🚀 Deployment

### Docker
\`\`\`bash
docker-compose up --build
\`\`\`

### Production Build
\`\`\`bash
./gradlew bootJar
java -jar build/libs/${this.options?.name || 'app'}-*.jar
\`\`\`

## 📄 License

MIT License - see LICENSE file for details.
`;
  }

  protected generateEnvExample(): string {
    return `# Server Configuration
SERVER_PORT=8080
SERVER_HOST=0.0.0.0

# Database Configuration
DATABASE_URL=jdbc:postgresql://localhost:5432/app_db
DATABASE_USER=postgres
DATABASE_PASSWORD=postgres
DATABASE_MAX_POOL_SIZE=10

# JWT Configuration
JWT_SECRET=your-secret-key-change-in-production
JWT_EXPIRATION=86400

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# Logging
LOG_LEVEL=INFO

# Environment
SPRING_PROFILES_ACTIVE=development`;
  }

  async generateTemplate(projectPath: string, options: any = {}): Promise<void> {
    // Store options for use in other methods
    this.options = options;
    
    // Create directory structure
    const directories = [
      'src/main/kotlin/com/example/config',
      'src/main/kotlin/com/example/controller',
      'src/main/kotlin/com/example/service',
      'src/main/kotlin/com/example/repository',
      'src/main/kotlin/com/example/entity',
      'src/main/kotlin/com/example/dto',
      'src/main/kotlin/com/example/security',
      'src/main/kotlin/com/example/exception',
      'src/main/resources/db/changelog/changes',
      'src/test/kotlin/com/example/controller',
      'gradle/wrapper'
    ];

    for (const dir of directories) {
      await fs.mkdir(path.join(projectPath, dir), { recursive: true });
    }

    // Generate all files
    const files = [
      { path: 'build.gradle.kts', content: this.generateBuildGradle() },
      { path: 'gradle.properties', content: 'kotlin.code.style=official\\norg.gradle.jvmargs=-Xmx2048m' },
      { path: 'settings.gradle.kts', content: `rootProject.name = "${options.name || 'spring-boot-kotlin-service'}"` },
      { path: '.gitignore', content: '.gradle\\nbuild/\\n.idea\\n*.iml\\nlogs/\\n*.log' },
      { path: 'src/main/kotlin/com/example/Application.kt', content: this.generateMainFile() },
      { path: 'README.md', content: this.generateReadmeContent() },
      { path: '.env.example', content: this.generateEnvExample() },
      
      ...this.generateServiceFiles(),
      ...this.generateRepositoryFiles(),
      ...this.generateModelFiles(),
      ...this.generateConfigFiles(),
      ...this.generateMiddlewareFiles(),
      ...this.generateTestFiles(),
      ...this.generateExceptionFiles(),
      ...this.generateDtoFiles(),
      ...this.generateLiquibaseFiles()
    ];

    // Add the routing file  
    files.push({
      path: 'src/main/kotlin/com/example/controller/AuthController.kt',
      content: this.generateRoutingFile()
    });

    // Write all files
    for (const file of files) {
      const fullPath = path.join(projectPath, file.path);
      await fs.mkdir(path.dirname(fullPath), { recursive: true });
      await fs.writeFile(fullPath, file.content);
    }
  }
}