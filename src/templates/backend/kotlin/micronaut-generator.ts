import { KotlinBackendGenerator } from './kotlin-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class MicronautGenerator extends KotlinBackendGenerator {
  constructor() {
    super('Micronaut');
  }

  protected getFrameworkPlugins(): string {
    return `id("io.micronaut.application") version "4.2.0"
    id("io.micronaut.aot") version "4.2.0"
    kotlin("plugin.allopen") version "1.9.20"
    kotlin("plugin.jpa") version "1.9.20"`;
  }

  protected getFrameworkDependencies(): string {
    return `implementation("io.micronaut:micronaut-http-server-netty")
    implementation("io.micronaut.kotlin:micronaut-kotlin-runtime")
    implementation("io.micronaut.data:micronaut-data-hibernate-jpa")
    implementation("io.micronaut.sql:micronaut-jdbc-hikari")
    implementation("io.micronaut.security:micronaut-security-jwt")
    implementation("io.micronaut.cache:micronaut-cache-caffeine")
    implementation("io.micronaut.redis:micronaut-redis-lettuce")
    implementation("io.micronaut.openapi:micronaut-openapi")
    implementation("io.micronaut.graphql:micronaut-graphql")
    implementation("io.micronaut.websocket:micronaut-websocket")
    implementation("io.micronaut.kafka:micronaut-kafka")
    implementation("io.micronaut.micrometer:micronaut-micrometer-core")
    implementation("io.micronaut.micrometer:micronaut-micrometer-registry-prometheus")
    implementation("io.micronaut.reactor:micronaut-reactor")
    implementation("io.micronaut.reactor:micronaut-reactor-http-client")
    implementation("io.micronaut.validation:micronaut-validation")
    implementation("io.micronaut.email:micronaut-email-javamail")
    implementation("io.micronaut.grpc:micronaut-grpc-server-runtime")
    implementation("jakarta.validation:jakarta.validation-api")
    implementation("jakarta.annotation:jakarta.annotation-api")
    implementation("at.favre.lib:bcrypt:0.10.2")
    runtimeOnly("ch.qos.logback:logback-classic")
    runtimeOnly("com.fasterxml.jackson.module:jackson-module-kotlin")
    runtimeOnly("org.postgresql:postgresql")
    runtimeOnly("com.h2database:h2")
    compileOnly("io.micronaut.openapi:micronaut-openapi-annotations")
    testImplementation("io.micronaut:micronaut-http-client")
    testImplementation("io.micronaut.test:micronaut-test-junit5")
    testImplementation("org.junit.jupiter:junit-jupiter-api")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine")`;
  }

  protected getFrameworkTasks(): string {
    return `micronaut {
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
    }
}

graalvmNative {
    toolchainDetection = false
}`;
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    const basePackage = options.organization || 'com.example';
    const srcDir = path.join(projectPath, 'src/main/kotlin', ...basePackage.split('.'));
    await fs.mkdir(srcDir, { recursive: true });

    await this.generateApplication(srcDir, basePackage, options);
    await this.generateControllers(srcDir, basePackage);
    await this.generateServices(srcDir, basePackage);
    await this.generateRepositories(srcDir, basePackage);
    await this.generateEntities(srcDir, basePackage);
    await this.generateDtos(srcDir, basePackage);
    await this.generateSecurity(srcDir, basePackage);
    await this.generateConfiguration(srcDir, basePackage);
    await this.generateWebSocket(srcDir, basePackage);
    await this.generateGraphQL(srcDir, basePackage);
    await this.generateGrpc(srcDir, basePackage);
    await this.generateUtils(srcDir, basePackage);
    await this.generateResources(projectPath);
    await this.generateTests(projectPath, basePackage);
  }

  private async generateApplication(srcDir: string, basePackage: string, options: any): Promise<void> {
    const appContent = `package ${basePackage}

import io.micronaut.runtime.Micronaut
import io.swagger.v3.oas.annotations.*
import io.swagger.v3.oas.annotations.info.*

@OpenAPIDefinition(
    info = Info(
        title = "${options.name}",
        version = "1.0",
        description = "Micronaut backend API",
        license = License(name = "Apache 2.0", url = "https://www.apache.org/licenses/LICENSE-2.0"),
        contact = Contact(name = "Support", email = "support@example.com")
    )
)
object Application {
    @JvmStatic
    fun main(args: Array<String>) {
        Micronaut.run(Application::class.java, *args)
    }
}`;

    await fs.writeFile(
      path.join(srcDir, 'Application.kt'),
      appContent
    );
  }

  private async generateControllers(srcDir: string, basePackage: string): Promise<void> {
    const controllerDir = path.join(srcDir, 'controller');
    await fs.mkdir(controllerDir, { recursive: true });

    const userControllerContent = `package ${basePackage}.controller

import ${basePackage}.dto.*
import ${basePackage}.service.UserService
import io.micronaut.data.model.Page
import io.micronaut.data.model.Pageable
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.*
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.security.SecurityRequirement
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import reactor.core.publisher.Mono

@Controller("/api/v1/users")
@Tag(name = "Users", description = "User management APIs")
@SecurityRequirement(name = "bearer-key")
@Secured(SecurityRule.IS_AUTHENTICATED)
class UserController(private val userService: UserService) {
    
    @Get
    @Operation(summary = "Get all users")
    @Secured("ADMIN")
    fun getAllUsers(pageable: Pageable): Mono<Page<UserDto>> {
        return userService.findAll(pageable)
    }
    
    @Get("/{id}")
    @Operation(summary = "Get user by ID")
    fun getUserById(@PathVariable id: Long): Mono<HttpResponse<UserDto>> {
        return userService.findById(id)
            .map { HttpResponse.ok(it) }
            .switchIfEmpty(Mono.just(HttpResponse.notFound()))
    }
    
    @Get("/me")
    @Operation(summary = "Get current user")
    fun getCurrentUser(): Mono<UserDto> {
        return userService.getCurrentUser()
    }
    
    @Put("/{id}")
    @Operation(summary = "Update user")
    fun updateUser(
        @PathVariable id: Long,
        @Valid @Body updateUserDto: UpdateUserDto
    ): Mono<HttpResponse<UserDto>> {
        return userService.update(id, updateUserDto)
            .map { HttpResponse.ok(it) }
            .switchIfEmpty(Mono.just(HttpResponse.notFound()))
    }
    
    @Delete("/{id}")
    @Operation(summary = "Delete user")
    @Secured("ADMIN")
    @Status(HttpStatus.NO_CONTENT)
    fun deleteUser(@PathVariable id: Long): Mono<HttpResponse<Void>> {
        return userService.delete(id)
            .map { HttpResponse.noContent<Void>() }
    }
}`;

    await fs.writeFile(
      path.join(controllerDir, 'UserController.kt'),
      userControllerContent
    );

    const authControllerContent = `package ${basePackage}.controller

import ${basePackage}.dto.*
import ${basePackage}.service.AuthService
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.*
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import reactor.core.publisher.Mono

@Controller("/api/v1/auth")
@Tag(name = "Authentication", description = "Authentication APIs")
@Secured(SecurityRule.IS_ANONYMOUS)
class AuthController(private val authService: AuthService) {
    
    @Post("/register")
    @Operation(summary = "Register new user")
    @Status(HttpStatus.CREATED)
    fun register(@Valid @Body registerDto: RegisterDto): Mono<TokenDto> {
        return authService.register(registerDto)
    }
    
    @Post("/login")
    @Operation(summary = "Login user")
    fun login(@Valid @Body loginDto: LoginDto): Mono<TokenDto> {
        return authService.login(loginDto)
    }
    
    @Post("/refresh")
    @Operation(summary = "Refresh access token")
    fun refresh(@Valid @Body refreshTokenDto: RefreshTokenDto): Mono<TokenDto> {
        return authService.refresh(refreshTokenDto)
    }
    
    @Post("/logout")
    @Operation(summary = "Logout user")
    @Status(HttpStatus.NO_CONTENT)
    @Secured(SecurityRule.IS_AUTHENTICATED)
    fun logout(@Header("Authorization") token: String): Mono<HttpResponse<Void>> {
        return authService.logout(token)
            .map { HttpResponse.noContent() }
    }
}`;

    await fs.writeFile(
      path.join(controllerDir, 'AuthController.kt'),
      authControllerContent
    );

    const healthControllerContent = `package ${basePackage}.controller

import io.micronaut.health.HealthStatus
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.management.health.indicator.HealthIndicator
import io.micronaut.management.health.indicator.HealthResult
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.Tag
import reactor.core.publisher.Mono
import jakarta.inject.Singleton

@Controller("/api/v1/health")
@Tag(name = "Health", description = "Health check APIs")
class HealthController {
    
    @Get
    @Operation(summary = "Health check")
    fun health(): Map<String, Any> {
        return mapOf(
            "status" to "UP",
            "timestamp" to System.currentTimeMillis(),
            "service" to "micronaut-api"
        )
    }
}

@Singleton
class CustomHealthIndicator : HealthIndicator {
    override fun getResult(): Mono<HealthResult> {
        return Mono.just(
            HealthResult.builder("custom")
                .status(HealthStatus.UP)
                .details(mapOf("service" to "micronaut-api"))
                .build()
        )
    }
}`;

    await fs.writeFile(
      path.join(controllerDir, 'HealthController.kt'),
      healthControllerContent
    );
  }

  private async generateServices(srcDir: string, basePackage: string): Promise<void> {
    const serviceDir = path.join(srcDir, 'service');
    await fs.mkdir(serviceDir, { recursive: true });

    const userServiceContent = `package ${basePackage}.service

import ${basePackage}.dto.*
import ${basePackage}.entity.User
import ${basePackage}.repository.UserRepository
import ${basePackage}.security.SecurityUtils
import io.micronaut.cache.annotation.CacheInvalidate
import io.micronaut.cache.annotation.Cacheable
import io.micronaut.data.model.Page
import io.micronaut.data.model.Pageable
import jakarta.inject.Singleton
import jakarta.transaction.Transactional
import reactor.core.publisher.Mono

@Singleton
@Transactional
open class UserService(
    private val userRepository: UserRepository,
    private val securityUtils: SecurityUtils
) {
    
    @Cacheable("users")
    open fun findAll(pageable: Pageable): Mono<Page<UserDto>> {
        return Mono.fromCallable {
            userRepository.findAll(pageable).map { it.toDto() }
        }
    }
    
    @Cacheable("users", key = "#id")
    open fun findById(id: Long): Mono<UserDto?> {
        return Mono.fromCallable {
            userRepository.findById(id).orElse(null)?.toDto()
        }
    }
    
    open fun findByEmail(email: String): Mono<User?> {
        return Mono.fromCallable {
            userRepository.findByEmail(email).orElse(null)
        }
    }
    
    open fun getCurrentUser(): Mono<UserDto> {
        return securityUtils.getCurrentUserEmail()
            .flatMap { email -> findByEmail(email) }
            .map { it?.toDto() ?: throw IllegalStateException("Current user not found") }
    }
    
    @CacheInvalidate("users", key = "#id")
    open fun update(id: Long, updateUserDto: UpdateUserDto): Mono<UserDto?> {
        return Mono.fromCallable {
            userRepository.findById(id).orElse(null)?.let { user ->
                updateUserDto.name?.let { user.name = it }
                updateUserDto.email?.let { user.email = it }
                userRepository.update(user).toDto()
            }
        }
    }
    
    @CacheInvalidate("users", key = "#id")
    open fun delete(id: Long): Mono<Unit> {
        return Mono.fromCallable {
            userRepository.deleteById(id)
        }
    }
    
    private fun User.toDto(): UserDto = UserDto(
        id = this.id!!,
        email = this.email,
        name = this.name,
        roles = this.roles.map { it.name },
        createdAt = this.createdAt,
        updatedAt = this.updatedAt
    )
}`;

    await fs.writeFile(
      path.join(serviceDir, 'UserService.kt'),
      userServiceContent
    );

    const authServiceContent = `package ${basePackage}.service

import ${basePackage}.dto.*
import ${basePackage}.entity.User
import ${basePackage}.entity.Role
import ${basePackage}.repository.UserRepository
import ${basePackage}.repository.RoleRepository
import ${basePackage}.security.JwtTokenProvider
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.AuthenticationException
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.Authenticator
import jakarta.inject.Singleton
import jakarta.transaction.Transactional
import reactor.core.publisher.Mono
import java.time.LocalDateTime
import at.favre.lib.crypto.bcrypt.BCrypt

@Singleton
@Transactional
open class AuthService(
    private val userRepository: UserRepository,
    private val roleRepository: RoleRepository,
    private val jwtTokenProvider: JwtTokenProvider
) : Authenticator<AuthenticationRequest<String, String>, AuthenticationResponse> {
    
    open fun register(registerDto: RegisterDto): Mono<TokenDto> {
        return Mono.fromCallable {
            if (userRepository.existsByEmail(registerDto.email)) {
                throw IllegalArgumentException("Email already registered")
            }
            
            val userRole = roleRepository.findByName("ROLE_USER").orElseThrow {
                IllegalStateException("Default role not found")
            }
            
            val user = User(
                email = registerDto.email,
                password = BCrypt.withDefaults().hashToString(12, registerDto.password.toCharArray()),
                name = registerDto.name,
                roles = mutableSetOf(userRole),
                isEnabled = true,
                createdAt = LocalDateTime.now(),
                updatedAt = LocalDateTime.now()
            )
            
            userRepository.save(user)
            generateTokens(user)
        }
    }
    
    open fun login(loginDto: LoginDto): Mono<TokenDto> {
        return authenticate(
            AuthenticationRequest.build(loginDto.email, loginDto.password)
        ).map { auth ->
            val user = userRepository.findByEmail(auth.name).orElseThrow()
            generateTokens(user)
        }
    }
    
    open fun refresh(refreshTokenDto: RefreshTokenDto): Mono<TokenDto> {
        return Mono.fromCallable {
            val email = jwtTokenProvider.validateTokenAndGetEmail(refreshTokenDto.refreshToken)
            val user = userRepository.findByEmail(email).orElseThrow {
                IllegalArgumentException("User not found")
            }
            generateTokens(user)
        }
    }
    
    open fun logout(token: String): Mono<Unit> {
        return Mono.fromCallable {
            jwtTokenProvider.invalidateToken(token)
        }
    }
    
    override fun authenticate(
        httpRequest: AuthenticationRequest<String, String>?
    ): Mono<AuthenticationResponse> {
        return Mono.fromCallable {
            val email = httpRequest?.identity ?: throw AuthenticationException("Invalid credentials")
            val password = httpRequest.secret ?: throw AuthenticationException("Invalid credentials")
            
            val user = userRepository.findByEmail(email).orElseThrow {
                AuthenticationException("Invalid credentials")
            }
            
            if (!BCrypt.verifyer().verify(password.toCharArray(), user.password).verified) {
                throw AuthenticationException("Invalid credentials")
            }
            
            AuthenticationResponse.success(
                user.email,
                user.roles.map { it.name }
            )
        }
    }
    
    private fun generateTokens(user: User): TokenDto {
        val accessToken = jwtTokenProvider.createAccessToken(user.email, user.roles.map { it.name })
        val refreshToken = jwtTokenProvider.createRefreshToken(user.email)
        
        return TokenDto(
            accessToken = accessToken,
            refreshToken = refreshToken,
            tokenType = "Bearer",
            expiresIn = jwtTokenProvider.accessTokenValidityInMilliseconds / 1000
        )
    }
}`;

    await fs.writeFile(
      path.join(serviceDir, 'AuthService.kt'),
      authServiceContent
    );
  }

  private async generateRepositories(srcDir: string, basePackage: string): Promise<void> {
    const repoDir = path.join(srcDir, 'repository');
    await fs.mkdir(repoDir, { recursive: true });

    const userRepoContent = `package ${basePackage}.repository

import ${basePackage}.entity.User
import io.micronaut.data.annotation.Query
import io.micronaut.data.annotation.Repository
import io.micronaut.data.jpa.repository.JpaRepository
import java.util.Optional

@Repository
interface UserRepository : JpaRepository<User, Long> {
    fun findByEmail(email: String): Optional<User>
    
    fun existsByEmail(email: String): Boolean
    
    @Query("SELECT u FROM User u LEFT JOIN FETCH u.roles WHERE u.email = :email")
    fun findByEmailWithRoles(email: String): Optional<User>
    
    @Query("SELECT u FROM User u WHERE u.isEnabled = true")
    fun findAllActive(): List<User>
}`;

    await fs.writeFile(
      path.join(repoDir, 'UserRepository.kt'),
      userRepoContent
    );

    const roleRepoContent = `package ${basePackage}.repository

import ${basePackage}.entity.Role
import io.micronaut.data.annotation.Repository
import io.micronaut.data.jpa.repository.JpaRepository
import java.util.Optional

@Repository
interface RoleRepository : JpaRepository<Role, Long> {
    fun findByName(name: String): Optional<Role>
}`;

    await fs.writeFile(
      path.join(repoDir, 'RoleRepository.kt'),
      roleRepoContent
    );
  }

  private async generateEntities(srcDir: string, basePackage: string): Promise<void> {
    const entityDir = path.join(srcDir, 'entity');
    await fs.mkdir(entityDir, { recursive: true });

    const userEntityContent = `package ${basePackage}.entity

import io.micronaut.data.annotation.GeneratedValue
import io.micronaut.data.annotation.Id
import io.micronaut.data.annotation.MappedEntity
import io.micronaut.security.authentication.Authentication
import jakarta.persistence.*
import java.security.Principal
import java.time.LocalDateTime

@MappedEntity("users")
@Entity
@Table(name = "users")
data class User(
    @field:Id
    @field:GeneratedValue(GeneratedValue.Type.IDENTITY)
    val id: Long? = null,
    
    @Column(unique = true, nullable = false)
    var email: String,
    
    @Column(nullable = false)
    var password: String,
    
    @Column(nullable = false)
    var name: String,
    
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "user_roles",
        joinColumns = [JoinColumn(name = "user_id")],
        inverseJoinColumns = [JoinColumn(name = "role_id")]
    )
    var roles: MutableSet<Role> = mutableSetOf(),
    
    @Column(nullable = false)
    var isEnabled: Boolean = true,
    
    @Column(nullable = false)
    var createdAt: LocalDateTime = LocalDateTime.now(),
    
    @Column(nullable = false)
    var updatedAt: LocalDateTime = LocalDateTime.now()
) : Principal {
    
    override fun getName(): String = email
    
    @PreUpdate
    fun preUpdate() {
        updatedAt = LocalDateTime.now()
    }
}`;

    await fs.writeFile(
      path.join(entityDir, 'User.kt'),
      userEntityContent
    );

    const roleEntityContent = `package ${basePackage}.entity

import io.micronaut.data.annotation.GeneratedValue
import io.micronaut.data.annotation.Id
import io.micronaut.data.annotation.MappedEntity
import jakarta.persistence.*

@MappedEntity("roles")
@Entity
@Table(name = "roles")
data class Role(
    @field:Id
    @field:GeneratedValue(GeneratedValue.Type.IDENTITY)
    val id: Long? = null,
    
    @Column(unique = true, nullable = false)
    val name: String,
    
    @Column
    val description: String? = null
)`;

    await fs.writeFile(
      path.join(entityDir, 'Role.kt'),
      roleEntityContent
    );
  }

  private async generateDtos(srcDir: string, basePackage: string): Promise<void> {
    const dtoDir = path.join(srcDir, 'dto');
    await fs.mkdir(dtoDir, { recursive: true });

    const userDtoContent = `package ${basePackage}.dto

import com.fasterxml.jackson.annotation.JsonFormat
import io.micronaut.core.annotation.Introspected
import java.time.LocalDateTime

@Introspected
data class UserDto(
    val id: Long,
    val email: String,
    val name: String,
    val roles: List<String>,
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    val createdAt: LocalDateTime,
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    val updatedAt: LocalDateTime
)

@Introspected
data class CreateUserDto(
    val email: String,
    val password: String,
    val name: String
)

@Introspected
data class UpdateUserDto(
    val name: String? = null,
    val email: String? = null
)`;

    await fs.writeFile(
      path.join(dtoDir, 'UserDto.kt'),
      userDtoContent
    );

    const authDtoContent = `package ${basePackage}.dto

import io.micronaut.core.annotation.Introspected
import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size

@Introspected
data class RegisterDto(
    @field:NotBlank(message = "Email is required")
    @field:Email(message = "Invalid email format")
    val email: String,
    
    @field:NotBlank(message = "Password is required")
    @field:Size(min = 8, message = "Password must be at least 8 characters")
    val password: String,
    
    @field:NotBlank(message = "Name is required")
    val name: String
)

@Introspected
data class LoginDto(
    @field:NotBlank(message = "Email is required")
    @field:Email(message = "Invalid email format")
    val email: String,
    
    @field:NotBlank(message = "Password is required")
    val password: String
)

@Introspected
data class TokenDto(
    val accessToken: String,
    val refreshToken: String,
    val tokenType: String = "Bearer",
    val expiresIn: Long
)

@Introspected
data class RefreshTokenDto(
    @field:NotBlank(message = "Refresh token is required")
    val refreshToken: String
)`;

    await fs.writeFile(
      path.join(dtoDir, 'AuthDto.kt'),
      authDtoContent
    );

    const errorDtoContent = `package ${basePackage}.dto

import com.fasterxml.jackson.annotation.JsonFormat
import io.micronaut.core.annotation.Introspected
import java.time.LocalDateTime

@Introspected
data class ErrorDto(
    val status: Int,
    val error: String,
    val message: String?,
    val path: String,
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    val timestamp: LocalDateTime = LocalDateTime.now()
)

@Introspected
data class ValidationErrorDto(
    val field: String,
    val message: String
)

@Introspected
data class ApiResponse<T>(
    val success: Boolean,
    val data: T? = null,
    val error: String? = null,
    val timestamp: Long = System.currentTimeMillis()
)`;

    await fs.writeFile(
      path.join(dtoDir, 'ErrorDto.kt'),
      errorDtoContent
    );
  }

  private async generateSecurity(srcDir: string, basePackage: string): Promise<void> {
    const securityDir = path.join(srcDir, 'security');
    await fs.mkdir(securityDir, { recursive: true });

    const jwtTokenProviderContent = `package ${basePackage}.security

import io.jsonwebtoken.*
import io.jsonwebtoken.security.Keys
import io.micronaut.context.annotation.Value
import jakarta.inject.Singleton
import java.util.*
import javax.crypto.SecretKey

@Singleton
class JwtTokenProvider {
    
    @Value("\\\${micronaut.security.token.jwt.generator.secret}")
    private lateinit var jwtSecret: String
    
    @Value("\\\${app.jwt.access-token-expiration:3600000}")
    val accessTokenValidityInMilliseconds: Long = 3600000
    
    @Value("\\\${app.jwt.refresh-token-expiration:2592000000}")
    private val refreshTokenValidityInMilliseconds: Long = 2592000000
    
    private val key: SecretKey by lazy {
        Keys.hmacShaKeyFor(jwtSecret.toByteArray())
    }
    
    fun createAccessToken(email: String, roles: List<String>): String {
        val now = Date()
        val validity = Date(now.time + accessTokenValidityInMilliseconds)
        
        return Jwts.builder()
            .setSubject(email)
            .claim("roles", roles)
            .setIssuedAt(now)
            .setExpiration(validity)
            .signWith(key)
            .compact()
    }
    
    fun createRefreshToken(email: String): String {
        val now = Date()
        val validity = Date(now.time + refreshTokenValidityInMilliseconds)
        
        return Jwts.builder()
            .setSubject(email)
            .setIssuedAt(now)
            .setExpiration(validity)
            .signWith(key)
            .compact()
    }
    
    fun validateTokenAndGetEmail(token: String): String {
        return try {
            val claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .body
            
            claims.subject
        } catch (e: JwtException) {
            throw IllegalArgumentException("Invalid JWT token", e)
        }
    }
    
    fun invalidateToken(token: String) {
        // Add to Redis blacklist
    }
}`;

    await fs.writeFile(
      path.join(securityDir, 'JwtTokenProvider.kt'),
      jwtTokenProviderContent
    );

    const authenticationProviderContent = `package ${basePackage}.security

import io.micronaut.http.HttpRequest
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.AuthenticationFailed
import io.micronaut.security.authentication.AuthenticationFailureReason
import jakarta.inject.Singleton
import reactor.core.publisher.Mono
import ${basePackage}.repository.UserRepository
import at.favre.lib.crypto.bcrypt.BCrypt

@Singleton
class AuthenticationProviderUserPassword(
    private val userRepository: UserRepository
) : AuthenticationProvider<HttpRequest<*>, String, String> {
    
    override fun authenticate(
        httpRequest: HttpRequest<*>?,
        authenticationRequest: AuthenticationRequest<String, String>
    ): Mono<AuthenticationResponse> {
        return Mono.create { emitter ->
            val email = authenticationRequest.identity
            val password = authenticationRequest.secret
            
            userRepository.findByEmail(email).ifPresentOrElse({ user ->
                if (BCrypt.verifyer().verify(password.toCharArray(), user.password).verified && user.isEnabled) {
                    emitter.success(
                        AuthenticationResponse.success(
                            user.email,
                            user.roles.map { it.name }
                        )
                    )
                } else {
                    emitter.error(
                        AuthenticationFailed(AuthenticationFailureReason.CREDENTIALS_DO_NOT_MATCH)
                    )
                }
            }) {
                emitter.error(
                    AuthenticationFailed(AuthenticationFailureReason.USER_NOT_FOUND)
                )
            }
        }
    }
}`;

    await fs.writeFile(
      path.join(securityDir, 'AuthenticationProvider.kt'),
      authenticationProviderContent
    );

    const securityUtilsContent = `package ${basePackage}.security

import io.micronaut.security.authentication.Authentication
import io.micronaut.security.utils.SecurityService
import jakarta.inject.Singleton
import reactor.core.publisher.Mono

@Singleton
class SecurityUtils(
    private val securityService: SecurityService
) {
    
    fun getCurrentUserEmail(): Mono<String> {
        return Mono.fromCallable {
            securityService.authentication()
                .map { it.name }
                .orElseThrow { IllegalStateException("User not authenticated") }
        }
    }
    
    fun isAuthenticated(): Boolean {
        return securityService.isAuthenticated
    }
    
    fun hasRole(role: String): Boolean {
        return securityService.authentication()
            .map { auth ->
                auth.roles.contains(role)
            }
            .orElse(false)
    }
}`;

    await fs.writeFile(
      path.join(securityDir, 'SecurityUtils.kt'),
      securityUtilsContent
    );
  }

  private async generateConfiguration(srcDir: string, basePackage: string): Promise<void> {
    const configDir = path.join(srcDir, 'config');
    await fs.mkdir(configDir, { recursive: true });

    const corsConfigContent = `package ${basePackage}.config

import io.micronaut.context.annotation.ConfigurationProperties
import io.micronaut.context.annotation.Requires
import io.micronaut.core.annotation.Nullable
import io.micronaut.http.HttpMethod

@ConfigurationProperties("app.cors")
@Requires(property = "app.cors.enabled", value = "true")
class CorsConfiguration {
    var enabled: Boolean = true
    
    @Nullable
    var allowedOrigins: List<String>? = null
    
    var allowedMethods: List<HttpMethod> = listOf(
        HttpMethod.GET,
        HttpMethod.POST,
        HttpMethod.PUT,
        HttpMethod.DELETE,
        HttpMethod.OPTIONS
    )
    
    var allowedHeaders: List<String> = listOf("*")
    
    var exposedHeaders: List<String> = listOf()
    
    var allowCredentials: Boolean = true
    
    var maxAge: Long = 3600
}`;

    await fs.writeFile(
      path.join(configDir, 'CorsConfiguration.kt'),
      corsConfigContent
    );

    const dataInitializerContent = `package ${basePackage}.config

import ${basePackage}.entity.Role
import ${basePackage}.repository.RoleRepository
import io.micronaut.context.annotation.Requires
import io.micronaut.context.event.StartupEvent
import io.micronaut.runtime.event.annotation.EventListener
import jakarta.inject.Singleton
import jakarta.transaction.Transactional

@Singleton
@Requires(property = "app.data.initialize", value = "true", defaultValue = "false")
open class DataInitializer(
    private val roleRepository: RoleRepository
) {
    
    @EventListener
    @Transactional
    open fun onStartup(event: StartupEvent) {
        initializeRoles()
    }
    
    private fun initializeRoles() {
        val roles = listOf(
            Role(name = "ROLE_USER", description = "Default user role"),
            Role(name = "ROLE_ADMIN", description = "Administrator role"),
            Role(name = "ROLE_MODERATOR", description = "Moderator role")
        )
        
        roles.forEach { role ->
            if (!roleRepository.findByName(role.name).isPresent) {
                roleRepository.save(role)
            }
        }
    }
}`;

    await fs.writeFile(
      path.join(configDir, 'DataInitializer.kt'),
      dataInitializerContent
    );
  }

  private async generateWebSocket(srcDir: string, basePackage: string): Promise<void> {
    const wsDir = path.join(srcDir, 'websocket');
    await fs.mkdir(wsDir, { recursive: true });

    const wsServerContent = `package ${basePackage}.websocket

import io.micronaut.websocket.WebSocketBroadcaster
import io.micronaut.websocket.WebSocketSession
import io.micronaut.websocket.annotation.OnClose
import io.micronaut.websocket.annotation.OnMessage
import io.micronaut.websocket.annotation.OnOpen
import io.micronaut.websocket.annotation.ServerWebSocket
import reactor.core.publisher.Mono
import java.util.concurrent.ConcurrentHashMap

@ServerWebSocket("/ws/chat/{topic}/{username}")
class ChatWebSocket(
    private val broadcaster: WebSocketBroadcaster
) {
    private val sessions = ConcurrentHashMap<String, WebSocketSession>()
    
    @OnOpen
    fun onOpen(topic: String, username: String, session: WebSocketSession): Mono<Void> {
        return Mono.fromCallable {
            sessions[session.id] = session
            broadcaster.broadcastSync(
                ChatMessage(
                    from = "System",
                    content = "$username joined the chat",
                    topic = topic
                ),
                isValid(topic)
            )
        }.then()
    }
    
    @OnMessage
    fun onMessage(
        topic: String,
        username: String,
        message: String,
        session: WebSocketSession
    ): Mono<Void> {
        return Mono.fromCallable {
            broadcaster.broadcastSync(
                ChatMessage(
                    from = username,
                    content = message,
                    topic = topic
                ),
                isValid(topic)
            )
        }.then()
    }
    
    @OnClose
    fun onClose(
        topic: String,
        username: String,
        session: WebSocketSession
    ): Mono<Void> {
        return Mono.fromCallable {
            sessions.remove(session.id)
            broadcaster.broadcastSync(
                ChatMessage(
                    from = "System",
                    content = "$username left the chat",
                    topic = topic
                ),
                isValid(topic)
            )
        }.then()
    }
    
    private fun isValid(topic: String): (WebSocketSession) -> Boolean = { session ->
        session.uriVariables["topic"] == topic
    }
}

data class ChatMessage(
    val from: String,
    val content: String,
    val topic: String,
    val timestamp: Long = System.currentTimeMillis()
)`;

    await fs.writeFile(
      path.join(wsDir, 'ChatWebSocket.kt'),
      wsServerContent
    );
  }

  private async generateGraphQL(srcDir: string, basePackage: string): Promise<void> {
    const graphqlDir = path.join(srcDir, 'graphql');
    await fs.mkdir(graphqlDir, { recursive: true });

    const queryResolverContent = `package ${basePackage}.graphql

import ${basePackage}.dto.UserDto
import ${basePackage}.service.UserService
import graphql.kickstart.tools.GraphQLQueryResolver
import io.micronaut.data.model.PageRequest
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import jakarta.inject.Singleton
import reactor.core.publisher.Mono
import reactor.core.publisher.Flux

@Singleton
@Secured(SecurityRule.IS_AUTHENTICATED)
class UserQueryResolver(
    private val userService: UserService
) : GraphQLQueryResolver {
    
    fun user(id: Long): Mono<UserDto?> {
        return userService.findById(id)
    }
    
    @Secured("ADMIN")
    fun users(page: Int = 0, size: Int = 10): Flux<UserDto> {
        return userService.findAll(PageRequest.of(page, size))
            .flatMapMany { Flux.fromIterable(it.content) }
    }
    
    fun me(): Mono<UserDto> {
        return userService.getCurrentUser()
    }
}`;

    await fs.writeFile(
      path.join(graphqlDir, 'UserQueryResolver.kt'),
      queryResolverContent
    );

    const mutationResolverContent = `package ${basePackage}.graphql

import ${basePackage}.dto.*
import ${basePackage}.service.AuthService
import ${basePackage}.service.UserService
import graphql.kickstart.tools.GraphQLMutationResolver
import io.micronaut.security.annotation.Secured
import io.micronaut.security.rules.SecurityRule
import jakarta.inject.Singleton
import reactor.core.publisher.Mono

@Singleton
class UserMutationResolver(
    private val authService: AuthService,
    private val userService: UserService
) : GraphQLMutationResolver {
    
    @Secured(SecurityRule.IS_ANONYMOUS)
    fun register(input: RegisterDto): Mono<TokenDto> {
        return authService.register(input)
    }
    
    @Secured(SecurityRule.IS_ANONYMOUS)
    fun login(input: LoginDto): Mono<TokenDto> {
        return authService.login(input)
    }
    
    @Secured(SecurityRule.IS_AUTHENTICATED)
    fun updateUser(id: Long, input: UpdateUserDto): Mono<UserDto?> {
        return userService.update(id, input)
    }
}`;

    await fs.writeFile(
      path.join(graphqlDir, 'UserMutationResolver.kt'),
      mutationResolverContent
    );

    const graphqlFactoryContent = `package ${basePackage}.graphql

import graphql.GraphQL
import graphql.kickstart.tools.SchemaParser
import io.micronaut.context.annotation.Factory
import io.micronaut.core.io.ResourceResolver
import jakarta.inject.Singleton

@Factory
class GraphQLFactory {
    
    @Singleton
    fun graphQL(
        resourceResolver: ResourceResolver,
        userQueryResolver: UserQueryResolver,
        userMutationResolver: UserMutationResolver
    ): GraphQL {
        val schemaParser = SchemaParser.newParser()
            .file("schema.graphqls")
            .resolvers(userQueryResolver, userMutationResolver)
            .build()
        
        return GraphQL.newGraphQL(schemaParser.makeExecutableSchema())
            .build()
    }
}`;

    await fs.writeFile(
      path.join(graphqlDir, 'GraphQLFactory.kt'),
      graphqlFactoryContent
    );
  }

  private async generateGrpc(srcDir: string, basePackage: string): Promise<void> {
    const grpcDir = path.join(srcDir, 'grpc');
    await fs.mkdir(grpcDir, { recursive: true });

    const userGrpcServiceContent = `package ${basePackage}.grpc

import ${basePackage}.dto.UserDto
import ${basePackage}.service.UserService
import io.grpc.Status
import io.grpc.StatusException
import io.grpc.stub.StreamObserver
import io.micronaut.grpc.annotation.GrpcService
import jakarta.inject.Inject

@GrpcService
class UserGrpcService : UserServiceGrpc.UserServiceImplBase() {
    
    @Inject
    lateinit var userService: UserService
    
    override fun getUser(
        request: GetUserRequest,
        responseObserver: StreamObserver<UserResponse>
    ) {
        userService.findById(request.id)
            .subscribe(
                { user ->
                    user?.let {
                        responseObserver.onNext(it.toGrpcResponse())
                        responseObserver.onCompleted()
                    } ?: run {
                        responseObserver.onError(
                            StatusException(Status.NOT_FOUND.withDescription("User not found"))
                        )
                    }
                },
                { error ->
                    responseObserver.onError(
                        StatusException(Status.INTERNAL.withDescription(error.message))
                    )
                }
            )
    }
    
    override fun listUsers(
        request: ListUsersRequest,
        responseObserver: StreamObserver<UserResponse>
    ) {
        userService.findAll(
            io.micronaut.data.model.PageRequest.of(request.page, request.size)
        ).subscribe(
            { page ->
                page.content.forEach { user ->
                    responseObserver.onNext(user.toGrpcResponse())
                }
                responseObserver.onCompleted()
            },
            { error ->
                responseObserver.onError(
                    StatusException(Status.INTERNAL.withDescription(error.message))
                )
            }
        )
    }
    
    private fun UserDto.toGrpcResponse(): UserResponse {
        return UserResponse.newBuilder()
            .setId(id)
            .setEmail(email)
            .setName(name)
            .addAllRoles(roles)
            .setCreatedAt(createdAt.toString())
            .setUpdatedAt(updatedAt.toString())
            .build()
    }
}`;

    await fs.writeFile(
      path.join(grpcDir, 'UserGrpcService.kt'),
      userGrpcServiceContent
    );
  }

  private async generateUtils(srcDir: string, basePackage: string): Promise<void> {
    const utilsDir = path.join(srcDir, 'utils');
    await fs.mkdir(utilsDir, { recursive: true });

    const validationUtilsContent = `package ${basePackage}.utils

object ValidationUtils {
    
    fun isValidEmail(email: String): Boolean {
        val emailRegex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\$".toRegex()
        return email.matches(emailRegex)
    }
    
    fun isStrongPassword(password: String): Boolean {
        return password.length >= 8 &&
               password.any { it.isUpperCase() } &&
               password.any { it.isLowerCase() } &&
               password.any { it.isDigit() } &&
               password.any { !it.isLetterOrDigit() }
    }
    
    fun sanitizeInput(input: String): String {
        return input.trim()
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#x27;")
            .replace("&", "&amp;")
    }
}`;

    await fs.writeFile(
      path.join(utilsDir, 'ValidationUtils.kt'),
      validationUtilsContent
    );

    const errorHandlerContent = `package ${basePackage}.utils

import ${basePackage}.dto.ErrorDto
import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import io.micronaut.http.annotation.Produces
import io.micronaut.http.server.exceptions.ExceptionHandler
import jakarta.inject.Singleton

@Produces
@Singleton
@Requires(classes = [IllegalArgumentException::class, ExceptionHandler::class])
class IllegalArgumentExceptionHandler : ExceptionHandler<IllegalArgumentException, HttpResponse<ErrorDto>> {
    
    override fun handle(request: HttpRequest<*>, exception: IllegalArgumentException): HttpResponse<ErrorDto> {
        return HttpResponse.badRequest(
            ErrorDto(
                status = HttpStatus.BAD_REQUEST.code,
                error = "Bad Request",
                message = exception.message,
                path = request.path
            )
        )
    }
}

@Produces
@Singleton
@Requires(classes = [NoSuchElementException::class, ExceptionHandler::class])
class NotFoundExceptionHandler : ExceptionHandler<NoSuchElementException, HttpResponse<ErrorDto>> {
    
    override fun handle(request: HttpRequest<*>, exception: NoSuchElementException): HttpResponse<ErrorDto> {
        return HttpResponse.notFound(
            ErrorDto(
                status = HttpStatus.NOT_FOUND.code,
                error = "Not Found",
                message = exception.message ?: "Resource not found",
                path = request.path
            )
        )
    }
}`;

    await fs.writeFile(
      path.join(utilsDir, 'ErrorHandler.kt'),
      errorHandlerContent
    );
  }

  private async generateResources(projectPath: string): Promise<void> {
    const resourcesDir = path.join(projectPath, 'src/main/resources');
    await fs.mkdir(resourcesDir, { recursive: true });

    const applicationYaml = `micronaut:
  application:
    name: micronaut-api
  server:
    port: \${PORT:8080}
    cors:
      enabled: true
      configurations:
        web:
          allowedOrigins:
            - http://localhost:3000
            - http://localhost:4200
          allowedMethods:
            - GET
            - POST
            - PUT
            - DELETE
            - OPTIONS
          allowedHeaders:
            - Content-Type
            - Authorization
          exposedHeaders:
            - Content-Type
            - Authorization
          allowCredentials: true
          maxAge: 3600
  security:
    enabled: true
    endpoints:
      login:
        enabled: false
      oauth:
        enabled: false
    token:
      jwt:
        enabled: true
        signatures:
          secret:
            generator:
              secret: \${JWT_SECRET:your-secret-key-here-please-change-in-production}
        generator:
          access-token:
            expiration: 3600
          refresh-token:
            enabled: true
            expiration: 2592000
    intercept-url-map:
      - pattern: /swagger/**
        access:
          - isAnonymous()
      - pattern: /api/v1/auth/**
        access:
          - isAnonymous()
      - pattern: /api/v1/health/**
        access:
          - isAnonymous()
  metrics:
    enabled: true
    export:
      prometheus:
        enabled: true
        step: PT1M
        descriptions: true
  router:
    static-resources:
      swagger:
        paths: classpath:META-INF/swagger
        mapping: /swagger/**

datasources:
  default:
    url: jdbc:postgresql://\${DB_HOST:localhost}:\${DB_PORT:5432}/\${DB_NAME:app_db}
    driverClassName: org.postgresql.Driver
    username: \${DB_USER:postgres}
    password: \${DB_PASSWORD:postgres}
    dialect: POSTGRES
    schema-generate: UPDATE
    
jpa:
  default:
    properties:
      hibernate:
        hbm2ddl:
          auto: update
        show_sql: false
        format_sql: true

redis:
  uri: redis://\${REDIS_HOST:localhost}:\${REDIS_PORT:6379}
  password: \${REDIS_PASSWORD:}

kafka:
  bootstrap:
    servers: \${KAFKA_SERVERS:localhost:9092}
  
graphql:
  enabled: true
  path: /graphql
  graphiql:
    enabled: true
    path: /graphiql

grpc:
  server:
    port: 50051
    keep-alive-time: 30s

jackson:
  serialization:
    write-dates-as-timestamps: false
  
app:
  data:
    initialize: true
  jwt:
    access-token-expiration: 3600000
    refresh-token-expiration: 2592000000`;

    await fs.writeFile(
      path.join(resourcesDir, 'application.yml'),
      applicationYaml
    );

    const logbackContent = `<configuration>
    <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>
    
    <root level="INFO">
        <appender-ref ref="STDOUT"/>
    </root>
    
    <logger name="com.example" level="DEBUG"/>
</configuration>`;

    await fs.writeFile(
      path.join(resourcesDir, 'logback.xml'),
      logbackContent
    );

    const graphqlSchema = `type Query {
  user(id: ID!): User
  users(page: Int = 0, size: Int = 10): [User!]!
  me: User!
}

type Mutation {
  register(input: RegisterInput!): AuthToken!
  login(input: LoginInput!): AuthToken!
  updateUser(id: ID!, input: UpdateUserInput!): User
}

type User {
  id: ID!
  email: String!
  name: String!
  roles: [String!]!
  createdAt: String!
  updatedAt: String!
}

type AuthToken {
  accessToken: String!
  refreshToken: String!
  tokenType: String!
  expiresIn: Int!
}

input RegisterInput {
  email: String!
  password: String!
  name: String!
}

input LoginInput {
  email: String!
  password: String!
}

input UpdateUserInput {
  name: String
  email: String
}`;

    await fs.writeFile(
      path.join(resourcesDir, 'schema.graphqls'),
      graphqlSchema
    );
  }

  private async generateTests(projectPath: string, basePackage: string): Promise<void> {
    const testDir = path.join(projectPath, 'src/test/kotlin', ...basePackage.split('.'));
    await fs.mkdir(testDir, { recursive: true });

    const userControllerTestContent = `package ${basePackage}.controller

import ${basePackage}.dto.*
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpStatus
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.annotation.Client
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import jakarta.inject.Inject
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

@MicronautTest
class UserControllerTest {

    @Inject
    @field:Client("/")
    lateinit var client: HttpClient

    @Test
    fun testHealthEndpoint() {
        val request = HttpRequest.GET<Map<String, Any>>("/api/v1/health")
        val response = client.toBlocking().exchange(request, Map::class.java)
        
        assertEquals(HttpStatus.OK, response.status)
        val body = response.body()
        assertNotNull(body)
        assertEquals("UP", body["status"])
    }

    @Test
    fun testUnauthorizedAccess() {
        val request = HttpRequest.GET<Any>("/api/v1/users")
        
        val exception = assertThrows(io.micronaut.http.client.exceptions.HttpClientResponseException::class.java) {
            client.toBlocking().exchange(request)
        }
        
        assertEquals(HttpStatus.UNAUTHORIZED, exception.status)
    }
}`;

    await fs.writeFile(
      path.join(testDir, 'controller/UserControllerTest.kt'),
      userControllerTestContent
    );

    const authServiceTestContent = `package ${basePackage}.service

import ${basePackage}.dto.RegisterDto
import ${basePackage}.repository.RoleRepository
import ${basePackage}.repository.UserRepository
import io.micronaut.test.extensions.junit5.annotation.MicronautTest
import jakarta.inject.Inject
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import reactor.test.StepVerifier

@MicronautTest(transactional = false)
class AuthServiceTest {

    @Inject
    lateinit var authService: AuthService

    @Inject
    lateinit var userRepository: UserRepository

    @Inject
    lateinit var roleRepository: RoleRepository

    @BeforeEach
    fun setup() {
        userRepository.deleteAll()
    }

    @Test
    fun testRegisterNewUser() {
        val registerDto = RegisterDto(
            email = "test@example.com",
            password = "password123",
            name = "Test User"
        )

        StepVerifier.create(authService.register(registerDto))
            .assertNext { token ->
                assertNotNull(token.accessToken)
                assertNotNull(token.refreshToken)
                assertEquals("Bearer", token.tokenType)
            }
            .verifyComplete()

        assertTrue(userRepository.existsByEmail("test@example.com"))
    }

    @Test
    fun testRegisterDuplicateEmail() {
        val registerDto = RegisterDto(
            email = "duplicate@example.com",
            password = "password123",
            name = "Test User"
        )

        authService.register(registerDto).block()

        StepVerifier.create(authService.register(registerDto))
            .expectError(IllegalArgumentException::class.java)
            .verify()
    }
}`;

    await fs.writeFile(
      path.join(testDir, 'service/AuthServiceTest.kt'),
      authServiceTestContent
    );

    const testResourcesDir = path.join(projectPath, 'src/test/resources');
    await fs.mkdir(testResourcesDir, { recursive: true });

    const testApplicationYaml = `micronaut:
  application:
    name: test-api

datasources:
  default:
    url: jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE
    driverClassName: org.h2.Driver
    username: sa
    password: ""
    dialect: H2
    schema-generate: CREATE_DROP

jpa:
  default:
    properties:
      hibernate:
        hbm2ddl:
          auto: create-drop
        show_sql: true

micronaut:
  security:
    token:
      jwt:
        signatures:
          secret:
            generator:
              secret: test-secret-key

app:
  data:
    initialize: true`;

    await fs.writeFile(
      path.join(testResourcesDir, 'application-test.yml'),
      testApplicationYaml
    );
  }
}

export default MicronautGenerator;