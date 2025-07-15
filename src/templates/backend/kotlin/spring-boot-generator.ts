import { KotlinBackendGenerator } from './kotlin-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class SpringBootGenerator extends KotlinBackendGenerator {
  constructor() {
    super('Spring Boot');
  }

  protected getFrameworkPlugins(): string {
    return `id("org.springframework.boot") version "3.2.0"
    id("io.spring.dependency-management") version "1.1.4"
    kotlin("plugin.spring") version "1.9.20"
    kotlin("plugin.jpa") version "1.9.20"`;
  }

  protected getFrameworkDependencies(): string {
    return `implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-webflux")
    implementation("org.springframework.boot:spring-boot-starter-data-jpa")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("org.springframework.boot:spring-boot-starter-cache")
    implementation("org.springframework.boot:spring-boot-starter-websocket")
    implementation("org.springframework.boot:spring-boot-starter-data-redis")
    implementation("org.springframework.boot:spring-boot-starter-oauth2-resource-server")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin")
    implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.3.0")
    implementation("org.springdoc:springdoc-openapi-starter-kotlin:2.3.0")
    implementation("org.springframework.kafka:spring-kafka")
    implementation("org.liquibase:liquibase-core")
    implementation("org.springframework.cloud:spring-cloud-starter-sleuth:3.1.9")
    implementation("org.springframework.boot:spring-boot-starter-graphql")
    implementation("com.graphql-java:graphql-java-extended-scalars:21.0")
    developmentOnly("org.springframework.boot:spring-boot-devtools")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.springframework.security:spring-security-test")
    testImplementation("org.springframework.boot:spring-boot-testcontainers")
    testImplementation("org.springframework.restdocs:spring-restdocs-mockmvc")
    testImplementation("com.ninja-squad:springmockk:4.0.2")`;
  }

  protected getFrameworkTasks(): string {
    return `springBoot {
    buildInfo()
}

tasks.bootJar {
    enabled = true
    archiveFileName.set("app.jar")
}

tasks.jar {
    enabled = false
}`;
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    const basePackage = options.organization || 'com.example';
    const srcDir = path.join(projectPath, 'src/main/kotlin', ...basePackage.split('.'));
    await fs.mkdir(srcDir, { recursive: true });

    await this.generateApplication(srcDir, basePackage, options);
    await this.generateConfiguration(srcDir, basePackage);
    await this.generateControllers(srcDir, basePackage);
    await this.generateServices(srcDir, basePackage);
    await this.generateRepositories(srcDir, basePackage);
    await this.generateEntities(srcDir, basePackage);
    await this.generateDtos(srcDir, basePackage);
    await this.generateSecurity(srcDir, basePackage);
    await this.generateExceptions(srcDir, basePackage);
    await this.generateWebSocket(srcDir, basePackage);
    await this.generateGraphQL(srcDir, basePackage);
    await this.generateUtils(srcDir, basePackage);
    await this.generateResources(projectPath);
    await this.generateTests(projectPath, basePackage);
  }

  private async generateApplication(srcDir: string, basePackage: string, options: any): Promise<void> {
    const appContent = `package ${basePackage}

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.cache.annotation.EnableCaching
import org.springframework.scheduling.annotation.EnableAsync
import org.springframework.scheduling.annotation.EnableScheduling

@SpringBootApplication
@EnableCaching
@EnableAsync
@EnableScheduling
class ${options.name.charAt(0).toUpperCase() + options.name.slice(1)}Application

fun main(args: Array<String>) {
    runApplication<${options.name.charAt(0).toUpperCase() + options.name.slice(1)}Application>(*args)
}`;

    await fs.writeFile(
      path.join(srcDir, `${options.name.charAt(0).toUpperCase() + options.name.slice(1)}Application.kt`),
      appContent
    );
  }

  private async generateConfiguration(srcDir: string, basePackage: string): Promise<void> {
    const configDir = path.join(srcDir, 'config');
    await fs.mkdir(configDir, { recursive: true });

    const webConfigContent = `package ${basePackage}.config

import org.springframework.context.annotation.Configuration
import org.springframework.web.servlet.config.annotation.CorsRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
class WebConfig : WebMvcConfigurer {
    
    @Value("\\\${app.cors.allowed-origins}")
    private lateinit var allowedOrigins: List<String>
    
    override fun addCorsMappings(registry: CorsRegistry) {
        registry.addMapping("/api/**")
            .allowedOrigins(*allowedOrigins.toTypedArray())
            .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
            .allowedHeaders("*")
            .allowCredentials(true)
            .maxAge(3600)
    }
    
    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource {
        val configuration = CorsConfiguration()
        configuration.allowedOrigins = allowedOrigins
        configuration.allowedMethods = listOf("*")
        configuration.allowedHeaders = listOf("*")
        configuration.allowCredentials = true
        
        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", configuration)
        return source
    }
}`;

    await fs.writeFile(
      path.join(configDir, 'WebConfig.kt'),
      webConfigContent
    );

    const cacheConfigContent = `package ${basePackage}.config

import org.springframework.cache.CacheManager
import org.springframework.cache.concurrent.ConcurrentMapCacheManager
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.redis.cache.RedisCacheConfiguration
import org.springframework.data.redis.cache.RedisCacheManager
import org.springframework.data.redis.connection.RedisConnectionFactory
import java.time.Duration

@Configuration
class CacheConfig {
    
    @Bean
    fun cacheManager(redisConnectionFactory: RedisConnectionFactory): CacheManager {
        val defaultConfig = RedisCacheConfiguration.defaultCacheConfig()
            .entryTtl(Duration.ofMinutes(10))
            .disableCachingNullValues()
        
        return RedisCacheManager.builder(redisConnectionFactory)
            .cacheDefaults(defaultConfig)
            .transactionAware()
            .build()
    }
}`;

    await fs.writeFile(
      path.join(configDir, 'CacheConfig.kt'),
      cacheConfigContent
    );

    const asyncConfigContent = `package ${basePackage}.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.scheduling.annotation.AsyncConfigurer
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor
import java.util.concurrent.Executor

@Configuration
class AsyncConfig : AsyncConfigurer {
    
    @Bean(name = ["taskExecutor"])
    override fun getAsyncExecutor(): Executor {
        val executor = ThreadPoolTaskExecutor()
        executor.corePoolSize = 2
        executor.maxPoolSize = 10
        executor.queueCapacity = 500
        executor.setThreadNamePrefix("Async-")
        executor.initialize()
        return executor
    }
}`;

    await fs.writeFile(
      path.join(configDir, 'AsyncConfig.kt'),
      asyncConfigContent
    );

    const openApiConfigContent = `package ${basePackage}.config

import io.swagger.v3.oas.models.Components
import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.oas.models.info.Info
import io.swagger.v3.oas.models.info.License
import io.swagger.v3.oas.models.security.SecurityRequirement
import io.swagger.v3.oas.models.security.SecurityScheme
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class OpenApiConfig {
    
    @Bean
    fun customOpenAPI(): OpenAPI {
        return OpenAPI()
            .info(
                Info()
                    .title("Spring Boot API")
                    .version("1.0.0")
                    .description("Spring Boot backend API documentation")
                    .license(License().name("Apache 2.0").url("http://springdoc.org"))
            )
            .components(
                Components()
                    .addSecuritySchemes(
                        "bearer-key",
                        SecurityScheme()
                            .type(SecurityScheme.Type.HTTP)
                            .scheme("bearer")
                            .bearerFormat("JWT")
                    )
            )
            .addSecurityItem(SecurityRequirement().addList("bearer-key"))
    }
}`;

    await fs.writeFile(
      path.join(configDir, 'OpenApiConfig.kt'),
      openApiConfigContent
    );
  }

  private async generateControllers(srcDir: string, basePackage: string): Promise<void> {
    const controllerDir = path.join(srcDir, 'controller');
    await fs.mkdir(controllerDir, { recursive: true });

    const userControllerContent = `package ${basePackage}.controller

import ${basePackage}.dto.*
import ${basePackage}.service.UserService
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
@RequestMapping("/api/v1/users")
@Tag(name = "Users", description = "User management APIs")
@SecurityRequirement(name = "bearer-key")
class UserController(private val userService: UserService) {
    
    @GetMapping
    @Operation(summary = "Get all users")
    @PreAuthorize("hasRole('ADMIN')")
    fun getAllUsers(pageable: Pageable): ResponseEntity<Page<UserDto>> {
        return ResponseEntity.ok(userService.findAll(pageable))
    }
    
    @GetMapping("/{id}")
    @Operation(summary = "Get user by ID")
    @PreAuthorize("hasRole('USER')")
    fun getUserById(@PathVariable id: Long): ResponseEntity<UserDto> {
        return userService.findById(id)
            ?.let { ResponseEntity.ok(it) }
            ?: ResponseEntity.notFound().build()
    }
    
    @GetMapping("/me")
    @Operation(summary = "Get current user")
    @PreAuthorize("hasRole('USER')")
    fun getCurrentUser(): ResponseEntity<UserDto> {
        return ResponseEntity.ok(userService.getCurrentUser())
    }
    
    @PutMapping("/{id}")
    @Operation(summary = "Update user")
    @PreAuthorize("hasRole('USER') and #id == authentication.principal.id or hasRole('ADMIN')")
    fun updateUser(
        @PathVariable id: Long,
        @Valid @RequestBody updateUserDto: UpdateUserDto
    ): ResponseEntity<UserDto> {
        return userService.update(id, updateUserDto)
            ?.let { ResponseEntity.ok(it) }
            ?: ResponseEntity.notFound().build()
    }
    
    @DeleteMapping("/{id}")
    @Operation(summary = "Delete user")
    @PreAuthorize("hasRole('ADMIN')")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun deleteUser(@PathVariable id: Long) {
        userService.delete(id)
    }
}`;

    await fs.writeFile(
      path.join(controllerDir, 'UserController.kt'),
      userControllerContent
    );

    const authControllerContent = `package ${basePackage}.controller

import ${basePackage}.dto.*
import ${basePackage}.service.AuthService
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Authentication", description = "Authentication APIs")
class AuthController(private val authService: AuthService) {
    
    @PostMapping("/register")
    @Operation(summary = "Register new user")
    fun register(@Valid @RequestBody registerDto: RegisterDto): ResponseEntity<TokenDto> {
        return ResponseEntity
            .status(HttpStatus.CREATED)
            .body(authService.register(registerDto))
    }
    
    @PostMapping("/login")
    @Operation(summary = "Login user")
    fun login(@Valid @RequestBody loginDto: LoginDto): ResponseEntity<TokenDto> {
        return ResponseEntity.ok(authService.login(loginDto))
    }
    
    @PostMapping("/refresh")
    @Operation(summary = "Refresh access token")
    fun refresh(@Valid @RequestBody refreshTokenDto: RefreshTokenDto): ResponseEntity<TokenDto> {
        return ResponseEntity.ok(authService.refresh(refreshTokenDto))
    }
    
    @PostMapping("/logout")
    @Operation(summary = "Logout user")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    fun logout(@RequestHeader("Authorization") token: String) {
        authService.logout(token)
    }
}`;

    await fs.writeFile(
      path.join(controllerDir, 'AuthController.kt'),
      authControllerContent
    );

    const healthControllerContent = `package ${basePackage}.controller

import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.Tag
import org.springframework.boot.actuate.health.Health
import org.springframework.boot.actuate.health.HealthIndicator
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/v1/health")
@Tag(name = "Health", description = "Health check APIs")
class HealthController : HealthIndicator {
    
    @GetMapping
    @Operation(summary = "Health check")
    fun healthCheck(): Map<String, Any> {
        return mapOf(
            "status" to "UP",
            "timestamp" to System.currentTimeMillis(),
            "service" to "spring-boot-api"
        )
    }
    
    override fun health(): Health {
        return Health.up()
            .withDetail("service", "spring-boot-api")
            .build()
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
import org.springframework.cache.annotation.CacheEvict
import org.springframework.cache.annotation.Cacheable
import org.springframework.data.domain.Page
import org.springframework.data.domain.Pageable
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
@Transactional
class UserService(
    private val userRepository: UserRepository,
    private val securityUtils: SecurityUtils
) {
    
    @Cacheable("users")
    @Transactional(readOnly = true)
    fun findAll(pageable: Pageable): Page<UserDto> {
        return userRepository.findAll(pageable).map { it.toDto() }
    }
    
    @Cacheable("users", key = "#id")
    @Transactional(readOnly = true)
    fun findById(id: Long): UserDto? {
        return userRepository.findById(id).orElse(null)?.toDto()
    }
    
    @Transactional(readOnly = true)
    fun findByEmail(email: String): User? {
        return userRepository.findByEmail(email)
    }
    
    @Transactional(readOnly = true)
    fun getCurrentUser(): UserDto {
        val email = securityUtils.getCurrentUserEmail()
        return findByEmail(email)?.toDto()
            ?: throw IllegalStateException("Current user not found")
    }
    
    @CacheEvict("users", key = "#id")
    fun update(id: Long, updateUserDto: UpdateUserDto): UserDto? {
        return userRepository.findById(id).orElse(null)?.let { user ->
            updateUserDto.name?.let { user.name = it }
            updateUserDto.email?.let { user.email = it }
            userRepository.save(user).toDto()
        }
    }
    
    @CacheEvict("users", key = "#id")
    fun delete(id: Long) {
        userRepository.deleteById(id)
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
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.LocalDateTime

@Service
@Transactional
class AuthService(
    private val userRepository: UserRepository,
    private val roleRepository: RoleRepository,
    private val passwordEncoder: PasswordEncoder,
    private val jwtTokenProvider: JwtTokenProvider,
    private val authenticationManager: AuthenticationManager
) {
    
    fun register(registerDto: RegisterDto): TokenDto {
        if (userRepository.existsByEmail(registerDto.email)) {
            throw IllegalArgumentException("Email already registered")
        }
        
        val userRole = roleRepository.findByName("ROLE_USER")
            ?: throw IllegalStateException("Default role not found")
        
        val user = User(
            email = registerDto.email,
            password = passwordEncoder.encode(registerDto.password),
            name = registerDto.name,
            roles = mutableSetOf(userRole),
            isEnabled = true,
            createdAt = LocalDateTime.now(),
            updatedAt = LocalDateTime.now()
        )
        
        userRepository.save(user)
        
        return generateTokens(user)
    }
    
    fun login(loginDto: LoginDto): TokenDto {
        authenticationManager.authenticate(
            UsernamePasswordAuthenticationToken(loginDto.email, loginDto.password)
        )
        
        val user = userRepository.findByEmail(loginDto.email)
            ?: throw IllegalArgumentException("Invalid credentials")
        
        return generateTokens(user)
    }
    
    fun refresh(refreshTokenDto: RefreshTokenDto): TokenDto {
        val email = jwtTokenProvider.validateTokenAndGetEmail(refreshTokenDto.refreshToken)
        val user = userRepository.findByEmail(email)
            ?: throw IllegalArgumentException("User not found")
        
        return generateTokens(user)
    }
    
    fun logout(token: String) {
        // Add token to blacklist or invalidate in Redis
        jwtTokenProvider.invalidateToken(token)
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
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.stereotype.Repository
import java.util.Optional

@Repository
interface UserRepository : JpaRepository<User, Long> {
    fun findByEmail(email: String): User?
    
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
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository

@Repository
interface RoleRepository : JpaRepository<Role, Long> {
    fun findByName(name: String): Role?
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

import jakarta.persistence.*
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import java.time.LocalDateTime

@Entity
@Table(name = "users")
class User(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long? = null,
    
    @Column(unique = true, nullable = false)
    var email: String,
    
    @Column(nullable = false)
    private var password: String,
    
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
) : UserDetails {
    
    override fun getAuthorities(): Collection<GrantedAuthority> {
        return roles.map { SimpleGrantedAuthority(it.name) }
    }
    
    override fun getPassword(): String = password
    
    fun setPassword(password: String) {
        this.password = password
    }
    
    override fun getUsername(): String = email
    
    override fun isAccountNonExpired(): Boolean = true
    
    override fun isAccountNonLocked(): Boolean = true
    
    override fun isCredentialsNonExpired(): Boolean = true
    
    override fun isEnabled(): Boolean = isEnabled
    
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

import jakarta.persistence.*

@Entity
@Table(name = "roles")
class Role(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
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
import java.time.LocalDateTime

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

data class CreateUserDto(
    val email: String,
    val password: String,
    val name: String
)

data class UpdateUserDto(
    val name: String? = null,
    val email: String? = null
)`;

    await fs.writeFile(
      path.join(dtoDir, 'UserDto.kt'),
      userDtoContent
    );

    const authDtoContent = `package ${basePackage}.dto

import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size

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

data class LoginDto(
    @field:NotBlank(message = "Email is required")
    @field:Email(message = "Invalid email format")
    val email: String,
    
    @field:NotBlank(message = "Password is required")
    val password: String
)

data class TokenDto(
    val accessToken: String,
    val refreshToken: String,
    val tokenType: String = "Bearer",
    val expiresIn: Long
)

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
import java.time.LocalDateTime

data class ErrorDto(
    val status: Int,
    val error: String,
    val message: String?,
    val path: String,
    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    val timestamp: LocalDateTime = LocalDateTime.now()
)

data class ValidationErrorDto(
    val field: String,
    val message: String
)

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

    const securityConfigContent = `package ${basePackage}.security

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
import org.springframework.web.cors.CorsConfigurationSource

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
class SecurityConfig(
    private val jwtAuthenticationEntryPoint: JwtAuthenticationEntryPoint,
    private val jwtAuthenticationFilter: JwtAuthenticationFilter,
    private val corsConfigurationSource: CorsConfigurationSource
) {
    
    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        return http
            .cors { it.configurationSource(corsConfigurationSource) }
            .csrf { it.disable() }
            .exceptionHandling { it.authenticationEntryPoint(jwtAuthenticationEntryPoint) }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .authorizeHttpRequests { auth ->
                auth.requestMatchers(
                    "/api/v1/auth/**",
                    "/api/v1/health/**",
                    "/actuator/**",
                    "/swagger-ui/**",
                    "/v3/api-docs/**",
                    "/ws/**"
                ).permitAll()
                .anyRequest().authenticated()
            }
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter::class.java)
            .build()
    }
    
    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()
    
    @Bean
    fun authenticationManager(config: AuthenticationConfiguration): AuthenticationManager {
        return config.authenticationManager
    }
}`;

    await fs.writeFile(
      path.join(securityDir, 'SecurityConfig.kt'),
      securityConfigContent
    );

    const jwtTokenProviderContent = `package ${basePackage}.security

import io.jsonwebtoken.*
import io.jsonwebtoken.security.Keys
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.util.*
import javax.crypto.SecretKey

@Component
class JwtTokenProvider {
    
    @Value("\\\${app.jwt.secret}")
    private lateinit var jwtSecret: String
    
    @Value("\\\${app.jwt.access-token-expiration}")
    val accessTokenValidityInMilliseconds: Long = 3600000 // 1 hour
    
    @Value("\\\${app.jwt.refresh-token-expiration}")
    private val refreshTokenValidityInMilliseconds: Long = 2592000000 // 30 days
    
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

    const jwtAuthFilterContent = `package ${basePackage}.security

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class JwtAuthenticationFilter(
    private val jwtTokenProvider: JwtTokenProvider,
    private val userDetailsService: UserDetailsService
) : OncePerRequestFilter() {
    
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val token = getTokenFromRequest(request)
        
        if (token != null) {
            try {
                val email = jwtTokenProvider.validateTokenAndGetEmail(token)
                val userDetails = userDetailsService.loadUserByUsername(email)
                
                val authentication = UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.authorities
                )
                authentication.details = WebAuthenticationDetailsSource().buildDetails(request)
                
                SecurityContextHolder.getContext().authentication = authentication
            } catch (e: Exception) {
                logger.error("Cannot set user authentication", e)
            }
        }
        
        filterChain.doFilter(request, response)
    }
    
    private fun getTokenFromRequest(request: HttpServletRequest): String? {
        val bearerToken = request.getHeader("Authorization")
        return if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            bearerToken.substring(7)
        } else null
    }
}`;

    await fs.writeFile(
      path.join(securityDir, 'JwtAuthenticationFilter.kt'),
      jwtAuthFilterContent
    );

    const jwtAuthEntryPointContent = `package ${basePackage}.security

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.stereotype.Component

@Component
class JwtAuthenticationEntryPoint : AuthenticationEntryPoint {
    
    override fun commence(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authException: AuthenticationException
    ) {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized")
    }
}`;

    await fs.writeFile(
      path.join(securityDir, 'JwtAuthenticationEntryPoint.kt'),
      jwtAuthEntryPointContent
    );

    const userDetailsServiceContent = `package ${basePackage}.security

import ${basePackage}.repository.UserRepository
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class CustomUserDetailsService(
    private val userRepository: UserRepository
) : UserDetailsService {
    
    @Transactional(readOnly = true)
    override fun loadUserByUsername(username: String): UserDetails {
        return userRepository.findByEmailWithRoles(username).orElseThrow {
            UsernameNotFoundException("User not found with email: $username")
        }
    }
}`;

    await fs.writeFile(
      path.join(securityDir, 'CustomUserDetailsService.kt'),
      userDetailsServiceContent
    );

    const securityUtilsContent = `package ${basePackage}.security

import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Component

@Component
class SecurityUtils {
    
    fun getCurrentUserEmail(): String {
        val authentication = SecurityContextHolder.getContext().authentication
        return when (val principal = authentication?.principal) {
            is UserDetails -> principal.username
            is String -> principal
            else -> throw IllegalStateException("User not authenticated")
        }
    }
    
    fun isAuthenticated(): Boolean {
        val authentication = SecurityContextHolder.getContext().authentication
        return authentication != null && authentication.isAuthenticated
    }
    
    fun hasRole(role: String): Boolean {
        val authentication = SecurityContextHolder.getContext().authentication
        return authentication?.authorities?.any { it.authority == role } ?: false
    }
}`;

    await fs.writeFile(
      path.join(securityDir, 'SecurityUtils.kt'),
      securityUtilsContent
    );
  }

  private async generateExceptions(srcDir: string, basePackage: string): Promise<void> {
    const exceptionDir = path.join(srcDir, 'exception');
    await fs.mkdir(exceptionDir, { recursive: true });

    const globalExceptionHandlerContent = `package ${basePackage}.exception

import ${basePackage}.dto.ErrorDto
import ${basePackage}.dto.ValidationErrorDto
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.AuthenticationException
import org.springframework.validation.FieldError
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import java.time.LocalDateTime

@RestControllerAdvice
class GlobalExceptionHandler {
    
    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun handleValidationExceptions(
        ex: MethodArgumentNotValidException,
        request: HttpServletRequest
    ): ResponseEntity<ErrorDto> {
        val errors = ex.bindingResult.allErrors.map { error ->
            val fieldName = (error as FieldError).field
            val errorMessage = error.defaultMessage ?: "Validation failed"
            ValidationErrorDto(fieldName, errorMessage)
        }
        
        val errorDto = ErrorDto(
            status = HttpStatus.BAD_REQUEST.value(),
            error = "Validation Failed",
            message = errors.joinToString(", ") { "\${it.field}: \${it.message}" },
            path = request.requestURI
        )
        
        return ResponseEntity.badRequest().body(errorDto)
    }
    
    @ExceptionHandler(ResourceNotFoundException::class)
    fun handleResourceNotFoundException(
        ex: ResourceNotFoundException,
        request: HttpServletRequest
    ): ResponseEntity<ErrorDto> {
        val errorDto = ErrorDto(
            status = HttpStatus.NOT_FOUND.value(),
            error = "Not Found",
            message = ex.message,
            path = request.requestURI
        )
        
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorDto)
    }
    
    @ExceptionHandler(BadCredentialsException::class)
    fun handleBadCredentialsException(
        ex: BadCredentialsException,
        request: HttpServletRequest
    ): ResponseEntity<ErrorDto> {
        val errorDto = ErrorDto(
            status = HttpStatus.UNAUTHORIZED.value(),
            error = "Unauthorized",
            message = "Invalid credentials",
            path = request.requestURI
        )
        
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorDto)
    }
    
    @ExceptionHandler(AuthenticationException::class)
    fun handleAuthenticationException(
        ex: AuthenticationException,
        request: HttpServletRequest
    ): ResponseEntity<ErrorDto> {
        val errorDto = ErrorDto(
            status = HttpStatus.UNAUTHORIZED.value(),
            error = "Unauthorized",
            message = ex.message,
            path = request.requestURI
        )
        
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorDto)
    }
    
    @ExceptionHandler(IllegalArgumentException::class)
    fun handleIllegalArgumentException(
        ex: IllegalArgumentException,
        request: HttpServletRequest
    ): ResponseEntity<ErrorDto> {
        val errorDto = ErrorDto(
            status = HttpStatus.BAD_REQUEST.value(),
            error = "Bad Request",
            message = ex.message,
            path = request.requestURI
        )
        
        return ResponseEntity.badRequest().body(errorDto)
    }
    
    @ExceptionHandler(Exception::class)
    fun handleGlobalException(
        ex: Exception,
        request: HttpServletRequest
    ): ResponseEntity<ErrorDto> {
        val errorDto = ErrorDto(
            status = HttpStatus.INTERNAL_SERVER_ERROR.value(),
            error = "Internal Server Error",
            message = "An unexpected error occurred",
            path = request.requestURI
        )
        
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorDto)
    }
}`;

    await fs.writeFile(
      path.join(exceptionDir, 'GlobalExceptionHandler.kt'),
      globalExceptionHandlerContent
    );

    const customExceptionsContent = `package ${basePackage}.exception

class ResourceNotFoundException(message: String) : RuntimeException(message)

class DuplicateResourceException(message: String) : RuntimeException(message)

class InvalidRequestException(message: String) : RuntimeException(message)

class UnauthorizedException(message: String) : RuntimeException(message)`;

    await fs.writeFile(
      path.join(exceptionDir, 'CustomExceptions.kt'),
      customExceptionsContent
    );
  }

  private async generateWebSocket(srcDir: string, basePackage: string): Promise<void> {
    const wsDir = path.join(srcDir, 'websocket');
    await fs.mkdir(wsDir, { recursive: true });

    const wsConfigContent = `package ${basePackage}.websocket

import org.springframework.context.annotation.Configuration
import org.springframework.messaging.simp.config.MessageBrokerRegistry
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker
import org.springframework.web.socket.config.annotation.StompEndpointRegistry
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer

@Configuration
@EnableWebSocketMessageBroker
class WebSocketConfig : WebSocketMessageBrokerConfigurer {
    
    override fun configureMessageBroker(config: MessageBrokerRegistry) {
        config.enableSimpleBroker("/topic", "/queue")
        config.setApplicationDestinationPrefixes("/app")
    }
    
    override fun registerStompEndpoints(registry: StompEndpointRegistry) {
        registry.addEndpoint("/ws")
            .setAllowedOriginPatterns("*")
            .withSockJS()
    }
}`;

    await fs.writeFile(
      path.join(wsDir, 'WebSocketConfig.kt'),
      wsConfigContent
    );

    const wsControllerContent = `package ${basePackage}.websocket

import org.springframework.messaging.handler.annotation.MessageMapping
import org.springframework.messaging.handler.annotation.SendTo
import org.springframework.messaging.simp.SimpMessagingTemplate
import org.springframework.stereotype.Controller
import java.time.LocalDateTime

@Controller
class WebSocketController(
    private val messagingTemplate: SimpMessagingTemplate
) {
    
    @MessageMapping("/chat")
    @SendTo("/topic/messages")
    fun sendMessage(message: ChatMessage): ChatMessage {
        return message.copy(timestamp = LocalDateTime.now())
    }
    
    fun sendToUser(username: String, message: ChatMessage) {
        messagingTemplate.convertAndSendToUser(
            username,
            "/queue/messages",
            message
        )
    }
}

data class ChatMessage(
    val from: String,
    val content: String,
    val timestamp: LocalDateTime = LocalDateTime.now()
)`;

    await fs.writeFile(
      path.join(wsDir, 'WebSocketController.kt'),
      wsControllerContent
    );
  }

  private async generateGraphQL(srcDir: string, basePackage: string): Promise<void> {
    const graphqlDir = path.join(srcDir, 'graphql');
    await fs.mkdir(graphqlDir, { recursive: true });

    const queryResolverContent = `package ${basePackage}.graphql

import ${basePackage}.dto.UserDto
import ${basePackage}.service.UserService
import org.springframework.graphql.data.method.annotation.Argument
import org.springframework.graphql.data.method.annotation.QueryMapping
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller

@Controller
class UserQueryResolver(
    private val userService: UserService
) {
    
    @QueryMapping
    @PreAuthorize("hasRole('USER')")
    fun user(@Argument id: Long): UserDto? {
        return userService.findById(id)
    }
    
    @QueryMapping
    @PreAuthorize("hasRole('ADMIN')")
    fun users(@Argument page: Int = 0, @Argument size: Int = 10): List<UserDto> {
        return userService.findAll(
            org.springframework.data.domain.PageRequest.of(page, size)
        ).content
    }
    
    @QueryMapping
    @PreAuthorize("hasRole('USER')")
    fun me(): UserDto {
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
import org.springframework.graphql.data.method.annotation.Argument
import org.springframework.graphql.data.method.annotation.MutationMapping
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Controller

@Controller
class UserMutationResolver(
    private val authService: AuthService,
    private val userService: UserService
) {
    
    @MutationMapping
    fun register(@Argument input: RegisterDto): TokenDto {
        return authService.register(input)
    }
    
    @MutationMapping
    fun login(@Argument input: LoginDto): TokenDto {
        return authService.login(input)
    }
    
    @MutationMapping
    @PreAuthorize("hasRole('USER')")
    fun updateUser(
        @Argument id: Long,
        @Argument input: UpdateUserDto
    ): UserDto? {
        return userService.update(id, input)
    }
}`;

    await fs.writeFile(
      path.join(graphqlDir, 'UserMutationResolver.kt'),
      mutationResolverContent
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
  }

  private async generateResources(projectPath: string): Promise<void> {
    const resourcesDir = path.join(projectPath, 'src/main/resources');
    await fs.mkdir(resourcesDir, { recursive: true });

    const applicationYaml = `spring:
  application:
    name: spring-boot-api
  
  datasource:
    url: jdbc:postgresql://\${DB_HOST:localhost}:\${DB_PORT:5432}/\${DB_NAME:app_db}
    username: \${DB_USER:postgres}
    password: \${DB_PASSWORD:postgres}
    driver-class-name: org.postgresql.Driver
    hikari:
      maximum-pool-size: 10
      minimum-idle: 5
      connection-timeout: 30000
      idle-timeout: 600000
      max-lifetime: 1800000
  
  jpa:
    hibernate:
      ddl-auto: update
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect
        format_sql: true
        show_sql: false
        use_sql_comments: true
        jdbc:
          lob:
            non_contextual_creation: true
  
  redis:
    host: \${REDIS_HOST:localhost}
    port: \${REDIS_PORT:6379}
    password: \${REDIS_PASSWORD:}
    timeout: 60000ms
    lettuce:
      pool:
        max-active: 8
        max-idle: 8
        min-idle: 0
  
  liquibase:
    change-log: classpath:db/changelog/db.changelog-master.xml
  
  kafka:
    bootstrap-servers: \${KAFKA_SERVERS:localhost:9092}
    producer:
      key-serializer: org.apache.kafka.common.serialization.StringSerializer
      value-serializer: org.springframework.kafka.support.serializer.JsonSerializer
    consumer:
      group-id: \${spring.application.name}
      key-deserializer: org.apache.kafka.common.serialization.StringDeserializer
      value-deserializer: org.springframework.kafka.support.serializer.JsonDeserializer
      properties:
        spring.json.trusted.packages: "*"
  
  graphql:
    graphiql:
      enabled: true
    path: /graphql

server:
  port: \${PORT:8080}
  compression:
    enabled: true
    mime-types: text/html,text/xml,text/plain,text/css,text/javascript,application/javascript,application/json
    min-response-size: 1024

app:
  jwt:
    secret: \${JWT_SECRET:your-secret-key-here-please-change-in-production}
    access-token-expiration: 3600000
    refresh-token-expiration: 2592000000
  
  cors:
    allowed-origins:
      - http://localhost:3000
      - http://localhost:4200

management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
  endpoint:
    health:
      show-details: always
  metrics:
    export:
      prometheus:
        enabled: true

springdoc:
  api-docs:
    path: /v3/api-docs
  swagger-ui:
    path: /swagger-ui
    operations-sorter: method

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
    name: logs/application.log`;

    await fs.writeFile(
      path.join(resourcesDir, 'application.yml'),
      applicationYaml
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

    const graphqlDir = path.join(resourcesDir, 'graphql');
    await fs.mkdir(graphqlDir, { recursive: true });
    await fs.writeFile(
      path.join(graphqlDir, 'schema.graphqls'),
      graphqlSchema
    );

    const dbDir = path.join(resourcesDir, 'db/changelog');
    await fs.mkdir(dbDir, { recursive: true });
    
    const dbChangelogMaster = `<?xml version="1.0" encoding="UTF-8"?>
<databaseChangeLog
    xmlns="http://www.liquibase.org/xml/ns/dbchangelog"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://www.liquibase.org/xml/ns/dbchangelog
        http://www.liquibase.org/xml/ns/dbchangelog/dbchangelog-4.9.xsd">

    <include file="db/changelog/001-create-users-table.xml"/>
    <include file="db/changelog/002-create-roles-table.xml"/>
    <include file="db/changelog/003-seed-initial-data.xml"/>

</databaseChangeLog>`;

    await fs.writeFile(
      path.join(dbDir, 'db.changelog-master.xml'),
      dbChangelogMaster
    );
  }

  private async generateTests(projectPath: string, basePackage: string): Promise<void> {
    const testDir = path.join(projectPath, 'src/test/kotlin', ...basePackage.split('.'));
    await fs.mkdir(testDir, { recursive: true });

    const integrationTestContent = `package ${basePackage}

import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ActiveProfiles

@SpringBootTest
@ActiveProfiles("test")
class ApplicationTests {

    @Test
    fun contextLoads() {
    }
}`;

    await fs.writeFile(
      path.join(testDir, 'ApplicationTests.kt'),
      integrationTestContent
    );

    const controllerTestDir = path.join(testDir, 'controller');
    await fs.mkdir(controllerTestDir, { recursive: true });

    const controllerTestContent = `package ${basePackage}.controller

import ${basePackage}.dto.LoginDto
import ${basePackage}.dto.RegisterDto
import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.post

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthControllerTest {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Autowired
    private lateinit var objectMapper: ObjectMapper

    @Test
    fun \`should register new user\`() {
        val registerDto = RegisterDto(
            email = "test@example.com",
            password = "password123",
            name = "Test User"
        )

        mockMvc.post("/api/v1/auth/register") {
            contentType = MediaType.APPLICATION_JSON
            content = objectMapper.writeValueAsString(registerDto)
        }.andExpect {
            status { isCreated() }
            jsonPath("$.accessToken") { exists() }
            jsonPath("$.refreshToken") { exists() }
        }
    }

    @Test
    fun \`should login with valid credentials\`() {
        val loginDto = LoginDto(
            email = "admin@example.com",
            password = "admin123"
        )

        mockMvc.post("/api/v1/auth/login") {
            contentType = MediaType.APPLICATION_JSON
            content = objectMapper.writeValueAsString(loginDto)
        }.andExpect {
            status { isOk() }
            jsonPath("$.accessToken") { exists() }
        }
    }
}`;

    await fs.writeFile(
      path.join(controllerTestDir, 'AuthControllerTest.kt'),
      controllerTestContent
    );

    const testResourcesDir = path.join(projectPath, 'src/test/resources');
    await fs.mkdir(testResourcesDir, { recursive: true });

    const testApplicationYaml = `spring:
  datasource:
    url: jdbc:h2:mem:testdb
    driver-class-name: org.h2.Driver
    username: sa
    password:

  jpa:
    hibernate:
      ddl-auto: create-drop
    properties:
      hibernate:
        dialect: org.hibernate.dialect.H2Dialect

  liquibase:
    enabled: false

app:
  jwt:
    secret: test-secret-key-for-testing
    access-token-expiration: 3600000
    refresh-token-expiration: 86400000`;

    await fs.writeFile(
      path.join(testResourcesDir, 'application-test.yml'),
      testApplicationYaml
    );
  }
}

export default SpringBootGenerator;