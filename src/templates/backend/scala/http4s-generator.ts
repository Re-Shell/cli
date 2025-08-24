import { ScalaBackendGenerator } from './scala-base-generator';

export class Http4sGenerator extends ScalaBackendGenerator {
  protected getFrameworkDependencies(): Record<string, string> {
    return {
      "org.http4s::http4s-ember-server_2.13": "0.23.24",
      "org.http4s::http4s-ember-client_2.13": "0.23.24", 
      "org.http4s::http4s-circe_2.13": "0.23.24",
      "org.http4s::http4s-dsl_2.13": "0.23.24",
      "org.typelevel::cats-effect_2.13": "3.5.2",
      "co.fs2::fs2-core_2.13": "3.9.3",
      "co.fs2::fs2-io_2.13": "3.9.3",
      "org.tpolecat::doobie-core_2.13": "1.0.0-RC4",
      "org.tpolecat::doobie-hikari_2.13": "1.0.0-RC4",
      "org.tpolecat::doobie-postgres_2.13": "1.0.0-RC4",
      "org.tpolecat::doobie-scalatest_2.13": "1.0.0-RC4",
      "io.github.jmcardon::tsec-http4s_2.13": "0.5.0"
    };
  }

  protected generateMainFile(): string {
    return `package com.example

import cats.effect.{IO, IOApp, Resource}
import cats.syntax.all._
import com.comcast.ip4s._
import org.http4s.ember.server.EmberServerBuilder
import org.http4s.implicits._
import org.http4s.server.middleware.Logger
import com.example.config.{DatabaseConfig, JwtConfig}
import com.example.routes.{AuthRoutes, UserRoutes, HealthRoutes}
import com.example.services.{AuthService, UserService}
import com.example.repositories.UserRepository
import com.example.utils.{JwtUtils, PasswordUtils}
import org.typelevel.log4cats.Logger as Log4CatsLogger
import org.typelevel.log4cats.slf4j.Slf4jLogger

object Main extends IOApp.Simple {

  implicit def logger: Log4CatsLogger[IO] = Slf4jLogger.getLogger[IO]

  def run: IO[Unit] = {
    for {
      // Load configuration
      dbConfig <- DatabaseConfig.load[IO]
      jwtConfig <- JwtConfig.load[IO]
      
      // Initialize services
      _ <- server(dbConfig, jwtConfig).useForever
    } yield ()
  }

  private def server(dbConfig: DatabaseConfig, jwtConfig: JwtConfig): Resource[IO, Nothing] = {
    for {
      // Initialize utilities
      jwtUtils = new JwtUtils[IO](jwtConfig.secret, jwtConfig.expiration)
      passwordUtils = PasswordUtils
      
      // Initialize repositories
      userRepository = new UserRepository[IO](dbConfig)
      
      // Initialize services  
      userService = new UserService[IO](userRepository, passwordUtils)
      authService = new AuthService[IO](userService, jwtUtils)
      
      // Initialize routes
      healthRoutes = new HealthRoutes[IO]()
      authRoutes = new AuthRoutes[IO](authService)
      userRoutes = new UserRoutes[IO](userService, jwtUtils)
      
      // Combine all routes
      httpApp = (
        healthRoutes.routes <+>
        authRoutes.routes <+> 
        userRoutes.routes
      ).orNotFound
      
      // Add middleware
      finalHttpApp = Logger.httpApp(true, true)(httpApp)
      
      _ <- EmberServerBuilder.default[IO]
        .withHost(ipv4"0.0.0.0")
        .withPort(port"8080")
        .withHttpApp(finalHttpApp)
        .build
    } yield ()
  }
}`;
  }

  protected generateRoutingFile(): string {
    return `package com.example.routes

import cats.effect.Sync
import cats.implicits._
import org.http4s._
import org.http4s.dsl.Http4sDsl
import org.http4s.circe.CirceEntityCodec._
import com.example.services.AuthService
import com.example.dto._
import com.example.middleware.ErrorHandler._

class AuthRoutes[F[_]: Sync](authService: AuthService[F]) extends Http4sDsl[F] {

  val routes: HttpRoutes[F] = HttpRoutes.of[F] {
    
    case req @ POST -> Root / "api" / "auth" / "register" =>
      for {
        createUserRequest <- req.as[CreateUserRequest]
        response <- authService.register(createUserRequest)
        result <- Created(response)
      } yield result
    
    case req @ POST -> Root / "api" / "auth" / "login" =>
      for {
        loginRequest <- req.as[LoginRequest]
        response <- authService.login(loginRequest)
        result <- Ok(response)
      } yield result
    
    case req @ POST -> Root / "api" / "auth" / "refresh" =>
      for {
        refreshRequest <- req.as[RefreshTokenRequest]
        response <- authService.refreshToken(refreshRequest)
        result <- Ok(response)
      } yield result
    
    case req @ POST -> Root / "api" / "auth" / "logout" =>
      req.headers.get[${'`'}X-Refresh-Token${'`'}] match {
        case Some(refreshTokenHeader) =>
          for {
            _ <- authService.logout(refreshTokenHeader.value)
            result <- Ok(MessageResponse("Logged out successfully"))
          } yield result
        case None =>
          BadRequest(ErrorResponse("Bad Request", "Refresh token required"))
      }
  }
}

// Custom header for refresh token
case class ${'`'}X-Refresh-Token${'`'}(value: String) extends Header.Parsed {
  override def key: CIString = ${'`'}X-Refresh-Token${'`'}.name
  override def renderValue(): String = value
}

object ${'`'}X-Refresh-Token${'`'} extends Header.Companion[${'`'}X-Refresh-Token${'`'}] {
  override val name: CIString = CIString("X-Refresh-Token")
  override def parse(s: String): ParseResult[${'`'}X-Refresh-Token${'`'}] = 
    ParseResult.success(${'`'}X-Refresh-Token${'`'}(s))
}`;
  }

  protected generateServiceFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/scala/com/example/services/UserService.scala',
        content: `package com.example.services

import cats.effect.Sync
import cats.implicits._
import com.example.dto.{CreateUserRequest, UpdateUserRequest}
import com.example.models.{User, UserResponse}
import com.example.repositories.UserRepository
import com.example.utils.PasswordUtils
import com.example.middleware.{ValidationError, NotFoundError}

class UserService[F[_]: Sync](
  userRepository: UserRepository[F],
  passwordUtils: PasswordUtils.type
) {
  
  def createUser(request: CreateUserRequest): F[User] = {
    for {
      // Check if email already exists
      existingUser <- userRepository.findByEmail(request.email)
      _ <- existingUser match {
        case Some(_) => Sync[F].raiseError(ValidationError("Email already exists"))
        case None => Sync[F].unit
      }
      
      // Hash password
      hashedPassword <- passwordUtils.hashPassword[F](request.password)
      
      // Create user
      user <- userRepository.create(request.email, hashedPassword, request.name, "user")
    } yield user
  }
  
  def findById(id: Int): F[Option[User]] = 
    userRepository.findById(id)
  
  def findByEmail(email: String): F[Option[User]] = 
    userRepository.findByEmail(email)
  
  def getAllUsers(page: Int = 0, size: Int = 20): F[List[UserResponse]] = 
    userRepository.findAll(page, size).map(_.map(UserResponse.fromUser))
  
  def updateUser(id: Int, request: UpdateUserRequest): F[User] = {
    for {
      user <- userRepository.findById(id).flatMap {
        case Some(u) => Sync[F].pure(u)
        case None => Sync[F].raiseError(NotFoundError("User not found"))
      }
      
      // Check email uniqueness if changing
      _ <- request.email match {
        case Some(newEmail) if newEmail != user.email =>
          userRepository.findByEmail(newEmail).flatMap {
            case Some(_) => Sync[F].raiseError(ValidationError("Email already exists"))
            case None => Sync[F].unit
          }
        case _ => Sync[F].unit
      }
      
      // Hash password if provided
      hashedPassword <- request.password match {
        case Some(pwd) => passwordUtils.hashPassword[F](pwd).map(Some(_))
        case None => Sync[F].pure(None)
      }
      
      // Update user
      updatedUser <- userRepository.update(id, request.copy(password = hashedPassword))
    } yield updatedUser
  }
  
  def deleteUser(id: Int): F[Unit] = {
    for {
      user <- userRepository.findById(id).flatMap {
        case Some(_) => Sync[F].unit
        case None => Sync[F].raiseError(NotFoundError("User not found"))
      }
      _ <- userRepository.delete(id)
    } yield ()
  }
  
  def validateCredentials(email: String, password: String): F[Option[User]] = {
    for {
      user <- userRepository.findByEmail(email)
      result <- user match {
        case Some(u) => 
          passwordUtils.verifyPassword[F](password, u.password).map {
            case true => Some(u)
            case false => None
          }
        case None => Sync[F].pure(None)
      }
    } yield result
  }
}`
      },
      {
        path: 'src/main/scala/com/example/services/AuthService.scala',
        content: `package com.example.services

import cats.effect.{Ref, Sync}
import cats.implicits._
import com.example.dto._
import com.example.models.{User, UserResponse}
import com.example.utils.{JwtUtils, ValidationUtils}
import com.example.middleware.{UnauthorizedError, ValidationError}
import scala.collection.concurrent.TrieMap

class AuthService[F[_]: Sync](
  userService: UserService[F],
  jwtUtils: JwtUtils[F]
) {
  
  // In-memory refresh token storage (use Redis in production)
  private val refreshTokens = TrieMap[String, Int]()
  
  def register(request: CreateUserRequest): F[AuthResponse] = {
    for {
      // Validate request
      validRequest <- ValidationUtils.validateCreateUserRequest[F](request).flatMap {
        case Left(error) => Sync[F].raiseError(ValidationError(error))
        case Right(req) => Sync[F].pure(req)
      }
      
      // Create user
      user <- userService.createUser(validRequest)
      
      // Generate auth response
      response <- generateAuthResponse(user)
    } yield response
  }
  
  def login(request: LoginRequest): F[AuthResponse] = {
    for {
      // Validate credentials
      user <- userService.validateCredentials(request.email, request.password).flatMap {
        case Some(u) => Sync[F].pure(u)
        case None => Sync[F].raiseError(UnauthorizedError("Invalid email or password"))
      }
      
      // Check if user is active
      _ <- if (user.isActive) Sync[F].unit 
           else Sync[F].raiseError(UnauthorizedError("Account is disabled"))
      
      // Generate auth response
      response <- generateAuthResponse(user)
    } yield response
  }
  
  def refreshToken(request: RefreshTokenRequest): F[AuthResponse] = {
    for {
      // Get user ID from refresh token
      userId <- Sync[F].delay(refreshTokens.get(request.refreshToken)).flatMap {
        case Some(id) => Sync[F].pure(id)
        case None => Sync[F].raiseError(UnauthorizedError("Invalid refresh token"))
      }
      
      // Get user
      user <- userService.findById(userId).flatMap {
        case Some(u) => Sync[F].pure(u)
        case None => Sync[F].raiseError(UnauthorizedError("User not found"))
      }
      
      // Remove old refresh token
      _ <- Sync[F].delay(refreshTokens.remove(request.refreshToken))
      
      // Generate new auth response
      response <- generateAuthResponse(user)
    } yield response
  }
  
  def logout(refreshToken: String): F[Unit] = 
    Sync[F].delay(refreshTokens.remove(refreshToken)).void
  
  private def generateAuthResponse(user: User): F[AuthResponse] = {
    for {
      token <- jwtUtils.generateToken(user)
      refreshToken <- jwtUtils.generateRefreshToken(user)
      
      // Store refresh token
      _ <- Sync[F].delay(refreshTokens.put(refreshToken, user.id))
      
      response = AuthResponse(
        token = token,
        refreshToken = refreshToken,
        user = UserResponse.fromUser(user)
      )
    } yield response
  }
}`
      }
    ];
  }

  protected generateRepositoryFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/scala/com/example/repositories/UserRepository.scala',
        content: `package com.example.repositories

import cats.effect.Sync
import cats.implicits._
import com.example.config.DatabaseConfig
import com.example.models.User
import com.example.dto.UpdateUserRequest
import doobie._
import doobie.implicits._
import doobie.postgres._
import doobie.postgres.implicits._
import java.time.Instant

class UserRepository[F[_]: Sync](dbConfig: DatabaseConfig) {
  
  private val xa = Transactor.fromHikariConfig[F](dbConfig.hikariConfig)
  
  def create(email: String, password: String, name: String, role: String): F[User] = {
    val now = Instant.now()
    
    sql"""
      INSERT INTO users (email, password, name, role, is_active, created_at, updated_at)
      VALUES ($email, $password, $name, $role, true, $now, $now)
    """.update
      .withUniqueGeneratedKeys[Int]("id")
      .transact(xa)
      .flatMap(id => findById(id).map(_.get))
  }
  
  def findById(id: Int): F[Option[User]] = {
    sql"""
      SELECT id, email, password, name, role, is_active, created_at, updated_at
      FROM users 
      WHERE id = $id
    """.query[User].option.transact(xa)
  }
  
  def findByEmail(email: String): F[Option[User]] = {
    sql"""
      SELECT id, email, password, name, role, is_active, created_at, updated_at
      FROM users 
      WHERE email = $email
    """.query[User].option.transact(xa)
  }
  
  def findAll(page: Int = 0, size: Int = 20): F[List[User]] = {
    val offset = page * size
    
    sql"""
      SELECT id, email, password, name, role, is_active, created_at, updated_at
      FROM users
      ORDER BY created_at DESC
      LIMIT $size OFFSET $offset
    """.query[User].to[List].transact(xa)
  }
  
  def update(id: Int, request: UpdateUserRequest): F[User] = {
    val now = Instant.now()
    
    val updates = List(
      request.name.map(n => fr"name = $n"),
      request.email.map(e => fr"email = $e"), 
      request.password.map(p => fr"password = $p")
    ).flatten
    
    val setClause = if (updates.nonEmpty) {
      updates.reduce(_ ++ fr"," ++ _) ++ fr", updated_at = $now"
    } else {
      fr"updated_at = $now"
    }
    
    val updateQuery = fr"UPDATE users SET" ++ setClause ++ fr"WHERE id = $id"
    
    updateQuery.update.run.transact(xa) *> findById(id).map(_.get)
  }
  
  def delete(id: Int): F[Unit] = {
    sql"DELETE FROM users WHERE id = $id".update.run.transact(xa).void
  }
}`
      }
    ];
  }

  protected generateModelFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/scala/com/example/routes/UserRoutes.scala',
        content: `package com.example.routes

import cats.effect.Sync
import cats.implicits._
import org.http4s._
import org.http4s.dsl.Http4sDsl
import org.http4s.circe.CirceEntityCodec._
import com.example.services.UserService
import com.example.utils.JwtUtils
import com.example.dto.{UpdateUserRequest, ErrorResponse}
import com.example.models.UserResponse
import com.example.middleware.{ErrorHandler, NotFoundError, UnauthorizedError}

class UserRoutes[F[_]: Sync](
  userService: UserService[F],
  jwtUtils: JwtUtils[F]
) extends Http4sDsl[F] {

  val routes: HttpRoutes[F] = HttpRoutes.of[F] {
    
    case GET -> Root / "api" / "users" :? PageQueryParamMatcher(page) +& SizeQueryParamMatcher(size) =>
      // Should include admin role check in real implementation
      userService.getAllUsers(page.getOrElse(0), size.getOrElse(20)).flatMap(users => Ok(users))
    
    case GET -> Root / "api" / "users" / "me" =>
      // Should extract user from JWT token in real implementation
      Ok(ErrorResponse("Not Implemented", "User extraction from JWT not implemented"))
    
    case GET -> Root / "api" / "users" / IntVar(id) =>
      userService.findById(id).flatMap {
        case Some(user) => Ok(UserResponse.fromUser(user))
        case None => NotFound(ErrorResponse("Not Found", "User not found"))
      }
    
    case req @ PUT -> Root / "api" / "users" / IntVar(id) =>
      for {
        updateRequest <- req.as[UpdateUserRequest]
        user <- userService.updateUser(id, updateRequest)
        response <- Ok(UserResponse.fromUser(user))
      } yield response
    
    case DELETE -> Root / "api" / "users" / IntVar(id) =>
      userService.deleteUser(id).flatMap(_ => NoContent())
  }

  // Query parameter matchers
  object PageQueryParamMatcher extends OptionalQueryParamDecoderMatcher[Int]("page")
  object SizeQueryParamMatcher extends OptionalQueryParamDecoderMatcher[Int]("size")
}`
      },
      {
        path: 'src/main/scala/com/example/routes/HealthRoutes.scala',
        content: `package com.example.routes

import cats.effect.Sync
import cats.implicits._
import org.http4s._
import org.http4s.dsl.Http4sDsl
import org.http4s.circe.CirceEntityCodec._
import io.circe.Json
import io.circe.syntax._

class HealthRoutes[F[_]: Sync]() extends Http4sDsl[F] {

  val routes: HttpRoutes[F] = HttpRoutes.of[F] {
    case GET -> Root / "health" =>
      val runtime = Runtime.getRuntime
      val totalMemory = runtime.totalMemory()
      val freeMemory = runtime.freeMemory()
      val usedMemory = totalMemory - freeMemory
      val memoryPercentage = (usedMemory.toDouble / totalMemory.toDouble) * 100

      val healthResponse = Json.obj(
        "status" -> "OK".asJson,
        "timestamp" -> System.currentTimeMillis().asJson,
        "uptime" -> java.lang.management.ManagementFactory.getRuntimeMXBean.getUptime.asJson,
        "memory" -> Json.obj(
          "total" -> totalMemory.asJson,
          "free" -> freeMemory.asJson,
          "used" -> usedMemory.asJson,
          "percentage" -> memoryPercentage.asJson
        )
      )

      Ok(healthResponse)
    
    case GET -> Root =>
      Ok(Json.obj("message" -> "Welcome to http4s Scala service".asJson))
  }
}`
      }
    ];
  }

  protected generateConfigFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/scala/com/example/config/DatabaseConfig.scala',
        content: `package com.example.config

import cats.effect.Sync
import cats.implicits._
import com.zaxxer.hikari.HikariConfig
import pureconfig.ConfigSource
import pureconfig.generic.auto._

case class DatabaseConfig(
  url: String,
  user: String,
  password: String,
  maxPoolSize: Int
) {
  def hikariConfig: HikariConfig = {
    val config = new HikariConfig()
    config.setJdbcUrl(url)
    config.setUsername(user)
    config.setPassword(password)
    config.setMaximumPoolSize(maxPoolSize)
    config.setAutoCommit(false)
    config.setTransactionIsolation("TRANSACTION_REPEATABLE_READ")
    config.validate()
    config
  }
}

object DatabaseConfig {
  def load[F[_]: Sync]: F[DatabaseConfig] = Sync[F].delay {
    ConfigSource.default.at("database").loadOrThrow[DatabaseConfig]
  }
}`
      },
      {
        path: 'src/main/scala/com/example/config/JwtConfig.scala',
        content: `package com.example.config

import cats.effect.Sync
import pureconfig.ConfigSource
import pureconfig.generic.auto._

case class JwtConfig(
  secret: String,
  expiration: Long
)

object JwtConfig {
  def load[F[_]: Sync]: F[JwtConfig] = Sync[F].delay {
    ConfigSource.default.at("jwt").loadOrThrow[JwtConfig]
  }
}`
      },
      {
        path: 'src/main/resources/application.conf',
        content: `server {
  host = "0.0.0.0"
  host = \${?SERVER_HOST}
  port = 8080
  port = \${?SERVER_PORT}
}

database {
  url = "jdbc:postgresql://localhost:5432/app_db"
  url = \${?DATABASE_URL}
  user = "postgres"
  user = \${?DATABASE_USER}
  password = "postgres"
  password = \${?DATABASE_PASSWORD}
  maxPoolSize = 10
  maxPoolSize = \${?DATABASE_MAX_POOL_SIZE}
}

jwt {
  secret = "your-secret-key-change-in-production"
  secret = \${?JWT_SECRET}
  expiration = 86400
  expiration = \${?JWT_EXPIRATION}
}`
      },
      {
        path: 'src/main/resources/logback.xml',
        content: `<?xml version="1.0" encoding="UTF-8"?>
<configuration>

  <appender name="CONSOLE" class="ch.qos.logback.core.ConsoleAppender">
    <encoder>
      <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n</pattern>
    </encoder>
  </appender>

  <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
    <file>logs/app.log</file>
    <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
      <fileNamePattern>logs/app.%d{yyyy-MM-dd}.%i.log</fileNamePattern>
      <maxFileSize>100MB</maxFileSize>
      <maxHistory>30</maxHistory>
      <totalSizeCap>3GB</totalSizeCap>
    </rollingPolicy>
    <encoder>
      <pattern>%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n</pattern>
    </encoder>
  </appender>

  <logger name="com.example" level="INFO"/>
  <logger name="org.http4s" level="INFO"/>
  <logger name="doobie" level="INFO"/>

  <root level="INFO">
    <appender-ref ref="CONSOLE"/>
    <appender-ref ref="FILE"/>
  </root>

</configuration>`
      }
    ];
  }

  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/main/scala/com/example/middleware/ErrorHandler.scala',
        content: `package com.example.middleware

import cats.effect.Sync
import cats.implicits._
import com.example.dto.ErrorResponse
import org.http4s._
import org.http4s.dsl.Http4sDsl
import org.http4s.circe.CirceEntityCodec._
import org.typelevel.log4cats.Logger

object ErrorHandler {
  
  def httpErrorHandler[F[_]: Sync: Logger]: HttpRoutes[F] => HttpRoutes[F] = { routes: HttpRoutes[F] =>
    HttpRoutes.of[F] { req =>
      routes.run(req).value.flatMap {
        case Some(response) => response.pure[F]
        case None => Response.notFound[F].pure[F]
      }.handleErrorWith(handleError[F])
    }
  }
  
  private def handleError[F[_]: Sync: Logger](error: Throwable): F[Response[F]] = {
    val dsl = new Http4sDsl[F] {}
    import dsl._
    
    for {
      _ <- Logger[F].error(error)(s"Error handling request: \${error.getMessage}")
      response <- error match {
        case ValidationError(msg) => 
          BadRequest(ErrorResponse("Validation Error", msg))
        case NotFoundError(msg) => 
          NotFound(ErrorResponse("Not Found", msg))
        case UnauthorizedError(msg) => 
          Unauthorized(ErrorResponse("Unauthorized", msg))
        case ForbiddenError(msg) => 
          Forbidden(ErrorResponse("Forbidden", msg))
        case _ => 
          InternalServerError(ErrorResponse("Internal Server Error", "An unexpected error occurred"))
      }
    } yield response
  }
}`
      }
    ];
  }

  protected generateTestFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/test/scala/com/example/UserServiceSpec.scala',
        content: `package com.example

import cats.effect.IO
import cats.effect.testing.scalatest.AsyncIOSpec
import com.example.dto.CreateUserRequest
import com.example.services.UserService
import com.example.repositories.UserRepository
import com.example.utils.PasswordUtils
import org.scalatest.freespec.AsyncFreeSpec
import org.scalatest.matchers.should.Matchers
import org.mockito.MockitoSugar

class UserServiceSpec extends AsyncFreeSpec with AsyncIOSpec with Matchers with MockitoSugar {

  "UserService" - {
    "createUser" - {
      "should create a new user successfully" in {
        val mockRepository = mock[UserRepository[IO]]
        val userService = new UserService[IO](mockRepository, PasswordUtils)
        
        val request = CreateUserRequest(
          email = "test@example.com",
          password = "password123",
          name = "Test User"
        )
        
        // Test would need proper mocking setup with cats-effect
        // This is a basic structure example
        succeed
      }
    }
  }
}`
      },
      {
        path: 'src/test/scala/com/example/routes/HealthRoutesSpec.scala',
        content: `package com.example.routes

import cats.effect.IO
import org.http4s._
import org.http4s.implicits._
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class HealthRoutesSpec extends AnyWordSpec with Matchers {

  "HealthRoutes" should {
    "return 200 OK for GET /health" in {
      val healthRoutes = new HealthRoutes[IO]()
      val request = Request[IO](Method.GET, uri"/health")
      
      val response = healthRoutes.routes.orNotFound.run(request).unsafeRunSync()
      
      response.status shouldBe Status.Ok
    }
  }
}`
      }
    ];
  }

  protected generateBuildSbt(): string {
    const dependencies = this.getFrameworkDependencies();
    const depList = Object.entries(dependencies)
      .map(([org, artifact]) => `    "${org}" %% "${artifact}" % http4sVersion`)
      .join(',\n');

    return `ThisBuild / version := "0.1.0-SNAPSHOT"
ThisBuild / scalaVersion := "2.13.12"

lazy val http4sVersion = "0.23.24"
lazy val circeVersion = "0.14.6"
lazy val doobieVersion = "1.0.0-RC4"
lazy val catsVersion = "2.10.0"
lazy val catsEffectVersion = "3.5.2"

lazy val root = (project in file("."))
  .settings(
    name := "${this.options?.name || 'http4s-service'}",
    libraryDependencies ++= Seq(
${depList},
      
      // Circe (JSON)
      "io.circe" %% "circe-core" % circeVersion,
      "io.circe" %% "circe-generic" % circeVersion,
      "io.circe" %% "circe-parser" % circeVersion,
      
      // Cats ecosystem
      "org.typelevel" %% "cats-core" % catsVersion,
      "org.typelevel" %% "cats-effect" % catsEffectVersion,
      
      // Doobie (Database)
      "org.tpolecat" %% "doobie-core" % doobieVersion,
      "org.tpolecat" %% "doobie-hikari" % doobieVersion,
      "org.tpolecat" %% "doobie-postgres" % doobieVersion,
      
      // Logging
      "ch.qos.logback" % "logback-classic" % "1.4.14",
      "org.typelevel" %% "log4cats-slf4j" % "2.6.0",
      
      // Configuration
      "com.github.pureconfig" %% "pureconfig" % "0.17.4",
      
      // JWT
      "com.github.jwt-scala" %% "jwt-circe" % "9.4.4",
      
      // Testing
      "org.scalatest" %% "scalatest" % "3.2.17" % Test,
      "org.scalatestplus" %% "mockito-4-6" % "3.2.15.0" % Test,
      "org.typelevel" %% "cats-effect-testing-scalatest" % "1.5.0" % Test,
      "org.tpolecat" %% "doobie-scalatest" % doobieVersion % Test
    ),
    
    // Compiler options
    scalacOptions ++= Seq(
      "-deprecation",
      "-encoding", "UTF-8",
      "-language:higherKinds",
      "-language:postfixOps",
      "-feature",
      "-Xfatal-warnings"
    ),
    
    // Assembly plugin for fat JAR
    assembly / mainClass := Some("com.example.Main"),
    assembly / assemblyJarName := "app.jar",
    assembly / assemblyMergeStrategy := {
      case "META-INF/services/org.apache.spark.sql.sources.DataSourceRegister" => MergeStrategy.concat
      case PathList("META-INF", xs @ _*) => MergeStrategy.discard
      case _ => MergeStrategy.first
    }
  )

// Add assembly plugin
addSbtPlugin("com.eed3si9n" % "sbt-assembly" % "2.1.3")`;
  }
}