import { ScalaBackendGenerator } from './scala-base-generator';

export class AkkaHttpGenerator extends ScalaBackendGenerator {
  protected getFrameworkDependencies(): Record<string, string> {
    return {
      "com.typesafe.akka::akka-actor-typed_2.13": "2.8.5",
      "com.typesafe.akka::akka-stream_2.13": "2.8.5",
      "com.typesafe.akka::akka-http_2.13": "10.5.3",
      "com.typesafe.akka::akka-http-spray-json_2.13": "10.5.3",
      "com.typesafe.akka::akka-slf4j_2.13": "2.8.5",
      "de.heikoseeberger::akka-http-circe_2.13": "1.39.2"
    };
  }

  protected generateMainFile(): string {
    return `package com.example

import akka.actor.typed.ActorSystem
import akka.actor.typed.scaladsl.Behaviors
import akka.http.scaladsl.Http
import akka.http.scaladsl.server.Route
import com.example.config.{DatabaseConfig, JwtConfig}
import com.example.routes.Routes
import com.example.services.{AuthService, UserService}
import com.example.repositories.UserRepository
import com.example.utils.{JwtUtils, PasswordUtils}
import com.typesafe.config.ConfigFactory
import org.typelevel.log4cats.slf4j.Slf4jLogger
import cats.effect.{IO, IOApp}
import cats.effect.unsafe.implicits.global
import scala.concurrent.duration._
import scala.util.{Failure, Success}

object Main extends IOApp.Simple {
  
  implicit val system: ActorSystem[Nothing] = ActorSystem(Behaviors.empty, "akka-http-server")
  implicit val logger = Slf4jLogger.getLogger[IO]
  
  def run: IO[Unit] = {
    val config = ConfigFactory.load()
    
    val host = config.getString("server.host")
    val port = config.getInt("server.port")
    
    val program = for {
      // Initialize configuration
      dbConfig <- DatabaseConfig.load[IO]
      jwtConfig <- JwtConfig.load[IO]
      
      // Initialize utilities
      jwtUtils = new JwtUtils[IO](jwtConfig.secret, jwtConfig.expiration)
      
      // Initialize repositories
      userRepository = new UserRepository[IO](dbConfig)
      
      // Initialize services
      userService = new UserService[IO](userRepository)
      authService = new AuthService[IO](userService, jwtUtils)
      
      // Initialize routes
      routes = new Routes[IO](authService, userService, jwtUtils)
      
      // Start server
      _ <- startServer(routes.routes, host, port)
    } yield ()
    
    program.handleErrorWith { error =>
      logger.error(error)("Failed to start server") *> IO.raiseError(error)
    }
  }
  
  private def startServer(routes: Route, host: String, port: Int): IO[Unit] = IO.async_ { cb =>
    Http().newServerAt(host, port).bind(routes).onComplete {
      case Success(binding) =>
        println(s"Server online at http://\${binding.localAddress.getHostString}:\${binding.localAddress.getPort}/")
        cb(Right(()))
      case Failure(ex) =>
        println(s"Failed to bind HTTP endpoint, terminating system: \${ex.getMessage}")
        cb(Left(ex))
    }
  }
}`;
  }

  protected generateRoutingFile(): string {
    return `package com.example.routes

import akka.actor.typed.ActorSystem
import akka.http.scaladsl.model.{ContentTypes, HttpEntity, StatusCodes}
import akka.http.scaladsl.server.{Directives, Route}
import cats.effect.IO
import cats.effect.unsafe.implicits.global
import com.example.dto._
import com.example.services.{AuthService, UserService}
import com.example.utils.JwtUtils
import com.example.middleware.ErrorHandler
import de.heikoseeberger.akkahttpcirce.FailFastCirceSupport._
import io.circe.syntax._
import scala.util.{Failure, Success}

class Routes[F[_]](
  authService: AuthService[F],
  userService: UserService[F], 
  jwtUtils: JwtUtils[F]
)(implicit system: ActorSystem[Nothing]) extends Directives {

  val routes: Route = {
    pathPrefix("api") {
      concat(
        healthRoute,
        authRoutes,
        userRoutes
      )
    } ~ pathSingleSlash {
      get {
        complete(HttpEntity(ContentTypes.\`text/html(UTF-8)\`, 
          s"<h1>Welcome to \${system.name}</h1>"))
      }
    }
  }

  private def healthRoute: Route =
    path("health") {
      get {
        complete(StatusCodes.OK, Map(
          "status" -> "OK",
          "timestamp" -> System.currentTimeMillis(),
          "service" -> system.name
        ).asJson)
      }
    }

  private def authRoutes: Route =
    pathPrefix("auth") {
      concat(
        path("register") {
          post {
            entity(as[CreateUserRequest]) { request =>
              onComplete(authService.register(request).unsafeToFuture()) {
                case Success(response) => complete(StatusCodes.Created, response)
                case Failure(error) => handleError(error)
              }
            }
          }
        },
        path("login") {
          post {
            entity(as[LoginRequest]) { request =>
              onComplete(authService.login(request).unsafeToFuture()) {
                case Success(response) => complete(StatusCodes.OK, response)
                case Failure(error) => handleError(error)
              }
            }
          }
        },
        path("refresh") {
          post {
            entity(as[RefreshTokenRequest]) { request =>
              onComplete(authService.refreshToken(request).unsafeToFuture()) {
                case Success(response) => complete(StatusCodes.OK, response)
                case Failure(error) => handleError(error)
              }
            }
          }
        },
        path("logout") {
          post {
            authenticateUser { user =>
              headerValueByName("X-Refresh-Token") { refreshToken =>
                onComplete(authService.logout(refreshToken).unsafeToFuture()) {
                  case Success(_) => complete(StatusCodes.OK, MessageResponse("Logged out successfully"))
                  case Failure(error) => handleError(error)
                }
              }
            }
          }
        }
      )
    }

  private def userRoutes: Route =
    pathPrefix("users") {
      concat(
        pathEnd {
          get {
            requireRole("admin") { _ =>
              parameters("page".as[Int].?, "size".as[Int].?) { (page, size) =>
                onComplete(userService.getAllUsers(page.getOrElse(0), size.getOrElse(20)).unsafeToFuture()) {
                  case Success(users) => complete(StatusCodes.OK, users)
                  case Failure(error) => handleError(error)
                }
              }
            }
          }
        },
        path("me") {
          get {
            authenticateUser { user =>
              complete(StatusCodes.OK, UserResponse.fromUser(user))
            }
          }
        },
        path(IntNumber) { id =>
          concat(
            get {
              authenticateUser { _ =>
                onComplete(userService.findById(id).unsafeToFuture()) {
                  case Success(Some(user)) => complete(StatusCodes.OK, UserResponse.fromUser(user))
                  case Success(None) => complete(StatusCodes.NotFound, ErrorResponse("Not Found", "User not found"))
                  case Failure(error) => handleError(error)
                }
              }
            },
            put {
              authenticateUser { authUser =>
                entity(as[UpdateUserRequest]) { request =>
                  onComplete(userService.updateUser(id, request).unsafeToFuture()) {
                    case Success(user) => complete(StatusCodes.OK, UserResponse.fromUser(user))
                    case Failure(error) => handleError(error)
                  }
                }
              }
            },
            delete {
              requireRole("admin") { _ =>
                onComplete(userService.deleteUser(id).unsafeToFuture()) {
                  case Success(_) => complete(StatusCodes.NoContent)
                  case Failure(error) => handleError(error)
                }
              }
            }
          )
        }
      )
    }

  private def authenticateUser: Directive1[com.example.models.User] =
    optionalHeaderValueByName("Authorization").flatMap {
      case Some(authHeader) if authHeader.startsWith("Bearer ") =>
        val token = authHeader.substring(7)
        onComplete(jwtUtils.getUserIdFromToken(token).unsafeToFuture()).flatMap {
          case Success(Some(userId)) =>
            onComplete(userService.findById(userId).unsafeToFuture()).flatMap {
              case Success(Some(user)) => provide(user)
              case _ => complete(StatusCodes.Unauthorized, ErrorResponse("Unauthorized", "Invalid token"))
            }
          case _ => complete(StatusCodes.Unauthorized, ErrorResponse("Unauthorized", "Invalid token"))
        }
      case _ => complete(StatusCodes.Unauthorized, ErrorResponse("Unauthorized", "Authorization header required"))
    }

  private def requireRole(role: String): Directive1[com.example.models.User] =
    authenticateUser.flatMap { user =>
      if (user.role == role) provide(user)
      else complete(StatusCodes.Forbidden, ErrorResponse("Forbidden", "Insufficient permissions"))
    }

  private def handleError(error: Throwable): Route = {
    val errorResponse = ErrorHandler.handleError[IO](error).unsafeRunSync()
    error match {
      case _: com.example.middleware.ValidationError => complete(StatusCodes.BadRequest, errorResponse)
      case _: com.example.middleware.NotFoundError => complete(StatusCodes.NotFound, errorResponse)
      case _: com.example.middleware.UnauthorizedError => complete(StatusCodes.Unauthorized, errorResponse)
      case _: com.example.middleware.ForbiddenError => complete(StatusCodes.Forbidden, errorResponse)
      case _ => complete(StatusCodes.InternalServerError, errorResponse)
    }
  }
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

class UserService[F[_]: Sync](userRepository: UserRepository[F]) {
  
  def createUser(request: CreateUserRequest): F[User] = {
    for {
      // Check if email already exists
      existingUser <- userRepository.findByEmail(request.email)
      _ <- existingUser match {
        case Some(_) => Sync[F].raiseError(ValidationError("Email already exists"))
        case None => Sync[F].unit
      }
      
      // Hash password
      hashedPassword <- PasswordUtils.hashPassword[F](request.password)
      
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
        case Some(pwd) => PasswordUtils.hashPassword[F](pwd).map(Some(_))
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
          PasswordUtils.verifyPassword[F](password, u.password).map {
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
    return [];
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
}

akka {
  loggers = ["akka.event.slf4j.Slf4jLogger"]
  loglevel = "INFO"
  logging-filter = "akka.event.slf4j.Slf4jLoggingFilter"
  
  actor {
    provider = "akka.actor.LocalActorRefProvider"
  }
  
  http {
    server {
      request-timeout = 20s
      idle-timeout = 60s
      bind-timeout = 1s
      linger-timeout = 1min
      max-connections = 1024
      pipelining-limit = 16
      
      parsing {
        max-uri-length = 4k
        max-method-length = 16
        max-response-reason-length = 64
        max-header-name-length = 64
        max-header-value-length = 8k
        max-header-count = 64
        max-content-length = 8m
      }
    }
  }
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
  <logger name="akka" level="INFO"/>
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
    return [];
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
import org.scalatest.freespec.AsyncFreeSpec
import org.scalatest.matchers.should.Matchers
import org.mockito.MockitoSugar

class UserServiceSpec extends AsyncFreeSpec with AsyncIOSpec with Matchers with MockitoSugar {

  "UserService" - {
    "createUser" - {
      "should create a new user successfully" in {
        val mockRepository = mock[UserRepository[IO]]
        val userService = new UserService[IO](mockRepository)
        
        val request = CreateUserRequest(
          email = "test@example.com",
          password = "password123",
          name = "Test User"
        )
        
        // Test would need proper mocking setup
        // This is a basic structure example
        succeed
      }
    }
  }
}`
      }
    ];
  }
}